//! Protected secret memory for Wardstone.
//!
//! Every unlocked secret in the process — the master key, the JWT signing key,
//! the database credential, live sessions — lives in one `memfd_secret(2)`
//! pool mapped at startup, and every argon2 pass runs in a slot of that same
//! pool. Those pages are never swapped, never appear in a core dump, and
//! cannot be read back through `/proc/<pid>/mem`, `ptrace` or DMA, because
//! secret memory is removed from the kernel's direct map and refused by
//! `get_user_pages`.
//!
//! The pool is a fixed, pre-locked budget, so it can be exhausted. When it is,
//! the arena **refuses** — there is no heap fallback, since a heap fallback
//! would silently undo every guarantee above. For the same reason there is no
//! test-only pool: `init(PRODUCTION_POOL)` is the only way in, and a host that
//! cannot provide the protections fails to boot with an error that names the
//! protection and the knob to turn.
//!
//! ```no_run
//! # fn main() -> Result<(), ws_secmem::SecMemError> {
//! // First thing in every binary mode:
//! let mem = ws_secmem::init(ws_secmem::PRODUCTION_POOL)?;
//!
//! let mut secret = mem.alloc_copy(b"not on the heap")?;
//! secret.fill(0); // wiped again on drop, and the region returns to the arena
//!
//! let mut slot = mem.kdf_slot(); // blocks until a slot is free
//! let blocks = slot.blocks(262_144)?; // 256 MiB of locked argon2 scratch
//! # let _ = blocks;
//! # Ok(())
//! # }
//! ```

mod arena;
mod harden;
mod slots;

use std::io;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

pub use arena::SecretBuf;
pub use slots::SlotGuard;

use arena::Pool;
use slots::SlotKind;

/// The per-process memlock budget Wardstone is deployed with: 512 MiB.
///
/// The pool must fit inside it. Deployments set it with compose's `ulimits:
/// memlock:`; an unprivileged LXC container additionally needs
/// `lxc.prlimit.memlock` on the host, because a container cannot raise its own
/// hard limit.
pub const LOCK_BUDGET: u64 = 536_870_912;

/// The shape of the pool: how many argon2 slots of what size, plus the arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolSpec {
    /// Slots for the master-key KDF (`m_cost = 262144`).
    pub kdf_slots: usize,
    /// Bytes per KDF slot.
    pub kdf_slot_bytes: usize,
    /// Slots for password hashing (`m_cost = 65536`).
    pub hash_slots: usize,
    /// Bytes per password-hash slot.
    pub hash_slot_bytes: usize,
    /// Bytes of general-purpose secret arena.
    pub arena_bytes: usize,
}

/// The one pool Wardstone runs with: 400 MiB inside the 512 MiB
/// [`LOCK_BUDGET`].
///
/// One 256 MiB KDF slot (the master-key KDF is serialised by construction —
/// one unlock at a time), two 64 MiB password-hash slots (so a second login
/// does not wait on the first), and a 16 MiB arena for keys, credentials and
/// up to 1,024 concurrent sessions.
pub const PRODUCTION_POOL: PoolSpec = PoolSpec {
    kdf_slots: 1,
    kdf_slot_bytes: 268_435_456,
    hash_slots: 2,
    hash_slot_bytes: 67_108_864,
    arena_bytes: 16_777_216,
};

/// A protection that could not be established, or a pool that cannot serve a
/// request.
///
/// Every `Display` names the protection that failed and the likely causes, so
/// an operator can act on a boot refusal without reading this source. No
/// variant can carry secret material.
#[derive(Debug, thiserror::Error)]
pub enum SecMemError {
    /// `RLIMIT_CORE` could not be dropped to zero.
    #[error(
        "core dumps could not be disabled (RLIMIT_CORE): {0}; a core file would contain every unlocked secret"
    )]
    CoreLimit(#[source] io::Error),

    /// `PR_SET_DUMPABLE` or `MADV_DONTDUMP` failed.
    #[error(
        "the process could not be made undumpable (PR_SET_DUMPABLE/MADV_DONTDUMP): {0}; a ptrace attach or a core dump could read the unlocked secrets"
    )]
    Dumpable(#[source] io::Error),

    /// `memfd_secret(2)` is not usable in this process.
    #[error(
        "memfd_secret is unavailable (errno {errno}): the kernel is older than 5.14, secretmem is disabled on the kernel command line, or a seccomp profile blocks syscall 447"
    )]
    SecretMemUnavailable { errno: i32 },

    /// The memlock budget cannot hold the pool.
    #[error(
        "the memlock limit is {have} bytes but Wardstone needs {need}: set ulimits memlock 536870912 (compose) — in an unprivileged LXC the host needs lxc.prlimit.memlock: 536870912"
    )]
    MemlockTooSmall { have: u64, need: u64 },

    /// The memlock limit could not be read at all.
    #[error(
        "the memlock limit could not be read (getrlimit(RLIMIT_MEMLOCK)): {0}; Wardstone will not map secrets it cannot prove will stay in RAM"
    )]
    MemlockUnreadable(#[source] io::Error),

    /// The pool could not be locked into RAM.
    #[error(
        "the secret pool could not be mapped and locked into RAM (errno {errno}): the memlock limit was large enough when checked a moment earlier, so the cause lies elsewhere — another mapping in this process holding part of the budget, the host being out of lockable memory, or a mapping the kernel refuses outright"
    )]
    MlockFailed { errno: i32 },

    /// The mapping does not behave as memory.
    #[error(
        "the secret pool failed its read-back probe at byte {offset}: the mapping was created but does not hold what is written to it, so it cannot be trusted with secrets"
    )]
    ProbeFailed { offset: usize },

    /// The arena is full. It never spills to the heap.
    #[error(
        "the secret arena cannot serve {requested} bytes: it is full, and secrets are never spilled to the heap — too many secrets are held open at once"
    )]
    ArenaFull { requested: usize },

    /// An argon2 `m_cost` larger than the slot it would run in.
    #[error(
        "the requested argon2 m_cost does not fit the locked slot: the pool is sized for Wardstone's fixed argon2 parameters"
    )]
    SlotTooSmall,
}

/// The process-wide protected pool.
///
/// Obtained from [`init`] or [`global`]; there is exactly one per process and
/// it lives for the life of the process.
pub struct SecMem {
    pool: Arc<Pool>,
}

impl SecMem {
    /// Reserves `len` bytes of secret memory.
    ///
    /// The contents are zero. Rounded up to a 64-byte granule internally.
    ///
    /// # Errors
    ///
    /// [`SecMemError::ArenaFull`] if the arena cannot serve the request. It is
    /// never served from the heap.
    pub fn alloc(&self, len: usize) -> Result<SecretBuf, SecMemError> {
        self.pool.alloc(len)
    }

    /// Reserves secret memory and copies `bytes` into it.
    ///
    /// The caller still owns `bytes` and is responsible for wiping it — this
    /// is the boundary where a secret crosses from ordinary memory into the
    /// pool, not a way to un-leak one.
    ///
    /// # Errors
    ///
    /// As [`SecMem::alloc`].
    pub fn alloc_copy(&self, bytes: &[u8]) -> Result<SecretBuf, SecMemError> {
        let mut buf = self.alloc(bytes.len())?;
        buf.copy_from_slice(bytes);
        Ok(buf)
    }

    /// Leases the KDF slot, blocking until it is free.
    ///
    /// **Blocks the calling OS thread**, not just the current task: the wait is
    /// a `Condvar`, invisible to an async runtime. An async caller must reach
    /// this through `tokio::task::spawn_blocking` — argon2 itself is a
    /// multi-hundred-millisecond CPU burn that belongs there regardless.
    pub fn kdf_slot(&self) -> SlotGuard<'_> {
        SlotGuard::acquire(&self.pool, SlotKind::Kdf)
    }

    /// Leases a password-hash slot, blocking until one is free.
    ///
    /// **Blocks the calling OS thread** — see [`SecMem::kdf_slot`]. With two
    /// slots and one login burst, the third concurrent hash waits here, so
    /// calling this on a runtime worker thread would stall unrelated requests.
    pub fn hash_slot(&self) -> SlotGuard<'_> {
        SlotGuard::acquire(&self.pool, SlotKind::Hash)
    }

    /// Bytes still available in the arena.
    ///
    /// The total of the free runs; a single allocation that large succeeds only
    /// if the arena is unfragmented.
    pub fn arena_free(&self) -> usize {
        self.pool.arena_free()
    }

    /// Read `len` bytes at absolute address `addr` back out of the
    /// protected arena.
    ///
    /// TEST-ONLY observability: it exists so a test can prove a dropped
    /// [`SecretBuf`]'s reservation reads as zero — the wipe its `Drop`
    /// promises — and nothing in production may read the pool through a
    /// raw pointer. Ruling 4: gated behind `test` builds and the
    /// `test-peek` cargo feature, which is enabled only through a
    /// dev-dependency of a test suite, never a normal dependency, so no
    /// production build of any dependent ever sees the accessor.
    ///
    /// `None` when `[addr, addr + len)` is not wholly inside the arena.
    #[cfg(any(test, feature = "test-peek"))]
    pub fn peek_for_test(&self, addr: *const u8, len: usize) -> Option<Vec<u8>> {
        self.pool.peek(addr, len)
    }
}

static INSTANCE: OnceLock<SecMem> = OnceLock::new();
/// Serialises construction so two racing callers cannot each map a pool and
/// charge the memlock budget twice.
static GATE: Mutex<()> = Mutex::new(());

/// Hardens the process, probes the host, and maps the pool.
///
/// Idempotent: the first call builds the pool and every later call returns it,
/// `spec` included — there is one pool per process, and the first caller's spec
/// wins.
///
/// Every binary mode and every test binary calls this before touching a
/// secret.
///
/// # Process-wide side effects
///
/// This is not a constructor; it changes the process permanently:
///
/// - `RLIMIT_CORE` becomes 0/0. The hard limit too, so nothing later can raise
///   it back.
/// - `PR_SET_DUMPABLE` becomes 0. Beyond stopping `ptrace` attach and core
///   dumps, this hands `/proc/self/{mem,environ,maps,smaps,pagemap,…}` to
///   `root:root` with mode 0600 for the rest of the process's life, so an
///   unprivileged process can no longer open its own. Anything that needs to
///   read those files must open them **before** calling `init`
///   (`/proc/self/status` stays 0444 and readable). Code that shells out is
///   unaffected: the child is a new process.
/// - 400 MiB of secret memory is mapped and faulted in, so RSS and the
///   process's `VmLck` both rise by the pool size and stay there.
///
/// # Errors
///
/// Any [`SecMemError`] from the hardening or the probe. The call is
/// fail-closed: a host that cannot provide a protection gets the error, never
/// a pool with the protection quietly missing.
pub fn init(spec: PoolSpec) -> Result<&'static SecMem, SecMemError> {
    if let Some(mem) = INSTANCE.get() {
        return Ok(mem);
    }

    // Nothing below can unwind while the gate is held, so a poisoned gate is
    // still a valid gate.
    let _gate = GATE.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(mem) = INSTANCE.get() {
        return Ok(mem);
    }

    harden::harden_process()?;
    let mem = SecMem {
        pool: Arc::new(Pool::build(spec)?),
    };
    Ok(INSTANCE.get_or_init(|| mem))
}

/// The process-wide pool, initialising it with [`PRODUCTION_POOL`] on first
/// use.
///
/// A caller that reaches a secret before startup ran [`init`] still gets a
/// fully hardened, probed pool rather than a failure — the same work, under the
/// same gate, fail-closed.
///
/// # Errors
///
/// As [`init`].
pub fn global() -> Result<&'static SecMem, SecMemError> {
    init(PRODUCTION_POOL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_production_pool_fits_the_lock_budget() {
        let spec = PRODUCTION_POOL;
        let total = spec.kdf_slots * spec.kdf_slot_bytes
            + spec.hash_slots * spec.hash_slot_bytes
            + spec.arena_bytes;
        assert_eq!(total, 419_430_400, "400 MiB");
        assert!(
            total as u64 <= LOCK_BUDGET,
            "the pool must fit the memlock budget"
        );
    }

    #[test]
    fn the_kdf_slot_holds_wardstones_kdf_cost() {
        // The master-key KDF runs at m_cost = 262144 KiB.
        assert_eq!(PRODUCTION_POOL.kdf_slot_bytes, 262_144 * 1024);
        // Password hashing runs at m_cost = 65536 KiB.
        assert_eq!(PRODUCTION_POOL.hash_slot_bytes, 65_536 * 1024);
    }

    #[test]
    fn no_error_display_leaks_secret_material() {
        // A sanity net over the copy: the messages name protections and
        // knobs, never bytes.
        let messages = [
            SecMemError::SecretMemUnavailable { errno: 38 }.to_string(),
            SecMemError::MemlockTooSmall {
                have: 8_388_608,
                need: 419_430_400,
            }
            .to_string(),
            SecMemError::MemlockUnreadable(io::Error::from_raw_os_error(libc::EINVAL)).to_string(),
            SecMemError::MlockFailed { errno: 11 }.to_string(),
            SecMemError::ProbeFailed { offset: 4095 }.to_string(),
            SecMemError::ArenaFull { requested: 64 }.to_string(),
            SecMemError::SlotTooSmall.to_string(),
        ];
        for message in messages {
            assert!(!message.is_empty());
            assert!(
                !message.contains("passphrase") && !message.contains("password"),
                "{message}"
            );
        }
    }

    /// Task 5 (seal-at-creation): a dropped `SecretBuf`'s reservation reads
    /// back as zero through the test-only peek — the volatile wipe its
    /// `Drop` promises, proven on a small dedicated pool. It cannot use
    /// `global()`: `the_pool_descriptor_is_close_on_exec` maps a second
    /// full production spec in a parallel test thread, and the host's
    /// 512 MiB memlock budget holds one 400 MiB pool, never two — and
    /// the wipe is a property of `SecretBuf`'s `Drop`, identical on any
    /// real `memfd_secret` pool. The production pool's own coverage runs
    /// alone in the ws-ca keystore suite's binary.
    #[test]
    fn a_dropped_buffer_reads_zero_through_the_peek() {
        let pool = std::sync::Arc::new(
            Pool::build(PoolSpec {
                kdf_slots: 1,
                kdf_slot_bytes: 64,
                hash_slots: 1,
                hash_slot_bytes: 64,
                arena_bytes: 4096,
            })
            .expect("a small pool must build on this host"),
        );

        let mut buf = pool.alloc(13).expect("the arena serves a small buffer");
        buf.copy_from_slice(b"wiped-on-drop");
        let addr = buf.as_ptr();
        let len = buf.len();
        drop(buf);

        let bytes = pool
            .peek(addr, len)
            .expect("the dropped region stays inside the arena");
        assert!(
            bytes.iter().all(|b| *b == 0),
            "a dropped SecretBuf's reservation must read as zero"
        );
    }
}
