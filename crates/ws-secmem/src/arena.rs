//! The `memfd_secret` mapping, its layout, and the refusing arena on top of it.
//!
//! One `memfd_secret(2)` descriptor backs the whole pool. Those pages are
//! never present in the kernel's direct map, are never swapped, cannot be
//! obtained through `get_user_pages` (so no `/proc/<pid>/mem` read, no DMA,
//! no ptrace peek reaches them) and are dropped from the direct map for the
//! lifetime of the mapping. The arena hands out 64-byte-granular slices of
//! the tail of that mapping and refuses when it is full — it never falls back
//! to the heap, because a heap fallback is exactly the leak this crate exists
//! to prevent.

use std::fmt;
use std::io;
use std::ops::{Deref, DerefMut};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::io::AsRawFd;
use std::ptr::{self, NonNull};
use std::slice;
use std::sync::{Arc, Mutex, PoisonError};

use zeroize::Zeroize;

use crate::slots::SlotSet;
use crate::{PoolSpec, SecMemError};

/// Allocation granularity of the arena, and the alignment every sub-range of
/// the pool inherits. 64 bytes is `align_of::<argon2::Block>()` and a cache
/// line, so no two live buffers ever share one.
pub(crate) const GRAIN: usize = 64;

/// Rounds `value` up to the next multiple of `to` (a power of two).
///
/// Saturating, so an absurd [`PoolSpec`] or allocation request is refused
/// (`MemlockTooSmall`, `ArenaFull`) rather than wrapping into a small one.
const fn align_up(value: usize, to: usize) -> usize {
    value.div_ceil(to).saturating_mul(to)
}

fn page_size() -> usize {
    // SAFETY: `sysconf` takes a name and returns a long; no pointers involved.
    let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if raw > 0 {
        raw as usize
    } else {
        4096
    }
}

/// The owned `memfd_secret` mapping.
struct Mapping {
    base: NonNull<u8>,
    len: usize,
    /// Held only so the secret-memory descriptor outlives the mapping; closed
    /// by `OwnedFd`'s own `Drop` after `munmap`.
    _fd: OwnedFd,
}

// SAFETY: a `Mapping` is an owned address range plus the descriptor that backs
// it. The raw pointer is the only reason it is not `Send`/`Sync` already;
// nothing reads or writes the range through the `Mapping` itself. Views into
// the range are handed out exclusively by the arena and the slot sets, which
// reserve disjoint sub-ranges under their own locks and do not hand the same
// sub-range to two holders, so sharing a `Mapping` across threads cannot
// create aliasing or a data race.
unsafe impl Send for Mapping {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for Mapping {}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: `base`/`len` are the exact arguments of the `mmap` that
        // produced them, and no view into the range outlives the `Pool` that
        // owns this mapping (`SecretBuf` keeps the pool alive through an
        // `Arc`). `fd` is closed afterwards by `OwnedFd`'s own `Drop`.
        unsafe {
            libc::munmap(self.base.as_ptr().cast::<libc::c_void>(), self.len);
        }
    }
}

impl Mapping {
    /// Maps `len` bytes of secret memory, excludes them from core dumps, and
    /// proves the range behaves as memory before anything secret is put in it.
    fn new(len: usize) -> Result<Self, SecMemError> {
        // `O_CLOEXEC`, not `MFD_CLOEXEC`: close-on-exec is the point (nothing
        // this process execs may inherit a handle on the secret pool), but
        // `memfd_secret` is not `memfd_create` — its flags word accepts
        // `O_CLOEXEC` alone and rejects `MFD_CLOEXEC` (0x1) with `EINVAL`.
        // Verified on this kernel; `fcntl(F_GETFD)` then reports `FD_CLOEXEC`.
        //
        // SAFETY: `memfd_secret` takes only a flags word, passed at the full
        // `c_long` width the variadic `syscall` ABI requires. glibc ships no
        // wrapper for it, hence the raw syscall.
        let raw =
            unsafe { libc::syscall(libc::SYS_memfd_secret, libc::c_long::from(libc::O_CLOEXEC)) };
        if raw < 0 {
            return Err(SecMemError::SecretMemUnavailable { errno: errno() });
        }
        // SAFETY: `raw` is a fresh, positive descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw as libc::c_int) };

        // SAFETY: `fd` is a live secret-memory descriptor with no mappings yet.
        if unsafe { libc::ftruncate(fd.as_raw_fd(), len as libc::off_t) } != 0 {
            return Err(SecMemError::SecretMemUnavailable { errno: errno() });
        }

        // MAP_SHARED is mandatory for secret memory: `secretmem_mmap` rejects
        // a private mapping outright.
        // SAFETY: `fd` is sized to `len` by the `ftruncate` above, so no part
        // of the mapping lies past the end of the file.
        let base = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        let base = match NonNull::new(base) {
            Some(base) if base.as_ptr() != libc::MAP_FAILED => base.cast::<u8>(),
            // `mmap` is where the kernel charges a secret-memory mapping
            // against RLIMIT_MEMLOCK (and where it would refuse an
            // unsupportable mapping outright), so a failure here is the pool
            // failing to be locked. The errno is carried through rather than
            // interpreted: EAGAIN is the budget, ENOMEM the host, EINVAL a
            // mapping the kernel will not make at all.
            _ => return Err(SecMemError::MlockFailed { errno: errno() }),
        };

        let mapping = Mapping { base, len, _fd: fd };

        // Secret memory is already `VM_DONTDUMP`, but core-dump exclusion is a
        // guarantee this crate owes its callers, so it is asserted rather than
        // assumed.
        // SAFETY: the range is exactly the mapping just created.
        if unsafe {
            libc::madvise(
                mapping.base.as_ptr().cast::<libc::c_void>(),
                mapping.len,
                libc::MADV_DONTDUMP,
            )
        } != 0
        {
            return Err(SecMemError::Dumpable(io::Error::last_os_error()));
        }

        mapping.probe()?;
        Ok(mapping)
    }

    /// Writes a page of a known pattern, reads it back, then faults in and
    /// zeroes the whole pool.
    ///
    /// Touching every page here is deliberate. Secret memory is populated on
    /// fault, so a pool that is only reserved could still fail halfway through
    /// an unlock; after this returns, the whole pool is resident, charged and
    /// known to be zero, which is also what makes the raw slices the arena and
    /// the slots hand out initialised memory.
    fn probe(&self) -> Result<(), SecMemError> {
        let page = page_size().min(self.len);

        // Both halves are volatile. A plain store-then-load pair over memory
        // the compiler can see is dead code it is entitled to delete, which
        // would leave the probe asserting nothing in a release build — the
        // only build that matters here.
        for offset in 0..page {
            let byte = (offset % 251) as u8;
            // SAFETY: `offset < page <= len`, the range is inside the mapping,
            // and nothing else can hold a view into it — the pool is not
            // published until `build` returns.
            unsafe { ptr::write_volatile(self.base.as_ptr().add(offset), byte) };
        }
        for offset in 0..page {
            let want = (offset % 251) as u8;
            // SAFETY: as above.
            let got = unsafe { ptr::read_volatile(self.base.as_ptr().add(offset)) };
            if got != want {
                return Err(SecMemError::ProbeFailed { offset });
            }
        }

        // SAFETY: as above, over the whole mapping.
        let whole = unsafe { slice::from_raw_parts_mut(self.base.as_ptr(), self.len) };
        // A plain memset, not a volatile wipe: nothing secret has ever been in
        // this pool yet, so there is nothing an optimiser could elide that
        // matters. Volatile wipes are for `SecretBuf`/`SlotGuard` drops, where
        // the bytes really are secret. At 400 MiB the difference is seconds of
        // boot time.
        whole.fill(0);
        Ok(())
    }

    /// The backing descriptor, for the close-on-exec test only.
    #[cfg(test)]
    fn raw_fd(&self) -> libc::c_int {
        self._fd.as_raw_fd()
    }

    /// Pointer to byte `offset` of the mapping.
    fn ptr_at(&self, offset: usize) -> *mut u8 {
        debug_assert!(offset <= self.len, "offset past the mapping");
        // SAFETY: `offset` is within the mapping, so the result is in bounds
        // (one past the end is permitted for a zero-length slice).
        unsafe { self.base.as_ptr().add(offset) }
    }
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// A free run of the arena, in arena-relative bytes.
#[derive(Clone, Copy, Debug)]
struct Region {
    offset: usize,
    len: usize,
}

/// First-fit allocator over the arena sub-range of the pool.
pub(crate) struct Arena {
    /// Offset of the arena within the mapping.
    base: usize,
    len: usize,
    /// Disjoint, offset-sorted, fully coalesced free runs.
    free: Mutex<Vec<Region>>,
}

impl Arena {
    fn new(base: usize, len: usize) -> Self {
        Arena {
            base,
            len,
            free: Mutex::new(vec![Region { offset: 0, len }]),
        }
    }

    fn free_list(&self) -> std::sync::MutexGuard<'_, Vec<Region>> {
        // A panic can never unwind while this lock is held — the critical
        // sections below only index and splice a `Vec` — so a poisoned lock
        // still protects a consistent free list.
        self.free.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reserves `requested` bytes, rounded up to [`GRAIN`]. Returns the
    /// arena-relative offset and the reserved capacity.
    fn reserve(&self, requested: usize) -> Result<(usize, usize), SecMemError> {
        let want = align_up(requested.max(1), GRAIN);
        let mut free = self.free_list();
        let index = free
            .iter()
            .position(|run| run.len >= want)
            .ok_or(SecMemError::ArenaFull { requested })?;

        let offset = free[index].offset;
        if free[index].len == want {
            free.remove(index);
        } else {
            free[index].offset += want;
            free[index].len -= want;
        }
        Ok((offset, want))
    }

    /// Returns a reservation, coalescing it with its neighbours.
    fn release(&self, offset: usize, len: usize) {
        debug_assert!(
            offset + len <= self.len,
            "a release outside the arena would corrupt the free list"
        );
        let mut free = self.free_list();
        let at = free.partition_point(|run| run.offset < offset);
        free.insert(at, Region { offset, len });

        if at + 1 < free.len() && free[at].offset + free[at].len == free[at + 1].offset {
            free[at].len += free[at + 1].len;
            free.remove(at + 1);
        }
        if at > 0 && free[at - 1].offset + free[at - 1].len == free[at].offset {
            free[at - 1].len += free[at].len;
            free.remove(at);
        }
    }

    fn free_bytes(&self) -> usize {
        self.free_list().iter().map(|run| run.len).sum()
    }
}

/// The whole locked pool: the mapping, its arena, and the two argon2 slot sets.
pub(crate) struct Pool {
    pub(crate) arena: Arena,
    pub(crate) kdf: SlotSet,
    pub(crate) hash: SlotSet,
    /// Declared last so the mapping is unmapped only after everything that
    /// describes a part of it has been dropped.
    map: Mapping,
}

impl Pool {
    pub(crate) fn build(spec: PoolSpec) -> Result<Self, SecMemError> {
        let kdf_slot = align_up(spec.kdf_slot_bytes, GRAIN);
        let hash_slot = align_up(spec.hash_slot_bytes, GRAIN);
        let arena_len = align_up(spec.arena_bytes, GRAIN);

        // Saturating throughout: a spec too large for the address space must
        // come out of `check_memlock_budget` as a refusal, never wrap into a
        // pool smaller than the slots that are then carved out of it.
        let kdf_total = kdf_slot.saturating_mul(spec.kdf_slots);
        let hash_total = hash_slot.saturating_mul(spec.hash_slots);
        // Offset of the arena: the slots come first, the arena takes the tail.
        let slots_total = kdf_total.saturating_add(hash_total);
        // The mapping is page-granular: `mmap` rounds its length up to a page
        // and a mapping past the end of the descriptor would fault with
        // SIGBUS, so the descriptor is sized to the rounded length too.
        let len = align_up(slots_total.saturating_add(arena_len), page_size());

        // Before the mapping, so an operator sees the limit and not an EAGAIN.
        crate::harden::check_memlock_budget(len)?;

        let map = Mapping::new(len)?;
        Ok(Pool {
            arena: Arena::new(slots_total, arena_len),
            kdf: SlotSet::new(0, kdf_slot, spec.kdf_slots),
            hash: SlotSet::new(kdf_total, hash_slot, spec.hash_slots),
            map,
        })
    }

    /// Pointer to byte `offset` of the mapping.
    pub(crate) fn ptr_at(&self, offset: usize) -> *mut u8 {
        self.map.ptr_at(offset)
    }

    pub(crate) fn arena_free(&self) -> usize {
        self.arena.free_bytes()
    }

    /// The descriptor flags of the pool's `memfd_secret` fd, for the
    /// close-on-exec test. Read-only, and it exposes no secret memory.
    #[cfg(test)]
    pub(crate) fn fd_flags(&self) -> libc::c_int {
        // SAFETY: `F_GETFD` only reads the descriptor's flags and takes no
        // further argument; the descriptor is owned by this mapping.
        unsafe { libc::fcntl(self.map.raw_fd(), libc::F_GETFD) }
    }

    pub(crate) fn alloc(self: &Arc<Self>, len: usize) -> Result<SecretBuf, SecMemError> {
        let (offset, cap) = self.arena.reserve(len)?;
        Ok(SecretBuf {
            pool: Arc::clone(self),
            offset,
            len,
            cap,
        })
    }

    /// Volatile read-back of `[addr, addr + len)` translated into the
    /// arena's range — the engine behind [`SecMem::peek_for_test`]
    /// (test-only, Ruling 4). `None` when the range is not wholly inside
    /// the arena.
    ///
    /// The reads are volatile so a release build cannot fold them away,
    /// exactly like the mapping probe. They expose nothing production
    /// code could not already read through a live view of the same
    /// region: the accessor exists so a test can prove a dropped
    /// [`SecretBuf`]'s reservation reads as zero — the wipe its `Drop`
    /// promises — and it is compiled out of every normal dependent.
    #[cfg(any(test, feature = "test-peek"))]
    pub(crate) fn peek(&self, addr: *const u8, len: usize) -> Option<Vec<u8>> {
        let arena_start = self.map.base.as_ptr() as usize + self.arena.base;
        let addr = addr as usize;
        if addr < arena_start {
            return None;
        }
        let offset = addr - arena_start;
        let available = self.arena.len.checked_sub(offset)?;
        if len > available {
            return None;
        }
        let mut out = Vec::with_capacity(len);
        for byte in 0..len {
            // SAFETY: `offset + len <= self.arena.len`, and the arena
            // lies inside the mapping — the same bound
            // `SecretBuf::as_ptr_mut` computes for its own views.
            out.push(unsafe {
                ptr::read_volatile(self.map.base.as_ptr().add(self.arena.base + offset + byte))
            });
        }
        Some(out)
    }
}

/// A buffer of secret memory.
///
/// Derefs to its bytes, wipes them volatilely on drop and returns its region to
/// the arena. It is deliberately not `Clone`: a copy would be a second plaintext
/// of the same secret, and the whole point of the arena is that there is exactly
/// one. `Debug` prints the length only.
pub struct SecretBuf {
    /// Keeps the mapping alive for as long as any buffer points into it.
    pool: Arc<Pool>,
    /// Arena-relative offset of the reservation.
    offset: usize,
    /// Length the caller asked for, and all that `Deref` exposes.
    len: usize,
    /// Granule-rounded reservation; wiped in full on drop.
    cap: usize,
}

impl SecretBuf {
    fn as_ptr_mut(&self) -> *mut u8 {
        self.pool.ptr_at(self.pool.arena.base + self.offset)
    }
}

impl Deref for SecretBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        // SAFETY: the arena reserved `[offset, offset + cap)` exclusively for
        // this buffer and will not hand it out again until `Drop` releases it,
        // the range lies inside the mapping the `Arc` keeps alive, and the
        // whole pool was written to zero by `Mapping::probe`, so every byte is
        // initialised.
        unsafe { slice::from_raw_parts(self.as_ptr_mut(), self.len) }
    }
}

impl DerefMut for SecretBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: as for `Deref`, plus `&mut self` proves this is the only
        // live view into the reservation.
        unsafe { slice::from_raw_parts_mut(self.as_ptr_mut(), self.len) }
    }
}

impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuf({} bytes)", self.len)
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        // SAFETY: as for `DerefMut`, over the full reservation rather than the
        // exposed prefix — a shorter secret may have been written through an
        // earlier, longer life of this region.
        let whole = unsafe { slice::from_raw_parts_mut(self.as_ptr_mut(), self.cap) };
        whole.zeroize();
        self.pool.arena.release(self.offset, self.cap);
    }
}

/// `SecretBuf` must stay `Send + Sync`: secrets are handed between tokio
/// worker threads and held in shared state. It is a compile error if a future
/// field (a `Cell`, an `Rc`, a bare `*mut`) takes that away.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SecretBuf>();
    assert_send_sync::<crate::SecMem>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pool_descriptor_is_close_on_exec() {
        // A real pool, so the assertion is about the descriptor the pool
        // actually runs on rather than a fixture.
        let pool = Pool::build(crate::PRODUCTION_POOL).expect("the pool must build on this host");
        let flags = pool.fd_flags();
        assert!(flags >= 0, "fcntl(F_GETFD) failed: {flags}");
        assert_eq!(
            flags & libc::FD_CLOEXEC,
            libc::FD_CLOEXEC,
            "the secret-memory descriptor must not survive an exec"
        );
    }

    fn arena() -> Arena {
        Arena::new(0, 1024)
    }

    #[test]
    fn a_reservation_is_rounded_up_to_the_granule() {
        let arena = arena();
        let (offset, cap) = arena.reserve(1).expect("one byte fits");
        assert_eq!(offset, 0);
        assert_eq!(cap, GRAIN);
        assert_eq!(arena.free_bytes(), 1024 - GRAIN);
    }

    #[test]
    fn a_zero_length_reservation_still_takes_a_granule() {
        let arena = arena();
        let (_, cap) = arena.reserve(0).expect("zero bytes still gets an address");
        assert_eq!(cap, GRAIN);
    }

    #[test]
    fn releases_coalesce_back_into_one_run() {
        let arena = arena();
        let a = arena.reserve(64).expect("a");
        let b = arena.reserve(64).expect("b");
        let c = arena.reserve(64).expect("c");
        assert_eq!(arena.free_list().len(), 1);

        // Release out of order so both the forward and backward merges run.
        arena.release(c.0, c.1);
        arena.release(a.0, a.1);
        assert_eq!(arena.free_list().len(), 2, "a hole remains while b is held");
        arena.release(b.0, b.1);

        let free = arena.free_list();
        assert_eq!(
            free.len(),
            1,
            "the arena must coalesce to one run: {free:?}"
        );
        assert_eq!(free[0].offset, 0);
        assert_eq!(free[0].len, 1024);
    }

    #[test]
    fn a_request_past_the_arena_is_refused() {
        let arena = arena();
        let err = arena.reserve(1025).expect_err("past the arena");
        assert!(matches!(err, SecMemError::ArenaFull { requested: 1025 }));
        assert_eq!(arena.free_bytes(), 1024, "a refusal must not consume");
    }

    #[test]
    fn fragmentation_is_first_fit() {
        let arena = arena();
        let a = arena.reserve(64).expect("a");
        let _b = arena.reserve(64).expect("b");
        arena.release(a.0, a.1);
        let (offset, _) = arena.reserve(64).expect("reuse");
        assert_eq!(offset, a.0, "first fit must reuse the lowest hole");
    }
}
