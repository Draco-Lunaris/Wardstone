//! Behaviour of the protected pool: the process hardening `init` performs, the
//! arena's refusal-rather-than-spilling contract, and the locked argon2 slots.
//!
//! Every test calls `init(PRODUCTION_POOL)` — there is no test-only pool.
//! All tests in this binary therefore share one process-wide pool, so the
//! arena tests measure against `arena_free()` rather than assuming an empty
//! arena, and serialise through `ARENA` so an exact-fit assertion cannot race
//! another test's live buffer.

use std::sync::mpsc;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use ws_secmem::{init, SecMem, SecMemError, PRODUCTION_POOL};

/// Serialises the tests that assert on arena occupancy.
static ARENA: Mutex<()> = Mutex::new(());

/// Serialises every test that takes a hash slot. There are only two, and
/// `hash_slots_are_exclusive_and_bounded` holds both while it proves a third
/// waiter blocks, so an unsynchronised third user would make that test's
/// timing meaningless (and make its own wait unbounded).
static HASH_SLOTS: Mutex<()> = Mutex::new(());

fn lock(mutex: &'static Mutex<()>) -> MutexGuard<'static, ()> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn arena_lock() -> MutexGuard<'static, ()> {
    lock(&ARENA)
}

fn hash_slot_lock() -> MutexGuard<'static, ()> {
    lock(&HASH_SLOTS)
}

fn secmem() -> &'static SecMem {
    init(PRODUCTION_POOL).expect("the protected pool must initialise on this host")
}

#[test]
fn init_disables_core_dumps_and_dumpability() {
    let _ = secmem();

    let mut limit = libc::rlimit {
        rlim_cur: u64::MAX,
        rlim_max: u64::MAX,
    };
    // SAFETY: `limit` is a live, correctly typed out-parameter.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) };
    assert_eq!(rc, 0, "getrlimit(RLIMIT_CORE) failed");
    assert_eq!(limit.rlim_cur, 0, "the core-dump soft limit must be zero");
    assert_eq!(limit.rlim_max, 0, "the core-dump hard limit must be zero");

    // SAFETY: PR_GET_DUMPABLE takes no further arguments and only reads.
    let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
    assert_eq!(dumpable, 0, "the process must be undumpable");
}

/// Field `name` of `/proc/self/status`, in kB.
fn proc_status_kib(name: &str) -> u64 {
    // 0444, so it stays readable after PR_SET_DUMPABLE=0 — unlike
    // /proc/self/mem, which `init` makes root-owned 0600.
    let status = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
    let line = status
        .lines()
        .find(|line| line.starts_with(name))
        .unwrap_or_else(|| panic!("{name} missing from /proc/self/status"));
    line.split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("unparseable {name} line: {line:?}"))
}

/// The property the whole design rests on: the pool is locked into RAM and can
/// never be swapped out. `mlock()` is deliberately not called — it cannot
/// succeed on secret memory, because `get_user_pages` refuses those pages,
/// which is the same refusal that hides them from `/proc/<pid>/mem`. Secret
/// memory is `VM_LOCKED` from `mmap`, and this is where that is proved rather
/// than asserted in a comment.
#[test]
fn the_pool_is_locked_into_ram() {
    // Holds a buffer, so it takes the arena lock like every other test that
    // occupies the arena.
    let _guard = arena_lock();
    let mem = secmem();
    let pool_bytes = PRODUCTION_POOL.kdf_slots * PRODUCTION_POOL.kdf_slot_bytes
        + PRODUCTION_POOL.hash_slots * PRODUCTION_POOL.hash_slot_bytes
        + PRODUCTION_POOL.arena_bytes;
    assert_eq!(pool_bytes, 419_430_400, "400 MiB");
    // Touch the pool so this cannot pass against a pool that was never mapped.
    let _witness = mem.alloc(64).expect("the pool must be usable");

    let locked = proc_status_kib("VmLck") * 1024;
    assert!(
        locked >= pool_bytes as u64,
        "VmLck is {locked} bytes, which cannot hold the {pool_bytes}-byte pool: \
         the pool is not locked into RAM"
    );
}

#[test]
fn a_dropped_buffer_is_wiped_and_reused() {
    let _guard = arena_lock();
    let mem = secmem();
    let free_before = mem.arena_free();

    let address = {
        let mut buf = mem.alloc(128).expect("128 bytes must fit in the arena");
        assert_eq!(buf.len(), 128);
        buf.fill(0xA5);
        assert!(buf.iter().all(|&b| b == 0xA5), "the fill must be visible");
        assert_eq!(mem.arena_free(), free_before - 128);
        buf.as_ptr() as usize
    };

    assert_eq!(
        mem.arena_free(),
        free_before,
        "dropping a buffer must return its region"
    );

    let reused = mem
        .alloc(128)
        .expect("the freed region must be allocatable");
    assert_eq!(
        reused.as_ptr() as usize,
        address,
        "first-fit must hand back the same region"
    );
    assert!(
        reused.iter().all(|&b| b == 0),
        "the region must have been wiped on drop"
    );
}

#[test]
fn the_arena_refuses_rather_than_spilling() {
    let _guard = arena_lock();
    let mem = secmem();
    let free = mem.arena_free();

    let err = mem
        .alloc(free + 64)
        .expect_err("one granule past the arena must be refused");
    assert!(
        matches!(err, SecMemError::ArenaFull { requested } if requested == free + 64),
        "expected ArenaFull, got {err:?}"
    );

    let whole = mem.alloc(free).expect("an exact fit must still succeed");
    assert_eq!(whole.len(), free);
    assert_eq!(mem.arena_free(), 0);
    drop(whole);
    assert_eq!(mem.arena_free(), free);
}

#[test]
fn hash_slots_are_exclusive_and_bounded() {
    let _guard = hash_slot_lock();
    let mem = secmem();
    let first = mem.hash_slot();
    let second = mem.hash_slot();

    let (tx, rx) = mpsc::channel();
    let third = std::thread::spawn(move || {
        let slot = mem.hash_slot();
        let _ = tx.send(());
        drop(slot);
    });

    assert!(
        rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "a third hash slot must block while both are held"
    );

    drop(first);
    rx.recv_timeout(Duration::from_millis(200))
        .expect("the third waiter must proceed once a slot frees");

    drop(second);
    third.join().expect("the waiting thread must finish");
}

/// A slot carries argon2 state — the whole password or master passphrase is
/// recoverable from the first block of a half-finished pass — so dropping a
/// guard must leave nothing behind for the next lease.
///
/// This also pins the `handed` high-water mark: the guard hands out 1 MiB, then
/// a smaller 512 KiB view, and the wipe must still cover the full 1 MiB. If
/// `handed` were overwritten instead of maximised, the tail would survive.
#[test]
fn a_dropped_slot_is_wiped_before_the_next_lease() {
    const BIG_KIB: u32 = 1024;
    const SMALL_KIB: u32 = 512;
    const SENTINEL: u64 = 0xA5A5_A5A5_A5A5_A5A5;

    let _guard = hash_slot_lock();
    let mem = secmem();

    {
        let mut slot = mem.hash_slot();
        let blocks = slot.blocks(BIG_KIB).expect("1 MiB must fit a hash slot");
        assert_eq!(blocks.len(), BIG_KIB as usize);
        for block in blocks.iter_mut() {
            block.as_mut().fill(SENTINEL);
        }
        // A later, smaller view must not shrink what gets wiped.
        let smaller = slot.blocks(SMALL_KIB).expect("512 KiB must fit too");
        assert_eq!(smaller.len(), SMALL_KIB as usize);
    }

    // Check BOTH slots rather than assuming which index came back: whichever
    // one was just dirtied, it must now read zero.
    let mut first = mem.hash_slot();
    let mut second = mem.hash_slot();
    for (which, slot) in [&mut first, &mut second].into_iter().enumerate() {
        let blocks = slot.blocks(BIG_KIB).expect("1 MiB must fit a hash slot");
        let dirty = blocks
            .iter()
            .position(|block| block.as_ref().iter().any(|&word| word != 0));
        assert_eq!(
            dirty, None,
            "slot {which}: block {dirty:?} survived the wipe on drop"
        );
    }
}

#[test]
fn a_slot_refuses_an_oversized_cost() {
    let mem = secmem();
    let mut slot = mem.kdf_slot();

    let err = slot
        .blocks(262_145)
        .expect_err("one KiB past the KDF slot must be refused");
    assert!(
        matches!(err, SecMemError::SlotTooSmall),
        "expected SlotTooSmall, got {err:?}"
    );

    let blocks = slot.blocks(262_144).expect("the full slot must be usable");
    assert_eq!(blocks.len(), 262_144, "one argon2 block per m_cost KiB");
}

#[test]
fn init_is_idempotent() {
    let first = init(PRODUCTION_POOL).expect("first init");
    let second = init(PRODUCTION_POOL).expect("second init");
    assert!(
        std::ptr::eq(first, second),
        "init must return the one process pool"
    );
}

#[test]
fn global_initialises_the_production_pool_on_first_use() {
    let viaglobal = ws_secmem::global().expect("global must initialise on first use");
    let viainit = init(PRODUCTION_POOL).expect("init");
    assert!(std::ptr::eq(viaglobal, viainit));
}

#[test]
fn a_secret_buf_never_prints_its_contents() {
    let _guard = arena_lock();
    let mem = secmem();
    let buf = mem
        .alloc_copy(b"super-secret-passphrase")
        .expect("alloc_copy");
    assert_eq!(&*buf, b"super-secret-passphrase");
    assert_eq!(format!("{buf:?}"), "SecretBuf(23 bytes)");
}
