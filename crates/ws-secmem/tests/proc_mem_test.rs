//! The arena's pages must not be readable through `/proc/self/mem`.
//!
//! This test owns its own test binary, and therefore its own process, for one
//! reason: `init` sets `PR_SET_DUMPABLE=0`, which hands `/proc/<pid>/*`
//! ownership to root, so a *later* `open("/proc/self/mem")` fails with EACCES
//! for an unprivileged process. The descriptor has to be opened before the
//! process is hardened, and only a single-test binary can guarantee that no
//! other test hardened the process first.
//!
//! The control read matters as much as the assertion: a same-thread-group
//! reader is always allowed through the ptrace check, so the heap sentinel
//! read MUST succeed through the very same descriptor. Without it this test
//! would pass for the wrong reason (e.g. a descriptor that reads nothing at
//! all).

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

use ws_secmem::{init, PRODUCTION_POOL};

/// `pread` of `/proc/self/mem` at `address`. Returns the raw return value and
/// the errno captured immediately afterwards.
fn pread_at(file: &File, out: &mut [u8], address: usize) -> (isize, Option<i32>) {
    // SAFETY: `out` is a live, writable buffer of `out.len()` bytes and `file`
    // owns the descriptor for the whole call.
    let rc = unsafe {
        libc::pread(
            file.as_raw_fd(),
            out.as_mut_ptr().cast::<libc::c_void>(),
            out.len(),
            address as libc::off_t,
        )
    };
    let errno = io::Error::last_os_error().raw_os_error();
    (rc, errno)
}

#[test]
fn arena_pages_are_hidden_from_proc_self_mem() {
    // Opened before `init` hardens the process — see the module comment.
    let mem_file = File::open("/proc/self/mem").expect("open /proc/self/mem");

    // Boxed so the control sentinel really is heap memory, like the
    // allocations the arena replaces.
    let heap_sentinel: Box<[u8; 32]> = Box::new([0x5Au8; 32]);

    let mem = init(PRODUCTION_POOL).expect("the protected pool must initialise on this host");
    let mut secret = mem.alloc(32).expect("32 bytes must fit in the arena");
    secret.copy_from_slice(&[0xA5u8; 32]);

    // Control: ordinary heap memory IS readable through this descriptor, so
    // the descriptor works and the ptrace check passes.
    let mut control = [0u8; 32];
    let (rc, errno) = pread_at(&mem_file, &mut control, heap_sentinel.as_ptr() as usize);
    assert_eq!(
        rc, 32,
        "control: the heap sentinel must be readable (errno {errno:?})"
    );
    assert_eq!(
        control, [0x5Au8; 32],
        "control: the heap sentinel must read back byte for byte"
    );

    // The arena is not.
    let mut stolen = [0u8; 32];
    let (rc, errno) = pread_at(&mem_file, &mut stolen, secret.as_ptr() as usize);
    assert!(
        rc < 0,
        "the arena sentinel must not be readable, but pread returned {rc}"
    );
    assert!(
        matches!(errno, Some(libc::EIO) | Some(libc::EACCES)),
        "expected EIO or EACCES from the arena read, got errno {errno:?}"
    );
    assert_eq!(stolen, [0u8; 32], "no arena byte may be copied out");

    // The secret is still intact in its own address space.
    assert_eq!(&*secret, &[0xA5u8; 32]);
}
