//! Process-wide hardening and the pre-flight probe.
//!
//! These run before a single secret page is mapped, so a host that cannot hold
//! the guarantees refuses the boot instead of running degraded.

use std::io;

use crate::SecMemError;

/// Drops the core-dump budget to zero (soft and hard) and marks the process
/// undumpable.
///
/// Both are needed: `RLIMIT_CORE = 0` stops the kernel writing a core file,
/// and `PR_SET_DUMPABLE = 0` additionally stops a same-uid process from
/// `ptrace`-attaching and reading the unlocked secrets out of us. Lowering the
/// hard limit as well means nothing later in the process can raise it back.
pub(crate) fn harden_process() -> Result<(), SecMemError> {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `zero` is a live, correctly typed `rlimit` for the whole call.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } != 0 {
        return Err(SecMemError::CoreLimit(io::Error::last_os_error()));
    }

    // SAFETY: PR_SET_DUMPABLE takes one integer argument and no pointers.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(SecMemError::Dumpable(io::Error::last_os_error()));
    }

    Ok(())
}

/// Refuses early if the memlock budget cannot hold the pool.
///
/// This check has to come *before* the mapping: a `memfd_secret` mapping is
/// charged against `RLIMIT_MEMLOCK` by `mmap` itself, which fails with a bare
/// `EAGAIN` that tells an operator nothing. Checking the limit first turns
/// that into [`SecMemError::MemlockTooSmall`], which names the knob to set.
pub(crate) fn check_memlock_budget(need: usize) -> Result<(), SecMemError> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a live, correctly typed out-parameter.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } != 0 {
        return Err(SecMemError::MemlockTooSmall {
            have: 0,
            need: need as u64,
        });
    }

    let have: u64 = limit.rlim_cur;
    if have < need as u64 {
        return Err(SecMemError::MemlockTooSmall {
            have,
            need: need as u64,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_budget_the_host_cannot_meet_is_refused() {
        let err = check_memlock_budget(usize::MAX).expect_err("usize::MAX cannot be locked");
        assert!(matches!(err, SecMemError::MemlockTooSmall { .. }));
    }

    #[test]
    fn a_single_page_is_always_within_budget() {
        check_memlock_budget(4096).expect("one page must fit in any sane memlock budget");
    }
}
