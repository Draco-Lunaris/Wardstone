//! Fail-closed refusals, proved against the real `secmem-probe` binary in a
//! child process: a restriction that makes a protection impossible must abort
//! the boot and name the protection, not downgrade it silently.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Command, Output};

fn probe() -> Command {
    Command::new(env!("CARGO_BIN_EXE_secmem-probe"))
}

fn run(command: &mut Command) -> Output {
    command.output().expect("the probe binary must spawn")
}

#[test]
fn a_small_memlock_limit_is_refused_by_name() {
    let mut command = probe();
    // SAFETY: the closure runs between fork and exec and calls only
    // `setrlimit`, which is async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 8 * 1024 * 1024,
                rlim_max: 8 * 1024 * 1024,
            };
            if libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let output = run(&mut command);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "an 8 MiB memlock limit must refuse the boot (stderr: {stderr})"
    );
    assert!(
        stderr.contains("memlock limit"),
        "the refusal must name the memlock limit: {stderr}"
    );
    assert!(
        stderr.contains("536870912"),
        "the refusal must name the required budget: {stderr}"
    );
}

/// `AUDIT_ARCH_X86_64`, which libc does not export.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// Classic-BPF opcodes used by the filter below.
#[cfg(target_arch = "x86_64")]
mod bpf {
    /// `BPF_LD | BPF_W | BPF_ABS`
    pub const LD_W_ABS: u16 = 0x20;
    /// `BPF_JMP | BPF_JEQ | BPF_K`
    pub const JEQ_K: u16 = 0x15;
    /// `BPF_RET | BPF_K`
    pub const RET_K: u16 = 0x06;
    /// `offsetof(struct seccomp_data, nr)`
    pub const OFF_NR: u32 = 0;
    /// `offsetof(struct seccomp_data, arch)`
    pub const OFF_ARCH: u32 = 4;
}

#[cfg(target_arch = "x86_64")]
fn filter_statement(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[cfg(target_arch = "x86_64")]
fn filter_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn a_blocked_memfd_secret_is_refused_by_name() {
    let mut command = probe();
    // SAFETY: the closure runs between fork and exec and calls only `prctl`,
    // which is async-signal-safe. The filter program lives on this stack
    // frame, and `PR_SET_SECCOMP` copies it into the kernel before returning.
    unsafe {
        command.pre_exec(|| {
            // nr 447 (memfd_secret) -> ENOSYS; everything else -> allow.
            let program = [
                filter_statement(bpf::LD_W_ABS, bpf::OFF_ARCH),
                filter_jump(bpf::JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
                filter_statement(bpf::RET_K, libc::SECCOMP_RET_ALLOW),
                filter_statement(bpf::LD_W_ABS, bpf::OFF_NR),
                filter_jump(bpf::JEQ_K, 447, 0, 1),
                filter_statement(
                    bpf::RET_K,
                    libc::SECCOMP_RET_ERRNO | (libc::ENOSYS as u32 & 0x0000_ffff),
                ),
                filter_statement(bpf::RET_K, libc::SECCOMP_RET_ALLOW),
            ];
            let prog = libc::sock_fprog {
                len: program.len() as u16,
                filter: program.as_ptr().cast_mut(),
            };

            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &prog as *const libc::sock_fprog,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let output = run(&mut command);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a blocked memfd_secret must refuse the boot (stderr: {stderr})"
    );
    assert!(
        stderr.contains("memfd_secret is unavailable"),
        "the refusal must name memfd_secret: {stderr}"
    );
    assert!(
        stderr.contains("syscall 447"),
        "the refusal must name the blocked syscall: {stderr}"
    );
}

#[test]
fn a_full_protection_set_boots() {
    let output = run(&mut probe());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "an unrestricted probe must boot (stderr: {stderr})"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "protections ok"
    );
}
