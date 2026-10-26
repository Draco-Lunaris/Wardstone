//! The `wardstone db-verifier` subcommand's output contract (Task 4): a
//! pure local mint — no database, no keys volume, no WARDSTONE_* env —
//! that prints a fresh 52-char credential with its SCRAM verifier (or,
//! under `--password-stdin`, ONLY the verifier for the operator's own
//! password, which is never echoed). The verifier recomputed locally
//! from the printed password and the verifier's own salt must equal the
//! printed verifier — the same recomputation Postgres performs at
//! login.
//!
//! These tests run the built binary (`CARGO_BIN_EXE_wardstone`) with the
//! environment scrubbed: the mode needs NO configuration, and proving
//! that under `env_clear` pins it (a stray WARDSTONE_* env must never be
//! load-bearing here).

use std::io::Write as _;
use std::process::{Command, Stdio};

use base64::Engine as _;
use ws_core::dbcred::scram_verifier;

/// The subcommand's iterations pin.
const ITERATIONS: u32 = 4096;

/// Run the built `wardstone` binary with the given args, env scrubbed,
/// and return its combined exit status and stdout.
fn run(args: &[&str]) -> (std::process::ExitStatus, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wardstone"));
    for arg in args {
        command.arg(arg);
    }
    // The mint is pure-local: scrub the environment to prove no
    // WARDSTONE_* (and no DATABASE_URL) is load-bearing.
    command.env_clear();
    let output = command.output().expect("run the built wardstone binary");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (output.status, stdout, stderr)
}

/// The `password: ` and `verifier: ` lines of a run, parsed.
fn parse(stdout: &str) -> (Option<String>, Option<String>) {
    let mut password = None;
    let mut verifier = None;
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("password: ") {
            password = Some(rest.to_owned());
        }
        if let Some(rest) = line.strip_prefix("verifier: ") {
            verifier = Some(rest.to_owned());
        }
    }
    (password, verifier)
}

/// The 16-byte salt a printed verifier carries, decoded from its own
/// base64 field — the independent input the local recomputation needs.
fn salt_of(verifier: &str) -> [u8; 16] {
    let parts: Vec<&str> = verifier.split('$').collect();
    assert_eq!(parts[0], "SCRAM-SHA-256", "the scheme segment: {verifier}");
    let (iterations, salt_b64) = parts[1]
        .split_once(':')
        .expect("the iteration:salt segment");
    assert_eq!(iterations, "4096", "the iteration pin: {verifier}");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(salt_b64)
        .expect("the salt decodes as standard base64");
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&decoded);
    salt
}

/// Default mode: `password: <52 chars>` then `verifier: <SCRAM…>` then the
/// operator hint, and the verifier is EXACTLY the recomputation from the
/// printed password and the verifier's own salt.
#[test]
fn the_subcommand_prints_a_password_and_its_verifier() {
    let (status, stdout, stderr) = run(&["db-verifier"]);
    assert!(
        status.success(),
        "db-verifier succeeds with no env; stdout: {stdout} stderr: {stderr}"
    );
    let (password, verifier) = parse(&stdout);
    let password = password.expect("a `password: ` line is printed");
    let verifier = verifier.expect("a `verifier: ` line is printed");
    assert_eq!(password.len(), 52, "52 typeable characters: {password}");
    assert!(
        password
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)),
        "lowercase base32 only: {password}"
    );
    assert!(
        verifier.starts_with("SCRAM-SHA-256$4096:"),
        "the SCRAM shape: {verifier}"
    );
    assert!(stdout.contains(".env"), "the hint names the .env file");
    assert_ne!(
        password, verifier,
        "the credential and its verifier are different lines"
    );
    assert_eq!(
        scram_verifier(password.as_bytes(), &salt_of(&verifier), ITERATIONS),
        verifier,
        "the printed verifier is the recomputation of the printed password"
    );
}

/// `--password-stdin` (the ruling's shape): the operator's chosen
/// password is read from stdin (one line, trailing newline stripped) and
/// NEVER echoed — no `password:` line exists — while the verifier still
/// recomputes from the chosen password.
#[test]
fn the_password_stdin_mode_prints_only_the_verifier() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wardstone"));
    command
        .arg("db-verifier")
        .arg("--password-stdin")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn db-verifier --password-stdin");
    {
        let mut stdin = child.stdin.take().expect("the child reads stdin");
        stdin
            .write_all(b"the-chosen-password\n")
            .expect("write the chosen password");
    } // dropped: EOF reaches the child
    let output = child.wait_with_output().expect("the child exits");
    assert!(
        output.status.success(),
        "stdin mode succeeds; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        !stdout.contains("password: "),
        "the chosen password is never echoed: {stdout}"
    );
    let (_, verifier) = parse(&stdout);
    let verifier = verifier.expect("a `verifier: ` line is printed");
    assert!(stdout.contains(".env"), "the hint names the .env file");
    assert_eq!(
        scram_verifier(b"the-chosen-password", &salt_of(&verifier), ITERATIONS),
        verifier,
        "the verifier is the recomputation of the stdin-chosen password"
    );
}
