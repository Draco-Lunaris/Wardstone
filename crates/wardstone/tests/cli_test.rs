//! The `wardstone` binary's own invocation contract: the mode argument
//! selects the process, anything else explains itself and exits non-zero.
//!
//! These tests run the built binary (`CARGO_BIN_EXE_wardstone`) with
//! `std::process::Command`: no configuration is required to reach the
//! usage paths, and the configuration-failure paths are driven with the
//! environment scrubbed — both fail before any database or keys-directory
//! access, so they are fast and DB-free.

use std::process::Command;

/// The built binary as an invocable command.
fn wardstone() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wardstone"))
}

/// The combined stdout+stderr of a finished run.
fn output_text(output: &std::process::Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

/// No argument: non-zero exit, and the usage names BOTH modes.
#[test]
fn no_argument_prints_usage_and_exits_non_zero() {
    let output = wardstone().output().expect("run the binary with no args");
    assert!(
        !output.status.success(),
        "no argument must exit non-zero, got {:?}",
        output.status.code()
    );
    let text = output_text(&output);
    assert!(
        text.contains("ui") && text.contains("api"),
        "the usage must name both modes, got: {text}"
    );
}

/// An unknown mode: the same contract as no argument.
#[test]
fn unknown_mode_prints_usage_and_exits_non_zero() {
    let output = wardstone()
        .arg("bogus")
        .output()
        .expect("run the binary with an unknown mode");
    assert!(
        !output.status.success(),
        "an unknown mode must exit non-zero, got {:?}",
        output.status.code()
    );
    let text = output_text(&output);
    assert!(
        text.contains("ui") && text.contains("api"),
        "the usage must name both modes, got: {text}"
    );
}

/// `--help`: zero exit, both modes named, on stdout.
#[test]
fn help_exits_zero_and_names_both_modes() {
    let output = wardstone()
        .arg("--help")
        .output()
        .expect("run the binary with --help");
    assert!(
        output.status.success(),
        "--help must exit zero, got {:?}",
        output.status.code()
    );
    let text = output_text(&output);
    assert!(
        text.contains("ui") && text.contains("api"),
        "--help must name both modes, got: {text}"
    );
}

/// `ui` without configuration: the environment contract is enforced
/// BEFORE any serving work, and every missing required name is listed.
#[test]
fn ui_without_required_environment_lists_the_missing_names() {
    let output = wardstone()
        .arg("ui")
        .env_remove("DATABASE_URL")
        .env_remove("WARDSTONE_KEYS_DIR")
        .output()
        .expect("run `wardstone ui` without configuration");
    assert!(
        !output.status.success(),
        "missing configuration must exit non-zero, got {:?}",
        output.status.code()
    );
    let text = output_text(&output);
    assert!(
        text.contains("DATABASE_URL") && text.contains("WARDSTONE_KEYS_DIR"),
        "the error must name every missing variable, got: {text}"
    );
}

/// `api` reads the same environment contract: the same failure shape.
#[test]
fn api_without_required_environment_lists_the_missing_names() {
    let output = wardstone()
        .arg("api")
        .env_remove("DATABASE_URL")
        .env_remove("WARDSTONE_KEYS_DIR")
        .output()
        .expect("run `wardstone api` without configuration");
    assert!(
        !output.status.success(),
        "missing configuration must exit non-zero, got {:?}",
        output.status.code()
    );
    let text = output_text(&output);
    assert!(
        text.contains("DATABASE_URL") && text.contains("WARDSTONE_KEYS_DIR"),
        "the error must name every missing variable, got: {text}"
    );
}

/// `api` with a password in its DATABASE_URL: refused at boot, before any
/// database or keys-directory access. The compose contract keeps the api's
/// URL password-less — its credential lives only in the sealed envelope —
/// so a password there is a misconfiguration, never a boot path (G5).
#[test]
fn api_refuses_a_password_bearing_database_url() {
    let keys = std::env::temp_dir().join(format!("ws-cli-api-pw-{}", std::process::id()));
    std::fs::create_dir_all(&keys).expect("create the scratch keys dir");
    let output = wardstone()
        .arg("api")
        .env(
            "DATABASE_URL",
            "postgres://wardstone:secret@127.0.0.1:1/wardstone",
        )
        .env("WARDSTONE_KEYS_DIR", &keys)
        .env("WARDSTONE_BIND", "127.0.0.1:0")
        .output()
        .expect("run `wardstone api` with a password-bearing URL");
    let _ = std::fs::remove_dir_all(&keys);
    assert!(
        !output.status.success(),
        "a password-bearing api URL must exit non-zero, got {:?}",
        output.status.code()
    );
    let text = output_text(&output);
    assert!(
        text.contains("password-less"),
        "the refusal must name the password-less contract, got: {text}"
    );
}
