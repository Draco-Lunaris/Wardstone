//! The secret-encryption helper: seal/open round-trip, tamper detection,
//! key-file creation/loading, and the key file's mode (Plan 2 Task 2).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use ws_core::crypto::SecretBox;
use ws_core::error::CoreError;

/// Per-test temp dir under `std::env::temp_dir()`, unique per test name and
/// process id, with any previous run's leftovers swept away first.
fn temp_dir(test_name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("ws-core-crypto-{test_name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("temp dir create");
    dir
}

#[test]
fn seal_then_open_round_trips() {
    let dir = temp_dir("roundtrip");
    let key_path = dir.join("secret-encryption.key");
    let secrets = SecretBox::create(&key_path).expect("create");

    let (ciphertext, nonce) = secrets.seal(b"totp secret").expect("seal");
    let plaintext = secrets.open(&ciphertext, &nonce).expect("open");
    assert_eq!(plaintext.as_slice(), b"totp secret");
}

#[test]
fn tampered_ciphertext_is_a_typed_error() {
    let dir = temp_dir("tamper");
    let key_path = dir.join("secret-encryption.key");
    let secrets = SecretBox::create(&key_path).expect("create");

    let (mut ciphertext, nonce) = secrets.seal(b"sensitive").expect("seal");
    ciphertext[0] ^= 0xff;
    match secrets.open(&ciphertext, &nonce) {
        Err(err) => assert!(matches!(err, CoreError::Crypto(_)), "got {err:?}"),
        Ok(plaintext) => panic!("tampered ciphertext decrypted to {plaintext:?}"),
    }

    // A ciphertext under the wrong key has the same failure: a fresh
    // key file decrypts nothing sealed by the original.
    let other_path = dir.join("other.key");
    let other = SecretBox::create(&other_path).expect("create other");
    let (ciphertext, nonce) = secrets.seal(b"sensitive").expect("seal");
    assert!(matches!(
        other.open(&ciphertext, &nonce),
        Err(CoreError::Crypto(_))
    ));
}

#[test]
fn create_then_load_round_trips_through_the_same_key() {
    let dir = temp_dir("create_load");
    let key_path = dir.join("secret-encryption.key");

    let created = SecretBox::create(&key_path).expect("create");
    let loaded = SecretBox::load(&key_path).expect("load");

    // Whatever `create` sealed, `load` must be able to open: the two
    // instances carry the very same key file's bytes.
    let (ciphertext, nonce) = created.seal(b"shared key").expect("seal");
    let plaintext = loaded.open(&ciphertext, &nonce).expect("open");
    assert_eq!(plaintext.as_slice(), b"shared key");
}

#[test]
fn create_on_an_existing_key_file_reuses_it() {
    let dir = temp_dir("reuse");
    let key_path = dir.join("secret-encryption.key");

    let first = SecretBox::create(&key_path).expect("create");
    let again = SecretBox::create(&key_path).expect("create again");

    // A second `create` must not mint a different key over the existing
    // file: data sealed before the call stays decryptable.
    let (ciphertext, nonce) = first.seal(b"before the second create").expect("seal");
    let plaintext = again.open(&ciphertext, &nonce).expect("open");
    assert_eq!(plaintext.as_slice(), b"before the second create");
}

#[test]
fn key_file_mode_is_0600() {
    let dir = temp_dir("mode");
    let key_path = dir.join("secret-encryption.key");
    SecretBox::create(&key_path).expect("create");

    let mode = fs::metadata(&key_path)
        .expect("key file exists")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "key file must be owner-only");
}

#[test]
fn load_rejects_a_short_key_file() {
    let dir = temp_dir("short");
    let key_path = dir.join("secret-encryption.key");
    fs::write(&key_path, [0u8; 16]).expect("write short key");

    match SecretBox::load(&key_path) {
        Err(err) => assert!(
            matches!(err, CoreError::Config(_)),
            "short key file must be a config error, got {err:?}"
        ),
        Ok(_) => panic!("a 16-byte key file must not load"),
    }
}
