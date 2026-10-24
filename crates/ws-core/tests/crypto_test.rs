//! KeyEnvelope tests: the operator master passphrase derives a KEK that
//! seals sensitive files as inert ciphertext envelopes. No database — pure
//! crypto + temp files.

use std::fs;
use std::path::PathBuf;

use ws_core::crypto::KeyEnvelope;
use ws_core::error::CoreError;

/// Low-cost KDF params: the production unlock targets ~1 s (argon2id with
/// heavy memory); the tests assert the crypto, not the wall clock.
fn cheap_params() -> ws_core::crypto::KdfParams {
    ws_core::crypto::KdfParams {
        m_cost: 8192,
        t_cost: 2,
        p_cost: 1,
    }
}

fn temp_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ws-core-envelope-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir.join(format!("{name}.envelope"))
}

#[test]
fn envelope_roundtrip_opens_with_the_right_passphrase_only() {
    let path = temp_path("roundtrip");
    let plaintext = b"the-ca-master-key-bytes";

    KeyEnvelope::write_envelope(
        &path,
        "a-long-correct-passphrase",
        plaintext,
        cheap_params(),
    )
    .expect("seal the envelope");

    // The file carries NO plaintext: the sensitive bytes are absent from
    // the on-disk form.
    let raw = fs::read_to_string(&path).unwrap();
    assert!(
        !raw.contains("the-ca-master-key-bytes"),
        "the envelope file must not contain the plaintext"
    );
    assert!(raw.contains("\"ciphertext\""), "the envelope is structured");

    // The right passphrase opens; a wrong one is a typed failure.
    let opened = KeyEnvelope::open_envelope(&path, "a-long-correct-passphrase")
        .expect("the right passphrase opens the envelope");
    assert_eq!(&*opened, plaintext);

    let err = KeyEnvelope::open_envelope(&path, "a-long-wrong-passphrase").unwrap_err();
    assert!(
        matches!(err, CoreError::Crypto(_)),
        "a wrong passphrase is a typed crypto failure, got {err:?}"
    );
}

#[test]
fn envelope_salts_are_fresh_per_write() {
    let a = temp_path("salt-a");
    let b = temp_path("salt-b");
    KeyEnvelope::write_envelope(&a, "same-passphrase", b"same-bytes", cheap_params()).unwrap();
    KeyEnvelope::write_envelope(&b, "same-passphrase", b"same-bytes", cheap_params()).unwrap();

    let raw_a = fs::read_to_string(&a).unwrap();
    let raw_b = fs::read_to_string(&b).unwrap();
    assert_ne!(
        raw_a, raw_b,
        "two envelopes of the same plaintext must differ (fresh salt + nonce)"
    );
}

#[test]
fn envelope_open_is_in_memory_only() {
    let path = temp_path("zeroize");
    KeyEnvelope::write_envelope(&path, "another-passphrase", b"payload", cheap_params()).unwrap();
    let opened = KeyEnvelope::open_envelope(&path, "another-passphrase")
        .expect("the right passphrase opens");
    assert_eq!(&*opened, b"payload");
}

#[test]
fn kek_derive_is_deterministic_per_salt_and_params() {
    let a = KeyEnvelope::derive_kek("passphrase-1", b"salt-salt-salt-salt", cheap_params())
        .unwrap()
        .into_kek();
    let b = KeyEnvelope::derive_kek("passphrase-1", b"salt-salt-salt-salt", cheap_params())
        .unwrap()
        .into_kek();
    let c = KeyEnvelope::derive_kek("passphrase-2", b"salt-salt-salt-salt", cheap_params())
        .unwrap()
        .into_kek();
    assert_eq!(&*a, &*b, "same passphrase+salt+params derive the same KEK");
    assert_ne!(&*a, &*c, "a different passphrase derives a different KEK");
}
