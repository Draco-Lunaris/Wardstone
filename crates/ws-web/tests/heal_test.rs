//! The crashed-conversion heal (the final review's F3): the conversion
//! seals the volume file by file, and a crash mid-arm leaves per-file
//! windows — an envelope that landed while its plaintext original
//! never got deleted, or a plaintext that never got wrapped at all.
//! The sealed boot's unlock heals both windows
//! ([`ws_web::setup::heal_keys_volume`]): the envelope is authoritative
//! (its presence deletes the stray plaintext), an unwrapped plaintext
//! wraps at the master envelope's generation and deletes, and the JWT
//! pair heals as one unit — a torn pair seals as-is and the sealed
//! loader refuses it loudly (the re-key runbook), never a silent boot
//! with a key whose tokens fail their own verification.
//!
//! Filesystem-only: no database, no listener — the fast suite.

use std::path::PathBuf;

/// A scratch keys volume per test.
fn temp_volume(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ws-web-heal-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Cheap argon2id parameters for the hand-written anchor envelopes:
/// the heal never OPENS the master (its generation is a header read),
/// so the anchor's KDF cost is irrelevant to the behavior under test.
fn cheap_params() -> ws_core::crypto::KdfParams {
    ws_core::crypto::KdfParams {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

/// The sealed boot's precondition: a master envelope (the anchor) at
/// generation 0 under `passphrase`.
fn write_anchor(dir: &std::path::Path, passphrase: &str) {
    ws_core::crypto::KeyEnvelope::write_envelope(
        &dir.join(ws_core::crypto::MASTER_ENVELOPE_FILE),
        passphrase,
        b"the-anchor-payload",
        cheap_params(),
        0,
    )
    .expect("write the anchor envelope");
}

const PASSPHRASE: &str = "the-master-passphrase";

#[test]
fn the_heal_deletes_a_stray_plaintext_beside_its_envelope() {
    // The crash window AFTER a wrap: the envelope landed, the plaintext
    // delete never ran. The envelope is authoritative — the heal
    // deletes the stray plaintext, and the idempotence heal finds
    // nothing left to do.
    let dir = temp_volume("stray-plaintext");
    write_anchor(&dir, PASSPHRASE);
    std::fs::write(dir.join("master.key"), b"the-plaintext-leftover").unwrap();
    ws_core::crypto::KeyEnvelope::write_envelope(
        &dir.join(ws_core::crypto::SECRET_ENVELOPE_FILE),
        PASSPHRASE,
        b"the-sealed-secret",
        cheap_params(),
        0,
    )
    .expect("seal the secret envelope");
    std::fs::write(
        dir.join(ws_api::state::SECRET_KEY_FILE),
        b"the-secret-leftover",
    )
    .unwrap();

    ws_web::setup::heal_keys_volume(&dir, PASSPHRASE).expect("the heal converges the volume");

    assert!(
        !dir.join("master.key").exists(),
        "the stray master plaintext dies beside its authoritative envelope"
    );
    assert!(
        !dir.join(ws_api::state::SECRET_KEY_FILE).exists(),
        "the stray secret plaintext dies beside its authoritative envelope"
    );
    let secret = ws_core::crypto::KeyEnvelope::open_envelope(
        &dir.join(ws_core::crypto::SECRET_ENVELOPE_FILE),
        PASSPHRASE,
    )
    .expect("the untouched envelope still opens");
    assert_eq!(
        secret.as_slice(),
        b"the-sealed-secret",
        "the heal never rewrites an envelope that already landed"
    );

    // Idempotent: a clean volume heals as a no-op.
    ws_web::setup::heal_keys_volume(&dir, PASSPHRASE).expect("the second heal is a no-op");
    assert!(!dir.join("master.key").exists());
}

#[test]
fn the_heal_wraps_an_unwrapped_plaintext_at_the_masters_generation() {
    // The crash window BEFORE a wrap: the plaintext never sealed. The
    // heal wraps it at the anchor's generation under the passphrase and
    // deletes the original — the volume converges to fully sealed.
    let dir = temp_volume("unwrapped-plaintext");
    write_anchor(&dir, PASSPHRASE);
    std::fs::write(
        dir.join(ws_api::state::SECRET_KEY_FILE),
        b"the-secret-bytes",
    )
    .unwrap();

    ws_web::setup::heal_keys_volume(&dir, PASSPHRASE).expect("the heal wraps the straggler");

    let envelope = dir.join(ws_core::crypto::SECRET_ENVELOPE_FILE);
    assert!(envelope.exists(), "the straggler is sealed");
    assert!(
        !dir.join(ws_api::state::SECRET_KEY_FILE).exists(),
        "the plaintext original is deleted"
    );
    let secret =
        ws_core::crypto::KeyEnvelope::open_envelope(&envelope, PASSPHRASE).expect("it opens");
    assert_eq!(
        secret.as_slice(),
        b"the-secret-bytes",
        "the payload survives"
    );
    assert_eq!(
        ws_core::crypto::KeyEnvelope::read_generation(&envelope).unwrap(),
        0,
        "the heal seals at the master envelope's generation"
    );
}

#[test]
fn the_heal_seals_a_whole_jwt_pair_that_reloads() {
    // The crash window before the jwt arm, whole pair: both pems sit as
    // plaintext. The heal seals the pair as one envelope and deletes
    // both originals — and the sealed pair LOADS (the F9 probe passes).
    let mint_dir = temp_volume("jwt-pair-source");
    let minted = ws_auth::jwt::JwtKeys::load_or_create(&mint_dir).expect("mint a real pair");
    let dir = temp_volume("jwt-whole");
    write_anchor(&dir, PASSPHRASE);
    std::fs::copy(
        mint_dir.join("jwt-signing-key.pem"),
        dir.join("jwt-signing-key.pem"),
    )
    .unwrap();
    std::fs::write(dir.join("jwt-verify-key.pem"), &minted.verification_key_pem).unwrap();

    ws_web::setup::heal_keys_volume(&dir, PASSPHRASE).expect("the heal seals the pair");

    assert!(
        !dir.join("jwt-signing-key.pem").exists() && !dir.join("jwt-verify-key.pem").exists(),
        "both plaintext originals are deleted"
    );
    let loaded = ws_auth::jwt::load_sealed(
        &dir.join(ws_core::crypto::JWT_ENVELOPE_FILE),
        PASSPHRASE.as_bytes(),
    )
    .expect("the healed pair loads");
    assert_eq!(&*loaded.signing_key, &*minted.signing_key);
    assert_eq!(loaded.verification_key_pem, minted.verification_key_pem);
}

#[test]
fn the_heal_keeps_a_torn_jwt_pair_loud() {
    // The crash window before the jwt arm, TORN pair: one pem was
    // never written. Sealing never heals what the loader refuses (the
    // load_sealed pair probe, F9): the heal seals the torn pair as-is
    // — deleting the plaintext so the volume is inert — and the sealed
    // LOAD refuses loudly, pointing at the re-key runbook.
    let mint_dir = temp_volume("jwt-torn-source");
    // The mint's PRODUCT is the plaintext pair on disk; the binding goes
    // unused because the torn arm copies the signing file, not the value.
    let _minted = ws_auth::jwt::JwtKeys::load_or_create(&mint_dir).expect("mint a real pair");
    let dir = temp_volume("jwt-torn");
    write_anchor(&dir, PASSPHRASE);
    std::fs::copy(
        mint_dir.join("jwt-signing-key.pem"),
        dir.join("jwt-signing-key.pem"),
    )
    .unwrap();

    ws_web::setup::heal_keys_volume(&dir, PASSPHRASE).expect("the heal seals even the torn pair");

    assert!(
        !dir.join("jwt-signing-key.pem").exists(),
        "the torn plaintext is deleted: the volume is inert"
    );
    assert!(
        dir.join(ws_core::crypto::JWT_ENVELOPE_FILE).exists(),
        "the torn pair is sealed as-is"
    );
    let refused = ws_auth::jwt::load_sealed(
        &dir.join(ws_core::crypto::JWT_ENVELOPE_FILE),
        PASSPHRASE.as_bytes(),
    );
    assert!(
        refused.is_err(),
        "the torn pair stays loud at the load — the re-key runbook, never a silent boot"
    );
}

#[test]
fn the_heal_refuses_a_volume_without_the_anchor() {
    // No master envelope: this is not a sealed boot's volume, and the
    // INIT conversion door owns it — the heal refuses loudly rather
    // than sealing anything against a generation it cannot name.
    let dir = temp_volume("no-anchor");
    std::fs::write(dir.join("master.key"), b"the-plaintext").unwrap();

    let err = ws_web::setup::heal_keys_volume(&dir, PASSPHRASE)
        .expect_err("a volume without the anchor cannot be healed");
    assert!(
        err.to_string().to_lowercase().contains("master"),
        "the refusal names the anchor: {err}"
    );
    assert!(
        dir.join("master.key").exists(),
        "the refusal seals and deletes nothing"
    );
}
