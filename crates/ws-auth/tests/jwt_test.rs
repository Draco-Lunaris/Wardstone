//! Ed25519 JWT issuing/validation tests: the access-token round trip, the
//! error taxonomy (`TokenInvalid` / `TokenExpired`), the sealed key pair
//! lifecycle (mint into the protected arena, seal, reload), and the pair
//! probe's mixed-pair refusal.

use std::fs;
use std::path::PathBuf;

use chrono::Utc;
use uuid::Uuid;
use ws_auth::error::AuthError;
use ws_auth::jwt::{issue_access_token, validate_access_token, AccessClaims, JwtKeys};

/// The legacy plaintext pair's file names. Nothing writes them anymore;
/// the sealed-boot tests assert their ABSENCE from a fresh volume (the
/// pair's only on-disk form is the envelope).
const SIGNING_KEY_FILE: &str = "jwt-signing-key.pem";
const VERIFY_KEY_FILE: &str = "jwt-verify-key.pem";

fn temp_keys_dir(test_name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ws-auth-jwt-{test_name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// Mint claims for now + `ttl_secs`, with a fresh jti and the given session id.
fn fresh_claims(username: &str, role: &str, sid: Option<Uuid>, ttl_secs: i64) -> AccessClaims {
    AccessClaims::new(Uuid::new_v4(), username, role, sid, ttl_secs)
}

#[test]
fn access_token_validates_and_carries_its_claims() {
    let keys = JwtKeys::generate(900).unwrap();

    let sid = Uuid::new_v4();
    let claims = fresh_claims("carol", "issuer", Some(sid), 900);
    let token = issue_access_token(&claims, &keys).unwrap();
    let decoded = validate_access_token(&token, &keys).unwrap();

    assert_eq!(decoded.user_id, claims.user_id);
    assert_eq!(decoded.username, "carol");
    assert_eq!(decoded.role, "issuer");
    assert_eq!(decoded.sid, Some(sid));
    assert_eq!(decoded.jti, claims.jti);
    assert_eq!(decoded.exp, claims.exp);
    assert_eq!(decoded.iat, claims.iat);
}

#[test]
fn token_signed_with_a_different_key_is_token_invalid() {
    let keys_a = JwtKeys::generate(900).unwrap();
    let keys_b = JwtKeys::generate(900).unwrap();

    let claims = fresh_claims("carol", "admin", None, 900);
    let token = issue_access_token(&claims, &keys_a).unwrap();

    let err = validate_access_token(&token, &keys_b).unwrap_err();
    assert!(
        matches!(err, AuthError::TokenInvalid),
        "a foreign-key token must map to TokenInvalid, got {err:?}"
    );
}

#[test]
fn expired_token_is_token_expired() {
    let keys = JwtKeys::generate(900).unwrap();

    let mut claims = fresh_claims("carol", "admin", None, 900);
    claims.exp = Utc::now().timestamp() - 3600;

    let token = issue_access_token(&claims, &keys).unwrap();
    let err = validate_access_token(&token, &keys).unwrap_err();
    assert!(
        matches!(err, AuthError::TokenExpired),
        "an expired token must map to TokenExpired, got {err:?}"
    );
}

#[test]
fn tampered_payload_is_token_invalid() {
    let keys = JwtKeys::generate(900).unwrap();

    let claims = fresh_claims("carol", "admin", None, 900);
    let token = issue_access_token(&claims, &keys).unwrap();

    // Flip the payload segment to a different claim set; the header and the
    // signature stay intact, so validation must fail on the signature.
    let other = issue_access_token(&fresh_claims("mallory", "viewer", None, 900), &keys).unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    let other_parts: Vec<&str> = other.split('.').collect();
    let tampered = format!("{}.{}.{}", parts[0], other_parts[1], parts[2]);

    let err = validate_access_token(&tampered, &keys).unwrap_err();
    assert!(
        matches!(err, AuthError::TokenInvalid),
        "a tampered payload must map to TokenInvalid, got {err:?}"
    );
}

/// The fresh-install arm of the sealed boot: with no envelope on the
/// volume (a password-less fresh install has no plaintext pair either —
/// nothing ever minted one), the load-or-create SEALED form mints the
/// pair in RAM, seals it as the envelope, and never writes plaintext.
/// The second call loads the very same pair back.
#[test]
fn load_or_create_sealed_mints_seals_and_reloads_a_fresh_pair() {
    let dir = temp_keys_dir("jwt-sealed-fresh");
    let envelope = dir.join("jwt-keys.envelope");

    let minted =
        ws_auth::jwt::load_or_create_sealed(&envelope, b"the-master-passphrase", 0).unwrap();
    assert!(
        !dir.join("jwt-signing-key.pem").exists() && !dir.join("jwt-verify-key.pem").exists(),
        "a fresh sealed install never writes the pair as plaintext"
    );
    assert!(envelope.exists(), "the fresh pair is sealed on disk");

    let reloaded =
        ws_auth::jwt::load_or_create_sealed(&envelope, b"the-master-passphrase", 0).unwrap();
    assert_eq!(
        &*reloaded.signing_key, &*minted.signing_key,
        "the second load returns the minted pair, not a fresh one"
    );
    assert_eq!(
        reloaded.verification_key_pem, minted.verification_key_pem,
        "the second load returns the minted pair, not a fresh one"
    );

    let refused = ws_auth::jwt::load_or_create_sealed(&envelope, b"wrong", 0);
    assert!(
        refused.is_err(),
        "a wrong passphrase must not mint over or open the existing envelope"
    );
}

#[test]
fn a_mixed_sealed_pair_fails_the_load_loudly() {
    // F9 (the final review): the sealed loader must run the pair probe
    // (assert_pair_usable — the sign-a-probe/verify roundtrip). An
    // envelope whose halves came from different pairs — any corruption —
    // must refuse at the LOAD with the re-key hint, never boot with a
    // key whose tokens fail their own verification on first use.
    //
    // The custody shape (the signing half is arena DER, never a field a
    // test can set) means the mixed envelope is minted from two
    // independent generated pairs: the signing PEM derived in-test from
    // the first pair's arena DER, the verification PEM taken from the
    // second — the deployed payload format, sealed with the core
    // envelope engine.
    let pair_a = ws_auth::jwt::JwtKeys::generate(900).expect("mint the first pair");
    let pair_b = ws_auth::jwt::JwtKeys::generate(900).expect("mint the second pair");
    let signing_a = {
        use ed25519_dalek::pkcs8::{DecodePrivateKey as _, KeypairBytes};
        use pkcs8::{EncodePrivateKey as _, LineEnding};
        KeypairBytes::from_pkcs8_der(&pair_a.signing_key)
            .expect("the minted signing half parses")
            .to_pkcs8_pem(LineEnding::LF)
            .expect("the signing half's PEM encodes")
            .to_string()
    };
    let verification_b = pair_b.verification_key_pem.clone();

    let mixed = serde_json::json!({
        "signing": signing_a,
        "verification": verification_b,
    })
    .to_string();
    let dir = temp_keys_dir("jwt-sealed-mixed-pair");
    fs::create_dir_all(&dir).unwrap();
    let envelope = dir.join("jwt-keys.envelope");
    ws_core::crypto::KeyEnvelope::write_envelope(
        &envelope,
        "the-master-passphrase",
        mixed.as_bytes(),
        ws_core::crypto::PROD_KDF_PARAMS,
        0,
    )
    .unwrap();

    let err = ws_auth::jwt::load_sealed(&envelope, b"the-master-passphrase")
        .expect_err("the mixed sealed pair must refuse the load");
    assert!(
        err.to_string().contains("mixed or invalid"),
        "the refusal names the pair probe, not a downstream token failure: {err}"
    );
}

/// Task 5 (the seal-at-creation plan): the sealed pair round trip —
/// `generate` mints the pair with its signing key in the protected
/// arena (no plaintext file is ever written), `write_sealed` seals it,
/// and `load_sealed` hands back a pair that still mints tokens its own
/// verification half accepts.
#[test]
fn a_sealed_pair_round_trips_and_mints() {
    let dir = temp_keys_dir("sealed-round-trip");
    fs::create_dir_all(&dir).unwrap();
    let envelope = dir.join("jwt-keys.envelope");

    let minted = ws_auth::jwt::JwtKeys::generate(900).expect("generate the pair into the arena");
    assert!(
        !dir.join(SIGNING_KEY_FILE).exists() && !dir.join(VERIFY_KEY_FILE).exists(),
        "generating for the sealed form never writes the pair as plaintext"
    );
    ws_auth::jwt::write_sealed(&envelope, b"the-master-passphrase", &minted, 0)
        .expect("seal the minted pair");

    let loaded = ws_auth::jwt::load_sealed(&envelope, b"the-master-passphrase")
        .expect("the sealed pair loads");
    assert_eq!(
        loaded.verification_key_pem, minted.verification_key_pem,
        "the public half survives the round trip unchanged"
    );

    let sid = Uuid::new_v4();
    let claims = fresh_claims("carol", "admin", Some(sid), 900);
    let token = issue_access_token(&claims, &loaded).expect("the loaded pair mints");
    let decoded = validate_access_token(&token, &loaded)
        .expect("the token validates against the loaded pair");
    assert_eq!(decoded.user_id, claims.user_id);
    assert_eq!(decoded.sid, Some(sid));
}

/// Task 5: the Debug rendering of JwtKeys carries no key material — no
/// PEM framing, no PEM body of the public half, and none of the DER the
/// signing half holds in the protected arena.
#[test]
fn jwt_keys_debug_shows_no_key_material() {
    let keys = ws_auth::jwt::JwtKeys::generate(900).expect("generate the pair");

    let rendered = format!("{keys:?}");
    assert!(
        !rendered.contains("-----BEGIN") && !rendered.contains("-----END"),
        "the Debug rendering carries no PEM framing: {rendered}"
    );
    assert!(
        !keys.verification_key_pem.is_empty() && !rendered.contains(&keys.verification_key_pem),
        "the Debug rendering omits the public half's PEM text"
    );
    assert!(
        !rendered.contains("PRIVATE KEY") && !rendered.contains("PUBLIC KEY"),
        "the Debug rendering names no key kind: {rendered}"
    );
}
