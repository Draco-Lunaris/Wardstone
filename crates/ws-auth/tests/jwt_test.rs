//! Ed25519 JWT issuing/validation tests: the access-token round trip, the
//! error taxonomy (`TokenInvalid` / `TokenExpired`), and the on-disk key pair
//! that `JwtKeys::load_or_create` generates on a virgin volume.

use std::fs;
use std::path::PathBuf;

use chrono::Utc;
use uuid::Uuid;
use ws_auth::error::AuthError;
use ws_auth::jwt::{issue_access_token, validate_access_token, AccessClaims, JwtKeys};

/// On-disk location of the JWT key pair (layout: `<dir>/jwt-{signing,verify}-key.pem`).
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
    let dir = temp_keys_dir("roundtrip");
    let keys = JwtKeys::load_or_create(&dir).unwrap();

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
    let dir_a = temp_keys_dir("wrong-key-a");
    let keys_a = JwtKeys::load_or_create(&dir_a).unwrap();
    let dir_b = temp_keys_dir("wrong-key-b");
    let keys_b = JwtKeys::load_or_create(&dir_b).unwrap();

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
    let dir = temp_keys_dir("expired");
    let keys = JwtKeys::load_or_create(&dir).unwrap();

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
    let dir = temp_keys_dir("tampered");
    let keys = JwtKeys::load_or_create(&dir).unwrap();

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

#[test]
fn load_or_create_on_a_missing_directory_generates_the_key_pair() {
    let dir = temp_keys_dir("generate");
    assert!(!dir.exists(), "the fixture must start from nothing");

    let keys = JwtKeys::load_or_create(&dir).unwrap();

    assert!(dir.exists(), "a virgin volume must gain the keys directory");
    assert!(dir.join(SIGNING_KEY_FILE).exists());
    assert!(dir.join(VERIFY_KEY_FILE).exists());
    assert!(!keys.signing_key.is_empty());
    assert!(!keys.verification_key_pem.trim().is_empty());
}

#[test]
fn a_second_load_returns_the_same_keys() {
    let dir = temp_keys_dir("stable");
    let first = JwtKeys::load_or_create(&dir).unwrap();
    let second = JwtKeys::load_or_create(&dir).unwrap();

    assert_eq!(&*first.signing_key, &*second.signing_key);
    assert_eq!(first.verification_key_pem, second.verification_key_pem);
}

#[cfg(unix)]
#[test]
fn generated_signing_key_file_is_mode_0600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_keys_dir("mode");
    let _keys = JwtKeys::load_or_create(&dir).unwrap();

    let mode = fs::metadata(dir.join(SIGNING_KEY_FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "the signing key holds private material and must be 0600"
    );
}

#[test]
fn a_token_signed_with_the_loaded_keys_validates() {
    let dir = temp_keys_dir("loaded");
    // First call generates; the second loads the same pair from disk.
    let first = JwtKeys::load_or_create(&dir).unwrap();
    let loaded = JwtKeys::load_or_create(&dir).unwrap();

    let claims = fresh_claims("carol", "admin", None, 900);
    let token = issue_access_token(&claims, &first).unwrap();
    let decoded = validate_access_token(&token, &loaded).unwrap();
    assert_eq!(decoded.username, "carol");
}

#[test]
fn a_mixed_key_pair_fails_the_load_loudly() {
    // Two real, independent pairs: the signing file from A, the
    // verification file from B — the exact shape a concurrent virgin-volume
    // boot race on a shared keys volume left on the deployed 2026-10-23
    // system (each file whole, the pair useless). The load must refuse it,
    // not silently sign tokens nothing can verify.
    let dir_a = temp_keys_dir("mixed-a");
    JwtKeys::load_or_create(&dir_a).unwrap();
    let dir_b = temp_keys_dir("mixed-b");
    JwtKeys::load_or_create(&dir_b).unwrap();

    // Task 5: the signing half is arena DER now, so the mixed pair is
    // planted from the plaintext FILES the legacy loader wrote — the
    // exact shape the deployed torn volume had.
    let dir = temp_keys_dir("mixed-pair");
    fs::create_dir_all(&dir).unwrap();
    fs::copy(dir_a.join(SIGNING_KEY_FILE), dir.join(SIGNING_KEY_FILE)).unwrap();
    fs::copy(dir_b.join(VERIFY_KEY_FILE), dir.join(VERIFY_KEY_FILE)).unwrap();

    let err = JwtKeys::load_or_create(&dir)
        .expect_err("a mixed key pair must be refused, not loaded as authentic");

    assert!(
        matches!(err, AuthError::Config(ref msg) if msg.contains("remove both")),
        "a mixed pair must fail as a configuration error carrying the \
         remove-both re-key hint, got {err:?}"
    );
}

#[cfg(unix)]
#[test]
fn racing_creators_serialize_into_one_consistent_pair() {
    // Eight takers released into load_or_create on one virgin directory —
    // the concurrent first boot of the ui and api processes on the shared
    // keys volume. Every taker must succeed, hold the SAME pair, and the
    // pair on disk must validate: the losers wait out the winner's complete
    // two-file write instead of colliding with it.
    use std::sync::{Arc, Barrier};

    const RACERS: usize = 8;
    let dir = temp_keys_dir("racing-creators");
    let barrier = Arc::new(Barrier::new(RACERS));

    let handles: Vec<_> = (0..RACERS)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let dir = dir.clone();
            std::thread::spawn(move || {
                barrier.wait();
                JwtKeys::load_or_create(&dir)
            })
        })
        .collect();
    let results: Vec<Result<JwtKeys, _>> = handles
        .into_iter()
        .map(|handle| handle.join().expect("a racing creator panicked"))
        .collect();

    for (i, result) in results.iter().enumerate() {
        assert!(result.is_ok(), "racing creator {i} failed: {result:?}");
    }
    let first = results
        .first()
        .expect("at least one racer")
        .as_ref()
        .unwrap();
    for (i, result) in results.iter().enumerate() {
        let keys = result.as_ref().unwrap();
        assert_eq!(
            &*keys.signing_key, &*first.signing_key,
            "racing creator {i} holds a different signing key than creator 0"
        );
        assert_eq!(
            keys.verification_key_pem, first.verification_key_pem,
            "racing creator {i} holds a different verification key than creator 0"
        );
    }

    // The disk pair the winners left behind must itself load cleanly —
    // a mixed two-file residue would fail the loader's own pair check.
    let disk = JwtKeys::load_or_create(&dir).unwrap();
    assert_eq!(&*disk.signing_key, &*first.signing_key);
    assert_eq!(disk.verification_key_pem, first.verification_key_pem);
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
    // F9 (the final review): the sealed loader must run the same pair
    // probe the plaintext loader runs (`assert_pair_usable` — the
    // sign-a-probe/verify roundtrip). An envelope whose halves came
    // from different pairs — a conversion that sealed a torn volume, or
    // any later corruption — must refuse at the LOAD with the re-key
    // hint, never boot with a key whose tokens fail their own
    // verification on first use.
    //
    // Task 5: the custody shape changed (the signing half is arena DER,
    // never a field a test can set), so the mixed envelope is built from
    // the legacy plaintext files' contents directly — the deployed
    // payload format — and sealed with the core envelope engine.
    let pair_a_dir = temp_keys_dir("jwt-sealed-mixed-a");
    JwtKeys::load_or_create(&pair_a_dir).unwrap();
    let pair_b_dir = temp_keys_dir("jwt-sealed-mixed-b");
    JwtKeys::load_or_create(&pair_b_dir).unwrap();
    let signing_a = fs::read_to_string(pair_a_dir.join(SIGNING_KEY_FILE)).unwrap();
    let verification_b = fs::read_to_string(pair_b_dir.join(VERIFY_KEY_FILE)).unwrap();

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
