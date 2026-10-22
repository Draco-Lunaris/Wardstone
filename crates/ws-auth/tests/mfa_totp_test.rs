//! TOTP MFA tests: secret generation (32 base32 characters of 20 bytes), the
//! RFC 6238 code round trip with an INDEPENDENT HMAC-SHA1 computation (not the
//! totp-rs one — both agreeing pins the algorithm against the spec), wrong-code
//! rejection, malformed-secret errors, and the otpauth provisioning URI.

use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use ws_auth::error::AuthError;
use ws_auth::mfa_totp::{generate_secret, provisioning_uri, verify_code};

/// The RFC 4226/6238 code for the given secret at the given unix step.
///
/// Deliberately self-contained: HMAC-SHA1 over the 8-byte big-endian counter,
/// dynamic truncation, 10^6 modulus, zero-padded 6 digits.
fn rfc6238_code(secret_bytes: &[u8], step: u64) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret_bytes).unwrap();
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    format!("{:06}", binary % 1_000_000)
}

/// Current TOTP secret, as raw bytes via totp-rs' base32 codec.
fn secret_bytes(secret_base32: &str) -> Vec<u8> {
    totp_rs::Secret::Encoded(secret_base32.to_string())
        .to_bytes()
        .unwrap()
}

#[test]
fn generated_secret_is_32_base32_characters() {
    let secret = generate_secret().unwrap();
    assert_eq!(secret.len(), 32, "20 raw bytes encode to 32 base32 chars");
    assert!(
        secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() && !b.is_ascii_lowercase()),
        "base32 RFC 4648 alphabet is A-Z2-7, got: {secret}"
    );
}

#[test]
fn verify_accepts_a_spec_computed_code() {
    let secret = generate_secret().unwrap();
    let step = (Utc::now().timestamp() as u64) / 30;
    let code = rfc6238_code(&secret_bytes(&secret), step);
    assert_eq!(code.len(), 6);
    assert!(
        verify_code("alice", &secret, &code).unwrap(),
        "independent RFC 6238 code must verify"
    );
}

#[test]
fn verify_accepts_totp_rs_generated_code() {
    let secret = generate_secret().unwrap();
    // Same construction as the implementation (issuer differs — the issuer and
    // account name only shape the URI, never the code).
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes(&secret),
        Some("Wardstone".to_string()),
        "alice".to_string(),
    )
    .unwrap();
    let code = totp.generate_current().unwrap();
    assert!(verify_code("alice", &secret, &code).unwrap());
}

#[test]
fn verify_rejects_a_wrong_code() {
    let secret = generate_secret().unwrap();
    let step = (Utc::now().timestamp() as u64) / 30;
    let right = rfc6238_code(&secret_bytes(&secret), step);
    // Shift every digit one place around a 10-digit ring: never the right code.
    let wrong: String = right
        .bytes()
        .map(|b| b'0' + (b - b'0' + 1) % 10)
        .map(|b| b as char)
        .collect();
    assert_ne!(wrong, right);
    assert!(!verify_code("alice", &secret, &wrong).unwrap());
}

#[test]
fn verify_is_not_a_panic_on_garbage_input() {
    // Malformed base32 secret: an Err, never a panic, never a bool.
    let err = verify_code("alice", "not!valid!base32!", "123456").unwrap_err();
    assert!(matches!(err, AuthError::Crypto(_)));
    // Malformed code: totp-rs compares codes as strings, so a non-matching
    // one is simply rejected as Ok(false) — the house behavior. No panic.
    let secret = generate_secret().unwrap();
    assert!(!verify_code("alice", &secret, "12ab").unwrap());
}

#[test]
fn provisioning_uri_is_a_well_formed_totp_uri() {
    let secret = generate_secret().unwrap();
    let uri = provisioning_uri("Wardstone", "alice", &secret);
    assert!(uri.starts_with("otpauth://totp/"), "got: {uri}");
    assert!(uri.contains("Wardstone"), "issuer prefix missing: {uri}");
    assert!(uri.contains("alice"), "account name missing: {uri}");
    assert!(uri.contains(&secret), "secret parameter missing: {uri}");
}
