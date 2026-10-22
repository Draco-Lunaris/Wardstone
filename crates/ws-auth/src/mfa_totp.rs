//! TOTP (time-based one-time password) MFA: HMAC-SHA1, 6 digits, 30-second
//! step, ±1 step skew — the RFC 6238 profile the house pins
//! (`linux-patch-manager/crates/pm-auth/src/mfa_totp.rs`), compatible with
//! Google Authenticator, Authy, and standard TOTP apps.
//!
//! Storage contract: the base32 secret is encrypted at rest by the CALLER
//! with the shared secret-encryption helper (`ws-core::crypto::SecretBox`'s
//! two-column pattern — encrypted bytes + nonce, the house
//! `pm-auth/src/session.rs` shape). These functions take and return
//! plaintext.

use totp_rs::{Algorithm, Secret, TOTP};

use crate::error::AuthError;

/// The RFC 6238 profile used everywhere: HMAC-SHA1 (the spec's mandatory
/// algorithm), 6 digits, 30-second step, ±1 step clock skew.
const TOTP_DIGITS: usize = 6;
const TOTP_SKEW: u8 = 1;
const TOTP_STEP: u64 = 30;

/// Generate a fresh TOTP secret, as 32 base32 characters encoding 20 raw
/// bytes — the RFC 6238 floor above the 128-bit minimum.
///
/// The caller encrypts the returned string before storing it.
pub fn generate_secret() -> Result<String, AuthError> {
    let secret = Secret::generate_secret();
    Ok(secret.to_encoded().to_string())
}

/// Verify a presented TOTP code against the user's plaintext secret.
///
/// The `username` is load-bearing, exactly as in the house
/// (`pm-auth/src/mfa_totp.rs:52`): it is the TOTP instance's account name, so
/// the enrollment URI (`otpauth://totp/Issuer:username`) and the verification
/// instance are bound to the individual account — a secret is never silently
/// re-provisioned under another user's URI.
///
/// Returns `Ok(false)` for a well-formed or malformed code of the wrong
/// digits (totp-rs compares codes as strings) and `Err(AuthError::MfaInvalid)`
/// only for an unverifiable attempt — a system-time failure. An error, never
/// a bool the caller might ignore for infrastructure reasons.
pub fn verify_code(username: &str, secret_base32: &str, code: &str) -> Result<bool, AuthError> {
    // The issuer shapes only the enrollment URI, never the code, so
    // verification needs none — and the login path must not depend on the
    // enrollment-time issuer being in reach.
    let totp = build_totp(None, username, secret_base32)?;
    totp.check_current(code).map_err(|_| AuthError::MfaInvalid)
}

/// Build the otpauth:// enrollment URI shown as a QR / manual-entry string.
///
/// Falls back to the raw, unescaped URI components if the secret cannot be
/// decoded (corrupt or hand-minted storage); a fresh secret from
/// [`generate_secret`] always produces the canonical escaped form.
pub fn provisioning_uri(issuer: &str, username: &str, secret_base32: &str) -> String {
    match build_totp(Some(issuer), username, secret_base32) {
        Ok(totp) => totp.get_url(),
        Err(_) => {
            format!("otpauth://totp/{issuer}:{username}?secret={secret_base32}&issuer={issuer}")
        }
    }
}

/// Build the profile-pinned TOTP instance. `account_name` is the username and
/// `issuer` the enrollment issuer — the house's `build_totp` passes both
/// straight into totp-rs' `TOTP::new`; the issuer here is `Some` only where
/// the URI matters.
fn build_totp(
    issuer: Option<&str>,
    account_name: &str,
    secret_base32: &str,
) -> Result<TOTP, AuthError> {
    let secret = Secret::Encoded(secret_base32.to_string());
    let secret_bytes = secret
        .to_bytes()
        .map_err(|_| AuthError::Crypto("invalid TOTP secret encoding".to_string()))?;
    TOTP::new(
        Algorithm::SHA1,
        TOTP_DIGITS,
        TOTP_SKEW,
        TOTP_STEP,
        secret_bytes,
        issuer.map(str::to_string),
        account_name.to_string(),
    )
    .map_err(|e| AuthError::Crypto(format!("TOTP construction failed: {e}")))
}
