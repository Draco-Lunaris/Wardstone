//! Typed errors for the auth layer, shared by every later auth task.

use thiserror::Error;

/// The error vocabulary of the auth layer.
///
/// The HTTP mapping is the API layer's concern, not this crate's, but the
/// variants are shaped so it is mechanical: the credential-bearing variants
/// ([`BadCredentials`](AuthError::BadCredentials), `TokenInvalid`,
/// `TokenExpired`, `MfaRequired`, `MfaInvalid`, `AccountLocked`,
/// `AccountDisabled`) surface as 401-class responses, [`Forbidden`]
/// as 403 — **a missing capability is authorization, not authentication**,
/// which is why it is its own variant rather than a `BadCredentials` flavor —
/// and [`NotFound`](AuthError::NotFound) as 404.
#[derive(Debug, Error)]
pub enum AuthError {
    /// The presented username/password pair does not match (401).
    #[error("invalid credentials")]
    BadCredentials,
    /// The caller is authenticated but lacks the required capability (403).
    #[error("missing required capability")]
    Forbidden,
    /// The presented token did not verify against the verification key (401).
    #[error("token is invalid")]
    TokenInvalid,
    /// The presented token is well-signed but past expiry (401).
    #[error("token has expired")]
    TokenExpired,
    /// The account has MFA enrolled and must present a code (401).
    #[error("multi-factor authentication required")]
    MfaRequired,
    /// The presented MFA code is wrong or stale (401).
    #[error("invalid multi-factor code")]
    MfaInvalid,
    /// The account is under a lockout window (401 for the presentation layer).
    #[error("account is locked")]
    AccountLocked,
    /// The account is administratively disabled (401).
    #[error("account is disabled")]
    AccountDisabled,
    /// Too many attempts for the configured window (429).
    #[error("rate limit exceeded")]
    RateLimited,
    /// The requested resource does not exist (404).
    #[error("not found")]
    NotFound,
    /// A deployment/configuration problem: key material missing, unreadable,
    /// or an incomplete key pair on disk.
    #[error("configuration error: {0}")]
    Config(String),
    /// A cryptographic operation failed (hashing, key encoding, JWT signing).
    #[error("cryptographic error: {0}")]
    Crypto(String),
}
