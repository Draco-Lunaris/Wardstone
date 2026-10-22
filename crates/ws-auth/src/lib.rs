//! ws-auth: the authentication primitives behind Wardstone's REST surface.
//!
//! - `password` — argon2id hashing and verification for user-chosen passwords
//!   (the `users.credential_hash` column stores the PHC strings it produces).
//! - `jwt` — Ed25519 (EdDSA) access-token issuing and validation, plus the
//!   on-disk signing/verification key pair that `JwtKeys::load_or_create`
//!   generates on a virgin volume.
//! - `mfa_totp` — TOTP MFA (RFC 6238 profile): secret generation, code
//!   verification, and otpauth:// enrollment URIs.
//! - `oidc` — generic OIDC SSO: discovery, authorization-code exchange, and
//!   ID-token signature verification against the provider JWKS.
//! - `service_identity` — service identities and the API tokens they mint,
//!   for scripted automation: a stored SHA-256 verifier, the plaintext
//!   returned once, and the resolved `Actor`.
//! - `refresh` — session refresh tokens (the house's opaque-token flow):
//!   issue, authenticate, rotate, revoke.
//! - `error` — the shared `AuthError` vocabulary (401/403/404 mapping).
//!
//! The shared access vocabulary (capabilities, roles, actor types, the
//! one actor type) is defined in `ws-core` — the schema owner, so that the
//! crate graph stays acyclic (`ws-core` must never depend on `ws-auth`) —
//! and re-exported from here as ws-auth's single import surface.

pub mod error;
pub mod jwt;
pub mod mfa_totp;
pub mod oidc;
pub mod password;
pub mod refresh;
pub mod service_identity;

use ws_core::error::CoreError;
pub use ws_core::models::rbac::{
    role_capabilities, Actor, ActorType, AuthMethod, Capability, Role,
};

use crate::error::AuthError;

/// Minting and verifier-hash plumbing shared by ws-auth's opaque bearer
/// tokens (API tokens and refresh tokens): every token is 32 OS-random
/// bytes, presented to the client exactly once as `{prefix}{hex}` — the
/// house's hex encoding (`pm-auth/src/refresh.rs:38-48`) — while storage
/// holds only `hex(Sha256(raw))` (the house's refresh-token verifier,
/// `pm-auth/src/refresh.rs:46`), NOT argon2id: the digest is fast because
/// these 256-bit random tokens are never attacker-chosen guesses, and the
/// raw value and its hex form never reach disk.
pub(crate) mod opaque_token {
    use rand::{rngs::SysRng, TryRng};
    use sha2::{Digest, Sha256};
    use zeroize::Zeroize;

    use crate::error::AuthError;

    /// Length of the raw token bytes: 256 bits, the house's token size.
    const TOKEN_BYTES: usize = 32;

    /// Mint a fresh token: returns the `(plaintext, token_hash)` pair — the
    /// client-presented `{prefix}{hex}`, and the `hex(Sha256(raw))` to
    /// store. The raw bytes are zero-wiped before returning; only their
    /// digest survives the call.
    pub(super) fn mint(prefix: &str) -> Result<(String, String), AuthError> {
        let mut raw = [0u8; TOKEN_BYTES];
        SysRng.try_fill_bytes(&mut raw).map_err(|e| {
            AuthError::Crypto(format!(
                "OS entropy source failed while minting a token: {e}"
            ))
        })?;
        let plaintext = format!("{prefix}{}", hex::encode(raw));
        let token_hash = hex::encode(Sha256::digest(raw));
        raw.zeroize();
        Ok((plaintext, token_hash))
    }

    /// The verifier hash a presented plaintext resolves to: `None` when the
    /// plaintext does not carry `prefix` followed by the hex form of
    /// exactly [`TOKEN_BYTES`] bytes — a malformed or foreign-prefixed
    /// bearer is simply unknown (an unauthenticated credential), not an
    /// error. The re-decoded raw bytes are zero-wiped after hashing.
    pub(super) fn parse(prefix: &str, plaintext: &str) -> Option<String> {
        let body = plaintext.strip_prefix(prefix)?;
        let raw = hex::decode(body).ok()?;
        if raw.len() != TOKEN_BYTES {
            return None;
        }
        let token_hash = hex::encode(Sha256::digest(&raw));
        let mut raw = raw;
        raw.zeroize();
        Some(token_hash)
    }
}

/// Map a `ws-core` storage error onto the auth vocabulary.
///
/// `AuthError` deliberately has no database variant: the API layer's error
/// table (`From<AuthError> for ApiError`, Task 10) is exhaustive over the
/// twelve variants, and a storage failure is the internal-error class. It
/// lands in [`AuthError::Config`] — that table's 500 bucket — with the
/// underlying message carried for the operator log (static sqlx and
/// `CoreError` displays carry no credential material).
pub(crate) fn from_core_error(err: CoreError) -> AuthError {
    match err {
        CoreError::Forbidden => AuthError::Forbidden,
        CoreError::Crypto(message) => AuthError::Crypto(message),
        CoreError::Config(message) => AuthError::Config(message),
        other => AuthError::Config(format!("auth storage failure: {other}")),
    }
}
