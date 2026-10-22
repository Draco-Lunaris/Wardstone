//! Argon2id hashing for user-chosen passwords.
//!
//! The `users.credential_hash` column stores the PHC string this module
//! produces. Bearer-token material is *not* hashed here: token digests use
//! plain SHA-256 (Task 8), because argon2id's slowness is only a virtue for
//! human-chosen secrets.

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::AuthError;

/// The hashing profile: argon2id v0x13 with the crate's recommended
/// parameters (`Argon2::default()`), with the algorithm pinned explicitly so
/// a future upstream default cannot silently move Wardstone off Argon2id.
fn argon2id() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default())
}

/// Hash a plaintext password with Argon2id and a fresh random salt.
///
/// Returns the PHC string format hash suitable for storage.
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    // `hash_password` draws its salt from the OS entropy source, so two calls
    // for the same password land on different salts.
    let hash: PasswordHash = argon2id()
        .hash_password(password.as_bytes())
        .map_err(|e| AuthError::Crypto(format!("argon2id hashing failed: {e}")))?;
    Ok(hash.to_string())
}

/// Verify a plaintext password against a stored Argon2id PHC hash.
///
/// Returns `Ok(false)` — not an error — when the password is wrong; an error
/// means the stored hash itself is unusable.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, AuthError> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| AuthError::Crypto(format!("invalid password hash format: {e}")))?;

    // Verification reuses the parameters stored in the PHC string, so hashes
    // minted under older cost stays verifiable.
    match <Argon2 as PasswordVerifier<PasswordHash>>::verify_password(
        &argon2id(),
        password.as_bytes(),
        &parsed,
    ) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::PasswordInvalid) => Ok(false),
        Err(e) => Err(AuthError::Crypto(format!(
            "argon2id verification failed: {e}"
        ))),
    }
}
