//! ws-auth: the authentication primitives behind Wardstone's REST surface.
//!
//! - `password` — argon2id hashing and verification for user-chosen passwords
//!   (the `users.credential_hash` column stores the PHC strings it produces).
//! - `jwt` — Ed25519 (EdDSA) access-token issuing and validation, plus the
//!   on-disk signing/verification key pair that `JwtKeys::load_or_create`
//!   generates on a virgin volume.
//! - `error` — the shared `AuthError` vocabulary (401/403/404 mapping).
//!
//! Task 2 adds the `ws-core` dependency and re-exports the shared access
//! vocabulary through `ws-auth`.

pub mod error;
pub mod jwt;
pub mod password;
