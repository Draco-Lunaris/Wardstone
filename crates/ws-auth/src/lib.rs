//! ws-auth: the authentication primitives behind Wardstone's REST surface.
//!
//! - `password` — argon2id hashing and verification for user-chosen passwords
//!   (the `users.credential_hash` column stores the PHC strings it produces).
//! - `jwt` — Ed25519 (EdDSA) access-token issuing and validation, plus the
//!   on-disk signing/verification key pair that `JwtKeys::load_or_create`
//!   generates on a virgin volume.
//! - `error` — the shared `AuthError` vocabulary (401/403/404 mapping).
//!
//! The shared access vocabulary (capabilities, roles, actor types, the
//! one actor type) is defined in `ws-core` — the schema owner, so that the
//! crate graph stays acyclic (`ws-core` must never depend on `ws-auth`) —
//! and re-exported from here as ws-auth's single import surface.

pub mod error;
pub mod jwt;
pub mod password;

pub use ws_core::models::rbac::{
    role_capabilities, Actor, ActorType, AuthMethod, Capability, Role,
};
