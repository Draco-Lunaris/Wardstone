//! ws-ca: certificate-authority engine — encrypted key store, CA creation,
//! issuance, and revocation primitives.

pub mod ca;
pub mod crl;
pub mod error;
pub mod issue;
pub mod keystore;
pub mod serial;

/// Re-export of [`ws_core::models::ca::KeyType`] so downstream crates can
/// consume the key-type enum through `ws-ca` alone (the dependency edge is
/// ws-ca → ws-core, never the reverse). The same type is also available at
/// [`ws_ca::ca::KeyType`].
pub use ca::KeyType;
