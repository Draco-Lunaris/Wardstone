//! Typed errors shared across `ws-ca` operations (keystore, CA creation,
//! issuance, CRL/OCSP), mirroring `ws-core`'s `CoreError` conventions.
//!
//! Rust-internal only (no serde): API/DTO serialization happens on separate
//! DTO types. No variant ever carries key material: `X509` and
//! `UnsupportedKeyType` hold algorithm names and parser messages, and the
//! key store maps every AEAD/base64/JSON failure to one of its opaque
//! variants before it can surface.

use thiserror::Error;

/// The error type produced by `ws-ca` operations.
///
/// The keystore variants are deliberately split so an operator can tell a
/// wrong master key from a damaged store, and a missing envelope from
/// either:
///
/// - [`CaError::WrongKey`] — the master key does not authenticate the
///   stored envelopes (restored volume with an old `master.key`).
/// - [`CaError::Corrupt`] — the store itself is damaged or inconsistent
///   (truncated envelope, malformed base64/JSON, inner-layer AEAD failure,
///   envelope in the wrong CA slot, short master key, or a master key that
///   is missing while envelopes exist).
/// - [`CaError::NotFound`] — no envelope exists for the requested CA id.
#[derive(Debug, Error)]
pub enum CaError {
    /// A filesystem or OS-entropy operation failed (directory/file access,
    /// random source exhaustion).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The key store is damaged or internally inconsistent (truncated
    /// envelope, malformed base64/JSON, inner-layer AEAD failure, envelope
    /// in the wrong CA slot, master key shorter than 32 bytes, or master
    /// key missing while CA envelopes exist).
    #[error("key store is damaged or inconsistent")]
    Corrupt,
    /// The master key does not match the stored key envelopes (outer AEAD
    /// verification failed). Re-initializing over this state is an explicit
    /// destructive action that lives outside the keystore.
    #[error("master key does not match the stored key envelopes")]
    WrongKey,
    /// No key envelope exists for the requested CA id. Deliberately a
    /// dedicated variant (not `Corrupt`): callers may bootstrap from
    /// "missing", but must never auto-recover from "corrupt".
    #[error("no key envelope for the requested CA")]
    NotFound,
    /// The keystore holds NO master key in memory: the instance is sealed
    /// and the operator has not performed the unlock. Key operations
    /// refuse until then (the sealed-at-rest design) — a sealed store can
    /// never silently serve or mint key material.
    #[error("the instance is sealed: unlock before performing key operations")]
    Sealed,
    /// Key or certificate generation failed inside `rcgen`.
    #[error("certificate generation error: {0}")]
    Rcgen(#[from] rcgen::Error),
    /// An X.509 structure failed to parse or encode.
    #[error("x509 error: {0}")]
    X509(String),
    /// The requested key type is not supported by this build.
    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(String),
    /// A database operation failed (connection, query, or decode).
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// A worker-loop failure (wrapped by `ws-worker`'s `WorkerError`).
    #[error("worker error: {0}")]
    Worker(String),
}
