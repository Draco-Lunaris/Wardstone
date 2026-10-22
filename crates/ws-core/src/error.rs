//! Typed errors shared across Wardstone crates.
//!
//! `CoreError` is Rust-internal (no serde): API/DTO serialization with JSON
//! snake_case casing happens on separate DTO types, not on this enum.

use thiserror::Error;

/// The error type produced by `ws-core` operations.
#[derive(Debug, Error)]
pub enum CoreError {
    /// A database operation failed (connection, query, or decode).
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    /// The applied-migration count in `_sqlx_migrations` does not match
    /// [`ws_core::db::REQUIRED_MIGRATION_COUNT`]: the database bookkeeping is
    /// lost (`found == 0` with schema present) or ahead of this binary.
    #[error("migration count mismatch: expected {expected}, found {found}")]
    Migration { expected: u16, found: u16 },
    /// A unique constraint was violated (e.g. inserting an existing name).
    #[error("duplicate resource")]
    Duplicate,
    /// An actor attempted an action outside its capability set
    /// ([`ws_core::models::rbac::Actor::require`]). The API layer maps
    /// this to HTTP 403.
    #[error("forbidden")]
    Forbidden,
    /// Cryptographic work failed (secret sealing/opening, os-entropy
    /// exhaustion). Messages are static and never carry key material.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// A configuration or environment problem detected at runtime.
    #[error("config error: {0}")]
    Config(String),
}
