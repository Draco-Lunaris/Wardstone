//! Typed errors for the Wardstone worker.
//!
//! The worker's failures come from two places: the database layer
//! (`ws_core::error::CoreError`) and the certificate-authority engine
//! (`ws_ca::error::CaError`). Both are wrapped with `#[from]`, so a
//! worker error always names the layer that failed without losing the
//! underlying cause.
//!
//! No variant carries key material: `CaError`'s own variants are
//! designed to hold algorithm names and parser messages only, and
//! [`WorkerError::Config`] holds configuration text.

use thiserror::Error;
use ws_ca::error::CaError;
use ws_core::error::CoreError;

/// The error type produced by worker jobs.
#[derive(Debug, Error)]
pub enum WorkerError {
    /// A database operation failed (connection, query, or decode).
    #[error("core error: {0}")]
    Core(#[from] CoreError),
    /// A certificate-authority operation failed (CRL/OCSP building, key
    /// loading).
    #[error("ca error: {0}")]
    Ca(#[from] CaError),
    /// A database operation the job performs directly failed (the CRL
    /// row's INSERT, the all-CA query).
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// The worker is misconfigured (for example: the keys directory is
    /// not set, so CA private keys cannot be loaded).
    #[error("config error: {0}")]
    Config(String),
}
