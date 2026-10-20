//! ws-worker: the background worker that keeps the CA's published
//! revocation state fresh.
//!
//! The worker owns two jobs today:
//!
//! - [`jobs::regen_crl_and_ocsp`] — for every CA whose revocation list
//!   has grown since its latest CRL, rebuild the CRL and publish one
//!   OCSP response per revoked certificate.
//! - [`run_scheduler`] — the never-ending loop that runs that job on a
//!   fixed interval. A failing job is logged and retried at the next
//!   tick; it never takes the worker down.

pub mod error;
pub mod jobs;

use std::time::Duration;

use sqlx::PgPool;
use ws_ca::keystore::KeyStore;

use crate::error::WorkerError;

/// How often the scheduler runs the regeneration job.
const SCHEDULER_INTERVAL: Duration = Duration::from_secs(60);

/// The worker scheduler: run the regeneration job every
/// [`SCHEDULER_INTERVAL`], forever.
///
/// The job's failures are logged (with `tracing::error!`) and retried at
/// the next tick — a transient database or keystore problem must never
/// take the worker down, because a CA that stops publishing CRLs is
/// worse than one that publishes them late. The function never returns.
pub async fn run_scheduler(pool: PgPool, keystore: KeyStore) -> ! {
    let mut ticker = tokio::time::interval(SCHEDULER_INTERVAL);
    loop {
        ticker.tick().await;
        if let Err(err) = jobs::regen_crl_and_ocsp(&pool, &keystore).await {
            tracing::error!(error = %err, "CRL/OCSP regeneration job failed");
        }
    }
}

/// Read the keys directory from the environment.
///
/// The worker needs the CA private keys to sign CRLs and OCSP
/// responses, and they live in the encrypted key store, which is
/// addressed by its directory. The directory is therefore taken from the
/// `WARDSTONE_KEYS_DIR` environment variable — the one piece of
/// deployment configuration the worker needs, and the same knob Plan 2's
/// bootstrap uses when it creates the first CA.
///
/// Errors: the variable missing or empty is [`WorkerError::Config`].
pub fn keys_dir_from_env() -> Result<std::path::PathBuf, WorkerError> {
    match std::env::var("WARDSTONE_KEYS_DIR") {
        Ok(dir) if !dir.trim().is_empty() => Ok(std::path::PathBuf::from(dir)),
        _ => Err(WorkerError::Config(
            "WARDSTONE_KEYS_DIR is not set: the worker needs the key store directory \
             to sign CRLs and OCSP responses"
                .to_owned(),
        )),
    }
}
