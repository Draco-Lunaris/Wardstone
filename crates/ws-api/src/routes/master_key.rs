//! The master-passphrase change route: `POST /api/v1/master-key`,
//! `manage_system` — the operator's user-managed rotation cadence (the
//! sealed-at-rest spec §5.7, Task 4b).
//!
//! The route is a thin, capability-gated shell around the ONE re-wrap
//! operation (`ws_core::crypto::rewrap_volume`): verify `current`
//! against the sealed volume, then re-wrap every envelope under `next`
//! at generation + 1, master last. Nothing about the DATABASE
//! credential changes — the change re-seals the current one, not
//! rotates it; rotation stays the unlock's per-unlock invariant.
//!
//! The audit row carries NO passphrases — the action name and the
//! generation the volume advanced to, nothing else. It commits after
//! the re-wrap: the mutation is file-shaped and cannot share a
//! transaction with the row, so the honest order is
//! mutation-then-audit (a row written first would claim a change that
//! an IO death mid-re-wrap could still abort; the reverse gap — a
//! completed change whose audit write failed — surfaces as the 500
//! below while the volume is consistently re-wrapped).
//!
//! A MIXED volume (a change that crashed mid-re-wrap; the generations
//! disagree) completes through the same call — the operator re-enters
//! the same `current` + `next` pair and the re-wrap converges the
//! stragglers — and equally at the next unlock, where the unlock page
//! offers the completion (the flow the spec names for a restart
//! mid-change).

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use ws_core::crypto::{
    rewrap_volume, KeyEnvelope, DB_CREDENTIAL_ENVELOPE_FILE, JWT_ENVELOPE_FILE,
    MASTER_ENVELOPE_FILE, SECRET_ENVELOPE_FILE,
};
use ws_core::error::CoreError;
use ws_core::models::rbac::Capability;
use ws_core::repo::audit_repo::AuditRepo;

use crate::auth_middleware::AuthActor;
use crate::error::ApiError;
use crate::routes::audit_entry;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", post(change_master_passphrase))
}

/// The four standard envelopes a passphrase change re-wraps — master
/// listed first for readability; the re-wrap's own write order puts it
/// LAST (the anchor rule).
const VOLUME_FILES: [&str; 4] = [
    MASTER_ENVELOPE_FILE,
    SECRET_ENVELOPE_FILE,
    DB_CREDENTIAL_ENVELOPE_FILE,
    JWT_ENVELOPE_FILE,
];

/// The change body: the volume's present passphrase and its next one.
/// The SPA collects `next` twice and confirms client-side (the setup
/// page's own convention); the api takes the pair as-is.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ChangeMasterKeyBody {
    pub current: String,
    pub next: String,
}

/// The change response: the generation the volume now sits at.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct MasterKeyChanged {
    pub generation: u64,
}

/// `POST /api/v1/master-key` — `manage_system`.
async fn change_master_passphrase(
    auth: AuthActor,
    State(state): State<AppState>,
    Json(body): Json<ChangeMasterKeyBody>,
) -> Result<(StatusCode, Json<MasterKeyChanged>), ApiError> {
    auth.require(Capability::ManageSystem)
        .map_err(ApiError::from)?;
    if body.current.trim().is_empty() || body.next.trim().is_empty() {
        return Err(ApiError::bad_request(
            "a current and a next passphrase are required",
        ));
    }
    let keys_dir = state.config.keys_dir.clone();
    // The change needs the COMPLETE set: a volume with an envelope
    // missing is the unlock flow's to heal (the fresh-install mint, the
    // re-key runbook), never this route's. The state errors map to
    // 409 before the re-wrap runs so they cannot masquerade as a wrong
    // passphrase.
    for file in VOLUME_FILES {
        if !keys_dir.join(file).exists() {
            return Err(ApiError::Conflict(format!(
                "the keys volume holds no {file} — this instance is not a sealed volume \
                 in a changeable state"
            )));
        }
    }
    let generations: std::result::Result<Vec<u64>, CoreError> = VOLUME_FILES
        .iter()
        .map(|file| KeyEnvelope::read_generation(&keys_dir.join(file)))
        .collect();
    let generations = match generations {
        Ok(generations) => generations,
        Err(e) => return Err(ApiError::from(e)),
    };
    let anchor = KeyEnvelope::read_generation(&keys_dir.join(MASTER_ENVELOPE_FILE))?;
    if generations
        .iter()
        .any(|generation| *generation != anchor && *generation != anchor + 1)
    {
        return Err(ApiError::Conflict(
            "the keys volume's generations are inconsistent — a change cannot run \
             against a volume this far from its anchor"
                .to_string(),
        ));
    }
    let advanced = rewrap_volume(&keys_dir, &VOLUME_FILES, &body.current, &body.next).map_err(
        |e| match e {
            // By here the volume's state is verified; the remaining
            // crypto failure is the passphrase refusing to open it.
            CoreError::Crypto(_) => ApiError::BadRequest {
                code: "wrong_passphrase",
                message: "the current passphrase did not open the volume".to_string(),
            },
            other => ApiError::from(other),
        },
    )?;

    let mut tx = state.pool.begin().await?;
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &auth.0,
                "master_key_changed",
                "system",
                "master-key",
                serde_json::json!({ "generation": advanced }),
            ),
        )
        .await?;
    tx.commit().await?;

    Ok((
        StatusCode::OK,
        Json(MasterKeyChanged {
            generation: advanced,
        }),
    ))
}
