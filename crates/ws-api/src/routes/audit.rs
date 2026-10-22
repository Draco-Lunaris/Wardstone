//! The audit routes: the tenant's log, paged, and its full export.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};

use ws_core::models::audit::AuditEntry;
use ws_core::models::rbac::Capability;
use ws_core::repo::audit_repo::AuditRepo;

use crate::auth_middleware::AuthActor;
use crate::error::ApiError;
use crate::routes::ListQuery;
use crate::state::AppState;

/// The export page size: full pages until a short page ends the log.
const EXPORT_PAGE_SIZE: u32 = 500;

/// A hard cap on the export loop: 50 pages of 500 entries is far past any
/// tenant log this product ships with; a runaway would otherwise page
/// forever if the repo's semantics ever drifted.
const EXPORT_MAX_PAGES: usize = 50;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_audit))
        .route("/export", get(export_audit))
}

/// `GET /api/v1/audit` — `read_audit`; one page, newest first.
async fn list_audit(
    auth: AuthActor,
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<AuditEntry>>, ApiError> {
    auth.require(Capability::ReadAudit)
        .map_err(ApiError::from)?;
    let entries = AuditRepo::new()
        .list_by_tenant(&state.pool, auth.tenant_id, query.page(), query.page_size())
        .await?;
    Ok(Json(entries))
}

/// `GET /api/v1/audit/export` — `read_audit`; the WHOLE tenant log, one
/// entry per element (paged under the hood until the log ends).
async fn export_audit(
    auth: AuthActor,
    State(state): State<AppState>,
) -> Result<Json<Vec<AuditEntry>>, ApiError> {
    auth.require(Capability::ReadAudit)
        .map_err(ApiError::from)?;
    let repo = AuditRepo::new();
    let mut all = Vec::new();
    for page in 0..EXPORT_MAX_PAGES {
        let entries = repo
            .list_by_tenant(&state.pool, auth.tenant_id, page as u32, EXPORT_PAGE_SIZE)
            .await?;
        let done = entries.len() < EXPORT_PAGE_SIZE as usize;
        all.extend(entries);
        if done {
            return Ok(Json(all));
        }
    }
    // The cap keeps a pathological future from looping; the operator gets
    // the first 25k entries and a clear error rather than a hang.
    Err(ApiError::Internal(
        "the audit log exceeds the export cap (50 pages of 500 entries)".to_string(),
    ))
}
