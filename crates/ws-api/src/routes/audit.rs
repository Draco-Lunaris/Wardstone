//! The audit routes: the tenant's log, paged and filterable, and its
//! full export.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use ws_core::models::audit::{AuditEntry, AuditFilter};
use ws_core::models::rbac::Capability;
use ws_core::repo::audit_repo::AuditRepo;

use crate::auth_middleware::AuthActor;
use crate::error::ApiError;
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

/// The `GET /api/v1/audit` query: the shared paging fields plus the filter
/// keys, all optional. `from`/`to` deserialize as RFC 3339 instants — a
/// malformed datetime is an axum `Query` rejection (400), never a silent
/// drop of the bound. The export route deliberately keeps bare paging.
#[derive(Debug, Deserialize, Default)]
pub struct AuditListQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub action: Option<String>,
}

impl AuditListQuery {
    /// The defaults are the shared paging ones: page 0, page size 100
    /// (clamped repo-side at 500 by `ws_core::repo::paging`).
    pub fn page(&self) -> u32 {
        self.page.unwrap_or(0)
    }

    pub fn page_size(&self) -> u32 {
        self.page_size.unwrap_or(100)
    }
}

/// `GET /api/v1/audit` — `read_audit`; one page, newest first, through the
/// composed [`AuditFilter`] (a filter axis applies only when its query
/// parameter is present).
async fn list_audit(
    auth: AuthActor,
    State(state): State<AppState>,
    Query(query): Query<AuditListQuery>,
) -> Result<Json<Vec<AuditEntry>>, ApiError> {
    auth.require(Capability::ReadAudit)
        .map_err(ApiError::from)?;
    // The paging values are read BEFORE the filter consumes the query's
    // fields (a partial move would borrow back the struct after it).
    let (page, page_size) = (query.page(), query.page_size());
    let filter = AuditFilter {
        from: query.from,
        to: query.to,
        action: query.action,
    };
    let entries = AuditRepo::new()
        .list_by_tenant_filtered(&state.pool, auth.tenant_id, &filter, page, page_size)
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
