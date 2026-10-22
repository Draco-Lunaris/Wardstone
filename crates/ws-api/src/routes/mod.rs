//! The route tree of the REST surface, the access-log middleware, and the
//! shared helpers every route module uses.
//!
//! Rate limiting: the public auth routes carry a `GovernorLayer` per the
//! house pattern — one GCRA bucket per peer IP, refilled per the config —
//! while every other route is protected by authentication and capability
//! checks. The layer is only attached when the config carries a rate
//! limit (the Task 13 binary does; in-process tests don't — axum's
//! `ConnectInfo` the peer-IP key extractor needs does not exist there).

pub mod audit;
pub mod auth;
pub mod cas;
pub mod certificates;
pub mod credentials;
pub mod health;
pub mod profiles;
pub mod root_trust;
pub mod tenants;
pub mod users;

use axum::extract::{Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use ws_core::models::audit::AuditEntry;
use ws_core::models::rbac::Actor;

use crate::state::AppState;

/// The full REST surface: everything under `/api/v1/`, plus the root-
/// level liveness and metrics spellings (`/healthz`, `/metrics`) — the
/// liveness probe of the Task 13 compose file points at the root, while
/// the versioned spellings keep the whole API under one prefix.
pub fn router(state: AppState) -> Router {
    let api_v1 = Router::new()
        .nest("/auth", auth::router(&state))
        .nest("/certificates", certificates::router())
        .nest("/profiles", profiles::router())
        .nest("/cas", cas::router())
        .nest("/audit", audit::router())
        .nest("/users", users::router())
        .nest(
            "/service-identities",
            credentials::service_identities_router(),
        )
        .nest("/one-shot-tokens", credentials::one_shot_tokens_router())
        .nest("/tenants", tenants::router())
        .nest("/root-trust", root_trust::router())
        .route("/healthz", get(health::healthz))
        .route("/metrics", get(health::metrics));

    Router::new()
        .nest("/api/v1", api_v1)
        .route("/healthz", get(health::healthz))
        .route("/metrics", get(health::metrics))
        // The access log: one line per request — method, path, status —
        // and NEVER a request or response body (the key-generation and
        // CA-key-export responses therefore cannot leak through logging).
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            access_log_middleware,
        ))
        .with_state(state)
}

/// The access-log middleware: captures the bounded log line BEFORE the
/// response body is ever touched, and emits the same line as a `debug!`
/// event for the Task 13 binary's tracing subscriber.
async fn access_log_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let response = next.run(request).await;
    let line = format!("{method} {path} -> {}", response.status().as_u16());
    state.access_log.push(line);
    tracing::debug!(
        method = %method,
        path = %path,
        status = response.status().as_u16(),
        "http request"
    );
    response
}

/// The audit entry a mutating handler records: caller-chosen id, the
/// acting actor (its type, method, session, and id per the audit
/// vocabulary), the action/target tuple, and the structured details. The
/// `tenant_id` is the ACTING actor's tenant (this is the log the actor's
/// tenant reads); `created_at` is database-owned — `record` never binds a
/// client timestamp.
pub fn audit_entry(
    actor: &Actor,
    action: &str,
    target_type: &str,
    target_id: &str,
    details: serde_json::Value,
) -> AuditEntry {
    audit_entry_with_id(
        Uuid::new_v4(),
        actor,
        action,
        target_type,
        target_id,
        details,
    )
}

/// The audit entry with a CALLER-CHOSEN id — the issuance path uses it so
/// the tests can force the audit INSERT to fail with a duplicate primary
/// key and prove the transactional contract. Every production call site
/// uses [`audit_entry`] (fresh id) instead.
pub fn audit_entry_with_id(
    id: Uuid,
    actor: &Actor,
    action: &str,
    target_type: &str,
    target_id: &str,
    details: serde_json::Value,
) -> AuditEntry {
    AuditEntry {
        id,
        tenant_id: actor.tenant_id,
        actor_type: actor.actor_type,
        auth_method: actor.auth_method,
        session_id: actor.session_id,
        actor_id: actor.actor_id.clone(),
        action: action.to_string(),
        target_type: target_type.to_string(),
        target_id: target_id.to_string(),
        details,
        created_at: Utc::now(),
    }
}

/// A JSON response that is never cached — used by every response whose
/// body carries (or touches) secret material: the key-generation leaf key,
/// the exported CA key, and the minted token plaintexts.
pub fn json_no_store<T: Serialize>(value: T) -> Response {
    let mut response = Json(value).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

/// A PKCS#8 DER payload as a PEM body (the keystore stores DER; the
/// export response is the PEM the operator saves). 64-character lines,
/// RFC 7468 form.
pub(crate) fn pem_from_der(label: &str, der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<String> = body
        .as_bytes()
        .chunks(64)
        .map(String::from_utf8_lossy)
        .map(String::from)
        .collect();
    format!(
        "-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n",
        lines = lines.join("\n")
    )
}

/// The shared list query (`?page=&page_size=`), defaulted and clamped by
/// the repositories' paging helper.
#[derive(Debug, Deserialize, Default)]
pub struct ListQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

impl ListQuery {
    pub fn page(&self) -> u32 {
        self.page.unwrap_or(0)
    }

    pub fn page_size(&self) -> u32 {
        self.page_size.unwrap_or(100)
    }
}
