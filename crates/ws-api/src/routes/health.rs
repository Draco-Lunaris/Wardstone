//! The liveness and metrics routes: public, no auth, no DB writes.
//!
//! `GET /healthz` answers from the process itself (the database having
//! gone away is not a liveness failure — the API still serves auth
//! failures correctly). `GET /metrics` speaks the Prometheus text format.

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

/// `GET /healthz` (mounted under `/api/v1` and at the root level by
/// `routes::router`).
pub async fn healthz() -> &'static str {
    "ok"
}

/// `GET /metrics` (also mounted at the root level): the Prometheus text
/// exposition — process liveness plus the in-process state sizes.
pub async fn metrics(State(state): State<AppState>) -> Response {
    let text = format!(
        "# HELP wardstone_up Whether the Wardstone API answered this scrape.\n\
         # TYPE wardstone_up gauge\n\
         wardstone_up 1\n\
         # HELP wardstone_oidc_states_pending Pending OIDC csrf states in the in-memory store.\n\
         # TYPE wardstone_oidc_states_pending gauge\n\
         wardstone_oidc_states_pending {}\n",
        state.oidc_states.pending_count()
    );
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        text,
    )
        .into_response()
}
