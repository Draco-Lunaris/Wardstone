//! The root-trust route: `GET /api/v1/root-trust/ca.crt`, gated by
//! `read_cas`. Returns the CA CERTIFICATE PEM — never the key.

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use ws_core::models::rbac::Capability;
use ws_core::repo::ca_repo::CaRepo;

use crate::auth_middleware::AuthActor;
use crate::error::ApiError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/ca.crt", get(download_root_cert))
}

/// `GET /api/v1/root-trust/ca.crt` — the tenant root CA's certificate as
/// the PEM body operators install into their trust stores. The private
/// key lives behind the `export_ca_keys` capability on a separate POST
/// route; this GET can never hand it out (the row's `cert_pem` is the
/// only body source).
async fn download_root_cert(
    auth: AuthActor,
    State(state): State<AppState>,
) -> Result<Response, ApiError> {
    auth.require(Capability::ReadCas).map_err(ApiError::from)?;
    let cas = CaRepo::new()
        .list_by_tenant(&state.pool, auth.tenant_id)
        .await?;
    let root = cas.iter().find(|ca| ca.is_root).ok_or_else(|| {
        ApiError::NotFound("no root certificate authority exists yet".to_string())
    })?;
    Ok((
        [(header::CONTENT_TYPE, "application/x-pem-file")],
        root.cert_pem.clone(),
    )
        .into_response())
}
