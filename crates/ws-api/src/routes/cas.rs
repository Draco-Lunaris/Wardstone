//! The CA routes: create (root or sub-CA), list, and the backup key
//! export.
//!
//! Route capabilities (the plan's table): `GET /cas` is `read_cas`;
//! `POST /cas` is `manage_cas`; `POST /cas/{id}/export-key` is
//! `export_ca_keys`. The key export is the most sensitive read in the
//! system: the private key is returned by the response exactly once per
//! request, marked `Cache-Control: no-store`, and its `ca_key_exported`
//! audit details carry only the reason — never the key.
//!
//! The key-generation work (an RSA CA key mint takes seconds) runs inside
//! `tokio::task::spawn_blocking`; the keystore is opened inside the task.

use axum::extract::{Path, State};
use axum::http::header;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use ws_ca::ca::{certificate_validity, create_root, create_sub_ca, CaLifetime, CaSpec, CreatedCa};
use ws_core::models::ca::{CaModel, KeyType};
use ws_core::models::rbac::Capability;
use ws_core::repo::audit_repo::AuditRepo;
use ws_core::repo::ca_repo::CaRepo;
use ws_core::repo::crl_repo::CrlRepo;

use crate::auth_middleware::AuthActor;
use crate::error::ApiError;
use crate::routes::{audit_entry, json_no_store, pem_from_der};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_ca).get(list_cas))
        .route("/{id}/export-key", post(export_ca_key))
        .route("/{id}/chain", get(get_ca_chain))
        .route("/{id}/crl", get(get_ca_crl))
}

/// The CA creation body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CreateCaBody {
    /// Operator-facing name (unique per tenant).
    pub name: String,
    /// The certificate subject common name.
    pub subject: String,
    /// The key algorithm (`ed25519`, `rsa2048`, `rsa3072`).
    pub key_type: String,
    /// True for a trust anchor; false for an intermediate naming
    /// `parent_id`.
    pub is_root: bool,
    /// The issuing parent (required for a sub-CA, ignored for a root).
    #[serde(default)]
    pub parent_id: Option<Uuid>,
}

/// One CA, as a DTO (the certificate PEM is public; no key path).
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CaResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub subject: String,
    pub is_root: bool,
    pub parent_id: Option<Uuid>,
    pub key_type: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub cert_pem: String,
    pub created_at: DateTime<Utc>,
}

impl CaResponse {
    fn of(ca: &CaModel) -> Self {
        CaResponse {
            id: ca.id,
            tenant_id: ca.tenant_id,
            name: ca.name.clone(),
            subject: ca.subject.clone(),
            is_root: ca.is_root,
            parent_id: ca.parent_id,
            key_type: ca.key_type.as_str().to_string(),
            not_before: ca.not_before,
            not_after: ca.not_after,
            cert_pem: ca.cert_pem.clone(),
            created_at: ca.created_at,
        }
    }
}

/// `POST /api/v1/cas` — `manage_cas`. Creates a root or sub-CA: the CA
/// key goes to the keystore (envelope-encrypted), the `cas` row and its
/// `ca_created` audit row commit together.
async fn create_ca(
    auth: AuthActor,
    State(state): State<AppState>,
    Json(body): Json<CreateCaBody>,
) -> Result<(StatusCode, Json<CaResponse>), ApiError> {
    auth.require(Capability::ManageCas)
        .map_err(ApiError::from)?;
    let name = body.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("a CA name is required"));
    }
    let subject = body.subject.trim();
    if subject.is_empty() {
        return Err(ApiError::bad_request("a CA subject is required"));
    }
    let key_type = body
        .key_type
        .parse::<KeyType>()
        .map_err(|_| ApiError::bad_request(format!("unknown CA key type {:?}", body.key_type)))?;

    // A sub-CA names its parent, which must exist in this tenant; a root
    // names none.
    let parent = match (body.is_root, body.parent_id) {
        (true, _) => None,
        (false, Some(parent_id)) => {
            let parent = CaRepo::new()
                .get(&state.pool, parent_id)
                .await?
                .filter(|parent| parent.tenant_id == auth.tenant_id)
                .ok_or_else(|| ApiError::NotFound("parent CA not found".to_string()))?;
            Some(parent)
        }
        (false, None) => {
            return Err(ApiError::bad_request("a sub-ca names a parent_id"));
        }
    };

    let spec = CaSpec {
        name: name.to_string(),
        subject: subject.to_string(),
        key_type,
        lifetime: if body.is_root {
            CaLifetime::Root
        } else {
            CaLifetime::SubCa
        },
    };

    // The mint (including RSA key generation) is CPU-bound and
    // synchronous: `spawn_blocking`. The keystore custody moves into the
    // task (legacy file mode on a plaintext volume, the unlocked arena
    // custody on a sealed instance); for a sub-CA the engine unwraps the
    // parent's key inside `create_sub_ca`, per use.
    let keystore = state.keystore()?;
    let created = tokio::task::spawn_blocking(move || -> Result<CreatedCa, ApiError> {
        let mut keystore = keystore;
        let created = match &parent {
            Some(parent) => create_sub_ca(&parent.cert_pem, &parent.id, &spec, &mut keystore),
            None => create_root(&spec, &mut keystore),
        }
        .map_err(ApiError::from)?;
        Ok(created)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("the ca task failed: {e}")))??;

    // The stored row carries the CREATED certificate's own validity
    // window (the engine derives it internally — skew margins, issuer
    // caps); it is read from the certificate rather than re-derived.
    let (not_before, not_after) =
        certificate_validity(&created.cert_pem).map_err(ApiError::from)?;

    let ca = CaModel {
        id: created.key_pair_id,
        tenant_id: auth.tenant_id,
        name: name.to_string(),
        subject: subject.to_string(),
        is_root: body.is_root,
        parent_id: body.parent_id.filter(|_| !body.is_root),
        key_type,
        not_before,
        not_after,
        cert_pem: created.cert_pem.clone(),
        // The keystore names the envelope file `ca/<key_pair_id>.key`
        // under the keys directory; the row stores that relative path.
        key_file: format!("ca/{}.key", created.key_pair_id),
        created_at: Utc::now(),
    };

    let mut tx = state.pool.begin().await?;
    CaRepo::new().insert(&mut *tx, &ca).await?;
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &auth.0,
                "ca_created",
                "ca",
                &ca.id.to_string(),
                serde_json::json!({
                    "key_type": ca.key_type.as_str(),
                    "is_root": ca.is_root,
                }),
            ),
        )
        .await?;
    tx.commit().await?;

    Ok((StatusCode::CREATED, Json(CaResponse::of(&ca))))
}

/// `GET /api/v1/cas` — `read_cas`.
async fn list_cas(
    auth: AuthActor,
    State(state): State<AppState>,
) -> Result<Json<Vec<CaResponse>>, ApiError> {
    auth.require(Capability::ReadCas).map_err(ApiError::from)?;
    let cas = CaRepo::new()
        .list_by_tenant(&state.pool, auth.tenant_id)
        .await?
        .iter()
        .map(CaResponse::of)
        .collect();
    Ok(Json(cas))
}

/// The export body (the reason lands in the audit details).
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct ExportCaKeyBody {
    #[serde(default)]
    pub reason: Option<String>,
}

/// The export response: the CA's PKCS#8 private key PEM, returned once
/// per request for operator backup — the server keeps its copy, and the
/// response is never cached.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ExportedCaKey {
    pub key_pem: String,
}

/// `POST /api/v1/cas/{id}/export-key` — `export_ca_keys` (admin-only:
/// only the Admin role bundle holds the capability). The envelope is
/// opened, the PKCS#8 DER becomes a PEM body, and the `ca_key_exported`
/// audit details record the reason — never the key. `Cache-Control:
/// no-store` on the response.
async fn export_ca_key(
    auth: AuthActor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<ExportCaKeyBody>,
) -> Result<axum::response::Response, ApiError> {
    auth.require(Capability::ExportCaKeys)
        .map_err(ApiError::from)?;
    let ca = CaRepo::new()
        .get(&state.pool, id)
        .await?
        .filter(|ca| ca.tenant_id == auth.tenant_id)
        .ok_or_else(|| ApiError::NotFound("ca not found".to_string()))?;
    let reason = body
        .reason
        .unwrap_or_else(|| "operator backup export".to_string());

    let keystore = state.keystore()?;
    // One per-use unwrap: the DER exists in the arena for exactly the
    // PEM render, then the reservation is wiped. The PEM itself is the
    // export's product — the response body the operator asked for — so
    // it is ordinary heap memory by construction, never custody.
    let key_pem = keystore
        .with_ca_key(&ca.id, |key_der| Ok(pem_from_der("PRIVATE KEY", key_der)))
        .map_err(ApiError::from)?;

    // The audit row commits on its own (the read-only export changes no
    // other row — the write-side contract is trivially satisfied by this
    // one entry).
    let mut tx = state.pool.begin().await?;
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &auth.0,
                "ca_key_exported",
                "ca",
                &ca.id.to_string(),
                serde_json::json!({ "reason": reason }),
            ),
        )
        .await?;
    tx.commit().await?;

    Ok(json_no_store(ExportedCaKey { key_pem }))
}

/// The latest published CRL for a CA (the `crls` row ws-worker's CRL job
/// writes). The PEM is the CRL document itself; nothing secret — but it is
/// only ever served with its exact timestamps, verbatim.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CrlResponse {
    pub ca_id: Uuid,
    pub issued_at: DateTime<Utc>,
    pub next_update: DateTime<Utc>,
    pub crl_pem: String,
}

/// `GET /api/v1/cas/{id}/chain` — `read_cas`. The CA's certificate chain
/// leaf-first: the named CA's certificate, then each parent's, up to the
/// root's — as one concatenated PEM body (`application/x-pem-file`, the
/// root-trust route's idiom). Another tenant's CA is indistinguishable
/// from a missing one (404), and the walk never starts on an id that has
/// not passed the tenant check.
async fn get_ca_chain(
    auth: AuthActor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    auth.require(Capability::ReadCas).map_err(ApiError::from)?;
    let ca = CaRepo::new()
        .get(&state.pool, id)
        .await?
        .filter(|ca| ca.tenant_id == auth.tenant_id)
        .ok_or_else(|| ApiError::NotFound("ca not found".to_string()))?;
    let chain = {
        // One pooled connection serves the multi-statement walk (the
        // repos' executor convention: several statements need a `&mut
        // PgConnection`); the walk re-checks the verified tenant per hop.
        let mut conn = state.pool.acquire().await?;
        CaRepo::new()
            .chain_to_root(&mut conn, auth.tenant_id, ca.id)
            .await?
    };
    let body: String = chain.iter().map(|ca| ca.cert_pem.as_str()).collect();
    Ok(([(header::CONTENT_TYPE, "application/x-pem-file")], body).into_response())
}

/// `GET /api/v1/cas/{id}/crl` — `read_cas`. The CA's newest published CRL
/// as JSON (`CrlResponse`), or 404 `not_found` when it has none. The
/// tenant filter sits inside the query (the 006 composite constraint backs
/// the denormalized `tenant_id`), and the CA itself is also checked
/// against the actor's tenant first — the route never keys a read on an
/// id another tenant may own. The error path never carries the PEM.
async fn get_ca_crl(
    auth: AuthActor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<CrlResponse>, ApiError> {
    auth.require(Capability::ReadCas).map_err(ApiError::from)?;
    CaRepo::new()
        .get(&state.pool, id)
        .await?
        .filter(|ca| ca.tenant_id == auth.tenant_id)
        .ok_or_else(|| ApiError::NotFound("ca not found".to_string()))?;
    let crl = CrlRepo::new()
        .latest_for_ca(&state.pool, auth.tenant_id, id)
        .await?
        .ok_or_else(|| ApiError::NotFound("no published CRL for this ca".to_string()))?;
    Ok(Json(CrlResponse {
        ca_id: crl.ca_id,
        issued_at: crl.issued_at,
        next_update: crl.next_update,
        crl_pem: crl.crl_pem,
    }))
}
