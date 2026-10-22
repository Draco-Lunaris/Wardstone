//! The credential routes: the service identities (and their API tokens),
//! and the one-shot tokens.
//!
//! Route capabilities (the plan's table): `GET /service-identities` and
//! `GET /one-shot-tokens` are `read_service_identities`;
//! `POST /service-identities` and its revoke are `manage_api_tokens`;
//! `POST /one-shot-tokens` is `manage_one_shot_tokens`.
//!
//! Token plaintexts (`ws_at_`, `ws_ot_`) are returned exactly once by the
//! mint responses and marked `Cache-Control: no-store`; the access log
//! never sees them, and the audit details carry the capability list/
//! expiry — never token material. The mint runs INSIDE the audit
//! transaction: `create_service_identity` is one CTE underneath, and the
//! `service_identity_created` row commits with it.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use ws_auth::one_shot::mint_one_shot;
use ws_auth::service_identity::create_service_identity;
use ws_core::models::credential::ServiceIdentityModel;
use ws_core::models::rbac::Capability;
use ws_core::repo::audit_repo::AuditRepo;
use ws_core::repo::credential_repo::CredentialRepo;

use crate::auth_middleware::AuthActor;
use crate::error::ApiError;
use crate::routes::{audit_entry, json_no_store, ListQuery};
use crate::state::AppState;

/// The one-shot token mint bounds: a token is a pull-flow window, not a
/// lease — hours, not days.
const ONE_SHOT_MIN_TTL: Duration = Duration::minutes(1);
const ONE_SHOT_MAX_TTL: Duration = Duration::hours(24);

pub fn service_identities_router() -> Router<AppState> {
    Router::new()
        .route(
            "/",
            post(create_service_identity_route).get(list_service_identities),
        )
        .route("/{id}/revoke", post(revoke_service_identity))
}

pub fn one_shot_tokens_router() -> Router<AppState> {
    Router::new().route("/", post(create_one_shot_token).get(list_one_shot_tokens))
}

/// One service identity, as a read DTO (never the token hash).
#[derive(Debug, Serialize)]
pub struct ServiceIdentityResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub capabilities: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// The create body: the token's capability grant, chosen explicitly at
/// creation (and capped by the creator's own set inside ws-auth).
#[derive(Debug, Deserialize)]
pub struct CreateServiceIdentityBody {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// The mint response: the plaintext token appears exactly once.
#[derive(Debug, Serialize)]
pub struct ServiceIdentityCreated {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub capabilities: Vec<String>,
    pub token: String,
    pub created_at: DateTime<Utc>,
}

/// `POST /api/v1/service-identities` — `manage_api_tokens`.
async fn create_service_identity_route(
    auth: AuthActor,
    State(state): State<AppState>,
    Json(body): Json<CreateServiceIdentityBody>,
) -> Result<axum::response::Response, ApiError> {
    auth.require(Capability::ManageApiTokens)
        .map_err(ApiError::from)?;
    let name = body.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("a name is required"));
    }
    let capabilities: Vec<Capability> = body
        .capabilities
        .iter()
        .map(|capability| {
            Capability::from_str(capability)
                .ok_or_else(|| ApiError::bad_request(format!("unknown capability {capability:?}")))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;

    // The mint (capability-capped at the creator, one CTE) and its
    // `service_identity_created` audit row share one transaction.
    let mut tx = state.pool.begin().await?;
    let created = create_service_identity(
        &mut *tx,
        name,
        body.description.as_deref(),
        &capabilities,
        &auth.0,
        &CredentialRepo::new(),
    )
    .await
    .map_err(ApiError::from)?;
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &auth.0,
                "service_identity_created",
                "service_identity",
                &created.id.to_string(),
                serde_json::json!({
                    "capabilities": capabilities
                        .iter()
                        .map(|capability| capability.as_str().to_string())
                        .collect::<Vec<_>>(),
                }),
            ),
        )
        .await?;
    tx.commit().await?;

    // The mint response carries the plaintext token exactly once and is
    // never cached; a mint is a 201.
    let mut response = json_no_store(ServiceIdentityCreated {
        id: created.id,
        name: created.name,
        description: created.description,
        capabilities: capabilities
            .iter()
            .map(|capability| capability.as_str().to_string())
            .collect(),
        token: created.token,
        created_at: created.created_at,
    });
    *response.status_mut() = StatusCode::CREATED;
    Ok(response)
}

/// `GET /api/v1/service-identities` — `read_service_identities`.
async fn list_service_identities(
    auth: AuthActor,
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<ServiceIdentityResponse>>, ApiError> {
    auth.require(Capability::ReadServiceIdentities)
        .map_err(ApiError::from)?;
    let repo = CredentialRepo::new();
    let identities = repo
        .list_service_identities(&state.pool, auth.tenant_id, query.page(), query.page_size())
        .await?;
    let mut out = Vec::with_capacity(identities.len());
    for identity in identities {
        let capabilities = repo
            .service_identity_capabilities(&state.pool, identity.id)
            .await?;
        out.push(ServiceIdentityResponse {
            id: identity.id,
            tenant_id: identity.tenant_id,
            name: identity.name,
            description: identity.description,
            capabilities: capabilities
                .iter()
                .map(|capability| capability.as_str().to_string())
                .collect(),
            created_at: identity.created_at,
            expires_at: identity.expires_at,
            revoked_at: identity.revoked_at,
        });
    }
    Ok(Json(out))
}

/// `POST /api/v1/service-identities/{id}/revoke` — `manage_api_tokens`;
/// idempotent (a second revoke changes nothing and writes no second row).
async fn revoke_service_identity(
    auth: AuthActor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    auth.require(Capability::ManageApiTokens)
        .map_err(ApiError::from)?;
    let repo = CredentialRepo::new();

    // The identity must exist in this tenant; a revocation target from
    // another tenant is a 404 (resolved by paging the tenant listing —
    // the repo resolves tokens by hash and grants by id only).
    let target = find_service_identity(&state.pool, auth.tenant_id, id).await?;
    if target.revoked_at.is_some() {
        return Ok(StatusCode::NO_CONTENT);
    }

    let mut tx = state.pool.begin().await?;
    repo.revoke_service_identity(&mut *tx, id).await?;
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &auth.0,
                "service_identity_revoked",
                "service_identity",
                &id.to_string(),
                serde_json::json!({}),
            ),
        )
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Locate a tenant's service identity by id across the listing pages.
async fn find_service_identity(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<ServiceIdentityModel, ApiError> {
    let repo = CredentialRepo::new();
    for page in 0..50_u32 {
        let identities = repo
            .list_service_identities(pool, tenant_id, page, 500)
            .await?;
        let found = identities.iter().find(|identity| identity.id == id);
        let done = identities.len() < 500;
        if let Some(found) = found {
            return Ok(found.clone());
        }
        if done {
            break;
        }
    }
    Err(ApiError::NotFound("service identity not found".to_string()))
}

/// The one-shot mint body: the pull-flow window in minutes.
#[derive(Debug, Deserialize)]
pub struct CreateOneShotTokenBody {
    #[serde(default)]
    pub ttl_minutes: Option<u32>,
}

/// The mint response: the plaintext token appears exactly once.
#[derive(Debug, Serialize)]
pub struct OneShotTokenCreated {
    pub id: Uuid,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

/// `POST /api/v1/one-shot-tokens` — `manage_one_shot_tokens`.
async fn create_one_shot_token(
    auth: AuthActor,
    State(state): State<AppState>,
    Json(body): Json<CreateOneShotTokenBody>,
) -> Result<axum::response::Response, ApiError> {
    auth.require(Capability::ManageOneShotTokens)
        .map_err(ApiError::from)?;
    let ttl_minutes = body.ttl_minutes.unwrap_or(60) as i64;
    let ttl = Duration::minutes(ttl_minutes);
    if ttl < ONE_SHOT_MIN_TTL {
        return Err(ApiError::bad_request(
            "a one-shot token's ttl must be at least one minute",
        ));
    }
    if ttl > ONE_SHOT_MAX_TTL {
        return Err(ApiError::bad_request(
            "a one-shot token's ttl must be at most 24 hours",
        ));
    }

    // The mint and its `one_shot_token_minted` audit row (the details
    // carry the expiry — never the token) share one transaction.
    let mut tx = state.pool.begin().await?;
    let minted = mint_one_shot(
        &mut *tx,
        auth.tenant_id,
        &auth.0,
        ttl,
        &CredentialRepo::new(),
    )
    .await
    .map_err(ApiError::from)?;
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &auth.0,
                "one_shot_token_minted",
                "one_shot_token",
                &minted.id.to_string(),
                serde_json::json!({ "expires_at": minted.expires_at.to_rfc3339() }),
            ),
        )
        .await?;
    tx.commit().await?;

    // The mint response carries the plaintext token exactly once and is
    // never cached; a mint is a 201.
    let mut response = json_no_store(OneShotTokenCreated {
        id: minted.id,
        token: minted.token,
        expires_at: minted.expires_at,
    });
    *response.status_mut() = StatusCode::CREATED;
    Ok(response)
}

/// `GET /api/v1/one-shot-tokens` — `read_service_identities` (the same
/// capability on both listings is the plan's deliberate choice: the
/// one-shot list is an operator's view of the pull-flow tokens, not a
/// separate grant).
async fn list_one_shot_tokens(
    auth: AuthActor,
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<OneShotTokenResponse>>, ApiError> {
    auth.require(Capability::ReadServiceIdentities)
        .map_err(ApiError::from)?;
    let tokens = CredentialRepo::new()
        .list_one_shot_tokens(&state.pool, auth.tenant_id, query.page(), query.page_size())
        .await?
        .into_iter()
        .map(|token| OneShotTokenResponse {
            id: token.id,
            minted_by: token.minted_by.map(|user| user.to_string()),
            created_at: token.created_at,
            expires_at: token.expires_at,
            used_at: token.used_at,
        })
        .collect();
    Ok(Json(tokens))
}

/// One one-shot token, as a read DTO (never the token hash; `minted_by`
/// is the minting user's id).
#[derive(Debug, Serialize)]
pub struct OneShotTokenResponse {
    pub id: Uuid,
    pub minted_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub used_at: Option<DateTime<Utc>>,
}
