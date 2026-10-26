//! The OIDC provider-configuration routes: the CRUD surface that enables
//! (or removes) SSO for the acting actor's tenant, plus the discovery
//! "test" route the UI's test button drives.
//!
//! The login-side OIDC flow is public and lives in `auth.rs`
//! (`/auth/oidc/*`); this module is the management surface — every route
//! on it EXCEPT the one-line status flag is `manage_system`: provider
//! configuration rewrites the tenant's login surface, which is system
//! administration. The management routes operate on the AUTHENTICATED
//! actor's tenant (the configuration row's primary key is `tenant_id`)
//! — never a path parameter. `GET /config/status` is the deliberate
//! exception: PUBLIC, read-only, answering whether SSO is configured
//! with no capability gate (the pre-auth login page's flag — see
//! [`config_status`]).
//!
//! The `client_secret` never leaves the server — it is SEALED at rest
//! under the instance's secret-encryption key (the TOTP pair's storage
//! shape) on write, and the stored seal opens into the protected arena
//! only through the shared conversion (`to_auth_config`), whose two
//! consumers are the login flow's token exchange and the saved-config
//! probe on this module's test route (the probe runs `discover`, which
//! itself never consumes the secret): the read response carries
//! `client_secret_set: bool` only, and the audit details carry
//! `provider_type` and `discovery_url` — never secret material.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use ws_auth::oidc::{discover, OidcConfig};
use ws_ca::keystore::protected_memory_failure;
use ws_core::models::credential::OidcConfigModel;
use ws_core::models::rbac::Capability;
use ws_core::repo::audit_repo::AuditRepo;
use ws_core::repo::oidc_repo::OidcConfigRepo;
use ws_core::repo::tenant_repo::TenantRepo;

use crate::auth_middleware::AuthActor;
use crate::error::ApiError;
use crate::routes::auth::primary_tenant;
use crate::routes::{audit_entry, json_no_store};
use crate::state::AppState;

/// The provider flavours the `oidc_config.provider_type` CHECK constraint
/// (migration 007) admits — validated here so a bad request is a clean
/// 400 rather than a typed database error.
const PROVIDER_TYPES: [&str; 3] = ["keycloak", "azure", "custom"];

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/config",
            get(get_config).put(put_config).delete(delete_config),
        )
        .route("/config/status", get(config_status))
        .route("/config/test", post(test_config))
}

/// `GET /api/v1/oidc/config/status` — PUBLIC: the login page's SSO flag.
///
/// Why it carries no capability gate and no `AuthActor` (a deliberate
/// exception on an otherwise all-`manage_system` module): the flag is
/// read BEFORE any session exists — ws-web's `/auth/ui/config` relay
/// probes this route with NO browser credentials by design, so gating it
/// behind `manage_system` would permanently 401 every pre-auth probe and
/// hide the login page's "Sign in with SSO" button forever. Read-only
/// (a bare repo GET) and secret-free: the answer carries `provider_type`
/// ONLY when a configuration exists, and NEVER `client_id`,
/// `redirect_uri`, `discovery_url`, or secret material — exactly the one
/// question "is SSO configured, and under which provider label does the
/// start route resolve `{provider}`". The tenant is resolved the same
/// way the OTHER public login-side route resolves it —
/// [`primary_tenant`] (the install's first-created tenant), the rule
/// `GET /auth/oidc/{provider}/start` shares — so the flag the SSO button
/// navigates with describes exactly the flow it starts, on the tenant
/// the login form's sibling flow operates on.
async fn config_status(
    State(state): State<AppState>,
) -> Result<axum::response::Response, ApiError> {
    let tenant = primary_tenant(&TenantRepo::new(), &state.pool).await?;
    match OidcConfigRepo::new().get(&state.pool, tenant.id).await? {
        Some(row) => Ok(json_no_store(json!({
            "configured": true,
            "provider_type": row.provider_type,
        }))),
        None => Ok(json_no_store(json!({
            "configured": false,
            "provider_type": serde_json::Value::Null,
        }))),
    }
}

/// The provider configuration, as the UI reads it — never the secret.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct OidcConfigResponse {
    pub provider_type: String,
    pub display_name: String,
    pub discovery_url: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: String,
    /// Whether a secret is stored (never `true` without one, never the
    /// secret itself).
    pub client_secret_set: bool,
}

/// The upsert body. `client_secret: None` keeps the stored secret on an
/// EXISTING row; a new row without a secret is a 400 (an empty string is
/// the public-client convention and is accepted as `Some("")`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UpsertOidcConfigBody {
    pub provider_type: String,
    pub display_name: String,
    pub discovery_url: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub scopes: String,
}

/// The body of the discovery-test route. The whole body is optional (the
/// UI sends it only when the operator is testing unsaved values);
/// `override` carries an upsert-shaped payload to probe INSTEAD of the
/// saved configuration.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OidcTestBody {
    #[serde(default, rename = "override")]
    pub r#override: Option<UpsertOidcConfigBody>,
}

/// A successful discovery probe: exactly the fields Wardstone consumes
/// (the `OidcDiscovery` shape).
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct OidcDiscoveryResponse {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

/// `GET /api/v1/oidc/config` — `manage_system`; 404 when unset (SSO is
/// simply not enabled for the tenant yet).
async fn get_config(
    auth: AuthActor,
    State(state): State<AppState>,
) -> Result<axum::response::Response, ApiError> {
    auth.require(Capability::ManageSystem)
        .map_err(ApiError::from)?;
    let row = OidcConfigRepo::new()
        .get(&state.pool, auth.tenant_id)
        .await?
        .ok_or_else(not_configured)?;
    Ok(json_no_store(OidcConfigResponse::of(&row)))
}

/// `PUT /api/v1/oidc/config` — `manage_system`. Validates the body, seals
/// the typed `client_secret` under the instance's secret-encryption key
/// (an EMPTY typed secret normalizes to the absent pair — the
/// public-client convention), keeps the stored seal byte-identical when
/// `client_secret` is `None` on an existing row (or refuses a secret-less
/// first configuration), upserts, and audits `oidc_config_updated` in one
/// transaction (the audit-failure rollback contract).
async fn put_config(
    auth: AuthActor,
    State(state): State<AppState>,
    Json(body): Json<UpsertOidcConfigBody>,
) -> Result<axum::response::Response, ApiError> {
    auth.require(Capability::ManageSystem)
        .map_err(ApiError::from)?;
    if !PROVIDER_TYPES.contains(&body.provider_type.as_str()) {
        return Err(ApiError::bad_request(format!(
            "provider_type must be one of keycloak, azure, custom (got {:?})",
            body.provider_type
        )));
    }
    if !is_https_url(&body.redirect_uri) {
        return Err(ApiError::bad_request("redirect_uri must be an https URL"));
    }

    // The upsert replaces the whole row, so a `None` secret on an
    // EXISTING row carries that row's stored seal forward BYTE-IDENTICAL
    // (never open+re-seal — resealing would churn the nonce and create a
    // needless unseal event); on a NEW row there is nothing to keep —
    // the secret is required. A typed EMPTY secret normalizes to the
    // ABSENT pair (the public client) — never a sealed empty ciphertext.
    // Read, upsert, and the audit row share one transaction.
    let mut tx = state.pool.begin().await?;
    let existing = OidcConfigRepo::new().get(&mut *tx, auth.tenant_id).await?;
    let secret_box = state.secret_box()?;
    let (client_secret_ciphertext, client_secret_nonce) = match body.client_secret.as_deref() {
        Some(secret) if !secret.is_empty() => {
            let (ciphertext, nonce) = secret_box.seal(secret.as_bytes()).map_err(ApiError::from)?;
            (Some(ciphertext), Some(nonce))
        }
        Some(_) => (None, None),
        None => match existing.as_ref() {
            Some(row) => (
                row.client_secret_ciphertext.clone(),
                row.client_secret_nonce.clone(),
            ),
            None => {
                return Err(ApiError::bad_request(
                    "client_secret is required when first configuring the provider",
                ))
            }
        },
    };
    let model = OidcConfigModel {
        tenant_id: auth.tenant_id,
        provider_type: body.provider_type,
        display_name: body.display_name,
        discovery_url: body.discovery_url,
        client_id: body.client_id,
        client_secret_ciphertext,
        client_secret_nonce,
        redirect_uri: body.redirect_uri,
        scopes: body.scopes,
    };
    OidcConfigRepo::new().upsert(&mut *tx, &model).await?;
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &auth.0,
                "oidc_config_updated",
                "oidc_config",
                &auth.tenant_id.to_string(),
                config_details(&model),
            ),
        )
        .await?;
    tx.commit().await?;

    // The PUT response is the same shape as the GET (never the secret).
    Ok(json_no_store(OidcConfigResponse::of(&model)))
}

/// `DELETE /api/v1/oidc/config` — `manage_system`; 404 when nothing is
/// configured, 204 with the `oidc_config_removed` audit row otherwise.
async fn delete_config(
    auth: AuthActor,
    State(state): State<AppState>,
) -> Result<StatusCode, ApiError> {
    auth.require(Capability::ManageSystem)
        .map_err(ApiError::from)?;
    let mut tx = state.pool.begin().await?;
    // Existence is established first — and the row's non-secret fields
    // feed the audit details; the guarded delete afterwards simply
    // repeats the tenant key.
    let existing = OidcConfigRepo::new()
        .get(&mut *tx, auth.tenant_id)
        .await?
        .ok_or_else(not_configured)?;
    OidcConfigRepo::new()
        .delete(&mut *tx, auth.tenant_id)
        .await?;
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &auth.0,
                "oidc_config_removed",
                "oidc_config",
                &auth.tenant_id.to_string(),
                config_details(&existing),
            ),
        )
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/oidc/config/test` — `manage_system`. Runs discovery
/// against the override payload when the body carries one, else against
/// the SAVED configuration (404 when none is saved). A failed probe is a
/// 400 whose message is the `AuthError` display — the ws-auth error text
/// never carries the `client_secret`.
async fn test_config(
    auth: AuthActor,
    State(state): State<AppState>,
    // The whole body is optional: a probe of the saved configuration
    // arrives with no JSON body at all (the absent-content-type case),
    // while `null` and a missing field both mean "no override".
    body: Option<Json<OidcTestBody>>,
) -> Result<axum::response::Response, ApiError> {
    auth.require(Capability::ManageSystem)
        .map_err(ApiError::from)?;
    let config: OidcConfig = match body.and_then(|Json(body)| body.r#override) {
        // An override is probed exactly as given; discovery uses only the
        // discovery URL. The TYPED override secret — never stored, never
        // read from the database — is copied into the protected arena, and
        // an absent or empty one is the public-client convention.
        Some(override_body) => {
            let mem = ws_secmem::global()
                .map_err(protected_memory_failure)
                .map_err(ApiError::from)?;
            let client_secret = match override_body.client_secret.as_deref() {
                Some(secret) if !secret.is_empty() => mem
                    .alloc_copy(secret.as_bytes())
                    .map_err(protected_memory_failure)
                    .map_err(ApiError::from)?,
                _ => mem
                    .alloc(0)
                    .map_err(protected_memory_failure)
                    .map_err(ApiError::from)?,
            };
            OidcConfig {
                provider_type: override_body.provider_type,
                display_name: override_body.display_name,
                discovery_url: override_body.discovery_url,
                client_id: override_body.client_id,
                client_secret,
                redirect_uri: override_body.redirect_uri,
                scopes: override_body.scopes,
            }
        }
        None => to_auth_config(
            &state,
            &OidcConfigRepo::new()
                .get(&state.pool, auth.tenant_id)
                .await?
                .ok_or_else(not_configured)?,
        )?,
    };
    let discovery = discover(&config).await.map_err(|e| {
        // The shared AuthError table maps `Config` to 500 (a login-flow
        // deployment failure is server-side); the test route is an
        // operator's reachability probe, and its failure is a reportable
        // result — 400 with the typed error's display.
        ApiError::bad_request(e.to_string())
    })?;
    Ok(json_no_store(OidcDiscoveryResponse {
        issuer: discovery.issuer,
        authorization_endpoint: discovery.authorization_endpoint,
        token_endpoint: discovery.token_endpoint,
        jwks_uri: discovery.jwks_uri,
    }))
}

/// The model → ws-auth conversion, as the login-flow side
/// (`auth.rs::provider_config`) and the saved-configuration probe both
/// perform it: the stored seal opens into the protected arena (never the
/// heap), an absent pair is the public-client convention, and a HALF pair
/// fails closed — see [`client_secret_of`].
pub(crate) fn to_auth_config(
    state: &AppState,
    model: &OidcConfigModel,
) -> Result<OidcConfig, ApiError> {
    Ok(OidcConfig {
        provider_type: model.provider_type.clone(),
        display_name: model.display_name.clone(),
        discovery_url: model.discovery_url.clone(),
        client_id: model.client_id.clone(),
        client_secret: client_secret_of(state, model)?,
        redirect_uri: model.redirect_uri.clone(),
        scopes: model.scopes.clone(),
    })
}

/// The stored client-secret seal opened into the protected arena — the
/// exact custody the token exchange receives (`SecretBox::open`'s
/// `Zeroizing` heap intermediate is a bounded transient; the arena copy
/// is the one the exchange reads). An ABSENT pair is the public-client
/// convention (an empty arena buffer). A HALF pair — ciphertext without
/// its nonce or vice versa, a damaged or corrupted row — fails CLOSED as
/// a typed refusal, never a silent public-client login (the same rule
/// the TOTP open side applies to a row that claims MFA but carries no
/// seal).
fn client_secret_of(
    state: &AppState,
    model: &OidcConfigModel,
) -> Result<ws_secmem::SecretBuf, ApiError> {
    let mem = ws_secmem::global()
        .map_err(protected_memory_failure)
        .map_err(ApiError::from)?;
    match (
        model.client_secret_ciphertext.as_deref(),
        model.client_secret_nonce.as_deref(),
    ) {
        (Some(ciphertext), Some(nonce)) => {
            let secret_box = state.secret_box()?;
            let opened = secret_box.open(ciphertext, nonce).map_err(ApiError::from)?;
            mem.alloc_copy(&opened)
                .map_err(protected_memory_failure)
                .map_err(ApiError::from)
        }
        (None, None) => mem
            .alloc(0)
            .map_err(protected_memory_failure)
            .map_err(ApiError::from),
        _ => Err(ApiError::Internal(
            "the provider configuration carries a damaged client-secret seal — refusing \
             rather than treating it as a public client"
                .to_string(),
        )),
    }
}

/// One config row as the read DTO — the secret is reduced to its
/// `client_secret_set` boolean.
impl OidcConfigResponse {
    fn of(model: &OidcConfigModel) -> Self {
        OidcConfigResponse {
            provider_type: model.provider_type.clone(),
            display_name: model.display_name.clone(),
            discovery_url: model.discovery_url.clone(),
            client_id: model.client_id.clone(),
            redirect_uri: model.redirect_uri.clone(),
            scopes: model.scopes.clone(),
            client_secret_set: model.client_secret_ciphertext.is_some(),
        }
    }
}

/// The audit details for a config mutation: the non-secret shape only.
fn config_details(model: &OidcConfigModel) -> serde_json::Value {
    serde_json::json!({
        "provider_type": model.provider_type,
        "discovery_url": model.discovery_url,
    })
}

/// A missing configuration is 404 on every route that needs one.
fn not_configured() -> ApiError {
    ApiError::NotFound("no OIDC provider configuration exists".to_string())
}

/// `redirect_uri` must be an https URL: the redirect hands an
/// authorization code to the browser's address bar, and a downgraded
/// scheme would leak it. Checked on the shape — https scheme plus a
/// non-empty authority — without another URL-parser dependency.
fn is_https_url(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    !authority.is_empty()
}
