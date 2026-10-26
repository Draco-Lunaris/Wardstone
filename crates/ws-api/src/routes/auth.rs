//! The auth routes: login, refresh, logout, `/me`, the TOTP lifecycle,
//! and the OIDC start/callback pair.
//!
//! Route capabilities (the plan's table):
//!
//! - `POST /login`, `/refresh`, `/oidc/*` — public, rate-limited per IP;
//! - `GET /me`, `POST /logout` — any authenticated actor (logout revokes
//!   ITS OWN refresh token);
//! - `POST /auth/totp/{enroll,activate,deactivate}` — any authenticated
//!   actor, but the operation is on ITS OWN account, so a machine actor
//!   (no user account) is refused 403.
//!
//! The audit write-side contract: logout and every TOTP mutation write
//! their `session_revoked` / `mfa_{enrolled,activated,deactivated}` row in
//! the SAME transaction as the change. Login itself is not in the audit
//! vocabulary (a failed login never changes state; a successful one's
//! session row is already the record).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Redirect;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::PeerIpKeyExtractor;
use tower_governor::GovernorLayer;
use uuid::Uuid;

use ws_auth::error::AuthError;
use ws_auth::jwt::{issue_access_token, AccessClaims};
use ws_auth::refresh::{authenticate_refresh_token, issue_refresh_token, rotate_refresh_token};
use ws_core::models::rbac::{Actor, ActorType, AuthMethod, Role};
use ws_core::models::tenant::Tenant;
use ws_core::models::user::UserModel;
use ws_core::repo::audit_repo::AuditRepo;
use ws_core::repo::oidc_repo::OidcConfigRepo;
use ws_core::repo::refresh_repo::RefreshTokenRepo;
use ws_core::repo::tenant_repo::TenantRepo;
use ws_core::repo::user_repo::UserRepo;

use crate::auth_middleware::{user_id_of, AuthActor};
use crate::error::ApiError;
use crate::routes::audit_entry;
use crate::state::{AppState, TOTP_ISSUER};

/// How many consecutive failures lock the account out (the house's
/// lockout policy shape; the login failure counter is the users row's
/// `failed_login_attempts`).
const LOCKOUT_THRESHOLD: i32 = 5;

/// How long a lockout window lasts.
const LOCKOUT_WINDOW: Duration = Duration::minutes(15);

pub fn router(state: &AppState) -> Router<AppState> {
    let public = Router::new()
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/oidc/{provider}/start", get(oidc_start))
        .route("/oidc/{provider}/callback", get(oidc_callback));
    // The GovernorLayer per the house pattern — per-IP GCRA on the public
    // auth routes. `None` in the config disables the layer (tests only:
    // axum's ConnectInfo the peer-IP key extractor needs does not exist
    // for an in-process oneshot request).
    let public = match state.config.auth_rate_limit {
        Some(limit) => {
            // `finish()` fails only on a zero burst or period (both
            // caller-configured). The router cannot be fallible, so a
            // broken number is a LOUDLY-LOGGED skip of the layer — never
            // a panic at boot; the Task 13 binary configures constants
            // where this branch is unreachable.
            match GovernorConfigBuilder::<PeerIpKeyExtractor, _>::default()
                .per_millisecond(limit.per_millis)
                .burst_size(limit.burst)
                .finish()
            {
                Some(config) => public.layer(GovernorLayer::new(std::sync::Arc::new(config))),
                None => {
                    tracing::error!(
                        per_millis = limit.per_millis,
                        burst = limit.burst,
                        "invalid auth rate-limit configuration: per_millis and burst must \
                         be positive; the auth routes run WITHOUT rate limiting"
                    );
                    public
                }
            }
        }
        None => public,
    };

    let protected = Router::new()
        .route("/logout", post(logout))
        .route("/me", get(me))
        .route("/totp/enroll", post(totp_enroll))
        .route("/totp/activate", post(totp_activate))
        .route("/totp/deactivate", post(totp_deactivate));

    public.merge(protected)
}

/// The v1 tenancy shape: a single-tenant instance by default, tenant-
/// shaped schema from day one. The public routes (login, OIDC start)
/// resolve THE tenant of the install: the FIRST created (the tenant the
/// setup flow made) — never "first by name", which is an accident of
/// `list`'s display order, not an install fact. A fresh database with no
/// tenant is a 404 — setup has not run. ONE helper so every call site
/// shares the same resolution rule. `pub(crate)` because the OIDC
/// config's PUBLIC status route (`routes/oidc.rs::config_status`) shares
/// it — the SSO flag must describe the same tenant the SSO flow runs on.
pub(crate) async fn primary_tenant(
    repo: &TenantRepo,
    executor: impl sqlx::PgExecutor<'_>,
) -> Result<Tenant, ApiError> {
    repo.oldest(executor).await?.ok_or_else(|| {
        ApiError::NotFound("no tenant exists yet (complete setup first)".to_string())
    })
}

/// A committed argon2id PHC string, generated ONCE with the house
/// parameters (`ws_auth::password::hash_password` over a fixed throwaway
/// input at implementation time — a hash of nothing meaningful, never any
/// account's password). The unknown-username login branch verifies against
/// it only to spend the same argon2id time a wrong-password verify spends,
/// so response timing cannot separate "no such user" from "wrong
/// password"; the verify's outcome is always discarded.
const DUMMY_ARGON2_PHC: &str =
    "$argon2id$v=19$m=65536,t=3,p=1$6A1B1e9sZrNceurghmzWiQ$v17JIRnYACQKRBs1QyWrxycoZI3Zv7A0DAn2uIhgFQo";

/// Run the dummy argon2id verify for the unknown-username branch, off the
/// async runtime exactly like the real verify (argon2 is slow by intent).
/// The result is discarded: whatever it says, the answer is the same 401.
async fn burn_dummy_verify(password: &str) -> Result<(), ApiError> {
    let password = password.to_string();
    let _ = tokio::task::spawn_blocking(move || {
        ws_auth::password::verify_password(&password, DUMMY_ARGON2_PHC)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("the password task failed: {e}")))?;
    Ok(())
}

/// The paired session tokens every auth flow returns.
#[derive(Debug, Serialize)]
struct SessionTokens {
    access_token: String,
    refresh_token: String,
}

/// The login body: username + password, plus the TOTP code when the
/// account has MFA enabled.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LoginBody {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub totp_code: Option<String>,
}

/// `POST /api/v1/auth/login` — public.
async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginBody>,
) -> Result<Json<SessionTokens>, ApiError> {
    let tenant = primary_tenant(&TenantRepo::new(), &state.pool).await?;
    let users = UserRepo::new();
    let user = match users
        .get_by_username(&state.pool, tenant.id, &body.username)
        .await?
    {
        Some(user) => user,
        None => {
            // Unknown user and wrong password are the SAME response (never
            // reveal which half was wrong) — and the same COST: the
            // unknown-username branch burns one argon2id verify so the
            // response timing cannot tell the two apart.
            burn_dummy_verify(&body.password).await?;
            return Err(ApiError::Unauthorized("invalid credentials".to_string()));
        }
    };

    // The lockout window: an account under lockout is refused before any
    // verification (the mapping table puts `AccountLocked` at 403).
    if let Some(locked_until) = user.locked_until {
        if locked_until > Utc::now() {
            return Err(ApiError::Forbidden("account is locked".to_string()));
        }
    }
    if !user.is_active {
        return Err(ApiError::Forbidden("account is disabled".to_string()));
    }
    let Some(hash) = user.password_hash.clone() else {
        return Err(ApiError::Unauthorized("invalid credentials".to_string()));
    };

    // Argon2id verification is deliberately slow — it runs in a blocking
    // thread so the runtime's worker threads are never stalled by it.
    let password = body.password.clone();
    let verified =
        tokio::task::spawn_blocking(move || ws_auth::password::verify_password(&password, &hash))
            .await
            .map_err(|e| ApiError::Internal(format!("the password task failed: {e}")))?
            .map_err(ApiError::from)?;
    if !verified {
        // Count the failure; lock the account out at the threshold.
        users.record_failed_login(&state.pool, user.id).await?;
        if let Some(updated) = users.get_by_id(&state.pool, user.id).await? {
            if updated.failed_login_attempts >= LOCKOUT_THRESHOLD {
                users
                    .lock_until(&state.pool, user.id, Utc::now() + LOCKOUT_WINDOW)
                    .await?;
            }
        }
        return Err(ApiError::Unauthorized("invalid credentials".to_string()));
    }

    // MFA: an enrolled-and-enabled account MUST present its code.
    if user.mfa_enabled {
        verify_totp_of_user(&state, &user, body.totp_code).await?;
    }

    // Login writes no audit row (a session's birth is recorded by the
    // refresh-token row itself) — but the account is unlocked and its
    // last-login bookkeeping catches up.
    users.clear_failed_logins(&state.pool, user.id).await?;
    users.touch_last_login(&state.pool, user.id).await?;

    let tokens = mint_session(&state, &user).await?;
    Ok(Json(tokens))
}

/// Verify the TOTP code of a user whose secret is stored (envelope-
/// sealed). Missing code is `MfaRequired` (401); wrong code is
/// `MfaInvalid` (401).
async fn verify_totp_of_user(
    state: &AppState,
    user: &UserModel,
    code: Option<String>,
) -> Result<(), ApiError> {
    let Some(code) = code else {
        return Err(ApiError::UnauthorizedMfa(
            "multi-factor authentication required".to_string(),
        ));
    };
    let (Some(encrypted), Some(nonce)) = (
        user.totp_secret_encrypted.clone(),
        user.totp_secret_nonce.clone(),
    ) else {
        return Err(ApiError::Internal(
            "the account has mfa enabled but carries no stored secret".to_string(),
        ));
    };
    let secret_box = state.secret_box()?;
    let secret = secret_box
        .open(&encrypted, &nonce)
        .map_err(ApiError::from)?;
    let secret = std::str::from_utf8(&secret)
        .map_err(|_| ApiError::Internal("the stored totp secret is not text".to_string()))?;
    match ws_auth::mfa_totp::verify_code(&user.username, secret, &code) {
        Ok(true) => Ok(()),
        Ok(false) | Err(AuthError::MfaInvalid) => Err(ApiError::Unauthorized(
            "invalid multi-factor code".to_string(),
        )),
        Err(other) => Err(ApiError::from(other)),
    }
}

/// `JwtKeys` carries its TTL as `u64` (the custody shape Task 5 pinned);
/// the claim-minting arithmetic is `i64`. A TTL beyond `i64::MAX` seconds
/// cannot be configured on any real volume, so the conversion cannot
/// fail in practice — the house default (15 minutes,
/// `DEFAULT_ACCESS_TTL_SECS`) is the fallback so the claim's `exp` can
/// never wrap into a negative timestamp.
fn claim_ttl_secs(keys: &ws_auth::jwt::JwtKeys) -> i64 {
    i64::try_from(keys.ttl_secs).unwrap_or(900)
}

/// The refresh body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RefreshBody {
    pub refresh_token: String,
}

/// `POST /api/v1/auth/refresh` — public (the presented token IS the
/// credential). Rotates the refresh token: the old one is dead the
/// moment the new one is returned (one atomic statement underneath).
async fn refresh(
    State(state): State<AppState>,
    Json(body): Json<RefreshBody>,
) -> Result<Json<SessionTokens>, ApiError> {
    let (refresh, user_id) = rotate_refresh_token(
        &body.refresh_token,
        &state.pool,
        None,
        None,
        &RefreshTokenRepo::new(),
    )
    .await
    .map_err(ApiError::from)?
    .ok_or_else(|| {
        ApiError::Unauthorized("refresh token is invalid, revoked, or expired".to_string())
    })?;

    let user = UserRepo::new()
        .get_by_id(&state.pool, user_id)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("account no longer exists".to_string()))?;
    if !user.is_active {
        return Err(ApiError::Forbidden("account is disabled".to_string()));
    }

    // The new access token carries the NEW refresh token's id as its
    // session id, so a revocation of the (only) live token kills it too.
    let claims = AccessClaims::new(
        user.id,
        &user.username,
        user.role.as_str(),
        Some(refresh.id),
        claim_ttl_secs(&state.jwt),
    );
    let access = issue_access_token(&claims, &state.jwt).map_err(ApiError::from)?;
    Ok(Json(SessionTokens {
        access_token: access,
        refresh_token: refresh.token,
    }))
}

/// Mint a session pair for a resolved user: a fresh refresh token (its
/// plaintext returned once) bound to an access token whose `sid` is the
/// refresh token's row id — the revocable session identity the audit row
/// records.
async fn mint_session(state: &AppState, user: &UserModel) -> Result<SessionTokens, ApiError> {
    let refresh = issue_refresh_token(
        &state.pool,
        user.tenant_id,
        user.id,
        None,
        None,
        &RefreshTokenRepo::new(),
    )
    .await
    .map_err(ApiError::from)?;
    let claims = AccessClaims::new(
        user.id,
        &user.username,
        user.role.as_str(),
        Some(refresh.id),
        claim_ttl_secs(&state.jwt),
    );
    let access = issue_access_token(&claims, &state.jwt).map_err(ApiError::from)?;
    Ok(SessionTokens {
        access_token: access,
        refresh_token: refresh.token,
    })
}

/// The logout body: the refresh token this session owns.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LogoutBody {
    pub refresh_token: String,
}

/// `POST /api/v1/auth/logout` — any authenticated actor; revokes ITS OWN
/// refresh token. The revocation and its `session_revoked` audit row
/// commit together.
async fn logout(
    auth: AuthActor,
    State(state): State<AppState>,
    Json(body): Json<LogoutBody>,
) -> Result<StatusCode, ApiError> {
    let user_id = user_id_of(&auth.0)?;
    let Some(token) =
        authenticate_refresh_token(&body.refresh_token, &state.pool, &RefreshTokenRepo::new())
            .await
            .map_err(ApiError::from)?
    else {
        // An unknown or malformed token revokes nothing — idempotent like
        // the house's unconditional revoke — but a 400 tells the caller
        // its body was not usable.
        return Err(ApiError::bad_request("malformed or unknown refresh token"));
    };

    // Its OWN token only: the token must belong to this user, and (when
    // the actor is a bound session) be the session the access token
    // carries as `sid`.
    if token.user_id != user_id || auth.0.session_id.is_some_and(|sid| sid != token.id) {
        return Err(ApiError::Forbidden(
            "the refresh token is not this session's".to_string(),
        ));
    }

    let mut tx = state.pool.begin().await?;
    RefreshTokenRepo::new().revoke(&mut *tx, token.id).await?;
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &auth.0,
                "session_revoked",
                "session",
                &token.id.to_string(),
                serde_json::json!({}),
            ),
        )
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/auth/me` — any authenticated actor.
async fn me(auth: AuthActor, State(state): State<AppState>) -> Result<Json<MeResponse>, ApiError> {
    let mut response = MeResponse {
        actor_type: auth.actor_type.to_string(),
        actor_id: auth.actor_id.clone(),
        tenant_id: auth.tenant_id,
        capabilities: auth
            .capabilities
            .iter()
            .map(|capability| capability.as_str().to_string())
            .collect(),
        username: None,
        display_name: None,
        role: None,
        mfa_enabled: None,
        sealed_volume: state.sealed_volume(),
    };
    if auth.actor_type == ActorType::User {
        let user = UserRepo::new()
            .get_by_id(&state.pool, user_id_of(&auth.0)?)
            .await?
            .ok_or_else(|| ApiError::NotFound("the account no longer exists".to_string()))?;
        response.username = Some(user.username);
        response.display_name = Some(user.display_name);
        response.role = Some(user.role.as_str().to_string());
        response.mfa_enabled = Some(user.mfa_enabled);
    }
    Ok(Json(response))
}

/// The `me` response: the actor's identity and capability set; the user's
/// own fields only when the actor is a human session.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct MeResponse {
    pub actor_type: String,
    pub actor_id: String,
    pub tenant_id: Uuid,
    pub capabilities: Vec<String>,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub role: Option<String>,
    pub mfa_enabled: Option<bool>,
    /// Whether the serving state is an unlocked sealed volume: the SPA
    /// gates its admin surface's passphrase-change entry on it (the
    /// legacy plaintext world carries `false`).
    pub sealed_volume: bool,
}

/// The TOTP mutation bodies (`activate`/`deactivate` verify a code).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TotpCodeBody {
    pub code: String,
}

/// The enroll response: the base32 secret (shown once to scan/configure)
/// and the otpauth:// provisioning URI.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TotpEnrolled {
    pub secret: String,
    pub provisioning_uri: String,
}

/// `POST /api/v1/auth/totp/enroll` — any authenticated actor, its OWN
/// account. Stores the sealed pending secret (NOT yet enabled) and writes
/// the `mfa_enrolled` audit row in the same transaction.
async fn totp_enroll(
    auth: AuthActor,
    State(state): State<AppState>,
) -> Result<Json<TotpEnrolled>, ApiError> {
    let user = owned_user(&auth, &state).await?;
    if user.mfa_enabled {
        return Err(ApiError::Conflict("mfa is already active".to_string()));
    }

    let secret = ws_auth::mfa_totp::generate_secret().map_err(ApiError::from)?;
    let provisioning_uri =
        ws_auth::mfa_totp::provisioning_uri(TOTP_ISSUER, &user.username, &secret);
    let secret_box = state.secret_box()?;
    let (encrypted, nonce) = secret_box.seal(secret.as_bytes()).map_err(ApiError::from)?;

    let mut tx = state.pool.begin().await?;
    UserRepo::new()
        .update_totp_credential(
            &mut *tx,
            user.id,
            Some(encrypted),
            Some(nonce),
            user.mfa_enabled,
        )
        .await?;
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &auth.0,
                "mfa_enrolled",
                "user",
                &user.id.to_string(),
                serde_json::json!({}),
            ),
        )
        .await?;
    tx.commit().await?;

    Ok(Json(TotpEnrolled {
        secret,
        provisioning_uri,
    }))
}

/// `POST /api/v1/auth/totp/activate` — verifies the first code against
/// the enrolled secret, then enables MFA; the `mfa_activated` audit row
/// commits with the flag flip.
async fn totp_activate(
    auth: AuthActor,
    State(state): State<AppState>,
    Json(body): Json<TotpCodeBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = owned_user(&auth, &state).await?;
    if has_stored_secret(&user).is_none() {
        return Err(ApiError::Conflict(
            "totp is not enrolled; call /auth/totp/enroll first".to_string(),
        ));
    }
    verify_totp_of_user(&state, &user, Some(body.code)).await?;

    let mut tx = state.pool.begin().await?;
    UserRepo::new()
        .update_totp_credential(
            &mut *tx,
            user.id,
            user.totp_secret_encrypted.clone(),
            user.totp_secret_nonce.clone(),
            true,
        )
        .await?;
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &auth.0,
                "mfa_activated",
                "user",
                &user.id.to_string(),
                serde_json::json!({}),
            ),
        )
        .await?;
    tx.commit().await?;
    Ok(Json(serde_json::json!({ "mfa_enabled": true })))
}

/// `POST /api/v1/auth/totp/deactivate` — verifies a code against the
/// active secret, then clears the credential and the flag; the
/// `mfa_deactivated` audit row commits with the clear.
async fn totp_deactivate(
    auth: AuthActor,
    State(state): State<AppState>,
    Json(body): Json<TotpCodeBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = owned_user(&auth, &state).await?;
    if !user.mfa_enabled {
        return Err(ApiError::Conflict("mfa is not active".to_string()));
    }
    verify_totp_of_user(&state, &user, Some(body.code)).await?;

    let mut tx = state.pool.begin().await?;
    UserRepo::new()
        .update_totp_credential(&mut *tx, user.id, None, None, false)
        .await?;
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &auth.0,
                "mfa_deactivated",
                "user",
                &user.id.to_string(),
                serde_json::json!({}),
            ),
        )
        .await?;
    tx.commit().await?;
    Ok(Json(serde_json::json!({ "mfa_enabled": false })))
}

/// The human user BEHIND the actor — the route operates on its own
/// account, so a machine actor (no user account) is refused 403.
async fn owned_user(auth: &AuthActor, state: &AppState) -> Result<UserModel, ApiError> {
    let user_id = user_id_of(&auth.0)?;
    UserRepo::new()
        .get_by_id(&state.pool, user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("the account no longer exists".to_string()))
}

/// The stored TOTP credential pair (or `None` when nothing is stored).
fn has_stored_secret(user: &UserModel) -> Option<()> {
    match (
        user.totp_secret_encrypted.is_some(),
        user.totp_secret_nonce.is_some(),
    ) {
        (true, true) => Some(()),
        _ => None,
    }
}

/// `GET /api/v1/auth/oidc/{provider}/start` — public. Resolves the
/// provider config, MINTS and stores the csrf state (the Task 3 R8
/// contract: the callback validates it; `exchange_code` deliberately does
/// NOT), and redirects to the provider's authorization endpoint with the
/// state parameter.
async fn oidc_start(
    State(state): State<AppState>,
    Path(provider): Path<String>,
) -> Result<Redirect, ApiError> {
    let tenant = primary_tenant(&TenantRepo::new(), &state.pool).await?;
    let config = provider_config(&state, tenant.id, &provider).await?;
    let state_token = state.oidc_states.mint(tenant.id).map_err(ApiError::from)?;

    // The authorization URL needs the provider's `authorization_endpoint`
    // — one discovery fetch on the start route. The state is already in
    // the store, so a (transient) network failure here can never mint a
    // state the user's browser still carries: the callback validates only
    // states minted and stored.
    let discovery = match ws_auth::oidc::discover(&config).await {
        Ok(discovery) => discovery,
        Err(e) => {
            tracing::warn!(error = %e, "oidc discovery failed on the start route");
            return Err(ApiError::from(e));
        }
    };

    let url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
        discovery.authorization_endpoint,
        url_encode(&config.client_id),
        url_encode(&config.redirect_uri),
        url_encode(&config.scopes),
        url_encode(&state_token),
    );
    Ok(Redirect::to(&url))
}

/// The query parameters of the callback.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OidcCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
}

/// `GET /api/v1/auth/oidc/{provider}/callback` — public. Validates AND
/// consumes the csrf state (a replayed state validates exactly once),
/// exchanges the code, matches/link/creates the account, and returns the
/// session tokens.
///
/// Provider account resolution: by `oidc_sub`, else — only for a
/// provider-VERIFIED email — matched-by-email (linked), else a new user.
async fn oidc_callback(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Query(query): Query<OidcCallbackQuery>,
) -> Result<Json<SessionTokens>, ApiError> {
    let code = query
        .code
        .filter(|code| !code.is_empty())
        .ok_or_else(|| ApiError::bad_request("the provider sent no code parameter"))?;
    let state_token = query
        .state
        .filter(|token| !token.is_empty())
        .ok_or_else(|| ApiError::Unauthorized("missing oidc state parameter".to_string()))?;

    // Task 3's R8: the csrf state is validated and consumed HERE, before
    // any token exchange. An unknown, expired, or replayed state is 401.
    let tenant_id = state.oidc_states.consume(&state_token).ok_or_else(|| {
        ApiError::Unauthorized("unknown, expired, or replayed oidc state".to_string())
    })?;

    let config = provider_config(&state, tenant_id, &provider).await?;
    let discovery = match ws_auth::oidc::discover(&config).await {
        Ok(discovery) => discovery,
        Err(e) => {
            tracing::warn!(error = %e, "oidc discovery failed on the callback route");
            return Err(ApiError::from(e));
        }
    };

    // R10: a token-endpoint rejection carries detail worth logging — the
    // handler warns with the typed error (its messages are static and
    // never carry the client_secret) before it maps to the user-facing
    // error.
    let identity =
        match ws_auth::oidc::exchange_code(&config, &discovery, &code, &state_token).await {
            Ok(identity) => identity,
            Err(e) => {
                tracing::warn!(error = ?e, "oidc code exchange rejected by the provider");
                return Err(ApiError::from(e));
            }
        };

    let user = resolve_oidc_user(&state, tenant_id, &identity).await?;
    if !user.is_active {
        return Err(ApiError::Forbidden("account is disabled".to_string()));
    }
    UserRepo::new()
        .touch_last_login(&state.pool, user.id)
        .await?;
    let tokens = mint_session(&state, &user).await?;
    Ok(Json(tokens))
}

/// The per-tenant configured provider row for `{provider}` — the row's
/// `provider_type` must equal the label in the path; anything else is a
/// 404 (the provider is not configured).
async fn provider_config(
    state: &AppState,
    tenant_id: Uuid,
    provider: &str,
) -> Result<ws_auth::oidc::OidcConfig, ApiError> {
    let row = OidcConfigRepo::new()
        .get(&state.pool, tenant_id)
        .await?
        .filter(|row| row.provider_type == provider)
        .ok_or_else(|| ApiError::NotFound(format!("provider {provider:?} is not configured")))?;
    Ok(ws_auth::oidc::OidcConfig {
        provider_type: row.provider_type,
        display_name: row.display_name,
        discovery_url: row.discovery_url,
        client_id: row.client_id,
        client_secret: row.client_secret,
        redirect_uri: row.redirect_uri,
        scopes: row.scopes,
    })
}

/// Match the verified provider identity to an account: by `oidc_sub`
/// (first-login linkage done), else by verified email (link now), else
/// create the account — the creation and its `user_created` audit row
/// commit together.
async fn resolve_oidc_user(
    state: &AppState,
    tenant_id: Uuid,
    identity: &ws_auth::oidc::OidcIdentity,
) -> Result<UserModel, ApiError> {
    let users = UserRepo::new();
    if let Some(user) = users
        .get_by_oidc_sub(&state.pool, tenant_id, &identity.subject)
        .await?
    {
        return Ok(user);
    }
    // Link-by-email ONLY with a provider-verified email: an unverified
    // email claim is attacker-controllable for most providers, and
    // linking one would be an account takeover.
    if identity.email_verified == Some(true) {
        if let Some(email) = &identity.email {
            if let Some(user) = users.get_by_email(&state.pool, tenant_id, email).await? {
                users
                    .link_oidc_sub(&state.pool, user.id, &identity.subject)
                    .await?;
                return users
                    .get_by_id(&state.pool, user.id)
                    .await?
                    .ok_or_else(|| ApiError::NotFound("the account no longer exists".to_string()));
            }
        }
    }
    create_oidc_user(state, tenant_id, identity).await
}

/// Create the SSO account: role `viewer` (least privilege — the operator
/// grants more explicitly), `auth_provider = "oidc"`, the subject stored.
/// The email is the account's unique identifier — an identity without a
/// verified-claim-matchable email cannot become an account.
async fn create_oidc_user(
    state: &AppState,
    tenant_id: Uuid,
    identity: &ws_auth::oidc::OidcIdentity,
) -> Result<UserModel, ApiError> {
    let email = identity.email.clone().ok_or_else(|| {
        ApiError::bad_request(
            "the provider identity carries no email claim; an account cannot be created",
        )
    })?;
    let username = username_for(
        &identity
            .display_name
            .clone()
            .unwrap_or_else(|| email.clone()),
    );
    let display_name = identity
        .display_name
        .clone()
        .unwrap_or_else(|| username.clone());
    let user = UserModel {
        id: Uuid::new_v4(),
        tenant_id,
        username,
        display_name,
        email,
        role: Role::Viewer,
        auth_provider: "oidc".to_string(),
        password_hash: None,
        totp_secret_encrypted: None,
        totp_secret_nonce: None,
        webauthn_credential: None,
        mfa_enabled: false,
        azure_oid: None,
        oidc_sub: Some(identity.subject.clone()),
        is_active: true,
        force_password_reset: false,
        failed_login_attempts: 0,
        locked_until: None,
        last_login_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let mut tx = state.pool.begin().await?;
    UserRepo::new().insert(&mut *tx, &user).await?;
    // The actor here is the SSO flow itself — no session, no user id yet
    // (the CREATED account is the target). `actor_type = system` with a
    // static actor id names the flow in the log.
    let flow = Actor {
        actor_type: ActorType::System,
        actor_id: "oidc-callback".to_string(),
        auth_method: AuthMethod::System,
        capabilities: vec![],
        session_id: None,
        tenant_id,
        minted_by: None,
    };
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &flow,
                "user_created",
                "user",
                &user.id.to_string(),
                serde_json::json!({ "role": user.role.as_str() }),
            ),
        )
        .await?;
    tx.commit().await?;
    Ok(user)
}

/// Derive a username from the identity's display name (or email): ASCII
/// alphanumerics plus `.`, `_`, `-`, truncated to 64 chars; a name with
/// no usable character falls back to `user`.
fn username_for(raw: &str) -> String {
    let sanitized: String = raw
        .chars()
        .take(64)
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    if sanitized.is_empty() {
        "user".to_string()
    } else {
        sanitized
    }
}

/// Minimal percent-encoding for the authorization-redirect query
/// parameters (client id, redirect URI, scopes, state) — no extra crate
/// for the three reserved characters this endpoint ever carries.
fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}
