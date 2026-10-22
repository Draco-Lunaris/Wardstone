//! The bearer-credential extractor: one `Authorization` header, two
//! credential shapes, one resolved [`Actor`].
//!
//! Bearer resolution order (the plan's pin):
//!
//! 1. a value with **three dot-separated segments is a JWT** (the session
//!    access token): validated against `JwtKeys`, the user resolved from
//!    the claims, and the capabilities read from the user's CURRENT role
//!    bundle (the `role_capabilities` table is the runtime authority);
//! 2. a value starting **`ws_at_` is an API token** (`ws-auth`'s service
//!    identity resolution, carrying the token's granted capabilities);
//! 3. a value starting **`ws_ot_` is a one-shot token** — refused here
//!    with 401 WITHOUT a lookup: a one-shot redeems ONLY at the pull
//!    route (`/certificates/pull`), whose handler claims it inside its
//!    issuance transaction. Resolving it here would hand a fixed
//!    `Issue` grant to every authenticated route, so the rejection is
//!    static — a stray bearer never burns the token and never resolves;
//! 4. anything else is 401.
//!
//! [`AuthActor`] is a newtype wrapper around `ws_core`'s [`Actor`]:
//! axum's `FromRequestParts` is a foreign trait and `Actor` is a foreign
//! type, so implementing the extractor for the actor directly would
//! violate the orphan rule (E0117). The wrapper is the only newtype —
//! the actor type itself stays single-sourced in `ws-core`, and the
//! wrapper derefs to it.
//!
//! Authorization (capability checks) stays in the handlers; this
//! middleware is authentication only.

use std::ops::Deref;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use uuid::Uuid;

use ws_auth::jwt::validate_access_token;
use ws_auth::service_identity::authenticate_token;
use ws_core::models::rbac::{Actor, ActorType};
use ws_core::repo::credential_repo::CredentialRepo;
use ws_core::repo::role_repo::RoleRepo;
use ws_core::repo::user_repo::UserRepo;

use crate::error::ApiError;
use crate::state::AppState;

/// An extracted actor: the resolved authentication context of the
/// request. Deref-shares the wrapped [`Actor`].
#[derive(Debug, Clone)]
pub struct AuthActor(pub Actor);

impl Deref for AuthActor {
    type Target = Actor;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for AuthActor
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app = AppState::from_ref(state);
        resolve_bearer_actor(&app, &parts.headers)
            .await
            .map(AuthActor)
    }
}

/// The bearer prefix, matched case-insensitively like every other HTTP
/// bearer consumer.
const BEARER_PREFIX: &str = "bearer ";

/// Resolve the request's `Authorization` header to its [`Actor`] per the
/// resolution order in the module docs.
pub async fn resolve_bearer_actor(
    app: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<Actor, ApiError> {
    let Some(header) = headers.get(axum::http::header::AUTHORIZATION) else {
        return Err(ApiError::Unauthorized(
            "missing Authorization bearer token".to_string(),
        ));
    };
    let value = header.to_str().map_err(|_| {
        ApiError::Unauthorized("Authorization header is not valid text".to_string())
    })?;
    let token = value
        .strip_prefix(BEARER_PREFIX)
        .or_else(|| value.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::Unauthorized("Authorization scheme must be Bearer".to_string()))?;

    // Three dot-separated segments: the JWT session access token.
    if token.split('.').count() == 3 {
        return resolve_session_actor(app, token).await;
    }
    if token.starts_with(ws_auth::service_identity::TOKEN_PREFIX) {
        return resolve_api_token_actor(app, token).await;
    }
    if token.starts_with(ws_auth::one_shot::TOKEN_PREFIX) {
        // A one-shot token is a pull-route credential: it redeems ONLY at
        // the certificate pull route, whose handler claims it inside its
        // issuance transaction. Here it is 401 WITHOUT a lookup — a stray
        // bearer never burns, and resolving it (lookup-only as that would
        // be) would hand its fixed `Issue` grant to this route.
        return Err(ApiError::Unauthorized(
            "credentials not accepted here (one-shot tokens redeem only at the \
             certificate pull route)"
                .to_string(),
        ));
    }
    Err(ApiError::Unauthorized(
        "unrecognized credential shape (expected a session JWT or ws_at_ token)".to_string(),
    ))
}

/// The JWT path: validate the signature/expiry, then resolve the CURRENT
/// user and role bundle. A token minted for a since-deleted or disabled
/// account does not authenticate.
async fn resolve_session_actor(app: &AppState, token: &str) -> Result<Actor, ApiError> {
    let claims = validate_access_token(token, &app.jwt).map_err(ApiError::from)?;
    let user_id = claims.user_id;
    let user = UserRepo::new()
        .get_by_id(&app.pool, user_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::Unauthorized(format!("user {user_id} no longer exists")))?;
    if !user.is_active {
        // Authentication material that cannot authenticate: 401, not 403 —
        // the account's deactivation is an account fact, not a capability
        // decision about THIS route. (A disabled account is the same shape
        // for every route, so it is an authentication outcome.)
        return Err(ApiError::Unauthorized("account is disabled".to_string()));
    }
    let capabilities = RoleRepo::new()
        .capabilities_for_role(&app.pool, user.role)
        .await
        .map_err(ApiError::from)?;
    Ok(Actor {
        actor_type: ActorType::User,
        actor_id: user.id.to_string(),
        auth_method: ws_core::models::rbac::AuthMethod::Session,
        capabilities,
        session_id: claims.sid,
        tenant_id: user.tenant_id,
        minted_by: None,
    })
}

/// The API-token path: resolve the stored identity (its capabilities are
/// the token's grant; revocation and expiry are handled inside ws-auth).
async fn resolve_api_token_actor(app: &AppState, token: &str) -> Result<Actor, ApiError> {
    authenticate_token(token, &app.pool, &CredentialRepo::new())
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| {
            ApiError::Unauthorized("api token is unknown, revoked, or expired".to_string())
        })
}

/// The user id behind a human-session actor: [`ActorType::User`] resolves
/// its `actor_id`, every other actor type has no user account and is
/// refused with 403 (the routes this guards operate on "its own
/// account", which a machine actor does not have).
pub fn user_id_of(actor: &Actor) -> Result<Uuid, ApiError> {
    match actor.actor_type {
        ActorType::User => Uuid::parse_str(&actor.actor_id)
            .map_err(|_| ApiError::Internal("the session actor id is not a user id".to_string())),
        _ => Err(ApiError::Forbidden(
            "this operation requires a human user account".to_string(),
        )),
    }
}
