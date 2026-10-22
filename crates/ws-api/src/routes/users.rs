//! The user-management routes: list, create, deactivate.
//!
//! Route capabilities (the plan's table): the list is `read_users`, the
//! create and the deactivate are `manage_users`. The create and the
//! deactivate write their `user_created` / `user_deactivated` audit rows
//! in the SAME transaction as the change. User responses never carry
//! password hashes or sealed MFA material.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use ws_core::models::rbac::{Capability, Role};
use ws_core::models::user::UserModel;
use ws_core::repo::audit_repo::AuditRepo;
use ws_core::repo::user_repo::UserRepo;

use crate::auth_middleware::AuthActor;
use crate::error::ApiError;
use crate::routes::{audit_entry, ListQuery};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_user).get(list_users))
        .route("/{id}/deactivate", post(deactivate_user))
}

/// One user, as a read DTO — no password hash, no sealed MFA bytes.
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub role: String,
    pub auth_provider: String,
    pub mfa_enabled: bool,
    pub is_active: bool,
    pub force_password_reset: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl UserResponse {
    fn of(user: &UserModel) -> Self {
        UserResponse {
            id: user.id,
            tenant_id: user.tenant_id,
            username: user.username.clone(),
            display_name: user.display_name.clone(),
            email: user.email.clone(),
            role: user.role.as_str().to_string(),
            auth_provider: user.auth_provider.clone(),
            mfa_enabled: user.mfa_enabled,
            is_active: user.is_active,
            force_password_reset: user.force_password_reset,
            last_login_at: user.last_login_at,
            created_at: user.created_at,
        }
    }
}

/// The create body: a local account with a password (hashed argon2id).
#[derive(Debug, Deserialize)]
pub struct CreateUserBody {
    pub username: String,
    #[serde(default)]
    pub display_name: String,
    pub email: String,
    pub role: String,
    pub password: String,
}

/// `POST /api/v1/users` — `manage_users`. The `user_created` audit
/// details carry the role.
async fn create_user(
    auth: AuthActor,
    State(state): State<AppState>,
    Json(body): Json<CreateUserBody>,
) -> Result<(StatusCode, Json<UserResponse>), ApiError> {
    auth.require(Capability::ManageUsers)
        .map_err(ApiError::from)?;
    let username = body.username.trim();
    if username.is_empty() {
        return Err(ApiError::bad_request("a username is required"));
    }
    if body.email.trim().is_empty() {
        return Err(ApiError::bad_request("an email is required"));
    }
    let role = Role::from_str(&body.role)
        .ok_or_else(|| ApiError::bad_request(format!("unknown role {:?}", body.role)))?;
    if body.password.is_empty() {
        return Err(ApiError::bad_request("a password is required"));
    }

    // Argon2id hashing is deliberately slow — blocking thread.
    let password = body.password.clone();
    let password_hash =
        tokio::task::spawn_blocking(move || ws_auth::password::hash_password(&password))
            .await
            .map_err(|e| ApiError::Internal(format!("the password task failed: {e}")))?
            .map_err(ApiError::from)?;

    let user = UserModel {
        id: Uuid::new_v4(),
        tenant_id: auth.tenant_id,
        username: username.to_string(),
        display_name: if body.display_name.is_empty() {
            username.to_string()
        } else {
            body.display_name.clone()
        },
        email: body.email.trim().to_string(),
        role,
        auth_provider: "local".to_string(),
        password_hash: Some(password_hash),
        totp_secret_encrypted: None,
        totp_secret_nonce: None,
        webauthn_credential: None,
        mfa_enabled: false,
        azure_oid: None,
        oidc_sub: None,
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
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &auth.0,
                "user_created",
                "user",
                &user.id.to_string(),
                serde_json::json!({ "role": user.role.as_str() }),
            ),
        )
        .await?;
    tx.commit().await?;

    Ok((StatusCode::CREATED, Json(UserResponse::of(&user))))
}

/// `POST /api/v1/users/{id}/deactivate` — `manage_users`; the only
/// user-removal path. The `user_deactivated` audit row commits with the
/// flag flip; deactivating an already-deactivated user changes nothing
/// and writes no second row; another tenant's user is a 404.
async fn deactivate_user(
    auth: AuthActor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    auth.require(Capability::ManageUsers)
        .map_err(ApiError::from)?;
    let user = UserRepo::new()
        .get_by_id(&state.pool, id)
        .await?
        .filter(|user| user.tenant_id == auth.tenant_id)
        .ok_or_else(|| ApiError::NotFound("user not found".to_string()))?;
    if !user.is_active {
        return Ok(StatusCode::NO_CONTENT);
    }
    if Uuid::parse_str(&auth.actor_id).ok() == Some(id) {
        // Self-deactivation would lock the operator out of their own
        // account mid-session; require another actor to do it.
        return Err(ApiError::bad_request(
            "an actor cannot deactivate its own account",
        ));
    }

    let mut tx = state.pool.begin().await?;
    UserRepo::new().deactivate(&mut *tx, id).await?;
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &auth.0,
                "user_deactivated",
                "user",
                &id.to_string(),
                serde_json::json!({}),
            ),
        )
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/users` — `read_users`.
async fn list_users(
    auth: AuthActor,
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<UserResponse>>, ApiError> {
    auth.require(Capability::ReadUsers)
        .map_err(ApiError::from)?;
    let users = UserRepo::new()
        .list_by_tenant(&state.pool, auth.tenant_id, query.page(), query.page_size())
        .await?
        .iter()
        .map(UserResponse::of)
        .collect();
    Ok(Json(users))
}
