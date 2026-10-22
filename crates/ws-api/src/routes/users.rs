//! The user-management routes: list, create, patch, deactivate.
//!
//! Route capabilities (the plan's table): the list is `read_users`, the
//! create, patch, and deactivate are `manage_users`. The create, patch,
//! and deactivate write their `user_created` / `user_role_changed` /
//! `user_activated` / `user_deactivated` audit rows in the SAME
//! transaction as the change. User responses never carry password hashes
//! or sealed MFA material.

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{patch, post};
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
        .route("/{id}", patch(patch_user))
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

/// The body of the patch route: either or both fields. The role is the
/// serde [`Role`] directly — any unknown spelling is a serde rejection
/// into the extractor, mapped to 400 `bad_request` (never axum's default
/// 422 rejection, whose body shape the SPA's error handling cannot read —
/// the house idiom the revoke route pinned).
#[derive(Debug, Deserialize)]
pub struct UpdateUserBody {
    #[serde(default)]
    pub role: Option<Role>,
    #[serde(default)]
    pub is_active: Option<bool>,
}

/// `PATCH /api/v1/users/{id}` — `manage_users`: role assignment and
/// account activation in one route. A `role` change writes
/// `user_role_changed` (details `{"from": ..., "to": ...}`);
/// `is_active: false` is the [`UserRepo::deactivate`] path with the
/// existing `user_deactivated` row; `is_active: true` is the
/// [`UserRepo::set_active`] path with the NEW `user_activated` row. Both
/// fields in one request apply role first, then the flag — in ONE
/// transaction, so every audit row commits or rolls back with the change.
/// A field naming the state the user already has is a no-op (no second
/// audit row), mirroring the deactivate route's idempotence; re-activation
/// has no special cases beyond the boolean — an SSO/OAuth identity returns
/// to the login path with its provider linkage untouched, because the
/// `users` row carries one `is_active` flag.
///
/// The last-admin guard [plan binding]: a change that would leave ZERO
/// active `Admin` users in the tenant (the role out of `Admin`, or
/// `is_active: false` onto an active admin) is refused `409` with the
/// fixed message. The count runs INSIDE the same transaction as the
/// update, but it is a NON-LOCKING read: under READ COMMITTED, two
/// concurrent PATCHes demoting two DIFFERENT active admins can each count
/// 2, both pass the guard, and both commit — leaving zero active admins.
/// That residual race is accepted (the single-operator UI cannot issue
/// two concurrent admin demotions against itself; a `FOR UPDATE` locking
/// count was considered and parked for the final review's triage, so only
/// the pinned in-transaction count is here). The acting actor may change
/// or deactivate THEMSELVES when they are not the last admin — the count
/// is tenant-wide, not actor-relative. Another tenant's user (or an
/// absent one) is a 404, indistinguishably.
async fn patch_user(
    auth: AuthActor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    body: Result<Json<UpdateUserBody>, JsonRejection>,
) -> Result<Json<UserResponse>, ApiError> {
    auth.require(Capability::ManageUsers)
        .map_err(ApiError::from)?;
    let Json(body) = body.map_err(|rejection| ApiError::BadRequest {
        code: "bad_request",
        message: rejection.body_text(),
    })?;
    let UpdateUserBody { role, is_active } = body;
    if role.is_none() && is_active.is_none() {
        return Err(ApiError::bad_request("nothing to update"));
    }

    // Tenant-scoped resolve: the row feeds the audit's `from`, the guard
    // condition, and the idempotence no-ops; a foreign or absent user is
    // a 404, indistinguishably.
    let user = UserRepo::new()
        .get_by_id(&state.pool, id)
        .await?
        .filter(|user| user.tenant_id == auth.tenant_id)
        .ok_or_else(|| ApiError::NotFound("user not found".to_string()))?;

    // Whether the requested change removes this row from the ACTIVE admin
    // pool: the count is only ever needed for exactly that case.
    let removes_active_admin = user.role == Role::Admin
        && user.is_active
        && (role.is_some_and(|new_role| new_role != Role::Admin) || is_active == Some(false));

    let mut tx = state.pool.begin().await?;
    if removes_active_admin {
        let active_admins: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM users \
             WHERE tenant_id = $1 AND role = 'admin' AND is_active = TRUE",
        )
        .bind(auth.tenant_id)
        .fetch_one(&mut *tx)
        .await?;
        if active_admins <= 1 {
            return Err(ApiError::Conflict(
                "refusing to remove the last active administrator".to_string(),
            ));
        }
    }

    // Role first, then the flag; the audit rows ride the same tx.
    if let Some(new_role) = role.filter(|new_role| *new_role != user.role) {
        UserRepo::new().update_role(&mut *tx, id, new_role).await?;
        AuditRepo::new()
            .record(
                &mut *tx,
                &audit_entry(
                    &auth.0,
                    "user_role_changed",
                    "user",
                    &id.to_string(),
                    serde_json::json!({
                        "from": user.role.as_str(),
                        "to": new_role.as_str()
                    }),
                ),
            )
            .await?;
    }
    if let Some(active) = is_active {
        if active && !user.is_active {
            UserRepo::new().set_active(&mut *tx, id, true).await?;
            AuditRepo::new()
                .record(
                    &mut *tx,
                    &audit_entry(
                        &auth.0,
                        "user_activated",
                        "user",
                        &id.to_string(),
                        serde_json::json!({}),
                    ),
                )
                .await?;
        } else if !active && user.is_active {
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
        }
    }
    tx.commit().await?;

    // A fresh read after the commit, the shape list/create respond with.
    let fresh = UserRepo::new()
        .get_by_id(&state.pool, id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".to_string()))?;
    Ok(Json(UserResponse::of(&fresh)))
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
