//! Repository over the `users` table.

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::error::CoreError;
use crate::models::rbac::Role;
use crate::models::user::UserModel;
use crate::repo::tenant_repo::map_unique;

/// Data access for [`UserModel`] rows.
///
/// Stateless by design: the repository holds no pool, and every method
/// takes `executor: impl PgExecutor<'_>` so a mutation and its audit row
/// can share one transaction (callers pass `&pool`, or `&mut *tx` inside a
/// transaction — `&mut Transaction` does not implement `PgExecutor` in
/// sqlx 0.8.6).
#[derive(Default)]
pub struct UserRepo;

/// Inline row shape for `sqlx::query_as` (house style: hand-mapped to the
/// model). `role` is the raw text column, decoded via `Role::from_str`;
/// the BYTEA columns decode into `Vec<u8>` and `webauthn_credential` into
/// the jsonb payload.
#[derive(sqlx::FromRow)]
struct UserRow {
    id: Uuid,
    tenant_id: Uuid,
    username: String,
    display_name: String,
    email: String,
    role: String,
    auth_provider: String,
    password_hash: Option<String>,
    totp_secret_encrypted: Option<Vec<u8>>,
    totp_secret_nonce: Option<Vec<u8>>,
    webauthn_credential: Option<JsonValue>,
    mfa_enabled: bool,
    azure_oid: Option<String>,
    oidc_sub: Option<String>,
    is_active: bool,
    force_password_reset: bool,
    failed_login_attempts: i32,
    locked_until: Option<DateTime<Utc>>,
    last_login_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// The user row's column list and table, shared by every read query.
const USER_FROM: &str =
    "SELECT id, tenant_id, username, display_name, email, role, auth_provider, password_hash, \
     totp_secret_encrypted, totp_secret_nonce, webauthn_credential, mfa_enabled, azure_oid, \
     oidc_sub, is_active, force_password_reset, failed_login_attempts, locked_until, \
     last_login_at, created_at, updated_at FROM users";

impl UserRow {
    /// Decode a row into the domain model, mapping `role` through
    /// `Role::from_str`; an unknown stored role is data-level damage and a
    /// [`CoreError::Config`], not a per-request failure.
    fn try_into_model(self) -> Result<UserModel, CoreError> {
        let role = Role::from_str(&self.role).ok_or_else(|| {
            CoreError::Config(format!("invalid role in users row: {:?}", self.role))
        })?;
        Ok(UserModel {
            id: self.id,
            tenant_id: self.tenant_id,
            username: self.username,
            display_name: self.display_name,
            email: self.email,
            role,
            auth_provider: self.auth_provider,
            password_hash: self.password_hash,
            totp_secret_encrypted: self.totp_secret_encrypted,
            totp_secret_nonce: self.totp_secret_nonce,
            webauthn_credential: self.webauthn_credential,
            mfa_enabled: self.mfa_enabled,
            azure_oid: self.azure_oid,
            oidc_sub: self.oidc_sub,
            is_active: self.is_active,
            force_password_reset: self.force_password_reset,
            failed_login_attempts: self.failed_login_attempts,
            locked_until: self.locked_until,
            last_login_at: self.last_login_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

impl UserRepo {
    /// Build the (stateless) repository.
    ///
    /// The body is the plan's house shape verbatim
    /// (`Self::default()`), satisfied by the derived `Default`
    /// (`clippy::new_without_default` is an error here under the house
    /// rule); the allow silences the newer, contradicting
    /// `clippy::default_constructed_unit_structs` style lint, which the
    /// house shape deliberately does not adopt.
    #[allow(clippy::default_constructed_unit_structs)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a user row exactly as given (every field, `created_at` and
    /// `updated_at` included: the model is authoritative, so `get` returns
    /// the same row). A unique-violation on `(tenant_id, username)`,
    /// `(tenant_id, email)`, `(tenant_id, oidc_sub)` or
    /// `(tenant_id, azure_oid)` becomes [`CoreError::Duplicate`].
    pub async fn insert(
        &self,
        executor: impl PgExecutor<'_>,
        u: &UserModel,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "INSERT INTO users (id, tenant_id, username, display_name, email, role, \
             auth_provider, password_hash, totp_secret_encrypted, totp_secret_nonce, \
             webauthn_credential, mfa_enabled, azure_oid, oidc_sub, is_active, \
             force_password_reset, failed_login_attempts, locked_until, last_login_at, \
             created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, \
             $17, $18, $19, $20, $21)",
        )
        .bind(u.id)
        .bind(u.tenant_id)
        .bind(&u.username)
        .bind(&u.display_name)
        .bind(&u.email)
        .bind(u.role.as_str())
        .bind(&u.auth_provider)
        .bind(&u.password_hash)
        .bind(&u.totp_secret_encrypted)
        .bind(&u.totp_secret_nonce)
        .bind(&u.webauthn_credential)
        .bind(u.mfa_enabled)
        .bind(&u.azure_oid)
        .bind(&u.oidc_sub)
        .bind(u.is_active)
        .bind(u.force_password_reset)
        .bind(u.failed_login_attempts)
        .bind(u.locked_until)
        .bind(u.last_login_at)
        .bind(u.created_at)
        .bind(u.updated_at)
        .execute(executor)
        .await
        .map_err(map_unique)?;
        Ok(())
    }

    /// Look a user up by per-tenant-unique username; `None` when absent.
    pub async fn get_by_username(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        username: &str,
    ) -> Result<Option<UserModel>, CoreError> {
        let row: Option<UserRow> = sqlx::query_as(&format!(
            "{USER_FROM} WHERE tenant_id = $1 AND username = $2"
        ))
        .bind(tenant_id)
        .bind(username)
        .fetch_optional(executor)
        .await?;
        Self::maybe(row)
    }

    /// Look a user up by id; `None` when absent.
    pub async fn get_by_id(
        &self,
        executor: impl PgExecutor<'_>,
        id: Uuid,
    ) -> Result<Option<UserModel>, CoreError> {
        let row: Option<UserRow> = sqlx::query_as(&format!("{USER_FROM} WHERE id = $1"))
            .bind(id)
            .fetch_optional(executor)
            .await?;
        Self::maybe(row)
    }

    /// Look a user up by per-tenant-unique OIDC subject; `None` when
    /// absent. This is the SSO login path's resolution of a provider
    /// subject claim to an account.
    pub async fn get_by_oidc_sub(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        sub: &str,
    ) -> Result<Option<UserModel>, CoreError> {
        let row: Option<UserRow> = sqlx::query_as(&format!(
            "{USER_FROM} WHERE tenant_id = $1 AND oidc_sub = $2"
        ))
        .bind(tenant_id)
        .bind(sub)
        .fetch_optional(executor)
        .await?;
        Self::maybe(row)
    }

    /// Look a user up by per-tenant-unique email; `None` when absent.
    pub async fn get_by_email(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        email: &str,
    ) -> Result<Option<UserModel>, CoreError> {
        let row: Option<UserRow> =
            sqlx::query_as(&format!("{USER_FROM} WHERE tenant_id = $1 AND email = $2"))
                .bind(tenant_id)
                .bind(email)
                .fetch_optional(executor)
                .await?;
        Self::maybe(row)
    }

    /// A tenant's users, one page at a time, username order for stable
    /// output (the shared [`crate::repo::paging`] helper: LIMIT/OFFSET,
    /// clamped page size).
    pub async fn list_by_tenant(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        page: u32,
        page_size: u32,
    ) -> Result<Vec<UserModel>, CoreError> {
        let (limit, offset) = crate::repo::paging(page, page_size)?;
        let rows: Vec<UserRow> = sqlx::query_as(&format!(
            "{USER_FROM} WHERE tenant_id = $1 ORDER BY username LIMIT $2 OFFSET $3"
        ))
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(executor)
        .await?;

        rows.into_iter()
            .map(UserRow::try_into_model)
            .collect::<Result<Vec<_>, CoreError>>()
    }

    /// Change the user's role (its capability bundle source). A
    /// nonexistent user updates zero rows; this stays a plain `Ok(())`,
    /// mirroring the house's structurally-idempotent updates.
    pub async fn update_role(
        &self,
        executor: impl PgExecutor<'_>,
        id: Uuid,
        role: Role,
    ) -> Result<(), CoreError> {
        sqlx::query("UPDATE users SET role = $2, updated_at = now() WHERE id = $1")
            .bind(id)
            .bind(role.as_str())
            .execute(executor)
            .await?;
        Ok(())
    }

    /// Deactivate the user — the only user-removal path: rows stay (for
    /// attribution and FKs), `is_active` flips, login refuses.
    pub async fn deactivate(
        &self,
        executor: impl PgExecutor<'_>,
        id: Uuid,
    ) -> Result<(), CoreError> {
        sqlx::query("UPDATE users SET is_active = FALSE, updated_at = now() WHERE id = $1")
            .bind(id)
            .execute(executor)
            .await?;
        Ok(())
    }

    /// Restore `is_active` — the re-activation path complementing
    /// [`UserRepo::deactivate`]: rows never left, so one boolean flip
    /// returns the user to the login path (an SSO/OAuth identity keeps its
    /// provider linkage; re-activation has no special cases). A
    /// nonexistent user updates zero rows; this stays a plain `Ok(())`,
    /// mirroring [`UserRepo::deactivate`]'s house style — the ROUTE
    /// decides 404 from its own resolve.
    pub async fn set_active(
        &self,
        executor: impl PgExecutor<'_>,
        id: Uuid,
        active: bool,
    ) -> Result<(), CoreError> {
        sqlx::query("UPDATE users SET is_active = $2, updated_at = now() WHERE id = $1")
            .bind(id)
            .bind(active)
            .execute(executor)
            .await?;
        Ok(())
    }

    /// Replace the user's TOTP credential wholesale — the encrypted secret,
    /// its nonce, and the enforcement flag in ONE statement, so a TOTP
    /// change and its audit row (written by the caller on the same
    /// executor) commit or roll back together. `None` secret/nonce clears
    /// the credential (deactivation); the caller chooses the new
    /// `mfa_enabled` value explicitly, since enroll keeps it false while
    /// activate sets it true.
    pub async fn update_totp_credential(
        &self,
        executor: impl PgExecutor<'_>,
        id: Uuid,
        totp_secret_encrypted: Option<Vec<u8>>,
        totp_secret_nonce: Option<Vec<u8>>,
        mfa_enabled: bool,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "UPDATE users SET totp_secret_encrypted = $2, totp_secret_nonce = $3, \
             mfa_enabled = $4, updated_at = now() WHERE id = $1",
        )
        .bind(id)
        .bind(totp_secret_encrypted)
        .bind(totp_secret_nonce)
        .bind(mfa_enabled)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Link an OIDC subject to the user (`users.oidc_sub`, unique per
    /// tenant) — the SSO login path's first-login linkage by verified
    /// email. A conflicting `(tenant_id, oidc_sub)` is
    /// [`CoreError::Duplicate`].
    pub async fn link_oidc_sub(
        &self,
        executor: impl PgExecutor<'_>,
        id: Uuid,
        sub: &str,
    ) -> Result<(), CoreError> {
        sqlx::query("UPDATE users SET oidc_sub = $2, updated_at = now() WHERE id = $1")
            .bind(id)
            .bind(sub)
            .execute(executor)
            .await
            .map_err(map_unique)?;
        Ok(())
    }

    /// Stamp `last_login_at` (the successful-login bookkeeping).
    pub async fn touch_last_login(
        &self,
        executor: impl PgExecutor<'_>,
        id: Uuid,
    ) -> Result<(), CoreError> {
        sqlx::query("UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = $1")
            .bind(id)
            .execute(executor)
            .await?;
        Ok(())
    }

    /// Count one failed login against the lockout policy. Consecutive
    /// calls (one attempt per statement) increment the shared counter; a
    /// login success path calls [`UserRepo::clear_failed_logins`].
    pub async fn record_failed_login(
        &self,
        executor: impl PgExecutor<'_>,
        id: Uuid,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "UPDATE users SET failed_login_attempts = failed_login_attempts + 1, \
             updated_at = now() WHERE id = $1",
        )
        .bind(id)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Reset the lockout inputs after a successful login (or an
    /// operator's manual unlock).
    pub async fn clear_failed_logins(
        &self,
        executor: impl PgExecutor<'_>,
        id: Uuid,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, \
             updated_at = now() WHERE id = $1",
        )
        .bind(id)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Lock the account's logins out until `until` (the lockout policy's
    /// punishment for too many consecutive failures).
    pub async fn lock_until(
        &self,
        executor: impl PgExecutor<'_>,
        id: Uuid,
        until: DateTime<Utc>,
    ) -> Result<(), CoreError> {
        sqlx::query("UPDATE users SET locked_until = $2, updated_at = now() WHERE id = $1")
            .bind(id)
            .bind(until)
            .execute(executor)
            .await?;
        Ok(())
    }

    /// `Some(row)` decoded, `None` passed through.
    fn maybe(row: Option<UserRow>) -> Result<Option<UserModel>, CoreError> {
        match row {
            Some(row) => Ok(Some(row.try_into_model()?)),
            None => Ok(None),
        }
    }
}
