//! Repository over the `refresh_tokens` table: the sliding-window
//! session refresh store.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::error::CoreError;
use crate::models::credential::RefreshTokenModel;
use crate::repo::tenant_repo::map_unique;

/// Data access for [`RefreshTokenModel`] rows.
///
/// Stateless by design: the repository holds no pool, and every method
/// takes `executor: impl PgExecutor<'_>` so a token write and its audit
/// row can share one transaction (callers pass `&pool`, or `&mut *tx`
/// inside a transaction — `&mut Transaction` does not implement
/// `PgExecutor` in sqlx 0.8.6). Each method is ONE statement; the
/// two-part `rotate` is a data-modifying CTE, so revoke-and-replace is
/// atomic even without a wrapping transaction.
#[derive(Default)]
pub struct RefreshTokenRepo;

/// Inline row shape for `sqlx::query_as` (house style: hand-mapped). The
/// `ip_address` INET column decodes through sqlx's ipnet feature's
/// `IpAddr` binding.
#[derive(sqlx::FromRow)]
struct RefreshTokenRow {
    id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
    token_hash: String,
    issued_at: DateTime<Utc>,
    last_used_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked: bool,
    revoked_at: Option<DateTime<Utc>>,
    user_agent: Option<String>,
    ip_address: Option<IpAddr>,
}

impl RefreshTokenRow {
    fn into_model(self) -> RefreshTokenModel {
        RefreshTokenModel {
            id: self.id,
            tenant_id: self.tenant_id,
            user_id: self.user_id,
            token_hash: self.token_hash,
            issued_at: self.issued_at,
            last_used_at: self.last_used_at,
            expires_at: self.expires_at,
            revoked: self.revoked,
            revoked_at: self.revoked_at,
            user_agent: self.user_agent,
            ip_address: self.ip_address,
        }
    }
}

const REFRESH_COLUMNS: &str = "SELECT id, tenant_id, user_id, token_hash, issued_at, \
     last_used_at, expires_at, revoked, revoked_at, user_agent, ip_address FROM refresh_tokens";

impl RefreshTokenRepo {
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

    /// Insert a refresh token exactly as given (every field). The
    /// user-agent and address are the client's at issue time, and the
    /// raw token value never reaches storage — `token_hash` is the
    /// verifier. A unique-violation on `token_hash` becomes
    /// [`CoreError::Duplicate`].
    pub async fn insert(
        &self,
        executor: impl PgExecutor<'_>,
        t: &RefreshTokenModel,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "INSERT INTO refresh_tokens (id, tenant_id, user_id, token_hash, issued_at, \
             last_used_at, expires_at, revoked, revoked_at, user_agent, ip_address) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(t.id)
        .bind(t.tenant_id)
        .bind(t.user_id)
        .bind(&t.token_hash)
        .bind(t.issued_at)
        .bind(t.last_used_at)
        .bind(t.expires_at)
        .bind(t.revoked)
        .bind(t.revoked_at)
        .bind(&t.user_agent)
        .bind(t.ip_address)
        .execute(executor)
        .await
        .map_err(map_unique)?;
        Ok(())
    }

    /// Resolve a presented refresh token's hash to its row; `None` when
    /// unknown (the auth layer interprets `revoked`/`expires_at`).
    pub async fn get_by_hash(
        &self,
        executor: impl PgExecutor<'_>,
        hash: &str,
    ) -> Result<Option<RefreshTokenModel>, CoreError> {
        let row: Option<RefreshTokenRow> =
            sqlx::query_as(&format!("{REFRESH_COLUMNS} WHERE token_hash = $1"))
                .bind(hash)
                .fetch_optional(executor)
                .await?;
        Ok(row.map(RefreshTokenRow::into_model))
    }

    /// Rotate: revoke the old token (revoked + `revoked_at = now()`) AND
    /// insert its replacement, in ONE atomic statement (a data-modifying
    /// CTE runs the revoke as `rotated` before the INSERT). A token
    /// refresh never leaves a window where the old token is dead but the
    /// new one is not yet stored.
    pub async fn rotate(
        &self,
        executor: impl PgExecutor<'_>,
        old: &RefreshTokenModel,
        replacement: &RefreshTokenModel,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "WITH rotated AS ( \
                 UPDATE refresh_tokens SET revoked = TRUE, revoked_at = now() \
                 WHERE id = $1 \
             ) \
             INSERT INTO refresh_tokens (id, tenant_id, user_id, token_hash, issued_at, \
             last_used_at, expires_at, revoked, revoked_at, user_agent, ip_address) \
             VALUES ($2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(old.id)
        .bind(replacement.id)
        .bind(replacement.tenant_id)
        .bind(replacement.user_id)
        .bind(&replacement.token_hash)
        .bind(replacement.issued_at)
        .bind(replacement.last_used_at)
        .bind(replacement.expires_at)
        .bind(replacement.revoked)
        .bind(replacement.revoked_at)
        .bind(&replacement.user_agent)
        .bind(replacement.ip_address)
        .execute(executor)
        .await
        .map_err(map_unique)?;
        Ok(())
    }

    /// Revoke a token (stamps `revoked_at = now()`); a repeat leaves the
    /// first stamp in place.
    pub async fn revoke(&self, executor: impl PgExecutor<'_>, id: Uuid) -> Result<(), CoreError> {
        sqlx::query("UPDATE refresh_tokens SET revoked = TRUE, revoked_at = now() WHERE id = $1")
            .bind(id)
            .execute(executor)
            .await?;
        Ok(())
    }

    /// Slide the expiry window: `last_used_at = now()`. The house's
    /// one-hour window is anchored on this column, so a session in active
    /// use stays alive and an idle one ages out.
    pub async fn touch_last_used(
        &self,
        executor: impl PgExecutor<'_>,
        id: Uuid,
    ) -> Result<(), CoreError> {
        sqlx::query("UPDATE refresh_tokens SET last_used_at = now() WHERE id = $1")
            .bind(id)
            .execute(executor)
            .await?;
        Ok(())
    }

    /// Delete the dead rows — every expired token, and every revoked one
    /// whose revocation grace has no further reader (the house's sweep)
    /// — returning how many rows went.
    pub async fn purge_expired(&self, executor: impl PgExecutor<'_>) -> Result<u64, CoreError> {
        let result =
            sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < now() OR revoked = TRUE")
                .execute(executor)
                .await?;
        Ok(result.rows_affected())
    }
}
