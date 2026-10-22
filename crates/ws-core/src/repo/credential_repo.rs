//! Repositories over the credential tables: `service_identities` (+
//! `service_identity_capabilities`) and `one_shot_tokens`.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::error::CoreError;
use crate::models::credential::{OneShotTokenModel, ServiceIdentityModel};
use crate::models::rbac::Capability;
use crate::repo::tenant_repo::map_unique;

/// Data access for [`ServiceIdentityModel`] and [`OneShotTokenModel`]
/// rows and their capability grants.
///
/// Stateless by design: the repository holds no pool, and every method
/// takes `executor: impl PgExecutor<'_>` so a mutation and its audit row
/// can share one transaction (callers pass `&pool`, or `&mut *tx` inside a
/// transaction — `&mut Transaction` does not implement `PgExecutor` in
/// sqlx 0.8.6).
#[derive(Default)]
pub struct CredentialRepo;

/// Inline row shape for a `service_identities` row.
#[derive(sqlx::FromRow)]
struct ServiceIdentityRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    description: Option<String>,
    created_by: Option<Uuid>,
    token_hash: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
}

const SERVICE_IDENTITY_COLUMNS: &str = "SELECT id, tenant_id, name, description, created_by, \
     token_hash, created_at, expires_at, revoked_at, last_used_at FROM service_identities";

/// Inline row shape for a `one_shot_tokens` row.
#[derive(sqlx::FromRow)]
struct OneShotTokenRow {
    id: Uuid,
    tenant_id: Uuid,
    minted_by: Option<Uuid>,
    token_hash: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    used_at: Option<DateTime<Utc>>,
}

/// Row shape of the consume UPDATE's RETURNING clause — exactly the six
/// columns it returns (token_hash is not among them; the caller supplied
/// the hash, and it is the same value the row matched on).
#[derive(sqlx::FromRow)]
struct ConsumedOneShotRow {
    id: Uuid,
    tenant_id: Uuid,
    minted_by: Option<Uuid>,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    used_at: Option<DateTime<Utc>>,
}

const ONE_SHOT_COLUMNS: &str = "SELECT id, tenant_id, minted_by, token_hash, created_at, \
     expires_at, used_at FROM one_shot_tokens";

impl ServiceIdentityRow {
    fn into_model(self) -> ServiceIdentityModel {
        ServiceIdentityModel {
            id: self.id,
            tenant_id: self.tenant_id,
            name: self.name,
            description: self.description,
            created_by: self.created_by,
            token_hash: self.token_hash,
            created_at: self.created_at,
            expires_at: self.expires_at,
            revoked_at: self.revoked_at,
            last_used_at: self.last_used_at,
        }
    }
}

impl OneShotTokenRow {
    fn into_model(self) -> OneShotTokenModel {
        OneShotTokenModel {
            id: self.id,
            tenant_id: self.tenant_id,
            minted_by: self.minted_by,
            token_hash: self.token_hash,
            created_at: self.created_at,
            expires_at: self.expires_at,
            used_at: self.used_at,
        }
    }
}

impl CredentialRepo {
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

    /// Insert a service identity exactly as given (every field). A
    /// unique-violation on `token_hash` becomes
    /// [`CoreError::Duplicate`].
    pub async fn insert_service_identity(
        &self,
        executor: impl PgExecutor<'_>,
        s: &ServiceIdentityModel,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "INSERT INTO service_identities (id, tenant_id, name, description, created_by, \
             token_hash, created_at, expires_at, revoked_at, last_used_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(s.id)
        .bind(s.tenant_id)
        .bind(&s.name)
        .bind(&s.description)
        .bind(s.created_by)
        .bind(&s.token_hash)
        .bind(s.created_at)
        .bind(s.expires_at)
        .bind(s.revoked_at)
        .bind(s.last_used_at)
        .execute(executor)
        .await
        .map_err(map_unique)?;
        Ok(())
    }

    /// Resolve a presented token's hash to its identity; `None` when no
    /// such identity exists (revocation and expiry are checked by the
    /// auth layer against the returned row).
    pub async fn get_service_identity_by_hash(
        &self,
        executor: impl PgExecutor<'_>,
        hash: &str,
    ) -> Result<Option<ServiceIdentityModel>, CoreError> {
        let row: Option<ServiceIdentityRow> =
            sqlx::query_as(&format!("{SERVICE_IDENTITY_COLUMNS} WHERE token_hash = $1"))
                .bind(hash)
                .fetch_optional(executor)
                .await?;
        Ok(row.map(ServiceIdentityRow::into_model))
    }

    /// A tenant's service identities, one page at a time, newest creation
    /// first (id tiebreaker for stable output; the shared
    /// [`crate::repo::paging`] helper).
    pub async fn list_service_identities(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        page: u32,
        page_size: u32,
    ) -> Result<Vec<ServiceIdentityModel>, CoreError> {
        let (limit, offset) = crate::repo::paging(page, page_size)?;
        let rows: Vec<ServiceIdentityRow> = sqlx::query_as(&format!(
            "{SERVICE_IDENTITY_COLUMNS} WHERE tenant_id = $1 \
             ORDER BY created_at DESC, id LIMIT $2 OFFSET $3"
        ))
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(executor)
        .await?;
        Ok(rows
            .into_iter()
            .map(ServiceIdentityRow::into_model)
            .collect())
    }

    /// Revoke a service identity (stamps `revoked_at = now()`). The
    /// `AND revoked_at IS NULL` guard makes a double revoke
    /// structurally idempotent: the second call updates zero rows and
    /// leaves `revoked_at` exactly where the first call set it.
    pub async fn revoke_service_identity(
        &self,
        executor: impl PgExecutor<'_>,
        id: Uuid,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "UPDATE service_identities SET revoked_at = now() \
             WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(id)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Replace the identity's capability grant with exactly `caps`, in
    /// ONE statement (a data-modifying CTE: delete the old grant rows,
    /// then insert the given list), so the grant is replaced atomically
    /// even without a wrapping transaction. An empty slice just clears
    /// the grant.
    pub async fn set_service_identity_capabilities(
        &self,
        executor: impl PgExecutor<'_>,
        service_identity_id: Uuid,
        caps: &[Capability],
    ) -> Result<(), CoreError> {
        let caps: Vec<String> = caps.iter().map(|c| c.as_str().to_string()).collect();
        sqlx::query(
            "WITH cleared AS ( \
                 DELETE FROM service_identity_capabilities WHERE service_identity_id = $1 \
             ) \
             INSERT INTO service_identity_capabilities (service_identity_id, capability) \
             SELECT $1, cap FROM UNNEST($2 ::text[]) AS cap",
        )
        .bind(service_identity_id)
        .bind(&caps)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// The identity's capability grant, in stored-name order; an unknown
    /// spelling is data-level damage and a [`CoreError::Config`].
    pub async fn service_identity_capabilities(
        &self,
        executor: impl PgExecutor<'_>,
        service_identity_id: Uuid,
    ) -> Result<Vec<Capability>, CoreError> {
        let raw: Vec<String> = sqlx::query_scalar(
            "SELECT capability FROM service_identity_capabilities \
             WHERE service_identity_id = $1 ORDER BY capability",
        )
        .bind(service_identity_id)
        .fetch_all(executor)
        .await?;

        raw.into_iter()
            .map(|c| {
                Capability::from_str(&c).ok_or_else(|| {
                    CoreError::Config(format!(
                        "invalid capability in service_identity_capabilities row: {c:?}"
                    ))
                })
            })
            .collect()
    }

    /// Insert a one-shot token exactly as given. A unique-violation on
    /// `token_hash` becomes [`CoreError::Duplicate`].
    pub async fn insert_one_shot_token(
        &self,
        executor: impl PgExecutor<'_>,
        t: &OneShotTokenModel,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "INSERT INTO one_shot_tokens (id, tenant_id, minted_by, token_hash, created_at, \
             expires_at) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(t.id)
        .bind(t.tenant_id)
        .bind(t.minted_by)
        .bind(&t.token_hash)
        .bind(t.created_at)
        .bind(t.expires_at)
        .execute(executor)
        .await
        .map_err(map_unique)?;
        Ok(())
    }

    /// A tenant's one-shot tokens, one page at a time, newest first (the
    /// shared [`crate::repo::paging`] helper): the listing the one-shot
    /// tokens route serves. Consumed and expired tokens stay listed (the
    /// audit trail of what was minted); the consumer reads `used_at` from
    /// the row.
    pub async fn list_one_shot_tokens(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        page: u32,
        page_size: u32,
    ) -> Result<Vec<OneShotTokenModel>, CoreError> {
        let (limit, offset) = crate::repo::paging(page, page_size)?;
        let rows: Vec<OneShotTokenRow> = sqlx::query_as(&format!(
            "{ONE_SHOT_COLUMNS} WHERE tenant_id = $1 ORDER BY created_at DESC, id \
             LIMIT $2 OFFSET $3"
        ))
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(executor)
        .await?;
        Ok(rows.into_iter().map(OneShotTokenRow::into_model).collect())
    }

    /// Resolve a presented one-shot token's hash to its row, used or not
    /// (the auth layer interprets `used_at`); `None` when unknown.
    pub async fn get_one_shot_by_hash(
        &self,
        executor: impl PgExecutor<'_>,
        hash: &str,
    ) -> Result<Option<OneShotTokenModel>, CoreError> {
        let row: Option<OneShotTokenRow> =
            sqlx::query_as(&format!("{ONE_SHOT_COLUMNS} WHERE token_hash = $1"))
                .bind(hash)
                .fetch_optional(executor)
                .await?;
        Ok(row.map(OneShotTokenRow::into_model))
    }

    /// Consume a one-shot token, in ONE statement: `used_at = now()` is
    /// written only for a row that is unused (`used_at IS NULL`), live
    /// (`expires_at > now()`), and known (`token_hash = $1`). A row count
    /// of zero — already used, expired, or unknown — collapses to
    /// `Ok(None)`; one row is `Ok(Some(model))` with the consumption
    /// instant set. Two concurrent consumers cannot both succeed: the
    /// row's write locks serialize them and the second's WHERE no longer
    /// matches.
    pub async fn consume_one_shot_by_hash(
        &self,
        executor: impl PgExecutor<'_>,
        hash: &str,
    ) -> Result<Option<OneShotTokenModel>, CoreError> {
        let row: Option<ConsumedOneShotRow> = sqlx::query_as(
            "UPDATE one_shot_tokens SET used_at = now() \
             WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() \
             RETURNING id, tenant_id, minted_by, created_at, expires_at, used_at",
        )
        .bind(hash)
        .fetch_optional(executor)
        .await?;
        Ok(row.map(|row: ConsumedOneShotRow| OneShotTokenModel {
            id: row.id,
            tenant_id: row.tenant_id,
            minted_by: row.minted_by,
            // The RETURNING clause does not carry token_hash; the caller
            // supplied it, and it is the same value the row matched on.
            token_hash: hash.to_string(),
            created_at: row.created_at,
            expires_at: row.expires_at,
            used_at: row.used_at,
        }))
    }
}
