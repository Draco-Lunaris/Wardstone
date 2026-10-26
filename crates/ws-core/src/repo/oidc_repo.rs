//! Repository over the `oidc_config` table: the per-tenant OIDC provider
//! configuration (one row per tenant; configured presence is enablement).

use sqlx::PgExecutor;
use uuid::Uuid;

use crate::error::CoreError;
use crate::models::credential::OidcConfigModel;
use crate::repo::tenant_repo::map_unique;

/// Data access for [`OidcConfigModel`] rows.
///
/// Stateless by design: the repository holds no pool, and every method
/// takes `executor: impl PgExecutor<'_>` (callers pass `&pool`, or
/// `&mut *tx` inside a transaction — `&mut Transaction` does not
/// implement `PgExecutor` in sqlx 0.8.6).
#[derive(Default)]
pub struct OidcConfigRepo;

/// Inline row shape for `sqlx::query_as` (house style: hand-mapped).
#[derive(sqlx::FromRow)]
struct OidcConfigRow {
    tenant_id: Uuid,
    provider_type: String,
    display_name: String,
    discovery_url: String,
    client_id: String,
    client_secret_ciphertext: Option<Vec<u8>>,
    client_secret_nonce: Option<Vec<u8>>,
    redirect_uri: String,
    scopes: String,
}

impl From<OidcConfigRow> for OidcConfigModel {
    fn from(row: OidcConfigRow) -> Self {
        OidcConfigModel {
            tenant_id: row.tenant_id,
            provider_type: row.provider_type,
            display_name: row.display_name,
            discovery_url: row.discovery_url,
            client_id: row.client_id,
            client_secret_ciphertext: row.client_secret_ciphertext,
            client_secret_nonce: row.client_secret_nonce,
            redirect_uri: row.redirect_uri,
            scopes: row.scopes,
        }
    }
}

const OIDC_COLUMNS: &str = "SELECT tenant_id, provider_type, display_name, discovery_url, \
     client_id, client_secret_ciphertext, client_secret_nonce, redirect_uri, scopes \
     FROM oidc_config";

impl OidcConfigRepo {
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

    /// The tenant's OIDC provider configuration; `None` when the tenant
    /// has none configured (SSO simply is not enabled for it).
    pub async fn get(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
    ) -> Result<Option<OidcConfigModel>, CoreError> {
        let row: Option<OidcConfigRow> =
            sqlx::query_as(&format!("{OIDC_COLUMNS} WHERE tenant_id = $1"))
                .bind(tenant_id)
                .fetch_optional(executor)
                .await?;
        Ok(row.map(Into::into))
    }

    /// Store (or replace — `tenant_id` is the table's primary key, so
    /// `ON CONFLICT` upserts rather than duplicates) the tenant's OIDC
    /// provider configuration exactly as given. A violation of the
    /// `provider_type` CHECK constraint (an unknown flavour) surfaces as
    /// a typed database error, never a stored bad row.
    pub async fn upsert(
        &self,
        executor: impl PgExecutor<'_>,
        config: &OidcConfigModel,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "INSERT INTO oidc_config (tenant_id, provider_type, display_name, discovery_url, \
             client_id, client_secret_ciphertext, client_secret_nonce, redirect_uri, scopes) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (tenant_id) DO UPDATE SET \
             provider_type = EXCLUDED.provider_type, \
             display_name = EXCLUDED.display_name, \
             discovery_url = EXCLUDED.discovery_url, \
             client_id = EXCLUDED.client_id, \
             client_secret_ciphertext = EXCLUDED.client_secret_ciphertext, \
             client_secret_nonce = EXCLUDED.client_secret_nonce, \
             redirect_uri = EXCLUDED.redirect_uri, \
             scopes = EXCLUDED.scopes",
        )
        .bind(config.tenant_id)
        .bind(&config.provider_type)
        .bind(&config.display_name)
        .bind(&config.discovery_url)
        .bind(&config.client_id)
        .bind(&config.client_secret_ciphertext)
        .bind(&config.client_secret_nonce)
        .bind(&config.redirect_uri)
        .bind(&config.scopes)
        .execute(executor)
        .await
        .map_err(map_unique)?;
        Ok(())
    }

    /// Remove the tenant's OIDC provider configuration. The guarded
    /// DELETE's affected-rows count is deliberately left unmapped — the
    /// house pattern for guarded deletes (`CredentialRepo::
    /// revoke_service_identity`): the route establishes existence first
    /// (via [`OidcConfigRepo::get`], which also feeds the audit details)
    /// and turns a missing row into its own 404, so a row that vanishes
    /// between the two reads is simply a no-op delete.
    pub async fn delete(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
    ) -> Result<(), CoreError> {
        sqlx::query("DELETE FROM oidc_config WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(executor)
            .await?;
        Ok(())
    }
}
