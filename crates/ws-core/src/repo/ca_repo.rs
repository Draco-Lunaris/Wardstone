//! Repository over the `cas` table.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::CoreError;
use crate::models::ca::{CaModel, KeyType};
use crate::repo::tenant_repo::map_unique;

/// Data access for [`CaModel`] rows.
pub struct CaRepo {
    pool: PgPool,
}

/// Inline row shape for `sqlx::query_as` (house style: hand-mapped to the
/// model). `key_type` is the raw text column, decoded via `KeyType::from_str`.
#[derive(sqlx::FromRow)]
struct CaRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    subject: String,
    is_root: bool,
    parent_id: Option<Uuid>,
    key_type: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    cert_pem: String,
    key_file: String,
    created_at: DateTime<Utc>,
}

impl CaRepo {
    /// Build a repository bound to the shared pool.
    pub fn new(pool: &PgPool) -> Self {
        CaRepo { pool: pool.clone() }
    }

    /// Insert a CA row exactly as given (`id`, `created_at`, every field: the
    /// model is authoritative — `created_at` is written explicitly rather
    /// than left to the `now()` default, so `get` returns the same row).
    /// `key_type` is bound via its text representation.
    pub async fn insert(&self, ca: &CaModel) -> Result<(), CoreError> {
        sqlx::query(
            "INSERT INTO cas (id, tenant_id, name, subject, is_root, parent_id, key_type, \
             not_before, not_after, cert_pem, key_file, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(ca.id)
        .bind(ca.tenant_id)
        .bind(&ca.name)
        .bind(&ca.subject)
        .bind(ca.is_root)
        .bind(ca.parent_id)
        .bind(ca.key_type.as_str())
        .bind(ca.not_before)
        .bind(ca.not_after)
        .bind(&ca.cert_pem)
        .bind(&ca.key_file)
        .bind(ca.created_at)
        .execute(&self.pool)
        .await
        .map_err(map_unique)?;
        Ok(())
    }

    /// Fetch a CA by id; `None` when absent.
    pub async fn get(&self, id: Uuid) -> Result<Option<CaModel>, CoreError> {
        let row: Option<CaRow> = sqlx::query_as(
            "SELECT id, tenant_id, name, subject, is_root, parent_id, key_type, \
             not_before, not_after, cert_pem, key_file, created_at \
             FROM cas WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into_model()?)),
            None => Ok(None),
        }
    }

    /// All CAs owned by a tenant, ordered by name for stable output.
    pub async fn list_by_tenant(&self, tenant_id: Uuid) -> Result<Vec<CaModel>, CoreError> {
        let rows: Vec<CaRow> = sqlx::query_as(
            "SELECT id, tenant_id, name, subject, is_root, parent_id, key_type, \
             not_before, not_after, cert_pem, key_file, created_at \
             FROM cas WHERE tenant_id = $1 ORDER BY name",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(CaRow::try_into_model)
            .collect::<Result<Vec<_>, CoreError>>()
    }

    /// CAs whose `parent_id` is the given CA, ordered by name.
    pub async fn children_of(&self, parent_id: Uuid) -> Result<Vec<CaModel>, CoreError> {
        let rows: Vec<CaRow> = sqlx::query_as(
            "SELECT id, tenant_id, name, subject, is_root, parent_id, key_type, \
             not_before, not_after, cert_pem, key_file, created_at \
             FROM cas WHERE parent_id = $1 ORDER BY name",
        )
        .bind(parent_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(CaRow::try_into_model)
            .collect::<Result<Vec<_>, CoreError>>()
    }
}

impl CaRow {
    /// Decode a row into the domain model, mapping the `key_type` text through
    /// `KeyType::from_str`; an unknown stored value is a [`CoreError::Config`]
    /// (data-level corruption, not a per-request failure).
    fn try_into_model(self) -> Result<CaModel, CoreError> {
        let key_type = self
            .key_type
            .parse::<KeyType>()
            .map_err(|err| CoreError::Config(format!("invalid key_type in row: {err}")))?;
        Ok(CaModel {
            id: self.id,
            tenant_id: self.tenant_id,
            name: self.name,
            subject: self.subject,
            is_root: self.is_root,
            parent_id: self.parent_id,
            key_type,
            not_before: self.not_before,
            not_after: self.not_after,
            cert_pem: self.cert_pem,
            key_file: self.key_file,
            created_at: self.created_at,
        })
    }
}
