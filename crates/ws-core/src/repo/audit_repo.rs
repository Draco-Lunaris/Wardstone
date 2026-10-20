//! Repository over the `audit_log` table.
//!
//! Append-only is structural: the surface is [`AuditRepo::record`] and
//! [`AuditRepo::list_by_tenant`] and nothing else — no update, no delete,
//! and no SQL anywhere in this module that could amend or remove a row.
//! Test cleanup uses raw `DELETE` statements against the database directly
//! (test scaffolding, outside this module).

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::CoreError;
use crate::models::audit::{ActorType, AuditEntry};
use crate::repo::tenant_repo::map_unique;

/// Data access for [`AuditEntry`] rows. Append-only by construction: there
/// is deliberately no update or delete method, so the type system keeps
/// every path to an `audit_log` row either an insert or a read.
pub struct AuditRepo {
    pool: PgPool,
}

/// Inline row shape for `sqlx::query_as` (house style: hand-mapped to the
/// model). `actor_type` is the raw text column, decoded via
/// `ActorType::from_str`; `details` is the `jsonb` column.
#[derive(sqlx::FromRow)]
struct AuditRow {
    id: Uuid,
    tenant_id: Uuid,
    actor_type: String,
    actor_id: String,
    action: String,
    target_type: String,
    target_id: String,
    details: JsonValue,
    created_at: DateTime<Utc>,
}

impl AuditRepo {
    /// Build a repository bound to the shared pool.
    pub fn new(pool: &PgPool) -> Self {
        AuditRepo { pool: pool.clone() }
    }

    /// Append one audit entry, exactly as given except for `created_at`:
    /// the database `now()` default owns that column and this method never
    /// binds a client timestamp, so an entry cannot be backdated. The
    /// entry's `id` still comes from the model (caller-chosen, so the
    /// caller can correlate the record with its operation). A
    /// unique-violation on the id — the same entry recorded twice — is
    /// [`CoreError::Duplicate`], never a silent overwrite.
    pub async fn record(&self, entry: &AuditEntry) -> Result<(), CoreError> {
        sqlx::query(
            "INSERT INTO audit_log (id, tenant_id, actor_type, actor_id, action, \
             target_type, target_id, details) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(entry.id)
        .bind(entry.tenant_id)
        .bind(entry.actor_type.as_str())
        .bind(&entry.actor_id)
        .bind(&entry.action)
        .bind(&entry.target_type)
        .bind(&entry.target_id)
        .bind(&entry.details)
        .execute(&self.pool)
        .await
        .map_err(map_unique)?;
        Ok(())
    }

    /// A tenant's audit entries, one page at a time, newest first
    /// (`created_at DESC`), LIMIT/OFFSET paging (`offset = page *
    /// page_size`). Ties on `created_at` resolve by `id` for stable
    /// output.
    pub async fn list_by_tenant(
        &self,
        tenant_id: Uuid,
        page: u32,
        page_size: u32,
    ) -> Result<Vec<AuditEntry>, CoreError> {
        let (limit, offset) = paging(page, page_size)?;
        let rows: Vec<AuditRow> = sqlx::query_as(
            "SELECT id, tenant_id, actor_type, actor_id, action, target_type, target_id, \
             details, created_at FROM audit_log WHERE tenant_id = $1 \
             ORDER BY created_at DESC, id LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(AuditRow::try_into_model)
            .collect::<Result<Vec<_>, CoreError>>()
    }
}

impl AuditRow {
    /// Decode a row into the domain model, mapping `actor_type` through
    /// `ActorType::from_str`; an unknown stored actor type is data-level
    /// damage and a [`CoreError::Config`], not a per-request failure.
    fn try_into_model(self) -> Result<AuditEntry, CoreError> {
        let actor_type = self
            .actor_type
            .parse::<ActorType>()
            .map_err(|err| CoreError::Config(format!("invalid actor_type in row: {err}")))?;
        Ok(AuditEntry {
            id: self.id,
            tenant_id: self.tenant_id,
            actor_type,
            actor_id: self.actor_id,
            action: self.action,
            target_type: self.target_type,
            target_id: self.target_id,
            details: self.details,
            created_at: self.created_at,
        })
    }
}

/// LIMIT/OFFSET values for a page: `page_size` and `page * page_size`.
/// The u32-by-u32 product cannot overflow u64, so the multiply is plain;
/// the i64 conversion is still typed — an offset beyond i64 is a caller
/// bug surfaced as [`CoreError::Config`], never a silent wrap.
fn paging(page: u32, page_size: u32) -> Result<(i64, i64), CoreError> {
    let offset = u64::from(page) * u64::from(page_size);
    let offset = i64::try_from(offset)
        .map_err(|_| CoreError::Config(format!("page offset {offset} overflows")))?;
    Ok((i64::from(page_size), offset))
}
