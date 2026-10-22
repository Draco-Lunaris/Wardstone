//! Repository over the `crls` table.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::error::CoreError;
use crate::models::crl::CrlEntry;

/// Data access for [`CrlEntry`] rows.
///
/// Stateless by design (the house shape): the repository holds no pool,
/// and every method takes `executor: impl PgExecutor<'_>`. The table is
/// written by ws-worker's CRL job in raw SQL; this repo is its read side.
#[derive(Default)]
pub struct CrlRepo;

/// Inline row shape for `sqlx::query_as` (house style: hand-mapped to the
/// model — the model itself stays free of sqlx derives).
#[derive(sqlx::FromRow)]
struct CrlRow {
    ca_id: Uuid,
    tenant_id: Uuid,
    issued_at: DateTime<Utc>,
    next_update: DateTime<Utc>,
    crl_pem: String,
}

impl CrlRepo {
    /// Build the (stateless) repository (`Default`, per the house shape;
    /// the allow counters the newer, contradicting
    /// `default_constructed_unit_structs` lint, which the house shape
    /// deliberately does not adopt).
    #[allow(clippy::default_constructed_unit_structs)]
    pub fn new() -> Self {
        Self::default()
    }

    /// The newest published CRL for the CA, or `None` when it has none:
    /// `ORDER BY issued_at DESC LIMIT 1`. The `tenant_id` filter is part of
    /// the query — a CRL row MUST match the caller's tenant (migration
    /// 006's composite `(ca_id, tenant_id)` foreign key backs the
    /// denormalized copy), never only the ca_id.
    pub async fn latest_for_ca(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        ca_id: Uuid,
    ) -> Result<Option<CrlEntry>, CoreError> {
        let row: Option<CrlRow> = sqlx::query_as(
            "SELECT ca_id, tenant_id, issued_at, next_update, crl_pem FROM crls \
             WHERE tenant_id = $1 AND ca_id = $2 \
             ORDER BY issued_at DESC LIMIT 1",
        )
        .bind(tenant_id)
        .bind(ca_id)
        .fetch_optional(executor)
        .await?;

        match row {
            Some(row) => Ok(Some(CrlEntry {
                ca_id: row.ca_id,
                tenant_id: row.tenant_id,
                issued_at: row.issued_at,
                next_update: row.next_update,
                crl_pem: row.crl_pem,
            })),
            None => Ok(None),
        }
    }
}
