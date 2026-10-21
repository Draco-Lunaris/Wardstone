//! Repository over the `tenants` table.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::CoreError;

/// Data access for [`Tenant`] rows.
pub struct TenantRepo {
    pool: PgPool,
}

/// Inline row shape for `sqlx::query_as` (house style: hand-mapped to the
/// model).
#[derive(sqlx::FromRow)]
struct TenantRow {
    id: Uuid,
    name: String,
    created_at: DateTime<Utc>,
}

impl From<TenantRow> for crate::models::tenant::Tenant {
    fn from(row: TenantRow) -> Self {
        crate::models::tenant::Tenant {
            id: row.id,
            name: row.name,
            created_at: row.created_at,
        }
    }
}

impl TenantRepo {
    /// Build a repository bound to the shared pool.
    pub fn new(pool: &PgPool) -> Self {
        TenantRepo { pool: pool.clone() }
    }

    /// Insert a tenant by name (id and `created_at` come from the database
    /// defaults) and return the stored row. A unique-violation on the name
    /// becomes [`CoreError::Duplicate`].
    pub async fn insert(&self, name: &str) -> Result<crate::models::tenant::Tenant, CoreError> {
        let row: TenantRow = sqlx::query_as(
            "INSERT INTO tenants (name) VALUES ($1) \
             RETURNING id, name, created_at",
        )
        .bind(name)
        .fetch_one(&self.pool)
        .await
        .map_err(map_unique)?;

        Ok(row.into())
    }

    /// Look up a tenant by its unique name; `None` when absent.
    pub async fn get_by_name(
        &self,
        name: &str,
    ) -> Result<Option<crate::models::tenant::Tenant>, CoreError> {
        let row: Option<TenantRow> = sqlx::query_as(
            "SELECT id, name, created_at FROM tenants \
             WHERE name = $1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Into::into))
    }

    /// All tenants, ordered by name for stable output.
    pub async fn list(&self) -> Result<Vec<crate::models::tenant::Tenant>, CoreError> {
        let rows: Vec<TenantRow> =
            sqlx::query_as("SELECT id, name, created_at FROM tenants ORDER BY name")
                .fetch_all(&self.pool)
                .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }
}

/// Map a query error, translating the Postgres unique-violation code (23505)
/// to [`CoreError::Duplicate`].
pub(crate) fn map_unique(err: sqlx::Error) -> CoreError {
    match &err {
        sqlx::Error::Database(db_err) => {
            if db_err.code().as_deref() == Some("23505") {
                CoreError::Duplicate
            } else {
                CoreError::Database(err)
            }
        }
        _ => CoreError::Database(err),
    }
}
