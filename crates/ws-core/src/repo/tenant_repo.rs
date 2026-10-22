//! Repository over the `tenants` table.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::error::CoreError;

/// Data access for [`Tenant`] rows.
///
/// Stateless by design: the repository holds no pool, and every method
/// takes `executor: impl PgExecutor<'_>` so a mutation and its audit row
/// can share one transaction (callers pass `&pool`, or `&mut *tx` inside a
/// transaction — `&mut Transaction` does not implement `PgExecutor` in
/// sqlx 0.8.6).
#[derive(Default)]
pub struct TenantRepo;

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

    /// Insert a tenant by name (id and `created_at` come from the database
    /// defaults) and return the stored row. A unique-violation on the name
    /// becomes [`CoreError::Duplicate`].
    pub async fn insert(
        &self,
        executor: impl PgExecutor<'_>,
        name: &str,
    ) -> Result<crate::models::tenant::Tenant, CoreError> {
        let row: TenantRow = sqlx::query_as(
            "INSERT INTO tenants (name) VALUES ($1) \
             RETURNING id, name, created_at",
        )
        .bind(name)
        .fetch_one(executor)
        .await
        .map_err(map_unique)?;

        Ok(row.into())
    }

    /// Look up a tenant by its unique name; `None` when absent.
    pub async fn get_by_name(
        &self,
        executor: impl PgExecutor<'_>,
        name: &str,
    ) -> Result<Option<crate::models::tenant::Tenant>, CoreError> {
        let row: Option<TenantRow> = sqlx::query_as(
            "SELECT id, name, created_at FROM tenants \
             WHERE name = $1",
        )
        .bind(name)
        .fetch_optional(executor)
        .await?;

        Ok(row.map(Into::into))
    }

    /// All tenants, ordered by name for stable output.
    pub async fn list(
        &self,
        executor: impl PgExecutor<'_>,
    ) -> Result<Vec<crate::models::tenant::Tenant>, CoreError> {
        let rows: Vec<TenantRow> =
            sqlx::query_as("SELECT id, name, created_at FROM tenants ORDER BY name")
                .fetch_all(executor)
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
