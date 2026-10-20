//! Database bootstrap: Postgres connection pool + numbered migrations.
//!
//! `sqlx::migrate!` embeds `migrations/*.sql` at compile time, so `connect`
//! runs from any working directory and the applied-checksum comparison is
//! pinned to the binary's schema.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::error::CoreError;

/// Number of migration files embedded from `crates/ws-core/migrations/`.
///
/// `connect` refuses to serve traffic against a database whose
/// `_sqlx_migrations` bookkeeping disagrees with this constant.
/// Bump it exactly when a migration file is added.
pub const REQUIRED_MIGRATION_COUNT: u16 = 3;

/// Open a Postgres connection pool (max 10 connections) and bring the database
/// up to date:
///
/// 1. Refuse a database where the schema exists but the migration bookkeeping
///    does not: `_sqlx_migrations` with zero rows while `tenants` exists means
///    the applied-migration history was lost (deleted by hand); re-running
///    migrations would silently paper over that. A genuinely fresh database
///    has neither table, so bootstrapping — including recovery from a crashed
///    first bootstrap, which can leave an empty `_sqlx_migrations` behind —
///    still works.
/// 2. Run the embedded migrations (idempotent: applied versions are skipped,
///    and upgrade gaps — e.g. one migration applied against a two-migration
///    binary — are bridged forward).
/// 3. Verify the bookkeeping count equals [`REQUIRED_MIGRATION_COUNT`],
///    returning [`CoreError::Migration`] on mismatch (e.g. the database is
///    ahead of this binary).
pub async fn connect(url: &str) -> Result<PgPool, CoreError> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(url)
        .await?;

    let migrations_table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = current_schema() \
         AND tablename = '_sqlx_migrations')",
    )
    .fetch_one(&pool)
    .await?;
    if migrations_table_exists {
        let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await?;
        if applied == 0 {
            // `tenants` is migration 001's root table (nothing references
            // other schemas here): its presence proves the schema was created,
            // so the missing bookkeeping rows are damage, not a fresh start.
            let schema_initialized: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = current_schema() \
                 AND tablename = 'tenants')",
            )
            .fetch_one(&pool)
            .await?;
            if schema_initialized {
                return Err(CoreError::Migration {
                    expected: REQUIRED_MIGRATION_COUNT,
                    found: 0,
                });
            }
        }
    }

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(migrate_error)?;

    let found: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await?;
    let found = u16::try_from(found)
        .map_err(|_| CoreError::Config(format!("migration count {found} does not fit u16")))?;
    if found != REQUIRED_MIGRATION_COUNT {
        return Err(CoreError::Migration {
            expected: REQUIRED_MIGRATION_COUNT,
            found,
        });
    }

    Ok(pool)
}

/// Map sqlx's migration failure set onto [`CoreError`]. `MigrateError::Execute`
/// wraps a genuine [`sqlx::Error`] and keeps its typed source; every other
/// variant (missing/edited migration, dirty state, source resolution) is a
/// deployment-level problem and becomes [`CoreError::Config`].
fn migrate_error(err: sqlx::migrate::MigrateError) -> CoreError {
    match err {
        sqlx::migrate::MigrateError::Execute(db_err) => CoreError::Database(db_err),
        other => CoreError::Config(format!("migration run failed: {other}")),
    }
}
