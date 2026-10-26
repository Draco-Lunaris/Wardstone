//! Database bootstrap: Postgres connection pool + numbered migrations.
//!
//! `sqlx::migrate!` embeds `migrations/*.sql` at compile time, so `connect`
//! runs from any working directory and the applied-checksum comparison is
//! pinned to the binary's schema.

use std::str::FromStr;

use sqlx::postgres::PgPoolOptions;
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use sqlx::PgPool;

use crate::error::CoreError;

/// Number of migration files embedded from `crates/ws-core/migrations/`.
///
/// `connect` refuses to serve traffic against a database whose
/// `_sqlx_migrations` bookkeeping disagrees with this constant.
/// Bump it exactly when a migration file is added.
pub const REQUIRED_MIGRATION_COUNT: u16 = 12;

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

/// The external-database URL policy (Task 10, D5): parse, don't
/// connect — a pure preflight check the binary runs at boot in BOTH
/// modes, additive beside (and after) the password-refusal gate.
///
/// The rule splits on the transport, which the parser alone reveals:
/// a SOCKET host is a local link — unix-socket peer credentials are
/// the protection there (D8), and no TLS keys apply; a TCP host is an
/// EXTERNAL database and must carry BOTH `sslmode=verify-full` and
/// `sslrootcert=<path>` (the operator mounts the CA bundle
/// read-only), else the URL is refused — a half-verified TLS link is
/// a downgrade, not a deployment. The refusal names both protections
/// whatever is missing, and connects never happen here (whether the
/// server answers is [`connect`]'s concern).
///
/// The `sslrootcert` check is a hand scan of the URL's query: sqlx
/// parses the key into a private field with no getter
/// (options/parse.rs:56-57 → `ssl_root_cert` → connection/tls.rs:58,
/// so the driver honors it end-to-end), and the hand-rolled scan is
/// the house's no-new-dependency precedent.
pub fn check_database_url(url: &str) -> Result<(), CoreError> {
    let options = PgConnectOptions::from_str(url)
        .map_err(|e| CoreError::Config(format!("database URL does not parse: {e}")))?;

    // A socket host is a local link: admitted with no TLS keys.
    if options.get_socket().is_some() {
        return Ok(());
    }

    // A TCP host is an external database: both protections or refusal.
    if matches!(options.get_ssl_mode(), PgSslMode::VerifyFull) && ssl_root_cert_configured(url) {
        return Ok(());
    }
    Err(CoreError::Config(format!(
        "an external (TCP) database URL must carry sslmode=verify-full and \
         sslrootcert=<path> (the operator's mounted CA bundle); this URL has \
         sslmode={:?} and {} — Wardstone refuses rather than downgrade TLS",
        options.get_ssl_mode(),
        if ssl_root_cert_configured(url) {
            "an sslrootcert"
        } else {
            "no sslrootcert"
        },
    )))
}

/// Whether the URL's query names a non-empty `sslrootcert` (sqlx also
/// accepts the `ssl-root-cert`/`ssl-ca` spellings). Only the PRESENCE
/// of a value is checked here — the path itself is validated where it
/// is used, by the driver's TLS handshake.
fn ssl_root_cert_configured(url: &str) -> bool {
    let Some((_, query)) = url.split_once('?') else {
        return false;
    };
    query.split('&').any(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        matches!(key, "sslrootcert" | "ssl-root-cert" | "ssl-ca") && !value.is_empty()
    })
}
