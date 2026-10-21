//! Integration tests for `ws_core::db::connect` (migration bootstrap).
//!
//! These tests run against a live Postgres and are marked `#[ignore]`.
//! Run them with:
//!
//! ```sh
//! DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test \
//!     cargo test -p ws-core -- --include-ignored
//! ```

use std::sync::OnceLock;
use tokio::sync::Mutex;

use ws_core::db::{connect, REQUIRED_MIGRATION_COUNT};
use ws_core::error::CoreError;

/// Serializes the tests against the shared database: the harness runs them on
/// separate threads, and `migration_count_guard_rejects_stale_db` mutates
/// `_sqlx_migrations` rows that `connect_runs_migrations` counts. A tokio
/// mutex because the guard is held across `.await` points.
static DB_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// The guard must be held (not dropped) until the test body finishes.
#[must_use = "the database lock must stay bound for the whole test body"]
async fn lock_db() -> tokio::sync::MutexGuard<'static, ()> {
    DB_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().await
}

/// Test database URL; `DATABASE_URL` overrides it.
fn database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://wardstone:wardstone@localhost:5432/wardstone_test".to_string()
    })
}

/// `connect` runs migration 001: the `_sqlx_migrations` bookkeeping table ends
/// up with `REQUIRED_MIGRATION_COUNT` rows and `tenants` exists but is empty
/// (the default tenant is inserted by Plan 2's bootstrap, not by migration 001).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn connect_runs_migrations() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply migration 001");

    let migrated: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .expect("query migration bookkeeping count");
    assert_eq!(
        migrated,
        i64::from(REQUIRED_MIGRATION_COUNT),
        "connect should leave exactly REQUIRED_MIGRATION_COUNT applied migrations"
    );

    let tenants: i64 = sqlx::query_scalar("SELECT count(*) FROM tenants")
        .fetch_one(&pool)
        .await
        .expect("query tenants count");
    assert_eq!(
        tenants, 0,
        "migration 001 must not seed a default tenant; Plan 2's bootstrap does that"
    );
}

/// Deleting a row from `_sqlx_migrations` while the schema survives means the
/// migration bookkeeping was lost; `connect` must refuse with
/// `CoreError::Migration` instead of silently re-running migrations.
///
/// The stashed bookkeeping row is restored before the assertions so the
/// database stays usable for repeated runs and for `connect_runs_migrations`.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn migration_count_guard_rejects_stale_db() {
    let _db = lock_db().await;
    let url = database_url();
    // Ensure the migrations are applied (idempotent) so there are rows to delete.
    let pool = connect(&url)
        .await
        .expect("initial connect should leave the database migrated");

    // Stash the bookkeeping row (plain table, not TEMP: pool connections differ).
    sqlx::query("DROP TABLE IF EXISTS _ws_test_mig_backup")
        .execute(&pool)
        .await
        .expect("drop stale backup table");
    sqlx::query("CREATE TABLE _ws_test_mig_backup AS SELECT * FROM _sqlx_migrations")
        .execute(&pool)
        .await
        .expect("back up migration bookkeeping rows");
    sqlx::query("DELETE FROM _sqlx_migrations")
        .execute(&pool)
        .await
        .expect("delete migration bookkeeping row");

    let outcome = connect(&url).await;

    // Restore before asserting, so a failing assertion cannot leave the
    // database without its bookkeeping row.
    sqlx::query("INSERT INTO _sqlx_migrations SELECT * FROM _ws_test_mig_backup")
        .execute(&pool)
        .await
        .expect("restore migration bookkeeping rows");
    sqlx::query("DROP TABLE _ws_test_mig_backup")
        .execute(&pool)
        .await
        .expect("drop backup table");

    let Err(err) = outcome else {
        panic!("connect must refuse a database whose migration bookkeeping was deleted");
    };
    assert!(
        matches!(
            err,
            CoreError::Migration {
                expected: REQUIRED_MIGRATION_COUNT,
                found: 0
            }
        ),
        "unexpected error: {err:?}"
    );
}
