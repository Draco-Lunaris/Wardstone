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
/// up with `REQUIRED_MIGRATION_COUNT` rows, and `tenants` exists — migration
/// 001 seeds NO tenant (Plan 2's first-run setup inserts the default tenant).
///
/// The original assertion pinned `tenants == 0`; Plan 2's DB-gated suites
/// legitimately create tenants (the setup flow, `POST /api/v1/tenants`, the
/// e2e), so the property is scoped to what migration 001 can own: the
/// tenant-name SET is snapshotted before and after the `connect` under test,
/// and `connect` must not change it — whether that set is empty (a virgin
/// database, where the tenants table does not exist before the first connect
/// and the snapshot is empty by construction) or carries another suite's
/// rows.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn connect_runs_migrations() {
    let _db = lock_db().await;
    let url = database_url();
    // Snapshot the tenant names BEFORE the connect under test, over a plain
    // pooled connection (the connect under test brings its own migrations).
    let probe = sqlx::PgPool::connect(&url)
        .await
        .expect("open a probe pool to snapshot the tenant names");
    let before: Vec<String> = match sqlx::query_scalar("SELECT name FROM tenants ORDER BY name")
        .fetch_all(&probe)
        .await
    {
        Ok(names) => names,
        // 42P01 = undefined_table: a virgin database, nothing seeded.
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("42P01") => {
            Vec::new()
        }
        Err(err) => panic!("could not snapshot the tenant names: {err}"),
    };
    probe.close().await;

    let pool = connect(&url)
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

    let after: Vec<String> = sqlx::query_scalar("SELECT name FROM tenants ORDER BY name")
        .fetch_all(&pool)
        .await
        .expect("query the tenant names after connect");
    assert_eq!(
        after, before,
        "connect must not seed or add tenants: migration 001 creates the table and \
         nothing else (Plan 2's first-run setup inserts the default tenant)"
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

/// Task 10 (D5): the external-DB URL policy — `check_database_url` is
/// pure (parse, don't connect), so this arm runs WITHOUT the database
/// and WITHOUT the suite lock: it never touches the shared server.
///
/// The rule: a socket host is a local link (D8's own-uid gate is the
/// protection there, not TLS — the bundled compose form rides the
/// authority percent-encoded, the one spelling sqlx parses); a TCP host
/// is an EXTERNAL database and must carry BOTH protections —
/// `sslmode=verify-full` and `sslrootcert=<path>` (the operator's
/// mounted CA bundle) — and the refusal names both, whatever is
/// missing.
#[test]
fn an_external_url_without_verify_full_is_refused() {
    use ws_core::db::check_database_url;

    // Socket forms: local links, admitted without any TLS keys. The
    // socket rides the URL's authority percent-encoded — the libpq
    // empty-host spelling (`user@/db?host=/path`) does not parse at
    // all (the url crate refuses an authority whose host is empty),
    // and the binary's password splice needs the userinfo, so the
    // percent-encoded authority is the compose contract's spelling.
    assert!(
        check_database_url("postgres://wardstone@%2Frun%2Fwardstone%2Fpg/wardstone").is_ok(),
        "the bundled socket form (the compose contract) is a local link"
    );
    assert!(
        check_database_url("postgres://wardstone@%2Fvar%2Frun%2Fpostgresql/wardstone_test").is_ok(),
        "a percent-encoded socket host is a local link"
    );
    assert!(
        check_database_url("postgres://wardstone@/wardstone?host=/run/wardstone/pg").is_err(),
        "the libpq empty-host spelling does not parse: refused, not misread"
    );

    // sslmode=require is a downgrade (no hostname/CA verification): the
    // refusal names BOTH the missing verify-full and the CA bundle.
    let err =
        check_database_url("postgres://wardstone@db.example.com:5432/wardstone?sslmode=require")
            .expect_err("sslmode=require is not verify-full and must be refused");
    let text = err.to_string();
    assert!(
        text.contains("verify-full"),
        "the refusal names sslmode=verify-full, got: {text}"
    );
    assert!(
        text.contains("sslrootcert"),
        "the refusal names the sslrootcert requirement too, got: {text}"
    );

    // verify-full WITHOUT the operator's CA bundle: the refusal still
    // names both protections.
    let err = check_database_url(
        "postgres://wardstone@db.example.com:5432/wardstone?sslmode=verify-full",
    )
    .expect_err("verify-full without sslrootcert must be refused");
    let text = err.to_string();
    assert!(
        text.contains("verify-full") && text.contains("sslrootcert"),
        "the refusal names both protections, got: {text}"
    );

    // The fully-armed external form passes the policy (whether the
    // server answers is `connect`'s concern, not this check's).
    assert!(
        check_database_url(
            "postgres://wardstone@db.example.com:5432/wardstone?\
             sslmode=verify-full&sslrootcert=/etc/ssl/certs/ca.crt"
        )
        .is_ok(),
        "verify-full plus sslrootcert is the one admitted external form"
    );

    // An unparsable URL is a configuration error, not a panic.
    let err = check_database_url("not-a-url").expect_err("garbage must be refused, not parsed");
    assert!(
        !err.to_string().is_empty(),
        "the parse failure carries a typed error message"
    );
}
