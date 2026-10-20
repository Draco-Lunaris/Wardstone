//! Integration tests for `ws_core::repo` (tenant and CA repositories).
//!
//! These tests run against a live Postgres and are marked `#[ignore]`.
//! Run them with:
//!
//! ```sh
//! DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test \
//!     cargo test -p ws-core -- --include-ignored
//! ```
//!
//! # Self-cleaning contract
//!
//! The shared `wardstone_test` database is also used by `tests/db_test.rs`,
//! whose `connect_runs_migrations` asserts that `tenants` is empty. To keep
//! that true after every run of this suite, no matter how it exits:
//!
//! 1. Every test starts by sweeping away rows a previously crashed run of
//!    this suite may have left behind (this suite's owned names only, cas
//!    rows before their tenant).
//! 2. Every row inserted during the body is deleted — CAs before their
//!    tenant, tenants last — *before* any assertion runs, so a failing
//!    assertion cannot leave rows behind. All query results are captured
//!    and unwrapped only after cleanup.
//!
//! # Cross-process serialization
//!
//! Each test body holds a session-level Postgres advisory lock
//! (`pg_advisory_lock`, key [`ADVISORY_KEY`]) for its whole duration, so any
//! other process using the same key serializes against it (the in-process
//! [`DB_TEST_LOCK`] mutex mirrors `db_test.rs`'s pattern and serializes this
//! binary's tests against each other). Plain `cargo test` runs each
//! integration-test binary sequentially and `db_test.rs` does not insert
//! tenant rows, so that pair is additionally safe by construction.

use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex;

use ws_core::db::connect;
use ws_core::error::CoreError;
use ws_core::models::ca::{CaModel, KeyType};
use ws_core::repo::ca_repo::CaRepo;
use ws_core::repo::tenant_repo::TenantRepo;

/// Postgres advisory-lock key for this suite: ASCII "WARDST" (0x5741445354)
/// plus the suite marker 0x0003, i.e. `0x0057_4144_5354_0003`. Processes
/// taking this key serialize their test bodies against this suite.
const ADVISORY_KEY: i64 = 0x0057_4144_5354_0003;

/// Tenant name this suite owns in `wardstone_test`; deleted before asserts.
const DEFAULT_TENANT: &str = "default";

/// Tenant and CA names this suite owns for the CA roundtrip; deleted before
/// asserts.
const CAS_TENANT: &str = "rt-ca-tenant";
const ROOT_CA_NAME: &str = "rt-root-ca";

/// In-process serialization, the same whole-body lock pattern as
/// `db_test.rs`: the harness runs tests on separate threads. A tokio mutex
/// because the guard is held across `.await` points.
static DB_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// The guard must be held (not dropped) until the test body finishes.
#[must_use = "the database lock must stay bound for the whole test body"]
async fn lock_db() -> tokio::sync::MutexGuard<'static, ()> {
    DB_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().await
}

/// Take the session-level advisory lock on a dedicated pooled connection.
/// The connection stays checked out for the whole test body (the caller
/// holds the guard), so the lock is bound to it; it is released by
/// [`release_advisory`] or, on a panic path, when the pool is dropped during
/// unwinding.
async fn lock_advisory(pool: &PgPool) -> PoolConnection<sqlx::Postgres> {
    let mut conn = pool
        .acquire()
        .await
        .expect("acquire connection for the advisory lock");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(ADVISORY_KEY)
        .execute(&mut *conn)
        .await
        .expect("take pg_advisory_lock");
    conn
}

/// Release the advisory lock taken by [`lock_advisory`] explicitly, so the
/// connection never returns to the pool while still holding it.
async fn release_advisory(conn: &mut PoolConnection<sqlx::Postgres>) {
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(ADVISORY_KEY)
        .execute(&mut **conn)
        .await
        .expect("release pg_advisory_lock");
}

/// Test database URL; `DATABASE_URL` overrides it.
fn database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://wardstone:wardstone@localhost:5432/wardstone_test".to_string()
    })
}

/// Parse a fixed RFC 3339 timestamp at whole-second precision, so it survives
/// the Postgres `timestamptz` microsecond roundtrip with exact equality.
fn ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .expect("valid fixed test timestamp")
        .with_timezone(&Utc)
}

/// Inserting a tenant persists it and `get_by_name` returns the same row;
/// a second insert of the same name hits the unique constraint and maps to
/// `CoreError::Duplicate`. Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn tenant_insert_get_roundtrip() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply migration 001");
    let mut advisory = lock_advisory(&pool).await;

    // Sweep debris from any previously crashed run of this suite.
    sqlx::query("DELETE FROM tenants WHERE name = $1")
        .bind(DEFAULT_TENANT)
        .execute(&pool)
        .await
        .expect("sweep stale 'default' tenant");

    let repo = TenantRepo::new(&pool);
    let inserted = repo.insert(DEFAULT_TENANT).await;
    let fetched = repo.get_by_name(DEFAULT_TENANT).await;
    let duplicate = repo.insert(DEFAULT_TENANT).await;

    // Cleanup BEFORE asserting: the tenant row is gone here no matter how the
    // assertions below turn out.
    sqlx::query("DELETE FROM tenants WHERE name = $1")
        .bind(DEFAULT_TENANT)
        .execute(&pool)
        .await
        .expect("delete the inserted tenant");
    release_advisory(&mut advisory).await;

    let inserted = inserted.expect("insert tenant 'default'");
    let fetched = fetched
        .expect("get_by_name 'default'")
        .expect("row present after insert");
    let duplicate = duplicate.expect_err("second insert of the same name must fail");

    assert_eq!(fetched, inserted);
    assert_eq!(fetched.name, DEFAULT_TENANT);
    assert!(matches!(duplicate, CoreError::Duplicate));
}

/// Inserting a CA row roundtrips through `get` (including the `key_type`
/// text-column mapping), `list_by_tenant` finds it, and `children_of` on the
/// childless root returns empty. Cleans up before asserting: CAs first,
/// tenant last.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn ca_insert_get_list_roundtrip() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply migration 001");
    let mut advisory = lock_advisory(&pool).await;

    // Sweep debris from any previously crashed run: CA rows first (children
    // before parents), then the tenant itself.
    sqlx::query("DELETE FROM cas WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)")
        .bind(CAS_TENANT)
        .execute(&pool)
        .await
        .expect("sweep stale CA rows");
    sqlx::query("DELETE FROM tenants WHERE name = $1")
        .bind(CAS_TENANT)
        .execute(&pool)
        .await
        .expect("sweep stale tenant");

    let tenants = TenantRepo::new(&pool);
    let tenant = tenants
        .insert(CAS_TENANT)
        .await
        .expect("insert test tenant for CA rows");

    let model = CaModel {
        id: uuid::Uuid::new_v4(),
        tenant_id: tenant.id,
        name: ROOT_CA_NAME.to_string(),
        subject: "CN=Wardstone Test Root CA".to_string(),
        is_root: true,
        parent_id: None,
        key_type: KeyType::Ed25519,
        not_before: ts("2026-01-01T00:00:00Z"),
        not_after: ts("2027-01-01T00:00:00Z"),
        cert_pem: "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n".to_string(),
        key_file: "/var/lib/wardstone/keys/rt-root-ca.pem".to_string(),
        created_at: ts("2026-06-15T12:30:00Z"),
    };

    let cas = CaRepo::new(&pool);
    let insert_ca = cas.insert(&model).await;
    let get_ca = cas.get(model.id).await;
    let list = cas.list_by_tenant(tenant.id).await;
    let children = cas.children_of(model.id).await;

    // Cleanup BEFORE asserting: this tenant's CA rows (the suite inserted
    // exactly one), then the tenant. Runs whether or not the CA insert
    // succeeded.
    sqlx::query("DELETE FROM cas WHERE tenant_id = $1")
        .bind(tenant.id)
        .execute(&pool)
        .await
        .expect("delete the inserted CA row");
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant.id)
        .execute(&pool)
        .await
        .expect("delete the test tenant");
    release_advisory(&mut advisory).await;

    insert_ca.expect("insert root CA");
    assert_eq!(get_ca.expect("get CA").expect("row present"), model);
    let list = list.expect("list_by_tenant");
    assert_eq!(list.len(), 1, "list_by_tenant should find the one CA");
    assert_eq!(list[0], model);
    assert!(
        children.expect("children_of").is_empty(),
        "a root CA has no children"
    );
}
