//! Integration tests for `ws_ca::serial` — DB-backed serial allocation.
//!
//! These tests run against a live Postgres and are marked `#[ignore]`.
//! Run them with:
//!
//! ```sh
//! DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test \
//!     cargo test -p ws-ca --test serial_test -- --include-ignored
//! ```
//!
//! # Self-cleaning contract
//!
//! The shared `wardstone_test` database is also used by the ws-core suites,
//! one of which asserts that `tenants` is empty after its runs. To keep that
//! true no matter how this suite exits: every test sweeps away rows a
//! previously crashed run may have left behind under this suite's owned
//! tenant name (`used_serials` first — they reference the CA, then the CA,
//! then the tenant), and every row inserted during the body is deleted
//! *before* any assertion runs, so a failing assertion cannot leave rows
//! behind. All query results are captured and unwrapped only after cleanup.
//!
//! # Cross-process serialization
//!
//! Each test body holds a session-level Postgres advisory lock for its whole
//! duration on the key [`ADVISORY_KEY`] — the "WARDST" family (ASCII
//! "WARDST" = 0x5741445354) with suite marker 0x0006. ws-core's repo_test.rs
//! holds 0x0003 (tenant/CA suites), 0x0004 (certificate suite), and 0x0005
//! (audit suite); this suite owns a disjoint row set, and plain `cargo test`
//! also runs test binaries sequentially, so the key is a belt against
//! concurrent cross-crate runs. The in-process mutex mirrors the ws-core
//! pattern for future tests added to this binary.

use std::collections::HashSet;
use std::sync::OnceLock;

use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex;

use ws_ca::serial::allocate_serial;
use ws_core::db::connect;

/// Postgres advisory-lock key for this suite: ASCII "WARDST" (0x5741445354)
/// plus the suite marker 0x0006. Processes taking this key serialize their
/// test bodies against this suite.
const ADVISORY_KEY: i64 = 0x0057_4144_5354_0006;

/// Tenant and CA names this suite owns; deleted before asserts.
const SERIAL_TENANT: &str = "rt-serial-tenant";
const SERIAL_CA_NAME: &str = "rt-serial-ca";

/// In-process serialization, the same whole-body lock pattern as the
/// ws-core suites: the harness runs tests on separate threads. A tokio
/// mutex because the guard is held across `.await` points.
static DB_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// The guard must be held (not dropped) until the test body finishes.
#[must_use = "the database lock must stay bound for the whole test body"]
async fn lock_db() -> tokio::sync::MutexGuard<'static, ()> {
    DB_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().await
}

/// Take the session-level advisory lock `key` on a dedicated pooled
/// connection. The connection stays checked out for the whole test body
/// (the caller holds the guard), so the lock is bound to it; it is released
/// by [`release_advisory`] or, on a panic path, when the pool is dropped
/// during unwinding.
async fn lock_advisory(pool: &PgPool, key: i64) -> PoolConnection<sqlx::Postgres> {
    let mut conn = pool
        .acquire()
        .await
        .expect("acquire connection for the advisory lock");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(key)
        .execute(&mut *conn)
        .await
        .expect("take pg_advisory_lock");
    conn
}

/// Release the advisory lock taken by [`lock_advisory`] explicitly, so the
/// connection never returns to the pool while still holding it.
async fn release_advisory(conn: &mut PoolConnection<sqlx::Postgres>, key: i64) {
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(key)
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

/// Sweep any rows a previously crashed run of this suite may have left
/// behind under the owned tenant name: allocated serials first (they
/// reference the CA), then the CA, then the tenant.
async fn sweep_serial_rows(pool: &PgPool) {
    for sql in [
        "DELETE FROM used_serials WHERE ca_id IN \
         (SELECT id FROM cas WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1))",
        "DELETE FROM cas WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM tenants WHERE name = $1",
    ] {
        sqlx::query(sql)
            .bind(SERIAL_TENANT)
            .execute(pool)
            .await
            .expect("sweep stale serial-suite rows");
    }
}

/// Delete the serial tests' rows before asserts: the allocated serials, the
/// CA row, then the tenant. Runs whether or not the inserts succeeded.
async fn delete_serial_rows(pool: &PgPool, ca_id: uuid::Uuid, tenant_id: uuid::Uuid) {
    sqlx::query("DELETE FROM used_serials WHERE ca_id = $1")
        .bind(ca_id)
        .execute(pool)
        .await
        .expect("delete allocated serials");
    sqlx::query("DELETE FROM cas WHERE id = $1")
        .bind(ca_id)
        .execute(pool)
        .await
        .expect("delete the serial-suite CA row");
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("delete the serial-suite tenant");
}

/// One real tenants + cas row pair so `used_serials.ca_id`'s foreign key
/// holds; timestamps bind as text through an explicit `::timestamptz` cast
/// (the PEM body is a test placeholder, as in the ws-core suites). Returns
/// `(ca_id, tenant_id)` for cleanup.
async fn insert_serial_fixture(pool: &PgPool) -> (uuid::Uuid, uuid::Uuid) {
    let ca_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(tenant_id)
        .bind(SERIAL_TENANT)
        .execute(pool)
        .await
        .expect("insert test tenant for serial rows");
    sqlx::query(
        "INSERT INTO cas (id, tenant_id, name, subject, is_root, parent_id, key_type, \
         not_before, not_after, cert_pem, key_file) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz, $9::timestamptz, $10, $11)",
    )
    .bind(ca_id)
    .bind(tenant_id)
    .bind(SERIAL_CA_NAME)
    .bind("CN=Wardstone Test Serial CA")
    .bind(true)
    .bind(Option::<uuid::Uuid>::None)
    .bind("ed25519")
    .bind("2026-01-01T00:00:00Z")
    .bind("2027-01-01T00:00:00Z")
    .bind("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n")
    .bind("/var/lib/wardstone/keys/rt-serial-ca.pem")
    .execute(pool)
    .await
    .expect("insert test CA row for serial allocation");
    (ca_id, tenant_id)
}

/// Allocating 100 serials for one CA yields 100 distinct values (HashSet),
/// every one a positive 63-bit number (serial 0 is rejected as a collision,
/// and the bigint serial columns must always accept the value). Cleans up
/// before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn test_serial_allocation_unique() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    sweep_serial_rows(&pool).await;

    let (ca_id, tenant_id) = insert_serial_fixture(&pool).await;

    let mut serials = Vec::with_capacity(100);
    let mut allocation_error: Option<String> = None;
    for _ in 0..100 {
        match allocate_serial(ca_id, tenant_id, &pool).await {
            Ok(serial) => serials.push(serial),
            Err(err) => {
                allocation_error = Some(err.to_string());
                break;
            }
        }
    }
    let unique: HashSet<u128> = serials.iter().copied().collect();
    let all_fit_i64 = serials.iter().all(|s| *s <= i64::MAX as u128);
    let all_nonzero = serials.iter().all(|&s| s != 0);

    // Cleanup BEFORE asserting: no matter how the loop above turned out.
    delete_serial_rows(&pool, ca_id, tenant_id).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    assert!(
        allocation_error.is_none(),
        "all 100 allocations must succeed: {allocation_error:?}"
    );
    assert_eq!(serials.len(), 100);
    assert_eq!(
        unique.len(),
        100,
        "100 allocations must yield 100 distinct serials"
    );
    assert!(
        all_fit_i64,
        "allocated serials must fit the bigint serial column"
    );
    assert!(
        all_nonzero,
        "serial 0 is invalid (RFC 5280) and must never be returned"
    );
}

/// The transactional contract: `allocate_serial` yields a serial only after
/// its INSERT persisted — the exact value is immediately present in
/// `used_serials`. Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn test_serial_allocation_persists() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    sweep_serial_rows(&pool).await;

    let (ca_id, tenant_id) = insert_serial_fixture(&pool).await;

    let allocated = allocate_serial(ca_id, tenant_id, &pool).await;
    let stored: Result<Vec<i64>, sqlx::Error> =
        sqlx::query_scalar("SELECT serial FROM used_serials WHERE ca_id = $1")
            .bind(ca_id)
            .fetch_all(&pool)
            .await;

    // Cleanup BEFORE asserting.
    delete_serial_rows(&pool, ca_id, tenant_id).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    let allocated = allocated.expect("allocate one serial");
    let stored = stored.expect("query used_serials");
    let stored: Vec<u128> = stored
        .into_iter()
        .map(|s| u128::try_from(s).expect("stored serials are positive"))
        .collect();
    assert_eq!(
        stored,
        vec![allocated],
        "the allocated serial must persist before allocate_serial returns"
    );
}

/// The tenancy contract: the `used_serials` row is attributable to the
/// tenant the allocation was made for. The allocator writes the tenant id
/// the caller supplied (it never looks the CA up), and the row carries it
/// — migration 005 makes every table tenant-attributable. Cleans up
/// before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn test_serial_allocation_records_the_tenant() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    sweep_serial_rows(&pool).await;

    let (ca_id, tenant_id) = insert_serial_fixture(&pool).await;

    let allocated = allocate_serial(ca_id, tenant_id, &pool).await;
    // The column itself, read back from the table.
    let stored_tenant: Result<Option<uuid::Uuid>, sqlx::Error> =
        sqlx::query_scalar("SELECT tenant_id FROM used_serials WHERE ca_id = $1 AND serial = $2")
            .bind(ca_id)
            .bind(i64::try_from(allocated.expect("allocate one serial")).expect("serial fits i64"))
            .fetch_one(&pool)
            .await;

    // Cleanup BEFORE asserting.
    delete_serial_rows(&pool, ca_id, tenant_id).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    let stored_tenant = stored_tenant.expect("query the stored tenant_id");
    assert_eq!(
        stored_tenant,
        Some(tenant_id),
        "the used_serials row carries the tenant it was allocated for"
    );
}
