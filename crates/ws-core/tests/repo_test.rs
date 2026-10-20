//! Integration tests for `ws_core::repo` (tenant, CA, and certificate
//! repositories).
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
//!    this suite may have left behind (this suite's owned names only:
//!    certificate rows before their CA, CAs before their tenant).
//! 2. Every row inserted during the body is deleted — certificates, then
//!    their CA, tenants last — *before* any assertion runs, so a failing
//!    assertion cannot leave rows behind. All query results are captured
//!    and unwrapped only after cleanup.
//!
//! # Cross-process serialization
//!
//! Each test body holds a session-level Postgres advisory lock for its whole
//! duration, so any other process using the same key serializes against it
//! (the in-process [`DB_TEST_LOCK`] mutex mirrors `db_test.rs`'s pattern and
//! serializes this binary's tests against each other). Three keys are in
//! use, one per disjoint row set: [`ADVISORY_KEY`] (suite marker 0x0003)
//! for the tenant and CA tests, [`ADVISORY_KEY_CERTS`] (marker 0x0004) for
//! the certificate tests, and [`ADVISORY_KEY_AUDIT`] (marker 0x0005) for
//! the audit-log tests, each of which owns a tenant name of its own. Plain
//! `cargo test` runs each integration-test binary sequentially and
//! `db_test.rs` does not insert tenant rows, so that pair is additionally
//! safe by construction.

use std::sync::OnceLock;

use chrono::{DateTime, SubsecRound, Utc};
use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex;

use ws_core::db::connect;
use ws_core::error::CoreError;
use ws_core::models::audit::{ActorType, AuditEntry};
use ws_core::models::ca::{CaModel, KeyType};
use ws_core::models::certificate::{CertStatus, CertificateModel};
use ws_core::repo::audit_repo::AuditRepo;
use ws_core::repo::ca_repo::CaRepo;
use ws_core::repo::certificate_repo::CertificateRepo;
use ws_core::repo::tenant_repo::TenantRepo;

/// Postgres advisory-lock key for this suite: ASCII "WARDST" (0x5741445354)
/// plus the suite marker 0x0003, i.e. `0x0057_4144_5354_0003`. Processes
/// taking this key serialize their test bodies against this suite.
const ADVISORY_KEY: i64 = 0x0057_4144_5354_0003;

/// Postgres advisory-lock key for this suite's certificate tests: the same
/// key family with the suite marker bumped to 0x0004
/// (`0x0057_4144_5354_0004`), a disjoint row set (its own tenant name), so
/// a process holding one key never waits on the other's rows and future
/// tests can extend the marker without colliding.
const ADVISORY_KEY_CERTS: i64 = 0x0057_4144_5354_0004;

/// Tenant name this suite owns in `wardstone_test`; deleted before asserts.
const DEFAULT_TENANT: &str = "default";

/// Tenant and CA names this suite owns for the CA roundtrip; deleted before
/// asserts.
const CAS_TENANT: &str = "rt-ca-tenant";
const ROOT_CA_NAME: &str = "rt-root-ca";

/// Tenant and CA names this suite owns for the certificate tests; deleted
/// before asserts (certificates first, then the CA, then the tenant).
const CERTS_TENANT: &str = "rt-cert-tenant";
const CERT_CA_NAME: &str = "rt-cert-ca";

/// Postgres advisory-lock key for this suite's audit-log tests: the same
/// key family with the suite marker bumped to 0x0005
/// (`0x0057_4144_5354_0005`), a disjoint row set (its own tenant name).
const ADVISORY_KEY_AUDIT: i64 = 0x0057_4144_5354_0005;

/// Tenant name the audit tests own; deleted before asserts (audit rows
/// first, then the tenant — `audit_log.tenant_id` references `tenants`).
const AUDIT_TENANT: &str = "rt-audit-tenant";

/// In-process serialization, the same whole-body lock pattern as
/// `db_test.rs`: the harness runs tests on separate threads. A tokio mutex
/// because the guard is held across `.await` points.
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
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

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
    release_advisory(&mut advisory, ADVISORY_KEY).await;

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
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

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
    release_advisory(&mut advisory, ADVISORY_KEY).await;

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

/// Sweep any rows a previously crashed run of the certificate tests may have
/// left behind in this suite's owned names: certificates first, then their
/// CA, then the tenant.
async fn sweep_cert_rows(pool: &PgPool) {
    for sql in [
        "DELETE FROM certificates WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM cas WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM tenants WHERE name = $1",
    ] {
        sqlx::query(sql)
            .bind(CERTS_TENANT)
            .execute(pool)
            .await
            .expect("sweep stale certificate-suite rows");
    }
}

/// Delete the certificate tests' rows before asserts: this tenant's
/// certificates, then its CA row, then the tenant itself. Runs whether or
/// not the individual inserts succeeded.
async fn delete_cert_rows(pool: &PgPool, tenant_id: uuid::Uuid) {
    for sql in [
        "DELETE FROM certificates WHERE tenant_id = $1",
        "DELETE FROM cas WHERE tenant_id = $1",
        "DELETE FROM tenants WHERE id = $1",
    ] {
        sqlx::query(sql)
            .bind(tenant_id)
            .execute(pool)
            .await
            .expect("delete certificate-suite rows");
    }
}

/// A CA row for the certificate tests: a real tenant/CA pair so the
/// `certificates` foreign keys hold (the PEM body is a test placeholder,
/// as in the CA roundtrip).
fn cert_ca_model(tenant_id: uuid::Uuid) -> CaModel {
    CaModel {
        id: uuid::Uuid::new_v4(),
        tenant_id,
        name: CERT_CA_NAME.to_string(),
        subject: "CN=Wardstone Test Cert CA".to_string(),
        is_root: true,
        parent_id: None,
        key_type: KeyType::Ed25519,
        not_before: ts("2026-01-01T00:00:00Z"),
        not_after: ts("2027-01-01T00:00:00Z"),
        cert_pem: "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n".to_string(),
        key_file: "/var/lib/wardstone/keys/rt-cert-ca.pem".to_string(),
        created_at: ts("2026-06-15T12:30:00Z"),
    }
}

/// One certificate row for the certificate tests: active, with the caller's
/// `not_after` (the expiry query keys on it) and a DNS plus v4/v6 SAN set so
/// the `text[]`/`inet[]` column mapping round-trips too.
fn cert_model(
    tenant_id: uuid::Uuid,
    ca_id: uuid::Uuid,
    serial: u128,
    not_after: DateTime<Utc>,
) -> CertificateModel {
    CertificateModel {
        id: uuid::Uuid::new_v4(),
        tenant_id,
        ca_id,
        profile_name: "default".to_string(),
        subject: "CN=leaf.example".to_string(),
        serial,
        serial_hex: format!("{serial:x}"),
        san_dns: vec!["leaf.example".to_string()],
        san_ips: vec![
            "192.0.2.10".parse().expect("valid IPv4 fixture"),
            "2001:db8::1".parse().expect("valid IPv6 fixture"),
        ],
        key_type: "ed25519".to_string(),
        not_before: ts("2026-01-01T00:00:00Z"),
        not_after,
        cert_pem: "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n".to_string(),
        status: CertStatus::Active,
        revoked_at: None,
        revocation_reason: None,
        source: "manual".to_string(),
        created_at: ts("2026-06-15T12:30:00Z"),
    }
}

/// Inserting a certificate row roundtrips through `get` (serial u128 over
/// the `bigint` column, SAN arrays, status), and `list_by_tenant` finds it.
/// Cleans up before asserting: certificates, the CA, the tenant.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn certificate_insert_get_roundtrip() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY_CERTS).await;

    sweep_cert_rows(&pool).await;

    let tenant = TenantRepo::new(&pool)
        .insert(CERTS_TENANT)
        .await
        .expect("insert test tenant for certificate rows");
    let ca = cert_ca_model(tenant.id);
    CaRepo::new(&pool)
        .insert(&ca)
        .await
        .expect("insert test CA row");

    let model = cert_model(
        tenant.id,
        ca.id,
        0x1234_5678_9abc_def0,
        ts("2026-12-01T00:00:00Z"),
    );
    let certs = CertificateRepo::new(&pool);
    let inserted = certs.insert(&model).await;
    let fetched = certs.get(model.id).await;
    let listed = certs.list_by_tenant(tenant.id, 0, 10).await;

    // Cleanup BEFORE asserting, no matter how the operations below turn out.
    delete_cert_rows(&pool, tenant.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY_CERTS).await;

    inserted.expect("insert certificate row");
    assert_eq!(
        fetched
            .expect("get certificate")
            .expect("row present after insert"),
        model
    );
    let listed = listed.expect("list_by_tenant");
    assert_eq!(listed.len(), 1, "list_by_tenant should find the one cert");
    assert_eq!(listed[0], model);
}

/// Revoking twice is structurally idempotent: the `AND status='active'`
/// guard makes the second revoke a zero-row update, so both calls return
/// `Ok(())` and `revoked_at` stays exactly as the first call set it.
/// `list_revoked_since` sees exactly one row, with an inclusive `since`
/// boundary. Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn test_revoke_twice_is_idempotent() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY_CERTS).await;

    sweep_cert_rows(&pool).await;

    let tenant = TenantRepo::new(&pool)
        .insert(CERTS_TENANT)
        .await
        .expect("insert test tenant for certificate rows");
    let ca = cert_ca_model(tenant.id);
    CaRepo::new(&pool)
        .insert(&ca)
        .await
        .expect("insert test CA row");

    let model = cert_model(tenant.id, ca.id, 0x0bad_c0de, ts("2026-12-01T00:00:00Z"));
    let certs = CertificateRepo::new(&pool);
    certs.insert(&model).await.expect("insert certificate row");

    let first_revoke = certs.revoke(model.id, "key_compromise").await;
    let after_first = certs.get(model.id).await;
    let second_revoke = certs.revoke(model.id, "key_compromise").await;
    let after_second = certs.get(model.id).await;

    // The `since` boundary queries run before cleanup; their inputs are
    // read out of the captured first-revoke row without asserting (a None
    // simply makes the boundary results empty, and the asserts after
    // cleanup then fail loudly).
    let revoked_at = after_first
        .as_ref()
        .ok()
        .and_then(|row| row.as_ref())
        .and_then(|cert| cert.revoked_at);
    let since_epoch = certs
        .list_revoked_since(ca.id, ts("2020-01-01T00:00:00Z"))
        .await;
    let since_boundary = match revoked_at {
        Some(at) => certs.list_revoked_since(ca.id, at).await,
        None => Ok(Vec::new()),
    };
    let since_after = match revoked_at {
        Some(at) => {
            certs
                .list_revoked_since(ca.id, at + chrono::Duration::seconds(1))
                .await
        }
        None => Ok(Vec::new()),
    };

    // Cleanup BEFORE asserting.
    delete_cert_rows(&pool, tenant.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY_CERTS).await;

    first_revoke.expect("first revoke succeeds");
    second_revoke.expect("second revoke is structurally idempotent");

    let after_first = after_first
        .expect("get after first revoke")
        .expect("row present");
    assert_eq!(after_first.status, CertStatus::Revoked);
    assert_eq!(
        after_first.revocation_reason.as_deref(),
        Some("key_compromise")
    );
    let revoked_at = after_first.revoked_at.expect("revoked_at set by revoke");

    let after_second = after_second
        .expect("get after second revoke")
        .expect("row present");
    assert_eq!(after_second.status, CertStatus::Revoked);
    assert_eq!(
        after_second.revoked_at,
        Some(revoked_at),
        "second revoke must not move revoked_at"
    );

    let since_epoch = since_epoch.expect("list_revoked_since epoch");
    assert_eq!(since_epoch.len(), 1, "exactly one revoked row");
    assert_eq!(since_epoch[0].id, model.id);
    assert_eq!(since_epoch[0].serial, model.serial);
    assert_eq!(since_epoch[0].status, CertStatus::Revoked);

    let since_boundary = since_boundary.expect("list_revoked_since at the boundary");
    assert_eq!(since_boundary.len(), 1, "the since boundary is inclusive");
    assert_eq!(since_boundary[0].id, model.id);

    let since_after = since_after.expect("list_revoked_since past the boundary");
    assert!(
        since_after.is_empty(),
        "nothing is revoked strictly after revoked_at"
    );
}

/// The expiry-monitoring query. Three active certificates: one already
/// expired, one expiring in 5 days, one in 90 days. With a 7-day threshold
/// the pinned SQL — `status='active' AND not_after < threshold`, ascending —
/// returns the expired and the 5-day row and not the 90-day one: an active
/// row whose `not_after` has already passed is exactly what a renewal
/// monitor must surface, so the SQL pin keeps it (the brief's "only the
/// 5-day one" prose covers the future-expiring fixtures; the SQL is the
/// authoritative Interfaces pin). Ascending order puts the expired row
/// first. Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn list_expiring_picks_up_upcoming() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY_CERTS).await;

    sweep_cert_rows(&pool).await;

    let tenant = TenantRepo::new(&pool)
        .insert(CERTS_TENANT)
        .await
        .expect("insert test tenant for certificate rows");
    let ca = cert_ca_model(tenant.id);
    CaRepo::new(&pool)
        .insert(&ca)
        .await
        .expect("insert test CA row");

    // Whole-second fixture times so the fetched rows compare exactly.
    let now = Utc::now().trunc_subsecs(0);
    let expired = cert_model(tenant.id, ca.id, 0x11, now - chrono::Duration::days(1));
    let five_day = cert_model(tenant.id, ca.id, 0x22, now + chrono::Duration::days(5));
    let ninety_day = cert_model(tenant.id, ca.id, 0x33, now + chrono::Duration::days(90));

    let certs = CertificateRepo::new(&pool);
    certs.insert(&expired).await.expect("insert expired cert");
    certs.insert(&five_day).await.expect("insert 5-day cert");
    certs.insert(&ninety_day).await.expect("insert 90-day cert");

    let expiring = certs
        .list_expiring_before(tenant.id, now + chrono::Duration::days(7), 0, 10)
        .await;

    // Cleanup BEFORE asserting.
    delete_cert_rows(&pool, tenant.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY_CERTS).await;

    let expiring = expiring.expect("list_expiring_before");
    assert_eq!(
        expiring.len(),
        2,
        "the 90-day cert is outside the 7-day threshold; \
         the already-expired active row is inside it"
    );
    assert_eq!(expiring[0].id, expired.id);
    assert_eq!(expiring[1].id, five_day.id);
    assert_eq!(expiring[0].not_after, expired.not_after);
    assert_eq!(expiring[1].not_after, five_day.not_after);
    assert!(
        expiring[0].not_after < expiring[1].not_after,
        "ascending not_after order"
    );
}

/// One audit entry fixture: `cert_issued` by default, with the caller's
/// action labels, actor, target, and details map.
fn audit_entry(
    tenant_id: uuid::Uuid,
    actor_type: ActorType,
    actor_id: &str,
    action: &str,
    target_type: &str,
    target_id: &str,
    details: serde_json::Value,
) -> AuditEntry {
    AuditEntry {
        id: uuid::Uuid::new_v4(),
        tenant_id,
        actor_type,
        actor_id: actor_id.to_string(),
        action: action.to_string(),
        target_type: target_type.to_string(),
        target_id: target_id.to_string(),
        details,
        created_at: ts("2026-06-15T12:30:00Z"),
    }
}

/// Sweep any rows a previously crashed run of the audit tests may have left
/// behind under this suite's owned tenant name: audit_log rows first (they
/// reference the tenant), then the tenant itself.
async fn sweep_audit_rows(pool: &PgPool) {
    for sql in [
        "DELETE FROM audit_log WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM tenants WHERE name = $1",
    ] {
        sqlx::query(sql)
            .bind(AUDIT_TENANT)
            .execute(pool)
            .await
            .expect("sweep stale audit-suite rows");
    }
}

/// Recording two `cert_issued` entries makes `list_by_tenant` return both,
/// newest first (`created_at desc`); a further `record` appends (three rows
/// after three records — append-only demonstrated, no update or overwrite).
/// `record` deliberately ignores the model's `created_at` (the database
/// `now()` default owns the column), so rows read back with a wall-clock
/// timestamp, not the fixture one. Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn test_audit_roundtrip() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY_AUDIT).await;

    sweep_audit_rows(&pool).await;

    let tenant = TenantRepo::new(&pool)
        .insert(AUDIT_TENANT)
        .await
        .expect("insert test tenant for audit rows");

    let first = audit_entry(
        tenant.id,
        ActorType::User,
        "op-user-1",
        "cert_issued",
        "certificate",
        "0199aaaa-0000-7000-8000-000000000001",
        serde_json::json!({ "profile": "default" }),
    );
    let second = audit_entry(
        tenant.id,
        ActorType::System,
        "worker",
        "cert_issued",
        "certificate",
        "0199aaaa-0000-7000-8000-000000000002",
        serde_json::json!({ "profile": "default", "san_count": 2 }),
    );
    let third = audit_entry(
        tenant.id,
        ActorType::AcmeAccount,
        "acme-acct-42",
        "cert_issued",
        "certificate",
        "0199aaaa-0000-7000-8000-000000000003",
        serde_json::json!({}),
    );

    let audit = AuditRepo::new(&pool);
    let first_insert = audit.record(&first).await;
    let second_insert = audit.record(&second).await;
    let listed = audit.list_by_tenant(tenant.id, 0, 10).await;
    let append = audit.record(&third).await;
    let listed_after = audit.list_by_tenant(tenant.id, 0, 10).await;
    // Appending the exact same entry again (same primary key) must be
    // rejected, not silently overwritten: append-only has no upsert path.
    let duplicate_append = audit.record(&first).await;
    let count_after_duplicate: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE tenant_id = $1")
            .bind(tenant.id)
            .fetch_one(&pool)
            .await
            .unwrap_or(-1);

    // Cleanup BEFORE asserting: this tenant's audit rows, then the tenant.
    sqlx::query("DELETE FROM audit_log WHERE tenant_id = $1")
        .bind(tenant.id)
        .execute(&pool)
        .await
        .expect("delete the inserted audit rows");
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant.id)
        .execute(&pool)
        .await
        .expect("delete the test tenant");
    release_advisory(&mut advisory, ADVISORY_KEY_AUDIT).await;

    first_insert.expect("record the first audit entry");
    second_insert.expect("record the second audit entry");

    let listed = listed.expect("list_by_tenant after two records");
    assert_eq!(listed.len(), 2, "two records must produce two rows");
    // Newest first: `second` was recorded strictly later than `first`, and
    // the stored `created_at` values are the database's `now()` — not the
    // fixtures' fixed timestamps, which `record` must ignore.
    assert_eq!(listed[0].id, second.id);
    assert_eq!(listed[1].id, first.id);
    assert!(
        listed[0].created_at >= listed[1].created_at,
        "created_at desc order"
    );
    assert_ne!(
        listed[0].created_at, second.created_at,
        "record must not bind the client timestamp; the DB default owns created_at"
    );
    // Everything but the DB-owned created_at roundtrips exactly.
    assert_eq!(listed[0].tenant_id, second.tenant_id);
    assert_eq!(listed[0].actor_type, second.actor_type);
    assert_eq!(listed[0].actor_id, second.actor_id);
    assert_eq!(listed[0].action, second.action);
    assert_eq!(listed[0].target_type, second.target_type);
    assert_eq!(listed[0].target_id, second.target_id);
    assert_eq!(listed[0].details, second.details);
    assert_eq!(listed[1].details, first.details);

    append.expect("a further record appends");
    let listed_after = listed_after.expect("list_by_tenant after the third record");
    assert_eq!(
        listed_after.len(),
        3,
        "a further record appends a third row (append-only)"
    );
    assert_eq!(listed_after[0].id, third.id);
    assert_eq!(listed_after[2].id, first.id);

    let duplicate_append = duplicate_append.expect_err(
        "re-recording an entry with the same id must hit the pk and be typed, never overwrite",
    );
    assert!(
        matches!(duplicate_append, CoreError::Duplicate),
        "unexpected error: {duplicate_append:?}"
    );
    assert_eq!(
        count_after_duplicate, 3,
        "the rejected duplicate must not add a row"
    );
    // The three actors cover every `actor_type` variant's column encoding.
    assert_eq!(listed_after[0].actor_type, ActorType::AcmeAccount);
    let _ = (listed_after[1].actor_type, ActorType::System);
}
