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
use ws_core::models::audit::{ActorType, AuditEntry, AuthMethod};
use ws_core::models::ca::{CaModel, KeyType};
use ws_core::models::certificate::{CertStatus, CertificateModel};
use ws_core::models::credential::{
    OidcConfigModel, OneShotTokenModel, RefreshTokenModel, ServiceIdentityModel,
};
use ws_core::models::ocsp::{OcspResponseModel, OcspStatus};
use ws_core::models::profile::{ProfileModel, ProfileRevisionModel};
use ws_core::models::rbac::{Capability, Role};
use ws_core::models::user::UserModel;
use ws_core::repo::audit_repo::AuditRepo;
use ws_core::repo::ca_repo::CaRepo;
use ws_core::repo::certificate_repo::CertificateRepo;
use ws_core::repo::credential_repo::CredentialRepo;
use ws_core::repo::ocsp_repo::OcspRepo;
use ws_core::repo::oidc_repo::OidcConfigRepo;
use ws_core::repo::paging;
use ws_core::repo::profile_repo::ProfileRepo;
use ws_core::repo::refresh_repo::RefreshTokenRepo;
use ws_core::repo::role_repo::RoleRepo;
use ws_core::repo::tenant_repo::TenantRepo;
use ws_core::repo::user_repo::UserRepo;

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

/// Postgres advisory-lock key for this suite's tenant-consistency tests:
/// the same key family with the suite marker bumped to 0x000a
/// (`0x0057_4144_5354_000a`), a disjoint row set (its own two tenant
/// names), so a process holding one key never waits on the other's rows.
const ADVISORY_KEY_TENANT_FK: i64 = 0x0057_4144_5354_000a;

/// The two tenant names this suite owns for the tenant-consistency tests;
/// deleted before asserts (child rows first, then the CAs, then the
/// tenants).
const TENANT_FK_TENANT_A: &str = "rt-tenantfk-a";
const TENANT_FK_TENANT_B: &str = "rt-tenantfk-b";

/// The CA name this suite owns for the tenant-consistency tests (unique
/// per tenant, so the same name may be used under both tenants).
const TENANT_FK_CA_NAME: &str = "rt-tenantfk-ca";

/// Tenant name the audit tests own; deleted before asserts (audit rows
/// first, then the tenant — `audit_log.tenant_id` references `tenants`).
const AUDIT_TENANT: &str = "rt-audit-tenant";

/// Postgres advisory-lock key for this suite's OCSP-response tests: the
/// same key family with the suite marker bumped to 0x0007
/// (`0x0057_4144_5354_0007`), a disjoint row set (its own tenant name).
const ADVISORY_KEY_OCSP: i64 = 0x0057_4144_5354_0007;

/// Tenant and CA names this suite owns for the OCSP-response tests;
/// deleted before asserts (OCSP responses first — they reference the CA
/// — then the CA, then the tenant).
const OCSP_TENANT: &str = "rt-ocsp-tenant";
const OCSP_CA_NAME: &str = "rt-ocsp-ca";

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

    let repo = TenantRepo::new();
    let inserted = repo.insert(&pool, DEFAULT_TENANT).await;
    let fetched = repo.get_by_name(&pool, DEFAULT_TENANT).await;
    let duplicate = repo.insert(&pool, DEFAULT_TENANT).await;

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

    let tenants = TenantRepo::new();
    let tenant = tenants
        .insert(&pool, CAS_TENANT)
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

    let cas = CaRepo::new();
    let insert_ca = cas.insert(&pool, &model).await;
    let get_ca = cas.get(&pool, model.id).await;
    let list = cas.list_by_tenant(&pool, tenant.id).await;
    let children = cas.children_of(&pool, model.id).await;

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
        profile_revision_id: None,
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
        revocation_detail: None,
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

    let tenant = TenantRepo::new()
        .insert(&pool, CERTS_TENANT)
        .await
        .expect("insert test tenant for certificate rows");
    let ca = cert_ca_model(tenant.id);
    CaRepo::new()
        .insert(&pool, &ca)
        .await
        .expect("insert test CA row");

    let model = cert_model(
        tenant.id,
        ca.id,
        0x1234_5678_9abc_def0,
        ts("2026-12-01T00:00:00Z"),
    );
    let certs = CertificateRepo::new();
    let inserted = certs.insert(&pool, &model).await;
    let fetched = certs.get(&pool, model.id).await;
    let listed = certs.list_by_tenant(&pool, tenant.id, 0, 10).await;

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

    let tenant = TenantRepo::new()
        .insert(&pool, CERTS_TENANT)
        .await
        .expect("insert test tenant for certificate rows");
    let ca = cert_ca_model(tenant.id);
    CaRepo::new()
        .insert(&pool, &ca)
        .await
        .expect("insert test CA row");

    let model = cert_model(tenant.id, ca.id, 0x0bad_c0de, ts("2026-12-01T00:00:00Z"));
    let certs = CertificateRepo::new();
    certs
        .insert(&pool, &model)
        .await
        .expect("insert certificate row");

    let first_revoke = certs
        .revoke(
            &pool,
            model.id,
            "key_compromise",
            Some("key held by an ex-employee"),
        )
        .await;
    let after_first = certs.get(&pool, model.id).await;
    let second_revoke = certs
        .revoke(
            &pool,
            model.id,
            "superseded",
            Some("a second revoke must not win"),
        )
        .await;
    let after_second = certs.get(&pool, model.id).await;

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
        .list_revoked_since(&pool, ca.id, ts("2020-01-01T00:00:00Z"))
        .await;
    let since_boundary = match revoked_at {
        Some(at) => certs.list_revoked_since(&pool, ca.id, at).await,
        None => Ok(Vec::new()),
    };
    let since_after = match revoked_at {
        Some(at) => {
            certs
                .list_revoked_since(&pool, ca.id, at + chrono::Duration::seconds(1))
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
    assert_eq!(
        after_first.revocation_detail.as_deref(),
        Some("key held by an ex-employee")
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
    assert_eq!(
        after_second.revocation_reason.as_deref(),
        Some("key_compromise"),
        "the second revoke keeps the FIRST reason"
    );
    assert_eq!(
        after_second.revocation_detail.as_deref(),
        Some("key held by an ex-employee"),
        "the second revoke keeps the FIRST detail"
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

    let tenant = TenantRepo::new()
        .insert(&pool, CERTS_TENANT)
        .await
        .expect("insert test tenant for certificate rows");
    let ca = cert_ca_model(tenant.id);
    CaRepo::new()
        .insert(&pool, &ca)
        .await
        .expect("insert test CA row");

    // Whole-second fixture times so the fetched rows compare exactly.
    let now = Utc::now().trunc_subsecs(0);
    let expired = cert_model(tenant.id, ca.id, 0x11, now - chrono::Duration::days(1));
    let five_day = cert_model(tenant.id, ca.id, 0x22, now + chrono::Duration::days(5));
    let ninety_day = cert_model(tenant.id, ca.id, 0x33, now + chrono::Duration::days(90));

    let certs = CertificateRepo::new();
    certs
        .insert(&pool, &expired)
        .await
        .expect("insert expired cert");
    certs
        .insert(&pool, &five_day)
        .await
        .expect("insert 5-day cert");
    certs
        .insert(&pool, &ninety_day)
        .await
        .expect("insert 90-day cert");

    let expiring = certs
        .list_expiring_before(&pool, tenant.id, now + chrono::Duration::days(7), 0, 10)
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

/// The slim column projection the dashboard sieve reads: exactly
/// (id, subject, serial_hex, not_after, status) — no PEM, no SAN arrays —
/// with the typed status decode, the `not_after DESC` order, the optional
/// status filter, and the shared paging. Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn list_slim_projects_only_the_slim_columns() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY_CERTS).await;

    sweep_cert_rows(&pool).await;

    let tenant = TenantRepo::new()
        .insert(&pool, CERTS_TENANT)
        .await
        .expect("insert test tenant for certificate rows");
    let ca = cert_ca_model(tenant.id);
    CaRepo::new()
        .insert(&pool, &ca)
        .await
        .expect("insert test CA row");

    let now = Utc::now().trunc_subsecs(0);
    let mut soonest = cert_model(tenant.id, ca.id, 0x44, now + chrono::Duration::days(5));
    soonest.subject = "CN=soonest.example".to_string();
    let mut middle = cert_model(tenant.id, ca.id, 0x55, now + chrono::Duration::days(50));
    middle.subject = "CN=middle.example".to_string();
    let mut revoked = cert_model(tenant.id, ca.id, 0x66, now + chrono::Duration::days(90));
    revoked.subject = "CN=revoked.example".to_string();
    revoked.status = CertStatus::Revoked;

    let certs = CertificateRepo::new();
    certs
        .insert(&pool, &soonest)
        .await
        .expect("insert the soonest cert");
    certs
        .insert(&pool, &middle)
        .await
        .expect("insert the middle cert");
    certs
        .insert(&pool, &revoked)
        .await
        .expect("insert the revoked cert");

    let all = certs.list_slim(&pool, tenant.id, None, 0, 10).await;
    let active = certs
        .list_slim(&pool, tenant.id, Some(CertStatus::Active), 0, 10)
        .await;
    let page = certs.list_slim(&pool, tenant.id, None, 0, 2).await;
    let other_tenant = certs
        .list_slim(&pool, uuid::Uuid::new_v4(), None, 0, 10)
        .await;

    // Cleanup BEFORE asserting.
    delete_cert_rows(&pool, tenant.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY_CERTS).await;

    let all = all.expect("list_slim");
    assert_eq!(all.len(), 3, "every row of the tenant");
    // not_after DESC is `list_by_tenant`'s order: furthest expiry FIRST,
    // so the 90-day revoked row leads and the 5-day one trails.
    assert_eq!(all[0].id, revoked.id);
    assert_eq!(
        all[0].status,
        CertStatus::Revoked,
        "the typed status decode"
    );
    assert_eq!(
        all[2].id, soonest.id,
        "not_after DESC puts the soonest expiry last"
    );
    assert_eq!(all[2].subject, "CN=soonest.example");
    assert_eq!(all[2].status, CertStatus::Active);

    let active = active.expect("list_slim with the status filter");
    assert_eq!(active.len(), 2, "the revoked row is excluded");
    for row in &active {
        assert_eq!(row.status, CertStatus::Active);
    }

    let page = page.expect("list_slim with paging");
    assert_eq!(page.len(), 2, "the limit applies");

    let other_tenant = other_tenant.expect("list_slim under another tenant");
    assert!(
        other_tenant.is_empty(),
        "another tenant's rows are invisible"
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
        // The auth method matches the actor type the fixture carries; the
        // session actor here has no session id, which the dedicated
        // auth-method roundtrip below covers instead.
        auth_method: match actor_type {
            ActorType::User => AuthMethod::Session,
            ActorType::ApiToken => AuthMethod::ApiToken,
            ActorType::OneShotToken => AuthMethod::OneShot,
            ActorType::System => AuthMethod::System,
            ActorType::AcmeAccount => AuthMethod::AcmeAccount,
        },
        session_id: None,
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

    let tenant = TenantRepo::new()
        .insert(&pool, AUDIT_TENANT)
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

    let audit = AuditRepo::new();
    let first_insert = audit.record(&pool, &first).await;
    let second_insert = audit.record(&pool, &second).await;
    let listed = audit.list_by_tenant(&pool, tenant.id, 0, 10).await;
    let append = audit.record(&pool, &third).await;
    let listed_after = audit.list_by_tenant(&pool, tenant.id, 0, 10).await;
    // Appending the exact same entry again (same primary key) must be
    // rejected, not silently overwritten: append-only has no upsert path.
    let duplicate_append = audit.record(&pool, &first).await;
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
    // Newest first: the stored `created_at` values are the database's
    // `now()` — not the fixtures' fixed timestamps, which `record` must
    // ignore. The two records can commit in the same `now()` microsecond,
    // and the `id` tiebreaker is random, so a strict position assert would
    // flake; instead the exact pair of ids must be the first two rows as a
    // set, and the desc ordering still pinned on `created_at`.
    let top_two: std::collections::HashSet<_> = [listed[0].id, listed[1].id].into_iter().collect();
    assert_eq!(
        top_two,
        [first.id, second.id].into_iter().collect(),
        "the two recorded entries are exactly the first two rows"
    );
    assert!(
        listed[0].created_at >= listed[1].created_at,
        "created_at desc order"
    );
    // Distinct commits land strictly desc; a same-microsecond tie is not an
    // error, so this only asserts what the ordering guarantees.
    if listed[0].created_at > listed[1].created_at {
        assert_eq!(listed[0].id, second.id, "strictly later commit lists first");
    }
    assert_ne!(
        listed[0].created_at, second.created_at,
        "record must not bind the client timestamp; the DB default owns created_at"
    );
    // Everything but the DB-owned created_at roundtrips exactly: both rows
    // against their fixtures, modulo created_at (asserted above), matched
    // position-agnostically by id.
    for row in &listed {
        let fixture = if row.id == second.id { &second } else { &first };
        assert_eq!(row.tenant_id, fixture.tenant_id);
        assert_eq!(row.actor_type, fixture.actor_type);
        assert_eq!(row.auth_method, fixture.auth_method);
        assert_eq!(row.session_id, fixture.session_id);
        assert_eq!(row.actor_id, fixture.actor_id);
        assert_eq!(row.action, fixture.action);
        assert_eq!(row.target_type, fixture.target_type);
        assert_eq!(row.target_id, fixture.target_id);
        assert_eq!(row.details, fixture.details);
    }

    append.expect("a further record appends");
    let listed_after = listed_after.expect("list_by_tenant after the third record");
    assert_eq!(
        listed_after.len(),
        3,
        "a further record appends a third row (append-only)"
    );
    // The third record is the newest row; the other two are the original
    // pair, in either order (same-microsecond tie makes position flaky).
    assert_eq!(listed_after[0].id, third.id);
    let trailing_two: std::collections::HashSet<_> = [listed_after[1].id, listed_after[2].id]
        .into_iter()
        .collect();
    assert_eq!(
        trailing_two,
        [first.id, second.id].into_iter().collect(),
        "the original pair fills the trailing rows"
    );

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
    // The three actors cover every `actor_type` variant's column encoding
    // (System/User decode against the first listing above; AcmeAccount here).
    assert_eq!(listed_after[0].actor_type, ActorType::AcmeAccount);
}

/// An OCSP response row roundtrips through `insert` and `get_latest`:
/// the stored response bytes come back verbatim, the status column
/// decodes, and `get_latest` returns the most recently published
/// response for the (ca_id, serial) pair — not the older one. A second
/// insert of the same response (same ca, serial and this_update) is a
/// typed duplicate, never a silent overwrite. Cleans up before
/// asserting: OCSP responses first (they reference the CA), then the CA,
/// then the tenant.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn test_ocsp_response_roundtrip() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY_OCSP).await;

    // Sweep debris from any previously crashed run: OCSP responses first
    // (they reference the CA), then the CA, then the tenant.
    for sql in [
        "DELETE FROM ocsp_responses WHERE ca_id IN \
         (SELECT id FROM cas WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1))",
        "DELETE FROM cas WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM tenants WHERE name = $1",
    ] {
        sqlx::query(sql)
            .bind(OCSP_TENANT)
            .execute(&pool)
            .await
            .expect("sweep stale OCSP-suite rows");
    }

    let tenant = TenantRepo::new()
        .insert(&pool, OCSP_TENANT)
        .await
        .expect("insert the test tenant for OCSP rows");
    let ca = CaModel {
        id: uuid::Uuid::new_v4(),
        tenant_id: tenant.id,
        name: OCSP_CA_NAME.to_string(),
        subject: "CN=Wardstone Test OCSP CA".to_string(),
        is_root: true,
        parent_id: None,
        key_type: KeyType::Ed25519,
        not_before: ts("2026-01-01T00:00:00Z"),
        not_after: ts("2027-01-01T00:00:00Z"),
        cert_pem: "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n".to_string(),
        key_file: "/var/lib/wardstone/keys/rt-ocsp-ca.pem".to_string(),
        created_at: ts("2026-06-15T12:30:00Z"),
    };
    CaRepo::new()
        .insert(&pool, &ca)
        .await
        .expect("insert the test CA row");

    let older = OcspResponseModel {
        id: uuid::Uuid::new_v4(),
        tenant_id: tenant.id,
        ca_id: ca.id,
        serial: 0x1234,
        status: OcspStatus::Good,
        this_update: ts("2026-01-01T00:00:00Z"),
        next_update: ts("2026-01-02T00:00:00Z"),
        resp_der: vec![0x30, 0x00],
    };
    let newer = OcspResponseModel {
        id: uuid::Uuid::new_v4(),
        tenant_id: tenant.id,
        ca_id: ca.id,
        serial: older.serial,
        status: OcspStatus::Revoked,
        this_update: ts("2026-01-03T00:00:00Z"),
        next_update: ts("2026-01-04T00:00:00Z"),
        resp_der: vec![0x30, 0x03, 0x02, 0x01, 0x00],
    };

    let ocsp = OcspRepo::new();
    let first_insert = ocsp.insert(&pool, &older).await;
    let second_insert = ocsp.insert(&pool, &newer).await;
    let latest = ocsp.get_latest(&pool, ca.id, newer.serial).await;
    let missing = ocsp.get_latest(&pool, ca.id, 0x9999).await;
    let duplicate = ocsp.insert(&pool, &newer).await;
    // The column itself, read back from the table: the model roundtrip
    // above proves the model carries the tenant, this proves the ROW
    // does (a `tenant_id` that the INSERT silently dropped would still
    // read back from the model).
    let stored_tenant: Result<Option<uuid::Uuid>, sqlx::Error> =
        sqlx::query_scalar("SELECT tenant_id FROM ocsp_responses WHERE id = $1")
            .bind(newer.id)
            .fetch_one(&pool)
            .await;

    // Cleanup BEFORE asserting: OCSP responses first (they reference the
    // CA), then the CA, then the tenant.
    for (sql, id) in [
        ("DELETE FROM ocsp_responses WHERE ca_id = $1", ca.id),
        ("DELETE FROM cas WHERE id = $1", ca.id),
        ("DELETE FROM tenants WHERE id = $1", tenant.id),
    ] {
        sqlx::query(sql)
            .bind(id)
            .execute(&pool)
            .await
            .expect("delete the inserted OCSP-suite rows");
    }
    release_advisory(&mut advisory, ADVISORY_KEY_OCSP).await;

    first_insert.expect("insert the older OCSP response");
    second_insert.expect("insert the newer OCSP response");
    let latest = latest
        .expect("get_latest")
        .expect("a response is present after insert");
    assert_eq!(
        latest.id, newer.id,
        "get_latest returns the most recently published response"
    );
    assert_eq!(latest.status, OcspStatus::Revoked);
    assert_eq!(
        latest.tenant_id, tenant.id,
        "the stored response carries the tenant it was written for"
    );
    assert_eq!(latest.ca_id, ca.id);
    assert_eq!(latest.serial, newer.serial);
    assert_eq!(latest.this_update, newer.this_update);
    assert_eq!(latest.next_update, newer.next_update);
    assert_eq!(
        latest.resp_der, newer.resp_der,
        "the stored response bytes come back verbatim"
    );
    assert!(
        missing.expect("get_latest for an unknown serial").is_none(),
        "a serial without a response has no latest response"
    );
    let duplicate = duplicate.expect_err("re-inserting the same response must be rejected");
    assert!(
        matches!(duplicate, CoreError::Duplicate),
        "unexpected error: {duplicate:?}"
    );
    assert_eq!(
        stored_tenant
            .expect("read the stored tenant_id column")
            .expect("the stored row's tenant_id is not NULL"),
        tenant.id,
        "the stored row carries the tenant id it was written with"
    );
}

/// The tenant-consistency invariant of migration 006: a child row of `cas`
/// may not name a `tenant_id` that differs from its own CA's tenant. The
/// `tenant_id` column is a DENORMALIZED copy of `cas.tenant_id`, and
/// nothing but the database enforces that the copy is right — without the
/// composite foreign key a row naming another tenant's id would show up in
/// that tenant's `CertificateRepo::list_by_tenant` listing, a silent
/// cross-tenant leak.
///
/// The composite foreign key is `DEFERRABLE INITIALLY DEFERRED`, so the
/// check fires at COMMIT. In autocommit mode a single statement is its own
/// transaction, so the violation is reported against that statement — which
/// is how the two rejected inserts below are observed.
///
/// Cleans up before asserting: child rows first, then the CAs, then the
/// tenants.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn tenant_fk_rejects_mismatched_tenant_child_row() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY_TENANT_FK).await;

    // Sweep debris from any previously crashed run: child rows first (they
    // reference the CA), then the CA rows, then the tenants.
    for sql in [
        "DELETE FROM ocsp_responses WHERE ca_id IN \
         (SELECT id FROM cas WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1))",
        "DELETE FROM crls WHERE ca_id IN \
         (SELECT id FROM cas WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1))",
        "DELETE FROM used_serials WHERE ca_id IN \
         (SELECT id FROM cas WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1))",
        "DELETE FROM certificates WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM cas WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM tenants WHERE name = $1",
    ] {
        for name in [TENANT_FK_TENANT_A, TENANT_FK_TENANT_B] {
            sqlx::query(sql)
                .bind(name)
                .execute(&pool)
                .await
                .expect("sweep stale tenant-consistency rows");
        }
    }

    // Two tenants, and a CA that belongs to tenant A.
    let tenants = TenantRepo::new();
    let tenant_a = tenants
        .insert(&pool, TENANT_FK_TENANT_A)
        .await
        .expect("insert tenant A for the tenant-consistency rows");
    let tenant_b = tenants
        .insert(&pool, TENANT_FK_TENANT_B)
        .await
        .expect("insert tenant B for the tenant-consistency rows");

    let ca = CaModel {
        id: uuid::Uuid::new_v4(),
        tenant_id: tenant_a.id,
        name: TENANT_FK_CA_NAME.to_string(),
        subject: "CN=Wardstone Test Tenant-FK CA".to_string(),
        is_root: true,
        parent_id: None,
        key_type: KeyType::Ed25519,
        not_before: ts("2026-01-01T00:00:00Z"),
        not_after: ts("2027-01-01T00:00:00Z"),
        cert_pem: "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n".to_string(),
        key_file: "/var/lib/wardstone/keys/rt-tenantfk-ca.pem".to_string(),
        created_at: ts("2026-06-15T12:30:00Z"),
    };
    CaRepo::new()
        .insert(&pool, &ca)
        .await
        .expect("insert the CA row that belongs to tenant A");

    // The hole: a `used_serials` row that names tenant B but points at
    // tenant A's CA. The single-column `tenant_id REFERENCES tenants(id)`
    // foreign key is satisfied (tenant B exists) — only the composite
    // foreign key can reject this.
    let drifted_serial =
        sqlx::query("INSERT INTO used_serials (tenant_id, ca_id, serial) VALUES ($1, $2, $3)")
            .bind(tenant_b.id)
            .bind(ca.id)
            .bind(4_242_i64)
            .execute(&pool)
            .await;

    // The same hole in the table that `CertificateRepo::list_by_tenant`
    // filters on: a certificate row that would show up in tenant B's
    // listing while its CA belongs to tenant A.
    let drifted_certificate = sqlx::query(
        "INSERT INTO certificates (id, tenant_id, ca_id, profile_name, subject, serial, \
         serial_hex, san_dns, san_ips, key_type, not_before, not_after, cert_pem, status, \
         revoked_at, revocation_reason, source, created_at) \
         VALUES ($1, $2, $3, 'default', 'CN=leaf.example', $4, $5, '{}'::text[], '{}'::inet[], \
         'ed25519', $6, $7, $8, 'active', NULL, NULL, 'manual', $9)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(tenant_b.id)
    .bind(ca.id)
    .bind(4_243_i64)
    .bind("1093")
    .bind(ts("2026-01-01T00:00:00Z"))
    .bind(ts("2026-12-01T00:00:00Z"))
    .bind("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n")
    .bind(ts("2026-06-15T12:30:00Z"))
    .execute(&pool)
    .await;

    // The control: the same insert naming tenant A — the CA's own tenant —
    // must be accepted.
    let consistent_serial =
        sqlx::query("INSERT INTO used_serials (tenant_id, ca_id, serial) VALUES ($1, $2, $3)")
            .bind(tenant_a.id)
            .bind(ca.id)
            .bind(4_244_i64)
            .execute(&pool)
            .await;

    // The row counts, read before cleanup so a rejected insert cannot have
    // left anything behind. Scoped to this test's own CA, so a row another
    // suite owns cannot perturb the count.
    let used_serials_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM used_serials WHERE ca_id = $1")
            .bind(ca.id)
            .fetch_one(&pool)
            .await
            .expect("count this CA's used_serials rows");
    let certificates_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM certificates WHERE ca_id = $1")
            .bind(ca.id)
            .fetch_one(&pool)
            .await
            .expect("count this CA's certificate rows");

    // Cleanup BEFORE asserting: child rows, then the CA, then the tenants.
    for sql in [
        "DELETE FROM used_serials WHERE ca_id = $1",
        "DELETE FROM certificates WHERE ca_id = $1",
        "DELETE FROM cas WHERE id = $1",
    ] {
        sqlx::query(sql)
            .bind(ca.id)
            .execute(&pool)
            .await
            .expect("delete the tenant-consistency rows");
    }
    for id in [tenant_a.id, tenant_b.id] {
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("delete the tenant-consistency tenants");
    }
    release_advisory(&mut advisory, ADVISORY_KEY_TENANT_FK).await;

    // Both drifted inserts are rejected with a foreign-key violation.
    for (label, constraint, outcome) in [
        ("used_serials", "used_serials_ca_tenant_fk", drifted_serial),
        (
            "certificates",
            "certificates_ca_tenant_fk",
            drifted_certificate,
        ),
    ] {
        let err = outcome.expect_err("a child row naming another tenant's id must be rejected");
        let sqlx::Error::Database(db_err) = &err else {
            panic!("{label}: expected a database error, got {err:?}");
        };
        assert_eq!(
            db_err.code().as_deref(),
            Some("23503"),
            "{label}: expected a foreign-key violation (SQLSTATE 23503), got {err:?}"
        );
        assert_eq!(
            db_err.constraint(),
            Some(constraint),
            "{label}: expected the composite tenant/CA foreign key to be the one violated, \
             got {err:?}"
        );
    }

    // The consistent insert is accepted, and the two rejected ones left no
    // rows behind.
    consistent_serial.expect("a child row naming the CA's own tenant must be accepted");
    assert_eq!(
        used_serials_count, 1,
        "only the consistent used_serials row may exist"
    );
    assert_eq!(
        certificates_count, 0,
        "the rejected certificate row must not exist"
    );
}

// ---------------------------------------------------------------------
// Plan 2: users, credentials, profiles, and the audit auth method.
//
// Postgres advisory-lock key for this suite's auth/profile tests: the
// "WARDST" family with suite marker 0x000c (`0x0057_4144_5354_000c`), the
// next free marker after schema_test's 0x000b — a disjoint row set (the
// tenant names below), so a process holding another suite's key never
// waits on these rows.
// ---------------------------------------------------------------------

/// Postgres advisory-lock key for this suite's auth/profile tests: suite
/// marker 0x000c of the "WARDST" family.
const ADVISORY_KEY_AUTH: i64 = 0x0057_4144_5354_000c;

/// Tenant names this suite owns for the auth/profile tests; deleted
/// before asserts (child rows first, tenants last).
const AUTH_TENANT: &str = "rt2-auth-tenant";
const AUTH_TENANT_B: &str = "rt2-auth-tenant-b";

/// Tenant name this suite owns for the audit auth-method roundtrip;
/// deleted before asserts (audit rows first, tenant last).
const AUTH_AUDIT_TENANT: &str = "rt2-auth-audit-tenant";

/// Sweep any rows a previously crashed run of the auth tests may have
/// left behind under this suite's owned tenant name: child rows in FK
/// order (refresh tokens, one-shot tokens, service-identity capability
/// rows and identities, users, OIDC config, profile revisions and
/// profiles, audit rows), then the tenant itself.
async fn sweep_auth_rows(pool: &PgPool, tenant_name: &str) {
    for sql in [
        "DELETE FROM refresh_tokens WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM one_shot_tokens WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM service_identity_capabilities WHERE service_identity_id IN \
         (SELECT id FROM service_identities WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1))",
        "DELETE FROM service_identities WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM users WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM oidc_config WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM profiles WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM audit_log WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM tenants WHERE name = $1",
    ] {
        sqlx::query(sql)
            .bind(tenant_name)
            .execute(pool)
            .await
            .expect("sweep stale auth-suite rows");
    }
}

/// Delete the auth tests' rows before asserts, in FK order, for the given
/// tenant id. Runs whether or not the individual inserts succeeded.
async fn delete_auth_rows(pool: &PgPool, tenant_id: uuid::Uuid) {
    for sql in [
        "DELETE FROM refresh_tokens WHERE tenant_id = $1",
        "DELETE FROM one_shot_tokens WHERE tenant_id = $1",
        "DELETE FROM service_identity_capabilities WHERE service_identity_id IN \
         (SELECT id FROM service_identities WHERE tenant_id = $1)",
        "DELETE FROM service_identities WHERE tenant_id = $1",
        "DELETE FROM users WHERE tenant_id = $1",
        "DELETE FROM oidc_config WHERE tenant_id = $1",
        "DELETE FROM profiles WHERE tenant_id = $1",
        "DELETE FROM audit_log WHERE tenant_id = $1",
        "DELETE FROM tenants WHERE id = $1",
    ] {
        sqlx::query(sql)
            .bind(tenant_id)
            .execute(pool)
            .await
            .expect("delete auth-suite rows");
    }
}

/// One user fixture: local provider with a password hash and an OIDC
/// subject, active, zero failed logins.
fn user_model(tenant_id: uuid::Uuid, username: &str) -> UserModel {
    UserModel {
        id: uuid::Uuid::new_v4(),
        tenant_id,
        username: username.to_string(),
        display_name: "Alice Example".to_string(),
        email: format!("{username}@example.test"),
        role: Role::Issuer,
        auth_provider: "local".to_string(),
        password_hash: Some("argon2id$test".to_string()),
        totp_secret_encrypted: None,
        totp_secret_nonce: None,
        webauthn_credential: None,
        mfa_enabled: false,
        azure_oid: None,
        oidc_sub: Some(format!("oidc-sub-{username}")),
        is_active: true,
        force_password_reset: false,
        failed_login_attempts: 0,
        locked_until: None,
        last_login_at: None,
        created_at: ts("2026-06-15T12:30:00Z"),
        updated_at: ts("2026-06-15T12:30:00Z"),
    }
}

/// One profile fixture with no current revision yet (the deferrable
/// circular reference is exercised by the profile concurrency test).
fn profile_model(tenant_id: uuid::Uuid) -> ProfileModel {
    ProfileModel {
        id: uuid::Uuid::new_v4(),
        tenant_id,
        name: "web-server".to_string(),
        description: Some("TLS server profiles".to_string()),
        current_revision_id: None,
        created_at: ts("2026-06-15T12:30:00Z"),
    }
}

/// One profile-revision fixture: the caller's revision number under the
/// fixture profile, with the default-profile key usage set.
fn profile_revision_model(profile_id: uuid::Uuid, revision: i32) -> ProfileRevisionModel {
    ProfileRevisionModel {
        id: uuid::Uuid::new_v4(),
        profile_id,
        revision,
        name: "web-server".to_string(),
        key_type: "rsa2048".to_string(),
        key_usages: vec![
            "digital_signature".to_string(),
            "key_encipherment".to_string(),
        ],
        eku: vec!["server_auth".to_string()],
        lifetime_days: 30,
        san_patterns: vec!["example.test".to_string(), "*.example.test".to_string()],
        is_legacy: false,
        created_at: ts("2026-06-15T12:30:00Z"),
        actor_id: "test".to_string(),
    }
}

/// One service-identity fixture with the caller's fixed token hash.
fn service_identity_model(tenant_id: uuid::Uuid) -> ServiceIdentityModel {
    ServiceIdentityModel {
        id: uuid::Uuid::new_v4(),
        tenant_id,
        name: "ci-bot".to_string(),
        description: Some("CI pipeline identity".to_string()),
        created_by: None,
        token_hash: "rt2-si-hash-1".to_string(),
        created_at: ts("2026-06-15T12:30:00Z"),
        expires_at: Some(ts("2030-01-01T00:00:00Z")),
        revoked_at: None,
        last_used_at: None,
    }
}

/// One one-shot-token fixture, unexpired and unused.
fn one_shot_token_model(tenant_id: uuid::Uuid) -> OneShotTokenModel {
    OneShotTokenModel {
        id: uuid::Uuid::new_v4(),
        tenant_id,
        minted_by: None,
        token_hash: "rt2-ost-hash-1".to_string(),
        created_at: ts("2026-06-15T12:30:00Z"),
        // Whole seconds: the `timestamptz` column truncates the fixture's
        // finer precision on the roundtrip, and the test compares the
        // fetched row against this model exactly.
        expires_at: Some((Utc::now() + chrono::Duration::hours(1)).trunc_subsecs(0)),
        used_at: None,
    }
}

/// One OIDC provider config fixture (Keycloak public client).
fn oidc_config_model(tenant_id: uuid::Uuid) -> OidcConfigModel {
    OidcConfigModel {
        tenant_id,
        provider_type: "keycloak".to_string(),
        display_name: "Corp SSO".to_string(),
        discovery_url: "https://idp.example.test/.well-known/openid-configuration".to_string(),
        client_id: "wardstone".to_string(),
        client_secret: String::new(),
        redirect_uri: "https://wardstone.example.test/api/oidc/callback".to_string(),
        scopes: "openid profile email".to_string(),
    }
}

/// One refresh-token fixture: unexpired, unrevoked, with a test user
/// agent and address.
fn refresh_token_model(
    tenant_id: uuid::Uuid,
    user_id: uuid::Uuid,
    token_hash: &str,
) -> RefreshTokenModel {
    RefreshTokenModel {
        id: uuid::Uuid::new_v4(),
        tenant_id,
        user_id,
        token_hash: token_hash.to_string(),
        issued_at: ts("2026-06-15T12:30:00Z"),
        last_used_at: ts("2026-06-15T12:30:00Z"),
        expires_at: ts("2030-01-01T00:00:00Z"),
        revoked: false,
        revoked_at: None,
        user_agent: Some("wardstone-test/1".to_string()),
        ip_address: Some("192.0.2.7".parse().expect("valid IPv4 fixture")),
    }
}

/// The shared paging helper created in this task (Plan 1's two private
/// copies move onto it in the next plan task): `paging(0, 10)` is
/// `(10, 0)` — limit first, offset second — `page_size` clamps to 500
/// (and the clamped value feeds the offset too), and the offset is
/// `page * page_size`.
#[test]
fn paging_clamps_page_size_and_offsets_by_page() {
    assert_eq!(paging(0, 10).expect("a plain page"), (10, 0));
    assert_eq!(
        paging(0, 10_000).expect("page_size above the clamp"),
        (500, 0)
    );
    assert_eq!(
        paging(0, u32::MAX).expect("u32::MAX page_size clamps"),
        (500, 0)
    );
    assert_eq!(paging(2, 10).expect("page 2 at size 10"), (10, 20));
}

/// A user inserts and reads back through every lookup path (username,
/// email, OIDC subject, id); the `role` text column round-trips through
/// `update_role` and deactivation flips `is_active`; and the uniqueness
/// on `(tenant_id, username)` / `(tenant_id, email)` is PER-TENANT: a
/// second tenant may reuse the same username and email, while a repeat
/// within one tenant is a typed [`CoreError::Duplicate`]. Cleans up
/// before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn user_insert_roundtrip_and_per_tenant_uniqueness() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY_AUTH).await;

    sweep_auth_rows(&pool, AUTH_TENANT).await;
    sweep_auth_rows(&pool, AUTH_TENANT_B).await;

    let tenants = TenantRepo::new();
    let tenant_a = tenants
        .insert(&pool, AUTH_TENANT)
        .await
        .expect("insert test tenant A for user rows");
    let tenant_b = tenants
        .insert(&pool, AUTH_TENANT_B)
        .await
        .expect("insert test tenant B for user rows");

    let alice = user_model(tenant_a.id, "alice");
    let users = UserRepo::new();
    let inserted = users.insert(&pool, &alice).await;
    let by_username = users.get_by_username(&pool, tenant_a.id, "alice").await;
    let by_email = users.get_by_email(&pool, tenant_a.id, &alice.email).await;
    let by_sub = users
        .get_by_oidc_sub(
            &pool,
            tenant_a.id,
            alice.oidc_sub.as_deref().expect("fixture has oidc_sub"),
        )
        .await;
    let by_id = users.get_by_id(&pool, alice.id).await;
    let listing = users.list_by_tenant(&pool, tenant_a.id, 0, 10).await;

    // Per-tenant uniqueness: a second tenant reuses BOTH username and
    // email, and the insert must succeed.
    let second_tenant = users.insert(&pool, &user_model(tenant_b.id, "alice")).await;
    // Within one tenant the unique constraint fires as a typed Duplicate.
    let duplicate = users.insert(&pool, &user_model(tenant_a.id, "alice")).await;

    // Role update and deactivation.
    let role_update = users.update_role(&pool, alice.id, Role::Admin).await;
    let after_role = users.get_by_id(&pool, alice.id).await;
    let deactivation = users.deactivate(&pool, alice.id).await;
    let after_deactivate = users.get_by_id(&pool, alice.id).await;

    // Cleanup BEFORE asserting.
    delete_auth_rows(&pool, tenant_a.id).await;
    delete_auth_rows(&pool, tenant_b.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY_AUTH).await;

    inserted.expect("insert user");
    assert_eq!(
        by_username.expect("get_by_username").expect("row present"),
        alice
    );
    assert_eq!(by_email.expect("get_by_email").expect("row present"), alice);
    assert_eq!(
        by_sub.expect("get_by_oidc_sub").expect("row present"),
        alice
    );
    assert_eq!(by_id.expect("get_by_id").expect("row present"), alice);

    let listing = listing.expect("list_by_tenant");
    assert_eq!(listing.len(), 1, "one user under tenant A");
    assert_eq!(listing[0].id, alice.id);

    second_tenant.expect("a second tenant may reuse the same username and email");
    let duplicate = duplicate.expect_err("same-tenant duplicate username must be typed");
    assert!(
        matches!(duplicate, CoreError::Duplicate),
        "unexpected error: {duplicate:?}"
    );

    role_update.expect("update_role");
    let after_role = after_role
        .expect("get after update_role")
        .expect("row present");
    assert_eq!(after_role.role, Role::Admin, "role updated");
    assert!(after_role.is_active, "update_role must not touch is_active");

    deactivation.expect("deactivate");
    let after_deactivate = after_deactivate
        .expect("get after deactivate")
        .expect("row present");
    assert!(
        !after_deactivate.is_active,
        "deactivate flips is_active off"
    );
    assert_eq!(after_deactivate.role, Role::Admin);
}

/// Each `record_failed_login` increments `failed_login_attempts`;
/// `lock_until` sets `locked_until`; `clear_failed_logins` resets the
/// attempts to zero and clears the lock. Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn failed_login_increments_and_locks() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY_AUTH).await;

    sweep_auth_rows(&pool, AUTH_TENANT).await;
    let tenant = TenantRepo::new()
        .insert(&pool, AUTH_TENANT)
        .await
        .expect("insert test tenant for user rows");
    let user = user_model(tenant.id, "lockout");
    UserRepo::new()
        .insert(&pool, &user)
        .await
        .expect("insert user row");

    let users = UserRepo::new();
    let first = users.record_failed_login(&pool, user.id).await;
    let after_first = users.get_by_id(&pool, user.id).await;
    let second = users.record_failed_login(&pool, user.id).await;
    let after_second = users.get_by_id(&pool, user.id).await;
    let lock = users
        .lock_until(&pool, user.id, ts("2030-01-01T00:00:00Z"))
        .await;
    let after_lock = users.get_by_id(&pool, user.id).await;
    let clear = users.clear_failed_logins(&pool, user.id).await;
    let after_clear = users.get_by_id(&pool, user.id).await;

    // Cleanup BEFORE asserting.
    delete_auth_rows(&pool, tenant.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY_AUTH).await;

    first.expect("first failed login");
    second.expect("second failed login");
    lock.expect("lock_until");
    clear.expect("clear_failed_logins");

    let after_first = after_first.expect("get").expect("row present");
    assert_eq!(after_first.failed_login_attempts, 1);
    let after_second = after_second.expect("get").expect("row present");
    assert_eq!(after_second.failed_login_attempts, 2);

    let after_lock = after_lock.expect("get").expect("row present");
    assert_eq!(
        after_lock.locked_until,
        Some(ts("2030-01-01T00:00:00Z")),
        "lock_until sets the lockout instant"
    );
    assert_eq!(
        after_lock.failed_login_attempts, 2,
        "lock_until must not touch the attempt counter"
    );

    let after_clear = after_clear.expect("get").expect("row present");
    assert_eq!(
        after_clear.failed_login_attempts, 0,
        "clear_failed_logins resets the counter"
    );
    assert!(
        after_clear.locked_until.is_none(),
        "clear_failed_logins clears the lock"
    );
}

/// A profile inserts with revision 1; `update` appends revision 2 and
/// repoints `current_revision_id`; revision 1 remains retrievable; and
/// `update` with a STALE expected revision affects zero rows and is a
/// typed error — the optimistic-concurrency property that makes repoint
/// races retry rather than silently overwrite. Cleans up before
/// asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn profile_revision_optimistic_concurrency() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY_AUTH).await;

    sweep_auth_rows(&pool, AUTH_TENANT).await;
    let tenant = TenantRepo::new()
        .insert(&pool, AUTH_TENANT)
        .await
        .expect("insert test tenant for profile rows");

    let profile = profile_model(tenant.id);
    let rev1 = profile_revision_model(profile.id, 1);
    let rev2 = profile_revision_model(profile.id, 2);
    let repo = ProfileRepo::new();
    let ins_profile = repo.insert_profile(&pool, &profile).await;
    let ins_rev1 = repo.insert_revision(&pool, &rev1).await;
    let first_repoint = repo.update(&pool, profile.id, None, rev1.id).await;
    let current_after_first = repo.current_revision(&pool, profile.id).await;
    let rev1_retrievable = repo.get_revision(&pool, rev1.id).await;
    let ins_rev2 = repo.insert_revision(&pool, &rev2).await;
    let second_repoint = repo.update(&pool, profile.id, Some(rev1.id), rev2.id).await;
    let current_after_second = repo.current_revision(&pool, profile.id).await;
    let profile_fetched = repo.get_profile(&pool, profile.id).await;
    let revisions = repo.list_revisions(&pool, profile.id).await;
    let listing = repo.list_by_tenant(&pool, tenant.id, 0, 10).await;
    // Stale expectations: a revision the profile has already left, and a
    // fresh start (None) after one was set. Both must fail, not overwrite.
    let stale_expected = repo.update(&pool, profile.id, Some(rev1.id), rev2.id).await;
    let stale_expected_none = repo.update(&pool, profile.id, None, rev1.id).await;

    // Cleanup BEFORE asserting.
    delete_auth_rows(&pool, tenant.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY_AUTH).await;

    ins_profile.expect("insert profile");
    ins_rev1.expect("insert revision 1");
    first_repoint.expect("point the profile at revision 1 (from NULL)");
    assert_eq!(
        current_after_first.expect("current_revision").expect("set"),
        rev1,
        "current_revision returns revision 1"
    );
    assert_eq!(
        rev1_retrievable
            .expect("get_revision")
            .expect("row present"),
        rev1,
        "revision 1 remains retrievable"
    );
    ins_rev2.expect("insert revision 2");
    second_repoint.expect("repoint to revision 2 from the expected stale one");
    assert_eq!(
        current_after_second
            .expect("current_revision")
            .expect("set"),
        rev2,
        "the profile's current revision is revision 2"
    );
    let profile_fetched = profile_fetched.expect("get_profile").expect("row present");
    // Every field except the pointer is unchanged, and the pointer moved
    // to revision 2 (asserted separately right below).
    let expected_profile = ProfileModel {
        current_revision_id: Some(rev2.id),
        ..profile.clone()
    };
    assert_eq!(profile_fetched, expected_profile, "only the pointer moved");
    assert_eq!(
        profile_fetched.current_revision_id,
        Some(rev2.id),
        "current_revision_id repoints at revision 2"
    );
    let revisions = revisions.expect("list_revisions");
    assert_eq!(revisions, vec![rev1, rev2], "both revisions, in order");

    let listing = listing.expect("list_by_tenant");
    assert_eq!(listing.len(), 1, "the one profile under the tenant");
    assert_eq!(listing[0].id, profile.id);

    let stale_expected = stale_expected.expect_err("a stale expected revision must fail");
    assert!(
        matches!(stale_expected, CoreError::Config(_)),
        "unexpected error: {stale_expected:?}"
    );
    let stale_expected_none = stale_expected_none.expect_err("NULL-expectation stale too");
    assert!(
        matches!(stale_expected_none, CoreError::Config(_)),
        "unexpected error: {stale_expected_none:?}"
    );
}

/// The description-edit write: `set_description` replaces the stored
/// description (the value the next read returns), a blank or empty string
/// lands as NULL (the round-trip contract the PUT path's response echoes),
/// and `None` clears it too. A missing profile row is a zero-row update,
/// still `Ok`. Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn set_description_roundtrips_and_blanks_to_null() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY_AUTH).await;

    sweep_auth_rows(&pool, AUTH_TENANT).await;
    let tenant = TenantRepo::new()
        .insert(&pool, AUTH_TENANT)
        .await
        .expect("insert test tenant for profile rows");

    let repo = ProfileRepo::new();
    let mut profile = profile_model(tenant.id);
    profile.description = None;
    repo.insert_profile(&pool, &profile)
        .await
        .expect("insert profile");

    let edited = repo
        .set_description(&pool, profile.id, Some("the new wording"))
        .await;
    let after_edit = repo.get_profile(&pool, profile.id).await;
    let blank = repo.set_description(&pool, profile.id, Some("   ")).await;
    let after_blank = repo.get_profile(&pool, profile.id).await;
    let empty = repo.set_description(&pool, profile.id, Some("")).await;
    let after_empty = repo.get_profile(&pool, profile.id).await;
    let none = repo.set_description(&pool, profile.id, None).await;
    let after_none = repo.get_profile(&pool, profile.id).await;
    let restored = repo
        .set_description(&pool, profile.id, Some("restored"))
        .await;
    let final_profile = repo.get_profile(&pool, profile.id).await;
    let missing = repo
        .set_description(&pool, uuid::Uuid::new_v4(), Some("x"))
        .await;

    // Cleanup BEFORE asserting.
    delete_auth_rows(&pool, tenant.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY_AUTH).await;

    edited.expect("set the description");
    blank.expect("set a blank description");
    empty.expect("set an empty description");
    none.expect("clear the description");
    restored.expect("set the description again");
    missing.expect("a missing profile is a zero-row update, not an error");

    let after_edit = after_edit.expect("get after edit").expect("row present");
    assert_eq!(
        after_edit.description.as_deref(),
        Some("the new wording"),
        "the description round-trips"
    );
    let after_blank = after_blank.expect("get after blank").expect("row present");
    assert_eq!(after_blank.description, None, "a blank string stores NULL");
    let after_empty = after_empty.expect("get after empty").expect("row present");
    assert_eq!(after_empty.description, None, "an empty string stores NULL");
    let after_none = after_none.expect("get after none").expect("row present");
    assert_eq!(after_none.description, None, "an absent description clears");
    let final_profile = final_profile.expect("final get").expect("row present");
    assert_eq!(final_profile.description.as_deref(), Some("restored"));
}

/// A service identity's capabilities are stored and read back; the
/// listing finds it and revoke stamps `revoked_at`; and a one-shot token
/// is retrievable by hash, with `consume_one_shot_by_hash` succeeding
/// exactly ONCE: the first call returns the row with `used_at` set, the
/// second returns `None` (used, expired, and unknown all collapse to
/// None). Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn service_identity_capabilities_and_one_shot_consume() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY_AUTH).await;

    sweep_auth_rows(&pool, AUTH_TENANT).await;
    let tenant = TenantRepo::new()
        .insert(&pool, AUTH_TENANT)
        .await
        .expect("insert test tenant for credential rows");

    let identity = service_identity_model(tenant.id);
    let token = one_shot_token_model(tenant.id);
    let creds = CredentialRepo::new();
    let ins_identity = creds.insert_service_identity(&pool, &identity).await;
    let by_hash = creds
        .get_service_identity_by_hash(&pool, &identity.token_hash)
        .await;
    let set_caps = creds
        .set_service_identity_capabilities(
            &pool,
            identity.id,
            &[Capability::Issue, Capability::ReadCas],
        )
        .await;
    let caps = creds
        .service_identity_capabilities(&pool, identity.id)
        .await;
    let listing = creds.list_service_identities(&pool, tenant.id, 0, 10).await;
    let revoke_identity = creds.revoke_service_identity(&pool, identity.id).await;
    let after_revoked = creds
        .get_service_identity_by_hash(&pool, &identity.token_hash)
        .await;

    let ins_token = creds.insert_one_shot_token(&pool, &token).await;
    let token_by_hash = creds.get_one_shot_by_hash(&pool, &token.token_hash).await;
    let first_consume = creds
        .consume_one_shot_by_hash(&pool, &token.token_hash)
        .await;
    let second_consume = creds
        .consume_one_shot_by_hash(&pool, &token.token_hash)
        .await;
    let after_consume = creds.get_one_shot_by_hash(&pool, &token.token_hash).await;

    // Cleanup BEFORE asserting.
    delete_auth_rows(&pool, tenant.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY_AUTH).await;

    ins_identity.expect("insert service identity");
    assert_eq!(
        by_hash
            .expect("get_service_identity_by_hash")
            .expect("row present"),
        identity
    );

    set_caps.expect("set_service_identity_capabilities");
    let caps = caps.expect("service_identity_capabilities");
    assert_eq!(caps.len(), 2, "both capabilities stored");
    for cap in [Capability::Issue, Capability::ReadCas] {
        assert!(caps.contains(&cap), "{cap:?} missing from read-back");
    }

    let listing = listing.expect("list_service_identities");
    assert_eq!(listing.len(), 1, "the one identity under the tenant");
    assert_eq!(listing[0].id, identity.id);

    revoke_identity.expect("revoke_service_identity");
    let after_revoked = after_revoked
        .expect("get after revoke")
        .expect("revoked identity still resolvable by hash");
    assert!(
        after_revoked.revoked_at.is_some(),
        "revoke stamps revoked_at"
    );

    ins_token.expect("insert one-shot token");
    assert_eq!(
        token_by_hash
            .expect("get_one_shot_by_hash")
            .expect("row present"),
        token
    );
    let first_consume = first_consume
        .expect("consume_one_shot_by_hash")
        .expect("a live, unused token consumes once");
    assert_eq!(first_consume.id, token.id);
    assert_eq!(first_consume.token_hash, token.token_hash);
    assert!(
        first_consume.used_at.is_some(),
        "the first consume marks the token used"
    );
    assert!(
        second_consume
            .expect("second consume_one_shot_by_hash")
            .is_none(),
        "consuming an already-used token returns None"
    );
    let after_consume = after_consume
        .expect("get after consume")
        .expect("row present");
    assert!(after_consume.used_at.is_some());
}

/// `RoleRepo::capabilities_for_role` reads the `role_capabilities` table
/// (which migration 007 seeded) and returns exactly the rbac bundles;
/// `seed_role_capabilities` re-writes the defaults idempotently — the
/// row count does not move. (No tenant row needed: the table is
/// cluster-global.)
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn role_capabilities_read_from_table_and_seed_is_idempotent() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY_AUTH).await;

    // No owned rows: role_capabilities is schema-seeded. Sweep is a no-op
    // by design; nothing this test creates (seed adds nothing) needs
    // deleting.

    let before_count: i64 = sqlx::query_scalar("SELECT count(*) FROM role_capabilities")
        .fetch_one(&pool)
        .await
        .expect("count role_capabilities rows");

    let roles = RoleRepo::new();
    let admin = roles.capabilities_for_role(&pool, Role::Admin).await;
    let issuer = roles.capabilities_for_role(&pool, Role::Issuer).await;
    let viewer = roles.capabilities_for_role(&pool, Role::Viewer).await;
    let reseed = roles.seed_role_capabilities(&pool).await;

    let after_count: i64 = sqlx::query_scalar("SELECT count(*) FROM role_capabilities")
        .fetch_one(&pool)
        .await
        .expect("count role_capabilities rows after reseeding");

    release_advisory(&mut advisory, ADVISORY_KEY_AUTH).await;

    reseed.expect("seed_role_capabilities");
    assert_eq!(
        before_count, after_count,
        "re-seeding must add no rows (ON CONFLICT DO NOTHING)"
    );

    // The table's rows (sorted for comparison) must be exactly the rbac
    // bundles — the table is the runtime authority, the bundles the pin.
    for (role, got) in [
        (Role::Admin, admin.expect("capabilities_for_role admin")),
        (Role::Issuer, issuer.expect("capabilities_for_role issuer")),
        (Role::Viewer, viewer.expect("capabilities_for_role viewer")),
    ] {
        let mut got: Vec<Capability> = got;
        got.sort_by_key(|c| c.as_str());
        let mut expected = ws_core::models::rbac::role_capabilities(role).to_vec();
        expected.sort_by_key(|c| c.as_str());
        assert_eq!(got, expected, "{role:?} bundle mismatch");
    }
}

/// A refresh token round-trips by hash; `touch_last_used` moves the
/// sliding window's anchor; `rotate` revokes the old token (stamping
/// `revoked_at`) AND makes the replacement retrievable, atomically from
/// the caller's view; `revoke` marks a token; and `purge_expired`
/// sweeps the revoked/expired rows. Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn refresh_token_roundtrip_and_rotate() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY_AUTH).await;

    sweep_auth_rows(&pool, AUTH_TENANT).await;
    let tenant = TenantRepo::new()
        .insert(&pool, AUTH_TENANT)
        .await
        .expect("insert test tenant for refresh-token rows");
    let user = user_model(tenant.id, "refresh-user");
    UserRepo::new()
        .insert(&pool, &user)
        .await
        .expect("insert user row");

    let old = refresh_token_model(tenant.id, user.id, "rt2-refresh-hash-1");
    let replacement = refresh_token_model(tenant.id, user.id, "rt2-refresh-hash-2");
    let repo = RefreshTokenRepo::new();
    let insert_old = repo.insert(&pool, &old).await;
    let by_hash = repo.get_by_hash(&pool, &old.token_hash).await;
    let touch = repo.touch_last_used(&pool, old.id).await;
    let after_touch = repo.get_by_hash(&pool, &old.token_hash).await;
    let rotate = repo.rotate(&pool, &old, &replacement).await;
    let old_after_rotate = repo.get_by_hash(&pool, &old.token_hash).await;
    let new_after_rotate = repo.get_by_hash(&pool, &replacement.token_hash).await;
    let revoke_new = repo.revoke(&pool, replacement.id).await;
    let new_after_revoke = repo.get_by_hash(&pool, &replacement.token_hash).await;
    let purge = repo.purge_expired(&pool).await;

    // Cleanup BEFORE asserting.
    delete_auth_rows(&pool, tenant.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY_AUTH).await;

    insert_old.expect("insert refresh token");
    assert_eq!(
        by_hash.expect("get_by_hash").expect("row present"),
        old,
        "the token row round-trips verbatim"
    );
    touch.expect("touch_last_used");
    let after_touch = after_touch.expect("get after touch").expect("row present");
    assert!(
        after_touch.last_used_at > old.last_used_at,
        "touch_last_used moves the sliding-window anchor forward"
    );

    rotate.expect("rotate");
    let old_after_rotate = old_after_rotate.expect("get old").expect("row present");
    assert!(old_after_rotate.revoked, "rotate revokes the old token");
    assert!(
        old_after_rotate.revoked_at.is_some(),
        "rotate stamps the old token's revoked_at"
    );
    assert_eq!(
        new_after_rotate.expect("get new").expect("row present"),
        replacement,
        "rotate inserts the replacement, retrievable by hash"
    );

    revoke_new.expect("revoke");
    let new_after_revoke = new_after_revoke.expect("get new").expect("row present");
    assert!(new_after_revoke.revoked, "revoke marks the token");
    assert!(new_after_revoke.revoked_at.is_some());

    let purge = purge.expect("purge_expired");
    assert!(
        purge >= 2,
        "both revoked tokens are swept by purge_expired (got {purge})"
    );
}

/// An OIDC config round-trips per tenant and `upsert` REPLACES the row:
/// a second `upsert` for the same tenant updates the stored values
/// (never a duplicate row — `tenant_id` is the primary key), and an
/// unconfigured tenant reads back as `None`. Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn oidc_config_roundtrip() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY_AUTH).await;

    sweep_auth_rows(&pool, AUTH_TENANT).await;
    let tenant = TenantRepo::new()
        .insert(&pool, AUTH_TENANT)
        .await
        .expect("insert test tenant for OIDC rows");

    let config = oidc_config_model(tenant.id);
    let repo = OidcConfigRepo::new();
    let first_upsert = repo.upsert(&pool, &config).await;
    let fetched = repo.get(&pool, tenant.id).await;
    let unconfigured = repo.get(&pool, uuid::Uuid::nil()).await;

    let mut second = config.clone();
    second.provider_type = "azure".to_string();
    second.display_name = "Changed Corp SSO".to_string();
    second.client_id = "wardstone-2".to_string();
    second.client_secret = "s3cret".to_string();
    second.discovery_url = "https://login.microsoft.com/common/discovery".to_string();
    let second_upsert = repo.upsert(&pool, &second).await;
    let after_upsert = repo.get(&pool, tenant.id).await;
    let row_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oidc_config WHERE tenant_id = $1")
            .bind(tenant.id)
            .fetch_one(&pool)
            .await
            .unwrap_or(-1);

    // Cleanup BEFORE asserting.
    delete_auth_rows(&pool, tenant.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY_AUTH).await;

    first_upsert.expect("upsert the config");
    assert_eq!(
        fetched.expect("get").expect("row present after upsert"),
        config
    );
    assert!(
        unconfigured.expect("get for unconfigured tenant").is_none(),
        "a tenant without a config row reads back as None"
    );
    second_upsert.expect("upsert the changed config");
    let after_upsert = after_upsert.expect("get after second upsert").expect("row");
    assert_eq!(
        after_upsert, second,
        "the second upsert replaces the values"
    );
    assert_eq!(
        row_count, 1,
        "upsert never leaves a second config row per tenant"
    );
}

/// An audit entry round-trips with its `auth_method` and `session_id`
/// (a session actor carries both); and the worker's `crl_built` write
/// — the exact shape `jobs.rs` records, `ActorType::System` with
/// `AuthMethod::System` and no session — is written WITH `auth_method`
/// (surviving migration 009's NOT NULL constraint), stored as
/// `'system'`, and round-trips. Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn audit_auth_method_roundtrip_and_crl_built_system() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY_AUTH).await;

    sweep_auth_rows(&pool, AUTH_AUDIT_TENANT).await;
    let tenant = TenantRepo::new()
        .insert(&pool, AUTH_AUDIT_TENANT)
        .await
        .expect("insert test tenant for audit rows");

    let session_entry = AuditEntry {
        id: uuid::Uuid::new_v4(),
        tenant_id: tenant.id,
        actor_type: ActorType::User,
        auth_method: AuthMethod::Session,
        session_id: Some(uuid::Uuid::new_v4()),
        actor_id: "op-user-1".to_string(),
        action: "cert_issued".to_string(),
        target_type: "certificate".to_string(),
        target_id: "0199aaaa-0000-7000-8000-000000000001".to_string(),
        details: serde_json::json!({ "profile": "default" }),
        created_at: ts("2026-06-15T12:30:00Z"),
    };
    // The worker's `crl_built` audit write, character for character as
    // `jobs.rs` constructs it (AuditMethod::System, no session).
    let crl_entry = AuditEntry {
        id: uuid::Uuid::new_v4(),
        tenant_id: tenant.id,
        actor_type: ActorType::System,
        auth_method: AuthMethod::System,
        session_id: None,
        actor_id: "worker".to_string(),
        action: "crl_built".to_string(),
        target_type: "ca".to_string(),
        target_id: uuid::Uuid::new_v4().to_string(),
        details: serde_json::json!({
            "ca_name": "rt-audit-ca",
            "revoked": 0,
            "next_update": "2026-06-16T12:30:00+00:00",
        }),
        created_at: ts("2026-06-15T12:30:00Z"),
    };

    let audit = AuditRepo::new();
    let session_record = audit.record(&pool, &session_entry).await;
    let crl_record = audit.record(&pool, &crl_entry).await;
    let listed = audit.list_by_tenant(&pool, tenant.id, 0, 10).await;
    // The stored columns read back raw: the row-level truth the model
    // roundtrip only implies.
    let stored_method: Option<String> =
        sqlx::query_scalar("SELECT auth_method FROM audit_log WHERE id = $1")
            .bind(crl_entry.id)
            .fetch_one(&pool)
            .await
            .unwrap_or(None);
    let stored_session: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT session_id FROM audit_log WHERE id = $1")
            .bind(crl_entry.id)
            .fetch_one(&pool)
            .await
            .unwrap_or(None);

    // Cleanup BEFORE asserting.
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
    release_advisory(&mut advisory, ADVISORY_KEY_AUTH).await;

    session_record.expect("record the session actor's entry");
    crl_record.expect("record the worker's crl_built entry (NOT NULL satisfied)");

    let listed = listed.expect("list_by_tenant");
    assert_eq!(listed.len(), 2);
    for row in &listed {
        if row.id == session_entry.id {
            assert_eq!(row.actor_type, ActorType::User);
            assert_eq!(row.auth_method, AuthMethod::Session);
            assert_eq!(row.session_id, session_entry.session_id);
        } else if row.id == crl_entry.id {
            assert_eq!(row.actor_type, ActorType::System);
            assert_eq!(row.auth_method, AuthMethod::System);
            assert_eq!(row.session_id, None);
        }
    }

    assert_eq!(
        stored_method.as_deref(),
        Some("system"),
        "the worker's crl_built row stores auth_method = 'system'"
    );
    assert_eq!(
        stored_session, None,
        "the system actor has no session (the column stays NULL)"
    );
}

// ---------------------------------------------------------------------
// Plan 2, task 6: the Plan 1 repositories go stateless and
// executor-agnostic.
//
// Postgres advisory-lock key for this suite's executor-shape tests: the
// "WARDST" family with suite marker 0x000d (`0x0057_4144_5354_000d`),
// one past schema_test's 0x000b and the auth suite's 0x000c — a disjoint
// row set (the tenant name below), so a process holding another suite's
// key never waits on these rows.
// ---------------------------------------------------------------------

/// Postgres advisory-lock key for this suite's executor-shape tests:
/// suite marker 0x000d of the "WARDST" family.
const ADVISORY_KEY_TX: i64 = 0x0057_4144_5354_000d;

/// Tenant name this suite owns for the executor-shape tests; deleted
/// before asserts (audit rows and certificates first, then the CA, then
/// the tenant).
const TX_TENANT: &str = "rt2-tx-tenant";

/// The Task 6 widening, end to end: the Plan 1 repositories are
/// stateless (`AuditRepo::new()` takes no pool) and every method takes
/// `executor: impl PgExecutor<'_>`, so the same method runs against a
/// transaction (`&mut *tx`) or against the shared pool (`&pool`) — and
/// `AuditRepo::record` works INSIDE the transaction, which is what makes
/// an issuance and its audit row atomic (the shape Task 10's audit
/// write-side depends on). A record written in a committed transaction
/// is listed alongside one written straight against the pool, both Plan
/// 1 repos with a `list_by_tenant` still return the right page, and a
/// rolled-back `record` disappears with its transaction. Cleans up
/// before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn plan1_repos_execute_against_a_transaction_and_the_pool() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY_TX).await;

    // Sweep debris from any previously crashed run of this suite.
    for sql in [
        "DELETE FROM audit_log WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM certificates WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM cas WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM tenants WHERE name = $1",
    ] {
        sqlx::query(sql)
            .bind(TX_TENANT)
            .execute(&pool)
            .await
            .expect("sweep stale executor-shape rows");
    }

    // The tenant, its CA, its certificate, and one audit entry — all in
    // ONE transaction through `&mut *tx`, the shape an issuance shares.
    let mut tx = pool.begin().await.expect("begin the transaction");
    let tenant = TenantRepo::new()
        .insert(&mut *tx, TX_TENANT)
        .await
        .expect("insert the test tenant in the transaction");
    let ca = cert_ca_model(tenant.id);
    CaRepo::new()
        .insert(&mut *tx, &ca)
        .await
        .expect("insert the CA row in the transaction");
    let cert = cert_model(tenant.id, ca.id, 0x77aa, ts("2026-12-01T00:00:00Z"));
    let certs = CertificateRepo::new();
    certs
        .insert(&mut *tx, &cert)
        .await
        .expect("insert the certificate row in the transaction");
    let in_tx_entry = audit_entry(
        tenant.id,
        ActorType::System,
        "worker",
        "cert_issued",
        "certificate",
        &cert.id.to_string(),
        serde_json::json!({ "via": "transaction" }),
    );
    let audit = AuditRepo::new();
    audit
        .record(&mut *tx, &in_tx_entry)
        .await
        .expect("record the audit entry in the transaction");

    // Reading inside the transaction: the listing (taken through the
    // SAME `&mut *tx` executor) sees the transaction's own uncommitted
    // record.
    let in_tx_listing = audit.list_by_tenant(&mut *tx, tenant.id, 0, 10).await;

    tx.commit().await.expect("commit the transaction");

    // A second audit entry straight against the pool — the same method,
    // a different executor (the tenant row is committed by now, so the
    // audit row's foreign key can hold).
    let via_pool_entry = audit_entry(
        tenant.id,
        ActorType::User,
        "op-user-9",
        "cert_issued",
        "certificate",
        &cert.id.to_string(),
        serde_json::json!({ "via": "pool" }),
    );
    let pool_record = audit.record(&pool, &via_pool_entry).await;

    // A third record inside a NEW transaction that is then rolled back:
    // the record must vanish with the transaction — no orphaned audit
    // row, nothing burned.
    let mut tx = pool
        .begin()
        .await
        .expect("begin the rolled-back transaction");
    let rolled_entry = audit_entry(
        tenant.id,
        ActorType::ApiToken,
        "api-token-7",
        "cert_issued",
        "certificate",
        &cert.id.to_string(),
        serde_json::json!({ "via": "rolled-back" }),
    );
    let rolled_record = audit.record(&mut *tx, &rolled_entry).await;
    tx.rollback().await.expect("roll the transaction back");

    // The page reads through the pool, after everything settled.
    let listing = audit.list_by_tenant(&pool, tenant.id, 0, 10).await;
    let cert_listing = certs.list_by_tenant(&pool, tenant.id, 0, 10).await;
    let audit_count_after_rollback: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE tenant_id = $1")
            .bind(tenant.id)
            .fetch_one(&pool)
            .await
            .unwrap_or(-1);

    // Cleanup BEFORE asserting.
    sqlx::query("DELETE FROM audit_log WHERE tenant_id = $1")
        .bind(tenant.id)
        .execute(&pool)
        .await
        .expect("delete the inserted audit rows");
    sqlx::query("DELETE FROM certificates WHERE tenant_id = $1")
        .bind(tenant.id)
        .execute(&pool)
        .await
        .expect("delete the certificate row");
    sqlx::query("DELETE FROM cas WHERE tenant_id = $1")
        .bind(tenant.id)
        .execute(&pool)
        .await
        .expect("delete the CA row");
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant.id)
        .execute(&pool)
        .await
        .expect("delete the test tenant");
    release_advisory(&mut advisory, ADVISORY_KEY_TX).await;

    pool_record.expect("record the audit entry via the pool");
    rolled_record.expect("record the audit entry in the rolled-back transaction");

    // Inside the transaction: exactly the transaction's own record — the
    // pool-side entry did not exist yet, and nothing else does.
    let in_tx_listing = in_tx_listing.expect("list_by_tenant inside the transaction");
    assert_eq!(
        in_tx_listing.len(),
        1,
        "the transaction sees its own uncommitted record"
    );
    assert_eq!(
        in_tx_listing[0].id, in_tx_entry.id,
        "the in-transaction listing is the entry recorded in the transaction"
    );

    // After the commit (through the pool): the same two, and the
    // rolled-back record never existed.
    let listing = listing.expect("list_by_tenant after the commit");
    assert_eq!(listing.len(), 2, "the committed listing holds two entries");
    let ids: std::collections::HashSet<_> = listing.iter().map(|row| row.id).collect();
    assert_eq!(
        ids,
        [in_tx_entry.id, via_pool_entry.id]
            .into_iter()
            .collect::<std::collections::HashSet<_>>(),
        "the committed entries are exactly the ones recorded"
    );
    assert_eq!(
        audit_count_after_rollback, 2,
        "the rolled-back record left no audit row behind"
    );

    // The certificate listing still forms the right page after the
    // widening (LIMIT/OFFSET through the shared paging helper).
    let cert_listing = cert_listing.expect("certificate list_by_tenant after the widening");
    assert_eq!(
        cert_listing.len(),
        1,
        "the page holds the single certificate"
    );
    assert_eq!(cert_listing[0], cert);

    // The audit listing likewise: the two entries, newest first.
    assert!(
        listing[0].created_at >= listing[1].created_at,
        "created_at desc order"
    );
}
