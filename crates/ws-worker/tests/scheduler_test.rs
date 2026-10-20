//! Integration tests for `ws_worker::jobs` — the CRL/OCSP regeneration
//! job.
//!
//! These tests run against a live Postgres and are marked `#[ignore]`.
//! Run them with:
//!
//! ```sh
//! DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test \
//!     cargo test -p ws-worker -- --include-ignored
//! ```
//!
//! # Self-cleaning contract
//!
//! The shared `wardstone_test` database is also used by the ws-core
//! suites, one of which asserts that `tenants` is empty after its runs.
//! To keep that true no matter how this suite exits: every test sweeps
//! away rows a previously crashed run may have left behind under this
//! suite's owned tenant name (OCSP responses first — they reference the
//! CA — then CRLs, certificates, the CA, the audit rows, and the tenant
//! last), and every row inserted during the body is deleted *before* any
//! assertion runs, so a failing assertion cannot leave rows behind.
//!
//! # Cross-process serialization
//!
//! Each test body holds a session-level Postgres advisory lock for its
//! whole duration on the key [`ADVISORY_KEY`] — the "WARDST" family
//! (ASCII "WARDST" = 0x5741445354) with suite marker 0x0008, the next
//! free marker after the ws-core suites (0x0003-0x0005) and ws-ca's
//! serial suite (0x0006). This suite owns a disjoint row set, and plain
//! `cargo test` also runs test binaries sequentially, so the key is a
//! belt against concurrent cross-crate runs. The in-process mutex
//! mirrors the ws-core pattern for future tests added to this binary.

use std::fs;
use std::sync::OnceLock;

use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex;
use ws_ca::ca::{create_root, CaLifetime, CaSpec, KeyType};
use ws_ca::keystore::KeyStore;
use ws_core::db::connect;
use ws_core::models::ca::CaModel;
use ws_core::models::certificate::{CertStatus, CertificateModel};
use ws_core::models::ocsp::OcspStatus;
use ws_core::repo::ca_repo::CaRepo;
use ws_core::repo::certificate_repo::CertificateRepo;
use ws_core::repo::ocsp_repo::OcspRepo;
use ws_worker::jobs::regen_crl_and_ocsp;
use x509_parser::prelude::FromDer;

/// Postgres advisory-lock key for this suite: ASCII "WARDST"
/// (0x5741445354) plus the suite marker 0x0008. Processes taking this
/// key serialize their test bodies against this suite.
const ADVISORY_KEY: i64 = 0x0057_4144_5354_0008;

/// Tenant and CA names this suite owns; deleted before asserts.
const WORKER_TENANT: &str = "rt-worker-tenant";
const WORKER_CA_NAME: &str = "rt-worker-ca";

/// The serial of the fixture certificate.
const LEAF_SERIAL: u128 = 0x0bad_c0de_0000_0001;

/// The serial of the fixture certificate of the CA whose key is missing.
const BROKEN_SERIAL: u128 = 0x0bad_c0de_0000_0002;

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
/// (the caller holds the guard), so the lock is bound to it; it is
/// released by [`release_advisory`] or, on a panic path, when the pool
/// is dropped during unwinding.
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

/// Release the advisory lock taken by [`lock_advisory`] explicitly, so
/// the connection never returns to the pool while still holding it.
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

/// Per-test temp keystore, mirroring the ws-ca suites' pattern: unique
/// per test name and process id, swept before use so stale runs can't
/// interfere.
fn temp_keystore(test_name: &str) -> KeyStore {
    let dir = std::env::temp_dir().join(format!("ws-worker-{test_name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let mut ks = KeyStore::open(&dir).expect("open the test key store");
    ks.ensure_master_key().expect("create the master key");
    ks
}

/// The Ed25519 root CA every test's certificates are issued by.
fn root_spec() -> CaSpec {
    CaSpec {
        name: WORKER_CA_NAME.to_owned(),
        subject: "Wardstone Test Worker Root".to_owned(),
        key_type: KeyType::Ed25519,
        lifetime: CaLifetime::Root,
    }
}

/// Sweep any rows a previously crashed run of this suite may have left
/// behind under the owned tenant name: OCSP responses first (they
/// reference the CA), then CRLs, certificates, the CA, the audit rows,
/// and the tenant last.
async fn sweep_worker_rows(pool: &PgPool) {
    for sql in [
        "DELETE FROM ocsp_responses WHERE ca_id IN \
         (SELECT id FROM cas WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1))",
        "DELETE FROM crls WHERE ca_id IN \
         (SELECT id FROM cas WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1))",
        "DELETE FROM certificates WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM cas WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM audit_log WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM tenants WHERE name = $1",
    ] {
        sqlx::query(sql)
            .bind(WORKER_TENANT)
            .execute(pool)
            .await
            .expect("sweep stale worker-suite rows");
    }
}

/// Delete the worker tests' rows before asserts: OCSP responses, CRLs,
/// certificates, the CA, the audit rows, and the tenant — in FK order.
/// Runs whether or not the inserts succeeded.
async fn delete_worker_rows(pool: &PgPool, tenant_id: uuid::Uuid) {
    for sql in [
        "DELETE FROM ocsp_responses WHERE ca_id IN \
         (SELECT id FROM cas WHERE tenant_id = $1)",
        "DELETE FROM crls WHERE ca_id IN (SELECT id FROM cas WHERE tenant_id = $1)",
        "DELETE FROM certificates WHERE tenant_id = $1",
        "DELETE FROM cas WHERE tenant_id = $1",
        "DELETE FROM audit_log WHERE tenant_id = $1",
        "DELETE FROM tenants WHERE id = $1",
    ] {
        sqlx::query(sql)
            .bind(tenant_id)
            .execute(pool)
            .await
            .expect("delete worker-suite rows");
    }
}

/// A revoked certificate row for the CA: active on insert, revoked right
/// after, so the job sees a revocation newer than the (absent) CRL.
async fn insert_revoked_cert(
    pool: &PgPool,
    tenant_id: uuid::Uuid,
    ca_id: uuid::Uuid,
    serial: u128,
) -> uuid::Uuid {
    let id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();
    let model = CertificateModel {
        id,
        tenant_id,
        ca_id,
        profile_name: "default".to_string(),
        subject: "CN=leaf.example".to_string(),
        serial,
        serial_hex: format!("{serial:x}"),
        san_dns: vec!["leaf.example".to_string()],
        san_ips: vec![],
        key_type: "ecdsa-p256".to_string(),
        not_before: now,
        not_after: now + chrono::Duration::days(30),
        cert_pem: "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n".to_string(),
        status: CertStatus::Active,
        revoked_at: None,
        revocation_reason: None,
        source: "manual".to_string(),
        created_at: now,
    };
    let certs = CertificateRepo::new(pool);
    certs
        .insert(&model)
        .await
        .expect("insert the certificate row");
    certs
        .revoke(id, "key_compromise")
        .await
        .expect("revoke the certificate row");
    id
}

/// The regeneration job publishes a CRL and an OCSP response for a
/// revoked certificate: after one run the `crls` table holds a row for
/// the CA, the latest OCSP response for the revoked serial is `revoked`,
/// and the CA's revocation is audited as `crl_built`. Cleans up before
/// asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn test_scheduler_regenerates_on_revocation() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    sweep_worker_rows(&pool).await;

    // The CA: a real Ed25519 root whose private key lives in the test
    // key store, so the job can sign with it. The CA row's id is the
    // key pair id, which is where the key store filed the key.
    let mut keystore = temp_keystore("regenerates-on-revocation");
    let root = create_root(&root_spec(), &mut keystore).expect("create the test root CA");

    let tenant = ws_core::repo::tenant_repo::TenantRepo::new(&pool)
        .insert(WORKER_TENANT)
        .await
        .expect("insert the test tenant");
    let ca = CaModel {
        id: root.key_pair_id,
        tenant_id: tenant.id,
        name: WORKER_CA_NAME.to_string(),
        subject: "CN=Wardstone Test Worker Root".to_string(),
        is_root: true,
        parent_id: None,
        key_type: KeyType::Ed25519,
        not_before: chrono::Utc::now() - chrono::Duration::days(1),
        not_after: chrono::Utc::now() + chrono::Duration::days(365),
        cert_pem: root.cert_pem.clone(),
        key_file: "keystore://ca".to_string(),
        created_at: chrono::Utc::now(),
    };
    CaRepo::new(&pool)
        .insert(&ca)
        .await
        .expect("insert the test CA row");

    let cert_id = insert_revoked_cert(&pool, tenant.id, ca.id, LEAF_SERIAL).await;

    let regenerated = regen_crl_and_ocsp(&pool, &keystore).await;

    // Read the results before the cleanup.
    let crl_count: i64 = sqlx::query_scalar("SELECT count(*) FROM crls WHERE ca_id = $1")
        .bind(ca.id)
        .fetch_one(&pool)
        .await
        .expect("count the CA's CRL rows");
    let latest = OcspRepo::new(&pool)
        .get_latest(ca.id, i64::try_from(LEAF_SERIAL).expect("serial fits i64"))
        .await
        .expect("get the latest OCSP response");
    let audit_actions: Vec<String> =
        sqlx::query_scalar("SELECT action FROM audit_log WHERE tenant_id = $1 AND target_id = $2")
            .bind(tenant.id)
            .bind(ca.id.to_string())
            .fetch_all(&pool)
            .await
            .expect("list the CA's audit actions");
    let cert_after = CertificateRepo::new(&pool)
        .get(cert_id)
        .await
        .expect("get the certificate row");

    // Cleanup BEFORE asserting.
    delete_worker_rows(&pool, tenant.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    assert_eq!(
        regenerated.expect("the regeneration job succeeds"),
        1,
        "exactly the one CA with a new revocation is regenerated"
    );
    assert_eq!(crl_count, 1, "a CRL row is written for the CA");
    let latest = latest.expect("an OCSP response exists for the revoked serial");
    assert_eq!(latest.status, OcspStatus::Revoked);
    assert_eq!(latest.ca_id, ca.id);
    assert_eq!(
        latest.serial,
        i64::try_from(LEAF_SERIAL).expect("serial fits i64")
    );
    assert!(
        !latest.resp_der.is_empty(),
        "the stored response carries the response bytes"
    );
    assert!(
        latest.next_update > latest.this_update,
        "the published response has a validity window"
    );
    assert!(
        audit_actions.contains(&"crl_built".to_string()),
        "the rebuilt CRL is audited: {audit_actions:?}"
    );
    let cert_after = cert_after.expect("the certificate row is present");
    assert_eq!(cert_after.status, CertStatus::Revoked);
    assert_eq!(
        cert_after.revocation_reason.as_deref(),
        Some("key_compromise")
    );
}

/// A CA whose private key is missing must not stop the other CAs: the
/// job logs the failure, reports it to the caller, and still publishes
/// for the CA it can sign for. Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn test_regen_isolates_a_failing_ca() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    sweep_worker_rows(&pool).await;

    let mut keystore = temp_keystore("isolates-a-failing-ca");
    let root = create_root(&root_spec(), &mut keystore).expect("create the test root CA");

    let tenant = ws_core::repo::tenant_repo::TenantRepo::new(&pool)
        .insert(WORKER_TENANT)
        .await
        .expect("insert the test tenant");
    let cas = CaRepo::new(&pool);
    let ca = CaModel {
        id: root.key_pair_id,
        tenant_id: tenant.id,
        name: WORKER_CA_NAME.to_string(),
        subject: "CN=Wardstone Test Worker Root".to_string(),
        is_root: true,
        parent_id: None,
        key_type: KeyType::Ed25519,
        not_before: chrono::Utc::now() - chrono::Duration::days(1),
        not_after: chrono::Utc::now() + chrono::Duration::days(365),
        cert_pem: root.cert_pem.clone(),
        key_file: "keystore://ca".to_string(),
        created_at: chrono::Utc::now(),
    };
    cas.insert(&ca).await.expect("insert the test CA row");
    // A second CA row whose key was never stored: the job must fail on
    // it without touching the first CA's results. It has a revocation of
    // its own, so the job really tries to sign for it.
    let broken = CaModel {
        id: uuid::Uuid::new_v4(),
        name: "rt-worker-ca-broken".to_string(),
        cert_pem: root.cert_pem.clone(),
        ..ca.clone()
    };
    cas.insert(&broken).await.expect("insert the second CA row");

    let cert_id = insert_revoked_cert(&pool, tenant.id, ca.id, LEAF_SERIAL).await;
    let broken_cert_id = insert_revoked_cert(&pool, tenant.id, broken.id, BROKEN_SERIAL).await;

    let result = regen_crl_and_ocsp(&pool, &keystore).await;

    let crl_count: i64 = sqlx::query_scalar("SELECT count(*) FROM crls WHERE ca_id = $1")
        .bind(ca.id)
        .fetch_one(&pool)
        .await
        .expect("count the CA's CRL rows");
    let broken_crl_count: i64 = sqlx::query_scalar("SELECT count(*) FROM crls WHERE ca_id = $1")
        .bind(broken.id)
        .fetch_one(&pool)
        .await
        .expect("count the broken CA's CRL rows");
    let latest = OcspRepo::new(&pool)
        .get_latest(ca.id, i64::try_from(LEAF_SERIAL).expect("serial fits i64"))
        .await
        .expect("get the latest OCSP response");

    // Cleanup BEFORE asserting.
    delete_worker_rows(&pool, tenant.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    assert!(
        result.is_err(),
        "the job reports the CA it could not sign for"
    );
    assert_eq!(
        crl_count, 1,
        "the healthy CA's CRL is published even though another CA failed"
    );
    assert_eq!(
        broken_crl_count, 0,
        "the CA whose key is missing publishes no CRL"
    );
    assert!(
        latest
            .expect("an OCSP response exists for the revoked serial")
            .status
            == OcspStatus::Revoked,
        "the healthy CA's OCSP response is published even though another CA failed"
    );
    let _ = cert_id;
    let _ = broken_cert_id;
}

/// A CA row for the given root CA: the row's id is the key pair id, so
/// the key store holds this CA's key under that id.
async fn insert_ca(
    pool: &PgPool,
    tenant_id: uuid::Uuid,
    root: &ws_ca::ca::CreatedCa,
    name: &str,
) -> CaModel {
    let ca = CaModel {
        id: root.key_pair_id,
        tenant_id,
        name: name.to_string(),
        subject: format!("CN={name}"),
        is_root: true,
        parent_id: None,
        key_type: KeyType::Ed25519,
        not_before: chrono::Utc::now() - chrono::Duration::days(1),
        not_after: chrono::Utc::now() + chrono::Duration::days(365),
        cert_pem: root.cert_pem.clone(),
        key_file: "keystore://ca".to_string(),
        created_at: chrono::Utc::now(),
    };
    CaRepo::new(pool)
        .insert(&ca)
        .await
        .expect("insert the test CA row");
    ca
}

/// An active (not revoked) certificate row.
async fn insert_active_cert(
    pool: &PgPool,
    tenant_id: uuid::Uuid,
    ca_id: uuid::Uuid,
    serial: u128,
) -> uuid::Uuid {
    let id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();
    let model = CertificateModel {
        id,
        tenant_id,
        ca_id,
        profile_name: "default".to_string(),
        subject: "CN=active.example".to_string(),
        serial,
        serial_hex: format!("{serial:x}"),
        san_dns: vec!["active.example".to_string()],
        san_ips: vec![],
        key_type: "ecdsa-p256".to_string(),
        not_before: now,
        not_after: now + chrono::Duration::days(30),
        cert_pem: "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n".to_string(),
        status: CertStatus::Active,
        revoked_at: None,
        revocation_reason: None,
        source: "manual".to_string(),
        created_at: now,
    };
    CertificateRepo::new(pool)
        .insert(&model)
        .await
        .expect("insert the active certificate row");
    id
}

/// A revoked certificate row with an explicit revocation instant.
///
/// The repository's `revoke` always stamps "now"; this helper writes
/// the revocation date directly, so a test can reproduce a revocation
/// that is older than a published CRL.
async fn insert_revoked_cert_at(
    pool: &PgPool,
    tenant_id: uuid::Uuid,
    ca_id: uuid::Uuid,
    serial: u128,
    revoked_at: chrono::DateTime<chrono::Utc>,
) -> uuid::Uuid {
    let id = insert_active_cert(pool, tenant_id, ca_id, serial).await;
    sqlx::query(
        "UPDATE certificates SET status = 'revoked', revoked_at = $2, \
         revocation_reason = 'key_compromise' WHERE id = $1",
    )
    .bind(id)
    .bind(revoked_at)
    .execute(pool)
    .await
    .expect("revoke the certificate row");
    id
}

/// A revoked certificate row whose revocation instant is NULL — data
/// damage the job must refuse rather than paper over.
async fn insert_revoked_cert_without_date(
    pool: &PgPool,
    tenant_id: uuid::Uuid,
    ca_id: uuid::Uuid,
    serial: u128,
) -> uuid::Uuid {
    let id = insert_active_cert(pool, tenant_id, ca_id, serial).await;
    sqlx::query(
        "UPDATE certificates SET status = 'revoked', revoked_at = NULL, \
         revocation_reason = 'key_compromise' WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("revoke the certificate row without a date");
    id
}

/// The revoked serials a published CRL lists.
fn crl_serials(crl_pem: &str) -> Vec<u128> {
    let (_, block) = x509_parser::pem::parse_x509_pem(crl_pem.as_bytes())
        .expect("the published CRL is valid PEM");
    let (_, crl) =
        x509_parser::revocation_list::CertificateRevocationList::from_der(&block.contents)
            .expect("the published CRL parses");
    crl.iter_revoked_certificates()
        .map(|entry| {
            entry
                .serial()
                .to_string()
                .parse::<u128>()
                .expect("a decimal serial")
        })
        .collect()
}

/// The number of CRL rows published for a CA.
async fn crl_count(pool: &PgPool, ca_id: uuid::Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM crls WHERE ca_id = $1")
        .bind(ca_id)
        .fetch_one(pool)
        .await
        .expect("count the CA's CRL rows")
}

/// A CA with nothing to do is skipped and not counted: the returned count
/// is the number of CAs for which work was actually done. Two CAs, one
/// with a revocation and one with only an active certificate: the first
/// run publishes a CRL for both (a CA with no revocations still
/// publishes an empty CRL — a relying party must be able to fetch a
/// current document), and the second run has nothing left to do, so the
/// count is 0. Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn test_regen_counts_only_cas_with_work() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    sweep_worker_rows(&pool).await;

    let mut keystore = temp_keystore("counts-only-cas-with-work");
    let revoking_root = create_root(&root_spec(), &mut keystore).expect("create the first root");
    let quiet_root = create_root(
        &CaSpec {
            name: "rt-worker-ca-quiet".to_owned(),
            subject: "Wardstone Test Worker Quiet Root".to_owned(),
            key_type: KeyType::Ed25519,
            lifetime: CaLifetime::Root,
        },
        &mut keystore,
    )
    .expect("create the second root");

    let tenant = ws_core::repo::tenant_repo::TenantRepo::new(&pool)
        .insert(WORKER_TENANT)
        .await
        .expect("insert the test tenant");
    let revoking = insert_ca(&pool, tenant.id, &revoking_root, WORKER_CA_NAME).await;
    let quiet = insert_ca(&pool, tenant.id, &quiet_root, "rt-worker-ca-quiet").await;

    insert_revoked_cert(&pool, tenant.id, revoking.id, LEAF_SERIAL).await;
    insert_active_cert(&pool, tenant.id, quiet.id, BROKEN_SERIAL).await;

    let first = regen_crl_and_ocsp(&pool, &keystore).await;
    let revoking_crls = crl_count(&pool, revoking.id).await;
    let quiet_crls = crl_count(&pool, quiet.id).await;
    let total_crls: i64 = sqlx::query_scalar("SELECT count(*) FROM crls")
        .fetch_one(&pool)
        .await
        .expect("count every CRL row");

    // The second run: both CAs are current, so nothing is published.
    let second = regen_crl_and_ocsp(&pool, &keystore).await;
    let total_crls_after: i64 = sqlx::query_scalar("SELECT count(*) FROM crls")
        .fetch_one(&pool)
        .await
        .expect("count every CRL row again");

    delete_worker_rows(&pool, tenant.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    assert_eq!(
        first.expect("the first run succeeds"),
        2,
        "both CAs are counted: both published a CRL"
    );
    assert_eq!(revoking_crls, 1, "the revoking CA gets a CRL");
    assert_eq!(
        quiet_crls, 1,
        "the CA without a revocation publishes an empty CRL"
    );
    assert_eq!(total_crls, 2, "one CRL row per CA");
    assert_eq!(
        second.expect("the second run succeeds"),
        0,
        "a CA with nothing to do is skipped and not counted"
    );
    assert_eq!(
        total_crls_after, total_crls,
        "the second run publishes nothing"
    );
}

/// An expired published CRL is refreshed even when no new revocation
/// arrived: relying parties must be able to fetch a current CRL.
/// Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn test_regen_republishes_expired_crl() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    sweep_worker_rows(&pool).await;

    let mut keystore = temp_keystore("republishes-expired-crl");
    let root = create_root(&root_spec(), &mut keystore).expect("create the test root CA");
    let tenant = ws_core::repo::tenant_repo::TenantRepo::new(&pool)
        .insert(WORKER_TENANT)
        .await
        .expect("insert the test tenant");
    let ca = insert_ca(&pool, tenant.id, &root, WORKER_CA_NAME).await;
    insert_revoked_cert(&pool, tenant.id, ca.id, LEAF_SERIAL).await;

    // The first run publishes the CRL.
    let first = regen_crl_and_ocsp(&pool, &keystore).await;

    // Age the published CRL: its next_update is now in the past.
    sqlx::query("UPDATE crls SET next_update = now() - interval '1 hour' WHERE ca_id = $1")
        .bind(ca.id)
        .execute(&pool)
        .await
        .expect("age the published CRL");

    let second = regen_crl_and_ocsp(&pool, &keystore).await;
    let crls = crl_count(&pool, ca.id).await;

    delete_worker_rows(&pool, tenant.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    assert_eq!(first.expect("the first run succeeds"), 1);
    assert_eq!(
        second.expect("the second run succeeds"),
        1,
        "the expired CRL is refreshed"
    );
    assert_eq!(crls, 2, "a second CRL row is published");
}

/// A revocation whose `revoked_at` is older than the published CRL's
/// issue instant, and which the published CRL does not list, must not be
/// lost: the CRL's content is compared with the database's, so the CRL
/// is republished with that serial and the serial gets an OCSP
/// response. Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn test_regen_republishes_lost_revocation() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    sweep_worker_rows(&pool).await;

    let mut keystore = temp_keystore("republishes-lost-revocation");
    let root = create_root(&root_spec(), &mut keystore).expect("create the test root CA");
    let tenant = ws_core::repo::tenant_repo::TenantRepo::new(&pool)
        .insert(WORKER_TENANT)
        .await
        .expect("insert the test tenant");
    let ca = insert_ca(&pool, tenant.id, &root, WORKER_CA_NAME).await;
    insert_revoked_cert(&pool, tenant.id, ca.id, LEAF_SERIAL).await;

    // The first run publishes a CRL listing the one revocation.
    regen_crl_and_ocsp(&pool, &keystore)
        .await
        .expect("the first run succeeds");

    // A revocation that happened before that CRL was issued, and that
    // the CRL therefore does not list.
    let older = chrono::Utc::now() - chrono::Duration::days(2);
    insert_revoked_cert_at(&pool, tenant.id, ca.id, BROKEN_SERIAL, older).await;

    let second = regen_crl_and_ocsp(&pool, &keystore).await;

    let newest_crl: String = sqlx::query_scalar(
        "SELECT crl_pem FROM crls WHERE ca_id = $1 ORDER BY issued_at DESC LIMIT 1",
    )
    .bind(ca.id)
    .fetch_one(&pool)
    .await
    .expect("read the newest published CRL");
    let listed = crl_serials(&newest_crl);
    let lost_response = OcspRepo::new(&pool)
        .get_latest(
            ca.id,
            i64::try_from(BROKEN_SERIAL).expect("serial fits i64"),
        )
        .await
        .expect("get the latest OCSP response for the lost revocation");

    delete_worker_rows(&pool, tenant.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    assert_eq!(
        second.expect("the second run succeeds"),
        1,
        "the CA with the lost revocation is republished"
    );
    assert!(
        listed.contains(&BROKEN_SERIAL),
        "the republished CRL must list the lost revocation: {listed:?}"
    );
    assert!(
        listed.contains(&LEAF_SERIAL),
        "the republished CRL still lists the earlier revocation: {listed:?}"
    );
    assert_eq!(
        lost_response
            .expect("an OCSP response exists for the lost revocation")
            .status,
        OcspStatus::Revoked,
        "the lost revocation gets an OCSP response"
    );
}

/// A missing OCSP response is republished even when the CRL is current:
/// the response is repaired on its own, without a new CRL. Cleans up
/// before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn test_regen_republishes_missing_ocsp_response() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    sweep_worker_rows(&pool).await;

    let mut keystore = temp_keystore("republishes-missing-ocsp");
    let root = create_root(&root_spec(), &mut keystore).expect("create the test root CA");
    let tenant = ws_core::repo::tenant_repo::TenantRepo::new(&pool)
        .insert(WORKER_TENANT)
        .await
        .expect("insert the test tenant");
    let ca = insert_ca(&pool, tenant.id, &root, WORKER_CA_NAME).await;
    insert_revoked_cert(&pool, tenant.id, ca.id, LEAF_SERIAL).await;

    regen_crl_and_ocsp(&pool, &keystore)
        .await
        .expect("the first run succeeds");
    let crls_before = crl_count(&pool, ca.id).await;

    // The OCSP response is lost; the CRL stays current.
    sqlx::query("DELETE FROM ocsp_responses WHERE ca_id = $1 AND serial = $2")
        .bind(ca.id)
        .bind(i64::try_from(LEAF_SERIAL).expect("serial fits i64"))
        .execute(&pool)
        .await
        .expect("delete the OCSP response");

    let second = regen_crl_and_ocsp(&pool, &keystore).await;
    let crls_after = crl_count(&pool, ca.id).await;
    let latest = OcspRepo::new(&pool)
        .get_latest(ca.id, i64::try_from(LEAF_SERIAL).expect("serial fits i64"))
        .await
        .expect("get the latest OCSP response");

    delete_worker_rows(&pool, tenant.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    assert_eq!(
        second.expect("the second run succeeds"),
        1,
        "the CA with the missing OCSP response is counted"
    );
    assert_eq!(
        crls_after, crls_before,
        "an OCSP-only repair does not publish a new CRL"
    );
    assert_eq!(
        latest.expect("an OCSP response exists again").status,
        OcspStatus::Revoked,
        "the missing OCSP response is written again"
    );
}

/// A revoked certificate without a revocation date is data damage: the
/// job fails loudly (a typed error) and publishes nothing for that CA —
/// the revocation date is never invented and the revocation is never
/// silently dropped. Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn test_regen_rejects_revocation_without_date() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    sweep_worker_rows(&pool).await;

    let mut keystore = temp_keystore("rejects-revocation-without-date");
    let root = create_root(&root_spec(), &mut keystore).expect("create the test root CA");
    let tenant = ws_core::repo::tenant_repo::TenantRepo::new(&pool)
        .insert(WORKER_TENANT)
        .await
        .expect("insert the test tenant");
    let ca = insert_ca(&pool, tenant.id, &root, WORKER_CA_NAME).await;
    insert_revoked_cert_without_date(&pool, tenant.id, ca.id, LEAF_SERIAL).await;

    let result = regen_crl_and_ocsp(&pool, &keystore).await;
    let crls = crl_count(&pool, ca.id).await;

    delete_worker_rows(&pool, tenant.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    let err = result.expect_err("a revocation without a date fails the job");
    assert!(
        matches!(err, ws_worker::error::WorkerError::Config(_)),
        "unexpected error: {err:?}"
    );
    assert_eq!(crls, 0, "no CRL is published for the damaged CA");
}

/// An OCSP answer whose validity window has lapsed is stale and must be
/// replaced, even while the CRL is current: a lapsed answer must not be
/// served any more. The refresh happens on its own — no new CRL is
/// published — and the stored answer ends up with a future `next_update`.
/// Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn test_regen_refreshes_expired_ocsp_response() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    sweep_worker_rows(&pool).await;

    let mut keystore = temp_keystore("refreshes-expired-ocsp");
    let root = create_root(&root_spec(), &mut keystore).expect("create the test root CA");
    let tenant = ws_core::repo::tenant_repo::TenantRepo::new(&pool)
        .insert(WORKER_TENANT)
        .await
        .expect("insert the test tenant");
    let ca = insert_ca(&pool, tenant.id, &root, WORKER_CA_NAME).await;
    insert_revoked_cert(&pool, tenant.id, ca.id, LEAF_SERIAL).await;

    regen_crl_and_ocsp(&pool, &keystore)
        .await
        .expect("the first run succeeds");
    let crls_before = crl_count(&pool, ca.id).await;
    let responses_before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM ocsp_responses WHERE ca_id = $1 AND serial = $2")
            .bind(ca.id)
            .bind(i64::try_from(LEAF_SERIAL).expect("serial fits i64"))
            .fetch_one(&pool)
            .await
            .expect("count the OCSP responses");

    // The answer's validity window lapses; the CRL stays current.
    sqlx::query(
        "UPDATE ocsp_responses SET next_update = now() - interval '1 hour' \
         WHERE ca_id = $1 AND serial = $2",
    )
    .bind(ca.id)
    .bind(i64::try_from(LEAF_SERIAL).expect("serial fits i64"))
    .execute(&pool)
    .await
    .expect("age the OCSP response");

    let second = regen_crl_and_ocsp(&pool, &keystore).await;
    let crls_after = crl_count(&pool, ca.id).await;
    let responses_after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM ocsp_responses WHERE ca_id = $1 AND serial = $2")
            .bind(ca.id)
            .bind(i64::try_from(LEAF_SERIAL).expect("serial fits i64"))
            .fetch_one(&pool)
            .await
            .expect("count the OCSP responses again");
    let latest = OcspRepo::new(&pool)
        .get_latest(ca.id, i64::try_from(LEAF_SERIAL).expect("serial fits i64"))
        .await
        .expect("get the latest OCSP response");

    delete_worker_rows(&pool, tenant.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    assert_eq!(
        second.expect("the second run succeeds"),
        1,
        "the CA with the lapsed answer is counted"
    );
    assert_eq!(
        responses_after,
        responses_before + 1,
        "a fresh OCSP response is written"
    );
    assert_eq!(
        crls_after, crls_before,
        "the OCSP refresh does not publish a new CRL"
    );
    let latest = latest.expect("an OCSP response exists");
    assert_eq!(latest.status, OcspStatus::Revoked);
    assert!(
        latest.next_update > chrono::Utc::now(),
        "the refreshed answer has a future next_update: {:?}",
        latest.next_update
    );
}
