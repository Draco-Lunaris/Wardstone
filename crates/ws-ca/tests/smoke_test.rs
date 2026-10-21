//! End-to-end smoke test: the whole Plan-1 CA forest, composing.
//!
//! This is the proof that the pieces built in Tasks 2-9 work together:
//! the schema and its repositories (`ws_core`), the encrypted key store,
//! root and sub-CA creation, leaf issuance from a CSR, transactional
//! serial allocation, the certificate record and its revocation, the
//! append-only audit log, and the worker's CRL/OCSP publication job.
//!
//! One `#[tokio::test]` walks the whole flow once:
//!
//! 1. Connect to Postgres (all five migrations applied).
//! 2. Create the default tenant.
//! 3. Create an Ed25519 root CA and an Ed25519 sub-CA under it, both
//!    with their private keys in an encrypted key store.
//! 4. Build a P-256 CSR in the test and issue a leaf from the sub-CA
//!    with a serial taken from the transactional allocator.
//! 5. Persist the certificate row and the audit entries
//!    (`ca_created`, `cert_issued`, `cert_revoked`).
//! 6. Revoke the leaf with `key_compromise` and run the worker's
//!    `regen_crl_and_ocsp` job.
//! 7. Assert: the published CRL lists the revoked serial and verifies
//!    against the sub-CA with stock OpenSSL; the latest OCSP response
//!    for the serial is `revoked` and stock OpenSSL parses it; the
//!    audit log shows the three actions in chronological order.
//! 8. Simulate a restart: drop the key store, reopen the same
//!    directory, and load the sub-CA's key again.
//!
//! # Self-cleaning contract
//!
//! The shared `wardstone_test` database is also used by the ws-core,
//! ws-ca serial, and ws-worker suites, one of which asserts that
//! `tenants` is empty after its runs. To keep that true no matter how
//! this suite exits: every test sweeps away rows a previously crashed
//! run may have left behind under this suite's owned tenant name, and
//! every row inserted during the body is deleted *before* any assertion
//! runs, so a failing assertion cannot leave rows behind. All query
//! results are captured and unwrapped only after cleanup.
//!
//! # Cross-process serialization
//!
//! The test body holds a session-level Postgres advisory lock for its
//! whole duration on the key [`ADVISORY_KEY`] — the "WARDST" family
//! (ASCII "WARDST" = 0x5741445354) with suite marker 0x0009, the next
//! free marker after the ws-core suites (0x0003-0x0005, 0x0007), ws-ca's
//! serial suite (0x0006), and ws-worker's suite (0x0008). This suite
//! owns a disjoint row set, and plain `cargo test` also runs test
//! binaries sequentially, so the key is a belt against concurrent
//! cross-crate runs. The in-process mutex mirrors the ws-core pattern
//! for future tests added to this binary.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use chrono::{Duration, Utc};
use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex;
use ws_ca::ca::{create_root, create_sub_ca, CaLifetime, CaSpec, KeyType};
use ws_ca::issue::{sign_leaf_with, LeafSpec, SanEntry};
use ws_ca::keystore::KeyStore;
use ws_ca::serial::allocate_serial;
use ws_core::db::connect;
use ws_core::models::audit::{ActorType, AuditEntry};
use ws_core::models::ca::CaModel;
use ws_core::models::certificate::{CertStatus, CertificateModel};
use ws_core::models::ocsp::OcspStatus;
use ws_core::repo::audit_repo::AuditRepo;
use ws_core::repo::ca_repo::CaRepo;
use ws_core::repo::certificate_repo::CertificateRepo;
use ws_core::repo::ocsp_repo::OcspRepo;
use ws_core::repo::tenant_repo::TenantRepo;
use ws_worker::jobs::regen_crl_and_ocsp;
use x509_parser::prelude::FromDer;
use x509_parser::revocation_list::CertificateRevocationList;

/// Postgres advisory-lock key for this suite: ASCII "WARDST"
/// (0x5741445354) plus the suite marker 0x0009. Processes taking this
/// key serialize their test bodies against this suite.
const ADVISORY_KEY: i64 = 0x0057_4144_5354_0009;

/// The tenant name this suite owns; deleted before asserts.
const SMOKE_TENANT: &str = "rt-smoke-tenant";

/// The root CA's name (unique per tenant).
const ROOT_CA_NAME: &str = "rt-smoke-root-ca";

/// The issuing sub-CA's name (unique per tenant).
const SUB_CA_NAME: &str = "rt-smoke-sub-ca";

/// The leaf's subject common name.
const LEAF_CN: &str = "leaf.example";

/// The leaf's subject alternative name.
const LEAF_SAN: &str = "leaf.example";

/// The profile label written on the certificate row.
const LEAF_PROFILE: &str = "smoke";

/// The revocation reason used for the leaf.
const REVOCATION_REASON: &str = "key_compromise";

/// The gap between the audit records.
///
/// The audit log's `created_at` is database-owned (`now()` at commit
/// time, microsecond resolution), so two records committed in the same
/// microsecond would tie and make a strict positional assertion
/// ambiguous. A short sleep between the records makes the ordering
/// assertion deterministic instead of flaky.
const AUDIT_GAP: std::time::Duration = std::time::Duration::from_millis(5);

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

/// The directory the test's key store lives in: unique per test name
/// and process id, swept before use so stale runs can't interfere.
fn temp_keystore_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ws-ca-smoke-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// A fresh key store in `dir` (the master key is created if it is not
/// there yet).
fn open_keystore(dir: &Path) -> KeyStore {
    let mut ks = KeyStore::open(dir).expect("open the test key store");
    ks.ensure_master_key().expect("create the master key");
    ks
}

/// The Ed25519 root CA of the forest.
fn root_spec() -> CaSpec {
    CaSpec {
        name: ROOT_CA_NAME.to_owned(),
        subject: "Wardstone Smoke Test Root".to_owned(),
        key_type: KeyType::Ed25519,
        lifetime: CaLifetime::Root,
    }
}

/// The Ed25519 issuing sub-CA of the forest.
fn sub_spec() -> CaSpec {
    CaSpec {
        name: SUB_CA_NAME.to_owned(),
        subject: "Wardstone Smoke Test Issuing CA".to_owned(),
        key_type: KeyType::Ed25519,
        lifetime: CaLifetime::SubCa,
    }
}

/// Mint a P-256 CSR for the leaf (the same pattern as the issuance
/// suite): the requester owns a P-256 key pair and asks for a
/// certificate with one DNS SAN.
fn mint_csr() -> String {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, LEAF_CN);
    params.subject_alt_names = vec![rcgen::SanType::DnsName(LEAF_SAN.try_into().unwrap())];
    let csr = params.serialize_request(&key_pair).unwrap();
    csr.pem().unwrap()
}

/// A scratch file path under the system temp dir, unique per test name
/// and process id, for handing PEMs and DER to the OpenSSL subprocess.
fn temp_path(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("ws-ca-smoke-{}-{suffix}", std::process::id()))
}

/// Whether the OpenSSL binary is available on this host.
///
/// The OpenSSL interop assertions are real (OpenSSL 3.0.13 is installed
/// on the build host), but they are skipped with a printed note when the
/// binary is absent, so the suite still runs on a bare Rust toolchain.
fn openssl_available() -> bool {
    match Command::new("openssl").arg("version").output() {
        Ok(out) => out.status.success(),
        Err(e) if e.kind() == ErrorKind::NotFound => false,
        Err(e) => panic!("failed to spawn openssl: {e}"),
    }
}

/// Run `openssl crl -in <crl_pem> -CAfile <ca_pem> -noout` and return its
/// combined output. The CRL and CA are written to scratch files first
/// (OpenSSL reads PEM from files, not from stdin, for `-CAfile`).
fn openssl_crl_verify(crl_pem: &str, ca_pem: &str) -> String {
    let crl_path = temp_path("crl.pem");
    let ca_path = temp_path("ca.pem");
    fs::write(&crl_path, crl_pem).expect("write the CRL for openssl");
    fs::write(&ca_path, ca_pem).expect("write the CA certificate for openssl");
    let out = Command::new("openssl")
        .arg("crl")
        .arg("-in")
        .arg(&crl_path)
        .arg("-CAfile")
        .arg(&ca_path)
        .arg("-noout")
        .output();
    let _ = fs::remove_file(&crl_path);
    let _ = fs::remove_file(&ca_path);
    let out = out.expect("spawn openssl crl");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "openssl crl -CAfile failed: {text}");
    text
}

/// Run `openssl ocsp -issuer <ca_pem> -cert <leaf_pem> -respin
/// <resp_der> -text` and return its combined output. The response
/// bytes are written to a scratch file first (`-respin` reads DER from
/// a file).
fn openssl_ocsp_parse(ca_pem: &str, leaf_pem: &str, resp_der: &[u8]) -> String {
    let ca_path = temp_path("ocsp-ca.pem");
    let leaf_path = temp_path("ocsp-leaf.pem");
    let resp_path = temp_path("ocsp-resp.der");
    fs::write(&ca_path, ca_pem).expect("write the CA certificate for openssl");
    fs::write(&leaf_path, leaf_pem).expect("write the leaf certificate for openssl");
    fs::write(&resp_path, resp_der).expect("write the OCSP response for openssl");
    let out = Command::new("openssl")
        .arg("ocsp")
        .arg("-issuer")
        .arg(&ca_path)
        .arg("-cert")
        .arg(&leaf_path)
        .arg("-respin")
        .arg(&resp_path)
        .arg("-text")
        .output();
    let _ = fs::remove_file(&ca_path);
    let _ = fs::remove_file(&leaf_path);
    let _ = fs::remove_file(&resp_path);
    let out = out.expect("spawn openssl ocsp");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "openssl ocsp failed: {text}");
    text
}

/// Sweep any rows a previously crashed run of this suite may have left
/// behind under the owned tenant name, in FK order: OCSP responses and
/// CRLs (they reference the CA), the used serials, the certificates,
/// the audit rows, the CAs (children before their parent), and the
/// tenant last.
async fn sweep_smoke_rows(pool: &PgPool) {
    for sql in [
        "DELETE FROM ocsp_responses WHERE ca_id IN \
         (SELECT id FROM cas WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1))",
        "DELETE FROM crls WHERE ca_id IN \
         (SELECT id FROM cas WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1))",
        "DELETE FROM used_serials WHERE ca_id IN \
         (SELECT id FROM cas WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1))",
        "DELETE FROM certificates WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM audit_log WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM cas WHERE parent_id IS NOT NULL AND tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM cas WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM tenants WHERE name = $1",
    ] {
        sqlx::query(sql)
            .bind(SMOKE_TENANT)
            .execute(pool)
            .await
            .expect("sweep stale smoke-suite rows");
    }
}

/// Delete the smoke test's rows before asserts, in FK order: OCSP
/// responses, CRLs, used serials, certificates, audit rows, the CAs
/// (children before their parent), and the tenant last. Runs whether
/// or not the inserts succeeded.
async fn delete_smoke_rows(pool: &PgPool, tenant_id: uuid::Uuid) {
    for sql in [
        "DELETE FROM ocsp_responses WHERE ca_id IN \
         (SELECT id FROM cas WHERE tenant_id = $1)",
        "DELETE FROM crls WHERE ca_id IN (SELECT id FROM cas WHERE tenant_id = $1)",
        "DELETE FROM used_serials WHERE ca_id IN (SELECT id FROM cas WHERE tenant_id = $1)",
        "DELETE FROM certificates WHERE tenant_id = $1",
        "DELETE FROM audit_log WHERE tenant_id = $1",
        "DELETE FROM cas WHERE parent_id IS NOT NULL AND tenant_id = $1",
        "DELETE FROM cas WHERE tenant_id = $1",
        "DELETE FROM tenants WHERE id = $1",
    ] {
        sqlx::query(sql)
            .bind(tenant_id)
            .execute(pool)
            .await
            .expect("delete smoke-suite rows");
    }
}

/// One audit entry: the caller's action label, actor, target, and
/// details.
fn audit_entry(
    tenant_id: uuid::Uuid,
    action: &str,
    target_type: &str,
    target_id: &str,
    details: serde_json::Value,
) -> AuditEntry {
    AuditEntry {
        id: uuid::Uuid::new_v4(),
        tenant_id,
        actor_type: ActorType::User,
        actor_id: "smoke-test".to_owned(),
        action: action.to_owned(),
        target_type: target_type.to_owned(),
        target_id: target_id.to_owned(),
        details,
        created_at: Utc::now(),
    }
}

/// The whole CA forest, end to end: root CA, issuing sub-CA, a leaf
/// issued from a CSR, the certificate record, the revocation, the
/// published CRL and OCSP response, the ordered audit log, and a
/// key store that survives a restart. Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn test_end_to_end_ca_forest() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    sweep_smoke_rows(&pool).await;

    // --- The CA forest -------------------------------------------------
    //
    // The key store holds both CA keys encrypted at rest; the directory
    // is reused verbatim by the restart simulation at the end of the
    // test.
    let keys_dir = temp_keystore_dir();
    let mut keystore = open_keystore(&keys_dir);
    let root = create_root(&root_spec(), &mut keystore).expect("create the root CA");
    // The documented caller contract: the parent's certificate PEM and
    // its DER private key travel together.
    let root_key = keystore
        .load_ca_key(&root.key_pair_id)
        .expect("load the root CA key from the key store");
    let sub = create_sub_ca(
        &root.cert_pem,
        root_key.as_slice(),
        &sub_spec(),
        &mut keystore,
    )
    .expect("create the sub-CA under the root");

    // --- The tenant and the CA rows -----------------------------------
    let tenant = TenantRepo::new(&pool)
        .insert(SMOKE_TENANT)
        .await
        .expect("insert the smoke tenant");
    let cas = CaRepo::new(&pool);
    let root_row = CaModel {
        id: root.key_pair_id,
        tenant_id: tenant.id,
        name: ROOT_CA_NAME.to_owned(),
        subject: "CN=Wardstone Smoke Test Root".to_owned(),
        is_root: true,
        parent_id: None,
        key_type: KeyType::Ed25519,
        not_before: Utc::now() - Duration::days(1),
        not_after: Utc::now() + Duration::days(3650),
        cert_pem: root.cert_pem.clone(),
        key_file: key_file_path(&keys_dir, &root.key_pair_id),
        created_at: Utc::now(),
    };
    cas.insert(&root_row).await.expect("insert the root CA row");
    let sub_row = CaModel {
        id: sub.key_pair_id,
        tenant_id: tenant.id,
        name: SUB_CA_NAME.to_owned(),
        subject: "CN=Wardstone Smoke Test Issuing CA".to_owned(),
        is_root: false,
        parent_id: Some(root.key_pair_id),
        key_type: KeyType::Ed25519,
        not_before: Utc::now() - Duration::days(1),
        not_after: Utc::now() + Duration::days(1825),
        cert_pem: sub.cert_pem.clone(),
        key_file: key_file_path(&keys_dir, &sub.key_pair_id),
        created_at: Utc::now(),
    };
    cas.insert(&sub_row).await.expect("insert the sub-CA row");

    // The forest really is a forest: the sub-CA is a child of the root.
    let children = cas
        .children_of(root.key_pair_id)
        .await
        .expect("list the root's children");
    let child_ids: Vec<uuid::Uuid> = children.iter().map(|ca| ca.id).collect();
    let fetched_sub = cas
        .get(sub.key_pair_id)
        .await
        .expect("fetch the sub-CA row")
        .expect("the sub-CA row is present");

    // --- The audit trail: the CA creations ----------------------------
    let audit = AuditRepo::new(&pool);
    tokio::time::sleep(AUDIT_GAP).await;
    audit
        .record(&audit_entry(
            tenant.id,
            "ca_created",
            "ca",
            &root.key_pair_id.to_string(),
            serde_json::json!({"name": ROOT_CA_NAME, "is_root": true}),
        ))
        .await
        .expect("record the root CA creation");
    tokio::time::sleep(AUDIT_GAP).await;
    audit
        .record(&audit_entry(
            tenant.id,
            "ca_created",
            "ca",
            &sub.key_pair_id.to_string(),
            serde_json::json!({"name": SUB_CA_NAME, "is_root": false}),
        ))
        .await
        .expect("record the sub-CA creation");

    // --- The leaf: a serial, a CSR, and an issued certificate ---------
    let serial = allocate_serial(sub.key_pair_id, tenant.id, &pool)
        .await
        .expect("allocate a serial for the sub-CA");
    let csr_pem = mint_csr();
    let issued = sign_leaf_with(
        &sub.cert_pem,
        sub.private_key_der.as_slice(),
        &csr_pem,
        &LeafSpec {
            sans: vec![SanEntry::Dns(LEAF_SAN.to_owned())],
            key_usages: vec![rcgen::KeyUsagePurpose::DigitalSignature],
            not_after: Some(Utc::now() + Duration::days(30)),
            subject_cn: None,
            serial,
        },
    )
    .expect("issue the leaf from the sub-CA");

    // The certificate record: the real values the issuance produced.
    let certs = CertificateRepo::new(&pool);
    let cert_id = uuid::Uuid::new_v4();
    let cert_row = CertificateModel {
        id: cert_id,
        tenant_id: tenant.id,
        ca_id: sub.key_pair_id,
        profile_name: LEAF_PROFILE.to_owned(),
        subject: format!("CN={LEAF_CN}"),
        serial,
        serial_hex: format!("{serial:x}"),
        san_dns: vec![LEAF_SAN.to_owned()],
        san_ips: vec![],
        key_type: "ecdsa-p256".to_owned(),
        not_before: issued.not_before,
        not_after: issued.not_after,
        cert_pem: issued.cert_pem.clone(),
        status: CertStatus::Active,
        revoked_at: None,
        revocation_reason: None,
        source: "manual".to_owned(),
        created_at: Utc::now(),
    };
    certs
        .insert(&cert_row)
        .await
        .expect("insert the certificate row");

    tokio::time::sleep(AUDIT_GAP).await;
    audit
        .record(&audit_entry(
            tenant.id,
            "cert_issued",
            "certificate",
            &cert_id.to_string(),
            serde_json::json!({"serial": format!("{serial:x}"), "ca_id": sub.key_pair_id.to_string()}),
        ))
        .await
        .expect("record the issuance");

    // --- The revocation -----------------------------------------------
    certs
        .revoke(cert_id, REVOCATION_REASON)
        .await
        .expect("revoke the certificate");
    tokio::time::sleep(AUDIT_GAP).await;
    audit
        .record(&audit_entry(
            tenant.id,
            "cert_revoked",
            "certificate",
            &cert_id.to_string(),
            serde_json::json!({"reason": REVOCATION_REASON}),
        ))
        .await
        .expect("record the revocation");

    // --- The worker publishes the CRL and the OCSP response ------------
    //
    // A short gap before the job runs keeps the worker's own audit
    // entries (`crl_built`) in a strictly later commit microsecond than
    // the `cert_revoked` entry above — the ordering assertion below must
    // not depend on a same-microsecond tie.
    tokio::time::sleep(AUDIT_GAP).await;
    let published = regen_crl_and_ocsp(&pool, &keystore).await;

    // --- Read every result before the cleanup -------------------------
    let revoked_row = certs
        .get(cert_id)
        .await
        .expect("read the certificate row")
        .expect("the certificate row is present");
    let crl_pem: String = sqlx::query_scalar(
        "SELECT crl_pem FROM crls WHERE ca_id = $1 ORDER BY issued_at DESC LIMIT 1",
    )
    .bind(sub.key_pair_id)
    .fetch_one(&pool)
    .await
    .expect("read the published CRL");
    // The published rows' tenant ids, read back from the columns.
    let crl_tenant: Result<Option<uuid::Uuid>, sqlx::Error> =
        sqlx::query_scalar("SELECT tenant_id FROM crls WHERE ca_id = $1 LIMIT 1")
            .bind(sub.key_pair_id)
            .fetch_one(&pool)
            .await;
    let used_serial_tenant: Result<Option<uuid::Uuid>, sqlx::Error> =
        sqlx::query_scalar("SELECT tenant_id FROM used_serials WHERE ca_id = $1 AND serial = $2")
            .bind(sub.key_pair_id)
            .bind(i64::try_from(serial).expect("the serial fits the bigint column"))
            .fetch_one(&pool)
            .await;
    let ocsp = OcspRepo::new(&pool);
    let latest_ocsp = ocsp
        .get_latest(
            sub.key_pair_id,
            i64::try_from(serial).expect("the serial fits the bigint column"),
        )
        .await
        .expect("read the latest OCSP response");
    let audit_entries = audit
        .list_by_tenant(tenant.id, 0, 100)
        .await
        .expect("list the tenant's audit entries");
    // The restart simulation: the in-process key store goes away
    // entirely, and a brand new one is opened on the same directory.
    let master_key_before = fs::read(keystore.master_key_path()).expect("read the master key");
    drop(keystore);
    let restarted = KeyStore::open(&keys_dir).expect("reopen the key store");
    let reloaded_sub_key = restarted
        .load_ca_key(&sub.key_pair_id)
        .expect("the sub-CA key survives the restart");
    let master_key_after = fs::read(restarted.master_key_path()).expect("read the master key");

    // --- Cleanup BEFORE asserting -------------------------------------
    delete_smoke_rows(&pool, tenant.id).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    // --- The forest is a forest ----------------------------------------
    assert_eq!(
        child_ids,
        vec![sub.key_pair_id],
        "the sub-CA is a child of the root CA"
    );
    assert_eq!(
        fetched_sub.parent_id,
        Some(root.key_pair_id),
        "the sub-CA row names the root as its parent"
    );
    assert!(!fetched_sub.is_root, "the sub-CA is not a trust anchor");

    // --- The leaf was issued by the sub-CA ----------------------------
    assert_eq!(
        issued.serial, serial,
        "the leaf carries the allocated serial"
    );
    assert_eq!(
        issued.cert_pem, cert_row.cert_pem,
        "the stored certificate is the issued one"
    );
    let (_, leaf_block) =
        x509_parser::pem::parse_x509_pem(issued.cert_pem.as_bytes()).expect("the leaf is PEM");
    let leaf_cert = leaf_block.parse_x509().expect("the leaf parses");
    let (_, ca_block) =
        x509_parser::pem::parse_x509_pem(sub.cert_pem.as_bytes()).expect("the sub-CA is PEM");
    let ca_cert = ca_block.parse_x509().expect("the sub-CA parses");
    assert_eq!(
        leaf_cert.issuer().as_raw(),
        ca_cert.subject().as_raw(),
        "the leaf is issued by the sub-CA, not by the root"
    );

    // --- The certificate record ----------------------------------------
    assert_eq!(revoked_row.status, CertStatus::Revoked);
    assert_eq!(
        revoked_row.revocation_reason.as_deref(),
        Some(REVOCATION_REASON)
    );
    assert!(revoked_row.revoked_at.is_some(), "the revocation is dated");
    assert_eq!(revoked_row.serial, serial);
    assert_eq!(revoked_row.serial_hex, format!("{serial:x}"));
    assert_eq!(revoked_row.not_before, issued.not_before);
    assert_eq!(revoked_row.not_after, issued.not_after);
    assert_eq!(revoked_row.san_dns, vec![LEAF_SAN.to_owned()]);
    assert_eq!(revoked_row.profile_name, LEAF_PROFILE);
    assert_eq!(revoked_row.source, "manual");

    // --- The published CRL lists the revoked serial --------------------
    //
    // The job's return value counts the CAs it published for, across the
    // whole database. Both of this suite's CAs are published for (the
    // root gets an empty CRL — a relying party must be able to fetch a
    // current document from every CA — and the sub-CA gets the CRL
    // listing the revocation), so the count is at least two.
    let published_count = published.expect("the regeneration job succeeds");
    assert!(
        published_count >= 2,
        "the job published for both of this suite's CAs: {published_count}"
    );
    let (_, crl_block) =
        x509_parser::pem::parse_x509_pem(crl_pem.as_bytes()).expect("the published CRL is PEM");
    let (_, crl) =
        CertificateRevocationList::from_der(&crl_block.contents).expect("the published CRL parses");
    let listed: Vec<u128> = crl
        .iter_revoked_certificates()
        .map(|entry| {
            entry
                .serial()
                .to_string()
                .parse::<u128>()
                .expect("a decimal serial")
        })
        .collect();
    assert!(
        listed.contains(&serial),
        "the published CRL lists the revoked serial {serial:x}: {listed:?}"
    );
    assert_eq!(
        crl_tenant
            .expect("read the published CRL's tenant_id")
            .expect("the published CRL row exists"),
        tenant.id,
        "the published CRL carries the tenant it was published for"
    );
    assert_eq!(
        used_serial_tenant
            .expect("read the used serial's tenant_id")
            .expect("the used serial row exists"),
        tenant.id,
        "the used serial carries the tenant it was allocated for"
    );
    assert_eq!(
        crl.issuer().as_raw(),
        ca_cert.subject().as_raw(),
        "the CRL is issued by the sub-CA"
    );
    if openssl_available() {
        let text = openssl_crl_verify(&crl_pem, &sub.cert_pem);
        eprintln!("openssl crl -CAfile output:\n{text}");
        assert!(
            text.contains("verify OK"),
            "openssl must verify the CRL against the sub-CA: {text}"
        );
    } else {
        eprintln!("note: openssl binary not found; skipping the openssl crl verification");
    }

    // --- The published OCSP response says `revoked` --------------------
    let latest_ocsp = latest_ocsp.expect("an OCSP response exists for the revoked serial");
    assert_eq!(latest_ocsp.status, OcspStatus::Revoked);
    assert_eq!(latest_ocsp.ca_id, sub.key_pair_id);
    assert_eq!(
        latest_ocsp.serial,
        i64::try_from(serial).expect("the serial fits the bigint column")
    );
    assert!(
        !latest_ocsp.resp_der.is_empty(),
        "the stored response carries the response bytes"
    );
    assert!(latest_ocsp.next_update > latest_ocsp.this_update);
    if openssl_available() {
        let text = openssl_ocsp_parse(&sub.cert_pem, &issued.cert_pem, &latest_ocsp.resp_der);
        eprintln!("openssl ocsp -text output:\n{text}");
        assert!(
            text.contains("revoked"),
            "openssl must report the certificate as revoked: {text}"
        );
        assert!(
            text.contains("Response verify OK"),
            "openssl must verify the response signature: {text}"
        );
    } else {
        eprintln!("note: openssl binary not found; skipping the openssl ocsp parse");
    }

    // --- The audit log tells the story in order -----------------------
    //
    // `list_by_tenant` returns newest first, so the chronological order
    // is the reverse of the listing. The three required actions must
    // appear in the order ca_created -> cert_issued -> cert_revoked.
    let chronological: Vec<&AuditEntry> = audit_entries.iter().rev().collect();
    let flow: Vec<&str> = chronological
        .iter()
        .map(|entry| entry.action.as_str())
        .filter(|action| {
            matches!(
                *action,
                "ca_created" | "cert_issued" | "cert_revoked" | "crl_built"
            )
        })
        .collect();
    // The required flow, with the worker's own `crl_built` entries
    // filtered out: two CA creations (the root and the sub-CA), the
    // issuance, and the revocation — in that order.
    let required_flow: Vec<&str> = chronological
        .iter()
        .map(|entry| entry.action.as_str())
        .filter(|action| matches!(*action, "ca_created" | "cert_issued" | "cert_revoked"))
        .collect();
    assert_eq!(
        required_flow,
        vec!["ca_created", "ca_created", "cert_issued", "cert_revoked"],
        "the audit log shows the CA creations, the issuance, and the revocation in order"
    );
    // The worker's CRL publications came after the revocation they
    // publish: the whole audited sequence, worker entries included, is
    // in that order.
    let crl_built_positions: Vec<usize> = flow
        .iter()
        .enumerate()
        .filter(|(_, action)| **action == "crl_built")
        .map(|(index, _)| index)
        .collect();
    let revoked_position = flow
        .iter()
        .position(|action| *action == "cert_revoked")
        .expect("the revocation is audited");
    for position in crl_built_positions {
        assert!(
            position > revoked_position,
            "the worker's CRL publication is audited after the revocation it publishes: {flow:?}"
        );
    }
    // The ordering is chronological, not an artifact of the listing: the
    // timestamps never decrease, and the audited flow's own timestamps
    // strictly increase (the records are separated by a sleep, so no two
    // of them share a commit microsecond).
    for pair in chronological.windows(2) {
        assert!(
            pair[0].created_at <= pair[1].created_at,
            "the audit log is in chronological order: {:?} then {:?}",
            pair[0].created_at,
            pair[1].created_at
        );
    }
    let flow_entries: Vec<&AuditEntry> = chronological
        .iter()
        .filter(|entry| {
            matches!(
                entry.action.as_str(),
                "ca_created" | "cert_issued" | "cert_revoked"
            )
        })
        .copied()
        .collect();
    for pair in flow_entries.windows(2) {
        assert!(
            pair[0].created_at < pair[1].created_at,
            "the audited flow's timestamps strictly increase: {:?} then {:?}",
            pair[0].created_at,
            pair[1].created_at
        );
    }

    // --- The key store survives a restart ------------------------------
    assert_eq!(
        reloaded_sub_key.as_slice(),
        sub.private_key_der.as_slice(),
        "the reopened key store returns the sub-CA's own key"
    );
    assert_eq!(
        master_key_before, master_key_after,
        "the master key was read, not regenerated"
    );
}

/// The path the key store files a CA's encrypted private key under.
fn key_file_path(dir: &Path, ca_id: &uuid::Uuid) -> String {
    dir.join("ca")
        .join(format!("{ca_id}.key"))
        .to_string_lossy()
        .to_string()
}
