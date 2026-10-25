//! Integration tests for `ws-web` (Task 11): the first-run setup page and
//! its submit, the unmounting of the setup route once the tenant exists,
//! and the self-signed setup certificate with its SHA-256 fingerprint.
//!
//! These tests run against a live Postgres and are marked `#[ignore]`.
//! Run them with:
//!
//! ```sh
//! DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test \
//!     cargo test -p ws-web --test setup_test -- --include-ignored
//! ```
//!
//! # Self-cleaning contract
//!
//! The shared `wardstone_test` database is also used by the ws-core and
//! ws-api suites, one of which asserts that `tenants` is empty after its
//! runs. Every test here sweeps away rows a previously crashed run may
//! have left behind under the setup tenant's name, and every row the body
//! inserts is deleted again BEFORE the assertions run (the same
//! self-cleaning contract ws-api's suite uses), so a failing assertion can
//! never leave rows behind. The results are captured before the cleanup.
//!
//! # Cross-process serialization
//!
//! Each test body holds a session-level Postgres advisory lock for its
//! whole duration on [`ADVISORY_KEY`] — the "WARDST" family with this
//! suite's marker 0x0010 (ws-core's suites hold 0x0003..0x0005, ws-ca's
//! serial suite 0x0006, and this plan's other suites 0x000b..0x000f).
//! The in-process mutex mirrors the ws-core pattern.

use std::path::PathBuf;
use std::sync::OnceLock;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex as TokioMutex;
use tower::ServiceExt;
use x509_parser::pem::parse_x509_pem;
use zeroize::Zeroizing;

use ws_ca::keystore::KeyStore;
use ws_core::db::connect;
use ws_web::setup::{tls, SetupFields, SetupState};
use ws_web::{run_setup, setup};

/// Postgres advisory-lock key for this suite: ASCII "WARDST" (0x5741445354)
/// plus the suite marker 0x0010.
const ADVISORY_KEY: i64 = 0x0057_4144_5354_0010;

/// The setup flow's target display hostname (the self-signed setup
/// certificate's SAN — it predates profiles and is not constrained by
/// them).
const HOSTNAME: &str = "wardstone-ui.test";

/// The CA-issued leaf's SAN the tests submit as `server_hostname`. Task 9
/// (Plan-2 I-3) makes setup refuse a hostname the built-in `web-server`
/// profile's SAN patterns forbid, so the submitted hostname must live
/// under the default domain's wildcard (`*.wardstone.test`) — it is NOT
/// [`HOSTNAME`], which only the boot certificate carries.
const LEAF_HOSTNAME: &str = "ui.wardstone.test";

/// A display-only fingerprint placeholder (the real one comes from
/// `setup_certificate`; the page only echoes the state it was given).
const PAGE_FINGERPRINT: &str = "abcd";

/// In-process serialization, the whole-body lock pattern of the ws-core
/// and ws-api suites: the harness runs tests on separate threads. A tokio
/// mutex because the guard is held across `.await` points.
static DB_TEST_LOCK: OnceLock<TokioMutex<()>> = OnceLock::new();

/// The guard must be held (not dropped) until the test body finishes.
#[must_use = "the database lock must stay bound for the whole test body"]
async fn lock_db() -> tokio::sync::MutexGuard<'static, ()> {
    DB_TEST_LOCK
        .get_or_init(|| TokioMutex::new(()))
        .lock()
        .await
}

/// Take the session-level advisory lock `key` on a dedicated pooled
/// connection (the ws-api/ws-ca suite pattern).
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

/// Release the advisory lock taken by [`lock_advisory`] explicitly.
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

/// Delete every row a previous run may have left under `name` (children
/// first, then the tenant) — the FK-first sweep ws-api's suite uses.
async fn sweep_tenant(pool: &PgPool, name: &str) {
    sqlx::query(
        "DELETE FROM audit_log WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
    )
    .bind(name)
    .execute(pool)
    .await
    .expect("sweep stale audit rows");
    sqlx::query(
        "DELETE FROM service_identity_capabilities WHERE service_identity_id IN \
         (SELECT id FROM service_identities WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1))",
    )
    .bind(name)
    .execute(pool)
    .await
    .expect("sweep stale capability grant rows");
    for table in [
        "DELETE FROM certificates WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM used_serials WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM one_shot_tokens WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM service_identities WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM profiles WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM cas WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM oidc_config WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM refresh_tokens WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM users WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM tenants WHERE name = $1",
    ] {
        sqlx::query(table)
            .bind(name)
            .execute(pool)
            .await
            .expect("sweep stale fixture-prefixed rows");
    }
}

/// The setup fields the tests submit.
fn test_fields() -> SetupFields {
    SetupFields {
        admin_username: "admin".to_string(),
        admin_password: "correct horse battery staple".to_string(),
        default_domain: "wardstone.test".to_string(),
        admin_cidrs: vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()],
        server_hostname: LEAF_HOSTNAME.to_string(),
        master_passphrase: "the-master-passphrase".to_string(),
        master_passphrase_confirm: "the-master-passphrase".to_string(),
    }
}

/// A per-test fixture: the pool, a fresh keys directory, and the held
/// advisory-lock connection.
struct Fixture {
    pool: PgPool,
    keys_dir: PathBuf,
    #[allow(dead_code)] // held for the whole body: serializes this suite
    advisory: Option<PoolConnection<sqlx::Postgres>>,
    /// Set once a role restore has verifiably landed; the panic-safe
    /// [`Drop`] net skips then.
    role_restored: bool,
    /// The panic-safe restore worker (see [`RestoreNet`]).
    net: RestoreNet,
}

/// The state the setup handlers need, from the fixture.
fn setup_state(fixture: &Fixture) -> SetupState {
    SetupState {
        pool: fixture.pool.clone(),
        keys_dir: fixture.keys_dir.clone(),
        fingerprint: PAGE_FINGERPRINT.to_string(),
        hostname: HOSTNAME.to_string(),
        tls_reload: None,
        // No api process exists in this suite's world: the setup commit's
        // relay finds a closed port and logs its WARN — the modeled
        // best-effort path, never a failed setup.
        api_base_url: "http://127.0.0.1:9".to_string(),
    }
}

impl Fixture {
    /// Restore the shared login role's password over the fixture's
    /// DEDICATED pre-rotation connection (established connections
    /// survive the conversion's rotation; the POOL may need a fresh
    /// connection at exactly the moment the password is rotated — the
    /// `28P01` that poisoned the 2026-10-25 full run). Idempotent.
    /// Called after every successful POST (before any post-rotation DB
    /// read), again by [`Fixture::cleanup`], and once more by the
    /// [`Drop`] net if a panic skipped both.
    async fn restore_role_password(&mut self) {
        let Some(conn) = self.advisory.as_mut() else {
            // The advisory connection is only ever released at the very
            // end of cleanup, after this restore — unreachable.
            panic!("the advisory connection must be held through the restore");
        };
        sqlx::query("ALTER USER wardstone PASSWORD 'wardstone'")
            .execute(&mut **conn)
            .await
            .expect("restore the shared test role's password");
        self.role_restored = true;
    }

    /// Delete every row this test created, restore the shared login
    /// role's password, release the advisory lock, and remove the keys
    /// directory. Runs BEFORE the assertions so a failing assert can
    /// never leave rows behind (the self-cleaning contract). The role
    /// restore is part of that contract: a successful setup POST runs
    /// the conversion, which rotates the `wardstone` login role's
    /// password — and every suite on this shared server connects as
    /// `wardstone:wardstone`, so a role left rotated breaks the next
    /// suite at its very first connect. The reset is idempotent for the
    /// tests that never reach the seal. The restore runs FIRST so the
    /// sweep below — over the pool — can never need a fresh connection
    /// while the password is rotated.
    async fn cleanup(&mut self) {
        self.restore_role_password().await;
        sweep_tenant(&self.pool, setup::DEFAULT_TENANT_NAME).await;
        if let Some(mut conn) = self.advisory.take() {
            release_advisory(&mut conn, ADVISORY_KEY).await;
        }
        let _ = std::fs::remove_dir_all(&self.keys_dir);
    }
}

/// The panic-safe restore net's worker: a dedicated thread whose own
/// little runtime owns a connection made AT FIXTURE TIME — sqlx
/// connections are runtime-affine (the socket registers with the
/// reactor that created it), so the Drop-time ALTER can never run over
/// a connection made on the test's runtime from a fresh one; it would
/// hang on a socket that runtime cannot wake. The fixture-built
/// connection is made while the bootstrap credential is still valid,
/// and established connections survive the rotation, so it can still
/// ALTER when Drop asks — the only moment the restore is actually
/// needed. Best-effort by design: if the worker's connect failed, the
/// channel's receiver is gone and the Drop-time send is a no-op (the
/// manual `sudo -u postgres psql` reset remains the documented
/// last resort).
struct RestoreNet {
    /// "please restore" — sent from Drop.
    request: std::sync::mpsc::Sender<()>,
    /// The worker's reply once the ALTER landed (Drop waits on it).
    reply: std::sync::mpsc::Receiver<()>,
}

/// Spawn the restore net's worker thread. The connection is created
/// immediately (the bootstrap credential is valid now); the worker then
/// parks on the request channel until the fixture drops.
fn spawn_restore_net(url: &str) -> RestoreNet {
    let (request, rx) = std::sync::mpsc::channel::<()>();
    let (tx, reply) = std::sync::mpsc::channel::<()>();
    let url = url.to_owned();
    std::thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };
        // Phase 1: the worker's own connection, on the worker's own
        // runtime, while the bootstrap credential is still valid.
        let connected: Result<sqlx::PgConnection, sqlx::Error> =
            runtime.block_on(sqlx::Connection::connect(&url));
        let mut conn = match connected {
            Ok(conn) => conn,
            Err(_) => return, // the net is dead; Drop's send no-ops
        };
        // Phase 2: park until the fixture asks (blocking is fine here —
        // this runtime has nothing else to run). Dropping the fixture
        // without a request (cleanup restored) drops the sender, this
        // recv errs, and the worker exits.
        if rx.recv().is_err() {
            return;
        }
        // Phase 3: the restore, over the connection this runtime made.
        runtime.block_on(async {
            let _ = sqlx::query("ALTER USER wardstone PASSWORD 'wardstone'")
                .execute(&mut conn)
                .await;
        });
        let _ = tx.send(());
    });
    RestoreNet { request, reply }
}

/// The panic-safe half of the self-cleaning contract: a test that
/// unwinds between its POST's rotation and `cleanup()` would otherwise
/// leave the shared role rotated, and every later test — this suite's
/// siblings included — fails at its first connect with a misleading
/// `28P01` (the 2026-10-25 full-run cascade: one post-rotation query
/// failure poisoned five sibling tests). Drop cannot await, so the
/// restore runs on the worker above, joined with a timeout (a hung
/// worker is leaked and reaped at process exit rather than hanging the
/// unwinding test). Idempotent, and skipped entirely when a restore
/// already verifiably landed.
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.keys_dir);
        if self.role_restored {
            return;
        }
        // The net is one-shot: the request IS the fixture's last word.
        let _ = self.net.request.send(());
        let _ = self
            .net
            .reply
            .recv_timeout(std::time::Duration::from_secs(15));
    }
}

/// Build the fixture: connect, take the advisory lock, sweep stale rows,
/// create a fresh keys directory, and arm the panic-safe restore net.
async fn fixture() -> Fixture {
    let url = database_url();
    let pool = connect(&url)
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let advisory = lock_advisory(&pool, ADVISORY_KEY).await;
    // Sweep-first: stale rows of a previously crashed run under the setup
    // tenant's fixed name.
    sweep_tenant(&pool, setup::DEFAULT_TENANT_NAME).await;

    let keys_dir = std::env::temp_dir().join(format!(
        "ws-web-test-keys-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let net = spawn_restore_net(&url);

    Fixture {
        pool,
        keys_dir,
        advisory: Some(advisory),
        role_restored: false,
        net,
    }
}

/// Drive the router with a `POST /setup` carrying `fields` as JSON.
async fn post_setup(router: Router, fields: &SetupFields) -> axum::http::Response<Body> {
    let payload: Value = serde_json::to_value(fields).expect("the setup fields must serialize");
    router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/setup")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("build the POST request"),
        )
        .await
        .expect("in-process POST /setup")
}

async fn body_string(response: axum::http::Response<Body>) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read the response body");
    String::from_utf8(bytes.to_vec()).expect("the setup bodies are UTF-8")
}

/// A GET /setup serves the page: 200, and the body carries the setup
/// certificate's fingerprint (the operator verifies it out of band) and
/// the instance hostname.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn setup_page_serves_200_and_shows_the_fingerprint() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;
    let router = setup::setup_router(setup_state(&fixture));

    let response = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/setup")
                .body(Body::empty())
                .expect("build the GET request"),
        )
        .await
        .expect("in-process GET /setup");

    assert_eq!(response.status(), StatusCode::OK, "the page serves");
    let html = body_string(response).await;
    assert!(
        html.contains(PAGE_FINGERPRINT),
        "the page must display the setup certificate's SHA-256 fingerprint"
    );
    assert!(
        html.contains(HOSTNAME),
        "the page must show the instance hostname the certificate is for"
    );

    fixture.cleanup().await;
}

/// The POST creates the tenant, the root CA (key in the keystore), the
/// admin user (argon2id hash, never plaintext), the two default profiles
/// with non-empty key usages and EKUs, the secret-encryption key file, and
/// the audit entries — and mints the server's own CA-issued leaf.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn setup_submit_creates_tenant_root_ca_admin_profiles_and_the_server_leaf() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;
    let fields = test_fields();
    let router = setup::setup_router(setup_state(&fixture));

    let response = post_setup(router, &fields).await;
    assert_eq!(response.status(), StatusCode::OK, "the setup POST succeeds");

    // The conversion rotated the shared role: restore it over the
    // fixture's dedicated connection BEFORE any post-rotation DB read —
    // the pool may need a fresh connection, which the rotated password
    // would refuse (the 28P01 self-defeat of the 2026-10-25 full run).
    fixture.restore_role_password().await;

    // Capture everything BEFORE the cleanup, then assert afterwards.
    let pool = fixture.pool.clone();
    let tenant_name = setup::DEFAULT_TENANT_NAME.to_string();
    let tenant_id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM tenants WHERE name = $1")
            .bind(&tenant_name)
            .fetch_optional(&pool)
            .await
            .expect("query the setup tenant");
    let tenant_id = tenant_id.expect("setup creates exactly the one tenant");

    let ca: Option<(uuid::Uuid, bool, String, String)> =
        sqlx::query_as("SELECT id, is_root, subject, key_type FROM cas WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_optional(&pool)
            .await
            .expect("query the setup root CA");
    let (ca_id, ca_is_root, ca_subject, ca_key_type) = ca.expect("setup creates the root CA");

    let admin: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT username, password_hash FROM users WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_optional(&pool)
            .await
            .expect("query the setup admin");

    let profiles: Vec<(uuid::Uuid, String)> =
        sqlx::query_as("SELECT id, name FROM profiles WHERE tenant_id = $1 ORDER BY name")
            .bind(tenant_id)
            .fetch_all(&pool)
            .await
            .expect("query the default profiles");

    let revisions: Vec<(uuid::Uuid, i32, Vec<String>, Vec<String>)> = sqlx::query_as(
        "SELECT profile_id, revision, key_usages, eku FROM profile_revisions \
         WHERE profile_id IN (SELECT id FROM profiles WHERE tenant_id = $1) \
         ORDER BY profile_id, revision",
    )
    .bind(tenant_id)
    .fetch_all(&pool)
    .await
    .expect("query the default profile revisions");

    let certs: Vec<(
        uuid::Uuid,
        String,
        String,
        String,
        String,
        Option<uuid::Uuid>,
    )> = sqlx::query_as(
        "SELECT id, subject, status, source, profile_name, profile_revision_id \
         FROM certificates WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_all(&pool)
    .await
    .expect("query the server leaf certificate");

    let audit_actions: Vec<String> =
        sqlx::query_scalar("SELECT action FROM audit_log WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_all(&pool)
            .await
            .expect("query the setup audit entries");

    // Captured BEFORE cleanup like the audit actions: the ca-created row's
    // JSON details carry the key type the bootstrap recorded.
    let ca_created_details: Option<(String,)> = sqlx::query_as(
        "SELECT details::text FROM audit_log WHERE tenant_id = $1 \
             AND action = 'ca_created'",
    )
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await
    .expect("query the ca_created audit row");

    // The leaf's issuer chain and DER: parsed while the keys directory
    // still exists (cleanup removes it just below).
    let leaf_pem: String = match certs.first() {
        Some((leaf_id, _, _, _, _, _)) => {
            sqlx::query_scalar("SELECT cert_pem FROM certificates WHERE id = $1")
                .bind(leaf_id)
                .fetch_one(&pool)
                .await
                .expect("fetch the leaf's PEM")
        }
        None => String::new(),
    };
    // The sealed-volume contract: the conversion wraps every plaintext
    // original into passphrase envelopes and deletes the originals, so
    // the legacy file-read store must refuse on this volume now — and
    // the passphrase-opened store must load the very same keys.
    let legacy_refused = KeyStore::open(&fixture.keys_dir)
        .and_then(|store| store.load_ca_key(&ca_id).map(|_| ()))
        .is_err();
    let unlocked_store = {
        let master = ws_core::crypto::KeyEnvelope::open_envelope(
            &fixture.keys_dir.join(setup::MASTER_ENVELOPE_FILE),
            &fields.master_passphrase,
        )
        .expect("open the master envelope with the setup passphrase");
        let mut master_bytes = [0u8; 32];
        master_bytes.copy_from_slice(&master);
        KeyStore::open_unlocked(&fixture.keys_dir, Zeroizing::new(master_bytes))
            .expect("open the unlocked store")
    };
    let root_key_loaded = unlocked_store.load_ca_key(&ca_id).is_ok();
    let leaf_key_loaded = certs
        .first()
        .map(|row| unlocked_store.load_ca_key(&row.0).is_ok())
        .unwrap_or(false);
    let secret_key_exists = fixture
        .keys_dir
        .join(ws_api::state::SECRET_KEY_FILE)
        .exists();
    // The envelopes this volume actually holds: master (the keystore
    // minted it), secret-encryption (run_setup minted it), and the DB
    // credential (the rotation always seals one). The JWT pair is the
    // api process's to mint — no api runs in this test's world, so the
    // conversion correctly leaves no jwt envelope behind; the e2e suite
    // pins that arm where the api actually shares the volume.
    let envelopes_exist = [
        setup::MASTER_ENVELOPE_FILE,
        "secret-encryption.envelope",
        setup::DB_CREDENTIAL_ENVELOPE_FILE,
    ]
    .iter()
    .all(|name| fixture.keys_dir.join(name).exists());

    fixture.cleanup().await;

    // Assertions (run after cleanup, per the self-cleaning contract).
    assert!(ca_is_root, "the setup CA is a root");
    assert_eq!(
        ca_subject, "wardstone.test",
        "the root's subject is the default domain the operator chose"
    );
    assert_eq!(
        ca_key_type, "ecdsa_p256",
        "the setup root must be the browser-universal ECDSA P-256 default \
         (an Ed25519 root cannot be trusted by Chromium-family browsers)"
    );
    assert!(
        root_key_loaded,
        "the root's key loads under the master passphrase"
    );
    assert!(
        legacy_refused,
        "the legacy file-read store must refuse on a converted volume"
    );
    assert!(
        envelopes_exist,
        "the conversion mints the envelopes for everything on the volume"
    );
    assert!(
        !secret_key_exists,
        "the conversion deletes the plaintext secret-encryption key"
    );

    let (admin_name, admin_hash) = admin.expect("setup creates the admin user");
    assert_eq!(admin_name, "admin");
    let hash = admin_hash.expect("the admin carries a password hash");
    assert!(
        hash.starts_with("$argon2id$"),
        "the stored hash must be an argon2id PHC string, got {hash:?}"
    );
    assert_ne!(
        hash, fields.admin_password,
        "the password is never plaintext"
    );
    assert!(
        ws_auth::password::verify_password(&fields.admin_password, &hash)
            .expect("verify the stored hash"),
        "the stored argon2id hash must verify the submitted password"
    );
    assert!(
        !ws_auth::password::verify_password("wrong password", &hash).unwrap_or(true),
        "a wrong password must not verify"
    );

    assert_eq!(profiles.len(), 2, "the two default profiles exist");
    let profile_names: Vec<&String> = profiles.iter().map(|(_, name)| name).collect();
    assert!(profile_names.contains(&&"web-server".to_string()));
    assert!(profile_names.contains(&&"web-server-ecdsa".to_string()));
    assert_eq!(revisions.len(), 2, "each default profile has revision 1");
    for (_, revision, key_usages, eku) in &revisions {
        assert_eq!(*revision, 1, "the default profiles start at revision 1");
        assert!(
            !key_usages.is_empty(),
            "a profile without key usages could issue nothing"
        );
        assert!(
            !eku.is_empty(),
            "a profile without an EKU list is incomplete"
        );
    }

    assert_eq!(certs.len(), 1, "setup mints exactly the server's own leaf");
    let (_leaf_id, leaf_subject, leaf_status, leaf_source, leaf_profile, leaf_revision) =
        certs[0].clone();
    assert_eq!(leaf_subject, format!("CN={LEAF_HOSTNAME}"));
    assert_eq!(leaf_status, "active");
    assert_eq!(leaf_source, "manual");
    assert_eq!(
        leaf_profile, "web-server",
        "the leaf follows the web-server profile"
    );
    assert!(
        leaf_revision.is_some(),
        "the leaf records its profile revision"
    );
    assert!(
        leaf_key_loaded,
        "the leaf's key loads under the master passphrase"
    );

    let leaf_pem_parsed = parse_x509_pem(leaf_pem.as_bytes())
        .expect("the leaf certificate is valid PEM")
        .1;
    let leaf_cert = leaf_pem_parsed.parse_x509().expect("the leaf DER parses");
    let leaf_issuer_cn = leaf_cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_owned);
    assert_eq!(
        leaf_issuer_cn.as_deref(),
        Some("wardstone.test"),
        "the leaf is signed by the setup root"
    );

    assert!(
        audit_actions
            .iter()
            .any(|action| action == "tenant_created"),
        "setup audits the tenant creation"
    );
    assert!(
        audit_actions.iter().any(|action| action == "ca_created"),
        "setup audits the root CA creation"
    );
    // The bootstrap audit row records the SAME key type the row does — the
    // operator's observability of "what key is my root" must never depend
    // on reading the cas row alone.
    let (ca_created_details,) = ca_created_details.expect("the ca_created audit row exists");
    let ca_created: Value =
        serde_json::from_str(&ca_created_details).expect("the ca_created audit details are JSON");
    assert_eq!(
        ca_created["key_type"], "ecdsa_p256",
        "the bootstrap audit row records the ECDSA P-256 root key type"
    );
    assert!(
        audit_actions.iter().any(|action| action == "user_created"),
        "setup audits the admin user creation"
    );
    assert_eq!(
        audit_actions
            .iter()
            .filter(|action| action.as_str() == "profile_created")
            .count(),
        2,
        "each default profile creation is audited"
    );
    assert!(
        audit_actions.iter().any(|action| action == "cert_issued"),
        "the server leaf issuance is audited"
    );
}

/// Run setup through the front-door composition: while no tenant exists
/// the setup page routes; once the tenant exists the setup route is GONE —
/// a request to it returns 404, not 403 — and /api/v1/* proxies onward.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn setup_route_is_gone_after_setup_and_api_v1_proxies() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;
    let fields = test_fields();

    // Before setup: the front door mounts the setup page.
    let before = ws_web::web_router(
        fixture.pool.clone(),
        fixture.keys_dir.clone(),
        PAGE_FINGERPRINT.to_string(),
        HOSTNAME.to_string(),
        None,                 // no listener to swap in the router suites
        "http://127.0.0.1:9", // intentionally nothing listens here
        ws_web::DEFAULT_SESSION_TTL,
        None, // no rate limiter on the front-door suites' routers
    )
    .await
    .expect("the front-door router builds while unconfigured");
    let response = before
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/setup")
                .body(Body::empty())
                .expect("build the GET request"),
        )
        .await
        .expect("in-process GET /setup");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "setup routes before setup"
    );

    // The setup submit itself runs through the pinned run_setup call.
    {
        let keys_dir = fixture.keys_dir.clone();
        let mut keystore = KeyStore::open(&keys_dir).expect("open the keystore");
        run_setup(&fields, &fixture.pool, &mut keystore)
            .await
            .expect("run_setup completes");
    }

    // After setup: rebuilding the front door leaves the setup route out —
    // 404, not 403.
    let after = ws_web::web_router(
        fixture.pool.clone(),
        fixture.keys_dir.clone(),
        PAGE_FINGERPRINT.to_string(),
        HOSTNAME.to_string(),
        None, // no listener to swap in the router suites
        "http://127.0.0.1:9",
        ws_web::DEFAULT_SESSION_TTL,
        None, // no rate limiter on the front-door suites' routers
    )
    .await
    .expect("the front-door router builds after setup");
    let get = after
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/setup")
                .body(Body::empty())
                .expect("build the GET request"),
        )
        .await
        .expect("in-process GET /setup");
    assert_eq!(get.status(), StatusCode::NOT_FOUND, "the setup GET is gone");
    let post = post_setup(after.clone(), &fields).await;
    assert_eq!(
        post.status(),
        StatusCode::NOT_FOUND,
        "the setup POST is gone, not merely refused"
    );

    // The proxy covers /api/v1/*: with nothing listening at the base URL
    // the forward fails visibly as a 502 (the API itself is mounted by the
    // Task 12/13 composition, not here).
    let proxied = after
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/healthz")
                .body(Body::empty())
                .expect("build the proxy request"),
        )
        .await
        .expect("in-process proxy request");
    assert_eq!(proxied.status(), StatusCode::BAD_GATEWAY);

    fixture.cleanup().await;
}

/// The setup certificate is self-signed, carries the configured SAN, its
/// returned fingerprint equals the SHA-256 of its own DER, and two calls
/// yield two different certificates (each is minted fresh; the plan does
/// NOT pin fingerprint stability across calls).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn setup_certificate_is_self_signed_matches_fingerprint_and_carries_the_san() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;

    let mut keystore = KeyStore::open(&fixture.keys_dir).expect("open the keystore");
    let (pem1, fingerprint_hex1) =
        tls::setup_certificate(&mut keystore, HOSTNAME).expect("mint the setup certificate");
    let (pem2, fingerprint_hex2) =
        tls::setup_certificate(&mut keystore, HOSTNAME).expect("re-mint the setup certificate");

    let (_, pem) = parse_x509_pem(pem1.as_bytes()).expect("the certificate is valid PEM");
    let der = pem.contents.clone();
    assert_eq!(
        hex::encode(Sha256::digest(&der)),
        fingerprint_hex1,
        "the returned fingerprint must equal the SHA-256 of the returned DER"
    );

    let cert = pem.parse_x509().expect("the DER parses");
    assert_eq!(
        cert.issuer(),
        cert.subject(),
        "the certificate is self-signed"
    );
    // The setup certificate's consumer is the operator's BROWSER: browsers
    // do not support Ed25519 TLS certificates (curl/openssl do — the gap
    // surfaced as ERR_SSL_PROTOCOL_ERROR in real deployment), so the mint
    // must stay on a browser-universal algorithm (ECDSA P-256).
    assert_eq!(
        cert.signature_algorithm.algorithm.to_id_string(),
        "1.2.840.10045.4.3.2",
        "the setup cert's signature is ecdsa-with-SHA256, not Ed25519 (1.3.101.112)"
    );
    assert_eq!(
        cert.public_key().algorithm.algorithm.to_id_string(),
        "1.2.840.10045.2.1",
        "the setup cert's public key is ECDSA (id-ecPublicKey), not Ed25519 (1.3.101.100) or RSA"
    );
    let san = cert
        .subject_alternative_name()
        .expect("the extensions parse")
        .expect("the setup certificate carries the SAN");
    let dns_names: Vec<String> = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            x509_parser::extensions::GeneralName::DNSName(name) => Some(name.to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(
        dns_names,
        vec![HOSTNAME.to_string()],
        "the setup certificate carries the configured SAN"
    );

    let (_, pem) = parse_x509_pem(pem2.as_bytes()).expect("the second PEM parses");
    assert_ne!(
        pem.contents, der,
        "two calls mint two different certificates (fresh key each time)"
    );
    assert_ne!(
        fingerprint_hex1, fingerprint_hex2,
        "the fingerprints differ along with the certificates"
    );

    assert!(
        keystore.master_key_path().exists(),
        "the keystore master key is generated before the setup key is stored"
    );
    keystore
        .load_setup_key()
        .expect("the setup slot holds the freshly minted key");

    fixture.cleanup().await;
}

/// Task 9 (Plan-2 I-3): a `server_hostname` the built-in `web-server`
/// profile's SAN patterns forbid is refused BEFORE anything is committed —
/// a 400 carrying the issuance path's message shape, the setup page still
/// serving (the route only mounts while the tenant is absent), and not a
/// single row written. A hostname the profile permits then proceeds
/// through the full bootstrap.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn setup_refuses_hostname_outside_profile_patterns() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;

    // No wildcard cover: `*.certificates.example.com` does not match a
    // bare `wardstone.example.com`, and the hostname is not the pattern's
    // own domain either.
    let refused_fields = SetupFields {
        default_domain: "certificates.example.com".to_string(),
        server_hostname: "wardstone.example.com".to_string(),
        ..test_fields()
    };
    let router = setup::setup_router(setup_state(&fixture));
    let response = post_setup(router, &refused_fields).await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a hostname the web-server profile forbids is a 400"
    );
    let body = body_string(response).await;
    let error = serde_json::from_str::<Value>(&body)
        .expect("the error body is JSON")
        .get("error")
        .and_then(Value::as_str)
        .expect("the error body carries an `error` message")
        .to_string();
    assert_eq!(
        error,
        "server_hostname is not permitted by the web-server profile: name \
         \"wardstone.example.com\" is not permitted by this profile",
        "the refusal carries the issuance path's specific message shape"
    );

    // The refusal commits nothing: no tenant row under the setup tenant's
    // name, and the front door still mounts the setup page (the route
    // exists only while the tenant is absent).
    let tenant_count: i64 = sqlx::query_scalar("SELECT count(*) FROM tenants WHERE name = $1")
        .bind(setup::DEFAULT_TENANT_NAME)
        .fetch_one(&fixture.pool)
        .await
        .expect("count the setup tenant");
    assert_eq!(tenant_count, 0, "the refusal writes no rows at all");
    let still_unconfigured = ws_web::web_router(
        fixture.pool.clone(),
        fixture.keys_dir.clone(),
        PAGE_FINGERPRINT.to_string(),
        HOSTNAME.to_string(),
        None,                 // no listener to swap in the router suites
        "http://127.0.0.1:9", // intentionally nothing listens here
        ws_web::DEFAULT_SESSION_TTL,
        None, // no rate limiter on the front-door suites' routers
    )
    .await
    .expect("the front-door router builds after the refusal");
    let get = still_unconfigured
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/setup")
                .body(Body::empty())
                .expect("build the GET request"),
        )
        .await
        .expect("in-process GET /setup after the refusal");
    assert_eq!(
        get.status(),
        StatusCode::OK,
        "the setup page still serves after the refusal"
    );

    // A matching hostname under the default domain's wildcard proceeds.
    let ok_fields = SetupFields {
        default_domain: "certificates.example.com".to_string(),
        server_hostname: "ca.certificates.example.com".to_string(),
        ..test_fields()
    };
    let router = setup::setup_router(setup_state(&fixture));
    let response = post_setup(router, &ok_fields).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a hostname the web-server profile permits completes the setup"
    );

    // The conversion rotated the shared role: restore before the
    // post-rotation reads below (the pool needs fresh connections).
    fixture.restore_role_password().await;

    // Capture before cleanup (the self-cleaning contract).
    let pool = fixture.pool.clone();
    let tenant_id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM tenants WHERE name = $1")
            .bind(setup::DEFAULT_TENANT_NAME)
            .fetch_optional(&pool)
            .await
            .expect("query the setup tenant");
    let tenant_id = tenant_id.expect("the permitted setup creates the tenant");
    let admin_hash: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_optional(&pool)
            .await
            .expect("query the setup admin");
    let leaf_subject: Option<String> =
        sqlx::query_scalar("SELECT subject FROM certificates WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_optional(&pool)
            .await
            .expect("query the setup leaf");

    fixture.cleanup().await;

    let hash = admin_hash.expect("setup creates the admin");
    assert!(
        ws_auth::password::verify_password(&refused_fields.admin_password, &hash)
            .expect("verify the stored hash"),
        "the admin's argon2id hash verifies the submitted password"
    );
    assert_eq!(
        leaf_subject,
        Some(format!("CN={}", ok_fields.server_hostname)),
        "the matching setup mints the leaf with the permitted hostname"
    );
}

/// Task 9: the leaf transaction audits the completion of setup itself —
/// exactly ONE `setup_completed` row per completed setup, the system
/// actor, target the tenant, details carrying the submitted domain and
/// admin CIDRs (house-style direct pool read; the setup test mounts no
/// API router).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn setup_completed_audit_row_written() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;
    let fields = test_fields();
    let router = setup::setup_router(setup_state(&fixture));
    let response = post_setup(router, &fields).await;
    assert_eq!(response.status(), StatusCode::OK, "the setup POST succeeds");

    // The conversion rotated the shared role: restore before the audit
    // reads below (the audit query needs a second pooled connection —
    // this exact ordering was the 2026-10-25 full-run failure).
    fixture.restore_role_password().await;

    let pool = fixture.pool.clone();
    let tenant_id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM tenants WHERE name = $1")
            .bind(setup::DEFAULT_TENANT_NAME)
            .fetch_optional(&pool)
            .await
            .expect("query the setup tenant");
    let rows: Vec<(String, String, String, String, String, String, Value)> = sqlx::query_as(
        "SELECT actor_type, auth_method, actor_id, action, target_type, target_id, details \
         FROM audit_log WHERE tenant_id = $1 AND action = 'setup_completed'",
    )
    .bind(tenant_id.expect("the completed setup created the tenant"))
    .fetch_all(&pool)
    .await
    .expect("query the setup_completed audit rows");

    fixture.cleanup().await;

    assert_eq!(
        rows.len(),
        1,
        "exactly one setup_completed row per completed setup"
    );
    let (actor_type, auth_method, actor_id, action, target_type, target_id, details) = &rows[0];
    assert_eq!(action, "setup_completed", "the completion action");
    assert_eq!(actor_type, "system", "the setup actor is the system");
    assert_eq!(auth_method, "system", "authenticated how machines are");
    assert_eq!(
        actor_id, "system:setup",
        "the same setup actor the bootstrap entries carry"
    );
    assert_eq!(target_type, "setup", "the completion targets the setup");
    assert_eq!(
        target_id,
        &tenant_id
            .expect("the completed setup created the tenant")
            .to_string(),
        "the completion targets the setup's tenant"
    );
    assert_eq!(
        details,
        &serde_json::json!({
            "domain": fields.default_domain,
            "admin_cidrs": fields.admin_cidrs,
        }),
        "the details carry the submitted domain and admin CIDRs"
    );
}

/// The panic-safe half of the self-cleaning contract, verified
/// deterministically. A test body that unwinds between its POST's
/// rotation and `cleanup()` leaves the shared `wardstone` role rotated;
/// every LATER test then fails at its very first connect with a
/// misleading `28P01` (the 2026-10-25 full-run cascade: one post-rotation
/// query failure poisoned five sibling tests and every suite after).
/// `drop(fixture)` runs exactly the Drop an unwind runs — no cleanup, no
/// restore — and the fresh bootstrap-credential connect afterwards is the
/// proof the net restored the role on the way down.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn a_fixture_dropped_mid_rotation_restores_the_shared_role() {
    let _db = lock_db().await;
    let fixture = fixture().await;
    let router = setup::setup_router(setup_state(&fixture));
    let response = post_setup(router, &test_fields()).await;
    assert_eq!(response.status(), StatusCode::OK, "the setup POST succeeds");

    // The deliberate unwind shape: the conversion has rotated the role,
    // cleanup never runs, and Drop fires mid-window.
    drop(fixture);

    // The proof: a fresh bootstrap-credential connect succeeds — the
    // net restored the role before the fence released.
    let pool = connect(&database_url())
        .await
        .expect("the dropped fixture restored the shared role");
    // The leaked world's rows: the POST created the setup tenant; sweep
    // it so the NEXT test starts clean (the fixture that would have done
    // this in cleanup was deliberately dropped).
    sweep_tenant(&pool, setup::DEFAULT_TENANT_NAME).await;
}

/// The upgrade conversion (Task 5): a legacy volume — the plaintext
/// master, secret, and JWT pair on the keys directory, a live database
/// whose role still authenticates with the env password — lands on the
/// INIT page, converts through its POST (envelopes minted, plaintext
/// deleted, the DB credential rotated so the old password stops
/// working), serves the full surface on the same listener, and a
/// REBOOTED door over the converted volume is the UNLOCK page: the
/// volume is sealed now, and the operator's passphrase opens it.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn a_legacy_volume_converts_and_the_reboot_lands_sealed() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;

    // The pre-sealing layout (the upgrade runbook's starting state).
    let keys_dir = fixture.keys_dir.clone();
    std::fs::create_dir_all(&keys_dir).unwrap();
    std::fs::write(keys_dir.join("master.key"), b"the-legacy-master-bytes").unwrap();
    std::fs::write(
        keys_dir.join(ws_api::state::SECRET_KEY_FILE),
        b"the-legacy-secret-bytes",
    )
    .unwrap();
    std::fs::write(
        keys_dir.join("jwt-signing-key.pem"),
        b"the legacy signing pem",
    )
    .unwrap();
    std::fs::write(
        keys_dir.join("jwt-verify-key.pem"),
        b"the legacy verify pem",
    )
    .unwrap();

    // The build closure proves the passphrase OPENS the converted volume
    // — it reads the master envelope and checks the wrapped bytes round-
    // trip — then hands back the full surface (the in-place resume).
    let proof_router =
        || axum::Router::new().route("/proof", axum::routing::get(|| async { "converted" }));
    let opening_ui = |keys_dir: std::path::PathBuf| {
        std::sync::Arc::new(ws_web::locked::SealedUi::new(std::sync::Arc::new(
            move |passphrase: &str, _: Option<&str>| {
                let keys_dir = keys_dir.clone();
                let passphrase = passphrase.to_owned();
                Box::pin(async move {
                    let master = ws_core::crypto::KeyEnvelope::open_envelope(
                        &keys_dir.join(ws_core::crypto::MASTER_ENVELOPE_FILE),
                        &passphrase,
                    )
                    .map_err(|e| format!("the converted volume did not open: {e}"))?;
                    if master.as_slice() != b"the-legacy-master-bytes" {
                        return Err("the wrapped bytes did not round-trip".to_owned());
                    }
                    Ok(proof_router())
                })
            },
        )))
    };
    let ui = opening_ui(keys_dir.clone());
    let init = ws_web::init::init_router(ui, &keys_dir, &database_url(), HOSTNAME);

    // The INIT page, not the unlock page: the volume is unsealed.
    let page = init
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let init_page_status = page.status();
    let init_page_html = body_string(page).await;

    // The conversion: the real seal_keys_volume runs against the
    // fixture's database (the rotation lands), and the door swaps to the
    // full surface on the same listener.
    let converted = init
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/init")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "passphrase": "the-conversion-passphrase",
                        "repeat": "the-conversion-passphrase",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let converted_status = converted.status();

    let served = init
        .clone()
        .oneshot(
            Request::builder()
                .uri("/proof")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let served_status = served.status();

    // The rotation's evidence, captured BEFORE the restore: a FRESH
    // connection with the env's now-retired password must be refused.
    // (The fixture's own pool predates the rotation — its established
    // connections survive — so the probe needs a fresh connect.)
    let bootstrap_dead = sqlx::PgPool::connect(&database_url())
        .await
        .map(|_| false)
        .unwrap_or(true);

    // The conversion rotated the shared role: restore it over the
    // fixture's dedicated connection BEFORE any later pool read.
    fixture.restore_role_password().await;

    // The volume's file state, captured before the cleanup removes the
    // keys directory.
    let envelopes_exist = [
        ws_core::crypto::MASTER_ENVELOPE_FILE,
        ws_core::crypto::SECRET_ENVELOPE_FILE,
        ws_core::crypto::JWT_ENVELOPE_FILE,
        ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE,
    ]
    .iter()
    .all(|file| keys_dir.join(file).exists());
    let plaintext_gone = [
        "master.key",
        ws_api::state::SECRET_KEY_FILE,
        "jwt-signing-key.pem",
        "jwt-verify-key.pem",
    ]
    .iter()
    .all(|file| !keys_dir.join(file).exists());

    // The REBOOT: a fresh door over the converted volume is the unlock
    // page — the volume derives as sealed now — and the same passphrase
    // unlocks it.
    let reboot_ui = opening_ui(keys_dir.clone());
    let reboot = ws_web::locked::locked_router(reboot_ui, &keys_dir, HOSTNAME);

    let reboot_page = reboot
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let reboot_page_status = reboot_page.status();
    let reboot_page_html = body_string(reboot_page).await;

    let unlocked = reboot
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "passphrase": "the-conversion-passphrase" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let unlocked_status = unlocked.status();

    let reboot_served = reboot
        .oneshot(
            Request::builder()
                .uri("/proof")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let reboot_served_status = reboot_served.status();

    fixture.cleanup().await;

    assert_eq!(init_page_status, StatusCode::OK);
    assert!(
        init_page_html.contains("holds unsealed key files"),
        "the INIT page names the volume's condition"
    );
    assert_eq!(
        converted_status,
        StatusCode::OK,
        "the conversion POST succeeds"
    );
    assert_eq!(
        served_status,
        StatusCode::OK,
        "the full surface serves in place"
    );
    assert!(envelopes_exist, "the conversion mints every envelope");
    assert!(
        plaintext_gone,
        "the conversion deletes every plaintext original"
    );
    assert!(
        bootstrap_dead,
        "the conversion's rotation retires the env password"
    );
    assert_eq!(reboot_page_status, StatusCode::OK);
    assert!(
        reboot_page_html.contains("is sealed")
            && !reboot_page_html.contains("holds unsealed key files"),
        "the rebooted door is the unlock page: the volume is sealed now"
    );
    assert_eq!(
        unlocked_status,
        StatusCode::OK,
        "the rebooted volume unlocks"
    );
    assert_eq!(
        reboot_served_status,
        StatusCode::OK,
        "the rebooted door serves the full surface after the unlock"
    );
}

/// The recovery runbook (spec §8): a re-initialized db volume leaves the
/// sealed credential envelope pointing at a dead password. The
/// operator's documented move — stop the stack, delete
/// `db-credential.envelope`, set a fresh `WARDSTONE_DB_PASSWORD`, boot —
/// must land on an unlock that RE-SEEDS: the ui's build mints a fresh
/// credential over the recovery URL's connection, ALTERs the role to
/// it, and seals it at the volume's generation, so the relayed api
/// unlock finds a live envelope again.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn the_recovery_boot_reseeds_the_db_credential_envelope() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;

    // A sealed volume whose db-credential envelope is gone (the
    // runbook's starting state).
    let keys_dir = fixture.keys_dir.clone();
    std::fs::create_dir_all(&keys_dir).unwrap();
    ws_core::crypto::KeyEnvelope::write_envelope(
        &keys_dir.join(ws_core::crypto::MASTER_ENVELOPE_FILE),
        "the-master-passphrase",
        b"the-master-bytes",
        ws_core::crypto::PROD_KDF_PARAMS,
        0,
    )
    .unwrap();
    assert!(!keys_dir
        .join(ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE)
        .exists());

    // The re-seed: over the recovery URL's connection (the fresh
    // bootstrap the operator set), a fresh credential is minted, the
    // role ALTER'd to it, and the envelope sealed at the volume's
    // generation.
    let fresh = setup::reseed_db_credential(&keys_dir, "the-master-passphrase", &database_url(), 0)
        .await
        .expect("the recovery re-seed succeeds");

    // The envelope is back, sealed under the volume's passphrase at the
    // volume's generation, and holds exactly the fresh credential.
    let resealed = ws_core::crypto::KeyEnvelope::open_envelope(
        &keys_dir.join(ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE),
        "the-master-passphrase",
    )
    .expect("the re-seeded envelope opens with the volume passphrase");
    assert_eq!(
        String::from_utf8_lossy(&resealed).into_owned(),
        fresh.clone(),
        "the re-sealed envelope holds exactly the fresh credential"
    );
    assert_eq!(
        ws_core::crypto::KeyEnvelope::read_generation(
            &keys_dir.join(ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE)
        )
        .unwrap(),
        0,
        "the re-seal lands at the volume's generation"
    );

    // The rotation is real: the recovery URL's credential no longer
    // connects, the fresh one does.
    let old_dead = sqlx::PgPool::connect(&database_url())
        .await
        .map(|_| false)
        .unwrap_or(true);
    let fresh_connects = sqlx::PgPool::connect(&format!(
        "postgres://wardstone:{fresh}@localhost:5432/wardstone_test"
    ))
    .await
    .is_ok();

    fixture.restore_role_password().await;
    fixture.cleanup().await;

    assert!(
        old_dead,
        "the re-seed's rotation retires the recovery URL's credential"
    );
    assert!(fresh_connects, "the fresh credential connects");
}
