//! Task 11 (Plan 4) integration suite: the certbot-shaped ACME conformance
//! run through the COMPOSED ws-web stack. The browser front door and the
//! API are separate processes in deployment; here ws-web's composed router
//! (`web_router_with_store`: the relay routes, the `/api/v1` proxy, and the
//! verbatim `/acme*` proxy) drives ws-api's REAL router serving on an
//! ephemeral loopback listener (`axum::serve` — the Plan-3 session_test
//! idiom), so every assertion in this suite crosses the front-door proxy
//! exactly as a real ACME client's traffic would.
//!
//! The client side is a minimal in-process ACME client built the way the
//! Plan-4 ws-api suite built its fixtures (openssl-minted key material,
//! compact JWSs signed one-request-per-fresh-nonce, the RFC 8555
//! protected-header shape), plus ws-acme's own arithmetic for the values a
//! real client computes (`key_authorization`, `dns01_record_value`,
//! RFC 7638 `thumbprint`) — the client provisions the same answers certbot
//! would, and the server verifies against ITS OWN independently computed
//! verdicts (nothing client-supplied is a verification input).
//!
//! # Why no real certbot subprocess
//!
//! The plan's Task 11 mentions driving a real certbot binary. That is
//! deliberately not done here: no certbot binary is guaranteed on the
//! hosts this suite runs on, and the conformance claim does not need it —
//! what makes certbot's run conformant is the PROTOCOL, and this suite
//! speaks the identical JWS protocol at the wire level (embedded-JWK
//! enrollment, kid-account POSTs, the nonce discipline, URL binding)
//! against the composed production stack. A subprocess would add OS
//! machinery, not protocol coverage; the four flows below ARE the
//! conformance run.
//!
//! Run against the shared dev Postgres:
//!
//! ```sh
//! DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test \
//!     cargo test -p ws-web --test acme_e2e_test -- --include-ignored
//! ```
//!
//! # Self-cleaning contract
//!
//! The suite's advisory key is `0x0057_4144_5354_0015` (the "WARDST" family
//! 0x5741445354, plan-allocated marker 0x0015 — the registry's next key
//! after ws-api's `0014` acme_test). Each test sweeps its owned tenant's
//! rows FK-first, holds the advisory lock across the body, and deletes
//! every created row (and the keys directory) BEFORE the assertions, so a
//! failing assert can never leave rows behind.

use std::collections::HashMap;
use std::future::Future;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, RwLock};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde_json::{json, Value};
use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex as TokioMutex;
use tower::ServiceExt;
use uuid::Uuid;

use ws_api::routes::acme::{ChallengeFetch, TxtResolver};
use ws_api::{AcmeConfig, ApiConfig, AppState, VerificationDeps};
use ws_auth::jwt::JwtKeys;
use ws_ca::ca::{create_root, CaLifetime, CaSpec};
use ws_ca::keystore::KeyStore;
use ws_ca::KeyType;
use ws_core::db::connect;
use ws_core::models::acme::{
    AcmeAuthorizationStatus, AcmeChallengeStatus, AcmeChallengeType, AcmeOrderStatus,
};
use ws_core::models::ca::CaModel;
use ws_core::models::certificate::CertStatus;
use ws_core::models::profile::{ProfileModel, ProfileRevisionModel};
use ws_core::repo::acme_repo::AcmeRepo;
use ws_core::repo::ca_repo::CaRepo;
use ws_core::repo::certificate_repo::CertificateRepo;
use ws_core::repo::profile_repo::ProfileRepo;
use ws_web::session::store::SessionStore;
use ws_web::{web_router_with_store, DEFAULT_IDLE_EVICTION, DEFAULT_SESSION_TTL};

/// Postgres advisory-lock key for this suite: ASCII "WARDST" (0x5741445354)
/// plus this suite's plan-allocated marker 0x0015.
const ADVISORY_KEY: i64 = 0x0057_4144_5354_0015;

/// The tenant name this suite owns; swept before use, deleted at the end.
const E2E_TENANT: &str = "rt-wsweb-acme-e2e";

/// The deployment hostname (the seed profile's domain; its DNS-name
/// pattern and the `*.` wildcard twin cover every identifier these tests
/// order).
const E2E_DOMAIN: &str = "wardstone-e2e.test";

/// The public URL base the fixture configures (the test stand-in for
/// `WARDSTONE_PUBLIC_URL`): every absolute assertion and every JWS `url`
/// binding derives from it, exactly as a real client would pin them. The
/// anti-Host-trust contract means this base need not be reachable — the
/// client strips it to the wire path for the front door.
const PUBLIC_URL: &str = "https://acme.wardstone-e2e.test";

/// The contact the account enrols with.
const CONTACT: &str = "mailto:ops@wardstone-e2e.test";

/// In-process serialization, the whole-body lock pattern of the house DB
/// suites.
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
/// connection (the house pattern).
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

/// Delete every row a previous run may have left under `name` (FK-first:
/// ACME children, issuance children, then audit/profiles/CAs/tenant).
async fn sweep_tenant(pool: &PgPool, name: &str) {
    for table in [
        "DELETE FROM acme_challenges WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM acme_authorizations WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM acme_orders WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM acme_accounts WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM certificates WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM used_serials WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM profiles WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM cas WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM audit_log WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM tenants WHERE name = $1",
    ] {
        sqlx::query(table)
            .bind(name)
            .execute(pool)
            .await
            .expect("sweep stale fixture rows");
    }
}

// ---------------------------------------------------------------------------
// The client side (openssl key fixtures + the compact JWS builder)
// ---------------------------------------------------------------------------

/// The openssl runner: stdout as text.
fn openssl_text(args: &[&str]) -> String {
    let out = Command::new("openssl")
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .expect("spawn openssl");
    assert!(out.status.success(), "openssl {args:?} failed");
    String::from_utf8(out.stdout).expect("openssl writes UTF-8 PEMs")
}

/// A key fixture: the private encoding key for signing and the public JWK
/// the new-account request embeds (the RFC 7638 thumbprint is taken from
/// that same JWK by ws-acme's own function).
struct KeyFixture {
    encoding_key: jsonwebtoken::EncodingKey,
    jwk: Value,
    alg: jsonwebtoken::Algorithm,
    alg_name: &'static str,
}

impl KeyFixture {
    /// An RSA-2048 key (RS256) generated AT TEST TIME — real ACME-client
    /// key material riding the same JOSE signing backend the verifier sits
    /// on. Minted once per suite binary.
    fn rsa2048() -> &'static KeyFixture {
        static KEY: OnceLock<KeyFixture> = OnceLock::new();
        KEY.get_or_init(|| {
            let pem = openssl_text(&[
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ]);
            let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes())
                .expect("the PEM parses as a JOSE key");
            let jwk = serde_json::to_value(
                jsonwebtoken::jwk::Jwk::from_encoding_key(
                    &encoding_key,
                    jsonwebtoken::Algorithm::RS256,
                )
                .expect("fixture JWK"),
            )
            .expect("JWK serializes");
            KeyFixture {
                encoding_key,
                jwk,
                alg: jsonwebtoken::Algorithm::RS256,
                alg_name: "RS256",
            }
        })
    }
}

/// What the protected header authenticates with: an existing account's kid
/// URL, or the embedded JWK (new-account style).
enum Identity {
    Kid(String),
    Jwk,
}

/// Build a client-side ACME request: a compact JWS whose protected header
/// carries the alg, the identity member, the `nonce` (one fresh nonce per
/// request, fetched from the server beforehand — the RFC 8555 §6.5
/// discipline), and the `url` the request binds itself to. A `Value::Null`
/// payload produces the empty POST-as-GET payload segment.
fn sign_acme_request(
    key: &KeyFixture,
    identity: &Identity,
    nonce: &str,
    url: &str,
    payload: &Value,
) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    let mut header = json!({ "alg": key.alg_name, "nonce": nonce, "url": url });
    match identity {
        Identity::Kid(kid) => header["kid"] = json!(kid),
        Identity::Jwk => header["jwk"] = key.jwk.clone(),
    }
    let protected = B64URL.encode(header.to_string());
    let payload_segment = match payload {
        Value::Null => String::new(),
        p => B64URL.encode(p.to_string()),
    };
    let signing_input = format!("{protected}.{payload_segment}");
    let signature =
        jsonwebtoken::crypto::sign(signing_input.as_bytes(), &key.encoding_key, key.alg)
            .expect("fixture signature computes under the fixture key");
    format!("{protected}.{payload_segment}.{signature}")
}

/// The DER bytes of one PEM body (PEMs the tests mint, download, and
/// revoke against).
fn pem_to_der(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("-----"))
        .collect();
    STANDARD
        .decode(body.as_bytes())
        .expect("the PEM body decodes as base64")
}

/// The RFC 8555 `csr`/`certificate` member: base64url of `pem`'s DER form.
fn member_b64url(pem: &str) -> String {
    URL_SAFE_NO_PAD.encode(pem_to_der(pem))
}

/// A valid ECDSA P-256 CSR (self-signed) for `cn` with DNS SANs `names` —
/// the ws-api suite's minting idiom; the seed profile pins `ecdsa-p256`,
/// so the signing leg's exact-algorithm rule is satisfied.
fn mint_csr(cn: &str, names: &[&str]) -> String {
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, KeyPair, SanType, PKCS_ECDSA_P256_SHA256,
    };
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;
    params.subject_alt_names = names
        .iter()
        .map(|n| SanType::DnsName((*n).try_into().unwrap()))
        .collect();
    let csr = params.serialize_request(&key_pair).unwrap();
    csr.pem().unwrap()
}

// ---------------------------------------------------------------------------
// The challenge-verification seams (Task 7's shapes, driven end to end)
// ---------------------------------------------------------------------------

/// The loopback HTTP-01 stub (the ws-api suite's std-net pattern): one std
/// thread, one swappable text body served for every GET, served paths
/// recorded for the server-side-fetch assertion. The stub answers over the
/// REAL loopback network, so the injected fetcher inside ws-api's state
/// genuinely fetches from it — the exact seam composition of a production
/// deployment (the client provisions the web answer, the server fetches
/// it from the identifier's authority).
struct ChallengeStub {
    base: String,
    served: Arc<StdMutex<Vec<String>>>,
    body: Arc<RwLock<String>>,
}

fn spawn_challenge_stub(body: &str) -> ChallengeStub {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("bind the loopback challenge stub");
    let port = listener.local_addr().expect("the stub port").port();
    let served = Arc::new(StdMutex::new(Vec::new()));
    let body = Arc::new(RwLock::new(body.to_owned()));
    let served_thread = served.clone();
    let body_thread = body.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 4096];
            let read = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..read]);
            let path = request
                .lines()
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .nth(1)
                .unwrap_or("/")
                .to_owned();
            served_thread
                .lock()
                .expect("the stub served log")
                .push(path);
            let answer = body_thread.read().expect("the stub body").clone();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                answer.len(),
                answer
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    });
    ChallengeStub {
        base: format!("http://127.0.0.1:{port}"),
        served,
        body,
    }
}

impl ChallengeStub {
    /// Swap the body the stub serves (the expected key authorization is
    /// only known once the challenge row exists).
    fn set_body(&self, body: String) {
        *self.body.write().expect("the stub body") = body;
    }

    /// The served-path snapshot, oldest first.
    fn served(&self) -> Vec<String> {
        self.served
            .lock()
            .expect("the served log")
            .iter()
            .cloned()
            .collect()
    }
}

/// The test HTTP-01 fetcher: the route must build EXACTLY the canonical
/// URL from the stored row (`http://<identifier>/.well-known/
/// acme-challenge/<token>`); that canonical URL is rewritten to the
/// loopback stub (same path, the stub's port) — anything else the route
/// might build fails the rewrite lookup, settles the challenge invalid,
/// and fails the test.
struct StubFetcher {
    client: reqwest::Client,
    rewrites: Arc<RwLock<HashMap<String, String>>>,
    calls: Arc<AtomicUsize>,
}

impl StubFetcher {
    fn new() -> Self {
        StubFetcher {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .no_proxy()
                .build()
                .expect("the stub-backed test client builds"),
            rewrites: Arc::new(RwLock::new(HashMap::new())),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn set_rewrite(&self, from: String, to: String) {
        self.rewrites
            .write()
            .expect("the rewrite table")
            .insert(from, to);
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ChallengeFetch for StubFetcher {
    fn fetch(&self, url: String) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mapped = self
            .rewrites
            .read()
            .expect("the rewrite table")
            .get(&url)
            .cloned()
            .ok_or_else(|| format!("unexpected fetch url: {url}"));
        let client = self.client.clone();
        Box::pin(async move {
            let mapped = mapped?;
            let response = client
                .get(&mapped)
                .send()
                .await
                .map_err(|err| format!("the HTTP request failed: {err}"))?;
            let status = response.status();
            let body = response
                .text()
                .await
                .map_err(|err| format!("the HTTP response body fetch failed: {err}"))?;
            if !status.is_success() {
                return Err(format!("the HTTP request returned status {status}"));
            }
            Ok(body)
        })
    }
}

/// The canned TXT resolver (the Task-7 seam): records keyed by the EXACT
/// (trailing-dot FQ) name the route queries; unlisted names answer the
/// empty record set. Swappable — the expected record value is only known
/// once the rows exist.
struct StaticTxtResolver {
    records: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl StaticTxtResolver {
    fn new() -> Self {
        StaticTxtResolver {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn set_record(&self, name: String, values: Vec<String>) {
        self.records
            .write()
            .expect("the record table")
            .insert(name, values);
    }
}

impl TxtResolver for StaticTxtResolver {
    fn resolve_txt(
        &self,
        name: String,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send>> {
        let records = self
            .records
            .read()
            .expect("the record table")
            .get(&name)
            .cloned()
            .unwrap_or_default();
        Box::pin(async move { Ok(records) })
    }
}

/// Spawn a router on an ephemeral loopback listener over plain HTTP and
/// return its base URL. The serve task lives until the process exits (the
/// session_test pattern).
async fn spawn_api(router: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the loopback ws-api listener");
    let addr = listener.local_addr().expect("the listener's local address");
    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("serve the ws-api router");
    });
    format!("http://{addr}")
}

// ---------------------------------------------------------------------------
// The composed environment
// ---------------------------------------------------------------------------

/// A per-test environment: the live pool, ws-web's COMPOSED router driving
/// ws-api's REAL router on loopback, the fixture tenant, the injected
/// challenge-verification seams, and the held advisory-lock connection.
struct Env {
    pool: PgPool,
    tenant_id: Uuid,
    web: axum::Router,
    keys_dir: PathBuf,
    stub: ChallengeStub,
    fetcher: Arc<StubFetcher>,
    resolver: Arc<StaticTxtResolver>,
    advisory: Option<PoolConnection<sqlx::Postgres>>,
}

impl Env {
    /// Delete every row this fixture (and the test body) created, release
    /// the advisory lock, and remove the keys directory. Runs BEFORE the
    /// assertions (the self-cleaning contract).
    async fn cleanup(&mut self) {
        for table in [
            "DELETE FROM acme_challenges WHERE tenant_id = $1",
            "DELETE FROM acme_authorizations WHERE tenant_id = $1",
            "DELETE FROM acme_orders WHERE tenant_id = $1",
            "DELETE FROM acme_accounts WHERE tenant_id = $1",
            "DELETE FROM certificates WHERE tenant_id = $1",
            "DELETE FROM used_serials WHERE tenant_id = $1",
            "DELETE FROM profiles WHERE tenant_id = $1",
            "DELETE FROM cas WHERE tenant_id = $1",
            "DELETE FROM audit_log WHERE tenant_id = $1",
            "DELETE FROM tenants WHERE id = $1",
        ] {
            sqlx::query(table)
                .bind(self.tenant_id)
                .execute(&self.pool)
                .await
                .expect("delete the fixture rows");
        }
        if let Some(mut conn) = self.advisory.take() {
            release_advisory(&mut conn, ADVISORY_KEY).await;
        }
        let _ = std::fs::remove_dir_all(&self.keys_dir);
    }
}

/// Build the environment: connect, take the advisory lock, sweep, insert
/// and pin the fixture tenant, build ws-api's REAL router (with the
/// challenge seams swapped in BEFORE the router wraps the state) on the
/// loopback listener, and wrap it in ws-web's COMPOSED router.
async fn env() -> Env {
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let advisory = lock_advisory(&pool, ADVISORY_KEY).await;
    sweep_tenant(&pool, E2E_TENANT).await;

    let tenant_id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(tenant_id)
        .bind(E2E_TENANT)
        .execute(&pool)
        .await
        .expect("insert fixture tenant");
    // The ACME surface resolves the install's PRIMARY tenant — the OLDEST
    // created (`created_at ASC, id ASC`). Pin this suite's tenant one
    // second BEFORE the epoch so it deterministically wins even while
    // another concurrently-running suite has its own epoch-pinned tenant
    // in the shared test database.
    sqlx::query("UPDATE tenants SET created_at = '1969-12-31 23:59:59+00' WHERE id = $1")
        .bind(tenant_id)
        .execute(&pool)
        .await
        .expect("pin the fixture tenant as the oldest");

    let keys_dir = std::env::temp_dir().join(format!(
        "ws-web-acme-e2e-keys-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    let mut keystore = KeyStore::open(&keys_dir).expect("open the fixture keystore");
    keystore.ensure_master_key().expect("ensure the master key");
    ws_core::crypto::SecretBox::create(&keys_dir.join("secret-encryption.key"))
        .expect("create the secret-encryption key");
    let jwt = JwtKeys::load_or_create(&keys_dir).expect("load or create the JWT key pair");

    let stub = spawn_challenge_stub("placeholder");
    let fetcher = Arc::new(StubFetcher::new());
    let resolver = Arc::new(StaticTxtResolver::new());

    let mut config = ApiConfig::new(E2E_DOMAIN.to_owned(), keys_dir.clone());
    config.acme = AcmeConfig {
        public_url: PUBLIC_URL.to_owned(),
        tos_url: None,
        acme_account_limit: None,
    };
    let mut state = AppState::new(pool.clone(), Arc::new(jwt), config);
    // The challenge-verification seams are swapped in BEFORE the router
    // wraps the state (the router clones it — a later mutation would not
    // reach it).
    state.verification = VerificationDeps::with_seams(fetcher.clone(), resolver.clone());
    let api_base = spawn_api(ws_api::router(state)).await;

    let store = Arc::new(SessionStore::new(
        DEFAULT_SESSION_TTL,
        DEFAULT_IDLE_EVICTION,
    ));
    let web = web_router_with_store(
        pool.clone(),
        keys_dir.clone(),
        "e2e-fingerprint".to_owned(),
        E2E_DOMAIN.to_owned(),
        &api_base,
        store,
        None, // the front-door limiters key on ConnectInfo, absent for a oneshot
    )
    .await
    .expect("build the composed ws-web router");

    Env {
        pool,
        tenant_id,
        web,
        keys_dir,
        stub,
        fetcher,
        resolver,
        advisory: Some(advisory),
    }
}

// ---------------------------------------------------------------------------
// Driving the front door
// ---------------------------------------------------------------------------

/// The response type the test helpers return.
type TestResponse = axum::http::Response<Body>;

async fn body_text(response: TestResponse) -> String {
    let bytes = to_bytes(response.into_body(), 4 << 20)
        .await
        .expect("read the response body");
    String::from_utf8(bytes.to_vec()).expect("the body is UTF-8")
}

async fn body_json(response: TestResponse) -> Value {
    let text = body_text(response).await;
    serde_json::from_str(&text).expect("the body is JSON")
}

fn nonce_of(response: &TestResponse) -> String {
    response
        .headers()
        .get("replay-nonce")
        .expect("every /acme response carries a Replay-Nonce")
        .to_str()
        .expect("the nonce is ASCII")
        .to_owned()
}

/// POST the JWS body at `path` THROUGH THE FRONT DOOR (ws-web's composed
/// router, tower oneshot — every ACME request in this suite crosses the
/// proxy exactly as the deployed traffic does).
async fn post_through_web(env: &Env, path: &str, jws: &str) -> TestResponse {
    let request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/jose+json")
        .body(Body::from(jws.to_owned()))
        .expect("build the ACME POST");
    env.web
        .clone()
        .oneshot(request)
        .await
        .expect("the composed router should respond")
}

/// GET a path through the front door (directory, nonce endpoint).
async fn get_through_web(env: &Env, path: &str) -> TestResponse {
    let request = Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(Body::empty())
        .expect("build the GET");
    env.web
        .clone()
        .oneshot(request)
        .await
        .expect("the composed router should respond")
}

/// Fetch a fresh nonce the way a client does: GET the nonce endpoint
/// through the front door and read the response header.
async fn fetch_nonce(env: &Env) -> String {
    let response = get_through_web(env, "/acme/new-nonce").await;
    nonce_of(&response)
}

/// The client-side thumbprint of the fixture key (ws-acme's own RFC 7638
/// arithmetic — the same function the server's kid resolution uses).
fn thumb_of(key: &KeyFixture) -> String {
    ws_acme::thumbprint(&key.jwk).expect("the fixture key is a thumbprintable JWK")
}

/// The account URL (the FULL RFC 7638 thumbprint as the last segment).
fn account_url(thumb: &str) -> String {
    format!("{PUBLIC_URL}/acme/{E2E_TENANT}/acct/{thumb}")
}

/// A kid-signed POST to an absolute ACME URL, driven through the front
/// door (the JWS binds the ABSOLUTE url member; the wire path is its
/// PUBLIC_URL-relative spelling — the anti-Host-trust contract, exercised
/// from the client's side). An empty payload is RFC POST-as-GET.
async fn kid_post(env: &Env, key: &KeyFixture, url: &str, payload: &Value) -> TestResponse {
    let nonce = fetch_nonce(env).await;
    let jws = sign_acme_request(
        key,
        &Identity::Kid(account_url(&thumb_of(key))),
        &nonce,
        url,
        payload,
    );
    let path = url
        .strip_prefix(PUBLIC_URL)
        .expect("a fixture-built absolute URL");
    post_through_web(env, path, &jws).await
}

/// The RFC 8555 §7.3 enrollment: an embedded-JWK new-account POST. No ToS
/// URL is configured, so the account mints `valid` immediately (the
/// settlement-9 posture). Returns the thumbprint.
async fn enroll_account(env: &Env, key: &KeyFixture) -> String {
    let thumb = thumb_of(key);
    let nonce = fetch_nonce(env).await;
    let jws = sign_acme_request(
        key,
        &Identity::Jwk,
        &nonce,
        &format!("{PUBLIC_URL}/acme/{E2E_TENANT}/new-account"),
        &json!({"termsOfServiceAgreed": true, "contact": [CONTACT]}),
    );
    let created = post_through_web(env, &format!("/acme/{E2E_TENANT}/new-account"), &jws).await;
    assert_eq!(created.status(), StatusCode::CREATED, "enrollment enrols");
    let location = created
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .expect("the account Location");
    assert_eq!(
        location,
        account_url(&thumb),
        "the account URL is absolute on the configured base"
    );
    thumb
}

/// The audit rows for `action` under the fixture tenant: (actor_type,
/// auth_method, actor_id, target_id, details), oldest first.
async fn audit_rows(env: &Env, action: &str) -> Vec<(String, String, String, String, Value)> {
    sqlx::query_as(
        "SELECT actor_type, auth_method, actor_id, target_id, details FROM audit_log \
         WHERE tenant_id = $1 AND action = $2 ORDER BY created_at",
    )
    .bind(env.tenant_id)
    .bind(action)
    .fetch_all(&env.pool)
    .await
    .expect("read the audit rows")
}

// ---------------------------------------------------------------------------
// Seeding fixtures (the profile issuing machine + a real root CA —
// setup-shaped state; the ACME protocol itself stays on the wire)
// ---------------------------------------------------------------------------

/// The REAL issuing profile under this tenant: "web-server" with revision
/// 1 as its CURRENT revision (the deferred-FK transaction the ws-api
/// suite's precedent uses), pinned `ecdsa-p256`, and this domain's
/// allow-list — the plain DNS name plus its `*.` wildcard, so BOTH e2e
/// identifier shapes (host… and *.…) fall inside the profile's SAN policy.
async fn seed_issuing_profile(env: &Env) {
    let profile_id = Uuid::new_v4();
    let revision_id = Uuid::new_v4();
    let mut tx = env
        .pool
        .begin()
        .await
        .expect("begin the profile seed transaction");
    ProfileRepo::new()
        .insert_profile(
            &mut *tx,
            &ProfileModel {
                id: profile_id,
                tenant_id: env.tenant_id,
                name: "web-server".to_owned(),
                description: None,
                current_revision_id: Some(revision_id),
                created_at: chrono::Utc::now(),
            },
        )
        .await
        .expect("seed the profile row");
    ProfileRepo::new()
        .insert_revision(
            &mut *tx,
            &ProfileRevisionModel {
                id: revision_id,
                profile_id,
                revision: 1,
                name: "init".to_owned(),
                key_type: "ecdsa-p256".to_owned(),
                key_usages: vec!["digital_signature".to_owned()],
                eku: vec!["server_auth".to_owned()],
                lifetime_days: 30,
                san_patterns: vec![E2E_DOMAIN.to_owned(), format!("*.{E2E_DOMAIN}")],
                is_legacy: false,
                created_at: chrono::Utc::now(),
                actor_id: "tests:wsweb-acme-e2e".to_owned(),
            },
        )
        .await
        .expect("seed the revision row");
    tx.commit().await.expect("commit the profile seed");
}

/// A REAL root CA: the key minted into the fixture keystore through
/// `ws_ca::ca::create_root` (the issuance signing leg loads it back) plus
/// the `cas` row the CA choice needs. Returns the root certificate PEM —
/// the chain tail the download body must carry.
async fn seed_root_ca(env: &Env) -> String {
    let mut keystore = KeyStore::open(&env.keys_dir).expect("open the fixture keystore");
    let created = create_root(
        &CaSpec {
            name: "e2e-test-root".to_owned(),
            subject: "Wardstone ACME E2E Root".to_owned(),
            key_type: KeyType::Ed25519,
            lifetime: CaLifetime::Root,
        },
        &mut keystore,
    )
    .expect("create the root CA");
    CaRepo::new()
        .insert(
            &env.pool,
            &CaModel {
                id: created.key_pair_id,
                tenant_id: env.tenant_id,
                name: "e2e-test-root".to_owned(),
                subject: "CN=Wardstone ACME E2E Root".to_owned(),
                is_root: true,
                parent_id: None,
                key_type: KeyType::Ed25519,
                not_before: chrono::Utc::now(),
                not_after: chrono::Utc::now() + chrono::Duration::days(3650),
                cert_pem: created.cert_pem.clone(),
                key_file: "tests/e2e-test-root".to_owned(),
                created_at: chrono::Utc::now(),
            },
        )
        .await
        .expect("insert the CA row");
    created.cert_pem
}

// ---------------------------------------------------------------------------
// The client's order-machine flow (each stage its own helper, so each test
// keeps the wire-level assertions of its own flavor)
// ---------------------------------------------------------------------------

fn order_url(order_id: Uuid) -> String {
    format!("{PUBLIC_URL}/acme/{E2E_TENANT}/orders/{order_id}")
}

fn authz_url(authz_id: Uuid) -> String {
    format!("{PUBLIC_URL}/acme/{E2E_TENANT}/authz/{authz_id}")
}

/// The uuid tail of an absolute URL handle (the Location IS the handle).
fn tail_uuid(url: &str) -> Uuid {
    Uuid::parse_str(url.rsplit('/').next().expect("a uuid tail"))
        .expect("the handle carries a uuid")
}

/// POST a new-order (kid-carried) for `identifier` through the front door,
/// asserting 201; returns (order id, creation body). The created
/// response's Location is read before the body consumes it.
async fn new_order(env: &Env, key: &KeyFixture, identifier: &str) -> (Uuid, Value) {
    let response = kid_post(
        env,
        key,
        &format!("{PUBLIC_URL}/acme/{E2E_TENANT}/new-order"),
        &json!({"identifiers": [{"type": "dns", "value": identifier}]}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "the order mints");
    let order_id = tail_uuid(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .expect("a Location on the created order"),
    );
    let body = body_json(response).await;
    (order_id, body)
}

/// POST-as-GET the first authorization URL of the creation body's
/// `authorizations` array and return its authorization object.
async fn read_authz(env: &Env, key: &KeyFixture, order_body: &Value) -> Value {
    let url = order_body["authorizations"][0]
        .as_str()
        .expect("an authz URL")
        .to_owned();
    let response = kid_post(env, key, &url, &Value::Null).await;
    let body = body_json(response).await;
    assert!(
        body["identifier"].is_object(),
        "an authorization object: {body}"
    );
    body
}

/// POST the empty trigger payload to `challenge_url_value` (the RFC 8555
/// §7.5.1 trigger), returning (status, body).
async fn trigger_challenge(
    env: &Env,
    key: &KeyFixture,
    challenge_url_value: &str,
) -> (StatusCode, Value) {
    let response = kid_post(env, key, challenge_url_value, &json!({})).await;
    let status = response.status();
    let body = body_json(response).await;
    (status, body)
}

/// Poll the order object POST-as-GET until it is `ready` (the challenge
/// settlement is synchronous, so the first read normally answers; the
/// loop is the client's RFC-shaped polling with a small bounded retry).
async fn poll_order_ready(env: &Env, key: &KeyFixture, order_id: Uuid) -> Value {
    for _ in 0..10 {
        let response = kid_post(env, key, &order_url(order_id), &Value::Null).await;
        assert_eq!(response.status(), StatusCode::OK, "the order reads");
        let body = body_json(response).await;
        if body["status"] == json!("ready") {
            return body;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the order never reached ready");
}

/// Finalize the order with a CSR carrying CN `cn` and DNS SANs `sans`,
/// returning (status, body).
async fn finalize(
    env: &Env,
    key: &KeyFixture,
    order_id: Uuid,
    cn: &str,
    sans: &[&str],
) -> (StatusCode, Value) {
    let csr = mint_csr(cn, sans);
    let response = kid_post(
        env,
        key,
        &format!("{PUBLIC_URL}/acme/{E2E_TENANT}/orders/{order_id}/finalize"),
        &json!({"csr": member_b64url(&csr)}),
    )
    .await;
    let status = response.status();
    let body = body_json(response).await;
    (status, body)
}

/// POST-as-GET the order's certificate URL, returning (status,
/// content-type, body text).
async fn download_certificate(
    env: &Env,
    key: &KeyFixture,
    order_id: Uuid,
) -> (StatusCode, Option<String>, String) {
    let response = kid_post(
        env,
        key,
        &format!("{PUBLIC_URL}/acme/{E2E_TENANT}/orders/{order_id}/certificate"),
        &Value::Null,
    )
    .await;
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|value| value.to_str().expect("ascii").to_owned());
    let body = body_text(response).await;
    (status, content_type, body)
}

/// Revoke the DER of `cert_pem` with the ACME reason integer, returning
/// (status, body text).
async fn revoke(
    env: &Env,
    key: &KeyFixture,
    cert_pem: &str,
    reason: Value,
) -> (StatusCode, String) {
    let response = kid_post(
        env,
        key,
        &format!("{PUBLIC_URL}/acme/{E2E_TENANT}/revoke-cert"),
        &json!({"certificate": member_b64url(cert_pem), "reason": reason}),
    )
    .await;
    let status = response.status();
    let body = body_text(response).await;
    (status, body)
}

/// Settle the HTTP-01 flavor of the FIRST authorization of an order whose
/// creation body is `order_body`: the client provisions the correct key
/// authorization at the loopback stub, and the server's INJECTED fetcher
/// verifies against its own fetch at the canonical path. Returns the
/// challenge token (for the served-path assertion).
async fn settle_http01(env: &Env, key: &KeyFixture, order_body: &Value) -> String {
    let authz = read_authz(env, key, order_body).await;
    let http_chall = authz["challenges"]
        .as_array()
        .expect("a challenges array")
        .iter()
        .find(|c| c["type"] == json!("http-01"))
        .expect("the http-01 flavor")
        .clone();
    let challenge_url_value = http_chall["url"].as_str().expect("a chall URL").to_owned();
    let token = http_chall["token"].as_str().expect("a token").to_owned();

    // The answer the CLIENT provisions (the same arithmetic certbot runs:
    // token || "." || thumbprint), served by the loopback stub at the
    // canonical path; the fetcher maps the identifier-authority URL the
    // route MUST build onto the stub.
    let expected = ws_acme::key_authorization(&token, &thumb_of(key));
    env.stub.set_body(expected);
    let identifier = authz["identifier"]["value"].as_str().expect("a dns value");
    let path = format!("/.well-known/acme-challenge/{token}");
    env.fetcher.set_rewrite(
        format!("http://{identifier}{path}"),
        format!("{}{path}", env.stub.base),
    );

    let (status, _body) = trigger_challenge(env, key, &challenge_url_value).await;
    assert_eq!(status, StatusCode::OK, "the challenge trigger answers");
    token
}

/// Full issuance on `identifier`: enroll, seed the profile and CA, place
/// the order, settle the HTTP-01 challenge through the stub, poll ready,
/// finalize with a CSR carrying exactly `identifier`. Returns the order
/// id; the caller drives the download/revocation flavor it tests.
async fn issue_certificate(env: &mut Env, identifier: &str) -> (Uuid, String) {
    let key = KeyFixture::rsa2048();
    enroll_account(env, key).await;
    seed_issuing_profile(env).await;
    let root_pem = seed_root_ca(env).await;
    let (order_id, order_body) = new_order(env, key, identifier).await;
    let _token = settle_http01(env, key, &order_body).await;
    let ready = poll_order_ready(env, key, order_id).await;
    assert_eq!(ready["status"], "ready");
    let (status, body) = finalize(env, key, order_id, identifier, &[identifier]).await;
    assert_eq!(status, StatusCode::OK, "finalize: {body}");
    assert_eq!(body["status"], "valid");
    (order_id, root_pem)
}

// ---------------------------------------------------------------------------
// The four conformance flows through the COMPOSED stack
// (directory → account → order → challenges → finalize → certificate →
// revocation → reuse) — the conformance run Task 11 exists for.
// ---------------------------------------------------------------------------

/// Test 1: the directory fetch through ws-web, the embedded-JWK enrollment
/// with no ToS configured, a dns-identifier order, the HTTP-01 challenge
/// answered by the loopback stub and verified by ws-api's INJECTED fetcher
/// over the real loopback network, the ready order finalized with a real
/// CSR, the certificate downloaded leaf-first, and the row/audit trail
/// (`source == "acme"`, the actor `acme_account`).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn acme_order_issues_end_to_end() {
    let _db = lock_db().await;
    let mut env = env().await;
    let key = KeyFixture::rsa2048();

    // -- directory: the member set and absolute URLs on the configured
    //    base, through the front door (ws-web forwards /acme verbatim).
    let directory = get_through_web(&env, &format!("/acme/{E2E_TENANT}/directory")).await;
    let directory_status = directory.status();
    let directory_nonce = nonce_of(&directory);
    let directory_link = directory
        .headers()
        .get(header::LINK)
        .map(|value| value.to_str().expect("ascii").to_owned());
    let directory_body = body_json(directory).await;

    // -- the nonce endpoint: 204 with no-store.
    let nonce_response = get_through_web(&env, "/acme/new-nonce").await;
    let nonce_status = nonce_response.status();
    let no_store = nonce_response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    drop(nonce_response);

    // -- enrollment (201 + the absolute account Location asserted inside)
    //    and the kid POST-as-GET read-back: no ToS configured, so the
    //    account mints valid immediately.
    let thumb = enroll_account(&env, key).await;
    let account_read = kid_post(&env, key, &account_url(&thumb), &Value::Null).await;
    let account_read_status = account_read.status();
    let account_read_body = body_json(account_read).await;

    // -- the issuing machine, seeded server-side (the profile and the CA
    //    are setup-shaped state; the ACME protocol stays on the wire).
    seed_issuing_profile(&env).await;
    let root_pem = seed_root_ca(&env).await;

    // -- new-order: 201 with the Location handle and the pending object.
    let (order_id, order_body) = new_order(&env, key, "host.wardstone-e2e.test").await;

    // -- the authorization object: both challenge flavors, with their
    //    absolute chall URLs inside, ready BEFORE the settle.
    let authz = read_authz(&env, key, &order_body).await;
    let http_chall_url = authz["challenges"]
        .as_array()
        .expect("a challenges array")
        .iter()
        .find(|c| c["type"] == json!("http-01"))
        .and_then(|c| c["url"].as_str())
        .expect("the http-01 chall URL")
        .to_owned();

    // -- the settle through the stub + the injected fetcher.
    let token = settle_http01(&env, key, &order_body).await;

    // -- the ready order; finalize with a real CSR; the download.
    let ready_body = poll_order_ready(&env, key, order_id).await;
    let (finalize_status, finalize_body) = finalize(
        &env,
        key,
        order_id,
        "host.wardstone-e2e.test",
        &["host.wardstone-e2e.test"],
    )
    .await;
    let (download_status, download_type, download_body) =
        download_certificate(&env, key, order_id).await;

    // -- the DB captures, then the cleanup, THEN the assertions.
    let order_row = AcmeRepo::new()
        .get_order(&env.pool, env.tenant_id, order_id)
        .await
        .expect("read the order row")
        .expect("the order row exists");
    let certificate_id = order_row.certificate_id.expect("the issued certificate id");
    let cert_row = CertificateRepo::new()
        .get(&env.pool, certificate_id)
        .await
        .expect("read the certificate row")
        .expect("the certificate row exists");
    let challenge_id = tail_uuid(&http_chall_url);
    let challenge_row = AcmeRepo::new()
        .get_challenge(&env.pool, env.tenant_id, challenge_id)
        .await
        .expect("read the challenge row")
        .expect("the challenge row exists");
    let authz_id = tail_uuid(
        order_body["authorizations"][0]
            .as_str()
            .expect("an authz URL"),
    );
    let authz_row = AcmeRepo::new()
        .get_authorization(&env.pool, env.tenant_id, authz_id)
        .await
        .expect("read the authorization row")
        .expect("the authorization row exists");
    let issued_audits = audit_rows(&env, "cert_issued").await;
    let served = env.stub.served();
    let fetcher_calls = env.fetcher.calls();
    let cert_pem = cert_row.cert_pem.clone();
    env.cleanup().await;

    // directory assertions
    assert_eq!(directory_status, StatusCode::OK);
    assert!(directory_nonce.len() >= 40, "a fresh Replay-Nonce");
    assert_eq!(
        directory_link, None,
        "no ToS is configured: no terms-of-service Link"
    );
    assert_eq!(
        directory_body["newNonce"],
        json!(format!("{PUBLIC_URL}/acme/new-nonce"))
    );
    assert_eq!(
        directory_body["newAccount"],
        json!(format!("{PUBLIC_URL}/acme/{E2E_TENANT}/new-account"))
    );
    assert_eq!(
        directory_body["newOrder"],
        json!(format!("{PUBLIC_URL}/acme/{E2E_TENANT}/new-order"))
    );
    assert_eq!(
        directory_body["revokeCert"],
        json!(format!("{PUBLIC_URL}/acme/{E2E_TENANT}/revoke-cert"))
    );
    assert_eq!(
        directory_body["keyChange"],
        json!(format!("{PUBLIC_URL}/acme/{E2E_TENANT}/key-change"))
    );
    assert!(
        directory_body.get("newAuthz").is_none(),
        "pre-authorization is not offered in v1"
    );
    assert_eq!(nonce_status, StatusCode::NO_CONTENT);
    assert_eq!(no_store.as_deref(), Some("no-store"));

    // account assertions
    assert_eq!(account_read_status, StatusCode::OK);
    assert_eq!(
        account_read_body["status"], "valid",
        "no ToS configured: the account is valid immediately"
    );

    // order assertions
    assert_eq!(order_body["status"], "pending");
    assert_eq!(order_body["profile"], "web-server");
    assert_eq!(
        order_body["finalize"],
        json!(format!(
            "{PUBLIC_URL}/acme/{E2E_TENANT}/orders/{order_id}/finalize"
        ))
    );

    // challenge assertions: the server-side fetch hit the canonical path
    // on the identifier's authority, exactly once, and the settled object
    // and row are valid.
    assert_eq!(
        served,
        vec![format!("/.well-known/acme-challenge/{token}")],
        "the server-side fetch hit the canonical path on the identifier"
    );
    assert_eq!(fetcher_calls, 1);
    assert_eq!(challenge_row.status, AcmeChallengeStatus::Valid);
    assert!(challenge_row.validated_at.is_some());
    // the settlement PROMOTION (fix round 1): the organically settled row
    // left the order-scope in the settle transaction, and it KEEPS the
    // 30-day reuse-window stamp the valid transition stamped.
    assert!(
        authz_row.order_id.is_none(),
        "a settled order-scoped authorization is promoted to account-level"
    );
    let fresh_days = (authz_row.expires_at - chrono::Utc::now()).num_days();
    assert!(
        (29..=30).contains(&fresh_days),
        "the promoted row keeps the 30-day reuse window, got {fresh_days} days"
    );

    // finalize + issuance assertions
    assert_eq!(ready_body["status"], "ready");
    assert_eq!(
        ready_body["authorizations"], order_body["authorizations"],
        "the READY order's poll still renders its (promoted) authorization \
         through the reuse-window lookup"
    );
    assert_eq!(
        finalize_status,
        StatusCode::OK,
        "finalize accepts a ready order: {finalize_body}"
    );
    assert_eq!(finalize_body["status"], "valid");
    assert_eq!(
        finalize_body["certificate"],
        json!(format!(
            "{PUBLIC_URL}/acme/{E2E_TENANT}/orders/{order_id}/certificate"
        ))
    );
    assert_eq!(
        download_status,
        StatusCode::OK,
        "the certificate URL serves: {download_body}"
    );
    assert_eq!(
        download_type.as_deref(),
        Some("application/pem-certificate-chain")
    );
    let leaf_at = download_body
        .find(&cert_pem)
        .expect("the leaf PEM in the download body");
    let root_at = download_body
        .find(&root_pem)
        .expect("the root PEM in the download body");
    assert!(
        leaf_at < root_at,
        "the chain body is leaf-first: leaf, then the CA chain"
    );

    // row + audit assertions
    assert_eq!(order_row.status, AcmeOrderStatus::Valid);
    assert!(order_row.csr_pem.is_some(), "the accepted CSR is recorded");
    assert_eq!(
        cert_row.source, "acme",
        "an ACME-issued certificate is the acme source"
    );
    assert_eq!(cert_row.status, CertStatus::Active);
    assert_eq!(cert_row.subject, "CN=host.wardstone-e2e.test");
    assert_eq!(cert_row.san_dns, vec!["host.wardstone-e2e.test".to_owned()]);
    assert_eq!(issued_audits.len(), 1, "ONE cert_issued audit row");
    assert_eq!(issued_audits[0].0, "acme_account", "the actor type");
    assert_eq!(issued_audits[0].1, "acme_account", "the auth method");
    assert_eq!(
        issued_audits[0].2,
        account_url(&thumb),
        "the actor is the account URL"
    );
    assert_eq!(issued_audits[0].3, certificate_id.to_string());
}

/// Test 2: the wildcard order — a `*.` identifier answers ONLY the dns-01
/// flavor (the RFC 8555 wildcard rule: no http-01 row exists, the
/// authorization object renders the value without the prefix with
/// `wildcard: true`), the server resolves the TXT record ITSELF through
/// the injected resolver, and the finalize issues the wildcard certificate
/// under the profile's `*.wardstone-e2e.test` SAN pattern.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn acme_wildcard_order_issues_via_dns01() {
    let _db = lock_db().await;
    let mut env = env().await;
    let key = KeyFixture::rsa2048();

    let thumb = enroll_account(&env, key).await;
    seed_issuing_profile(&env).await;
    let root_pem = seed_root_ca(&env).await;

    let (order_id, order_body) = new_order(&env, key, "*.wardstone-e2e.test").await;

    // -- the wire shape: the order keeps the VERBATIM wildcard identifier;
    //    the authorization object renders it WITHOUT the prefix with
    //    `wildcard: true`, carrying the dns-01 challenge ALONE.
    let authz = read_authz(&env, key, &order_body).await;
    let dns_chall_url = authz["challenges"]
        .as_array()
        .expect("a challenges array")
        .iter()
        .find(|c| c["type"] == json!("dns-01"))
        .and_then(|c| c["url"].as_str())
        .expect("the dns-01 chall URL")
        .to_owned();

    // -- the client provisions the TXT record exactly as a real client
    //    would: base64url(SHA256(key authorization)) on the
    //    `_acme-challenge.<identifier-without-prefix>.` name.
    let dns_token = authz["challenges"][0]["token"]
        .as_str()
        .expect("a token")
        .to_owned();
    let expected_record =
        ws_acme::dns01_record_value(&ws_acme::key_authorization(&dns_token, &thumb_of(key)));
    env.resolver.set_record(
        "_acme-challenge.wardstone-e2e.test.".to_owned(),
        vec![expected_record],
    );

    let (challenge_status, challenge_body) = trigger_challenge(&env, key, &dns_chall_url).await;

    // -- the ready order; finalize with a CSR whose CN carries the
    //    identifier (the wildcard order identifier rides the CN; the
    //    certificate's SANs come from the order, per the issuance core).
    let ready_body = poll_order_ready(&env, key, order_id).await;
    let (finalize_status, finalize_body) = finalize(
        &env,
        key,
        order_id,
        "wardstone-e2e.test",
        &["*.wardstone-e2e.test"],
    )
    .await;
    let (download_status, download_type, download_body) =
        download_certificate(&env, key, order_id).await;

    // -- DB captures, cleanup, assertions.
    let order_row = AcmeRepo::new()
        .get_order(&env.pool, env.tenant_id, order_id)
        .await
        .expect("read the order row")
        .expect("the order row exists");
    let certificate_id = order_row.certificate_id.expect("the issued certificate id");
    let cert_row = CertificateRepo::new()
        .get(&env.pool, certificate_id)
        .await
        .expect("read the certificate row")
        .expect("the certificate row exists");
    let authz_id = tail_uuid(
        order_body["authorizations"][0]
            .as_str()
            .expect("an authz URL"),
    );
    let challenge_rows = AcmeRepo::new()
        .list_challenges_by_authorization(&env.pool, env.tenant_id, authz_id)
        .await
        .expect("read the challenge rows");
    let issued_audits = audit_rows(&env, "cert_issued").await;
    let fetcher_calls = env.fetcher.calls();
    let cert_pem = cert_row.cert_pem.clone();
    env.cleanup().await;

    // wire assertions
    assert_eq!(
        order_body["identifiers"],
        json!([{"type": "dns", "value": "*.wardstone-e2e.test"}]),
        "the order carries the verbatim wildcard identifier"
    );
    assert_eq!(
        authz["identifier"],
        json!({"type": "dns", "value": "wardstone-e2e.test"}),
        "the authorization value is without the prefix"
    );
    assert_eq!(authz["wildcard"], true);
    assert_eq!(
        challenge_rows.len(),
        1,
        "a wildcard authorization mints the dns-01 flavor ALONE"
    );
    assert_eq!(challenge_rows[0].challenge_type, AcmeChallengeType::Dns01);
    assert_eq!(challenge_rows[0].status, AcmeChallengeStatus::Valid);

    // the verification resolved the DNS layer through the injected seam;
    // NO HTTP fetch ever ran.
    assert_eq!(challenge_status, StatusCode::OK);
    assert_eq!(challenge_body["status"], "valid");
    assert_eq!(fetcher_calls, 0, "no HTTP fetch on the dns-01 path");

    // finalize + certificate assertions
    assert_eq!(ready_body["status"], "ready");
    assert_eq!(
        finalize_status,
        StatusCode::OK,
        "the wildcard order finalizes: {finalize_body}"
    );
    assert_eq!(finalize_body["status"], "valid");
    assert_eq!(
        download_status,
        StatusCode::OK,
        "the certificate URL serves: {download_body}"
    );
    assert_eq!(
        download_type.as_deref(),
        Some("application/pem-certificate-chain")
    );
    let leaf_at = download_body
        .find(&cert_pem)
        .expect("the leaf PEM in the download body");
    let root_at = download_body
        .find(&root_pem)
        .expect("the root PEM in the download body");
    assert!(leaf_at < root_at, "the chain body is leaf-first");

    // row + audit assertions
    assert_eq!(order_row.status, AcmeOrderStatus::Valid);
    assert_eq!(cert_row.source, "acme");
    assert_eq!(cert_row.status, CertStatus::Active);
    assert_eq!(
        cert_row.subject, "CN=wardstone-e2e.test",
        "the CSR's own common name is the subject"
    );
    assert!(
        cert_row
            .san_dns
            .contains(&"*.wardstone-e2e.test".to_owned()),
        "the wildcard identifier rides the certificate's SANs: {:?}",
        cert_row.san_dns
    );
    assert_eq!(issued_audits.len(), 1, "ONE cert_issued audit row");
    assert_eq!(issued_audits[0].0, "acme_account");
    assert_eq!(issued_audits[0].2, account_url(&thumb));
    assert_eq!(issued_audits[0].3, certificate_id.to_string());
}

/// Test 3: revocation via the ACCOUNT key — the issued certificate
/// revokes through `POST /acme/{tenant}/revoke-cert` (reason superseded =
/// 4, the RFC 8555 integer), the row lands `revoked` with the typed
/// reason and ONE `cert_revoked` audit row attributed to the account, and
/// a second revoke of the same certificate is the idempotent 200 whose
/// first reason stands.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn acme_revocation_via_account_key() {
    let _db = lock_db().await;
    let mut env = env().await;

    // full issuance through the front door: the cert to revoke exists the
    // way production would have made it.
    let (order_id, _root_pem) = issue_certificate(&mut env, "host.wardstone-e2e.test").await;
    let key = KeyFixture::rsa2048();

    let order_row = AcmeRepo::new()
        .get_order(&env.pool, env.tenant_id, order_id)
        .await
        .expect("read the order row")
        .expect("the order row exists");
    let certificate_id = order_row.certificate_id.expect("the issued certificate id");
    let cert_pem = CertificateRepo::new()
        .get(&env.pool, certificate_id)
        .await
        .expect("read the certificate row")
        .expect("the certificate row exists")
        .cert_pem;

    // -- the first revoke: reason 4 (superseded).
    let (revoke_status, revoke_body) = revoke(&env, key, &cert_pem, json!(4)).await;
    let after = CertificateRepo::new()
        .get(&env.pool, certificate_id)
        .await
        .expect("read the certificate row after revoke")
        .expect("the certificate exists");

    // -- the second revoke: the idempotent no-op.
    let (again_status, again_body) = revoke(&env, key, &cert_pem, json!(4)).await;
    let after_again = CertificateRepo::new()
        .get(&env.pool, certificate_id)
        .await
        .expect("read the certificate row after the repeat")
        .expect("the certificate exists");
    let revoked_audits = audit_rows(&env, "cert_revoked").await;
    env.cleanup().await;

    assert_eq!(revoke_status, StatusCode::OK, "the revocation succeeds");
    assert_eq!(revoke_body, "", "the 200 body is empty (RFC 8555 §7.6)");
    assert_eq!(after.status, CertStatus::Revoked);
    assert_eq!(after.revocation_reason.as_deref(), Some("superseded"));
    assert_eq!(again_status, StatusCode::OK, "the repeat is idempotent");
    assert_eq!(again_body, "", "the repeat body is empty too");
    assert_eq!(
        after_again.status,
        CertStatus::Revoked,
        "the certificate stays revoked"
    );
    assert_eq!(
        after_again.revocation_reason.as_deref(),
        Some("superseded"),
        "the FIRST revoke's reason stands after the idempotent repeat"
    );
    assert_eq!(revoked_audits.len(), 1, "ONE cert_revoked audit row");
    assert_eq!(revoked_audits[0].0, "acme_account");
    assert_eq!(revoked_audits[0].1, "acme_account");
    assert_eq!(revoked_audits[0].3, certificate_id.to_string());
    assert_eq!(revoked_audits[0].4["reason"], "superseded");
}

/// Test 4: the renew-flavored reuse window, driven ORGANICALLY — order 1
/// issues all the way (its HTTP-01 settlement PROMOTED its order-scoped
/// authorization to account-level inside the settle transaction, fix
/// round 1), and the SECOND order on the SAME identifier reuses that row
/// with NO seeding at all: the order points at the EXISTING
/// authorization URL, nothing is minted for the identifier, and the
/// `acme_order_created` audit row credits `reused_authorization_count: 1`
/// with `minted_authorization_count: 0`.
///
/// (The SEEDED account-level variant stays in the ws-api suite as the
/// Task-6 regression pin for the LOOKUP itself; this test pins the LOOP:
/// settle → promotion → organic reuse.)
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn second_order_reuses_authorizations() {
    let _db = lock_db().await;
    let mut env = env().await;

    // order 1 issues all the way: enrollment, profile + CA seeding, the
    // HTTP-01 settlement (whose transaction promotes the row), finalize.
    let (order_id, root_pem) = issue_certificate(&mut env, "host.wardstone-e2e.test").await;
    let key = KeyFixture::rsa2048();

    // -- the second order through the front door. NO account-level row is
    //    seeded: the one it must reuse is the one order 1's own settlement
    //    promoted.
    let (second_order_id, second_body) = new_order(&env, key, "host.wardstone-e2e.test").await;

    // -- D5's renewal criterion as a RUN, not a pinned state: the ready
    //    renewal order finalizes with NO further challenge work and its
    //    certificate downloads.
    let (finalize_status, finalize_body) = finalize(
        &env,
        key,
        second_order_id,
        "host.wardstone-e2e.test",
        &["host.wardstone-e2e.test"],
    )
    .await;
    let (download_status, download_type, download_body) =
        download_certificate(&env, key, second_order_id).await;

    // -- DB captures, then the cleanup, THEN the assertions.
    let identifier_rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM acme_authorizations \
         WHERE tenant_id = $1 AND identifier = $2",
    )
    .bind(env.tenant_id)
    .bind("host.wardstone-e2e.test")
    .fetch_all(&env.pool)
    .await
    .expect("list the identifier's authorizations");
    let reused_id = identifier_rows
        .first()
        .copied()
        .expect("order 1's settled authorization exists")
        .0;
    let reuse_row = AcmeRepo::new()
        .get_authorization(&env.pool, env.tenant_id, reused_id)
        .await
        .expect("read the reused row")
        .expect("it exists");
    let challenge_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM acme_challenges WHERE tenant_id = $1 AND authorization_id = $2",
    )
    .bind(env.tenant_id)
    .bind(reused_id)
    .fetch_one(&env.pool)
    .await
    .expect("count the challenges");
    let order_one_row = AcmeRepo::new()
        .get_order(&env.pool, env.tenant_id, order_id)
        .await
        .expect("read order one")
        .expect("it exists");
    let order_one_certificate_id = order_one_row
        .certificate_id
        .expect("the first order issued its certificate");
    let second_order_row = AcmeRepo::new()
        .get_order(&env.pool, env.tenant_id, second_order_id)
        .await
        .expect("read the renewal order")
        .expect("it exists");
    let second_certificate_id = second_order_row
        .certificate_id
        .expect("the renewal order issued its certificate");
    let second_cert_row = CertificateRepo::new()
        .get(&env.pool, second_certificate_id)
        .await
        .expect("read the renewal certificate")
        .expect("it exists");
    let issued_audits = audit_rows(&env, "cert_issued").await;
    let created_audits = audit_rows(&env, "acme_order_created").await;
    env.cleanup().await;

    assert_eq!(
        identifier_rows.len(),
        1,
        "no second authorization was minted for the identifier"
    );
    assert_eq!(
        second_body["authorizations"],
        json!([authz_url(reused_id)]),
        "the SECOND order reuses the row the FIRST settlement promoted"
    );
    assert_eq!(
        second_body["status"], "ready",
        "the renewal order is ready BY CREATION: its every identifier \
         reused an already-valid authorization"
    );
    assert_ne!(second_order_id, order_id);
    assert!(
        reuse_row.order_id.is_none(),
        "the promoted row stays account-level (order_id NULL)"
    );
    assert_eq!(reuse_row.status, AcmeAuthorizationStatus::Valid);
    assert_eq!(
        challenge_count.0, 2,
        "no challenge rows for the renewal: only order 1's settled pair exists"
    );
    assert_eq!(
        order_one_row.status,
        AcmeOrderStatus::Valid,
        "the first order's issued state is untouched"
    );
    // the D5 run: the ready renewal finalizes with no further challenge
    // work and its certificate downloads.
    assert_eq!(second_order_row.status, AcmeOrderStatus::Valid);
    assert_eq!(
        finalize_status,
        StatusCode::OK,
        "the renewal finalizes: {finalize_body}"
    );
    assert_eq!(finalize_body["status"], "valid");
    assert_eq!(
        finalize_body["certificate"],
        json!(format!(
            "{PUBLIC_URL}/acme/{E2E_TENANT}/orders/{second_order_id}/certificate"
        ))
    );
    assert_eq!(
        download_status,
        StatusCode::OK,
        "the renewal's certificate URL serves: {download_body}"
    );
    assert_eq!(
        download_type.as_deref(),
        Some("application/pem-certificate-chain")
    );
    let leaf_at = download_body
        .find(&second_cert_row.cert_pem)
        .expect("the renewal's leaf PEM in the download body");
    let root_at = download_body
        .find(&root_pem)
        .expect("the root PEM in the download body");
    assert!(leaf_at < root_at, "the chain body is leaf-first");
    assert_eq!(second_cert_row.source, "acme");
    assert_eq!(second_cert_row.status, CertStatus::Active);
    assert_eq!(issued_audits.len(), 2, "both issuances audited");
    let audit_targets: Vec<&str> = issued_audits.iter().map(|row| row.3.as_str()).collect();
    assert!(
        audit_targets.contains(&order_one_certificate_id.to_string().as_str())
            && audit_targets.contains(&second_certificate_id.to_string().as_str()),
        "both certificates carry their cert_issued audit rows"
    );
    assert_eq!(created_audits.len(), 2, "both orders audited");
    assert_eq!(created_audits[1].4["reused_authorization_count"], 1);
    assert_eq!(created_audits[1].4["minted_authorization_count"], 0);
    assert_eq!(
        created_audits[0].4["reused_authorization_count"], 0,
        "the first order minted its own authorization"
    );
    assert_eq!(created_audits[0].4["minted_authorization_count"], 1);
}
