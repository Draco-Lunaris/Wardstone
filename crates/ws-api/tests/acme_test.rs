//! Integration tests for the ACME (RFC 8555) route surface (Plan-4
//! Tasks 5-7): directory, new-nonce, new-account (the ToS gate and
//! only-return-existing included), the account URL (POST-as-GET, update,
//! deactivation with its cascade), the atomic account-key rollover, and
//! the order machine — new-order (profile resolution, identifier
//! validation, the REUSE window), order and authorization POST-as-GET —
//! plus Task 7's synchronous challenge verification (HTTP-01 fetched
//! through a loopback stub over REAL reqwest at the canonical path,
//! DNS-01 resolved through a canned TXT resolver): the server computes
//! the expected answer from its own row and the account key, and no test
//! can feed it one (Review Focus 1).
//!
//! These tests run against a live Postgres and are marked `#[ignore]`.
//! Run them with:
//!
//! ```sh
//! DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test \
//!     cargo test -p ws-api --test acme_test -- --include-ignored
//! ```
//!
//! # Self-cleaning contract
//!
//! Every test sweeps ACME rows (FK-first) away under this suite's owned
//! tenant name before use and deletes every row it created BEFORE the
//! assertions run, so a failing assert cannot leave rows behind. All query
//! results are captured and unwrapped only after cleanup.
//!
//! # Cross-process serialization
//!
//! Each test body holds a session-level Postgres advisory lock for its
//! whole duration on the key [`ADVISORY_KEY`] — the "WARDST" family with
//! suite marker `0x0014` (CLAUDE.md's registry; 0003-0013 are taken).
//!
//! # The client side
//!
//! The tests BUILD the ACME requests with the `tests/acme_common` helpers:
//! openssl-minted keys and compact JWSs signed exactly as a real ACME
//! client signs (one fresh nonce per request, fetched from a previous
//! response's `Replay-Nonce`), so Task 4's verification floor — nonce
//! single-use, the `url` binding, alg-key pinning — is re-verified THROUGH
//! the HTTP layer, not just in its own crate.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, RwLock};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde_json::{json, Value};
use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex as TokioMutex;
use tower::ServiceExt;
use uuid::Uuid;

use ws_api::routes::acme::{ChallengeFetch, TxtResolver};
use ws_api::{AcmeConfig, ApiConfig, AppState, AuthRateLimit, VerificationDeps};
use ws_auth::jwt::JwtKeys;
use ws_ca::ca::{create_root, CaLifetime, CaSpec};
use ws_ca::keystore::KeyStore;
use ws_ca::KeyType;
use ws_core::db::connect;
use ws_core::models::acme::{
    AcmeAuthorizationModel, AcmeAuthorizationStatus, AcmeChallengeModel, AcmeChallengeStatus,
    AcmeChallengeType, AcmeOrderModel, AcmeOrderStatus,
};
use ws_core::models::ca::CaModel;
use ws_core::models::certificate::CertStatus;
use ws_core::models::profile::{ProfileModel, ProfileRevisionModel};
use ws_core::repo::acme_repo::AcmeRepo;
use ws_core::repo::ca_repo::CaRepo;
use ws_core::repo::certificate_repo::CertificateRepo;
use ws_core::repo::profile_repo::ProfileRepo;

use acme_common::{ed25519, p256, rsa2048, Identity, KeyFixture};

/// The client-side JWS builder fixtures (openssl keys + compact signers).
mod acme_common;

/// The response type the test helpers return.
type TestResponse = axum::http::Response<axum::body::Body>;

/// Postgres advisory-lock key for this suite: ASCII "WARDST" (0x5741445354)
/// plus the suite marker 0x0014.
const ADVISORY_KEY: i64 = 0x0057_4144_5354_0014;

/// The tenant name this suite owns; swept before use, deleted at the end.
const ACME_TENANT: &str = "rt-acme-tenant";

/// The public URL base the fixture configures (the test stand-in for
/// `WARDSTONE_PUBLIC_URL`): every absolute URL assertion derives from it.
const PUBLIC_URL: &str = "https://acme.wardstone.test";

/// The contact the fixture accounts offer.
const CONTACT: &str = "mailto:ops@wardstone.test";

/// In-process serialization, the api_test pattern (tests run on separate
/// threads; the advisory lock serializes across processes).
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
/// connection, exactly like the api_test suite.
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

/// A per-test fixture: the built router, the fixture tenant, and the held
/// advisory-lock connection.
struct Fixture {
    router: axum::Router,
    pool: PgPool,
    tenant_id: Uuid,
    #[allow(dead_code)] // held for the whole body: serializes this suite
    advisory: Option<PoolConnection<sqlx::Postgres>>,
    keys_dir: PathBuf,
}

impl Fixture {
    /// Delete every row this fixture (and the test body) created, then
    /// release the advisory lock. Runs BEFORE the assertions, so a failing
    /// assert can never leave rows behind (the self-cleaning contract).
    /// ACME children first (challenges → authorizations → orders →
    /// accounts), then Task 8's issuance children (certificates, serials),
    /// then the audit log, profiles, CAs, and the tenant.
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
                .expect("delete fixture rows");
        }
        if self.advisory.is_some() {
            let mut conn = self.advisory.take().expect("advisory connection held");
            release_advisory(&mut conn, ADVISORY_KEY).await;
        }
        let _ = std::fs::remove_dir_all(&self.keys_dir);
    }
}

/// The fixture's config shape: the ACME `tos_url`, the limiter config
/// (BOTH the new-account per-IP GCRA — through `auth_rate_limit` — and
/// the per-account bucket — through `AcmeConfig::acme_account_limit` —
/// ride the one value; they are decoupled knobs in production), and the
/// `public_url` (None = the unconfigured degrade posture) — plus
/// the challenge-verification seams a test may swap in (the stub fetcher
/// and/or the canned TXT resolver) before the router wraps the state.
#[derive(Default)]
struct FixtureConfig<'a> {
    tos_url: Option<&'a str>,
    rate_limit: Option<AuthRateLimit>,
    public_url: Option<&'a str>,
    verification: Option<VerificationDeps>,
}

/// Build the fixture: connect, take the advisory lock, sweep stale rows,
/// insert the tenant, and build the router. No user rows are needed: the
/// ACME surface authenticates with JWSes, never with bearers.
async fn fixture_with(config: FixtureConfig<'_>) -> Fixture {
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    // Sweep-first: stale rows of a previously crashed run under the owned
    // tenant name (FK-first).
    sweep_tenant(&pool, ACME_TENANT).await;

    let tenant_id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(tenant_id)
        .bind(ACME_TENANT)
        .execute(&pool)
        .await
        .expect("insert fixture tenant");
    // The ACME surface resolves the install's PRIMARY tenant — the OLDEST
    // created. Pin the fixture tenant's created_at to the epoch so it is
    // the oldest even if another suite left debris behind: the resolution
    // then stays deterministic whatever the shared test DB holds.
    sqlx::query("UPDATE tenants SET created_at = '1970-01-01 00:00:00+00' WHERE id = $1")
        .bind(tenant_id)
        .execute(&pool)
        .await
        .expect("pin the fixture tenant as the oldest");

    let keys_dir = std::env::temp_dir().join(format!(
        "ws-api-acme-test-keys-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    let mut keystore = ws_ca::keystore::KeyStore::open(&keys_dir).expect("open keystore");
    keystore.ensure_master_key().expect("ensure master key");
    ws_core::crypto::SecretBox::create(&keys_dir.join("secret-encryption.key"))
        .expect("create the secret-encryption key");
    let jwt = JwtKeys::load_or_create(&keys_dir).expect("load or create the JWT key pair");

    let mut api_config = ApiConfig::new("wardstone.test".to_string(), keys_dir.clone());
    api_config.acme = AcmeConfig {
        public_url: config.public_url.unwrap_or_default().to_string(),
        tos_url: config.tos_url.map(str::to_string),
        // The per-account bucket rides its OWN knob (decoupled from the
        // auth disable); the fixture drives BOTH limiters with the one
        // config value a test names.
        acme_account_limit: config.rate_limit,
    };
    api_config.auth_rate_limit = config.rate_limit;
    let mut state = AppState::new(pool.clone(), std::sync::Arc::new(jwt), api_config);
    // The challenge-verification seams a test swaps in BEFORE the router
    // wraps the state (the router clones it — a later mutation would not
    // reach it).
    if let Some(verification) = config.verification {
        state.verification = verification;
    }
    let router = ws_api::router(state.clone());

    Fixture {
        router,
        pool,
        tenant_id,
        advisory: Some(advisory),
        keys_dir,
    }
}

/// The standard fixture: the configured public URL, no ToS, no limiter.
async fn fixture() -> Fixture {
    fixture_with(FixtureConfig {
        public_url: Some(PUBLIC_URL),
        ..FixtureConfig::default()
    })
    .await
}

/// Delete every row a previous run may have left under `name` (children
/// first, then the tenant — Task 8's issuance children included,
/// certificates before the CAs their rows reference).
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
            .expect("sweep stale fixture-prefixed rows");
    }
}

/// Send a request to the fixture router and return the response.
async fn send(fixture: &Fixture, request: Request<Body>) -> TestResponse {
    fixture
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("the router should respond")
}

/// An ACME POST: the JWS compact serialization as
/// `application/jose+json` body.
fn acme_post(uri: &str, jws: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/jose+json")
        .body(Body::from(jws.to_owned()))
        .expect("build the ACME POST")
}

/// A plain GET (directory, nonce endpoint).
fn plain_get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("build the GET")
}

/// A HEAD (the nonce endpoint's bodyless twin).
fn plain_head(uri: &str) -> Request<Body> {
    Request::builder()
        .method("HEAD")
        .uri(uri)
        .body(Body::empty())
        .expect("build the HEAD")
}

/// Inject the `ConnectInfo` the per-IP GCRA's `PeerIpKeyExtractor` reads —
/// the ui_rate_limit_test pattern (the real listener fills the same
/// extension per connection).
fn with_peer(request: Request<Body>, ip: Ipv4Addr, port: u16) -> Request<Body> {
    let mut request = request;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(IpAddr::from(ip), port)));
    request
}

/// Read the response body as text (test-only unwrappers, after cleanup the
/// assertions run).
async fn body_text(response: TestResponse) -> String {
    let bytes = to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read the response body");
    String::from_utf8(bytes.to_vec()).expect("the body is UTF-8")
}

/// Read the response body as JSON.
async fn body_json(response: TestResponse) -> Value {
    let text = body_text(response).await;
    serde_json::from_str(&text).expect("the body is JSON")
}

/// The fresh `Replay-Nonce` every /acme response carries.
fn nonce_of(response: &TestResponse) -> String {
    response
        .headers()
        .get("replay-nonce")
        .expect("every /acme response carries a Replay-Nonce")
        .to_str()
        .expect("the nonce is ASCII")
        .to_owned()
}

/// Fetch a nonce the way a client does: GET the nonce endpoint and read
/// the response header.
async fn fetch_nonce(fixture: &Fixture) -> String {
    let response = send(fixture, plain_get("/acme/new-nonce")).await;
    nonce_of(&response)
}

/// The client-side thumbprint of a fixture key.
fn thumb_of(key: &KeyFixture) -> String {
    ws_acme::thumbprint(&key.jwk).expect("the fixture key is a thumbprintable JWK")
}

/// An account URL (the FULL RFC 7638 thumbprint as the last segment).
fn account_url(thumbprint: &str) -> String {
    format!("{PUBLIC_URL}/acme/{ACME_TENANT}/acct/{thumbprint}")
}

/// POST a new-account request for `key` (agreed, with contact); returns
/// the account's thumbprint and the response.
async fn create_account(fixture: &Fixture, key: &KeyFixture) -> (String, TestResponse) {
    let thumb = thumb_of(key);
    let nonce = fetch_nonce(fixture).await;
    let jws = acme_common::sign_acme_request(
        key,
        &Identity::Jwk,
        &nonce,
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/new-account"),
        &json!({"termsOfServiceAgreed": true, "contact": [CONTACT]}),
    );
    let response = send(
        fixture,
        acme_post(&format!("/acme/{ACME_TENANT}/new-account"), &jws),
    )
    .await;
    (thumb, response)
}

/// A kid-signed POST-as-GET (the empty payload) to an account URL.
async fn post_as_get(fixture: &Fixture, key: &KeyFixture, thumbprint: &str) -> TestResponse {
    let account = account_url(thumbprint);
    let nonce = fetch_nonce(fixture).await;
    let jws = acme_common::sign_acme_request(
        key,
        &Identity::Kid(account.clone()),
        &nonce,
        &account,
        &Value::Null,
    );
    send(
        fixture,
        acme_post(&format!("/acme/{ACME_TENANT}/acct/{thumbprint}"), &jws),
    )
    .await
}

/// The ACME audit rows for `action` under the fixture tenant: (actor_type,
/// auth_method, actor_id, target_id, details) — captured AFTER cleanup has
/// a chance to run (call it before the asserts, discard nothing).
async fn audit_rows(
    fixture: &Fixture,
    action: &str,
) -> Vec<(String, String, String, String, Value)> {
    sqlx::query_as(
        "SELECT actor_type, auth_method, actor_id, target_id, details FROM audit_log \
         WHERE tenant_id = $1 AND action = $2 ORDER BY created_at",
    )
    .bind(fixture.tenant_id)
    .bind(action)
    .fetch_all(&fixture.pool)
    .await
    .expect("read the audit rows")
}

// ---------------------------------------------------------------------------
// Directory and nonce endpoint
// ---------------------------------------------------------------------------

/// The directory: absolute URLs derived from the CONFIGURED public_url +
/// tenant (never a Host header), no `newAuthz` in v1, and a fresh
/// Replay-Nonce on the response.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn directory_offers_absolute_urls_from_the_configured_public_url() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let response = send(&fx, plain_get(&format!("/acme/{ACME_TENANT}/directory"))).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get("replay-nonce").is_some(),
        "the directory carries a fresh Replay-Nonce"
    );
    assert!(
        response.headers().get("link").is_none(),
        "no ToS is configured: no terms-of-service Link"
    );
    let directory = body_json(response).await;
    assert_eq!(
        directory["newNonce"],
        json!(format!("{PUBLIC_URL}/acme/new-nonce"))
    );
    assert_eq!(
        directory["newAccount"],
        json!(format!("{PUBLIC_URL}/acme/{ACME_TENANT}/new-account"))
    );
    assert_eq!(
        directory["newOrder"],
        json!(format!("{PUBLIC_URL}/acme/{ACME_TENANT}/new-order"))
    );
    assert_eq!(
        directory["revokeCert"],
        json!(format!("{PUBLIC_URL}/acme/{ACME_TENANT}/revoke-cert"))
    );
    assert_eq!(
        directory["keyChange"],
        json!(format!("{PUBLIC_URL}/acme/{ACME_TENANT}/key-change"))
    );
    assert!(
        directory.get("newAuthz").is_none(),
        "pre-authorization is not offered in v1"
    );

    fx.cleanup().await;
}

/// The unconfigured-public-URL degradation: a blank `WARDSTONE_PUBLIC_URL`
/// boots, but the directory answers the `serverInternal` problem document
/// (with its fresh Replay-Nonce — and a loud boot warning the binary logs).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn directory_degrades_to_server_internal_without_a_public_url() {
    let _db = lock_db().await;
    let mut fx = fixture_with(FixtureConfig::default()).await;

    let response = send(&fx, plain_get(&format!("/acme/{ACME_TENANT}/directory"))).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("content type")
            .to_str()
            .expect("ascii"),
        "application/problem+json"
    );
    assert!(
        response.headers().get("replay-nonce").is_some(),
        "even the degraded answer carries a fresh Replay-Nonce"
    );
    let problem = body_json(response).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:serverInternal");
    assert_eq!(problem["status"], 500);

    fx.cleanup().await;
}

/// With a ToS configured, the directory carries the
/// `Link: <tos>;rel="terms-of-service"` header.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn directory_carrys_the_tos_link_when_configured() {
    let _db = lock_db().await;
    let mut fx = fixture_with(FixtureConfig {
        public_url: Some(PUBLIC_URL),
        tos_url: Some("https://acme.wardstone.test/terms"),
        ..FixtureConfig::default()
    })
    .await;

    let response = send(&fx, plain_get(&format!("/acme/{ACME_TENANT}/directory"))).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::LINK)
            .expect("the ToS Link header")
            .to_str()
            .expect("ascii"),
        "<https://acme.wardstone.test/terms>;rel=\"terms-of-service\""
    );

    fx.cleanup().await;
}

/// The nonce endpoint: 204, no body, a fresh Replay-Nonce,
/// `Cache-Control: no-store`; HEAD responds bodyless under the same terms;
/// successive fetches mint DIFFERENT nonces.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn new_nonce_answers_204_with_a_fresh_nonce_and_no_store() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let response = send(&fx, plain_get("/acme/new-nonce")).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .expect("cache control")
            .to_str()
            .expect("ascii"),
        "no-store"
    );
    let first = nonce_of(&response);
    assert!(!first.is_empty());
    assert!(body_text(response).await.is_empty(), "204 has no body");

    let head = send(&fx, plain_head("/acme/new-nonce")).await;
    assert_eq!(head.status(), StatusCode::NO_CONTENT, "HEAD shares the GET");
    let second = nonce_of(&head);
    assert_ne!(first, second, "every response mints a fresh nonce");

    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// new-account
// ---------------------------------------------------------------------------

/// The happy enrollment: 201, the `Location` under the FULL RFC 7638
/// thumbprint, the valid account object with contact and orders URL, the
/// DB row, and the `acme_account_created` audit row in the spec's pinned
/// AcmeAccount actor shape.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn new_account_mints_a_valid_account_with_location_and_audit_row() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let (thumb, response) = create_account(&fx, rsa2048()).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .expect("location")
            .to_str()
            .expect("ascii"),
        account_url(&thumb)
    );
    let account = body_json(response).await;
    assert_eq!(account["status"], "valid");
    assert_eq!(account["contact"], json!([CONTACT]));
    assert_eq!(
        account["orders"],
        json!(format!(
            "{PUBLIC_URL}/acme/{ACME_TENANT}/acct/{thumb}/orders"
        ))
    );

    // The DB row: valid, contact stored.
    let row = AcmeRepo::new()
        .get_account(&fx.pool, fx.tenant_id, &thumb)
        .await
        .expect("read the account row")
        .expect("the account exists");
    assert_eq!(row.jwk_thumbprint, thumb);
    assert_eq!(row.status.to_string(), "valid");
    assert_eq!(row.contact.as_deref(), Some(CONTACT));

    // The audit row: the ACCOUNT is the actor.
    let created = audit_rows(&fx, "acme_account_created").await;
    fx.cleanup().await;
    assert_eq!(created.len(), 1, "exactly one creation audit row");
    let (actor_type, auth_method, actor_id, target_id, details) = &created[0];
    assert_eq!(actor_type, "acme_account");
    assert_eq!(auth_method, "acme_account");
    assert_eq!(actor_id, &account_url(&thumb));
    assert_eq!(target_id, &row.id.to_string());
    assert_eq!(details["jwk_thumbprint"], thumb);
    assert_eq!(details["status"], "valid");
}

/// Idempotency: a repeat `new-account` for the SAME key returns the SAME
/// account (200 with the existing Location) and applies any offered
/// contact change — under the update audit vocabulary.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn new_account_returns_the_existing_account_and_applies_changes() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let (thumb, first) = create_account(&fx, rsa2048()).await;
    assert_eq!(first.status(), StatusCode::CREATED);

    // A repeat with a DIFFERENT contact: 200, same location, contact
    // updated.
    let nonce = fetch_nonce(&fx).await;
    let jws = acme_common::sign_acme_request(
        rsa2048(),
        &Identity::Jwk,
        &nonce,
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/new-account"),
        &json!({"termsOfServiceAgreed": true, "contact": ["mailto:new@wardstone.test"]}),
    );
    let second = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/new-account"), &jws),
    )
    .await;
    assert_eq!(second.status(), StatusCode::OK, "existing → 200, not 201");
    assert_eq!(
        second
            .headers()
            .get(header::LOCATION)
            .expect("location")
            .to_str()
            .expect("ascii"),
        account_url(&thumb),
        "the SAME account comes back"
    );
    let body = body_json(second).await;
    assert_eq!(body["contact"], json!(["mailto:new@wardstone.test"]));

    let created = audit_rows(&fx, "acme_account_created").await;
    let updated = audit_rows(&fx, "acme_account_updated").await;
    fx.cleanup().await;
    assert_eq!(created.len(), 1, "no second creation");
    assert_eq!(updated.len(), 1, "the contact change is one update row");
}

/// `onlyReturnExisting`: a probe for an existing key returns its account
/// (200); a probe for an unknown key gets the RFC's 404
/// `accountDoesNotExist` problem document.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn only_return_existing_answers_the_existing_account_or_account_does_not_exist() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let (thumb, created) = create_account(&fx, rsa2048()).await;
    assert_eq!(created.status(), StatusCode::CREATED);

    let nonce = fetch_nonce(&fx).await;
    let jws = acme_common::sign_acme_request(
        rsa2048(),
        &Identity::Jwk,
        &nonce,
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/new-account"),
        &json!({"onlyReturnExisting": true}),
    );
    let probe = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/new-account"), &jws),
    )
    .await;
    assert_eq!(probe.status(), StatusCode::OK);
    assert_eq!(
        probe
            .headers()
            .get(header::LOCATION)
            .expect("location")
            .to_str()
            .expect("ascii"),
        account_url(&thumb)
    );

    // The unknown-key half: a DIFFERENT fixture key.
    let nonce = fetch_nonce(&fx).await;
    let jws = acme_common::sign_acme_request(
        p256(),
        &Identity::Jwk,
        &nonce,
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/new-account"),
        &json!({"onlyReturnExisting": true}),
    );
    let missing = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/new-account"), &jws),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        missing
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("content type")
            .to_str()
            .expect("ascii"),
        "application/problem+json"
    );
    let problem = body_json(missing).await;
    assert_eq!(
        problem["type"],
        "urn:ietf:params:acme:error:accountDoesNotExist"
    );
    assert_eq!(problem["status"], 404);

    fx.cleanup().await;
}

/// The ToS gate (spec settlement 9): with a ToS published and the client
/// not agreeing, the account is minted `pending` and the answer is a 403
/// `userActionRequired` problem carrying the ToS Link and the minted
/// account's Location; agreeing (a repeat new-account with
/// `termsOfServiceAgreed`) promotes it to `valid` and stamps
/// `tos_agreed_at`.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn tos_is_enforced_when_a_tos_url_is_configured() {
    let _db = lock_db().await;
    let mut fx = fixture_with(FixtureConfig {
        public_url: Some(PUBLIC_URL),
        tos_url: Some("https://acme.wardstone.test/terms"),
        ..FixtureConfig::default()
    })
    .await;

    let signed_out = sign_without_agreement(&fx, rsa2048()).await;
    assert_eq!(signed_out.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        signed_out
            .headers()
            .get(header::LINK)
            .expect("the ToS Link on the problem")
            .to_str()
            .expect("ascii"),
        "<https://acme.wardstone.test/terms>;rel=\"terms-of-service\""
    );
    let pending_url = signed_out
        .headers()
        .get(header::LOCATION)
        .expect("the pending account's location")
        .to_str()
        .expect("ascii")
        .to_owned();
    let problem = body_json(signed_out).await;
    assert_eq!(
        problem["type"],
        "urn:ietf:params:acme:error:userActionRequired"
    );
    assert_eq!(problem["status"], 403);

    // The account exists — but pending, and agreeing later with a ToS
    // stamp.
    let thumb = thumb_of(rsa2048());
    let pending = AcmeRepo::new()
        .get_account(&fx.pool, fx.tenant_id, &thumb)
        .await
        .expect("read the pending account")
        .expect("it was minted");
    assert_eq!(pending.status.to_string(), "pending");
    assert!(pending.tos_agreed_at.is_none());
    assert_eq!(pending_url, account_url(&thumb));

    // Agreement: a repeat new-account with the flag set — 200 with the
    // SAME account, now valid.
    let agreed = send(
        &fx,
        acme_post(
            &format!("/acme/{ACME_TENANT}/new-account"),
            &signed_account_jws(&fx, rsa2048(), true).await,
        ),
    )
    .await;
    assert_eq!(agreed.status(), StatusCode::OK, "existing → 200");
    let body = body_json(agreed).await;
    assert_eq!(body["status"], "valid");
    let promoted = AcmeRepo::new()
        .get_account(&fx.pool, fx.tenant_id, &thumb)
        .await
        .expect("read the promoted account")
        .expect("it exists");
    assert_eq!(promoted.status.to_string(), "valid");
    assert!(promoted.tos_agreed_at.is_some(), "the agreement is stamped");

    let created = audit_rows(&fx, "acme_account_created").await;
    let updated = audit_rows(&fx, "acme_account_updated").await;
    fx.cleanup().await;
    assert_eq!(created.len(), 1, "the pending mint is the one creation");
    assert_eq!(updated.len(), 1, "the promotion is one update row");
}

/// A jwk+kid pair in one protected header is refused at the new-account
/// boundary (the Review-Focus-3 trap, re-verified through the HTTP
/// layer), and so is a kid-only new-account request (the key must be
/// EMBEDDED).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn new_account_rejects_kid_identifiers() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let new_account_url = format!("{PUBLIC_URL}/acme/{ACME_TENANT}/new-account");

    // kid + jwk together.
    let nonce = fetch_nonce(&fx).await;
    let header = json!({
        "alg": rsa2048().alg_name,
        "kid": account_url("AAAATrapTrapTrapTrapTrapTrapTrapTrapTrapTrapTrap"),
        "jwk": rsa2048().jwk,
        "nonce": nonce,
        "url": new_account_url,
    });
    let jws = acme_common::sign_with_header(rsa2048(), &header, &json!({}));
    let both = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/new-account"), &jws),
    )
    .await;
    assert_eq!(both.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(both).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:malformed");

    // kid-only: the key must be embedded on new-account.
    let nonce = fetch_nonce(&fx).await;
    let kid_only = acme_common::sign_acme_request(
        rsa2048(),
        &Identity::Kid(account_url(&thumb_of(rsa2048()))),
        &nonce,
        &new_account_url,
        &json!({}),
    );
    let response = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/new-account"), &kid_only),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(response).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:malformed");

    fx.cleanup().await;
}

/// A kid URL that resolves to NO account in THIS tenant is the RFC's 404
/// `accountDoesNotExist` lookup failure — never a cross-tenant account,
/// never a 500.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn an_unresolvable_kid_answers_account_does_not_exist() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    // A well-formed tenant-local URL naming a thumbprint that exists
    // NOWHERE. (The ghost string is not a real key — it only needs to sit
    // where a thumbprint would, so the parse succeeds and the LOOKUP
    // misses.)
    let ghost = account_url("GHOSTGHOSTGHOSTGHOSTGHOSTGHOSTGHOSTGHOSTGHOSTGHO");
    let nonce = fetch_nonce(&fx).await;
    let jws = acme_common::sign_acme_request(
        ed25519(),
        &Identity::Kid(ghost),
        &nonce,
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/acct/does-not-matter"),
        &Value::Null,
    );
    let response = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/acct/does-not-matter"), &jws),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let problem = body_json(response).await;
    assert_eq!(
        problem["type"],
        "urn:ietf:params:acme:error:accountDoesNotExist"
    );

    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// The account URL: POST-as-GET, update, deactivation
// ---------------------------------------------------------------------------

/// POST-as-GET (the empty payload) reads the account: 200 with the object
/// and the account's Location.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn post_as_get_returns_the_account_object() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let (thumb, created) = create_account(&fx, rsa2048()).await;
    assert_eq!(created.status(), StatusCode::CREATED);

    let read = post_as_get(&fx, rsa2048(), &thumb).await;
    assert_eq!(read.status(), StatusCode::OK);
    assert_eq!(
        read.headers()
            .get(header::LOCATION)
            .expect("location")
            .to_str()
            .expect("ascii"),
        account_url(&thumb)
    );
    let body = body_json(read).await;
    assert_eq!(body["status"], "valid");
    assert_eq!(body["contact"], json!([CONTACT]));
    assert_eq!(
        body["orders"],
        json!(format!(
            "{PUBLIC_URL}/acme/{ACME_TENANT}/acct/{thumb}/orders"
        ))
    );

    fx.cleanup().await;
}

/// The `contact` update: an offered array stores the first URI (v1's
/// single stored value), an empty array clears it, and each actual change
/// lands one `acme_account_updated` audit row.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn account_update_applies_contact_changes_with_an_audit_row() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let (thumb, created) = create_account(&fx, rsa2048()).await;
    assert_eq!(created.status(), StatusCode::CREATED);

    // Set a new contact.
    let nonce = fetch_nonce(&fx).await;
    let account = account_url(&thumb);
    let jws = acme_common::sign_acme_request(
        rsa2048(),
        &Identity::Kid(account.clone()),
        &nonce,
        &account,
        &json!({"contact": ["mailto:new@wardstone.test"]}),
    );
    let updated = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/acct/{thumb}"), &jws),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::OK);
    assert_eq!(
        body_json(updated).await["contact"],
        json!(["mailto:new@wardstone.test"])
    );

    // Clear it with an empty array.
    let nonce = fetch_nonce(&fx).await;
    let jws = acme_common::sign_acme_request(
        rsa2048(),
        &Identity::Kid(account.clone()),
        &nonce,
        &account,
        &json!({"contact": []}),
    );
    let cleared = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/acct/{thumb}"), &jws),
    )
    .await;
    assert_eq!(cleared.status(), StatusCode::OK);
    assert_eq!(body_json(cleared).await["contact"], json!([]));
    let row = AcmeRepo::new()
        .get_account(&fx.pool, fx.tenant_id, &thumb)
        .await
        .expect("read the row")
        .expect("exists");
    assert_eq!(
        row.contact, None,
        "an empty contact array clears the stored value"
    );

    let updates = audit_rows(&fx, "acme_account_updated").await;
    fx.cleanup().await;
    assert_eq!(updates.len(), 2, "two real changes, two audit rows");
}

/// The deactivation cascade (spec settlement 9): `status: "deactivated"`
/// sets the account state AND invalidates its PENDING authorizations and
/// OPEN orders — already-decided authorizations stay as they are — and
/// the audit row carries the cascade counts.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn deactivation_cascades_to_pending_authorizations_and_open_orders() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let (thumb, created) = create_account(&fx, rsa2048()).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let account = AcmeRepo::new()
        .get_account(&fx.pool, fx.tenant_id, &thumb)
        .await
        .expect("read the account")
        .expect("exists");

    // Seed: one PENDING and one VALID authorization, one PENDING order —
    // directly through the Task-2 repo (in-fixture pre-authorizations).
    let now = chrono::Utc::now();
    let order = AcmeOrderModel {
        id: Uuid::new_v4(),
        tenant_id: fx.tenant_id,
        account_id: account.id,
        status: AcmeOrderStatus::Pending,
        profile_name: "web-server".to_owned(),
        identifiers: json!([{"type": "dns", "value": "host.wardstone.test"}]),
        csr_pem: None,
        not_before: None,
        not_after: None,
        certificate_id: None,
        error: None,
        expires_at: now + chrono::Duration::days(7),
        created_at: now,
    };
    AcmeRepo::new()
        .insert_order(&fx.pool, &order)
        .await
        .expect("seed the order");
    let pending_authz = AcmeAuthorizationModel {
        id: Uuid::new_v4(),
        tenant_id: fx.tenant_id,
        account_id: account.id,
        identifier: "host.wardstone.test".to_owned(),
        status: AcmeAuthorizationStatus::Pending,
        expires_at: now + chrono::Duration::days(30),
        reused_from: None,
        order_id: Some(order.id),
        created_at: now,
    };
    AcmeRepo::new()
        .insert_authorization(&fx.pool, &pending_authz)
        .await
        .expect("seed the pending authz");
    let valid_authz = AcmeAuthorizationModel {
        id: Uuid::new_v4(),
        tenant_id: fx.tenant_id,
        account_id: account.id,
        identifier: "valid.wardstone.test".to_owned(),
        status: AcmeAuthorizationStatus::Valid,
        expires_at: now + chrono::Duration::days(30),
        reused_from: None,
        order_id: None,
        created_at: now,
    };
    AcmeRepo::new()
        .insert_authorization(&fx.pool, &valid_authz)
        .await
        .expect("seed the valid authz");

    // Deactivate through the account URL.
    let nonce = fetch_nonce(&fx).await;
    let account_url_str = account_url(&thumb);
    let jws = acme_common::sign_acme_request(
        rsa2048(),
        &Identity::Kid(account_url_str.clone()),
        &nonce,
        &account_url_str,
        &json!({"status": "deactivated"}),
    );
    let response = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/acct/{thumb}"), &jws),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["status"], "deactivated");

    // The cascade, read back (rows captured BEFORE the asserts).
    let pending_after: Option<(String,)> =
        sqlx::query_as("SELECT status FROM acme_authorizations WHERE id = $1")
            .bind(pending_authz.id)
            .fetch_optional(&fx.pool)
            .await
            .expect("read the pending authz");
    let valid_after: Option<(String,)> =
        sqlx::query_as("SELECT status FROM acme_authorizations WHERE id = $1")
            .bind(valid_authz.id)
            .fetch_optional(&fx.pool)
            .await
            .expect("read the valid authz");
    let order_after: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT status, error FROM acme_orders WHERE id = $1")
            .bind(order.id)
            .fetch_optional(&fx.pool)
            .await
            .expect("read the order");
    let deactivated = audit_rows(&fx, "acme_account_deactivated").await;
    fx.cleanup().await;

    assert_eq!(
        pending_after.expect("pending row").0,
        "deactivated",
        "a PENDING authorization is invalidated"
    );
    assert_eq!(
        valid_after.expect("valid row").0,
        "valid",
        "an already-VALID authorization is untouched"
    );
    let order_after = order_after.expect("order row");
    assert_eq!(order_after.0, "invalid", "an OPEN order is invalidated");
    assert_eq!(order_after.1.as_deref(), Some("account deactivated"));

    assert_eq!(deactivated.len(), 1);
    let (_, _, actor_id, _, details) = &deactivated[0];
    assert_eq!(actor_id, &account_url_str);
    assert_eq!(details["authorizations_invalidated"], 1);
    assert_eq!(details["orders_invalidated"], 1);
}

/// Deactivation is a one-way gate: further mutations are refused with the
/// 401 `unauthorized` problem, while POST-as-GET stays readable (the
/// client must be able to see the state it landed in).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn a_deactivated_account_refuses_mutations_but_stays_readable() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let (thumb, created) = create_account(&fx, rsa2048()).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let account_url_str = account_url(&thumb);

    // Deactivate.
    let nonce = fetch_nonce(&fx).await;
    let jws = acme_common::sign_acme_request(
        rsa2048(),
        &Identity::Kid(account_url_str.clone()),
        &nonce,
        &account_url_str,
        &json!({"status": "deactivated"}),
    );
    let response = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/acct/{thumb}"), &jws),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Still readable.
    let read = post_as_get(&fx, rsa2048(), &thumb).await;
    assert_eq!(read.status(), StatusCode::OK);
    assert_eq!(body_json(read).await["status"], "deactivated");

    // A contact change is refused.
    let nonce = fetch_nonce(&fx).await;
    let jws = acme_common::sign_acme_request(
        rsa2048(),
        &Identity::Kid(account_url_str.clone()),
        &nonce,
        &account_url_str,
        &json!({"contact": [CONTACT]}),
    );
    let refused = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/acct/{thumb}"), &jws),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    let problem = body_json(refused).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:unauthorized");

    // And the key cannot re-register through new-account either.
    let nonce = fetch_nonce(&fx).await;
    let jws = acme_common::sign_acme_request(
        rsa2048(),
        &Identity::Jwk,
        &nonce,
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/new-account"),
        &json!({"termsOfServiceAgreed": true}),
    );
    let reregister = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/new-account"), &jws),
    )
    .await;
    assert_eq!(reregister.status(), StatusCode::UNAUTHORIZED);

    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// Account-key rollover
// ---------------------------------------------------------------------------

/// The §7.3.5 roll: the OUTER JWS is signed by the OLD key (kid = the
/// account URL) with a fresh nonce, wrapping the INNER JWS — signed by
/// the NEW key (its `jwk` embedded), SAME url, nonce OMITTED — whose
/// payload is `{"account", "oldKey"}`. 200 with the NEW Location, ONE row
/// (the row id survives, so order linkage survives), the audit row, the
/// old kid DEAD, the new kid live.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn key_change_rolls_the_account_key_in_a_single_transaction() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let (old_thumb, created) = create_account(&fx, rsa2048()).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let old_account = AcmeRepo::new()
        .get_account(&fx.pool, fx.tenant_id, &old_thumb)
        .await
        .expect("read the account")
        .expect("exists");

    let new_thumb = thumb_of(p256());
    assert_ne!(old_thumb, new_thumb);
    let old_url = account_url(&old_thumb);
    let new_url = account_url(&new_thumb);
    let key_change_url = format!("{PUBLIC_URL}/acme/{ACME_TENANT}/key-change");

    // The INNER JWS: signed by the NEW key with its `jwk` embedded, the
    // SAME url as the outer, and NO nonce member (RFC 8555 §7.3.5 — the
    // outer envelope is the request the nonce disciplines), over
    // {"account": url, "oldKey": the OLD key's JWK}.
    let inner = acme_common::sign_with_header(
        p256(),
        &json!({"alg": p256().alg_name, "jwk": p256().jwk, "url": key_change_url}),
        &json!({"account": old_url, "oldKey": rsa2048().jwk}),
    );
    // The OUTER JWS: signed by the OLD key as that account's kid, with a
    // fresh nonce, over the inner JWS in flattened JSON serialization.
    let outer_nonce = fetch_nonce(&fx).await;
    let outer = acme_common::sign_acme_request(
        rsa2048(),
        &Identity::Kid(old_url.clone()),
        &outer_nonce,
        &key_change_url,
        &acme_common::inner_jws_object(&inner),
    );

    // The wire shape, decoded from the bytes POSTed: the outer carries the
    // kid + the nonce; the inner embeds the NEW key and carries NO kid and
    // NO nonce.
    let decode_b64 = |segment: &str| {
        String::from_utf8(
            URL_SAFE_NO_PAD
                .decode(segment)
                .expect("the segment is unpadded base64url"),
        )
        .expect("the segment is UTF-8")
    };
    let outer_header: Value = serde_json::from_str(&decode_b64(
        outer
            .split('.')
            .next()
            .expect("the outer's protected segment"),
    ))
    .expect("the outer's protected header is JSON");
    assert_eq!(
        outer_header["kid"],
        json!(old_url),
        "the outer is kid-carried by the OLD account URL"
    );
    assert!(
        outer_header.get("nonce").is_some(),
        "the outer envelope is the one that carries the anti-replay nonce"
    );
    let outer_payload: Value = serde_json::from_str(&decode_b64(
        outer
            .split('.')
            .nth(1)
            .expect("the outer's payload segment"),
    ))
    .expect("the outer's payload is JSON");
    assert!(
        outer_payload.get("protected").is_some()
            && outer_payload.get("payload").is_some()
            && outer_payload.get("signature").is_some(),
        "the outer wraps the inner JWS as a flattened JSON serialization"
    );
    let inner_header: Value = serde_json::from_str(&decode_b64(
        outer_payload["protected"]
            .as_str()
            .expect("the inner's protected"),
    ))
    .expect("the inner's protected header is JSON");
    assert!(
        inner_header.get("kid").is_none(),
        "the inner MUST NOT carry a kid: it embeds its key"
    );
    assert_eq!(
        inner_header["jwk"],
        p256().jwk,
        "the inner embeds the NEW key"
    );
    assert!(
        inner_header.get("nonce").is_none(),
        "RFC 8555 §7.3.5: the inner JWS omits the nonce"
    );
    let response = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/key-change"), &outer),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .expect("location")
            .to_str()
            .expect("ascii"),
        new_url,
        "the NEW account location comes back"
    );

    // ONE row: the id survives (order linkage preserved), the thumbprint
    // swapped.
    let rolled = AcmeRepo::new()
        .get_account_by_id(&fx.pool, fx.tenant_id, old_account.id)
        .await
        .expect("read the account")
        .expect("the SAME row");
    assert_eq!(rolled.jwk_thumbprint, new_thumb);

    // The old kid is now a lookup failure.
    let old_read = post_as_get(&fx, rsa2048(), &old_thumb).await;
    assert_eq!(
        old_read.status(),
        StatusCode::NOT_FOUND,
        "the old kid is dead"
    );
    let problem = body_json(old_read).await;
    assert_eq!(
        problem["type"],
        "urn:ietf:params:acme:error:accountDoesNotExist"
    );
    // The new kid works.
    let new_read = post_as_get(&fx, p256(), &new_thumb).await;
    assert_eq!(new_read.status(), StatusCode::OK);
    assert_eq!(body_json(new_read).await["status"], "valid");

    let changed = audit_rows(&fx, "acme_account_key_changed").await;
    fx.cleanup().await;
    assert_eq!(changed.len(), 1);
    let (_, _, actor_id, target_id, details) = &changed[0];
    assert_eq!(
        actor_id, &new_url,
        "the actor is the account at its NEW url"
    );
    assert_eq!(target_id, &rolled.id.to_string());
    assert_eq!(details["previous_thumbprint"], old_thumb);
    assert_eq!(details["new_thumbprint"], new_thumb);
}

// ---------------------------------------------------------------------------
// Nonce discipline through the HTTP layer (Review Focus 2)
// ---------------------------------------------------------------------------

/// A spent nonce fails its replay EVEN after a successful request: the
/// second presentation — however valid the new JWS on top — is the 400
/// `badNonce` the client retries from, with a fresh Replay-Nonce to
/// retry from.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn a_spent_nonce_fails_its_replay() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let new_account_url = format!("{PUBLIC_URL}/acme/{ACME_TENANT}/new-account");

    // Spend the nonce on a legitimate request.
    let nonce = fetch_nonce(&fx).await;
    let first = acme_common::sign_acme_request(
        rsa2048(),
        &Identity::Jwk,
        &nonce,
        &new_account_url,
        &json!({"termsOfServiceAgreed": true}),
    );
    let spent = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/new-account"), &first),
    )
    .await;
    assert_eq!(
        spent.status(),
        StatusCode::CREATED,
        "the first request succeeds"
    );

    // Re-present the SAME nonce under a DIFFERENT (perfectly valid) key.
    let replayed = acme_common::sign_acme_request(
        p256(),
        &Identity::Jwk,
        &nonce,
        &new_account_url,
        &json!({"termsOfServiceAgreed": true}),
    );
    let reply = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/new-account"), &replayed),
    )
    .await;
    assert_eq!(reply.status(), StatusCode::BAD_REQUEST);
    assert_ne!(
        nonce_of(&reply),
        nonce,
        "the refusal carries a FRESH nonce to retry from"
    );
    let problem = body_json(reply).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:badNonce");
    assert_eq!(problem["status"], 400);

    // And no second account was minted by the replay.
    let created = audit_rows(&fx, "acme_account_created").await;
    fx.cleanup().await;
    assert_eq!(created.len(), 1, "the replay created nothing");
}

/// Task 4's trap, re-verified through the HTTP layer: a nonce burns
/// BEFORE the signature verdict, so a request whose signature fails
/// cannot re-present its nonce even after the attacker fixes their own
/// signature.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn the_nonce_burns_irrespective_of_the_signature_verdict() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let new_account_url = format!("{PUBLIC_URL}/acme/{ACME_TENANT}/new-account");

    let nonce = fetch_nonce(&fx).await;
    let honest = acme_common::sign_acme_request(
        rsa2048(),
        &Identity::Jwk,
        &nonce,
        &new_account_url,
        &json!({"termsOfServiceAgreed": false}),
    );
    // Tamper the signature (still unpadded base64url) and send that: the
    // verdict is 401 unauthorized — but the nonce is SPENT.
    let tampered = acme_common::tamper_signature(&honest);
    let bad = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/new-account"), &tampered),
    )
    .await;
    assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
    let problem = body_json(bad).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:unauthorized");

    // The honest request with the SAME nonce is now a badNonce — the burn
    // happened before the signature verdict.
    let retry = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/new-account"), &honest),
    )
    .await;
    assert_eq!(
        retry.status(),
        StatusCode::BAD_REQUEST,
        "the same nonce is unusable after the failed verification"
    );
    let problem = body_json(retry).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:badNonce");

    fx.cleanup().await;
}

/// A protected header without a nonce member is the badNonce refusal —
/// there is nothing to spend, and nothing mutates.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn a_request_without_a_nonce_is_rejected() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let new_account_url = format!("{PUBLIC_URL}/acme/{ACME_TENANT}/new-account");

    let header = json!({
        "alg": rsa2048().alg_name,
        "jwk": rsa2048().jwk,
        "url": new_account_url,
    });
    let no_nonce = acme_common::sign_with_header(rsa2048(), &header, &json!({}));
    let response = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/new-account"), &no_nonce),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(response).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:badNonce");

    let created = audit_rows(&fx, "acme_account_created").await;
    fx.cleanup().await;
    assert!(created.is_empty(), "nothing mutated");
}

/// A JWS minted for one URL is malformed at another (the verifier's url
/// binding, through the HTTP layer).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn a_url_bound_for_another_endpoint_is_malformed() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    // Signed for the KEY-CHANGE url (or any other), POSTed to new-account.
    let nonce = fetch_nonce(&fx).await;
    let jws = acme_common::sign_acme_request(
        rsa2048(),
        &Identity::Jwk,
        &nonce,
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/key-change"),
        &json!({"termsOfServiceAgreed": true}),
    );
    let response = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/new-account"), &jws),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let problem = body_json(response).await;
    assert_eq!(problem["type"], "urn:ietf:params:acme:error:malformed");

    let created = audit_rows(&fx, "acme_account_created").await;
    fx.cleanup().await;
    assert!(created.is_empty(), "nothing mutated");
}

// ---------------------------------------------------------------------------
// Tenancy and rate limiting
// ---------------------------------------------------------------------------

/// The wrong tenant PATH segment is ONE 404 problem document ("unknown
/// ACME tenant") — never a cross-tenant read, whatever the body.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn mismatched_tenant_paths_are_unknown_acme_tenants() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    for uri in [
        "/acme/some-other-tenant/directory",
        "/acme/default/directory",
    ] {
        let response = send(&fx, plain_get(uri)).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .expect("content type")
                .to_str()
                .expect("ascii"),
            "application/problem+json"
        );
        let problem = body_json(response).await;
        assert_eq!(problem["type"], "urn:ietf:params:acme:error:malformed");
        assert_eq!(problem["detail"], "unknown ACME tenant");
    }

    // Even an enrollment-shaped POST to a foreign tenant path is refused
    // before anything reads its body.
    let response = send(
        &fx,
        acme_post("/acme/default/new-account", "not-even-a-jws"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let problem = body_json(response).await;
    assert_eq!(problem["detail"], "unknown ACME tenant");

    fx.cleanup().await;
}

/// Review Focus 5: new-account is gated by the per-IP GCRA BEFORE anything
/// else — the second rapid enrollment from the same peer IP is 429 (with
/// the GovernorLayer's Retry-After), while the same burst from a DIFFERENT
/// loopback alias keeps its own bucket and enrols.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn new_account_is_rate_limited_per_ip() {
    let _db = lock_db().await;
    let mut fx = fixture_with(FixtureConfig {
        public_url: Some(PUBLIC_URL),
        // Burst 1 with a refill period far longer than the run: the first
        // enrollment spends the whole bucket.
        rate_limit: Some(AuthRateLimit {
            per_millis: 60_000,
            burst: 1,
        }),
        ..FixtureConfig::default()
    })
    .await;
    let new_account_url = format!("{PUBLIC_URL}/acme/{ACME_TENANT}/new-account");
    let peer_a = Ipv4Addr::new(127, 0, 0, 1);
    let peer_b = Ipv4Addr::new(127, 0, 0, 2);

    // First enrollment from PEER_A: passes the limiter, mints account 1.
    let nonce = fetch_nonce(&fx).await;
    let first = acme_common::sign_acme_request(
        rsa2048(),
        &Identity::Jwk,
        &nonce,
        &new_account_url,
        &json!({"termsOfServiceAgreed": true}),
    );
    let response = send(
        &fx,
        with_peer(
            acme_post(&format!("/acme/{ACME_TENANT}/new-account"), &first),
            peer_a,
            44444,
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "the first enrollment passes"
    );

    // Second rapid enrollment from the SAME IP — 429 with Retry-After.
    let nonce = fetch_nonce(&fx).await;
    let second = acme_common::sign_acme_request(
        p256(),
        &Identity::Jwk,
        &nonce,
        &new_account_url,
        &json!({"termsOfServiceAgreed": true}),
    );
    let limited = send(
        &fx,
        with_peer(
            acme_post(&format!("/acme/{ACME_TENANT}/new-account"), &second),
            peer_a,
            55555,
        ),
    )
    .await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        limited.headers().get("retry-after").is_some(),
        "the GovernorLayer's 429 carries Retry-After"
    );

    // A different peer alias keeps its own bucket: account 2 mints.
    let nonce = fetch_nonce(&fx).await;
    let third = acme_common::sign_acme_request(
        ed25519(),
        &Identity::Jwk,
        &nonce,
        &new_account_url,
        &json!({"termsOfServiceAgreed": true}),
    );
    let through = send(
        &fx,
        with_peer(
            acme_post(&format!("/acme/{ACME_TENANT}/new-account"), &third),
            peer_b,
            44444,
        ),
    )
    .await;
    assert_eq!(through.status(), StatusCode::CREATED, "buckets are per-IP");

    let created = audit_rows(&fx, "acme_account_created").await;
    fx.cleanup().await;
    assert_eq!(
        created.len(),
        2,
        "only the two non-limited enrollments minted"
    );
}

// ---------------------------------------------------------------------------
// Request builders the tests above use
// ---------------------------------------------------------------------------

/// A new-account JWS for `key` with an explicit agreement flag and no
/// contact (ToS-gate flows).
async fn signed_account_jws(fixture: &Fixture, key: &KeyFixture, agreed: bool) -> String {
    let nonce = fetch_nonce(fixture).await;
    acme_common::sign_acme_request(
        key,
        &Identity::Jwk,
        &nonce,
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/new-account"),
        &json!({"termsOfServiceAgreed": agreed}),
    )
}

/// The ToS gate's first request: a new-account JWS WITHOUT agreement.
async fn sign_without_agreement(fixture: &Fixture, key: &KeyFixture) -> TestResponse {
    let jws = signed_account_jws(fixture, key, false).await;
    send(
        fixture,
        acme_post(&format!("/acme/{ACME_TENANT}/new-account"), &jws),
    )
    .await
}

// ---------------------------------------------------------------------------
// The order machine (Plan-4 Task 6): new-order, reuse window,
// order/authz POST-as-GET
// ---------------------------------------------------------------------------

/// A profile fixture row under the fixture tenant (setup's built-ins are
/// named profiles; the ACME order surface resolves the order's `profile`
/// member against them by name).
fn profile_row(tenant_id: Uuid, name: &str) -> ProfileModel {
    ProfileModel {
        id: Uuid::new_v4(),
        tenant_id,
        name: name.to_owned(),
        description: None,
        current_revision_id: None,
        created_at: chrono::Utc::now(),
    }
}

/// Seed a named profile under the fixture tenant, through the Task-2 repo.
async fn seed_profile(fixture: &Fixture, name: &str) {
    ProfileRepo::new()
        .insert_profile(&fixture.pool, &profile_row(fixture.tenant_id, name))
        .await
        .expect("seed the profile row");
}

/// The absolute order-object URL.
fn order_url(order_id: Uuid) -> String {
    format!("{PUBLIC_URL}/acme/{ACME_TENANT}/orders/{order_id}")
}

/// The absolute authorization-object URL.
fn authz_url(authz_id: Uuid) -> String {
    format!("{PUBLIC_URL}/acme/{ACME_TENANT}/authz/{authz_id}")
}

/// A kid-signed POST-as-GET to ANY order-machine resource URL (the
/// account URL as the kid, the empty payload).
async fn kid_post_as_get(fixture: &Fixture, key: &KeyFixture, url: &str) -> TestResponse {
    let nonce = fetch_nonce(fixture).await;
    let account = account_url(&thumb_of(key));
    let jws =
        acme_common::sign_acme_request(key, &Identity::Kid(account), &nonce, url, &Value::Null);
    let path = url
        .strip_prefix(PUBLIC_URL)
        .expect("a fixture-built absolute URL");
    send(fixture, acme_post(path, &jws)).await
}

/// A kid-signed new-order POST with the caller's payload object.
async fn post_new_order(fixture: &Fixture, key: &KeyFixture, payload: Value) -> TestResponse {
    let nonce = fetch_nonce(fixture).await;
    let jws = acme_common::sign_acme_request(
        key,
        &Identity::Kid(account_url(&thumb_of(key))),
        &nonce,
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/new-order"),
        &payload,
    );
    send(
        fixture,
        acme_post(&format!("/acme/{ACME_TENANT}/new-order"), &jws),
    )
    .await
}

/// The id tail of the `Location` a created order carries (the order
/// object itself carries no id member — the Location IS the handle).
fn location_order_id(response: &TestResponse) -> String {
    response
        .headers()
        .get(header::LOCATION)
        .expect("a Location on the created order")
        .to_str()
        .expect("ascii")
        .rsplit('/')
        .next()
        .expect("a uuid tail")
        .to_owned()
}

/// How many orders live under the fixture tenant (the refused-request
/// leg's "nothing was created" check).
async fn order_count(fixture: &Fixture) -> i64 {
    sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM acme_orders WHERE tenant_id = $1")
        .bind(fixture.tenant_id)
        .fetch_one(&fixture.pool)
        .await
        .expect("count the orders")
        .0
}

/// How many authorizations live under the fixture tenant.
async fn authz_count(fixture: &Fixture) -> i64 {
    sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM acme_authorizations WHERE tenant_id = $1")
        .bind(fixture.tenant_id)
        .fetch_one(&fixture.pool)
        .await
        .expect("count the authorizations")
        .0
}

/// The happy new-order: 201 with the order `Location`, a pending order
/// object carrying the default `web-server` profile and the finalize URL,
/// ONE freshly minted pending authorization on the 7-day retry window
/// with its BOTH-flavor challenge pair (http-01 + dns-01, distinct
/// OS-random tokens), and the `acme_order_created` audit row in the
/// pinned AcmeAccount actor shape.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn new_order_mints_a_pending_order_with_an_authorization_url() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let (thumb, created) = create_account(&fx, rsa2048()).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let account = AcmeRepo::new()
        .get_account(&fx.pool, fx.tenant_id, &thumb)
        .await
        .expect("read the account")
        .expect("it exists");
    seed_profile(&fx, "web-server").await;

    let response = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "host.wardstone.test"}]}),
    )
    .await;
    let status = response.status();
    let order_id = Uuid::parse_str(&location_order_id(&response)).expect("the Location's id");
    let order_object = body_json(response).await;

    let order_row = AcmeRepo::new()
        .get_order(&fx.pool, fx.tenant_id, order_id)
        .await
        .expect("read the order row")
        .expect("it was minted");
    let authz_rows = AcmeRepo::new()
        .list_authorizations_by_order(&fx.pool, fx.tenant_id, order_id)
        .await
        .expect("read the order's authorizations");
    let challenge_rows = AcmeRepo::new()
        .list_challenges_by_authorization(&fx.pool, fx.tenant_id, authz_rows[0].id)
        .await
        .expect("read the authz's challenges");
    let created_audit = audit_rows(&fx, "acme_order_created").await;
    fx.cleanup().await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(order_object["status"], "pending");
    assert_eq!(order_object["profile"], "web-server");
    assert_eq!(
        order_object["identifiers"],
        json!([{"type": "dns", "value": "host.wardstone.test"}])
    );
    assert_eq!(
        order_object["finalize"],
        json!(format!(
            "{PUBLIC_URL}/acme/{ACME_TENANT}/orders/{order_id}/finalize"
        ))
    );
    assert_eq!(
        order_object["authorizations"],
        json!([authz_url(authz_rows[0].id)]),
        "the 201 body lists the order's ONE fresh authorization URL"
    );
    assert!(
        order_object.get("certificate").is_none(),
        "no certificate on a pending order"
    );
    assert!(order_object["expires"].is_string());

    assert_eq!(order_row.status, AcmeOrderStatus::Pending);
    assert_eq!(order_row.profile_name, "web-server");
    assert_eq!(order_row.account_id, account.id);
    assert_eq!(
        order_row.expires_at,
        order_row.created_at + chrono::Duration::days(7),
        "the 7-day order window"
    );

    assert_eq!(authz_rows.len(), 1, "one identifier, one fresh authz");
    let authz = &authz_rows[0];
    assert_eq!(authz.identifier, "host.wardstone.test");
    assert_eq!(authz.status, AcmeAuthorizationStatus::Pending);
    assert_eq!(authz.order_id, Some(order_id));
    assert_eq!(authz.reused_from, None);
    assert_eq!(
        authz.expires_at, order_row.expires_at,
        "the fresh authz shares the order's 7-day retry window"
    );

    assert_eq!(challenge_rows.len(), 2, "BOTH flavors minted");
    let types: Vec<_> = challenge_rows.iter().map(|c| c.challenge_type).collect();
    assert!(types.contains(&AcmeChallengeType::Http01));
    assert!(types.contains(&AcmeChallengeType::Dns01));
    assert!(
        challenge_rows[0].token != challenge_rows[1].token,
        "each challenge holds its own OS-random token"
    );
    assert!(challenge_rows
        .iter()
        .all(|c| c.status == AcmeChallengeStatus::Pending));

    assert_eq!(created_audit.len(), 1, "exactly one creation audit row");
    let (actor_type, auth_method, actor_id, target_id, details) = &created_audit[0];
    assert_eq!(actor_type, "acme_account");
    assert_eq!(auth_method, "acme_account");
    assert_eq!(actor_id, &account_url(&thumb));
    assert_eq!(target_id, &order_id.to_string());
    assert_eq!(details["profile"], "web-server");
    assert_eq!(details["reused_authorization_count"], 0);
    assert_eq!(details["minted_authorization_count"], 1);
}

/// The Wardstone `profile` extension member: absent → the default
/// `web-server`; the plan-text spelling `profile_name` (and its camelCase
/// twin) is accepted as the alias; BOTH members with different values is
/// `malformed`; and an unknown profile is a 400 `malformed` problem
/// naming it (the plan's Task-6 pin).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn new_order_resolves_the_profile_member() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let (_thumb, created) = create_account(&fx, rsa2048()).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    seed_profile(&fx, "web-server").await;

    // Absent profile member → the default profile.
    let response = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "a.wardstone.test"}]}),
    )
    .await;
    let defaulted = response.status();
    let defaulted_profile = body_json(response).await["profile"].clone();

    // The plan-text alias spelling.
    seed_profile(&fx, "web-server-ecdsa").await;
    let response = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "b.wardstone.test"}],
               "profile_name": "web-server-ecdsa"}),
    )
    .await;
    let aliased = response.status();
    let aliased_profile = body_json(response).await["profile"].clone();

    // Both members, DIFFERENT values: refused.
    let response = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "c.wardstone.test"}],
               "profile": "web-server", "profile_name": "web-server-ecdsa"}),
    )
    .await;
    let conflicting = response.status();
    let conflicting_body = body_json(response).await;

    // Unknown profile: 400 malformed, the name in the detail.
    let response = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "d.wardstone.test"}],
               "profile": "no-such-profile"}),
    )
    .await;
    let unknown = response.status();
    let unknown_body = body_json(response).await;

    let orders_after = order_count(&fx).await;
    fx.cleanup().await;

    assert_eq!(defaulted, StatusCode::CREATED);
    assert_eq!(defaulted_profile, "web-server");
    assert_eq!(aliased, StatusCode::CREATED);
    assert_eq!(aliased_profile, "web-server-ecdsa");
    assert_eq!(conflicting, StatusCode::BAD_REQUEST);
    assert_eq!(
        conflicting_body["type"],
        "urn:ietf:params:acme:error:malformed"
    );
    assert_eq!(unknown, StatusCode::BAD_REQUEST);
    assert_eq!(unknown_body["type"], "urn:ietf:params:acme:error:malformed");
    assert!(
        unknown_body["detail"]
            .as_str()
            .expect("detail")
            .contains("no-such-profile"),
        "the problem names the missing profile"
    );
    assert_eq!(
        orders_after, 2,
        "only the two well-formed orders were created"
    );
}

/// Identifier validation: a foreign identifier TYPE is the RFC registry's
/// `rejectedIdentifier` (the type named in the detail); an empty value, a
/// leading dot, an empty identifiers array, and a repeated value are
/// `malformed` — and none of the refusals minted anything.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn new_order_rejects_foreign_identifier_types_and_bad_dns_values() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let (_thumb, created) = create_account(&fx, rsa2048()).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    seed_profile(&fx, "web-server").await;

    let foreign_type = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "ip", "value": "127.0.0.1"}]}),
    )
    .await;
    let foreign_status = foreign_type.status();
    let foreign_body = body_json(foreign_type).await;

    let empty_value = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": ""}]}),
    )
    .await;
    let empty_status = empty_value.status();
    let empty_body = body_json(empty_value).await;

    let leading_dot = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": ".host.wardstone.test"}]}),
    )
    .await;
    let dot_status = leading_dot.status();

    let none_at_all = post_new_order(&fx, rsa2048(), json!({"identifiers": []})).await;
    let none_status = none_at_all.status();

    let repeated = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "a.wardstone.test"},
                               {"type": "dns", "value": "a.wardstone.test"}]}),
    )
    .await;
    let repeated_status = repeated.status();

    // Fix round 1 (F2): the identifier charset is a trust boundary — the
    // HTTP-01 fetch URL is built from the identifier, so characters that
    // could shape the fetch AUTHORITY (userinfo, port, escapes, a bare
    // wildcard) are refused `malformed` at new-order.
    let userinfo = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "internal@evil.test"}]}),
    )
    .await;
    let userinfo_status = userinfo.status();
    let userinfo_body = body_json(userinfo).await;
    let port_shaped = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "evil.test:8080"}]}),
    )
    .await;
    let port_status = port_shaped.status();
    let escaped = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "evil%2Etest"}]}),
    )
    .await;
    let escape_status = escaped.status();
    let bare_wildcard = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "*evil.test"}]}),
    )
    .await;
    let bare_wildcard_status = bare_wildcard.status();
    let underscore = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "evil_test.wardstone.test"}]}),
    )
    .await;
    let underscore_status = underscore.status();

    let orders_after = order_count(&fx).await;
    let authzs_after = authz_count(&fx).await;
    fx.cleanup().await;

    assert_eq!(foreign_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        foreign_body["type"],
        "urn:ietf:params:acme:error:rejectedIdentifier"
    );
    assert!(
        foreign_body["detail"]
            .as_str()
            .expect("detail")
            .contains("ip"),
        "the problem names the rejected identifier type"
    );
    assert_eq!(empty_status, StatusCode::BAD_REQUEST);
    assert_eq!(empty_body["type"], "urn:ietf:params:acme:error:malformed");
    assert_eq!(dot_status, StatusCode::BAD_REQUEST);
    assert_eq!(none_status, StatusCode::BAD_REQUEST);
    assert_eq!(repeated_status, StatusCode::BAD_REQUEST);
    assert_eq!(userinfo_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        userinfo_body["type"],
        "urn:ietf:params:acme:error:malformed"
    );
    assert_eq!(port_status, StatusCode::BAD_REQUEST);
    assert_eq!(escape_status, StatusCode::BAD_REQUEST);
    assert_eq!(bare_wildcard_status, StatusCode::BAD_REQUEST);
    assert_eq!(underscore_status, StatusCode::BAD_REQUEST);
    assert_eq!(orders_after, 0, "every refusal created nothing");
    assert_eq!(authzs_after, 0, "every refusal created nothing");
}

/// new-order is a CREATION endpoint: the POST-as-GET (empty payload) is
/// refused `malformed`, and nothing was created.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn new_order_refuses_post_as_get() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let (_thumb, created) = create_account(&fx, rsa2048()).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    seed_profile(&fx, "web-server").await;

    let response = kid_post_as_get(
        &fx,
        rsa2048(),
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/new-order"),
    )
    .await;
    let status = response.status();
    let body = body_json(response).await;
    let orders_after = order_count(&fx).await;
    fx.cleanup().await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["type"], "urn:ietf:params:acme:error:malformed");
    assert_eq!(orders_after, 0);
}

/// The account-status gate: a `pending` account (the ToS gate minted it)
/// and a `deactivated` account both get the 401 `unauthorized` refusal,
/// and mint nothing.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn new_order_refuses_a_pending_account() {
    let _db = lock_db().await;
    let mut fx = fixture_with(FixtureConfig {
        public_url: Some(PUBLIC_URL),
        tos_url: Some("https://acme.wardstone.test/terms"),
        ..FixtureConfig::default()
    })
    .await;

    let signed_out = sign_without_agreement(&fx, rsa2048()).await;
    assert_eq!(signed_out.status(), StatusCode::FORBIDDEN, "the ToS gate");

    let response = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "host.wardstone.test"}]}),
    )
    .await;
    let status = response.status();
    let body = body_json(response).await;
    let orders_after = order_count(&fx).await;
    fx.cleanup().await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["type"], "urn:ietf:params:acme:error:unauthorized");
    assert_eq!(orders_after, 0);
}

#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn new_order_refuses_a_deactivated_account() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let (thumb, created) = create_account(&fx, rsa2048()).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    seed_profile(&fx, "web-server").await;

    // Deactivate through the account URL (the Task-5 flow).
    let account_url_str = account_url(&thumb);
    let nonce = fetch_nonce(&fx).await;
    let jws = acme_common::sign_acme_request(
        rsa2048(),
        &Identity::Kid(account_url_str),
        &nonce,
        &account_url(&thumb),
        &json!({"status": "deactivated"}),
    );
    let deactivated = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/acct/{thumb}"), &jws),
    )
    .await;
    assert_eq!(deactivated.status(), StatusCode::OK);

    let response = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "host.wardstone.test"}]}),
    )
    .await;
    let status = response.status();
    let body = body_json(response).await;
    let orders_after = order_count(&fx).await;
    fx.cleanup().await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["type"], "urn:ietf:params:acme:error:unauthorized");
    assert_eq!(orders_after, 0);
}

/// Within the 30-day reuse window: a `valid` account-level authorization
/// on the identifier is REUSED — the order's `authorizations` array points
/// at the EXISTING authorization URL, the reused row stays account-level
/// (`order_id` stays NULL), and NO new row is minted for the identifier.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn new_order_reuses_a_valid_authorization_within_the_window() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let (thumb, created) = create_account(&fx, rsa2048()).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    seed_profile(&fx, "web-server").await;
    let account = AcmeRepo::new()
        .get_account(&fx.pool, fx.tenant_id, &thumb)
        .await
        .expect("read the account")
        .expect("it exists");

    let existing = AcmeAuthorizationModel {
        id: Uuid::new_v4(),
        tenant_id: fx.tenant_id,
        account_id: account.id,
        identifier: "site.wardstone.test".to_owned(),
        status: AcmeAuthorizationStatus::Valid,
        expires_at: chrono::Utc::now() + chrono::Duration::days(29),
        reused_from: None,
        order_id: None,
        created_at: chrono::Utc::now() - chrono::Duration::days(1),
    };
    AcmeRepo::new()
        .insert_authorization(&fx.pool, &existing)
        .await
        .expect("seed the valid reuse row");

    let response = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "site.wardstone.test"}]}),
    )
    .await;
    let status = response.status();
    let _order_id = Uuid::parse_str(&location_order_id(&response)).expect("the Location's id");
    let body = body_json(response).await;
    let created_audit = audit_rows(&fx, "acme_order_created").await;
    let authzs_after = authz_count(&fx).await;
    let reuse_row = AcmeRepo::new()
        .get_authorization(&fx.pool, fx.tenant_id, existing.id)
        .await
        .expect("read the reuse row")
        .expect("it survives");
    fx.cleanup().await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        body["authorizations"],
        json!([authz_url(existing.id)]),
        "the EXISTING authorization URL is reused"
    );
    assert_eq!(authzs_after, 1, "no new row was minted for the identifier");
    assert!(
        reuse_row.order_id.is_none(),
        "a reused row keeps order_id NULL (Task 2's design)"
    );
    assert_eq!(reuse_row.status, AcmeAuthorizationStatus::Valid);
    assert_eq!(created_audit.len(), 1);
    assert_eq!(created_audit[0].4["reused_authorization_count"], 1);
    assert_eq!(created_audit[0].4["minted_authorization_count"], 0);
}

/// Review Focus 5, route-level: an account-level `valid` authorization
/// whose `expires_at` has PASSED is OUTSIDE the reuse window — the next
/// new-order mints a fresh order-scoped pending row (the injected-`now`
/// repo-level window test lives in the Task-2 repo suite).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn reused_authorization_respects_window() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let (thumb, created) = create_account(&fx, rsa2048()).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    seed_profile(&fx, "web-server").await;
    let account = AcmeRepo::new()
        .get_account(&fx.pool, fx.tenant_id, &thumb)
        .await
        .expect("read the account")
        .expect("it exists");

    let expired = AcmeAuthorizationModel {
        id: Uuid::new_v4(),
        tenant_id: fx.tenant_id,
        account_id: account.id,
        identifier: "site.wardstone.test".to_owned(),
        status: AcmeAuthorizationStatus::Valid,
        expires_at: chrono::Utc::now() - chrono::Duration::hours(1),
        reused_from: None,
        order_id: None,
        created_at: chrono::Utc::now() - chrono::Duration::days(8),
    };
    AcmeRepo::new()
        .insert_authorization(&fx.pool, &expired)
        .await
        .expect("seed the expired valid row");

    let response = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "site.wardstone.test"}]}),
    )
    .await;
    let status = response.status();
    let order_id = Uuid::parse_str(&location_order_id(&response)).expect("the Location's id");
    let body = body_json(response).await;
    let authz_rows = AcmeRepo::new()
        .list_authorizations_by_order(&fx.pool, fx.tenant_id, order_id)
        .await
        .expect("read the order's authorizations");
    let authzs_after = authz_count(&fx).await;
    let expired_row: Option<(AcmeAuthorizationStatus, Option<Uuid>)> = AcmeRepo::new()
        .get_authorization(&fx.pool, fx.tenant_id, expired.id)
        .await
        .expect("read the expired row")
        .map(|row| (row.status, row.order_id));
    fx.cleanup().await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(authz_rows.len(), 1, "a fresh pending authz was minted");
    assert_ne!(authz_rows[0].id, expired.id);
    assert_eq!(authz_rows[0].status, AcmeAuthorizationStatus::Pending);
    assert_eq!(authz_rows[0].order_id, Some(order_id));
    assert_eq!(
        body["authorizations"],
        json!([authz_url(authz_rows[0].id)]),
        "the NEW authz URL, never the expired row's"
    );
    assert_eq!(authzs_after, 2, "the expired row was not consumed away");
    let expired_row = expired_row.expect("the expired row survives untouched");
    assert_eq!(expired_row.0, AcmeAuthorizationStatus::Valid);
    assert!(expired_row.1.is_none());
}

/// Order POST-as-GET: the object round-trips identically to the creation
/// body; a FOREIGN account's kid finds nothing (one 404, no existence
/// oracle); an unknown id and a non-uuid path are 404s too.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn order_post_as_get_renders_the_order_object_account_scoped() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let (_, created) = create_account(&fx, rsa2048()).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let (_, created_b) = create_account(&fx, p256()).await;
    assert_eq!(created_b.status(), StatusCode::CREATED);
    seed_profile(&fx, "web-server").await;

    let response = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "host.wardstone.test"}]}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let order_id = Uuid::parse_str(&location_order_id(&response)).expect("the Location's id");
    let creation_body = body_json(response).await;

    let read = kid_post_as_get(&fx, rsa2048(), &order_url(order_id)).await;
    let read_status = read.status();
    let read_body = body_json(read).await;

    let foreign = kid_post_as_get(&fx, p256(), &order_url(order_id)).await;
    let foreign_status = foreign.status();
    let foreign_body = body_json(foreign).await;

    let missing = kid_post_as_get(&fx, rsa2048(), &order_url(Uuid::new_v4())).await;
    let missing_status = missing.status();
    let missing_body = body_json(missing).await;

    let not_a_uuid = kid_post_as_get(
        &fx,
        rsa2048(),
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/orders/not-a-uuid"),
    )
    .await;
    let not_a_uuid_status = not_a_uuid.status();

    fx.cleanup().await;

    assert_eq!(read_status, StatusCode::OK);
    assert_eq!(
        read_body, creation_body,
        "the POST-as-GET body equals the creation body"
    );
    assert_eq!(foreign_status, StatusCode::NOT_FOUND);
    assert_eq!(foreign_body["type"], "urn:ietf:params:acme:error:malformed");
    assert_eq!(missing_status, StatusCode::NOT_FOUND);
    assert_eq!(missing_body["type"], "urn:ietf:params:acme:error:malformed");
    assert_eq!(not_a_uuid_status, StatusCode::NOT_FOUND);
}

/// Authorization POST-as-GET: the object renders the identifier, the
/// expiry, and BOTH stored challenges with their absolute `chall` URLs and
/// tokens (matching the DB rows); a foreign account finds nothing.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn authz_post_as_get_renders_the_challenge_pair_account_scoped() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let (_, created) = create_account(&fx, rsa2048()).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let (_, created_b) = create_account(&fx, p256()).await;
    assert_eq!(created_b.status(), StatusCode::CREATED);
    seed_profile(&fx, "web-server").await;

    let response = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "host.wardstone.test"}]}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let _order_id = Uuid::parse_str(&location_order_id(&response)).expect("the Location's id");
    let creation_body = body_json(response).await;
    let authz_id = Uuid::parse_str(
        creation_body["authorizations"][0]
            .as_str()
            .expect("an authz URL")
            .rsplit('/')
            .next()
            .expect("a uuid tail"),
    )
    .expect("the authz id");

    let read = kid_post_as_get(&fx, rsa2048(), &authz_url(authz_id)).await;
    let read_status = read.status();
    let read_body = body_json(read).await;

    let challenge_rows = AcmeRepo::new()
        .list_challenges_by_authorization(&fx.pool, fx.tenant_id, authz_id)
        .await
        .expect("read the authz's challenges");
    let foreign = kid_post_as_get(&fx, p256(), &authz_url(authz_id)).await;
    let foreign_status = foreign.status();
    let missing = kid_post_as_get(&fx, rsa2048(), &authz_url(Uuid::new_v4())).await;
    let missing_status = missing.status();
    fx.cleanup().await;

    assert_eq!(read_status, StatusCode::OK);
    assert_eq!(read_body["status"], "pending");
    assert_eq!(
        read_body["identifier"],
        json!({"type": "dns", "value": "host.wardstone.test"})
    );
    assert!(read_body["expires"].is_string());
    assert!(
        read_body.get("wildcard").is_none(),
        "a plain identifier carries no wildcard member"
    );
    assert_eq!(challenge_rows.len(), 2);
    let mut db_pairs: Vec<(String, String, String)> = challenge_rows
        .iter()
        .map(|c| {
            (
                c.challenge_type.as_str().to_owned(),
                format!("{PUBLIC_URL}/acme/{ACME_TENANT}/chall/{}", c.id),
                c.token.clone(),
            )
        })
        .collect();
    let mut body_pairs: Vec<(String, String, String)> = read_body["challenges"]
        .as_array()
        .expect("a challenge array")
        .iter()
        .filter_map(|c| {
            Some((
                c["type"].as_str()?.to_owned(),
                c["url"].as_str()?.to_owned(),
                c["token"].as_str()?.to_owned(),
            ))
        })
        .collect();
    db_pairs.sort();
    body_pairs.sort();
    assert_eq!(body_pairs, db_pairs, "types, urls, and tokens match the DB");
    assert_eq!(foreign_status, StatusCode::NOT_FOUND);
    assert_eq!(missing_status, StatusCode::NOT_FOUND);
}

/// An INVALID order object carries its `error` problem document and NO
/// `authorizations` member (the per-status content shape; a valid order's
/// `certificate` URL arrives with Task 8's serving route).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn an_invalid_order_object_carries_its_error() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let (thumb, created) = create_account(&fx, rsa2048()).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    seed_profile(&fx, "web-server").await;
    let account = AcmeRepo::new()
        .get_account(&fx.pool, fx.tenant_id, &thumb)
        .await
        .expect("read the account")
        .expect("it exists");

    let order = AcmeOrderModel {
        id: Uuid::new_v4(),
        tenant_id: fx.tenant_id,
        account_id: account.id,
        status: AcmeOrderStatus::Invalid,
        profile_name: "web-server".to_owned(),
        identifiers: json!([{"type": "dns", "value": "host.wardstone.test"}]),
        csr_pem: None,
        not_before: None,
        not_after: None,
        certificate_id: None,
        error: Some("account deactivated".to_owned()),
        expires_at: chrono::Utc::now() + chrono::Duration::days(7),
        created_at: chrono::Utc::now(),
    };
    AcmeRepo::new()
        .insert_order(&fx.pool, &order)
        .await
        .expect("seed the invalid order");

    let read = kid_post_as_get(&fx, rsa2048(), &order_url(order.id)).await;
    let status = read.status();
    let body = body_json(read).await;
    fx.cleanup().await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "invalid");
    assert_eq!(
        body["error"]["type"],
        "urn:ietf:params:acme:error:serverInternal"
    );
    assert_eq!(body["error"]["detail"], "account deactivated");
    assert!(
        body.get("authorizations").is_none(),
        "an order past pending carries no authorizations array"
    );
    assert!(body.get("certificate").is_none());
    assert!(
        body["finalize"].is_string(),
        "the finalize URL is always carried"
    );
}

/// A `*.`-prefixed order identifier (Task 10's e2e case, stored verbatim
/// on the rows): the authorization OBJECT renders the value WITHOUT the
/// prefix plus `wildcard: true` — RFC 8555 §7.5.1's wildcard-authority
/// form — while the reuse key stays the verbatim stored string.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn a_wildcard_identifier_renders_the_rfc_authorization_object() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let (thumb, created) = create_account(&fx, rsa2048()).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    seed_profile(&fx, "web-server").await;
    let _account = AcmeRepo::new()
        .get_account(&fx.pool, fx.tenant_id, &thumb)
        .await
        .expect("read the account")
        .expect("it exists");

    let response = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "*.wild.wardstone.test"}]}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let creation_body = body_json(response).await;
    let authz_id = Uuid::parse_str(
        creation_body["authorizations"][0]
            .as_str()
            .expect("an authz URL")
            .rsplit('/')
            .next()
            .expect("a uuid tail"),
    )
    .expect("the authz id");

    let read = kid_post_as_get(&fx, rsa2048(), &authz_url(authz_id)).await;
    let read_status = read.status();
    let read_body = body_json(read).await;
    let stored: Option<(String,)> =
        sqlx::query_as("SELECT identifier FROM acme_authorizations WHERE id = $1")
            .bind(authz_id)
            .fetch_optional(&fx.pool)
            .await
            .expect("read the authz row");
    fx.cleanup().await;

    assert_eq!(read_status, StatusCode::OK);
    assert_eq!(
        read_body["identifier"],
        json!({"type": "dns", "value": "wild.wardstone.test"}),
        "the wildcard prefix is off the wire value"
    );
    assert_eq!(read_body["wildcard"], true);
    let stored = stored.expect("the authz row was minted").0;
    assert_eq!(
        stored, "*.wild.wardstone.test",
        "the row stores the order's verbatim identifier (the reuse key)"
    );
}

// ---------------------------------------------------------------------------
// Challenge verification (Plan-4 Task 7): the loopback stub, the
// injectable seams, and the synchronous verdict tests
// ---------------------------------------------------------------------------

/// The loopback HTTP-01 stub (the ws-auth oidc_test std-net pattern): one
/// std thread, one text body served for every /.well-known/acme-challenge
/// GET, served paths recorded for the server-side-fetch assertions. The
/// body swaps behind a lock: the expected key authorization is only known
/// after the challenge rows exist.
struct ChallengeStub {
    base: String,
    served: Arc<StdMutex<Vec<String>>>,
    body: Arc<RwLock<String>>,
}

fn spawn_challenge_stub(body: &str) -> ChallengeStub {
    use std::io::{Read, Write};
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
    fn set_body(&self, body: String) {
        *self.body.write().expect("the stub body") = body;
    }
}

/// The test HTTP-01 fetcher: the route must build EXACTLY the canonical
/// URL from the stored row (anything else refuses — the assertion of the
/// server-side fetch), and the fetch itself is REAL reqwest against the
/// loopback stub through the same bounded, proxyless client construction
/// the production fetcher uses.
struct StubFetcher {
    client: reqwest::Client,
    rewrites: Arc<RwLock<HashMap<String, String>>>,
    calls: Arc<AtomicUsize>,
}

impl StubFetcher {
    fn new(rewrites: HashMap<String, String>) -> Self {
        StubFetcher {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .no_proxy()
                .build()
                .expect("the stub-backed test client builds"),
            rewrites: Arc::new(RwLock::new(rewrites)),
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

/// A fetcher that holds the verification in flight until the test
/// releases it (a oneshot channel, race-free): the rate-limit test races
/// a second POST against the held request.
struct GatedFetcher {
    inner: Arc<dyn ChallengeFetch>,
    calls: Arc<AtomicUsize>,
    release: Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>>,
}

impl GatedFetcher {
    /// The gated fetcher over `inner`, with the counter the test waits
    /// on, and an EMPTY release slot the test fills with its oneshot
    /// receiver.
    fn new(inner: Arc<dyn ChallengeFetch>) -> Self {
        GatedFetcher {
            inner,
            calls: Arc::new(AtomicUsize::new(0)),
            release: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ChallengeFetch for GatedFetcher {
    fn fetch(&self, url: String) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>> {
        // The count lands BEFORE the release await: observing it proves
        // the attempt reached the outbound-fetch stage (i.e. it already
        // passed the route's pacing gate).
        self.calls.fetch_add(1, Ordering::SeqCst);
        let inner = self.inner.clone();
        let release = self.release.clone();
        Box::pin(async move {
            let rx = release.lock().await.take();
            if let Some(rx) = rx {
                let _ = rx.await;
            }
            inner.fetch(url).await
        })
    }
}

/// The canned TXT resolver: records keyed by the EXACT (trailing-dot FQ)
/// name the route queries; an unlisted name answers the empty record set
/// (the NXDOMAIN shape). Swappable behind a lock — the expected record
/// value is only known after the rows exist.
struct StaticTxtResolver {
    records: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl StaticTxtResolver {
    fn new(records: HashMap<String, Vec<String>>) -> Self {
        StaticTxtResolver {
            records: Arc::new(RwLock::new(records)),
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

/// The challenge tests' verification deps: explicit seams, never network.
fn verification_deps(
    fetcher: Arc<dyn ChallengeFetch>,
    resolver: Arc<dyn TxtResolver>,
) -> VerificationDeps {
    VerificationDeps::with_seams(fetcher, resolver)
}

/// A kid-signed POST to a challenge URL: `json!({})` is the RFC 8555
/// §7.5.1 trigger, `Value::Null` is RFC POST-as-GET.
async fn post_chall(
    fixture: &Fixture,
    key: &KeyFixture,
    challenge_id: Uuid,
    payload: Value,
) -> TestResponse {
    let url = format!("{PUBLIC_URL}/acme/{ACME_TENANT}/chall/{challenge_id}");
    let nonce = fetch_nonce(fixture).await;
    let jws = acme_common::sign_acme_request(
        key,
        &Identity::Kid(account_url(&thumb_of(key))),
        &nonce,
        &url,
        &payload,
    );
    send(
        fixture,
        acme_post(&format!("/acme/{ACME_TENANT}/chall/{challenge_id}"), &jws),
    )
    .await
}

/// The challenge tests' common prelude: account + profile + one order on
/// one identifier; returns the order id, the authz id, and BOTH stored
/// challenge rows (for a wildcard identifier the caller sees the dns-01
/// row alone).
async fn mint_order_with_challenges(
    fixture: &Fixture,
    key: &KeyFixture,
    identifier: &str,
) -> (Uuid, Uuid, Vec<AcmeChallengeModel>) {
    let (_thumb, created) = create_account(fixture, key).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    seed_profile(fixture, "web-server").await;
    let response = post_new_order(
        fixture,
        key,
        json!({"identifiers": [{"type": "dns", "value": identifier}]}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let order_id = Uuid::parse_str(&location_order_id(&response)).expect("the Location's id");
    let authz_rows = AcmeRepo::new()
        .list_authorizations_by_order(&fixture.pool, fixture.tenant_id, order_id)
        .await
        .expect("the order's authorizations");
    let challenge_rows = AcmeRepo::new()
        .list_challenges_by_authorization(&fixture.pool, fixture.tenant_id, authz_rows[0].id)
        .await
        .expect("the challenge rows");
    (order_id, authz_rows[0].id, challenge_rows)
}

/// The canonical HTTP-01 fetch URL the route must build, and the loopback
/// URL the rewrite maps it to (same path, the stub's port).
fn http01_urls(stub: &ChallengeStub, token: &str) -> (String, String) {
    let path = format!("/.well-known/acme-challenge/{token}");
    (
        format!("http://host.wardstone.test{path}"),
        format!("{}{path}", stub.base),
    )
}

/// Review Focus 1 (HTTP-01 happy path): the server fetches the canonical
/// `/.well-known/acme-challenge/<token>` from ITS OWN connection, the
/// response body EXACTLY equals the computed key authorization, and the
/// settled state cascades (challenge valid → authz valid with the 30-day
/// reuse window → order ready).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn http01_verifies_from_server_side_fetch() {
    let _db = lock_db().await;
    let stub = spawn_challenge_stub("placeholder");
    let fetcher = Arc::new(StubFetcher::new(HashMap::new()));
    let resolver = Arc::new(StaticTxtResolver::new(HashMap::new()));
    let mut fx = fixture_with(FixtureConfig {
        public_url: Some(PUBLIC_URL),
        verification: Some(verification_deps(fetcher.clone(), resolver.clone())),
        ..FixtureConfig::default()
    })
    .await;
    let (order_id, authz_id, challenges) =
        mint_order_with_challenges(&fx, rsa2048(), "host.wardstone.test").await;
    let http_row = challenges
        .iter()
        .find(|c| c.challenge_type == AcmeChallengeType::Http01)
        .expect("the http-01 row")
        .clone();

    // The stub serves the CORRECT key authorization — computed here the
    // same way the server computes it (stored token + the account's own
    // thumbprint; both sides land on the same value only in this test's
    // capacity as the client that provisioned the answer).
    let expected = ws_acme::key_authorization(&http_row.token, &thumb_of(rsa2048()));
    stub.set_body(expected);
    let (canonical, target) = http01_urls(&stub, &http_row.token);
    fetcher.set_rewrite(canonical, target);

    let response = post_chall(&fx, rsa2048(), http_row.id, json!({})).await;
    let status = response.status();
    let body = body_json(response).await;
    let served = stub.served.lock().expect("served").clone();
    let row = AcmeRepo::new()
        .get_challenge(&fx.pool, fx.tenant_id, http_row.id)
        .await
        .expect("read the challenge")
        .expect("it exists");
    let authz_row = AcmeRepo::new()
        .get_authorization(&fx.pool, fx.tenant_id, authz_id)
        .await
        .expect("read the authz")
        .expect("it exists");
    let order_row = AcmeRepo::new()
        .get_order(&fx.pool, fx.tenant_id, order_id)
        .await
        .expect("read the order")
        .expect("it exists");
    let invalidations = audit_rows(&fx, "acme_order_invalidated").await;
    fx.cleanup().await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["type"], "http-01");
    assert_eq!(body["token"], json!(http_row.token));
    assert_eq!(body["status"], "valid");
    assert!(body["validated"].is_string());
    assert!(
        body.get("error").is_none(),
        "a valid challenge carries no error member"
    );
    assert_eq!(row.status, AcmeChallengeStatus::Valid);
    assert!(row.validated_at.is_some());
    assert_eq!(authz_row.status, AcmeAuthorizationStatus::Valid);
    let fresh_days = (authz_row.expires_at - chrono::Utc::now()).num_days();
    assert!(
        (29..=30).contains(&fresh_days),
        "the 30-day reuse window is stamped on the valid authz, got {fresh_days} days"
    );
    assert_eq!(
        order_row.status,
        AcmeOrderStatus::Ready,
        "all-valid authorizations make the order ready"
    );
    assert!(
        invalidations.is_empty(),
        "no invalidation on the happy path"
    );
    assert_eq!(
        served,
        vec![format!("/.well-known/acme-challenge/{}", http_row.token)],
        "the server-side fetch hit the canonical path, once"
    );
    assert_eq!(fetcher.calls(), 1);
}

/// The mismatch: a served body that is not the computed key authorization
/// settles the challenge INVALID — and the terminal cascade runs (authz
/// invalid → order invalid + the `acme_order_invalidated` audit row), so
/// re-POSTing is refused (authz invalid is terminal per RFC).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn http01_wrong_body_invalidates_the_authorization_and_the_order() {
    let _db = lock_db().await;
    let stub = spawn_challenge_stub("not-the-answer");
    let fetcher = Arc::new(StubFetcher::new(HashMap::new()));
    let mut fx = fixture_with(FixtureConfig {
        public_url: Some(PUBLIC_URL),
        verification: Some(verification_deps(
            fetcher.clone(),
            Arc::new(StaticTxtResolver::new(HashMap::new())),
        )),
        ..FixtureConfig::default()
    })
    .await;
    let (order_id, authz_id, challenges) =
        mint_order_with_challenges(&fx, rsa2048(), "host.wardstone.test").await;
    let http_row = challenges
        .iter()
        .find(|c| c.challenge_type == AcmeChallengeType::Http01)
        .expect("the http-01 row")
        .clone();
    let (canonical, target) = http01_urls(&stub, &http_row.token);
    fetcher.set_rewrite(canonical, target);

    let response = post_chall(&fx, rsa2048(), http_row.id, json!({})).await;
    let status = response.status();
    let body = body_json(response).await;

    // Terminal: the re-POST is refused outright.
    let repost = post_chall(&fx, rsa2048(), http_row.id, json!({})).await;
    let repost_status = repost.status();
    let repost_problem = body_json(repost).await;

    let row = AcmeRepo::new()
        .get_challenge(&fx.pool, fx.tenant_id, http_row.id)
        .await
        .expect("read the challenge")
        .expect("it exists");
    let authz_row = AcmeRepo::new()
        .get_authorization(&fx.pool, fx.tenant_id, authz_id)
        .await
        .expect("read the authz")
        .expect("it exists");
    let order_row = AcmeRepo::new()
        .get_order(&fx.pool, fx.tenant_id, order_id)
        .await
        .expect("read the order")
        .expect("it exists");
    let invalidations = audit_rows(&fx, "acme_order_invalidated").await;
    fx.cleanup().await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "invalid");
    assert!(
        body["error"]["detail"]
            .as_str()
            .expect("the error detail")
            .contains("does not match the expected value"),
        "the fetch mismatch is the recorded failure, got {:?}",
        body["error"]["detail"]
    );
    assert_eq!(row.status, AcmeChallengeStatus::Invalid);
    assert!(row.error.is_some());
    assert_eq!(authz_row.status, AcmeAuthorizationStatus::Invalid);
    assert_eq!(order_row.status, AcmeOrderStatus::Invalid);
    assert!(
        order_row.error.as_deref().is_some_and(|error| {
            error.contains("host.wardstone.test") && error.contains("does not match")
        }),
        "the order error names the failed authorization, got {:?}",
        order_row.error
    );
    assert_eq!(invalidations.len(), 1);
    let (_, _, actor_id, target_id, details) = &invalidations[0];
    assert_eq!(actor_id, &account_url(&thumb_of(rsa2048())));
    assert_eq!(target_id, &order_id.to_string());
    assert_eq!(details["identifier"], "host.wardstone.test");
    assert!(details["order_url"].is_string());
    assert_eq!(repost_status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        repost_problem["type"],
        "urn:ietf:params:acme:error:unauthorized"
    );
}

/// The outbound fetch is the server's own: a connection-refused origin
/// (the oidc_test bind-read-port-drop shape) fails the verification with
/// the fetch error recorded — never a fallback to anything the client
/// could influence.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn http01_fails_when_the_connection_is_refused() {
    let _db = lock_db().await;
    // Bind, read the port, drop: nothing listens there anymore.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the dead port");
    let dead_port = listener.local_addr().expect("the dead port").port();
    drop(listener);

    let fetcher = Arc::new(StubFetcher::new(HashMap::new()));
    let mut fx = fixture_with(FixtureConfig {
        public_url: Some(PUBLIC_URL),
        verification: Some(verification_deps(
            fetcher.clone(),
            Arc::new(StaticTxtResolver::new(HashMap::new())),
        )),
        ..FixtureConfig::default()
    })
    .await;
    let (order_id, _authz_id, challenges) =
        mint_order_with_challenges(&fx, rsa2048(), "host.wardstone.test").await;
    let http_row = challenges
        .iter()
        .find(|c| c.challenge_type == AcmeChallengeType::Http01)
        .expect("the http-01 row")
        .clone();
    fetcher.set_rewrite(
        format!(
            "http://host.wardstone.test/.well-known/acme-challenge/{}",
            http_row.token
        ),
        format!(
            "http://127.0.0.1:{dead_port}/.well-known/acme-challenge/{}",
            http_row.token
        ),
    );

    let response = post_chall(&fx, rsa2048(), http_row.id, json!({})).await;
    let status = response.status();
    let body = body_json(response).await;
    let order_row = AcmeRepo::new()
        .get_order(&fx.pool, fx.tenant_id, order_id)
        .await
        .expect("read the order")
        .expect("it exists");
    fx.cleanup().await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "invalid");
    assert!(
        body["error"]["detail"]
            .as_str()
            .expect("the error detail")
            .contains("the HTTP request failed"),
        "the fetch failure is the recorded error, got {:?}",
        body["error"]["detail"]
    );
    assert_eq!(order_row.status, AcmeOrderStatus::Invalid);
}

/// DNS-01 happy path: the server itself resolves
/// `_acme-challenge.<identifier>.`, and ANY record equal to the COMPUTED
/// `base64url(SHA256(key authorization))` settles the challenge valid
/// (cascading to the ready order). No HTTP fetch ever runs.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn dns01_verifies_the_computed_txt_record() {
    let _db = lock_db().await;
    let fetcher = Arc::new(StubFetcher::new(HashMap::new()));
    let resolver = Arc::new(StaticTxtResolver::new(HashMap::new()));
    let mut fx = fixture_with(FixtureConfig {
        public_url: Some(PUBLIC_URL),
        verification: Some(verification_deps(fetcher.clone(), resolver.clone())),
        ..FixtureConfig::default()
    })
    .await;
    let (order_id, authz_id, challenges) =
        mint_order_with_challenges(&fx, rsa2048(), "host.wardstone.test").await;
    let dns_row = challenges
        .iter()
        .find(|c| c.challenge_type == AcmeChallengeType::Dns01)
        .expect("the dns-01 row")
        .clone();

    let expected = ws_acme::dns01_record_value(&ws_acme::key_authorization(
        &dns_row.token,
        &thumb_of(rsa2048()),
    ));
    resolver.set_record(
        "_acme-challenge.host.wardstone.test.".to_owned(),
        vec!["other-record-value".to_owned(), expected.clone()],
    );

    let response = post_chall(&fx, rsa2048(), dns_row.id, json!({})).await;
    let status = response.status();
    let body = body_json(response).await;
    let row = AcmeRepo::new()
        .get_challenge(&fx.pool, fx.tenant_id, dns_row.id)
        .await
        .expect("read the challenge")
        .expect("it exists");
    let authz_row = AcmeRepo::new()
        .get_authorization(&fx.pool, fx.tenant_id, authz_id)
        .await
        .expect("read the authz")
        .expect("it exists");
    let order_row = AcmeRepo::new()
        .get_order(&fx.pool, fx.tenant_id, order_id)
        .await
        .expect("read the order")
        .expect("it exists");
    fx.cleanup().await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "valid");
    assert_eq!(row.status, AcmeChallengeStatus::Valid);
    assert_eq!(authz_row.status, AcmeAuthorizationStatus::Valid);
    assert_eq!(order_row.status, AcmeOrderStatus::Ready);
    assert_eq!(
        fetcher.calls(),
        0,
        "DNS-01 verification never touches the HTTP layer"
    );
}

/// The RFC 8555 wildcard rule end-to-end: a `*.` authorization mints its
/// dns-01 challenge ALONE (http-01 cannot prove a wildcard), and the TXT
/// lookup name is the identifier WITHOUT the prefix.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn dns01_a_wildcard_authorization_mints_dns01_only_and_verifies() {
    let _db = lock_db().await;
    let fetcher = Arc::new(StubFetcher::new(HashMap::new()));
    let resolver = Arc::new(StaticTxtResolver::new(HashMap::new()));
    let mut fx = fixture_with(FixtureConfig {
        public_url: Some(PUBLIC_URL),
        verification: Some(verification_deps(fetcher.clone(), resolver.clone())),
        ..FixtureConfig::default()
    })
    .await;
    let (order_id, authz_id, challenges) =
        mint_order_with_challenges(&fx, rsa2048(), "*.wild.wardstone.test").await;
    assert_eq!(
        challenges.len(),
        1,
        "a wildcard authorization carries no http-01 challenge"
    );
    let dns_row = challenges[0].clone();

    let expected = ws_acme::dns01_record_value(&ws_acme::key_authorization(
        &dns_row.token,
        &thumb_of(rsa2048()),
    ));
    resolver.set_record(
        "_acme-challenge.wild.wardstone.test.".to_owned(),
        vec![expected],
    );

    let response = post_chall(&fx, rsa2048(), dns_row.id, json!({})).await;
    let status = response.status();
    let body = body_json(response).await;
    let authz_row = AcmeRepo::new()
        .get_authorization(&fx.pool, fx.tenant_id, authz_id)
        .await
        .expect("read the authz")
        .expect("it exists");
    let order_row = AcmeRepo::new()
        .get_order(&fx.pool, fx.tenant_id, order_id)
        .await
        .expect("read the order")
        .expect("it exists");
    fx.cleanup().await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "valid");
    assert_eq!(authz_row.status, AcmeAuthorizationStatus::Valid);
    assert_eq!(order_row.status, AcmeOrderStatus::Ready);
}

/// The DNS-01 negative: no record matches (the empty record set — the
/// NXDOMAIN shape a not-yet-propagated deployment produces), so the
/// challenge goes invalid and the terminal cascade runs.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn dns01_fails_when_no_record_matches() {
    let _db = lock_db().await;
    let mut fx = fixture_with(FixtureConfig {
        public_url: Some(PUBLIC_URL),
        verification: Some(verification_deps(
            Arc::new(StubFetcher::new(HashMap::new())),
            // NO records at all.
            Arc::new(StaticTxtResolver::new(HashMap::new())),
        )),
        ..FixtureConfig::default()
    })
    .await;
    let (order_id, authz_id, challenges) =
        mint_order_with_challenges(&fx, rsa2048(), "host.wardstone.test").await;
    let dns_row = challenges
        .iter()
        .find(|c| c.challenge_type == AcmeChallengeType::Dns01)
        .expect("the dns-01 row")
        .clone();

    let response = post_chall(&fx, rsa2048(), dns_row.id, json!({})).await;
    let status = response.status();
    let body = body_json(response).await;
    let authz_row = AcmeRepo::new()
        .get_authorization(&fx.pool, fx.tenant_id, authz_id)
        .await
        .expect("read the authz")
        .expect("it exists");
    let order_row = AcmeRepo::new()
        .get_order(&fx.pool, fx.tenant_id, order_id)
        .await
        .expect("read the order")
        .expect("it exists");
    fx.cleanup().await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "invalid");
    assert!(
        body["error"]["detail"]
            .as_str()
            .expect("the error detail")
            .contains("_acme-challenge.host.wardstone.test."),
        "the resolver name is the recorded failure, got {:?}",
        body["error"]["detail"]
    );
    assert_eq!(authz_row.status, AcmeAuthorizationStatus::Invalid);
    assert_eq!(order_row.status, AcmeOrderStatus::Invalid);
}

/// Review Focus 1: a client CANNOT POST an answer anywhere. The payload
/// carries the CORRECT dns-01 record value as a suggested response field,
/// yet the resolver has no record — the verification still uses the
/// server-computed value against the DNS layer, and the challenge goes
/// invalid regardless of the body (§7.5.1: response-object members are
/// ignored wholesale).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn dns01_rejects_client_suggested_payload() {
    let _db = lock_db().await;
    let mut fx = fixture_with(FixtureConfig {
        public_url: Some(PUBLIC_URL),
        verification: Some(verification_deps(
            Arc::new(StubFetcher::new(HashMap::new())),
            Arc::new(StaticTxtResolver::new(HashMap::new())),
        )),
        ..FixtureConfig::default()
    })
    .await;
    let (order_id, authz_id, challenges) =
        mint_order_with_challenges(&fx, rsa2048(), "host.wardstone.test").await;
    let dns_row = challenges
        .iter()
        .find(|c| c.challenge_type == AcmeChallengeType::Dns01)
        .expect("the dns-01 row")
        .clone();

    // The suggested answer is exactly the value a compliant client would
    // provision: if the route read ANY of it, this POST could not fail.
    let suggested_record = ws_acme::dns01_record_value(&ws_acme::key_authorization(
        &dns_row.token,
        &thumb_of(rsa2048()),
    ));
    let response = post_chall(
        &fx,
        rsa2048(),
        dns_row.id,
        json!({ "keyAuthorization": suggested_record }),
    )
    .await;
    let status = response.status();
    let body = body_json(response).await;
    let authz_row = AcmeRepo::new()
        .get_authorization(&fx.pool, fx.tenant_id, authz_id)
        .await
        .expect("read the authz")
        .expect("it exists");
    let order_row = AcmeRepo::new()
        .get_order(&fx.pool, fx.tenant_id, order_id)
        .await
        .expect("read the order")
        .expect("it exists");
    fx.cleanup().await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["status"], "invalid",
        "the suggested answer is not an input: the stale resolver fails it"
    );
    assert!(
        body["error"]["detail"]
            .as_str()
            .expect("the error detail")
            .contains("no TXT record"),
        "the DNS layer's truth is the verdict, got {:?}",
        body["error"]["detail"]
    );
    assert_eq!(authz_row.status, AcmeAuthorizationStatus::Invalid);
    assert_eq!(order_row.status, AcmeOrderStatus::Invalid);
}

/// Settlement D5's pacing: while one verification is in flight (held by
/// the gate), a second POST on the SAME authorization is the 400
/// `rateLimited` problem — and touches nothing (the held verification
/// completes from a single fetch; no second outbound attempt ever runs).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn a_second_rapid_verification_attempt_is_rate_limited() {
    let _db = lock_db().await;
    let stub = spawn_challenge_stub("placeholder");
    let stub_fetcher = Arc::new(StubFetcher::new(HashMap::new()));
    let gated = Arc::new(GatedFetcher::new(stub_fetcher.clone()));
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    *gated.release.lock().await = Some(release_rx);
    let mut fx = fixture_with(FixtureConfig {
        public_url: Some(PUBLIC_URL),
        verification: Some(verification_deps(
            gated.clone(),
            Arc::new(StaticTxtResolver::new(HashMap::new())),
        )),
        ..FixtureConfig::default()
    })
    .await;
    let (_order_id, authz_id, challenges) =
        mint_order_with_challenges(&fx, rsa2048(), "host.wardstone.test").await;
    let http_row = challenges
        .iter()
        .find(|c| c.challenge_type == AcmeChallengeType::Http01)
        .expect("the http-01 row")
        .clone();
    stub.set_body(ws_acme::key_authorization(
        &http_row.token,
        &thumb_of(rsa2048()),
    ));
    let (canonical, target) = http01_urls(&stub, &http_row.token);
    stub_fetcher.set_rewrite(canonical, target);

    // The first verification, held in flight: spawn the request (the
    // router clones fine — oneshot takes it by value) and wait until it
    // is inside the fetch.
    let first_nonce = fetch_nonce(&fx).await;
    let first_jws = acme_common::sign_acme_request(
        rsa2048(),
        &Identity::Kid(account_url(&thumb_of(rsa2048()))),
        &first_nonce,
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/chall/{}", http_row.id),
        &json!({}),
    );
    let first_request = acme_post(
        &format!("/acme/{ACME_TENANT}/chall/{}", http_row.id),
        &first_jws,
    );
    let router = fx.router.clone();
    let first_task =
        tokio::spawn(async move { router.oneshot(first_request).await.expect("the router") });
    let mut waited = 0;
    while gated.calls() == 0 {
        assert!(
            waited < 200,
            "the first verification never reached the fetch"
        );
        waited += 1;
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    // The racing second POST on the same authorization: paced out.
    let second = post_chall(&fx, rsa2048(), http_row.id, json!({})).await;
    let second_status = second.status();
    let second_problem = body_json(second).await;

    // Release; the held verification completes from its single fetch.
    let _ = release_tx.send(());
    let first = first_task.await.expect("the held task joins");
    let first_status = first.status();
    let first_body = body_json(first).await;

    let row = AcmeRepo::new()
        .get_challenge(&fx.pool, fx.tenant_id, http_row.id)
        .await
        .expect("read the challenge")
        .expect("it exists");
    let authz_row = AcmeRepo::new()
        .get_authorization(&fx.pool, fx.tenant_id, authz_id)
        .await
        .expect("read the authz")
        .expect("it exists");
    fx.cleanup().await;

    assert_eq!(second_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        second_problem["type"],
        "urn:ietf:params:acme:error:rateLimited"
    );
    assert_eq!(first_status, StatusCode::OK, "the held attempt completes");
    assert_eq!(first_body["status"], "valid");
    assert_eq!(
        row.status,
        AcmeChallengeStatus::Valid,
        "the pacing refusal touched nothing: the one attempt settled valid"
    );
    assert_eq!(authz_row.status, AcmeAuthorizationStatus::Valid);
    assert_eq!(
        stub_fetcher.calls(),
        1,
        "no second outbound attempt was ever made"
    );
}

/// POST-as-GET on the challenge URL (the empty payload) is a plain read:
/// the object answers as it stands, nothing verifies, nothing mutates.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn challenge_post_as_get_returns_the_object_without_verifying() {
    let _db = lock_db().await;
    let fetcher = Arc::new(StubFetcher::new(HashMap::new()));
    let mut fx = fixture_with(FixtureConfig {
        public_url: Some(PUBLIC_URL),
        verification: Some(verification_deps(
            fetcher.clone(),
            Arc::new(StaticTxtResolver::new(HashMap::new())),
        )),
        ..FixtureConfig::default()
    })
    .await;
    let (_order_id, _authz_id, challenges) =
        mint_order_with_challenges(&fx, rsa2048(), "host.wardstone.test").await;
    let http_row = challenges
        .iter()
        .find(|c| c.challenge_type == AcmeChallengeType::Http01)
        .expect("the http-01 row")
        .clone();

    let response = post_chall(&fx, rsa2048(), http_row.id, Value::Null).await;
    let status = response.status();
    let body = body_json(response).await;
    fx.cleanup().await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "pending");
    assert!(body.get("validated").is_none());
    assert!(body.get("error").is_none());
    assert_eq!(fetcher.calls(), 0, "POST-as-GET never verifies anything");
}

/// The expiry self-transition (the Task-6 carrying obligation): a PENDING
/// authorization past its 7-day window transitions ITSELF where the
/// surface touches it — a POST-as-GET read renders `expired`, a trigger
/// POST refuses `unauthorized` with the expiry in the detail, and its
/// order invalidates under the audit row — all without touching the
/// challenge rows (there is no `expired` problem URN in the §6.7
/// registry; the refusal type carries the state in the detail).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn an_expired_authorization_transitions_itself_and_refuses_the_chall_post() {
    let _db = lock_db().await;
    let fetcher = Arc::new(StubFetcher::new(HashMap::new()));
    let mut fx = fixture_with(FixtureConfig {
        public_url: Some(PUBLIC_URL),
        verification: Some(verification_deps(
            fetcher.clone(),
            Arc::new(StaticTxtResolver::new(HashMap::new())),
        )),
        ..FixtureConfig::default()
    })
    .await;
    let (order_id, authz_id, challenges) =
        mint_order_with_challenges(&fx, rsa2048(), "host.wardstone.test").await;
    let http_row = challenges
        .iter()
        .find(|c| c.challenge_type == AcmeChallengeType::Http01)
        .expect("the http-01 row")
        .clone();
    sqlx::query(
        "UPDATE acme_authorizations SET expires_at = now() - interval '1 hour' \
                 WHERE id = $1",
    )
    .bind(authz_id)
    .execute(&fx.pool)
    .await
    .expect("age the authz past its window");

    // The read leg: POST-as-GET transitions the row and renders it.
    let read = post_chall(&fx, rsa2048(), http_row.id, Value::Null).await;
    let read_status = read.status();
    let read_body = body_json(read).await;

    // The trigger leg: a verification on the expired authz is refused.
    let trigger = post_chall(&fx, rsa2048(), http_row.id, json!({})).await;
    let trigger_status = trigger.status();
    let trigger_problem = body_json(trigger).await;

    let authz_row = AcmeRepo::new()
        .get_authorization(&fx.pool, fx.tenant_id, authz_id)
        .await
        .expect("read the authz")
        .expect("it exists");
    let challenge_row = AcmeRepo::new()
        .get_challenge(&fx.pool, fx.tenant_id, http_row.id)
        .await
        .expect("read the challenge")
        .expect("it exists");
    let order_row = AcmeRepo::new()
        .get_order(&fx.pool, fx.tenant_id, order_id)
        .await
        .expect("read the order")
        .expect("it exists");
    let invalidations = audit_rows(&fx, "acme_order_invalidated").await;
    fx.cleanup().await;

    assert_eq!(read_status, StatusCode::OK);
    assert!(
        read_body["status"].is_string(),
        "the challenge object answers as it stands"
    );
    assert_eq!(trigger_status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        trigger_problem["type"],
        "urn:ietf:params:acme:error:unauthorized"
    );
    assert!(
        trigger_problem["detail"]
            .as_str()
            .expect("the refusal detail")
            .contains("expired"),
        "the expiry is named in the refusal, got {:?}",
        trigger_problem["detail"]
    );
    assert_eq!(
        authz_row.status,
        AcmeAuthorizationStatus::Expired,
        "the authz transitioned itself past the window"
    );
    assert_eq!(
        challenge_row.status,
        AcmeChallengeStatus::Pending,
        "the challenge rows are untouched: no verification ran"
    );
    assert_eq!(order_row.status, AcmeOrderStatus::Invalid);
    assert!(
        order_row
            .error
            .as_deref()
            .is_some_and(|error| error.contains("expired")),
        "the order error names the expiry, got {:?}",
        order_row.error
    );
    assert_eq!(invalidations.len(), 1);
}

/// The account-scoped shape carries over to challenges: a foreign
/// account's kid finds nothing (one 404, no oracle), and so does an
/// unknown id and a non-uuid path.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn a_foreign_or_missing_challenge_is_not_found() {
    let _db = lock_db().await;
    let stub = spawn_challenge_stub("placeholder");
    let fetcher = Arc::new(StubFetcher::new(HashMap::new()));
    let mut fx = fixture_with(FixtureConfig {
        public_url: Some(PUBLIC_URL),
        verification: Some(verification_deps(
            fetcher.clone(),
            Arc::new(StaticTxtResolver::new(HashMap::new())),
        )),
        ..FixtureConfig::default()
    })
    .await;
    let (_order_id, _authz_id, challenges) =
        mint_order_with_challenges(&fx, rsa2048(), "host.wardstone.test").await;
    let http_row = challenges
        .iter()
        .find(|c| c.challenge_type == AcmeChallengeType::Http01)
        .expect("the http-01 row")
        .clone();
    let (canonical, target) = http01_urls(&stub, &http_row.token);
    fetcher.set_rewrite(canonical, target);

    // A different account's kid: the challenge of account A's authz is
    // invisible.
    let (_, created_b) = create_account(&fx, p256()).await;
    assert_eq!(created_b.status(), StatusCode::CREATED);
    let foreign = post_chall(&fx, p256(), http_row.id, json!({})).await;
    let foreign_status = foreign.status();
    let foreign_problem = body_json(foreign).await;

    let missing = post_chall(&fx, rsa2048(), Uuid::new_v4(), json!({})).await;
    let missing_status = missing.status();
    let missing_body = body_json(missing).await;

    // A non-uuid path segment.
    let nonce = fetch_nonce(&fx).await;
    let bad_jws = acme_common::sign_acme_request(
        rsa2048(),
        &Identity::Kid(account_url(&thumb_of(rsa2048()))),
        &nonce,
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/chall/not-a-uuid"),
        &json!({}),
    );
    let bad = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/chall/not-a-uuid"), &bad_jws),
    )
    .await;
    let bad_status = bad.status();

    fx.cleanup().await;

    assert_eq!(foreign_status, StatusCode::NOT_FOUND);
    assert_eq!(
        foreign_problem["type"], "urn:ietf:params:acme:error:malformed",
        "one 404 problem document, no existence oracle"
    );
    assert_eq!(missing_status, StatusCode::NOT_FOUND);
    assert_eq!(missing_body["type"], "urn:ietf:params:acme:error:malformed");
    assert_eq!(bad_status, StatusCode::NOT_FOUND);
}

/// T6-M5, the two-account reuse-isolation leg: a DIFFERENT account's
/// `valid` authorization on the same identifier is NOT reusable — the
/// reuse window is per (account, identifier) — so this account's order
/// MINTS a fresh pending authorization (`reused_authorization_count` 0,
/// `minted_authorization_count` 1 in the audit row) while the other
/// account's row stays untouched. Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn new_order_does_not_reuse_another_accounts_authorization() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    // Account B holds the valid account-level reuse row on the identifier.
    let (thumb_b, created_b) = create_account(&fx, p256()).await;
    assert_eq!(created_b.status(), StatusCode::CREATED);
    let account_b = AcmeRepo::new()
        .get_account(&fx.pool, fx.tenant_id, &thumb_b)
        .await
        .expect("read account B")
        .expect("it exists");
    let foreign_valid = AcmeAuthorizationModel {
        id: Uuid::new_v4(),
        tenant_id: fx.tenant_id,
        account_id: account_b.id,
        identifier: "site.wardstone.test".to_owned(),
        status: AcmeAuthorizationStatus::Valid,
        expires_at: chrono::Utc::now() + chrono::Duration::days(29),
        reused_from: None,
        order_id: None,
        created_at: chrono::Utc::now() - chrono::Duration::days(1),
    };
    AcmeRepo::new()
        .insert_authorization(&fx.pool, &foreign_valid)
        .await
        .expect("seed account B's valid authorization");

    // Account A orders the SAME identifier.
    let (thumb_a, created_a) = create_account(&fx, rsa2048()).await;
    assert_eq!(created_a.status(), StatusCode::CREATED);
    let account_a = AcmeRepo::new()
        .get_account(&fx.pool, fx.tenant_id, &thumb_a)
        .await
        .expect("read account A")
        .expect("it exists");
    seed_profile(&fx, "web-server").await;
    let response = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "site.wardstone.test"}]}),
    )
    .await;
    let status = response.status();
    let order_id = Uuid::parse_str(&location_order_id(&response)).expect("the Location's id");
    let body = body_json(response).await;

    let authz_rows = AcmeRepo::new()
        .list_authorizations_by_order(&fx.pool, fx.tenant_id, order_id)
        .await
        .expect("read the order's authorizations");
    let created_audit = audit_rows(&fx, "acme_order_created").await;
    let authzs_after = authz_count(&fx).await;
    let foreign_after = AcmeRepo::new()
        .get_authorization(&fx.pool, fx.tenant_id, foreign_valid.id)
        .await
        .expect("read account B's row")
        .expect("it survives");

    fx.cleanup().await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(authz_rows.len(), 1, "a fresh order-scoped authz was minted");
    assert_eq!(
        authz_rows[0].account_id, account_a.id,
        "the fresh row belongs to ACCOUNT A"
    );
    assert_eq!(authz_rows[0].status, AcmeAuthorizationStatus::Pending);
    assert_eq!(
        body["authorizations"],
        json!([authz_url(authz_rows[0].id)]),
        "the order points at the NEW authz URL, never account B's"
    );
    assert_eq!(created_audit.len(), 1);
    assert_eq!(created_audit[0].4["reused_authorization_count"], 0);
    assert_eq!(created_audit[0].4["minted_authorization_count"], 1);
    assert_eq!(
        authzs_after, 2,
        "one row per account: nothing was reused across accounts"
    );
    assert_eq!(
        foreign_after.status,
        AcmeAuthorizationStatus::Valid,
        "account B's row is untouched"
    );
    assert!(foreign_after.order_id.is_none());
}

/// Fix round 1 (F1): RFC 8555 §7.1.6 has NO valid→invalid authorization
/// edge. Once http-01 settles the authorization valid (order ready), a
/// trigger on the still-pending dns-01 SIBLING is refused WITHOUT running
/// the verifier — the authz stays valid, the order stays ready, the
/// sibling row stays pending — while the settled challenge itself still
/// answers its standing object. Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn a_trigger_cannot_regress_a_valid_authorization() {
    let _db = lock_db().await;
    let stub = spawn_challenge_stub("placeholder");
    let fetcher = Arc::new(StubFetcher::new(HashMap::new()));
    let mut fx = fixture_with(FixtureConfig {
        public_url: Some(PUBLIC_URL),
        verification: Some(verification_deps(
            fetcher.clone(),
            Arc::new(StaticTxtResolver::new(HashMap::new())),
        )),
        ..FixtureConfig::default()
    })
    .await;
    let (order_id, authz_id, challenges) =
        mint_order_with_challenges(&fx, rsa2048(), "host.wardstone.test").await;
    let http_row = challenges
        .iter()
        .find(|c| c.challenge_type == AcmeChallengeType::Http01)
        .expect("the http-01 row")
        .clone();
    let dns_row = challenges
        .iter()
        .find(|c| c.challenge_type == AcmeChallengeType::Dns01)
        .expect("the dns-01 row")
        .clone();
    stub.set_body(ws_acme::key_authorization(
        &http_row.token,
        &thumb_of(rsa2048()),
    ));
    let (canonical, target) = http01_urls(&stub, &http_row.token);
    fetcher.set_rewrite(canonical, target);

    // http-01 settles the authz valid.
    let settle = post_chall(&fx, rsa2048(), http_row.id, json!({})).await;
    let settle_status = settle.status();
    let settle_body = body_json(settle).await;

    // The sibling trigger: refused, no verifier run (the authz is valid).
    let sibling = post_chall(&fx, rsa2048(), dns_row.id, json!({})).await;
    let sibling_status = sibling.status();
    let sibling_problem = body_json(sibling).await;

    // The settled challenge still answers its standing object.
    let settled = post_chall(&fx, rsa2048(), http_row.id, json!({})).await;
    let settled_status = settled.status();
    let settled_body = body_json(settled).await;

    let authz_row = AcmeRepo::new()
        .get_authorization(&fx.pool, fx.tenant_id, authz_id)
        .await
        .expect("read the authz")
        .expect("it exists");
    let order_row = AcmeRepo::new()
        .get_order(&fx.pool, fx.tenant_id, order_id)
        .await
        .expect("read the order")
        .expect("it exists");
    let sibling_after = AcmeRepo::new()
        .get_challenge(&fx.pool, fx.tenant_id, dns_row.id)
        .await
        .expect("read the sibling challenge")
        .expect("it exists");
    fx.cleanup().await;

    assert_eq!(settle_status, StatusCode::OK);
    assert_eq!(settle_body["status"], "valid");
    assert_eq!(sibling_status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        sibling_problem["type"],
        "urn:ietf:params:acme:error:unauthorized"
    );
    assert!(
        sibling_problem["detail"]
            .as_str()
            .expect("the refusal detail")
            .contains("already valid"),
        "the refusal names the standing state, got {:?}",
        sibling_problem["detail"]
    );
    assert_eq!(settled_status, StatusCode::OK);
    assert_eq!(settled_body["status"], "valid");
    assert_eq!(
        authz_row.status,
        AcmeAuthorizationStatus::Valid,
        "the authz cannot regress"
    );
    assert_eq!(
        order_row.status,
        AcmeOrderStatus::Ready,
        "the ready order cannot regress"
    );
    assert_eq!(
        sibling_after.status,
        AcmeChallengeStatus::Pending,
        "the sibling row is untouched"
    );
    assert_eq!(
        fetcher.calls(),
        1,
        "only the http-01 settle ever fetched: the sibling trigger ran no verifier"
    );
}

/// A new-account POST from a SPECIFIC peer IP: the per-account limiter
/// test needs the GCRA (per-IP) and the account limiter (per-account) in
/// one fixture, so the two account creations ride distinct peers.
async fn create_account_as_peer(fixture: &Fixture, key: &KeyFixture, ip: Ipv4Addr) -> TestResponse {
    let nonce = fetch_nonce(fixture).await;
    let jws = acme_common::sign_acme_request(
        key,
        &Identity::Jwk,
        &nonce,
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/new-account"),
        &json!({"termsOfServiceAgreed": true, "contact": [CONTACT]}),
    );
    send(
        fixture,
        with_peer(
            acme_post(&format!("/acme/{ACME_TENANT}/new-account"), &jws),
            ip,
            44444,
        ),
    )
    .await
}

/// Fix round 1 (F3), settlement D8: authenticated ACME is rate-limited
/// PER ACCOUNT — its own `AcmeConfig::acme_account_limit` knob (the auth
/// disable deliberately does not reach it); only new-account stays per-IP
/// GCRA, because no account exists to key on. Burst 1 with a 60s refill:
/// account A's SECOND POST — any
/// route, POST-as-GET included — is the 429 rateLimited problem, while
/// account B keeps its own bucket. Cleans up before asserting.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn authenticated_acme_routes_are_rate_limited_per_account() {
    let _db = lock_db().await;
    let mut fx = fixture_with(FixtureConfig {
        public_url: Some(PUBLIC_URL),
        rate_limit: Some(AuthRateLimit {
            per_millis: 60_000,
            burst: 1,
        }),
        ..FixtureConfig::default()
    })
    .await;

    let created_a = create_account_as_peer(&fx, rsa2048(), Ipv4Addr::new(127, 0, 0, 1)).await;
    assert_eq!(
        created_a.status(),
        StatusCode::CREATED,
        "account A enrols through its own GCRA bucket"
    );
    let created_b = create_account_as_peer(&fx, p256(), Ipv4Addr::new(127, 0, 0, 2)).await;
    assert_eq!(
        created_b.status(),
        StatusCode::CREATED,
        "account B enrols through ITS OWN GCRA bucket"
    );
    seed_profile(&fx, "web-server").await;

    // Account A's first POST: through (the bucket starts full).
    let first = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "a.wardstone.test"}]}),
    )
    .await;
    let first_status = first.status();
    let order_id = Uuid::parse_str(&location_order_id(&first)).expect("the Location's id");

    // Account A's second POST: the 429 rateLimited problem.
    let second = post_new_order(
        &fx,
        rsa2048(),
        json!({"identifiers": [{"type": "dns", "value": "b.wardstone.test"}]}),
    )
    .await;
    let second_status = second.status();
    let second_problem = body_json(second).await;

    // POST-as-GET rides the same bucket: still refused.
    let read = kid_post_as_get(
        &fx,
        rsa2048(),
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/orders/{order_id}"),
    )
    .await;
    let read_status = read.status();

    // Account B keeps its own bucket.
    let b_order = post_new_order(
        &fx,
        p256(),
        json!({"identifiers": [{"type": "dns", "value": "c.wardstone.test"}]}),
    )
    .await;
    let b_status = b_order.status();

    let orders_after = order_count(&fx).await;
    fx.cleanup().await;

    assert_eq!(first_status, StatusCode::CREATED);
    assert_eq!(second_status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        second_problem["type"],
        "urn:ietf:params:acme:error:rateLimited"
    );
    assert_eq!(
        read_status,
        StatusCode::TOO_MANY_REQUESTS,
        "POST-as-GET rides the same account bucket"
    );
    assert_eq!(b_status, StatusCode::CREATED, "the buckets are per-account");
    assert_eq!(orders_after, 2, "the refusals minted nothing");
}

// ---------------------------------------------------------------------------
// Finalize, certificate download, and revocation (Plan 4 Task 8): the
// issuance loop closes on the ACME surface
// ---------------------------------------------------------------------------

/// The CSR-minting idiom of api_test's helper, restated locally: a valid
/// ECDSA P-256 CSR (self-signed) for `cn` with DNS SANs `names`. The
/// issuing profile under these tests pins `ecdsa-p256`, satisfying the
/// signing leg's exact-algorithm rule.
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

/// The DER bytes of one PEM body (the PEMs the tests mint, download, and
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

/// A FULL issuing profile under the fixture tenant: "web-server" with
/// revision 1 as its CURRENT revision (`current_revision_id` forward-
/// referenced inside one transaction, the deferred FK blessing), pinned
/// `ecdsa-p256`, and the wardstone.test allow-list. The plain
/// [`seed_profile`] rows carry no revision — fine for new-order, but
/// finalize's issuance needs one.
async fn seed_issuing_profile(fixture: &Fixture, name: &str) {
    let profile_id = Uuid::new_v4();
    let revision_id = Uuid::new_v4();
    let mut tx = fixture
        .pool
        .begin()
        .await
        .expect("begin the profile seed transaction");
    ProfileRepo::new()
        .insert_profile(
            &mut *tx,
            &ProfileModel {
                id: profile_id,
                tenant_id: fixture.tenant_id,
                name: name.to_owned(),
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
                san_patterns: vec!["wardstone.test".to_owned(), "*.wardstone.test".to_owned()],
                is_legacy: false,
                created_at: chrono::Utc::now(),
                actor_id: "tests:acme".to_owned(),
            },
        )
        .await
        .expect("seed the revision row");
    tx.commit().await.expect("commit the profile seed");
}

/// A REAL root CA for the fixture tenant: the key minted into the fixture
/// keystore through `ws_ca::ca::create_root` (the issuance signing leg
/// loads it back) plus the `cas` row `choose_ca` needs. Returns the root
/// certificate PEM — the chain tail the download body must carry.
async fn seed_root_ca(fixture: &Fixture) -> String {
    let mut keystore = KeyStore::open(&fixture.keys_dir).expect("open the fixture keystore");
    let created = create_root(
        &CaSpec {
            name: "acme-test-root".to_owned(),
            subject: "Wardstone ACME Test Root".to_owned(),
            key_type: KeyType::Ed25519,
            lifetime: CaLifetime::Root,
        },
        &mut keystore,
    )
    .expect("create the root CA");
    CaRepo::new()
        .insert(
            &fixture.pool,
            &CaModel {
                id: created.key_pair_id,
                tenant_id: fixture.tenant_id,
                name: "acme-test-root".to_owned(),
                subject: "CN=Wardstone ACME Test Root".to_owned(),
                is_root: true,
                parent_id: None,
                key_type: KeyType::Ed25519,
                not_before: chrono::Utc::now(),
                not_after: chrono::Utc::now() + chrono::Duration::days(3650),
                cert_pem: created.cert_pem.clone(),
                key_file: "tests/acme-test-root".to_owned(),
                created_at: chrono::Utc::now(),
            },
        )
        .await
        .expect("insert the CA row");
    created.cert_pem
}

/// The Task-8 issuance prelude, up to a usable order machine: account +
/// issuing profile + root CA, all ONCE per fixture. Returns the root CA's
/// PEM (for the download-body chain assertion).
async fn setup_issuance(fixture: &Fixture, key: &KeyFixture) -> String {
    let (_thumb, created) = create_account(fixture, key).await;
    assert_eq!(created.status(), StatusCode::CREATED, "the account enrols");
    seed_issuing_profile(fixture, "web-server").await;
    seed_root_ca(fixture).await
}

/// One order on `identifier`, driven to `ready` by seeding the outcome
/// Task 7's verification produces: every order-scoped authorization
/// stamped `valid` (with the 30-day reuse window) and the order `ready`.
/// The finalize tests are about the ISSUANCE loop; the challenge path
/// that legitimately reaches these states has its own suite.
async fn mint_ready_order(fixture: &Fixture, key: &KeyFixture, identifier: &str) -> Uuid {
    let response = post_new_order(
        fixture,
        key,
        json!({"identifiers": [{"type": "dns", "value": identifier}]}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "the order mints");
    let order_id = Uuid::parse_str(&location_order_id(&response)).expect("the Location's id");
    let authz_rows = AcmeRepo::new()
        .list_authorizations_by_order(&fixture.pool, fixture.tenant_id, order_id)
        .await
        .expect("the order's authorizations");
    for authz in &authz_rows {
        AcmeRepo::new()
            .update_authorization_status(
                &fixture.pool,
                fixture.tenant_id,
                authz.id,
                AcmeAuthorizationStatus::Valid,
                Some(chrono::Utc::now() + chrono::Duration::days(30)),
            )
            .await
            .expect("stamp the authorization valid");
    }
    AcmeRepo::new()
        .update_order_status(
            &fixture.pool,
            fixture.tenant_id,
            order_id,
            AcmeOrderStatus::Ready,
            None,
            None,
        )
        .await
        .expect("stamp the order ready");
    order_id
}

/// A kid-signed finalize POST with the caller's payload.
async fn post_finalize(
    fixture: &Fixture,
    key: &KeyFixture,
    order_id: Uuid,
    payload: Value,
) -> TestResponse {
    let nonce = fetch_nonce(fixture).await;
    let jws = acme_common::sign_acme_request(
        key,
        &Identity::Kid(account_url(&thumb_of(key))),
        &nonce,
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/orders/{order_id}/finalize"),
        &payload,
    );
    send(
        fixture,
        acme_post(
            &format!("/acme/{ACME_TENANT}/orders/{order_id}/finalize"),
            &jws,
        ),
    )
    .await
}

/// A kid-signed revoke-cert POST with the caller's payload.
async fn post_revoke(fixture: &Fixture, key: &KeyFixture, payload: Value) -> TestResponse {
    let nonce = fetch_nonce(fixture).await;
    let jws = acme_common::sign_acme_request(
        key,
        &Identity::Kid(account_url(&thumb_of(key))),
        &nonce,
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/revoke-cert"),
        &payload,
    );
    send(
        fixture,
        acme_post(&format!("/acme/{ACME_TENANT}/revoke-cert"), &jws),
    )
    .await
}

/// Finalize an order with a self-minted CSR carrying exactly `identifier`
/// (CN and SAN), returning the `(status, body)` pair.
async fn finalize_with_csr(
    fixture: &Fixture,
    key: &KeyFixture,
    order_id: Uuid,
    identifier: &str,
) -> (StatusCode, Value) {
    let csr = mint_csr(identifier, &[identifier]);
    let response = post_finalize(fixture, key, order_id, json!({"csr": member_b64url(&csr)})).await;
    let status = response.status();
    let body = body_json(response).await;
    (status, body)
}

/// Review Focus 1-4 (the issuance loop): a `ready` order finalizes into a
/// `valid` one carrying the `certificate` member; the CSR is recorded on
/// the order row; the certificate row is the `acme` SOURCE with the
/// issued names; ONE `cert_issued` audit row attributes the issuance to
/// the ACME account; and the certificate URL serves `application/
/// pem-certificate-chain` with the leaf FIRST and the root CA after it.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn finalize_happy_path_issues_and_the_certificate_url_serves_the_chain() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let key = rsa2048();
    let root_pem = setup_issuance(&fx, key).await;
    let order_id = mint_ready_order(&fx, key, "finalize.wardstone.test").await;

    let (status, body) = finalize_with_csr(&fx, key, order_id, "finalize.wardstone.test").await;

    let order_row = AcmeRepo::new()
        .get_order(&fx.pool, fx.tenant_id, order_id)
        .await
        .expect("read the order row");
    let certificate_id = order_row.as_ref().and_then(|order| order.certificate_id);
    let cert_row = match certificate_id {
        Some(id) => CertificateRepo::new()
            .get(&fx.pool, id)
            .await
            .expect("read the certificate row"),
        None => None,
    };
    let audits = audit_rows(&fx, "cert_issued").await;
    let download = kid_post_as_get(
        &fx,
        key,
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/orders/{order_id}/certificate"),
    )
    .await;
    let download_status = download.status();
    let download_type = download
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|value| value.to_str().expect("ascii").to_owned());
    let download_body = body_text(download).await;
    fx.cleanup().await;

    assert_eq!(
        status,
        StatusCode::OK,
        "finalize accepts a ready order: {body}"
    );
    assert_eq!(body["status"], "valid");
    assert_eq!(
        body["certificate"],
        format!("{PUBLIC_URL}/acme/{ACME_TENANT}/orders/{order_id}/certificate")
    );
    let order_row = order_row.expect("the order row exists");
    assert_eq!(order_row.status, AcmeOrderStatus::Valid);
    assert!(order_row.csr_pem.is_some(), "the accepted CSR is recorded");
    let certificate_id = certificate_id.expect("the order carries its certificate id");
    let cert_row = cert_row.expect("the certificate row exists");
    assert_eq!(
        cert_row.source, "acme",
        "an ACME-issued certificate is the acme source"
    );
    assert_eq!(cert_row.status, CertStatus::Active);
    assert_eq!(cert_row.subject, "CN=finalize.wardstone.test");
    assert_eq!(cert_row.san_dns, vec!["finalize.wardstone.test".to_owned()]);
    assert_eq!(audits.len(), 1, "ONE cert_issued audit row");
    assert_eq!(
        audits[0].0, "acme_account",
        "the audit actor is the account"
    );
    assert_eq!(audits[0].1, "acme_account");
    assert_eq!(
        audits[0].3,
        certificate_id.to_string(),
        "the audit targets the certificate"
    );
    assert_eq!(download_status, StatusCode::OK, "the download serves");
    assert_eq!(
        download_type.as_deref(),
        Some("application/pem-certificate-chain")
    );
    let leaf_at = download_body
        .find(&cert_row.cert_pem)
        .expect("the leaf PEM in the download body");
    let root_at = download_body
        .find(&root_pem)
        .expect("the root PEM in the download body");
    assert!(
        leaf_at < root_at,
        "the chain body is leaf-first: leaf, then the CA chain"
    );
}

/// Review Focus 4: a SAN outside the profile's patterns never issues —
/// the problem document carries the SAME message the manual path returns
/// (`not_permitted_by_profile`'s generic form, because the ACME account
/// holds no `read_profiles`), and the order STAYS `ready` for the
/// client's retry (a failed finalize writes nothing).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn acme_finalize_respects_profile_san_policy() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let key = rsa2048();
    setup_issuance(&fx, key).await;
    let order_id = mint_ready_order(&fx, key, "outside.example.net").await;

    let (status, body) = finalize_with_csr(&fx, key, order_id, "outside.example.net").await;

    let poll = kid_post_as_get(&fx, key, &order_url(order_id)).await;
    let poll_body = body_json(poll).await;
    let audits = audit_rows(&fx, "cert_issued").await;
    fx.cleanup().await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["type"], "urn:ietf:params:acme:error:malformed");
    assert_eq!(
        body["detail"], "not permitted by policy",
        "the SAME message semantics the manual path returns"
    );
    assert_eq!(
        poll_body["status"], "ready",
        "a refused finalize leaves the order ready"
    );
    assert!(audits.is_empty(), "nothing was issued");
}

/// RFC 8555 §7.4's `badCSR` gate: a CSR whose identifiers differ from the
/// order's is refused and the order stays `ready`.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn finalize_refuses_a_csr_whose_identifiers_differ_from_the_order() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let key = rsa2048();
    setup_issuance(&fx, key).await;
    let order_id = mint_ready_order(&fx, key, "good.wardstone.test").await;

    // "elsewhere.wardstone.test" is PERMITTED by the profile's patterns —
    // the refusal is the order-consistency gate, not policy.
    let csr = mint_csr("elsewhere.wardstone.test", &["elsewhere.wardstone.test"]);
    let response = post_finalize(&fx, key, order_id, json!({"csr": member_b64url(&csr)})).await;
    let status = response.status();
    let body = body_json(response).await;

    let poll = kid_post_as_get(&fx, key, &order_url(order_id)).await;
    let poll_body = body_json(poll).await;
    let audits = audit_rows(&fx, "cert_issued").await;
    fx.cleanup().await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["type"], "urn:ietf:params:acme:error:badCSR");
    assert_eq!(
        poll_body["status"], "ready",
        "a badCSR leaves the order ready"
    );
    assert!(audits.is_empty(), "nothing was issued");
}

/// RFC 8555 §7.4: finalize on an order that is not `ready` answers the
/// 403 `orderNotReady` problem (a pending order's authorizations are not
/// settled yet).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn finalize_on_a_non_ready_order_answers_order_not_ready() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let key = rsa2048();
    setup_issuance(&fx, key).await;
    // mint_ready_order is NOT called: the order stays pending.
    let response = post_new_order(
        &fx,
        key,
        json!({"identifiers": [{"type": "dns", "value": "pending.wardstone.test"}]}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let order_id = Uuid::parse_str(&location_order_id(&response)).expect("the Location's id");

    let (status, body) = finalize_with_csr(&fx, key, order_id, "pending.wardstone.test").await;
    fx.cleanup().await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["type"], "urn:ietf:params:acme:error:orderNotReady");
}

/// The finalize request's CSR handling: a POST-as-GET, a payload without
/// a `csr` member, a non-base64url member, and a base64url value that is
/// not a PKCS#10 request are each refused (the last as `badCSR`), and
/// none of them writes anything.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn finalize_refuses_malformed_and_unparsable_csrs() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let key = rsa2048();
    setup_issuance(&fx, key).await;
    let order_id = mint_ready_order(&fx, key, "csr-shape.wardstone.test").await;

    let no_csr = post_finalize(&fx, key, order_id, json!({})).await;
    let no_csr_status = no_csr.status();
    let no_csr_body = body_json(no_csr).await;
    let not_b64 = post_finalize(&fx, key, order_id, json!({"csr": "!!!not-b64url"})).await;
    let not_b64_status = not_b64.status();
    let not_b64_body = body_json(not_b64).await;
    let not_pkcs10 = post_finalize(
        &fx,
        key,
        order_id,
        json!({"csr": URL_SAFE_NO_PAD.encode(b"definitely not a CSR")}),
    )
    .await;
    let not_pkcs10_status = not_pkcs10.status();
    let not_pkcs10_body = body_json(not_pkcs10).await;

    let poll = kid_post_as_get(&fx, key, &order_url(order_id)).await;
    let poll_body = body_json(poll).await;
    fx.cleanup().await;

    assert_eq!(no_csr_status, StatusCode::BAD_REQUEST);
    assert_eq!(no_csr_body["type"], "urn:ietf:params:acme:error:malformed");
    assert_eq!(not_b64_status, StatusCode::BAD_REQUEST);
    assert_eq!(not_b64_body["type"], "urn:ietf:params:acme:error:malformed");
    assert_eq!(not_pkcs10_status, StatusCode::BAD_REQUEST);
    assert_eq!(not_pkcs10_body["type"], "urn:ietf:params:acme:error:badCSR");
    assert_eq!(poll_body["status"], "ready", "nothing changed the order");
}

/// The certificate URL serves only a `valid` order: a pending order
/// answers 403 `orderNotReady`, an invalid one answers 403 carrying the
/// order's RECORDED error as the problem detail.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn an_order_without_a_certificate_refuses_the_download() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let key = rsa2048();
    setup_issuance(&fx, key).await;
    let response = post_new_order(
        &fx,
        key,
        json!({"identifiers": [{"type": "dns", "value": "no-cert.wardstone.test"}]}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let order_id = Uuid::parse_str(&location_order_id(&response)).expect("the Location's id");
    let certificate_url = format!("{PUBLIC_URL}/acme/{ACME_TENANT}/orders/{order_id}/certificate");

    let pending = kid_post_as_get(&fx, key, &certificate_url).await;
    let pending_status = pending.status();
    let pending_body = body_json(pending).await;

    AcmeRepo::new()
        .update_order_status(
            &fx.pool,
            fx.tenant_id,
            order_id,
            AcmeOrderStatus::Invalid,
            None,
            Some("the authorization for no-cert.wardstone.test failed: the fetch did not match"),
        )
        .await
        .expect("invalidate the order");
    let invalid = kid_post_as_get(&fx, key, &certificate_url).await;
    let invalid_status = invalid.status();
    let invalid_body = body_json(invalid).await;
    fx.cleanup().await;

    assert_eq!(pending_status, StatusCode::FORBIDDEN);
    assert_eq!(
        pending_body["type"],
        "urn:ietf:params:acme:error:orderNotReady"
    );
    assert_eq!(invalid_status, StatusCode::FORBIDDEN);
    assert_eq!(
        invalid_body["type"],
        "urn:ietf:params:acme:error:serverInternal"
    );
    assert!(
        invalid_body["detail"]
            .as_str()
            .expect("a detail string")
            .contains("no-cert.wardstone.test failed"),
        "the recorded error is the detail: {}",
        invalid_body["detail"]
    );
}

/// The revocation happy path: the issuing account's kid-keyed JWS with
/// the leaf's base64url DER revokes through the SAME machinery as the
/// manual route (typed reason stored; ONE `cert_revoked` audit row), a
/// second revocation of the same certificate is a problem-free idempotent
/// no-op, and the first revoke's stored reason stands.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn revoke_by_account_key_revokes_the_issued_certificate() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let key = rsa2048();
    setup_issuance(&fx, key).await;
    let order_id = mint_ready_order(&fx, key, "revoke-me.wardstone.test").await;
    let (finalize_status, finalize_body) =
        finalize_with_csr(&fx, key, order_id, "revoke-me.wardstone.test").await;
    assert_eq!(finalize_status, StatusCode::OK, "finalize: {finalize_body}");
    let certificate_id = AcmeRepo::new()
        .get_order(&fx.pool, fx.tenant_id, order_id)
        .await
        .expect("read the order row")
        .expect("the order exists")
        .certificate_id
        .expect("the certificate id");

    let member = {
        let cert_row = CertificateRepo::new()
            .get(&fx.pool, certificate_id)
            .await
            .expect("read the certificate row")
            .expect("the certificate exists");
        member_b64url(&cert_row.cert_pem)
    };
    let revoke = post_revoke(&fx, key, json!({"certificate": member, "reason": 1})).await;
    let revoke_status = revoke.status();
    let revoke_body = body_text(revoke).await;
    let after = CertificateRepo::new()
        .get(&fx.pool, certificate_id)
        .await
        .expect("read the certificate row after revoke")
        .expect("the certificate exists");
    let again = post_revoke(&fx, key, json!({"certificate": member, "reason": 4})).await;
    let again_status = again.status();
    let after_again = CertificateRepo::new()
        .get(&fx.pool, certificate_id)
        .await
        .expect("read the certificate row after the repeat")
        .expect("the certificate exists");
    let audits = audit_rows(&fx, "cert_revoked").await;
    fx.cleanup().await;

    assert_eq!(revoke_status, StatusCode::OK, "the revocation succeeds");
    assert_eq!(revoke_body, "", "the 200 body is empty (RFC 8555 §7.6)");
    assert_eq!(after.status, CertStatus::Revoked);
    assert_eq!(after.revocation_reason.as_deref(), Some("key_compromise"));
    assert_eq!(again_status, StatusCode::OK, "the repeat is idempotent");
    assert_eq!(
        after_again.revocation_reason.as_deref(),
        Some("key_compromise"),
        "the FIRST revoke's reason stands after the idempotent repeat"
    );
    assert_eq!(audits.len(), 1, "ONE cert_revoked audit row");
    assert_eq!(audits[0].0, "acme_account");
    assert_eq!(audits[0].3, certificate_id.to_string());
    assert_eq!(audits[0].4["reason"], "key_compromise");
}

/// The ACME reason integers map onto the typed enum 1:1 by name: 4 →
/// `superseded`, 8 → `privilege_withdrawn` (the RFC 8555 table's 8, which
/// the RFC 5280 register spells differently — this surface follows RFC
/// 8555), and an ABSENT reason → `unspecified`.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn acme_revocation_reasons_map_onto_the_typed_enum() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let key = rsa2048();
    setup_issuance(&fx, key).await;

    let mut revoked: Vec<(Option<String>, Option<String>)> = Vec::new();
    for (identifier, reason) in [
        ("r-superseded.wardstone.test", Some::<Value>(json!(4))),
        ("r-privilege.wardstone.test", Some(json!(8))),
        ("r-none.wardstone.test", None),
    ] {
        let order_id = mint_ready_order(&fx, key, identifier).await;
        let (status, body) = finalize_with_csr(&fx, key, order_id, identifier).await;
        assert_eq!(status, StatusCode::OK, "finalize {identifier}: {body}");
        let certificate_id = AcmeRepo::new()
            .get_order(&fx.pool, fx.tenant_id, order_id)
            .await
            .expect("read the order row")
            .expect("the order exists")
            .certificate_id
            .expect("the certificate id");
        let member = {
            let cert_row = CertificateRepo::new()
                .get(&fx.pool, certificate_id)
                .await
                .expect("read the certificate row")
                .expect("the certificate exists");
            member_b64url(&cert_row.cert_pem)
        };
        let mut payload = json!({"certificate": member});
        if let Some(reason) = reason {
            payload["reason"] = reason;
        }
        let revoke = post_revoke(&fx, key, payload).await;
        let revoke_status = revoke.status();
        let stored = CertificateRepo::new()
            .get(&fx.pool, certificate_id)
            .await
            .expect("read the certificate row")
            .expect("the certificate exists")
            .revocation_reason;
        revoked.push((Some(revoke_status.to_string()), stored));
        let _ = certificate_id; // captured through `revoked` below
    }
    fx.cleanup().await;

    assert_eq!(revoked[0].0.as_deref(), Some("200 OK"));
    assert_eq!(revoked[0].1.as_deref(), Some("superseded"));
    assert_eq!(revoked[1].1.as_deref(), Some("privilege_withdrawn"));
    assert_eq!(revoked[2].1.as_deref(), Some("unspecified"));
}

/// The remove-from-CRL reason (RFC 8555's integers 7 AND 10) is refused
/// with the `malformed` problem naming it: a Wardstone revocation is
/// terminal and no CRL/OCSP builder maps a `remove_from_crl` reason
/// extension. An unknown reason VALUE falls back to `unspecified` and
/// proceeds (here: to the ownership refusal, the certificate being
/// unknown).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn a_remove_from_crl_reason_is_refused() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let key = rsa2048();
    setup_issuance(&fx, key).await;
    let member = URL_SAFE_NO_PAD.encode(b"whatever bytes; the refusal precedes resolution");

    let seven = post_revoke(&fx, key, json!({"certificate": member, "reason": 7})).await;
    let seven_status = seven.status();
    let seven_body = body_json(seven).await;
    let ten = post_revoke(&fx, key, json!({"certificate": member, "reason": 10})).await;
    let ten_status = ten.status();
    let ten_body = body_json(ten).await;
    let unknown = post_revoke(&fx, key, json!({"certificate": member, "reason": 99})).await;
    let unknown_status = unknown.status();
    let unknown_body = body_json(unknown).await;
    let non_integer = post_revoke(
        &fx,
        key,
        json!({"certificate": member, "reason": "keyCompromise"}),
    )
    .await;
    let non_integer_status = non_integer.status();
    fx.cleanup().await;

    assert_eq!(seven_status, StatusCode::BAD_REQUEST);
    assert_eq!(seven_body["type"], "urn:ietf:params:acme:error:malformed");
    assert!(
        seven_body["detail"]
            .as_str()
            .expect("detail")
            .contains("remove-from-CRL"),
        "the refusal names the reason: {}",
        seven_body["detail"]
    );
    assert_eq!(ten_status, StatusCode::BAD_REQUEST);
    assert_eq!(ten_body["type"], "urn:ietf:params:acme:error:malformed");
    assert_eq!(
        unknown_status,
        StatusCode::UNAUTHORIZED,
        "an unknown reason value falls back to unspecified and proceeds"
    );
    assert_eq!(
        unknown_body["type"],
        "urn:ietf:params:acme:error:unauthorized"
    );
    assert_eq!(
        non_integer_status,
        StatusCode::UNAUTHORIZED,
        "a non-integer reason member is leniently unspecified, never a 400"
    );
}

/// The D7 authorization settlement: a certificate another account issued
/// (or an unknown one) earns the ONE 401 `unauthorized` problem — no
/// existence oracle.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn revoke_refuses_certificates_outside_the_account() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let key_a = rsa2048();
    let ca_pem = setup_issuance(&fx, key_a).await;
    let order_id = mint_ready_order(&fx, key_a, "revoke-a.wardstone.test").await;
    let (status, body) = finalize_with_csr(&fx, key_a, order_id, "revoke-a.wardstone.test").await;
    assert_eq!(status, StatusCode::OK, "A finalizes: {body}");
    let certificate_id = AcmeRepo::new()
        .get_order(&fx.pool, fx.tenant_id, order_id)
        .await
        .expect("read the order row")
        .expect("the order exists")
        .certificate_id
        .expect("the certificate id");
    let member = {
        let cert_row = CertificateRepo::new()
            .get(&fx.pool, certificate_id)
            .await
            .expect("read the certificate row")
            .expect("the certificate exists");
        member_b64url(&cert_row.cert_pem)
    };

    let key_b = p256();
    let (_thumb_b, created_b) = create_account(&fx, key_b).await;
    assert_eq!(created_b.status(), StatusCode::CREATED);
    let foreign = post_revoke(&fx, key_b, json!({"certificate": member, "reason": 1})).await;
    let foreign_status = foreign.status();
    let foreign_body = body_json(foreign).await;
    let unknown = post_revoke(
        &fx,
        key_b,
        json!({"certificate": URL_SAFE_NO_PAD.encode(b"unknown certificate bytes"), "reason": 1}),
    )
    .await;
    let unknown_status = unknown.status();
    let unknown_body = body_json(unknown).await;

    let cert_after = CertificateRepo::new()
        .get(&fx.pool, certificate_id)
        .await
        .expect("read the certificate row")
        .expect("the certificate exists");
    fx.cleanup().await;

    let _ = ca_pem; // chain context only
    assert_eq!(foreign_status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        foreign_body["type"], "urn:ietf:params:acme:error:unauthorized",
        "another account's certificate is indistinguishable from an unknown one"
    );
    assert_eq!(unknown_status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        unknown_body["type"],
        "urn:ietf:params:acme:error:unauthorized"
    );
    assert_eq!(
        cert_after.status,
        CertStatus::Active,
        "the refusals touch nothing"
    );
}

/// Settlement D7: a certificate-key proof-of-possession JWS (embedded
/// jwk, no account kid) is DECLINED for revocation — the 400
/// `unauthorized` problem names `cert_key_pop_declined`, and the
/// certificate stays as it was.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn a_certificate_key_jws_cannot_revoke() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let key = rsa2048();
    setup_issuance(&fx, key).await;
    let order_id = mint_ready_order(&fx, key, "pop-declined.wardstone.test").await;
    let (status, body) = finalize_with_csr(&fx, key, order_id, "pop-declined.wardstone.test").await;
    assert_eq!(status, StatusCode::OK, "finalize: {body}");
    let certificate_id = AcmeRepo::new()
        .get_order(&fx.pool, fx.tenant_id, order_id)
        .await
        .expect("read the order row")
        .expect("the order exists")
        .certificate_id
        .expect("the certificate id");
    let member = {
        let cert_row = CertificateRepo::new()
            .get(&fx.pool, certificate_id)
            .await
            .expect("read the certificate row")
            .expect("the certificate exists");
        member_b64url(&cert_row.cert_pem)
    };

    // A FRESH key signs the revocation with its key EMBEDDED (the RFC
    // 8555 §6.2/§7.6 cert-key shape); it holds no account kid.
    let pop_key = ed25519();
    let nonce = fetch_nonce(&fx).await;
    let jws = acme_common::sign_acme_request(
        pop_key,
        &Identity::Jwk,
        &nonce,
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/revoke-cert"),
        &json!({"certificate": member, "reason": 1}),
    );
    let pop = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/revoke-cert"), &jws),
    )
    .await;
    let pop_status = pop.status();
    let pop_body = body_json(pop).await;
    let cert_after = CertificateRepo::new()
        .get(&fx.pool, certificate_id)
        .await
        .expect("read the certificate row")
        .expect("the certificate exists");
    fx.cleanup().await;

    assert_eq!(pop_status, StatusCode::BAD_REQUEST);
    assert_eq!(pop_body["type"], "urn:ietf:params:acme:error:unauthorized");
    assert!(
        pop_body["detail"]
            .as_str()
            .expect("detail")
            .contains("cert_key_pop_declined"),
        "the decline names the settlement: {}",
        pop_body["detail"]
    );
    assert_eq!(cert_after.status, CertStatus::Active, "nothing was revoked");
}

/// Review Focus 3's carried half (deferred from Task 5): a kid that does
/// not name an account URL of THIS tenant never resolves — the 404
/// `accountDoesNotExist` lookup failure, never a cross-tenant account.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn a_kid_from_another_tenant_fails_the_lookup() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let key = rsa2048();
    let (_thumb, created) = create_account(&fx, key).await;
    assert_eq!(created.status(), StatusCode::CREATED);

    let other_tenant_kid = format!("{PUBLIC_URL}/acme/other-tenant/acct/{}", thumb_of(key));
    let nonce = fetch_nonce(&fx).await;
    let jws = acme_common::sign_acme_request(
        key,
        &Identity::Kid(other_tenant_kid),
        &nonce,
        &format!("{PUBLIC_URL}/acme/{ACME_TENANT}/new-order"),
        &json!({"identifiers": [{"type": "dns", "value": "x.wardstone.test"}]}),
    );
    let response = send(
        &fx,
        acme_post(&format!("/acme/{ACME_TENANT}/new-order"), &jws),
    )
    .await;
    let status = response.status();
    let body = body_json(response).await;
    fx.cleanup().await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        body["type"], "urn:ietf:params:acme:error:accountDoesNotExist",
        "a foreign-tenant kid is a lookup failure, never a cross-tenant account"
    );
}
