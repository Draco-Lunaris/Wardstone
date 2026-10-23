//! Integration tests for the ACME (RFC 8555) route surface (Plan-4
//! Task 5): directory, new-nonce, new-account (the ToS gate and
//! only-return-existing included), the account URL (POST-as-GET, update,
//! deactivation with its cascade), and the atomic account-key rollover.
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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::OnceLock;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Value};
use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex as TokioMutex;
use tower::ServiceExt;
use uuid::Uuid;

use ws_api::{AcmeConfig, ApiConfig, AppState, AuthRateLimit};
use ws_auth::jwt::JwtKeys;
use ws_core::db::connect;
use ws_core::models::acme::{
    AcmeAuthorizationModel, AcmeAuthorizationStatus, AcmeOrderModel, AcmeOrderStatus,
};
use ws_core::repo::acme_repo::AcmeRepo;

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
    /// accounts), then the audit log, then the tenant.
    async fn cleanup(&mut self) {
        for table in [
            "DELETE FROM acme_challenges WHERE tenant_id = $1",
            "DELETE FROM acme_authorizations WHERE tenant_id = $1",
            "DELETE FROM acme_orders WHERE tenant_id = $1",
            "DELETE FROM acme_accounts WHERE tenant_id = $1",
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

/// The fixture's config shape: the ACME `tos_url`, the new-account GCRA,
/// and the `public_url` (None = the unconfigured degrade posture).
#[derive(Default)]
struct FixtureConfig<'a> {
    tos_url: Option<&'a str>,
    rate_limit: Option<AuthRateLimit>,
    public_url: Option<&'a str>,
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
    };
    api_config.auth_rate_limit = config.rate_limit;
    let state = AppState::new(pool.clone(), std::sync::Arc::new(jwt), api_config);
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
/// first, then the tenant).
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
