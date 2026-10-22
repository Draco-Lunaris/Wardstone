//! Integration tests for the OIDC provider-configuration routes (Plan 3
//! Task 5): `GET`/`PUT`/`DELETE` `/api/v1/oidc/config` and
//! `POST /api/v1/oidc/config/test`.
//!
//! These tests run against a live Postgres and are marked `#[ignore]`.
//! Run them with:
//!
//! ```sh
//! DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test \
//!     cargo test -p ws-api --test oidc_test -- --include-ignored
//! ```
//!
//! # Self-cleaning contract
//!
//! The shared `wardstone_test` database is used by the other DB-gated
//! suites. Every test sweeps away rows a previously crashed run may have
//! left behind under this suite's owned tenant name, and every row
//! inserted during the body is deleted *before* the assertions run, so a
//! failing assertion cannot leave rows behind. All query results are
//! captured and unwrapped only after cleanup.
//!
//! # Cross-process serialization
//!
//! Each test body holds a session-level Postgres advisory lock for its
//! whole duration on the key [`ADVISORY_KEY`] — the "WARDST" family
//! (ASCII "WARDST" = 0x5741445354) with suite marker 0x0012 (0x0003-0x0011
//! are taken by the older suites; this is the plan's fresh allocation).
//! The in-process mutex mirrors the other suites' pattern.
//!
//! # Network isolation
//!
//! No test reaches an external network. The discovery-failure paths use
//! `http://127.0.0.1:9/...` (connect refused, fast — no 10 s timeout); the
//! success path uses a one-shot loopback HTTP server on an ephemeral port
//! serving a static discovery document. The `client_secret` asserted in
//! some payloads is test fixture material only.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use axum::http::{header, HeaderValue, Request, StatusCode};
use axum::Router;
use serde_json::{json, Value};
use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex as TokioMutex;
use tower::ServiceExt;
use uuid::Uuid;

use ws_api::{ApiConfig, AppState};
use ws_auth::jwt::{issue_access_token, AccessClaims, JwtKeys};
use ws_core::db::connect;
use ws_core::models::rbac::Role;
use ws_core::repo::user_repo::UserRepo;

/// The response type the test helpers return.
type TestResponse = axum::http::Response<axum::body::Body>;

/// Postgres advisory-lock key for this suite: ASCII "WARDST" (0x5741445354)
/// plus the suite marker 0x0012.
const ADVISORY_KEY: i64 = 0x0057_4144_5354_0012;

/// The tenant name this suite owns; swept before use, deleted at the end.
const OIDC_TENANT: &str = "rt-oidc-tenant";

/// The static discovery document the loopback server serves; the
/// positive-path tests assert its `issuer` round-trips.
const DISCOVERY_JSON: &str = "{\"issuer\":\"https://sso.wardstone.test/realms/wardstone\",\
     \"authorization_endpoint\":\"https://sso.wardstone.test/realms/wardstone/authorize\",\
     \"token_endpoint\":\"https://sso.wardstone.test/realms/wardstone/token\",\
     \"jwks_uri\":\"https://sso.wardstone.test/realms/wardstone/certs\"}";

/// A connect-refused URL: port 9, where nothing listens — the fast
/// failure shape `discover()` reports (connect refused in milliseconds,
/// well inside ws-auth's 10 s client timeout).
const UNREACHABLE_DISCOVERY_URL: &str = "http://127.0.0.1:9/.well-known/openid-configuration";

/// In-process serialization, the same whole-body lock pattern as the
/// other DB-gated suites.
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
/// connection.
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

/// A per-test fixture: the app state, the built router, the fixture tenant
/// and admin user, and the held advisory-lock connection.
struct Fixture {
    state: AppState,
    router: Router,
    pool: PgPool,
    tenant_id: Uuid,
    admin_id: Uuid,
    #[allow(dead_code)] // held for the whole body: serializes this suite
    advisory: Option<PoolConnection<sqlx::Postgres>>,
    keys_dir: PathBuf,
}

impl Fixture {
    /// Delete every row this fixture (and the test body) created, then
    /// release the advisory lock. Runs BEFORE the assertions, so a failing
    /// assert can never leave rows behind (the self-cleaning contract).
    async fn cleanup(&mut self) {
        for table in [
            "DELETE FROM audit_log WHERE tenant_id = $1",
            "DELETE FROM oidc_config WHERE tenant_id = $1",
            "DELETE FROM refresh_tokens WHERE tenant_id = $1",
            "DELETE FROM users WHERE tenant_id = $1",
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
        // The per-fixture keys directory (JWT key pair).
        let _ = std::fs::remove_dir_all(&self.keys_dir);
    }
}

/// Build the fixture: connect, take the advisory lock, sweep stale rows,
/// insert the tenant + admin user, mint the admin access token, and build
/// the router.
async fn fixture() -> Fixture {
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    // Sweep-first: stale rows of a previously crashed run under the owned
    // tenant name.
    sweep_tenant(&pool, OIDC_TENANT).await;

    let tenant_id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(tenant_id)
        .bind(OIDC_TENANT)
        .execute(&pool)
        .await
        .expect("insert fixture tenant");

    let admin_id = Uuid::new_v4();
    insert_user(&pool, tenant_id, admin_id).await;

    let keys_dir = std::env::temp_dir().join(format!(
        "ws-api-oidc-test-keys-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    let jwt = JwtKeys::load_or_create(&keys_dir).expect("load or create the JWT key pair");

    let config = ApiConfig::new("wardstone.test".to_string(), keys_dir.clone());
    let state = AppState::new(pool.clone(), Arc::new(jwt), config);
    let router = ws_api::router(state.clone());

    Fixture {
        state: state.clone(),
        router,
        pool,
        tenant_id,
        admin_id,
        advisory: Some(advisory),
        keys_dir,
    }
}

/// Delete every row a previous run may have left under `name` (children
/// first, then the tenant).
async fn sweep_tenant(pool: &PgPool, name: &str) {
    sqlx::query(
        "DELETE FROM audit_log WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
    )
    .bind(name)
    .execute(pool)
    .await
    .expect("sweep stale audit rows");
    for table in [
        "DELETE FROM certificates WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM one_shot_tokens WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM service_identity_capabilities WHERE service_identity_id IN \
         (SELECT id FROM service_identities WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1))",
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

/// A minimal, active admin user row (no password).
async fn insert_user(pool: &PgPool, tenant_id: Uuid, id: Uuid) {
    UserRepo::new()
        .insert(
            pool,
            &ws_core::models::user::UserModel {
                id,
                tenant_id,
                username: "admin".to_string(),
                display_name: "admin".to_string(),
                email: "admin@wardstone.test".to_string(),
                role: Role::Admin,
                auth_provider: "local".to_string(),
                password_hash: None,
                totp_secret_encrypted: None,
                totp_secret_nonce: None,
                webauthn_credential: None,
                mfa_enabled: false,
                azure_oid: None,
                oidc_sub: None,
                is_active: true,
                force_password_reset: false,
                failed_login_attempts: 0,
                locked_until: None,
                last_login_at: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            },
        )
        .await
        .expect("insert fixture user");
}

/// Mint a session access token for the fixture's admin user (the bearer
/// shape the middleware resolves; the router itself needs no other state).
fn admin_token(fixture: &Fixture) -> String {
    let claims = AccessClaims::new(fixture.admin_id, "admin", "admin", None, 900);
    issue_access_token(&claims, &fixture.state.jwt).expect("issue the admin access token")
}

/// Send a request to the fixture router and return the response.
async fn send(fixture: &Fixture, request: Request<axum::body::Body>) -> TestResponse {
    fixture
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("the router should respond")
}

fn bearer(value: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("Bearer {value}")).expect("valid header value")
}

/// A GET request with an `Authorization: Bearer <token>` header.
async fn get_bearer(fixture: &Fixture, uri: &str, token: &str) -> TestResponse {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::AUTHORIZATION, bearer(token))
        .body(axum::body::Body::empty())
        .expect("build request");
    send(fixture, req).await
}

/// A DELETE request with an `Authorization: Bearer <token>` header.
async fn delete_bearer(fixture: &Fixture, uri: &str, token: &str) -> TestResponse {
    let req = Request::builder()
        .method("DELETE")
        .uri(uri)
        .header(header::AUTHORIZATION, bearer(token))
        .body(axum::body::Body::empty())
        .expect("build request");
    send(fixture, req).await
}

/// A POST request with a JSON body and (optional) bearer header.
async fn post_json(
    fixture: &Fixture,
    uri: &str,
    token: Option<&str>,
    body: serde_json::Value,
) -> TestResponse {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, bearer(token));
    }
    let req = builder
        .body(axum::body::Body::from(body.to_string()))
        .expect("build request");
    send(fixture, req).await
}

/// A POST request with NO JSON body at all (the saved-config probe).
async fn post_empty(fixture: &Fixture, uri: &str, token: &str) -> TestResponse {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::AUTHORIZATION, bearer(token))
        .body(axum::body::Body::empty())
        .expect("build request");
    send(fixture, req).await
}

/// A PUT request with a JSON body and (optional) bearer header.
async fn put_json(
    fixture: &Fixture,
    uri: &str,
    token: Option<&str>,
    body: serde_json::Value,
) -> TestResponse {
    let mut builder = Request::builder()
        .method("PUT")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, bearer(token));
    }
    let req = builder
        .body(axum::body::Body::from(body.to_string()))
        .expect("build request");
    send(fixture, req).await
}

/// A response body as JSON (only for responses that carry one).
async fn json_body(res: TestResponse) -> Value {
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .expect("read the response body");
    serde_json::from_slice(&bytes).expect("a json body")
}

/// Read a JSON error body's `error.code`.
fn error_code(body: &Value) -> String {
    body["error"]["code"]
        .as_str()
        .expect("error body carries an error.code")
        .to_string()
}

/// Read a JSON error body's `error.message`.
fn error_message(body: &Value) -> String {
    body["error"]["message"]
        .as_str()
        .expect("error body carries an error.message")
        .to_string()
}

/// The audit rows of the fixture tenant, in write order (the target
/// tuple the config routes write).
async fn audit_rows(fixture: &Fixture) -> Vec<(String, String, String, Value)> {
    sqlx::query_as::<_, (String, String, String, Value)>(
        "SELECT action, target_type, target_id, details FROM audit_log \
         WHERE tenant_id = $1 ORDER BY created_at, id",
    )
    .bind(fixture.tenant_id)
    .fetch_all(&fixture.pool)
    .await
    .expect("read audit rows")
}

/// A complete, valid provider payload. Tests mutate the returned object
/// for the individual negative cases.
fn config_body() -> Value {
    json!({
        "provider_type": "keycloak",
        "display_name": "House Keycloak",
        "discovery_url": "https://sso.wardstone.test/realms/wardstone/.well-known/openid-configuration",
        "client_id": "wardstone",
        "client_secret": "ws_test_secret_material",
        "redirect_uri": "https://ca.wardstone.test/api/v1/auth/oidc/keycloak/callback",
        "scopes": "openid profile email"
    })
}

/// Spawn the loopback discovery server and return its
/// `/.well-known/openid-configuration` URL. A blocking std-net thread —
/// the same shape ws-auth's OIDC suite serves its provider stubs with —
/// that answers every request with the static discovery document. Runtime
/// independent, and it lives for the whole test process (loopback-only
/// material; no explicit teardown).
fn spawn_discovery_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the loopback discovery server");
    let port = listener.local_addr().expect("local addr").port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).unwrap_or(0);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                DISCOVERY_JSON.len(),
                DISCOVERY_JSON
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    });
    format!("http://127.0.0.1:{port}/.well-known/openid-configuration")
}

// ---------------------------------------------------------------------------
// The required tests
// ---------------------------------------------------------------------------

/// GET with nothing configured is 404 (SSO is simply not enabled yet).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn get_unconfigured_is_404() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let res = get_bearer(&fx, "/api/v1/oidc/config", &admin_token(&fx)).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body = json_body(res).await;
    assert_eq!(error_code(&body), "not_found");

    fx.cleanup().await;
}

/// A valid PUT round-trips through GET; `client_secret_set` is true and
/// the secret material appears NOWHERE in the responses, which carry
/// `Cache-Control: no-store`.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn put_roundtrips_and_never_exposes_the_secret() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);

    let res = put_json(&fx, "/api/v1/oidc/config", Some(&token), config_body()).await;
    assert_eq!(res.status(), StatusCode::OK, "the put must succeed");
    assert_eq!(
        res.headers()
            .get(header::CACHE_CONTROL)
            .map(|v| v.to_str().expect("header text")),
        Some("no-store"),
        "the PUT response is no-store"
    );

    let res = get_bearer(&fx, "/api/v1/oidc/config", &token).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(header::CACHE_CONTROL)
            .map(|v| v.to_str().expect("header text")),
        Some("no-store"),
        "the GET response is no-store"
    );
    let body = json_body(res).await;
    fx.cleanup().await;

    let sent = config_body();
    assert_eq!(body["provider_type"], sent["provider_type"]);
    assert_eq!(body["display_name"], sent["display_name"]);
    assert_eq!(body["discovery_url"], sent["discovery_url"]);
    assert_eq!(body["client_id"], sent["client_id"]);
    assert_eq!(body["redirect_uri"], sent["redirect_uri"]);
    assert_eq!(body["scopes"], sent["scopes"]);
    assert_eq!(body["client_secret_set"], true);
    assert!(
        body.get("client_secret").is_none(),
        "no client_secret field on the read response"
    );
    assert!(
        !serde_json::to_string(&body)
            .expect("serialize the read DTO")
            .contains("ws_test_secret_material"),
        "no secret material anywhere in the read response"
    );
}

/// PUT with `client_secret: null` on an EXISTING row keeps the stored
/// secret (`client_secret_set` stays true — the row it replaces carried
/// one, and `None` means keep, not clear).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn put_null_secret_keeps_the_stored_secret() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);

    let mut first = config_body();
    let res = put_json(&fx, "/api/v1/oidc/config", Some(&token), first.clone()).await;
    assert_eq!(res.status(), StatusCode::OK, "first put must succeed");
    first["client_secret"] = Value::Null;
    let res = put_json(&fx, "/api/v1/oidc/config", Some(&token), first).await;
    assert_eq!(res.status(), StatusCode::OK, "null-secret put must succeed");
    let second_set = json_body(res).await["client_secret_set"].clone();

    let res = get_bearer(&fx, "/api/v1/oidc/config", &token).await;
    let read = json_body(res).await;
    fx.cleanup().await;

    assert_eq!(second_set, true, "the replaced row still carries a secret");
    assert_eq!(read["client_secret_set"], true);
}

/// `client_secret: null` on a NEW row is 400 — nothing to keep it with.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn put_null_secret_on_a_new_row_is_400() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);

    let mut body = config_body();
    body["client_secret"] = Value::Null;
    let res = put_json(&fx, "/api/v1/oidc/config", Some(&token), body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let error = json_body(res).await;
    fx.cleanup().await;

    assert_eq!(error_code(&error), "bad_request");
    assert!(error_message(&error).contains("client_secret"));
}

/// A provider_type outside the migration's CHECK vocabulary is 400 (an
/// `okta` value never reaches the database as a typed error).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn unknown_provider_type_is_400() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);

    let mut body = config_body();
    body["provider_type"] = json!("okta");
    let res = put_json(&fx, "/api/v1/oidc/config", Some(&token), body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let error = json_body(res).await;
    fx.cleanup().await;

    assert_eq!(error_code(&error), "bad_request");
    assert!(error_message(&error).contains("keycloak, azure, custom"));
}

/// A non-https redirect_uri is 400 — the redirect carries the
/// authorization code, and a downgraded scheme would leak it.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn non_https_redirect_uri_is_400() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);

    let mut body = config_body();
    body["redirect_uri"] = json!("http://ca.wardstone.test/callback");
    let res = put_json(&fx, "/api/v1/oidc/config", Some(&token), body).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let error = json_body(res).await;
    fx.cleanup().await;

    assert_eq!(error_code(&error), "bad_request");
    assert!(error_message(&error).contains("https"));
}

/// DELETE on nothing configured is 404 (the route's decision); a
/// configured row deletes to 204 with GET 404 afterwards; the lifecycle
/// leaves ONE `oidc_config_updated` row and ONE `oidc_config_removed`
/// row, target-type `oidc_config`, target-id the tenant, details without
/// any secret material.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn delete_lifecycle_is_204_and_audited() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);

    let res = delete_bearer(&fx, "/api/v1/oidc/config", &token).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "nothing to delete yet");
    let res = put_json(&fx, "/api/v1/oidc/config", Some(&token), config_body()).await;
    assert_eq!(res.status(), StatusCode::OK, "the put must succeed");
    let res = delete_bearer(&fx, "/api/v1/oidc/config", &token).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let res = get_bearer(&fx, "/api/v1/oidc/config", &token).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "deleted means 404");

    let rows = audit_rows(&fx).await;
    fx.cleanup().await;

    let updated: Vec<_> = rows
        .iter()
        .filter(|(a, ..)| a == "oidc_config_updated")
        .collect();
    let removed: Vec<_> = rows
        .iter()
        .filter(|(a, ..)| a == "oidc_config_removed")
        .collect();
    assert_eq!(updated.len(), 1, "exactly one oidc_config_updated row");
    assert_eq!(removed.len(), 1, "exactly one oidc_config_removed row");
    for (_action, target_type, target_id, details) in rows
        .iter()
        .filter(|(action, ..)| action.starts_with("oidc_config"))
    {
        assert_eq!(target_type.to_string(), "oidc_config");
        assert_eq!(target_id.to_string(), fx.tenant_id.to_string());
        assert_eq!(details["provider_type"], "keycloak");
        assert_eq!(details["discovery_url"], config_body()["discovery_url"]);
        assert!(
            !details.to_string().contains("ws_test_secret_material"),
            "no secret material in the audit details"
        );
    }
}

/// The test route probes the SAVED configuration when the body carries no
/// override: an unreachable discovery URL fails as 400 `bad_request` with
/// the `AuthError` display — and the same for an override body, which
/// wins over the saved configuration.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn test_route_reports_discovery_failure_as_400() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);

    let mut body = config_body();
    body["discovery_url"] = json!(UNREACHABLE_DISCOVERY_URL);
    let res = put_json(&fx, "/api/v1/oidc/config", Some(&token), body.clone()).await;
    assert_eq!(res.status(), StatusCode::OK, "saved config must succeed");

    let res = post_empty(&fx, "/api/v1/oidc/config/test", &token).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let error = json_body(res).await;
    assert_eq!(error_code(&error), "bad_request");
    assert!(
        error_message(&error)
            .starts_with("configuration error: failed to fetch OIDC discovery document"),
        "the probe's message is the AuthError display: {}",
        error_message(&error)
    );
    assert!(
        !error_message(&error).contains("ws_test_secret_material"),
        "the probe's message never carries the secret"
    );

    // An override wins over the saved configuration: the probe uses its
    // (also unreachable) discovery URL.
    let res = post_json(
        &fx,
        "/api/v1/oidc/config/test",
        Some(&token),
        json!({ "override": body }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "override is probed");

    fx.cleanup().await;
}

/// The positive path: the test route reaches a LIVE discovery document
/// served by the loopback fixture server — first against the saved
/// configuration, then against an override payload — and the issuer
/// round-trips. No external network is touched.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn test_route_roundtrips_a_local_discovery_document() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);
    let discovery_url = spawn_discovery_server();

    let mut saved = config_body();
    saved["discovery_url"] = json!(discovery_url.clone());
    let res = put_json(&fx, "/api/v1/oidc/config", Some(&token), saved).await;
    assert_eq!(res.status(), StatusCode::OK, "saved config must succeed");

    let res = post_empty(&fx, "/api/v1/oidc/config/test", &token).await;
    let status = res.status();
    let cache_control = res
        .headers()
        .get(header::CACHE_CONTROL)
        .map(|v| v.to_str().expect("header text").to_string());
    let probe = json_body(res).await;
    assert_eq!(status, StatusCode::OK, "saved-config probe body: {probe}");
    assert_eq!(cache_control.as_deref(), Some("no-store"));
    assert_eq!(
        probe["issuer"],
        "https://sso.wardstone.test/realms/wardstone"
    );
    assert_eq!(
        probe["authorization_endpoint"],
        "https://sso.wardstone.test/realms/wardstone/authorize"
    );
    assert_eq!(
        probe["authorization_endpoint"],
        "https://sso.wardstone.test/realms/wardstone/authorize"
    );

    // The override path: probe an unsaved payload against the same live
    // local server.
    let mut override_payload = config_body();
    override_payload["provider_type"] = json!("custom");
    override_payload["discovery_url"] = json!(discovery_url);
    let res = post_json(
        &fx,
        "/api/v1/oidc/config/test",
        Some(&token),
        json!({ "override": override_payload }),
    )
    .await;
    let status = res.status();
    let probe = json_body(res).await;
    assert_eq!(status, StatusCode::OK, "override probe body: {probe}");

    fx.cleanup().await;
    assert_eq!(
        probe["issuer"],
        "https://sso.wardstone.test/realms/wardstone"
    );
}
