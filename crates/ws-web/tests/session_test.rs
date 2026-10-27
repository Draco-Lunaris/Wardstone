//! Task 12 integration suite: the server-side session relay. The browser
//! NEVER holds a token — ws-web mints the `wardstone_session` cookie at
//! login, holds the JWT pair in its own memory store, injects
//! `Authorization: Bearer <access>` on every proxied request, rotates a
//! dead access token through ONE ws-api refresh under the per-session
//! lock, and revokes/clears on logout.
//!
//! The suite spawns ws-api's REAL router on an ephemeral loopback listener
//! (`axum::serve`, plain HTTP — unlike ws-auth's blocking-socket stubs,
//! which only serve fixtures, this listener carries real request routing)
//! with `auth_rate_limit: None`, then drives ws-web's composed router
//! (`web_router_with_store`: the relay routes, the proxy with the SAME
//! `Arc<SessionStore>`, and the SPA fallback) through `tower`'s oneshot.
//!
//! Concurrency assertions ride a counting middleware layered around the
//! local ws-api router: it tallies `POST /api/v1/auth/refresh` calls, so
//! the Review-Focus test can pin EXACTLY ONE refresh while two concurrent
//! expired probes both succeed.
//!
//! Run against the shared dev Postgres:
//!
//! ```sh
//! DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test \
//!     cargo test -p ws-web --test session_test -- --include-ignored
//! ```
//!
//! # Self-cleaning contract
//!
//! The suite's advisory key is `0x0057_4144_5354_0013` (the "WARDST" family
//! 0x5741445354, plan-allocated marker 0x0013). Each test: sweep-first
//! (children, then the tenant), hold the session-level advisory lock across
//! the body, and delete every created row (and the keys directory) at the
//! end. The in-process tokio mutex mirrors the house pattern.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::TcpListener as StdTcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, Method, Request as HttpRequest, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::Router;
use serde_json::{json, Value};
use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex as TokioMutex;
use tower::ServiceExt;
use uuid::Uuid;

use ws_api::state::{ApiConfig, AppState};
use ws_auth::jwt::{issue_access_token, AccessClaims, JwtKeys};
use ws_core::db::DbMode;
use ws_core::models::rbac::Role;
use ws_core::models::user::UserModel;
use ws_core::repo::user_repo::UserRepo;
use ws_web::session::store::{SessionEntry, SessionStore, MAX_SESSIONS};
use ws_web::session::{CSRF_HEADER_NAME, CSRF_HEADER_VALUE, SESSION_COOKIE};
use ws_web::web_router_with_store;

/// Postgres advisory-lock key for this suite: ASCII "WARDST" (0x5741445354)
/// plus this suite's plan-allocated marker 0x0013.
const ADVISORY_KEY: i64 = 0x0057_4144_5354_0013;

/// The tenant name this suite owns; swept before use, deleted at the end.
const RELAY_TENANT: &str = "ws-web-relay-tenant";

/// The setup admin's password (the login route verifies the argon2id hash
/// stored here against it).
const ADMIN_PASSWORD: &str = "relay correct horse battery staple";

/// The live-Postgres store TTL (the ws-api JWT access token ALSO lives 15
/// minutes; the store bookkeeping matches).
const DEFAULT_TTL: Duration = Duration::from_secs(900);

/// The static discovery document the loopback provider stub serves (the
/// ws-api oidc_test shape — only the START route needs discovery, which
/// resolves the provider's authorization_endpoint).
const DISCOVERY_JSON: &str = "{\"issuer\":\"https://sso.wardstone.test/realms/wardstone\",\
     \"authorization_endpoint\":\"https://sso.wardstone.test/realms/wardstone/authorize\",\
     \"token_endpoint\":\"https://sso.wardstone.test/realms/wardstone/token\",\
     \"jwks_uri\":\"https://sso.wardstone.test/realms/wardstone/certs\"}";

/// In-process serialization, the whole-body lock pattern of the ws-core,
/// ws-api, and ws-web suites.
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
/// connection (the ws-api/ws-web suite pattern).
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
/// first, then the tenant) — the FK-first sweep the house suites use.
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
        "DELETE FROM one_shot_tokens WHERE tenant_id IN (SELECT id from tenants WHERE name = $1)",
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

/// The refresh-call counter's middleware: tallies `POST /api/v1/auth/refresh`
/// requests that REACH the local ws-api router — the concurrency tests
/// assert against this count.
async fn count_refresh(
    State(counter): State<Arc<AtomicUsize>>,
    req: Request,
    next: Next,
) -> Response {
    if req.method() == Method::POST && req.uri().path() == "/api/v1/auth/refresh" {
        counter.fetch_add(1, Ordering::SeqCst);
    }
    next.run(req).await
}

/// Spawn `router` on an ephemeral loopback listener over plain HTTP and
/// return its base URL. The serve task lives until the test process exits.
async fn spawn_api(router: Router) -> String {
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

/// A per-test environment: the live pool, the REAL ws-api router serving
/// on loopback (with the refresh counter layered around it), ws-web's
/// composed relay+proxy router sharing the SAME `Arc<SessionStore>`, the
/// fixture tenant + admin user, and the held advisory-lock connection.
struct TestEnv {
    pool: PgPool,
    keys_dir: PathBuf,
    /// The ws-api router, kept for DIRECT calls (device-side operations
    /// that bypass ws-web: the oidc-config PUT, the revocation checks).
    api: Router,
    /// ws-web's composed router (relay + proxy + SPA fallback).
    web: Router,
    /// The SAME store instance the web router serves.
    store: Arc<SessionStore>,
    jwt: Arc<JwtKeys>,
    refresh_counter: Arc<AtomicUsize>,
    #[allow(dead_code)] // reserved: future tests may need the tenant id
    tenant_id: Uuid,
    admin_id: Uuid,
    #[allow(dead_code)] // held for the whole body: serializes this suite
    advisory: Option<PoolConnection<sqlx::Postgres>>,
}

impl TestEnv {
    /// Delete every row this test created (under the fixture tenant's
    /// name), release the advisory lock, and remove the keys directory.
    async fn cleanup(&mut self) {
        sweep_tenant(&self.pool, RELAY_TENANT).await;
        if let Some(mut conn) = self.advisory.take() {
            release_advisory(&mut conn, ADVISORY_KEY).await;
        }
        let _ = std::fs::remove_dir_all(&self.keys_dir);
    }
}

/// Build the environment with `ttl` as the store's access lifetime (the
/// test seam: `Duration::ZERO` makes every stored access token instantly
/// stale, forcing the rotation machinery).
async fn env(ttl: Duration) -> TestEnv {
    let pool = ws_core::db::connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let advisory = lock_advisory(&pool, ADVISORY_KEY).await;
    sweep_tenant(&pool, RELAY_TENANT).await;

    let tenant_id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(tenant_id)
        .bind(RELAY_TENANT)
        .execute(&pool)
        .await
        .expect("insert fixture tenant");

    // The admin user WITH a working password (the relay's login relays it
    // through to ws-api's argon2id verification).
    let admin_id = Uuid::new_v4();
    let hash = tokio::task::spawn_blocking({
        let password = ADMIN_PASSWORD.to_owned();
        move || ws_auth::password::hash_password(&password)
    })
    .await
    .expect("the hash task")
    .expect("hash the fixture admin password");
    UserRepo::new()
        .insert(
            &pool,
            &UserModel {
                id: admin_id,
                tenant_id,
                username: "admin".to_string(),
                display_name: "admin".to_string(),
                email: "admin@relay.test".to_string(),
                role: Role::Admin,
                auth_provider: "local".to_string(),
                password_hash: Some(hash),
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
        .expect("insert fixture admin user");

    let keys_dir = std::env::temp_dir().join(format!(
        "ws-web-session-test-keys-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    // The seal-at-creation custody: the master, the secret-encryption
    // key, and the JWT pair are minted straight into the protected arena
    // — no plaintext key file is ever written.
    let mem = ws_secmem::global().expect("the protected pool initializes");
    let master = mem
        .alloc_copy(&[7u8; 32])
        .expect("the arena holds the test master");
    let secret_box = ws_core::crypto::SecretBox::from_key(
        mem.alloc_copy(&[9u8; 32])
            .expect("the arena holds the test secret key"),
    );
    let jwt = Arc::new(JwtKeys::generate(900).expect("mint the JWT key pair"));
    let config = ApiConfig::new("wardstone-relay.test".to_owned(), keys_dir.clone());
    let state = AppState::new_unlocked(pool.clone(), jwt.clone(), config, master, secret_box);
    let refresh_counter = Arc::new(AtomicUsize::new(0));
    // Built ONCE: one clone serves the loopback listener, one stays in the
    // env for direct (bypass-ws-web) oneshot calls — both share the
    // refresh counter through its Arc.
    let api_router = ws_api::router(state).layer(axum::middleware::from_fn_with_state(
        refresh_counter.clone(),
        count_refresh,
    ));
    let api_base = spawn_api(api_router.clone()).await;

    let store = Arc::new(SessionStore::new(ttl, ws_web::DEFAULT_IDLE_EVICTION));
    let web = web_router_with_store(
        pool.clone(),
        keys_dir.clone(),
        "relay-fingerprint".to_owned(),
        "ui.relay.test".to_owned(),
        None, // no listener to swap in the router suites
        &api_base,
        // Never unlocked here: an absent relay directory keeps the
        // unlock relay inert (Task 10, D8).
        &std::env::temp_dir().join("ws-web-session-no-relay/relay.sock"),
        database_url(),
        DbMode::External, // the suite's world is the external deployment
        store.clone(),
        None, // the relay tests' requests carry no ConnectInfo for the per-IP limiter
    )
    .await
    .expect("build the ws-web composed router");

    TestEnv {
        pool,
        keys_dir,
        api: api_router,
        web,
        store,
        jwt,
        refresh_counter,
        tenant_id,
        admin_id,
        advisory: Some(advisory),
    }
}

// ---------------------------------------------------------------------------
// Request helpers (the tests are the only unwrappers in this suite)
// ---------------------------------------------------------------------------

/// Drive one request through a router via `tower`'s oneshot.
async fn drive(
    router: &Router,
    method: Method,
    uri: &str,
    cookie: Option<&str>,
    bearer: Option<&str>,
    csrf: bool,
    json_body: Option<Value>,
) -> axum::http::Response<Body> {
    let mut builder = HttpRequest::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if csrf {
        builder = builder.header(CSRF_HEADER_NAME, CSRF_HEADER_VALUE);
    }
    let request = match json_body {
        Some(value) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(value.to_string()))
            .expect("build the JSON request"),
        None => builder.body(Body::empty()).expect("build the request"),
    };
    router
        .clone()
        .oneshot(request)
        .await
        .expect("the router should respond")
}

/// Read a response body as raw bytes.
async fn body_bytes(response: axum::http::Response<Body>) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), 4 << 20)
        .await
        .expect("read the response body")
        .to_vec()
}

/// Read a response body as JSON.
async fn body_json(response: axum::http::Response<Body>) -> Value {
    let bytes = body_bytes(response).await;
    serde_json::from_slice(&bytes).expect("the response body is JSON")
}

/// The raw `Cookie` header value presenting `id` as the session.
fn cookie_raw(id: &Uuid) -> String {
    format!("{SESSION_COOKIE}={id}")
}

/// Everything a successful relay login produced.
struct LoggedIn {
    session_id: Uuid,
    set_cookie: String,
    me: Value,
}

/// Login the fixture admin through the relay (the UI's own flow: the POST
/// carries the CSRF marker; the browser never sees a token).
async fn login_admin(env: &TestEnv) -> LoggedIn {
    let response = drive(
        &env.web,
        Method::POST,
        "/auth/ui/login",
        None,
        None,
        true,
        Some(json!({"username": "admin", "password": ADMIN_PASSWORD})),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the relayed login succeeds"
    );
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("the login sets the session cookie")
        .to_str()
        .expect("the cookie value is ASCII")
        .to_owned();
    let me = body_json(response).await;
    assert_eq!(me["username"], "admin", "the identity reaches the browser");
    let pair = set_cookie.split(';').next().expect("the cookie pair");
    let id = pair
        .strip_prefix(&format!("{SESSION_COOKIE}="))
        .expect("the cookie carries the session id");
    let session_id = Uuid::parse_str(id).expect("the cookie value is a session uuid");
    LoggedIn {
        session_id,
        set_cookie,
        me,
    }
}

/// Spawn the loopback discovery server and return its
/// `/.well-known/openid-configuration` URL (the ws-api oidc_test shape: a
/// blocking std-net thread answering every request with the static
/// discovery document; loopback-only, lives for the process).
fn spawn_discovery_server() -> String {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind the loopback discovery server");
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
// The tests
// ---------------------------------------------------------------------------

/// Login through the relay: 200 with the MeResponse identity (and NO token
/// fields anywhere), the session cookie with all four flags, and a store
/// entry holding the JWT pair.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn ui_login_sets_cookie_and_me() {
    let _db = lock_db().await;
    let mut env = env(DEFAULT_TTL).await;

    let login = login_admin(&env).await;

    // The body is EXACTLY the MeResponse identity — no token fields at all.
    let expected_keys: HashSet<String> = [
        "actor_type",
        "actor_id",
        "tenant_id",
        "capabilities",
        "username",
        "display_name",
        "role",
        "mfa_enabled",
        "sealed_volume",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let got_keys: HashSet<String> = login
        .me
        .as_object()
        .expect("the login body is a JSON object")
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        got_keys, expected_keys,
        "the login body is the identity only"
    );
    let text = login.me.to_string();
    assert!(
        !text.contains("access_token") && !text.contains("refresh_token"),
        "no token field may appear in the login response body: {text}"
    );
    assert!(
        !text.contains("ws_rt_"),
        "no token material of any shape may appear: {text}"
    );
    assert_eq!(login.me["actor_type"], "user");
    assert_eq!(login.me["role"], "admin");

    // The cookie: the session id + all four pinned flags.
    assert!(
        login.set_cookie.starts_with(&format!("{SESSION_COOKIE}=")),
        "the cookie is the session cookie: {}",
        login.set_cookie
    );
    for flag in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"] {
        assert!(
            login.set_cookie.contains(flag),
            "the cookie carries {flag}: {}",
            login.set_cookie
        );
    }

    // The server side holds the JWT pair; the browser's view above is all
    // there is.
    let entry = env
        .store
        .get(login.session_id)
        .await
        .expect("the store holds the session");
    assert_eq!(entry.username, "admin");
    assert_eq!(entry.role, "admin");
    assert!(!entry.access_token.is_empty());
    assert!(entry.refresh_token.starts_with(b"ws_rt_"));

    env.cleanup().await;
}

/// The injection proof: a cookie-only request through ws-web's proxy
/// arrives at ws-api AUTHENTICATED (the correct username) — because
/// ws-web injected the stored `Authorization` bearer, which the test
/// never sent.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn proxied_request_carries_injected_authorization() {
    let _db = lock_db().await;
    let mut env = env(DEFAULT_TTL).await;
    let login = login_admin(&env).await;

    let response = drive(
        &env.web,
        Method::GET,
        "/api/v1/auth/me",
        Some(&cookie_raw(&login.session_id)),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the cookie session authenticated through injection"
    );
    let me = body_json(response).await;
    assert_eq!(me["username"], "admin", "the injected identity resolved");

    // No rotation was needed: the stored access token was fresh.
    assert_eq!(
        env.refresh_counter.load(Ordering::SeqCst),
        0,
        "a fresh session proxies without any refresh call"
    );

    env.cleanup().await;
}

/// Without a session cookie the proxy forwards verbatim: ws-api's own 401
/// (its error envelope shape, untouched) is what the caller sees.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn proxied_request_without_session_gets_401() {
    let _db = lock_db().await;
    let mut env = env(DEFAULT_TTL).await;

    let response = drive(
        &env.web,
        Method::GET,
        "/api/v1/auth/me",
        None,
        None,
        false,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(response).await;
    assert_eq!(
        body["error"]["code"], "unauthorized",
        "ws-api's own error envelope passes through untouched: {body}"
    );

    env.cleanup().await;
}

/// Logout: revokes the refresh token SERVER-side (a later direct refresh
/// with the old token is refused), removes the store entry, clears the
/// cookie (Max-Age=0), is CSRF-refused without the marker, and is
/// idempotent across repeats.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn ui_logout_revokes_and_clears() {
    let _db = lock_db().await;
    let mut env = env(DEFAULT_TTL).await;
    let login = login_admin(&env).await;

    // First: the CSRF rule also guards the relay's own mutating route — a
    // cookie-carrying POST without the marker is refused HERE (403), not
    // relayed, and the session survives.
    let response = drive(
        &env.web,
        Method::POST,
        "/auth/ui/logout",
        Some(&cookie_raw(&login.session_id)),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "no marker, no logout"
    );
    let refusal = body_json(response).await;
    assert_eq!(refusal["error"]["code"], "forbidden");
    assert!(
        env.store.get(login.session_id).await.is_some(),
        "the refused logout left the session alive"
    );

    // Capture the refresh token from the store BEFORE revocation (the
    // store is the only place the browser-never-sees token lives; the
    // access token stays valid until its own JWT expiry by ws-api's
    // stateless design — the refresh row is what revocation kills).
    let refresh = {
        let entry = env
            .store
            .get(login.session_id)
            .await
            .expect("the session still exists");
        // The store's arena custody, materialized once for the direct
        // revocation below (the product materializes the same way, via
        // the relay's `refresh_token_of`).
        String::from_utf8_lossy(&entry.refresh_token[..]).into_owned()
    };

    // The real logout relays the revocation (Bearer + refresh body) and
    // clears everything locally.
    let response = drive(
        &env.web,
        Method::POST,
        "/auth/ui/logout",
        Some(&cookie_raw(&login.session_id)),
        None,
        true,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "logout succeeds");
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("logout clears the cookie")
        .to_str()
        .expect("ascii")
        .to_owned();
    assert!(
        set_cookie.starts_with(&format!("{SESSION_COOKIE}=;")) && set_cookie.contains("Max-Age=0"),
        "the logout clears the cookie: {set_cookie}"
    );
    for flag in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"] {
        assert!(set_cookie.contains(flag), "the cleared cookie keeps {flag}");
    }
    assert!(
        env.store.get(login.session_id).await.is_none(),
        "the store entry is gone"
    );

    // The revocation was SERVER-side: a direct refresh with the revoked
    // token is refused by ws-api (401, its own envelope).
    let api = env.api.clone();
    let response = drive(
        &api,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        None,
        false,
        Some(json!({"refresh_token": refresh})),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "the revoked refresh token no longer works"
    );
    let body = body_json(response).await;
    assert_eq!(body["error"]["code"], "unauthorized");

    // The access token is equally dead for NEW relays: the cookie remains
    // in this test's hands but carries no store entry, so the proxied /me
    // request goes out UNinjected and ws-api's 401 passes through.
    let response = drive(
        &env.web,
        Method::GET,
        "/api/v1/auth/me",
        Some(&cookie_raw(&login.session_id)),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(response).await;
    assert_eq!(
        body["error"]["code"], "unauthorized",
        "passthrough shape: {body}"
    );

    // Idempotent: logging out again with the (now unknown) session is the
    // same quiet 204, not an error.
    let response = drive(
        &env.web,
        Method::POST,
        "/auth/ui/logout",
        Some(&cookie_raw(&login.session_id)),
        None,
        true,
        None,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "idempotent logout"
    );
    // Scope note (pin): the ACCESS token itself stays valid until its own
    // JWT expiry — ws-api's bearer middleware is stateless-JWT and a
    // revoked refresh row does not retroactively kill it; that is ws-api's
    // accepted token semantics, not ws-web's. The relay's guarantee is
    // exactly what this test proved: the revocation reached the refresh
    // row, the store entry died, and the browser's cookie carries nothing
    // that can authenticate a NEW request through ws-web anymore.

    env.cleanup().await;
}

/// The OIDC start route is a verbatim redirect relay: ws-api mints the
/// authorization URL (config + csrf state) and ws-web passes the status
/// and Location through untouched — the provider's redirect_uri (the
/// ws-web PUBLIC callback, admin-set in Task 5's config) travels exactly
/// as ws-api wrote it. The full callback→exchange flow is Task 19's e2e
/// territory.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn oidc_start_redirects_verbatim() {
    let _db = lock_db().await;
    let mut env = env(DEFAULT_TTL).await;

    // Seed the provider config against the loopback discovery stub (the
    // Task 5 PUT, driven DIRECTLY against the local ws-api with a minted
    // admin bearer — this test is about ws-web's relay, not the proxy's
    // injection for management calls).
    let discovery_url = spawn_discovery_server();
    let config = json!({
        "provider_type": "keycloak",
        "display_name": "House Keycloak",
        "discovery_url": discovery_url,
        "client_id": "wardstone-ui-test",
        "client_secret": "ws_test_secret_material",
        "redirect_uri": "https://ui.relay.test/auth/ui/oidc/keycloak/callback",
        "scopes": "openid profile email"
    });
    let claims = AccessClaims::new(env.admin_id, "admin", "admin", None, 900);
    let token = issue_access_token(&claims, &env.jwt).expect("mint the admin bearer");
    let api = env.api.clone();
    let response = drive(
        &api,
        Method::PUT,
        "/api/v1/oidc/config",
        None,
        Some(&token),
        false,
        Some(config),
    )
    .await;
    assert!(
        response.status().is_success(),
        "the provider config seeds: {}",
        response.status()
    );

    // The relay forwards the start: ws-api resolves discovery (the live
    // stub), mints the state, and returns its redirect — ws-web must not
    // alter status or Location.
    let response = drive(
        &env.web,
        Method::GET,
        "/auth/ui/oidc/keycloak/start",
        None,
        None,
        false,
        None,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "ws-api's Redirect::to is a 303 and ws-web passes it through as-is"
    );
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("the redirect carries its Location")
        .to_str()
        .expect("the location is ASCII")
        .to_owned();
    assert!(
        location.starts_with("https://sso.wardstone.test/realms/wardstone/authorize?"),
        "the location IS the provider's authorization endpoint: {location}"
    );
    for piece in [
        "response_type=code",
        "client_id=wardstone-ui-test",
        "redirect_uri=",
        "scope=openid",
        "state=",
    ] {
        assert!(
            location.contains(piece),
            "the minted URL carries {piece}: {location}"
        );
    }
    // The redirect_uri inside is ws-web's PUBLIC callback (the value the
    // admin set in the config), percent-encoded or not the host survives.
    assert!(
        location.contains("ui.relay.test"),
        "the redirect_uri points at ws-web's public callback: {location}"
    );
    let state = location.split("state=").nth(1).unwrap_or("");
    assert!(!state.is_empty(), "ws-api minted a nonempty csrf state");
    assert!(
        !location.contains("client_secret"),
        "the secret never travels in the authorization URL: {location}"
    );

    env.cleanup().await;
}

/// THE Review-Focus-1 test: two concurrent proxied requests on the SAME
/// expired session — both succeed, and the per-session rotation lock
/// collapses them into EXACTLY ONE ws-api refresh call (the second waiter
/// re-reads the fresh tokens under the lock and skips its own).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn both_concurrent_rotations_succeed() {
    let _db = lock_db().await;
    // The ZERO ttl seam: every stored access token is instantly stale, so
    // each request enters the rotation machinery.
    let mut env = env(Duration::ZERO).await;
    let login = login_admin(&env).await;

    let session_id = login.session_id;
    let first = tokio::spawn({
        let web = env.web.clone();
        let cookie = cookie_raw(&session_id);
        async move {
            drive(
                &web,
                Method::GET,
                "/api/v1/auth/me",
                Some(&cookie),
                None,
                false,
                None,
            )
            .await
        }
    });
    let second = tokio::spawn({
        let web = env.web.clone();
        let cookie = cookie_raw(&session_id);
        async move {
            drive(
                &web,
                Method::GET,
                "/api/v1/auth/me",
                Some(&cookie),
                None,
                false,
                None,
            )
            .await
        }
    });

    let (first, second) = tokio::join!(first, second);
    let first = first.expect("the first task");
    let second = second.expect("the second task");
    assert_eq!(first.status(), StatusCode::OK, "the first probe succeeds");
    assert_eq!(
        second.status(),
        StatusCode::OK,
        "the second probe succeeds too"
    );
    let me = body_json(first).await;
    assert_eq!(me["username"], "admin");
    let me = body_json(second).await;
    assert_eq!(me["username"], "admin");

    // The heart of the pin: ONE refresh call reached ws-api. No 401 was
    // ever served to the browser.
    assert_eq!(
        env.refresh_counter.load(Ordering::SeqCst),
        1,
        "the concurrent expired probes collapsed into exactly one refresh"
    );

    env.cleanup().await;
}

/// A rotation that CANNOT succeed (the refresh token was revoked
/// server-side mid-session) kills the browser session cleanly: 401 with
/// the session-expired shape, the clearing cookie, the store entry gone,
/// and the next request stays logged out.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn rotation_failure_kills_session_cleanly() {
    let _db = lock_db().await;
    let mut env = env(DEFAULT_TTL).await;
    let login = login_admin(&env).await;

    // Revoke the session's refresh row through DIRECT ws-api logout (the
    // session's own pair from the store — the shape ws-api's handler
    // demands: bearer matches the body's token id via sid).
    let (access, refresh) = {
        let entry = env
            .store
            .get(login.session_id)
            .await
            .expect("the session exists pre-revocation");
        // The store's arena custody, materialized once for the direct
        // ws-api logout below (the relay's own materialization shape).
        (
            String::from_utf8_lossy(&entry.access_token[..]).into_owned(),
            String::from_utf8_lossy(&entry.refresh_token[..]).into_owned(),
        )
    };
    let api = env.api.clone();
    let response = drive(
        &api,
        Method::POST,
        "/api/v1/auth/logout",
        None,
        Some(&access),
        false,
        Some(json!({"refresh_token": refresh})),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "the direct logout revokes the refresh row"
    );

    // Force the store bookkeeping stale so the next proxied request takes
    // the rotation path (test seam; the real clock does this after 15 min).
    env.store.force_expire(login.session_id).await;

    // The proxied GET now: expiry → locked refresh against the REVOKED
    // token → rotation failure → the session dies cleanly.
    let response = drive(
        &env.web,
        Method::GET,
        "/api/v1/auth/me",
        Some(&cookie_raw(&login.session_id)),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("the death clears the cookie")
        .to_str()
        .expect("ascii")
        .to_owned();
    let body = body_json(response).await;
    assert_eq!(body["error"]["code"], "unauthorized", "shape: {body}");
    assert_eq!(
        body["error"]["message"], "session expired",
        "ws-web's own session-expired refusal (not a passthrough)"
    );
    assert!(
        set_cookie.contains(&format!("{SESSION_COOKIE}=;")) && set_cookie.contains("Max-Age=0"),
        "the killed session clears the cookie: {set_cookie}"
    );
    assert!(
        env.store.get(login.session_id).await.is_none(),
        "the dead session's entry is removed"
    );

    // The next request is STILL logged out (no resurrecting zombie state).
    let response = drive(
        &env.web,
        Method::GET,
        "/api/v1/auth/me",
        Some(&cookie_raw(&login.session_id)),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    env.cleanup().await;
}

/// THE logout-vs-rotation race (the round-1 Important fix's cover): a
/// logout and a rotation racing on the SAME session must never strand a
/// LIVE refresh row in ws-api. With the ZERO ttl every proxied request
/// takes the rotation path; the per-session rotation_lock serializes
/// logout's revoke against it, and the locked logout re-reads the CURRENT
/// generation under the lock — so whichever order lands (logout first or
/// rotation first), every ws-api-minted refresh row ends up revoked (by
/// the logout) or rotated away (dead by ws-api's own rotate CTE, which
/// stamps `revoked_at` on the old row). The invariant is asserted
/// DIRECTLY on the test pool over the refresh_tokens table.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn logout_after_concurrent_rotation_leaves_no_live_refresh() {
    let _db = lock_db().await;
    let mut env = env(Duration::ZERO).await;
    let login = login_admin(&env).await;

    let first = tokio::spawn({
        let web = env.web.clone();
        let cookie = cookie_raw(&login.session_id);
        async move {
            drive(
                &web,
                Method::GET,
                "/api/v1/auth/me",
                Some(&cookie),
                None,
                false,
                None,
            )
            .await
        }
    });
    let second = tokio::spawn({
        let web = env.web.clone();
        let cookie = cookie_raw(&login.session_id);
        async move {
            drive(
                &web,
                Method::POST,
                "/auth/ui/logout",
                Some(&cookie),
                None,
                true,
                None,
            )
            .await
        }
    });
    let (first, second) = tokio::join!(first, second);
    let first = first.expect("the proxied task");
    let second = second.expect("the logout task");

    // Both sides complete without wedging. The proxied request is either
    // 200 (it rotated before the logout killed the entry) or 401 (the
    // logout won: the out-going forward had no store entry, hence no
    // injected Authorization) — the invariant below holds for BOTH.
    assert!(
        first.status() == StatusCode::OK || first.status() == StatusCode::UNAUTHORIZED,
        "the concurrent proxied request completes one way or the other: {}",
        first.status()
    );
    assert_eq!(
        second.status(),
        StatusCode::NO_CONTENT,
        "the racing logout is a quiet 204"
    );

    // THE INVARIANT, direct on the pool: the fixture user has NO live
    // (never-revoked) refresh row. Rotation-dead rows carry `revoked_at`
    // from ws-api's rotate CTE; logout-revoked rows carry it from the
    // handler's revoke. Neither interleaving may mint a row that only
    // ws-web's memory ever held.
    let live = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(env.admin_id)
    .fetch_one(&env.pool)
    .await
    .expect("count the live refresh rows");
    assert_eq!(
        live, 0,
        "no live refresh row may survive the logout/rotation race"
    );

    // The store entry is gone and the session stays dead at the relay.
    assert!(env.store.get(login.session_id).await.is_none());
    let response = drive(
        &env.web,
        Method::GET,
        "/api/v1/auth/me",
        Some(&cookie_raw(&login.session_id)),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    env.cleanup().await;
}

// ---------------------------------------------------------------------------
// The arena-backed store (Task 8): capacity eviction — DB-free, real arena
// ---------------------------------------------------------------------------

/// A far-future idle window so ONLY the capacity eviction acts in the
/// tests below (the idle clock's own semantics are the injected-clock
/// unit tests' territory, in the store's own module).
const NO_IDLE_EVICTION: Duration = Duration::from_secs(86400 * 365);

/// The capacity tests serialize against each other. Each hammers the
/// process-global arena with ~2,050 claims in the same first
/// seconds of the test binary's life, and the wipe test's assertion
/// reads the victim's just-RELEASED granules — a region the allocator is
/// entitled to hand to ANY concurrent claim (first-fit picks the lowest
/// free run, and the victim's are the lowest). The peer test's steady
/// claim stream is exactly the interference that would make the peek
/// read reused bytes instead of the wipe; the lock removes it, leaving
/// the wipe test's microsecond observation window without a claimer
/// (the DB tests claim through the same global arena, but their logins
/// are seconds apart — orders of magnitude too slow to land in the
/// window). The lock is a tokio mutex because the guard must sit across
/// the tests' await points for the whole test body.
static CAPACITY_SUITE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// One fresh entry: fixed identity fields, both tokens claimed straight
/// into the protected arena (Ruling 20: the real global pool, no test
/// stand-in). `index` keeps every entry's tokens distinct.
fn arena_entry(mem: &ws_secmem::SecMem, index: usize) -> SessionEntry {
    let access = mem
        .alloc_copy(format!("ws_at_capacity-{index}").as_bytes())
        .expect("the arena holds the access token");
    let refresh = mem
        .alloc_copy(format!("ws_rt_capacity-{index}").as_bytes())
        .expect("the arena holds the refresh token");
    SessionEntry::new(
        Uuid::new_v4(),
        format!("session-{index}"),
        "admin".to_owned(),
        access,
        refresh,
    )
}

/// Review Focus 3, pin 1: the store holds at most `MAX_SESSIONS`
/// entries. The 1,025th insert evicts the least-recently-touched entry
/// first — with sequential inserts that is the FIRST session, and the
/// newest survives. (No `get` call sits between the inserts: `get`
/// TOUCHES its entry, so a mid-loop read would rewrite the touch order
/// this test's eviction asserts depend on. The capacity boundary's
/// pin — the 1,024th insert at len 1,023 evicts NOTHING — is the
/// sibling test below, which makes no eviction assertions for the
/// same reason.)
#[tokio::test]
async fn login_1025_evicts_the_oldest() {
    // Serialized against the other capacity tests (see CAPACITY_SUITE).
    let _suite = CAPACITY_SUITE.lock().await;
    let mem = ws_secmem::global().expect("the protected pool initializes");
    let store = SessionStore::new(Duration::from_secs(900), NO_IDLE_EVICTION);

    let mut first = None;
    let mut newest = None;
    for index in 0..=MAX_SESSIONS {
        let id = store.insert(arena_entry(mem, index)).await;
        if index == 0 {
            first = Some(id);
        }
        newest = Some(id);
    }

    assert_eq!(
        store.len().await,
        MAX_SESSIONS,
        "capacity holds at MAX_SESSIONS, never grows"
    );
    assert!(
        store.get(first.expect("the first insert")).await.is_none(),
        "the least-recently-touched session (the first) was evicted"
    );
    assert!(
        store
            .get(newest.expect("the newest insert"))
            .await
            .is_some(),
        "the newest session survived"
    );
}

/// Fix round 1, the capacity boundary pin: the guard fires AT capacity,
/// not below it. 1,023 sessions → the 1,024th insert → the store holds
/// exactly `MAX_SESSIONS` and EVERY session still resolves — the
/// oldest and the boundary insert itself included. No eviction
/// assertion follows: `get` TOUCHES its entry, so a post-`get` touch
/// order would lie about which insert is least-recently-touched.
#[tokio::test]
async fn the_1024th_insert_at_len_1023_evicts_nothing() {
    // Serialized against the other capacity tests (see CAPACITY_SUITE).
    let _suite = CAPACITY_SUITE.lock().await;
    let mem = ws_secmem::global().expect("the protected pool initializes");
    let store = SessionStore::new(Duration::from_secs(900), NO_IDLE_EVICTION);

    let mut first = None;
    for index in 0..MAX_SESSIONS - 1 {
        let id = store.insert(arena_entry(mem, index)).await;
        if index == 0 {
            first = Some(id);
        }
    }
    assert_eq!(
        store.len().await,
        MAX_SESSIONS - 1,
        "1,023 sessions sit one below capacity"
    );

    let boundary = store.insert(arena_entry(mem, MAX_SESSIONS - 1)).await;
    assert_eq!(
        store.len().await,
        MAX_SESSIONS,
        "the boundary insert brings the store to exactly MAX_SESSIONS"
    );
    assert!(
        store.get(first.expect("the first insert")).await.is_some(),
        "the 1,024th insert at len 1,023 evicts nothing"
    );
    assert!(
        store.get(boundary).await.is_some(),
        "the boundary insert itself stays live"
    );
}

/// Review Focus 3, pin 2: an evicted entry's token reservations read back
/// ZERO through the test-only arena peek — the wipe the dropped
/// `SecretBuf`'s `Drop` promises, on the real global pool. The addresses
/// are recorded BEFORE the store takes custody, so the assertion reads
/// exactly the buffers the evicted generation held.
///
/// Every filler pair is pre-claimed BEFORE any insert: `store.insert`
/// takes no arena allocation of its own, so once the capacity eviction
/// wipes and releases the victim's regions nothing allocates from the
/// arena again before the peek. (Claiming the fillers lazily inside the
/// insert loop would let a later `alloc_copy` legitimately REUSE the
/// victim's just-released region — the allocator's right, but it would
/// make this assertion read reused bytes instead of the wipe.)
#[tokio::test]
async fn an_evicted_sessions_tokens_are_wiped() {
    // Serialized against the other capacity tests (see CAPACITY_SUITE):
    // the assertion below reads freed-then-wiped granules, and this lock
    // keeps the heavy concurrent claimers out of the window.
    let _suite = CAPACITY_SUITE.lock().await;
    let mem = ws_secmem::global().expect("the protected pool initializes");
    let store = SessionStore::new(Duration::from_secs(900), NO_IDLE_EVICTION);

    // The victim: the oldest entry, whose two token reservations' absolute
    // addresses are recorded before the arena custody moves into the
    // store.
    let access = mem
        .alloc_copy(b"ws_at_evict-me-access")
        .expect("the arena holds the victim's access token");
    let refresh = mem
        .alloc_copy(b"ws_rt_evict-me-refresh")
        .expect("the arena holds the victim's refresh token");
    let access_addr = access.as_ptr();
    let access_len = access.len();
    let refresh_addr = refresh.as_ptr();
    let refresh_len = refresh.len();
    let victim = store
        .insert(SessionEntry::new(
            Uuid::new_v4(),
            "victim".to_owned(),
            "admin".to_owned(),
            access,
            refresh,
        ))
        .await;

    // Fill to capacity + 1 from the PRE-CLAIMED pairs: the victim is the
    // least-recently-touched, so the capacity eviction takes exactly it —
    // and no insert after the eviction touches the arena at all.
    let fillers: Vec<SessionEntry> = (1..=MAX_SESSIONS)
        .map(|index| arena_entry(mem, index))
        .collect();
    for filler in fillers {
        store.insert(filler).await;
    }
    assert_eq!(store.len().await, MAX_SESSIONS);
    assert!(
        store.get(victim).await.is_none(),
        "the victim was evicted at capacity"
    );

    // The evicted generation's token `Arc`s died with the map slot: both
    // reservations must read as zero.
    let wiped_access = mem
        .peek_for_test(access_addr, access_len)
        .expect("the access reservation stays inside the arena");
    assert!(
        wiped_access.iter().all(|byte| *byte == 0),
        "the evicted session's access token buffer is wiped"
    );
    let wiped_refresh = mem
        .peek_for_test(refresh_addr, refresh_len)
        .expect("the refresh reservation stays inside the arena");
    assert!(
        wiped_refresh.iter().all(|byte| *byte == 0),
        "the evicted session's refresh token buffer is wiped"
    );
}
