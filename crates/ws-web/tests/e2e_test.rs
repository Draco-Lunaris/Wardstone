//! End-to-end API smoke test (Task 14): the proof that the assembled plan
//! works as a system. ONE live-Postgres test mounts ws-web's setup router
//! and ws-api's router over the SAME pool and drives the whole product:
//!
//! 1. first-run setup through the real setup route (admin, domain, CIDRs,
//!    hostname — tenant, root CA, argon2id admin, two default profiles,
//!    and the CA-issued server leaf all commit);
//! 2. login as the setup admin through the real login route (JWT pair);
//! 3. profile creation through the API;
//! 4. leaf issuance from a PKCS#10 CSR, asserted down to the certificate:
//!    it parses, it is signed by the setup root, it carries the profile's
//!    EKU and key usages, and its validity span equals the profile's
//!    lifetime exactly;
//! 5. revocation;
//! 6. the audit trail: `ca_created`, `cert_issued`, `cert_revoked` in
//!    order, each with the right `auth_method`;
//! 7. a service identity's API token issuing a second leaf, with the
//!    audit row's `actor_type` = `api_token`;
//! 8. the setup route is GONE (unmounted, a plain 404) once a tenant
//!    exists.
//!
//! Task 19 adds TWO further DB-gated tests — the BROWSER-EQUIVALENT path
//! over ws-web's composed front door (ws-web's setup surface, `/auth/ui`
//! session relay, and `/api/v1` proxy against ws-api's REAL router on an
//! in-process loopback listener, the session_test idiom):
//!
//! - `ui_session_end_to_end` — first-run setup through the composed
//!   router, then the browser's day: the UI login (four cookie flags, an
//!   identity body shaped to the EXACT MeResponse key set), cookie-only
//!   proxied reads and writes (profile list, CSR issuance, a typed-reason
//!   revocation, the trust chain, the estate statistics), the logout
//!   (cookie cleared, the revoked server-side), and the dead session's
//!   401 — with EVERY response body swept for `ws_rt_`/`ws_at_`/
//!   `Bearer ` (the token boundary: the browser never holds a token).
//! - `ui_oidc_end_to_end` — the generic-provider SSO round trip against
//!   `common/oidc_provider.rs` (the Task 19 loopback provider fixture:
//!   an openssl-generated RSA keypair and a genuinely RS256-signed
//!   id_token): the config PUT through the proxy, the start redirect to
//!   the fixture's authorization endpoint, the callback's code exchange
//!   into a session, the on-the-fly SSO account, and a second round trip
//!   resolving BY the stored subject.
//!
//! Run against the shared dev Postgres:
//!
//! ```sh
//! DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test \
//!     cargo test -p ws-web --test e2e_test -- --include-ignored
//! ```
//!
//! # Self-cleaning contract
//!
//! One advisory lock for this whole plan's DB suites remains free
//! (0x0011). Every test here sweeps away rows a previously crashed run
//! may have left under the setup tenant's name (children first, then the
//! tenant) and deletes every row it created BEFORE the main assertions
//! run: the DB reads that back them (the audit trail, the setup-gone
//! checks) are captured while the tenant still exists, `cleanup` removes
//! the rows and the keys directory, and only then are the captured
//! values asserted on.
//!
//! # Cross-process serialization
//!
//! The body holds a session-level Postgres advisory lock on
//! [`ADVISORY_KEY`] — the "WARDST" family (0x5741445354) with this
//! suite's plan-allocated marker 0x0011 (keys 0x0003..0x0010 are taken
//! by the other suites). The in-process tokio mutex mirrors the
//! ws-core/ws-api/ws-web house pattern; both go in and come out
//! together, before any of the suite's own rows are written and after
//! the last of them is deleted.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex as TokioMutex;
use tower::ServiceExt;
use uuid::Uuid;
use x509_parser::pem::parse_x509_pem;
use zeroize::Zeroizing;

use ws_api::state::{ApiConfig, AppState};
use ws_web::session::store::SessionStore;
use ws_web::session::{CSRF_HEADER_NAME, CSRF_HEADER_VALUE, SESSION_COOKIE};
use ws_web::setup::{self, SetupFields, SetupState};

// Task 19's shared fixture: the loopback OIDC provider stub
// (tests/common/oidc_provider.rs).
mod common;

use common::oidc_provider::{OidcProvider, CODE};

/// Postgres advisory-lock key for this suite: ASCII "WARDST" (0x5741445354)
/// plus this suite's marker 0x0011 (the e2e suite's allocation; the other
/// suites hold 0x0003..0x0010).
const ADVISORY_KEY: i64 = 0x0057_4144_5354_0011;

/// The default domain the setup collects: the root CA's subject, the
/// built-in profiles' name base, and the API process's `ApiConfig.domain`.
const DOMAIN: &str = "wardstone-e2e.test";

/// The instance hostname the setup collects: the CA-issued server leaf's
/// SAN (matched by the built-in `*.wardstone-e2e.test` pattern).
const HOSTNAME: &str = "ui.wardstone-e2e.test";

/// Display-only page fingerprint placeholder (the page only echoes the
/// state it was given; the real fingerprint flow is ws-web's suite).
const PAGE_FINGERPRINT: &str = "e2e-fingerprint";

/// The setup admin's password (the login route verifies the argon2id
/// hash stored at setup against it).
const ADMIN_PASSWORD: &str = "correct horse battery staple";

/// The profile the API test creates pins a 30-day lifetime; the issued
/// leaf's validity span must equal it exactly.
const LIFETIME_DAYS: i64 = 30;

/// The setup flow's master passphrase: the POST seals the volume under
/// it, and every post-setup construction (the api's unlock, the e2e's
/// own probes) opens with it.
const SETUP_PASSPHRASE: &str = "the-master-passphrase";

/// In-process serialization, the whole-body lock pattern of the ws-core,
/// ws-api, and ws-web suites: the harness runs tests on separate
/// threads. A tokio mutex because the guard is held across `.await`s.
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

/// A fresh connection with the URL's own (bootstrap) credential: proves
/// whether the shared login role's password still matches it. The
/// conversion — and the api's relayed unlock — rotate the credential, so
/// a `false` after a setup POST is the rotation's real evidence.
async fn bootstrap_credential_connects() -> bool {
    sqlx::PgPool::connect(&database_url()).await.is_ok()
}

/// Delete every row a previous run may have left under `name` (children
/// first, then the tenant) — the FK-first sweep the ws-api and ws-web
/// suites use.
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
        "DELETE FROM one_shot_tokens WHERE tenant_id IN (SELECT id from tenants WHERE name = $1)",
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

/// A per-test fixture: the live pool, a fresh keys directory, and the
/// held advisory-lock connection.
struct Fixture {
    pool: PgPool,
    keys_dir: PathBuf,
    #[allow(dead_code)] // held for the whole body: serializes this suite
    advisory: Option<PoolConnection<sqlx::Postgres>>,
}

/// The fixed 16-byte salt the shared role's restore verifier uses
/// (Task 4's ruling: NO plaintext ALTER on the test side either — the
/// restore sets the verifier form of `wardstone`'s bootstrap password,
/// and a fixed salt keeps that verifier deterministic across every
/// suite that restores the shared role).
const FIXED_TEST_SALT: [u8; 16] = *b"0123456789abcdef";

/// The shared test role's restore statement: the SCRAM-SHA-256
/// verifier of the bootstrap password `wardstone` — Postgres stores
/// the verifier as-is and the plaintext behind it logs in, so every
/// suite's `wardstone:wardstone` connect keeps working.
fn restore_statement() -> String {
    format!(
        "ALTER USER wardstone PASSWORD '{}'",
        ws_core::dbcred::scram_verifier(
            b"wardstone",
            &FIXED_TEST_SALT,
            ws_core::dbcred::SCRAM_ITERATIONS,
        )
    )
}

impl Fixture {
    /// Restore the shared login role's password IMMEDIATELY after a setup
    /// POST (the conversion — and the api's relayed unlock — rotate it):
    /// unlike [`Self::cleanup`], this runs before any assertion can
    /// panic, so a mid-test failure can never leave the rotated password
    /// behind for the next suite's first connect.
    async fn restore_role_password(&self) {
        sqlx::query(&restore_statement())
            .execute(&self.pool)
            .await
            .expect("restore the shared test role's password");
    }

    /// Delete every row this test created (under the setup tenant's
    /// name), restore the shared login role's password, release the
    /// advisory lock, and remove the keys directory. The role restore is
    /// part of the self-cleaning contract: a successful setup POST runs
    /// the conversion, which rotates the `wardstone` login role's
    /// password — and every suite on this shared server connects as
    /// `wardstone:wardstone`, so a role left rotated breaks the next
    /// suite at its very first connect. The reset is idempotent for the
    /// tests that never reach the seal.
    async fn cleanup(&mut self) {
        sweep_tenant(&self.pool, setup::DEFAULT_TENANT_NAME).await;
        sqlx::query(&restore_statement())
            .execute(&self.pool)
            .await
            .expect("restore the shared test role's password");
        if let Some(mut conn) = self.advisory.take() {
            release_advisory(&mut conn, ADVISORY_KEY).await;
        }
        let _ = std::fs::remove_dir_all(&self.keys_dir);
    }
}

/// Build the fixture: connect (migrations apply), take the advisory
/// lock, sweep stale rows, create a fresh keys directory.
async fn fixture() -> Fixture {
    let pool = ws_core::db::connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let advisory = lock_advisory(&pool, ADVISORY_KEY).await;
    sweep_tenant(&pool, setup::DEFAULT_TENANT_NAME).await;

    let keys_dir = std::env::temp_dir().join(format!(
        "ws-web-e2e-keys-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));

    Fixture {
        pool,
        keys_dir,
        advisory: Some(advisory),
    }
}

/// A POST with a JSON body and (optional) bearer header against `router`.
async fn post_json(
    router: &Router,
    uri: &str,
    token: Option<&str>,
    body: Value,
) -> axum::http::Response<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = builder
        .body(Body::from(body.to_string()))
        .expect("build the POST request");
    router
        .clone()
        .oneshot(request)
        .await
        .expect("the router should respond")
}

/// A GET with a bearer header against `router`.
async fn get_bearer(router: &Router, uri: &str, token: &str) -> axum::http::Response<Body> {
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("build the GET request");
    router
        .clone()
        .oneshot(request)
        .await
        .expect("the router should respond")
}

/// Read a JSON response body.
async fn body_json(response: axum::http::Response<Body>) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 4 << 20)
        .await
        .expect("read the response body");
    serde_json::from_slice(&bytes).expect("the response body is JSON")
}

/// A valid ECDSA P-256 CSR (self-signed) for `cn` with DNS SANs `names`
/// — the same mint the ws-api suite uses (the profile pins ecdsa-p256).
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
// Task 19: the composed-front-door stack (ws-api on loopback + ws-web)
// ---------------------------------------------------------------------------

/// The api process's fresh-install boot under the sealed design: the
/// REAL production unlock builder behind the sealed shell, on an
/// ephemeral loopback listener (plain HTTP — the compose-internal
/// channel). Pre-setup the volume holds nothing to unlock and the api
/// sits sealed (healthz `200 sealed`, everything else 503) — exactly the
/// compose contract, where only the setup commit's relay brings the
/// full surface up. Its TCP base URL is what ws-web's /api/v1 proxy and
/// session relay target (ruling 28f); the setup commit's unlock relay
/// rides the Unix socket it returns alongside (Task 10, D8).
async fn spawn_sealed_api(fixture: &Fixture) -> (String, PathBuf) {
    let keys_dir = fixture.keys_dir.clone();
    let url = database_url();
    let config = ApiConfig::new(DOMAIN.to_string(), fixture.keys_dir.clone());
    let build: ws_api::sealed::LockedBuild =
        std::sync::Arc::new(move |req: &ws_api::sealed::UnlockRequest| {
            let keys_dir = keys_dir.clone();
            let url = url.clone();
            let config = config.clone();
            let passphrase = req.passphrase.clone();
            let next_passphrase = req.next_passphrase.clone();
            Box::pin(async move {
                ws_api::sealed::unlocked_router_from_envelopes(
                    &keys_dir,
                    &url,
                    &config,
                    &passphrase,
                    next_passphrase.as_deref(),
                )
                .await
            })
        });
    let relay_dir = std::env::temp_dir().join(format!(
        "ws-e2e-sealed-relay-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    std::fs::create_dir_all(&relay_dir).expect("create the api's relay directory");
    let relay_socket = relay_dir.join("relay.sock");
    let api = Arc::new(ws_api::sealed::SealedApi::new(build, relay_dir));
    let app = ws_api::sealed::sealed_router(api.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the loopback sealed-api listener");
    let addr = listener.local_addr().expect("the listener's local address");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("serve the sealed api");
    });
    let relay_listener =
        ws_api::sealed::bind_relay_socket(&relay_socket).expect("bind the api's relay socket");
    let own_uid = ws_api::sealed::current_uid();
    tokio::spawn(async move {
        ws_api::sealed::serve_relay(relay_listener, api, own_uid)
            .await
            .expect("serve the api's relay socket");
    });
    (format!("http://{addr}"), relay_socket)
}

/// ws-web's composed front door (relay + proxy + SPA fallback) pointed at
/// `api_base`: the production 15-minute session TTL, and NO per-IP rate
/// limiter (in-process oneshot requests carry no `ConnectInfo` — the
/// session_test reasoning).
async fn front(
    pool: &PgPool,
    keys_dir: &std::path::Path,
    api_base: &str,
    relay_socket: &std::path::Path,
) -> Router {
    ws_web::web_router_with_store(
        pool.clone(),
        keys_dir.to_path_buf(),
        PAGE_FINGERPRINT.to_string(),
        HOSTNAME.to_string(),
        None, // no listener to swap in the router suites
        api_base,
        relay_socket,
        database_url(),
        Arc::new(SessionStore::new(
            ws_web::DEFAULT_SESSION_TTL,
            ws_web::DEFAULT_IDLE_EVICTION,
        )),
        None,
    )
    .await
    .expect("build the composed front-door router")
}

/// The FIRST-RUN SETUP driven through the composed front door itself (the
/// browser's POST /setup), and the RESTARTED front door after it. A
/// Router's setup mounting is decided at BUILD time (`web_router`'s
/// `tenant_exists` check), so the lifecycle is two builds: the pre-setup
/// build serves the POST, and the post-setup build is the restarted door
/// the browser flow runs on. The api process is up from the start as the
/// sealed shell (the compose contract: a fresh install's api carries no
/// credential to build a pool from) — the setup commit's relay is the one
/// event that unlocks it, and this helper proves that whole production
/// path end to end: seal → relay → the api's own rotation → the full
/// surface behind the delegate. Returns the post-setup router and the
/// setup body's text.
async fn setup_and_restarted_front(fixture: &Fixture) -> (Router, String) {
    let (api_base, relay_socket) = spawn_sealed_api(fixture).await;
    let pre_setup = front(&fixture.pool, &fixture.keys_dir, &api_base, &relay_socket).await;
    let fields = SetupFields {
        admin_username: "admin".to_string(),
        admin_password: ADMIN_PASSWORD.to_string(),
        default_domain: DOMAIN.to_string(),
        admin_cidrs: vec!["10.0.0.0/8".to_string()],
        server_hostname: HOSTNAME.to_string(),
        db_password: Zeroizing::new("wardstone".to_string()),
        master_passphrase: SETUP_PASSPHRASE.to_string(),
        master_passphrase_confirm: SETUP_PASSPHRASE.to_string(),
    };
    let response = web_request(
        &pre_setup,
        Method::POST,
        "/setup",
        None,
        false,
        Some(serde_json::to_value(&fields).expect("the setup fields must serialize")),
    )
    .await;
    // Capture first, restore second: the conversion — and the api's
    // relayed unlock — rotate the shared login role's password, and the
    // restore must land before any assertion below can panic (the
    // self-cleaning contract).
    let post_status = response.status();
    let bootstrap_dead = !bootstrap_credential_connects().await;
    fixture.restore_role_password().await;
    assert_eq!(post_status, StatusCode::OK, "the setup POST succeeds");
    let setup_body = body_str(response).await;
    let parsed = parse_json(&setup_body);
    assert_eq!(parsed["status"], "ok", "the setup submit reports success");
    assert_eq!(
        parsed["resume"], true,
        "the setup submit carries the resume contract (the listener swaps \
         onto the CA-issued leaf in place — no restart, no re-listen)"
    );
    // The seal-at-creation setup sealed the shared volume's FOUR
    // bootstrap envelopes — the JWT pair's included (every key is minted
    // straight into its envelope; the relayed unlock merely opens it).
    assert!(
        [
            ws_web::setup::MASTER_ENVELOPE_FILE,
            ws_web::setup::SECRET_ENVELOPE_FILE,
            ws_web::setup::JWT_ENVELOPE_FILE,
            ws_web::setup::DB_CREDENTIAL_ENVELOPE_FILE,
        ]
        .iter()
        .all(|name| fixture.keys_dir.join(name).exists()),
        "the setup seals the shared volume"
    );
    assert!(
        !fixture.keys_dir.join("jwt-signing-key.pem").exists()
            && !fixture.keys_dir.join("jwt-verify-key.pem").exists(),
        "no plaintext JWT key pair ever exists on a fresh install"
    );
    // The rotation's real evidence: the bootstrap credential the compose
    // env carried is dead (both the conversion's and the api's own
    // rotation ALTERed the role).
    assert!(
        bootstrap_dead,
        "the conversion and the relayed unlock kill the bootstrap credential"
    );
    // The relay actually landed: the api process came up with its full
    // surface behind the sealed shell's delegate.
    let health = reqwest::get(format!("{api_base}/api/v1/healthz"))
        .await
        .expect("probe the api's health surface")
        .text()
        .await
        .expect("read the health body");
    assert!(
        health.contains(r#""state":"unlocked""#),
        "the setup commit's relay unlocked the api: {health}"
    );
    let web = front(&fixture.pool, &fixture.keys_dir, &api_base, &relay_socket).await;
    (web, setup_body)
}

/// The setup admin's login through the UI relay: 200 with the identity
/// ONLY (the exact MeResponse key set, zero token fields — the shape pin
/// that makes the token boundary structural, not just swept), and the
/// cookie with all four flags. Returns the session id and the body text.
async fn ui_login_admin(web: &Router) -> (Uuid, String) {
    let response = web_request(
        web,
        Method::POST,
        "/auth/ui/login",
        None,
        true,
        Some(json!({"username": "admin", "password": ADMIN_PASSWORD})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "the UI login succeeds");
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("the login sets the session cookie")
        .to_str()
        .expect("the cookie value is ASCII")
        .to_owned();
    assert!(
        set_cookie.starts_with(&format!("{SESSION_COOKIE}=")),
        "the cookie is the session cookie: {set_cookie}"
    );
    assert_cookie_flags(&set_cookie);
    let text = body_str(response).await;
    let body = parse_json(&text);
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
    let got_keys: HashSet<String> = body
        .as_object()
        .expect("the login body is a JSON object")
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        got_keys, expected_keys,
        "the login body is the identity only"
    );
    assert_eq!(body["username"], "admin");
    assert_eq!(body["role"], "admin");
    assert_eq!(body["actor_type"], "user");
    (session_id_of(&set_cookie), text)
}

/// Drive one request through a router via `tower`'s oneshot (the
/// session_test idiom): an optional session cookie, the CSRF marker the
/// cookie-carrying mutating routes demand, a JSON body.
async fn web_request(
    router: &Router,
    method: Method,
    uri: &str,
    cookie: Option<&str>,
    csrf: bool,
    json_body: Option<Value>,
) -> axum::http::Response<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
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

/// Read a response body as text (the form the token-boundary sweep scans).
async fn body_str(response: axum::http::Response<Body>) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 4 << 20)
        .await
        .expect("read the response body");
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Parse a body's text as JSON (used after the text joined the sweep).
fn parse_json(text: &str) -> Value {
    serde_json::from_str(text).expect("the response body is JSON")
}

/// The raw `Cookie` header value presenting `id` as the session.
fn cookie_raw(id: &Uuid) -> String {
    format!("{SESSION_COOKIE}={id}")
}

/// The session id a successful login's `Set-Cookie` line carries.
fn session_id_of(set_cookie: &str) -> Uuid {
    let pair = set_cookie.split(';').next().expect("the cookie pair");
    let value = pair
        .strip_prefix(&format!("{SESSION_COOKIE}="))
        .expect("the cookie carries the session id");
    Uuid::parse_str(value).expect("the cookie value is a session uuid")
}

/// The four cookie flags the relay pins, asserted on a `Set-Cookie` line.
fn assert_cookie_flags(set_cookie: &str) {
    for flag in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"] {
        assert!(
            set_cookie.contains(flag),
            "the cookie carries {flag}: {set_cookie}"
        );
    }
}

/// THE token-boundary assertion: no response body of the flow carries
/// session or API-token material — the `ws_rt_` refresh-prefix, the
/// `ws_at_` API-token-prefix, the `Bearer ` scheme word (the injected
/// header's wire form), or any extra fixture-named marker.
fn assert_token_boundary(bodies: &[String], extra_markers: &[&str]) {
    let joined = bodies.join("\n");
    let mut markers: Vec<&str> = vec!["ws_rt_", "ws_at_", "Bearer "];
    markers.extend(extra_markers.iter().copied());
    for marker in markers {
        assert!(
            !joined.contains(marker),
            "a response body carries {marker:?} — the browser must never hold token material"
        );
    }
}

/// The end-to-end scenario, in this exact order (see the module docs).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn setup_login_issue_revoke_and_service_identity_work_end_to_end() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;

    // -- 1. First-run setup through the real setup route --------------------
    // No api process exists in this world (the sealed-shell relay path
    // and the builder's rotation are the front-door suites' and
    // ws-api's own coverage): no relay socket exists, and
    // the setup must succeed ANYWAY — the best-effort contract whose
    // recovery is the api's restart plus its own unlock.
    let setup_router = setup::setup_router(SetupState {
        keys_dir: fixture.keys_dir.clone(),
        fingerprint: PAGE_FINGERPRINT.to_string(),
        hostname: HOSTNAME.to_string(),
        tls_reload: None,
        // The modeled no-api world (Task 10, D8): an absent relay
        // directory keeps the setup commit's unlock relay inert.
        relay_socket: std::env::temp_dir().join("ws-e2e-no-relay/relay.sock"),
        database_url: database_url(),
    });
    let fields = SetupFields {
        admin_username: "admin".to_string(),
        admin_password: ADMIN_PASSWORD.to_string(),
        default_domain: DOMAIN.to_string(),
        admin_cidrs: vec!["10.0.0.0/8".to_string()],
        server_hostname: HOSTNAME.to_string(),
        db_password: Zeroizing::new("wardstone".to_string()),
        master_passphrase: SETUP_PASSPHRASE.to_string(),
        master_passphrase_confirm: SETUP_PASSPHRASE.to_string(),
    };
    let response = post_json(
        &setup_router,
        "/setup",
        None,
        serde_json::to_value(&fields).expect("the setup fields must serialize"),
    )
    .await;
    // Capture first, restore second: the conversion rotates the shared
    // login role's password, and the restore must land before any
    // assertion below can panic (the self-cleaning contract).
    let post_status = response.status();
    let bootstrap_dead = !bootstrap_credential_connects().await;
    fixture.restore_role_password().await;
    assert_eq!(post_status, StatusCode::OK, "the setup POST succeeds");
    assert!(
        bootstrap_dead,
        "the conversion's rotation kills the bootstrap credential"
    );
    let setup_body = body_json(response).await;
    assert_eq!(
        setup_body["status"], "ok",
        "the setup submit reports success"
    );
    assert_eq!(
        setup_body["resume"], true,
        "the setup submit carries the resume contract (the listener swaps onto \
         the CA-issued leaf in place — no restart, no re-listen)"
    );

    // -- 2. The API router over the SAME pool and keys directory ------------
    // The api process's post-unlock construction, modeled in-process:
    // the JWT pair's envelope was minted by the setup commit itself
    // (seal-at-creation: no key is ever minted in plaintext and
    // converted later), so this call merely LOADS it, and the CA
    // master + secret-encryption keys open from their envelopes into
    // RAM custody — the sealed volume holds no plaintext for the file
    // mode to read. The builder's own pool + rotation are the
    // sealed-test's and the front-door helper's coverage; here the
    // fixture's pool keeps this world divergence-free while the
    // CUSTODY (what the issuance cycle exercises) is the production
    // shape.
    let jwt = ws_auth::jwt::load_or_create_sealed(
        &fixture.keys_dir.join(ws_web::setup::JWT_ENVELOPE_FILE),
        SETUP_PASSPHRASE.as_bytes(),
        0,
    )
    .expect("load the setup-minted JWT pair envelope");
    assert!(
        !fixture.keys_dir.join("jwt-signing-key.pem").exists()
            && !fixture.keys_dir.join("jwt-verify-key.pem").exists(),
        "no plaintext JWT key pair ever exists on a fresh install"
    );
    let master = ws_core::crypto::KeyEnvelope::open_envelope(
        &fixture.keys_dir.join(ws_web::setup::MASTER_ENVELOPE_FILE),
        SETUP_PASSPHRASE,
    )
    .expect("open the master envelope the setup sealed");
    let secret = ws_core::crypto::KeyEnvelope::open_envelope(
        &fixture.keys_dir.join(ws_web::setup::SECRET_ENVELOPE_FILE),
        SETUP_PASSPHRASE,
    )
    .expect("open the secret-encryption envelope the setup sealed");
    let config = ApiConfig::new(DOMAIN.to_string(), fixture.keys_dir.clone());
    let mem = ws_secmem::global().expect("the protected pool initializes");
    let state = AppState::new_unlocked(
        fixture.pool.clone(),
        Arc::new(jwt),
        config,
        mem.alloc_copy(&master[..])
            .expect("the arena holds the master"),
        ws_core::crypto::SecretBox::from_key(
            mem.alloc_copy(&secret[..])
                .expect("the arena holds the secret key"),
        ),
    );
    let router = ws_api::router(state);

    // -- 3. Authenticate as the setup admin through the real login route ----
    let response = post_json(
        &router,
        "/api/v1/auth/login",
        None,
        json!({"username": "admin", "password": ADMIN_PASSWORD}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "the admin logs in");
    let login = body_json(response).await;
    let access = login["access_token"]
        .as_str()
        .expect("the login response carries an access token")
        .to_string();
    let refresh = login["refresh_token"]
        .as_str()
        .expect("the login response pairs a refresh token")
        .to_string();
    assert!(
        refresh.starts_with("ws_rt_"),
        "the refresh token carries the ws_rt_ prefix"
    );

    // -- 4. Create a profile through the API --------------------------------
    let response = post_json(
        &router,
        "/api/v1/profiles",
        Some(&access),
        json!({
            "name": "e2e-service",
            "description": "created by the e2e smoke test",
            "key_type": "ecdsa-p256",
            "key_usages": ["digital_signature", "key_encipherment"],
            "eku": ["server_auth"],
            "lifetime_days": LIFETIME_DAYS,
            "san_patterns": ["wardstone-e2e.test", "*.wardstone-e2e.test"]
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "create the profile");
    let profile = body_json(response).await;
    let profile_id: Uuid = profile["id"]
        .as_str()
        .expect("the profile response carries its id")
        .parse()
        .expect("the profile id is a UUID");
    let revision = &profile["current_revision"];
    let lifetime_days = revision["lifetime_days"]
        .as_i64()
        .expect("the profile revision carries its lifetime");
    let revision_id: Uuid = revision["id"]
        .as_str()
        .expect("the profile carries its current revision id")
        .parse()
        .expect("the revision id is a UUID");

    // -- 5. Issue a leaf from a CSR ------------------------------------------
    let cn = "svc.wardstone-e2e.test";
    let response = post_json(
        &router,
        "/api/v1/certificates",
        Some(&access),
        json!({
            "profile_id": profile_id,
            "subject_cn": cn,
            "sans": [cn],
            "csr_pem": mint_csr(cn, &[cn])
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "issue the first leaf");
    let issued = body_json(response).await;
    let cert_id: Uuid = issued["certificate_id"]
        .as_str()
        .expect("the issuance response carries the certificate id")
        .parse()
        .expect("the certificate id is a UUID");
    let cert_pem: String = issued["cert_pem"]
        .as_str()
        .expect("the issuance response carries the certificate PEM")
        .to_string();
    let issued_not_before: DateTime<Utc> = issued["not_before"]
        .as_str()
        .expect("the issuance response carries not_before")
        .parse()
        .expect("not_before is an RFC 3339 timestamp");
    let issued_not_after: DateTime<Utc> = issued["not_after"]
        .as_str()
        .expect("the issuance response carries not_after")
        .parse()
        .expect("not_after is an RFC 3339 timestamp");
    assert!(
        issued.get("private_key_pem").is_none(),
        "the CSR path must not return a private key (the client generated it)"
    );
    assert_eq!(
        issued["profile_name"], "e2e-service",
        "the leaf records the profile it was issued under"
    );
    assert_eq!(
        issued["profile_revision_id"]
            .as_str()
            .expect("the leaf records its profile revision"),
        revision_id.to_string(),
        "the leaf is pinned to the profile's current revision"
    );

    // The read endpoint agrees with the issuance response.
    let response = get_bearer(&router, &format!("/api/v1/certificates/{cert_id}"), &access).await;
    assert_eq!(response.status(), StatusCode::OK, "read the leaf back");
    let read_back = body_json(response).await;
    assert_eq!(read_back["status"], "active", "the fresh leaf is active");

    // -- 6. Revoke it ---------------------------------------------------------
    let response = post_json(
        &router,
        &format!("/api/v1/certificates/{cert_id}/revoke"),
        Some(&access),
        json!({"reason": "key_compromise"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "revoke the leaf");
    let revoked = body_json(response).await;
    assert_eq!(
        revoked["status"], "revoked",
        "the revoke response reports the new status"
    );
    let response = get_bearer(&router, &format!("/api/v1/certificates/{cert_id}"), &access).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "read the revoked leaf back"
    );
    let read_back = body_json(response).await;
    assert_eq!(
        read_back["status"], "revoked",
        "the read endpoint reports the revocation"
    );
    assert!(
        !read_back["revoked_at"].is_null(),
        "the revoked leaf carries its revocation timestamp"
    );
    assert_eq!(
        read_back["revocation_reason"], "key_compromise",
        "the revoked leaf carries the typed reason name"
    );

    // -- 7. A service identity's API token issues a second leaf --------------
    let response = post_json(
        &router,
        "/api/v1/service-identities",
        Some(&access),
        json!({
            "name": "e2e-worker",
            "description": "issued by the e2e smoke test",
            "capabilities": ["issue", "read_certificates"]
        }),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "create the service identity"
    );
    let identity = body_json(response).await;
    let api_token = identity["token"]
        .as_str()
        .expect("the mint response carries the plaintext token exactly once")
        .to_string();
    assert!(
        api_token.starts_with("ws_at_"),
        "the API token carries the ws_at_ prefix"
    );

    let cn2 = "worker.wardstone-e2e.test";
    let response = post_json(
        &router,
        "/api/v1/certificates",
        Some(&api_token),
        json!({
            "profile_id": profile_id,
            "subject_cn": cn2,
            "sans": [cn2],
            "csr_pem": mint_csr(cn2, &[cn2])
        }),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the service identity issues its own leaf"
    );
    let issued2 = body_json(response).await;
    let cert_id2: Uuid = issued2["certificate_id"]
        .as_str()
        .expect("the second issuance response carries the certificate id")
        .parse()
        .expect("the second certificate id is a UUID");

    // -- 8. The audit trail, read through the API (read_audit) ---------------
    let response = get_bearer(&router, "/api/v1/audit/export", &access).await;
    assert_eq!(response.status(), StatusCode::OK, "export the audit trail");
    let audit = body_json(response).await;
    let audit = audit
        .as_array()
        .expect("the export is a JSON array of entries")
        .clone();

    // -- 9. The setup route is GONE (unmounted, not refused) ------------------
    // This must run while the tenant still exists: `web_router` mounts the
    // setup routes exactly when the default tenant does NOT exist.
    let front = ws_web::web_router(
        fixture.pool.clone(),
        fixture.keys_dir.clone(),
        PAGE_FINGERPRINT.to_string(),
        HOSTNAME.to_string(),
        None,                 // no listener to swap in the router suites
        "http://127.0.0.1:9", // intentionally nothing listens here
        // The modeled no-api world's relay socket (Task 10, D8).
        &std::env::temp_dir().join("ws-e2e-no-relay/relay.sock"),
        database_url(), // the URL whose login role the conversion rotates
        ws_web::DEFAULT_SESSION_TTL,
        None, // no rate limiter on the front-door suites' routers
    )
    .await
    .expect("the front-door router builds after setup");
    let setup_gone_get = front
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/setup")
                .body(Body::empty())
                .expect("build the GET request"),
        )
        .await
        .expect("in-process GET /setup")
        .status();
    let setup_gone_post = post_setup_status(&front, &fields).await;

    // -- Cleanup (before the deep assertions, per the self-cleaning
    // contract): rows deleted, advisory lock released, keys dir removed.
    fixture.cleanup().await;

    // -- Assertions on the captured values ------------------------------------
    assert_eq!(
        setup_gone_get,
        StatusCode::NOT_FOUND,
        "the setup GET is not routed once a tenant exists"
    );
    assert_eq!(
        setup_gone_post,
        StatusCode::NOT_FOUND,
        "the setup POST is not routed (a plain 404, not a refusal)"
    );

    // The certificate parses and is signed by the setup root.
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes()).expect("the leaf is valid PEM");
    let cert = pem.parse_x509().expect("the leaf DER parses");
    let issuer_cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_owned);
    assert_eq!(
        issuer_cn.as_deref(),
        Some(DOMAIN),
        "the leaf is signed by the setup root (its subject is the setup domain)"
    );

    // The certificate carries the profile's EKU and key usages.
    let ku = cert
        .key_usage()
        .expect("the extensions parse")
        .expect("the profile pins key usages, so the leaf carries them");
    assert!(ku.critical, "the keyUsage extension is critical");
    assert!(ku.value.digital_signature(), "digital_signature is pinned");
    assert!(ku.value.key_encipherment(), "key_encipherment is pinned");
    assert!(!ku.value.key_cert_sign(), "a leaf is not a CA");
    let eku = cert
        .extended_key_usage()
        .expect("the extensions parse")
        .expect("the profile pins an EKU, so the leaf carries it");
    assert!(eku.value.server_auth, "the leaf carries the profile's EKU");

    // The response DTO's span equals the profile's lifetime EXACTLY
    // (not_after = not_before + lifetime — the skew margin lives in
    // not_before).
    assert_eq!(
        issued_not_after - issued_not_before,
        Duration::days(lifetime_days),
        "the leaf's span is the profile's {}-day lifetime exactly",
        lifetime_days
    );
    // The ENCODED certificate says the same thing: the parsed DER's own
    // validity carries the exact span, and it never diverges from the
    // response DTO's timestamps (the same DER-vs-DTO pair ws-ca's issue
    // tests pin).
    let validity = cert.validity();
    assert_eq!(
        validity.not_after.timestamp() - validity.not_before.timestamp(),
        lifetime_days * 86_400,
        "the encoded certificate's span is the profile's {}-day lifetime exactly",
        lifetime_days
    );
    assert_eq!(
        validity.not_before.timestamp(),
        issued_not_before.timestamp(),
        "the response DTO's not_before is the encoded certificate's"
    );
    assert_eq!(
        validity.not_after.timestamp(),
        issued_not_after.timestamp(),
        "the response DTO's not_after is the encoded certificate's"
    );

    // The audit trail: chronological order (the export is newest-first),
    // then the pinned sequence. `ca_created`, `cert_issued`, and
    // `cert_revoked` follow in that order, each with its right actor.
    let chronological: Vec<&Value> = audit.iter().rev().collect();
    let action_of = |entry: &Value| entry["action"].as_str().unwrap_or_default().to_string();
    let find_in_order =
        |chronological: &[&Value], start: usize, predicate: &dyn Fn(&Value) -> bool| {
            (start..chronological.len()).find(|&index| predicate(chronological[index]))
        };
    let ca_created = find_in_order(&chronological, 0, &|entry| action_of(entry) == "ca_created")
        .unwrap_or_else(|| panic!("the audit trail carries ca_created: {chronological:?}"));
    let ca_row = chronological[ca_created];
    assert_eq!(
        ca_row["actor_type"], "system",
        "the setup CA creation acts as the system"
    );
    assert_eq!(
        ca_row["auth_method"], "system",
        "the setup rows carry auth_method system"
    );

    let cert_issued = find_in_order(&chronological, ca_created + 1, &|entry| {
        action_of(entry) == "cert_issued" && entry["auth_method"] == "session"
    })
    .unwrap_or_else(|| {
        panic!("a session-issued cert_issued follows ca_created: {chronological:?}")
    });
    let session_issue_row = chronological[cert_issued];
    assert_eq!(
        session_issue_row["actor_type"], "user",
        "the admin session issues as a user"
    );
    assert_eq!(
        session_issue_row["target_id"],
        cert_id.to_string(),
        "the session cert_issued row targets the first leaf"
    );

    let cert_revoked = find_in_order(&chronological, cert_issued + 1, &|entry| {
        action_of(entry) == "cert_revoked"
    })
    .unwrap_or_else(|| panic!("cert_revoked follows cert_issued: {chronological:?}"));
    let revoke_row = chronological[cert_revoked];
    assert_eq!(
        revoke_row["auth_method"], "session",
        "the revocation acts over the admin's session"
    );
    assert_eq!(
        revoke_row["target_id"],
        cert_id.to_string(),
        "the cert_revoked row targets the first leaf"
    );

    let api_token_issue_rows: Vec<&&Value> = chronological
        .iter()
        .filter(|entry| action_of(entry) == "cert_issued" && entry["actor_type"] == "api_token")
        .collect();
    assert_eq!(
        api_token_issue_rows.len(),
        1,
        "exactly one issuance acts through an API token: {chronological:?}"
    );
    let api_token_row = api_token_issue_rows[0];
    assert_eq!(
        api_token_row["auth_method"], "api_token",
        "the API-token issuance row carries auth_method api_token"
    );
    assert_eq!(
        api_token_row["target_id"],
        cert_id2.to_string(),
        "the API-token issuance row targets the second leaf"
    );
}

/// Task 19's main pin: the UI SESSION path end to end, over the REAL
/// ws-api behind ws-web's composed front door. The setup runs through
/// the composed router itself; everything after it is the browser's day:
/// the cookie-flag login, cookie-only proxied reads and writes, the
/// typed-reason revocation, the chain, the statistics, the logout, and
/// the dead session's refusal — with EVERY response body swept for token
/// material (the browser must never hold `ws_rt_`/`ws_at_`/`Bearer `).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn ui_session_end_to_end() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;

    // -- 1. First-run setup through the composed front door ------------------
    let (web, setup_body) = setup_and_restarted_front(&fixture).await;
    let mut bodies = vec![setup_body];

    // The restarted door's setup surface is REPLACED (the unmounted
    // router), so a POST that slips through — a stale bookmark — gets the
    // plain 404 the setup/e2e suites pin: not refused, not routed at all.
    let late_fields = SetupFields {
        admin_username: "admin".to_string(),
        admin_password: ADMIN_PASSWORD.to_string(),
        default_domain: DOMAIN.to_string(),
        admin_cidrs: vec!["10.0.0.0/8".to_string()],
        server_hostname: HOSTNAME.to_string(),
        db_password: Zeroizing::new("wardstone".to_string()),
        master_passphrase: "the-master-passphrase".to_string(),
        master_passphrase_confirm: "the-master-passphrase".to_string(),
    };
    let response = web_request(
        &web,
        Method::POST,
        "/setup",
        None,
        false,
        Some(serde_json::to_value(&late_fields).expect("the setup fields must serialize")),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "the setup POST is not routed once a tenant exists"
    );

    // -- 2. The UI login: a cookie, an identity, and NO token ----------------
    let (session_id, login_body) = ui_login_admin(&web).await;
    bodies.push(login_body);
    let cookie = cookie_raw(&session_id);

    // -- 3. Cookie-only proxied reads: me, then the built-in profiles -------
    // (the cookie in; ws-web injects the stored bearer — the browser never
    // sees it — so every body from here joins the boundary sweep).
    let response = web_request(
        &web,
        Method::GET,
        "/api/v1/auth/me",
        Some(&cookie),
        false,
        None,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the cookie session authenticates through injection"
    );
    let text = body_str(response).await;
    let me = parse_json(&text);
    bodies.push(text);
    assert_eq!(me["username"], "admin", "the injected identity resolved");
    assert!(
        me["tenant_id"].is_string() && me["actor_id"].is_string(),
        "the identity carries its tenant and actor ids: {me}"
    );

    let response = web_request(
        &web,
        Method::GET,
        "/api/v1/profiles",
        Some(&cookie),
        false,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "the profiles list reads");
    let text = body_str(response).await;
    let profiles = parse_json(&text);
    bodies.push(text);
    let profiles = profiles
        .as_array()
        .expect("the profiles list is a JSON array");
    assert_eq!(
        profiles.len(),
        2,
        "setup's two built-in profiles are all there is: {profiles:?}"
    );
    assert!(
        profiles
            .iter()
            .any(|profile| profile["name"] == "web-server"),
        "the built-in web-server profile is present: {profiles:?}"
    );
    let profile_id: Uuid = profiles
        .iter()
        .find(|profile| profile["name"] == "web-server-ecdsa")
        .and_then(|profile| profile["id"].as_str())
        .expect("the built-in web-server-ecdsa profile is present")
        .parse()
        .expect("the profile id is a UUID");

    // -- 4. Issue a leaf through the proxied POST (the CSR path) -------------
    // The CSRF marker rides too — it is what the UI's own fetch sends, and
    // what the proxy's rule demands of any cookie-carrying mutation.
    let cn = "svc.wardstone-e2e.test";
    let response = web_request(
        &web,
        Method::POST,
        "/api/v1/certificates",
        Some(&cookie),
        true,
        Some(json!({
            "profile_id": profile_id,
            "subject_cn": cn,
            "sans": [cn],
            "csr_pem": mint_csr(cn, &[cn])
        })),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the proxied CSR issuance succeeds (the dual-path POST answers 200 \
         through json_no_store — not 201)"
    );
    let text = body_str(response).await;
    let issued = parse_json(&text);
    bodies.push(text);
    let cert_id: Uuid = issued["certificate_id"]
        .as_str()
        .expect("the issuance response carries the certificate id")
        .parse()
        .expect("the certificate id is a UUID");
    assert!(
        issued.get("private_key_pem").is_none(),
        "the CSR path returns no private key (the CSR holder keeps it)"
    );
    let cert_pem: String = issued["cert_pem"]
        .as_str()
        .expect("the issuance response carries the certificate PEM")
        .to_string();

    // -- 5. Revoke with the TYPED reason (the Plan-2 API shape) --------------
    let response = web_request(
        &web,
        Method::POST,
        &format!("/api/v1/certificates/{cert_id}/revoke"),
        Some(&cookie),
        true,
        Some(json!({"reason": "superseded", "detail": "replacing"})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "the revocation succeeds");
    let text = body_str(response).await;
    let revoked = parse_json(&text);
    bodies.push(text);
    assert_eq!(
        revoked["status"], "revoked",
        "the revoke response reports the new status"
    );
    assert_eq!(
        revoked["detail"], "replacing",
        "the free-text detail travels the typed-reason request"
    );

    // -- 6. Read-back: the typed reason survives the round trip --------------
    let response = web_request(
        &web,
        Method::GET,
        &format!("/api/v1/certificates/{cert_id}"),
        Some(&cookie),
        false,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "read the revoked leaf");
    let text = body_str(response).await;
    let detail = parse_json(&text);
    bodies.push(text);
    assert_eq!(detail["status"], "revoked");
    assert!(
        !detail["revoked_at"].is_null(),
        "the revoked leaf carries its revocation timestamp"
    );
    assert_eq!(
        detail["revocation_reason"], "superseded",
        "the TYPED reason name, not free text"
    );
    assert_eq!(
        detail["revocation_detail"], "replacing",
        "the detail is stored verbatim"
    );

    // -- 7. The trust chain: leaf-first PEM -----------------------------------
    let response = web_request(
        &web,
        Method::GET,
        &format!("/api/v1/certificates/{cert_id}/chain"),
        Some(&cookie),
        false,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "the chain reads");
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|value| value.to_str().expect("the content type is ASCII"))
            .expect("the chain carries a content type"),
        "application/x-pem-file",
        "the chain is a PEM body"
    );
    let chain = body_str(response).await;
    bodies.push(chain.clone());
    assert!(
        chain.matches("-----BEGIN CERTIFICATE-----").count() >= 2,
        "the chain carries the leaf and its issuing root"
    );
    assert!(
        chain.contains(&cert_pem),
        "the chain is leaf-first (the issued PEM comes first)"
    );

    // -- 8. The estate statistics agree with what just happened -------------
    let response = web_request(
        &web,
        Method::GET,
        "/api/v1/certificates/statistics",
        Some(&cookie),
        false,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "the statistics read");
    let text = body_str(response).await;
    let statistics = parse_json(&text);
    bodies.push(text);
    // The fresh tenant's whole estate: the setup's CA-issued server leaf
    // is the one ACTIVE row; the leaf this flow just revoked is the one
    // REVOKED row.
    assert_eq!(
        statistics["active"], 1,
        "the one active certificate is setup's server leaf: {statistics}"
    );
    assert_eq!(
        statistics["revoked"], 1,
        "the one revoked certificate is this flow's leaf: {statistics}"
    );

    // -- 9. Logout: revokes server-side, clears the cookie -------------------
    let response = web_request(
        &web,
        Method::POST,
        "/auth/ui/logout",
        Some(&cookie),
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
        set_cookie.starts_with(&format!("{SESSION_COOKIE}=;")),
        "the logout clears the cookie: {set_cookie}"
    );
    assert!(
        set_cookie.contains("Max-Age=0"),
        "the cleared cookie carries Max-Age=0: {set_cookie}"
    );
    assert_cookie_flags(&set_cookie);

    // -- 10. The dead session stays dead --------------------------------------
    let response = web_request(
        &web,
        Method::GET,
        "/api/v1/auth/me",
        Some(&cookie),
        false,
        None,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "the cleared session cannot authenticate a new request"
    );
    let text = body_str(response).await;
    bodies.push(text.clone());
    assert_eq!(
        parse_json(&text)["error"]["code"],
        "unauthorized",
        "ws-api's own error envelope passes through: {text}"
    );

    // -- 11. THE token boundary: no body of the WHOLE flow carries a token ---
    assert_token_boundary(&bodies, &[]);

    fixture.cleanup().await;
}

/// Task 19's second pin: the GENERIC-PROVIDER OIDC round trip through
/// every seam. The provider is `common/oidc_provider.rs` — a loopback
/// stub whose RSA keypair is generated at test time (the `openssl` CLI,
/// the house pattern) and whose id_token is genuinely RS256-signed — so
/// ws-api's REAL discovery/token-exchange/JWKS-verification runs, not a
/// mock.
///
/// The account-resolution decision this test documents (ws-api HEAD,
/// `routes/auth.rs::resolve_oidc_user`): match by stored `oidc_sub`
/// first; link by email ONLY when the provider verifies it; CREATE
/// otherwise. The fixture identity carries an email no seeded user holds
/// (with `email_verified: true`), so the flow takes the CREATE path: a
/// least-privilege `viewer` with `auth_provider = "oidc"` and the subject
/// stored — NOT a link into the admin (whose row stays `local` and
/// subject-less). The second round trip then resolves BY the stored
/// subject: no second account is created.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn ui_oidc_end_to_end() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;

    // -- The loopback provider fixture ---------------------------------------
    let client_id = "wardstone-ui-e2e";
    let subject = "ws-oidc-sub-e2e-0001";
    let email = "sso.user@wardstone-e2e.test";
    let name = "sso.user"; // username_for sanitizes to exactly this
    let provider = OidcProvider::spawn(client_id, subject, email, name);

    // -- Setup through the composed front door, then the admin's session ----
    let (web, setup_body) = setup_and_restarted_front(&fixture).await;
    let mut bodies = vec![setup_body];
    let (admin_session, login_body) = ui_login_admin(&web).await;
    bodies.push(login_body);
    let cookie = cookie_raw(&admin_session);

    // -- Seed the provider config THROUGH the proxy ---------------------------
    // The ManageSystem PUT rides the admin's cookie session (injected
    // bearer + the CSRF marker); the discovery_url is the fixture's.
    let response = web_request(
        &web,
        Method::PUT,
        "/api/v1/oidc/config",
        Some(&cookie),
        true,
        Some(json!({
            "provider_type": "custom",
            "display_name": "House OIDC (e2e fixture)",
            "discovery_url": provider.discovery_url(),
            "client_id": client_id,
            "client_secret": "ws_test_secret_material",
            "redirect_uri": format!("https://{HOSTNAME}/auth/ui/oidc/custom/callback"),
            "scopes": "openid profile email",
        })),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the provider config seeds through the proxied PUT"
    );
    let text = body_str(response).await;
    let config = parse_json(&text);
    bodies.push(text);
    assert_eq!(config["provider_type"], "custom");
    assert_eq!(
        config["client_secret_set"], true,
        "the read shape reports a stored secret"
    );
    assert!(
        config.get("client_secret").is_none(),
        "the secret never leaves the server: {config}"
    );

    // The login-page's SSO flag, relayed PUBLICLY (a fresh browser's very
    // first request, no session): configured, under the provider label
    // the start route resolves.
    let response = web_request(&web, Method::GET, "/auth/ui/config", None, false, None).await;
    assert_eq!(response.status(), StatusCode::OK, "the flag reads pre-auth");
    let text = body_str(response).await;
    let flag = parse_json(&text);
    bodies.push(text);
    assert_eq!(flag["oidc_configured"], true);
    assert_eq!(
        flag["provider"], "custom",
        "the relay answers the provider-type label"
    );

    // -- The start: a verbatim 303 to the fixture's authorize endpoint -------
    let response = web_request(
        &web,
        Method::GET,
        "/auth/ui/oidc/custom/start",
        None,
        false,
        None,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "ws-api's Redirect::to is a 303, passed through untouched"
    );
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("the redirect carries its Location")
        .to_str()
        .expect("the location is ASCII")
        .to_owned();
    assert!(
        location.starts_with(&provider.authorization_endpoint()),
        "the location IS the fixture's authorization endpoint: {location}"
    );
    for piece in [
        "response_type=code",
        "client_id=wardstone-ui-e2e",
        "scope=openid",
        "redirect_uri=",
        HOSTNAME,
    ] {
        assert!(
            location.contains(piece),
            "the minted URL carries {piece}: {location}"
        );
    }
    assert!(
        !location.contains("client_secret"),
        "the secret never travels in the authorization URL: {location}"
    );
    let state = location
        .split("state=")
        .nth(1)
        .unwrap_or_default()
        .split('&')
        .next()
        .unwrap_or_default()
        .to_string();
    assert!(!state.is_empty(), "ws-api minted a nonempty csrf state");

    // -- The callback: exchange at the fixture, session minted, 303 to / -----
    // The provider bounces the browser HERE (the config's redirect_uri
    // host), carrying the code and ws-api's own state.
    let response = web_request(
        &web,
        Method::GET,
        &format!("/auth/ui/oidc/custom/callback?code={CODE}&state={state}"),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "the exchange succeeded and the relay mints the session"
    );
    let back = response
        .headers()
        .get(header::LOCATION)
        .expect("the callback redirects")
        .to_str()
        .expect("ascii")
        .to_owned();
    assert_eq!(back, "/", "the successful callback lands on the SPA root");
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("the callback sets the session cookie")
        .to_str()
        .expect("ascii")
        .to_owned();
    assert!(set_cookie.starts_with(&format!("{SESSION_COOKIE}=")));
    assert_cookie_flags(&set_cookie);
    let sso_session = session_id_of(&set_cookie);

    // -- The OIDC session resolves the created account ------------------------
    let response = web_request(
        &web,
        Method::GET,
        "/api/v1/auth/me",
        Some(&cookie_raw(&sso_session)),
        false,
        None,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the SSO session authenticates through injection"
    );
    let text = body_str(response).await;
    let me = parse_json(&text);
    bodies.push(text);
    assert_eq!(
        me["username"], name,
        "the created account answers with its sanitized username"
    );
    assert_eq!(
        me["role"], "viewer",
        "the on-the-fly account is the LEAST-PRIVILEGE role"
    );
    assert_eq!(me["actor_type"], "user");

    // -- The account, read DIRECTLY from the DB -------------------------------
    // The CREATE path's shape: the subject stored, `oidc` as the
    // provider, the fixture email as the unique identifier.
    let rows = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT username, role, auth_provider, email FROM users WHERE oidc_sub = $1",
    )
    .bind(subject)
    .fetch_all(&fixture.pool)
    .await
    .expect("read the subject-linked user rows");
    assert_eq!(
        rows.len(),
        1,
        "exactly one account carries the subject: {rows:?}"
    );
    assert_eq!(
        rows[0],
        (
            name.to_string(),
            "viewer".to_string(),
            "oidc".to_string(),
            email.to_string()
        ),
        "the created account is the SSO identity, least-privilege"
    );

    // The admin's own account is NOT linked (the email never matched, and
    // nothing in the flow links without a match): still local, still
    // subject-less.
    let (admin_sub, admin_provider): (Option<String>, String) = sqlx::query_as(
        "SELECT oidc_sub, auth_provider FROM users WHERE username = 'admin' \
         AND tenant_id = (SELECT id FROM tenants WHERE name = $1)",
    )
    .bind(setup::DEFAULT_TENANT_NAME)
    .fetch_one(&fixture.pool)
    .await
    .expect("read the setup admin row");
    assert!(
        admin_sub.is_none(),
        "the admin's account is not linked by the SSO flow: {admin_sub:?}"
    );
    assert_eq!(admin_provider, "local");

    // -- Second round trip: resolution BY the stored subject ------------------
    // The linkage `resolve_oidc_user` does on the FIRST login now short-
    // circuits every later one: the same subject finds the SAME account,
    // creating no duplicate.
    let response = web_request(
        &web,
        Method::GET,
        "/auth/ui/oidc/custom/start",
        None,
        false,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("the second start redirects")
        .to_str()
        .expect("ascii")
        .to_owned();
    let state_two = location
        .split("state=")
        .nth(1)
        .unwrap_or_default()
        .split('&')
        .next()
        .unwrap_or_default()
        .to_string();
    assert!(
        !state_two.is_empty() && state_two != state,
        "a fresh state mints per start (never reused): {state_two}"
    );
    let response = web_request(
        &web,
        Method::GET,
        &format!("/auth/ui/oidc/custom/callback?code={CODE}&state={state_two}"),
        None,
        false,
        None,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "the second exchange resolves by the stored subject"
    );
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("the second callback sets the cookie")
        .to_str()
        .expect("ascii")
        .to_owned();
    let second_session = session_id_of(&set_cookie);
    let response = web_request(
        &web,
        Method::GET,
        "/api/v1/auth/me",
        Some(&cookie_raw(&second_session)),
        false,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    // The second round trip's body joins the sweep too: the token-boundary
    // claim at the test's end is exhaustive only if EVERY body the flow
    // produced is in the set — this /me was the one straggler.
    let me_text = body_str(response).await;
    bodies.push(me_text.clone());
    let me = parse_json(&me_text);
    assert_eq!(
        me["username"], name,
        "the same account answers the second round trip"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE oidc_sub = $1")
        .bind(subject)
        .fetch_one(&fixture.pool)
        .await
        .expect("count the subject-linked users");
    assert_eq!(
        count, 1,
        "the by-subject resolution created no duplicate account"
    );

    // -- THE token boundary: no body of the flow carries token material ------
    // The fixture's own provider-side access token is an extra named
    // marker: if it ever leaked into a browser-facing body, the boundary
    // is broken even though it carries no ws_ prefix.
    assert_token_boundary(&bodies, &[common::oidc_provider::FIXTURE_ACCESS_TOKEN]);

    fixture.cleanup().await;
}

/// The front-door POST /setup's status (the GET was driven separately
/// above); captured before cleanup, asserted after it.
async fn post_setup_status(front: &Router, fields: &SetupFields) -> StatusCode {
    let payload: Value = serde_json::to_value(fields).expect("the setup fields must serialize");
    post_json(front, "/setup", None, payload).await.status()
}
