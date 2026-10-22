//! Integration tests for the `ws-api` axum surface (Task 10).
//!
//! These tests run against a live Postgres and are marked `#[ignore]`.
//! Run them with:
//!
//! ```sh
//! DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test \
//!     cargo test -p ws-api --test api_test -- --include-ignored
//! ```
//!
//! # Self-cleaning contract
//!
//! The shared `wardstone_test` database is also used by the ws-core suites,
//! one of which asserts that `tenants` is empty after its runs. To keep that
//! true no matter how this suite exits: every test sweeps away rows a
//! previously crashed run may have left behind under this suite's owned
//! tenant name, and every row inserted during the body is deleted *before*
//! the assertions run, so a failing assertion cannot leave rows behind.
//! All query results are captured and unwrapped only after cleanup.
//!
//! # Cross-process serialization
//!
//! Each test body holds a session-level Postgres advisory lock for its whole
//! duration on the key [`ADVISORY_KEY`] — the "WARDST" family (ASCII
//! "WARDST" = 0x5741445354) with suite marker 0x000f. ws-core's suites hold
//! 0x0003..0x0005 and ws-ca's serial suite holds 0x0006; this suite owns a
//! disjoint row set, and plain `cargo test` also runs test binaries
//! sequentially, so the key is a belt against concurrent cross-crate runs.
//! The in-process mutex mirrors the ws-core pattern.

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use axum::http::{header, HeaderValue, Request, StatusCode};
use axum::Router;
use chrono::{DateTime, Duration, SecondsFormat, SubsecRound, Utc};
use serde_json::{json, Value};
use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex as TokioMutex;
use tower::ServiceExt;
use uuid::Uuid;

use ws_api::{ApiConfig, AppState};
use ws_auth::jwt::{issue_access_token, AccessClaims, JwtKeys};
use ws_auth::service_identity::create_service_identity;
use ws_core::db::connect;
use ws_core::models::rbac::Role;
use ws_core::models::rbac::{Actor, ActorType, AuthMethod, Capability, ALL_CAPABILITIES};
use ws_core::repo::audit_repo::AuditRepo;
use ws_core::repo::credential_repo::CredentialRepo;

/// The response type the test helpers return.
type TestResponse = axum::http::Response<axum::body::Body>;

/// Postgres advisory-lock key for this suite: ASCII "WARDST" (0x5741445354)
/// plus the suite marker 0x000f. Processes taking this key serialize their
/// test bodies against this suite.
const ADVISORY_KEY: i64 = 0x0057_4144_5354_000f;

/// The tenant name this suite owns; swept before use, deleted at the end.
const API_TENANT: &str = "rt-api-tenant";

/// In-process serialization, the same whole-body lock pattern as the
/// ws-core suites: the harness runs tests on separate threads. A tokio
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
/// connection, exactly like the ws-ca suites.
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
    /// Tenants created by the test body (in addition to [`API_TENANT`]);
    /// all of them are deleted by `cleanup`.
    extra_tenants: Mutex<Vec<Uuid>>,
}

impl Fixture {
    /// Delete every row this fixture (and the test body) created, then
    /// release the advisory lock. Runs BEFORE the assertions, so a failing
    /// assert can never leave rows behind (the self-cleaning contract).
    async fn cleanup(&mut self) {
        sqlx::query("DELETE FROM audit_log WHERE tenant_id = $1")
            .bind(self.tenant_id)
            .execute(&self.pool)
            .await
            .expect("delete fixture audit rows");
        for table in [
            "DELETE FROM certificates WHERE tenant_id = $1",
            "DELETE FROM used_serials WHERE tenant_id = $1",
            "DELETE FROM one_shot_tokens WHERE tenant_id = $1",
            "DELETE FROM service_identity_capabilities WHERE service_identity_id \
             IN (SELECT id FROM service_identities WHERE tenant_id = $1)",
            "DELETE FROM service_identities WHERE tenant_id = $1",
            "DELETE FROM profiles WHERE tenant_id = $1",
            "DELETE FROM cas WHERE tenant_id = $1",
            "DELETE FROM oidc_config WHERE tenant_id = $1",
            "DELETE FROM refresh_tokens WHERE tenant_id = $1",
            "DELETE FROM users WHERE tenant_id = $1",
        ] {
            sqlx::query(table)
                .bind(self.tenant_id)
                .execute(&self.pool)
                .await
                .expect("delete fixture rows");
        }
        let mut extra = self.extra_tenants.lock().unwrap().clone();
        extra.push(self.tenant_id);
        for tenant_id in extra {
            // A tenant created by the body may already have audit rows
            // recorded under the OTHER tenant's log (the actor's tenant) —
            // those are covered above. Profiles and users created for the
            // extra tenant must go first: their FKs reference it.
            sqlx::query("DELETE FROM audit_log WHERE tenant_id = $1")
                .bind(tenant_id)
                .execute(&self.pool)
                .await
                .expect("delete extra tenant audit rows");
            for table in [
                "DELETE FROM certificates WHERE tenant_id = $1",
                "DELETE FROM profiles WHERE tenant_id = $1",
                "DELETE FROM cas WHERE tenant_id = $1",
                "DELETE FROM users WHERE tenant_id = $1",
                "DELETE FROM tenants WHERE id = $1",
            ] {
                sqlx::query(table)
                    .bind(tenant_id)
                    .execute(&self.pool)
                    .await
                    .expect("delete extra tenant rows");
            }
        }
        if self.advisory.is_some() {
            let mut conn = self.advisory.take().expect("advisory connection held");
            release_advisory(&mut conn, ADVISORY_KEY).await;
        }
        // The per-fixture keys directory (JWT pair + keystore master key).
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
    sweep_tenant(&pool, API_TENANT).await;

    let tenant_id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(tenant_id)
        .bind(API_TENANT)
        .execute(&pool)
        .await
        .expect("insert fixture tenant");

    let admin_id = Uuid::new_v4();
    insert_user(&pool, tenant_id, admin_id, "admin", Role::Admin).await;

    let keys_dir = std::env::temp_dir().join(format!(
        "ws-api-test-keys-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    let mut keystore = ws_ca::keystore::KeyStore::open(&keys_dir).expect("open keystore");
    keystore.ensure_master_key().expect("ensure master key");
    // The TOTP/OIDC secret-encryption envelope key (created at setup).
    ws_core::crypto::SecretBox::create(&keys_dir.join("secret-encryption.key"))
        .expect("create the secret-encryption key");
    let jwt = JwtKeys::load_or_create(&keys_dir).expect("load or create the JWT key pair");

    let config = ApiConfig::new("wardstone.test".to_string(), keys_dir.clone());
    let state = AppState::new(pool.clone(), std::sync::Arc::new(jwt), config);
    let router = ws_api::router(state.clone());

    Fixture {
        state,
        router,
        pool,
        tenant_id,
        admin_id,
        advisory: Some(advisory),
        keys_dir,
        extra_tenants: Mutex::new(Vec::new()),
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

/// A minimal, active user row (no password unless `password_hash` given).
async fn insert_user(pool: &PgPool, tenant_id: Uuid, id: Uuid, username: &str, role: Role) {
    ws_core::repo::user_repo::UserRepo::new()
        .insert(
            pool,
            &ws_core::models::user::UserModel {
                id,
                tenant_id,
                username: username.to_string(),
                display_name: username.to_string(),
                email: format!("{username}@wardstone.test"),
                role,
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
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        )
        .await
        .expect("insert fixture user");
}

/// The actor shape of the fixture's admin user (used as the creator for
/// token mints, whose creator actor must be a user id).
fn admin_actor(fixture: &Fixture) -> Actor {
    Actor {
        actor_type: ActorType::User,
        actor_id: fixture.admin_id.to_string(),
        auth_method: AuthMethod::Session,
        capabilities: ALL_CAPABILITIES.to_vec(),
        session_id: None,
        tenant_id: fixture.tenant_id,
        minted_by: None,
    }
}

/// Mint an API token for a service identity carrying exactly `caps`.
async fn api_token(fixture: &Fixture, caps: &[Capability]) -> String {
    create_service_identity(
        &fixture.pool,
        &format!("matrix-token-{}", Uuid::new_v4()),
        None,
        caps,
        &admin_actor(fixture),
        &CredentialRepo::new(),
    )
    .await
    .expect("mint the service identity token")
    .token
}

/// Mint a session access token for the fixture's admin user.
fn admin_token(fixture: &Fixture) -> String {
    let claims = AccessClaims::new(fixture.admin_id, "admin", "admin", None, 900);
    issue_access_token(&claims, &fixture.state.jwt).expect("issue the admin access token")
}

/// A session access token for `user_id` with role `role`.
fn session_token(fixture: &Fixture, user_id: Uuid, username: &str, role: &str) -> String {
    let claims = AccessClaims::new(user_id, username, role, None, 900);
    issue_access_token(&claims, &fixture.state.jwt).expect("issue a session access token")
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

/// Read a JSON error body's `error.code`.
fn error_code(body: &Value) -> String {
    body["error"]["code"]
        .as_str()
        .expect("error body carries an error.code")
        .to_string()
}

/// A valid ECDSA P-256 CSR (self-signed) for `cn` with DNS SANs `names`.
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

/// Create the issuance fixture through the API itself: one `ecdsa-p256`
/// profile with the `wardstone.test` SAN allow-list, one Ed25519 root CA.
/// Returns `(profile_id, ca_id)`.
async fn setup_profile_and_ca(fixture: &Fixture) -> (Uuid, Uuid) {
    let token = admin_token(fixture);
    let profile_res = post_json(
        fixture,
        "/api/v1/profiles",
        Some(&token),
        json!({
            "name": "test-profile",
            "description": "issued by the api test",
            "key_type": "ecdsa-p256",
            "key_usages": ["digital_signature"],
            "eku": ["server_auth"],
            "lifetime_days": 30,
            "san_patterns": ["wardstone.test", "*.wardstone.test"]
        }),
    )
    .await;
    assert_eq!(profile_res.status(), StatusCode::CREATED, "create profile");
    let profile_body = axum::body::to_bytes(profile_res.into_body(), 1 << 20)
        .await
        .unwrap();
    let profile: Value = serde_json::from_slice(&profile_body).unwrap();
    let profile_id = profile["id"].as_str().unwrap().parse::<Uuid>().unwrap();

    let ca_res = post_json(
        fixture,
        "/api/v1/cas",
        Some(&token),
        json!({
            "name": "test-root-ca",
            "subject": "Wardstone Test Root",
            "key_type": "ed25519",
            "is_root": true
        }),
    )
    .await;
    assert_eq!(ca_res.status(), StatusCode::CREATED, "create CA");
    let ca_body = axum::body::to_bytes(ca_res.into_body(), 1 << 20)
        .await
        .unwrap();
    let ca: Value = serde_json::from_slice(&ca_body).unwrap();
    let ca_id = ca["id"].as_str().unwrap().parse::<Uuid>().unwrap();

    (profile_id, ca_id)
}

/// Issue one certificate through the API (the CSR path) and return the
/// `(status, body)` pair.
async fn issue_csr(
    fixture: &Fixture,
    profile_id: Uuid,
    cn: &str,
    names: &[&str],
) -> (StatusCode, Value) {
    let token = admin_token(fixture);
    let res = post_json(
        fixture,
        "/api/v1/certificates",
        Some(&token),
        json!({
            "profile_id": profile_id,
            "subject_cn": cn,
            "sans": names,
            "csr_pem": mint_csr(cn, names)
        }),
    )
    .await;
    let status = res.status();
    let body = axum::body::to_bytes(res.into_body(), 4 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&body)
        .unwrap_or_else(|_| json!({"error": {"message": "non-json body"}}));
    (status, body)
}

/// Audit rows of the fixture tenant as (action, actor_type, auth_method,
/// details) rows.
async fn audit_rows(fixture: &Fixture) -> Vec<(String, String, String, Value)> {
    sqlx::query_as::<_, (String, String, String, Value)>(
        "SELECT action, actor_type, auth_method, details FROM audit_log \
         WHERE tenant_id = $1 ORDER BY created_at, id",
    )
    .bind(fixture.tenant_id)
    .fetch_all(&fixture.pool)
    .await
    .expect("read audit rows")
}

// ---------------------------------------------------------------------------
// The required tests
// ---------------------------------------------------------------------------

/// A request with no Authorization header is 401 — and a bearer the
/// middleware cannot recognize is 401 too (never 500, never 403).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn missing_or_garbage_bearer_is_401() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let res = send(
        &fx,
        Request::builder()
            .method("GET")
            .uri("/api/v1/certificates")
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/certificates")
        .header(header::AUTHORIZATION, "not-a-bearer-thing")
        .body(axum::body::Body::empty())
        .unwrap();
    let res = send(&fx, req).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/certificates")
        .header(header::AUTHORIZATION, bearer("ws_at_deadbeef"))
        .body(axum::body::Body::empty())
        .unwrap();
    let res = send(&fx, req).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    fx.cleanup().await;
}

/// A valid session token reaches the handler; a token whose actor lacks the
/// route capability is 403 — authorization, not authentication — and the
/// error code is `forbidden`.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn session_token_reaches_handler_and_wrong_capability_is_403() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    // An admin session token reaches the read endpoint: 200 with a JSON list.
    let res = get_bearer(&fx, "/api/v1/certificates", &admin_token(&fx)).await;
    assert_eq!(res.status(), StatusCode::OK);

    // A service identity with NO capabilities authenticates fine but is 403
    // on a route it may not call (403 — not 401 — is the assertion).
    let token = api_token(&fx, &[]).await;
    let res = get_bearer(&fx, "/api/v1/certificates", &token).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error_code(&body), "forbidden");

    // An expired/garbage JWT is 401 (authentication), not 403.
    let res = get_bearer(&fx, "/api/v1/certificates", "garbage.token.value").await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    fx.cleanup().await;
}

/// A successful issuance writes exactly ONE audit row, with the acting
/// user's `actor_type`/`auth_method` and the `cert_issued` action.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn issue_writes_exactly_one_audit_row() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let (profile_id, _ca_id) = setup_profile_and_ca(&fx).await;

    let (status, body) = issue_csr(
        &fx,
        profile_id,
        "host.wardstone.test",
        &["host.wardstone.test"],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "issue body: {body}");

    let rows = audit_rows(&fx).await;
    let rows = rows
        .iter()
        .filter(|(a, ..)| a == "cert_issued")
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1, "exactly one cert_issued row");
    let (action, actor_type, auth_method, details) = rows[0];
    assert_eq!(action, "cert_issued");
    assert_eq!(actor_type, "user");
    assert_eq!(auth_method, "session");
    assert_eq!(details["profile_id"], profile_id.to_string());
    assert!(
        details["serial"].is_string(),
        "the serial, as its string form"
    );
    assert!(details["sans"].is_array());

    fx.cleanup().await;
}

/// A mutation whose audit insert fails leaves NO mutation behind: the audit
/// row is forced to collide on `audit_log`'s primary key (a duplicate `id`),
/// the transaction aborts, and the certificate row must not exist — and the
/// serial drawn for it is released, not burned.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn audit_failure_rolls_back_the_mutation() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let (profile_id, _ca_id) = setup_profile_and_ca(&fx).await;

    // Pre-insert an audit row whose id the issuance must reuse — the
    // duplicate id forces the audit INSERT to fail with 23505
    // (CoreError::Duplicate), aborting the transaction.
    let doomed_audit_id = Uuid::new_v4();
    let doomed_cert_id = Uuid::new_v4();
    AuditRepo::new()
        .record(
            &fx.pool,
            &ws_core::models::audit::AuditEntry {
                id: doomed_audit_id,
                tenant_id: fx.tenant_id,
                actor_type: ActorType::User,
                auth_method: AuthMethod::Session,
                session_id: None,
                actor_id: fx.admin_id.to_string(),
                action: "pre-inserted".to_string(),
                target_type: "audit".to_string(),
                target_id: "collision".to_string(),
                details: json!({}),
                created_at: Utc::now(),
            },
        )
        .await
        .expect("pre-insert the colliding audit row");

    let actor = admin_actor(&fx);
    let body = ws_api::routes::certificates::IssueCertificateBody {
        profile_id,
        subject_cn: "host.wardstone.test".to_string(),
        sans: vec!["host.wardstone.test".to_string()],
        csr_pem: Some(mint_csr("host.wardstone.test", &["host.wardstone.test"])),
    };
    let outcome = ws_api::routes::certificates::issue_certificate_core(
        &fx.state,
        &actor,
        &body,
        doomed_cert_id,
        doomed_audit_id,
        None,
    )
    .await;
    assert!(
        outcome.is_err(),
        "the duplicate audit id must fail the issuance"
    );

    // The certificate row must not exist, and its serial must be back.
    let certs = sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM certificates WHERE id = $1")
        .bind(doomed_cert_id)
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    let serials =
        sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM used_serials WHERE tenant_id = $1")
            .bind(fx.tenant_id)
            .fetch_one(&fx.pool)
            .await
            .unwrap();
    fx.cleanup().await;

    assert_eq!(
        certs.0, 0,
        "no certificate row survives a failed audit insert"
    );
    assert_eq!(serials.0, 0, "the allocated serial is released, not burned");
}

/// Profile naming errors are specific for actors who may READ the profile
/// and generic otherwise; a non-issuer is always refused at the capability
/// check, before any validation.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn profile_naming_errors_are_specific_for_readers_and_generic_for_others() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let (profile_id, _ca_id) = setup_profile_and_ca(&fx).await;

    // (a) An actor holding Issue + ReadProfiles sees the specific message:
    // it names the failing name, never the permitted set.
    let token = admin_token(&fx);
    let res = post_json(
        &fx,
        "/api/v1/certificates",
        Some(&token),
        json!({
            "profile_id": profile_id,
            "subject_cn": "evil.other.com",
            "sans": ["evil.other.com"],
            "csr_pem": mint_csr("evil.other.com", &["evil.other.com"])
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error_code(&body), "not_permitted_by_profile");
    let message = body["error"]["message"].as_str().unwrap().to_string();
    assert!(
        message.contains("evil.other.com"),
        "names the failing name: {message}"
    );
    assert!(
        !message.contains("wardstone.test"),
        "never dumps the permitted set: {message}"
    );

    // (b) An actor with Issue but WITHOUT ReadProfiles gets the generic
    // message and learns nothing about the profile's contents.
    let narrow = api_token(&fx, &[Capability::Issue]).await;
    let res = post_json(
        &fx,
        "/api/v1/certificates",
        Some(&narrow),
        json!({
            "profile_id": profile_id,
            "subject_cn": "evil.other.com",
            "sans": ["evil.other.com"],
            "csr_pem": mint_csr("evil.other.com", &["evil.other.com"])
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error_code(&body), "not_permitted_by_profile");
    let message = body["error"]["message"].as_str().unwrap().to_string();
    assert!(
        message.contains("not permitted by policy"),
        "generic message: {message}"
    );
    assert!(
        !message.contains("evil.other.com") && !message.contains("wardstone.test"),
        "the generic message names neither the name nor the set: {message}"
    );

    // (c) An actor without Issue is refused by the capability check (403),
    // before any validation — even one who could read the profile.
    let viewer = api_token(&fx, &[Capability::ReadProfiles]).await;
    let res = post_json(
        &fx,
        "/api/v1/certificates",
        Some(&viewer),
        json!({
            "profile_id": profile_id,
            "subject_cn": "evil.other.com",
            "sans": ["evil.other.com"],
            "csr_pem": mint_csr("evil.other.com", &["evil.other.com"])
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // (d) An empty SAN list is refused (proposing no names is a different
    // artifact, not a subset).
    let res = post_json(
        &fx,
        "/api/v1/certificates",
        Some(&token),
        json!({
            "profile_id": profile_id,
            "subject_cn": "host.wardstone.test",
            "sans": [],
            "csr_pem": mint_csr("host.wardstone.test", &[])
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    fx.cleanup().await;
}

/// The two issuance paths are separate capabilities: an actor holding
/// `issue` cannot reach the server-key-generation path even though it CAN
/// reach the CSR path with the same profile.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn non_issuer_cannot_reach_the_key_generation_path() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let (profile_id, _ca_id) = setup_profile_and_ca(&fx).await;

    // An actor holding exactly `issue` CANNOT use the key-generation path
    // (no csr_pem): the required capability there is generate_leaf_key.
    let narrow = api_token(&fx, &[Capability::Issue]).await;
    let res = post_json(
        &fx,
        "/api/v1/certificates",
        Some(&narrow),
        json!({
            "profile_id": profile_id,
            "subject_cn": "host.wardstone.test",
            "sans": ["host.wardstone.test"]
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // The same actor CAN reach the CSR path (proving the 403 above is about
    // the path, not the actor).
    let res = post_json(
        &fx,
        "/api/v1/certificates",
        Some(&narrow),
        json!({
            "profile_id": profile_id,
            "subject_cn": "host.wardstone.test",
            "sans": ["host.wardstone.test"],
            "csr_pem": mint_csr("host.wardstone.test", &["host.wardstone.test"])
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    fx.cleanup().await;
}

/// The key-generation response carries the key exactly once, carries
/// `Cache-Control: no-store`, its `key_generated` audit row carries no key
/// material, no read endpoint hands the key back, and the key never
/// appears in the captured access log.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn key_generation_response_is_redacted_everywhere() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let (profile_id, _ca_id) = setup_profile_and_ca(&fx).await;
    let token = admin_token(&fx);

    let res = post_json(
        &fx,
        "/api/v1/certificates",
        Some(&token),
        json!({
            "profile_id": profile_id,
            "subject_cn": "gen.wardstone.test",
            "sans": ["gen.wardstone.test"]
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "the key-generation response is never cached"
    );
    let raw = axum::body::to_bytes(res.into_body(), 8 << 20)
        .await
        .unwrap();
    let raw_text = String::from_utf8(raw.to_vec()).unwrap();
    assert_eq!(
        raw_text.matches("BEGIN PRIVATE KEY").count(),
        1,
        "the private key appears exactly once in the response"
    );
    let body: Value = serde_json::from_str(&raw_text).unwrap();
    let cert_id = body["certificate_id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();

    // The audit row's action is key_generated and its details carry no key.
    let rows = audit_rows(&fx).await;
    let rows = rows
        .iter()
        .filter(|(a, ..)| a == "key_generated")
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1, "exactly one key_generated row");
    let (_, actor_type, _, details) = rows[0];
    assert_eq!(actor_type, "user");
    let details_text = details.to_string();
    assert!(
        !details_text.contains("PRIVATE KEY") && !details_text.contains("BEGIN"),
        "the key_generated details never carry key material: {details_text}"
    );
    assert_eq!(details["profile_id"], profile_id.to_string());
    assert_eq!(details["key_type"], "ecdsa-p256");

    // No later read endpoint returns the key.
    let res = get_bearer(&fx, &format!("/api/v1/certificates/{cert_id}"), &token).await;
    assert_eq!(res.status(), StatusCode::OK);
    let raw = axum::body::to_bytes(res.into_body(), 4 << 20)
        .await
        .unwrap();
    let text = String::from_utf8(raw.to_vec()).unwrap();
    assert!(
        !text.contains("PRIVATE KEY"),
        "the read endpoint never returns the key: {text}"
    );

    // The captured access log carries method/path/status only.
    let log = fx.state.access_log.snapshot();
    assert!(
        !log.iter()
            .any(|l| l.contains("PRIVATE KEY") || l.contains("BEGIN")),
        "the access log never carries the key: {log:?}"
    );
    assert!(
        log.iter().any(|l| l.contains("POST /api/v1/certificates")),
        "the key-generation request itself is logged: {log:?}"
    );

    fx.cleanup().await;
}

/// The one-shot pull endpoint issues exactly once: a bogus bearer does not
/// burn the token (the extractor is lookup-only), the first valid pull
/// issues, and a second attempt with the same token is 401.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn one_shot_pull_issues_exactly_once() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let (profile_id, _ca_id) = setup_profile_and_ca(&fx).await;

    // Mint a one-shot token through its route.
    let token = admin_token(&fx);
    let res = post_json(
        &fx,
        "/api/v1/one-shot-tokens",
        Some(&token),
        json!({"ttl_minutes": 10}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    let one_shot = body["token"].as_str().unwrap().to_string();
    assert!(one_shot.starts_with("ws_ot_"));

    // A stray bearer (malformed one-shot) must NOT burn the token.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates/pull")
        .header(
            header::AUTHORIZATION,
            bearer("ws_ot_00000000000000000000000000000000"),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            json!({
                "profile_id": profile_id,
                "subject_cn": "pull.wardstone.test",
                "sans": ["pull.wardstone.test"],
                "csr_pem": mint_csr("pull.wardstone.test", &["pull.wardstone.test"])
            })
            .to_string(),
        ))
        .unwrap();
    let res = send(&fx, req).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // And a valid API-token bearer is not accepted on the pull route at
    // all: it is gated by a one-shot token. (The body is deserialize-valid
    // — axum's extractor rejection would 422 before the handler's 401.)
    let at_token = api_token(&fx, &[Capability::Issue]).await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates/pull")
        .header(header::AUTHORIZATION, bearer(&at_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            json!({
                "profile_id": profile_id,
                "subject_cn": "pull.wardstone.test",
                "sans": ["pull.wardstone.test"],
                "csr_pem": mint_csr("pull.wardstone.test", &["pull.wardstone.test"])
            })
            .to_string(),
        ))
        .unwrap();
    let res = send(&fx, req).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // First valid pull: issues.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates/pull")
        .header(header::AUTHORIZATION, bearer(&one_shot))
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            json!({
                "profile_id": profile_id,
                "subject_cn": "pull.wardstone.test",
                "sans": ["pull.wardstone.test"],
                "csr_pem": mint_csr("pull.wardstone.test", &["pull.wardstone.test"])
            })
            .to_string(),
        ))
        .unwrap();
    let res = send(&fx, req).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), 4 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    let cert_id = body["certificate_id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();

    // Second attempt with the same token: 401 — the token is consumed.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates/pull")
        .header(header::AUTHORIZATION, bearer(&one_shot))
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            json!({
                "profile_id": profile_id,
                "subject_cn": "pull.wardstone.test",
                "sans": ["pull.wardstone.test"],
                "csr_pem": mint_csr("pull.wardstone.test", &["pull.wardstone.test"])
            })
            .to_string(),
        ))
        .unwrap();
    let res = send(&fx, req).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // The one-shot actor carries the minting user's id, which the audit
    // row's cert_issued details carry as `minted_by`.
    let rows = audit_rows(&fx)
        .await
        .into_iter()
        .filter(|(a, at, _, _)| a == "cert_issued" && at == "one_shot_token")
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].3["minted_by"], fx.admin_id.to_string());

    // The issued certificate is readable by an actor holding read.
    let res = get_bearer(
        &fx,
        &format!("/api/v1/certificates/{cert_id}"),
        &admin_token(&fx),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    fx.cleanup().await;
}

/// A one-shot token is a pull-route credential ONLY: the direct issuance
/// route `POST /api/v1/certificates` — reachable with an issue-capable
/// actor — refuses the one-shot bearer with 401 (the middleware never
/// resolves `ws_ot_` credentials, so the route cannot mint from them),
/// and the rejected bearer does not burn the token: the row's `used_at`
/// stays NULL, so the legitimate pull can still redeem it later.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn one_shot_bearer_refused_on_issuance_route_not_burned() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let (profile_id, _ca_id) = setup_profile_and_ca(&fx).await;

    // Mint a valid one-shot token through its route.
    let res = post_json(
        &fx,
        "/api/v1/one-shot-tokens",
        Some(&admin_token(&fx)),
        json!({"ttl_minutes": 10}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    let one_shot = body["token"].as_str().unwrap().to_string();
    assert!(one_shot.starts_with("ws_ot_"));

    // The direct issuance route refuses the one-shot bearer outright.
    let res = post_json(
        &fx,
        "/api/v1/certificates",
        Some(&one_shot),
        json!({
            "profile_id": profile_id,
            "subject_cn": "direct.wardstone.test",
            "sans": ["direct.wardstone.test"],
            "csr_pem": mint_csr("direct.wardstone.test", &["direct.wardstone.test"])
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // The rejected bearer never burned the token: the row is unclaimed.
    let rows: Vec<(Option<DateTime<Utc>>,)> =
        sqlx::query_as("SELECT used_at FROM one_shot_tokens WHERE tenant_id = $1")
            .bind(fx.tenant_id)
            .fetch_all(&fx.pool)
            .await
            .expect("read the one-shot row after the refused bearer");
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].0.is_none(),
        "a one-shot bearer refused by the issuance route must not burn the token"
    );

    fx.cleanup().await;
}

/// A profile edit that moves the revision makes the issuance retry against
/// the NEW revision rather than record a stale one.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn revision_move_makes_issuance_retry_not_record_stale() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let (profile_id, _ca_id) = setup_profile_and_ca(&fx).await;
    let token = admin_token(&fx);

    // Move the profile to revision 2 through the API.
    let res = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/profiles/{profile_id}"))
        .header(header::AUTHORIZATION, bearer(&token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            json!({
                "key_type": "ecdsa-p256",
                "key_usages": ["digital_signature"],
                "eku": ["server_auth"],
                "lifetime_days": 30,
                "san_patterns": ["wardstone.test", "*.wardstone.test"]
            })
            .to_string(),
        ))
        .unwrap();
    let res = send(&fx, res).await;
    assert_eq!(res.status(), StatusCode::OK, "profile edit");
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let revised: Value = serde_json::from_slice(&raw).unwrap();
    let revision_2 = revised["current_revision"]["id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();

    // Call the issuance core with the STALE revision pinned: the CAS must
    // fail, the issuance must retry against the current (revision 2), and
    // the certificate must carry revision 2's id — never the stale one.
    let actor = admin_actor(&fx);

    // Pin a definitely-stale revision: revision 1's row id.
    let revisions = ws_core::repo::profile_repo::ProfileRepo::new()
        .list_revisions(&fx.pool, profile_id)
        .await
        .unwrap();
    let rev1_id = revisions
        .iter()
        .find(|r| r.revision == 1)
        .expect("revision 1 exists")
        .id;

    let body = ws_api::routes::certificates::IssueCertificateBody {
        profile_id,
        subject_cn: "retry.wardstone.test".to_string(),
        sans: vec!["retry.wardstone.test".to_string()],
        csr_pem: Some(mint_csr("retry.wardstone.test", &["retry.wardstone.test"])),
    };
    let issued = ws_api::routes::certificates::issue_certificate_core(
        &fx.state,
        &actor,
        &body,
        Uuid::new_v4(),
        Uuid::new_v4(),
        Some(rev1_id),
    )
    .await
    .expect("the issuance retries onto the current revision");
    fx.cleanup().await;

    assert_eq!(
        issued.profile_revision_id, revision_2,
        "the certificate is pinned to the CURRENT revision, not the stale one"
    );
}

/// Every route in the capability table refuses a token lacking its
/// capability (403, not 401), and answers a token holding exactly that
/// capability with something other than 401/403 (validation failures
/// downstream are fine — the authorization boundary is what this proves).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn capability_table_refusal_matrix() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let (_profile_id, ca_id) = setup_profile_and_ca(&fx).await;
    let some_user = Uuid::new_v4();

    // (method, path, body-json, required capability). Bodies deserialize
    // (axum's extractor rejection would 422 before the handler's capability
    // check — not an authorization boundary) but name no real resource, so
    // the "permitted" leg proves authorization, not business-logic success
    // (covered by the dedicated tests above).
    let table: Vec<(&str, String, Option<Value>, Capability)> = vec![
        (
            "GET",
            "/api/v1/certificates".into(),
            None,
            Capability::ReadCertificates,
        ),
        (
            "GET",
            format!("/api/v1/certificates/{}", Uuid::new_v4()),
            None,
            Capability::ReadCertificates,
        ),
        (
            "POST",
            "/api/v1/certificates".into(),
            Some(
                json!({"profile_id": Uuid::new_v4(), "subject_cn": "x.test", "sans": ["x.test"], "csr_pem": "not a csr"}),
            ),
            Capability::Issue,
        ),
        // The key-generation path holds its own capability.
        (
            "POST",
            "/api/v1/certificates".into(),
            Some(json!({"profile_id": Uuid::new_v4(), "subject_cn": "x.test"})),
            Capability::GenerateLeafKey,
        ),
        (
            "POST",
            format!("/api/v1/certificates/{}/revoke", Uuid::new_v4()),
            Some(json!({"reason": "r"})),
            Capability::Issue,
        ),
        (
            "GET",
            "/api/v1/profiles".into(),
            None,
            Capability::ReadProfiles,
        ),
        (
            "GET",
            format!("/api/v1/profiles/{}", Uuid::new_v4()),
            None,
            Capability::ReadProfiles,
        ),
        (
            "GET",
            format!("/api/v1/profiles/{}/revisions", Uuid::new_v4()),
            None,
            Capability::ReadProfiles,
        ),
        (
            "POST",
            "/api/v1/profiles".into(),
            Some(
                json!({"name": "", "key_type": "ecdsa-p256", "key_usages": ["digital_signature"], "eku": ["server_auth"], "lifetime_days": 30, "san_patterns": ["d.test"]}),
            ),
            Capability::ManageProfiles,
        ),
        (
            "PUT",
            format!("/api/v1/profiles/{}", Uuid::new_v4()),
            Some(
                json!({"key_type": "ecdsa-p256", "key_usages": ["digital_signature"], "eku": ["server_auth"], "lifetime_days": 30, "san_patterns": ["d.test"]}),
            ),
            Capability::ManageProfiles,
        ),
        ("GET", "/api/v1/cas".into(), None, Capability::ReadCas),
        (
            "POST",
            "/api/v1/cas".into(),
            Some(json!({"name": "", "subject": "", "key_type": "ed25519", "is_root": true})),
            Capability::ManageCas,
        ),
        (
            "POST",
            format!("/api/v1/cas/{ca_id}/export-key"),
            Some(json!({})),
            Capability::ExportCaKeys,
        ),
        (
            "GET",
            "/api/v1/root-trust/ca.crt".into(),
            None,
            Capability::ReadCas,
        ),
        ("GET", "/api/v1/audit".into(), None, Capability::ReadAudit),
        (
            "GET",
            "/api/v1/audit/export".into(),
            None,
            Capability::ReadAudit,
        ),
        ("GET", "/api/v1/users".into(), None, Capability::ReadUsers),
        (
            "POST",
            "/api/v1/users".into(),
            Some(json!({"username": "", "email": "x@y.test", "role": "issuer", "password": "pw"})),
            Capability::ManageUsers,
        ),
        (
            "POST",
            format!("/api/v1/users/{some_user}/deactivate"),
            Some(json!({})),
            Capability::ManageUsers,
        ),
        (
            "GET",
            "/api/v1/service-identities".into(),
            None,
            Capability::ReadServiceIdentities,
        ),
        (
            "POST",
            "/api/v1/service-identities".into(),
            Some(json!({"name": ""})),
            Capability::ManageApiTokens,
        ),
        (
            "POST",
            format!("/api/v1/service-identities/{}/revoke", Uuid::new_v4()),
            None,
            Capability::ManageApiTokens,
        ),
        (
            "GET",
            "/api/v1/one-shot-tokens".into(),
            None,
            Capability::ReadServiceIdentities,
        ),
        (
            "POST",
            "/api/v1/one-shot-tokens".into(),
            Some(json!({"ttl_minutes": 0})),
            Capability::ManageOneShotTokens,
        ),
        (
            "POST",
            "/api/v1/tenants".into(),
            Some(json!({"name": "", "domain": ""})),
            Capability::ManageSystem,
        ),
    ];

    let no_caps = api_token(&fx, &[]).await;
    for (method, path, body, cap) in table {
        // The token LACKING the capability is 403 — never 401.
        let res: TestResponse = match method {
            "GET" => get_bearer(&fx, &path, &no_caps).await,
            "POST" => {
                post_json(
                    &fx,
                    &path,
                    Some(&no_caps),
                    body.clone().unwrap_or(json!({})),
                )
                .await
            }
            "PUT" => {
                put_json(
                    &fx,
                    &path,
                    Some(&no_caps),
                    body.clone().unwrap_or(json!({})),
                )
                .await
            }
            other => panic!("unexpected method {other}"),
        };
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "{method} {path} must refuse a token without {cap:?}"
        );

        // The token holding EXACTLY the capability is not refused by the
        // authorization layer.
        let holder = api_token(&fx, &[cap]).await;
        let res: TestResponse = match method {
            "GET" => get_bearer(&fx, &path, &holder).await,
            "POST" => post_json(&fx, &path, Some(&holder), body.clone().unwrap_or(json!({}))).await,
            "PUT" => put_json(&fx, &path, Some(&holder), body.clone().unwrap_or(json!({}))).await,
            other => panic!("unexpected method {other}"),
        };
        assert_ne!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path} with {cap:?} holder must not be 401"
        );
        assert_ne!(
            res.status(),
            StatusCode::FORBIDDEN,
            "{method} {path} with {cap:?} holder must not be 403"
        );
    }

    fx.cleanup().await;
}

/// PUT convenience for the matrix.
async fn put_json(fixture: &Fixture, uri: &str, token: Option<&str>, body: Value) -> TestResponse {
    let mut builder = axum::http::Request::builder()
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

/// The auth lifecycle: login issues paired tokens, refresh rotates (and
/// kills the old refresh token), logout revokes the session and writes the
/// `session_revoked` audit row, and `me` reflects the session actor.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn login_refresh_logout_lifecycle() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    // A real login needs a password: insert the user FIRST, then hash one
    // (in a blocking thread, like the handler does) and attach it.
    let user_id = Uuid::new_v4();
    insert_user(&fx.pool, fx.tenant_id, user_id, "operator", Role::Issuer).await;
    let hash = {
        let hashed = tokio::task::spawn_blocking(|| {
            ws_auth::password::hash_password("correct horse battery staple")
        })
        .await
        .unwrap()
        .unwrap();
        hashed
    };
    sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
        .bind(user_id)
        .bind(&hash)
        .execute(&fx.pool)
        .await
        .expect("set the user's password hash");

    // Login: wrong password is 401, no user is 401 (uniform).
    let res = post_json(
        &fx,
        "/api/v1/auth/login",
        None,
        json!({"username": "operator", "password": "wrong password"}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Login: success pairs the access token with a refresh token.
    let res = post_json(
        &fx,
        "/api/v1/auth/login",
        None,
        json!({"username": "operator", "password": "correct horse battery staple"}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let login: Value = serde_json::from_slice(&raw).unwrap();
    let access = login["access_token"].as_str().unwrap().to_string();
    let refresh = login["refresh_token"].as_str().unwrap().to_string();
    assert!(refresh.starts_with("ws_rt_"));

    // me reflects the session actor.
    let res = get_bearer(&fx, "/api/v1/auth/me", &access).await;
    assert_eq!(res.status(), StatusCode::OK);
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let me: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(me["actor_type"], "user");
    assert_eq!(me["username"], "operator");

    // Refresh rotates: the new pair works, the OLD refresh token is dead.
    let res = post_json(
        &fx,
        "/api/v1/auth/refresh",
        None,
        json!({"refresh_token": refresh}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let rotated: Value = serde_json::from_slice(&raw).unwrap();
    let old_refresh = login["refresh_token"].as_str().unwrap();
    let res = post_json(
        &fx,
        "/api/v1/auth/refresh",
        None,
        json!({"refresh_token": old_refresh}),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "rotation revokes the old token"
    );

    // Logout revokes the (rotated) session and writes session_revoked.
    let current_refresh = rotated["refresh_token"].as_str().unwrap().to_string();
    let res = post_json(
        &fx,
        "/api/v1/auth/logout",
        Some(rotated["access_token"].as_str().unwrap()),
        json!({"refresh_token": current_refresh}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "logout succeeds");
    let res = post_json(
        &fx,
        "/api/v1/auth/refresh",
        None,
        json!({"refresh_token": current_refresh}),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "logout revoked the session"
    );

    let rows = audit_rows(&fx).await;
    let rows = rows
        .iter()
        .filter(|(a, ..)| a == "session_revoked")
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1, "exactly one session_revoked audit row");
    assert_eq!(rows[0].1, "user");
    assert_eq!(rows[0].2, "session");

    fx.cleanup().await;
}

/// The TOTP MFA flow: enroll returns the secret + provisioning URI, the
/// first code activates, login then requires the code, deactivate clears
/// it — each with its audit row in the same transaction as the change.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn totp_mfa_flow_with_audit_rows() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let user_id = Uuid::new_v4();
    let username = "totp-operator";
    insert_user(&fx.pool, fx.tenant_id, user_id, username, Role::Issuer).await;
    let token = session_token(&fx, user_id, username, "issuer");

    // Enroll.
    let res = post_json(&fx, "/api/v1/auth/totp/enroll", Some(&token), json!({})).await;
    assert_eq!(res.status(), StatusCode::OK);
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let enrolled: Value = serde_json::from_slice(&raw).unwrap();
    let secret = enrolled["secret"].as_str().unwrap().to_string();
    assert!(enrolled["provisioning_uri"]
        .as_str()
        .unwrap()
        .contains("otpauth://"));

    // Compute a current code with the workspace's totp-rs pin.
    fn current_code(secret: &str) -> String {
        use totp_rs::{Algorithm, Secret, TOTP};
        let secret = Secret::Encoded(secret.to_string());
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_bytes().unwrap(),
            None,
            "totp-operator".to_string(),
        )
        .unwrap();
        totp.generate_current().unwrap()
    }

    // Activate with the first code.
    let res = post_json(
        &fx,
        "/api/v1/auth/totp/activate",
        Some(&token),
        json!({"code": current_code(&secret)}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    // Wrong code is rejected.
    let res = post_json(
        &fx,
        "/api/v1/auth/totp/deactivate",
        Some(&token),
        json!({"code": "000000"}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Deactivate with a real code.
    let res = post_json(
        &fx,
        "/api/v1/auth/totp/deactivate",
        Some(&token),
        json!({"code": current_code(&secret)}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let rows = audit_rows(&fx).await;
    for action in ["mfa_enrolled", "mfa_activated", "mfa_deactivated"] {
        let rows: Vec<_> = rows.iter().filter(|(a, ..)| a == action).collect();
        assert_eq!(rows.len(), 1, "exactly one {action} row");
        assert_eq!(rows[0].1, "user");
        assert_eq!(rows[0].2, "session");
        assert_eq!(rows[0].3, json!({}), "{action} carries no details keys");
    }

    fx.cleanup().await;
}

/// CA lifecycle through the API: create a root and a sub-CA, list them,
/// download the root trust certificate, and export the CA key (admin-only,
/// no-store, audited, key material never in the log).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn ca_lifecycle_root_trust_and_key_export() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);
    let (_profile_id, ca_id) = setup_profile_and_ca(&fx).await;

    // A sub-CA underneath the root.
    let res = post_json(
        &fx,
        "/api/v1/cas",
        Some(&token),
        json!({
            "name": "sub-ca",
            "subject": "Wardstone Test Sub",
            "key_type": "ed25519",
            "is_root": false,
            "parent_id": ca_id
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);

    // List: both CAs.
    let res = get_bearer(&fx, "/api/v1/cas", &token).await;
    assert_eq!(res.status(), StatusCode::OK);
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let listed: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 2);

    // Root trust download: the CERTIFICATE, never the key.
    let res = get_bearer(&fx, "/api/v1/root-trust/ca.crt", &token).await;
    assert_eq!(res.status(), StatusCode::OK);
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let text = String::from_utf8(raw.to_vec()).unwrap();
    assert!(text.contains("BEGIN CERTIFICATE"), "the certificate PEM");
    assert!(!text.contains("PRIVATE KEY"), "never the key");

    // Export the root CA key: admin-only, no-store, once per response.
    let res = post_json(
        &fx,
        &format!("/api/v1/cas/{ca_id}/export-key"),
        Some(&token),
        json!({}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let text = String::from_utf8(raw.to_vec()).unwrap();
    assert_eq!(text.matches("BEGIN PRIVATE KEY").count(), 1);

    // Audit: ca_key_exported with a reason, never key material.
    let rows = audit_rows(&fx).await;
    let exports: Vec<_> = rows
        .iter()
        .filter(|(a, ..)| a == "ca_key_exported")
        .collect();
    assert_eq!(exports.len(), 1);
    let details_text = exports[0].3.to_string();
    assert!(
        !details_text.contains("PRIVATE"),
        "ca_key_exported details never carry key material: {details_text}"
    );
    let created: Vec<_> = rows.iter().filter(|(a, ..)| a == "ca_created").collect();
    assert_eq!(created.len(), 2, "ca_created for root and sub");

    // Issuer cannot export.
    let issuer = api_token(&fx, &[Capability::Issue]).await;
    let res = post_json(
        &fx,
        &format!("/api/v1/cas/{ca_id}/export-key"),
        Some(&issuer),
        json!({}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    fx.cleanup().await;
}

/// The tenants route creates a tenant and seeds its built-in default
/// profiles, with the `tenant_created` audit row.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn tenants_route_seeds_default_profiles() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);

    let res = post_json(
        &fx,
        "/api/v1/tenants",
        Some(&token),
        json!({"name": "rt-api-secondary", "domain": "rx.test", "domain_cidrs": ["10.100.0.0/16"]}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let created: Value = serde_json::from_slice(&raw).unwrap();
    let tenant_id = created["id"].as_str().unwrap().parse::<Uuid>().unwrap();
    fx.extra_tenants.lock().unwrap().push(tenant_id);

    // Seeded profiles: exactly the two built-ins with the domain's list.
    // Captured BEFORE cleanup (the rows go with it).
    let profiles = ws_core::repo::profile_repo::ProfileRepo::new()
        .list_by_tenant(&fx.pool, tenant_id, 0, 100)
        .await
        .unwrap();
    let mut revision_patterns: Vec<Vec<String>> = Vec::new();
    for p in &profiles {
        let rev = ws_core::repo::profile_repo::ProfileRepo::new()
            .current_revision(&fx.pool, p.id)
            .await
            .unwrap()
            .expect("the seeded profile has revision 1");
        revision_patterns.push(rev.san_patterns);
    }
    // The audit row is captured BEFORE cleanup too.
    let rows = audit_rows(&fx).await;
    fx.cleanup().await;

    assert_eq!(profiles.len(), 2, "the two built-in default profiles");
    let names: Vec<_> = profiles.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"web-server") && names.contains(&"web-server-ecdsa"));
    for patterns in revision_patterns {
        assert_eq!(
            patterns,
            vec![
                "rx.test".to_string(),
                "*.rx.test".to_string(),
                "10.100.0.0/16".to_string()
            ]
        );
    }

    let created: Vec<_> = rows
        .iter()
        .filter(|(a, ..)| a == "tenant_created")
        .collect();
    assert_eq!(created.len(), 1);
    assert_eq!(
        created[0].3,
        json!({}),
        "tenant_created carries no details keys"
    );
}

/// The OIDC callback validates the csrf state before any token exchange: a
/// bogus (or missing) state is refused without any provider call.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn oidc_callback_rejects_a_bogus_state() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let res = send(
        &fx,
        Request::builder()
            .method("GET")
            .uri("/api/v1/auth/oidc/keycloak/callback?code=x&state=bogus-state")
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // And no state at all is refused too.
    let res = send(
        &fx,
        Request::builder()
            .method("GET")
            .uri("/api/v1/auth/oidc/keycloak/callback?code=x")
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    fx.cleanup().await;
}

/// The OIDC start route mints a csrf state (the Task 3 R8 contract: the
/// API layer owns state minting and validation) — a configured provider
/// redirects with a state the callback's store knows.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn oidc_start_mints_csrf_state() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    // Configure the (single) tenant's OIDC provider. The discovery URL is
    // unreachable here — start is expected to fail on the network leg, but
    // only AFTER the state was minted and stored.
    sqlx::query(
        "INSERT INTO oidc_config (tenant_id, provider_type, display_name, discovery_url, \
         client_id, client_secret, redirect_uri, scopes) \
         VALUES ($1, 'custom', 'Test IdP', 'http://127.0.0.1:9/.well-known/openid-configuration', \
         'client', '', 'http://127.0.0.1:9/callback', 'openid profile email')",
    )
    .bind(fx.tenant_id)
    .execute(&fx.pool)
    .await
    .expect("insert the oidc config row");

    let res = send(
        &fx,
        Request::builder()
            .method("GET")
            .uri("/api/v1/auth/oidc/custom/start")
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    fx.cleanup().await;

    // The provider is unreachable, so the route fails with 500 — but only
    // AFTER the csrf state was minted and stored (the internal error, not
    // a 404 for an unconfigured provider, and not a 401 on a public route).
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        fx.state.oidc_states.pending_count() >= 1,
        "the csrf state was minted before the network leg"
    );
}

/// Revocation is idempotent and audited: the first revoke writes one
/// `cert_revoked` row, a second revoke writes none.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn revocation_is_idempotent_and_audited() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let (profile_id, _ca_id) = setup_profile_and_ca(&fx).await;
    let (_, body) = issue_csr(
        &fx,
        profile_id,
        "revoke.wardstone.test",
        &["revoke.wardstone.test"],
    )
    .await;
    let cert_id = body["certificate_id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();
    let token = admin_token(&fx);

    let res = post_json(
        &fx,
        &format!("/api/v1/certificates/{cert_id}/revoke"),
        Some(&token),
        json!({"reason": "key compromise"}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let res = post_json(
        &fx,
        &format!("/api/v1/certificates/{cert_id}/revoke"),
        Some(&token),
        json!({"reason": "key compromise"}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "revoke is idempotent");

    let rows = audit_rows(&fx).await;
    let revoked: Vec<_> = rows.iter().filter(|(a, ..)| a == "cert_revoked").collect();
    fx.cleanup().await;

    assert_eq!(revoked.len(), 1, "the second revoke writes no row");
    assert_eq!(revoked[0].3["reason"], "key compromise");
}

/// Health and metrics are public and cheap.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn health_and_metrics_are_public() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let res = send(
        &fx,
        Request::builder()
            .method("GET")
            .uri("/api/v1/healthz")
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let res = send(
        &fx,
        Request::builder()
            .method("GET")
            .uri("/api/v1/metrics")
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let text = String::from_utf8(raw.to_vec()).unwrap();
    assert!(text.contains("wardstone_up"));

    fx.cleanup().await;
}

/// The `*.` pattern is refused at profile-creation time (the fail-closed
/// matcher fix Task 10 carries): a profile proposing `*.` is a 400, not a
/// stored open wildcard.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn profile_creation_refuses_the_star_dot_pattern() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);

    let res = post_json(
        &fx,
        "/api/v1/profiles",
        Some(&token),
        json!({
            "name": "bad-pattern",
            "key_type": "ecdsa-p256",
            "key_usages": ["digital_signature"],
            "eku": ["server_auth"],
            "lifetime_days": 30,
            "san_patterns": ["*."]
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    fx.cleanup().await;
}

// ---------------------------------------------------------------------------
// The filtered listing and estate statistics (Plan 3 Task 1)
// ---------------------------------------------------------------------------

/// Create a profile named `name` permitting the `*.example.test` SAN
/// wildcard, through the API; returns the profile id.
async fn create_filter_profile(fixture: &Fixture, token: &str, name: &str) -> Uuid {
    let res = post_json(
        fixture,
        "/api/v1/profiles",
        Some(token),
        json!({
            "name": name,
            "description": "the filtered-listing fixture profile",
            "key_type": "ecdsa-p256",
            "key_usages": ["digital_signature"],
            "eku": ["server_auth"],
            "lifetime_days": 30,
            "san_patterns": ["*.example.test"]
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create profile {name}");
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&raw).unwrap();
    body["id"].as_str().unwrap().parse::<Uuid>().unwrap()
}

/// A GET request's parsed JSON body (the response must be 200).
async fn get_json(fixture: &Fixture, uri: &str, token: &str) -> Value {
    let res = get_bearer(fixture, uri, token).await;
    assert_eq!(res.status(), StatusCode::OK, "GET {uri}");
    let raw = axum::body::to_bytes(res.into_body(), 4 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&raw).unwrap()
}

/// The certificates list composes its filter parameters: `status`, `profile`
/// (the profile NAME), `q` (subject | serial_hex | certificate SAN), and
/// `ca` (the issuing CA id). A revoked certificate is matched by its
/// profile, by a serial-hex search, and excluded by `status=active`; an
/// unknown CA id matches nothing; an unparseable status is a 400.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn filtered_listing_matches_status_profile_search_and_ca() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);

    // Two profiles whose NAMES the profile filter keys on, one CA.
    let web_server = create_filter_profile(&fx, &token, "web-server").await;
    let web_server_ecdsa = create_filter_profile(&fx, &token, "web-server-ecdsa").await;
    let res = post_json(
        &fx,
        "/api/v1/cas",
        Some(&token),
        json!({
            "name": "filter-root-ca",
            "subject": "Wardstone Filter Root",
            "key_type": "ed25519",
            "is_root": true
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create the filter CA");

    // A: active, profile web-server, SAN a.example.test.
    let (a_status, a_body) =
        issue_csr(&fx, web_server, "a.example.test", &["a.example.test"]).await;
    assert_eq!(a_status, StatusCode::OK, "issue A: {a_body}");
    let a_id = a_body["certificate_id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();
    let a_serial_hex = a_body["serial_hex"].as_str().unwrap().to_string();

    // B: revoked, profile web-server-ecdsa, SAN b.example.test.
    let (b_status, b_body) =
        issue_csr(&fx, web_server_ecdsa, "b.example.test", &["b.example.test"]).await;
    assert_eq!(b_status, StatusCode::OK, "issue B: {b_body}");
    let b_id = b_body["certificate_id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();
    let b_serial_hex = b_body["serial_hex"].as_str().unwrap().to_string();

    let res = post_json(
        &fx,
        &format!("/api/v1/certificates/{b_id}/revoke"),
        Some(&token),
        json!({"reason": "filter fixture revoke"}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "revoke B");

    // Every list query runs BEFORE cleanup (the self-cleaning contract).
    let unfiltered = get_json(&fx, "/api/v1/certificates", &token).await;
    let by_status = get_json(&fx, "/api/v1/certificates?status=active", &token).await;
    let by_profile = get_json(&fx, "/api/v1/certificates?profile=web-server-ecdsa", &token).await;
    let q_san = get_json(&fx, "/api/v1/certificates?q=a.example.test", &token).await;
    // The serial-hex search needle: a PREFIX of B's hex — extended to the
    // full hex only if the (random) short prefix also appears in A's.
    let mut needle: String = b_serial_hex.chars().take(10).collect();
    if a_serial_hex.contains(&needle) {
        needle = b_serial_hex.clone();
    }
    let q_serial = get_json(&fx, &format!("/api/v1/certificates?q={needle}"), &token).await;
    let by_other_ca = get_json(
        &fx,
        &format!("/api/v1/certificates?ca={}", Uuid::new_v4()),
        &token,
    )
    .await;
    let bad_status_res = get_bearer(&fx, "/api/v1/certificates?status=bogus", &token).await;
    let bad_status = bad_status_res.status();
    let raw = axum::body::to_bytes(bad_status_res.into_body(), 1 << 20)
        .await
        .unwrap();
    let bad_status_body: Value = serde_json::from_slice(&raw).unwrap_or(json!({}));
    fx.cleanup().await;

    let ids = |list: &Value| -> Vec<Uuid> {
        list.as_array()
            .expect("the list body is a JSON array")
            .iter()
            .map(|row| row["id"].as_str().unwrap().parse::<Uuid>().unwrap())
            .collect()
    };

    assert_eq!(ids(&unfiltered), vec![a_id, b_id], "no filter lists both");
    assert_eq!(
        ids(&by_status),
        vec![a_id],
        "status=active lists only the active certificate"
    );
    assert_eq!(
        ids(&by_profile),
        vec![b_id],
        "profile=web-server-ecdsa lists only B"
    );
    assert_eq!(ids(&q_san), vec![a_id], "the SAN search matches only A");
    assert_eq!(
        ids(&q_serial),
        vec![b_id],
        "the serial-hex search matches only B"
    );
    assert!(
        ids(&by_other_ca).is_empty(),
        "an unknown CA id matches nothing"
    );
    assert_eq!(
        bad_status,
        StatusCode::BAD_REQUEST,
        "an unknown status is 400"
    );
    assert_eq!(
        error_code(&bad_status_body),
        "bad_request",
        "the invalid-status code"
    );
}

/// The estate statistics endpoint counts, in one response: active,
/// revoked, and active-and-expiring-within-the-30-day horizon. Four
/// certificates are issued and their `not_after` pinned by direct row
/// update so the horizon is deterministic: A (+10d) and D (+5d) expire
/// soon, B (+40d) does not, C is revoked.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn statistics_counts_active_revoked_expiring() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let (profile_id, _ca_id) = setup_profile_and_ca(&fx).await;
    let token = admin_token(&fx);

    // Issue four certificates through the API (the CSR path).
    let mut cert_ids = Vec::new();
    for cn in [
        "a.wardstone.test",
        "b.wardstone.test",
        "c.wardstone.test",
        "d.wardstone.test",
    ] {
        let (status, body) = issue_csr(&fx, profile_id, cn, &[cn]).await;
        assert_eq!(status, StatusCode::OK, "issue {cn}: {body}");
        cert_ids.push(
            body["certificate_id"]
                .as_str()
                .unwrap()
                .parse::<Uuid>()
                .unwrap(),
        );
    }

    // Pin the expiries: A +10d, B +40d, D +5d (C stays profile-expired and
    // is revoked below — revoked rows sit outside the horizon either way).
    let expiry_legs = [
        (cert_ids[0], Duration::days(10)),
        (cert_ids[1], Duration::days(40)),
        (cert_ids[3], Duration::days(5)),
    ];
    for (id, leg) in expiry_legs {
        sqlx::query("UPDATE certificates SET not_after = $2 WHERE id = $1")
            .bind(id)
            .bind(Utc::now() + leg)
            .execute(&fx.pool)
            .await
            .expect("pin the certificate expiry");
    }

    // Revoke C.
    let res = post_json(
        &fx,
        &format!("/api/v1/certificates/{}/revoke", cert_ids[2]),
        Some(&token),
        json!({"reason": "statistics fixture revoke"}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "revoke C");

    // The statistics GET runs BEFORE cleanup.
    let res = get_bearer(&fx, "/api/v1/certificates/statistics", &token).await;
    let status = res.status();
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let stats: Value = serde_json::from_slice(&raw).unwrap_or(json!({}));
    fx.cleanup().await;

    assert_eq!(status, StatusCode::OK, "the statistics route answers");
    assert_eq!(stats["active"], 3, "A, B, D are active");
    assert_eq!(stats["revoked"], 1, "C is revoked");
    assert_eq!(
        stats["expiring_soon"], 2,
        "A (+10d) and D (+5d) expire within the 30-day horizon"
    );
}

// ---------------------------------------------------------------------------
// The audit list filters (Plan 3 Task 2)
// ---------------------------------------------------------------------------

/// The audit list filters by `action` (exact), by `from`/`to` on
/// `created_at`, and composes both ends of the date bracket. The suite's
/// seeded events run through the normal mutation routes and are backdated
/// by DIRECT row UPDATE for determinism: the `ca_created` row three hours
/// ago, the two `cert_issued` rows 61 and 59 minutes ago (never a tie on
/// `created_at`, whose ties resolve by the random id), while the fixture's
/// `profile_created` row stays at wall-clock now — the too-new entry the
/// `to` bound must exclude.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn audit_filter_by_date_and_action() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let (profile_id, ca_id) = setup_profile_and_ca(&fx).await;
    let token = admin_token(&fx);

    // Two issuances: A seeded older, B newer.
    let (a_status, a_body) = issue_csr(
        &fx,
        profile_id,
        "a-audit.wardstone.test",
        &["a-audit.wardstone.test"],
    )
    .await;
    assert_eq!(a_status, StatusCode::OK, "issue A: {a_body}");
    let a_target = a_body["certificate_id"].as_str().unwrap().to_string();
    let (b_status, b_body) = issue_csr(
        &fx,
        profile_id,
        "b-audit.wardstone.test",
        &["b-audit.wardstone.test"],
    )
    .await;
    assert_eq!(b_status, StatusCode::OK, "issue B: {b_body}");
    let b_target = b_body["certificate_id"].as_str().unwrap().to_string();

    // Backdate: the CA creation three hours ago, A one hour and a minute
    // ago, B a minute shy of an hour; `profile_created` stays at now.
    let now = Utc::now();
    sqlx::query(
        "UPDATE audit_log SET created_at = $1 WHERE tenant_id = $2 AND action = 'ca_created'",
    )
    .bind(now - Duration::hours(3))
    .bind(fx.tenant_id)
    .execute(&fx.pool)
    .await
    .expect("backdate the ca_created row");
    for (target, age) in [
        (&a_target, Duration::minutes(61)),
        (&b_target, Duration::minutes(59)),
    ] {
        sqlx::query(
            "UPDATE audit_log SET created_at = $1 WHERE tenant_id = $2 \
             AND action = 'cert_issued' AND target_id = $3",
        )
        .bind(now - age)
        .bind(fx.tenant_id)
        .bind(target.as_str())
        .execute(&fx.pool)
        .await
        .expect("backdate a cert_issued row");
    }

    // Every list query runs BEFORE cleanup (the self-cleaning contract).
    let unfiltered = get_json(&fx, "/api/v1/audit", &token).await;
    let by_action = get_json(&fx, "/api/v1/audit?action=cert_issued", &token).await;
    // The Z-suffixed RFC 3339 form: URL-safe (a `+` offset would decode
    // as a space and the query would fall apart).
    let from = (now - Duration::hours(2)).to_rfc3339_opts(SecondsFormat::Nanos, true);
    let to = (now - Duration::minutes(30)).to_rfc3339_opts(SecondsFormat::Nanos, true);
    let after_from = get_json(&fx, &format!("/api/v1/audit?from={from}"), &token).await;
    let bracket = get_json(&fx, &format!("/api/v1/audit?from={from}&to={to}"), &token).await;
    fx.cleanup().await;

    let targets = |list: &Value| -> Vec<String> {
        list.as_array()
            .expect("the list body is a JSON array")
            .iter()
            .map(|row| row["target_id"].as_str().expect("target_id").to_string())
            .collect()
    };

    // Unfiltered: exactly the fixture's four rows, newest first — the
    // wall-clock profile row, then B, then A, then the backdated CA row.
    assert_eq!(
        targets(&unfiltered),
        vec![
            profile_id.to_string(),
            b_target.clone(),
            a_target.clone(),
            ca_id.to_string()
        ],
        "the full log, newest first"
    );
    assert_eq!(
        targets(&by_action),
        vec![b_target.clone(), a_target.clone()],
        "action=cert_issued lists only the two issuances, newest first"
    );
    assert_eq!(
        targets(&after_from),
        vec![profile_id.to_string(), b_target.clone(), a_target.clone()],
        "from excludes the three-hour-old CA-creation row"
    );
    assert_eq!(
        targets(&bracket),
        vec![b_target, a_target],
        "the from/to bracket excludes both too-old and too-new rows"
    );
}

// ---------------------------------------------------------------------------
// The CRL retrieval and trust-chain routes (Plan 3 Task 3)
// ---------------------------------------------------------------------------

/// The CRL route serves the NEWEST published CRL for the CA. Two `crls`
/// rows are seeded by direct INSERT into the ws-worker-owned table (its job
/// path is untouched — the rows are the seed, not a writer) with distinct
/// `issued_at` stamps, and the response must carry the newer row's
/// `issued_at`, `next_update`, and PEM verbatim, nothing more. A CA that
/// exists but never published a CRL is a 404 `not_found`.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn crl_route_serves_newest() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);
    let (_profile_id, ca_id) = setup_profile_and_ca(&fx).await;

    // Two CRL rows: OLD two hours ago (already expired), NEW half an hour
    // ago. `issued_at` is seeded explicitly — the route's ORDER BY keys on
    // it, so no backdating of anything else is involved. The stamps are
    // rounded to microsecond precision: a `timestamptz` column truncates
    // finer digits on write, and the comparison must compare what is
    // stored, not what was bound.
    let now = Utc::now().round_subsecs(6);
    let old_pem = "-----BEGIN X509 CRL-----\nOLDTESTCRL\n-----END X509 CRL-----\n";
    let new_pem = "-----BEGIN X509 CRL-----\nNEWTESTCRL\n-----END X509 CRL-----\n";
    let old_issued = now - Duration::hours(2);
    let old_next = now - Duration::hours(1);
    let new_issued = now - Duration::minutes(30);
    let new_next = now + Duration::hours(12);
    let seeds = [
        (old_issued, old_next, old_pem),
        (new_issued, new_next, new_pem),
    ];
    for (seeded_issued, seeded_next, crl_pem) in seeds {
        sqlx::query(
            "INSERT INTO crls (id, tenant_id, ca_id, issued_at, next_update, crl_pem) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::new_v4())
        .bind(fx.tenant_id)
        .bind(ca_id)
        .bind(seeded_issued)
        .bind(seeded_next)
        .bind(crl_pem)
        .execute(&fx.pool)
        .await
        .expect("seed a crls row");
    }

    // The sibling CA that exists but has never published a CRL.
    let empty_res = post_json(
        &fx,
        "/api/v1/cas",
        Some(&token),
        json!({
            "name": "crl-empty-root",
            "subject": "Wardstone CRL Empty",
            "key_type": "ed25519",
            "is_root": true
        }),
    )
    .await;
    assert_eq!(
        empty_res.status(),
        StatusCode::CREATED,
        "create the CA without CRLs"
    );
    let raw = axum::body::to_bytes(empty_res.into_body(), 1 << 20)
        .await
        .unwrap();
    let empty_ca: Value = serde_json::from_slice(&raw).unwrap();
    let empty_ca_id = empty_ca["id"].as_str().unwrap().parse::<Uuid>().unwrap();

    // Both GETs run BEFORE cleanup (the self-cleaning contract).
    let res = get_bearer(&fx, &format!("/api/v1/cas/{ca_id}/crl"), &token).await;
    let status = res.status();
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&raw).unwrap_or(json!({}));
    let no_crl_res = get_bearer(&fx, &format!("/api/v1/cas/{empty_ca_id}/crl"), &token).await;
    let no_crl_status = no_crl_res.status();
    let raw = axum::body::to_bytes(no_crl_res.into_body(), 1 << 20)
        .await
        .unwrap();
    let no_crl_body: Value = serde_json::from_slice(&raw).unwrap_or(json!({}));

    // Drop the seeded CRL rows before cleanup: cleanup deletes the `cas`
    // rows, and the `crls` rows' foreign keys would block those deletes.
    sqlx::query("DELETE FROM crls WHERE tenant_id = $1")
        .bind(fx.tenant_id)
        .execute(&fx.pool)
        .await
        .expect("delete the seeded crls rows");
    fx.cleanup().await;

    assert_eq!(status, StatusCode::OK, "the CRL route answers");
    assert_eq!(
        body["ca_id"].as_str().unwrap().parse::<Uuid>().unwrap(),
        ca_id,
        "the served CRL names the requested CA"
    );
    assert_eq!(
        body["issued_at"]
            .as_str()
            .unwrap()
            .parse::<DateTime<Utc>>()
            .unwrap(),
        new_issued,
        "the NEWEST row's issued_at"
    );
    assert_eq!(
        body["next_update"]
            .as_str()
            .unwrap()
            .parse::<DateTime<Utc>>()
            .unwrap(),
        new_next,
        "the newest row's next_update"
    );
    assert_eq!(
        body["crl_pem"].as_str(),
        Some(new_pem),
        "the newest row's PEM, verbatim"
    );
    assert_eq!(
        body.as_object().unwrap().len(),
        4,
        "exactly ca_id, issued_at, next_update, crl_pem"
    );

    assert_eq!(
        no_crl_status,
        StatusCode::NOT_FOUND,
        "no published CRL is 404"
    );
    assert_eq!(error_code(&no_crl_body), "not_found");
}

/// The chain routes assemble the trust chain leaf-first with the PEM body
/// `application/x-pem-file`: `/cas/{id}/chain` concatenates the CA's
/// certificate up to its root's (a leaf certificate never appears), and
/// `/certificates/{id}/chain` puts the leaf PEM FIRST, then its issuing
/// chain. The leaf is issued through the normal issuance helper and its
/// `ca_id` is then repointed at the intermediate by direct UPDATE — the
/// issuance helper always issues from the tenant's root, and the same-
/// tenant repoint keeps the composite tenant/CA foreign key intact.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn chain_routes_walk_to_root() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);
    let (profile_id, root_id) = setup_profile_and_ca(&fx).await;

    // The intermediate under the root, through the API (create_ca).
    let res = post_json(
        &fx,
        "/api/v1/cas",
        Some(&token),
        json!({
            "name": "chain-intermediate",
            "subject": "Wardstone Chain Intermediate",
            "key_type": "ed25519",
            "is_root": false,
            "parent_id": root_id
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create the intermediate");
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let intermediate: Value = serde_json::from_slice(&raw).unwrap();
    let intermediate_id = intermediate["id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();
    let intermediate_pem = intermediate["cert_pem"].as_str().unwrap().to_string();

    // The root's PEM, from the list (setup_profile_and_ca discards the body).
    let listed = get_json(&fx, "/api/v1/cas", &token).await;
    let root_pem = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|ca| ca["id"].as_str().unwrap().parse::<Uuid>().unwrap() == root_id)
        .expect("the fixture root is listed")["cert_pem"]
        .as_str()
        .unwrap()
        .to_string();

    // A leaf through the normal issuance helper, then repointed under the
    // intermediate (same tenant). The name fits the fixture profile's
    // `wardstone.test` SAN allow-list.
    let (leaf_status, leaf_body) = issue_csr(
        &fx,
        profile_id,
        "leaf.chain.wardstone.test",
        &["leaf.chain.wardstone.test"],
    )
    .await;
    assert_eq!(leaf_status, StatusCode::OK, "issue the leaf: {leaf_body}");
    let leaf_id = leaf_body["certificate_id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();
    let leaf_pem = leaf_body["cert_pem"].as_str().unwrap().to_string();
    sqlx::query("UPDATE certificates SET ca_id = $2 WHERE id = $1")
        .bind(leaf_id)
        .bind(intermediate_id)
        .execute(&fx.pool)
        .await
        .expect("repoint the leaf at the intermediate");

    // Both chain GETs run BEFORE cleanup (the self-cleaning contract).
    let cert_res = get_bearer(
        &fx,
        &format!("/api/v1/certificates/{leaf_id}/chain"),
        &token,
    )
    .await;
    let cert_status = cert_res.status();
    let cert_type = cert_res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let cert_raw = axum::body::to_bytes(cert_res.into_body(), 1 << 20)
        .await
        .unwrap();
    let cert_chain = String::from_utf8(cert_raw.to_vec()).unwrap();
    let ca_res = get_bearer(&fx, &format!("/api/v1/cas/{intermediate_id}/chain"), &token).await;
    let ca_status = ca_res.status();
    let ca_raw = axum::body::to_bytes(ca_res.into_body(), 1 << 20)
        .await
        .unwrap();
    let ca_chain = String::from_utf8(ca_raw.to_vec()).unwrap();

    fx.cleanup().await;

    assert_eq!(
        cert_status,
        StatusCode::OK,
        "the certificate chain route answers"
    );
    assert_eq!(
        cert_type, "application/x-pem-file",
        "the chain body's content type"
    );
    let leaf_at = cert_chain
        .find(&leaf_pem)
        .expect("the leaf's PEM in the body");
    let intermediate_at = cert_chain
        .find(&intermediate_pem)
        .expect("the intermediate's PEM in the body");
    let root_at = cert_chain
        .find(&root_pem)
        .expect("the root's PEM in the body");
    assert!(
        leaf_at < intermediate_at && intermediate_at < root_at,
        "the certificate chain is leaf-first: leaf, intermediate, root"
    );

    assert_eq!(ca_status, StatusCode::OK, "the CA chain route answers");
    let int_at = ca_chain
        .find(&intermediate_pem)
        .expect("the intermediate's PEM in the body");
    let root_at2 = ca_chain
        .find(&root_pem)
        .expect("the root's PEM in the body");
    assert!(
        int_at < root_at2,
        "the CA chain walks intermediate then root"
    );
    assert!(
        ca_chain.find(&leaf_pem).is_none(),
        "the CA chain never contains a leaf certificate"
    );
}

/// The chain walk refuses a CROSS-TENANT parent. The schema normally
/// refuses it too — migration 008's `cas_parent_tenant_fk` composite
/// foreign key keeps a CA's parent in-tenant — so this regression
/// temporarily DROPS that constraint to bend the schema by direct UPDATE
/// (re-adding it VALIDATED after cleanup, and the sweep-first section also
/// heals a constraint a crashed run may have left dropped). The bend: a
/// second tenant seeded raw, the actor tenant's sub-CA's `parent_id`
/// repointed at the foreign CA, and both chain routes must answer 500
/// (`internal` — the `CoreError::Config` mapping) WITHOUT the foreign
/// CA's PEM. Cross-tenant parents are prevented at `create_ca` (the API
/// filters the named parent to the actor's tenant — the foreign rows here
/// are seeded raw precisely because the API refuses); the walk's per-hop
/// tenant check is the third belt, behind the schema and the API.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn chain_walk_refuses_cross_tenant_parent() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);
    let (profile_id, root_id) = setup_profile_and_ca(&fx).await;

    // The sub-CA under the fixture root, through the API: the parent check
    // at create_ca accepts this one (same tenant).
    let res = post_json(
        &fx,
        "/api/v1/cas",
        Some(&token),
        json!({
            "name": "chain-cross-tenant",
            "subject": "Wardstone Cross-Tenant Chain",
            "key_type": "ed25519",
            "is_root": false,
            "parent_id": root_id
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create the sub-CA");
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let sub: Value = serde_json::from_slice(&raw).unwrap();
    let sub_id = sub["id"].as_str().unwrap().parse::<Uuid>().unwrap();

    // Sweep-first, then the second tenant and its CA, seeded raw: the API
    // would refuse a cross-tenant parent — that refusal is exactly what
    // this belt is for.
    sqlx::query("DELETE FROM cas WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)")
        .bind("rt-api-foreign-chain")
        .execute(&fx.pool)
        .await
        .expect("sweep stale foreign-chain cas rows");
    sqlx::query("DELETE FROM tenants WHERE name = $1")
        .bind("rt-api-foreign-chain")
        .execute(&fx.pool)
        .await
        .expect("sweep stale foreign-chain tenant");
    // Heal the schema a previously crashed run may have damaged (this test
    // drops cas_parent_tenant_fk to bend the edge): re-add it if absent.
    // The sweep-first contract covers the schema, not just the rows.
    sqlx::query(
        "DO $$ BEGIN \
         IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'cas_parent_tenant_fk') THEN \
         ALTER TABLE cas ADD CONSTRAINT cas_parent_tenant_fk \
         FOREIGN KEY (parent_id, tenant_id) REFERENCES cas (id, tenant_id) \
         DEFERRABLE INITIALLY DEFERRED; \
         END IF; END $$;",
    )
    .execute(&fx.pool)
    .await
    .expect("heal cas_parent_tenant_fk if a crashed run dropped it");
    let foreign_tenant = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(foreign_tenant)
        .bind("rt-api-foreign-chain")
        .execute(&fx.pool)
        .await
        .expect("insert the foreign tenant");
    let foreign_ca = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO cas (id, tenant_id, name, subject, is_root, parent_id, key_type, \
         not_before, not_after, cert_pem, key_file, created_at) \
         VALUES ($1, $2, $3, $4, true, NULL, 'ed25519', now(), now(), $5, 'ca/foreign.key', now())",
    )
    .bind(foreign_ca)
    .bind(foreign_tenant)
    .bind("foreign-root-ca")
    .bind("Wardstone Foreign Root")
    .bind("-----BEGIN CERTIFICATE-----\nFOREIGNCHAINPEM\n-----END CERTIFICATE-----\n")
    .execute(&fx.pool)
    .await
    .expect("insert the foreign ca");

    // Bend the schema: the sub's parent becomes the foreign CA. The 008
    // foreign key would refuse this write — the schema itself keeps a CA's
    // parent in-tenant — so the constraint is dropped for the bend
    // (re-added validated after cleanup).
    sqlx::query("ALTER TABLE cas DROP CONSTRAINT cas_parent_tenant_fk")
        .execute(&fx.pool)
        .await
        .expect("drop cas_parent_tenant_fk for the bend");
    sqlx::query("UPDATE cas SET parent_id = $2 WHERE id = $1")
        .bind(sub_id)
        .bind(foreign_ca)
        .execute(&fx.pool)
        .await
        .expect("seed the cross-tenant parent");

    // A leaf issued through the normal helper, repointed at the sub (same
    // tenant), so the certificate chain route walks the bent edge too.
    let (leaf_status, leaf_body) = issue_csr(
        &fx,
        profile_id,
        "x.chain.wardstone.test",
        &["x.chain.wardstone.test"],
    )
    .await;
    assert_eq!(leaf_status, StatusCode::OK, "issue the leaf: {leaf_body}");
    let leaf_id = leaf_body["certificate_id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();
    sqlx::query("UPDATE certificates SET ca_id = $2 WHERE id = $1")
        .bind(leaf_id)
        .bind(sub_id)
        .execute(&fx.pool)
        .await
        .expect("repoint the leaf at the sub");

    // Both GETs run BEFORE cleanup (the self-cleaning contract).
    let ca_res = get_bearer(&fx, &format!("/api/v1/cas/{sub_id}/chain"), &token).await;
    let ca_status = ca_res.status();
    let raw = axum::body::to_bytes(ca_res.into_body(), 1 << 20)
        .await
        .unwrap();
    let ca_text = String::from_utf8(raw.to_vec()).unwrap();
    let ca_body: Value = serde_json::from_str(&ca_text).unwrap_or(json!({}));
    let cert_res = get_bearer(
        &fx,
        &format!("/api/v1/certificates/{leaf_id}/chain"),
        &token,
    )
    .await;
    let cert_status = cert_res.status();
    let raw = axum::body::to_bytes(cert_res.into_body(), 1 << 20)
        .await
        .unwrap();
    let cert_text = String::from_utf8(raw.to_vec()).unwrap();
    let cert_body: Value = serde_json::from_str(&cert_text).unwrap_or(json!({}));

    // Cleanup covers the fixture tenant; the schema FK is restored BEFORE
    // the foreign rows go (nothing references the foreign CA by then: the
    // bent sub row was deleted with the fixture rows, so the re-added
    // constraint validates cleanly), then the foreign rows.
    fx.cleanup().await;
    sqlx::query(
        "ALTER TABLE cas ADD CONSTRAINT cas_parent_tenant_fk \
         FOREIGN KEY (parent_id, tenant_id) REFERENCES cas (id, tenant_id) \
         DEFERRABLE INITIALLY DEFERRED",
    )
    .execute(&fx.pool)
    .await
    .expect("re-add cas_parent_tenant_fk");
    sqlx::query("DELETE FROM cas WHERE tenant_id = $1")
        .bind(foreign_tenant)
        .execute(&fx.pool)
        .await
        .expect("delete the foreign cas rows");
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(foreign_tenant)
        .execute(&fx.pool)
        .await
        .expect("delete the foreign tenant");

    assert_eq!(
        ca_status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "the CA chain walk refuses a cross-tenant parent"
    );
    assert_eq!(
        error_code(&ca_body),
        "internal",
        "the CoreError::Config mapping"
    );
    assert!(
        !ca_text.contains("FOREIGNCHAINPEM"),
        "the foreign CA's PEM never enters the response: {ca_text}"
    );
    assert_eq!(
        cert_status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "the certificate chain walk refuses a cross-tenant parent"
    );
    assert_eq!(error_code(&cert_body), "internal");
    assert!(
        !cert_text.contains("FOREIGNCHAINPEM"),
        "the foreign CA's PEM never enters the response: {cert_text}"
    );
}
