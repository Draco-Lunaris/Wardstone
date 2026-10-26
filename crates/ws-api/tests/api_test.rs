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
use ws_core::models::acme::{
    AcmeAccountModel, AcmeAccountStatus, AcmeAuthorizationModel, AcmeAuthorizationStatus,
    AcmeOrderModel, AcmeOrderStatus,
};
use ws_core::models::rbac::Role;
use ws_core::models::rbac::{Actor, ActorType, AuthMethod, Capability, ALL_CAPABILITIES};
use ws_core::repo::acme_repo::AcmeRepo;
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

/// The earlier-sorted, later-created tenant of the primary-tenant test;
/// swept before use so a crashed run's debris cannot collide with the
/// insert below.
const LOGIN_ORDER_TENANT: &str = "aaa-login-order-tenant";

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
            // The ACME children first (challenges → authorizations →
            // orders → accounts): the Plan-4 Task-10 REST tests seed ACME
            // rows, and `acme_orders.certificate_id` references
            // certificates.
            "DELETE FROM acme_challenges WHERE tenant_id = $1",
            "DELETE FROM acme_authorizations WHERE tenant_id = $1",
            "DELETE FROM acme_orders WHERE tenant_id = $1",
            "DELETE FROM acme_accounts WHERE tenant_id = $1",
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
    let (pool, advisory, tenant_id, admin_id) = fixture_base().await;

    let keys_dir = std::env::temp_dir().join(format!(
        "ws-api-test-keys-{}-{}",
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
    let jwt = JwtKeys::generate(900).expect("mint the JWT key pair");

    let config = ApiConfig::new("wardstone.test".to_string(), keys_dir.clone());
    let state = AppState::new_unlocked(
        pool.clone(),
        std::sync::Arc::new(jwt),
        config,
        master,
        secret_box,
    );
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

/// The fixture's shared base: the pool, the advisory lock, and the tenant
/// + admin the route tests authenticate as.
async fn fixture_base() -> (
    PgPool,
    sqlx::pool::PoolConnection<sqlx::Postgres>,
    Uuid,
    Uuid,
) {
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

    (pool, advisory, tenant_id, admin_id)
}

/// The sealed-at-rest test world: the keys directory holds the FOUR
/// passphrase envelopes (cheap KDF parameters — the tests assert the
/// change flow, not the argon2 wall clock) and the state serves as the
/// unlock built it, RAM custody over the volume. The master-key route
/// is the consumer; nothing here rotates the database role (the change
/// re-seals the CURRENT credential — rotation stays the unlock's).
async fn sealed_fixture() -> Fixture {
    let (pool, advisory, tenant_id, admin_id) = fixture_base().await;

    let keys_dir = std::env::temp_dir().join(format!(
        "ws-api-test-sealed-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    std::fs::create_dir_all(&keys_dir).expect("create the keys dir");

    let cheap_params = ws_core::crypto::KdfParams {
        m_cost: 8192,
        t_cost: 2,
        p_cost: 1,
    };
    const PASSPHRASE: &str = "the-current-master-passphrase";
    let master = [7u8; 32];
    ws_core::crypto::KeyEnvelope::write_envelope(
        &keys_dir.join(ws_core::crypto::MASTER_ENVELOPE_FILE),
        PASSPHRASE,
        &master,
        cheap_params,
        0,
    )
    .expect("mint the master envelope");
    let secret = [9u8; 32];
    ws_core::crypto::KeyEnvelope::write_envelope(
        &keys_dir.join(ws_core::crypto::SECRET_ENVELOPE_FILE),
        PASSPHRASE,
        &secret,
        cheap_params,
        0,
    )
    .expect("mint the secret-encryption envelope");
    ws_core::crypto::KeyEnvelope::write_envelope(
        &keys_dir.join(ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE),
        PASSPHRASE,
        b"the-current-db-credential",
        cheap_params,
        0,
    )
    .expect("mint the db-credential envelope");
    // The JWT pair mints straight into its envelope — the fresh-install
    // production shape (no plaintext pair ever exists on a sealed volume).
    let jwt = ws_auth::jwt::load_or_create_sealed(
        &keys_dir.join(ws_core::crypto::JWT_ENVELOPE_FILE),
        PASSPHRASE.as_bytes(),
        0,
    )
    .expect("mint the JWT pair into its envelope");

    let config = ApiConfig::new("wardstone.test".to_string(), keys_dir.clone());
    let mem = ws_secmem::global().expect("the protected pool initializes");
    let state = AppState::new_unlocked(
        pool.clone(),
        std::sync::Arc::new(jwt),
        config,
        mem.alloc_copy(&master).expect("the arena holds the master"),
        ws_core::crypto::SecretBox::from_key(
            mem.alloc_copy(&secret)
                .expect("the arena holds the secret key"),
        ),
    );
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
        // The ACME children first (see Fixture::cleanup's comment).
        "DELETE FROM acme_challenges WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM acme_authorizations WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM acme_orders WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM acme_accounts WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
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

/// Attach an argon2id-hashed password to an (already inserted) user row:
/// the hash is computed in a blocking thread, exactly like the login
/// handler hashes nothing but the verify does.
async fn set_password(pool: &PgPool, user_id: Uuid, password: String) {
    let hash = tokio::task::spawn_blocking(move || ws_auth::password::hash_password(&password))
        .await
        .unwrap()
        .unwrap();
    sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
        .bind(user_id)
        .bind(&hash)
        .execute(pool)
        .await
        .expect("set the user's password hash");
}

/// Compute a current TOTP code for a base32 secret with the workspace's
/// totp-rs pin (shared by the MFA-flow and the login tests).
fn current_totp_code(secret: &str, account: &str) -> String {
    use totp_rs::{Algorithm, Secret, TOTP};
    let secret = Secret::Encoded(secret.to_string());
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().unwrap(),
        None,
        account.to_string(),
    )
    .unwrap();
    totp.generate_current().unwrap()
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

/// A DELETE request with a bearer header (the no-body verbs, shaped like
/// [`get_bearer`]).
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

/// A genuine database failure through the issuance CAS (`ProfileRepo::update`)
/// surfaces as the MAPPED 500 — never as the retries-exhausted Conflict —
/// and the failed attempt rolls back completely.
///
/// Failure-injection mechanism (the Task 3 FK-bend test's drop-and-heal
/// idiom, sweep first): a `CHECK (false) NOT VALID` constraint on
/// `profiles`. Pure DDL, and NOT VALID means existing rows are never
/// re-validated — the constraint is evaluated ONLY on writes, so every
/// SELECT the issuance flow runs before the CAS still succeeds and EXACTLY
/// the `UPDATE profiles` statement fails with a check violation
/// (`sqlx::Error` → `CoreError::Database` → the mapping table's 500, which
/// is a different code AND status from `ApiError::Conflict`).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn cas_database_failure_maps_to_500_not_retry_conflict() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    // Self-heal FIRST — BEFORE any fixture write. A predecessor run of
    // THIS test that crashed between the inject below and the final heal
    // leaves `ws_test_invalid_check` on `profiles`; with it in place every
    // INSERT into `profiles` violates the check, so `setup_profile_and_ca`
    // would fail before this test got a chance to heal anything. This
    // placement claims nothing more: dropping the constraint here does not
    // repair a live schema fault — it only guarantees this test starts
    // from a constraint-free `profiles` table so IT can re-inject and
    // clean up after itself (the heal-after-attempt below stays).
    sqlx::query("ALTER TABLE profiles DROP CONSTRAINT IF EXISTS ws_test_invalid_check")
        .execute(&fx.pool)
        .await
        .expect("sweep a stale injected check constraint");
    let (profile_id, _ca_id) = setup_profile_and_ca(&fx).await;
    let actor = admin_actor(&fx);

    sqlx::query(
        "ALTER TABLE profiles ADD CONSTRAINT ws_test_invalid_check \
         CHECK (false) NOT VALID",
    )
    .execute(&fx.pool)
    .await
    .expect("inject the write-failing check constraint");

    // Baselines BEFORE the failed attempt, compared after: the rollback
    // must leave no certificate, no `cert_issued` audit row, and no burned
    // serial row behind.
    let (certs_before, audits_before, serials_before): (i64, i64, i64) = (
        sqlx::query_scalar("SELECT count(*) FROM certificates WHERE tenant_id = $1")
            .bind(fx.tenant_id)
            .fetch_one(&fx.pool)
            .await
            .unwrap(),
        sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE tenant_id = $1 AND action = 'cert_issued'",
        )
        .bind(fx.tenant_id)
        .fetch_one(&fx.pool)
        .await
        .unwrap(),
        sqlx::query_scalar("SELECT count(*) FROM used_serials WHERE tenant_id = $1")
            .bind(fx.tenant_id)
            .fetch_one(&fx.pool)
            .await
            .unwrap(),
    );

    // The core loop and the HTTP leg BOTH run while the constraint is in
    // place, WITHOUT asserting: NOTHING between the injection and the heal
    // may panic — a panic there would leave the schema broken for every
    // later suite (which is why every assertion lives AFTER the heal). The
    // core leg captures the `Result` un-demolished; the HTTP leg captures
    // status and body with panic-proof reads.
    let body = ws_api::routes::certificates::IssueCertificateBody {
        profile_id,
        subject_cn: "casfail.wardstone.test".to_string(),
        sans: vec!["casfail.wardstone.test".to_string()],
        csr_pem: Some(mint_csr(
            "casfail.wardstone.test",
            &["casfail.wardstone.test"],
        )),
    };
    let core = ws_api::routes::certificates::issue_certificate_core(
        &fx.state,
        &actor,
        &body,
        Uuid::new_v4(),
        Uuid::new_v4(),
        None,
    )
    .await;

    let token = admin_token(&fx);
    let res = post_json(
        &fx,
        "/api/v1/certificates",
        Some(&token),
        json!({
            "profile_id": profile_id,
            "subject_cn": "casfail.wardstone.test",
            "sans": ["casfail.wardstone.test"],
            "csr_pem": mint_csr("casfail.wardstone.test", &["casfail.wardstone.test"])
        }),
    )
    .await;
    let status = res.status();
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    let mapped: Value = serde_json::from_slice(&raw).unwrap_or(json!({}));

    // Heal the schema BEFORE any assertion (a failed assert must never
    // leave the constraint behind).
    sqlx::query("ALTER TABLE profiles DROP CONSTRAINT ws_test_invalid_check")
        .execute(&fx.pool)
        .await
        .expect("heal the injected check constraint");

    // The core loop: a `CoreError::Database` from the CAS propagates as
    // the mapped `ApiError::Internal` from the FIRST attempt — the bounded
    // retry counts only `Ok(None)` (the revision moved), never `Err`.
    let err = core.expect_err("the injected DB failure makes issuance fail");
    assert!(
        matches!(err, ws_api::ApiError::Internal(_)),
        "a genuine CAS DB failure maps to Internal (500), got: {err:?}"
    );
    assert!(
        !matches!(err, ws_api::ApiError::Conflict(_)),
        "a genuine DB failure must NOT arrive as the retries-exhausted Conflict"
    );

    // The HTTP surface renders the mapped error: 500 with body code
    // `internal` under the `error` object, never the conflict-shape 409.
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "the route renders the mapped database error as a 500"
    );
    assert_eq!(
        mapped["error"]["code"], "internal",
        "the 500 body carries the mapped `internal` code"
    );
    assert_ne!(
        mapped["error"]["code"], "conflict",
        "a genuine DB failure must not render the conflict code"
    );

    let (certs_after, audits_after, serials_after): (i64, i64, i64) = (
        sqlx::query_scalar("SELECT count(*) FROM certificates WHERE tenant_id = $1")
            .bind(fx.tenant_id)
            .fetch_one(&fx.pool)
            .await
            .unwrap(),
        sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE tenant_id = $1 AND action = 'cert_issued'",
        )
        .bind(fx.tenant_id)
        .fetch_one(&fx.pool)
        .await
        .unwrap(),
        sqlx::query_scalar("SELECT count(*) FROM used_serials WHERE tenant_id = $1")
            .bind(fx.tenant_id)
            .fetch_one(&fx.pool)
            .await
            .unwrap(),
    );
    assert_eq!(
        (certs_before, audits_before, serials_before),
        (certs_after, audits_after, serials_after),
        "the failed issuance attempt rolls back completely (no certificate row, \
         no cert_issued audit row, no burned serial)"
    );

    fx.cleanup().await;
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
            Some(json!({"reason": "superseded"})),
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
        (
            "POST",
            "/api/v1/master-key".into(),
            Some(json!({"current": "a-current", "next": "a-next"})),
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
    assert_eq!(
        me["sealed_volume"], true,
        "every volume is sealed at creation, got: {me}"
    );

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

    // Activate with the first code.
    let res = post_json(
        &fx,
        "/api/v1/auth/totp/activate",
        Some(&token),
        json!({"code": current_totp_code(&secret, username)}),
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
        json!({"code": current_totp_code(&secret, username)}),
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

/// Login resolves the primary tenant by CREATION order (the setup
/// tenant), never by name: a second tenant whose name sorts EARLIER but
/// whose created_at is LATER must not win. The fixture tenant is
/// backdated with the house direct-UPDATE idiom so it is provably the
/// oldest row in the shared database, and the young tenant is backdated
/// to be unambiguously younger while sorting first alphabetically.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn login_resolves_oldest_primary_tenant() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    sweep_tenant(&fx.pool, LOGIN_ORDER_TENANT).await;

    // 2000-01-01 and 2001-01-01: two fixed instants one year apart so the
    // creation order is deterministic against the clock and against any
    // concurrent suite's tenants (all far newer than 2000).
    let year_2000 = DateTime::from_timestamp(946_684_800, 0).unwrap();
    let year_2001 = DateTime::from_timestamp(978_307_200, 0).unwrap();

    sqlx::query("UPDATE tenants SET created_at = $1 WHERE id = $2")
        .bind(year_2000)
        .bind(fx.tenant_id)
        .execute(&fx.pool)
        .await
        .expect("backdate the fixture tenant to 2000");

    // The password user lives in the fixture (setup) tenant.
    let user_id = Uuid::new_v4();
    insert_user(&fx.pool, fx.tenant_id, user_id, "setup-admin", Role::Admin).await;
    set_password(
        &fx.pool,
        user_id,
        "correct horse battery staple".to_string(),
    )
    .await;

    // The younger tenant, whose name sorts FIRST: the alphabetical-
    // resolution bug this test pins would pick this row and the login
    // below would fail (the admin is in the older tenant).
    let young_tenant = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(young_tenant)
        .bind(LOGIN_ORDER_TENANT)
        .execute(&fx.pool)
        .await
        .expect("insert the younger tenant");
    fx.extra_tenants.lock().unwrap().push(young_tenant);
    sqlx::query("UPDATE tenants SET created_at = $1 WHERE id = $2")
        .bind(year_2001)
        .bind(young_tenant)
        .execute(&fx.pool)
        .await
        .expect("backdate the younger tenant to 2001");

    let res = post_json(
        &fx,
        "/api/v1/auth/login",
        None,
        json!({"username": "setup-admin", "password": "correct horse battery staple"}),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "login lands on the setup tenant"
    );
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let login: Value = serde_json::from_slice(&raw).unwrap();
    let access = login["access_token"].as_str().unwrap().to_string();

    // The session actor's tenant is the OLDEST tenant.
    let res = get_bearer(&fx, "/api/v1/auth/me", &access).await;
    assert_eq!(res.status(), StatusCode::OK);
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let me: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(
        me["tenant_id"].as_str().unwrap(),
        fx.tenant_id.to_string(),
        "the login session belongs to the first-created tenant"
    );

    fx.cleanup().await;
}

/// Login without the TOTP code an MFA-enabled account requires: 401 whose
/// body carries the STRUCTURED code `mfa_required` (not the generic
/// `unauthorized`), so the SPA can route the user to the MFA prompt.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn login_mfa_error_carries_code() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let user_id = Uuid::new_v4();
    let username = "mfa-login-operator";
    insert_user(&fx.pool, fx.tenant_id, user_id, username, Role::Issuer).await;
    set_password(
        &fx.pool,
        user_id,
        "correct horse battery staple".to_string(),
    )
    .await;
    let token = session_token(&fx, user_id, username, "issuer");

    // Enroll + activate the account's TOTP (the lifecycle the MFA flow
    // test pins, compressed to the two calls).
    let res = post_json(&fx, "/api/v1/auth/totp/enroll", Some(&token), json!({})).await;
    assert_eq!(res.status(), StatusCode::OK);
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let enrolled: Value = serde_json::from_slice(&raw).unwrap();
    let secret = enrolled["secret"].as_str().unwrap().to_string();
    let res = post_json(
        &fx,
        "/api/v1/auth/totp/activate",
        Some(&token),
        json!({"code": current_totp_code(&secret, username)}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    // Login with the right password but no code: 401, code `mfa_required`.
    let res = post_json(
        &fx,
        "/api/v1/auth/login",
        None,
        json!({"username": username, "password": "correct horse battery staple"}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(error_code(&body), "mfa_required");

    fx.cleanup().await;
}

/// An unknown username and a known username with a wrong password answer
/// IDENTICALLY — same 401, same body — the uniform-credentials rule. The
/// unknown-user path burns the same argon2id time as the verify path (the
/// constant-time treatment); the timing itself is not observable in the
/// response, so this pins the observable shape the rule requires.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn login_unknown_user_matches_known_user_error_shape() {
    let _db = lock_db().await;
    let mut fx = fixture().await;

    let user_id = Uuid::new_v4();
    insert_user(&fx.pool, fx.tenant_id, user_id, "padded-user", Role::Issuer).await;
    set_password(
        &fx.pool,
        user_id,
        "correct horse battery staple".to_string(),
    )
    .await;

    let unknown = post_json(
        &fx,
        "/api/v1/auth/login",
        None,
        json!({"username": "no-such-user", "password": "some wrong password"}),
    )
    .await;
    let known = post_json(
        &fx,
        "/api/v1/auth/login",
        None,
        json!({"username": "padded-user", "password": "some wrong password"}),
    )
    .await;
    assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(known.status(), StatusCode::UNAUTHORIZED);
    let unknown = axum::body::to_bytes(unknown.into_body(), 1 << 20)
        .await
        .unwrap();
    let known = axum::body::to_bytes(known.into_body(), 1 << 20)
        .await
        .unwrap();
    let unknown: Value = serde_json::from_slice(&unknown).unwrap();
    let known: Value = serde_json::from_slice(&known).unwrap();
    assert_eq!(
        unknown, known,
        "unknown-user and wrong-password bodies are identical"
    );
    assert_eq!(error_code(&unknown), "unauthorized");

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

    // Configure the (single) tenant's OIDC provider: an ABSENT secret pair
    // (the public-client convention — the columns default to NULL). The
    // discovery URL is unreachable here — start is expected to fail on the
    // network leg, but only AFTER the state was minted and stored.
    sqlx::query(
        "INSERT INTO oidc_config (tenant_id, provider_type, display_name, discovery_url, \
         client_id, redirect_uri, scopes) \
         VALUES ($1, 'custom', 'Test IdP', 'http://127.0.0.1:9/.well-known/openid-configuration', \
         'client', 'http://127.0.0.1:9/callback', 'openid profile email')",
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
        json!({"reason": "key_compromise"}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let res = post_json(
        &fx,
        &format!("/api/v1/certificates/{cert_id}/revoke"),
        Some(&token),
        json!({"reason": "key_compromise"}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "revoke is idempotent");

    let rows = audit_rows(&fx).await;
    let revoked: Vec<_> = rows.iter().filter(|(a, ..)| a == "cert_revoked").collect();
    fx.cleanup().await;

    assert_eq!(revoked.len(), 1, "the second revoke writes no row");
    assert_eq!(revoked[0].3["reason"], "key_compromise");
}

/// The stored revocation reason is the exact snake_case name
/// ws-worker's `reason_from_str` maps into `CrlReason::KeyCompromise`
/// (the CRL/OCSP contract: worker-side, an unknown stored spelling
/// silently yields NO reason extension). The raw row is asserted, not
/// the API DTO, so the test pins the DB contract itself.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn typed_reason_reaches_crl_contract() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let (profile_id, _ca_id) = setup_profile_and_ca(&fx).await;
    let (_, body) = issue_csr(
        &fx,
        profile_id,
        "typed.wardstone.test",
        &["typed.wardstone.test"],
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
        json!({"reason": "key_compromise", "detail": null}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    // Capture the raw row BEFORE cleanup, then sweep.
    let stored: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT revocation_reason, revocation_detail FROM certificates WHERE id = $1",
    )
    .bind(cert_id)
    .fetch_optional(&fx.pool)
    .await
    .expect("select the revocation pair");
    fx.cleanup().await;

    let (reason, detail) = stored.expect("the certificate row exists");
    assert_eq!(
        reason.as_deref(),
        Some("key_compromise"),
        "the stored reason is the exact name worker's reason_from_str parses"
    );
    assert_eq!(detail.as_deref(), None, "no detail was supplied");
}

/// The optional detail round-trips: stored verbatim on the first revoke,
/// kept on a second (idempotent revoke keeps the FIRST reason/detail
/// pair), and visible in the certificate GET response.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn revocation_detail_roundtrip() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let (profile_id, _ca_id) = setup_profile_and_ca(&fx).await;
    let (_, body) = issue_csr(
        &fx,
        profile_id,
        "detail.wardstone.test",
        &["detail.wardstone.test"],
    )
    .await;
    let cert_id = body["certificate_id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();
    let token = admin_token(&fx);
    let first_detail = "under investigation since the 2026-10 incident";

    let res = post_json(
        &fx,
        &format!("/api/v1/certificates/{cert_id}/revoke"),
        Some(&token),
        json!({"reason": "certificate_hold", "detail": first_detail}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let res = post_json(
        &fx,
        &format!("/api/v1/certificates/{cert_id}/revoke"),
        Some(&token),
        json!({"reason": "superseded", "detail": "a later revoke must not win"}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "revoke is idempotent");

    let stored: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT revocation_reason, revocation_detail FROM certificates WHERE id = $1",
    )
    .bind(cert_id)
    .fetch_optional(&fx.pool)
    .await
    .expect("select the revocation pair");
    let get_res = get_bearer(&fx, &format!("/api/v1/certificates/{cert_id}"), &token).await;
    assert_eq!(get_res.status(), StatusCode::OK);
    let get_body = axum::body::to_bytes(get_res.into_body(), 4 << 20)
        .await
        .unwrap();
    let get_body: Value = serde_json::from_slice(&get_body).unwrap();
    fx.cleanup().await;

    let (reason, detail) = stored.expect("the certificate row exists");
    assert_eq!(
        reason.as_deref(),
        Some("certificate_hold"),
        "a second revoke keeps the FIRST reason"
    );
    assert_eq!(
        detail.as_deref(),
        Some(first_detail),
        "a second revoke keeps the FIRST detail"
    );
    assert_eq!(get_body["revocation_reason"], "certificate_hold");
    assert_eq!(get_body["revocation_detail"], first_detail);
}

/// An unknown reason name is a serde rejection mapped to 400
/// `bad_request`, and a detail longer than 2000 characters is 400
/// `bad_request` too; the certificate stays active.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn revoke_rejects_unknown_reason_and_oversized_detail() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let (profile_id, _ca_id) = setup_profile_and_ca(&fx).await;
    let (_, body) = issue_csr(
        &fx,
        profile_id,
        "reject.wardstone.test",
        &["reject.wardstone.test"],
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
        json!({"reason": "totally_not_a_reason"}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body_bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(error_code(&body), "bad_request");

    let oversized = "x".repeat(2001);
    let res = post_json(
        &fx,
        &format!("/api/v1/certificates/{cert_id}/revoke"),
        Some(&token),
        json!({"reason": "superseded", "detail": oversized}),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body_bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(error_code(&body), "bad_request");

    let get_res = get_bearer(&fx, &format!("/api/v1/certificates/{cert_id}"), &token).await;
    assert_eq!(get_res.status(), StatusCode::OK);
    let get_bytes = axum::body::to_bytes(get_res.into_body(), 4 << 20)
        .await
        .unwrap();
    let get_body: Value = serde_json::from_slice(&get_bytes).unwrap();
    fx.cleanup().await;
    assert_eq!(get_body["status"], "active", "the rejects never revoked");
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

/// The PUT edit path persists the description (the round-trip the admin
/// table renders): a description on the PUT body lands in the row the list
/// serves, the PUT response echoes the STORED value (not merely the
/// request's), a blank one stores NULL and round-trips as `null`, and the
/// create path is unchanged. One profile, edited twice.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn profile_put_persists_the_description() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);
    let policy = json!({
        "key_type": "ecdsa-p256",
        "key_usages": ["digital_signature"],
        "eku": ["server_auth"],
        "lifetime_days": 30,
        "san_patterns": ["d.test"]
    });

    let mut create_body = policy.clone();
    create_body["name"] = json!("desc-edit");
    create_body["description"] = json!("first wording");
    let create_res = post_json(&fx, "/api/v1/profiles", Some(&token), create_body).await;
    assert_eq!(
        create_res.status(),
        StatusCode::CREATED,
        "create the profile"
    );
    let raw = axum::body::to_bytes(create_res.into_body(), 1 << 20)
        .await
        .unwrap();
    let created: Value = serde_json::from_slice(&raw).unwrap();
    let profile_id = created["id"].as_str().unwrap().to_string();
    assert_eq!(
        created["description"], "first wording",
        "the create path persists and echoes the description (unchanged)"
    );

    let mut edit_body = policy.clone();
    edit_body["description"] = json!("second wording");
    let edit_res = put_json(
        &fx,
        &format!("/api/v1/profiles/{profile_id}"),
        Some(&token),
        edit_body,
    )
    .await;
    let edit_status = edit_res.status();
    let raw = axum::body::to_bytes(edit_res.into_body(), 1 << 20)
        .await
        .unwrap();
    let edited: Value = serde_json::from_slice(&raw).unwrap();
    let first_list = get_json(&fx, "/api/v1/profiles", &token).await;

    let mut blank_body = policy.clone();
    blank_body["description"] = json!("   ");
    let blank_res = put_json(
        &fx,
        &format!("/api/v1/profiles/{profile_id}"),
        Some(&token),
        blank_body,
    )
    .await;
    let blank_status = blank_res.status();
    let raw = axum::body::to_bytes(blank_res.into_body(), 1 << 20)
        .await
        .unwrap();
    let blanked: Value = serde_json::from_slice(&raw).unwrap();
    let second_list = get_json(&fx, "/api/v1/profiles", &token).await;

    let audits = audit_rows(&fx).await;
    let row_description = |list: &Value| -> Value {
        list.as_array()
            .expect("the list body is a JSON array")
            .iter()
            .find(|profile| profile["id"].as_str() == Some(profile_id.as_str()))
            .map(|profile| profile["description"].clone())
            .expect("the edited profile appears in the list")
    };

    fx.cleanup().await;

    assert_eq!(edit_status, StatusCode::OK, "the description edit");
    assert_eq!(
        edited["description"], "second wording",
        "the PUT response echoes the STORED description"
    );
    assert_eq!(
        row_description(&first_list),
        json!("second wording"),
        "the edit persisted into the row the list serves"
    );
    assert_eq!(blank_status, StatusCode::OK, "the blank edit");
    assert_eq!(
        blanked["description"],
        json!(null),
        "a blank description stores NULL and the response echoes null"
    );
    assert_eq!(
        row_description(&second_list),
        json!(null),
        "the cleared description round-trips as null"
    );
    let actions: Vec<&str> = audits.iter().map(|(action, ..)| action.as_str()).collect();
    assert_eq!(
        actions,
        vec!["profile_created", "profile_revised", "profile_revised"],
        "exactly the create and the two edit audit rows: {audits:?}"
    );
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
        json!({"reason": "superseded"}),
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

    // The listing contract orders by `not_after DESC` and ties on `id`
    // (equal-expiry rows keep a stable order across calls and pages).
    // The expectation is computed by parsing the LISTING'S OWN rows —
    // never a string compare of RFC 3339 (fractional digits of
    // differing lengths invert: ".98Z" vs ".987Z") and never a bare id
    // sort. The mints do NOT have distinct expiries to fall back on:
    // one profile's leaves share the midnight-anchored validity window,
    // so both mint in this test at the SAME `not_after` and the id
    // tiebreak is the whole order — which is exactly what the 2026-10-25
    // full-run flake was (the filtered query lacked the tiebreak and
    // Postgres was free to hand the tied rows back in heap order).
    let expected: Vec<Uuid> = {
        let mut rows: Vec<(DateTime<Utc>, Uuid)> = unfiltered
            .as_array()
            .expect("the unfiltered list is a JSON array")
            .iter()
            .map(|row| {
                (
                    DateTime::parse_from_rfc3339(row["not_after"].as_str().unwrap())
                        .expect("the row's not_after is RFC 3339")
                        .with_timezone(&Utc),
                    row["id"].as_str().unwrap().parse::<Uuid>().unwrap(),
                )
            })
            .collect();
        rows.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        rows.into_iter().map(|(_, id)| id).collect()
    };
    assert_eq!(ids(&unfiltered), expected, "no filter lists both");
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

/// The slim list, the dashboard sieve's feed: `GET /certificates/slim`
/// answers `{id, subject, serial_hex, not_after, status}` and NOTHING
/// else (no PEM, no SAN arrays, no audit fields), honors the `status`
/// filter, and gates on `read_certificates` like the full list does.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn slim_listing_serves_the_sieve_projection() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);
    let (profile_id, _ca_id) = setup_profile_and_ca(&fx).await;

    let (a_status, a_body) = issue_csr(
        &fx,
        profile_id,
        "slim-a.wardstone.test",
        &["slim-a.wardstone.test"],
    )
    .await;
    assert_eq!(a_status, StatusCode::OK, "issue A: {a_body}");
    let a_id = a_body["certificate_id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();
    let a_serial_hex = a_body["serial_hex"].as_str().unwrap().to_string();
    let (b_status, b_body) = issue_csr(
        &fx,
        profile_id,
        "slim-b.wardstone.test",
        &["slim-b.wardstone.test"],
    )
    .await;
    assert_eq!(b_status, StatusCode::OK, "issue B: {b_body}");
    let b_id = b_body["certificate_id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();
    let revoke = post_json(
        &fx,
        &format!("/api/v1/certificates/{b_id}/revoke"),
        Some(&token),
        json!({"reason": "superseded"}),
    )
    .await;
    assert_eq!(revoke.status(), StatusCode::OK, "revoke B");

    let slim = get_json(&fx, "/api/v1/certificates/slim", &token).await;
    let slim_active = get_json(&fx, "/api/v1/certificates/slim?status=active", &token).await;
    let gate_status = get_bearer(&fx, "/api/v1/certificates/slim", &api_token(&fx, &[]).await)
        .await
        .status();

    fx.cleanup().await;

    let rows = slim.as_array().expect("the slim body is a JSON array");
    let a_row = rows
        .iter()
        .find(|row| row["id"].as_str() == Some(a_id.to_string().as_str()))
        .expect("A appears in the slim list");
    let mut keys: Vec<&str> = a_row
        .as_object()
        .expect("a slim row is a JSON object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["id", "not_after", "serial_hex", "status", "subject"],
        "the slim projection carries EXACTLY five fields"
    );
    assert_eq!(a_row["subject"], "CN=slim-a.wardstone.test");
    assert_eq!(a_row["serial_hex"], a_serial_hex);
    assert_eq!(a_row["status"], "active");
    assert!(
        a_row["not_after"].is_string(),
        "not_after arrives as an RFC 3339 timestamp"
    );

    let ids = |list: &Value| -> Vec<Uuid> {
        list.as_array()
            .expect("the slim body is a JSON array")
            .iter()
            .map(|row| row["id"].as_str().unwrap().parse::<Uuid>().unwrap())
            .collect()
    };
    assert!(
        ids(&slim).contains(&a_id) && ids(&slim).contains(&b_id),
        "the unfiltered slim list lists both"
    );
    let active_ids = ids(&slim_active);
    assert!(active_ids.contains(&a_id), "the active filter keeps A");
    assert!(
        !active_ids.contains(&b_id),
        "the active filter drops the revoked B"
    );
    let b_row = rows
        .iter()
        .find(|row| row["id"].as_str() == Some(b_id.to_string().as_str()))
        .expect("B appears in the slim list");
    assert_eq!(b_row["status"], "revoked", "the revoked status decodes");

    assert_eq!(gate_status, StatusCode::FORBIDDEN, "the capability gate");
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
        json!({"reason": "cessation_of_operation"}),
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

// ---------------------------------------------------------------------------
// Profile deletion with reference refusal (Plan 3 Task 6)
// ---------------------------------------------------------------------------

/// `DELETE /api/v1/profiles/{id}`: an UNREFERENCED profile deletes (204,
/// gone on re-read, one `profile_deleted` audit row carrying the profile's
/// name), a profile any certificate references is refused with 409 and the
/// fixed message (the setup built-ins — e.g. a default web-server profile
/// that an issued leaf pins — are exactly this case), and an unknown or
/// another tenant's profile id is a 404, indistinguishably. All captured
/// response data is asserted after cleanup.
/// A PATCH request with a JSON body and (optional) bearer header, shaped
/// like [`put_json`].
async fn patch_json(
    fixture: &Fixture,
    uri: &str,
    token: Option<&str>,
    body: Value,
) -> TestResponse {
    let mut builder = Request::builder()
        .method("PATCH")
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

#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn profile_delete_refuses_when_referenced() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);

    // The unreferenced path: a fresh profile nothing has issued from.
    let profile_id = create_filter_profile(&fx, &token, "delete-me").await;
    let delete_uri = format!("/api/v1/profiles/{profile_id}");
    let delete_status = delete_bearer(&fx, &delete_uri, &token).await.status();
    // The re-read and the audited row are captured BEFORE cleanup.
    let get_res = get_bearer(&fx, &delete_uri, &token).await;
    let get_status = get_res.status();
    let audit_res = get_bearer(&fx, "/api/v1/audit?action=profile_deleted", &token).await;
    let audit_status = audit_res.status();
    let audit_raw = axum::body::to_bytes(audit_res.into_body(), 4 << 20)
        .await
        .unwrap();
    let audit: Value = serde_json::from_slice(&audit_raw).unwrap();

    // The referenced path: a leaf issued from the fixture profile pins its
    // revision (active history counts — a revoked one would too), so the
    // deletion is refused. A setup-built-in profile in the same position
    // (e.g. the default web-server profile behind the fixture leaf)
    // refuses the same way.
    let (referenced_id, _ca_id) = setup_profile_and_ca(&fx).await;
    let (issue_status, issue_body) = issue_csr(
        &fx,
        referenced_id,
        "leaf.delete.wardstone.test",
        &["leaf.delete.wardstone.test"],
    )
    .await;
    assert_eq!(issue_status, StatusCode::OK, "issue the leaf: {issue_body}");
    let ref_res = delete_bearer(&fx, &format!("/api/v1/profiles/{referenced_id}"), &token).await;
    let ref_status = ref_res.status();
    let ref_raw = axum::body::to_bytes(ref_res.into_body(), 1 << 20)
        .await
        .unwrap();
    let ref_body: Value = serde_json::from_slice(&ref_raw).unwrap();

    // Unknown id and another tenant's id are both 404.
    let unknown_status =
        delete_bearer(&fx, &format!("/api/v1/profiles/{}", Uuid::new_v4()), &token)
            .await
            .status();
    let foreign_name = "rt-api-foreign-profile";
    sqlx::query("DELETE FROM profiles WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)")
        .bind(foreign_name)
        .execute(&fx.pool)
        .await
        .expect("sweep stale foreign-profile rows");
    sqlx::query("DELETE FROM tenants WHERE name = $1")
        .bind(foreign_name)
        .execute(&fx.pool)
        .await
        .expect("sweep stale foreign-profile tenant");
    let foreign_tenant = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(foreign_tenant)
        .bind(foreign_name)
        .execute(&fx.pool)
        .await
        .expect("insert the foreign-profile tenant");
    fx.extra_tenants.lock().unwrap().push(foreign_tenant);
    let foreign_profile = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO profiles (id, tenant_id, name, description, current_revision_id, created_at) \
         VALUES ($1, $2, 'foreign-profile', NULL, NULL, now())",
    )
    .bind(foreign_profile)
    .bind(foreign_tenant)
    .execute(&fx.pool)
    .await
    .expect("insert the foreign-profile row");
    let foreign_status = delete_bearer(&fx, &format!("/api/v1/profiles/{foreign_profile}"), &token)
        .await
        .status();

    fx.cleanup().await;

    // Unreferenced: 204, and the profile is gone on re-read.
    assert_eq!(
        delete_status,
        StatusCode::NO_CONTENT,
        "an unreferenced profile deletes"
    );
    assert_eq!(get_status, StatusCode::NOT_FOUND, "gone after the delete");

    // Exactly one `profile_deleted` row, with the profile's name.
    assert_eq!(
        audit_status,
        StatusCode::OK,
        "the audit list serves the action filter"
    );
    let deleted = audit.as_array().expect("the audit list is an array");
    assert_eq!(
        deleted.len(),
        1,
        "exactly one profile_deleted row: {deleted:?}"
    );
    assert_eq!(deleted[0]["target_type"], "profile");
    assert_eq!(deleted[0]["target_id"], profile_id.to_string());
    assert_eq!(deleted[0]["details"], json!({ "name": "delete-me" }));

    // Referenced: 409 with the fixed message, code `conflict`.
    assert_eq!(ref_status, StatusCode::CONFLICT, "the referenced refusal");
    assert_eq!(error_code(&ref_body), "conflict");
    assert_eq!(
        ref_body["error"]["message"].as_str().unwrap(),
        "profile is referenced by certificates and cannot be deleted"
    );

    // Unknown and foreign ids are 404, indistinguishably.
    assert_eq!(unknown_status, StatusCode::NOT_FOUND, "an unknown id");
    assert_eq!(foreign_status, StatusCode::NOT_FOUND, "a foreign tenant id");
}

// ---------------------------------------------------------------------------
// The user PATCH route (role assignment and activation)
// ---------------------------------------------------------------------------

/// `PATCH /api/v1/users/{id}`: a role change, an activation flip, and
/// both fields in one request — the response mirrors the fresh row, the
/// `users` row follows, and each real change writes its audit row in the
/// house order (the role row before the flag row).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn user_role_and_active_patch() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);
    let user_id = Uuid::new_v4();
    insert_user(&fx.pool, fx.tenant_id, user_id, "patchee", Role::Issuer).await;
    let uri = format!("/api/v1/users/{user_id}");

    // Role: issuer -> viewer.
    let role_res = patch_json(&fx, &uri, Some(&token), json!({ "role": "viewer" })).await;
    let role_status = role_res.status();
    let role_raw = axum::body::to_bytes(role_res.into_body(), 1 << 20)
        .await
        .unwrap();
    let role_body: Value = serde_json::from_slice(&role_raw).unwrap();
    let after_role: (String, bool) =
        sqlx::query_as("SELECT role, is_active FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&fx.pool)
            .await
            .expect("read the user row after the role patch");

    // Deactivate, then reactivate: is_active flips each way.
    let deact_status = patch_json(&fx, &uri, Some(&token), json!({ "is_active": false }))
        .await
        .status();
    let after_deact: bool = sqlx::query_scalar("SELECT is_active FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&fx.pool)
        .await
        .expect("read is_active after the deactivation");
    let act_status = patch_json(&fx, &uri, Some(&token), json!({ "is_active": true }))
        .await
        .status();
    let after_act: bool = sqlx::query_scalar("SELECT is_active FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&fx.pool)
        .await
        .expect("read is_active after the reactivation");

    // Both fields in ONE request: role first, then the flag.
    let both_res = patch_json(
        &fx,
        &uri,
        Some(&token),
        json!({ "role": "issuer", "is_active": false }),
    )
    .await;
    let both_status = both_res.status();
    let after_both: (String, bool) =
        sqlx::query_as("SELECT role, is_active FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&fx.pool)
            .await
            .expect("read the user row after the combined patch");

    let audits = audit_rows(&fx).await;
    // The target tuples ride the same pre-cleanup capture window: the
    // self-cleaning contract reads everything before cleanup deletes the
    // audit rows.
    let targets: Vec<(String, String, String)> =
        sqlx::query_as("SELECT action, target_type, target_id FROM audit_log WHERE tenant_id = $1")
            .bind(fx.tenant_id)
            .fetch_all(&fx.pool)
            .await
            .expect("read the patch audit target tuples");

    fx.cleanup().await;

    assert_eq!(role_status, StatusCode::OK, "the role patch");
    assert_eq!(role_body["role"], "viewer", "the response carries the role");
    assert_eq!(
        role_body["is_active"], true,
        "an inactive field is untouched"
    );
    assert_eq!(after_role, ("viewer".to_string(), true), "the row role");

    assert_eq!(deact_status, StatusCode::OK, "the deactivation");
    assert!(!after_deact, "is_active flips to FALSE");
    assert_eq!(act_status, StatusCode::OK, "the reactivation");
    assert!(after_act, "is_active flips back to TRUE");

    assert_eq!(both_status, StatusCode::OK, "the combined patch");
    assert_eq!(after_both, ("issuer".to_string(), false));

    // Exactly the five expected audit actions. The first three come from
    // three separate requests (distinct transaction timestamps, so their
    // order under `ORDER BY created_at, id` is deterministic); the
    // combined request's two rows share ONE `created_at` (`now()` is the
    // transaction timestamp), so their relative order is decided by a
    // caller-chosen UUIDv4 tie-break — asserted as a SET with per-action
    // details, never positionally.
    let actions: Vec<&str> = audits.iter().map(|(action, ..)| action.as_str()).collect();
    assert_eq!(
        actions.len(),
        5,
        "exactly the five patch audit rows: {audits:?}"
    );
    assert_eq!(
        actions[..3],
        ["user_role_changed", "user_deactivated", "user_activated"],
        "the single-field requests' audit rows in order: {audits:?}"
    );
    let combined_actions: std::collections::BTreeSet<&str> = actions[3..].iter().copied().collect();
    assert_eq!(
        combined_actions,
        ["user_role_changed", "user_deactivated"]
            .into_iter()
            .collect(),
        "the combined request's two audit rows, order aside: {audits:?}"
    );
    // The role rows carry from/to exactly; the flag rows are empty-detail.
    assert_eq!(
        audits[0].3,
        json!({ "from": "issuer", "to": "viewer" }),
        "the first role change's from/to"
    );
    assert_eq!(audits[1].3, json!({}), "user_deactivated");
    assert_eq!(audits[2].3, json!({}), "user_activated");
    for row in &audits[3..] {
        match row.0.as_str() {
            "user_role_changed" => assert_eq!(
                row.3,
                json!({ "from": "viewer", "to": "issuer" }),
                "the combined request's role change details"
            ),
            "user_deactivated" => assert_eq!(row.3, json!({}), "the combined deactivate"),
            other => panic!("unexpected audit action in the combined pair: {other}"),
        }
    }

    // Every patch audit row targets the patched user with target_type
    // "user" (the target tuple the route's audit entries carry; read back
    // directly because the `audit_rows` helper does not select it).
    assert_eq!(targets.len(), 5, "one audit row per audit_rows row");
    assert!(
        targets
            .iter()
            .all(|(_, target_type, target_id)| target_type == "user"
                && *target_id == user_id.to_string()),
        "every patch audit row targets the patched user: {targets:?}"
    );
}

/// The last-admin guard on a ROLE change: the fixture's single active
/// admin demoting themselves is refused 409 with the exact message; the
/// row keeps its role; no audit rows are written.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn last_admin_role_demotion_refused() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    // The fixture admin is the tenant's only active admin, and the
    // acting actor on its own account: the tenant-wide count refuses
    // regardless of who is acting.
    let token = admin_token(&fx);
    let res = patch_json(
        &fx,
        &format!("/api/v1/users/{}", fx.admin_id),
        Some(&token),
        json!({ "role": "viewer" }),
    )
    .await;
    let status = res.status();
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&raw).unwrap();
    let row: (String, bool) = sqlx::query_as("SELECT role, is_active FROM users WHERE id = $1")
        .bind(fx.admin_id)
        .fetch_one(&fx.pool)
        .await
        .expect("read the admin row");
    let audits = audit_rows(&fx).await;

    fx.cleanup().await;

    assert_eq!(status, StatusCode::CONFLICT, "the demotion refusal");
    assert_eq!(error_code(&body), "conflict");
    assert_eq!(
        body["error"]["message"].as_str().unwrap(),
        "refusing to remove the last active administrator"
    );
    assert_eq!(row, ("admin".to_string(), true), "the row is unchanged");
    assert!(
        audits.is_empty(),
        "no audit rows on the refusal: {audits:?}"
    );
}

/// The same last-admin guard on an ACTIVATION change: `is_active: false`
/// onto the tenant's only active admin is refused the same way.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn last_admin_deactivation_refused() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);
    let res = patch_json(
        &fx,
        &format!("/api/v1/users/{}", fx.admin_id),
        Some(&token),
        json!({ "is_active": false }),
    )
    .await;
    let status = res.status();
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&raw).unwrap();
    let row: (String, bool) = sqlx::query_as("SELECT role, is_active FROM users WHERE id = $1")
        .bind(fx.admin_id)
        .fetch_one(&fx.pool)
        .await
        .expect("read the admin row");
    let audits = audit_rows(&fx).await;

    fx.cleanup().await;

    assert_eq!(status, StatusCode::CONFLICT, "the deactivation refusal");
    assert_eq!(error_code(&body), "conflict");
    assert_eq!(
        body["error"]["message"].as_str().unwrap(),
        "refusing to remove the last active administrator"
    );
    assert_eq!(row, ("admin".to_string(), true), "the row is unchanged");
    assert!(
        audits.is_empty(),
        "no audit rows on the refusal: {audits:?}"
    );
}

/// An empty PATCH body (`{}`) names no change at all: 400 with code
/// `bad_request` and the fixed "nothing to update" message.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn user_patch_requires_payload() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);
    let res = patch_json(
        &fx,
        &format!("/api/v1/users/{}", fx.admin_id),
        Some(&token),
        json!({}),
    )
    .await;
    let status = res.status();
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&raw).unwrap();

    fx.cleanup().await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "the empty body");
    assert_eq!(error_code(&body), "bad_request");
    assert_eq!(
        body["error"]["message"].as_str().unwrap(),
        "nothing to update"
    );
}

/// An unknown user id and another tenant's user id are both 404,
/// indistinguishably (the PATCH body is otherwise valid).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn user_patch_unknown_and_foreign_ids_are_404() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);
    let unknown_status = patch_json(
        &fx,
        &format!("/api/v1/users/{}", Uuid::new_v4()),
        Some(&token),
        json!({ "role": "viewer" }),
    )
    .await
    .status();

    // Another tenant's user, swept-then-seeded like the profile suite's
    // foreign rows.
    let foreign_name = "rt-api-foreign-user";
    sqlx::query(
        "DELETE FROM audit_log WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
    )
    .bind(foreign_name)
    .execute(&fx.pool)
    .await
    .expect("sweep stale foreign-user audit rows");
    sqlx::query(
        "DELETE FROM users WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
    )
    .bind(foreign_name)
    .execute(&fx.pool)
    .await
    .expect("sweep stale foreign-user rows");
    sqlx::query("DELETE FROM tenants WHERE name = $1")
        .bind(foreign_name)
        .execute(&fx.pool)
        .await
        .expect("sweep stale foreign-user tenant");
    let foreign_tenant = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(foreign_tenant)
        .bind(foreign_name)
        .execute(&fx.pool)
        .await
        .expect("insert the foreign-user tenant");
    fx.extra_tenants.lock().unwrap().push(foreign_tenant);
    let foreign_user = Uuid::new_v4();
    insert_user(
        &fx.pool,
        foreign_tenant,
        foreign_user,
        "foreign-user",
        Role::Viewer,
    )
    .await;
    let foreign_status = patch_json(
        &fx,
        &format!("/api/v1/users/{foreign_user}"),
        Some(&token),
        json!({ "role": "admin" }),
    )
    .await
    .status();

    fx.cleanup().await;

    assert_eq!(unknown_status, StatusCode::NOT_FOUND, "an unknown id");
    assert_eq!(foreign_status, StatusCode::NOT_FOUND, "a foreign tenant id");
}

/// The deactivate route runs the SAME self-deactivation policy the PATCH
/// route pins: the acting actor may deactivate THEMSELVES when the tenant
/// retains another active admin (the count is tenant-wide, not actor-
/// relative). The route's `user_deactivated` audit row is untouched, and a
/// second deactivate of the now-inactive user is an idempotent no-op.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn self_deactivation_allowed_with_a_second_admin() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);
    // A second ACTIVE admin so the self-deactivation is not the
    // last-admin case.
    insert_user(
        &fx.pool,
        fx.tenant_id,
        Uuid::new_v4(),
        "admin-two",
        Role::Admin,
    )
    .await;

    let res = post_json(
        &fx,
        &format!("/api/v1/users/{}/deactivate", fx.admin_id),
        Some(&token),
        json!({}),
    )
    .await;
    let status = res.status();
    let after = sqlx::query_scalar::<_, bool>("SELECT is_active FROM users WHERE id = $1")
        .bind(fx.admin_id)
        .fetch_one(&fx.pool)
        .await
        .expect("read the admin row after self-deactivation");
    let audits = audit_rows(&fx).await;

    fx.cleanup().await;

    assert_eq!(status, StatusCode::NO_CONTENT, "the self-deactivation");
    assert!(!after, "is_active flips to FALSE");
    let actions: Vec<&str> = audits.iter().map(|(action, ..)| action.as_str()).collect();
    assert_eq!(
        actions,
        vec!["user_deactivated"],
        "exactly one audit row: {audits:?}"
    );
}

/// The last-admin guard applies to the self-deactivation too: with NO
/// second active admin, the actor deactivating their own account is
/// refused 409 with the exact PATCH-route message, the row is unchanged,
/// and no audit rows are written.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn self_deactivation_still_refused_as_last_admin() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);

    let res = post_json(
        &fx,
        &format!("/api/v1/users/{}/deactivate", fx.admin_id),
        Some(&token),
        json!({}),
    )
    .await;
    let status = res.status();
    let raw = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&raw).unwrap();
    let row: (String, bool) = sqlx::query_as("SELECT role, is_active FROM users WHERE id = $1")
        .bind(fx.admin_id)
        .fetch_one(&fx.pool)
        .await
        .expect("read the admin row");
    let audits = audit_rows(&fx).await;

    fx.cleanup().await;

    assert_eq!(status, StatusCode::CONFLICT, "the last-admin refusal");
    assert_eq!(error_code(&body), "conflict");
    assert_eq!(
        body["error"]["message"].as_str().unwrap(),
        "refusing to remove the last active administrator"
    );
    assert_eq!(row, ("admin".to_string(), true), "the row is unchanged");
    assert!(
        audits.is_empty(),
        "no audit rows on the refusal: {audits:?}"
    );
}

/// The deactivate route keeps its tenant scoping: another tenant's user
/// (and an absent one) is a 404, indistinguishably.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn deactivate_unknown_and_foreign_ids_are_404() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);
    let unknown_status = post_json(
        &fx,
        &format!("/api/v1/users/{}/deactivate", Uuid::new_v4()),
        Some(&token),
        json!({}),
    )
    .await
    .status();

    let foreign_name = "rt-api-foreign-deactivate-user";
    sqlx::query(
        "DELETE FROM audit_log WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
    )
    .bind(foreign_name)
    .execute(&fx.pool)
    .await
    .expect("sweep stale foreign-user audit rows");
    sqlx::query(
        "DELETE FROM users WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1)",
    )
    .bind(foreign_name)
    .execute(&fx.pool)
    .await
    .expect("sweep stale foreign-user rows");
    sqlx::query("DELETE FROM tenants WHERE name = $1")
        .bind(foreign_name)
        .execute(&fx.pool)
        .await
        .expect("sweep stale foreign-user tenant");
    let foreign_tenant = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
        .bind(foreign_tenant)
        .bind(foreign_name)
        .execute(&fx.pool)
        .await
        .expect("insert the foreign-user tenant");
    fx.extra_tenants.lock().unwrap().push(foreign_tenant);
    let foreign_user = Uuid::new_v4();
    insert_user(
        &fx.pool,
        foreign_tenant,
        foreign_user,
        "foreign-deactivate-user",
        Role::Viewer,
    )
    .await;
    let foreign_status = post_json(
        &fx,
        &format!("/api/v1/users/{foreign_user}/deactivate"),
        Some(&token),
        json!({}),
    )
    .await
    .status();

    fx.cleanup().await;

    assert_eq!(unknown_status, StatusCode::NOT_FOUND, "an unknown id");
    assert_eq!(foreign_status, StatusCode::NOT_FOUND, "a foreign tenant id");
}

// ---------------------------------------------------------------------------
// The ACME UI-facing REST routes (Plan 4 Task 10)
// ---------------------------------------------------------------------------

/// Read a JSON response body as a serde_json `Value`.
async fn json_body(res: TestResponse, cap: usize) -> Value {
    let bytes = axum::body::to_bytes(res.into_body(), cap).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Seed one `acme_accounts` row directly through the Task-2 repo (no JWS
/// machinery needed — the REST projection reads the SAME rows).
async fn seed_acme_account(
    fx: &Fixture,
    thumbprint: &str,
    status: AcmeAccountStatus,
) -> AcmeAccountModel {
    let account = AcmeAccountModel {
        id: Uuid::new_v4(),
        tenant_id: fx.tenant_id,
        jwk_thumbprint: thumbprint.to_string(),
        jwk: json!({"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}),
        status,
        tos_agreed_at: None,
        contact: Some(format!("mailto:{thumbprint}@wardstone.test")),
        created_at: Utc::now(),
    };
    AcmeRepo::new()
        .insert_account(&fx.pool, &account)
        .await
        .expect("seed the acme account");
    account
}

/// Seed one `acme_orders` row for `account_id` (`certificate_id` stays
/// `None` at the route-test level: the column is a real foreign key and
/// the repo-level suite covers the certificate-keyed lookup).
async fn seed_acme_order(
    fx: &Fixture,
    account_id: Uuid,
    status: AcmeOrderStatus,
) -> AcmeOrderModel {
    let order = AcmeOrderModel {
        id: Uuid::new_v4(),
        tenant_id: fx.tenant_id,
        account_id,
        status,
        profile_name: "web-server".to_string(),
        identifiers: json!([{"type": "dns", "value": "host.wardstone.test"}]),
        csr_pem: None,
        not_before: None,
        not_after: None,
        certificate_id: None,
        error: None,
        expires_at: Utc::now() + Duration::days(7),
        created_at: Utc::now(),
    };
    AcmeRepo::new()
        .insert_order(&fx.pool, &order)
        .await
        .expect("seed the acme order");
    order
}

/// The REST projection's reads: the list carries `orders_count` per
/// account, the detail serves the account plus its recent orders, and the
/// orders route scopes to exactly one of `account_id` / `certificate_id`
/// (neither is a 400; a miss answers an EMPTY list). Unknown accounts are
/// one indistinguishable 404.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn ui_acme_rest_lists_accounts_orders_and_details() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);

    let account = seed_acme_account(&fx, "ui-acme-thumb-a", AcmeAccountStatus::Valid).await;
    let other = seed_acme_account(&fx, "ui-acme-thumb-b", AcmeAccountStatus::Deactivated).await;
    seed_acme_order(&fx, account.id, AcmeOrderStatus::Pending).await;
    seed_acme_order(&fx, account.id, AcmeOrderStatus::Valid).await;

    let list_status = get_bearer(&fx, "/api/v1/acme/accounts", &token)
        .await
        .status();
    let list = json_body(
        get_bearer(&fx, "/api/v1/acme/accounts", &token).await,
        1 << 20,
    )
    .await;
    let detail_status = get_bearer(
        &fx,
        &format!("/api/v1/acme/accounts/{}", account.id),
        &token,
    )
    .await
    .status();
    let detail = json_body(
        get_bearer(
            &fx,
            &format!("/api/v1/acme/accounts/{}", account.id),
            &token,
        )
        .await,
        1 << 20,
    )
    .await;
    let unknown = Uuid::new_v4();
    let unknown_detail = get_bearer(&fx, &format!("/api/v1/acme/accounts/{unknown}"), &token).await;
    let unknown_detail_status = unknown_detail.status();
    let unknown_detail_code = error_code(&json_body(unknown_detail, 1 << 20).await);
    let orders_by_account = json_body(
        get_bearer(
            &fx,
            &format!("/api/v1/acme/orders?account_id={}", account.id),
            &token,
        )
        .await,
        1 << 20,
    )
    .await;
    let orders_of_other = json_body(
        get_bearer(
            &fx,
            &format!("/api/v1/acme/orders?account_id={}", other.id),
            &token,
        )
        .await,
        1 << 20,
    )
    .await;
    let orders_by_unknown_certificate = json_body(
        get_bearer(
            &fx,
            &format!("/api/v1/acme/orders?certificate_id={}", Uuid::new_v4()),
            &token,
        )
        .await,
        1 << 20,
    )
    .await;
    let unscoped = get_bearer(&fx, "/api/v1/acme/orders", &token).await;
    let orders_unscoped_status = unscoped.status();
    let orders_unscoped_code = error_code(&json_body(unscoped, 1 << 20).await);

    fx.cleanup().await;

    assert_eq!(list_status, StatusCode::OK);
    let rows = list.as_array().expect("a JSON array");
    assert_eq!(rows.len(), 2);
    let listed: Vec<&Value> = rows
        .iter()
        .filter(|row| row["id"] == account.id.to_string())
        .collect();
    let other_row: Vec<&Value> = rows
        .iter()
        .filter(|row| row["id"] == other.id.to_string())
        .collect();
    assert_eq!(listed.len(), 1);
    assert_eq!(other_row.len(), 1);
    assert_eq!(listed[0]["orders_count"], 2, "both seeded orders count");
    assert_eq!(other_row[0]["orders_count"], 0);
    assert_eq!(listed[0]["jwk_thumbprint"], "ui-acme-thumb-a");
    assert_eq!(listed[0]["status"], "valid");
    assert_eq!(other_row[0]["status"], "deactivated");
    assert!(listed[0]["contact"].is_string());

    assert_eq!(detail_status, StatusCode::OK);
    assert_eq!(detail["id"], account.id.to_string());
    assert_eq!(detail["status"], "valid");
    assert_eq!(
        detail["orders"].as_array().expect("orders array").len(),
        2,
        "the detail serves the account's recent orders"
    );
    let first_order = &detail["orders"][0];
    assert_eq!(first_order["profile_name"], "web-server");
    assert_eq!(first_order["account_id"], account.id.to_string());
    assert!(first_order["identifiers"].as_array().is_some());
    assert!(first_order["certificate_id"].is_null());

    assert_eq!(unknown_detail_status, StatusCode::NOT_FOUND);
    assert_eq!(unknown_detail_code, "not_found");

    assert_eq!(
        orders_by_account.as_array().expect("a JSON array").len(),
        2,
        "the account's orders page through the same rows"
    );
    assert_eq!(
        orders_of_other.as_array().expect("a JSON array").len(),
        0,
        "an account without orders lists empty, never an error"
    );
    assert_eq!(
        orders_by_unknown_certificate
            .as_array()
            .expect("a JSON array")
            .len(),
        0,
        "a certificate with no order answers an empty list"
    );
    assert_eq!(orders_unscoped_status, StatusCode::BAD_REQUEST);
    assert_eq!(orders_unscoped_code, "bad_request");
}

/// The REST deactivation drives the SAME cascade the JWS machine path
/// runs — pending authorizations invalidated, open orders stamped invalid
/// — commits the audit row with the CALLING USER as the actor (a human
/// acted), and is idempotent: a repeat answers 0/0 and writes no second
/// audit row.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn ui_acme_rest_deactivate_cascades_and_audits_the_calling_user() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let token = admin_token(&fx);

    let account = seed_acme_account(&fx, "ui-acme-thumb-c", AcmeAccountStatus::Valid).await;
    let order = seed_acme_order(&fx, account.id, AcmeOrderStatus::Pending).await;
    let now = Utc::now();
    let pending_authz = AcmeAuthorizationModel {
        id: Uuid::new_v4(),
        tenant_id: fx.tenant_id,
        account_id: account.id,
        identifier: "pending.wardstone.test".to_string(),
        status: AcmeAuthorizationStatus::Pending,
        expires_at: now + Duration::days(7),
        reused_from: None,
        order_id: Some(order.id),
        created_at: now,
    };
    AcmeRepo::new()
        .insert_authorization(&fx.pool, &pending_authz)
        .await
        .expect("seed the pending authorization");
    let valid_authz = AcmeAuthorizationModel {
        id: Uuid::new_v4(),
        tenant_id: fx.tenant_id,
        account_id: account.id,
        identifier: "valid.wardstone.test".to_string(),
        status: AcmeAuthorizationStatus::Valid,
        expires_at: now + Duration::days(30),
        reused_from: None,
        order_id: None,
        created_at: now,
    };
    AcmeRepo::new()
        .insert_authorization(&fx.pool, &valid_authz)
        .await
        .expect("seed the valid authorization");

    let first_response = post_json(
        &fx,
        &format!("/api/v1/acme/accounts/{}/deactivate", account.id),
        Some(&token),
        json!({}),
    )
    .await;
    let first_status = first_response.status();
    let first = json_body(first_response, 1 << 20).await;
    let repeat = json_body(
        post_json(
            &fx,
            &format!("/api/v1/acme/accounts/{}/deactivate", account.id),
            Some(&token),
            json!({}),
        )
        .await,
        1 << 20,
    )
    .await;

    // Readback through the repos BEFORE the fixture's self-clean.
    let account_after = AcmeRepo::new()
        .get_account_by_id(&fx.pool, fx.tenant_id, account.id)
        .await
        .expect("read the deactivated account")
        .expect("the account row survives deactivation");
    let pending_after = AcmeRepo::new()
        .get_authorization(&fx.pool, fx.tenant_id, pending_authz.id)
        .await
        .expect("read the pending authorization")
        .expect("row present");
    let valid_after = AcmeRepo::new()
        .get_authorization(&fx.pool, fx.tenant_id, valid_authz.id)
        .await
        .expect("read the valid authorization")
        .expect("row present");
    let order_after = AcmeRepo::new()
        .get_order(&fx.pool, fx.tenant_id, order.id)
        .await
        .expect("read the open order")
        .expect("row present");
    let audit = audit_rows(&fx).await;

    fx.cleanup().await;

    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(first["status"], "deactivated");
    assert_eq!(first["authorizations_invalidated"], 1);
    assert_eq!(first["orders_invalidated"], 1);
    assert_eq!(repeat["authorizations_invalidated"], 0, "idempotent");
    assert_eq!(repeat["orders_invalidated"], 0);

    assert_eq!(account_after.status, AcmeAccountStatus::Deactivated);
    assert_eq!(pending_after.status, AcmeAuthorizationStatus::Deactivated);
    assert_eq!(valid_after.status, AcmeAuthorizationStatus::Valid);
    assert_eq!(order_after.status, AcmeOrderStatus::Invalid);
    assert_eq!(order_after.error.as_deref(), Some("account deactivated"));

    let rows: Vec<_> = audit
        .iter()
        .filter(|(action, ..)| action == "acme_account_deactivated")
        .collect();
    assert_eq!(rows.len(), 1, "exactly one audit row across both POSTs");
    let (action, actor_type, auth_method, details) = rows[0];
    assert_eq!(action, "acme_account_deactivated");
    assert_eq!(actor_type, "user", "the CALLING USER is the actor");
    assert_eq!(auth_method, "session");
    assert_eq!(details["jwk_thumbprint"], "ui-acme-thumb-c");
    assert_eq!(details["surface"], "rest");
    assert_eq!(details["authorizations_invalidated"], 1);
    assert_eq!(details["orders_invalidated"], 1);
}

/// The capability split the REST projection gates on: `read_acme` alone
/// reads both lists and is 403 on the deactivation; a no-grant token is
/// 403 everywhere; an admin (both capabilities) gets a 404 on an unknown
/// account's deactivation — authorization first, indistinguishable 404
/// last.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn ui_acme_rest_capability_gates_and_unknown_404s() {
    let _db = lock_db().await;
    let mut fx = fixture().await;
    let admin = admin_token(&fx);
    let readonly = api_token(&fx, &[Capability::ReadAcme]).await;
    let nogrant = api_token(&fx, &[]).await;
    let unknown = Uuid::new_v4();

    let readonly_list = get_bearer(&fx, "/api/v1/acme/accounts", &readonly)
        .await
        .status();
    let readonly_orders = get_bearer(
        &fx,
        &format!("/api/v1/acme/orders?account_id={}", Uuid::new_v4()),
        &readonly,
    )
    .await
    .status();
    let readonly_deactivate = post_json(
        &fx,
        &format!("/api/v1/acme/accounts/{unknown}/deactivate"),
        Some(&readonly),
        json!({}),
    )
    .await;
    let readonly_deactivate_status = readonly_deactivate.status();
    let readonly_deactivate_code = error_code(&json_body(readonly_deactivate, 1 << 20).await);
    let nogrant_list = get_bearer(&fx, "/api/v1/acme/accounts", &nogrant)
        .await
        .status();
    let nogrant_detail = get_bearer(&fx, &format!("/api/v1/acme/accounts/{unknown}"), &nogrant)
        .await
        .status();
    let nogrant_deactivate = post_json(
        &fx,
        &format!("/api/v1/acme/accounts/{unknown}/deactivate"),
        Some(&nogrant),
        json!({}),
    )
    .await
    .status();
    let admin_unknown = post_json(
        &fx,
        &format!("/api/v1/acme/accounts/{unknown}/deactivate"),
        Some(&admin),
        json!({}),
    )
    .await;
    let admin_unknown_status = admin_unknown.status();
    let admin_unknown_code = error_code(&json_body(admin_unknown, 1 << 20).await);

    fx.cleanup().await;

    assert_eq!(readonly_list, StatusCode::OK);
    assert_eq!(readonly_orders, StatusCode::OK);
    assert_eq!(readonly_deactivate_status, StatusCode::FORBIDDEN);
    assert_eq!(readonly_deactivate_code, "forbidden");
    assert_eq!(nogrant_list, StatusCode::FORBIDDEN);
    assert_eq!(nogrant_detail, StatusCode::FORBIDDEN);
    assert_eq!(nogrant_deactivate, StatusCode::FORBIDDEN);
    assert_eq!(admin_unknown_status, StatusCode::NOT_FOUND);
    assert_eq!(admin_unknown_code, "not_found");
}

// --- Task 4b: the master-passphrase change route ---

/// The four standard envelopes, one home for the change tests' opens.
const SEALED_VOLUME_FILES: [&str; 4] = [
    ws_core::crypto::MASTER_ENVELOPE_FILE,
    ws_core::crypto::SECRET_ENVELOPE_FILE,
    ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE,
    ws_core::crypto::JWT_ENVELOPE_FILE,
];

#[tokio::test]
async fn master_key_change_rewraps_the_volume_and_audits() {
    let mut fx = sealed_fixture().await;
    let token = api_token(&fx, &[Capability::ManageSystem]).await;

    let res = post_json(
        &fx,
        "/api/v1/master-key",
        Some(&token),
        json!({
            "current": "the-current-master-passphrase",
            "next": "the-next-master-passphrase",
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "the change succeeds");
    let body = json_body(res, 4096).await;
    assert_eq!(
        body["generation"], 1,
        "the response names the new generation"
    );

    // Every envelope now opens under the NEXT passphrase only, at the
    // advanced generation — the change re-wraps the whole volume or
    // nothing.
    for file in SEALED_VOLUME_FILES {
        let opened = ws_core::crypto::KeyEnvelope::open_envelope(
            &fx.keys_dir.join(file),
            "the-next-master-passphrase",
        )
        .unwrap_or_else(|e| panic!("the next passphrase opens {file}: {e}"));
        assert_eq!(
            ws_core::crypto::KeyEnvelope::read_generation(&fx.keys_dir.join(file)).unwrap(),
            1,
            "{file} advanced to generation 1"
        );
        let err = ws_core::crypto::KeyEnvelope::open_envelope(
            &fx.keys_dir.join(file),
            "the-current-master-passphrase",
        )
        .unwrap_err();
        assert!(
            matches!(err, ws_core::error::CoreError::Crypto(_)),
            "the retired passphrase no longer opens {file}"
        );
        let _ = opened;
    }
    // The retired passphrase no longer opens the JWT pair's SEALED form
    // either — the envelope above is the pair's only home.
    let jwt_err = ws_auth::jwt::load_sealed(
        &fx.keys_dir.join(ws_core::crypto::JWT_ENVELOPE_FILE),
        "the-current-master-passphrase".as_bytes(),
    )
    .unwrap_err();
    assert!(
        jwt_err.to_string().contains("crypto"),
        "the retired passphrase refuses the JWT envelope: {jwt_err}"
    );

    // The audit row: one `master_key_changed` under the acting tenant,
    // carrying the generation and NO passphrase material.
    let (count, details): (i64, serde_json::Value) =
        sqlx::query_as("SELECT count(*), details FROM audit_log WHERE tenant_id = $1 AND action = 'master_key_changed' GROUP BY details")
            .bind(fx.tenant_id)
            .fetch_one(&fx.pool)
            .await
            .expect("the change wrote its audit row");
    assert_eq!(count, 1, "exactly one master_key_changed row");
    assert_eq!(details["generation"], 1, "the row carries the generation");
    assert!(
        !details.to_string().contains("passphrase"),
        "the audit row carries no passphrase material: {details}"
    );

    fx.cleanup().await;
}

#[tokio::test]
async fn master_key_change_refuses_a_wrong_current_and_touches_nothing() {
    let mut fx = sealed_fixture().await;
    let token = api_token(&fx, &[Capability::ManageSystem]).await;

    let res = post_json(
        &fx,
        "/api/v1/master-key",
        Some(&token),
        json!({
            "current": "a-wrong-current-passphrase",
            "next": "the-next-master-passphrase",
        }),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "a wrong current is a typed 400"
    );
    let body = json_body(res, 4096).await;
    assert_eq!(
        body["error"]["code"], "wrong_passphrase",
        "the failure's machine code names the passphrase, nothing else: {body}"
    );

    for file in SEALED_VOLUME_FILES {
        ws_core::crypto::KeyEnvelope::open_envelope(
            &fx.keys_dir.join(file),
            "the-current-master-passphrase",
        )
        .unwrap_or_else(|e| panic!("a refused change leaves {file} untouched: {e}"));
        assert_eq!(
            ws_core::crypto::KeyEnvelope::read_generation(&fx.keys_dir.join(file)).unwrap(),
            0,
            "a refused change advances nothing in {file}"
        );
    }
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM audit_log WHERE tenant_id = $1 AND action = 'master_key_changed'",
    )
    .bind(fx.tenant_id)
    .fetch_optional(&fx.pool)
    .await
    .unwrap();
    assert!(row.is_none(), "a refused change writes no audit row");

    fx.cleanup().await;
}

/// `me` names the sealed volume (Task 4b): the SPA gates its admin
/// change-form entry on the flag, so the unlocked state — the state
/// the sealed instance's unlock built — carries it, and the legacy
/// file-read state does not.
#[tokio::test]
async fn me_names_the_sealed_volume_for_the_spa() {
    let mut fx = sealed_fixture().await;
    let token = api_token(&fx, &[Capability::ManageSystem]).await;

    let res = get_bearer(&fx, "/api/v1/auth/me", &token).await;
    assert_eq!(res.status(), StatusCode::OK);
    let me = json_body(res, 4096).await;
    assert_eq!(
        me["sealed_volume"], true,
        "the unlocked state carries the sealed-volume flag, got: {me}"
    );

    fx.cleanup().await;
}
