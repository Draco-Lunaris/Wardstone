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

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex as TokioMutex;
use tower::ServiceExt;
use uuid::Uuid;
use x509_parser::pem::parse_x509_pem;

use ws_api::state::{ApiConfig, AppState};
use ws_web::setup::{self, SetupFields, SetupState};

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

impl Fixture {
    /// Delete every row this test created (under the setup tenant's
    /// name), release the advisory lock, and remove the keys directory.
    async fn cleanup(&mut self) {
        sweep_tenant(&self.pool, setup::DEFAULT_TENANT_NAME).await;
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

/// The end-to-end scenario, in this exact order (see the module docs).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn setup_login_issue_revoke_and_service_identity_work_end_to_end() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;

    // -- 1. First-run setup through the real setup route --------------------
    let setup_router = setup::setup_router(SetupState {
        pool: fixture.pool.clone(),
        keys_dir: fixture.keys_dir.clone(),
        fingerprint: PAGE_FINGERPRINT.to_string(),
        hostname: HOSTNAME.to_string(),
    });
    let fields = SetupFields {
        admin_username: "admin".to_string(),
        admin_password: ADMIN_PASSWORD.to_string(),
        default_domain: DOMAIN.to_string(),
        admin_cidrs: vec!["10.0.0.0/8".to_string()],
        server_hostname: HOSTNAME.to_string(),
    };
    let response = post_json(
        &setup_router,
        "/setup",
        None,
        serde_json::to_value(&fields).expect("the setup fields must serialize"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "the setup POST succeeds");
    let setup_body = body_json(response).await;
    assert_eq!(
        setup_body["status"], "ok",
        "the setup submit reports success"
    );
    assert_eq!(
        setup_body["restart"], true,
        "the setup submit carries the restart contract (the ui process exits so \
         compose brings it back on the CA-issued leaf)"
    );

    // -- 2. The API router over the SAME pool and keys directory ------------
    // The setup flow created the secret-encryption key file and the
    // keystore; the API process loads (here: generates — setup does not
    // touch the JWT pair) the Ed25519 JWT keys from the same directory.
    let jwt = ws_auth::jwt::JwtKeys::load_or_create(&fixture.keys_dir)
        .expect("load or create the JWT key pair in the setup keys dir");
    let config = ApiConfig::new(DOMAIN.to_string(), fixture.keys_dir.clone());
    let state = AppState::new(fixture.pool.clone(), Arc::new(jwt), config);
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
        "http://127.0.0.1:9", // intentionally nothing listens here
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

/// The front-door POST /setup's status (the GET was driven separately
/// above); captured before cleanup, asserted after it.
async fn post_setup_status(front: &Router, fields: &SetupFields) -> StatusCode {
    let payload: Value = serde_json::to_value(fields).expect("the setup fields must serialize");
    post_json(front, "/setup", None, payload).await.status()
}
