//! Integration tests for `ws_auth::service_identity` (API tokens for
//! scripted automation) and `ws_auth::refresh` (session refresh tokens).
//!
//! These tests run against a live Postgres and are marked `#[ignore]`.
//! Run them with:
//!
//! ```sh
//! DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test \
//!     cargo test -p ws-auth -- --include-ignored
//! ```
//!
//! # Self-cleaning contract
//!
//! The shared `wardstone_test` database is also used by
//! `crates/ws-core/tests/db_test.rs`, whose `connect_runs_migrations`
//! asserts that `tenants` is empty. To keep that true after every run of
//! this suite, no matter how it exits:
//!
//! 1. Every test starts by sweeping away rows a previously crashed run of
//!    this suite may have left behind (this suite's owned tenant names
//!    only: service identities first, refresh tokens next, then the users
//!    (whose delete cascades both token tables' leftovers), tenant last).
//! 2. Every row inserted during the body is deleted in the same FK order —
//!    *before* any assertion runs, so a failing assertion cannot leave rows
//!    behind. All query results are captured and unwrapped only after
//!    cleanup.
//!
//! # Cross-process serialization
//!
//! Each test body holds the session-level Postgres advisory lock
//! [`ADVISORY_KEY`] for its whole duration (on a dedicated pooled
//! connection), so any other process using the same key serializes against
//! it; the in-process [`DB_TEST_LOCK`] mutex mirrors `repo_test.rs`'s
//! pattern and serializes this binary's tests against each other. The key
//! is the same `0x0057_4144_5354` (`"WARDST"`) family with this suite's
//! marker `0x000d`, disjoint from every other suite's key.

use std::net::IpAddr;
use std::sync::OnceLock;

use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex;
use uuid::Uuid;

use ws_auth::refresh;
use ws_auth::service_identity;
use ws_core::db::connect;
use ws_core::models::credential::{RefreshTokenModel, ServiceIdentityModel};
use ws_core::models::rbac::{role_capabilities, Actor, ActorType, AuthMethod, Capability, Role};
use ws_core::models::user::UserModel;
use ws_core::repo::credential_repo::CredentialRepo;
use ws_core::repo::refresh_repo::RefreshTokenRepo;
use ws_core::repo::tenant_repo::TenantRepo;
use ws_core::repo::user_repo::UserRepo;

/// Postgres advisory-lock key for this suite: ASCII "WARDST" (0x5741445354)
/// plus this suite's marker 0x000d, i.e. `0x0057_4144_5354_000d`. Processes
/// taking this key serialize their test bodies against this suite.
const ADVISORY_KEY: i64 = 0x0057_4144_5354_000d;

/// Tenant name this suite owns for the service-identity tests; deleted
/// before asserts (identities first, users next, tenant last).
const SI_TENANT: &str = "rt-si-tenant";

/// The admin username this suite owns under [`SI_TENANT`].
const SI_USER: &str = "rt-si-admin";

/// Tenant name this suite owns for the refresh-token tests, disjoint from
/// [`SI_TENANT`]; deleted before asserts, same FK order.
const REFRESH_TENANT: &str = "rt-si-refresh-tenant";

/// The username this suite owns under [`REFRESH_TENANT`].
const REFRESH_USER: &str = "rt-si-refresh-admin";

/// In-process serialization, the same whole-body lock pattern as
/// `ws-core`'s `repo_test.rs`: the harness runs tests on separate threads,
/// and the guard is held across `.await` points, so a tokio mutex.
static DB_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// The guard must be held (not dropped) until the test body finishes.
#[must_use = "the database lock must stay bound for the whole test body"]
async fn lock_db() -> tokio::sync::MutexGuard<'static, ()> {
    DB_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().await
}

/// Take the session-level advisory lock `key` on a dedicated pooled
/// connection. The connection stays checked out for the whole test body
/// (the caller holds the guard), so the lock is bound to it; it is released
/// by [`release_advisory`] or, on a panic path, when the pool is dropped
/// during unwinding.
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

/// Release the advisory lock taken by [`lock_advisory`] explicitly, so the
/// connection never returns to the pool while still holding it.
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

/// The SHA-256 verifier hash of a token's raw bytes: `hex(Sha256(raw))` —
/// exactly what storage must hold, and nothing else.
fn expected_hash(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}

/// The raw bytes a presented `ws_at_`/`ws_rt_` plaintext carries: the
/// prefix, then the hex form of the 32 random bytes (the house's encoding).
fn raw_of(plaintext: &str) -> Vec<u8> {
    let body = plaintext
        .strip_prefix("ws_at_")
        .or_else(|| plaintext.strip_prefix("ws_rt_"))
        .unwrap_or(plaintext);
    hex::decode(body).expect("test token body is hex")
}

/// Delete this suite's rows owned by `tenant_name`, FK order: service
/// identities (their capability rows cascade), refresh tokens, users (a
/// belt-and-suspenders second token sweep), tenant last.
async fn sweep(pool: &PgPool, tenant_name: &str) {
    sqlx::query(
        "DELETE FROM service_identities \
         WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
    )
    .bind(tenant_name)
    .execute(pool)
    .await
    .expect("sweep service_identities rows");
    sqlx::query(
        "DELETE FROM refresh_tokens \
         WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
    )
    .bind(tenant_name)
    .execute(pool)
    .await
    .expect("sweep refresh_tokens rows");
    sqlx::query(
        "DELETE FROM users \
         WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
    )
    .bind(tenant_name)
    .execute(pool)
    .await
    .expect("sweep users rows");
    sqlx::query("DELETE FROM tenants WHERE name = $1")
        .bind(tenant_name)
        .execute(pool)
        .await
        .expect("sweep tenant row");
}

/// A fresh tenant plus one local-user admin account under it, swept and
/// seeded for a test body. Returns `(tenant_id, user_id)`.
async fn seed_tenant_and_user(pool: &PgPool, tenant_name: &str, username: &str) -> (Uuid, Uuid) {
    let tenant = TenantRepo::new()
        .insert(pool, tenant_name)
        .await
        .expect("seed test tenant");
    let user = user_model(tenant.id, username);
    UserRepo::new()
        .insert(pool, &user)
        .await
        .expect("seed test user");
    (tenant.id, user.id)
}

/// The UserModel rows this suite seeds: a plain local admin account.
fn user_model(tenant_id: Uuid, username: &str) -> UserModel {
    let now = Utc::now();
    UserModel {
        id: Uuid::new_v4(),
        tenant_id,
        username: username.to_string(),
        display_name: username.to_string(),
        email: format!("{username}@wardstone.test"),
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
        created_at: now,
        updated_at: now,
    }
}

/// The human Actor that mints identities in these tests: an admin (the
/// `actor_id` is the user id, as the JWT middleware resolves it).
fn admin_actor(user_id: Uuid, tenant_id: Uuid) -> Actor {
    Actor {
        actor_type: ActorType::User,
        actor_id: user_id.to_string(),
        auth_method: AuthMethod::Session,
        capabilities: role_capabilities(Role::Admin).to_vec(),
        session_id: Some(Uuid::new_v4()),
        tenant_id,
        minted_by: None,
    }
}

/// The human Actor for the over-privilege test: a Viewer, whose bundle is
/// read-only.
fn viewer_actor(user_id: Uuid, tenant_id: Uuid) -> Actor {
    Actor {
        actor_type: ActorType::User,
        actor_id: user_id.to_string(),
        auth_method: AuthMethod::Session,
        capabilities: role_capabilities(Role::Viewer).to_vec(),
        session_id: Some(Uuid::new_v4()),
        tenant_id,
        minted_by: None,
    }
}

/// The token plaintext of an in-flight result, for calls that must run
/// before cleanup: when the mint failed the empty plaintext simply looks up
/// as `None` (captured, unwrapped post-cleanup), and the mint error itself
/// keeps working on the original `Result`.
fn si_token(
    created: &Result<service_identity::ServiceIdentity, ws_auth::error::AuthError>,
) -> String {
    created
        .as_ref()
        .ok()
        .map(|s| s.token.clone())
        .unwrap_or_default()
}

/// Same as [`si_token`], for a refresh token.
fn rt_token(issued: &Result<refresh::RefreshToken, ws_auth::error::AuthError>) -> String {
    issued
        .as_ref()
        .ok()
        .map(|rt| rt.token.clone())
        .unwrap_or_default()
}

/// Minting a service identity stores ONLY the SHA-256 hash of the token's
/// raw bytes — never the plaintext or its hex form — and the returned
/// plaintext carries the `ws_at_` prefix followed by 32 bytes of hex, with
/// the stored row's name/description/creator matching the request.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn created_service_identity_stores_verifier_hash_and_roundtrips() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;
    sweep(&pool, SI_TENANT).await;

    let (tenant_id, user_id) = seed_tenant_and_user(&pool, SI_TENANT, SI_USER).await;
    let creator = admin_actor(user_id, tenant_id);
    let requested = [Capability::Issue, Capability::ReadCertificates];
    let repo = CredentialRepo::new();

    let created = service_identity::create_service_identity(
        &pool,
        "ci-worker",
        Some("CI automation"),
        &requested,
        &creator,
        &repo,
    )
    .await;
    // The verifier-hash lookup is exercised through authenticate_token
    // (the created row must be reachable by exactly sha256(raw)).
    let hash_lookup = service_identity::authenticate_token(&si_token(&created), &pool, &repo).await;
    let listed = repo.list_service_identities(&pool, tenant_id, 0, 100).await;

    // Cleanup BEFORE asserting: this tenant's rows in FK order.
    sweep(&pool, SI_TENANT).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    let created = created.expect("create_service_identity succeeds");
    let token = created.token;
    assert!(
        token.starts_with("ws_at_"),
        "token should carry the ws_at_ prefix"
    );
    let hex_body = token.strip_prefix("ws_at_").expect("prefix present");
    let raw = hex::decode(hex_body).expect("token body is hex");
    assert_eq!(raw.len(), 32, "token is 32 random bytes, hex-encoded");
    assert!(
        !token.contains(&expected_hash(&raw)),
        "the plaintext never carries its own verifier hash"
    );

    // The created row authenticates through its verifier hash — exactly
    // sha256(raw) — resolving the identity's stored capabilities.
    let actor = hash_lookup
        .expect("authenticate_token succeeds")
        .expect("identity stored under sha256(raw_bytes)");
    assert_eq!(actor.actor_id, created.id.to_string());
    assert_eq!(actor.tenant_id, tenant_id);
    assert_eq!(actor.capabilities, requested.to_vec());
    assert_eq!(created.capabilities, requested.to_vec());

    let listed = listed.expect("list succeeds");
    assert_eq!(listed.len(), 1, "exactly one identity was created");
    assert_eq!(listed[0].token_hash, expected_hash(&raw));
    assert_ne!(listed[0].token_hash, token);
    assert_ne!(listed[0].token_hash, hex_body);
    assert_eq!(listed[0].tenant_id, tenant_id);
    assert_eq!(listed[0].name, "ci-worker");
    assert_eq!(listed[0].description.as_deref(), Some("CI automation"));
    assert_eq!(listed[0].created_by, Some(user_id));
    assert!(listed[0].revoked_at.is_none());
    assert_eq!(created.id, listed[0].id);
    assert_eq!(created.created_at, listed[0].created_at);
    assert_eq!(created.expires_at, listed[0].expires_at);
}

/// `authenticate_token` with the right plaintext resolves an Actor with the
/// identity's stored capabilities, `actor_type = ApiToken`, and the
/// identity's tenant; a wrong plaintext resolves `None`.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn authenticate_token_resolves_actor_with_stored_capabilities() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;
    sweep(&pool, SI_TENANT).await;

    let (tenant_id, user_id) = seed_tenant_and_user(&pool, SI_TENANT, SI_USER).await;
    let creator = admin_actor(user_id, tenant_id);
    let requested = [Capability::Issue, Capability::ReadServiceIdentities];

    let created = service_identity::create_service_identity(
        &pool,
        "actor-resolver",
        None,
        &requested,
        &creator,
        &CredentialRepo::new(),
    )
    .await;
    let good =
        service_identity::authenticate_token(&si_token(&created), &pool, &CredentialRepo::new())
            .await;
    let wrong = service_identity::authenticate_token(
        &format!("ws_at_{}", hex::encode([0x5au8; 32])),
        &pool,
        &CredentialRepo::new(),
    )
    .await;

    sweep(&pool, SI_TENANT).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    let created = created.expect("create_service_identity succeeds");
    let actor = good
        .expect("authenticate_token succeeds")
        .expect("the right token resolves an actor");
    assert_eq!(actor.actor_type, ActorType::ApiToken);
    assert_eq!(actor.auth_method, AuthMethod::ApiToken);
    assert_eq!(actor.actor_id, created.id.to_string());
    assert_eq!(actor.tenant_id, tenant_id);
    assert_eq!(actor.session_id, None);
    assert_eq!(actor.minted_by, None);
    assert_eq!(actor.capabilities, requested.to_vec());

    assert!(
        wrong.expect("wrong-token check succeeds").is_none(),
        "an unknown plaintext resolves no actor"
    );
}

/// A revoked identity's token no longer authenticates.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn authenticate_token_rejects_revoked_token() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;
    sweep(&pool, SI_TENANT).await;

    let (tenant_id, user_id) = seed_tenant_and_user(&pool, SI_TENANT, SI_USER).await;
    let creator = admin_actor(user_id, tenant_id);
    let repo = CredentialRepo::new();

    let created = service_identity::create_service_identity(
        &pool,
        "to-be-revoked",
        None,
        &[Capability::Issue],
        &creator,
        &repo,
    )
    .await;
    let token = si_token(&created);
    let before = service_identity::authenticate_token(&token, &pool, &repo).await;
    let revoked = match &created {
        Ok(c) => repo.revoke_service_identity(&pool, c.id).await,
        Err(_) => Err(ws_core::error::CoreError::Config(
            "no identity to revoke".to_string(),
        )),
    };
    let after = service_identity::authenticate_token(&token, &pool, &repo).await;

    sweep(&pool, SI_TENANT).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    assert!(
        before.expect("pre-revoke check succeeds").is_some(),
        "the token works before revocation"
    );
    revoked.expect("revoke succeeds");
    assert!(
        after.expect("post-revoke check succeeds").is_none(),
        "a revoked token resolves no actor"
    );
}

/// An expired identity's token no longer authenticates, and an
/// unknown-prefixed plaintext resolves `None` (no error).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn authenticate_token_rejects_expired_and_unknown_tokens() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;
    sweep(&pool, SI_TENANT).await;

    let (tenant_id, user_id) = seed_tenant_and_user(&pool, SI_TENANT, SI_USER).await;

    // Fabricate the expired identity directly (create_service_identity sets
    // no expiry): a known token_hash with expires_at in the past.
    let raw = [0x42u8; 32];
    let plaintext = format!("ws_at_{}", hex::encode(raw));
    let repo = CredentialRepo::new();
    let model = ServiceIdentityModel {
        id: Uuid::new_v4(),
        tenant_id,
        name: "expired-identity".to_string(),
        description: None,
        created_by: Some(user_id),
        token_hash: expected_hash(&raw),
        created_at: Utc::now() - Duration::hours(2),
        expires_at: Some(Utc::now() - Duration::hours(1)),
        revoked_at: None,
        last_used_at: None,
    };
    repo.insert_service_identity(&pool, &model)
        .await
        .expect("seed expired identity");

    let expired = service_identity::authenticate_token(&plaintext, &pool, &repo).await;
    let unknown = service_identity::authenticate_token(
        &format!("ws_at_{}", hex::encode([0x11u8; 32])),
        &pool,
        &repo,
    )
    .await;
    let wrong_prefix =
        service_identity::authenticate_token(&format!("ws_rt_{}", hex::encode(raw)), &pool, &repo)
            .await;

    sweep(&pool, SI_TENANT).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    assert!(
        expired.expect("expired-token check succeeds").is_none(),
        "an expired identity resolves no actor"
    );
    assert!(
        unknown.expect("unknown-token check succeeds").is_none(),
        "an unknown token resolves no actor"
    );
    assert!(
        wrong_prefix.expect("wrong-prefix check succeeds").is_none(),
        "an API-token plaintext must not match a refresh-prefixed lookup"
    );
}

/// The Review Focus item: a request naming a capability its creator lacks
/// is a typed error (`Forbidden`), and no identity row is created.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn api_token_capabilities_cannot_exceed_creator() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;
    sweep(&pool, SI_TENANT).await;

    let (tenant_id, user_id) = seed_tenant_and_user(&pool, SI_TENANT, SI_USER).await;
    // A Viewer holds no `issue` capability: requesting it must fail loudly.
    let creator = viewer_actor(user_id, tenant_id);
    assert!(!creator.can(Capability::Issue), "viewer holds no issue cap");

    let attempted = service_identity::create_service_identity(
        &pool,
        "over-privileged",
        None,
        &[Capability::Issue],
        &creator,
        &CredentialRepo::new(),
    )
    .await;
    let listed = CredentialRepo::new()
        .list_service_identities(&pool, tenant_id, 0, 100)
        .await;

    sweep(&pool, SI_TENANT).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    let attempted = match attempted {
        Err(err) => err,
        Ok(_) => panic!("minting above the creator's capabilities is an error"),
    };
    assert!(
        matches!(attempted, ws_auth::error::AuthError::Forbidden),
        "expected Forbidden, got {attempted:?}"
    );
    assert_eq!(
        listed.expect("list succeeds").len(),
        0,
        "no identity row is left behind by the refused mint"
    );
}

/// Issuing a refresh token stores only the verifier hash; the plaintext
/// carries the `ws_rt_` prefix and 32 bytes of hex; `authenticate_…`
/// resolves it for the owning user/tenant until it is revoked.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn refresh_issue_authenticate_and_revoke_roundtrip() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;
    sweep(&pool, REFRESH_TENANT).await;

    let (tenant_id, user_id) = seed_tenant_and_user(&pool, REFRESH_TENANT, REFRESH_USER).await;
    let repo = RefreshTokenRepo::new();

    let issued = refresh::issue_refresh_token(
        &pool,
        tenant_id,
        user_id,
        Some("wardstone-test/1.0"),
        Some("10.0.0.1".parse::<IpAddr>().expect("test ip")),
        &repo,
    )
    .await;
    let token = rt_token(&issued);
    let good = refresh::authenticate_refresh_token(&token, &pool, &repo).await;
    let stored = repo
        .get_by_hash(&pool, &expected_hash(&raw_of(&token)))
        .await;
    let revoke = refresh::revoke_refresh_token(&token, &pool, &repo).await;
    let after_revoke = refresh::authenticate_refresh_token(&token, &pool, &repo).await;

    sweep(&pool, REFRESH_TENANT).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    let issued = issued.expect("issue_refresh_token succeeds");
    assert!(
        issued.token.starts_with("ws_rt_"),
        "plaintext carries the ws_rt_ prefix"
    );
    let hex_body = issued.token.strip_prefix("ws_rt_").expect("prefix present");
    let raw = hex::decode(hex_body).expect("hex body");
    assert_eq!(raw.len(), 32, "token is 32 random bytes, hex-encoded");
    assert_eq!(issued.user_id, user_id);
    assert_eq!(issued.tenant_id, tenant_id);
    assert_eq!(issued.expires_at - issued.issued_at, Duration::hours(1));

    let live = good
        .expect("authenticate succeeds")
        .expect("token authenticates before revocation");
    assert_eq!(live.user_id, user_id);
    assert_eq!(live.tenant_id, tenant_id);

    let row = stored.expect("hash lookup succeeds").expect("row stored");
    assert_eq!(row.token_hash, expected_hash(&raw));
    assert_ne!(row.token_hash, issued.token);
    assert_ne!(row.token_hash, hex_body);
    assert!(!row.revoked);
    assert_eq!(row.user_agent.as_deref(), Some("wardstone-test/1.0"));
    assert_eq!(
        row.ip_address,
        Some("10.0.0.1".parse::<IpAddr>().expect("ip"))
    );

    revoke.expect("revoke succeeds");
    assert!(
        after_revoke.expect("post-revoke check succeeds").is_none(),
        "a revoked refresh token resolves nothing"
    );
}

/// Rotating a live refresh token retires it atomically: the old plaintext
/// stops authenticating, the replacement authenticates for the same user,
/// and both plaintexts differ.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn refresh_rotate_replaces_the_token_and_kills_its_predecessor() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;
    sweep(&pool, REFRESH_TENANT).await;

    let (tenant_id, user_id) = seed_tenant_and_user(&pool, REFRESH_TENANT, REFRESH_USER).await;
    let repo = RefreshTokenRepo::new();

    let issued = refresh::issue_refresh_token(&pool, tenant_id, user_id, None, None, &repo).await;
    let old_token = rt_token(&issued);
    let rotated = refresh::rotate_refresh_token(&old_token, &pool, None, None, &repo).await;
    let new_token = rotated
        .as_ref()
        .ok()
        .and_then(|res| res.as_ref().map(|(new, _)| new.token.clone()))
        .unwrap_or_default();
    let old_auth = refresh::authenticate_refresh_token(&old_token, &pool, &repo).await;
    let new_auth = refresh::authenticate_refresh_token(&new_token, &pool, &repo).await;

    sweep(&pool, REFRESH_TENANT).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    let issued = issued.expect("issue succeeds");
    let (replacement, rotated_user) = rotated
        .expect("rotate succeeds")
        .expect("a live token rotates to a replacement");
    assert_eq!(rotated_user, user_id, "rotation returns the owning user");
    assert_ne!(replacement.token, issued.token);
    assert_eq!(replacement.user_id, user_id);
    assert_eq!(replacement.tenant_id, tenant_id);
    assert_ne!(
        expected_hash(&raw_of(&replacement.token)),
        expected_hash(&raw_of(&issued.token)),
        "the replacement has its own verifier hash"
    );

    assert!(
        old_auth.expect("old-token check succeeds").is_none(),
        "the rotated-away plaintext must not authenticate"
    );
    assert!(
        new_auth.expect("new-token check succeeds").is_some(),
        "the replacement authenticates"
    );
}

/// Refresh tokens past expiry (or never issued) authenticate as `None` and
/// refuse rotation; an unknown plaintext revokes nothing (idempotent).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn refresh_rejects_expired_unknown_and_wrong_prefix() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;
    sweep(&pool, REFRESH_TENANT).await;

    let (tenant_id, user_id) = seed_tenant_and_user(&pool, REFRESH_TENANT, REFRESH_USER).await;
    let repo = RefreshTokenRepo::new();

    // Fabricate the expired row directly: a live-looking hash, past expiry.
    let raw = [0x77u8; 32];
    let plaintext = format!("ws_rt_{}", hex::encode(raw));
    let now = Utc::now();
    let model = RefreshTokenModel {
        id: Uuid::new_v4(),
        tenant_id,
        user_id,
        token_hash: expected_hash(&raw),
        issued_at: now - Duration::hours(3),
        last_used_at: now - Duration::hours(2),
        expires_at: now - Duration::hours(1),
        revoked: false,
        revoked_at: None,
        user_agent: None,
        ip_address: None,
    };
    repo.insert(&pool, &model)
        .await
        .expect("seed expired refresh token");

    let expired = refresh::authenticate_refresh_token(&plaintext, &pool, &repo).await;
    let rotate_expired = refresh::rotate_refresh_token(&plaintext, &pool, None, None, &repo).await;
    let unknown = refresh::authenticate_refresh_token(
        &format!("ws_rt_{}", hex::encode([0x33u8; 32])),
        &pool,
        &repo,
    )
    .await;
    let revoke_unknown = refresh::revoke_refresh_token(
        &format!("ws_rt_{}", hex::encode([0x33u8; 32])),
        &pool,
        &repo,
    )
    .await;
    let wrong_prefix =
        refresh::authenticate_refresh_token(&format!("ws_at_{}", hex::encode(raw)), &pool, &repo)
            .await;

    sweep(&pool, REFRESH_TENANT).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    assert!(
        expired.expect("expired check succeeds").is_none(),
        "an expired refresh token resolves nothing"
    );
    assert!(
        rotate_expired.expect("rotate-expired succeeds").is_none(),
        "an expired refresh token does not rotate"
    );
    assert!(
        unknown.expect("unknown check succeeds").is_none(),
        "an unknown refresh token resolves nothing"
    );
    revoke_unknown.expect("revoking an unknown token is an idempotent no-op");
    assert!(
        wrong_prefix.expect("wrong-prefix check succeeds").is_none(),
        "an API-token plaintext must not match a refresh lookup"
    );
}
