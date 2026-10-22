//! Integration tests for `ws_auth::one_shot` (single-use operator tokens
//! for the token-gated pull flow).
//!
//! These tests run against a live Postgres and are marked `#[ignore]`.
//! Run them with:
//!
//! ```sh
//! DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test \
//!     cargo test -p ws-auth --test one_shot_test -- --include-ignored
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
//!    only: one-shot tokens first, then the users (whose delete would be
//!    blocked by leftover token attributions), tenant last).
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
//! marker `0x000e`, disjoint from every other suite's key.

use std::sync::OnceLock;

use chrono::{Duration, SubsecRound, Utc};
use sha2::{Digest, Sha256};
use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex;
use uuid::Uuid;

use ws_auth::one_shot;
use ws_core::db::connect;
use ws_core::models::credential::OneShotTokenModel;
use ws_core::models::rbac::{role_capabilities, Actor, ActorType, AuthMethod, Capability, Role};
use ws_core::models::user::UserModel;
use ws_core::repo::credential_repo::CredentialRepo;
use ws_core::repo::tenant_repo::TenantRepo;
use ws_core::repo::user_repo::UserRepo;

/// Postgres advisory-lock key for this suite: ASCII "WARDST" (0x5741445354)
/// plus this suite's marker 0x000e, i.e. `0x0057_4144_5354_000e`. Processes
/// taking this key serialize their test bodies against this suite.
const ADVISORY_KEY: i64 = 0x0057_4144_5354_000e;

/// Tenant name this suite owns; deleted before asserts (tokens first,
/// users next, tenant last).
const OT_TENANT: &str = "ot-tenant";

/// The admin username this suite owns under [`OT_TENANT`].
const OT_USER: &str = "ot-admin";

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

/// The raw bytes a presented `ws_ot_` plaintext carries: the prefix, then
/// the hex form of the 32 random bytes (the house's encoding).
fn raw_of(plaintext: &str) -> Vec<u8> {
    let body = plaintext.strip_prefix("ws_ot_").unwrap_or(plaintext);
    hex::decode(body).expect("test token body is hex")
}

/// Delete this suite's rows owned by `tenant_name`, FK order: one-shot
/// tokens, users (the minted_by references must be gone first), tenant last.
async fn sweep(pool: &PgPool, tenant_name: &str) {
    sqlx::query(
        "DELETE FROM one_shot_tokens \
         WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
    )
    .bind(tenant_name)
    .execute(pool)
    .await
    .expect("sweep one_shot_tokens rows");
    sqlx::query("DELETE FROM users WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)")
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

/// The human Actor that mints one-shot tokens in these tests: an admin
/// (the `actor_id` is the user id, as the JWT middleware resolves it).
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

/// The token plaintext of an in-flight mint result, for calls that must run
/// before cleanup: when the mint failed the empty plaintext simply looks up
/// as `None` (captured, unwrapped post-cleanup), and the mint error itself
/// keeps working on the original `Result`.
fn ot_token(created: &Result<one_shot::OneShotToken, ws_auth::error::AuthError>) -> String {
    created
        .as_ref()
        .ok()
        .map(|t| t.token.clone())
        .unwrap_or_default()
}

/// A minted one-shot token carries the `ws_ot_` prefix plus 32 bytes of
/// hex, never its own verifier hash; the stored row holds exactly
/// `hex(Sha256(raw))` — not the plaintext or its hex body — and carries
/// the minting tenant, the minting user, and the requested TTL.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn minted_one_shot_stores_verifier_hash_only() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;
    sweep(&pool, OT_TENANT).await;

    let ttl = Duration::hours(1);
    let (tenant_id, user_id) = seed_tenant_and_user(&pool, OT_TENANT, OT_USER).await;
    let minter = admin_actor(user_id, tenant_id);
    let repo = CredentialRepo::new();

    let minted = one_shot::mint_one_shot(&pool, tenant_id, &minter, ttl, &repo).await;
    let stored_hash = minted
        .as_ref()
        .ok()
        .map(|t| expected_hash(&raw_of(&t.token)))
        .unwrap_or_default();
    let stored = repo.get_one_shot_by_hash(&pool, &stored_hash).await;

    // Cleanup BEFORE asserting: this tenant's rows in FK order.
    sweep(&pool, OT_TENANT).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    let minted = minted.expect("mint_one_shot succeeds");
    assert!(
        minted.token.starts_with("ws_ot_"),
        "token should carry the ws_ot_ prefix"
    );
    let hex_body = minted.token.strip_prefix("ws_ot_").expect("prefix present");
    let raw = hex::decode(hex_body).expect("token body is hex");
    assert_eq!(raw.len(), 32, "token is 32 random bytes, hex-encoded");
    assert!(
        !minted.token.contains(&expected_hash(&raw)),
        "the plaintext never carries its own verifier hash"
    );
    assert_eq!(minted.tenant_id, tenant_id);

    let stored = stored
        .expect("hash lookup succeeds")
        .expect("row stored under sha256(raw_bytes)");
    assert_eq!(stored.token_hash, expected_hash(&raw));
    assert_ne!(stored.token_hash, minted.token);
    assert_ne!(stored.token_hash, hex_body);
    assert_eq!(stored.tenant_id, tenant_id);
    assert_eq!(stored.minted_by, Some(user_id));
    assert_eq!(stored.id, minted.id);
    assert_eq!(stored.expires_at, Some(minted.expires_at));
    assert_eq!(
        stored.expires_at.unwrap() - stored.created_at,
        ttl,
        "the mint stores exactly the requested TTL"
    );
    assert!(stored.used_at.is_none(), "a minted token is not yet used");
}

/// `claim_one_shot` is the atomic consume: it resolves the minted token to
/// an `Actor` with `actor_type = OneShotToken`, `auth_method = OneShot`,
/// the `Issue` capability, and `minted_by` attribution — exactly once. The
/// second claim of the same token returns `None` (already used), the row's
/// `used_at` is stamped after the first claim, and the lookup-only
/// `consume_one_shot` also refuses it afterward.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn claim_one_shot_succeeds_exactly_once() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;
    sweep(&pool, OT_TENANT).await;

    let (tenant_id, user_id) = seed_tenant_and_user(&pool, OT_TENANT, OT_USER).await;
    let minter = admin_actor(user_id, tenant_id);
    let repo = CredentialRepo::new();

    let minted =
        one_shot::mint_one_shot(&pool, tenant_id, &minter, Duration::hours(1), &repo).await;
    let token = ot_token(&minted);
    let first_claim = one_shot::claim_one_shot(&token, &pool, &repo).await;
    let row_after_claim = repo
        .get_one_shot_by_hash(&pool, &expected_hash(&raw_of(&token)))
        .await;
    let second_claim = one_shot::claim_one_shot(&token, &pool, &repo).await;
    let consume_after_claim = one_shot::consume_one_shot(&token, &pool, &repo).await;

    sweep(&pool, OT_TENANT).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    let minted = minted.expect("mint_one_shot succeeds");
    let actor = first_claim
        .expect("claim succeeds")
        .expect("the fresh token claims");
    assert_eq!(actor.actor_type, ActorType::OneShotToken);
    assert_eq!(actor.auth_method, AuthMethod::OneShot);
    assert_eq!(actor.capabilities, vec![Capability::Issue]);
    assert_eq!(actor.actor_id, minted.id.to_string());
    assert_eq!(actor.tenant_id, tenant_id);
    assert_eq!(actor.session_id, None);
    assert_eq!(
        actor.minted_by,
        Some(user_id.to_string()),
        "the actor carries the human who minted it"
    );

    let row = row_after_claim
        .expect("row lookup succeeds")
        .expect("row still present after the claim");
    assert!(row.used_at.is_some(), "a successful claim stamps used_at");
    assert_eq!(row.token_hash, expected_hash(&raw_of(&token)));

    assert!(
        second_claim.expect("second claim succeeds").is_none(),
        "a one-shot token claims exactly once"
    );
    assert!(
        consume_after_claim
            .expect("consume-after-claim succeeds")
            .is_none(),
        "the lookup-only form refuses an already-used token as None"
    );
}

/// `consume_one_shot` is lookup-only: it resolves the minted token's
/// `Actor` but never stamps `used_at`, so the atomic claim still succeeds
/// afterward — a stray bearer must not burn a token.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn consume_one_shot_looks_up_without_burning() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;
    sweep(&pool, OT_TENANT).await;

    let (tenant_id, user_id) = seed_tenant_and_user(&pool, OT_TENANT, OT_USER).await;
    let minter = admin_actor(user_id, tenant_id);
    let repo = CredentialRepo::new();

    let minted =
        one_shot::mint_one_shot(&pool, tenant_id, &minter, Duration::hours(1), &repo).await;
    let token = ot_token(&minted);
    let lookup = one_shot::consume_one_shot(&token, &pool, &repo).await;
    let row_after_lookup = repo
        .get_one_shot_by_hash(&pool, &expected_hash(&raw_of(&token)))
        .await;
    let claim_after_lookup = one_shot::claim_one_shot(&token, &pool, &repo).await;

    sweep(&pool, OT_TENANT).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    let minted = minted.expect("mint_one_shot succeeds");
    let actor = lookup
        .expect("consume_one_shot succeeds")
        .expect("the fresh token resolves an actor");
    assert_eq!(actor.actor_type, ActorType::OneShotToken);
    assert_eq!(actor.auth_method, AuthMethod::OneShot);
    assert_eq!(actor.capabilities, vec![Capability::Issue]);
    assert_eq!(actor.actor_id, minted.id.to_string());
    assert_eq!(actor.tenant_id, tenant_id);
    assert_eq!(actor.minted_by, Some(user_id.to_string()));

    let row = row_after_lookup
        .expect("row lookup succeeds")
        .expect("row still present after the lookup");
    assert!(
        row.used_at.is_none(),
        "the lookup-only form must not stamp used_at"
    );
    assert!(
        claim_after_lookup
            .expect("claim after lookup succeeds")
            .is_some(),
        "a token that was only looked up can still be claimed"
    );
}

/// Expired, unknown, malformed, and wrongly-prefixed plaintexts claim and
/// resolve as `None` (an unauthenticated credential is not an error); an
/// expired row's `used_at` stays unset after those attempts.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn expired_and_unknown_tokens_resolve_none() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;
    sweep(&pool, OT_TENANT).await;

    let (tenant_id, user_id) = seed_tenant_and_user(&pool, OT_TENANT, OT_USER).await;
    let repo = CredentialRepo::new();

    // Fabricate the expired row directly (the mint sets a future expiry):
    // a live-looking token_hash, created an hour ago, expired half an hour
    // ago, never used, attributed to the seeded user.
    let raw = [0x42u8; 32];
    let plaintext = format!("ws_ot_{}", hex::encode(raw));
    let now = Utc::now().trunc_subsecs(6);
    let model = OneShotTokenModel {
        id: Uuid::new_v4(),
        tenant_id,
        minted_by: Some(user_id),
        token_hash: expected_hash(&raw),
        created_at: now - Duration::hours(1),
        expires_at: Some(now - Duration::minutes(30)),
        used_at: None,
    };
    repo.insert_one_shot_token(&pool, &model)
        .await
        .expect("seed expired one-shot token");

    let expired_claim = one_shot::claim_one_shot(&plaintext, &pool, &repo).await;
    let expired_consume = one_shot::consume_one_shot(&plaintext, &pool, &repo).await;
    let unknown_claim = one_shot::claim_one_shot(
        &format!("ws_ot_{}", hex::encode([0x99u8; 32])),
        &pool,
        &repo,
    )
    .await;
    let unknown_consume = one_shot::consume_one_shot(
        &format!("ws_ot_{}", hex::encode([0x99u8; 32])),
        &pool,
        &repo,
    )
    .await;
    let malformed_claim = one_shot::claim_one_shot("not-a-token", &pool, &repo).await;
    let wrong_prefix_claim =
        one_shot::claim_one_shot(&format!("ws_at_{}", hex::encode(raw)), &pool, &repo).await;
    let row = repo.get_one_shot_by_hash(&pool, &expected_hash(&raw)).await;

    sweep(&pool, OT_TENANT).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    assert!(
        expired_claim.expect("expired claim succeeds").is_none(),
        "an expired one-shot token does not claim"
    );
    assert!(
        expired_consume.expect("expired consume succeeds").is_none(),
        "an expired one-shot token resolves no actor"
    );
    assert!(
        unknown_claim.expect("unknown claim succeeds").is_none(),
        "an unknown token does not claim"
    );
    assert!(
        unknown_consume.expect("unknown consume succeeds").is_none(),
        "an unknown token resolves no actor"
    );
    assert!(
        malformed_claim.expect("malformed claim succeeds").is_none(),
        "a malformed plaintext does not claim"
    );
    assert!(
        wrong_prefix_claim
            .expect("wrong-prefix claim succeeds")
            .is_none(),
        "an API-token plaintext must not match a one-shot lookup"
    );
    let row = row.expect("row lookup succeeds").expect("row present");
    assert!(
        row.used_at.is_none(),
        "failed claims must not stamp used_at"
    );
}
