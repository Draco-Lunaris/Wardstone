//! The sealed-mode tests (ws-api side): the health surface answers 200
//! with the state field in both modes (liveness — compose never churns a
//! correctly-locked service); every non-unlock route answers 503 `sealed`
//! while sealed; the unlock POST swaps the full router in and the next
//! request reaches it; a second unlock is a conflict; a wrong passphrase
//! leaves the state unchanged.
//!
//! The DB-gated cases below pin the PRODUCTION build closure
//! ([`unlocked_router_from_envelopes`]): the unlock opens the sealed
//! volume's three envelopes, rotates the database credential
//! unconditionally, and mints the JWT pair straight into its envelope
//! (a fresh install never writes plaintext). They run against the live
//! test server like the suite's DB-gated siblings:
//!
//! ```text
//! DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test \
//!     cargo test -p ws-api --test sealed_test -- --include-ignored
//! ```

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use tower::ServiceExt;

use ws_api::sealed::{sealed_router, SealedApi};

/// A trivial full router the build closure swaps in: one route proving
/// delegation reached it.
fn full_router() -> Router {
    Router::new().route("/api/v1/full", get(|| async { "the full surface" }))
}

#[tokio::test]
async fn sealed_healthz_is_200_with_the_state_and_everything_else_503s() {
    let api = std::sync::Arc::new(SealedApi::new(std::sync::Arc::new(
        |_: &ws_api::sealed::UnlockRequest| Box::pin(async move { Ok(full_router()) }),
    )));
    let router = sealed_router(api);

    let health = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK, "liveness is unconditional");
    let body = axum::body::to_bytes(health.into_body(), 1 << 10)
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&body).contains(r#""state":"sealed""#),
        "the health surface carries the state field"
    );

    let sealed = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/full")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        sealed.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "the full surface is 503 while sealed"
    );
    let body = axum::body::to_bytes(sealed.into_body(), 1 << 10)
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&body).contains(r#""code":"sealed""#),
        "the 503 speaks the house JSON envelope"
    );
}

#[tokio::test]
async fn the_unlock_swaps_the_full_router_in_and_healthz_flips() {
    let api = std::sync::Arc::new(SealedApi::new(std::sync::Arc::new(
        |_: &ws_api::sealed::UnlockRequest| Box::pin(async move { Ok(full_router()) }),
    )));
    let router = sealed_router(api);

    let unlock = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/internal/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "passphrase": "the-master-passphrase" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unlock.status(), StatusCode::OK, "the unlock succeeds");

    // The same router now delegates: the full surface answers.
    let after = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/full")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        after.status(),
        StatusCode::OK,
        "the full surface answers after the unlock"
    );

    let health = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(health.into_body(), 1 << 10)
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&body).contains(r#""state":"unlocked""#),
        "the health surface reports unlocked"
    );
}

#[tokio::test]
async fn a_wrong_passphrase_changes_nothing_and_a_second_unlock_conflicts() {
    let api = std::sync::Arc::new(SealedApi::new(std::sync::Arc::new(
        |req: &ws_api::sealed::UnlockRequest| {
            let ok = req.passphrase == "the-master-passphrase";
            Box::pin(async move {
                if ok {
                    Ok(full_router())
                } else {
                    Err(ws_api::error::ApiError::Unauthorized(
                        "the master passphrase was refused".to_string(),
                    ))
                }
            })
        },
    )));
    let router = sealed_router(api);

    let refused = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/internal/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "passphrase": "wrong" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        refused.status(),
        StatusCode::UNAUTHORIZED,
        "the wrong passphrase is refused"
    );
    let still = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/full")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        still.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a refused unlock leaves the state sealed"
    );

    let ok = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/internal/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "passphrase": "the-master-passphrase" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);

    let second = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/internal/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "passphrase": "the-master-passphrase" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        second.status(),
        StatusCode::CONFLICT,
        "a second unlock is a conflict"
    );
}

// ---------------------------------------------------------------------------
// The DB-gated production-builder cases. The builder ROTATES the shared
// login role's password (its unconditional per-unlock rotation), so these
// serialize on this suite's own advisory key and restore the role before
// any assertion can panic.
// ---------------------------------------------------------------------------

/// This suite's advisory-lock key — the "WARDST" family (ASCII
/// W-A-R-D-S-T packed big-endian) with a per-suite ordinal; 0016 is the
/// first free key after the suites the house ledger has assigned.
const ADVISORY_KEY: i64 = 0x0057_4144_5354_0016;

/// The process-local DB fence, held from BEFORE the fixture's connect:
/// the builder cases ROTATE the shared login role, and a parallel peer's
/// fixture connect landing inside that window would fail
/// authentication spuriously. The advisory lock alone cannot order this
/// — it is taken only after the connect it must protect.
static DB: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

async fn lock_db() -> tokio::sync::MutexGuard<'static, ()> {
    DB.get_or_init(|| tokio::sync::Mutex::new(())).lock().await
}

/// Test database URL; `DATABASE_URL` overrides it.
fn database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://wardstone:wardstone@localhost:5432/wardstone_test".to_string()
    })
}

/// The shared login role's bootstrap credential (the URL's password) —
/// a fresh connection with it proves the role's password still matches.
async fn bootstrap_credential_connects() -> bool {
    sqlx::PgPool::connect(&database_url()).await.is_ok()
}

/// A DB-gated fixture: the live pool (connected with the bootstrap
/// credential BEFORE any rotation), the held advisory-lock connection,
/// and a fresh keys directory.
struct Fixture {
    pool: sqlx::PgPool,
    #[allow(dead_code)] // held for the whole body: serializes this suite
    advisory: sqlx::pool::PoolConnection<sqlx::Postgres>,
    keys_dir: std::path::PathBuf,
}

impl Fixture {
    /// Restore the shared login role's password over the
    /// pre-rotation connection (established connections survive the
    /// rotation), BEFORE any assertion can panic. Idempotent.
    async fn restore_role_password(&self) {
        sqlx::query("ALTER USER wardstone PASSWORD 'wardstone'")
            .execute(&self.pool)
            .await
            .expect("restore the shared test role's password");
    }

    /// Restore the role and remove the keys directory.
    async fn cleanup(&self) {
        self.restore_role_password().await;
        let _ = std::fs::remove_dir_all(&self.keys_dir);
    }
}

async fn fixture() -> Fixture {
    let pool = ws_core::db::connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut conn = pool
        .acquire()
        .await
        .expect("acquire the advisory-lock connection");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(ADVISORY_KEY)
        .execute(&mut *conn)
        .await
        .expect("take this suite's advisory lock");
    let keys_dir = std::env::temp_dir().join(format!(
        "ws-api-sealed-keys-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&keys_dir).expect("create the keys directory");
    Fixture {
        pool,
        advisory: conn,
        keys_dir,
    }
}

/// Mint the three envelopes a converted volume holds — the conversion's
/// exact outputs, hand-minted: this suite pins the BUILDER; ws-web's
/// suites own the conversion itself. The db-credential envelope seals
/// the CURRENT role password, so the builder's connection with it
/// matches the live role.
fn mint_sealed_volume(keys_dir: &std::path::Path, passphrase: &str) {
    let master = [7u8; 32];
    ws_core::crypto::KeyEnvelope::write_envelope(
        &keys_dir.join(ws_core::crypto::MASTER_ENVELOPE_FILE),
        passphrase,
        &master,
        ws_core::crypto::PROD_KDF_PARAMS,
    )
    .expect("mint the master envelope");
    let secret = [9u8; 32];
    ws_core::crypto::KeyEnvelope::write_envelope(
        &keys_dir.join(ws_core::crypto::SECRET_ENVELOPE_FILE),
        passphrase,
        &secret,
        ws_core::crypto::PROD_KDF_PARAMS,
    )
    .expect("mint the secret-encryption envelope");
    ws_core::crypto::KeyEnvelope::write_envelope(
        &keys_dir.join(ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE),
        passphrase,
        b"wardstone",
        ws_core::crypto::PROD_KDF_PARAMS,
    )
    .expect("mint the db-credential envelope");
}

/// The api [`ws_api::state::ApiConfig`] the builder takes, in the test
/// world's shape.
fn api_config(keys_dir: &std::path::Path) -> ws_api::state::ApiConfig {
    ws_api::state::ApiConfig::new("sealed.test".to_string(), keys_dir.to_path_buf())
}

/// An unlock against a volume that is NOT sealed (no master envelope —
/// the fresh-install window before the setup conversion) is refused
/// with ZERO side effects: no JWT pair minted under the caller's
/// passphrase, no credential rotation. A compose-internal race that
/// beats the setup commit must leave nothing behind that the real
/// relay's passphrase could no longer open.
#[tokio::test]
#[ignore = "DB-gated: rotates the shared login role (restored)"]
async fn the_builder_refuses_an_unsealed_volume_with_no_side_effects() {
    let _db = lock_db().await;
    let fixture = fixture().await;
    let url = database_url();

    let built = ws_api::sealed::unlocked_router_from_envelopes(
        &fixture.keys_dir,
        &url,
        &api_config(&fixture.keys_dir),
        "the-master-passphrase",
    )
    .await;
    assert!(built.is_err(), "an unsealed volume has nothing to unlock");
    assert!(
        !fixture
            .keys_dir
            .join(ws_core::crypto::JWT_ENVELOPE_FILE)
            .exists(),
        "the refused unlock mints no JWT envelope (the real relay's \
         passphrase must stay able to mint it)"
    );
    assert!(
        bootstrap_credential_connects().await,
        "the refused unlock rotates nothing"
    );
    fixture.cleanup().await;
}

/// The production unlock: the three envelopes open, the database
/// credential rotates (the bootstrap credential dies), the fresh
/// credential is re-sealed, the JWT pair mints straight into its
/// envelope, and the built router serves.
#[tokio::test]
#[ignore = "DB-gated: rotates the shared login role (restored)"]
async fn the_builder_unlocks_rotates_and_mints_the_jwt_pair() {
    let _db = lock_db().await;
    let fixture = fixture().await;
    mint_sealed_volume(&fixture.keys_dir, "the-master-passphrase");
    let url = database_url();

    let router = ws_api::sealed::unlocked_router_from_envelopes(
        &fixture.keys_dir,
        &url,
        &api_config(&fixture.keys_dir),
        "the-master-passphrase",
    )
    .await
    .expect("the sealed volume unlocks");
    let health = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("probe the built router");
    assert_eq!(health.status(), StatusCode::OK, "the built router serves");

    // Mint-at-unlock: a fresh install's JWT pair exists only as the
    // envelope the builder just wrote — plaintext was never on the volume.
    assert!(
        fixture
            .keys_dir
            .join(ws_core::crypto::JWT_ENVELOPE_FILE)
            .exists(),
        "the unlock mints the JWT pair into its envelope"
    );
    assert!(
        !fixture.keys_dir.join("jwt-signing-key.pem").exists()
            && !fixture.keys_dir.join("jwt-verify-key.pem").exists(),
        "no plaintext JWT pair is ever written"
    );

    // The rotation: the bootstrap credential is dead...
    assert!(
        !bootstrap_credential_connects().await,
        "the rotation kills the credential the envelope held"
    );
    // ...and the re-sealed credential works: it IS the live role's
    // password now.
    let resealed = ws_core::crypto::KeyEnvelope::open_envelope(
        &fixture
            .keys_dir
            .join(ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE),
        "the-master-passphrase",
    )
    .expect("open the re-sealed credential envelope");
    let rotated_url =
        ws_core::crypto::substitute_db_password(&url, &String::from_utf8_lossy(&resealed));
    let rotated = sqlx::PgPool::connect(&rotated_url).await;
    assert!(
        rotated.is_ok(),
        "the re-sealed credential is the live role password"
    );
    drop(rotated);

    fixture.cleanup().await;
}

/// A wrong passphrase against a sealed volume changes nothing: the
/// envelopes stay as they are, no JWT pair mints, no rotation runs.
#[tokio::test]
#[ignore = "DB-gated: the sealed-volume world (role restored)"]
async fn the_builder_refuses_a_wrong_passphrase_without_side_effects() {
    let _db = lock_db().await;
    let fixture = fixture().await;
    mint_sealed_volume(&fixture.keys_dir, "the-master-passphrase");
    let url = database_url();

    let built = ws_api::sealed::unlocked_router_from_envelopes(
        &fixture.keys_dir,
        &url,
        &api_config(&fixture.keys_dir),
        "not-the-master-passphrase",
    )
    .await;
    assert!(built.is_err(), "the wrong passphrase is refused");
    assert!(
        !fixture
            .keys_dir
            .join(ws_core::crypto::JWT_ENVELOPE_FILE)
            .exists(),
        "the refused unlock mints no JWT envelope"
    );
    assert!(
        bootstrap_credential_connects().await,
        "the refused unlock rotates nothing"
    );
    let current = ws_core::crypto::KeyEnvelope::open_envelope(
        &fixture
            .keys_dir
            .join(ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE),
        "the-master-passphrase",
    )
    .expect("the original credential envelope still opens with its passphrase");
    assert_eq!(
        &*current, b"wardstone",
        "the refused unlock leaves the sealed credential as it was"
    );
    fixture.cleanup().await;
}
