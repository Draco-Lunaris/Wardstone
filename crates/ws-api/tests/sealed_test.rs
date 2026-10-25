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

/// A fresh keys volume for the relay-nonce claim (F2): each test mints
/// its own, so the one-time consume never crosses tests.
fn nonce_keys(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ws-api-sealed-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn sealed_healthz_is_200_with_the_state_and_everything_else_503s() {
    let api = std::sync::Arc::new(SealedApi::new(
        std::sync::Arc::new(|_: &ws_api::sealed::UnlockRequest| {
            Box::pin(async move { Ok(full_router()) })
        }),
        nonce_keys("healthz"),
    ));
    let router = sealed_router(api, None);

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
    let keys = nonce_keys("swap");
    let api = std::sync::Arc::new(SealedApi::new(
        std::sync::Arc::new(|_: &ws_api::sealed::UnlockRequest| {
            Box::pin(async move { Ok(full_router()) })
        }),
        keys.clone(),
    ));
    let router = sealed_router(api, None);

    let unlock = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/internal/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "passphrase": "the-master-passphrase",
                        "nonce": ws_core::crypto::mint_relay_nonce(&keys).unwrap(),
                    })
                    .to_string(),
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
    let keys = nonce_keys("wrong-pass");
    let api = std::sync::Arc::new(SealedApi::new(
        std::sync::Arc::new(|req: &ws_api::sealed::UnlockRequest| {
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
        }),
        keys.clone(),
    ));
    let router = sealed_router(api, None);

    // Every POST carries a freshly minted claim (the consume is spent
    // even when the passphrase then fails), so each refusal below is
    // the PASSPHRASE's, not the nonce's.
    let refused = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/internal/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "passphrase": "wrong",
                        "nonce": ws_core::crypto::mint_relay_nonce(&keys).unwrap(),
                    })
                    .to_string(),
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
                    serde_json::json!({
                        "passphrase": "the-master-passphrase",
                        "nonce": ws_core::crypto::mint_relay_nonce(&keys).unwrap(),
                    })
                    .to_string(),
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
                    serde_json::json!({
                        "passphrase": "the-master-passphrase",
                        "nonce": ws_core::crypto::mint_relay_nonce(&keys).unwrap(),
                    })
                    .to_string(),
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
    /// The suite's advisory-lock connection — also the DEDICATED
    /// pre-rotation connection the restore runs over (the pool may
    /// need a fresh connection at exactly the moment the password is
    /// rotated; this one survives the rotation).
    advisory: sqlx::pool::PoolConnection<sqlx::Postgres>,
    keys_dir: std::path::PathBuf,
    /// Whether a restore already verifiably landed (Drop's net skips).
    role_restored: bool,
    /// The panic-safe restore net (the reference implementation is
    /// ws-web's setup_test; the binding rules live in CLAUDE.md).
    net: RestoreNet,
}

impl Fixture {
    /// Restore the shared login role's password over the
    /// pre-rotation advisory connection (established connections
    /// survive the rotation), BEFORE any post-rotation read or
    /// assertion can panic. Idempotent.
    async fn restore_role_password(&mut self) {
        sqlx::query("ALTER USER wardstone PASSWORD 'wardstone'")
            .execute(&mut *self.advisory)
            .await
            .expect("restore the shared test role's password");
        self.role_restored = true;
    }

    /// Restore the role and remove the keys directory.
    async fn cleanup(&mut self) {
        self.restore_role_password().await;
        let _ = std::fs::remove_dir_all(&self.keys_dir);
    }
}

/// The panic-safe restore net's channels: Drop cannot await, so a
/// worker thread (its own little runtime, its OWN connection made while
/// the shared credential is still valid — sqlx connections are
/// runtime-affine) performs the ALTER on request. The reference
/// implementation is `ws-web tests/setup_test.rs`'s `RestoreNet`.
struct RestoreNet {
    /// "please restore" — sent from Drop.
    request: std::sync::mpsc::Sender<()>,
    /// The worker's reply once the ALTER landed (Drop waits on it).
    reply: std::sync::mpsc::Receiver<()>,
}

/// Spawn the restore net's worker thread. The connection is created
/// immediately (the shared credential is valid now); the worker then
/// parks on the request channel until the fixture drops.
fn spawn_restore_net(url: &str) -> RestoreNet {
    let (request, rx) = std::sync::mpsc::channel::<()>();
    let (tx, reply) = std::sync::mpsc::channel::<()>();
    let url = url.to_owned();
    std::thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };
        let connected: Result<sqlx::PgConnection, sqlx::Error> =
            runtime.block_on(sqlx::Connection::connect(&url));
        let mut conn = match connected {
            Ok(conn) => conn,
            Err(_) => return, // the net is dead; Drop's send no-ops
        };
        if rx.recv().is_err() {
            return;
        }
        runtime.block_on(async {
            let _ = sqlx::query("ALTER USER wardstone PASSWORD 'wardstone'")
                .execute(&mut conn)
                .await;
        });
        let _ = tx.send(());
    });
    RestoreNet { request, reply }
}

/// The panic-safe half of the self-cleaning contract: a test that
/// unwinds between its rotation and `cleanup()` would otherwise leave
/// the shared role rotated, and every later suite fails at its first
/// connect with a misleading `28P01` (exactly how the 2026-10-25 RED
/// run poisoned sealed_test's siblings: the consistent-volume
/// completion test ran a FULL unlock through the inert threading,
/// rotated, then panicked at its `.err().expect()` — the deferred
/// minor this port retires). Idempotent, and skipped entirely when a
/// restore already verifiably landed.
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.keys_dir);
        if self.role_restored {
            return;
        }
        // The net is one-shot: the request IS the fixture's last word.
        let _ = self.net.request.send(());
        let _ = self
            .net
            .reply
            .recv_timeout(std::time::Duration::from_secs(15));
    }
}

async fn fixture() -> Fixture {
    let url = database_url();
    let net = spawn_restore_net(&url);
    let pool = ws_core::db::connect(&url)
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
        advisory: conn,
        keys_dir,
        role_restored: false,
        net,
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
        0,
    )
    .expect("mint the master envelope");
    let secret = [9u8; 32];
    ws_core::crypto::KeyEnvelope::write_envelope(
        &keys_dir.join(ws_core::crypto::SECRET_ENVELOPE_FILE),
        passphrase,
        &secret,
        ws_core::crypto::PROD_KDF_PARAMS,
        0,
    )
    .expect("mint the secret-encryption envelope");
    ws_core::crypto::KeyEnvelope::write_envelope(
        &keys_dir.join(ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE),
        passphrase,
        b"wardstone",
        ws_core::crypto::PROD_KDF_PARAMS,
        0,
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
    let mut fixture = fixture().await;
    let url = database_url();

    let built = ws_api::sealed::unlocked_router_from_envelopes(
        &fixture.keys_dir,
        &url,
        &api_config(&fixture.keys_dir),
        "the-master-passphrase",
        None,
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
    let mut fixture = fixture().await;
    mint_sealed_volume(&fixture.keys_dir, "the-master-passphrase");
    let url = database_url();

    let router = ws_api::sealed::unlocked_router_from_envelopes(
        &fixture.keys_dir,
        &url,
        &api_config(&fixture.keys_dir),
        "the-master-passphrase",
        None,
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
    let mut fixture = fixture().await;
    mint_sealed_volume(&fixture.keys_dir, "the-master-passphrase");
    let url = database_url();

    let built = ws_api::sealed::unlocked_router_from_envelopes(
        &fixture.keys_dir,
        &url,
        &api_config(&fixture.keys_dir),
        "not-the-master-passphrase",
        None,
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

// --- Task 4b: the mixed-state completion at unlock ---

/// A crashed passphrase change's aftermath, hand-minted: the
/// db-credential envelope already re-wrapped under the NEXT passphrase
/// at generation 1, the master + secret envelopes still at generation 0
/// under the current one (master is written LAST — the anchor rule).
/// The jwt envelope is deliberately ABSENT (the fresh-install shape):
/// the completion re-wraps what exists, and the builder's normal
/// mint-at-unlock then stamps the fresh pair at the advanced generation
/// under the next passphrase.
fn mint_mixed_volume(keys_dir: &std::path::Path, current: &str, next: &str) {
    use ws_core::crypto::KeyEnvelope;
    let params = ws_core::crypto::KdfParams {
        m_cost: 8192,
        t_cost: 2,
        p_cost: 1,
    };
    KeyEnvelope::write_envelope(
        &keys_dir.join(ws_core::crypto::MASTER_ENVELOPE_FILE),
        current,
        &[7u8; 32],
        params,
        0,
    )
    .expect("mint the master envelope at the current generation");
    KeyEnvelope::write_envelope(
        &keys_dir.join(ws_core::crypto::SECRET_ENVELOPE_FILE),
        current,
        &[9u8; 32],
        params,
        0,
    )
    .expect("mint the secret envelope at the current generation");
    KeyEnvelope::write_envelope(
        &keys_dir.join(ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE),
        next,
        b"wardstone",
        params,
        1,
    )
    .expect("mint the advanced db-credential envelope");
}

/// The generation every standard envelope in `keys_dir` records — one
/// value per envelope, or None where the file is absent.
fn volume_generations(
    keys_dir: &std::path::Path,
) -> std::result::Result<Vec<(&'static str, Option<u64>)>, ws_core::error::CoreError> {
    [
        ws_core::crypto::MASTER_ENVELOPE_FILE,
        ws_core::crypto::SECRET_ENVELOPE_FILE,
        ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE,
        ws_core::crypto::JWT_ENVELOPE_FILE,
    ]
    .iter()
    .map(|file| {
        let path = keys_dir.join(file);
        if path.exists() {
            Ok((
                *file,
                Some(ws_core::crypto::KeyEnvelope::read_generation(&path)?),
            ))
        } else {
            Ok((*file, None))
        }
    })
    .collect()
}

/// The completion flow the unlock page re-offers (spec §5.7): against a
/// MIXED volume the operator re-enters the interrupted change's
/// `current` + `next`, the builder converges the volume to one
/// generation under `next`, and the unlock proceeds under `next` alone —
/// the fresh JWT pair included, minted straight into its envelope at
/// the ADVANCED generation.
#[tokio::test]
#[ignore = "DB-gated: rotates the shared login role (restored)"]
async fn the_builder_completes_a_mixed_volume_at_unlock() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;
    mint_mixed_volume(
        &fixture.keys_dir,
        "the-master-passphrase",
        "the-next-passphrase",
    );
    let url = database_url();

    let router = ws_api::sealed::unlocked_router_from_envelopes(
        &fixture.keys_dir,
        &url,
        &api_config(&fixture.keys_dir),
        "the-master-passphrase",
        Some("the-next-passphrase"),
    )
    .await
    .expect("the mixed volume completes and unlocks");
    let health = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("probe the built router");
    assert_eq!(
        health.status(),
        StatusCode::OK,
        "the completed unlock serves"
    );

    // The volume converged: every envelope — the minted JWT pair
    // included — sits at generation 1 under the NEXT passphrase, and
    // the retired current opens nothing.
    for (file, generation) in volume_generations(&fixture.keys_dir).unwrap() {
        assert_eq!(generation, Some(1), "{file} advanced to generation 1");
        let opened = ws_core::crypto::KeyEnvelope::open_envelope(
            &fixture.keys_dir.join(file),
            "the-next-passphrase",
        )
        .unwrap_or_else(|e| panic!("the next passphrase opens {file}: {e}"));
        drop(opened);
        let err = ws_core::crypto::KeyEnvelope::open_envelope(
            &fixture.keys_dir.join(file),
            "the-master-passphrase",
        )
        .unwrap_err();
        assert!(
            matches!(err, ws_core::error::CoreError::Crypto(_)),
            "the retired passphrase no longer opens {file}"
        );
    }

    fixture.cleanup().await;
}

/// A `next_passphrase` against a CONSISTENT volume is refused: the
/// unlock must never become a hidden passphrase-change path, and the
/// volume is left exactly as it was.
#[tokio::test]
#[ignore = "DB-gated: the sealed-volume world (role restored)"]
async fn the_builder_refuses_a_completion_on_a_consistent_volume() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;
    mint_sealed_volume(&fixture.keys_dir, "the-master-passphrase");
    let url = database_url();

    let built = ws_api::sealed::unlocked_router_from_envelopes(
        &fixture.keys_dir,
        &url,
        &api_config(&fixture.keys_dir),
        "the-master-passphrase",
        Some("a-next-passphrase"),
    )
    .await;
    let err = built.expect_err("a consistent volume refuses the completion");
    assert!(
        err.to_string().to_lowercase().contains("no completion"),
        "the refusal names the condition, got: {err}"
    );
    for (file, generation) in volume_generations(&fixture.keys_dir).unwrap() {
        let expected = if file == ws_core::crypto::JWT_ENVELOPE_FILE {
            None
        } else {
            Some(0)
        };
        assert_eq!(generation, expected, "{file} is untouched");
        if expected.is_some() {
            ws_core::crypto::KeyEnvelope::open_envelope(
                &fixture.keys_dir.join(file),
                "the-master-passphrase",
            )
            .unwrap_or_else(|e| panic!("the refused completion leaves {file} openable: {e}"));
        }
    }
    assert!(
        bootstrap_credential_connects().await,
        "the refused completion rotates nothing"
    );

    fixture.cleanup().await;
}

/// A mixed volume unlocked WITHOUT the completion is refused with the
/// error that names the completion — the operator is never left
/// guessing which of their two passphrases the instance wants.
#[tokio::test]
#[ignore = "DB-gated: the sealed-volume world (role restored)"]
async fn the_builder_names_the_completion_a_mixed_volume_needs() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;
    mint_mixed_volume(
        &fixture.keys_dir,
        "the-master-passphrase",
        "the-next-passphrase",
    );
    let url = database_url();

    let built = ws_api::sealed::unlocked_router_from_envelopes(
        &fixture.keys_dir,
        &url,
        &api_config(&fixture.keys_dir),
        "the-master-passphrase",
        None,
    )
    .await;
    let err = built.expect_err("a bare unlock refuses a mixed volume");
    assert!(
        err.to_string().to_lowercase().contains("completion"),
        "the refusal names the completion, got: {err}"
    );
    // Nothing converged and nothing rotated: the advanced envelope still
    // opens under the NEXT passphrase, the anchor pair still under the
    // current one.
    ws_core::crypto::KeyEnvelope::open_envelope(
        &fixture
            .keys_dir
            .join(ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE),
        "the-next-passphrase",
    )
    .expect("the refused bare unlock re-wraps nothing (advanced file)");
    ws_core::crypto::KeyEnvelope::open_envelope(
        &fixture.keys_dir.join(ws_core::crypto::MASTER_ENVELOPE_FILE),
        "the-master-passphrase",
    )
    .expect("the refused bare unlock re-wraps nothing (anchor file)");
    assert!(
        bootstrap_credential_connects().await,
        "the refused bare unlock rotates nothing"
    );

    fixture.cleanup().await;
}

#[tokio::test]
async fn the_internal_unlock_post_is_rate_limited_per_ip() {
    // F1 (the final review): the internal unlock endpoint is the same
    // credential surface the public /unlock is — anything that can
    // reach the api's listener must spend a GCRA bucket credit per
    // attempt, exactly like the auth routes (spec §5.1's budget shared
    // across the credential surfaces).
    let keys = nonce_keys("rate-limit");
    let api = std::sync::Arc::new(SealedApi::new(
        std::sync::Arc::new(|req: &ws_api::sealed::UnlockRequest| {
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
        }),
        keys.clone(),
    ));
    let one_shot = Some(ws_api::AuthRateLimit {
        per_millis: 60_000,
        burst: 1,
    });
    let router = sealed_router(api, one_shot);

    let first = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/internal/unlock")
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    50003,
                ))))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "passphrase": "wrong",
                        "nonce": ws_core::crypto::mint_relay_nonce(&keys).unwrap(),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        first.status(),
        StatusCode::UNAUTHORIZED,
        "the first attempt reaches the handler and costs its bucket credit"
    );

    let second = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/internal/unlock")
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    50003,
                ))))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "passphrase": "wrong" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        second.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the bucket is spent: the second rapid attempt never reaches the handler"
    );
}

#[tokio::test]
async fn concurrent_unlocks_serialize_instead_of_double_building() {
    // F4's api half: the builder rotates the DB credential at EVERY
    // unlock, so two racing builds each ALTER + re-seal — an
    // interleaving strands the credential into the recovery runbook
    // through nothing but a double-click. The second unlock must wait
    // on the first and refuse, never reaching the build.
    use std::sync::atomic::{AtomicUsize, Ordering};
    let builds = std::sync::Arc::new(AtomicUsize::new(0));
    let counted = builds.clone();
    let keys = nonce_keys("concurrent");
    let api = std::sync::Arc::new(SealedApi::new(
        std::sync::Arc::new(move |req: &ws_api::sealed::UnlockRequest| {
            let ok = req.passphrase == "the-master-passphrase";
            counted.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                if ok {
                    Ok(full_router())
                } else {
                    Err(ws_api::error::ApiError::Unauthorized(
                        "the master passphrase was refused".to_string(),
                    ))
                }
            })
        }),
        keys.clone(),
    ));
    let req = ws_api::sealed::UnlockRequest {
        passphrase: "the-master-passphrase".to_string(),
        next_passphrase: None,
        nonce: ws_core::crypto::mint_relay_nonce(&keys).unwrap(),
    };
    let a = api.unlock(&req);
    let b = api.unlock(&req);
    let (a, b) = tokio::join!(a, b);
    let succeeded = usize::from(a.is_ok()) + usize::from(b.is_ok());
    assert_eq!(succeeded, 1, "exactly one unlock may build");
    assert_eq!(
        builds.load(Ordering::SeqCst),
        1,
        "the losing unlock never reaches the build"
    );
    assert!(
        !keys.join(ws_core::crypto::RELAY_NONCE_FILE).exists(),
        "the winner consumed the one-time claim exactly once"
    );
}

#[tokio::test]
async fn the_internal_unlock_consumes_the_one_time_volume_nonce() {
    // F2 (the final review): spec §10 — the ui→api unlock call must not
    // be replayable by anything else on the internal network. The relay
    // mints a one-time nonce into the shared keys volume and the POST
    // carries it; the api refuses a POST without the matching claim,
    // and the matching consume deletes it — a captured POST is dead
    // after the real unlock.
    let keys = nonce_keys("nonce");
    let api = std::sync::Arc::new(SealedApi::new(
        std::sync::Arc::new(|_: &ws_api::sealed::UnlockRequest| {
            Box::pin(async move { Ok(full_router()) })
        }),
        keys.clone(),
    ));
    let router = sealed_router(api, None);

    // No nonce: refused even with the passphrase the build accepts.
    let bare = router
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
        bare.status(),
        StatusCode::UNAUTHORIZED,
        "a POST without the volume's nonce is refused"
    );
    let health = axum::body::to_bytes(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body(),
        1 << 10,
    )
    .await
    .unwrap();
    assert!(
        String::from_utf8_lossy(&health).contains(r#""state":"sealed""#),
        "the refused POST unlocked nothing"
    );

    // The minted nonce unlocks — and consumes the claim.
    let nonce = ws_core::crypto::mint_relay_nonce(&keys).expect("mint the relay nonce");
    let ok = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/internal/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "passphrase": "the-master-passphrase",
                        "nonce": nonce,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK, "the minted nonce unlocks");
    assert!(
        !keys.join(ws_core::crypto::RELAY_NONCE_FILE).exists(),
        "the successful unlock consumed the claim"
    );

    // The replay: the same captured POST is dead — the claim is gone.
    let replay = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/internal/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "passphrase": "the-master-passphrase",
                        "nonce": nonce,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        replay.status(),
        StatusCode::OK,
        "the replayed POST cannot unlock again"
    );
}

#[tokio::test]
async fn a_stale_nonce_is_refused_while_the_live_claim_unlocks() {
    // F2's supersede half: each relay mint REPLACES the claim, so a
    // nonce captured from an earlier relay attempt is dead the moment
    // the ui re-offers the form — the api compares against the file,
    // not against history.
    let keys = nonce_keys("stale");
    let api = std::sync::Arc::new(SealedApi::new(
        std::sync::Arc::new(|req: &ws_api::sealed::UnlockRequest| {
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
        }),
        keys.clone(),
    ));
    let router = sealed_router(api, None);

    let stale = ws_core::crypto::mint_relay_nonce(&keys).expect("mint");
    let live = ws_core::crypto::mint_relay_nonce(&keys).expect("re-mint supersedes");
    assert_ne!(stale, live);
    let refused = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/internal/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "passphrase": "the-master-passphrase",
                        "nonce": stale,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        refused.status(),
        StatusCode::UNAUTHORIZED,
        "the superseded nonce is refused"
    );
    let ok = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/internal/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "passphrase": "the-master-passphrase",
                        "nonce": live,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK, "the live claim unlocks");
}
