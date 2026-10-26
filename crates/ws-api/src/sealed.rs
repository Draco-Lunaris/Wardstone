//! The api process's sealed mode (threat-model §4): before the operator
//! performs the unlock, the api serves ONLY the health surface (liveness +
//! the current state) and the internal unlock endpoint. Everything else —
//! the whole `/api/v1` REST surface — answers `503 sealed`.
//!
//! The unlock relay: the ui front door collects the master passphrase
//! over its TLS front door and relays it here ONCE, over the
//! compose-internal channel. The api derives the same argon2id KEK, opens
//! its envelopes (the DB credential, the JWT key pair, the master KEK),
//! builds its pool + migrations, constructs the FULL `ws_api::router`,
//! and swaps it in behind the sealed service. The passphrase then exists
//! only in the two processes' RAM.
//!
//! The late-bound pattern: `axum::serve` takes ONE router; the sealed
//! shell's fallback delegates to the full router held behind an
//! `ArcSwapOption`. Everything the full router needs exists only inside
//! the unlock handler's build closure — `main` supplies it at boot, the
//! module stays ignorant of main's configuration.

use std::sync::{Arc, RwLock};

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tower::Service;

use crate::error::ApiError;

/// The master passphrase as delivered by the unlock relay. The api derives
/// the KEK itself; the bytes are zeroized when this struct drops.
/// `next_passphrase` is non-None ONLY on the mixed-state completion (a
/// passphrase change that crashed mid-re-wrap): the unlock page re-offers
/// the completion and the operator re-enters the same `current` + `next`
/// pair (spec §5.7). `nonce` is the relay's one-time claim (spec §10,
/// the final review's F2): minted into the shared keys volume by the ui
/// process, consumed by the unlock itself — a captured POST is dead.
#[derive(Debug)]
pub struct UnlockRequest {
    pub passphrase: String,
    pub next_passphrase: Option<String>,
    pub nonce: String,
}

/// A late-bound full router with the sealed shell. The unlock is
/// serialized (the final review's F4): the builder rotates the DB
/// credential at EVERY unlock, and two racing builds would each ALTER +
/// re-seal — an interleaving can strand the credential into the
/// recovery runbook. The mutex spans the whole check→build→swap window
/// AND the relay-nonce consume, so the claim's check+delete is atomic
/// against a concurrent replay of the same POST.
pub struct SealedApi {
    router: RwLock<Option<Arc<Router>>>,
    build: LockedBuild,
    keys_dir: std::path::PathBuf,
    unlock_window: tokio::sync::Mutex<()>,
}

pub type LockedBuild = Arc<
    dyn Fn(&UnlockRequest) -> futures_util::future::BoxFuture<'static, Result<Router, ApiError>>
        + Send
        + Sync,
>;

impl SealedApi {
    /// Build the sealed shell around `build` and the shared `keys_dir`
    /// (the compose volume both processes mount): main's closure
    /// receives the unlock request and returns the FULL router (pool +
    /// migrations + `ws_api::router`), or a typed failure if the
    /// envelopes or the DB refuse. The keys dir is the relay nonce's
    /// claim home — the unlock consumes the claim file itself.
    pub fn new(build: LockedBuild, keys_dir: std::path::PathBuf) -> Self {
        SealedApi {
            router: RwLock::new(None),
            build,
            keys_dir,
            unlock_window: tokio::sync::Mutex::new(()),
        }
    }

    /// Is the full service live? (The health surface and the ui's unlock
    /// page read this through the relayed state field.)
    pub fn is_unlocked(&self) -> bool {
        self.router.read().map(|r| r.is_some()).unwrap_or(false)
    }

    /// The ONE unlock: consumes the request's one-time relay nonce, runs
    /// the build closure, and swaps the full router in. Idempotent
    /// failure-safe: a failed build changes NOTHING, and the next unlock
    /// retries. The guard spans consume, check, build, and swap — a
    /// racing replay of the same POST waits its turn and finds the claim
    /// already consumed; a racing second unlock never reaches the
    /// rotation.
    pub async fn unlock(&self, request: &UnlockRequest) -> Result<(), ApiError> {
        let _window = self.unlock_window.lock().await;
        // The one-time claim (spec §10), consumed INSIDE the serialized
        // window so the check+delete is one atomic step: a concurrent
        // replay of the same POST cannot also consume it. The refusal is
        // the generic shape — the network attacker learns nothing about
        // WHICH part of the relay was wrong. A consumed nonce is spent
        // even when the passphrase then fails: the ui's next relay
        // attempt mints a fresh claim, so the operator's retry is
        // unaffected while a captured POST dies at its first use.
        ws_core::crypto::consume_relay_nonce(&self.keys_dir, &request.nonce)
            .map_err(|e| ApiError::Unauthorized(format!("the relay nonce: {e}")))?;
        if self.is_unlocked() {
            return Err(ApiError::Conflict(
                "the instance is already unlocked".to_string(),
            ));
        }
        let router = (self.build)(request).await?;
        *self.router.write().map_err(|_poisoned| {
            ApiError::Internal("the sealed api state is corrupted".to_string())
        })? = Some(Arc::new(router));
        Ok(())
    }
}

/// The sealed api's server router: the health surface, the internal
/// unlock endpoint, and the delegate fallback into the full router once
/// unlocked. Served by `main` in place of the plain full router. The
/// internal unlock POST carries the per-IP GCRA (spec §5.1: it is the
/// same credential surface the public unlock route is, on the same
/// house budget — anything that can reach this listener spends a
/// bucket credit per guess).
pub fn sealed_router(sealed: Arc<SealedApi>, rate_limit: Option<crate::AuthRateLimit>) -> Router {
    let unlock = match rate_limit {
        Some(limit) => {
            // The auth.rs idiom verbatim: `finish()` fails only on a zero
            // burst or period (both caller-configured); a broken number is
            // a loudly-logged skip, never a panic.
            match tower_governor::governor::GovernorConfigBuilder::<
                tower_governor::key_extractor::PeerIpKeyExtractor,
                _,
            >::default()
            .per_millisecond(limit.per_millis)
            .burst_size(limit.burst)
            .finish()
            {
                Some(config) => Router::new()
                    .route("/api/internal/unlock", post(unlock_handler))
                    .with_state(sealed.clone())
                    .layer(tower_governor::GovernorLayer::new(Arc::new(config))),
                None => {
                    tracing::error!(
                        per_millis = limit.per_millis,
                        burst = limit.burst,
                        "invalid unlock rate-limit configuration: per_millis and burst must \
                         be positive; the internal unlock route runs WITHOUT rate limiting"
                    );
                    Router::new()
                        .route("/api/internal/unlock", post(unlock_handler))
                        .with_state(sealed.clone())
                }
            }
        }
        None => Router::new()
            .route("/api/internal/unlock", post(unlock_handler))
            .with_state(sealed.clone()),
    };
    Router::new()
        .route("/api/v1/healthz", get(healthz))
        .with_state(sealed.clone())
        .merge(unlock)
        .fallback_service(SealedDelegate {
            api: sealed.clone(),
        })
}

/// The production build closure's body — the one construct every sealed
/// api process (and the e2e world) unlocks through: open the volume's
/// four envelopes, rotate the database credential unconditionally (spec
/// §5.6 — a leaked credential, including the compose bootstrap, dies at
/// the next unlock), load the JWT pair from its sealed envelope, and
/// return the FULL router over RAM custody
/// ([`crate::AppState::new_unlocked`]) — the converted volume holds no
/// plaintext for the file mode to read.
///
/// The ORDER is the security contract. The four envelope opens come
/// first: a volume without the master envelope is not sealed, and an
/// unlock against it is refused with zero side effects; a sealed
/// volume missing its JWT envelope is torn or corrupt, refused by the
/// gate BEFORE any secret is unwrapped or the database touched — never
/// healed by a mint (a fresh pair would silently re-key every token).
/// The JWT pair loads LAST, only once the passphrase is proven against
/// existing sealed material — so neither a wrong passphrase nor a
/// compose-internal race can leave a JWT envelope behind that the real
/// passphrase would no longer open.
///
/// `next_passphrase` is the mixed-state completion (Task 4b, spec
/// §5.7): when a passphrase change crashed mid-re-wrap the envelope
/// generations disagree, and the unlock page re-offers the completion —
/// the operator re-enters the interrupted change's `current` (the
/// anchor still opens it; master is written LAST) plus the same `next`
/// — and the builder converges the volume BEFORE building: the
/// straggler envelopes (the master's generation, under `current`) and
/// the advanced ones (under `next`) all re-wrap to one generation
/// under `next`, and the unlock then proceeds under `next` alone. On a
/// CONSISTENT volume a `next_passphrase` is refused — the unlock must
/// never be a hidden passphrase-change path — and a mixed volume
/// without one is refused with the error that names the completion.
pub async fn unlocked_router_from_envelopes(
    keys_dir: &std::path::Path,
    database_url: &str,
    config: &crate::state::ApiConfig,
    passphrase: &str,
    next_passphrase: Option<&str>,
) -> Result<Router, ApiError> {
    use ws_core::crypto::{
        substitute_db_password, KeyEnvelope, DB_CREDENTIAL_ENVELOPE_FILE, JWT_ENVELOPE_FILE,
        MASTER_ENVELOPE_FILE, SECRET_ENVELOPE_FILE,
    };

    // The master envelope: the keystore's unwrapped custody. Its absence
    // IS the unsealed state (the boot predicate's other half) — there is
    // nothing to unlock, and nothing may be written. Its generation is
    // the volume's passphrase epoch: the rotation re-seals at it, and
    // a disagreement with the other envelopes is the mixed state a
    // crashed passphrase change leaves behind.
    let volume_generation = KeyEnvelope::read_generation(&keys_dir.join(MASTER_ENVELOPE_FILE))?;

    // The mixed-state completion (spec §5.7). Which envelopes the volume
    // actually holds decides the state: a sealed volume always carries
    // all four envelopes (setup writes them before the master marker),
    // so the scan reads what EXISTS as the mixed-state evidence. A
    // generation the file
    // cannot name (a v1 envelope, a damaged header) fails loudly right
    // here rather than misreading as a mixed volume.
    let mut present: Vec<&'static str> = Vec::new();
    for file in [
        MASTER_ENVELOPE_FILE,
        SECRET_ENVELOPE_FILE,
        DB_CREDENTIAL_ENVELOPE_FILE,
        JWT_ENVELOPE_FILE,
    ] {
        if keys_dir.join(file).exists() {
            present.push(file);
        }
    }
    let mut mixed = false;
    for file in &present {
        if KeyEnvelope::read_generation(&keys_dir.join(file))? != volume_generation {
            mixed = true;
        }
    }
    // The four states, one branch each. The completion converges the
    // volume BEFORE anything else: `rewrap_volume` opens every present
    // envelope first (a wrong `current` = zero writes, pinned in
    // ws-core) and re-wraps them all — the master anchor LAST — to one
    // advanced generation under `next`; the unlock then proceeds under
    // `next` alone. A `next` on a consistent volume is refused (the
    // unlock is never a hidden passphrase-change path), and a mixed
    // volume without one is refused naming the completion (the
    // operator is never left guessing which passphrase the instance
    // wants).
    let (passphrase, volume_generation) = match (mixed, next_passphrase) {
        (true, Some(next)) => {
            let advanced = ws_core::crypto::rewrap_volume(keys_dir, &present, passphrase, next)?;
            (next, advanced)
        }
        (true, None) => {
            return Err(ApiError::BadRequest {
                code: "completion_required",
                message: "the volume holds an unfinished passphrase change: the \
                         completion needs the current passphrase and the new one \
                         together"
                    .to_string(),
            });
        }
        (false, Some(_)) => {
            return Err(ApiError::BadRequest {
                code: "no_completion_pending",
                message: "no completion is pending on this volume: unlock without \
                          the new passphrase (the admin surface changes it once \
                          unlocked)"
                    .to_string(),
            });
        }
        (false, None) => (passphrase, volume_generation),
    };
    // The torn-volume gate (D1): a sealed volume ALWAYS carries the JWT
    // envelope — setup writes it before the master marker — so its
    // absence means the keys volume is torn or corrupt, and the unlock
    // REFUSES rather than silently re-keying every token by minting a
    // fresh pair. Checked before any secret is unwrapped or the
    // database is touched: a volume that cannot unlock must leave
    // zero side effects.
    if !present.contains(&JWT_ENVELOPE_FILE) {
        return Err(ApiError::BadRequest {
            code: "jwt_envelope_missing",
            message: format!(
                "the sealed volume is missing its jwt key envelope ({}): \
                 a sealed volume always carries one, so the keys volume is \
                 torn or corrupt — the unlock refuses rather than silently \
                 re-keying every token",
                keys_dir.join(JWT_ENVELOPE_FILE).display()
            ),
        });
    }
    // The unwrapped keys' live custody starts here: each envelope's
    // plaintext crosses straight into the protected arena, and the
    // zeroizing heap copy the envelope's KDF produced is wiped at the
    // end of its statement. (The flow is unchanged — only the custody
    // type the router receives.)
    let mem = ws_secmem::global()
        .map_err(ws_ca::keystore::protected_memory_failure)
        .map_err(ApiError::from)?;
    let master = KeyEnvelope::open_envelope(&keys_dir.join(MASTER_ENVELOPE_FILE), passphrase)?;
    let master = mem
        .alloc_copy(&master)
        .map_err(ws_ca::keystore::protected_memory_failure)
        .map_err(ApiError::from)?;
    // The secret-encryption key: same treatment (the TOTP/OIDC
    // SecretBox's key, held in the arena for the process's life).
    let secret = KeyEnvelope::open_envelope(&keys_dir.join(SECRET_ENVELOPE_FILE), passphrase)?;
    let secret = mem
        .alloc_copy(&secret)
        .map_err(ws_ca::keystore::protected_memory_failure)
        .map_err(ApiError::from)?;
    let secret_box = ws_core::crypto::SecretBox::from_key(secret);
    // The DB credential: the envelope holds the CURRENT one, and a
    // `.pending` sibling — a rotation that crashed between its ALTER
    // and its promote — may hold the one the ALTER already made live.
    // Required too: the conversion mints it, and the password-less
    // compose URL this process carries cannot connect with anything
    // else. The pending-first rule: try the pending; it connecting
    // means PROMOTE it (it is the live one), its `28P01` refusal means
    // the crash was BEFORE the ALTER — delete the stale pending and
    // connect with the current one.
    let db_credential_path = keys_dir.join(DB_CREDENTIAL_ENVELOPE_FILE);
    let candidates =
        ws_core::dbcred::open_db_credential(&db_credential_path, passphrase.as_bytes())?;
    let current_connect_url =
        substitute_db_password(database_url, &String::from_utf8_lossy(&candidates.current));
    let pool = match &candidates.pending {
        Some(pending) => {
            let pending_url =
                substitute_db_password(database_url, &String::from_utf8_lossy(pending));
            match ws_core::db::connect(&pending_url).await {
                Ok(pool) => {
                    ws_core::dbcred::promote_pending(&db_credential_path)?;
                    pool
                }
                Err(err) if invalid_password(&err) => {
                    ws_core::dbcred::discard_pending(&db_credential_path)?;
                    ws_core::db::connect(&current_connect_url).await?
                }
                Err(err) => return Err(err.into()),
            }
        }
        None => ws_core::db::connect(&current_connect_url).await?,
    };
    // The rotation (spec §5.6): the shared step
    // ([`ws_core::dbcred::rotate_db_credential`]) — fresh in-memory
    // credential, the ALTER in VERIFIER form over a dedicated
    // connection, the crash-safe pending envelope — sealed at the
    // volume's generation.
    let role = ws_core::crypto::db_role_of(database_url)?;
    let mut rotation_conn = pool
        .acquire()
        .await
        .map_err(ws_core::error::CoreError::from)?;
    let fresh = ws_core::dbcred::rotate_db_credential(
        &mut rotation_conn,
        &role,
        &db_credential_path,
        passphrase.as_bytes(),
        volume_generation,
    )
    .await?;
    drop(rotation_conn);
    drop(pool);
    let pool = ws_core::db::connect(&substitute_db_password(
        database_url,
        &String::from_utf8_lossy(&fresh),
    ))
    .await?;
    // The JWT pair: a sealed load only — the torn-volume gate above
    // already refused a missing envelope, so this open can never fall
    // back to a mint (a silent re-key of every issued token). LAST, per
    // the order contract above.
    let jwt = ws_auth::jwt::load_sealed(&keys_dir.join(JWT_ENVELOPE_FILE), passphrase.as_bytes())?;
    Ok(crate::router(crate::AppState::new_unlocked(
        pool,
        Arc::new(jwt),
        config.clone(),
        master,
        secret_box,
    )))
}

/// A Postgres `28P01` (invalid_password) refusal — the signal that a
/// `.pending` db credential the rotation never made live is stale: the
/// unlock deletes it and connects with the envelope's current one.
fn invalid_password(err: &ws_core::error::CoreError) -> bool {
    matches!(
        err,
        ws_core::error::CoreError::Database(db)
            if db.as_database_error().and_then(|e| e.code()).as_deref() == Some("28P01")
    )
}

/// Liveness is unconditional: a sealed instance answers 200 with its
/// current state so compose never churns a correctly-locked service
/// (threat-model decision: locked is a state, not a crash).
async fn healthz(State(sealed): State<Arc<SealedApi>>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "state": if sealed.is_unlocked() { "unlocked" } else { "sealed" },
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct UnlockBody {
    passphrase: String,
    /// Present only on the mixed-state completion (the unlock page
    /// re-offers it; a bare unlock POST never carries it).
    #[serde(default)]
    next_passphrase: Option<String>,
    /// The relay's one-time volume claim (spec §10): minted by the ui's
    /// relay, consumed by the unlock. Absent or wrong on any POST that
    /// did not come through the volume holder's relay.
    #[serde(default)]
    nonce: Option<String>,
}

async fn unlock_handler(
    State(sealed): State<Arc<SealedApi>>,
    Json(body): Json<UnlockBody>,
) -> Response {
    let request = UnlockRequest {
        passphrase: body.passphrase,
        next_passphrase: body.next_passphrase,
        nonce: body.nonce.unwrap_or_default(),
    };
    match sealed.unlock(&request).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "state": "unlocked" })),
        )
            .into_response(),
        Err(ApiError::Conflict(message)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": { "code": "already_unlocked", "message": message }
            })),
        )
            .into_response(),
        // The completion refusals (the builder's two volume-state
        // conditions): 409 with their own code — the relayed body is
        // what the operator reads on the unlock page, and a mixed
        // volume must say "completion", never a misleading
        // "passphrase refused".
        Err(ApiError::BadRequest { code, message }) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": { "code": code, "message": message }
            })),
        )
            .into_response(),
        Err(err) => {
            // The detail goes to stderr; the body carries the generic
            // refusal (the unlock failure may carry envelope internals).
            tracing::error!(error = %err, "an unlock attempt was refused");
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": { "code": "unlock_failed",
                        "message": "the master passphrase was refused; the instance is unchanged" }
                })),
            )
                .into_response()
        }
    }
}

/// The delegate fallback: while sealed, 503 + the typed code; unlocked,
/// the request is handled by the full router (a Router clone shares the
/// underlying service state by design). The future type is Router's own —
/// already boxed behind an Infallible error, so delegation is exact.
#[derive(Clone)]
struct SealedDelegate {
    api: Arc<SealedApi>,
}

impl Service<Request<Body>> for SealedDelegate {
    type Response = Response;
    type Error = std::convert::Infallible;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        match self.api.router.read() {
            Ok(guard) => match guard.as_ref() {
                Some(router) => {
                    let mut service = Router::clone(router);
                    Box::pin(Service::call(&mut service, request))
                }
                None => Box::pin(async { Ok(sealed_503()) }),
            },
            Err(_) => Box::pin(async { Ok(sealed_503()) }),
        }
    }
}
fn sealed_503() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": { "code": "sealed",
                "message": "the instance is sealed: unlock to continue" }
        })),
    )
        .into_response()
}
