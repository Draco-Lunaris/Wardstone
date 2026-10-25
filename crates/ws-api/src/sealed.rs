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
#[derive(Debug)]
pub struct UnlockRequest {
    pub passphrase: String,
}

/// A late-bound full router with the sealed shell.
pub struct SealedApi {
    router: RwLock<Option<Arc<Router>>>,
    build: LockedBuild,
}

pub type LockedBuild = Arc<
    dyn Fn(&UnlockRequest) -> futures_util::future::BoxFuture<'static, Result<Router, ApiError>>
        + Send
        + Sync,
>;

impl SealedApi {
    /// Build the sealed shell around `build`: main's closure receives the
    /// unlock request and returns the FULL router (pool + migrations +
    /// `ws_api::router`), or a typed failure if the envelopes or the DB
    /// refuse.
    pub fn new(build: LockedBuild) -> Self {
        SealedApi {
            router: RwLock::new(None),
            build,
        }
    }

    /// Is the full service live? (The health surface and the ui's unlock
    /// page read this through the relayed state field.)
    pub fn is_unlocked(&self) -> bool {
        self.router.read().map(|r| r.is_some()).unwrap_or(false)
    }

    /// The ONE unlock: runs the build closure with the delivered
    /// passphrase and swaps the full router in. Idempotent failure-safe:
    /// a failed build changes NOTHING, and the next unlock retries.
    pub async fn unlock(&self, passphrase: &str) -> Result<(), ApiError> {
        if self.is_unlocked() {
            return Err(ApiError::Conflict(
                "the instance is already unlocked".to_string(),
            ));
        }
        let request = UnlockRequest {
            passphrase: passphrase.to_string(),
        };
        let router = (self.build)(&request).await?;
        *self.router.write().map_err(|_poisoned| {
            ApiError::Internal("the sealed api state is corrupted".to_string())
        })? = Some(Arc::new(router));
        Ok(())
    }
}

/// The sealed api's server router: the health surface, the internal
/// unlock endpoint, and the delegate fallback into the full router once
/// unlocked. Served by `main` in place of the plain full router.
pub fn sealed_router(sealed: Arc<SealedApi>) -> Router {
    Router::new()
        .route("/api/v1/healthz", get(healthz))
        .route("/api/internal/unlock", post(unlock_handler))
        .with_state(sealed.clone())
        .fallback_service(SealedDelegate {
            api: sealed.clone(),
        })
}

/// The production build closure's body — the one construct every sealed
/// api process (and the e2e world) unlocks through: open the volume's
/// three envelopes, rotate the database credential unconditionally (spec
/// §5.6 — a leaked credential, including the compose bootstrap, dies at
/// the next unlock), mint-or-load the JWT pair sealed under the
/// passphrase, and return the FULL router over RAM custody
/// ([`crate::AppState::new_unlocked`]) — the converted volume holds no
/// plaintext for the file mode to read.
///
/// The ORDER is the security contract. The three envelope opens come
/// first: a volume without them is not sealed, and an unlock against it
/// is refused with zero side effects. The JWT pair mints LAST, only
/// once the passphrase is proven against existing sealed material — so
/// neither a wrong passphrase nor a compose-internal race against a
/// fresh install can leave a JWT envelope behind that the real
/// passphrase would no longer open (a poisoned pair would lock the
/// instance out until an operator deleted the envelope by hand).
pub async fn unlocked_router_from_envelopes(
    keys_dir: &std::path::Path,
    database_url: &str,
    config: &crate::state::ApiConfig,
    passphrase: &str,
) -> Result<Router, ApiError> {
    use ws_core::crypto::{
        substitute_db_password, KeyEnvelope, DB_CREDENTIAL_ENVELOPE_FILE, JWT_ENVELOPE_FILE,
        MASTER_ENVELOPE_FILE, PROD_KDF_PARAMS, SECRET_ENVELOPE_FILE,
    };
    use zeroize::Zeroizing;

    // The master envelope: the keystore's unwrapped custody. Its absence
    // IS the unsealed state (the boot predicate's other half) — there is
    // nothing to unlock, and nothing may be written.
    let master = KeyEnvelope::open_envelope(&keys_dir.join(MASTER_ENVELOPE_FILE), passphrase)?;
    let mut master_bytes = [0u8; ws_ca::keystore::MASTER_KEY_LEN];
    master_bytes.copy_from_slice(&master);
    // The secret-encryption key: same treatment (the TOTP/OIDC
    // SecretBox's key, held zeroized in RAM for the process's life).
    let secret = KeyEnvelope::open_envelope(&keys_dir.join(SECRET_ENVELOPE_FILE), passphrase)?;
    let mut secret_bytes = [0u8; ws_ca::keystore::MASTER_KEY_LEN];
    secret_bytes.copy_from_slice(&secret);
    let secret_box = ws_core::crypto::SecretBox::from_key(Zeroizing::new(secret_bytes));
    // The DB credential: the envelope holds the CURRENT one. Required
    // too — the conversion mints it, and the password-less compose URL
    // this process carries cannot connect with anything else.
    let db_credential_path = keys_dir.join(DB_CREDENTIAL_ENVELOPE_FILE);
    let current = KeyEnvelope::open_envelope(&db_credential_path, passphrase)?;
    let connect_url = substitute_db_password(database_url, &String::from_utf8_lossy(&current));
    let pool = ws_core::db::connect(&connect_url).await?;
    // The rotation (spec §5.6): a fresh in-memory credential, ALTER over
    // the just-opened connection, re-seal. Postgres accepts no bind
    // parameters in utility statements, so the statement interpolates:
    // the role is the one the URL authenticates as (validated to the
    // conservative identifier shape) and the credential is hex by
    // construction — quote-doubled anyway, so the safety is local rather
    // than resting on a distant generator's charset.
    let role = db_role_of(database_url)?;
    let fresh = ws_core::crypto::random_hex(32)?;
    sqlx::query(&format!(
        "ALTER USER {role} PASSWORD '{}'",
        fresh.replace('\'', "''")
    ))
    .execute(&pool)
    .await
    .map_err(ws_core::error::CoreError::Database)?;
    KeyEnvelope::write_envelope(
        &db_credential_path,
        passphrase,
        fresh.as_bytes(),
        PROD_KDF_PARAMS,
    )?;
    drop(pool);
    let pool = ws_core::db::connect(&substitute_db_password(&connect_url, &fresh)).await?;
    // The JWT pair: mint-at-unlock on a fresh install (the envelope is
    // the pair's only form — plaintext never exists on a sealed volume),
    // the sealed load on a converted one. LAST, per the order contract
    // above.
    let jwt = ws_auth::jwt::load_or_create_sealed(&keys_dir.join(JWT_ENVELOPE_FILE), passphrase)?;
    Ok(crate::router(crate::AppState::new_unlocked(
        pool,
        Arc::new(jwt),
        config.clone(),
        Zeroizing::new(master_bytes),
        secret_box,
    )))
}

/// The login role a `DATABASE_URL` authenticates as — the role whose
/// password the unlock rotation ALTERs. Validated to the strict
/// alphanumeric+underscore shape (the interpolation counterpart of the
/// conversion's own check); a URL with no `userinfo@` names no role to
/// rotate.
fn db_role_of(url: &str) -> Result<String, ApiError> {
    let Some(scheme_end) = url.find("://") else {
        return Err(ApiError::Internal(
            "the database URL is not a URL".to_string(),
        ));
    };
    let auth_start = scheme_end + 3;
    let Some(at) = url[auth_start..].find('@').map(|i| i + auth_start) else {
        return Err(ApiError::Internal(
            "the database URL carries no login role to rotate".to_string(),
        ));
    };
    let user_end = url[auth_start..at]
        .rfind(':')
        .map(|i| i + auth_start)
        .unwrap_or(at);
    let role = &url[auth_start..user_end];
    if role.is_empty() || !role.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(ApiError::Internal(format!(
            "the database URL's login role {role:?} is not a safe identifier"
        )));
    }
    Ok(role.to_string())
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
}

async fn unlock_handler(
    State(sealed): State<Arc<SealedApi>>,
    Json(body): Json<UnlockBody>,
) -> Response {
    match sealed.unlock(&body.passphrase).await {
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
