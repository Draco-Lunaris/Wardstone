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

pub type LockedBuild = Arc<dyn Fn(&UnlockRequest) -> Result<Router, ApiError> + Send + Sync>;

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
    pub fn unlock(&self, passphrase: &str) -> Result<(), ApiError> {
        if self.is_unlocked() {
            return Err(ApiError::Conflict(
                "the instance is already unlocked".to_string(),
            ));
        }
        let request = UnlockRequest {
            passphrase: passphrase.to_string(),
        };
        let router = (self.build)(&request)?;
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
    match sealed.unlock(&body.passphrase) {
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
