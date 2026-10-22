//! ws-api: the axum REST surface over `/api/v1/` — the front door of the
//! whole product.
//!
//! - `state` — [`AppState`]: the pool, the JWT key pair, the deployment
//!   config (setup hostname/SAN, the keys dir, the rate limits, the admin
//!   CIDRs collected at setup), the bounded access log, and the OIDC
//!   csrf-state store.
//! - `error` — [`ApiError`]: one enum, one JSON body shape
//!   (`{"error": {"code", "message"}}`), and the two conversion tables
//!   (`CoreError` and `AuthError`) every handler's `?` flows through.
//! - `auth_middleware` — the bearer extractor: one header, three
//!   credential shapes (session JWT, `ws_at_` API token, `ws_ot_`
//!   one-shot token — looked up but never claimed), one [`Actor`],
//!   wrapped in the orphan-rule-required newtype.
//! - `routes` — the route tree with the capability checks carried in the
//!   handlers (the plan's route→capability table is the test suite's
//!   oracle) and the audit write-side contract: every mutation commits
//!   its change and its audit entry in ONE transaction.
//!
//! The binary (Task 13) builds an [`AppState`] and serves
//! [`router(state)`].

pub mod auth_middleware;
pub mod error;
pub mod routes;
pub mod state;

/// Re-export at the crate root for the call sites that import the whole
/// vocabulary (`ws_api::error`, `ws_api::routes`, `ws_api::state`) —
/// plus the two names every consumer needs: the state and the router.
pub use error::ApiError;
pub use routes::router;
pub use state::{ApiConfig, AppState, AuthRateLimit, OidcStateStore};
