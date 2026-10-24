//! ws-api: the axum REST surface over `/api/v1/` — the front door of the
//! whole product.
//!
//! - `state` — [`AppState`]: the pool, the JWT key pair, the deployment
//!   config (setup hostname/SAN, the keys dir, the rate limits, the admin
//!   CIDRs collected at setup, the ACME URL base), the bounded access
//!   log, the OIDC csrf-state store, and the ACME nonce ledger.
//! - `error` — [`ApiError`]: one enum, one JSON body shape
//!   (`{"error": {"code", "message"}}`), and the two conversion tables
//!   (`CoreError` and `AuthError`) every handler's `?` flows through.
//! - `auth_middleware` — the bearer extractor: one header, two
//!   credential shapes (session JWT, `ws_at_` API token), one [`Actor`],
//!   wrapped in the orphan-rule-required newtype. A `ws_ot_` one-shot
//!   bearer is refused here without a lookup: it redeems only at the
//!   certificate pull route.
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
pub mod sealed;
pub mod state;

/// Re-export at the crate root for the call sites that import the whole
/// vocabulary (`ws_api::error`, `ws_api::routes`, `ws_api::state`) —
/// plus the two names every consumer needs: the state and the router.
pub use error::ApiError;
pub use routes::router;
pub use state::{AcmeConfig, ApiConfig, AppState, AuthRateLimit, OidcStateStore, VerificationDeps};
