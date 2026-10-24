//! The API error vocabulary: one enum, one JSON body shape, and the two
//! conversion tables every handler's `?` flows through.
//!
//! The JSON body of every error is `{"error": {"code": ..., "message":
//! ...}}` — a single shape so the SPA's error handling is total. The
//! status mapping is the plan's:
//!
//! | variant | status |
//! |---|---|
//! | [`ApiError::BadRequest`] (and the `not_permitted_by_profile` case) | 400 |
//! | [`ApiError::Unauthorized`] | 401 |
//! | [`ApiError::UnauthorizedMfa`] | 401 (code `mfa_required`) |
//! | [`ApiError::Forbidden`] | 403 |
//! | [`ApiError::NotFound`] | 404 |
//! | [`ApiError::Conflict`] | 409 |
//! | [`ApiError::RateLimited`] | 429 |
//! | [`ApiError::Internal`] | 500 |
//!
//! Two conversion tables feed `impl<E> From<E> for ApiError`:
//!
//! - [`from_core_error`] — the `CoreError` mapping: `Database`/`Migration`
//!   → 500, `Duplicate` → 409, `Forbidden` → 403, and `Config` → **500**
//!   (a corrupt stored profile is a server-side data problem, not a client
//!   error).
//! - `From<AuthError>` — a SEPARATE conversion, because `AuthError` lives
//!   in `ws-auth` and can never be produced by a function whose parameter
//!   is a `CoreError`. The auth flows map credential problems to 401,
//!   capability/account problems to 403, and rate limiting to 429.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use thiserror::Error;

use ws_auth::error::AuthError;
use ws_ca::error::CaError;
use ws_core::error::CoreError;

/// The error type of the REST surface.
#[derive(Debug, Error)]
pub enum ApiError {
    /// A malformed request (validation failure). `code` is the machine
    /// code in the JSON body — usually `bad_request`, but specific
    /// validation outcomes carry their own code (a rejected SAN is 400
    /// with code `not_permitted_by_profile`: a name the profile does not
    /// permit is distinct from `Forbidden` 403, which means "you may not
    /// do this at all").
    #[error("{message}")]
    BadRequest {
        /// Machine code in the JSON body.
        code: &'static str,
        /// Human-readable message.
        message: String,
    },
    /// Authentication failed (401).
    #[error("{0}")]
    Unauthorized(String),
    /// Authentication NEEDS a multi-factor code (401) — its own variant
    /// so the body code is `mfa_required`, not `unauthorized`, and the
    /// SPA can route the user to the MFA prompt instead of the generic
    /// login-failure path.
    #[error("{0}")]
    UnauthorizedMfa(String),
    /// Authorization failed: the actor may not do this at all (403).
    #[error("{0}")]
    Forbidden(String),
    /// The requested resource does not exist — or belongs to another
    /// tenant, which MUST be indistinguishable (404).
    #[error("{0}")]
    NotFound(String),
    /// The request conflicts with existing state (409).
    #[error("{0}")]
    Conflict(String),
    /// Too many requests (429).
    #[error("{0}")]
    RateLimited(String),
    /// An internal failure the client cannot fix (500). The message is
    /// static and never carries credentials.
    #[error("{0}")]
    Internal(String),
}

/// The JSON body shape of every error response.
#[derive(Serialize)]
struct ApiErrorBody {
    error: ApiErrorMessage,
}

/// The `error` object of the body.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct ApiErrorMessage {
    code: &'static str,
    message: String,
}

impl ApiError {
    /// A plain bad request (code `bad_request`).
    pub fn bad_request(message: impl Into<String>) -> Self {
        ApiError::BadRequest {
            code: "bad_request",
            message: message.into(),
        }
    }

    /// A name the profile does not permit: 400 with the code
    /// `not_permitted_by_profile` — distinct from 403, which means "you
    /// may not do this at all". The message is either the specific
    /// constraint name (for actors who may read the profile) or the
    /// generic policy refusal (for everyone else); it NEVER dumps the
    /// permitted set.
    pub fn not_permitted_by_profile(message: impl Into<String>) -> Self {
        ApiError::BadRequest {
            code: "not_permitted_by_profile",
            message: message.into(),
        }
    }

    /// The generic 500: one message for every server-side failure whose
    /// detail the operator gets from the log, never the response body
    /// (threat-model G9). `Database`/`Config`/`Crypto` details are logged,
    /// not sent — the response body carries only what the client could act
    /// on, which for an internal failure is nothing.
    pub fn internal_generic() -> Self {
        ApiError::Internal("an internal server error occurred".to_string())
    }

    /// The machine code this error renders in its JSON body.
    fn code(&self) -> &'static str {
        match self {
            ApiError::BadRequest { code, .. } => code,
            ApiError::Unauthorized(_) => "unauthorized",
            ApiError::UnauthorizedMfa(_) => "mfa_required",
            ApiError::Forbidden(_) => "forbidden",
            ApiError::NotFound(_) => "not_found",
            ApiError::Conflict(_) => "conflict",
            ApiError::RateLimited(_) => "rate_limited",
            ApiError::Internal(_) => "internal",
        }
    }

    /// The HTTP status this error renders.
    fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest { .. } => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::UnauthorizedMfa(_) => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The error's human-readable message (the `Display` text).
    fn message(&self) -> String {
        match self {
            ApiError::BadRequest { message, .. } => message.clone(),
            ApiError::Unauthorized(m)
            | ApiError::UnauthorizedMfa(m)
            | ApiError::Forbidden(m)
            | ApiError::NotFound(m)
            | ApiError::Conflict(m)
            | ApiError::RateLimited(m)
            | ApiError::Internal(m) => m.clone(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = ApiErrorBody {
            error: ApiErrorMessage {
                code: self.code(),
                message: self.message(),
            },
        };
        (status, Json(body)).into_response()
    }
}

/// The `CoreError` → `ApiError` mapping table (the plan's):
///
/// - `Database` → **500 (generic)**: the sqlx detail is logged for the
///   operator, never sent (threat-model G9);
/// - `Migration` → **500 (generic)**, for the same reason;
/// - `Duplicate` → `Conflict` 409;
/// - `Forbidden` → `Forbidden` 403 (a missing capability is
///   authorization, not authentication);
/// - `Config` / `Crypto` → **500 (generic)**: server-side problems whose
///   stored-profile detail is logged, not sent.
///
impl From<CoreError> for ApiError {
    fn from(err: CoreError) -> Self {
        match err {
            CoreError::Database(e) => {
                tracing::error!(error = %e, "a database error reached the API surface");
                ApiError::internal_generic()
            }
            CoreError::Migration { expected, found } => {
                tracing::error!(expected, found, "migration count mismatch");
                ApiError::internal_generic()
            }
            CoreError::Duplicate => ApiError::Conflict("the resource already exists".to_string()),
            CoreError::Forbidden => ApiError::Forbidden("missing required capability".to_string()),
            CoreError::Config(message) => {
                tracing::error!(error = %message, "a config error reached the API surface");
                ApiError::internal_generic()
            }
            CoreError::Crypto(message) => {
                tracing::error!(error = %message, "a crypto error reached the API surface");
                ApiError::internal_generic()
            }
        }
    }
}

/// The `AuthError` → `ApiError` mapping — a SEPARATE conversion, because
/// `AuthError` lives in `ws-auth` and cannot be produced by a function
/// taking a `CoreError`. Exhaustive over the frozen twelve variants:
///
/// - `Forbidden` → 403 (authorization, not authentication);
/// - `BadCredentials` / `TokenInvalid` / `TokenExpired` → 401;
/// - `MfaRequired` → 401 as [`ApiError::UnauthorizedMfa`] (body code
///   `mfa_required` — a structured signal, not the generic failure);
/// - `MfaInvalid` → 401;
/// - `AccountLocked` / `AccountDisabled` → 403;
/// - `RateLimited` → 429;
/// - `NotFound` → 404;
/// - `Config` / `Crypto` → 500.
impl From<AuthError> for ApiError {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::Forbidden => ApiError::Forbidden("missing required capability".to_string()),
            AuthError::BadCredentials => ApiError::Unauthorized("invalid credentials".to_string()),
            AuthError::TokenInvalid => ApiError::Unauthorized("token is invalid".to_string()),
            AuthError::TokenExpired => ApiError::Unauthorized("token has expired".to_string()),
            AuthError::MfaRequired => {
                ApiError::UnauthorizedMfa("multi-factor authentication required".to_string())
            }
            AuthError::MfaInvalid => {
                ApiError::Unauthorized("invalid multi-factor code".to_string())
            }
            AuthError::AccountLocked => ApiError::Forbidden("account is locked".to_string()),
            AuthError::AccountDisabled => ApiError::Forbidden("account is disabled".to_string()),
            AuthError::RateLimited => ApiError::RateLimited("rate limit exceeded".to_string()),
            AuthError::NotFound => ApiError::NotFound("not found".to_string()),
            // Deployment-shaped failures (discovery/JWKS/token-endpoint
            // transport) carry provider URLs and ports — logged for the
            // operator, generalized for the wire (threat-model G9).
            AuthError::Config(message) => {
                tracing::error!(error = %message, "an auth config error reached the API surface");
                ApiError::internal_generic()
            }
            AuthError::Crypto(message) => {
                tracing::error!(error = %message, "an auth crypto error reached the API surface");
                ApiError::internal_generic()
            }
        }
    }
}

/// The `CaError` → `ApiError` mapping: malformed CSR input or an
/// unsupported key is the CLIENT's error (400); everything else — keystore
/// damage, rcgen failure, a missing envelope — is server-side (500).
impl From<CaError> for ApiError {
    fn from(err: CaError) -> Self {
        match err {
            CaError::X509(message) => ApiError::bad_request(message),
            CaError::UnsupportedKeyType(message) => ApiError::bad_request(message),
            other => {
                tracing::error!(error = %other, "a certificate-authority error reached the API surface");
                ApiError::internal_generic()
            }
        }
    }
}

/// A raw sqlx error (transaction begin/commit outside the repos' typed
/// surface) is a database failure: 500.
impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        tracing::error!(error = %err, "a database error reached the API surface");
        ApiError::internal_generic()
    }
}

/// The `CoreError` mapping table as a free function (the plan names it
/// `from_core_error`); the `From` impl above is the same mapping and the
/// `?` operator uses it.
pub fn from_core_error(err: CoreError) -> ApiError {
    ApiError::from(err)
}
