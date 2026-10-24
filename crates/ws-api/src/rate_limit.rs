//! The house rate-limit error handler: per-IP GCRA wherever a credential
//! surface meets the network, and ONE response contract — the house JSON
//! error envelope. tower_governor's default 429 body is its own plain
//! text; the browser stack parses `{"error": {"code", "message"}}`
//! verbatim, so a plain-text 429 was a second response vocabulary on the
//! same wire (threat-model G13). The handler also re-attaches the
//! governor's own extra headers (`Retry-After`).

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tower_governor::GovernorError;

/// The house error handler for [`GovernorLayer`]: every limited route in
/// the product answers the JSON envelope, with the governor's carried
/// headers (`Retry-After`) re-attached.
///
/// Usage at a call site, exactly the pre-existing shape plus one link:
/// `GovernorLayer::new(Arc::new(config)).error_handler(house_error_handler())`.
pub fn house_error_handler() -> impl Fn(GovernorError) -> Response<Body> + Send + Sync + 'static {
    move |error| {
        let (status, message, headers): (StatusCode, String, Option<axum::http::HeaderMap>) =
            match error {
                GovernorError::TooManyRequests { wait_time, headers } => (
                    StatusCode::TOO_MANY_REQUESTS,
                    format!("too many requests; wait {wait_time}s and try again"),
                    headers,
                ),
                GovernorError::UnableToExtractKey => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "the rate-limit key could not be extracted".to_string(),
                    None,
                ),
                GovernorError::Other { code, msg, headers } => (
                    code,
                    msg.unwrap_or_else(|| "rate limiting failed".to_string()),
                    headers,
                ),
            };
        let code_tag = if status == StatusCode::TOO_MANY_REQUESTS {
            "rate_limited"
        } else {
            "internal"
        };
        let mut response = (
            status,
            axum::Json(serde_json::json!({ "error": { "code": code_tag, "message": message } })),
        )
            .into_response();
        if let Some(extra) = headers {
            response.headers_mut().extend(extra);
        }
        response
    }
}
