//! The `/api/v1` path proxy: the browser talks ONLY to ws-web; the API
//! process publishes no ports to the LAN.
//!
//! Every `/api/v1*` request is forwarded VERBATIM to the API's base URL
//! over the internal network (`reqwest`): the method, the headers minus
//! the hop-by-hop set (and `Host`, which the transport re-derives), the
//! exact path-and-query, and the full body. The response streams back
//! with the upstream status and headers, minus the same hop-by-hop set.
//! ws-api's routes are never mounted here — the two are separate,
//! independently restartable processes (the spec's anti-goal rules out one
//! process serving both).

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, Method, Response as HttpResponse, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::{Json, Router};
use thiserror::Error;

use crate::session::{self, CSRF_HEADER_NAME, CSRF_HEADER_VALUE};

/// The proxy's connect timeout: an unreachable API process must fail the
/// forward quickly, not pin the browser request while TCP retries.
const PROXY_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The proxy's total request timeout (connect through full response
/// body). Generous for the API's interactive surface, but finite: a
/// dropped-packet upstream must end in a typed 502 rather than wedging
/// the ws-web connection indefinitely.
const PROXY_TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Build the proxy router for the API's base URL over the internal
/// network, e.g. `http://ws-api:8080` (Task 12's `WARDSTONE_API_URL`
/// default). A trailing slash is tolerated and dropped.
pub fn api_router(api_base_url: &str) -> Router {
    // Both timeouts are deliberate: without them a black-holing upstream
    // holds the browser request open with no bound, and this front door
    // becomes a wedge vector. The client fails fast on connect and gives
    // the API a generous-but-finite total to answer. The construction is
    // fallible per the house rule (no panics in library code), so a failed
    // build — an essentially unreachable TLS-backend init error — is
    // carried as a fail-closed per-request 502, never an unbounded
    // fallback client.
    let backend = Arc::new(ProxyBackend {
        client: proxy_client().ok(),
        base: api_base_url.trim_end_matches('/').to_owned(),
    });
    Router::new()
        .route("/api/v1", any(proxy_request))
        .route("/api/v1/{*path}", any(proxy_request))
        .with_state(backend)
}

/// The proxy's reqwest client: the bounded construction (connect and
/// total timeouts; the ws-auth `oidc::http_client` precedent for fallible
/// client builds). `api_router`'s pinned signature is infallible, so its
/// failure travels as `ProxyBackend.client == None`.
fn proxy_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .connect_timeout(PROXY_CONNECT_TIMEOUT)
        .timeout(PROXY_TOTAL_TIMEOUT)
        .build()
}

/// The proxy target: the reqwest client (unless the per-config
/// construction failed — then every forward fails closed) and the API base
/// URL it forwards to. `Clone` (the axum state bound) is cheap — the
/// client holds its own connection pool internals behind an `Arc` already,
/// and the backend wraps in `Arc`.
#[derive(Debug, Clone)]
struct ProxyBackend {
    client: Option<reqwest::Client>,
    base: String,
}

/// A proxy-side failure: the API is unreachable, misbehaved at the
/// transport level, or timed out (the client's bounded connect and total
/// request timeouts turn a black-holing upstream into an error instead of
/// an unbounded hang). Surfaced as a 502 so the operator sees a forwarded
/// failure.
#[derive(Debug, Error)]
#[error("the API process is unreachable: {0}")]
pub struct ProxyError(String);

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_GATEWAY, self.0).into_response()
    }
}

/// Forward one request.
async fn proxy_request(
    State(backend): State<Arc<ProxyBackend>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ProxyError> {
    // The CSRF rule (Task 11): a request that presents a `wardstone_session`
    // cookie and mutates (POST/PUT/PATCH/DELETE) must also carry
    // `X-Requested-With: wardstone-ui` — the marker the Wardstone UI sets on
    // its own fetches. A cross-site form post carries the browser's cookies
    // but cannot set the header, so session cookies bought with a stolen
    // login cannot be spent by third-party pages. Requests WITHOUT the
    // session cookie (machine tokens, the pull flow) pass through
    // untouched; the session id is only detected here, not yet resolved
    // (Task 12 wires the store — the rule is detection-based until then).
    if matches!(
        method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) && session::read_session_id(&headers).is_some()
        && !has_csrf_header(&headers)
    {
        return Ok(csrf_forbidden_response());
    }

    // The exact upstream path-and-query — the API owns its own route tree
    // under /api/v1, so the prefix is forwarded unchanged, not re-based.
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    let target = format!("{}{}", backend.base, path_and_query);

    let Some(client) = backend.client.as_ref() else {
        return Err(ProxyError(
            "the proxy HTTP client could not be initialized".to_owned(),
        ));
    };
    let mut request = client.request(method, &target);
    for (name, value) in &headers {
        // Host and the hop-by-hop set are transport concerns the forward
        // re-derives; everything else (Authorization included) is the
        // caller's and travels unchanged.
        if is_hop_by_hop(name) {
            continue;
        }
        request = request.header(name.clone(), value.clone());
    }

    let upstream = request
        .body(body.to_vec())
        .send()
        .await
        .map_err(|err| ProxyError(err.to_string()))?;

    let status = upstream.status();
    let upstream_headers = upstream.headers().clone();
    let payload = upstream
        .bytes()
        .await
        .map_err(|err| ProxyError(err.to_string()))?;

    let mut response = HttpResponse::builder().status(status);
    for (name, value) in &upstream_headers {
        // The same rule in reverse; the body is a finite Bytes copy, so
        // Content-Length is re-derived by this response's transport too.
        if is_hop_by_hop(name) {
            continue;
        }
        response = response.header(name.clone(), value.clone());
    }
    response
        .body(Body::from(payload))
        .map_err(|err| ProxyError(format!("the forwarded response broke: {err}")))
}

/// The hop-by-hop header set (RFC 7230 section 6.1) plus the transport
/// re-derived ones (`host`, `content-length`): never copied across the
/// proxy hop in either direction.
fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "upgrade"
    )
}

/// Does the request carry the CSRF marker header with the required value?
/// A header present but not decodable as UTF-8, or present with any other
/// value, is not the marker: fail closed.
fn has_csrf_header(headers: &HeaderMap) -> bool {
    headers
        .get(CSRF_HEADER_NAME)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == CSRF_HEADER_VALUE)
}

/// The rule's refusal: `403 Forbidden` with the API-standard error envelope,
/// shape-consistent with ws-api's responses but distinct from the proxy's
/// transport failures (a `ProxyError` is upstream-side; this is a request
/// this front door refuses itself).
fn csrf_forbidden_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": {
                "code": "forbidden",
                "message": "missing wardstone-ui request header"
            }
        })),
    )
        .into_response()
}
