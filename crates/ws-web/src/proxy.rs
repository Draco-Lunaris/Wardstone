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
use axum::Router;
use thiserror::Error;

/// Build the proxy router for the API's base URL over the internal
/// network, e.g. `http://ws-api:8080` (Task 12's `WARDSTONE_API_URL`
/// default). A trailing slash is tolerated and dropped.
pub fn api_router(api_base_url: &str) -> Router {
    let backend = Arc::new(ProxyBackend {
        client: reqwest::Client::new(),
        base: api_base_url.trim_end_matches('/').to_owned(),
    });
    Router::new()
        .route("/api/v1", any(proxy_request))
        .route("/api/v1/{*path}", any(proxy_request))
        .with_state(backend)
}

/// The proxy target: the reqwest client and the API base URL it forwards
/// to. `Clone` (the axum state bound) is cheap — the client holds its own
/// connection pool internals behind an `Arc` already, and the backend
/// wraps in `Arc`.
#[derive(Debug, Clone)]
struct ProxyBackend {
    client: reqwest::Client,
    base: String,
}

/// A proxy-side failure: the API is unreachable or misbehaved at the
/// transport level. Surfaced as a 502 so the operator sees a forwarded
/// failure, never a hang.
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
    // The exact upstream path-and-query — the API owns its own route tree
    // under /api/v1, so the prefix is forwarded unchanged, not re-based.
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    let target = format!("{}{}", backend.base, path_and_query);

    let mut request = backend.client.request(method, &target);
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
