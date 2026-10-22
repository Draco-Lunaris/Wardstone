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
use std::time::Instant;

use axum::body::{Body, Bytes};
use axum::extract::{Extension, State};
use axum::http::{
    header, HeaderMap, HeaderName, Method, Response as HttpResponse, StatusCode, Uri,
};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::{Json, Router};
use thiserror::Error;

use crate::session::relay::{rotate_once, RotationOutcome};
use crate::session::store::SessionStore;
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
/// failure travels as `ProxyBackend.client == None`. The session relay
/// builds its client with the same constructor.
pub(crate) fn proxy_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .connect_timeout(PROXY_CONNECT_TIMEOUT)
        .timeout(PROXY_TOTAL_TIMEOUT)
        // Never follow redirects: the front door's contract is VERBATIM
        // passthrough — ws-api's redirect responses (the OIDC start's
        // authorization URL) travel to the caller untouched; a following
        // client would chase `https://sso.….test/…` itself, turn a 303
        // into a transport failure, and erase the Location the caller
        // needs.
        .redirect(reqwest::redirect::Policy::none())
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
pub struct ProxyError(pub(crate) String);

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_GATEWAY, self.0).into_response()
    }
}

/// Forward one request.
async fn proxy_request(
    State(backend): State<Arc<ProxyBackend>>,
    session_store: Option<Extension<Arc<SessionStore>>>,
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
    if let Some(refusal) = csrf_refusal(&method, &headers) {
        return Ok(refusal);
    }

    // The exact upstream path-and-query — the API owns its own route tree
    // under /api/v1, so the prefix is forwarded unchanged, not re-based.
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());

    let Some(client) = backend.client.as_ref() else {
        return Err(ProxyError(
            "the proxy HTTP client could not be initialized".to_owned(),
        ));
    };

    // Task 12 — session resolution: a request presenting the session
    // cookie whose id resolves in the store is a BROWSER SESSION; it gets
    // the stored access token injected (replacing any caller-supplied
    // Authorization: the cookie session IS the credential). Machine-token
    // requests (no cookie, or an unknown/expired cookie) forward exactly
    // as before, Authorization header and all.
    let session = match (session_store.as_ref(), session::read_session_id(&headers)) {
        (Some(Extension(store)), Some(id)) => {
            store.get(id).await.map(|entry| (store.clone(), id, entry))
        }
        _ => None,
    };

    // Expiry FIRST (the cheap local check): a fresh token is injected and
    // forwarded; a stale one skips straight to the rotation section below.
    let injected: Option<String> = session.as_ref().and_then(|(_, _, entry)| {
        (entry.access_expires_at > Instant::now()).then(|| entry.access_token.clone())
    });

    // Stale per bookkeeping: rotate BEFORE forwarding. At most ONE forward
    // happens after the rotation (the "retry the request ONCE" pin) — a
    // fresh token that ws-api still rejects passes through verbatim.
    if let Some((store, id, entry)) = &session {
        if injected.is_none() {
            return match rotate_once(
                store,
                *id,
                entry,
                &entry.access_token,
                client,
                &backend.base,
            )
            .await
            {
                RotationOutcome::Died => Ok(session_expired_response()),
                RotationOutcome::Fresh { access, .. } => {
                    forward_one(
                        client,
                        &backend.base,
                        &method,
                        &path_and_query,
                        &headers,
                        body.clone(),
                        Some(&access),
                    )
                    .await
                }
            };
        }
    }

    let response = forward_one(
        client,
        &backend.base,
        &method,
        &path_and_query,
        &headers,
        body.clone(),
        injected.as_deref(),
    )
    .await?;

    // Mid-flight 401 on an INJECTED request: the token died between our
    // bookkeeping and the API's answer (revoked remotely, clock skew).
    // ONE locked rotation, then one retry — never more.
    let Some((store, id, entry)) = session else {
        return Ok(response);
    };
    if response.status() != StatusCode::UNAUTHORIZED {
        return Ok(response);
    }
    let observed: &str = injected.as_deref().unwrap_or(entry.access_token.as_str());
    match rotate_once(&store, id, &entry, observed, client, &backend.base).await {
        RotationOutcome::Died => Ok(session_expired_response()),
        RotationOutcome::Fresh { access, .. } => {
            forward_one(
                client,
                &backend.base,
                &method,
                &path_and_query,
                &headers,
                body,
                Some(&access),
            )
            .await
        }
    }
}

/// One verbatim forward to the API base: method, path-and-query, headers
/// (minus the hop-by-hop set), and the full buffered body. `authorization`
/// replaces the caller's `Authorization` header (session injection) — when
/// `None` the caller's own header travels unchanged (machine tokens).
async fn forward_one(
    client: &reqwest::Client,
    base: &str,
    method: &Method,
    path_and_query: &str,
    headers: &HeaderMap,
    body: Bytes,
    authorization: Option<&str>,
) -> Result<Response, ProxyError> {
    let target = format!("{base}{path_and_query}");
    let mut request = client.request(method.clone(), &target);
    for (name, value) in headers {
        // Host and the hop-by-hop set are transport concerns the forward
        // re-derives; everything else is the caller's and travels
        // unchanged — unless a session token is being injected, in which
        // case any caller-supplied Authorization is dropped first.
        if is_hop_by_hop(name) {
            continue;
        }
        if authorization.is_some() && name.as_str() == "authorization" {
            continue;
        }
        request = request.header(name.clone(), value.clone());
    }
    if let Some(authorization) = authorization {
        request = request.header(header::AUTHORIZATION, format!("Bearer {authorization}"));
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

/// A dead session's refusal: ws-web's OWN response (not a passthrough —
/// the session that would have authenticated no longer exists): 401 with
/// the API-standard error envelope, `session expired` spelled out, and
/// the clearing cookie so the browser forgets the dead id immediately.
fn session_expired_response() -> Response {
    // StatusCode leads: axum's tuple impls take the status only as the
    // FIRST element (it is not an IntoResponseParts).
    (
        StatusCode::UNAUTHORIZED,
        [(header::SET_COOKIE, session::build_session_cookie_clear())],
        Json(serde_json::json!({
            "error": {
                "code": "unauthorized",
                "message": "session expired"
            }
        })),
    )
        .into_response()
}

/// The CSRF rule as a reusable refusal for every cookie-carrying mutating
/// route (the proxy's `/api/v1/*` AND the relay's `/auth/ui/logout` /
/// `/auth/ui/login`): a session cookie with no `X-Requested-With:
/// wardstone-ui` marker is refused here, 403, before any relay or forward.
pub(crate) fn csrf_refusal(method: &Method, headers: &HeaderMap) -> Option<Response> {
    if matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) && session::read_session_id(headers).is_some()
        && !has_csrf_header(headers)
    {
        Some(csrf_forbidden_response())
    } else {
        None
    }
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
