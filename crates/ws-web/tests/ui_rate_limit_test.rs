//! The Task 13 GCRA limiter on the `/auth/ui` nest, NON-DB.
//!
//! The suite pins three properties of [`ws_web::session::relay_router`]'s
//! GovernorLayer:
//!
//! 1. two rapid logins from the SAME peer IP — the second is 429 (the
//!    exact shape ws-api's default `GovernorLayer` produces: a plain 429
//!    with `Retry-After`, the body naming the wait);
//! 2. keying is per-IP (a different socket from the same IP is still
//!    limited; a different loopback alias keeps its own bucket) and the
//!    layer covers the WHOLE nest (login, oidc start, logout), not just
//!    login;
//! 3. `None` mounts nothing.
//!
//! No database, no upstream, no real sockets: the router is driven
//! in-process through `tower::ServiceExt::oneshot`, with the peer address
//! the `PeerIpKeyExtractor` keys on injected as `ConnectInfo` in the
//! request's extensions — the exact `extension` the real TLS listener's
//! `into_make_service_with_connect_info::<SocketAddr>()` (Task 11) fills
//! per connection. Simpler than serving the router on an ephemeral port
//! and dialing two TCP clients, and it asserts the same key-extraction
//! code path.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Request, Response, StatusCode};
use tower::ServiceExt;
use ws_api::AuthRateLimit;
use ws_web::session::{relay_router, SessionStore};

/// Burst of 1 with a refill period far longer than any test run: the
/// FIRST request from an IP spends the whole bucket and every later one
/// inside the window is 429 — the sharpest assertion the burst semantics
/// allow.
const ONE_SHOT: Option<AuthRateLimit> = Some(AuthRateLimit {
    per_millis: 60_000,
    burst: 1,
});

/// Nothing listens here: any relayed login/OIDC start that PASSED the
/// limiter deterministically answers 502 (the connection-refused
/// `ProxyError`), while a limited request never reaches the relay at all.
const DEAD_API: &str = "http://127.0.0.1:1";

/// The two loopback alias IPs the test keys buckets on (both are
/// loopback; neither is actually dialed — the addresses are injected, so
/// the alias form `127.0.0.{2-}` just has to be a valid `SocketAddr`).
const PEER_A: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const PEER_B: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// The relay router the tests drive: one store, the dead upstream, and
/// the test's `rate_limit` choice.
fn relay_router_for(rate_limit: Option<AuthRateLimit>) -> axum::Router {
    relay_router(
        std::sync::Arc::new(SessionStore::new(std::time::Duration::from_secs(60))),
        DEAD_API,
        rate_limit,
    )
}

/// Build one relay request whose extensions carry the `ConnectInfo` the
/// per-IP key extractor reads (`body` is the JSON for POST routes; empty
/// for the GET passthroughs).
fn request_from(ip: Ipv4Addr, port: u16, method: &str, uri: &str, body: &[u8]) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        // The login route's `Json` extractor refuses a bodyless/content-
        // typeless request with 415 before anything else reads it.
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_vec()))
        .expect("build the relay request");
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(IpAddr::from(ip), port)));
    request
}

fn login_from(ip: Ipv4Addr, port: u16) -> Request<Body> {
    request_from(
        ip,
        port,
        "POST",
        "/auth/ui/login",
        br#"{"username":"u","password":"p"}"#,
    )
}

fn oidc_start_from(ip: Ipv4Addr, port: u16) -> Request<Body> {
    request_from(ip, port, "GET", "/auth/ui/oidc/github/start", b"")
}

fn logout_from(ip: Ipv4Addr, port: u16) -> Request<Body> {
    request_from(ip, port, "POST", "/auth/ui/logout", b"")
}

/// Drive one request through the router. (Test-only unwrappers.)
async fn send(router: &axum::Router, request: Request<Body>) -> Response<Body> {
    router
        .clone()
        .oneshot(request)
        .await
        .expect("the router should respond")
}

/// Property 1: the first login from an IP passes (and fails at the dead
/// relay target — 502, never 429), the second from the SAME IP — on a
/// DIFFERENT local port, so the bucket is keyed per-IP, not per-socket —
/// is 429, with the default `GovernorLayer` shape ws-api's auth routes
/// answer with (the UI must treat both limiters identically).
#[tokio::test]
async fn second_login_from_the_same_ip_is_429() {
    let router = relay_router_for(ONE_SHOT);

    let first = send(&router, login_from(PEER_A, 44444)).await;
    assert_eq!(
        first.status(),
        StatusCode::BAD_GATEWAY,
        "the first login passes the limiter and dies at the relay target"
    );

    let second = send(&router, login_from(PEER_A, 55555)).await;
    assert_eq!(
        second.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a rapid second login from the same peer IP is limited"
    );
    assert!(
        second.headers().get(header::RETRY_AFTER).is_some(),
        "the default tower_governor 429 carries Retry-After (the shape ws-api answers with)"
    );
}

/// Property 2, both halves: the layer covers every `/auth/ui` route (an
/// oidc start and a logout from the exhausted IP are both limited) and
/// the buckets are per-IP (a fresh loopback alias — PEER_B, its own
/// `ConnectInfo` — still gets through: its logout is the quiet in-process
/// 204 a cookie-less logout answers).
#[tokio::test]
async fn the_whole_nest_is_limited_but_buckets_are_per_ip() {
    let router = relay_router_for(ONE_SHOT);

    let first = send(&router, login_from(PEER_A, 44444)).await;
    assert_eq!(first.status(), StatusCode::BAD_GATEWAY);

    assert_eq!(
        send(&router, oidc_start_from(PEER_A, 45444)).await.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the oidc start route shares the IP's bucket"
    );
    assert_eq!(
        send(&router, logout_from(PEER_A, 46444)).await.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the logout route shares the IP's bucket"
    );

    assert_eq!(
        send(&router, logout_from(PEER_B, 44444)).await.status(),
        StatusCode::NO_CONTENT,
        "PEER_B's bucket is empty: a cookie-less logout answers its quiet 204"
    );
}

/// Property 3: `None` mounts no layer — a burst of same-IP logins is
/// never limited (each dies at the relay target instead).
#[tokio::test]
async fn rate_limit_none_mounts_no_layer() {
    let router = relay_router_for(None);

    for _ in 0..5 {
        let response = send(&router, login_from(PEER_A, 44444)).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_GATEWAY,
            "an unlimited nest never answers 429"
        );
    }
}
