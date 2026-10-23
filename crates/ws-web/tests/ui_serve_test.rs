//! Integration tests for `ws-web`'s UI serving (Task 11): the embedded
//! `ui/dist` SPA router (index, hashed assets, the SPA fallback), the
//! session-cookie module's round trip, and the proxy's CSRF header rule.
//!
//! These tests are NON-DB: no pool, no advisory key, no rows touched. The
//! composition under test mirrors [`ws_web::web_router`]'s shape (which
//! needs a pool) — an API router mounted FIRST and `ws_web::ui::ui_router`
//! mounted LAST as the composed router's fallback, so the suite proves the
//! fallback only ever runs when no earlier route matched. Two
//! compositions drive the two halves:
//!
//! - a stub `/api/v1/healthz` route + the ui fallback (router-shape
//!   tests: API precedence never masked, SPA routes served);
//! - the REAL `api_router` aimed at a dead loopback port (CSRF-rule
//!   tests: what passes the check then 502s at the unreachable upstream);
//! - the REAL `acme_router`, and the composed
//!   `session_router_with_store` (relay + api proxy + acme proxy), for
//!   the ACME forwarding tests (Plan 4 Task 9: /acme past the fallback,
//!   outside the CSRF rule and the session machinery).

use axum::body::Body;
use axum::http::{header, HeaderValue, Method, Request, StatusCode};
use axum::routing::get;
use axum::Router;
use tower::ServiceExt;
use uuid::Uuid;

use ws_web::session::SessionStore;
use ws_web::{acme_router, api_router, session, session_router_with_store, ui};

/// Where the committed bundle lives, from ws-web's own manifest dir
/// (the same directory the binary embeds at compile time). The tests
/// read the hashed asset's name off disk so a rebuild's new hash keeps
/// the suite green without a source change.
static UI_DIST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ui/dist");

/// The stub composition standing for [`ws_web::web_router`]: a route the
/// API surface "owns" mounted first, the SPA router on the fallback.
fn stub_health_router() -> Router {
    Router::new()
        .route("/api/v1/healthz", get(|| async { "ok" }))
        .fallback_service(ui::ui_router())
}

/// The real proxy composition: `/api/v1/*` forwarded to a loopback port
/// on which nothing listens (an immediate connection refusal — the 502
/// the CSRF tests run past the rule into).
fn proxy_router() -> Router {
    api_router("http://127.0.0.1:9").fallback_service(ui::ui_router())
}

/// The response body (the tests are the only unwrappers in this suite).
async fn body(response: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read the response body")
        .to_vec()
}

/// The name of the committed hashed JS asset under `ui/dist/assets`.
fn committed_js_asset() -> String {
    let dir = std::path::Path::new(UI_DIST).join("assets");
    let entries = std::fs::read_dir(&dir).expect("read the committed assets dir");
    for entry in entries {
        let path = entry.expect("entry in the committed assets dir").path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("js") {
            return path
                .file_name()
                .expect("the entry has a file name")
                .to_str()
                .expect("the asset name is UTF-8")
                .to_string();
        }
    }
    panic!("the committed ui/dist/assets holds no .js bundle — ui/dist is not built/committed");
}

/// A session cookie header value for `id`, exactly as the login sets it.
fn cookie(id: &Uuid) -> HeaderValue {
    HeaderValue::from_str(&session::build_session_cookie(&id.to_string()))
        .expect("the built cookie value is a valid header value")
}

/// # The embedded SPA (router shape)

#[tokio::test]
async fn spa_fallback_never_masks_api() {
    let router = stub_health_router();

    // The API route mounted FIRST answers — the fallback below it must
    // never be consulted for it (the fallback runs only when no earlier
    // route matched).
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "the API route answers");
    assert_eq!(body(response).await, b"ok".to_vec());
}

#[tokio::test]
async fn index_serves_the_committed_html_no_cache() {
    let response = stub_health_router()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/html; charset=utf-8"),
        "the document is served as HTML"
    );
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-cache"),
        "index.html is always revalidated"
    );
    let index = body(response).await;
    let committed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../ui/dist/index.html"
    ))
    .expect("read the committed index.html from disk");
    assert_eq!(index, committed, "exactly the embedded committed document");
}

#[tokio::test]
async fn assets_serve_immutable_and_missing_assets_404() {
    let router = stub_health_router();

    // The committed hashed bundle, by its real name.
    let asset_name = committed_js_asset();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/assets/{asset_name}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{asset_name} serves");
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/javascript; charset=utf-8"),
        "JS assets are served as javascript"
    );
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("public, max-age=31536000, immutable"),
        "hashed assets are immutable"
    );
    let on_disk = std::fs::read(
        std::path::Path::new(UI_DIST)
            .join("assets")
            .join(&asset_name),
    )
    .expect("read the committed asset from disk");
    assert_eq!(body(response).await, on_disk);

    // A missing asset WITH an extension is a plain 404 — never the SPA
    // fallback (a mistyped hashed link must not masquerade as document).
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/assets/missing.xyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Same rule off the assets prefix: a GET to a root-level file name.
    let response = router
        .oneshot(
            Request::builder()
                .uri("/missing.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "an extension path never falls back to the document"
    );
}

#[tokio::test]
async fn extension_free_paths_fall_back_to_the_document() {
    let router = stub_health_router();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/certificates")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a client route falls back"
    );
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/html; charset=utf-8"),
        "the fallback serves the document"
    );
    let committed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../ui/dist/index.html"
    ))
    .expect("read the committed index.html from disk");
    assert_eq!(body(response).await, committed);
}

#[tokio::test]
async fn api_prefix_always_reaches_the_proxy_not_the_fallback() {
    // The REAL composed shape: /api/v1/* is a proxy route; a GET to a
    // path under it that matches no real API route is FORWARDED (502 to
    // the dead upstream here), never served the document.
    let response = proxy_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/no-real-route")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "the unmatched /api/v1 path was forwarded, not caught by the SPA fallback"
    );
}

/// # The session cookie module

#[test]
fn session_cookie_roundtrip() {
    let id = Uuid::new_v4();
    let cookie_value = session::build_session_cookie(&id.to_string());
    assert!(cookie_value.starts_with("wardstone_session="));

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&cookie_value).unwrap(),
    );
    assert_eq!(session::read_session_id(&headers), Some(id), "round trip");

    let mut malformed = axum::http::HeaderMap::new();
    malformed.insert(
        header::COOKIE,
        HeaderValue::from_static("wardstone_session=not-a-uuid"),
    );
    assert_eq!(
        session::read_session_id(&malformed),
        None,
        "a malformed value is not a session"
    );

    assert_eq!(
        session::read_session_id(&axum::http::HeaderMap::new()),
        None,
        "no Cookie header is no session"
    );
}

// # The proxy's CSRF rule

async fn csrf_case(
    router: Router,
    method: Method,
    cookie_value: Option<HeaderValue>,
    csrf_header: Option<HeaderValue>,
) -> StatusCode {
    let mut builder = Request::builder().method(method).uri("/api/v1/things");
    if let Some(value) = cookie_value {
        builder = builder.header(header::COOKIE, value);
    }
    if let Some(value) = csrf_header {
        builder = builder.header(session::CSRF_HEADER_NAME, value);
    }
    let response = router
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    response.status()
}

#[tokio::test]
async fn csrf_rule_blocks_cookie_mutations_without_header() {
    let router = proxy_router();
    let status = csrf_case(router, Method::POST, Some(cookie(&Uuid::new_v4())), None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "cookie + mutation, no marker"
    );
}

#[tokio::test]
async fn csrf_forbidden_body_is_the_error_envelope() {
    let response = proxy_router()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/v1/things/1")
                .header(header::COOKIE, cookie(&Uuid::new_v4()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let json: serde_json::Value =
        serde_json::from_slice(&body(response).await).expect("the refusal is JSON");
    assert_eq!(
        json,
        serde_json::json!({
            "error": {
                "code": "forbidden",
                "message": "missing wardstone-ui request header"
            }
        })
    );
}

#[tokio::test]
async fn csrf_ok_cases_pass_the_check_into_the_proxy() {
    let id = Uuid::new_v4();

    // A cookie-carrying mutation WITH the marker passes the rule (and
    // 502s at the unreachable upstream — the check itself passed).
    let with_marker = csrf_case(
        proxy_router(),
        Method::POST,
        Some(cookie(&id)),
        Some(HeaderValue::from_static("wardstone-ui")),
    )
    .await;
    assert_eq!(
        with_marker,
        StatusCode::BAD_GATEWAY,
        "the marked request was forwarded"
    );

    // WITHOUT a session cookie no marker is required: machine tokens and
    // the pull flow are untouched (again past the check, 502 at upstream).
    let cookieless = csrf_case(proxy_router(), Method::POST, None, None).await;
    assert_eq!(
        cookieless,
        StatusCode::BAD_GATEWAY,
        "a cookieless mutation needs no marker"
    );

    // A GET mutation-in-name-only? GETs never trip the rule either.
    let get_with_cookie = csrf_case(proxy_router(), Method::GET, Some(cookie(&id)), None).await;
    assert_eq!(
        get_with_cookie,
        StatusCode::BAD_GATEWAY,
        "GET carries no rule"
    );
}

/// # The ACME surfaces (Plan 4 Task 9)
///
/// The ACME proxy composition: `/acme*` forwarded to a dead loopback port
/// (an immediate connection refusal — the forwarded 502 the assertions
/// read), the SPA router on the fallback — the real front door's shape.
fn acme_router_dead() -> Router {
    acme_router("http://127.0.0.1:9", None).fallback_service(ui::ui_router())
}

/// The COMPOSED front-door core ([`ws_web::web_router_with_store`]'s
/// DB-free merge): the relay nest, the `/api/v1` proxy (store Extension
/// attached), AND the `/acme` proxy — one store, dead upstream — with the
/// SPA router on the fallback. The acme assertions drive THIS whenever the
/// question is the real stack's precedence or isolation.
fn composed_router() -> Router {
    session_router_with_store(
        std::sync::Arc::new(SessionStore::new(
            std::time::Duration::from_secs(60),
            ws_web::DEFAULT_IDLE_EVICTION,
        )),
        "http://127.0.0.1:9",
        None,
    )
    .fallback_service(ui::ui_router())
}

#[tokio::test]
async fn acme_routes_forward_past_the_fallback() {
    // Every route shape ws-api mounts under /acme — the tenantless
    // nonce endpoint, the directory (certbot's --server entry point),
    // and a per-tenant account URL — FORWARDED: against the dead
    // upstream that is a 502, never the SPA fallback's 200 + index.html.
    let forwarded = acme_router_dead();
    for (method, uri) in [
        (Method::GET, "/acme/primary/directory"),
        (Method::POST, "/acme/primary/new-account"),
        (Method::GET, "/acme/new-nonce"),
        (Method::POST, "/acme/primary/acct/dead-beef-thumbprint"),
    ] {
        let response = forwarded
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_GATEWAY,
            "{method} {uri} was forwarded, not caught by the SPA fallback"
        );
    }

    // The same shapes through the COMPOSED stack (relay + api proxy +
    // acme proxy, one store): the merge carries the /acme routes too.
    let response = composed_router()
        .oneshot(
            Request::builder()
                .uri("/acme/primary/directory")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "the composed front door forwards the ACME directory request"
    );

    // Regression guard: the SPA fallback is still the LAST resort — an
    // extension-less path outside every mounted prefix reaches the
    // document through the same composition.
    let response = composed_router()
        .oneshot(
            Request::builder()
                .uri("/certificates")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the SPA fallback still serves client routes"
    );
}

#[tokio::test]
async fn acme_mutations_with_a_session_cookie_forward_without_the_csrf_rule() {
    // The CSRF rule (and the whole session machinery) belongs to the
    // BROWSER surfaces: an ACME POST is JWS machine traffic whose
    // authority is the account key. A request that happens to carry a
    // `wardstone_session` cookie (a browser tab pointed at the ACME
    // endpoint, say) must still be forwarded verbatim — no marker
    // demanded, no session resolved/injected — so against the dead
    // upstream it answers the forwarded 502, NOT the rule's 403.
    let response = composed_router()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/acme/primary/new-account")
                .header(header::COOKIE, cookie(&Uuid::new_v4()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "the cookie-carrying ACME mutation was forwarded — the CSRF rule never fires on /acme"
    );
}

/// # The unmounted setup routes (the non-DB half of the unmount contract)

#[tokio::test]
async fn unmounted_setup_routes_are_explicit_404s_over_the_fallback() {
    // The composed shape of the CONFIGURED branch of `web_router`: the
    // setup routes are gone and their EXPLICIT 404 replacement stands in
    // — left to the SPA fallback, the extension-less `GET /setup` would
    // come back 200 + index.html and the endpoint would not actually be
    // unrouted (the defect this composition fixed).
    let router = stub_health_router().merge(ws_web::setup_unmounted_router());

    // GET /setup is 404, not the UI document.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/setup")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "GET /setup is gone, not the document"
    );

    // POST /setup too — a plain 404, not a refusal (never 403).
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/setup")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "POST /setup is gone, not merely refused"
    );

    // The replacement is surgical: other extension-less client routes
    // still fall back to the document, so the SPA routing survives.
    let response = router
        .oneshot(
            Request::builder()
                .uri("/certificates")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the SPA fallback still serves other client routes"
    );
}
