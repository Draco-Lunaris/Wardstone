//! Task 14's public `/auth/ui/config` route, NON-DB: the relay router is
//! driven through `tower`'s oneshot against a STUB upstream that serves
//! `GET /api/v1/oidc/config/status` — ws-api's PUBLIC status surface
//! (fix round 1) — with canned answers (unlike [`ws_web`]'s session
//! suite, this route's mapping needs no pool, no rows, no real auth
//! flow).
//!
//! The mapping pinned here:
//! - upstream 200 `{"configured": true, "provider_type": "keycloak"}` →
//!   `{"oidc_configured": true, "provider": "keycloak"}` (the label
//!   ws-api resolves the start route's `{provider}` against);
//! - upstream 200 `{"configured": false, "provider_type": null}` (an
//!   unset row — the status route answers 200, not 404) → `false`;
//! - upstream 404 (defensive: any non-success) → `false` — the button
//!   hides, never errors.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Request, Response, StatusCode};
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};
use tower::ServiceExt;

use ws_web::session::{relay_router, SessionStore};

/// Spawn a stub upstream on an ephemeral loopback port answering
/// `GET /api/v1/oidc/config/status` with exactly (status, body). Returns
/// the base URL for the relay.
async fn spawn_stub(status: StatusCode, body: &'static str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the stub upstream");
    let addr = listener.local_addr().expect("the stub's address");
    let app = Router::new().route(
        "/api/v1/oidc/config/status",
        get(move || async move { (status, body) }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve the stub");
    });
    format!("http://{addr}")
}

/// Drive `GET /auth/ui/config` through the relay (no rate limit, like the
/// other non-DB suites) and unpack the answer body as JSON.
async fn config_answer(base: &str) -> (StatusCode, Value, Option<String>) {
    let router = relay_router(
        Arc::new(SessionStore::new(Duration::from_secs(60))),
        base,
        None,
    );
    let response: Response<Body> = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/auth/ui/config")
                .body(Body::empty())
                .expect("build the config request"),
        )
        .await
        .expect("the relay answers");
    let status = response.status();
    let cache = response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read the config body");
    let body: Value = serde_json::from_slice(&bytes).expect("the config answer is JSON");
    (status, body, cache)
}

#[tokio::test]
async fn a_configured_upstream_row_maps_to_true_with_the_provider_label() {
    let base = spawn_stub(
        StatusCode::OK,
        r#"{"configured": true, "provider_type": "keycloak"}"#,
    )
    .await;

    let (status, body, cache) = config_answer(&base).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({ "oidc_configured": true, "provider": "keycloak" })
    );
    // An auth-adjacent answer is never cacheable.
    assert_eq!(cache.as_deref(), Some("no-store"));
}

#[tokio::test]
async fn an_unset_row_configured_false_maps_to_false() {
    // The status route answers 200 with `configured: false` when no
    // provider row exists — the relay folds it into "no button".
    let base = spawn_stub(
        StatusCode::OK,
        r#"{"configured": false, "provider_type": null}"#,
    )
    .await;

    let (status, body, _) = config_answer(&base).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "oidc_configured": false, "provider": null }));
}

#[tokio::test]
async fn a_non_success_upstream_maps_to_false_not_an_error() {
    // Defensive pin: whatever non-success shape hits the probe (a 404
    // from a future relay change, a proxy refusal), the login page gets
    // "not configured", never an error it would have to handle.
    let base = spawn_stub(
        StatusCode::NOT_FOUND,
        r#"{"error":{"code":"not_found","message":"no route"}}"#,
    )
    .await;

    let (status, body, _) = config_answer(&base).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "oidc_configured": false, "provider": null }));
}
