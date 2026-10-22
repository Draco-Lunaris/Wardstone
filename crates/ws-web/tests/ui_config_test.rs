//! Task 14's public `/auth/ui/config` route, NON-DB: the relay router is
//! driven through `tower`'s oneshot against a STUB upstream that serves
//! `GET /api/v1/oidc/config` with canned answers (unlike [`ws_web`]'s
//! session suite, this route's mapping needs no pool, no rows, no real
//! auth flow).
//!
//! The mapping pinned here:
//! - upstream 200 → `{"oidc_configured": true, "provider": <provider_type>}`
//!   (the label ws-api resolves the start route's `{provider}` against);
//! - upstream 404 → `{"oidc_configured": false, "provider": null}` (SSO
//!   unset for the tenant);
//! - upstream 401 → the same `false` — ws-api gates its config GET behind
//!   `manage_system`, and this probe carries no browser credentials, so
//!   the gate's refusal MUST read as "not configured" (hide the button),
//!   never as an error the login page would have to handle. The decision
//!   is documented in [`ws_web::session::relay::ui_config`] and
//!   `ui/README.md`.

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
/// `GET /api/v1/oidc/config` with exactly (status, body). Returns the
/// base URL for the relay.
async fn spawn_stub(status: StatusCode, body: &'static str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the stub upstream");
    let addr = listener.local_addr().expect("the stub's address");
    let app = Router::new().route(
        "/api/v1/oidc/config",
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
        r#"{
            "provider_type": "keycloak",
            "display_name": "Keycloak",
            "discovery_url": "https://idp.example.com/.well-known/openid-configuration",
            "client_id": "wardstone",
            "redirect_uri": "https://wardstone.example.com/auth/ui/oidc/keycloak/callback",
            "scopes": "openid email profile",
            "client_secret_set": true
        }"#,
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
async fn an_unset_row_404_maps_to_false() {
    let base = spawn_stub(
        StatusCode::NOT_FOUND,
        r#"{"error":{"code":"not_found","message":"oidc is not configured for this tenant"}}"#,
    )
    .await;

    let (status, body, _) = config_answer(&base).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "oidc_configured": false, "provider": null }));
}

#[tokio::test]
async fn the_auth_gates_401_maps_to_false_not_an_error() {
    // ws-api's `manage_system` refusal, EXACTLY as the unauthenticated
    // probe receives it: the relay folds it into "not configured".
    let base = spawn_stub(
        StatusCode::UNAUTHORIZED,
        r#"{"error":{"code":"unauthorized","message":"Authorization scheme must be Bearer"}}"#,
    )
    .await;

    let (status, body, _) = config_answer(&base).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "oidc_configured": false, "provider": null }));
}
