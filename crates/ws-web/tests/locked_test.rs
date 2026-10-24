//! The sealed front-door tests (ws-web side): the locked router serves the
//! unlock page and the health surface while sealed, 503s everything else,
//! and swaps to the full router on a successful unlock (the `resume`
//! contract — no restart, no re-listen).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use tower::ServiceExt;

use ws_web::locked::{locked_router, SealedUi};

fn full_router() -> Router {
    Router::new().route("/the-full-surface", get(|| async { "full" }))
}

#[tokio::test]
async fn the_locked_door_serves_unlock_healthz_and_503s_the_rest() {
    let ui = Arc::new(SealedUi::new(Arc::new(|_: &str| Ok(full_router()))));
    let router = locked_router(ui, "ca.example.test");

    let page = router
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let body = axum::body::to_bytes(page.into_body(), 1 << 16)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("ca.example.test is sealed"),
        "the unlock page names the instance"
    );
    assert!(
        html.contains("master passphrase"),
        "the unlock page asks for the master passphrase"
    );

    let health = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    let body = axum::body::to_bytes(health.into_body(), 1 << 10)
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&body).contains(r#""state":"sealed""#),
        "the health surface reports sealed"
    );

    let refused = router
        .oneshot(
            Request::builder()
                .uri("/the-full-surface")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn the_unlock_resumes_the_full_router_in_place() {
    let ui = Arc::new(SealedUi::new(Arc::new(|_: &str| Ok(full_router()))));
    let router = locked_router(ui, "ca.example.test");

    let unlock = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "passphrase": "the-master-passphrase" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unlock.status(), StatusCode::OK);

    // The SAME listener now serves the full surface — the resume contract.
    let after = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/the-full-surface")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        after.status(),
        StatusCode::OK,
        "the full surface answers on the same listener after the unlock"
    );
}

#[tokio::test]
async fn a_refused_unlock_leaves_the_door_locked() {
    let ui = Arc::new(SealedUi::new(Arc::new(|passphrase: &str| {
        if passphrase == "the-master-passphrase" {
            Ok(full_router())
        } else {
            Err("wrong".to_string())
        }
    })));
    let router = locked_router(ui, "ca.example.test");

    let refused = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "passphrase": "wrong" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);

    let still = router
        .oneshot(
            Request::builder()
                .uri("/the-full-surface")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        still.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a refused unlock leaves the instance sealed"
    );
}
