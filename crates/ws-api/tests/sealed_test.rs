//! The sealed-mode tests (ws-api side): the health surface answers 200
//! with the state field in both modes (liveness — compose never churns a
//! correctly-locked service); every non-unlock route answers 503 `sealed`
//! while sealed; the unlock POST swaps the full router in and the next
//! request reaches it; a second unlock is a conflict; a wrong passphrase
//! leaves the state unchanged.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use tower::ServiceExt;

use ws_api::sealed::{sealed_router, SealedApi};

/// A trivial full router the build closure swaps in: one route proving
/// delegation reached it.
fn full_router() -> Router {
    Router::new().route("/api/v1/full", get(|| async { "the full surface" }))
}

#[tokio::test]
async fn sealed_healthz_is_200_with_the_state_and_everything_else_503s() {
    let api = std::sync::Arc::new(SealedApi::new(std::sync::Arc::new(
        |_: &ws_api::sealed::UnlockRequest| Box::pin(async move { Ok(full_router()) }),
    )));
    let router = sealed_router(api);

    let health = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK, "liveness is unconditional");
    let body = axum::body::to_bytes(health.into_body(), 1 << 10)
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&body).contains(r#""state":"sealed""#),
        "the health surface carries the state field"
    );

    let sealed = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/full")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        sealed.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "the full surface is 503 while sealed"
    );
    let body = axum::body::to_bytes(sealed.into_body(), 1 << 10)
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&body).contains(r#""code":"sealed""#),
        "the 503 speaks the house JSON envelope"
    );
}

#[tokio::test]
async fn the_unlock_swaps_the_full_router_in_and_healthz_flips() {
    let api = std::sync::Arc::new(SealedApi::new(std::sync::Arc::new(
        |_: &ws_api::sealed::UnlockRequest| Box::pin(async move { Ok(full_router()) }),
    )));
    let router = sealed_router(api);

    let unlock = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/internal/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "passphrase": "the-master-passphrase" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unlock.status(), StatusCode::OK, "the unlock succeeds");

    // The same router now delegates: the full surface answers.
    let after = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/full")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        after.status(),
        StatusCode::OK,
        "the full surface answers after the unlock"
    );

    let health = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(health.into_body(), 1 << 10)
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&body).contains(r#""state":"unlocked""#),
        "the health surface reports unlocked"
    );
}

#[tokio::test]
async fn a_wrong_passphrase_changes_nothing_and_a_second_unlock_conflicts() {
    let api = std::sync::Arc::new(SealedApi::new(std::sync::Arc::new(
        |req: &ws_api::sealed::UnlockRequest| {
            let ok = req.passphrase == "the-master-passphrase";
            Box::pin(async move {
                if ok {
                    Ok(full_router())
                } else {
                    Err(ws_api::error::ApiError::Unauthorized(
                        "the master passphrase was refused".to_string(),
                    ))
                }
            })
        },
    )));
    let router = sealed_router(api);

    let refused = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/internal/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "passphrase": "wrong" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        refused.status(),
        StatusCode::UNAUTHORIZED,
        "the wrong passphrase is refused"
    );
    let still = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/full")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        still.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a refused unlock leaves the state sealed"
    );

    let ok = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/internal/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "passphrase": "the-master-passphrase" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);

    let second = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/internal/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "passphrase": "the-master-passphrase" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        second.status(),
        StatusCode::CONFLICT,
        "a second unlock is a conflict"
    );
}
