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
    let ui = Arc::new(SealedUi::new(Arc::new(|_: &str, _: Option<&str>| {
        Box::pin(async move { Ok(full_router()) })
    })));
    let router = locked_router(ui, &temp_keys("door"), "ca.example.test");

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
    let ui = Arc::new(SealedUi::new(Arc::new(|_: &str, _: Option<&str>| {
        Box::pin(async move { Ok(full_router()) })
    })));
    let router = locked_router(ui, &temp_keys("resume"), "ca.example.test");

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
    let ui = Arc::new(SealedUi::new(Arc::new(
        |passphrase: &str, _: Option<&str>| {
            let passphrase = passphrase.to_string();
            Box::pin(async move {
                if passphrase == "the-master-passphrase" {
                    Ok(full_router())
                } else {
                    Err("wrong".to_string())
                }
            })
        },
    )));
    let router = locked_router(ui, &temp_keys("refusal-door"), "ca.example.test");

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

// --- Task 4b: the mixed-state completion at the front door ---

/// A keys directory in the suite's temp space.
fn temp_keys(name: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("ws-web-locked-keys-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cheap_params() -> ws_core::crypto::KdfParams {
    ws_core::crypto::KdfParams {
        m_cost: 8192,
        t_cost: 2,
        p_cost: 1,
    }
}

/// The crashed passphrase change's aftermath, hand-minted: the
/// db-credential envelope advanced to the next generation under the new
/// passphrase, the master + secret envelopes still under the current
/// one (master is written LAST — the anchor rule). The JWT envelope is
/// deliberately absent: the completion re-wraps what exists.
fn mint_mixed_volume(keys_dir: &std::path::Path) {
    for (file, passphrase, generation) in [
        (
            ws_core::crypto::MASTER_ENVELOPE_FILE,
            "the-current-passphrase",
            0u64,
        ),
        (
            ws_core::crypto::SECRET_ENVELOPE_FILE,
            "the-current-passphrase",
            0,
        ),
        (
            ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE,
            "the-next-passphrase",
            1,
        ),
    ] {
        ws_core::crypto::KeyEnvelope::write_envelope(
            &keys_dir.join(file),
            passphrase,
            b"a-payload",
            cheap_params(),
            generation,
        )
        .expect("mint the mixed-volume envelope");
    }
}

/// The page RE-OFFERS the completion (spec §5.7): on a mixed volume the
/// unlock form grows the new-passphrase field and names the condition —
/// the operator is never left guessing which passphrase the instance
/// wants.
#[tokio::test]
async fn the_unlock_page_offers_the_completion_on_a_mixed_volume() {
    let keys_dir = temp_keys("mixed-page");
    mint_mixed_volume(&keys_dir);
    let ui = Arc::new(SealedUi::new(Arc::new(|_: &str, _: Option<&str>| {
        Box::pin(async move { Ok(full_router()) })
    })));
    let router = locked_router(ui, &keys_dir, "ca.example.test");

    let page = router
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let body = axum::body::to_bytes(page.into_body(), 1 << 16)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("did not finish"),
        "the page names the unfinished change, got: {html}"
    );
    assert!(
        html.contains(r#"id="next-passphrase""#),
        "the completion form carries the new-passphrase field, got: {html}"
    );
}

/// On a consistent volume the page stays exactly the single-field form
/// (a next field there would invite a passphrase change the unlock
/// must refuse anyway).
#[tokio::test]
async fn the_unlock_page_stays_a_single_field_on_a_consistent_volume() {
    let keys_dir = temp_keys("clean-page");
    for file in [
        ws_core::crypto::MASTER_ENVELOPE_FILE,
        ws_core::crypto::SECRET_ENVELOPE_FILE,
        ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE,
    ] {
        ws_core::crypto::KeyEnvelope::write_envelope(
            &keys_dir.join(file),
            "the-current-passphrase",
            b"a-payload",
            cheap_params(),
            0,
        )
        .expect("mint the clean-volume envelope");
    }
    let ui = Arc::new(SealedUi::new(Arc::new(|_: &str, _: Option<&str>| {
        Box::pin(async move { Ok(full_router()) })
    })));
    let router = locked_router(ui, &keys_dir, "ca.example.test");

    let page = router
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let body = axum::body::to_bytes(page.into_body(), 1 << 16)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(
        !html.contains("next-passphrase"),
        "the single-field form invites no completion, got: {html}"
    );
    assert!(
        html.contains("master passphrase"),
        "the clean volume asks for the master passphrase"
    );
}

/// The POST's `next_passphrase` reaches the build closure: the ui's own
/// build runs the completion before it opens the volume, so the field
/// the page offered must arrive at the operator's unlock builder.
#[tokio::test]
async fn a_next_passphrase_reaches_the_build_closure() {
    let seen = Arc::new(std::sync::Mutex::new((String::new(), None::<String>)));
    let capture = seen.clone();
    let ui = Arc::new(SealedUi::new(Arc::new(
        move |passphrase: &str, next: Option<&str>| {
            let passphrase = passphrase.to_string();
            let next = next.map(str::to_string);
            let capture = capture.clone();
            Box::pin(async move {
                *capture.lock().unwrap() = (passphrase, next);
                Ok(full_router())
            })
        },
    )));
    let router = locked_router(ui, &temp_keys("relay-closure"), "ca.example.test");

    let unlock = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "passphrase": "the-current-passphrase",
                        "next_passphrase": "the-new-passphrase",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unlock.status(), StatusCode::OK, "the threaded unlock lands");
    let (passphrase, next) = seen.lock().unwrap().clone();
    assert_eq!(passphrase, "the-current-passphrase");
    assert_eq!(
        next.as_deref(),
        Some("the-new-passphrase"),
        "the closure sees the offered completion"
    );
}

/// The refusal that names the completion reaches the operator as its
/// own 409 — never as a misleading "passphrase was refused" (the page
/// relays this body; the operator must learn to re-enter both).
#[tokio::test]
async fn the_unlock_refusal_names_the_completion_required() {
    let ui = Arc::new(SealedUi::new(Arc::new(|_: &str, _: Option<&str>| {
        Box::pin(async move { Err("completion_required".to_string()) })
    })));
    let router = locked_router(ui, &temp_keys("refusal-mixed"), "ca.example.test");

    let refused = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "passphrase": "the-current-passphrase" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(refused.into_body(), 1 << 10)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body["error"]["code"], "completion_required",
        "the body names the completion, got: {body}"
    );
}

/// The symmetric refusal: a `next_passphrase` against a consistent
/// volume is its own 409 — the unlock is never a hidden
/// passphrase-change path.
#[tokio::test]
async fn the_unlock_refusal_names_no_completion_pending() {
    let ui = Arc::new(SealedUi::new(Arc::new(|_: &str, _: Option<&str>| {
        Box::pin(async move { Err("no_completion_pending".to_string()) })
    })));
    let router = locked_router(ui, &temp_keys("refusal-clean"), "ca.example.test");

    let refused = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/unlock")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "passphrase": "the-current-passphrase" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(refused.into_body(), 1 << 10)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body["error"]["code"], "no_completion_pending",
        "the body names the condition, got: {body}"
    );
}
