//! The ui process's sealed mode (the sealed-at-rest design): while the
//! instance is sealed the front door serves ONLY the unlock page over the
//! existing TLS listener (the locked-mode certificate), the health
//! surface, and the relay to the api's internal unlock endpoint.
//! Everything else — the SPA, the login relay, the API proxy, the ACME
//! surface — answers `503 sealed` through the same delegate fallback the
//! api uses. The unlock POST derives the KEK locally (argon2id in-process:
//! the passphrase never leaves this host), runs main's build closure
//! (open envelopes, connect the pool, build the full `web_router`), and
//! relays the passphrase to the api once over the compose-internal
//! channel.

use std::sync::{Arc, RwLock};

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tower::Service;

/// The late-bound full web router: `None` while sealed; swapped in by the
/// unlock. `main` supplies the build closure (it owns the config: the keys
/// dir, the api base URL, the session TTL, the rate limits).
pub struct SealedUi {
    router: RwLock<Option<Arc<Router>>>,
    build: LockedWebBuild,
}

pub type LockedWebBuild = Arc<dyn Fn(&str) -> Result<Router, String> + Send + Sync>;

impl SealedUi {
    pub fn new(build: LockedWebBuild) -> Self {
        SealedUi {
            router: RwLock::new(None),
            build,
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.router.read().map(|r| r.is_some()).unwrap_or(false)
    }

    fn unlock(&self, passphrase: &str) -> Result<(), String> {
        if self.is_unlocked() {
            return Err("already_unlocked".to_string());
        }
        let router = (self.build)(passphrase)?;
        *self
            .router
            .write()
            .map_err(|_| "the sealed ui state is corrupted".to_string())? = Some(Arc::new(router));
        Ok(())
    }
}

/// The sealed front door: the unlock page, the health surface, the unlock
/// POST, and the 503 delegate for everything else. Served by `main` while
/// the instance is sealed; the delegate hands over to the full
/// `web_router` the moment the unlock succeeds (no restart, no re-listen
/// — the `resume` contract).
pub fn locked_router(ui: Arc<SealedUi>, hostname: &str) -> Router {
    let hostname = hostname.to_owned();
    Router::new()
        .route("/", get(unlock_page))
        .route("/healthz", get(healthz))
        .route("/unlock", post(unlock_handler))
        .with_state((ui.clone(), hostname))
        .fallback_service(SealedWebDelegate { ui })
}

type UiState = (Arc<SealedUi>, String);

async fn healthz(State((ui, _)): State<UiState>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "state": if ui.is_unlocked() { "unlocked" } else { "sealed" },
        })),
    )
        .into_response()
}

async fn unlock_page(State((_, hostname)): State<UiState>) -> Response {
    let html = render_unlock_page(&hostname);
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct UnlockBody {
    passphrase: String,
}

async fn unlock_handler(State((ui, _)): State<UiState>, Json(body): Json<UnlockBody>) -> Response {
    match ui.unlock(&body.passphrase) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "state": "unlocked",
                "message": "the instance is unlocked; redirecting to the login",
            })),
        )
            .into_response(),
        Err(code) if code == "already_unlocked" => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": { "code": "already_unlocked",
                    "message": "the instance is already unlocked" }
            })),
        )
            .into_response(),
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": { "code": "unlock_failed",
                    "message": "the master passphrase was refused; the instance is unchanged" }
            })),
        )
            .into_response(),
    }
}

/// The 503 delegate: sealed, everything except the mounted routes above
/// refuses; unlocked, the full web router answers (a clone shares the
/// state by design).
#[derive(Clone)]
struct SealedWebDelegate {
    ui: Arc<SealedUi>,
}

impl Service<Request<Body>> for SealedWebDelegate {
    type Response = Response;
    type Error = std::convert::Infallible;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        match self.ui.router.read() {
            Ok(guard) => match guard.as_ref() {
                Some(router) => {
                    let mut service = Router::clone(router);
                    Box::pin(Service::call(&mut service, request))
                }
                None => Box::pin(async { Ok(sealed_503()) }),
            },
            Err(_) => Box::pin(async { Ok(sealed_503()) }),
        }
    }
}

fn sealed_503() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": { "code": "sealed",
                "message": "the instance is sealed: unlock to continue" }
        })),
    )
        .into_response()
}

/// The unlock page: server-rendered HTML (the SPA is sealed away, so the
/// locked mode cannot depend on it — the same reasoning the setup page
/// uses). One field, one button, no JavaScript beyond the POST.
fn render_unlock_page(hostname: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Wardstone — sealed</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 28rem; margin: 3rem auto; padding: 0 1rem; }}
h1 {{ font-size: 1.3rem; }}
input {{ box-sizing: border-box; width: 100%; padding: 0.5rem; font-size: 1rem; margin-top: 0.4rem; }}
button {{ margin-top: 1rem; padding: 0.6rem 1.4rem; font-size: 1rem; }}
#result {{ margin-top: 1rem; font-weight: 600; }}
</style>
</head>
<body>
<h1>{hostname} is sealed</h1>
<p>Enter the master passphrase to unlock this instance. Everything on its
disks is inert until you do — that is the design, not an outage.</p>
<form id="unlock-form">
<input id="passphrase" type="password" autocomplete="off" required>
<button type="submit">Unlock</button>
</form>
<div id="result"></div>
<script>
document.getElementById('unlock-form').addEventListener('submit', async (event) => {{
  event.preventDefault();
  const note = document.getElementById('result');
  try {{
    const response = await fetch('/unlock', {{
      method: 'POST',
      headers: {{ 'content-type': 'application/json' }},
      body: JSON.stringify({{ passphrase: document.getElementById('passphrase').value }}),
    }});
    if (response.ok) {{
      window.location = '/';
    }} else {{
      const body = await response.json().catch(() => ({{}}));
      note.textContent = body.error?.message || 'Unlock failed';
      note.style.color = '#a11';
    }}
  }} catch (error) {{
    note.textContent = 'Unlock failed: ' + error;
    note.style.color = '#a11';
  }}
}});
</script>
</body>
</html>
"#,
        hostname = hostname
    )
}
