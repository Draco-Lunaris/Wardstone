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
/// dir, the api base URL, the session TTL, the rate limits). The unlock
/// is serialized: check-then-build with no lock would let two racing
/// POSTs both run the build (the final review's F4 — the api side of the
/// same race double-rotates the DB credential), so the mutex spans the
/// whole check→build→swap window and the second unlock waits its turn
/// and refuses.
pub struct SealedUi {
    router: RwLock<Option<Arc<Router>>>,
    build: LockedWebBuild,
    unlock_window: tokio::sync::Mutex<()>,
}

pub type LockedWebBuild = Arc<
    dyn Fn(&str, Option<&str>) -> futures_util::future::BoxFuture<'static, Result<Router, String>>
        + Send
        + Sync,
>;

impl SealedUi {
    pub fn new(build: LockedWebBuild) -> Self {
        SealedUi {
            router: RwLock::new(None),
            build,
            unlock_window: tokio::sync::Mutex::new(()),
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.router.read().map(|r| r.is_some()).unwrap_or(false)
    }

    /// The ONE unlock: `passphrase` is the volume's current one;
    /// `next_passphrase` is present only on the mixed-state completion
    /// (spec §5.7 — the page re-offers the interrupted change, and the
    /// build closure converges the volume before it opens it).
    pub async fn unlock(
        &self,
        passphrase: &str,
        next_passphrase: Option<&str>,
    ) -> Result<(), String> {
        // The serialized window (F4): the guard spans check, build, and
        // swap — a racing second unlock waits here, then sees the
        // already-swapped router and refuses without building.
        let _window = self.unlock_window.lock().await;
        if self.is_unlocked() {
            return Err("already_unlocked".to_string());
        }
        let router = (self.build)(passphrase, next_passphrase).await?;
        *self
            .router
            .write()
            .map_err(|_| "the sealed ui state is corrupted".to_string())? = Some(Arc::new(router));
        Ok(())
    }
}

/// Relay the unlock to the api process ONCE (spec §5): a POST of the
/// passphrase over the compose-internal channel — the same trust
/// domain the api's own plaintext HTTP occupies. Best-effort BY DESIGN:
/// the api may be seeding a fresh install, a redeploy racer, or already
/// unlocked; every one of those is the spec's documented fallback, and
/// the CALLER logs the verdict — the relay never fails the ui's own
/// unlock.
///
/// The POST carries the volume's one-time nonce (spec §10, the final
/// review's F2): minted into `keys_dir` right here — only a volume
/// holder can write the claim — and consumed by the api's unlock, so a
/// captured POST is dead after the real one. Each relay attempt mints
/// afresh, which makes a superseded attempt's nonce dead too. The
/// client is BOUNDED (the final review's F8, the proxy's numbers): a
/// hung api fails the relay in bounded time instead of hanging the
/// operator's unlock POST forever.
pub async fn relay_unlock(
    keys_dir: &std::path::Path,
    api_base_url: &str,
    passphrase: &str,
) -> Result<(), String> {
    let nonce =
        ws_core::crypto::mint_relay_nonce(keys_dir).map_err(|e| format!("the relay nonce: {e}"))?;
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| format!("the relay transport: {e}"))?;
    let response = client
        .post(format!("{api_base_url}/api/internal/unlock"))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "passphrase": passphrase, "nonce": nonce }).to_string())
        .send()
        .await
        .map_err(|e| format!("the relay transport: {e}"))?;
    if response.status().is_success() || response.status().as_u16() == 409 {
        // 409 = already unlocked: the api is live and serving; the relay's
        // job is done either way.
        return Ok(());
    }
    Err(format!(
        "the api answered the relay with HTTP {}",
        response.status().as_u16()
    ))
}

/// The sealed front door: the unlock page, the health surface, the unlock
/// POST, and the 503 delegate for everything else. Served by `main` while
/// the instance is sealed; the delegate hands over to the full
/// `web_router` the moment the unlock succeeds (no restart, no re-listen
/// — the `resume` contract).
pub fn locked_router(
    ui: Arc<SealedUi>,
    keys_dir: &std::path::Path,
    hostname: &str,
    rate_limit: Option<ws_api::AuthRateLimit>,
) -> Router {
    let hostname = hostname.to_owned();
    let keys_dir = keys_dir.to_path_buf();
    let state = (ui.clone(), keys_dir, hostname);
    let unlock = crate::gcra(
        Router::new().route("/unlock", post(unlock_handler)),
        rate_limit,
        "/unlock",
    )
    .with_state(state.clone());
    Router::new()
        .route("/", get(unlock_page))
        .route("/healthz", get(healthz))
        .with_state(state)
        .merge(unlock)
        .fallback_service(SealedWebDelegate {
            ui: ui.clone(),
            refusal: sealed_503,
        })
}

type UiState = (Arc<SealedUi>, std::path::PathBuf, String);

async fn healthz(State((ui, _, _)): State<UiState>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "state": if ui.is_unlocked() { "unlocked" } else { "sealed" },
        })),
    )
        .into_response()
}

async fn unlock_page(State((ui, keys_dir, hostname)): State<UiState>) -> Response {
    // The unlocked process must not keep serving the passphrase form at
    // "/": the unlock POST's own success script sends the operator here,
    // and the spec routes them to the normal login instead (the final
    // review's G3 — the exact "/" registration outranks the fallback
    // delegate for the process's whole life).
    if ui.is_unlocked() {
        return axum::response::Redirect::to("/login").into_response();
    }
    // The completion probe (spec §5.7): a crashed passphrase change
    // leaves the envelope generations disagreeing, and the page
    // re-offers the completion. A volume the scan cannot read renders
    // the plain form — the POST then names the real condition.
    let mixed = ws_core::crypto::scan_volume(&keys_dir)
        .map(|scan| scan.mixed)
        .unwrap_or(false);
    let html = render_unlock_page(&hostname, mixed);
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
    /// Present only on the mixed-state completion (the page offers it
    /// when the envelope generations disagree).
    #[serde(default)]
    next_passphrase: Option<String>,
}

async fn unlock_handler(
    State((ui, _, _)): State<UiState>,
    Json(body): Json<UnlockBody>,
) -> Response {
    match ui
        .unlock(&body.passphrase, body.next_passphrase.as_deref())
        .await
    {
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
        // The completion refusals (the build closure's volume-state
        // conditions): the relayed body is what the operator reads on
        // the unlock page, and a mixed volume must say "completion" —
        // never a misleading "passphrase was refused".
        Err(code) if code == "completion_required" => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": { "code": "completion_required",
                    "message": "the volume holds an unfinished passphrase change: \
                                the completion needs the current passphrase and \
                                the new one together" }
            })),
        )
            .into_response(),
        Err(code) if code == "no_completion_pending" => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": { "code": "no_completion_pending",
                    "message": "no completion is pending on this volume: unlock \
                                without the new passphrase (the admin surface \
                                changes it once unlocked)" }
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
/// state by design). The refusal body is the door's own — the unlock
/// door names the seal, the INIT door names the conversion.
#[derive(Clone)]
pub(crate) struct SealedWebDelegate {
    pub(crate) ui: Arc<SealedUi>,
    pub(crate) refusal: fn() -> Response,
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
        // The fn pointer copies out of `self` so the refusal future
        // borrows nothing (the `Future` must be `'static`).
        let refusal = self.refusal;
        match self.ui.router.read() {
            Ok(guard) => match guard.as_ref() {
                Some(router) => {
                    let mut service = Router::clone(router);
                    Box::pin(Service::call(&mut service, request))
                }
                None => Box::pin(async move { Ok(refusal()) }),
            },
            Err(_) => Box::pin(async move { Ok(refusal()) }),
        }
    }
}

pub(crate) fn sealed_503() -> Response {
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
/// uses). One field, one button, no JavaScript beyond the POST — and on
/// a mixed volume (the crashed change's aftermath, probed at render
/// time) the completion re-offer: the new-passphrase field joins the
/// form and the copy names the condition (spec §5.7).
fn render_unlock_page(hostname: &str, mixed: bool) -> String {
    let (lede, extra_field, payload) = if mixed {
        (
            "A passphrase change did not finish — the disks still hold \
             envelopes sealed under both passphrases. Enter the current \
             passphrase and the new one together to complete the change \
             and unlock.",
            concat!(
                r#"<label for="next-passphrase">New passphrase</label>"#,
                "\n",
                r#"<input id="next-passphrase" type="password" autocomplete="off" required>"#,
            ),
            "JSON.stringify({ passphrase: document.getElementById('passphrase').value, \
             next_passphrase: document.getElementById('next-passphrase').value })",
        )
    } else {
        (
            "Enter the master passphrase to unlock this instance. Everything \
             on its disks is inert until you do — that is the design, not an \
             outage.",
            "",
            "JSON.stringify({ passphrase: document.getElementById('passphrase').value })",
        )
    };
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
<p>{lede}</p>
<form id="unlock-form">
<input id="passphrase" type="password" autocomplete="off" required>
{extra_field}
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
      body: {payload},
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
        hostname = hostname,
        lede = lede,
        extra_field = extra_field,
        payload = payload,
    )
}
