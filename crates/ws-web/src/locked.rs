//! The ui process's sealed mode (the sealed-at-rest design): while the
//! instance is sealed the front door serves ONLY the unlock page over the
//! existing TLS listener (the locked-mode certificate), the health
//! surface, and the relay to the api's Unix-socket unlock endpoint.
//! Everything else — the SPA, the login relay, the API proxy, the ACME
//! surface — answers `503 sealed` through the same delegate fallback the
//! api uses. The unlock POST derives the KEK locally (argon2id in-process:
//! the passphrase never leaves this host), runs main's build closure
//! (open envelopes, resolve the tenant and the serving leaf, RELEASE the
//! pool — the api's relayed unlock rotates the database credential, so
//! the unlocked front door holds no database connection at all), and
//! relays the passphrase to the api once over the Unix relay socket
//! (Task 10, D8). A volume without `db-credential.envelope` grows the
//! database-password field: the recovery runbook's typed password
//! re-seals the credential before anything connects. A sealed volume
//! whose database holds no default tenant is the torn state: the build
//! reports [`INTERRUPTED_SETUP_REFUSAL`], this router answers the POST
//! with the same copy, and the binary exits the process non-zero.

use std::sync::{Arc, RwLock};

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tower::Service;

/// The torn-state refusal (Task 7's verbatim copy): a sealed volume
/// whose database holds no default tenant is the aftermath of a setup
/// that crashed AFTER sealing — `master.envelope` is written LAST, so
/// the sealed marker promises the seal landed but never that the
/// install did. Nothing auto-recovers from a half-finished install
/// (the database side may itself be incomplete), so the unlock's build
/// sends the process a fatal with this copy and the door answers the
/// POST's 409 with the same words: remove both volumes and run setup
/// again.
pub const INTERRUPTED_SETUP_REFUSAL: &str =
    "setup was interrupted after sealing — remove both volumes and run setup again";

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
    dyn Fn(
            &str,
            Option<&str>,
            Option<&str>,
        ) -> futures_util::future::BoxFuture<'static, Result<Router, String>>
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
    /// build closure converges the volume before it opens it); and
    /// `db_password` is present only on the recovery runbook's boot
    /// (Task 7): the volume holds no `db-credential.envelope`, so the
    /// TYPED database password is what re-seals it.
    pub async fn unlock(
        &self,
        passphrase: &str,
        next_passphrase: Option<&str>,
        db_password: Option<&str>,
    ) -> Result<(), String> {
        // The serialized window (F4): the guard spans check, build, and
        // swap — a racing second unlock waits here, then sees the
        // already-swapped router and refuses without building.
        let _window = self.unlock_window.lock().await;
        if self.is_unlocked() {
            return Err("already_unlocked".to_string());
        }
        let router = (self.build)(passphrase, next_passphrase, db_password).await?;
        *self
            .router
            .write()
            .map_err(|_| "the sealed ui state is corrupted".to_string())? = Some(Arc::new(router));
        Ok(())
    }
}

/// Relay the unlock to the api process ONCE (spec §5): a minimal
/// HTTP/1.1 POST of the passphrase over the api's Unix-socket listener
/// (Task 10, D8: a local link — `SO_PEERCRED` is the transport's
/// credential, and no HTTP client stack rides the relay: the POST is
/// spoken by hand, and only the `/api/v1` PROXY keeps a client, over
/// the internal network (ruling 28f). Best-effort BY DESIGN: the api
/// may be seeding a fresh install, a redeploy racer, or already
/// unlocked; every one of those is the spec's documented fallback, and
/// the CALLER logs the verdict — the relay never fails the ui's own
/// unlock.
///
/// The POST carries the relay dir's one-time nonce (spec §10, the
/// final review's F2): minted into the socket's OWN directory right
/// here — only a relay-dir holder can write the claim, and the nonce
/// is an authenticator, so it never touches the keys volume (G1) — and
/// consumed by the api's unlock, so a captured POST is dead after the
/// real one. Each relay attempt mints afresh, which makes a
/// superseded attempt's nonce dead too. The call is BOUNDED (the
/// final review's F8, the proxy's numbers): a hung api fails the
/// relay in bounded time instead of hanging the operator's unlock
/// POST forever.
pub async fn relay_unlock(socket_path: &std::path::Path, passphrase: &str) -> Result<(), String> {
    // The claim FIRST: the nonce must exist before the POST leaves,
    // and its home is the socket's own directory —
    // `socket.parent()/relay-nonce`, no second env var names it.
    let relay_dir = socket_path
        .parent()
        .ok_or_else(|| "the relay socket has no parent directory".to_string())?;
    let nonce = ws_core::crypto::mint_relay_nonce(relay_dir)
        .map_err(|e| format!("the relay nonce: {e}"))?;
    let body = serde_json::json!({ "passphrase": passphrase, "nonce": nonce }).to_string();
    let request = format!(
        "POST /unlock HTTP/1.1\r\nhost: wardstone-relay\r\ncontent-type: application/json\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let relay = async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::UnixStream::connect(socket_path)
            .await
            .map_err(|e| format!("the relay transport: {e}"))?;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("the relay transport: {e}"))?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|e| format!("the relay transport: {e}"))?;
        Ok::<_, String>(response)
    };
    // `connection: close` makes the api's answer end at EOF, so
    // read_to_end terminates; the timeout is the belt on top (F8).
    let response = tokio::time::timeout(std::time::Duration::from_secs(60), relay)
        .await
        .map_err(|_| "the relay transport timed out after 60s".to_string())??;
    // The status line is all the relay reads: "HTTP/1.1 <code> …".
    let status = std::str::from_utf8(&response)
        .ok()
        .and_then(|text| text.lines().next())
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok());
    let code = status.ok_or_else(|| {
        format!(
            "the api's relay answer is not an HTTP status line: {}",
            String::from_utf8_lossy(&response)
        )
    })?;
    // 2xx = unlocked; 409 = already unlocked: the api is live and
    // serving; the relay's job is done either way.
    if (200..300).contains(&code) || code == 409 {
        return Ok(());
    }
    Err(format!("the api answered the relay with HTTP {code}"))
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
        .fallback_service(SealedWebDelegate { ui: ui.clone() })
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
    // The completion probe (spec §5.7) and the recovery probe (Task 7):
    // a crashed passphrase change leaves the envelope generations
    // disagreeing (the page re-offers the completion), and a volume
    // WITHOUT `db-credential.envelope` grows the database-password field
    // (the recovery runbook's typed re-seal). A volume the scan cannot
    // read renders the plain form — the POST then names the real
    // condition.
    let mixed = ws_core::crypto::scan_volume(&keys_dir)
        .map(|scan| scan.mixed)
        .unwrap_or(false);
    let needs_db_password = !keys_dir
        .join(ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE)
        .exists();
    let html = render_unlock_page(&hostname, mixed, needs_db_password);
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
    /// Present only on the recovery runbook's boot (Task 7): the volume
    /// holds no `db-credential.envelope`, so the TYPED database password
    /// re-seals it before anything connects.
    #[serde(default)]
    db_password: Option<String>,
}

async fn unlock_handler(
    State((ui, keys_dir, _)): State<UiState>,
    Json(body): Json<UnlockBody>,
) -> Response {
    // The recovery runbook's pre-check (Task 7): without the sealed db
    // credential the build needs the TYPED password — and refusing
    // BEFORE the build spends neither the argon2 derive nor the
    // unlock-window mutex on a request that could only fail. The 400
    // names the field so the page (and the operator) learn exactly
    // what to add.
    if !keys_dir
        .join(ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE)
        .exists()
        && body.db_password.is_none()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": { "code": "db_password_required",
                    "message": "the keys volume holds no db-credential envelope: \
                                the db_password field is required to re-seal it \
                                (the recovery runbook)" }
            })),
        )
            .into_response();
    }
    match ui
        .unlock(
            &body.passphrase,
            body.next_passphrase.as_deref(),
            body.db_password.as_deref(),
        )
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
        // The torn state (Task 7): the build resolved the tenant and
        // found none — an interrupted setup. The binary exits the
        // process on this verdict; the POST's own response carries the
        // same copy so the operator's browser shows it, not a generic
        // refusal.
        Err(code) if code == INTERRUPTED_SETUP_REFUSAL => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": { "code": "setup_interrupted",
                    "message": INTERRUPTED_SETUP_REFUSAL }
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
pub(crate) struct SealedWebDelegate {
    pub(crate) ui: Arc<SealedUi>,
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
                None => Box::pin(async move { Ok(sealed_503()) }),
            },
            Err(_) => Box::pin(async move { Ok(sealed_503()) }),
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
/// uses). One passphrase field, one button, no JavaScript beyond the
/// POST — plus, per the volume's probed state, the mixed completion's
/// new-passphrase field (spec §5.7) and/or the recovery runbook's
/// database-password field (Task 7: no `db-credential.envelope` means
/// the typed password must re-seal it). The lede names whichever
/// condition the page re-offers, so the operator is never left guessing
/// which fields the instance wants.
fn render_unlock_page(hostname: &str, mixed: bool, needs_db_password: bool) -> String {
    // The lede names the condition by precedence: a crashed completion
    // outranks the recovery (a mixed volume still holds its
    // db-credential envelope or it would not be mixed), and both
    // outrank the plain sealed copy.
    let lede = if mixed {
        "A passphrase change did not finish — the disks still hold \
         envelopes sealed under both passphrases. Enter the current \
         passphrase and the new one together to complete the change \
         and unlock."
    } else if needs_db_password {
        "The keys volume holds no sealed database credential — the \
         recovery runbook. Enter the master passphrase and the \
         database's password together: the typed password re-seals \
         the credential, and the unlock continues."
    } else {
        "Enter the master passphrase to unlock this instance. Everything \
         on its disks is inert until you do — that is the design, not an \
         outage."
    };
    let mut fields = String::new();
    if mixed {
        fields.push_str(concat!(
            r#"<label for="next-passphrase">New passphrase</label>"#,
            "\n",
            r#"<input id="next-passphrase" type="password" autocomplete="off" required>"#,
            "\n",
        ));
    }
    if needs_db_password {
        fields.push_str(concat!(
            r#"<label for="db-password">Database password</label>"#,
            "\n",
            r#"<input id="db-password" type="password" autocomplete="off" required>"#,
            "\n",
        ));
    }
    // The POST payload carries exactly the fields the form shows — a
    // plain volume never sends the optional keys.
    let mut payload =
        String::from("JSON.stringify({ passphrase: document.getElementById('passphrase').value");
    if mixed {
        payload.push_str(", next_passphrase: document.getElementById('next-passphrase').value");
    }
    if needs_db_password {
        payload.push_str(", db_password: document.getElementById('db-password').value");
    }
    payload.push_str(" })");
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
{fields}
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
        fields = fields,
        payload = payload,
    )
}
