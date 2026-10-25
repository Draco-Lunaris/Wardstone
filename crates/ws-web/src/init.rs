//! The INIT conversion page (the sealed-at-rest design's
//! `LegacyConversion` state): a volume that still holds plaintext key
//! files lands here on boot. The operator sets the master passphrase
//! (entered twice); the POST runs the one-time conversion — every
//! plaintext file wraps into a passphrase-sealed envelope, the DB
//! credential rotates and seals, the plaintext originals are deleted —
//! and the SAME listener hands over to the full unlocked surface (the
//! `resume` contract; the build closure relays the passphrase to the
//! api process exactly as the unlock flow's does). The next boot
//! derives `sealed` and serves the unlock page instead.

use std::path::Path;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use crate::locked::{SealedUi, SealedWebDelegate};
use ws_core::crypto::MASTER_ENVELOPE_FILE;

/// The boot predicate (the design's state derivation): ANY pre-sealing
/// plaintext file — the master key, the secret-encryption key, or
/// either JWT PEM (a torn pair included) — marks the volume for the
/// conversion page. The sealed predicate outranks this one at the boot
/// (`main` checks it first), so a torn conversion's stray plaintext
/// under a present `master.envelope` still boots the unlock path.
pub fn legacy_volume(keys_dir: &Path) -> bool {
    [
        "master.key",
        ws_api::state::SECRET_KEY_FILE,
        "jwt-signing-key.pem",
        "jwt-verify-key.pem",
    ]
    .iter()
    .any(|file| keys_dir.join(file).exists())
}

type InitState = (Arc<SealedUi>, std::path::PathBuf, String, String);

/// The conversion front door: the INIT page, the health surface, the
/// conversion POST, and the 503 delegate for everything else. Served by
/// `main` while the volume holds plaintext; the delegate hands over to
/// the full `web_router` the moment the conversion succeeds (no
/// restart, no re-listen — the `resume` contract).
pub fn init_router(
    ui: Arc<SealedUi>,
    keys_dir: &Path,
    database_url: &str,
    hostname: &str,
    rate_limit: Option<ws_api::AuthRateLimit>,
) -> Router {
    let hostname = hostname.to_owned();
    let keys_dir = keys_dir.to_path_buf();
    let database_url = database_url.to_owned();
    let state = (ui.clone(), keys_dir, database_url, hostname);
    // The conversion POST SETS the master passphrase — the most
    // sensitive credential the instance has — so it carries the same
    // per-IP GCRA the unlock route does (spec §5.1's shared budget).
    let init = crate::gcra(
        Router::new().route("/init", post(init_handler)),
        rate_limit,
        "/init",
    )
    .with_state(state.clone());
    Router::new()
        .route("/", get(init_page))
        .route("/healthz", get(init_healthz))
        .with_state(state)
        .merge(init)
        .fallback_service(SealedWebDelegate {
            ui,
            refusal: unsealed_503,
        })
}

async fn init_healthz(State((ui, _, _, _)): State<InitState>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "state": if ui.is_unlocked() { "unlocked" } else { "uninitialized" },
        })),
    )
        .into_response()
}

async fn init_page(State((ui, _, _, hostname)): State<InitState>) -> Response {
    // Once the conversion + unlock succeed, the same listener must not
    // keep telling the operator the volume "holds unsealed key files"
    // at "/" — they are routed to the normal login (the final review's
    // G3, the INIT door's half).
    if ui.is_unlocked() {
        return axum::response::Redirect::to("/login").into_response();
    }
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        render_init_page(&hostname),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct InitBody {
    passphrase: String,
    repeat: String,
}

async fn init_handler(
    State((ui, keys_dir, database_url, _)): State<InitState>,
    Json(body): Json<InitBody>,
) -> Response {
    // The validation runs BEFORE anything touches the volume or the
    // database: a refusal must be side-effect-free.
    if body.passphrase.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": { "code": "passphrase_required",
                    "message": "a master passphrase is required: it seals every key \
                                on this instance and is not recoverable" }
            })),
        )
            .into_response();
    }
    if body.passphrase != body.repeat {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": { "code": "passphrase_mismatch",
                    "message": "the passphrase and its confirmation do not match" }
            })),
        )
            .into_response();
    }

    // The conversion step is skipped when the volume is already sealed —
    // a retry after a conversion whose unlock step failed finds nothing
    // left to convert and falls through to the plain unlock.
    if !keys_dir.join(MASTER_ENVELOPE_FILE).exists() {
        if let Err(reason) = convert_volume(&keys_dir, &body.passphrase, &database_url).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": { "code": "conversion_failed", "message": reason }
                })),
            )
                .into_response();
        }
    }

    match ui.unlock(&body.passphrase, None).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "state": "unlocked",
                "message": "the volume is converted and unlocked; redirecting to the login",
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
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": { "code": "unlock_failed",
                    "message": "the volume converted but the unlock was refused; \
                                retry the POST — the conversion step is already done" }
            })),
        )
            .into_response(),
    }
}

/// The one-time conversion over a fresh pool from the environment's
/// `DATABASE_URL` (a legacy install's URL still authenticates — the
/// rotation retires it). The pool closes before the unlock runs: the
/// unlocked router builds its own pool from the sealed credential.
async fn convert_volume(
    keys_dir: &Path,
    passphrase: &str,
    database_url: &str,
) -> Result<(), String> {
    let role = ws_core::crypto::db_role_of(database_url)
        .map_err(|e| format!("the conversion's database URL: {e}"))?;
    let pool = sqlx::PgPool::connect(database_url)
        .await
        .map_err(|e| format!("the conversion's database connection: {e}"))?;
    let sealed = crate::setup::seal_keys_volume(keys_dir, passphrase, &pool, &role).await;
    pool.close().await;
    sealed.map_err(|e| format!("the conversion: {e}"))
}

fn unsealed_503() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": { "code": "uninitialized",
                "message": "the instance still holds plaintext key files: \
                            convert to continue" }
        })),
    )
        .into_response()
}

/// The INIT page: server-rendered HTML (the SPA may not exist on a
/// legacy volume's boot), two fields, one button, no JavaScript beyond
/// the POST — the same shape the unlock page uses.
fn render_init_page(hostname: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Wardstone — unsealed</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 28rem; margin: 3rem auto; padding: 0 1rem; }}
h1 {{ font-size: 1.3rem; }}
input {{ box-sizing: border-box; width: 100%; padding: 0.5rem; font-size: 1rem; margin-top: 0.4rem; }}
button {{ margin-top: 1rem; padding: 0.6rem 1.4rem; font-size: 1rem; }}
#result {{ margin-top: 1rem; font-weight: 600; }}
</style>
</head>
<body>
<h1>{hostname} holds unsealed key files</h1>
<p>This instance still stores its keys as plaintext files. Set the master
passphrase to perform the one-time conversion: every key file wraps into a
passphrase-sealed envelope, the database credential rotates, and the
plaintext originals are deleted. The next boot asks for this passphrase and
cannot open without it — it is stored nowhere and <strong>cannot be recovered</strong>.</p>
<form id="init-form">
<label for="passphrase">Master passphrase</label>
<input id="passphrase" type="password" autocomplete="off" required>
<label for="repeat-passphrase">Repeat the master passphrase</label>
<input id="repeat-passphrase" type="password" autocomplete="off" required>
<button type="submit">Convert and continue</button>
</form>
<div id="result"></div>
<script>
document.getElementById('init-form').addEventListener('submit', async (event) => {{
  event.preventDefault();
  const note = document.getElementById('result');
  try {{
    const response = await fetch('/init', {{
      method: 'POST',
      headers: {{ 'content-type': 'application/json' }},
      body: JSON.stringify({{
        passphrase: document.getElementById('passphrase').value,
        repeat: document.getElementById('repeat-passphrase').value,
      }}),
    }});
    if (response.ok) {{
      window.location = '/';
    }} else {{
      const body = await response.json().catch(() => ({{}}));
      note.textContent = body.error?.message || 'The conversion failed';
      note.style.color = '#a11';
    }}
  }} catch (error) {{
    note.textContent = 'The conversion failed: ' + error;
    note.style.color = '#a11';
  }}
}});
</script>
</body>
</html>
"#,
        hostname = hostname,
    )
}
