//! The first-run setup page: the GET renders the form (with the setup
//! certificate's SHA-256 fingerprint for out-of-band verification) and
//! the POST runs the bootstrap.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use thiserror::Error;

use super::{run_setup, validate_hostname_permitted, SetupFields, SetupState};

/// The setup page. The fingerprint is the SHA-256 of the DER of the
/// certificate the TLS listener is serving for THIS request — the binary
/// computes it when it mounts the setup page and passes it through
/// [`SetupState`] — so the operator verifies the certificate out of band
/// instead of clicking through a browser warning.
pub async fn setup_page(State(state): State<SetupState>) -> Html<String> {
    Html(render(&state.fingerprint, &state.hostname))
}

/// The setup submit: validate, run the bootstrap, and report.
///
/// # The TLS switch is a process restart
///
/// The bootstrap has written the CA-issued leaf into the keystore (its
/// certificate row and key envelope) by the time this response is sent;
/// the response body carries `"restart": true`, and the `wardstone ui`
/// binary treats THAT as its signal to exit with a success code, letting
/// the compose service's `restart: unless-stopped` bring the process back
/// up serving the CA-issued certificate. axum-server also supports a
/// graceful listener restart, but the exit-and-restart path is the
/// simplest correct implementation for a single-purpose, stateless
/// process — and it re-runs the boot checks the process owns (JWT keys,
/// keystore open, conditional setup mount) instead of hot-swapping one
/// certificate underneath them.
pub async fn submit_setup(
    State(state): State<SetupState>,
    Json(fields): Json<SetupFields>,
) -> Result<Json<serde_json::Value>, SubmitError> {
    validate(&fields).map_err(SubmitError::BadRequest)?;

    // The Plan-2 I-3 fix's primary seam: refuse a `server_hostname` the
    // built-in `web-server` profile's SAN patterns forbid BEFORE any
    // bootstrap work — nothing is committed, the form gets a 400. The
    // same check is re-applied by `run_setup` inside its leaf transaction
    // as defense-in-depth for direct library callers (see
    // `validate_hostname_permitted`'s "two checks").
    validate_hostname_permitted(&fields).map_err(SubmitError::BadRequest)?;

    let keys_dir = state.keys_dir;
    let mut keystore = ws_ca::keystore::KeyStore::open(&keys_dir)?;
    run_setup(&fields, &state.pool, &mut keystore).await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "restart": true,
        "message": "Wardstone is configured. The UI process must restart now to serve \
                    TLS from the CA-issued certificate; it will come back on its own.",
        "hostname": fields.server_hostname,
    })))
}

/// A setup-submit failure: a malformed form is the caller's mistake (400),
/// anything the bootstrap rejects is an operator problem to look at (500,
/// with the typed message).
#[derive(Debug, Error)]
pub enum SubmitError {
    /// The form failed its basic checks.
    #[error("invalid setup form: {0}")]
    BadRequest(String),
    /// The bootstrap transaction (or the TLS material around it) failed.
    #[error(transparent)]
    Setup(#[from] ws_ca::error::CaError),
}

impl IntoResponse for SubmitError {
    fn into_response(self) -> Response {
        match self {
            SubmitError::BadRequest(message) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": message })),
            )
                .into_response(),
            SubmitError::Setup(inner) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": inner.to_string() })),
            )
                .into_response(),
        }
    }
}

/// The server-side form checks (matching `run_setup`'s own policy) so a
/// blank field is a 400 for the form user, not a 500 from the bootstrap.
fn validate(fields: &SetupFields) -> Result<(), String> {
    let required = [
        ("admin_username", fields.admin_username.as_str()),
        ("admin_password", fields.admin_password.as_str()),
        ("default_domain", fields.default_domain.as_str()),
        ("server_hostname", fields.server_hostname.as_str()),
    ];
    for (name, value) in required {
        if value.trim().is_empty() {
            return Err(format!("{name} must not be blank"));
        }
    }
    if fields.admin_cidrs.iter().any(|cidr| cidr.trim().is_empty()) {
        return Err("admin_cidrs entries must not be blank".to_owned());
    }
    Ok(())
}

/// The page's stylesheet. Kept out of the `format!` templates so the CSS
/// braces stay plain.
const STYLE: &str = "
body { font-family: system-ui, sans-serif; margin: 3rem auto; max-width: 34rem; color: #1a1a2a; }
h1 { font-size: 1.4rem; }
code.fingerprint { display: block; word-break: break-all; font-size: 0.8rem; background: #f2f2f6; padding: 0.6rem; border-radius: 4px; }
form label { display: block; margin-top: 0.9rem; font-weight: 600; font-size: 0.9rem; }
form input, form textarea { box-sizing: border-box; width: 100%; padding: 0.45rem; font-size: 1rem; }
button { margin-top: 1.2rem; padding: 0.6rem 1.4rem; font-size: 1rem; }
#result { margin-top: 1rem; font-weight: 600; }
.hint { color: #555; font-size: 0.85rem; }
";

/// The form's submit script. Kept out of the `format!` templates so the
/// JS braces stay plain.
const SCRIPT: &str = "
document.getElementById('setup-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.target;
  const payload = {
    admin_username: form.admin_username.value,
    admin_password: form.admin_password.value,
    default_domain: form.default_domain.value,
    admin_cidrs: form.admin_cidrs.value.split(',').map(s => s.trim()).filter(Boolean),
    server_hostname: form.server_hostname.value,
  };
  const note = document.getElementById('result');
  try {
    const response = await fetch('/setup', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const body = await response.json().catch(() => ({}));
    note.textContent = response.ok ? body.message : (body.error || 'Setup failed');
    if (!response.ok) { note.style.color = '#a11'; }
  } catch (error) {
    note.textContent = 'Setup failed: ' + error;
    note.style.color = '#a11';
  }
});
";

/// Render the setup page.
fn render(fingerprint: &str, hostname: &str) -> String {
    let fingerprint = html_escape(fingerprint);
    let hostname = html_escape(hostname);
    format!(
        concat!(
            "<!doctype html>\n",
            "<html lang=\"en\">\n",
            "<head>\n",
            "<meta charset=\"utf-8\">\n",
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
            "<title>Wardstone — first-run setup</title>\n",
            "<style>{style}</style>\n",
            "</head>\n",
            "<body>\n",
            "<h1>Wardstone — first-run setup</h1>\n",
            "<p>This instance is not configured yet: creating the first admin account \
             below sets up the tenant, the root certificate authority, and the built-in \
             certificate profiles.</p>\n",
            "<p class=\"hint\">Your browser is on a self-signed setup certificate for \
             <strong>{hostname}</strong>. To make sure you are really talking to this \
             instance, verify its SHA-256 fingerprint out of band:</p>\n",
            "<code class=\"fingerprint\">{fingerprint}</code>\n",
            "<form id=\"setup-form\">\n",
            "<label for=\"admin_username\">Admin username</label>\n",
            "<input id=\"admin_username\" name=\"admin_username\" autocomplete=\"username\" required>\n",
            "<label for=\"admin_password\">Admin password</label>\n",
            "<input id=\"admin_password\" name=\"admin_password\" type=\"password\" autocomplete=\"new-password\" required>\n",
            "<label for=\"default_domain\">Default domain</label>\n",
            "<input id=\"default_domain\" name=\"default_domain\" placeholder=\"certificates.example.com\" required>\n",
            "<label for=\"admin_cidrs\">Admin CIDRs (comma-separated, optional)</label>\n",
            "<textarea id=\"admin_cidrs\" name=\"admin_cidrs\" rows=\"2\" placeholder=\"10.0.0.0/8, 192.168.0.0/16\"></textarea>\n",
            "<label for=\"server_hostname\">Server hostname</label>\n",
            "<input id=\"server_hostname\" name=\"server_hostname\" placeholder=\"wardstone.example.com\" required>\n",
            "<p class=\"hint\">The server hostname is the SAN of the certificate this UI \
             will serve after setup — it is not derived from the default domain.</p>\n",
            "<button type=\"submit\">Complete setup</button>\n",
            "</form>\n",
            "<div id=\"result\"></div>\n",
            "<script>{script}</script>\n",
            "</body>\n",
            "</html>\n",
        ),
        style = STYLE,
        hostname = hostname,
        fingerprint = fingerprint,
        script = SCRIPT,
    )
}

/// Escape the few values interpolated into the page (the fingerprint and
/// hostname come from operator configuration, and a hostile value must not
/// become markup).
fn html_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// # Unit tests
#[cfg(test)]
mod tests {
    use super::{html_escape, render};

    /// The page shows the operator's fingerprint and hostname, escaped.
    #[test]
    fn test_render_escapes_and_shows_the_deployment_values() {
        let page = render("aabbccdd", "wardstone-ui.example.com");
        assert!(page.contains("<code class=\"fingerprint\">aabbccdd</code>"));
        assert!(page.contains("wardstone-ui.example.com"));
    }

    /// Markup in a configured value renders as text, never as tags.
    #[test]
    fn test_html_escape_neutralizes_markup() {
        assert_eq!(
            html_escape("<script>&\"'x"),
            "&lt;script&gt;&amp;&quot;&#39;x"
        );
        assert_eq!(html_escape("plain.value"), "plain.value");
    }
}
