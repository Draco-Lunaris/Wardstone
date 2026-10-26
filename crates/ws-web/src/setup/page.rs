//! The first-run setup page: the GET renders the form (with the setup
//! certificate's SHA-256 fingerprint for out-of-band verification) and
//! the POST runs the bootstrap.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use thiserror::Error;
use zeroize::Zeroizing;

use super::{run_setup, validate_hostname_permitted, SetupError, SetupFields, SetupState};

/// The setup page. The fingerprint is the SHA-256 of the DER of the
/// certificate the TLS listener is serving for THIS request — the binary
/// computes it when it mounts the setup page and passes it through
/// [`SetupState`] — so the operator verifies the certificate out of band
/// instead of clicking through a browser warning.
pub async fn setup_page(State(state): State<SetupState>) -> Html<String> {
    Html(render(&state.fingerprint, &state.hostname))
}

/// The setup submit: validate, run the seal-at-creation bootstrap (the
/// pool rides the typed `db_password`; the master envelope lands LAST;
/// the DB credential rotation follows the commit), relay the unlock to
/// the api, resume the listener onto the CA-issued leaf IN PLACE, and
/// report.
///
/// The relay order is the design's (the D1 step list's successor): it
/// runs AFTER the rotation inside [`run_setup`] — so the api's unlock
/// opens the ROTATED credential — and BEFORE the TLS swap below.
pub async fn submit_setup(
    State(state): State<SetupState>,
    Json(fields): Json<SetupFields>,
) -> Result<Json<serde_json::Value>, SubmitError> {
    validate(&fields).map_err(SubmitError::BadRequest)?;

    // The Plan-2 I-3 fix's primary seam: refuse a `server_hostname` the
    // built-in `web-server` profile's SAN patterns forbid BEFORE any
    // bootstrap work — nothing is committed, the form gets a 400. The
    // same check is re-applied by `run_setup` inside its setup
    // transaction as defense-in-depth for direct library callers (see
    // `validate_hostname_permitted`'s "two checks").
    validate_hostname_permitted(&fields).map_err(SubmitError::BadRequest)?;

    let keys_dir = state.keys_dir.clone();
    let outcome = run_setup(&fields, &state.database_url, &keys_dir).await?;

    // The fresh-install flow's api half (the compose contract): the api
    // process booted as the sealed shell — its password-less
    // DATABASE_URL leaves it nothing to build a pool from — and this one
    // relay is the event that brings its full surface up. It runs AFTER
    // the rotation (the api's unlock opens the rotated credential).
    // Best-effort BY DESIGN (spec §5): a relay that does not land leaves
    // the api sealed, the logged verdict names it, and the documented
    // recovery is the api's restart plus its own unlock — the operator's
    // setup result never depends on it.
    if let Err(reason) =
        crate::locked::relay_unlock(&keys_dir, &state.api_base_url, &fields.master_passphrase).await
    {
        tracing::warn!(
            error = %reason,
            "the setup commit's api unlock relay did not land; the api stays \
             sealed until its restart and unlock"
        );
    }

    // The resume contract: the listener swaps onto the CA-issued leaf IN
    // PLACE — no restart, no re-listen. The operator continues straight
    // to the login on the same connection. The leaf key's PEM lives in a
    // `Zeroizing` buffer until the reload consumes it (Task 8's resolver
    // removes this interim PEM handoff).
    if let Some(reload) = state.tls_reload.clone() {
        let key_pem = pkcs8_pem_of(&outcome.leaf_key);
        reload
            .reload_from_pem(
                outcome.leaf_cert_pem.clone().into_bytes(),
                key_pem.as_str().as_bytes().to_vec(),
            )
            .await
            .map_err(|e| {
                SubmitError::Setup(SetupError::Ca(ws_ca::error::CaError::Worker(format!(
                    "the TLS resume failed: {e}"
                ))))
            })?;
        tracing::info!("the listener resumed onto the CA-issued leaf in place");
    }

    Ok(Json(serde_json::json!({
        "status": "ok",
        "resume": true,
        "message": "Wardstone is configured and sealed: the master passphrase you set \
                    unlocks every future start of this instance. Continue to the login.",
        "hostname": fields.server_hostname,
    })))
}

/// A PKCS#8 DER private key as the PEM form the reload takes (the same
/// 64-column wrapping the house uses). The returned buffer is
/// `Zeroizing`: the leaf key's PEM form exists only for the reload's
/// interim handoff (Task 8's resolver removes it).
fn pkcs8_pem_of(der: &ws_secmem::SecretBuf) -> Zeroizing<String> {
    use base64::Engine as _;

    let body = base64::engine::general_purpose::STANDARD.encode(&der[..]);
    let mut pem = Zeroizing::new(String::from("-----BEGIN PRIVATE KEY-----\n"));
    let mut rest = body.as_str();
    while !rest.is_empty() {
        let (line, tail) = rest.split_at(rest.len().min(64));
        pem.push_str(line);
        pem.push('\n');
        rest = tail;
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem
}

/// A setup-submit failure: the typed vocabulary the seal-at-creation
/// bootstrap produces. The page answers a 400 the operator can retry
/// (form checks, a wrong database password), a 409 for an existing
/// install (the state conflict — this pair of volumes cannot proceed at
/// all), and a 500 for everything else (the server logs carry the typed
/// message). No message ever carries key material, a passphrase, or a
/// password.
#[derive(Debug, Error)]
pub enum SubmitError {
    /// The form failed its basic checks.
    #[error("invalid setup form: {0}")]
    BadRequest(String),
    /// The bootstrap (or the TLS resume around it) failed.
    #[error(transparent)]
    Setup(#[from] SetupError),
}

impl IntoResponse for SubmitError {
    fn into_response(self) -> Response {
        match self {
            SubmitError::BadRequest(message) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": message })),
            )
                .into_response(),
            // The operator can retry with corrected input; the copy is
            // the form's own, never internals.
            SubmitError::Setup(SetupError::Validation(message)) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": message })),
            )
                .into_response(),
            SubmitError::Setup(SetupError::DbRejected) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "the database rejected that password" })),
            )
                .into_response(),
            // The copy is the design's exact refusal — verbatim.
            SubmitError::Setup(SetupError::InstallExists) => (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "the database already holds an install but the keys volume \
                     is empty — restore the matching keys volume, or remove both \
                     volumes and run setup again"
                })),
            )
                .into_response(),
            SubmitError::Setup(other) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": other.to_string() })),
            )
                .into_response(),
        }
    }
}

/// The server-side form checks (matching `run_setup`'s own policy) so a
/// blank field is a 400 for the form user, not a 500 from the bootstrap.
fn validate(fields: &SetupFields) -> Result<(), String> {
    // The master passphrase: required, confirmed. The page warns it is
    // not recoverable — the validation refuses blanks and mismatches with
    // the same 400 shape as every other field.
    if fields.master_passphrase.trim().is_empty() {
        return Err("a master passphrase is required: it seals every key on this              instance and is not recoverable"
            .to_string());
    }
    if fields.master_passphrase != fields.master_passphrase_confirm {
        return Err("the master passphrase and its confirmation do not match".to_string());
    }
    let required = [
        ("admin_username", fields.admin_username.as_str()),
        ("admin_password", fields.admin_password.as_str()),
        ("default_domain", fields.default_domain.as_str()),
        ("server_hostname", fields.server_hostname.as_str()),
        ("db_password", fields.db_password.as_str()),
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
    master_passphrase: form.master_passphrase.value,
    master_passphrase_confirm: form.master_passphrase_confirm.value,
    admin_username: form.admin_username.value,
    admin_password: form.admin_password.value,
    default_domain: form.default_domain.value,
    admin_cidrs: form.admin_cidrs.value.split(',').map(s => s.trim()).filter(Boolean),
    server_hostname: form.server_hostname.value,
    db_password: form.db_password.value,
  };
  const note = document.getElementById('result');
  try {
    const response = await fetch('/setup', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const body = await response.json().catch(() => ({}));
    if (response.ok) {
      note.style.color = '#161';
      // NOTE: this script lives inside a Rust double-quoted string — the JS
      // must never contain a raw double quote. The login link is therefore
      // built with DOM calls (single quotes only).
      const login = document.createElement('a');
      login.href = location.origin + '/';
      login.textContent = 'open the operator login';
      note.textContent = 'Setup complete. This instance is sealed — ' + body.message + ' ';
      note.appendChild(login);
      note.insertAdjacentText('beforeend',
        ' Log in with the admin account you just created. Expect one more ' +
        'certificate warning on the new leaf, and accept it once: from now on ' +
        'every restart of this instance shows the sealed page first.');
    } else {
      note.textContent = body.error || 'Setup failed';
      note.style.color = '#a11';
    }
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
            "<p class=\"hint\"><strong>Set the master passphrase.</strong> It seals every key on this \
     instance — the CA keys, the database credential, the session keys — into ciphertext that only \
     this passphrase opens. It is stored nowhere and <strong>cannot be recovered</strong>: keep it in \
     your password manager. Every future start of this instance asks for it.</p>\n",
    "<label for=\"master_passphrase\">Master passphrase (seals every key; not recoverable)</label>\n",
    "<input id=\"master_passphrase\" name=\"master_passphrase\" type=\"password\" autocomplete=\"new-password\" required>\n",
    "<label for=\"master_passphrase_confirm\">Confirm the master passphrase</label>\n",
    "<input id=\"master_passphrase_confirm\" name=\"master_passphrase_confirm\" type=\"password\" autocomplete=\"new-password\" required>\n",
    "<label for=\"admin_username\">Admin username</label>\n",
            "<input id=\"admin_username\" name=\"admin_username\" autocomplete=\"username\" required>\n",
            "<label for=\"admin_password\">Admin password</label>\n",
            "<input id=\"admin_password\" name=\"admin_password\" type=\"password\" autocomplete=\"new-password\" required>\n",
            "<label for=\"default_domain\">Default domain — the SAN scope for issued certificates</label>\n",
            "<input id=\"default_domain\" name=\"default_domain\" placeholder=\"example.com\" required>\n",
            "<p class=\"hint\">The <strong>bare registrable domain</strong> every issued certificate's name must fit \
             — e.g. <code>example.com</code>, never <code>*.example.com</code> or <code>certificates.example.com</code>. \
             Profile SAN patterns derive from it (the domain itself plus one-label subdomains), and the server \
             hostname below must be a subdomain of it.</p>\n",
            "<label for=\"admin_cidrs\">Admin CIDRs (comma-separated, optional)</label>\n",
            "<textarea id=\"admin_cidrs\" name=\"admin_cidrs\" rows=\"2\" placeholder=\"10.0.0.0/8, 192.168.0.0/16\"></textarea>\n",
            "<label for=\"server_hostname\">Server hostname — must be a subdomain of the default domain</label>\n",
            "<input id=\"server_hostname\" name=\"server_hostname\" placeholder=\"wardstone.example.com\" required>\n",
            "<p class=\"hint\">The server hostname is the SAN of the certificate this UI \
             will serve after setup — it is not derived from the default domain, but it MUST \
             fall under the default domain above (e.g. <code>wardstone.example.com</code> \
             with default domain <code>example.com</code>).</p>\n",
            "<label for=\"db_password\">Database password — the login credential DATABASE_URL's role carries today</label>\n",
            "<input id=\"db_password\" name=\"db_password\" type=\"password\" autocomplete=\"current-password\" required>\n",
            "<p class=\"hint\">Setup connects with this password exactly once, rotates the \
             database role to a fresh random credential, and seals that one under the master \
             passphrase — the password you type here is never stored.</p>\n",
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
