//! ws-web: the TLS front door of the whole product — the first-run setup
//! surface, the `/api/v1` path proxy to the API process, and the TLS
//! listener glue the `wardstone` binary (Plan 2's Task 12) serves.
//!
//! - `setup` — the first-run flow: the setup page (GET), the setup submit
//!   (POST, running the bootstrap transaction), the conditional mounting
//!   ([`setup_router`] mounted only while no tenant exists —
//!   [`setup::tenant_exists`]), and the self-signed setup certificate
//!   whose SHA-256 fingerprint the page displays for out-of-band
//!   verification.
//! - `proxy` — the verbatim forwarders: the browser talks ONLY to
//!   ws-web; ws-api publishes no ports to the LAN, so every `/api/v1/*`
//!   request is proxied verbatim to the API base URL over the internal
//!   network, and so is every `/acme*` request (the RFC 8555 machine
//!   surface — no session machinery on it). ws-api's own routes are
//!   never mounted here.
//! - `ui` — the embedded SPA (`ui/dist`, git-committed and included into
//!   the binary with `include_dir` at compile time): `/`, the hashed
//!   `/assets/*`, and the SPA fallback, mounted LAST (the composed
//!   router's fallback) so it never masks the API or setup routes above
//!   it.
//! - `session` — the browser-session cookie plumbing: the wire form of the
//!   `wardstone_session` cookie and the `X-Requested-With: wardstone-ui`
//!   CSRF marker the proxy's rule requires (Task 12 adds the store).
//!
//! The three are composed by [`web_router`]: the API proxy is always
//! mounted, the setup routes exist only while the default tenant does not
//! (the setup endpoint is not routed once it does — the Review Focus item
//! 5 — not merely refused), and the SPA router rides the fallback, so
//! earlier routes always win. [`serve_tls`] is the listener the Task 12
//! binary puts that router on: HTTPS from the very first request, on
//! either the setup certificate or the CA-issued leaf — with the client's
//! socket address attached to every request (`ConnectInfo`, Task 12's
//! per-IP limiter's key input).

pub mod proxy;
pub mod session;
pub mod setup;
pub mod ui;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use axum::Extension;
use axum::Router;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sqlx::PgPool;
use ws_ca::error::CaError;

use session::relay::relay_router;
use session::store::SessionStore;

pub use proxy::{acme_router, api_router, api_router_with_auth_limit};
pub use setup::{
    run_setup, setup_router, setup_unmounted_router, tenant_exists, SetupFields, SetupState,
};

/// The default server-side access-token lifetime ws-web bookkeeps (15
/// minutes, matching ws-api's JWT access-token TTL): past this stamp the
/// proxy rotates proactively through one locked refresh. The `wardstone`
/// binary passes this value at [`web_router`]; env override is a Task 13
/// concern. Tests pass `Duration::ZERO` (always rotate).
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(900);

/// The default server-side idle-eviction window ws-web bookkeeps: an entry
/// nobody has touched for six hours (`get`, a login insert, or a token
/// rotation all touch) is dropped from the store the next time anything
/// reads it. This is memory hygiene for forgotten browser tabs, not
/// revocation: the ws-api refresh token a dropped entry carried stays valid
/// under the stateless-JWT model. Env override is a Task 13 concern.
pub const DEFAULT_IDLE_EVICTION: Duration = Duration::from_secs(6 * 3600);

/// The front-door router a fresh (`ui`-mode) process serves: the setup
/// surface ONLY while the default tenant does not exist, plus the
/// `/api/v1` proxy and the `/auth/ui` session relay in every phase. The
/// caller checks nothing — this function performs the `tenant_exists`
/// check itself, so the unmount mechanism is the EXPLICIT replacement
/// router: with the tenant present the setup routes are swapped for
/// [`setup_unmounted_router`]'s plain 404s — a request to `/setup` never
/// reaches the SPA fallback, which would otherwise answer 200 +
/// `index.html`.
///
/// The session store is constructed here with `session_access_ttl` (the
/// 15-minute [`DEFAULT_SESSION_TTL`] for the binary); tests that need a
/// handle on the SAME store instance use [`web_router_with_store`].
///
/// `rate_limit` is the GCRA configuration the binary parsed for the web
/// front door's auth surfaces (`Some` — the per-client-IP limiter
/// mounted on BOTH the `/auth/ui` relay nest AND the proxied
/// `POST /api/v1/auth/login`/`/refresh` routes; the ui binary always
/// configures it); the existing binary env contract feeds it, and tests
/// that run `web_router` pass `None` (no limiter — an in-process
/// oneshot request carries no `ConnectInfo` for the per-IP key extractor,
/// the same reason ws-api's tests disable its layer).
pub async fn web_router(
    pool: PgPool,
    keys_dir: PathBuf,
    fingerprint: String,
    hostname: String,
    api_base_url: &str,
    session_access_ttl: Duration,
    rate_limit: Option<ws_api::AuthRateLimit>,
) -> Result<Router, CaError> {
    let store = std::sync::Arc::new(SessionStore::new(session_access_ttl, DEFAULT_IDLE_EVICTION));
    web_router_with_store(
        pool,
        keys_dir,
        fingerprint,
        hostname,
        api_base_url,
        store,
        rate_limit,
    )
    .await
}

/// [`web_router`] with the caller owning the `Arc<SessionStore>` instance:
/// ws-web's relay routes and the proxy's Authorization injection MUST see
/// the SAME store (one instance answers login-minting and request-time
/// token reads) — this constructor is the pin that makes "same Arc"
/// structural instead of a promise, and it is how the session_test suite
/// inspects store contents alongside a live router.
///
/// `rate_limit` threads to auth surfaces AND the ACME enrollment edge —
/// [`relay_router`]'s `/auth/ui` GCRA nest, the proxy's `/api/v1/auth`
/// limiter scope, and the proxy's `/acme` ENROLLMENT route
/// (`POST /acme/{tenant}/new-account`, the one unauthenticated ACME
/// mutator — see [`proxy::acme_router`]; see [`web_router`] and
/// [`session_router_with_store`]).
pub async fn web_router_with_store(
    pool: PgPool,
    keys_dir: PathBuf,
    fingerprint: String,
    hostname: String,
    api_base_url: &str,
    store: std::sync::Arc<SessionStore>,
    rate_limit: Option<ws_api::AuthRateLimit>,
) -> Result<Router, CaError> {
    // The setup mounting contract, structurally: BOTH branches live in
    // this one if/else, so either the setup routes or their explicit 404
    // replacement ([`setup_unmounted_router`]) is mounted — never
    // neither. The explicit replacement is load-bearing: the SPA
    // fallback below catches any extension-less GET, so an unmounted
    // `/setup` left to it would answer 200 + index.html instead of the
    // plain 404 the setup/e2e suites pin (404, not 403).
    let app = if !tenant_exists(&pool).await? {
        session_router_with_store(store, api_base_url, rate_limit).merge(setup_router(SetupState {
            pool,
            keys_dir,
            fingerprint,
            hostname,
        }))
    } else {
        session_router_with_store(store, api_base_url, rate_limit).merge(setup_unmounted_router())
    };
    // The SPA router rides LAST: `fallback_service` runs only when no
    // earlier route matched (the precedence the ui-serve suite pins), so
    // the API proxy, the relay, and the setup surface above are never
    // masked. A Router is itself a fallback Service — `ui::ui_router()`
    // carries its own route tree (`/`, `/assets/*`, the SPA catch-all) and
    // its own routing.
    // The request-body ceiling: the SAME bound ws-api enforces, so the
    // proxy never accepts what the API would refuse (threat-model G12).
    let app = app.layer(axum::extract::DefaultBodyLimit::max(
        ws_api::REQUEST_BODY_LIMIT,
    ));
    // The response-header baseline (threat-model G4): nosniff, both forms
    // of frame denial, referrer minimization — on EVERY response ws-web
    // serves (SPA, setup page, proxied API/ACME bodies alike).
    let app = app.layer(axum::middleware::from_fn(security_headers));
    Ok(app.fallback_service(ui::ui_router()))
}

/// The response-header baseline. The CSP is deliberately narrow here:
/// `frame-ancestors 'none'` (clickjacking) without a default-src policy —
/// the SPA's asset story deserves its own task, and a hand-rolled
/// default-src that breaks assets would be its own security incident.
pub async fn security_headers(
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    let heads = response.headers_mut();
    heads.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    heads.insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    heads.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static("frame-ancestors 'none'"),
    );
    heads.insert(
        axum::http::header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    response
}

/// The DB-free core of [`web_router_with_store`]: the `/auth/ui` relay
/// nest, the `/api/v1` proxy (its auth routes limiter-scoped per
/// `rate_limit`), and the `/acme` proxy (its ENROLLMENT route
/// limiter-scoped per the SAME value — the one unauthenticated ACME
/// mutator, per-IP limited at this edge because ws-api's per-IP bucket
/// collapses behind the proxy; the rest of `/acme` forwards unlimited)
/// merged — every web-fronted route EXCEPT the setup surface and the SPA
/// fallback, which need the tenant check. Public so the rate-limit suite
/// can drive the COMPOSED stack (relay AND proxy in one router, the
/// precedence the real front door serves — static auth routes over the
/// catch-all) without a database.
///
/// The ONE store instance rides BOTH session surfaces: as the relay
/// routes' state (mint/rotate/kill) and as an `Extension` on the proxy
/// router (read-only injection). The `Option<Extension<_>>` extractor in
/// the proxy handler keeps `api_router` usable standalone (no store: zero
/// injection, the machine-token surface is untouched). The `/acme` proxy
/// intentionally gets NEITHER the store nor the session machinery — its
/// handler forwards JWS machine traffic verbatim (see
/// [`proxy::acme_router`]).
pub fn session_router_with_store(
    store: std::sync::Arc<SessionStore>,
    api_base_url: &str,
    rate_limit: Option<ws_api::AuthRateLimit>,
) -> Router {
    let api = api_router_with_auth_limit(api_base_url, rate_limit).layer(Extension(store.clone()));
    let relay = relay_router(store, api_base_url, rate_limit);
    Router::new()
        .merge(relay)
        .merge(api)
        .merge(acme_router(api_base_url, rate_limit))
}

/// Build the rustls [`rustls::ServerConfig`] for a PEM certificate paired
/// with a PKCS#8 DER private key (the exact form every envelope-encrypted
/// key in the keystore holds and every issued certificate is stored in).
///
/// The `ring` crypto provider is selected explicitly: the workspace pins
/// BOTH rustls edges with default features OFF (see the workspace
/// `Cargo.toml` — `aws-lc-rs` cannot build in this container image), and
/// no global default is installed, so this process makes the choice
/// per-config instead of relying on mutable process-wide state.
pub fn rustls_server_config(
    cert_pem: &str,
    key_der: &[u8],
) -> Result<rustls::ServerConfig, CaError> {
    let cert = rustls::pki_types::CertificateDer::from(pem_to_der(cert_pem)?);
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(key_der.to_vec());
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| CaError::X509(format!("tls: protocol versions: {err}")))?
        // No client certificate is accepted: the browser authenticates
        // with its login, not with client certificates.
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .map_err(|err| CaError::X509(format!("tls: certificate/key pair rejected: {err}")))
}

/// Serve `router` under TLS from `cert_pem` + `key_der` (PKCS#8 DER) on
/// `addr`. The Task 12 `ui` binary calls this on [`web_router`]'s output
/// with EITHER the setup certificate (the keystore setup slot,
/// `ca/setup.key`) while no tenant exists, OR the CA-issued server leaf
/// (cert: the `certificates` row, key: the envelope under the
/// certificate's id) after setup — a process restart, not a hot reload,
/// is the TLS switch between the two.
pub async fn serve_tls(
    addr: SocketAddr,
    router: Router,
    cert_pem: &str,
    key_der: &[u8],
) -> Result<(), CaError> {
    let config = rustls_server_config(cert_pem, key_der)?;
    // axum-server keeps the rustls config under an ArcSwap so an operator
    // tooling path could hot-reload it; we pass ours in wrapped once.
    axum_server::tls_rustls::bind_rustls(
        addr,
        axum_server::tls_rustls::RustlsConfig::from_config(std::sync::Arc::new(config)),
    )
    .serve(router.into_make_service_with_connect_info::<SocketAddr>())
    .await
    .map_err(CaError::Io)
}

/// A PEM body's DER bytes: the base64 payload between the BEGIN/END
/// lines. The workspace's own base64 encoder (the one ws-ca's keystore
/// and ws-api's export use); no extra PEM-parsing crate on top of rustls's
/// pki-types, which take DER only.
fn pem_to_der(pem: &str) -> Result<Vec<u8>, CaError> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    BASE64
        .decode(body)
        .map_err(|_| CaError::X509("pem body is not valid base64".to_owned()))
}

/// # Unit tests
#[cfg(test)]
mod tests {
    // A nested module does not inherit the crate root's trait import; the
    // Engine trait must be in scope for `STANDARD.encode` here.
    use base64::Engine as _;

    use super::pem_to_der;

    /// The PEM/DER helper accepts the exact PEM shapes ws-ca emits
    /// (64-character-wrapped base64 payloads between the BEGIN/END lines)
    /// and refuses a non-base64 body.
    #[test]
    fn test_pem_to_der_round_trips_and_refuses_garbage() {
        let der = b"some der bytes that must survive the round trip";
        let encoded = base64::engine::general_purpose::STANDARD.encode(der);
        let pem = format!("-----BEGIN CERTIFICATE-----\n{encoded}\n-----END CERTIFICATE-----\n");
        assert_eq!(
            pem_to_der(&pem).expect("decode the PEM body"),
            der.to_vec(),
            "the DER bytes must survive the PEM wrapper"
        );
        let bad = "-----BEGIN CERTIFICATE-----\nnot base64!!!\n-----END CERTIFICATE-----\n";
        assert!(pem_to_der(bad).is_err(), "a non-base64 body is refused");
    }
}
