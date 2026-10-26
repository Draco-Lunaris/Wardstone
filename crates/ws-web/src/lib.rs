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
//! earlier routes always win. [`serve_tls_with_config`] is the listener
//! the Task 12
//! binary puts that router on: HTTPS from the very first request, on
//! either the setup certificate or the CA-issued leaf — with the client's
//! socket address attached to every request (`ConnectInfo`, Task 12's
//! per-IP limiter's key input).

pub mod locked;
pub mod proxy;
pub mod session;
pub mod setup;
pub mod tls_signer;
pub mod ui;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use axum::Extension;
use axum::Router;
use sqlx::PgPool;
use ws_ca::error::CaError;

use session::relay::relay_router;
use session::store::SessionStore;

/// Mount the per-IP GCRA on a credential sub-router (spec §5.1: the
/// unlock and setup POSTs are credential surfaces — wrong
/// passphrases cost argon2 memory-hard compute AND a bucket credit,
/// with the house defaults the auth surface shares). The ONE home for
/// the mount: the `/auth/ui` relay routes and the locked door's
/// `POST /unlock` pass through here, keyed on the connected socket the TLS listener attaches
/// (`ConnectInfo`; the tests inject the same extension).
pub(crate) fn gcra<S>(
    router: Router<S>,
    rate_limit: Option<ws_api::AuthRateLimit>,
    surface: &str,
) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    match rate_limit {
        Some(limit) => {
            // `finish()` fails only on a zero burst or period (both
            // caller-configured; the binary refuses a zero at boot, so
            // this skip branch is unreachable from `run_ui`). The router
            // constructor cannot be fallible — mirroring ws-api, a broken
            // number is a LOUDLY-LOGGED skip of the layer, never a panic
            // at boot.
            match tower_governor::governor::GovernorConfigBuilder::<
                tower_governor::key_extractor::PeerIpKeyExtractor,
                _,
            >::default()
            .per_millisecond(limit.per_millis)
            .burst_size(limit.burst)
            .finish()
            {
                Some(config) => router.layer(tower_governor::GovernorLayer::new(
                    std::sync::Arc::new(config),
                )),
                None => {
                    tracing::error!(
                        per_millis = limit.per_millis,
                        burst = limit.burst,
                        "invalid rate-limit configuration on {surface}: per_millis and \
                         burst must be positive; the {surface} routes run WITHOUT rate \
                         limiting"
                    );
                    router
                }
            }
        }
        None => router,
    }
}

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
///
/// `tls_reload` is the listener's serving-certificate RESOLVER — the
/// handle the SETUP branch's commit swaps onto the CA-issued leaf in
/// place (the resume contract; the swap IS the reload, see
/// [`tls_signer::SwapResolver`]). It matters only while the setup
/// surface mounts (no tenant yet): the binary passes `Some(clone)` on
/// that boot path and `None` on the others; tests pass `None` (no
/// listener to swap).
#[allow(clippy::too_many_arguments)]
pub async fn web_router(
    pool: PgPool,
    keys_dir: PathBuf,
    fingerprint: String,
    hostname: String,
    tls_reload: Option<std::sync::Arc<tls_signer::SwapResolver>>,
    api_base_url: &str,
    database_url: String,
    session_access_ttl: Duration,
    rate_limit: Option<ws_api::AuthRateLimit>,
) -> Result<Router, CaError> {
    let store = std::sync::Arc::new(SessionStore::new(session_access_ttl, DEFAULT_IDLE_EVICTION));
    web_router_with_store(
        pool,
        keys_dir,
        fingerprint,
        hostname,
        tls_reload,
        api_base_url,
        database_url,
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
#[allow(clippy::too_many_arguments)]
pub async fn web_router_with_store(
    pool: PgPool,
    keys_dir: PathBuf,
    fingerprint: String,
    hostname: String,
    tls_reload: Option<std::sync::Arc<tls_signer::SwapResolver>>,
    api_base_url: &str,
    database_url: String,
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
            keys_dir,
            fingerprint,
            hostname,
            tls_reload,
            api_base_url: api_base_url.to_owned(),
            database_url,
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
    Ok(app.fallback_service(ui::ui_router()))
}

/// The DB-free core of [`web_router_with_store`]: the `/auth/ui` relay
/// nest, the `/api/v1` proxy (its auth routes limiter-scoped per
/// `rate_limit`), and the `/acme` proxy (its ENROLLMENT route
/// limiter-scoped per the SAME value — the one unauthenticated ACME
/// mutator, per-IP limited at this edge because ws-api's per-IP bucket
/// collapses behind the proxy; the rest of `/acme` forwards unlimited),
/// and the `/healthz` liveness route (see the route's own comment)
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
        // Liveness, the compose contract: always 200 with a state field,
        // never a readiness gate — a correctly-locked service is never
        // restart-churned by its own healthcheck. The locked router owns
        // the route in the sealed lifecycle (`sealed`/`unlocked`); this
        // one answers the UNSEALED boot. It must be a real route, not a
        // fallback catch: left unrouted, the extension-less GET would
        // fall through to the SPA document, answering a live-looking 200
        // + `index.html` that says nothing.
        .route(
            "/healthz",
            axum::routing::get(|| async { axum::Json(serde_json::json!({ "state": "serving" })) }),
        )
}

/// The FIRST-RUN front-door router (Task 7's boot rule): the setup
/// surface with NO database connection behind it. The boot dispatched on
/// the sealed marker's ABSENCE — a fresh install, where no tenant can
/// exist behind an unsealed volume and setup is the only path in — so
/// this router is built WITHOUT a pool: the RAM-only certificate, the
/// setup page, the session relay, and the proxies are the whole
/// surface, and the setup POST is the first thing that ever dials the
/// database (with the operator's typed password, via
/// [`setup::run_setup`]). A pool-less router is what makes the
/// closed-port boot test pin real behavior: the process serves the
/// page while `DATABASE_URL` points at a dead port, and a restart
/// before setup writes nothing and accumulates nothing.
///
/// `tls_reload` is the listener's serving-certificate RESOLVER — the
/// handle the setup commit swaps onto the CA-issued leaf in place (the
/// resume contract; the swap IS the reload); the boot passes
/// `Some(clone)`.
#[allow(clippy::too_many_arguments)]
pub fn first_run_web_router(
    keys_dir: PathBuf,
    fingerprint: String,
    hostname: String,
    tls_reload: Option<std::sync::Arc<tls_signer::SwapResolver>>,
    api_base_url: &str,
    database_url: String,
    session_access_ttl: Duration,
    rate_limit: Option<ws_api::AuthRateLimit>,
) -> Router {
    let store = std::sync::Arc::new(SessionStore::new(session_access_ttl, DEFAULT_IDLE_EVICTION));
    session_router_with_store(store, api_base_url, rate_limit)
        .merge(setup_router(SetupState {
            keys_dir,
            fingerprint,
            hostname,
            tls_reload,
            api_base_url: api_base_url.to_owned(),
            database_url,
        }))
        // The SPA rides LAST as always: the setup routes and the proxy
        // above are never masked.
        .fallback_service(ui::ui_router())
}

/// The UNLOCKED front-door router (Task 7's pool release, Review Focus
/// 1): the session relay, the `/api/v1` and `/acme` proxies, the plain
/// 404s for the retired setup surface, and the SPA — with NO database
/// pool anywhere in it. The unlock build resolved the tenant and the
/// serving leaf BEFORE the api relay (whose rotation invalidates every
/// fresh ui connection) and released its pool; this router serves
/// pool-less for the process's whole remaining life, and everything
/// database-touching rides the proxy to the api.
pub fn unlocked_web_router(
    api_base_url: &str,
    session_access_ttl: Duration,
    rate_limit: Option<ws_api::AuthRateLimit>,
) -> Router {
    let store = std::sync::Arc::new(SessionStore::new(session_access_ttl, DEFAULT_IDLE_EVICTION));
    session_router_with_store(store, api_base_url, rate_limit)
        .merge(setup_unmounted_router())
        .fallback_service(ui::ui_router())
}

/// Serve `router` under TLS from `resolver`'s CURRENT certificate pair
/// (the serving-certificate resolver — [`tls_signer::SwapResolver`]).
/// The sealed boot binds with the ephemeral certificate and the unlock
/// closure — or the setup commit on the first-run listener — swaps the
/// same listener onto the CA-issued leaf: the swap IS the reload, no
/// re-listen and no restart at any point.
pub async fn serve_tls_with_config(
    addr: SocketAddr,
    resolver: std::sync::Arc<tls_signer::SwapResolver>,
    router: Router,
) -> Result<(), CaError> {
    let config = tls_signer::rustls_server_config(resolver)?;
    axum_server::tls_rustls::bind_rustls(
        addr,
        axum_server::tls_rustls::RustlsConfig::from_config(std::sync::Arc::new(config)),
    )
    .serve(router.into_make_service_with_connect_info::<SocketAddr>())
    .await
    .map_err(CaError::Io)
}
