//! The `wardstone` binary: ONE image with TWO invocation modes.
//!
//! - `wardstone ui` — the TLS front door: the first-run setup page while
//!   no tenant exists, the CA-issued server leaf afterwards, and the
//!   `/api/v1` proxy in every phase (all of the logic lives in `ws-web`).
//! - `wardstone api` — the REST surface, served DIRECTLY as plain HTTP
//!   for the internal network (the logic lives in `ws-api`).
//!
//! The separate-process anti-goal this shape realizes: the UI and the API
//! are independently restartable — the compose bundle (a later task) runs
//! them as two services of the same image, `wardstone ui` / `wardstone
//! api`, and `ws-web` publishes the only LAN port.
//!
//! `main` is a thin dispatcher: it parses the mode argument, reads the
//! shared environment contract, initializes logging, and hands over to
//! [`run_ui`] / [`run_api`]. The process lifecycle the binary owns:
//! open the pool (`ws_core::db::connect` runs the migrations), load OR
//! create the JWT key pair (`JwtKeys::load_or_create` — on a virgin volume
//! the keys must exist before the setup page can be served), open the
//! keystore, then serve.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use tracing_subscriber::EnvFilter;
use ws_ca::error::CaError;
use ws_ca::keystore::KeyStore;
use ws_core::error::CoreError;
use ws_core::models::certificate::{CertStatus, CertificateModel};
use ws_core::repo::certificate_repo::CertificateRepo;
use ws_core::repo::tenant_repo::TenantRepo;
use zeroize::Zeroizing;

/// The listen address when `WARDSTONE_BIND` is unset (the brief's pin).
const DEFAULT_BIND: &str = "0.0.0.0:8443";

/// The proxy target when `WARDSTONE_API_URL` is unset (the brief's pin):
/// the compose service name of the `api` mode on the internal network.
const DEFAULT_API_URL: &str = "http://ws-api:8080";

/// The auth-routes GCRA refill period when not configured (house value:
/// one credit per 500 ms — the same constants ws-api's `AuthRateLimit`
/// docs name as the house's).
const DEFAULT_RATE_PER_MILLIS: u64 = 500;

/// The auth-routes GCRA burst when not configured (house value: 20 per IP).
const DEFAULT_RATE_BURST: u32 = 20;

/// The built-in profile the serving leaf is issued under: setup mints the
/// UI's own leaf on `web-server`, and an operator re-issue of the server
/// leaf naturally rides the same built-in profile.
const SERVING_LEAF_PROFILE: &str = "web-server";

/// How often the setup watcher re-checks for a completed setup.
const SETUP_WATCH_INTERVAL: Duration = Duration::from_secs(1);

/// How long the watcher waits after the first sight of the tenant before
/// exiting: the setup POST's `restart: true` response (whose bootstrap
/// committed that tenant) must reach the operator's browser first.
const SETUP_EXIT_GRACE: Duration = Duration::from_secs(3);

/// The boot contract, read from the environment — the SAME contract for
/// both modes.
#[derive(Debug, Clone)]
struct BootConfig {
    /// `DATABASE_URL` (required): the Postgres connection URL.
    database_url: String,
    /// `WARDSTONE_KEYS_DIR` (required): the keystore directory — master
    /// KEK, CA key envelopes, the setup slot, the JWT key pair, and the
    /// secret-encryption key file all live under it.
    keys_dir: PathBuf,
    /// `WARDSTONE_SERVER_HOSTNAME`: the setup certificate's SAN. Absent
    /// means ws-web's `PLACEHOLDER_SAN` (the certificate is minted BEFORE
    /// the form is filled in, so its SAN can only come from the config).
    server_hostname: Option<String>,
    /// `WARDSTONE_API_URL`: ws-web's proxy target (`ui` only; `api` has
    /// no proxy). Defaults to [`DEFAULT_API_URL`].
    api_url: String,
    /// `WARDSTONE_BIND`: the listen address (both modes; the compose
    /// bundle gives each service its own value). Defaults to
    /// [`DEFAULT_BIND`].
    bind: SocketAddr,
    /// The public auth routes' rate limit (`api` only — the layer lives
    /// in ws-api and is keyed on the peer IP; `ui` mounts none of those
    /// routes, so a ui boot ignores this field entirely, including the
    /// disable switch below). `Some` (the limiter mounted) with the
    /// house defaults unless `WARDSTONE_RATE_LIMIT_PER_MILLIS` /
    /// `WARDSTONE_RATE_LIMIT_BURST` configure them; a zero value is a
    /// boot failure, not a silent un-limited listener. `None` when
    /// `WARDSTONE_AUTH_RATE_LIMIT_DISABLED` is truthy — the UI-fronted
    /// shape, where every operator login reaches ws-api through ws-web's
    /// proxy from ONE loopback IP and a per-IP limiter would throttle
    /// ALL operators collectively (ws-web enforces the per-client limit
    /// on `/auth/ui/*` instead). When the disable var is truthy the
    /// rate-limit env vars are NOT read or validated at all: any value
    /// they carry is inert.
    auth_rate_limit: Option<ws_api::AuthRateLimit>,
    /// The `/auth/ui` routes' rate limit (`ui` only): the per-client-IP
    /// GCRA ws-web mounts on the UI auth routes' nest (Task 13 — the
    /// Plan-2 I-1 limiter placement). In a UI-fronted deployment ws-api's
    /// own per-IP limiter sees only ws-web's proxy's ONE loopback IP, so
    /// ws-web is where the per-client limit lives. Parsed from the SAME
    /// `WARDSTONE_RATE_LIMIT_PER_MILLIS` / `_BURST` contract (defaults
    /// {DEFAULT_RATE_PER_MILLIS}/{DEFAULT_RATE_BURST}); keyed on the real
    /// peer address (`ConnectInfo`, Task 11's serving shape). Unlike the
    /// api field, the disable switch below does NOT gate it — a
    /// UI-fronted deployment disables ws-api's limiter BECAUSE ws-web
    /// limits instead, so a ui boot keeps this one mounted (and its env
    /// values validated) regardless of the switch. `None` in api mode (no
    /// web router exists to mount it on).
    web_rate_limit: Option<ws_api::AuthRateLimit>,
    /// The absolute URL base every ACME (RFC 8555) URL is built from
    /// (`WARDSTONE_PUBLIC_URL`, `api` only; e.g. `https://ca.home.test`).
    /// The ui mode constructs no ACME URLs and ignores it. OPTIONAL (the
    /// deployment choice): unset or blank leaves the process booting, but
    /// the ACME routes that would build an absolute URL answer the problem
    /// document `serverInternal` and the boot logs a loud warning — a
    /// misconfigured ACME env degrades the ACME surface alone, never the
    /// whole CA.
    public_url: Option<String>,
    /// The terms-of-service document URL (`WARDSTONE_ACME_TOS_URL`, `api`
    /// only, optional). Set, the directory answers with `Link:
    /// <tos>;rel="terms-of-service"` and `new-account` mints `pending`
    /// accounts until the client agrees; unset, there is no ToS flow at
    /// all (spec settlement 9).
    acme_tos_url: Option<String>,
    /// The ACME per-account rate limiter's config (`api` only): armed
    /// with the house rate defaults unless
    /// `WARDSTONE_ACME_ACCOUNT_LIMIT_DISABLED` is truthy (`1`/`true` —
    /// the only disable words; anything else fails the boot loudly).
    /// Deliberately its OWN switch, NOT the auth disable: that one exists
    /// because per-IP keying collapses behind ws-web's proxy, while this
    /// limiter keys on the ACCOUNT id, which does NOT collapse — so
    /// turning the auth limiter off must never silently unlimit enrolled
    /// accounts (fix round 1 decoupling). The `ui` mode ignores this
    /// field like the other ACME envs.
    acme_account_limit: Option<ws_api::AuthRateLimit>,
}

/// Variables whose absence is fatal, with their roles — listed together
/// so one boot failure names EVERYTHING the operator must set.
const REQUIRED_ENV: [(&str, &str); 2] = [
    ("DATABASE_URL", "the Postgres connection URL"),
    ("WARDSTONE_KEYS_DIR", "the keystore directory"),
];

/// The typed boot vocabulary: configuration problems carry a message that
/// names the env variable to fix; every underlying crate error flows
/// through its source (the house's transparent-error shape).
#[derive(Debug, thiserror::Error)]
enum BootError {
    /// The environment contract is unmet or unparsable.
    #[error("configuration error: {0}")]
    Config(String),
    /// Pool/migration/repo failures (`ws_core`).
    #[error(transparent)]
    Core(#[from] CoreError),
    /// JWT key-pair failures (`ws-auth`).
    #[error(transparent)]
    Auth(#[from] ws_auth::error::AuthError),
    /// Keystore/TLS material failures (`ws-ca`, `ws-web`).
    #[error(transparent)]
    Ca(#[from] ws_ca::error::CaError),
    /// The TCP listener failed to bind or the serve loop failed.
    #[error("listener error: {0}")]
    Io(#[from] std::io::Error),
}

/// Which serving mode a [`BootConfig`] is parsed for: the one place the
/// rate-limit contract differs (the api's disable switch does not reach
/// the ui's own `/auth/ui` limiter).
#[derive(Debug, Clone, Copy)]
enum BootMode {
    Ui,
    Api,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    initialize_logging();

    let mode = std::env::args().nth(1);
    match mode.as_deref() {
        Some("ui") => run_result(async { run_ui(config_from_env(BootMode::Ui)?).await }.await),
        Some("api") => run_result(async { run_api(config_from_env(BootMode::Api)?).await }.await),
        Some("-h") | Some("--help") => {
            print!("{}", usage_text());
            std::process::ExitCode::SUCCESS
        }
        // No argument, or an unknown one: the usage on STDERR (so it is
        // visible under a service whose stdout is redirected) and a
        // non-zero exit.
        _ => {
            eprint!("{}", usage_text());
            eprintln!(
                "error: expected a mode (`ui` or `api`), got {}",
                mode.map(|m| format!("`{m}`"))
                    .unwrap_or_else(|| "no argument".to_owned())
            );
            std::process::ExitCode::from(2)
        }
    }
}

/// Turn a `Result` from a runner into a process exit: a boot failure is
/// printed to stderr and fails the process (the caller's responsibility —
/// compose restart loops on a crash-looping process get the reason on
/// every attempt).
fn run_result(result: Result<(), BootError>) -> std::process::ExitCode {
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Initialize the log subscriber: the fmt layer writing to stdout, the
/// level from `RUST_LOG` (defaulting to `info` so the boot lines — which
/// TLS material serves, the fallback decisions — are visible by default).
fn initialize_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

/// The usage message: short, naming both modes and the env contract.
fn usage_text() -> String {
    format!(
        "wardstone — the Wardstone certificate authority\n\
         \n\
         Usage: wardstone <MODE>\n\
         \n\
         Modes:\n\
         \x20 ui   serve the TLS front door: the first-run setup page before \
         setup, the CA-issued server leaf after, and the /api/v1 proxy\n\
         \x20 api  serve the REST API directly (plain HTTP for the internal \
         network)\n\
         \n\
         Configuration (environment, both modes):\n\
         \x20 DATABASE_URL               required — the Postgres connection URL\n\
         \x20 WARDSTONE_KEYS_DIR         required — the keystore directory\n\
         \x20 WARDSTONE_SERVER_HOSTNAME  the setup certificate's SAN (optional)\n\
         \x20 WARDSTONE_API_URL          the UI's proxy target (ui; default \
         {DEFAULT_API_URL})\n\
         \x20 WARDSTONE_BIND             the listen address (default \
         {DEFAULT_BIND})\n\
         \x20 WARDSTONE_RATE_LIMIT_PER_MILLIS / _BURST\n\
         \x20                            the auth rate limit values (both modes: \
the api's auth routes, and the ui's /auth/ui login routes; defaults \
{DEFAULT_RATE_PER_MILLIS}/{DEFAULT_RATE_BURST})\n\
         \x20 WARDSTONE_AUTH_RATE_LIMIT_DISABLED\n\
         \x20                            `true` disables the api's auth \
rate limiter (api; for UI-fronted deployments — the ui's own /auth/ui \
limiter stays on)\n\
         \x20 WARDSTONE_PUBLIC_URL        the absolute base URL for the ACME \
surface (api; unset degrades the ACME routes to serverInternal problems)\n\
         \x20 WARDSTONE_ACME_TOS_URL     the terms-of-service URL the ACME \
directory links (api; optional — unset means no ToS flow)\n\
         \x20 WARDSTONE_ACME_ACCOUNT_LIMIT_DISABLED\n\
         \x20                            `true` disables the ACME per-account \
rate limiter (api; `1`/`true` only — anything else fails the boot. Its \
OWN switch: the auth disable above does NOT unlimit enrolled accounts, \
whose keying survives the proxy hop)\n"
    )
}

/// Read [`BootConfig`] from the process environment, for `mode`.
fn config_from_env(mode: BootMode) -> Result<BootConfig, BootError> {
    config_from(mode, |name| {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    })
}

/// [`config_from_env`] with the lookup abstracted out — the pure core the
/// unit tests drive without process-global env manipulation.
fn config_from(
    mode: BootMode,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<BootConfig, BootError> {
    let missing: Vec<String> = REQUIRED_ENV
        .iter()
        .filter(|(name, _)| lookup(name).is_none())
        .map(|(name, role)| format!("{name} ({role})"))
        .collect();
    if !missing.is_empty() {
        return Err(BootError::Config(format!(
            "missing required environment variables: {}",
            missing.join(", ")
        )));
    }

    let database_url = lookup("DATABASE_URL")
        .expect("DATABASE_URL was just verified present by the REQUIRED_ENV check");
    let keys_dir = PathBuf::from(
        lookup("WARDSTONE_KEYS_DIR").expect("WARDSTONE_KEYS_DIR was just verified present"),
    );

    let bind = match lookup("WARDSTONE_BIND") {
        None => DEFAULT_BIND.to_owned(),
        Some(value) => value,
    };
    let bind = bind.parse().map_err(|_| {
        BootError::Config(format!("WARDSTONE_BIND is not a listen address: {bind:?}"))
    })?;

    let api_url = match lookup("WARDSTONE_API_URL") {
        None => DEFAULT_API_URL.to_owned(),
        Some(value) => value,
    };

    let auth_rate_limit = auth_rate_limit_from(&lookup)?;
    // The ACME per-account limiter: its OWN switch, the same loud-toggle
    // contract as the auth one, parsed in BOTH modes (api consumes it;
    // ui ignores the field, like the other ACME envs).
    let acme_account_limit = acme_account_limit_from(&lookup)?;
    // The web limiter: parsed (and validated) ONLY in ui mode, from the
    // same rate envs, unconditionally — the disable switch above is the
    // API's machinery and never unlimits the UI's own /auth/ui limiter.
    let web_rate_limit = match mode {
        BootMode::Api => None,
        BootMode::Ui => Some(rate_limit_from(
            &lookup,
            DEFAULT_RATE_PER_MILLIS,
            DEFAULT_RATE_BURST,
        )?),
    };

    Ok(BootConfig {
        database_url,
        keys_dir,
        server_hostname: lookup("WARDSTONE_SERVER_HOSTNAME"),
        api_url,
        bind,
        auth_rate_limit,
        web_rate_limit,
        // The ACME envs (api mode consumes them; ui ignores the fields):
        // the URL/ToS lookups are OPTIONAL — blank is already filtered to
        // None by the lookup contract — and the account limiter's switch
        // follows the auth switch's loud-toggle contract.
        public_url: lookup("WARDSTONE_PUBLIC_URL"),
        acme_tos_url: lookup("WARDSTONE_ACME_TOS_URL"),
        acme_account_limit,
    })
}

/// The public auth routes' rate limit: `Some` unless truthy
/// `WARDSTONE_AUTH_RATE_LIMIT_DISABLED` turns the limiter OFF
/// (`auth_rate_limit: None`). Only `1` and `true` — case-insensitive —
/// are disable words; any OTHER non-blank value fails the boot loudly
/// with the variable and its value named (`false`, `0`, `no` are NOT
/// disable words: a mistyped switch must never silently change the
/// security posture). When the switch is truthy the rate-limit env vars
/// are not read FOR THE AUTH LIMITER — but the ACME per-account limiter
/// (fix round 1) shares them under its OWN switch
/// (`WARDSTONE_ACME_ACCOUNT_LIMIT_DISABLED`), so they stay readable and
/// validated while that limiter is armed, and are fully inert only when
/// BOTH switches are truthy. Unset or blank keeps the limiter on with
/// the configured (or default) values, and the zero/unparsable checks in
/// [`rate_limit_from`] stay in force.
fn auth_rate_limit_from(
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<Option<ws_api::AuthRateLimit>, BootError> {
    match lookup("WARDSTONE_AUTH_RATE_LIMIT_DISABLED") {
        None => Ok(Some(rate_limit_from(
            lookup,
            DEFAULT_RATE_PER_MILLIS,
            DEFAULT_RATE_BURST,
        )?)),
        Some(value) => {
            let word = value.trim();
            if word == "1" || word.eq_ignore_ascii_case("true") {
                Ok(None)
            } else {
                Err(BootError::Config(format!(
                    "WARDSTONE_AUTH_RATE_LIMIT_DISABLED only takes `1` or `true` \
                     (case-insensitive) to disable the auth rate limiter; got \
                     {value:?}"
                )))
            }
        }
    }
}

/// The ACME per-account rate limit: `Some` (the house defaults, or the
/// `WARDSTONE_RATE_LIMIT_*` envs where set) unless truthy
/// `WARDSTONE_ACME_ACCOUNT_LIMIT_DISABLED` turns the limiter OFF. The
/// SAME loud-toggle contract [`auth_rate_limit_from`] pins: only `1` and
/// `true` — case-insensitive — are disable words; any OTHER non-blank
/// value fails the boot loudly. The switch is deliberately INDEPENDENT
/// of `WARDSTONE_AUTH_RATE_LIMIT_DISABLED`: that one exists because per-IP
/// keying collapses behind ws-web's proxy, while this limiter keys on the
/// account id and does NOT collapse — so disabling the auth limiter must
/// not silently unlimit enrolled accounts (fix round 1 decoupling).
fn acme_account_limit_from(
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<Option<ws_api::AuthRateLimit>, BootError> {
    match lookup("WARDSTONE_ACME_ACCOUNT_LIMIT_DISABLED") {
        None => Ok(Some(rate_limit_from(
            lookup,
            DEFAULT_RATE_PER_MILLIS,
            DEFAULT_RATE_BURST,
        )?)),
        Some(value) => {
            let word = value.trim();
            if word == "1" || word.eq_ignore_ascii_case("true") {
                Ok(None)
            } else {
                Err(BootError::Config(format!(
                    "WARDSTONE_ACME_ACCOUNT_LIMIT_DISABLED only takes `1` or `true` \
                     (case-insensitive) to disable the per-account ACME rate limiter; got \
                     {value:?}"
                )))
            }
        }
    }
}

/// The public auth routes' rate limit: the house defaults unless
/// `WARDSTONE_RATE_LIMIT_PER_MILLIS` / `WARDSTONE_RATE_LIMIT_BURST`
/// configure it. A parse failure or a zero value is a typed boot error —
/// a broken number must FAIL the boot loudly, never serve the auth routes
/// unlimited (ws-api logs-and-skips only for values that reach the
/// infallible router builder; the binary can refuse at boot, and should).
fn rate_limit_from(
    lookup: &impl Fn(&str) -> Option<String>,
    default_per_millis: u64,
    default_burst: u32,
) -> Result<ws_api::AuthRateLimit, BootError> {
    let per_millis = match lookup("WARDSTONE_RATE_LIMIT_PER_MILLIS") {
        None => default_per_millis,
        Some(value) => value.trim().parse().map_err(|_| {
            BootError::Config(format!(
                "WARDSTONE_RATE_LIMIT_PER_MILLIS is not a millisecond count: {value:?}"
            ))
        })?,
    };
    let burst = match lookup("WARDSTONE_RATE_LIMIT_BURST") {
        None => default_burst,
        Some(value) => value.trim().parse().map_err(|_| {
            BootError::Config(format!(
                "WARDSTONE_RATE_LIMIT_BURST is not a burst size: {value:?}"
            ))
        })?,
    };
    if per_millis == 0 || burst == 0 {
        return Err(BootError::Config(
            "the auth rate limit needs positive WARDSTONE_RATE_LIMIT_PER_MILLIS \
             and WARDSTONE_RATE_LIMIT_BURST values (zero disables nothing, it \
             breaks the governor)"
                .to_owned(),
        ));
    }
    Ok(ws_api::AuthRateLimit { per_millis, burst })
}

/// The `ui` mode: the TLS front door over ws-web's composition and
/// serving glue. The serving certificate is resolved at boot:
///
/// - no default tenant: the FIRST-RUN setup — a freshly minted
///   self-signed setup certificate (its key in the keystore's setup slot,
///   its SHA-256 fingerprint displayed on the page), with the setup
///   routes mounted ([`ws_web::web_router`] performs the mount check
///   itself). A completion watcher exits the process with a success code
///   once setup commits the tenant (see [`setup_watch`]).
/// - tenant with an active `web-server` leaf: the CA-issued leaf — the
///   certificates row's PEM plus the key envelope under the certificate
///   id (the leaf is a first-class issuance: `load_ca_key(cert.id)`).
/// - tenant WITHOUT an active leaf — the pinned torn state of a crash
///   between setup's bootstrap commit and the leaf-issuance transaction:
///   a fresh setup certificate keeps TLS SERVING (see [`resolve_serving_leaf`]'s
///   docs for the exact walk and the WARN line that records the
///   choice; recovery is operator-initiated: log in and re-issue the
///   server leaf through the proxied API).
async fn run_ui(cfg: BootConfig) -> Result<(), BootError> {
    let pool = ws_core::db::connect(&cfg.database_url).await?;
    // The JWT keys are the process-lifecycle boot step the brief pins:
    // they exist (or are created) before anything is served — on a virgin
    // volume the setup page is reachable ONLY behind this line. The pair
    // itself is used by ws-api (the separate `api` process); `ui` just
    // guarantees it exists.
    ws_auth::jwt::JwtKeys::load_or_create(&cfg.keys_dir)?;
    let mut keystore = KeyStore::open(&cfg.keys_dir)?;
    let hostname = cfg
        .server_hostname
        .clone()
        .unwrap_or_else(|| ws_web::setup::tls::PLACEHOLDER_SAN.to_owned());

    if !ws_web::tenant_exists(&pool).await? {
        // First run: mint the setup certificate (its key lands in the
        // setup slot), then load the slot back as the TLS key — the
        // round-trip doubles as the slot's post-mint readback.
        let (cert_pem, fingerprint) =
            ws_web::setup::tls::setup_certificate(&mut keystore, &hostname)?;
        let key = keystore.load_setup_key()?;
        tracing::info!(
            hostname = %hostname,
            fingerprint = %fingerprint,
            bind = %cfg.bind,
            "no tenant yet: serving the first-run setup page over the \
             self-signed setup certificate"
        );
        // Watch for a completed setup: only `run_setup` creates the
        // default tenant, so its first appearance IS the `restart: true`
        // signal the setup POST documents.
        tokio::spawn(setup_watch(pool.clone()));
        let router = ws_web::web_router(
            pool,
            cfg.keys_dir.clone(),
            fingerprint,
            hostname,
            &cfg.api_url,
            ws_web::DEFAULT_SESSION_TTL,
            cfg.web_rate_limit,
        )
        .await?;
        return serve_ui(cfg, router, &cert_pem, &key).await;
    }

    // Configured instance: resolve the CA-issued leaf (the controller
    // ruling: by its certificates row + `load_ca_key(cert.id)`).
    let tenant = TenantRepo::new()
        .get_by_name(&pool, ws_web::setup::DEFAULT_TENANT_NAME)
        .await?
        .ok_or_else(|| {
            BootError::Config(
                "the default tenant existed at the boot check but vanished before \
                 the leaf resolution (concurrent modification at boot?)"
                    .to_owned(),
            )
        })?;
    let certs = CertificateRepo::new()
        .list_by_tenant(&pool, tenant.id, 0, 500)
        .await?;

    let leaf = match resolve_serving_leaf(&certs, |leaf| keystore.load_ca_key(&leaf.id))? {
        Some((leaf, ca_key)) => {
            tracing::info!(
                certificate_id = %leaf.id,
                serial = %leaf.serial_hex,
                subject = %leaf.subject,
                bind = %cfg.bind,
                "serving TLS from the CA-issued server leaf"
            );
            // The setup routes are not mounted once the tenant exists, so
            // the fingerprint argument is inert — the empty string keeps
            // that inertness readable at the router call below.
            Some((leaf.cert_pem.clone(), ca_key, String::new()))
        }
        None => {
            // The pinned torn state: the setup bootstrap committed (the
            // tenant and everything else exist) but the leaf issuance
            // transaction never did — no active web-server certificate
            // row. Keep SERVING on a fresh setup certificate; record the
            // decision in the log (the choice must be visible).
            tracing::warn!(
                bind = %cfg.bind,
                "the default tenant exists but no active web-server \
                 certificate row was found (typical cause: a crash between \
                 the setup commit and the leaf issuance); falling back to a \
                 freshly minted setup certificate so TLS keeps serving — \
                 recovery is operator-initiated: log in and re-issue the \
                 server leaf via the API"
            );
            let (cert_pem, fingerprint) =
                ws_web::setup::tls::setup_certificate(&mut keystore, &hostname)?;
            let key = keystore.load_setup_key()?;
            Some((cert_pem, key, fingerprint))
        }
    };
    let (cert_pem, key_der, fingerprint) = match leaf {
        Some(triple) => triple,
        None => {
            return Err(BootError::Config(
                "the serving-certificate resolution found nothing to serve".to_owned(),
            ))
        }
    };

    // No setup routes exist once the tenant does — `web_router` unmounts
    // them itself; the proxy is what the UI serves (and on the fallback
    // path it is how the operator reaches the recovery flow).
    let router = ws_web::web_router(
        pool,
        cfg.keys_dir.clone(),
        fingerprint,
        hostname,
        &cfg.api_url,
        ws_web::DEFAULT_SESSION_TTL,
        cfg.web_rate_limit,
    )
    .await?;
    serve_ui(cfg, router, &cert_pem, &key_der).await
}

/// Put the front-door router on the TLS listener. Nothing returns from
/// [`ws_web::serve_tls`] in the normal course (the serve loop runs until
/// the process exits — including the watcher's exit after setup).
async fn serve_ui(
    cfg: BootConfig,
    router: axum::Router,
    cert_pem: &str,
    key_der: &[u8],
) -> Result<(), BootError> {
    Ok(ws_web::serve_tls(cfg.bind, router, cert_pem, key_der).await?)
}

/// The setup-completion watcher: only [`ws_web::run_setup`] creates the
/// default tenant, so its first appearance is the moment the setup POST
/// has done its work and the process should restart onto the CA-issued
/// leaf. The choice is stated in code HERE rather than in the HTTP layer:
/// the POST response's `"restart": true` documents the contract for the
/// operator, and the compose service's `restart: unless-stopped` brings
/// the process back on the next invocation of this function's caller —
/// which then resolves the leaf at boot.
///
/// A transient DB outage mid-watch is logged and retried: killing the
/// only listener over a hiccup would be worse than a late exit.
async fn setup_watch(pool: sqlx::PgPool) {
    loop {
        tokio::time::sleep(SETUP_WATCH_INTERVAL).await;
        match ws_web::tenant_exists(&pool).await {
            Ok(true) => {
                tracing::info!(
                    "setup completed: exiting with a success code so the \
                     service manager brings the process back serving the \
                     CA-issued certificate"
                );
                // Let the POST response reach the operator's browser
                // before the exit tears down the connection.
                tokio::time::sleep(SETUP_EXIT_GRACE).await;
                std::process::exit(0);
            }
            Ok(false) => {}
            Err(err) => {
                tracing::warn!("setup watch: tenant check failed, retrying: {err}");
            }
        }
    }
}

/// The `api` mode: ws-api's REST router served DIRECTLY as plain HTTP —
/// the compose service publishes no ports for it to the LAN; ws-web's
/// proxy is the only path in from there.
///
/// The serving shape is pinned: `into_make_service_with_connect_info`
/// gives every request a real peer address, which is what makes
/// ws-api's `GovernorLayer` per-IP rate limiting actually effective (its
/// key extractor is the peer IP; without `ConnectInfo` the layer would
/// see none).
/// The sealed-at-rest envelope file names on the keys volume (the
/// design's state predicate: `master.envelope` present ⇒ the instance
/// is sealed at boot).
const MASTER_ENVELOPE_FILE: &str = "master.envelope";
const JWT_ENVELOPE_FILE: &str = "jwt-keys.envelope";
const DB_CREDENTIAL_ENVELOPE_FILE: &str = "db-credential.envelope";

/// Keys-directory-only state derivation (spec §3): `master.envelope`
/// present → the instance boots sealed and waits for the unlock relay.
fn sealed_instance(keys_dir: &std::path::Path) -> bool {
    keys_dir.join(MASTER_ENVELOPE_FILE).exists()
}

/// Substitute the password portion of a `postgres://user:pass@…` URL,
/// leaving user/host/port/db untouched. Inserts a password when the URL
/// carries none. The URL that reaches here is operator-supplied env; the
/// substitution never logs the result.
fn substitute_db_password(url: &str, password: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let auth_start = scheme_end + 3;
    let Some(at) = url[auth_start..].find('@').map(|i| i + auth_start) else {
        return url.to_string();
    };
    match url[auth_start..at].rfind(':') {
        Some(colon_rel) => {
            let colon_abs = auth_start + colon_rel;
            format!("{}{}{}", &url[..=colon_abs], password, &url[at..])
        }
        None => format!("{}:{}{}", &url[..at], password, &url[at..]),
    }
}

/// The api's [`ws_api::ApiConfig`] from the boot env — shared by both the
/// legacy boot and the sealed unlock's build closure.
fn api_config_from(cfg: &BootConfig) -> ws_api::ApiConfig {
    if cfg.public_url.is_none() {
        tracing::warn!(
            "WARDSTONE_PUBLIC_URL is not set: the ACME directory cannot build \
             absolute URLs and every ACME route that needs one will answer \
             urn:ietf:params:acme:error:serverInternal until it is configured"
        );
    }
    ws_api::ApiConfig {
        domain: cfg
            .server_hostname
            .clone()
            .unwrap_or_else(|| ws_web::setup::tls::PLACEHOLDER_SAN.to_owned()),
        keys_dir: cfg.keys_dir.clone(),
        admin_cidrs: Vec::new(),
        auth_rate_limit: cfg.auth_rate_limit,
        acme: ws_api::AcmeConfig {
            public_url: cfg.public_url.clone().unwrap_or_default(),
            tos_url: cfg.acme_tos_url.clone(),
            acme_account_limit: cfg.acme_account_limit,
        },
    }
}

/// The sealed api boot: the process binds its listener immediately (the
/// health surface answers `200 sealed`) and waits for the ui's unlock
/// relay. The build closure opens the envelopes, rotates the DB credential
/// (unconditionally, every unlock — a leaked credential dies at the next
/// unlock), and swaps the FULL `ws_api::router` in.
async fn run_api_sealed(cfg: BootConfig) -> Result<(), BootError> {
    let keys_dir = cfg.keys_dir.clone();
    let database_url = cfg.database_url.clone();
    let config = api_config_from(&cfg);

    let build: ws_api::sealed::LockedBuild =
        std::sync::Arc::new(move |req: &ws_api::sealed::UnlockRequest| {
            let keys_dir = keys_dir.clone();
            let database_url = database_url.clone();
            let config = config.clone();
            let passphrase = req.passphrase.clone();
            futures_util::future::FutureExt::boxed(async move {
                // The JWT pair: sealed under the passphrase.
                let jwt = ws_auth::jwt::load_sealed(&keys_dir.join(JWT_ENVELOPE_FILE), &passphrase)
                    .map_err(ws_api::error::ApiError::from)?;
                // The DB credential: the envelope holds the CURRENT one; a
                // fresh install (envelope absent) connects with the env's
                // bootstrap credential.
                let db_credential_path = keys_dir.join(DB_CREDENTIAL_ENVELOPE_FILE);
                let connect_url = match ws_core::crypto::KeyEnvelope::open_envelope(
                    &db_credential_path,
                    &passphrase,
                ) {
                    Ok(current) => {
                        substitute_db_password(&database_url, &String::from_utf8_lossy(&current))
                    }
                    Err(ws_core::error::CoreError::Config(_)) => database_url.clone(),
                    Err(other) => {
                        return Err(ws_api::error::ApiError::from(other));
                    }
                };
                let pool = ws_core::db::connect(&connect_url).await?;
                // The rotation (spec §5.6): a fresh in-memory credential,
                // ALTER over the just-opened connection, re-seal. A leaked
                // credential (including the compose bootstrap) dies here.
                let fresh = ws_core::crypto::random_hex(32)?;
                sqlx::query("ALTER USER wardstone PASSWORD $1")
                    .bind(&fresh)
                    .execute(&pool)
                    .await
                    .map_err(ws_core::error::CoreError::Database)?;
                ws_core::crypto::KeyEnvelope::write_envelope(
                    &db_credential_path,
                    &passphrase,
                    fresh.as_bytes(),
                    ws_core::crypto::PROD_KDF_PARAMS,
                )?;
                drop(pool);
                let pool =
                    ws_core::db::connect(&substitute_db_password(&connect_url, &fresh)).await?;
                Ok(ws_api::router(ws_api::AppState::new(
                    pool,
                    std::sync::Arc::new(jwt),
                    config,
                )))
            })
        });

    let api = std::sync::Arc::new(ws_api::sealed::SealedApi::new(build));
    let app = ws_api::sealed::sealed_router(api);
    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    tracing::info!(
        bind = %cfg.bind,
        "serving the sealed REST API: unlock through the front door to continue"
    );
    Ok(axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?)
}

async fn run_api(cfg: BootConfig) -> Result<(), BootError> {
    // The sealed instance: the envelopes exist, so the process waits for
    // the unlock relay instead of touching any key material at boot.
    if sealed_instance(&cfg.keys_dir) {
        return run_api_sealed(cfg).await;
    }
    let pool = ws_core::db::connect(&cfg.database_url).await?;
    // The JWT key pair: ws-api signs every access token with it. Loading
    // (or creating, on a virgin volume) exactly once per boot — the same
    // on-disk pair the `ui` process guarantees exists.
    let jwt = std::sync::Arc::new(ws_auth::jwt::JwtKeys::load_or_create(&cfg.keys_dir)?);

    let config = api_config_from(&cfg);
    let app = ws_api::router(ws_api::AppState::new(pool, jwt, config));

    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    tracing::info!(bind = %cfg.bind, "serving the REST API");
    Ok(axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?)
}

/// The serving-leaf candidates over a tenant's certificates: ACTIVE
/// certificates issued on the built-in `web-server` profile — the profile
/// setup itself mints the UI's leaf on, and the one an operator re-issue
/// of the server leaf naturally rides — newest `created_at` first. An
/// empty list means NO serving leaf exists (the pinned torn state: the UI
/// falls back to the setup certificate).
///
/// Deliberately NOT "any active certificate": the UI's own leaf is the
/// `web-server` one, and serving some other workload's domain certificate
/// would present the wrong identity to the browsers that connect here.
///
/// The newest-first order covers the re-issue flow naturally: once a fresh
/// leaf exists on the same profile, the next boot presents it; revoked
/// leaves drop out through the `active` predicate.
fn serving_leaf_candidates(certs: &[CertificateModel]) -> Vec<&CertificateModel> {
    let mut candidates: Vec<&CertificateModel> = certs
        .iter()
        .filter(|cert| {
            cert.status == CertStatus::Active && cert.profile_name == SERVING_LEAF_PROFILE
        })
        .collect();
    candidates.sort_by_key(|cert| std::cmp::Reverse(cert.created_at));
    candidates
}

/// Walk the serving-leaf candidates newest-first and serve the first leaf
/// whose key envelope the keystore actually holds, pairing the row with
/// its loaded key so the caller binds TLS without a second keystore trip.
/// `Ok(None)` — every candidate unenvelopable, or none at all — sends the
/// caller to the setup-certificate fallback.
///
/// A candidate whose envelope is MISSING is passed by, not fatal: an
/// ACME-issued certificate (or any client-key issuance) has no server-side
/// private key by design, so the keystore reports NotFound for rows that
/// are real, active certificates owned by their clients. The first such
/// renewal to appear above a manual leaf used to abort the boot — a crash
/// loop on every restart — because the newest-wins pick loaded the key of
/// a certificate this server provably cannot key. Skipping keeps the
/// walk's identity promise intact: the UI only ever serves a leaf whose
/// key it holds.
///
/// Any OTHER load error (a corrupt envelope, an io failure at the master
/// key) aborts the boot: those are keystore-integrity incidents, and
/// silently serving an older leaf over a broken keystore would mask the
/// damage the operator needs to see.
/// The walk's resolution when a leaf is servable: the row paired with the
/// key bytes its envelope loaded.
type ServedLeaf<'a> = (&'a CertificateModel, Zeroizing<Vec<u8>>);

fn resolve_serving_leaf(
    certs: &[CertificateModel],
    load_key: impl Fn(&CertificateModel) -> Result<Zeroizing<Vec<u8>>, CaError>,
) -> Result<Option<ServedLeaf<'_>>, CaError> {
    for leaf in serving_leaf_candidates(certs) {
        match load_key(leaf) {
            Ok(key) => return Ok(Some((leaf, key))),
            Err(CaError::NotFound) => {
                tracing::warn!(
                    certificate_id = %leaf.id,
                    serial = %leaf.serial_hex,
                    subject = %leaf.subject,
                    "skipping an active web-server leaf whose key envelope the \
                     keystore does not hold — an ACME/client-key certificate \
                     cannot serve here (its private key lives with its \
                     client); falling back to the next-newest leaf"
                );
            }
            Err(err) => return Err(err),
        }
    }
    Ok(None)
}

/// # Unit tests
///
/// The pure helpers the boot paths are built from: the mode/usage
/// contract lives in `tests/cli_test.rs` (against the built binary);
/// these cover the config parse, the rate-limit policy, and the
/// serving-leaf selection.
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use std::net::Ipv4Addr;
    use uuid::Uuid;

    /// A lookup over a static table: the pure-config test harness. It
    /// mimics [`config_from_env`]'s env semantics — including the blank
    /// string being unset. The explicit lifetimes tie the returned
    /// closure to the borrowed table.
    fn table<'a>(entries: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            entries
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
                .filter(|value| !value.trim().is_empty())
        }
    }

    /// The minimal complete table: both required values, nothing else.
    const MINIMAL: [(&str, &str); 2] = [
        (
            "DATABASE_URL",
            "postgres://wardstone:wardstone@db/wardstone",
        ),
        ("WARDSTONE_KEYS_DIR", "/var/lib/wardstone/keys"),
    ];

    /// The full config parses; the two defaults are the brief's pins.
    #[test]
    fn config_minimal_table_gets_every_default() {
        let cfg = config_from(BootMode::Api, table(&MINIMAL)).expect("the minimal table parses");
        assert_eq!(
            cfg.database_url,
            "postgres://wardstone:wardstone@db/wardstone"
        );
        assert_eq!(cfg.keys_dir, PathBuf::from("/var/lib/wardstone/keys"));
        assert!(cfg.server_hostname.is_none(), "no hostname configured");
        assert_eq!(cfg.api_url, "http://ws-api:8080");
        assert_eq!(cfg.bind, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8443)));
        let rl = cfg
            .auth_rate_limit
            .expect("the limiter is configured when the disable var is unset");
        assert_eq!(rl.per_millis, 500);
        assert_eq!(rl.burst, 20);
    }

    /// Every override is honored; a missing variable is named in the error.
    #[test]
    fn config_overrides_are_honored_and_missing_names_are_listed() {
        let entries = [
            MINIMAL[0],
            MINIMAL[1],
            ("WARDSTONE_SERVER_HOSTNAME", "ca.example.test"),
            ("WARDSTONE_API_URL", "http://api.internal:9000"),
            ("WARDSTONE_BIND", "127.0.0.1:9443"),
            ("WARDSTONE_RATE_LIMIT_PER_MILLIS", "100"),
            ("WARDSTONE_RATE_LIMIT_BURST", "5"),
        ];
        let cfg = config_from(BootMode::Api, table(&entries)).expect("the full table parses");
        assert_eq!(cfg.server_hostname.as_deref(), Some("ca.example.test"));
        assert_eq!(cfg.api_url, "http://api.internal:9000");
        assert_eq!(cfg.bind, SocketAddr::from((Ipv4Addr::LOCALHOST, 9443)));
        let rl = cfg.auth_rate_limit.expect("the limiter is configured");
        assert_eq!((rl.per_millis, rl.burst), (100, 5));

        let err = config_from(BootMode::Api, table(&[MINIMAL[0]]))
            .expect_err("a missing keys dir must fail");
        assert!(
            err.to_string().contains("WARDSTONE_KEYS_DIR"),
            "the error names the missing variable: {err}"
        );
        let err = config_from(BootMode::Api, table(&[MINIMAL[1]]))
            .expect_err("a missing database url must fail");
        assert!(
            err.to_string().contains("DATABASE_URL"),
            "the error names the missing variable: {err}"
        );
    }

    /// Blank values count as unset (the compose file may hand us "").
    #[test]
    fn config_blank_values_are_unset() {
        let entries = [("DATABASE_URL", "   "), ("WARDSTONE_KEYS_DIR", "")];
        let err = config_from(BootMode::Api, table(&entries))
            .expect_err("blank required values must fail");
        assert!(
            err.to_string().contains("DATABASE_URL")
                && err.to_string().contains("WARDSTONE_KEYS_DIR"),
            "blank values are treated as missing: {err}"
        );
    }

    /// A hostile bind string and a zero rate-limit value both fail the
    /// boot loudly (never a silently unlimited or unbound service).
    #[test]
    fn config_rejects_bad_bind_and_zero_rate_limit() {
        let bind = [MINIMAL[0], MINIMAL[1], ("WARDSTONE_BIND", "not-an-address")];
        let err = config_from(BootMode::Api, table(&bind)).expect_err("a bad bind must fail");
        assert!(
            err.to_string().contains("WARDSTONE_BIND"),
            "the error names the variable: {err}"
        );

        let zero_burst = [MINIMAL[0], MINIMAL[1], ("WARDSTONE_RATE_LIMIT_BURST", "0")];
        let err =
            config_from(BootMode::Api, table(&zero_burst)).expect_err("a zero burst must fail");
        assert!(
            err.to_string().contains("WARDSTONE_RATE_LIMIT_BURST"),
            "the error names the variable: {err}"
        );

        let zero_period = [
            MINIMAL[0],
            MINIMAL[1],
            ("WARDSTONE_RATE_LIMIT_PER_MILLIS", "0"),
        ];
        let err =
            config_from(BootMode::Api, table(&zero_period)).expect_err("a zero period must fail");
        assert!(
            err.to_string().contains("WARDSTONE_RATE_LIMIT_PER_MILLIS"),
            "the error names the variable: {err}"
        );

        let garbage = [
            MINIMAL[0],
            MINIMAL[1],
            ("WARDSTONE_RATE_LIMIT_PER_MILLIS", "soon"),
        ];
        let err = config_from(BootMode::Api, table(&garbage))
            .expect_err("a non-numeric rate limit must fail");
        assert!(
            err.to_string().contains("WARDSTONE_RATE_LIMIT_PER_MILLIS"),
            "the error names the variable: {err}"
        );
    }

    /// The `WARDSTONE_AUTH_RATE_LIMIT_DISABLED` switch: only `1` and
    /// `true` (case-insensitive) disable the limiter — and make the
    /// rate-limit env vars inert FOR THE AUTH LIMITER. Unset or blank
    /// keeps it on; ANY other non-blank value fails the boot loudly,
    /// naming the variable and the offending value (`false` and `0` are
    /// deliberately NOT disable words — a mistyped switch must never
    /// silently change the security posture).
    ///
    /// Fix round 1 nuance: the ACME per-account limiter shares the
    /// `WARDSTONE_RATE_LIMIT_*` envs under its OWN switch, so garbage in
    /// those envs is a loud failure while the ACME limiter is armed — the
    /// envs are fully inert only when BOTH switches are truthy (a
    /// deployment that wants every limiter off must say so twice).
    #[test]
    fn auth_rate_limit_disabled_switch_semantics() {
        let truthy = [
            MINIMAL[0],
            MINIMAL[1],
            ("WARDSTONE_AUTH_RATE_LIMIT_DISABLED", "true"),
        ];
        let cfg = config_from(BootMode::Api, table(&truthy)).expect("`true` disables the limiter");
        assert!(cfg.auth_rate_limit.is_none(), "the limiter is off");

        // With the auth limiter OFF but the per-account ACME limiter
        // armed (its own switch untouched), the shared rate envs are
        // still read and validated — a broken number refuses to
        // mis-tune a limiter that is running.
        let garbage = [
            MINIMAL[0],
            MINIMAL[1],
            ("WARDSTONE_AUTH_RATE_LIMIT_DISABLED", "true"),
            ("WARDSTONE_RATE_LIMIT_PER_MILLIS", "soon"),
        ];
        let err = config_from(BootMode::Api, table(&garbage))
            .expect_err("the armed ACME limiter still validates the shared rate envs");
        assert!(
            err.to_string().contains("WARDSTONE_RATE_LIMIT_PER_MILLIS"),
            "the error names the variable: {err}"
        );

        // With BOTH switches truthy the rate envs are fully inert: zero
        // and garbage are simply never read.
        let both_off = [
            MINIMAL[0],
            MINIMAL[1],
            ("WARDSTONE_AUTH_RATE_LIMIT_DISABLED", "true"),
            ("WARDSTONE_ACME_ACCOUNT_LIMIT_DISABLED", "true"),
            ("WARDSTONE_RATE_LIMIT_PER_MILLIS", "soon"),
            ("WARDSTONE_RATE_LIMIT_BURST", "0"),
        ];
        let cfg = config_from(BootMode::Api, table(&both_off))
            .expect("both limiters off: the rate envs are fully inert");
        assert!(
            cfg.auth_rate_limit.is_none() && cfg.acme_account_limit.is_none(),
            "both limiters are off"
        );

        let upper = [
            MINIMAL[0],
            MINIMAL[1],
            ("WARDSTONE_AUTH_RATE_LIMIT_DISABLED", "TRUE"),
        ];
        let cfg = config_from(BootMode::Api, table(&upper)).expect("`TRUE` disables the limiter");
        assert!(cfg.auth_rate_limit.is_none(), "case-insensitive");

        let one = [
            MINIMAL[0],
            MINIMAL[1],
            ("WARDSTONE_AUTH_RATE_LIMIT_DISABLED", "1"),
        ];
        let cfg = config_from(BootMode::Api, table(&one)).expect("`1` disables the limiter");
        assert!(cfg.auth_rate_limit.is_none(), "the numeric disable word");

        let blank = [
            MINIMAL[0],
            MINIMAL[1],
            ("WARDSTONE_AUTH_RATE_LIMIT_DISABLED", ""),
        ];
        let cfg = config_from(BootMode::Api, table(&blank)).expect("blank equals unset");
        assert!(
            cfg.auth_rate_limit.is_some(),
            "blank/unset keeps the limiter on"
        );

        for word in ["false", "0", "no", "on", "yes"] {
            let entries = [
                MINIMAL[0],
                MINIMAL[1],
                ("WARDSTONE_AUTH_RATE_LIMIT_DISABLED", word),
            ];
            let err = config_from(BootMode::Api, table(&entries))
                .expect_err("a non-disable word fails the boot loudly");
            let message = err.to_string();
            assert!(
                message.contains("WARDSTONE_AUTH_RATE_LIMIT_DISABLED"),
                "the error names the variable: {message}"
            );
            assert!(
                message.contains(word),
                "the error names the offending value: {message}"
            );
        }
    }

    /// A `web-server`-shaped [`CertificateModel`] with the given status
    /// and age (`minutes_ago` before now). The serial is the age too —
    /// its exact value is never load-bearing in these tests.
    fn cert(status: CertStatus, minutes_ago: i64) -> CertificateModel {
        CertificateModel {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            ca_id: Uuid::new_v4(),
            profile_revision_id: None,
            profile_name: "web-server".to_owned(),
            subject: "CN=ca.example.test".to_owned(),
            serial: u128::from(minutes_ago.unsigned_abs()),
            serial_hex: format!("{minutes_ago:x}"),
            san_dns: vec!["ca.example.test".to_owned()],
            san_ips: vec![],
            key_type: "rsa2048".to_owned(),
            not_before: Utc::now() - Duration::days(1),
            not_after: Utc::now() + Duration::days(30),
            cert_pem: "-----BEGIN CERTIFICATE-----".to_owned(),
            status,
            revoked_at: None,
            revocation_reason: None,
            revocation_detail: None,
            source: "manual".to_owned(),
            created_at: Utc::now() - Duration::minutes(minutes_ago),
        }
    }

    /// The DB-URL password substitution replaces exactly the password and
    /// leaves everything else byte-identical — and inserts a password into
    /// a URL that carried none.
    #[test]
    fn db_password_substitution_is_surgical() {
        let url = "postgres://wardstone:old-secret@db:5432/wardstone";
        let substituted = substitute_db_password(url, "new-credential");
        assert_eq!(
            substituted, "postgres://wardstone:new-credential@db:5432/wardstone",
            "only the password changes"
        );
        let bare = "postgres://wardstone@db:5432/wardstone";
        assert_eq!(
            substitute_db_password(bare, "inserted"),
            "postgres://wardstone:inserted@db:5432/wardstone",
            "a password-less URL gains one"
        );
        let weird = "not-a-url";
        assert_eq!(
            substitute_db_password(weird, "x"),
            weird,
            "a non-URL passes through"
        );
    }

    /// The sealed-instance predicate: `master.envelope` present ⇒ sealed.
    #[test]
    fn sealed_instance_reads_the_envelope_predicate() {
        let dir = std::env::temp_dir().join(format!("ws-sealed-predicate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!sealed_instance(&dir), "a clean dir is not sealed");
        std::fs::write(dir.join(MASTER_ENVELOPE_FILE), b"{}").unwrap();
        assert!(
            sealed_instance(&dir),
            "master.envelope marks the sealed state"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The selection: active web-server certificates only, newest first,
    /// revoked and foreign-profile rows never chosen.
    #[test]
    fn serving_leaf_candidates_orders_active_web_server_newest_first() {
        let old_active = cert(CertStatus::Active, 100);
        let new_active = cert(CertStatus::Active, 10);
        let revoked_newer = cert(CertStatus::Revoked, 5);
        let foreign = {
            let mut c = cert(CertStatus::Active, 3);
            c.profile_name = "server".to_owned();
            c
        };
        // The candidates are bound so the borrowed slice outlives the
        // call and the later single-cert assertions can reuse the rows.
        let table = [
            old_active.clone(),
            new_active.clone(),
            revoked_newer.clone(),
            foreign,
        ];

        let ids: Vec<_> = serving_leaf_candidates(&table)
            .into_iter()
            .map(|c| c.id)
            .collect();
        assert_eq!(
            ids,
            vec![new_active.id, old_active.id],
            "newest active web-server leaf first; revoked and foreign-profile rows never chosen"
        );

        let only_revoked = [revoked_newer];
        assert!(
            serving_leaf_candidates(&only_revoked).is_empty(),
            "a revoked leaf is not servable"
        );
        assert!(
            serving_leaf_candidates(&[]).is_empty(),
            "an empty table has no leaf: the boot falls back to the setup certificate"
        );
    }

    /// The walk serves the newest candidate and hands its loaded key back,
    /// keyed to that candidate.
    #[test]
    fn resolve_serving_leaf_serves_the_newest_candidate_with_its_loaded_key() {
        let old_active = cert(CertStatus::Active, 100);
        let new_active = cert(CertStatus::Active, 10);
        let table = [old_active, new_active.clone()];
        let (leaf, key) = resolve_serving_leaf(&table, |c| {
            Ok(Zeroizing::new(c.id.to_string().into_bytes()))
        })
        .expect("the walk must not abort the boot when keys load")
        .expect("candidates exist");
        assert_eq!(leaf.id, new_active.id, "the newest candidate wins");
        assert_eq!(
            *key,
            new_active.id.to_string().into_bytes(),
            "the served key is the loaded one for the served leaf"
        );
    }

    /// A candidate whose envelope is corrupt aborts the boot — an
    /// integrity incident is never worked around by silently serving a
    /// different identity.
    #[test]
    fn resolve_serving_leaf_hard_fails_on_a_corrupt_envelope() {
        let only = cert(CertStatus::Active, 10);
        let table = [only];
        let err = resolve_serving_leaf(&table, |_| Err(CaError::Corrupt))
            .expect_err("a corrupt envelope must abort the boot");
        assert!(matches!(err, CaError::Corrupt), "got {err:?}");
    }

    /// The newest candidate holds NO key envelope — the shape an ACME
    /// (client-key) certificate leaves behind by design: the private key
    /// never existed server-side, so the keystore reports NotFound. The
    /// walk must pass that candidate by with a WARN and serve the next
    /// leaf it can actually load — not abort the boot (the deployed
    /// system crash-looped on exactly this at 18:31) and not silently
    /// pretend to serve an identity it cannot key.
    #[test]
    fn resolve_serving_leaf_walks_past_a_candidate_with_no_key_envelope() {
        let old_active = cert(CertStatus::Active, 100);
        let new_active = cert(CertStatus::Active, 10);
        let table = [old_active.clone(), new_active.clone()];
        let loaded = std::cell::RefCell::new(Vec::new());
        let (leaf, key) = resolve_serving_leaf(&table, |c| {
            loaded.borrow_mut().push(c.id);
            if c.id == new_active.id {
                Err(CaError::NotFound)
            } else {
                Ok(Zeroizing::new(c.id.to_string().into_bytes()))
            }
        })
        .expect("a missing envelope must not abort the boot")
        .expect("the next-newest leaf is servable");
        assert_eq!(
            leaf.id, old_active.id,
            "the walk serves the next-newest leaf after the unenveloped one"
        );
        assert_eq!(
            *key,
            old_active.id.to_string().into_bytes(),
            "the served key is the loaded one for the served leaf"
        );
        assert_eq!(
            *loaded.borrow(),
            vec![new_active.id, old_active.id],
            "the walk stayed on the newest-first candidate order"
        );
    }

    /// No candidates at all (or none on the serving profile): the walk
    /// resolves to None and the caller takes the setup-certificate
    /// fallback — the pinned torn state. No load is attempted.
    #[test]
    fn resolve_serving_leaf_with_no_candidates_resolves_to_none() {
        let mut foreign = cert(CertStatus::Active, 10);
        foreign.profile_name = "server".to_owned();
        let table = [foreign];

        let load = |_: &CertificateModel| {
            Result::<Zeroizing<Vec<u8>>, CaError>::Ok(Zeroizing::new(Vec::new()))
        };
        assert!(
            resolve_serving_leaf(&table, load)
                .expect("no load is attempted")
                .is_none(),
            "a foreign-profile-only table has no serving leaf"
        );
        assert!(
            resolve_serving_leaf(&[], load)
                .expect("no load is attempted")
                .is_none(),
            "an empty table has no serving leaf"
        );
    }

    /// The usage names both modes and the required variables (the CLI
    /// tests assert the same contract through the real binary — this is
    /// the unit-level pin so a regression is visible without a build).
    #[test]
    fn usage_names_both_modes_and_required_env() {
        let usage = usage_text();
        assert!(usage.contains("ui") && usage.contains("api"));
        assert!(usage.contains("DATABASE_URL"));
        assert!(usage.contains("WARDSTONE_KEYS_DIR"));
    }

    /// The ui boot parses the WEB limiter from the SAME rate-limit env
    /// contract the api limiter reads: the house defaults when unset, the
    /// configured values otherwise.
    #[test]
    fn ui_mode_parses_the_web_rate_limit_from_the_same_envs() {
        let cfg = config_from(BootMode::Ui, table(&MINIMAL)).expect("the minimal table parses");
        let web = cfg
            .web_rate_limit
            .expect("the ui's /auth/ui limiter is configured");
        assert_eq!((web.per_millis, web.burst), (500, 20), "house defaults");

        let overrides = [
            MINIMAL[0],
            MINIMAL[1],
            ("WARDSTONE_RATE_LIMIT_PER_MILLIS", "250"),
            ("WARDSTONE_RATE_LIMIT_BURST", "7"),
        ];
        let cfg = config_from(BootMode::Ui, table(&overrides)).expect("the overrides parse");
        let web = cfg.web_rate_limit.expect("the limiter is configured");
        assert_eq!((web.per_millis, web.burst), (250, 7));
    }

    /// The disable switch is the API's machinery: a ui boot keeps its own
    /// `/auth/ui` limiter mounted with the (default) values even when the
    /// switch is truthy — and its rate envs are still validated, since
    /// the web limiter is the one that consumes them in ui mode.
    #[test]
    fn ui_mode_keeps_the_web_limiter_when_the_api_switch_is_disabled() {
        let disabled = [
            MINIMAL[0],
            MINIMAL[1],
            ("WARDSTONE_AUTH_RATE_LIMIT_DISABLED", "true"),
        ];
        let cfg = config_from(BootMode::Ui, table(&disabled)).expect("the disabled table parses");
        assert!(cfg.auth_rate_limit.is_none(), "the api limiter is off");
        let web = cfg
            .web_rate_limit
            .expect("the ui limiter is NOT disabled by the api switch");
        assert_eq!((web.per_millis, web.burst), (500, 20), "house defaults");

        let zero = [MINIMAL[0], MINIMAL[1], ("WARDSTONE_RATE_LIMIT_BURST", "0")];
        let err = config_from(BootMode::Ui, table(&zero))
            .expect_err("a zero burst must fail a ui boot: its limiter consumes it");
        assert!(
            err.to_string().contains("WARDSTONE_RATE_LIMIT_BURST"),
            "the error names the variable: {err}"
        );
    }

    /// api mode never builds the web router, so it parses no web limiter
    /// (and — Task 10, unchanged — a truthy disable switch leaves its
    /// rate envs unread).
    #[test]
    fn api_mode_has_no_web_rate_limit() {
        let cfg = config_from(BootMode::Api, table(&MINIMAL)).expect("the minimal table parses");
        assert!(cfg.web_rate_limit.is_none(), "no web router in api mode");
    }

    /// The ACME env contract: `WARDSTONE_PUBLIC_URL` is OPTIONAL (blank or
    /// unset is the degrade-to-`serverInternal` posture, never a boot
    /// failure) and `WARDSTONE_ACME_TOS_URL` is optional and independent —
    /// a ToS URL without a public URL would be inert, since nothing can
    /// build absolute URLs without the base.
    #[test]
    fn acme_envs_are_optional_and_pass_through() {
        let bare = config_from(BootMode::Api, table(&MINIMAL)).expect("bare table parses");
        assert!(
            bare.public_url.is_none(),
            "no WARDSTONE_PUBLIC_URL → unset (the warn-and-degrade posture)"
        );
        assert!(bare.acme_tos_url.is_none(), "no ToS URL configured");

        let full = [
            MINIMAL[0],
            MINIMAL[1],
            ("WARDSTONE_PUBLIC_URL", "https://ca.home.test"),
            ("WARDSTONE_ACME_TOS_URL", "https://ca.home.test/terms"),
        ];
        let cfg = config_from(BootMode::Api, table(&full)).expect("the full table parses");
        assert_eq!(cfg.public_url.as_deref(), Some("https://ca.home.test"));
        assert_eq!(
            cfg.acme_tos_url.as_deref(),
            Some("https://ca.home.test/terms")
        );

        let blank = [
            MINIMAL[0],
            MINIMAL[1],
            ("WARDSTONE_PUBLIC_URL", "   "),
            ("WARDSTONE_ACME_TOS_URL", ""),
        ];
        let cfg = config_from(BootMode::Api, table(&blank)).expect("blank values parse");
        assert!(
            cfg.public_url.is_none() && cfg.acme_tos_url.is_none(),
            "blank ACME env values count as unset (the lookup contract)"
        );
    }

    /// The ACME per-account limiter's switch semantics (fix round 1): ON
    /// by default with the house rate envs (the `WARDSTONE_RATE_LIMIT_*`
    /// pair tunes it); only `1`/`true` — case-insensitive — disarm it;
    /// any OTHER non-blank value fails the boot loudly; and the auth
    /// disable switch does NOT touch it (the two limiters are decoupled
    /// knobs: uuid keying survives the proxy hop, per-IP keying does not).
    #[test]
    fn acme_account_limit_switch_semantics() {
        let bare = config_from(BootMode::Api, table(&MINIMAL)).expect("bare table parses");
        let on = bare
            .acme_account_limit
            .expect("an unset switch keeps the per-account limiter ON");
        assert_eq!((on.per_millis, on.burst), (500, 20), "house defaults");

        let tuned = [
            MINIMAL[0],
            MINIMAL[1],
            ("WARDSTONE_RATE_LIMIT_PER_MILLIS", "250"),
            ("WARDSTONE_RATE_LIMIT_BURST", "7"),
        ];
        let cfg = config_from(BootMode::Api, table(&tuned)).expect("the tuned table parses");
        let on = cfg.acme_account_limit.expect("still ON with tuned envs");
        assert_eq!((on.per_millis, on.burst), (250, 7));

        for word in ["1", "true", "TRUE", "True"] {
            let off = [
                MINIMAL[0],
                MINIMAL[1],
                ("WARDSTONE_ACME_ACCOUNT_LIMIT_DISABLED", word),
            ];
            let cfg = config_from(BootMode::Api, table(&off)).expect("the disable word parses");
            assert!(
                cfg.acme_account_limit.is_none(),
                "{word} disarms the per-account limiter"
            );
        }

        let junk = [
            MINIMAL[0],
            MINIMAL[1],
            ("WARDSTONE_ACME_ACCOUNT_LIMIT_DISABLED", "false"),
        ];
        let err = config_from(BootMode::Api, table(&junk))
            .expect_err("a non-disable word must fail the boot loudly");
        assert!(
            err.to_string()
                .contains("WARDSTONE_ACME_ACCOUNT_LIMIT_DISABLED"),
            "the error names the variable: {err}"
        );

        // The AUTH disable switch is a different knob: turning the auth
        // limiter off leaves the per-account ACME limiter armed.
        let auth_off = [
            MINIMAL[0],
            MINIMAL[1],
            ("WARDSTONE_AUTH_RATE_LIMIT_DISABLED", "true"),
        ];
        let cfg = config_from(BootMode::Api, table(&auth_off)).expect("the auth-off table parses");
        assert!(
            cfg.auth_rate_limit.is_none() && cfg.acme_account_limit.is_some(),
            "the auth disable does not unlimit the ACME account limiter"
        );
    }

    /// The tenant name the boot lookup and the setup flow agree on: the
    /// one constant ws-web's setup defines, read back through the same
    /// path the config check uses.
    #[test]
    fn default_tenant_uses_the_setup_convention_name() {
        assert_eq!(ws_web::setup::DEFAULT_TENANT_NAME, "default");
    }

    /// The fallback's WARN path and the leaf's INFO path are log lines;
    /// what is pinnable without a DB is that the selection helper the
    /// fallback consults IS the one the leaf path consults — one
    /// predicate, two boot outcomes.
    #[test]
    fn serving_leaf_predicate_is_shared_by_both_boot_outcomes() {
        let leaf = cert(CertStatus::Active, 0);
        assert!(serving_leaf_candidates(&[]).is_empty());
        assert!(
            !serving_leaf_candidates(std::slice::from_ref(&leaf)).is_empty(),
            "the same one-predicate rule drives both boot outcomes"
        );
    }
}
