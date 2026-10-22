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
use ws_ca::keystore::KeyStore;
use ws_core::error::CoreError;
use ws_core::models::certificate::{CertStatus, CertificateModel};
use ws_core::repo::certificate_repo::CertificateRepo;
use ws_core::repo::tenant_repo::TenantRepo;

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
    /// in ws-api; `ui` mounts none of those routes). Defaults to the
    /// house constants; `WARDSTONE_RATE_LIMIT_PER_MILLIS` /
    /// `WARDSTONE_RATE_LIMIT_BURST` may configure them for the compose
    /// bundle. A zero value is a boot failure, not a silent un-limited
    /// listener.
    rate_limit: ws_api::AuthRateLimit,
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

#[tokio::main]
async fn main() -> std::process::ExitCode {
    initialize_logging();

    let mode = std::env::args().nth(1);
    match mode.as_deref() {
        Some("ui") => run_result(async { run_ui(config_from_env()?).await }.await),
        Some("api") => run_result(async { run_api(config_from_env()?).await }.await),
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
         \x20 WARDSTONE_BIND             the listen address (default {DEFAULT_BIND})\n"
    )
}

/// Read [`BootConfig`] from the process environment.
fn config_from_env() -> Result<BootConfig, BootError> {
    config_from(|name| std::env::var(name).ok().filter(|v| !v.trim().is_empty()))
}

/// [`config_from_env`] with the lookup abstracted out — the pure core the
/// unit tests drive without process-global env manipulation.
fn config_from(lookup: impl Fn(&str) -> Option<String>) -> Result<BootConfig, BootError> {
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

    let rate_limit = rate_limit_from(&lookup, DEFAULT_RATE_PER_MILLIS, DEFAULT_RATE_BURST)?;

    Ok(BootConfig {
        database_url,
        keys_dir,
        server_hostname: lookup("WARDSTONE_SERVER_HOSTNAME"),
        api_url,
        bind,
        rate_limit,
    })
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
///   a fresh setup certificate keeps TLS SERVING (see [`select_serving_leaf`]'s
///   docs for the exact predicate and the WARN line that records the
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

    let leaf = match select_serving_leaf(&certs) {
        Some(leaf) => {
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
            Some((
                leaf.cert_pem.clone(),
                keystore.load_ca_key(&leaf.id)?,
                String::new(),
            ))
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
async fn run_api(cfg: BootConfig) -> Result<(), BootError> {
    let pool = ws_core::db::connect(&cfg.database_url).await?;
    // The JWT key pair: ws-api signs every access token with it. Loading
    // (or creating, on a virgin volume) exactly once per boot — the same
    // on-disk pair the `ui` process guarantees exists.
    let jwt = std::sync::Arc::new(ws_auth::jwt::JwtKeys::load_or_create(&cfg.keys_dir)?);

    let config = ws_api::ApiConfig {
        domain: cfg
            .server_hostname
            .clone()
            .unwrap_or_else(|| ws_web::setup::tls::PLACEHOLDER_SAN.to_owned()),
        keys_dir: cfg.keys_dir.clone(),
        // The admin CIDRs are collected by the setup flow (which runs in
        // the `ui` process and persists them through the profiles /
        // deployment values it creates); the API surface currently reads
        // no runtime behavior from this field, so the empty vector is the
        // honest value a directly-served `api` process has at boot.
        admin_cidrs: Vec::new(),
        // The per-IP GCRA on the public auth routes: configured (the
        // house defaults) so the `GovernorLayer` is actually mounted —
        // ws-api's `None` branch is the TESTS-ONLY shape.
        auth_rate_limit: Some(cfg.rate_limit),
    };
    let app = ws_api::router(ws_api::AppState::new(pool, jwt, config));

    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    tracing::info!(bind = %cfg.bind, "serving the REST API");
    Ok(axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?)
}

/// The serving-leaf predicate over a tenant's certificates: an ACTIVE
/// certificate issued on the built-in `web-server` profile — the profile
/// setup itself mints the UI's leaf on, and the one an operator re-issue
/// of the server leaf naturally rides — newest `created_at` wins. `None`
/// means NO serving leaf exists (the pinned torn state: the UI falls back
/// to the setup certificate).
///
/// Deliberately NOT "any active certificate": the UI's own leaf is the
/// `web-server` one, and serving some other workload's domain certificate
/// would present the wrong identity to the browsers that connect here.
///
/// The newest-wins rule covers the re-issue flow naturally: once a fresh
/// leaf exists on the same profile, the next boot presents it; revoked
/// leaves drop out through the `active` predicate.
fn select_serving_leaf(certs: &[CertificateModel]) -> Option<&CertificateModel> {
    certs
        .iter()
        .filter(|cert| {
            cert.status == CertStatus::Active && cert.profile_name == SERVING_LEAF_PROFILE
        })
        .max_by(|a, b| a.created_at.cmp(&b.created_at))
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
        let cfg = config_from(table(&MINIMAL)).expect("the minimal table parses");
        assert_eq!(
            cfg.database_url,
            "postgres://wardstone:wardstone@db/wardstone"
        );
        assert_eq!(cfg.keys_dir, PathBuf::from("/var/lib/wardstone/keys"));
        assert!(cfg.server_hostname.is_none(), "no hostname configured");
        assert_eq!(cfg.api_url, "http://ws-api:8080");
        assert_eq!(cfg.bind, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8443)));
        assert_eq!(cfg.rate_limit.per_millis, 500);
        assert_eq!(cfg.rate_limit.burst, 20);
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
        let cfg = config_from(table(&entries)).expect("the full table parses");
        assert_eq!(cfg.server_hostname.as_deref(), Some("ca.example.test"));
        assert_eq!(cfg.api_url, "http://api.internal:9000");
        assert_eq!(cfg.bind, SocketAddr::from((Ipv4Addr::LOCALHOST, 9443)));
        assert_eq!((cfg.rate_limit.per_millis, cfg.rate_limit.burst), (100, 5));

        let err = config_from(table(&[MINIMAL[0]])).expect_err("a missing keys dir must fail");
        assert!(
            err.to_string().contains("WARDSTONE_KEYS_DIR"),
            "the error names the missing variable: {err}"
        );
        let err = config_from(table(&[MINIMAL[1]])).expect_err("a missing database url must fail");
        assert!(
            err.to_string().contains("DATABASE_URL"),
            "the error names the missing variable: {err}"
        );
    }

    /// Blank values count as unset (the compose file may hand us "").
    #[test]
    fn config_blank_values_are_unset() {
        let entries = [("DATABASE_URL", "   "), ("WARDSTONE_KEYS_DIR", "")];
        let err = config_from(table(&entries)).expect_err("blank required values must fail");
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
        let err = config_from(table(&bind)).expect_err("a bad bind must fail");
        assert!(
            err.to_string().contains("WARDSTONE_BIND"),
            "the error names the variable: {err}"
        );

        let zero_burst = [MINIMAL[0], MINIMAL[1], ("WARDSTONE_RATE_LIMIT_BURST", "0")];
        let err = config_from(table(&zero_burst)).expect_err("a zero burst must fail");
        assert!(
            err.to_string().contains("WARDSTONE_RATE_LIMIT_BURST"),
            "the error names the variable: {err}"
        );

        let zero_period = [
            MINIMAL[0],
            MINIMAL[1],
            ("WARDSTONE_RATE_LIMIT_PER_MILLIS", "0"),
        ];
        let err = config_from(table(&zero_period)).expect_err("a zero period must fail");
        assert!(
            err.to_string().contains("WARDSTONE_RATE_LIMIT_PER_MILLIS"),
            "the error names the variable: {err}"
        );

        let garbage = [
            MINIMAL[0],
            MINIMAL[1],
            ("WARDSTONE_RATE_LIMIT_PER_MILLIS", "soon"),
        ];
        let err = config_from(table(&garbage)).expect_err("a non-numeric rate limit must fail");
        assert!(
            err.to_string().contains("WARDSTONE_RATE_LIMIT_PER_MILLIS"),
            "the error names the variable: {err}"
        );
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
            source: "manual".to_owned(),
            created_at: Utc::now() - Duration::minutes(minutes_ago),
        }
    }

    /// The selection: active web-server certificates only, newest first,
    /// revoked and foreign-profile rows never chosen.
    #[test]
    fn select_serving_leaf_picks_the_newest_active_web_server_cert() {
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
            old_active,
            new_active.clone(),
            revoked_newer.clone(),
            foreign,
        ];
        let picks = select_serving_leaf(&table).expect("an active web-server cert exists");
        assert_eq!(picks.id, new_active.id, "newest active wins");

        assert!(
            select_serving_leaf(&[revoked_newer]).is_none(),
            "a revoked leaf is not servable"
        );
        assert!(
            select_serving_leaf(&[]).is_none(),
            "an empty table has no leaf: the boot falls back to the setup certificate"
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
        assert!(select_serving_leaf(&[]).is_none());
        assert!(
            select_serving_leaf(std::slice::from_ref(&leaf)).is_some(),
            "the same one-predicate rule drives both boot outcomes"
        );
    }
}
