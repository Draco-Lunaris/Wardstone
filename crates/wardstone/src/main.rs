//! The `wardstone` binary: ONE image with TWO invocation modes.
//!
//! - `wardstone ui` — the TLS front door: the first-run setup page while
//!   no tenant exists, the CA-issued server leaf afterwards, and the
//!   `/api/v1` proxy in every phase (all of the logic lives in `ws-web`).
//! - `wardstone api` — the REST surface, served DIRECTLY as plain HTTP
//!   for the internal network (the logic lives in `ws-api`).
//! - `wardstone db-verifier` — a pure LOCAL mint (Task 4): a fresh
//!   typeable database login credential with its Postgres
//!   SCRAM-SHA-256 verifier for the operator to install in `.env`, or
//!   (`--password-stdin`) the verifier of the operator's own chosen
//!   password. No environment, no database, no keys volume; neither
//!   value is ever logged.
//!
//! The separate-process anti-goal this shape realizes: the UI and the API
//! are independently restartable — the compose bundle (a later task) runs
//! them as two services of the same image, `wardstone ui` / `wardstone
//! api`, and `ws-web` publishes the only LAN port.
//!
//! `main` is a thin dispatcher: it parses the mode argument, reads the
//! shared environment contract, initializes logging (and the protected
//! memory pool — every mode's FIRST act), and hands over to
//! [`run_ui`] / [`run_api`]. The boot rule both modes share
//! (seal-at-creation): `master.envelope` absent → the first-run setup
//! page over a RAM-only certificate with NO database connection and
//! nothing written to the keys volume; present → the locked page, whose
//! unlock resolves the tenant and the serving leaf BEFORE the api relay
//! (whose credential rotation would strand any fresh ui connection) and
//! then releases the pool — the unlocked front door holds no database
//! connection at all.

use std::net::SocketAddr;
use std::path::PathBuf;

use tracing_subscriber::EnvFilter;
use ws_ca::error::CaError;
use ws_ca::leafkey::LeafKeyType;
use ws_core::error::CoreError;
use ws_core::models::certificate::{CertStatus, CertificateModel};
use ws_secmem::SecretBuf;
use ws_web::tls_signer::{ArenaKey, SwapResolver};
use zeroize::Zeroizing;

/// The listen address when `WARDSTONE_BIND` is unset (the brief's pin).
const DEFAULT_BIND: &str = "0.0.0.0:8443";

/// The proxy target when `WARDSTONE_API_URL` is unset (the brief's pin):
/// the compose service name of the `api` mode on the internal network.
const DEFAULT_API_URL: &str = "http://ws-api:8080";

/// The relay socket's path when `WARDSTONE_RELAY_SOCKET` is unset (the
/// brief's pin): the compose contract's path inside the shared relay
/// volume (ruling 28a's host-/run bind mount).
const DEFAULT_RELAY_SOCKET: &str = "/run/wardstone/relay/relay.sock";

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
    /// `WARDSTONE_RELAY_SOCKET`: the unlock relay's Unix-socket path
    /// (BOTH modes — the api binds it during the locked/boot phase and
    /// the ui's unlock relay dials it; Task 10, D8: no network listener
    /// carries the relay). Defaults to [`DEFAULT_RELAY_SOCKET`]; the
    /// api's bind forces mode 0600 and checks every peer's
    /// `SO_PEERCRED` uid against its own.
    relay_socket: PathBuf,
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
        // The db-verifier mint is pure-local: no env contract, no
        // database, no keys volume — so no config parse, and no tracing
        // on the path (its output is stdout-or-nothing by contract).
        Some("db-verifier") => run_db_verifier(std::env::args().nth(2).as_deref()),
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
                "error: expected a mode (`ui`, `api`, or `db-verifier`), got {}",
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

/// The `db-verifier` mint (Task 4): a PURE-LOCAL subcommand — no
/// environment contract, no database, no keys volume — that mints
/// Postgres login material for the operator to install by hand.
/// Default mode: a fresh 52-char typeable credential, its
/// SCRAM-SHA-256 verifier, and the hint that only the VERIFIER belongs
/// in `.env` (single-quoted; the plaintext behind it is what actually
/// logs in). `--password-stdin`: the operator's own chosen password is
/// read from stdin (one line, trailing newline stripped) and NEVER
/// echoed — only the verifier and the hint print. An empty chosen
/// password is refused loudly (an empty login credential would lock the
/// role's owner out at the next connect, silently).
///
/// Neither value is logged at any level, anywhere: the output contract
/// is stdout-or-nothing, and no tracing call sits on this path (a log
/// line would outlive the operator's terminal).
fn run_db_verifier(second: Option<&str>) -> std::process::ExitCode {
    // The protected arena before ANY print (Task 7's init-order pin):
    // every mode initializes ws-secmem first, and a refusal here keeps
    // this path's own failure shape — stderr and a non-zero exit, no
    // panic and no tracing line (the stdout contract below still
    // holds: nothing credential-shaped is ever logged).
    if let Err(err) = ws_secmem::init(ws_secmem::PRODUCTION_POOL) {
        eprintln!("error: {}", ws_ca::keystore::protected_memory_failure(err));
        return std::process::ExitCode::FAILURE;
    }
    let salt = match ws_core::dbcred::fresh_scram_salt() {
        Ok(salt) => salt,
        Err(err) => {
            eprintln!("error: {err}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match second {
        None => {
            let fresh = match ws_core::dbcred::generate_db_password() {
                Ok(fresh) => fresh,
                Err(err) => {
                    eprintln!("error: {err}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            let verifier =
                ws_core::dbcred::scram_verifier(&fresh, &salt, ws_core::dbcred::SCRAM_ITERATIONS);
            println!("password: {}", String::from_utf8_lossy(&fresh));
            println!("verifier: {verifier}");
            print_verifier_hint(&verifier);
        }
        Some("--password-stdin") => {
            use std::io::BufRead as _;

            let mut chosen = String::new();
            if let Err(err) = std::io::stdin().lock().read_line(&mut chosen) {
                eprintln!("error: reading the chosen password from stdin: {err}");
                return std::process::ExitCode::FAILURE;
            }
            let chosen = chosen.strip_suffix('\n').map_or(chosen.as_str(), |line| {
                line.strip_suffix('\r').unwrap_or(line)
            });
            if chosen.is_empty() {
                eprintln!("error: the chosen password read from stdin is empty");
                return std::process::ExitCode::FAILURE;
            }
            let verifier = ws_core::dbcred::scram_verifier(
                chosen.as_bytes(),
                &salt,
                ws_core::dbcred::SCRAM_ITERATIONS,
            );
            println!("verifier: {verifier}");
            print_verifier_hint(&verifier);
        }
        Some(other) => {
            eprint!("{}", usage_text());
            eprintln!(
                "error: expected no argument or `--password-stdin` after db-verifier, got `{other}`"
            );
            return std::process::ExitCode::from(2);
        }
    }
    std::process::ExitCode::SUCCESS
}

/// The operator hint both mint modes print: ONLY the verifier belongs
/// in `.env`, single-quoted (Postgres stores the verifier as-is; the
/// plaintext behind it — not the verifier — is what logs in).
fn print_verifier_hint(verifier: &str) {
    println!(
        "hint: put only the verifier in .env, single-quoted: WARDSTONE_DB_PASSWORD='{verifier}'"
    );
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
         \x20 db-verifier  mint a fresh database login credential with its \
         Postgres SCRAM verifier for the operator to install in .env \
         (local-only: no environment, no database, no keys volume; \
         --password-stdin hashes a chosen password instead)\n\
         \n\
         Configuration (environment, both modes):\n\
         \x20 DATABASE_URL               required — the Postgres connection URL\n\
         \x20 WARDSTONE_KEYS_DIR         required — the keystore directory\n\
         \x20 WARDSTONE_SERVER_HOSTNAME  the setup certificate's SAN (optional)\n\
         \x20 WARDSTONE_API_URL          the UI's proxy target (ui; default \
         {DEFAULT_API_URL})\n\
         \x20 WARDSTONE_RELAY_SOCKET     the unlock relay's Unix-socket path \
(both modes; default {DEFAULT_RELAY_SOCKET})\n\
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

    // The relay socket: read in BOTH modes (the api binds it, the ui
    // dials it), defaulting to the compose contract's shared-volume
    // path. An empty value is already filtered to None by the lookup
    // contract, so it means the default, not a blank path.
    let relay_socket = match lookup("WARDSTONE_RELAY_SOCKET") {
        None => PathBuf::from(DEFAULT_RELAY_SOCKET),
        Some(value) => PathBuf::from(value),
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
        relay_socket,
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

/// The sealed `ui` boot: the front door binds with an EPHEMERAL
/// sealed-mode certificate (no key material exists in this process yet)
/// and serves the locked page until the operator's unlock.
///
/// The build closure ([`unlocked_web_build`]) is where the world comes
/// up: it converges a mixed volume when the completion pair rides along,
/// opens the envelopes (the master for the keystore, the DB credential
/// for the pool — or the unlock form's typed database password on the
/// recovery runbook), resolves the tenant and the serving leaf (the
/// newest ACTIVE `web-server` row whose key envelope the keystore
/// actually holds — [`resolve_serving_leaf`]'s walk), and reloads the
/// listener's TLS onto the CA-issued leaf in place (the resume
/// contract). A tenant WITHOUT a servable leaf keeps the sealed
/// certificate serving (the WARN line records the choice; recovery is
/// operator-initiated: log in and re-issue the server leaf through the
/// proxied API). A volume whose database holds NO tenant is the torn
/// state: the build's fatal exits the process non-zero with the spec's
/// copy.
async fn run_ui_sealed(cfg: BootConfig) -> Result<(), BootError> {
    let hostname = cfg
        .server_hostname
        .clone()
        .unwrap_or_else(|| ws_web::setup::tls::PLACEHOLDER_SAN.to_owned());
    // The ephemeral sealed certificate: hours of validity, no keystore.
    let (sealed_pem, sealed_key, sealed_fingerprint) =
        ws_web::setup::tls::sealed_certificate(&hostname)?;
    // The sealed key crosses into the resolver's custody exactly once (a
    // ws-secmem arena reservation inside the `ArenaKey`: RAM custody,
    // wiped when the resolver drops it — no intermediate heap or PEM
    // copy), and the ONE resolver serves the sealed certificate now and
    // the CA-issued leaf after the unlock: the swap IS the reload.
    let resolver = std::sync::Arc::new(SwapResolver::new());
    resolver.swap_pem(
        &sealed_pem,
        ArenaKey::new(sealed_key, LeafKeyType::EcdsaP256),
    )?;
    let reload_handle = resolver.clone();

    // The torn-state exit channel: a build that resolves the tenant and
    // finds none is a REFUSED boot (the process must not keep serving a
    // volume whose install never completed) — but the build runs inside
    // the unlock POST's request task, so the fatal crosses here and the
    // serve loop unwinds with a non-zero exit carrying the spec's copy
    // (the POST's own 409 shows the operator the same words).
    let (fatal_tx, mut fatal_rx) = tokio::sync::mpsc::unbounded_channel::<BootError>();
    let build = unlocked_web_build(&cfg, reload_handle, fatal_tx);
    let ui = std::sync::Arc::new(ws_web::locked::SealedUi::new(build));
    let router = ws_web::locked::locked_router(ui, &cfg.keys_dir, &hostname, cfg.web_rate_limit);
    tracing::info!(
        hostname = %hostname,
        fingerprint = %sealed_fingerprint,
        bind = %cfg.bind,
        "serving the sealed front door: enter the master passphrase to continue"
    );
    // The serve loop races the fatal channel: whichever ends first wins —
    // a listener failure returns its error, a torn verdict exits the
    // process non-zero (`run_result` prints the copy on stderr).
    let serve = ws_web::serve_tls_with_config(cfg.bind, resolver, router);
    tokio::pin!(serve);
    tokio::select! {
        result = &mut serve => result.map_err(BootError::from),
        Some(verdict) = fatal_rx.recv() => Err(verdict),
    }
}

/// The web build the sealed boot hands its `SealedUi`: it converges a
/// mixed volume when the completion pair rides along, opens the
/// envelopes, builds the ui's pool from the sealed DB credential (or
/// re-seals a lost one from the unlock form's typed database password —
/// the recovery runbook), resolves the tenant and the serving leaf,
/// RELEASES the pool, relays the passphrase to the api (best-effort,
/// logged), and returns the pool-less unlocked router (Review Focus 1:
/// the api's relayed unlock rotates the database credential, so any
/// fresh ui connection after the relay dies 28P01 — the unlocked front
/// door holds no database connection at all). A sealed volume implies
/// setup committed, so there is no setup-commit TLS swap to wire here.
///
/// `fatal` carries the torn-state verdict (a sealed volume whose
/// database holds no default tenant): the build runs inside the unlock
/// POST's request task, so the refusal crosses the channel to the serve
/// loop and the process exits non-zero — while the build's own error
/// string makes the POST answer 409 with the same copy.
fn unlocked_web_build(
    cfg: &BootConfig,
    reload: std::sync::Arc<ws_web::tls_signer::SwapResolver>,
    fatal: tokio::sync::mpsc::UnboundedSender<BootError>,
) -> ws_web::locked::LockedWebBuild {
    let keys_dir = cfg.keys_dir.clone();
    // The ui's connections carry the process's application_name label:
    // sqlx parses the query parameter onto the backend's registration,
    // Task 11's Postgres-side scans key off the ui/api labels, and the
    // label rides the QUERY — every credential splice below rewrites
    // only the authority, so the label reaches the live connection.
    let database_url = with_application_name(&cfg.database_url, UI_APP_NAME);
    let api_url = cfg.api_url.clone();
    let relay_socket = cfg.relay_socket.clone();
    let session_ttl = ws_web::DEFAULT_SESSION_TTL;
    let rate_limit = cfg.web_rate_limit;

    std::sync::Arc::new(
        move |passphrase: &str, next_passphrase: Option<&str>, db_password: Option<&str>| {
            let keys_dir = keys_dir.clone();
            let database_url = database_url.clone();
            let api_url = api_url.clone();
            let relay_socket = relay_socket.clone();
            let reload = reload.clone();
            let fatal = fatal.clone();
            let passphrase = passphrase.to_string();
            let next_passphrase = next_passphrase.map(str::to_string);
            let db_password = db_password.map(str::to_string);
            futures_util::future::FutureExt::boxed(async move {
                let err = |msg: String| msg; // the ui's build reports strings
                                             // The mixed-state completion (spec §5.7), the same arm the
                                             // api builder runs: a crashed passphrase change leaves the
                                             // envelope generations disagreeing, the page re-offered the
                                             // completion, and the volume converges BEFORE anything
                                             // opens. The ui converges it and proceeds under the new
                                             // passphrase — the relay then carries the EFFECTIVE one
                                             // alone, so the api unlocks a volume that is already clean
                                             // (relaying the pair would trip the api's
                                             // no_completion_pending refusal).
                let scan = ws_core::crypto::scan_volume(&keys_dir)
                    .map_err(|e| err(format!("the volume scan: {e}")))?;
                let passphrase = match (scan.mixed, next_passphrase) {
                    (true, Some(next)) => {
                        ws_core::crypto::rewrap_volume(
                            &keys_dir,
                            &scan.present,
                            &passphrase,
                            &next,
                        )
                        .map_err(|e| err(format!("the volume completion: {e}")))?;
                        next
                    }
                    (true, None) => {
                        return Err(err("completion_required".to_string()));
                    }
                    (false, Some(_)) => {
                        return Err(err("no_completion_pending".to_string()));
                    }
                    (false, None) => passphrase,
                };
                // The master envelope: the keystore's unwrapped custody.
                let master = ws_core::crypto::KeyEnvelope::open_envelope(
                    &keys_dir.join(MASTER_ENVELOPE_FILE),
                    &passphrase,
                )
                .map_err(|e| err(format!("the master envelope: {e}")))?;
                let mut master_bytes = Zeroizing::new([0u8; 32]);
                master_bytes.copy_from_slice(&master);
                // The unlocked keystore holds its master as a ws-secmem arena
                // reservation: the envelope's Zeroizing plaintext dies at this
                // scope's end and only the protected copy crosses into the
                // keystore's custody.
                let master_buf = ws_secmem::global()
                    .and_then(|mem| mem.alloc_copy(&master_bytes[..]))
                    .map_err(|e| err(format!("the master key's protected arena: {e}")))?;
                let keystore = ws_ca::keystore::KeyStore::open_unlocked(&keys_dir, master_buf)
                    .map_err(|e| err(format!("the keystore: {e}")))?;

                // The ui's only pool: the db credential, read-only per the
                // spec (the api rotates it, the ui re-reads it). The
                // pending-first rule is the CALLER's (the unlock): try the
                // `.pending` sibling first (a rotation whose commit step
                // crashed); a live connect promotes it atomically, a 28P01
                // discards it (a pending that cannot log in was never made
                // live on the database side) and falls to the current
                // credential. One exception: the recovery runbook (spec §8)
                // — an operator who lost the credential deletes the
                // envelope, sets a fresh bootstrap password, and reboots; the
                // envelope's absence is the ONLY thing distinguishing that
                // boot, so the unlock form's TYPED database password re-seals
                // it through the identical first-install step (the shared
                // rotation) before anything else connects.
                let db_credential_path = keys_dir.join(DB_CREDENTIAL_ENVELOPE_FILE);
                let pool = if db_credential_path.exists() {
                    let candidates = ws_core::dbcred::open_db_credential(
                        &db_credential_path,
                        passphrase.as_bytes(),
                    )
                    .map_err(|e| err(format!("the db credential: {e}")))?;
                    let mut live = None;
                    if let Some(pending) = candidates.pending.as_ref() {
                        match ws_core::db::connect(&substitute_db_password(
                            &database_url,
                            &String::from_utf8_lossy(pending),
                        ))
                        .await
                        {
                            Ok(pool) => {
                                ws_core::dbcred::promote_pending(&db_credential_path).map_err(
                                    |e| err(format!("the pending credential's promotion: {e}")),
                                )?;
                                live = Some(pool);
                            }
                            Err(e) if db_rejected(&e) => {
                                ws_core::dbcred::discard_pending(&db_credential_path).map_err(
                                    |e| err(format!("the pending credential's discard: {e}")),
                                )?;
                            }
                            Err(e) => return Err(err(format!("the database: {e}"))),
                        }
                    }
                    match live {
                        Some(pool) => pool,
                        None => ws_core::db::connect(&substitute_db_password(
                            &database_url,
                            &String::from_utf8_lossy(&candidates.current),
                        ))
                        .await
                        .map_err(|e| err(format!("the database: {e}")))?,
                    }
                } else {
                    // The recovery runbook (spec §8): the unlock form's
                    // typed database password IS the fresh bootstrap
                    // credential the operator set; the rotation re-seals it
                    // into the envelope before the pool connects with it.
                    // The locked page's 400 has normally already refused a
                    // missing field — this is the build's own guard for the
                    // race where the envelope vanished mid-POST.
                    let typed = db_password.ok_or_else(|| {
                        err("the db_password field is required when the volume holds \
                             no db-credential envelope (the recovery runbook)"
                            .to_string())
                    })?;
                    let generation = ws_core::crypto::KeyEnvelope::read_generation(
                        &keys_dir.join(MASTER_ENVELOPE_FILE),
                    )
                    .map_err(|e| err(format!("the recovery generation: {e}")))?;
                    let fresh = ws_web::setup::recover_db_credential(
                        &keys_dir,
                        passphrase.as_bytes(),
                        &database_url,
                        typed.as_bytes(),
                        generation,
                    )
                    .await
                    .map_err(|e| err(format!("the db re-seal: {e}")))?;
                    ws_core::db::connect(&substitute_db_password(
                        &database_url,
                        &String::from_utf8_lossy(&fresh),
                    ))
                    .await
                    .map_err(|e| err(format!("the database: {e}")))?
                };

                // The tenant and the serving leaf resolve HERE, before the
                // relay (Review Focus 1): the api's relayed unlock rotates
                // the database credential, and every FRESH ui connection
                // after the relay dies 28P01 — so these reads ride the pool
                // this build is about to release, never a post-relay dial.
                let tenant = ws_core::repo::tenant_repo::TenantRepo::new()
                    .get_by_name(&pool, ws_web::setup::DEFAULT_TENANT_NAME)
                    .await
                    .map_err(|e| err(format!("the tenant lookup: {e}")))?
                    .ok_or_else(|| {
                        // The torn state: the sealed marker promises the
                        // seal landed, but the database holds no tenant —
                        // setup crashed after sealing. Nothing
                        // auto-recovers from a half-finished install (the
                        // database side may itself be incomplete): the fatal
                        // exits the process non-zero and the POST's 409
                        // carries the same copy.
                        let _ = fatal.send(BootError::Config(
                            ws_web::locked::INTERRUPTED_SETUP_REFUSAL.to_owned(),
                        ));
                        err(ws_web::locked::INTERRUPTED_SETUP_REFUSAL.to_string())
                    })?;
                let certs = ws_core::repo::certificate_repo::CertificateRepo::new()
                    .list_by_tenant(&pool, tenant.id, 0, 500)
                    .await
                    .map_err(|e| err(format!("the certificate listing: {e}")))?;
                let leaf = resolve_serving_leaf(&certs, |leaf| keystore.unwrap_ca_key(&leaf.id))
                    .map_err(|e| err(format!("the serving-leaf walk: {e}")))?;
                match leaf {
                    Some((leaf_row, key_der)) => {
                        // The row's key_type names the algorithm the key
                        // was minted as; the resolver's signer rebuilds
                        // exactly that backend for every signature.
                        let kind = LeafKeyType::from_str(&leaf_row.key_type).ok_or_else(|| {
                            err(format!(
                                "the serving leaf row pins an unusable key type {:?}",
                                leaf_row.key_type
                            ))
                        })?;
                        // The swap IS the reload: the resolver publishes
                        // the CA-issued pair for the very NEXT handshake,
                        // and the key's reservation moves into arena
                        // custody inside the `ArenaKey` — no PEM form, no
                        // heap copy, ever.
                        reload
                            .swap_pem(&leaf_row.cert_pem, ArenaKey::new(key_der, kind))
                            .map_err(|e| err(format!("the TLS reload: {e}")))?;
                        tracing::info!(
                            certificate_id = %leaf_row.id,
                            subject = %leaf_row.subject,
                            "the TLS listener resumed onto the CA-issued leaf"
                        );
                    }
                    None => {
                        // The torn state keeps the sealed certificate: the
                        // operator reaches the recovery flow next.
                        tracing::warn!(
                            "no active serving leaf after unlock; the sealed \
                             certificate keeps serving"
                        );
                    }
                }

                // The pool's whole life ends HERE (Review Focus 1): the
                // unlocked front door serves pool-less — everything
                // database-touching rides the proxy to the api from this
                // moment on, and the relay's rotation cannot strand a
                // connection that no longer exists.
                drop(pool);
                // Relay the unlock to the api: one POST, best-effort with
                // a logged verdict (the api may be seeding, a redeploy
                // racer, or already unlocked — every one of those is the
                // spec's documented fallback, never a ui failure).
                if let Err(e) = ws_web::locked::relay_unlock(&relay_socket, &passphrase).await {
                    tracing::warn!(
                        error = %e,
                        "the api unlock relay did not complete; the api logs its own state"
                    );
                }
                tracing::info!(
                    "the sealed front door unlocked: the tenant and serving leaf \
                     resolved, the pool released; no database connection is held"
                );
                Ok(ws_web::unlocked_web_router(
                    &api_url,
                    session_ttl,
                    rate_limit,
                ))
            })
        },
    )
}

/// The `ui` mode: the TLS front door. The boot dispatches on the sealed
/// marker alone (`master.envelope`): present → the locked page
/// ([`run_ui_sealed`]); absent → the FIRST-RUN setup page over a
/// RAM-only self-signed certificate with NO database connection — a
/// fresh install's shape, where no tenant can exist behind an unsealed
/// volume (setup is the only path in, and the setup POST is the first
/// thing that ever dials the database).
async fn run_ui(cfg: BootConfig) -> Result<(), BootError> {
    // The protected arena is the process's FIRST act: the unlock's
    // argon2 derive sits on the KDF slot, and every certificate mint or
    // envelope open claims the pool — it must exist before any of them
    // run (the same idiom the api and db-verifier boots use).
    ws_secmem::init(ws_secmem::PRODUCTION_POOL)
        .map_err(ws_ca::keystore::protected_memory_failure)?;
    // The compose contract (Review Focus 5): the ui's DATABASE_URL is
    // password-less — its credential lives only in the sealed
    // `db-credential.envelope` (or the setup page's typed field, the
    // first install's shape). A password in the URL is refused before
    // any key or database work.
    if db_url_has_password(&cfg.database_url) {
        return Err(BootError::Config(
            "DATABASE_URL carries a password; Wardstone reads the database \
             credential only from its sealed envelope or the setup page"
                .to_owned(),
        ));
    }
    // Task 10's external-DB policy (D5), additive beside the password
    // gate and after it: parse, don't connect — a socket URL is a
    // local link, a TCP URL must carry sslmode=verify-full AND the
    // operator's sslrootcert.
    ws_core::db::check_database_url(&cfg.database_url)?;
    if sealed_instance(&cfg.keys_dir) {
        return run_ui_sealed(cfg).await;
    }
    let hostname = cfg
        .server_hostname
        .clone()
        .unwrap_or_else(|| ws_web::setup::tls::PLACEHOLDER_SAN.to_owned());
    // The RAM-only first-run certificate: self-signed, keyed in the
    // protected arena, written NOWHERE — two boots before setup leave
    // the keys volume empty, and the boot dials no database. The setup
    // page echoes the fingerprint for the operator's out-of-band check;
    // the setup commit's resolver swap replaces the certificate in
    // place (the resume contract — the swap IS the reload).
    let (cert_pem, key_der, fingerprint) = ws_web::setup::tls::first_run_certificate(&hostname)?;
    let resolver = std::sync::Arc::new(SwapResolver::new());
    resolver.swap_pem(&cert_pem, ArenaKey::new(key_der, LeafKeyType::EcdsaP256))?;
    tracing::info!(
        hostname = %hostname,
        fingerprint = %fingerprint,
        bind = %cfg.bind,
        "no master envelope: serving the first-run setup page"
    );
    // The pool-less first-run router: the setup surface with nothing
    // behind it — no keystore, no JWT pair, no pool exists in this
    // process until the setup POST builds the world.
    let router = ws_web::first_run_web_router(
        cfg.keys_dir.clone(),
        fingerprint,
        hostname,
        Some(resolver.clone()),
        &cfg.api_url,
        &cfg.relay_socket,
        cfg.database_url.clone(),
        ws_web::DEFAULT_SESSION_TTL,
        cfg.web_rate_limit,
    );
    Ok(ws_web::serve_tls_with_config(cfg.bind, resolver, router).await?)
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
/// The sealed-at-rest envelope file names on the keys volume, from
/// ws-core's single home for the contract (the design's state predicate:
/// `master.envelope` present ⇒ the instance is sealed at boot).
use ws_core::crypto::{substitute_db_password, DB_CREDENTIAL_ENVELOPE_FILE, MASTER_ENVELOPE_FILE};

/// Keys-directory-only state derivation (spec §3): `master.envelope`
/// present → the instance boots sealed and waits for the unlock relay.
fn sealed_instance(keys_dir: &std::path::Path) -> bool {
    keys_dir.join(MASTER_ENVELOPE_FILE).exists()
}

/// Does the operator-supplied DATABASE_URL carry a password? The
/// password-less compose contract — BOTH modes refuse a URL password
/// (the credential lives only in the sealed envelope, or the setup
/// page's / unlock form's typed field): the api always boots the sealed
/// shell (it builds no pool at boot and waits for the setup commit's or
/// the unlock's relay), and a ui password would smuggle a credential
/// around the sealed custody (G5, Review Focus 5). The parsing
/// mirrors [`substitute_db_password`]'s: the password is whatever
/// follows the last `:` in the `://…@` authority.
fn db_url_has_password(url: &str) -> bool {
    let Some(scheme_end) = url.find("://") else {
        return false;
    };
    let auth_start = scheme_end + 3;
    let Some(at) = url[auth_start..].find('@').map(|i| i + auth_start) else {
        return false;
    };
    url[auth_start..at].rfind(':').is_some()
}

/// The `application_name` the ui process labels its database
/// connections with (sqlx parses the query parameter onto the backend's
/// pg_stat_activity row): Task 11's Postgres-side scans key off the
/// ui/api labels, and the boot battery's terminate sweep targets them.
const UI_APP_NAME: &str = "wardstone-ui";

/// The api process's label — [`UI_APP_NAME`]'s twin.
const API_APP_NAME: &str = "wardstone-api";

/// Append the process's `application_name` to a connection URL as a
/// query parameter (sqlx parses it onto the backend's registration).
/// Idempotent, and the label rides the QUERY — so it survives every
/// [`substitute_db_password`] splice (which rewrites only the
/// authority) and never disturbs [`db_url_has_password`]'s parse.
fn with_application_name(url: &str, name: &str) -> String {
    if url.contains("application_name=") {
        url.to_owned()
    } else if url.contains('?') {
        format!("{url}&application_name={name}")
    } else {
        format!("{url}?application_name={name}")
    }
}

/// The database's own "wrong password" verdict (SQLSTATE `28P01`) — the
/// pending-first rule's only tolerated connect failure: a pending
/// credential that cannot log in was never made live on the database
/// side. Mirrors ws-api's `invalid_password` and ws-web's `db_rejected`
/// (the house idiom: the SQLSTATE, never message text).
fn db_rejected(err: &CoreError) -> bool {
    matches!(
        err,
        CoreError::Database(db)
            if db.as_database_error().and_then(|e| e.code()).as_deref() == Some("28P01")
    )
}

/// The api's [`ws_api::ApiConfig`] from the boot env, for the sealed
/// unlock's build closure.
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

/// The sealed api boot: the process binds its TCP listener immediately
/// (the health surface answers `200 sealed`) and its Unix relay socket
/// (Task 10, D8: the unlock's ONLY transport — every peer's
/// `SO_PEERCRED` uid is checked against the api's own before any body
/// byte is read), and waits for the ui's unlock relay. The build
/// closure is the ws-api builder
/// ([`ws_api::sealed::unlocked_router_from_envelopes`]): it opens the
/// envelopes, rotates the DB credential (unconditionally, every unlock —
/// a leaked credential dies at the next unlock), and swaps the FULL
/// `ws_api::router` in over RAM custody.
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
            let next_passphrase = req.next_passphrase.clone();
            futures_util::future::FutureExt::boxed(async move {
                ws_api::sealed::unlocked_router_from_envelopes(
                    &keys_dir,
                    &database_url,
                    &config,
                    &passphrase,
                    next_passphrase.as_deref(),
                )
                .await
            })
        });

    // The relay socket's directory is the relay nonce's claim home
    // (Task 10: `socket.parent()/relay-nonce`, G1 — never the keys
    // volume), and the socket itself is the unlock's ONLY transport
    // (D8): bound here, during the locked phase, before anything
    // serves. The operator's pre-step created the directory (compose's
    // inline comment); a missing parent fails this bind loudly.
    let relay_dir = cfg
        .relay_socket
        .parent()
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| {
            BootError::Config(format!(
                "WARDSTONE_RELAY_SOCKET {:?} has no parent directory",
                cfg.relay_socket
            ))
        })?;
    let api = std::sync::Arc::new(ws_api::sealed::SealedApi::new(build, relay_dir));
    let app = ws_api::sealed::sealed_router(api.clone());
    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    let relay_listener = ws_api::sealed::bind_relay_socket(&cfg.relay_socket)?;
    let own_uid = ws_api::sealed::current_uid();
    tracing::info!(
        bind = %cfg.bind,
        relay_socket = %cfg.relay_socket.display(),
        "serving the sealed REST API: unlock through the front door's relay to continue"
    );
    // The two listeners serve CONCURRENTLY and the process dies with
    // either: the TCP surface is the health/`/api/v1` surface (ruling
    // 28f keeps it on the internal network), the relay socket is the
    // unlock's one path in — a dead relay is a locked instance that can
    // never be unlocked.
    let serve_tcp = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    );
    let serve_relay = ws_api::sealed::serve_relay(relay_listener, api, own_uid);
    tokio::select! {
        result = serve_tcp => result.map_err(BootError::from),
        result = serve_relay => result.map_err(BootError::from),
    }
}

async fn run_api(mut cfg: BootConfig) -> Result<(), BootError> {
    // The protected arena is the process's FIRST act (the unlock's
    // argon2 derive sits on the KDF slot; the sealed surface's envelope
    // opens claim the pool the moment the relay lands).
    ws_secmem::init(ws_secmem::PRODUCTION_POOL)
        .map_err(ws_ca::keystore::protected_memory_failure)?;
    // The compose contract: the api's DATABASE_URL is password-less — its
    // credential lives only in the sealed envelope. The api always boots
    // the sealed shell (a fresh install's setup commit, or the unlock,
    // relays it up); a password in the URL is a misconfiguration (G5).
    if db_url_has_password(&cfg.database_url) {
        return Err(BootError::Config(
            "the api's DATABASE_URL carries a password: it must be password-less \
             (postgres://wardstone@db:5432/wardstone) — the credential lives in \
             the sealed keys volume"
                .to_owned(),
        ));
    }
    // Task 10's external-DB policy (D5), additive beside the password
    // gate and after it: parse, don't connect — a socket URL is a
    // local link, a TCP URL must carry sslmode=verify-full AND the
    // operator's sslrootcert.
    ws_core::db::check_database_url(&cfg.database_url)?;
    // The api's connections carry their process label (Task 11's
    // Postgres-side scans key off the ui/api `application_name`s, and
    // the label rides the query through every credential splice).
    cfg.database_url = with_application_name(&cfg.database_url, API_APP_NAME);
    run_api_sealed(cfg).await
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
/// key its envelope unwrapped — a protected-arena reservation (a ws-secmem
/// `SecretBuf`) that MOVES into the resolver's `ArenaKey` custody at the
/// swap (the swap IS the reload; no PEM form exists at any point), or is
/// wiped when this handle drops unused.
type ServedLeaf<'a> = (&'a CertificateModel, SecretBuf);

fn resolve_serving_leaf(
    certs: &[CertificateModel],
    load_key: impl Fn(&CertificateModel) -> Result<SecretBuf, CaError>,
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

    /// The relay socket: BOTH modes read `WARDSTONE_RELAY_SOCKET` (the
    /// api binds it, the ui's relay dials it), with the compose
    /// contract's default path (ruling 28a's host-/run relay volume).
    #[test]
    fn config_parses_the_relay_socket_in_both_modes() {
        let ui = config_from(BootMode::Ui, table(&MINIMAL)).expect("the minimal table parses");
        assert_eq!(
            ui.relay_socket,
            PathBuf::from("/run/wardstone/relay/relay.sock")
        );
        let api = config_from(BootMode::Api, table(&MINIMAL)).expect("the minimal table parses");
        assert_eq!(
            api.relay_socket,
            PathBuf::from("/run/wardstone/relay/relay.sock"),
            "the default is mode-independent"
        );

        let entries = [
            MINIMAL[0],
            MINIMAL[1],
            ("WARDSTONE_RELAY_SOCKET", "/run/relay/custom.sock"),
        ];
        let cfg = config_from(BootMode::Api, table(&entries)).expect("the override parses");
        assert_eq!(cfg.relay_socket, PathBuf::from("/run/relay/custom.sock"));
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
        let mem = ws_secmem::global().expect("the pool must initialize on this host");
        let (leaf, key) = resolve_serving_leaf(&table, |c| {
            Ok(mem
                .alloc_copy(c.id.to_string().as_bytes())
                .expect("the arena serves the tiny key"))
        })
        .expect("the walk must not abort the boot when keys load")
        .expect("candidates exist");
        assert_eq!(leaf.id, new_active.id, "the newest candidate wins");
        assert_eq!(
            &*key,
            new_active.id.to_string().as_bytes(),
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
        let mem = ws_secmem::global().expect("the pool must initialize on this host");
        let (leaf, key) = resolve_serving_leaf(&table, |c| {
            loaded.borrow_mut().push(c.id);
            if c.id == new_active.id {
                Err(CaError::NotFound)
            } else {
                Ok(mem
                    .alloc_copy(c.id.to_string().as_bytes())
                    .expect("the arena serves the tiny key"))
            }
        })
        .expect("a missing envelope must not abort the boot")
        .expect("the next-newest leaf is servable");
        assert_eq!(
            leaf.id, old_active.id,
            "the walk serves the next-newest leaf after the unenveloped one"
        );
        assert_eq!(
            &*key,
            old_active.id.to_string().as_bytes(),
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
            Result::<SecretBuf, CaError>::Ok(
                ws_secmem::global()
                    .and_then(|mem| mem.alloc_copy(b""))
                    .expect("the arena serves the empty key"),
            )
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

    /// The application-name splice: a bare URL gains the label as the
    /// query's first parameter, a URL with query params gains it
    /// `&`-joined, an already-labelled URL comes back unchanged
    /// (idempotent), and the label never disturbs the password parse
    /// (it rides the query, not the authority) nor the credential
    /// splice (which rewrites only the authority) — so a labelled URL
    /// connects live with its label and its substituted credential
    /// together.
    #[test]
    fn application_name_splices_as_a_query_parameter() {
        let bare = "postgres://wardstone@db:5432/wardstone";
        let labelled = with_application_name(bare, UI_APP_NAME);
        assert_eq!(
            labelled,
            "postgres://wardstone@db:5432/wardstone?application_name=wardstone-ui"
        );
        let queried = "postgres://wardstone@db:5432/wardstone?sslmode=disable";
        assert_eq!(
            with_application_name(queried, UI_APP_NAME),
            "postgres://wardstone@db:5432/wardstone?sslmode=disable&application_name=wardstone-ui"
        );
        assert_eq!(
            with_application_name(&labelled, UI_APP_NAME),
            labelled,
            "the splice is idempotent"
        );
        assert!(
            !db_url_has_password(&with_application_name(
                "postgres://wardstone@db:5432/wardstone",
                UI_APP_NAME
            )),
            "the label rides the query — a password-less URL stays password-less"
        );
        assert_eq!(
            substitute_db_password(&with_application_name(bare, API_APP_NAME), "wardstone"),
            "postgres://wardstone:wardstone@db:5432/wardstone?application_name=wardstone-api",
            "the credential splice preserves the label"
        );
    }
}
