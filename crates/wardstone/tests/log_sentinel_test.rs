//! The log sentinel (Task 11 of the seal-at-creation plan): drive the
//! same full lifecycle as the disk-scan suite — first-run setup, an
//! unlock, a passphrase change, the D5 recovery rotation, an OIDC
//! configuration — against the REAL binary (`CARGO_BIN_EXE_wardstone`)
//! on a scratch keys volume, but at `RUST_LOG=trace` and INCLUDING the
//! failed attempts (a wrong passphrase at the unlock page, a wrong DB
//! password at the setup page, a bad OIDC secret configuration
//! attempt). Every secret the lifecycle mints, carries, or REJECTS is
//! collected as a needle and searched — in every form: raw bytes, hex,
//! base64, PEM body — through the captured stdout+stderr of both
//! children: no needle may appear in the captured output at ANY level.
//! A hit is a leak in an earlier task, never a fixture problem: the
//! failure names the needle, the haystack, and the offset, and the
//! task contract stops there.
//!
//! Beyond the plan's needle list, the suite hunts one more class: the
//! submitted-but-REJECTED values (the wrong passphrase, the wrong DB
//! password) — an error path that echoes what was submitted leaks a
//! future-correct passphrase — and the SCRAM-VERIFIER class (the
//! Global Constraint: no secret, credential, passphrase, token,
//! verifier, or key material in any log line at any level). The
//! rotations mint their verifiers with random salts, so no needle can
//! hunt them by value; the verifier prefix hunts the class.
//!
//! The flow sequence and where every needle is collected:
//!
//! 1. **Setup** (the first-run ui child, no api child yet — the api's
//!    unlock relay would supersede the conversion's fresh credential
//!    before it could ever be observed, so the api joins at step 3 and
//!    the real unlock POST at step 4 relays it up): a WRONG typed
//!    database password is POSTed first (the failed attempt; its value
//!    joins the needles), then the real POST `/setup` runs the
//!    conversion, which rotates the shared login role from the typed
//!    password to a fresh sealed value. Needles: the master passphrase,
//!    the admin password, both typed database passwords, and the
//!    conversion's fresh credential (opened from
//!    `db-credential.envelope`), the master key, the secret-encryption
//!    key, the JWT signing key (DER, via `ws_auth::jwt::load_sealed`),
//!    and the root-CA and serving-leaf private keys (DER, via the
//!    production chain: master envelope → `KeyStore::open_unlocked` →
//!    `unwrap_ca_key`).
//! 2. **Unlock**: the ui child restarts onto the sealed door, a WRONG
//!    passphrase is POSTed first (the failed attempt; its value joins
//!    the needles), then the real POST `/unlock` relays the api child
//!    up (its per-unlock rotation lands); needle: that rotation's fresh
//!    credential.
//! 3. **A passphrase change**: one envelope is hand-re-sealed under the
//!    new passphrase at the master's generation + 1 — the exact mixed
//!    volume a crashed change leaves — and the completion unlock
//!    (`passphrase` + `next_passphrase`) converges it. Both passphrases
//!    stay needles forever.
//! 4. **A rotation** (the D5 recovery runbook's actual world): with the
//!    children stopped, `db-credential.envelope` is removed, the ui
//!    restarts, and the unlock page's typed database password (the
//!    CURRENT role password, opened from the envelope BEFORE its
//!    removal) drives `recover_db_credential`'s fresh rotation. The
//!    restarted api child is then unlocked through the production relay
//!    (`ws_web::locked::relay_unlock`), whose own rotation is collected
//!    too.
//! 5. **An OIDC config**: the admin logs in through the ui front door
//!    and PUTs the provider config (with a known `client_secret`)
//!    through the `/api/v1` proxy, then the FAILED attempt probes the
//!    config test route with the secret and an unreachable discovery
//!    URL (the discovery failure path carries the typed secret in
//!    flight). The secret is a needle.
//!
//! The typed database password is set by the fixture in SCRAM-VERIFIER
//! form (never plaintext in any ALTER) to a value distinct from the
//! shared role's bootstrap password: the bootstrap value IS the public
//! role name, and a needle that doubles as a role name would collide
//! with ordinary log content (`user=wardstone`) by construction — a
//! degenerate collision, not a leak.
//!
//! The suite is a ROTATING suite (binding DB-gated conventions): the
//! process-local tokio-mutex fence before the fixture connect, the
//! dedicated pre-rotation connection for the restore, the role restored
//! before any post-rotation read, the panic-safe Drop net, and the
//! SCRAM-verifier restore statement. Rows are swept (FK order) before
//! and after the test; the suite's advisory key is `0x0057_4144_5354_0020`
//! (the "WARDST" family; never shared with another suite).

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex as TokioMutex;
use ws_core::crypto::{
    KeyEnvelope, DB_CREDENTIAL_ENVELOPE_FILE, JWT_ENVELOPE_FILE, MASTER_ENVELOPE_FILE,
    SECRET_ENVELOPE_FILE,
};

/// Postgres advisory-lock key for this suite: ASCII "WARDST"
/// (0x5741445354) plus the suite marker 0x0020.
const ADVISORY_KEY: i64 = 0x0057_4144_5354_0020;

/// The tenant setup creates (ws-web's `setup::DEFAULT_TENANT_NAME`).
const DEFAULT_TENANT: &str = "default";

/// The first-run boot's log line (the boot rule's unsealed arm).
const SETUP_PAGE_LOG: &str = "no master envelope: serving the first-run setup page";

/// The sealed front door's boot log line.
const SEALED_DOOR_LOG: &str = "serving the sealed front door";

/// The sealed api's boot log line.
const API_SEALED_LOG: &str = "serving the sealed REST API";

/// The volume's master passphrase for the first half of the flow. It
/// stays a needle after the change: a dead passphrase is still secret.
const PASSPHRASE_1: &str = "the-master-passphrase";

/// The passphrase the change converges the volume onto (the completion
/// unlock's `next_passphrase`).
const PASSPHRASE_2: &str = "the-rotated-master-passphrase";

/// The setup form's admin password (stored as an argon2id hash).
const ADMIN_PASSWORD: &str = "task11 admin horse staple correct";

/// The typed database password the setup POST connects with. The
/// fixture sets the shared role's password to THIS value in verifier
/// form before the children boot (see the module docs: the bootstrap
/// password doubles as the public role name and would be a degenerate
/// needle collision).
const TYPED_DB_PASSWORD: &str = "task11-typed-db-password-9c31af";

/// The fixed 16-byte salt the typed password's verifier is built with
/// (deterministic like the restore's `FIXED_TEST_SALT`).
const TYPED_PASSWORD_SALT: [u8; 16] = *b"task11-salt-16b!";

/// The failed setup attempt's WRONG typed database password: submitted
/// material must never come back out either, so it joins the needles.
const WRONG_DB_PASSWORD: &str = "task11-wrong-typed-db-password";

/// The failed unlock attempt's WRONG master passphrase: same rule — an
/// error path that echoes what was submitted leaks a future-correct
/// passphrase.
const WRONG_PASSPHRASE: &str = "task11-wrong-master-passphrase";

/// The OIDC provider config's known client secret.
const OIDC_CLIENT_SECRET: &str = "task11-oidc-client-secret-77bd2e";

/// The failed OIDC probe's unreachable discovery URL (connection
/// refused, fast, and `https` — the wire shape's requirement).
const UNREACHABLE_DISCOVERY_URL: &str = "https://127.0.0.1:9/.well-known/openid-configuration";

/// The setup form's default domain and the server hostname (the CA-
/// issued leaf's SAN; must fall under the domain).
const DEFAULT_DOMAIN: &str = "wardstone.example";
const SERVER_HOSTNAME: &str = "ui.wardstone.example";

/// How long a boot may take to log its decision (migrations included).
const BOOT_WAIT: Duration = Duration::from_secs(60);

/// The children's tracing level for this suite: EVERYTHING, by the
/// brief's contract ("no needle ... in any log line at any level").
const RUST_LOG: &str = "trace";

static DB_TEST_LOCK: OnceLock<TokioMutex<()>> = OnceLock::new();

#[must_use = "the database lock must stay bound for the whole test body"]
async fn lock_db() -> tokio::sync::MutexGuard<'static, ()> {
    DB_TEST_LOCK
        .get_or_init(|| TokioMutex::new(()))
        .lock()
        .await
}

/// Test database URL; `DATABASE_URL` overrides it.
fn database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://wardstone:wardstone@localhost:5432/wardstone_test".to_string()
    })
}

/// The test process's own connection URL: the database URL with this
/// suite's `application_name` label appended.
fn test_database_url() -> String {
    with_application_name(&database_url(), "wardstone-log-sentinel-test")
}

/// The URL the CHILDREN boot with: the compose contract's password-less
/// socket form (the percent-encoded authority is what sqlx parses).
fn child_database_url() -> String {
    "postgres://wardstone@%2Fvar%2Frun%2Fpostgresql/wardstone_test".to_string()
}

/// Append an `application_name` label to a connection URL (the same
/// splice the binary's boot performs).
fn with_application_name(url: &str, name: &str) -> String {
    if url.contains("application_name=") {
        url.to_owned()
    } else if url.contains('?') {
        format!("{url}&application_name={name}")
    } else {
        format!("{url}?application_name={name}")
    }
}

/// Delete every row a previous run may have left under the default
/// tenant (children first, then the tenant) — boot_test's sweep.
async fn sweep_default_tenant(pool: &PgPool) {
    for statement in [
        "DELETE FROM audit_log WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM service_identity_capabilities WHERE service_identity_id IN \
         (SELECT id FROM service_identities WHERE tenant_id IN \
         (SELECT id FROM tenants WHERE name = $1))",
        "DELETE FROM certificates WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM used_serials WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM one_shot_tokens WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM service_identities WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM profiles WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM cas WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM oidc_config WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM refresh_tokens WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM users WHERE tenant_id IN (SELECT id FROM tenants WHERE name = $1)",
        "DELETE FROM tenants WHERE name = $1",
    ] {
        sqlx::query(statement)
            .bind(DEFAULT_TENANT)
            .execute(pool)
            .await
            .expect("sweep the default tenant's rows");
    }
}

/// A fresh, empty keys directory unique to this test.
fn scratch_keys_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ws-log-sentinel-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the scratch keys dir");
    dir
}

/// A fresh relay directory's socket path, unique to this test. The SAME
/// path is handed to every child across the test's restarts (the api
/// binds it; the ui dials it): the harness never sweeps it — the test
/// owns the directory and removes it at cleanup.
fn scratch_relay_socket(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ws-log-sentinel-relay-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the scratch relay dir");
    dir.join("relay.sock")
}

/// A loopback port nothing is listening on right now.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("reserve a loopback port")
}

/// Block until the child's listener accepts on `port` (the boot log
/// lines are emitted just BEFORE the bind).
fn wait_for_tcp(port: u16) {
    let deadline = Instant::now() + BOOT_WAIT;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the child never bound 127.0.0.1:{port}");
}

/// The TLS probe client: the children serve self-signed certificates —
/// the tests assert behavior, not the certificate chain.
fn tls_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(120))
        .build()
        .expect("build the TLS probe client")
}

async fn https_post_json(port: u16, path: &str, body: serde_json::Value) -> reqwest::Response {
    tls_client()
        .post(format!("https://127.0.0.1:{port}{path}"))
        .json(&body)
        .send()
        .await
        .expect("the JSON POST reaches the child")
}

/// The admin's login through the ui front door (the session relay):
/// returns the raw `Cookie` header value for the session.
async fn https_login(port: u16, username: &str, password: &str) -> String {
    let response = tls_client()
        .post(format!("https://127.0.0.1:{port}/auth/ui/login"))
        .header(
            ws_web::session::CSRF_HEADER_NAME,
            ws_web::session::CSRF_HEADER_VALUE,
        )
        .json(&serde_json::json!({ "username": username, "password": password }))
        .send()
        .await
        .expect("the login POST reaches the ui");
    assert_eq!(
        response.status().as_u16(),
        200,
        "the admin login through the front door succeeds"
    );
    let set_cookie = response
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .expect("the login sets the session cookie")
        .to_str()
        .expect("the cookie value is ASCII")
        .to_owned();
    assert!(
        set_cookie.starts_with(&format!("{}=", ws_web::session::SESSION_COOKIE)),
        "the login sets the session cookie: {set_cookie}"
    );
    set_cookie
        .split(';')
        .next()
        .expect("the cookie pair")
        .to_owned()
}

/// A cookie-carrying JSON request through the ui's `/api/v1` proxy (the
/// CSRF marker the mutating proxied routes demand).
async fn https_with_session(
    port: u16,
    method: reqwest::Method,
    path: &str,
    cookie: &str,
    body: serde_json::Value,
) -> reqwest::Response {
    tls_client()
        .request(method, format!("https://127.0.0.1:{port}{path}"))
        .header(reqwest::header::COOKIE, cookie)
        .header(
            ws_web::session::CSRF_HEADER_NAME,
            ws_web::session::CSRF_HEADER_VALUE,
        )
        .json(&body)
        .send()
        .await
        .expect("the proxied request reaches the ui")
}

/// The fixed 16-byte salt the shared role's restore verifier uses (the
/// binding ruling: no plaintext ALTER on the test side either).
const FIXED_TEST_SALT: [u8; 16] = *b"0123456789abcdef";

/// The shared test role's restore statement: the SCRAM-SHA-256 verifier
/// of the bootstrap password `wardstone` — Postgres stores the verifier
/// as-is and the plaintext behind it logs in.
fn restore_statement() -> String {
    format!(
        "ALTER USER wardstone PASSWORD '{}'",
        ws_core::dbcred::scram_verifier(
            b"wardstone",
            &FIXED_TEST_SALT,
            ws_core::dbcred::SCRAM_ITERATIONS,
        )
    )
}

/// The panic-safe restore net's channels: Drop cannot await, so a
/// worker thread (its own little runtime, its OWN connection made while
/// the shared credential is still valid) performs the ALTER on request.
struct RestoreNet {
    request: mpsc::Sender<()>,
    reply: mpsc::Receiver<()>,
}

/// Spawn the restore net's worker thread. The connection is created
/// immediately; the worker parks on the request channel until the
/// fixture drops.
fn spawn_restore_net(url: &str) -> RestoreNet {
    let (request, rx) = mpsc::channel::<()>();
    let (tx, reply) = mpsc::channel::<()>();
    let url = url.to_owned();
    std::thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };
        let connected: Result<sqlx::PgConnection, sqlx::Error> =
            runtime.block_on(sqlx::Connection::connect(&url));
        let mut conn = match connected {
            Ok(conn) => conn,
            Err(_) => return, // the net is dead; Drop's send no-ops
        };
        if rx.recv().is_err() {
            return;
        }
        runtime.block_on(async {
            let _ = sqlx::query(&restore_statement()).execute(&mut conn).await;
        });
        let _ = tx.send(());
    });
    RestoreNet { request, reply }
}

/// A rotating-suite fixture: the live pool (connected with the bootstrap
/// credential BEFORE anything rotates), the held advisory-lock
/// connection — also the DEDICATED pre-rotation connection the restore
/// runs over — and a fresh keys directory. The fixture ALSO sets the
/// shared role's password to [`TYPED_DB_PASSWORD`] in SCRAM-VERIFIER
/// form: the setup POST's typed field must carry the role's CURRENT
/// password, and the bootstrap value doubles as the public role name
/// (the degenerate collision the module docs explain).
struct Fixture {
    pool: PgPool,
    advisory: PoolConnection<sqlx::Postgres>,
    keys_dir: PathBuf,
    /// Whether a restore already verifiably landed (Drop's net skips).
    role_restored: bool,
    net: RestoreNet,
}

impl Fixture {
    /// Restore the shared login role's password over the dedicated
    /// pre-rotation connection, BEFORE any post-rotation read or
    /// assertion can panic. Idempotent.
    async fn restore_role_password(&mut self) {
        sqlx::query(&restore_statement())
            .execute(&mut *self.advisory)
            .await
            .expect("restore the shared test role's password");
        self.role_restored = true;
    }

    /// Restore the role, sweep this test's rows, release the advisory
    /// lock (the restore comes first: the pool may need a fresh
    /// connection at exactly the moment the password was rotated).
    async fn cleanup(&mut self) {
        self.restore_role_password().await;
        sweep_default_tenant(&self.pool).await;
        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(ADVISORY_KEY)
            .execute(&mut *self.advisory)
            .await
            .expect("release pg_advisory_lock");
    }
}

/// The panic-safe half of the self-cleaning contract: a test unwinding
/// between its rotation and `cleanup()` must not leave the shared role
/// rotated for every later suite.
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.keys_dir);
        if self.role_restored {
            return;
        }
        // The net is one-shot: the request IS the fixture's last word.
        let _ = self.net.request.send(());
        let _ = self.net.reply.recv_timeout(Duration::from_secs(15));
    }
}

/// Build the rotating fixture: net first (its connection is made while
/// the shared credential is still valid), then the labelled pool, then
/// the advisory lock, then the sweep, then the typed-password verifier.
async fn fixture(tag: &str) -> Fixture {
    let url = test_database_url();
    let net = spawn_restore_net(&url);
    let pool = ws_core::db::connect(&url)
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut conn = pool
        .acquire()
        .await
        .expect("acquire the advisory-lock connection");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(ADVISORY_KEY)
        .execute(&mut *conn)
        .await
        .expect("take pg_advisory_lock");
    sweep_default_tenant(&pool).await;
    // The typed database password, in verifier form (never plaintext in
    // any ALTER): the setup POST connects with it exactly once.
    let typed_verifier = ws_core::dbcred::scram_verifier(
        TYPED_DB_PASSWORD.as_bytes(),
        &TYPED_PASSWORD_SALT,
        ws_core::dbcred::SCRAM_ITERATIONS,
    );
    sqlx::query(&format!("ALTER USER wardstone PASSWORD '{typed_verifier}'"))
        .execute(&mut *conn)
        .await
        .expect("set the typed database password in verifier form");
    Fixture {
        pool,
        advisory: conn,
        keys_dir: scratch_keys_dir(tag),
        role_restored: false,
        net,
    }
}

/// The merged output of every child this test spawns: each spawned
/// process's stdout AND stderr line-reader appends here, so the
/// captured-output haystack is complete without any drain discipline.
type OutputLog = Arc<Mutex<String>>;

/// A running `wardstone` child. The boot_test harness's shape, with two
/// differences this suite needs: the tracing level is a parameter
/// (this suite runs at trace), and `Drop` only kills the child — the
/// relay socket's directory is SHARED across the test's restarts and
/// both children, so the harness never sweeps it (the test owns it).
struct Boot {
    child: Child,
    bind_port: u16,
}

impl Boot {
    #[allow(clippy::too_many_arguments)]
    fn start(
        mode: &str,
        keys_dir: &Path,
        db_url: &str,
        bind_port: u16,
        api_url: Option<String>,
        relay_socket: PathBuf,
        rust_log: &str,
        output: &OutputLog,
    ) -> Boot {
        if let Some(parent) = relay_socket.parent() {
            std::fs::create_dir_all(parent).expect("create the relay socket's directory");
        }
        let mut command = Command::new(env!("CARGO_BIN_EXE_wardstone"));
        command
            .arg(mode)
            .env("DATABASE_URL", db_url)
            .env("WARDSTONE_KEYS_DIR", keys_dir)
            .env("WARDSTONE_RELAY_SOCKET", &relay_socket)
            .env("WARDSTONE_BIND", format!("127.0.0.1:{bind_port}"))
            .env("RUST_LOG", rust_log)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(api_url) = api_url {
            command.env("WARDSTONE_API_URL", api_url);
        }
        let mut child = command.spawn().expect("spawn the wardstone child");
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        for stream in [
            Box::new(stdout) as Box<dyn std::io::Read + Send>,
            Box::new(stderr),
        ] {
            let output = output.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    let mut sink = output.lock().expect("the output accumulator");
                    sink.push_str(&line);
                    sink.push('\n');
                }
            });
        }
        Boot { child, bind_port }
    }

    /// The ui child (the TLS front door).
    fn ui(
        keys_dir: &Path,
        api_url: Option<String>,
        relay_socket: PathBuf,
        output: &OutputLog,
    ) -> Boot {
        Boot::start(
            "ui",
            keys_dir,
            &child_database_url(),
            free_port(),
            api_url,
            relay_socket,
            RUST_LOG,
            output,
        )
    }

    /// The api child (the sealed REST surface + the relay socket). The
    /// bind port is EXPLICIT: the recovery-phase ui boots BEFORE the
    /// api that rejoins later, and its `/api/v1` proxy must point at
    /// the port that api will take.
    fn api(keys_dir: &Path, bind_port: u16, relay_socket: PathBuf, output: &OutputLog) -> Boot {
        Boot::start(
            "api",
            keys_dir,
            &child_database_url(),
            bind_port,
            None,
            relay_socket,
            RUST_LOG,
            output,
        )
    }

    /// The port the child's listener binds.
    fn port(&self) -> u16 {
        self.bind_port
    }

    /// The accumulated output once it contains any of `markers`, or
    /// everything seen when [`BOOT_WAIT`] runs out first.
    fn output_until(&self, markers: &[&str], output: &OutputLog) -> String {
        let deadline = Instant::now() + BOOT_WAIT;
        while Instant::now() < deadline {
            {
                let sink = output.lock().expect("the output accumulator");
                if markers.iter().any(|marker| sink.contains(marker)) {
                    return sink.clone();
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        output.lock().expect("the output accumulator").clone()
    }

    /// The exit status once the process ends, or `None` if it is still
    /// running after [`BOOT_WAIT`].
    #[allow(dead_code)] // the harness keeps the full boot_test surface
    fn wait_exit(&mut self) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + BOOT_WAIT;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().expect("poll the child process") {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        None
    }

    /// Is the child still running?
    #[allow(dead_code)] // the harness keeps the full boot_test surface
    fn is_alive(&mut self) -> bool {
        self.child
            .try_wait()
            .expect("poll the child process")
            .is_none()
    }
}

impl Drop for Boot {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// The scanner — IDENTICAL in both Task 11 suites (the brief's contract:
// one helper module or a duplicated-but-identical one; the suites are
// separate files with separate advisory keys).
// ---------------------------------------------------------------------------

/// The form names, in the order [`needle_forms`] builds them.
const FORM_NAMES: [&str; 4] = ["raw", "hex", "base64", "pem body"];

/// One needle: its name and the byte patterns to hunt for.
struct Needle {
    name: &'static str,
    forms: Vec<Vec<u8>>,
}

/// The naive substring search the scanner runs (the haystacks are small;
/// no smarter algorithm is warranted).
fn find_form(haystack: &[u8], form: &[u8]) -> Option<usize> {
    if form.is_empty() || haystack.len() < form.len() {
        return None;
    }
    haystack
        .windows(form.len())
        .position(|window| window == form)
}

/// The lowercase hex form of `bytes`.
fn hex_form(bytes: &[u8]) -> Vec<u8> {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out.into_bytes()
}

/// The standard base64 form of `bytes`.
fn base64_form(bytes: &[u8]) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    B64.encode(bytes).into_bytes()
}

/// The PEM-body form of `bytes`: the base64 body an armored PEM carries,
/// wrapped at the conventional 64 columns with the armor stripped.
fn pem_body_form(bytes: &[u8]) -> Vec<u8> {
    let body = String::from_utf8(base64_form(bytes)).expect("base64 is ASCII");
    let mut out = String::with_capacity(body.len() + body.len() / 64 + 8);
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.into_bytes()
}

/// Every form a needle is searched in: the raw bytes, the lowercase hex,
/// the single-line base64, and the wrapped PEM body. Encoded-at-rest
/// leaks are caught by these forms, so haystacks are searched raw.
fn needle_forms(raw: &[u8]) -> Vec<Vec<u8>> {
    let mut forms = Vec::with_capacity(FORM_NAMES.len());
    forms.push(raw.to_vec());
    forms.push(hex_form(raw));
    forms.push(base64_form(raw));
    forms.push(pem_body_form(raw));
    forms
}

/// Build one named needle from its raw value.
fn make_needle(name: &'static str, raw: &[u8]) -> Needle {
    Needle {
        name,
        forms: needle_forms(raw),
    }
}

/// Add a needle, deduplicating by value: the same value already hunts
/// under an earlier name (every rotated credential is opened right after
/// its rotation, so a value unchanged by a later event is not re-added).
fn add_needle(needles: &mut Vec<Needle>, name: &'static str, raw: &[u8]) {
    if needles.iter().any(|needle| {
        needle
            .forms
            .first()
            .is_some_and(|form| form.as_slice() == raw)
    }) {
        return;
    }
    needles.push(make_needle(name, raw));
}

/// A lossy ±48-byte window around a hit, for the failure's context.
fn context_window(haystack: &[u8], offset: usize) -> String {
    let start = offset.saturating_sub(48);
    let end = (offset + 48).min(haystack.len());
    String::from_utf8_lossy(&haystack[start..end]).into_owned()
}

/// Scan one named haystack: every form of every needle must be absent.
/// A hit panics with the needle's name, the form, the haystack, the
/// offset, and the surrounding context — the report's defect record.
fn scan_haystack(haystack_name: &str, haystack: &[u8], needles: &[Needle]) {
    for needle in needles {
        for (index, form) in needle.forms.iter().enumerate() {
            if let Some(offset) = find_form(haystack, form) {
                panic!(
                    "needle {:?} ({}) hit haystack {:?} at offset {offset} — context: {:?}",
                    needle.name,
                    FORM_NAMES[index],
                    haystack_name,
                    context_window(haystack, offset),
                );
            }
        }
    }
}

/// The SCRAM-VERIFIER prefixes: a verifier string always begins
/// `scram-sha-256$<iterations>:...` (Postgres stores it lowercase; both
/// spellings are hunted). The bare method name carries no `$` — only a
/// verifier does.
const SCRAM_VERIFIER_PREFIXES: [&str; 2] = ["SCRAM-SHA-256$", "scram-sha-256$"];

/// The verifier-class sentinel: the rotations mint their SCRAM verifiers
/// with random salts, so no needle can hunt them by value — the prefix
/// hunts the class (the Global Constraint: no verifier in any log line
/// at any level). A hit is a leak in an earlier task, reported the same
/// way a needle hit is.
fn scan_for_verifier_leaks(haystack_name: &str, haystack: &[u8]) {
    for prefix in SCRAM_VERIFIER_PREFIXES {
        if let Some(offset) = find_form(haystack, prefix.as_bytes()) {
            panic!(
                "a SCRAM verifier hit haystack {haystack_name:?} at offset {offset} \
                 — context: {:?}",
                context_window(haystack, offset),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The non-vacuousness arm (this task's RED discipline)
// ---------------------------------------------------------------------------

/// A scanner that cannot find anything proves nothing. This fast,
/// DB-free arm plants EVERY needle form — raw, hex, base64, PEM body —
/// in its own scratch haystack (built here from first principles, NOT
/// via [`needle_forms`], so an incomplete scanner cannot pass by agreeing
/// with itself) and asserts the scanner flags each one, plus the
/// negative: a clean haystack passes untouched.
#[test]
fn scanner_flags_every_planted_needle_form() {
    let secret = b"task11 scanner non-vacuousness secret 5d0c8e";
    // The four canonical forms, built from first principles here — NOT
    // via `needle_forms` — so an incomplete scanner cannot pass by
    // agreeing with itself.
    let mut hex = String::new();
    for byte in secret {
        hex.push_str(&format!("{byte:02x}"));
    }
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let single_line = B64.encode(secret);
    let mut wrapped = String::new();
    for chunk in single_line.as_bytes().chunks(64) {
        wrapped.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        wrapped.push('\n');
    }
    let planted = [
        secret.to_vec(),
        hex.into_bytes(),
        single_line.into_bytes(),
        wrapped.into_bytes(),
    ];
    // The scanner must hunt in every form: its needle carries four
    // forms, and each canonical form — planted in a scratch haystack on
    // its own, so one form cannot mask another — is matched by one of
    // them.
    let needle = make_needle("the arm's secret", secret);
    assert_eq!(
        needle.forms.len(),
        FORM_NAMES.len(),
        "the scanner must build every needle form"
    );
    for (index, form) in planted.iter().enumerate() {
        let mut haystack = b"prefix-bytes-then-the-planted-form:".to_vec();
        haystack.extend_from_slice(form);
        haystack.extend_from_slice(b":suffix-bytes");
        let flagged = needle
            .forms
            .iter()
            .any(|candidate| find_form(&haystack, candidate).is_some());
        assert!(
            flagged,
            "the scanner must flag the {} form of a planted needle",
            FORM_NAMES[index]
        );
    }
    // The negative leg: a clean haystack passes untouched.
    let clean = b"nothing secret lives here: only ordinary fixture words";
    scan_haystack(
        "the clean scratch haystack",
        clean,
        &[make_needle("the arm's secret", secret)],
    );
}

// ---------------------------------------------------------------------------
// The log sentinel itself
// ---------------------------------------------------------------------------

/// Open the current sealed database credential with `passphrase` — the
/// brief's needle-source rule: the same production open the api's
/// unlock builder performs (`open_db_credential`'s `current` value).
fn open_db_credential_value(keys_dir: &Path, passphrase: &str) -> String {
    let candidates = ws_core::dbcred::open_db_credential(
        &keys_dir.join(DB_CREDENTIAL_ENVELOPE_FILE),
        passphrase.as_bytes(),
    )
    .expect("open the db credential envelope");
    String::from_utf8_lossy(&candidates.current).into_owned()
}

/// The setup POST's body (the `SetupFields` wire shape).
fn setup_body(db_password: &str) -> serde_json::Value {
    serde_json::json!({
        "admin_username": "admin",
        "admin_password": ADMIN_PASSWORD,
        "default_domain": DEFAULT_DOMAIN,
        "admin_cidrs": ["127.0.0.0/8"],
        "server_hostname": SERVER_HOSTNAME,
        "db_password": db_password,
        "master_passphrase": PASSPHRASE_1,
        "master_passphrase_confirm": PASSPHRASE_1,
    })
}

/// THE log sentinel: the full lifecycle plus the failed attempts, at
/// `RUST_LOG=trace`, and no needle — nor any SCRAM verifier — anywhere
/// in the captured output of either child.
#[tokio::test]
#[ignore = "requires a live Postgres at DATABASE_URL"]
async fn no_secret_appears_in_process_output() {
    let _guard = lock_db().await;
    let mut fx = fixture("log-sentinel").await;
    let relay = scratch_relay_socket("log-sentinel");
    let output: OutputLog = Arc::new(Mutex::new(String::new()));
    let mut needles: Vec<Needle> = Vec::new();

    // -- Phase 1: the first-run setup (no api child yet — see the module
    //    docs: the api joins at the unlock, so the conversion's fresh
    //    credential is observable before its superseding rotation) ----
    let ui1 = Boot::ui(&fx.keys_dir, None, relay.clone(), &output);
    let boot_out = ui1.output_until(&[SETUP_PAGE_LOG], &output);
    wait_for_tcp(ui1.port());
    assert!(
        boot_out.contains(SETUP_PAGE_LOG),
        "the first-run boot serves the setup page, got:\n{boot_out}"
    );
    // The failed attempt: a WRONG typed database password, rejected by
    // the database (28P01 → the page's 400). The submitted value joins
    // the needles: an error path that echoes it is a leak.
    let wrong_setup = https_post_json(ui1.port(), "/setup", setup_body(WRONG_DB_PASSWORD)).await;
    assert_eq!(
        wrong_setup.status().as_u16(),
        400,
        "the setup page rejects a wrong typed database password"
    );
    let setup = https_post_json(ui1.port(), "/setup", setup_body(TYPED_DB_PASSWORD)).await;
    assert_eq!(
        setup.status().as_u16(),
        200,
        "the setup POST completes the seal-at-creation bootstrap"
    );
    add_needle(
        &mut needles,
        "the master passphrase",
        PASSPHRASE_1.as_bytes(),
    );
    add_needle(
        &mut needles,
        "the admin password",
        ADMIN_PASSWORD.as_bytes(),
    );
    add_needle(
        &mut needles,
        "the rejected typed database password",
        WRONG_DB_PASSWORD.as_bytes(),
    );
    add_needle(
        &mut needles,
        "the typed database password",
        TYPED_DB_PASSWORD.as_bytes(),
    );
    add_needle(
        &mut needles,
        "the setup-conversion database credential",
        open_db_credential_value(&fx.keys_dir, PASSPHRASE_1).as_bytes(),
    );
    // The static keys, opened exactly the way the production opens do:
    // the master via `open_envelope`, the secret via `open_envelope`,
    // the JWT pair via `load_sealed` (its signing half is the DER), and
    // the CA/leaf keys via the master → keystore → `unwrap_ca_key` chain.
    let master_key =
        KeyEnvelope::open_envelope(&fx.keys_dir.join(MASTER_ENVELOPE_FILE), PASSPHRASE_1)
            .expect("open the master envelope");
    let secret_key =
        KeyEnvelope::open_envelope(&fx.keys_dir.join(SECRET_ENVELOPE_FILE), PASSPHRASE_1)
            .expect("open the secret-encryption envelope");
    let jwt_pair = ws_auth::jwt::load_sealed(
        &fx.keys_dir.join(JWT_ENVELOPE_FILE),
        PASSPHRASE_1.as_bytes(),
    )
    .expect("open the sealed JWT pair");
    add_needle(&mut needles, "the master key", &master_key[..]);
    add_needle(&mut needles, "the secret-encryption key", &secret_key[..]);
    add_needle(
        &mut needles,
        "the JWT signing key (DER)",
        &jwt_pair.signing_key[..],
    );
    let ca_id: uuid::Uuid = sqlx::query_scalar(
        "SELECT id FROM cas WHERE is_root \
         AND tenant_id = (SELECT id FROM tenants WHERE name = $1)",
    )
    .bind(DEFAULT_TENANT)
    .fetch_one(&fx.pool)
    .await
    .expect("the root CA row");
    let leaf_id: uuid::Uuid = sqlx::query_scalar(
        "SELECT c.id FROM certificates c \
         JOIN tenants t ON t.id = c.tenant_id \
         WHERE t.name = $1 AND c.profile_name = 'web-server' AND c.status = 'active'",
    )
    .bind(DEFAULT_TENANT)
    .fetch_one(&fx.pool)
    .await
    .expect("the active serving-leaf row");
    let mem = ws_secmem::global().expect("the protected arena");
    let master_buf = mem
        .alloc_copy(&master_key[..])
        .expect("copy the master key into the protected arena");
    let keystore = ws_ca::keystore::KeyStore::open_unlocked(&fx.keys_dir, master_buf)
        .expect("open the unlocked keystore");
    let ca_key = keystore
        .unwrap_ca_key(&ca_id)
        .expect("unwrap the root CA key");
    let leaf_key = keystore
        .unwrap_ca_key(&leaf_id)
        .expect("unwrap the serving-leaf key");
    add_needle(&mut needles, "the root CA private key (DER)", &ca_key[..]);
    add_needle(
        &mut needles,
        "the serving-leaf private key (DER)",
        &leaf_key[..],
    );

    // -- Phase 2: the api child joins (sealed) --------------------------------
    let api1 = Boot::api(&fx.keys_dir, free_port(), relay.clone(), &output);
    let api_boot = api1.output_until(&[API_SEALED_LOG], &output);
    wait_for_tcp(api1.port());
    assert!(
        api_boot.contains(API_SEALED_LOG),
        "the api child boots its sealed shell, got:\n{api_boot}"
    );
    let api_url = format!("http://127.0.0.1:{}", api1.port());

    // -- Phase 3: the unlock (the ui restarts onto the sealed door; the
    //    unlock POST relays the api up, whose per-unlock rotation the
    //    open below collects) --------------------------------------------------
    drop(ui1);
    let ui2 = Boot::ui(&fx.keys_dir, Some(api_url.clone()), relay.clone(), &output);
    let door = ui2.output_until(&[SEALED_DOOR_LOG], &output);
    wait_for_tcp(ui2.port());
    assert!(
        door.contains(SEALED_DOOR_LOG),
        "the ui restart boots the sealed door, got:\n{door}"
    );
    // The failed attempt: a WRONG master passphrase, rejected by the
    // envelope open (401). The submitted value joins the needles.
    let wrong_unlock = https_post_json(
        ui2.port(),
        "/unlock",
        serde_json::json!({ "passphrase": WRONG_PASSPHRASE }),
    )
    .await;
    assert_eq!(
        wrong_unlock.status().as_u16(),
        401,
        "the unlock page rejects a wrong master passphrase"
    );
    add_needle(
        &mut needles,
        "the rejected master passphrase",
        WRONG_PASSPHRASE.as_bytes(),
    );
    let unlock = https_post_json(
        ui2.port(),
        "/unlock",
        serde_json::json!({ "passphrase": PASSPHRASE_1 }),
    )
    .await;
    assert_eq!(
        unlock.status().as_u16(),
        200,
        "the unlock POST unlocks against the live api"
    );
    add_needle(
        &mut needles,
        "the api-unlock database credential",
        open_db_credential_value(&fx.keys_dir, PASSPHRASE_1).as_bytes(),
    );

    // -- Phase 4: the passphrase change (the mixed-volume completion) ----------
    drop(ui2);
    let (_, params, _) = KeyEnvelope::read_kdf_state(&fx.keys_dir.join(SECRET_ENVELOPE_FILE))
        .expect("read the secret envelope's KDF state");
    let master_generation = KeyEnvelope::read_generation(&fx.keys_dir.join(MASTER_ENVELOPE_FILE))
        .expect("read the master envelope's generation");
    KeyEnvelope::write_envelope(
        &fx.keys_dir.join(SECRET_ENVELOPE_FILE),
        PASSPHRASE_2,
        &secret_key[..],
        params,
        master_generation + 1,
    )
    .expect("hand-mix the volume (the crashed-change shape)");
    let ui3 = Boot::ui(&fx.keys_dir, Some(api_url), relay.clone(), &output);
    ui3.output_until(&[SEALED_DOOR_LOG], &output);
    wait_for_tcp(ui3.port());
    let completion = https_post_json(
        ui3.port(),
        "/unlock",
        serde_json::json!({
            "passphrase": PASSPHRASE_1,
            "next_passphrase": PASSPHRASE_2,
        }),
    )
    .await;
    assert_eq!(
        completion.status().as_u16(),
        200,
        "the completion unlock converges the mixed volume"
    );
    add_needle(
        &mut needles,
        "the completed-change master passphrase",
        PASSPHRASE_2.as_bytes(),
    );
    // After every rotation event: open the envelope (the effective
    // passphrase is the new one from here on).
    add_needle(
        &mut needles,
        "the post-change database credential",
        open_db_credential_value(&fx.keys_dir, PASSPHRASE_2).as_bytes(),
    );

    // -- Phase 5: the rotation (the D5 recovery runbook) ------------------------
    drop(ui3);
    drop(api1);
    // The api that rejoins after the recovery takes a RESERVED port:
    // the recovery ui must already point its `/api/v1` proxy at it (the
    // OIDC phase rides that proxy) even though it boots before the api.
    let api2_port = free_port();
    let api2_url = format!("http://127.0.0.1:{api2_port}");
    let typed_recovery = open_db_credential_value(&fx.keys_dir, PASSPHRASE_2);
    std::fs::remove_file(fx.keys_dir.join(DB_CREDENTIAL_ENVELOPE_FILE))
        .expect("remove the db-credential envelope (the recovery runbook)");
    let ui4 = Boot::ui(&fx.keys_dir, Some(api2_url), relay.clone(), &output);
    ui4.output_until(&[SEALED_DOOR_LOG], &output);
    wait_for_tcp(ui4.port());
    let recovery = https_post_json(
        ui4.port(),
        "/unlock",
        serde_json::json!({
            "passphrase": PASSPHRASE_2,
            "db_password": typed_recovery,
        }),
    )
    .await;
    assert_eq!(
        recovery.status().as_u16(),
        200,
        "the recovery unlock re-seals the credential with the typed password"
    );
    add_needle(
        &mut needles,
        "the recovery database credential",
        open_db_credential_value(&fx.keys_dir, PASSPHRASE_2).as_bytes(),
    );

    // -- Phase 6: the api rejoins and is unlocked through the production
    //    relay (its own rotation collected) -------------------------------------
    let api2 = Boot::api(&fx.keys_dir, api2_port, relay.clone(), &output);
    let api_boot = api2.output_until(&[API_SEALED_LOG], &output);
    wait_for_tcp(api2.port());
    assert!(
        api_boot.contains(API_SEALED_LOG),
        "the restarted api boots its sealed shell, got:\n{api_boot}"
    );
    ws_web::locked::relay_unlock(&relay, PASSPHRASE_2)
        .await
        .expect("the api's unlock relay lands");
    add_needle(
        &mut needles,
        "the api re-unlock database credential",
        open_db_credential_value(&fx.keys_dir, PASSPHRASE_2).as_bytes(),
    );
    let api_health: serde_json::Value = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/api/v1/healthz", api2.port()))
        .send()
        .await
        .expect("the api healthz answers")
        .json()
        .await
        .expect("the api healthz is JSON");
    assert_eq!(
        api_health["state"], "unlocked",
        "the restarted api is unlocked through the relay"
    );

    // -- Phase 7: the OIDC configuration (the ui front door + proxy) ----------
    let cookie = https_login(ui4.port(), "admin", ADMIN_PASSWORD).await;
    let oidc_put = https_with_session(
        ui4.port(),
        reqwest::Method::PUT,
        "/api/v1/oidc/config",
        &cookie,
        serde_json::json!({
            "provider_type": "custom",
            "display_name": "Task 11 house provider",
            "discovery_url": "https://oidc.wardstone.example/.well-known/openid-configuration",
            "client_id": "wardstone-task11",
            "client_secret": OIDC_CLIENT_SECRET,
            "redirect_uri": format!("https://{SERVER_HOSTNAME}/auth/ui/oidc/custom/callback"),
            "scopes": "openid profile email",
        }),
    )
    .await;
    assert_eq!(
        oidc_put.status().as_u16(),
        200,
        "the OIDC provider config seeds through the proxied PUT"
    );
    let oidc_body: serde_json::Value = oidc_put.json().await.expect("the PUT body is JSON");
    assert_eq!(
        oidc_body["client_secret_set"], true,
        "the read shape reports the stored secret"
    );
    assert!(
        oidc_body.get("client_secret").is_none(),
        "the secret never leaves the server: {oidc_body}"
    );
    add_needle(
        &mut needles,
        "the OIDC client secret",
        OIDC_CLIENT_SECRET.as_bytes(),
    );
    // The failed attempt: the config test route probes the (unreachable)
    // discovery URL with the typed secret in flight — the discovery
    // failure path must report the error without the material.
    let bad_probe = https_with_session(
        ui4.port(),
        reqwest::Method::POST,
        "/api/v1/oidc/config/test",
        &cookie,
        serde_json::json!({
            "override": {
                "provider_type": "custom",
                "display_name": "Task 11 house provider",
                "discovery_url": UNREACHABLE_DISCOVERY_URL,
                "client_id": "wardstone-task11",
                "client_secret": OIDC_CLIENT_SECRET,
                "redirect_uri": format!("https://{SERVER_HOSTNAME}/auth/ui/oidc/custom/callback"),
                "scopes": "openid profile email",
            }
        }),
    )
    .await;
    assert_eq!(
        bad_probe.status().as_u16(),
        400,
        "the unreachable discovery probe reports a failure"
    );

    // -- Phase 8: stop the children, let the readers flush, capture ------------
    drop(ui4);
    drop(api2);
    std::thread::sleep(Duration::from_millis(500));
    let captured = output.lock().expect("the output accumulator").clone();

    // -- Phase 9: the haystack — the captured output itself ---------------------
    scan_haystack(
        "the children's captured output",
        captured.as_bytes(),
        &needles,
    );
    // The verifier class (see the module docs): no SCRAM verifier in
    // any log line at any level.
    scan_for_verifier_leaks("the children's captured output", captured.as_bytes());

    // -- Cleanup ----------------------------------------------------------------
    fx.cleanup().await;
    let _ = std::fs::remove_dir_all(
        relay
            .parent()
            .expect("the relay socket has a parent directory"),
    );
}
