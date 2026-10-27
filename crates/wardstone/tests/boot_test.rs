//! The `wardstone` boot decision against a live database (and, for the
//! sealed volume, over the children's real TLS listeners): the built
//! binary (`CARGO_BIN_EXE_wardstone`) runs with a scratch keys
//! directory, and the tests read which front door it chose from its log
//! lines — the sealed cases also drive the real unlock POST over TLS.
//!
//! The boot rule (seal-at-creation): `master.envelope` absent → the
//! first-run setup page on the RAM-only certificate with NO database
//! connection (the closed-port case pins that absence); present → the
//! locked page, and the unlock resolves the tenant + the serving leaf
//! BEFORE the api relay and then releases its pool — the api's relayed
//! unlock rotates the database credential, so any fresh ui connection
//! after the relay fails `28P01` (Review Focus 1). A sealed volume
//! whose database holds no default tenant is the torn state of a setup
//! that crashed after sealing, and the two recovery shapes are pinned
//! separately: the bundled volume WITHOUT a `db-credential.envelope`
//! heals only through the re-armed peer door (a closed door refuses
//! with the runbook's re-arm copy and the process stays alive and
//! sealed), while the volume WITH the envelope connects as the sealed
//! credential, finds no tenant, and the process EXITS non-zero with
//! the spec's exact refusal copy.
//!
//! Every database-backed test sweeps the default tenant before and after
//! its body and holds a session-level advisory lock on [`ADVISORY_KEY`] (the
//! "WARDST" family with this suite's marker 0x0017) plus the
//! in-process mutex for the harness's threads. The cases that rotate
//! the shared login role (the torn state's recovery and the api's
//! per-unlock rotation) fence on that mutex BEFORE the fixture's
//! connect, restore the role over the fixture's DEDICATED pre-rotation
//! connection before any post-rotation read, and carry the panic-safe
//! Drop restore net (`ws-api tests/sealed_test.rs` is the reference).
//! The first-run and password-refusal cases need no live database;
//! they ride the same battery because they drive the same binary.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex as TokioMutex;
use ws_core::crypto::{
    DB_CREDENTIAL_ENVELOPE_FILE, JWT_ENVELOPE_FILE, MASTER_ENVELOPE_FILE, SECRET_ENVELOPE_FILE,
};

/// Postgres advisory-lock key for this suite: ASCII "WARDST" (0x5741445354)
/// plus the suite marker 0x0017.
const ADVISORY_KEY: i64 = 0x0057_4144_5354_0017;

/// The tenant setup creates (ws-web's `setup::DEFAULT_TENANT_NAME`).
const DEFAULT_TENANT: &str = "default";

/// The first-run boot's log line (the boot rule's unsealed arm).
const SETUP_PAGE_LOG: &str = "no master envelope: serving the first-run setup page";

/// The sealed front door's boot log line.
const SEALED_DOOR_LOG: &str = "serving the sealed front door";

/// The sealed api's boot log line.
const API_SEALED_LOG: &str = "serving the sealed REST API";

/// The torn-state refusal (spec's exact copy): a sealed volume whose
/// database holds no default tenant is an interrupted setup.
const TORN_REFUSAL: &str =
    "setup was interrupted after sealing — remove both volumes and run setup again";

/// The ui's password-URL refusal (Review Focus 5, the spec's exact copy).
const UI_PASSWORD_REFUSAL: &str = "DATABASE_URL carries a password; Wardstone reads the database credential only from its sealed envelope or the setup page";

/// The stale-variable refusal (the plan's pinned copy): an upgraded old
/// bundle may still carry `WARDSTONE_DB_PASSWORD`, but the bundled
/// database has no password at all.
const STALE_DB_PASSWORD_REFUSAL: &str = "WARDSTONE_DB_PASSWORD is obsolete in the bundled deployment — the bundled database has no password (setup takes over the role through the peer-authenticated door); delete the variable from .env and run again";

/// The bundled heal's pinned lede: the unlock page names the peer door
/// (never a typed database password) when a bundled volume holds no
/// db-credential envelope.
const BUNDLED_HEAL_LEDE: &str =
    "The keys volume holds no sealed database credential — the bundled \
 recovery runbook. Run its re-arm step (docker/README.md), then enter the \
 master passphrase: the instance re-seals the credential itself through the \
 setup door and closes it again.";

/// The bundled heal's door-closed refusal, as the build surfaces it:
/// `SetupError::HealDoorClosed`'s pinned copy wrapped in the build's
/// `the db re-seal:` prefix — the words the unlock POST's answer
/// carries.
const HEAL_DOOR_REFUSAL: &str = "the db re-seal: the database's setup door is closed: run the \
 bundled recovery runbook's re-arm step (docker/README.md) and unlock again";

/// The master passphrase the hand-minted envelopes seal under.
const PASSPHRASE: &str = "the-master-passphrase";

/// How long a boot may take to log its decision (migrations included).
const BOOT_WAIT: Duration = Duration::from_secs(60);

static DB_TEST_LOCK: OnceLock<TokioMutex<()>> = OnceLock::new();

#[must_use = "the database lock must stay bound for the whole test body"]
async fn lock_db() -> tokio::sync::MutexGuard<'static, ()> {
    DB_TEST_LOCK
        .get_or_init(|| TokioMutex::new(()))
        .lock()
        .await
}

/// Test database URL; `DATABASE_URL` overrides it. This is the TEST
/// process's own URL — it carries the compose credential and the
/// `wardstone-boot-test` application label (the terminate sweep below
/// spares exactly the labelled connections, so the fixture's own
/// backends can never be caught by it).
fn database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://wardstone:wardstone@localhost:5432/wardstone_test".to_string()
    })
}

/// The test process's own connection URL: the database URL with this
/// suite's `application_name` label appended.
fn test_database_url() -> String {
    with_application_name(&database_url(), "wardstone-boot-test")
}

/// The URL the CHILDREN boot with: the compose contract's password-less
/// socket form (Task 10, D8) — the ui refuses a password-bearing URL at
/// boot, `check_database_url` refuses the bare TCP form, and the
/// children read their credential from the sealed envelope (or the
/// typed recovery password), never from the URL. The socket rides the
/// authority percent-encoded: sqlx cannot parse the libpq empty-host
/// spelling, and the binary's password splice needs the userinfo.
fn child_database_url() -> String {
    "postgres://wardstone@%2Fvar%2Frun%2Fpostgresql/wardstone_test".to_string()
}

/// Append an `application_name` label to a connection URL (the same
/// splice the binary's boot performs — a query parameter, never the
/// authority).
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
/// tenant (children first, then the tenant) — ws-web setup_test's sweep.
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
    let dir = std::env::temp_dir().join(format!("ws-boot-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the scratch keys dir");
    dir
}

/// A fresh, empty relay directory unique to this test (Task 10, D8):
/// the api child BINDS its relay socket here and the ui child dials it
/// — the dual-process test passes the SAME path to both.
fn scratch_relay_socket(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ws-boot-relay-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the scratch relay dir");
    dir.join("relay.sock")
}

/// Every file name currently in a keys directory (the write-nothing
/// assertions compare against an empty list).
fn keys_dir_entries(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
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

/// The cheap KDF parameters the hand-minted envelopes seal under (the
/// envelope carries its own parameters; the children derive with them).
fn cheap_params() -> ws_core::crypto::KdfParams {
    ws_core::crypto::KdfParams {
        m_cost: 8192,
        t_cost: 2,
        p_cost: 1,
    }
}

/// Mint one envelope under the suite passphrase at generation 0.
fn mint_envelope(path: &Path, payload: &[u8]) {
    ws_core::crypto::KeyEnvelope::write_envelope(path, PASSPHRASE, payload, cheap_params(), 0)
        .expect("mint the envelope");
}

/// The TLS probe client: the children serve self-signed certificates
/// (the RAM-only first-run certificate or the ephemeral sealed one) —
/// the tests assert behavior, not the certificate chain.
fn tls_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(30))
        .build()
        .expect("build the TLS probe client")
}

async fn https_get(port: u16, path: &str) -> reqwest::Result<reqwest::Response> {
    tls_client()
        .get(format!("https://127.0.0.1:{port}{path}"))
        .send()
        .await
}

async fn https_unlock(port: u16, body: serde_json::Value) -> reqwest::Result<reqwest::Response> {
    tls_client()
        .post(format!("https://127.0.0.1:{port}/unlock"))
        .json(&body)
        .send()
        .await
}

/// The fixed 16-byte salt the shared role's restore verifier uses
/// (Task 4's ruling: NO plaintext ALTER on the test side either — the
/// restore sets the verifier form of `wardstone`'s bootstrap password,
/// and a fixed salt keeps that verifier deterministic across every
/// suite that restores the shared role).
const FIXED_TEST_SALT: [u8; 16] = *b"0123456789abcdef";

/// The shared test role's restore statement: the SCRAM-SHA-256
/// verifier of the bootstrap password `wardstone` — Postgres stores
/// the verifier as-is and the plaintext behind it logs in, so every
/// suite's `wardstone:wardstone` connect keeps working.
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
/// the shared credential is still valid — sqlx connections are
/// runtime-affine) performs the ALTER on request. The reference
/// implementation is `ws-api tests/sealed_test.rs`'s `RestoreNet`.
struct RestoreNet {
    /// "please restore" — sent from Drop.
    request: mpsc::Sender<()>,
    /// The worker's reply once the ALTER landed (Drop waits on it).
    reply: mpsc::Receiver<()>,
}

/// Spawn the restore net's worker thread. The connection is created
/// immediately (the shared credential is valid now); the worker then
/// parks on the request channel until the fixture drops.
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

/// A DB-gated fixture for the tests whose child ROTATES the shared
/// login role: the live pool (connected with the bootstrap credential
/// BEFORE any rotation), the held advisory-lock connection — also the
/// DEDICATED pre-rotation connection the restore runs over — and a
/// fresh keys directory.
struct Fixture {
    pool: PgPool,
    advisory: PoolConnection<sqlx::Postgres>,
    keys_dir: PathBuf,
    /// Whether a restore already verifiably landed (Drop's net skips).
    role_restored: bool,
    net: RestoreNet,
}

impl Fixture {
    /// Restore the shared login role's password over the pre-rotation
    /// advisory connection (established connections survive the
    /// rotation), BEFORE any post-rotation read or assertion can
    /// panic. Idempotent.
    async fn restore_role_password(&mut self) {
        sqlx::query(&restore_statement())
            .execute(&mut *self.advisory)
            .await
            .expect("restore the shared test role's password");
        self.role_restored = true;
    }

    /// Restore the role, sweep this test's rows, release the advisory
    /// lock — the binding order puts the restore BEFORE the sweep (the
    /// pool may need a fresh connection at exactly the moment the
    /// password was rotated).
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

/// The panic-safe half of the self-cleaning contract: a test that
/// unwinds between its rotation and `cleanup()` would otherwise leave
/// the shared role rotated, and every later suite fails at its first
/// connect with a misleading `28P01`.
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

/// The rotating fixture: net first (its connection is made while the
/// shared credential is still valid), then the labelled pool, then the
/// advisory lock.
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
    Fixture {
        pool,
        advisory: conn,
        keys_dir: scratch_keys_dir(tag),
        role_restored: false,
        net,
    }
}

/// A running `wardstone` child with its merged output streamed line by
/// line. The children boot with the password-less compose-contract URL
/// (`db_url`) — the ui refuses a password-bearing one — and their
/// listeners bind `127.0.0.1:{bind_port}`.
struct Boot {
    child: Child,
    lines: mpsc::Receiver<String>,
    bind_port: u16,
    /// The relay socket path the child was handed (Drop sweeps its
    /// directory — the api's socket file included).
    relay_socket: PathBuf,
}

impl Boot {
    fn start(
        mode: &str,
        keys_dir: &Path,
        db_url: &str,
        bind_port: u16,
        api_url: Option<String>,
        relay_socket: PathBuf,
        extra_env: &[(String, String)],
    ) -> Boot {
        // The api mode binds the relay socket, so its parent directory
        // must exist by the time the child reaches the bind.
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
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(api_url) = api_url {
            command.env("WARDSTONE_API_URL", api_url);
        }
        // Case-specific environment (the compose-contract knobs a later
        // boot case needs); applied last so an extra entry overrides the
        // stock values above.
        for (name, value) in extra_env {
            command.env(name, value);
        }
        let mut child = command.spawn().expect("spawn the wardstone child");
        let (tx, lines) = mpsc::channel();
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        for stream in [
            Box::new(stdout) as Box<dyn std::io::Read + Send>,
            Box::new(stderr),
        ] {
            let tx = tx.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
        }
        Boot {
            child,
            lines,
            bind_port,
            relay_socket,
        }
    }

    fn ui(
        keys_dir: &Path,
        db_url: &str,
        bind_port: u16,
        api_url: Option<String>,
        relay_socket: PathBuf,
    ) -> Boot {
        Boot::start(
            "ui",
            keys_dir,
            db_url,
            bind_port,
            api_url,
            relay_socket,
            &[],
        )
    }

    fn api(keys_dir: &Path, db_url: &str, bind_port: u16, relay_socket: PathBuf) -> Boot {
        Boot::start("api", keys_dir, db_url, bind_port, None, relay_socket, &[])
    }

    /// The port the child's listener binds.
    fn port(&self) -> u16 {
        self.bind_port
    }

    /// Every line up to and including the first that contains any of
    /// `markers`, or everything seen when [`BOOT_WAIT`] (or the output)
    /// runs out first.
    fn output_until(&self, markers: &[&str]) -> String {
        let deadline = Instant::now() + BOOT_WAIT;
        let mut seen = String::new();
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    let hit = markers.iter().any(|m| line.contains(m));
                    seen.push_str(&line);
                    seen.push('\n');
                    if hit {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        seen
    }

    /// Every line that has arrived so far, without waiting.
    fn drain_output(&self) -> String {
        let mut seen = String::new();
        while let Ok(line) = self.lines.try_recv() {
            seen.push_str(&line);
            seen.push('\n');
        }
        seen
    }

    /// The exit status once the process ends, or `None` if it is still
    /// running after [`BOOT_WAIT`].
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
        if let Some(parent) = self.relay_socket.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}

/// A fresh install before setup: the boot dispatches on the sealed
/// marker alone, so a volume with no `master.envelope` serves the
/// first-run setup page WITHOUT touching the database — the
/// `DATABASE_URL` points at a socket directory that does not exist
/// (the bare-TCP form Task 10's `check_database_url` refuses anyway),
/// and any connect attempt would have failed the boot before the line
/// was logged.
#[tokio::test]
#[ignore = "part of the DB-gated boot battery (--include-ignored)"]
async fn no_master_envelope_serves_setup_without_touching_the_database() {
    let keys = scratch_keys_dir("first-run-no-db");
    let db_url = "postgres://wardstone@%2Frun%2Fwardstone-boot-absent/wardstone_test".to_string();
    let mut boot = Boot::ui(
        &keys,
        &db_url,
        free_port(),
        None,
        scratch_relay_socket("first-run-no-db"),
    );
    let out = boot.output_until(&[SETUP_PAGE_LOG]);
    // "Stays up": the closed port makes any dial fatal, so a live
    // process after the line is proof no dial happened.
    std::thread::sleep(Duration::from_millis(500));
    let alive = boot.is_alive();
    let after = boot.drain_output();
    drop(boot);
    let entries = keys_dir_entries(&keys);
    let _ = std::fs::remove_dir_all(&keys);

    assert!(
        out.contains(SETUP_PAGE_LOG),
        "the closed-port boot serves the first-run setup page, got:\n{out}\n{after}"
    );
    assert!(
        alive,
        "the first-run boot stays up without the database, output so far:\n{out}\n{after}"
    );
    assert!(
        entries.is_empty(),
        "the first-run boot writes nothing to the keys volume, found: {entries:?}"
    );
}

/// A restart before setup: two first-run boots in a row must leave the
/// keys volume empty — the RAM-only certificate leaves no trace, so a
/// restart does not accumulate strays (and never wrote the plaintext
/// keys the pre-seal boot once did).
#[tokio::test]
#[ignore = "part of the DB-gated boot battery (--include-ignored)"]
async fn a_restart_before_setup_writes_nothing() {
    let keys = scratch_keys_dir("restart-nothing");
    let db_url = child_database_url();
    let relay = scratch_relay_socket("restart-nothing");

    let first = Boot::ui(&keys, &db_url, free_port(), None, relay.clone());
    let first_out = first.output_until(&[SETUP_PAGE_LOG]);
    drop(first);
    let second = Boot::ui(&keys, &db_url, free_port(), None, relay);
    let second_out = second.output_until(&[SETUP_PAGE_LOG]);
    drop(second);

    let entries = keys_dir_entries(&keys);
    let _ = std::fs::remove_dir_all(&keys);
    assert!(
        first_out.contains(SETUP_PAGE_LOG),
        "the first boot serves the setup page, got:\n{first_out}"
    );
    assert!(
        second_out.contains(SETUP_PAGE_LOG),
        "the restart before setup serves the setup page again, got:\n{second_out}"
    );
    assert!(
        entries.is_empty(),
        "two boots before setup must write NOTHING to the keys volume (the RAM-only \
         certificate leaves no trace), found: {entries:?}"
    );
}

/// A password in the ui's `DATABASE_URL` is refused at boot (Review
/// Focus 5): the ui reads its credential only from the sealed envelope
/// (or the setup page's typed field), never from the environment —
/// the refusal names the contract and exits non-zero, before any key
/// or database work.
#[tokio::test]
#[ignore = "part of the DB-gated boot battery (--include-ignored)"]
async fn a_password_in_the_ui_database_url_is_refused() {
    let keys = scratch_keys_dir("ui-pw-refusal");
    let mut boot = Boot::ui(
        &keys,
        "postgres://wardstone:a-typed-password@127.0.0.1:5/wardstone_test",
        free_port(),
        None,
        scratch_relay_socket("ui-pw-refusal"),
    );
    let status = boot.wait_exit();
    std::thread::sleep(Duration::from_millis(300));
    let out = boot.drain_output();
    drop(boot);
    let _ = std::fs::remove_dir_all(&keys);

    let status = status.unwrap_or_else(|| {
        panic!("a password-bearing ui URL must refuse at boot, but it kept serving:\n{out}")
    });
    assert!(
        !status.success(),
        "the ui password-URL refusal exits non-zero, got {status:?}"
    );
    assert!(
        out.contains(UI_PASSWORD_REFUSAL),
        "the refusal carries the spec's exact copy, got:\n{out}"
    );
}

/// A stale `WARDSTONE_DB_PASSWORD` from the old bundle's `.env`: the
/// bundled deployment's database has no password at all, so the
/// variable is dead weight that reads as live configuration — the ui
/// refuses at boot with the plan's exact copy and exits non-zero,
/// before any key or database work. The sibling pass case: the same
/// boot WITHOUT the variable reaches the first-run setup page (unset
/// and empty-string both pass; the empty-string variant needs no case
/// of its own).
#[tokio::test]
#[ignore = "part of the DB-gated boot battery (--include-ignored)"]
async fn a_stale_bundled_db_password_refuses_the_boot() {
    let keys = scratch_keys_dir("stale-db-password");
    let db_url = child_database_url();
    let relay = scratch_relay_socket("stale-db-password");
    let mut boot = Boot::start(
        "ui",
        &keys,
        &db_url,
        free_port(),
        None,
        relay.clone(),
        &[("WARDSTONE_DB_PASSWORD".into(), "x".into())],
    );
    let status = boot.wait_exit();
    std::thread::sleep(Duration::from_millis(300));
    let out = boot.drain_output();
    drop(boot);

    let status = status.unwrap_or_else(|| {
        panic!(
            "a stale bundled WARDSTONE_DB_PASSWORD must refuse at boot, but it kept serving:\n{out}"
        )
    });
    assert!(
        !status.success(),
        "the stale-variable refusal exits non-zero, got {status:?}"
    );
    assert!(
        out.contains(STALE_DB_PASSWORD_REFUSAL),
        "the refusal carries the plan's exact copy, got:\n{out}"
    );

    // The sibling pass case: the same boot WITHOUT the variable serves
    // the first-run setup page — the gate is silent (the boot dials no
    // database in this phase, so no lock is needed).
    let clean = Boot::ui(&keys, &db_url, free_port(), None, relay);
    let clean_out = clean.output_until(&[SETUP_PAGE_LOG]);
    drop(clean);
    let _ = std::fs::remove_dir_all(&keys);
    assert!(
        clean_out.contains(SETUP_PAGE_LOG),
        "without the stale variable the boot serves the setup page, got:\n{clean_out}"
    );
}

/// A bundled volume with no db-credential envelope — the bundled
/// deployment's heal state: the page offers NO database-password field
/// (the re-armed peer door replaces the typed credential) and carries
/// the bundled lede naming the runbook's re-arm step, and the
/// passphrase-only POST heals through the peer door — which the dev
/// host does not arm (no `ws_setup` role, no peer line), so the refusal
/// is the door-closed copy and NOTHING else happens: the process stays
/// alive and sealed, no envelope appears, and nothing rotates.
#[tokio::test]
#[ignore = "requires a live Postgres at DATABASE_URL"]
async fn a_bundled_volume_without_a_credential_heals_only_through_the_rearmed_door() {
    let _guard = lock_db().await;
    let mut fx = fixture("heal-door").await;
    sweep_default_tenant(&fx.pool).await;

    mint_envelope(&fx.keys_dir.join(MASTER_ENVELOPE_FILE), &[7u8; 32]);
    let mut ui = Boot::ui(
        &fx.keys_dir,
        &child_database_url(),
        free_port(),
        None,
        scratch_relay_socket("heal-door"),
    );
    let boot_out = ui.output_until(&[SEALED_DOOR_LOG]);
    wait_for_tcp(ui.port());

    // The page offers NO database-password field and carries the
    // bundled lede: the peer door, not a typed password, is the heal.
    let page = https_get(ui.port(), "/")
        .await
        .expect("the unlock page answers over TLS");
    let html = page.text().await.expect("the page body");
    assert!(
        !html.contains(r#"id="db-password""#),
        "the bundled page offers no database-password field, got: {html}"
    );
    assert!(
        html.contains(BUNDLED_HEAL_LEDE),
        "the bundled lede names the runbook's re-arm step, got: {html}"
    );

    // The passphrase-only POST: the pre-check demands no typed password
    // on a bundled volume, the build heals through the peer door, and
    // the closed door's refusal is the re-arm copy wrapped in the
    // build's db re-seal prefix.
    let unlock = https_unlock(ui.port(), serde_json::json!({ "passphrase": PASSPHRASE }))
        .await
        .expect("the unlock POST must reach the ui");
    assert_eq!(
        unlock.status().as_u16(),
        409,
        "the refused heal answers the unlock POST with the build's refusal shape"
    );
    let refusal = unlock.text().await.expect("the refusal body");
    assert!(
        refusal.contains(HEAL_DOOR_REFUSAL),
        "the refusal carries the door-closed copy wrapped in the db re-seal prefix, got: {refusal}"
    );

    // The verdict is a refusal, never a fatal: the process stays alive
    // and sealed, and no envelope appeared on the volume.
    std::thread::sleep(Duration::from_millis(500));
    let alive = ui.is_alive();
    let health = https_get(ui.port(), "/healthz")
        .await
        .expect("the refused heal keeps the health surface serving");
    let health_body = health.text().await.expect("the health body");
    let sealed = health_body.contains(r#""state":"sealed""#);
    let nothing_sealed = !fx.keys_dir.join(DB_CREDENTIAL_ENVELOPE_FILE).exists();
    let out = format!("{boot_out}{}", ui.drain_output());
    // Restore the shared role before any assertion can panic (nothing
    // rotated here — the refusal precedes any dial as the door's — the
    // net is the suite's standing discipline).
    fx.cleanup().await;
    drop(ui);

    assert!(
        alive,
        "the door-closed refusal is not fatal, but the ui exited, output:\n{out}"
    );
    assert!(
        sealed,
        "the front door stays sealed after the refused heal, health: {health_body}"
    );
    assert!(
        !out.contains(TORN_REFUSAL),
        "no torn refusal surfaced, got:\n{out}"
    );
    assert!(
        nothing_sealed,
        "the refused heal sealed no db-credential envelope on the volume"
    );
}

/// The state the new ordering actually produces — the torn-fatal case:
/// a sealed volume whose db-credential envelope EXISTS but whose
/// database holds no default tenant (a setup that crashed after
/// sealing, before the tenant row landed). The hand-minted envelope
/// seals the dev role's live bootstrap password, so the unlock's pool
/// connects as `wardstone`, the tenant lookup finds nothing, and the
/// process EXITS non-zero with the spec's exact refusal copy while the
/// POST answers the same copy with a 409.
#[tokio::test]
#[ignore = "requires a live Postgres at DATABASE_URL"]
async fn a_sealed_volume_with_a_credential_and_no_tenant_is_refused() {
    let _guard = lock_db().await;
    let mut fx = fixture("torn-cred").await;
    sweep_default_tenant(&fx.pool).await;

    mint_envelope(&fx.keys_dir.join(MASTER_ENVELOPE_FILE), &[7u8; 32]);
    // The credential the build connects with: the dev role's live
    // bootstrap password, hand-sealed with the suite passphrase.
    mint_envelope(&fx.keys_dir.join(DB_CREDENTIAL_ENVELOPE_FILE), b"wardstone");
    let mut ui = Boot::ui(
        &fx.keys_dir,
        &child_database_url(),
        free_port(),
        None,
        scratch_relay_socket("torn-cred"),
    );
    let boot_out = ui.output_until(&[SEALED_DOOR_LOG]);
    wait_for_tcp(ui.port());

    let unlock = https_unlock(ui.port(), serde_json::json!({ "passphrase": PASSPHRASE })).await;
    let status = ui.wait_exit();
    let out = format!("{boot_out}{}", ui.drain_output());
    // Restore the shared role before any assertion can panic (the ui's
    // unlock never rotates — only the api's relayed one does — but the
    // net is the suite's standing discipline).
    fx.cleanup().await;
    drop(ui);

    let status = status
        .unwrap_or_else(|| panic!("the torn state must exit the ui, but it kept serving:\n{out}"));
    assert!(
        !status.success(),
        "the torn-state refusal exits non-zero, got {status:?}"
    );
    assert!(
        out.contains(TORN_REFUSAL),
        "the refusal carries the spec's exact copy, got:\n{out}"
    );
    // The unlock POST's own refusal is a 409 naming the condition when
    // the response lands at all — the process exits as the response is
    // written, so a transport error mid-response is the same verdict.
    if let Ok(response) = unlock {
        assert_eq!(
            response.status().as_u16(),
            409,
            "the unlock POST's refusal is a 409 naming the torn state"
        );
    }
}

/// The ui reads nothing after the api rotates (Review Focus 1): the
/// unlock resolves the tenant and the serving leaf BEFORE the relay —
/// the relay's api unlock rotates the shared credential out from under
/// every fresh connection — and then releases the pool, so the unlocked
/// front door holds NO database connection. The test force-closes every
/// backend the ui might still hold (`pg_terminate_backend` for the
/// ui's `application_name`, plus any unlabelled straggler) and the ui
/// keeps serving with no database error. The api's own pool carries
/// the `wardstone-api` label (Task 11's scan keys off them).
#[tokio::test]
#[ignore = "requires a live Postgres at DATABASE_URL"]
async fn the_ui_reads_nothing_after_the_api_rotates() {
    let _guard = lock_db().await;
    let mut fx = fixture("dual").await;
    sweep_default_tenant(&fx.pool).await;
    sqlx::query("INSERT INTO tenants (name) VALUES ($1)")
        .bind(DEFAULT_TENANT)
        .execute(&fx.pool)
        .await
        .expect("insert the default tenant");

    // The sealed volume both children unlock through: the master, the
    // secret-encryption key, the JWT pair, and the CURRENT login
    // credential (the role's live bootstrap password) — the api's
    // unlock is load-only, so the fixture seals the JWT envelope itself
    // — no tenant certificates (the leafless fallback is the unlocked
    // shape this test pins).
    mint_envelope(&fx.keys_dir.join(MASTER_ENVELOPE_FILE), &[7u8; 32]);
    mint_envelope(&fx.keys_dir.join(SECRET_ENVELOPE_FILE), &[9u8; 32]);
    mint_envelope(&fx.keys_dir.join(DB_CREDENTIAL_ENVELOPE_FILE), b"wardstone");
    let jwt_pair = ws_auth::jwt::JwtKeys::generate(900).expect("mint the fixture's JWT pair");
    ws_auth::jwt::write_sealed(
        &fx.keys_dir.join(JWT_ENVELOPE_FILE),
        PASSPHRASE.as_bytes(),
        &jwt_pair,
        0,
    )
    .expect("seal the fixture's JWT pair");

    // One relay socket both children share (Task 10, D8): the api binds
    // it, the ui dials it, and SO_PEERCRED admits the peer because both
    // children run as this test's own uid.
    let relay = scratch_relay_socket("dual");
    let api = Boot::api(
        &fx.keys_dir,
        &child_database_url(),
        free_port(),
        relay.clone(),
    );
    let api_boot = api.output_until(&[API_SEALED_LOG]);
    wait_for_tcp(api.port());
    let mut ui = Boot::ui(
        &fx.keys_dir,
        &child_database_url(),
        free_port(),
        Some(format!("http://127.0.0.1:{}", api.port())),
        relay,
    );
    let ui_boot = ui.output_until(&[SEALED_DOOR_LOG]);
    wait_for_tcp(ui.port());
    assert!(
        api_boot.contains(API_SEALED_LOG) && ui_boot.contains(SEALED_DOOR_LOG),
        "both children must boot their sealed shells, got:\napi:\n{api_boot}\nui:\n{ui_boot}"
    );

    // The one unlock through the ui's real TLS front door: the build
    // resolves the tenant + leaf, releases the pool, and relays — the
    // api's unlock rotates the credential and brings its full surface
    // up before the ui's POST returns.
    let unlock = https_unlock(ui.port(), serde_json::json!({ "passphrase": PASSPHRASE }))
        .await
        .expect("the unlock POST must reach the ui");
    assert_eq!(
        unlock.status().as_u16(),
        200,
        "the ui unlocks against the live api"
    );

    // The pre-sweep verdict: the pool release must already have
    // happened when the unlock's 200 returned — a retained-but-idle ui
    // pool cannot pass this leg, where only the force-close sweep
    // below would mask it.
    let ui_backends_pre: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity WHERE application_name = 'wardstone-ui'",
    )
    .fetch_one(&fx.pool)
    .await
    .expect("count the ui's labelled backends before the sweep");
    assert_eq!(
        ui_backends_pre, 0,
        "the ui holds no database connection the moment the unlock returns"
    );

    // The relay landed: the api reports unlocked, and its pool carries
    // the wardstone-api label (a fresh post-rotation connection).
    let api_health: serde_json::Value = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/api/v1/healthz", api.port()))
        .send()
        .await
        .expect("the api healthz answers")
        .json()
        .await
        .expect("the api healthz is JSON");
    assert_eq!(
        api_health["state"], "unlocked",
        "the relayed api unlock completed, got: {api_health}"
    );
    let api_backends: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity WHERE application_name = 'wardstone-api'",
    )
    .fetch_one(&fx.pool)
    .await
    .expect("count the api's labelled backends");
    assert!(
        api_backends >= 1,
        "the api's unlocked pool carries the wardstone-api label, got {api_backends}"
    );

    // Force-close every backend the ui might still hold — the mandated
    // `wardstone-ui` sweep plus any unlabelled straggler — never the
    // test's own labelled connections and never the api's pool.
    sqlx::query(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
         WHERE usename = current_user AND pid <> pg_backend_pid() \
         AND application_name NOT IN ('wardstone-api', 'wardstone-boot-test')",
    )
    .execute(&fx.pool)
    .await
    .expect("force-close the ui's backends");

    // The ui keeps serving with NO database error.
    let health = https_get(ui.port(), "/healthz")
        .await
        .expect("the unlocked ui keeps serving /healthz");
    assert_eq!(health.status().as_u16(), 200);
    let health: serde_json::Value = health.json().await.expect("the healthz is JSON");
    assert_eq!(
        health["state"], "unlocked",
        "the front door reports unlocked"
    );

    let login = https_get(ui.port(), "/login")
        .await
        .expect("the unlocked ui keeps serving the SPA");
    assert_eq!(
        login.status().as_u16(),
        200,
        "the full surface answers on the same listener after the termination"
    );

    // A settle window, then the verdict: no database error surfaced and
    // the ui holds no backend at all.
    std::thread::sleep(Duration::from_millis(1500));
    let ui_out = ui.drain_output();
    let ui_backends: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity WHERE application_name = 'wardstone-ui'",
    )
    .fetch_one(&fx.pool)
    .await
    .expect("count the ui's labelled backends");
    assert!(
        ui.is_alive(),
        "the ui keeps serving after its connections were force-closed"
    );
    assert!(
        !ui_out.contains("28P01"),
        "no refused credential surfaced in the ui's output, got:\n{ui_out}"
    );
    assert!(
        !ui_out.contains("the tenant lookup")
            && !ui_out.contains("the certificate listing")
            && !ui_out.contains("the database:"),
        "no database error surfaced in the ui's output after the rotation, got:\n{ui_out}"
    );
    assert_eq!(
        ui_backends, 0,
        "the unlocked ui holds no database connection"
    );

    drop(ui);
    drop(api);
    fx.cleanup().await;
}
