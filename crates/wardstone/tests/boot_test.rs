//! The `wardstone ui` boot decision against a live database: the built
//! binary (`CARGO_BIN_EXE_wardstone`) runs with a scratch keys directory,
//! and the test reads which front door it chose from its log lines.
//!
//! Two unsealed-volume boots are pinned:
//! - no tenant yet → the first-run setup page, even when an earlier boot
//!   already wrote the pre-setup plaintext keys (a restart before setup);
//! - a tenant beside an unsealed volume (setup committed but crashed
//!   before sealing) → a loud refusal, never the full app on plaintext.
//!
//! DB-gated (`--include-ignored`). Each test sweeps the default tenant
//! before AND after its body, and holds a session-level advisory lock on
//! [`ADVISORY_KEY`] — the "WARDST" family with this suite's marker
//! 0x0017 — plus the in-process mutex for the harness's threads. No test
//! here submits setup, so the shared role's password never rotates.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::OnceLock;
use std::time::Duration;

use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex as TokioMutex;

/// Postgres advisory-lock key for this suite: ASCII "WARDST" (0x5741445354)
/// plus the suite marker 0x0017.
const ADVISORY_KEY: i64 = 0x0057_4144_5354_0017;

/// The tenant setup creates (ws-web's `setup::DEFAULT_TENANT_NAME`).
const DEFAULT_TENANT: &str = "default";

/// The setup page's boot log line, and the unsealed-configured refusal's.
const SETUP_PAGE_LOG: &str = "no tenant yet: serving the first-run setup page";
const REFUSAL_LOG: &str = "the keys volume is not sealed";

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

async fn lock_advisory(pool: &PgPool) -> PoolConnection<sqlx::Postgres> {
    let mut conn = pool
        .acquire()
        .await
        .expect("acquire connection for the advisory lock");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(ADVISORY_KEY)
        .execute(&mut *conn)
        .await
        .expect("take pg_advisory_lock");
    conn
}

async fn release_advisory(mut conn: PoolConnection<sqlx::Postgres>) {
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(ADVISORY_KEY)
        .execute(&mut *conn)
        .await
        .expect("release pg_advisory_lock");
}

/// Test database URL; `DATABASE_URL` overrides it.
fn database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://wardstone:wardstone@localhost:5432/wardstone_test".to_string()
    })
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

/// A loopback port nothing is listening on right now.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("reserve a loopback port")
}

/// A running `wardstone ui` with its merged output streamed line by line.
struct Boot {
    child: Child,
    lines: mpsc::Receiver<String>,
}

impl Boot {
    fn start(keys_dir: &Path) -> Boot {
        let mut child = Command::new(env!("CARGO_BIN_EXE_wardstone"))
            .arg("ui")
            .env("DATABASE_URL", database_url())
            .env("WARDSTONE_KEYS_DIR", keys_dir)
            .env("WARDSTONE_BIND", format!("127.0.0.1:{}", free_port()))
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn `wardstone ui`");
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
        Boot { child, lines }
    }

    /// Every line up to and including the first that contains any of
    /// `markers`, or everything seen when [`BOOT_WAIT`] (or the output)
    /// runs out first.
    fn output_until(&self, markers: &[&str]) -> String {
        let deadline = std::time::Instant::now() + BOOT_WAIT;
        let mut seen = String::new();
        while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
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

    /// The exit status once the process ends, or `None` if it is still
    /// running after [`BOOT_WAIT`].
    fn wait_exit(&mut self) -> Option<std::process::ExitStatus> {
        let deadline = std::time::Instant::now() + BOOT_WAIT;
        while std::time::Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().expect("poll the ui process") {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        None
    }
}

impl Drop for Boot {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A fresh install restarted before setup: the first boot writes the
/// pre-setup plaintext keys, and the second boot must still serve the
/// setup page — the plaintext of a not-yet-set-up volume is not an
/// install to convert.
#[tokio::test]
#[ignore = "requires a live Postgres at DATABASE_URL"]
async fn a_restart_before_setup_serves_the_setup_page_again() {
    let _guard = lock_db().await;
    let pool = ws_core::db::connect(&database_url())
        .await
        .expect("connect to the test database");
    let advisory = lock_advisory(&pool).await;
    sweep_default_tenant(&pool).await;
    let keys = scratch_keys_dir("restart");

    let first = Boot::start(&keys);
    let first_out = first.output_until(&[SETUP_PAGE_LOG]);
    drop(first);
    let second = Boot::start(&keys);
    let second_out = second.output_until(&[SETUP_PAGE_LOG, "conversion page"]);
    drop(second);

    let _ = std::fs::remove_dir_all(&keys);
    sweep_default_tenant(&pool).await;
    release_advisory(advisory).await;

    assert!(
        first_out.contains(SETUP_PAGE_LOG),
        "the first boot serves the setup page, got:\n{first_out}"
    );
    assert!(
        second_out.contains(SETUP_PAGE_LOG),
        "the restart before setup must serve the setup page again, got:\n{second_out}"
    );
}

/// Setup committed the tenant but crashed before sealing the volume: the
/// boot refuses loudly and exits non-zero — it never serves the app on
/// plaintext keys.
#[tokio::test]
#[ignore = "requires a live Postgres at DATABASE_URL"]
async fn a_tenant_beside_an_unsealed_volume_is_refused() {
    let _guard = lock_db().await;
    let pool = ws_core::db::connect(&database_url())
        .await
        .expect("connect to the test database");
    let advisory = lock_advisory(&pool).await;
    sweep_default_tenant(&pool).await;
    sqlx::query("INSERT INTO tenants (name) VALUES ($1)")
        .bind(DEFAULT_TENANT)
        .execute(&pool)
        .await
        .expect("insert the default tenant");
    let keys = scratch_keys_dir("unsealed-tenant");

    let mut boot = Boot::start(&keys);
    let status = boot.wait_exit();
    let out = boot.output_until(&[REFUSAL_LOG]);
    drop(boot);

    let _ = std::fs::remove_dir_all(&keys);
    sweep_default_tenant(&pool).await;
    release_advisory(advisory).await;

    let status = status.unwrap_or_else(|| {
        panic!("the boot must exit, but it was still serving after {BOOT_WAIT:?}:\n{out}")
    });
    assert!(
        !status.success(),
        "the refusal exits non-zero, got {status:?}"
    );
    assert!(
        out.contains(REFUSAL_LOG),
        "the refusal names the unsealed volume, got:\n{out}"
    );
}
