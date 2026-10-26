//! DB-gated coverage of `ws_core::dbcred`'s rotation (Task 4): the
//! verifier-only ALTER, the crash-safe pending envelope, and the
//! advisory-locked rotation itself.
//!
//! These tests run against a live Postgres and are marked `#[ignore]`.
//! Run them with:
//!
//! ```sh
//! DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test \
//!     cargo test -p ws-core --test rotation_test -- --include-ignored
//! ```
//!
//! # The probe role
//!
//! The rotation needs a login role whose password it can ALTER. The
//! shared `wardstone` role has no CREATEROLE attribute, so a test cannot
//! create roles — and cannot ALTER another role's password either — but
//! Postgres lets a role change ITS OWN password. The suite therefore
//! rotates a dedicated probe role, `ws_rot_probe`, CONNECTED AS ITSELF:
//! provisioned out-of-band exactly like the shared `wardstone` role
//! (the dev-environment runbook):
//!
//! ```sh
//! sudo -n -u postgres psql -c \
//!     "CREATE ROLE ws_rot_probe LOGIN PASSWORD 'ws_rot_probe';"
//! ```
//!
//! Its password is restored to the verifier form of `ws_rot_probe` after
//! every test (a role left rotated breaks the NEXT run at its fixture
//! connect); a poisoned probe resets with:
//!
//! ```sh
//! sudo -n -u postgres psql -c \
//!     "ALTER USER ws_rot_probe PASSWORD 'ws_rot_probe';"
//! ```
//!
//! # Serialization
//!
//! In-process: the tokio-mutex fence before every fixture connect (the
//! harness runs tests on separate threads). Cross-process: the suite's
//! session-level advisory lock on [`ADVISORY_KEY`] — the "WARDST" family,
//! marker 0x0018. The rotation's own serialization (two rotations on
//! separate connections) is the production advisory key
//! [`ws_core::dbcred::ROTATION_LOCK_KEY`], exercised by
//! [`concurrent_rotations_serialize`].

use std::path::PathBuf;
use std::sync::OnceLock;

use sqlx::PgConnection;
use tokio::sync::Mutex as TokioMutex;
use ws_core::dbcred::{
    alter_role_password, discard_pending, generate_db_password, open_db_credential, pending_path,
    promote_pending, rotate_db_credential, scram_verifier, DbCredentialCandidates,
};

/// Postgres advisory-lock key for this suite: ASCII "WARDST" (0x5741445354)
/// plus the suite marker 0x0018 (0003-0017 are taken; CLAUDE.md's table).
const ADVISORY_KEY: i64 = 0x0057_4144_5354_0018;

/// The rotation suite's dedicated login role (see the module docs: the
/// shared `wardstone` role cannot be ALTER'd by this suite's connection,
/// and the suite never touches it — zero cross-suite interference).
const PROBE_ROLE: &str = "ws_rot_probe";

/// The probe role's provisioned password, and the value every test
/// restores it to (in verifier form).
const PROBE_PASSWORD: &str = "ws_rot_probe";

/// The passphrase the test envelopes seal under (arbitrary, but fixed
/// so hand-minted current envelopes and rotation writes agree).
const PASSPHRASE: &str = "the-rotation-suite-passphrase";

/// The fixed 16-byte salt the probe role's RESTORE verifier uses. The
/// restore statements must set the password in verifier form (Task 4's
/// ruling: no plaintext ALTER anywhere), and a fixed salt keeps that
/// verifier deterministic across every suite that restores the role.
const FIXED_TEST_SALT: [u8; 16] = *b"0123456789abcdef";

/// The SCRAM iterations the restore and rotation verifiers use (the
/// production pin).
const ITERATIONS: u32 = 4096;

/// In-process serialization, the whole-body lock pattern of the ws-core
/// and ws-api suites: a tokio mutex because the guard is held across
/// `.await` points, and it must be taken BEFORE the fixture connect.
static DB_TEST_LOCK: OnceLock<TokioMutex<()>> = OnceLock::new();

/// The guard must be held (not dropped) until the test body finishes.
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

/// The probe role's connect URL: the test database URL's authority swapped
/// to `ws_rot_probe:<password>` — the same host/port/database knob
/// `DATABASE_URL` already controls, with the probe's own login.
fn probe_url_with(password: &str) -> String {
    let base = database_url();
    let Some(scheme_end) = base.find("://") else {
        panic!("the test database URL is not a URL: {base}");
    };
    let auth_start = scheme_end + 3;
    let Some(at) = base[auth_start..].find('@').map(|i| i + auth_start) else {
        panic!("the test database URL carries no login authority: {base}");
    };
    format!(
        "{}{PROBE_ROLE}:{password}{}",
        &base[..auth_start],
        &base[at..]
    )
}

/// The probe role's connect URL with its provisioned password.
fn probe_url() -> String {
    probe_url_with(PROBE_PASSWORD)
}

/// Cheap KDF parameters for the hand-minted "current" envelopes (the
/// pre-crash state a test builds by hand); the rotations themselves seal
/// at the production parameters, exactly as production does.
fn cheap_params() -> ws_core::crypto::KdfParams {
    ws_core::crypto::KdfParams {
        m_cost: 8192,
        t_cost: 2,
        p_cost: 1,
    }
}

/// The probe role's restore statement: the verifier form of the
/// provisioned password (Task 4's ruling — no plaintext ALTER anywhere,
/// test side included).
fn restore_statement() -> String {
    format!(
        "ALTER ROLE {PROBE_ROLE} PASSWORD '{}'",
        scram_verifier(PROBE_PASSWORD.as_bytes(), &FIXED_TEST_SALT, ITERATIONS)
    )
}

/// A Postgres server SQLSTATE, when the error carries one.
fn server_code(err: &sqlx::Error) -> Option<String> {
    err.as_database_error()
        .and_then(|db| db.code())
        .map(|code| code.into_owned())
}

/// Open a probe connection — the fully-qualified form, because
/// `connect` is a TRAIT associated function and inference alone
/// cannot pick the impl when the result is only consumed as a bool.
async fn connect_probe(url: &str) -> Result<PgConnection, sqlx::Error> {
    <PgConnection as sqlx::Connection>::connect(url).await
}

/// The statement-capture seam (the sanctioned shape: the test wraps the
/// EXECUTOR the production ALTER helper takes, so the statement observed
/// is the one production sends — same SQL, same call). Records every
/// statement that rides the connection while it is wrapped.
struct Capturing<'a> {
    conn: &'a mut PgConnection,
    seen: &'a mut Vec<String>,
}

impl std::fmt::Debug for Capturing<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Capturing").finish_non_exhaustive()
    }
}

impl<'c> sqlx::Executor<'c> for Capturing<'c> {
    type Database = sqlx::Postgres;

    fn fetch_many<'e, 'q: 'e, E>(
        self,
        query: E,
    ) -> futures_util::stream::BoxStream<
        'e,
        Result<sqlx::Either<sqlx::postgres::PgQueryResult, sqlx::postgres::PgRow>, sqlx::Error>,
    >
    where
        'c: 'e,
        E: 'q + sqlx::Execute<'q, sqlx::Postgres>,
    {
        self.seen.push(query.sql().to_owned());
        sqlx::Executor::fetch_many(&mut *self.conn, query)
    }

    // The trait's three other REQUIRED methods (`fetch_optional`,
    // `prepare_with`, `describe`) are recorded and delegated too — the
    // wrapper is a faithful pass-through, never a weaker executor.

    fn fetch_optional<'e, 'q: 'e, E>(
        self,
        query: E,
    ) -> futures_util::future::BoxFuture<'e, Result<Option<sqlx::postgres::PgRow>, sqlx::Error>>
    where
        'c: 'e,
        E: 'q + sqlx::Execute<'q, sqlx::Postgres>,
    {
        self.seen.push(query.sql().to_owned());
        sqlx::Executor::fetch_optional(&mut *self.conn, query)
    }

    fn prepare_with<'e, 'q: 'e>(
        self,
        sql: &'q str,
        parameters: &'e [sqlx::postgres::PgTypeInfo],
    ) -> futures_util::future::BoxFuture<'e, Result<sqlx::postgres::PgStatement<'q>, sqlx::Error>>
    where
        'c: 'e,
    {
        self.seen.push(sql.to_owned());
        sqlx::Executor::prepare_with(&mut *self.conn, sql, parameters)
    }

    fn describe<'e, 'q: 'e>(
        self,
        sql: &'q str,
    ) -> futures_util::future::BoxFuture<'e, Result<sqlx::Describe<sqlx::Postgres>, sqlx::Error>>
    where
        'c: 'e,
    {
        self.seen.push(sql.to_owned());
        sqlx::Executor::describe(&mut *self.conn, sql)
    }
}

/// The panic-safe restore net (the setup_test reference pattern): a
/// dedicated thread whose own little runtime owns a probe connection made
/// AT FIXTURE TIME — sqlx connections are runtime-affine, and the
/// fixture-built connection survives any later rotation of the probe's
/// password, so it can still ALTER (its own password) when Drop asks.
/// Best-effort by design; the documented last resort is the sudo reset
/// in the module docs.
struct RestoreNet {
    request: std::sync::mpsc::Sender<()>,
    reply: std::sync::mpsc::Receiver<()>,
}

fn spawn_restore_net(url: &str) -> RestoreNet {
    let (request, rx) = std::sync::mpsc::channel::<()>();
    let (tx, reply) = std::sync::mpsc::channel::<()>();
    let url = url.to_owned();
    std::thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };
        // The worker's own connection, on the worker's own runtime, while
        // the provisioned password is still valid.
        let connected: Result<PgConnection, sqlx::Error> = runtime.block_on(connect_probe(&url));
        let mut conn = match connected {
            Ok(conn) => conn,
            Err(_) => return, // the net is dead; Drop's send no-ops
        };
        if rx.recv().is_err() {
            return;
        }
        // Phase 3: the restore, over the connection this runtime made.
        runtime.block_on(async {
            let _ = sqlx::query(&restore_statement()).execute(&mut conn).await;
        });
        let _ = tx.send(());
    });
    RestoreNet { request, reply }
}

/// The per-test fixture: a DEDICATED pre-rotation probe connection (it
/// doubles as the advisory holder and the restore path — established
/// connections survive the rotation), the panic-safe net, and a scratch
/// keys directory for the envelopes.
struct Fixture {
    restore: Option<PgConnection>,
    net: RestoreNet,
    keys_dir: PathBuf,
    role_restored: bool,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.keys_dir);
        if self.role_restored {
            return;
        }
        // The net is one-shot: the request IS the fixture's last word.
        let _ = self.net.request.send(());
        let _ = self
            .net
            .reply
            .recv_timeout(std::time::Duration::from_secs(15));
    }
}

impl Fixture {
    /// The dedicated connection (unreachable after cleanup — the same
    /// invariant as setup_test's advisory holder).
    fn conn(&mut self) -> &mut PgConnection {
        self.restore
            .as_mut()
            .expect("the restore connection is held through the test body")
    }

    /// Restore the probe role's password (verifier form) over the
    /// dedicated pre-rotation connection. Idempotent.
    async fn restore_role_password(&mut self) {
        sqlx::query(&restore_statement())
            .execute(self.conn())
            .await
            .expect("restore the probe role's password");
        self.role_restored = true;
    }

    /// Restore the role, release the advisory lock, and remove the keys
    /// directory — BEFORE the assertions, so a failing assert can never
    /// leave the probe rotated for the next run.
    async fn cleanup(&mut self) {
        self.restore_role_password().await;
        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(ADVISORY_KEY)
            .execute(self.conn())
            .await
            .expect("release the suite's advisory lock");
        self.restore = None;
        let _ = std::fs::remove_dir_all(&self.keys_dir);
    }
}

/// Build the fixture: connect as the probe role, take the session
/// advisory lock, arm the restore net, and make the scratch keys dir.
async fn fixture() -> Fixture {
    let url = probe_url();
    let mut conn = connect_probe(&url).await.expect(
        "connect as the probe role ws_rot_probe (provision it with the \
             module-doc runbook if this dev environment lacks it)",
    );
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(ADVISORY_KEY)
        .execute(&mut conn)
        .await
        .expect("take the suite's advisory lock");
    let net = spawn_restore_net(&url);
    let keys_dir = std::env::temp_dir().join(format!("ws-rotation-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&keys_dir).expect("create the scratch keys directory");
    Fixture {
        restore: Some(conn),
        net,
        keys_dir,
        role_restored: false,
    }
}

/// Postgres stores the verifier as-is and the PLAINTEXT behind it logs
/// in: after `ALTER ROLE ws_rot_probe PASSWORD '<verifier>'`, the
/// password connects and a one-character mutation is refused with
/// `28P01` (invalid_password) — the same code the pending-credential
/// dance keys on.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn postgres_accepts_the_plaintext_behind_our_verifier() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;

    let password = "the-probe-password";
    let verifier = scram_verifier(password.as_bytes(), &FIXED_TEST_SALT, ITERATIONS);
    sqlx::query(&format!("ALTER ROLE {PROBE_ROLE} PASSWORD '{verifier}'"))
        .execute(fixture.conn())
        .await
        .expect("the verifier-form ALTER lands");

    // Results are captured before the cleanup, per the self-cleaning
    // contract — the cleanup restores the probe before any assert can
    // panic.
    let plaintext_connects = connect_probe(&probe_url_with(password)).await.is_ok();
    let wrong = connect_probe(&probe_url_with(&format!("{password}x")))
        .await
        .expect_err("a one-character mutation of the password is refused");
    let wrong_code = server_code(&wrong);

    fixture.cleanup().await;

    assert!(
        plaintext_connects,
        "the plaintext behind our verifier logs in"
    );
    assert_eq!(
        wrong_code.as_deref(),
        Some("28P01"),
        "a wrong password is refused with invalid_password: {wrong_code:?}"
    );
}

/// The ALTER statement the rotation sends carries the VERIFIER, never
/// the fresh credential: the executor the production ALTER helper takes
/// is wrapped (the sanctioned capture seam — the helper is the one
/// statement-sending step `rotate_db_credential` itself calls, so the
/// wrapped statement is the one production sends). The brief's
/// `log_statement='all'` garnish is NOT set here: the suite connects as
/// the probe role, and a non-superuser cannot set that GUC (SQLSTATE
/// `42501`, established empirically) — the wrapped executor observes
/// the statement text DIRECTLY, which is the stronger observation
/// anyway (the exact bytes sent, not what the server chose to log).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn the_alter_statement_never_carries_the_plaintext() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;

    let fresh = generate_db_password().expect("the protected pool allocates");
    let fresh_text = String::from_utf8_lossy(&fresh).into_owned();
    let verifier = scram_verifier(&fresh, &FIXED_TEST_SALT, ITERATIONS);

    let mut seen = Vec::new();
    alter_role_password(
        Capturing {
            conn: fixture.conn(),
            seen: &mut seen,
        },
        PROBE_ROLE,
        &verifier,
    )
    .await
    .expect("the wrapped ALTER executes against the real database");

    // The ALTER was real: the fresh credential now logs in.
    let fresh_connects = connect_probe(&probe_url_with(&fresh_text)).await.is_ok();

    fixture.cleanup().await;

    assert_eq!(seen.len(), 1, "exactly one statement was sent");
    let statement = &seen[0];
    assert!(
        statement.contains(&format!("ALTER ROLE {PROBE_ROLE} PASSWORD 'SCRAM-SHA-256$")),
        "the statement carries the verifier: {statement}"
    );
    assert!(
        !statement.contains(&fresh_text),
        "the returned credential never rides the statement: {statement}"
    );
    assert!(
        fresh_connects,
        "the plaintext behind the captured verifier logs in"
    );
}

/// A crash between the ALTER and the promote recovers from `.pending`:
/// the test runs the PUBLIC pieces up to and including the ALTER only
/// (generate, write the pending envelope sealed, ALTER the role) and
/// stops — the promote rename is the step that "crashed". Afterwards
/// `open_db_credential` offers both candidates, the pending one
/// connects (it is the LIVE credential), and promoting it removes
/// `.pending` and leaves the envelope holding it.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn a_crash_between_alter_and_promote_recovers_from_pending() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;

    let envelope = fixture
        .keys_dir
        .join(ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE);
    let pending = pending_path(&envelope);

    // The pre-crash state: the envelope holds the probe's LIVE
    // credential (the provisioned password), hand-minted with cheap KDF
    // parameters — the crash simulation below seals its pending at the
    // production parameters, exactly as the rotation does.
    ws_core::crypto::KeyEnvelope::write_envelope(
        &envelope,
        PASSPHRASE,
        PROBE_PASSWORD.as_bytes(),
        cheap_params(),
        0,
    )
    .expect("mint the pre-crash current envelope");

    // The crash simulation — the public pieces, through the ALTER only.
    let fresh = generate_db_password().expect("the protected pool allocates");
    let verifier = scram_verifier(&fresh, &FIXED_TEST_SALT, ITERATIONS);
    ws_core::crypto::KeyEnvelope::write_envelope(
        &pending,
        PASSPHRASE,
        &fresh,
        ws_core::crypto::PROD_KDF_PARAMS,
        0,
    )
    .expect("the pending envelope is written before the ALTER");
    alter_role_password(fixture.conn(), PROBE_ROLE, &verifier)
        .await
        .expect("the ALTER lands");
    // The promote rename "crashed" right here.

    let candidates =
        open_db_credential(&envelope, PASSPHRASE.as_bytes()).expect("both candidates open");
    assert_eq!(
        candidates.current.as_slice(),
        PROBE_PASSWORD.as_bytes(),
        "the envelope's current credential is the pre-crash one"
    );
    let pending_credential = candidates
        .pending
        .clone()
        .expect("the .pending sibling is offered");
    let pending_text = String::from_utf8_lossy(&pending_credential).into_owned();

    // The pending credential is the LIVE one: it connects, and is
    // promoted.
    let pending_connects = connect_probe(&probe_url_with(&pending_text)).await.is_ok();
    promote_pending(&envelope).expect("the promote rename lands");
    let pending_gone = !pending.exists();
    let reopened =
        open_db_credential(&envelope, PASSPHRASE.as_bytes()).expect("the promoted envelope opens");
    let reopened_current = reopened.current.clone();
    let reopened_pending_none = reopened.pending.is_none();

    fixture.cleanup().await;

    assert!(
        pending_connects,
        "the pending credential — the one the ALTER made live — connects"
    );
    assert!(pending_gone, "the promote removes the .pending sibling");
    assert!(
        reopened_pending_none,
        "no .pending remains after the promote"
    );
    assert_eq!(
        reopened_current.as_slice(),
        pending_credential.as_slice(),
        "the envelope now holds the promoted credential"
    );
}

/// A crash BEFORE the ALTER discards the pending: the pending envelope
/// was written but the ALTER never ran, so the OLD credential still
/// connects and the pending one is refused with `28P01` — the caller's
/// delete-on-`28P01` rule then removes `.pending`.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn a_crash_before_alter_discards_pending() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;

    let envelope = fixture
        .keys_dir
        .join(ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE);
    let pending = pending_path(&envelope);

    ws_core::crypto::KeyEnvelope::write_envelope(
        &envelope,
        PASSPHRASE,
        PROBE_PASSWORD.as_bytes(),
        cheap_params(),
        0,
    )
    .expect("mint the current envelope");

    // The crash simulation — the pending write only, no ALTER.
    let fresh = generate_db_password().expect("the protected pool allocates");
    let fresh_text = String::from_utf8_lossy(&fresh).into_owned();
    ws_core::crypto::KeyEnvelope::write_envelope(
        &pending,
        PASSPHRASE,
        &fresh,
        ws_core::crypto::PROD_KDF_PARAMS,
        0,
    )
    .expect("the pending envelope is written");
    // No ALTER: the pending credential never became live.

    let candidates =
        open_db_credential(&envelope, PASSPHRASE.as_bytes()).expect("both candidates open");
    assert!(
        candidates.pending.is_some(),
        "the .pending sibling is offered"
    );

    // The pending one is refused with 28P01 — the caller's delete rule.
    let wrong = connect_probe(&probe_url_with(&fresh_text))
        .await
        .expect_err("the never-ALTER'd pending credential is refused");
    let wrong_code = server_code(&wrong);
    discard_pending(&envelope).expect("the delete-on-28P01 rule runs");
    let pending_gone = !pending.exists();

    // The old credential still connects.
    let old_connects = connect_probe(&probe_url()).await.is_ok();

    fixture.cleanup().await;

    assert_eq!(
        wrong_code.as_deref(),
        Some("28P01"),
        "the stale pending is refused with invalid_password: {wrong_code:?}"
    );
    assert!(pending_gone, "the delete-on-28P01 rule removes .pending");
    assert!(old_connects, "the old credential still connects");
}

/// Two rotations racing on separate connections serialize on the
/// production advisory lock: both complete, the envelope afterwards
/// opens to a credential that connects, and no `.pending` remains.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn concurrent_rotations_serialize() {
    let _db = lock_db().await;
    let mut fixture = fixture().await;

    let envelope = fixture
        .keys_dir
        .join(ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE);
    let mut conn_a = connect_probe(&probe_url())
        .await
        .expect("the first rotation connection opens as the probe");
    let mut conn_b = connect_probe(&probe_url())
        .await
        .expect("the second rotation connection opens as the probe");

    let (a, b) = tokio::join!(
        rotate_db_credential(&mut conn_a, PROBE_ROLE, &envelope, PASSPHRASE.as_bytes(), 7,),
        rotate_db_credential(&mut conn_b, PROBE_ROLE, &envelope, PASSPHRASE.as_bytes(), 7,),
    );
    a.expect("rotation a completes");
    b.expect("rotation b completes");

    let candidates: DbCredentialCandidates =
        open_db_credential(&envelope, PASSPHRASE.as_bytes()).expect("the envelope opens");
    let winner = candidates.current.clone();
    let no_pending = candidates.pending.is_none() && !pending_path(&envelope).exists();

    let winner_connects = connect_probe(&probe_url_with(&String::from_utf8_lossy(&winner)))
        .await
        .is_ok();

    fixture.cleanup().await;

    assert!(no_pending, "no .pending remains after both rotations");
    assert!(
        winner_connects,
        "the envelope opens to a credential that connects"
    );
}
