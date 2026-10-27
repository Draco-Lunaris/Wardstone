//! Database bootstrap: Postgres connection pool + numbered migrations.
//!
//! `sqlx::migrate!` embeds `migrations/*.sql` at compile time, so `connect`
//! runs from any working directory and the applied-checksum comparison is
//! pinned to the binary's schema.

use std::str::FromStr;

use sqlx::postgres::PgPoolOptions;
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use sqlx::ConnectOptions;
use sqlx::PgConnection;
use sqlx::PgPool;

use crate::error::CoreError;

/// Number of migration files embedded from `crates/ws-core/migrations/`.
///
/// `connect` refuses to serve traffic against a database whose
/// `_sqlx_migrations` bookkeeping disagrees with this constant.
/// Bump it exactly when a migration file is added.
pub const REQUIRED_MIGRATION_COUNT: u16 = 12;

/// Open a Postgres connection pool (max 10 connections) and bring the
/// database up to date through [`migrate_and_check`] — the one home for
/// the migration and bookkeeping-count policy (see its steps).
pub async fn connect(url: &str) -> Result<PgPool, CoreError> {
    let options = connect_options_with_statement_logging_off(url)?;
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await?;

    // One pooled connection carries the whole migration + count check
    // (the same single-connection shape the migrator itself uses), then
    // returns to the pool before serving.
    let mut conn = pool.acquire().await?;
    migrate_and_check(&mut conn).await?;
    drop(conn);

    Ok(pool)
}

/// Bring the database up to date over a Postgres connection and verify
/// the bookkeeping — the ONE home for the migration + count policy,
/// shared by [`connect`]'s pool-acquired connection and the bundled
/// first-run setup's peer connection (which runs it `SET ROLE`'d to the
/// URL's login role, so object ownership is byte-identical to a
/// pool-based run):
///
/// 1. Refuse a database where the schema exists but the migration
///    bookkeeping does not: `_sqlx_migrations` with zero rows while
///    `tenants` exists means the applied-migration history was lost
///    (deleted by hand); re-running migrations would silently paper over
///    that. A genuinely fresh database has neither table, so
///    bootstrapping — including recovery from a crashed first bootstrap,
///    which can leave an empty `_sqlx_migrations` behind — still works.
/// 2. Run the embedded migrations (idempotent: applied versions are
///    skipped, and upgrade gaps — e.g. one migration applied against a
///    two-migration binary — are bridged forward).
/// 3. Verify the bookkeeping count equals [`REQUIRED_MIGRATION_COUNT`],
///    returning [`CoreError::Migration`] on mismatch (e.g. the database
///    is ahead of this binary).
pub async fn migrate_and_check(conn: &mut PgConnection) -> Result<(), CoreError> {
    let migrations_table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = current_schema() \
         AND tablename = '_sqlx_migrations')",
    )
    .fetch_one(&mut *conn)
    .await?;
    if migrations_table_exists {
        let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
            .fetch_one(&mut *conn)
            .await?;
        if applied == 0 {
            // `tenants` is migration 001's root table (nothing references
            // other schemas here): its presence proves the schema was created,
            // so the missing bookkeeping rows are damage, not a fresh start.
            let schema_initialized: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = current_schema() \
                 AND tablename = 'tenants')",
            )
            .fetch_one(&mut *conn)
            .await?;
            if schema_initialized {
                return Err(CoreError::Migration {
                    expected: REQUIRED_MIGRATION_COUNT,
                    found: 0,
                });
            }
        }
    }

    // `run_direct`, not `run`: the bundled setup arm awaits this inline
    // inside a Send-required handler future, and `run`'s `Acquire` bound
    // is lifetime-tied for `&mut PgConnection`
    // (`impl<'c> Acquire<'c> for &'c mut C`), so the auto-trait check
    // fails with "not general enough". The `&Pool` impl is
    // lifetime-free, which is why `connect`'s own `run(&pool)` never
    // hit this. `run_direct` is exactly what `run` does internally
    // after acquiring: same migrations, same connection.
    sqlx::migrate!("./migrations")
        .run_direct(&mut *conn)
        .await
        .map_err(migrate_error)?;

    let found: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&mut *conn)
        .await?;
    let found = u16::try_from(found)
        .map_err(|_| CoreError::Config(format!("migration count {found} does not fit u16")))?;
    if found != REQUIRED_MIGRATION_COUNT {
        return Err(CoreError::Migration {
            expected: REQUIRED_MIGRATION_COUNT,
            found,
        });
    }

    Ok(())
}

/// Parse `url` into [`PgConnectOptions`] with sqlx's statement logging
/// turned OFF — the one shared surface every production connection the
/// binaries create is built from ([`connect`]'s pool and the ui's
/// dedicated recovery connection).
///
/// The WHY (the Global Constraint: no secret, credential, passphrase,
/// token, verifier, or key material in any log line or error message at
/// ANY level): the DB credential rotation's `ALTER ROLE … PASSWORD
/// '<verifier>'` inlines the freshly minted SCRAM verifier into the
/// statement text — Postgres utility statements accept no bind
/// parameters — and sqlx logs the full statement text of every
/// execution: TRACE for statements, WARN for slow ones (>1s by
/// default). BOTH setters go OFF, so a slow ALTER under load cannot
/// leak at WARN either; the suppression happens here because sqlx
/// keeps its per-connection log settings private with no runtime
/// accessor. sqlx never logs bind VALUES and the tree's only
/// value-inlined statement is the ALTER, so nothing observable is lost.
pub fn connect_options_with_statement_logging_off(
    url: &str,
) -> Result<PgConnectOptions, CoreError> {
    let options = PgConnectOptions::from_str(url)
        .map_err(|e| CoreError::Config(format!("database URL does not parse: {e}")))?;
    Ok(options
        .log_statements(log::LevelFilter::Off)
        .log_slow_statements(log::LevelFilter::Off, std::time::Duration::from_secs(1)))
}

/// The deployment a database URL implies: the bundled Postgres that
/// ships beside Wardstone in the compose image, or an external server
/// reached over TCP. The connection shape IS the mode — the same
/// transport split [`check_database_url`] makes — so first-run code
/// can gate mode-specific doors without ever asking the database.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DbMode {
    /// The database lives beside Wardstone and speaks over its shared
    /// unix socket — the bundled deployment, where unix-socket peer
    /// credentials are the protection and no TLS applies.
    Bundled,
    /// The database is a separate server reached over TCP — an
    /// external deployment, which must be TLS-verified end to end.
    External,
}

/// Classify `url` into [`DbMode`] by parsing it — no connection, no
/// query: a socket host (the same `get_socket().is_some()` edge
/// [`check_database_url`] splits on) is [`DbMode::Bundled`], anything
/// else is [`DbMode::External`]. A URL that does not parse is
/// [`CoreError::Config`], the same refusal the option builders give.
pub fn db_mode(url: &str) -> Result<DbMode, CoreError> {
    let options = PgConnectOptions::from_str(url)
        .map_err(|e| CoreError::Config(format!("database URL does not parse: {e}")))?;
    if options.get_socket().is_some() {
        Ok(DbMode::Bundled)
    } else {
        Ok(DbMode::External)
    }
}

/// The first-run setup door's connect options: build on
/// [`connect_options_with_statement_logging_off`] (the role-rotation
/// ALTER that rides this connection inherits that builder's
/// statement-logging-off guarantee — see its WHY), refuse anything
/// but the bundled shared-socket form, and log in as the passwordless
/// [`SETUP_ROLE`](crate::dbcred::SETUP_ROLE), whose identity is the
/// socket's own peer credential (`SO_PEERCRED` — the server trusts the
/// connecting OS user, never a password). No password is ever set: the
/// URL's own shape carries none, and a TCP URL is refused outright.
pub fn peer_setup_connect_options(url: &str) -> Result<PgConnectOptions, CoreError> {
    let options = connect_options_with_statement_logging_off(url)?;
    if options.get_socket().is_none() {
        return Err(CoreError::Config(
            "the peer setup door is a bundled-only concept: the URL must be the shared-socket form"
                .to_string(),
        ));
    }
    Ok(options.username(crate::dbcred::SETUP_ROLE))
}

/// Map sqlx's migration failure set onto [`CoreError`]. `MigrateError::Execute`
/// wraps a genuine [`sqlx::Error`] and keeps its typed source; every other
/// variant (missing/edited migration, dirty state, source resolution) is a
/// deployment-level problem and becomes [`CoreError::Config`].
fn migrate_error(err: sqlx::migrate::MigrateError) -> CoreError {
    match err {
        sqlx::migrate::MigrateError::Execute(db_err) => CoreError::Database(db_err),
        other => CoreError::Config(format!("migration run failed: {other}")),
    }
}

/// The external-database URL policy (Task 10, D5): parse, don't
/// connect — a pure preflight check the binary runs at boot in BOTH
/// modes, additive beside (and after) the password-refusal gate.
///
/// The rule splits on the transport, which the parser alone reveals:
/// a SOCKET host is a local link — unix-socket peer credentials are
/// the protection there (D8), and no TLS keys apply; a TCP host is an
/// EXTERNAL database and must carry BOTH `sslmode=verify-full` and
/// `sslrootcert=<path>` (the operator mounts the CA bundle
/// read-only), else the URL is refused — a half-verified TLS link is
/// a downgrade, not a deployment. The refusal names both protections
/// whatever is missing, and connects never happen here (whether the
/// server answers is [`connect`]'s concern).
///
/// The `sslrootcert` check is a hand scan of the URL's query: sqlx
/// parses the key into a private field with no getter
/// (options/parse.rs:56-57 → `ssl_root_cert` → connection/tls.rs:58,
/// so the driver honors it end-to-end), and the hand-rolled scan is
/// the house's no-new-dependency precedent.
pub fn check_database_url(url: &str) -> Result<(), CoreError> {
    let options = PgConnectOptions::from_str(url)
        .map_err(|e| CoreError::Config(format!("database URL does not parse: {e}")))?;

    // A socket host is a local link: admitted with no TLS keys.
    if options.get_socket().is_some() {
        return Ok(());
    }

    // A TCP host is an external database: both protections or refusal.
    if matches!(options.get_ssl_mode(), PgSslMode::VerifyFull) && ssl_root_cert_configured(url) {
        return Ok(());
    }
    Err(CoreError::Config(format!(
        "an external (TCP) database URL must carry sslmode=verify-full and \
         sslrootcert=<path> (the operator's mounted CA bundle); this URL has \
         sslmode={:?} and {} — Wardstone refuses rather than downgrade TLS",
        options.get_ssl_mode(),
        if ssl_root_cert_configured(url) {
            "an sslrootcert"
        } else {
            "no sslrootcert"
        },
    )))
}

/// Whether the URL's query names a non-empty `sslrootcert` (sqlx also
/// accepts the `ssl-root-cert`/`ssl-ca` spellings). Only the PRESENCE
/// of a value is checked here — the path itself is validated where it
/// is used, by the driver's TLS handshake.
fn ssl_root_cert_configured(url: &str) -> bool {
    let Some((_, query)) = url.split_once('?') else {
        return false;
    };
    query.split('&').any(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        matches!(key, "sslrootcert" | "ssl-root-cert" | "ssl-ca") && !value.is_empty()
    })
}

/// # Unit tests
///
/// Parse-level only: the connection shape IS the mode, and the option
/// builders never connect. No database is touched here.
#[cfg(test)]
mod tests {
    use super::{db_mode, peer_setup_connect_options, DbMode};
    use crate::error::CoreError;

    /// The bundled shared-socket form (the compose deployment's own URL).
    const SOCKET_URL: &str = "postgres://wardstone@%2Frun%2Fwardstone%2Fpg/wardstone";

    /// The external TCP form, carrying both mandated protections.
    const TCP_URL: &str =
        "postgres://wardstone@localhost:5432/wardstone?sslmode=verify-full&sslrootcert=/ca.pem";

    #[test]
    fn a_socket_url_is_the_bundled_mode() {
        assert_eq!(
            db_mode(SOCKET_URL).expect("the bundled URL parses"),
            DbMode::Bundled
        );
    }

    #[test]
    fn a_tcp_url_is_the_external_mode() {
        assert_eq!(
            db_mode(TCP_URL).expect("the external URL parses"),
            DbMode::External
        );
    }

    #[test]
    fn an_unparseable_url_is_a_config_error() {
        let err = db_mode("not a url").expect_err("a URL-shaped string that is not a URL");
        assert!(
            matches!(err, CoreError::Config(_)),
            "a parse failure is Config, got {err:?}"
        );
    }

    /// The socket survives and the login is the setup role; the URL's
    /// own shape carries no password (boot's gate refuses one), and no
    /// builder step adds one — `PgConnectOptions` keeps its password
    /// private with no getter, so the observable pins are the
    /// username, the socket, and the database.
    #[test]
    fn peer_options_carry_the_setup_role_over_the_socket() {
        let options = peer_setup_connect_options(SOCKET_URL).expect("the bundled URL parses");
        assert_eq!(
            options.get_username(),
            crate::dbcred::SETUP_ROLE,
            "the door logs in as the setup role"
        );
        assert_eq!(
            options.get_socket().map(|path| path.display().to_string()),
            Some("/run/wardstone/pg".to_string()),
            "the socket survives the username swap"
        );
        assert_eq!(
            options.get_database(),
            Some("wardstone"),
            "the built options stay connect-shaped"
        );
    }

    #[test]
    fn peer_options_refuse_an_external_url() {
        let err = peer_setup_connect_options(TCP_URL).expect_err("a TCP URL is refused outright");
        assert!(
            matches!(err, CoreError::Config(_)),
            "the refusal is Config, got {err:?}"
        );
        assert!(
            err.to_string().contains("bundled-only concept"),
            "the refusal names the door's constraint: {err}"
        );
    }
}
