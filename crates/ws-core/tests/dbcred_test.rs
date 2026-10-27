//! Coverage of `ws_core::dbcred`: the fast (no database) shape pins —
//! the SCRAM-SHA-256 verifier and the generated credential's typeable
//! form — plus one DB-gated pin of the setup-role disarm.
//!
//! The rotation itself and the crash-window recovery live in
//! `rotation_test.rs` — DB-gated, advisory key `0x0018`. The disarm pin
//! here takes no advisory key: it mutates no shared state (the dev
//! database has no setup role, so its ALTER refuses with `42704`), and
//! the DB-gated suites run serialized and alone. Run it with:
//!
//! ```sh
//! DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test \
//!     cargo test -p ws-core --test dbcred_test -- --include-ignored
//! ```

use sqlx::PgConnection;
use ws_core::dbcred::{disarm_setup_role, generate_db_password, scram_verifier, SETUP_ROLE};
use ws_core::error::CoreError;

/// Test database URL; `DATABASE_URL` overrides it.
fn database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://wardstone:wardstone@localhost:5432/wardstone_test".to_string()
    })
}

/// The shape pin, regex-equivalent, piecewise: the brief pins
/// `^SCRAM-SHA-256\$4096:[A-Za-z0-9+/=]{24}\$[A-Za-z0-9+/=]{44}:[A-Za-z0-9+/=]{44}$`
/// — asserted structurally here rather than pulling a regex dependency
/// into the workspace (the no-new-dependency stance this task is bound
/// to). `expect` is allowed: this file is a test.
fn assert_b64_field(field: &str, expect_len: usize) {
    assert_eq!(
        field.len(),
        expect_len,
        "the base64 field must be exactly {expect_len} chars (padded standard base64)"
    );
    assert!(
        field
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='),
        "the base64 field carries only standard-alphabet characters"
    );
}

/// `SCRAM-SHA-256$<iter>:<b64 salt>$<b64 StoredKey>:<b64 ServerKey>` —
/// exactly the string form Postgres stores as-is when it rides
/// `ALTER ROLE … PASSWORD '<verifier>'`: 4096 iterations, a 16-byte salt
/// (24 padded chars), and two 32-byte keys (44 padded chars each).
#[test]
fn the_verifier_has_postgres_shape() {
    let verifier = scram_verifier(b"any password at all", &[0u8; 16], 4096);
    let parts: Vec<&str> = verifier.split('$').collect();
    assert_eq!(
        parts.len(),
        3,
        "the verifier splits into exactly three '$'-separated segments"
    );
    assert_eq!(
        parts[0], "SCRAM-SHA-256",
        "the scheme segment is the SCRAM-SHA-256 marker"
    );
    let (iterations, salt) = parts[1]
        .split_once(':')
        .expect("the middle segment is '<iterations>:<salt>'");
    assert_eq!(iterations, "4096", "the iteration count is the pin");
    assert_b64_field(salt, 24);
    let (stored_key, server_key) = parts[2]
        .split_once(':')
        .expect("the last segment is '<StoredKey>:<ServerKey>'");
    assert_b64_field(stored_key, 44);
    assert_b64_field(server_key, 44);
}

/// 32 random bytes as RFC 4648 base32, lowercase, unpadded: 52
/// characters from `a-z2-7` — typeable without quotes in a shell, an
/// `.env` file, or a `psql` prompt. Two generations never agree (the
/// 256 bits behind them are fresh OS entropy).
#[test]
fn the_generated_password_is_52_lowercase_base32() {
    let first = generate_db_password().expect("the protected pool allocates");
    let second = generate_db_password().expect("the protected pool allocates again");
    for (label, password) in [("first", &first), ("second", &second)] {
        assert_eq!(password.len(), 52, "the {label} password is 52 chars");
        assert!(
            password
                .iter()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(b)),
            "the {label} password is lowercase base32 (a-z, 2-7) only"
        );
    }
    assert_ne!(
        first.as_ref(),
        second.as_ref(),
        "two generations are two different credentials"
    );
}

/// The disarm statement is a real `ALTER ROLE` against exactly the
/// setup role. The dev database has no `ws_setup` role — the shared
/// `wardstone` role is neither superuser nor createrole, and the plan
/// forbids new host prerequisites — so the live server answers
/// `42704` naming the role, which proves the statement's shape (an
/// ALTER, not some softer utility call) and its target (the role the
/// constant names, never the shared `wardstone` role). The pin is the
/// refusal, not a successful disarm; the expected text is built from
/// [`SETUP_ROLE`] itself, so the copy Task 2's `SetupError` mapping
/// table carries references the same constant.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn the_disarm_statement_is_alter_role_against_the_setup_role() {
    // The fully-qualified form: `connect` is a TRAIT associated
    // function and inference alone cannot pick the impl here.
    let mut conn = <PgConnection as sqlx::Connection>::connect(&database_url())
        .await
        .expect("connect to the test database");

    let err = disarm_setup_role(&mut conn).await.expect_err(
        "the dev database has no ws_setup role, so the disarm ALTER refuses with 42704",
    );
    let CoreError::Database(db) = err else {
        panic!("the refusal is the server's, not a config error: {err:?}");
    };
    let db_err = db
        .as_database_error()
        .expect("the 42704 refusal is a database error");

    let code = db_err.code().map(|code| code.into_owned());
    let message = db_err.message().to_owned();

    assert_eq!(
        code.as_deref(),
        Some("42704"),
        "the undefined role is refused with SQLSTATE 42704: {code:?}"
    );
    assert!(
        message.contains(&format!("role \"{SETUP_ROLE}\" does not exist")),
        "the server names exactly the setup role: {message}"
    );
}
