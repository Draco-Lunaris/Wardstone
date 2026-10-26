//! Fast (no database) coverage of `ws_core::dbcred`: the SCRAM-SHA-256
//! verifier's shape and the generated credential's typeable form.
//!
//! The Postgres-facing half of the module (the rotation itself, the
//! crash-window recovery) lives in `rotation_test.rs` — DB-gated, advisory
//! key `0x0018`.

use ws_core::dbcred::{generate_db_password, scram_verifier};

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
