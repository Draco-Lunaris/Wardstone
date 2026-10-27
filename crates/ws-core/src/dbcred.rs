//! The database login credential: its Postgres verifier, the typeable
//! generated password, and the crash-safe rotation that installs them
//! (Task 4 — the seal-at-creation plan).
//!
//! # Why a verifier-only rotation
//!
//! The previous rotation interpolated the fresh PLAINTEXT credential
//! into `ALTER … PASSWORD '<plaintext>'` — a statement that server
//! logging (`log_statement='all'`), `pg_stat_activity`, and network
//! captures all see. Postgres accepts a full SCRAM-SHA-256 verifier
//! string in the PASSWORD position and stores it AS-IS: the server
//! never needs the plaintext, and a statement that carries only the
//! verifier leaks nothing reusable. The plaintext exists (in the
//! sealed envelope and protected RAM) exactly where the old rotation
//! had it — the ALTER is the only step that changed.
//!
//! # The crash-safe pending envelope
//!
//! The old order — ALTER first, envelope second — had an unhealable
//! window: a crash between the two leaves the role rotated and the
//! sealed credential stale, and the operator is in the recovery
//! runbook. The new order writes the fresh credential to a
//! `<envelope>.pending` sibling FIRST (sealed, the same envelope
//! format), then ALTERs, then promotes the pending by atomic rename:
//!
//! - crash after the promote: complete — the envelope holds the live
//!   credential;
//! - crash between the ALTER and the promote: recoverable — the
//!   pending holds the LIVE credential; [`open_db_credential`] offers
//!   both, the caller tries the pending first and promotes it on
//!   success;
//! - crash before the ALTER: recoverable — the pending never became
//!   live; it is refused with Postgres `28P01` (invalid_password), the
//!   caller deletes it and the current credential connects.
//!
//! # Serialization
//!
//! [`rotate_db_credential`] takes a session-level advisory lock
//! ([`ROTATION_LOCK_KEY`]) on ITS OWN connection first: two tasks or
//! processes racing the rotation serialize instead of interleaving
//! ALTERs and rewrites. The lock is released on every return path —
//! see [`RotationLockGuard`] for the panic/cancellation path.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use rand::{rngs::SysRng, TryRng};
use sqlx::PgConnection;
use ws_secmem::SecretBuf;
use zeroize::Zeroizing;

use crate::crypto::{
    is_safe_role_identifier, protected_memory_failure, KeyEnvelope, PROD_KDF_PARAMS,
};
use crate::error::CoreError;

/// The SCRAM iteration count the rotation and the `db-verifier` mint
/// pin: RFC 7677's floor is 4096 and Postgres itself defaults to 4096.
pub const SCRAM_ITERATIONS: u32 = 4096;

/// The advisory-lock key serializing credential rotations: ASCII
/// "WARDST" + "RT" — deliberately OUTSIDE the `0x…00xx` family the
/// DB-gated test suites' keys come from (CLAUDE.md's table), so a test
/// suite's lock can never serialize against a production rotation.
pub const ROTATION_LOCK_KEY: i64 = 0x0057_4144_5354_5254;

/// The Postgres SCRAM-SHA-256 password verifier for `password` (RFC
/// 5802/7677): `SCRAM-SHA-256$<iter>:<b64 salt>$<b64 StoredKey>:<b64
/// ServerKey>` — the exact string form Postgres stores AS-IS when it
/// rides `ALTER ROLE … PASSWORD '<verifier>'`. The derivation (RFC
/// 5802 §3 under the `SCRAM-SHA-256` profile): SaltedPassword =
/// PBKDF2-HMAC-SHA-256(password, salt, iterations); ClientKey =
/// HMAC-SaltedPassword("Client Key"); StoredKey = SHA-256(ClientKey);
/// ServerKey = HMAC-SaltedPassword("Server Key") — all via `ring`
/// (`pbkdf2`, `hmac`, `digest`), keeping the crypto-provider graph to
/// the same `ring` the rustls pins already force. The intermediate
/// SaltedPassword is zeroized on drop; the verifier itself is derived
/// data — safe to store in Postgres by design.
pub fn scram_verifier(password: &[u8], salt: &[u8; 16], iterations: u32) -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    // ring's PBKDF2 takes a non-zero count; the pin is 4096, and a zero
    // caller value is clamped to one rather than panicking (the house
    // style has no unwrap outside tests).
    let iterations = std::num::NonZeroU32::new(iterations).unwrap_or(std::num::NonZeroU32::MIN);
    let mut salted_password = Zeroizing::new([0u8; 32]);
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password,
        salted_password.as_mut(),
    );
    let client_key = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, salted_password.as_ref()),
        b"Client Key",
    );
    let stored_key = ring::digest::digest(&ring::digest::SHA256, client_key.as_ref());
    let server_key = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, salted_password.as_ref()),
        b"Server Key",
    );
    format!(
        "SCRAM-SHA-256${}:{}${}:{}",
        iterations.get(),
        B64.encode(salt),
        B64.encode(stored_key.as_ref()),
        B64.encode(server_key.as_ref()),
    )
}

/// A fresh OS-entropy 16-byte SCRAM salt — the one entropy call the
/// verifier's callers need besides the credential itself, kept here so
/// no consumer of this module touches `rand` directly.
pub fn fresh_scram_salt() -> Result<[u8; 16], CoreError> {
    let mut salt = [0u8; 16];
    SysRng.try_fill_bytes(&mut salt).map_err(|e| {
        CoreError::Crypto(format!("os entropy unavailable for the verifier salt: {e}"))
    })?;
    Ok(salt)
}

/// A fresh database login credential: 32 OS-entropy bytes as RFC 4648
/// base32, lowercase, unpadded — 52 characters of `a-z2-7`, typeable
/// without quotes at a shell, in an `.env` file, or at a `psql`
/// prompt. The returned [`SecretBuf`] lives in the process's
/// `memfd_secret` pool (see ws-secmem): never swapped, wiped on drop.
pub fn generate_db_password() -> Result<SecretBuf, CoreError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    SysRng.try_fill_bytes(bytes.as_mut()).map_err(|e| {
        CoreError::Crypto(format!("os entropy unavailable for the db credential: {e}"))
    })?;
    let encoded = Zeroizing::new(base32_lower_unpadded(bytes.as_ref()));
    let pool = ws_secmem::global().map_err(protected_memory_failure)?;
    pool.alloc_copy(encoded.as_bytes())
        .map_err(protected_memory_failure)
}

/// RFC 4648 base32, LOWERCASE, unpadded — inlined rather than pulled
/// in as a dependency (the task's no-new-dependency stance): 5-bit
/// groups over MSB-first bits, alphabet `a-z2-7`, no `=` padding
/// (32 bytes encode to 52 characters; the trailing bit of the last
/// group is zero-padded, which is the encoding's own contract, not a
/// truncation).
fn base32_lower_unpadded(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[index] as char);
    }
    out
}

/// The two credentials an unlock must consider: the envelope's current
/// one, and the `.pending` sibling a rotation crash left behind (see
/// the module docs for which crash window leaves which candidate
/// LIVE). The custody is [`Zeroizing`] — the type
/// [`KeyEnvelope::open_envelope`] already returns — rather than a
/// fresh protected copy: duplicating the plaintext into a second
/// buffer would only widen its footprint for the microseconds the
/// caller needs it.
pub struct DbCredentialCandidates {
    /// The envelope's current sealed credential.
    pub current: Zeroizing<Vec<u8>>,
    /// The `.pending` sibling's credential, when one exists.
    pub pending: Option<Zeroizing<Vec<u8>>>,
}

/// Open the envelope's current credential and, when a `.pending`
/// sibling exists, that one too. The CALLER's rule (the unlock): try
/// `pending` first — it connecting means the crash was after the
/// ALTER and the pending is LIVE, so promote it; its `28P01` refusal
/// means the crash was before the ALTER, so delete it and connect
/// with `current`.
///
/// A `.pending` that fails to open is an error, not a silent skip: a
/// damaged pending may or may not have been the live one, and that
/// call is the operator's, not the code's.
pub fn open_db_credential(
    envelope_path: &Path,
    passphrase: &[u8],
) -> Result<DbCredentialCandidates, CoreError> {
    let passphrase = std::str::from_utf8(passphrase)
        .map_err(|_| CoreError::Config("the volume passphrase is not valid UTF-8".to_string()))?;
    let current = KeyEnvelope::open_envelope(envelope_path, passphrase)?;
    let pending_path = pending_path(envelope_path);
    let pending = if pending_path.exists() {
        Some(KeyEnvelope::open_envelope(&pending_path, passphrase)?)
    } else {
        None
    };
    Ok(DbCredentialCandidates { current, pending })
}

/// The pending sibling's path: `<envelope>.pending` (an `OsString`
/// push, so the rule survives any extension the envelope path itself
/// carries — unlike `with_extension`, which would eat one).
pub fn pending_path(envelope_path: &Path) -> PathBuf {
    let mut name = envelope_path.as_os_str().to_os_string();
    name.push(".pending");
    PathBuf::from(name)
}

/// Promote the pending sibling over the envelope (the rotation's
/// final step, and the crash-window recovery's): the atomic rename IS
/// the promotion — the envelope holds either the old or the new
/// credential, never a torn mix — with a parent-directory fsync after,
/// the same durability step the keys volume's other crash-atomic
/// writes use.
pub fn promote_pending(envelope_path: &Path) -> Result<(), CoreError> {
    let pending = pending_path(envelope_path);
    std::fs::rename(&pending, envelope_path).map_err(|e| envelope_io(envelope_path, e))?;
    sync_parent(envelope_path)
}

/// Delete the pending sibling (the `28P01` rule: a pending that cannot
/// log in was never made live). Idempotent — an absent pending is the
/// desired end state.
pub fn discard_pending(envelope_path: &Path) -> Result<(), CoreError> {
    let pending = pending_path(envelope_path);
    match std::fs::remove_file(&pending) {
        Ok(()) => sync_parent(envelope_path),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(envelope_io(envelope_path, e)),
    }
}

/// Envelope io failures are configuration/environment problems; the
/// message names the path and never any credential material.
fn envelope_io(path: &Path, e: std::io::Error) -> CoreError {
    CoreError::Config(format!(
        "the db credential envelope {}: {e}",
        path.display()
    ))
}

/// fsync the envelope's parent directory — the durability step every
/// crash-atomic rename/delete needs (the name change is not durable
/// until the directory entry is synced).
fn sync_parent(path: &Path) -> Result<(), CoreError> {
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| envelope_io(path, e))?;
    }
    Ok(())
}

/// The ALTER, as its own step: `ALTER ROLE <role> PASSWORD
/// '<verifier>'` — Postgres stores the verifier string AS-IS and the
/// PLAINTEXT behind it is what logs in. Postgres accepts no bind
/// parameters in utility statements, so the verifier rides the
/// statement text: it carries no secret (the plaintext never appears
/// in it), the role is validated to [`is_safe_role_identifier`], and
/// the verifier's base64 alphabet cannot escape its single-quoted
/// literal (quote-doubled anyway, belt and braces).
///
/// `#[doc(hidden)]` because the signature is the sanctioned seam the
/// rotation suite's statement-capture test wraps: production
/// ([`rotate_db_credential`]) calls this with the same SQL in the
/// same order, so wrapping this executor observes the statement the
/// rotation actually sends.
#[doc(hidden)]
pub async fn alter_role_password(
    executor: impl sqlx::PgExecutor<'_>,
    role: &str,
    verifier: &str,
) -> Result<(), CoreError> {
    if !is_safe_role_identifier(role) {
        return Err(CoreError::Config(format!(
            "the db login role name {role:?} is not a safe identifier"
        )));
    }
    sqlx::query(&format!(
        "ALTER ROLE {role} PASSWORD '{}'",
        verifier.replace('\'', "''")
    ))
    .execute(executor)
    .await?;
    Ok(())
}

/// The passwordless bootstrap role the first-run setup door connects
/// as: it exists only in the bundled deployment, where the shared unix
/// socket's peer credentials (`SO_PEERCRED`) are the whole
/// authentication — the server trusts the connecting OS user and no
/// password is ever set. The name is underscored, so it is SQL-unquoted
/// everywhere (spec's call 1).
pub const SETUP_ROLE: &str = "ws_setup";

/// Close the setup door once first-run setup has rotated the
/// `wardstone` role's credential: `ALTER ROLE … NOLOGIN` makes
/// [`SETUP_ROLE`] unable to log in again. The statement is the same
/// format-inlined shape [`alter_role_password`] uses (Postgres utility
/// statements accept no bind parameters), carries no secret, and is
/// idempotent — a role already `NOLOGIN` alters cleanly.
pub async fn disarm_setup_role(executor: impl sqlx::PgExecutor<'_>) -> Result<(), CoreError> {
    sqlx::query(&format!("ALTER ROLE {SETUP_ROLE} NOLOGIN"))
        .execute(executor)
        .await?;
    Ok(())
}

/// The advisory lock's lease over the rotation connection (Ruling 15: a
/// SESSION-level `pg_advisory_lock` on a pooled connection that is
/// never unlocked stalls every later rotation that lands on that
/// session). The guard exists because async `Drop` is impossible:
///
/// - every RESULT path runs [`RotationLockGuard::release`], which
///   AWAITS the unlock before the rotation returns — the common case
///   never leaks the session lock;
/// - the PANIC/cancellation path (the rotation future dropped
///   mid-await, or a panic unwinding through it) runs [`Drop`], which
///   drives the unlock query a single `poll` with the noop waker: the
///   first poll writes the statement to the socket, so the server
///   executes the unlock even though the response is never read. The
///   connection is SPENT afterwards (an unread response sits in its
///   buffer) — a caller that survives the unwind must close it, not
///   pool it. A `Pending` from that single poll (nothing written)
///   leaves the lock held until the session ends: the honest failure,
///   and the reason the awaited `release` on every result path is the
///   contract, with `Drop` only the net.
struct RotationLockGuard<'a> {
    conn: &'a mut PgConnection,
    armed: bool,
}

impl RotationLockGuard<'_> {
    /// The RESULT-path release: awaited on every return from
    /// [`rotate_db_credential`], success or failure. Disarms FIRST —
    /// after this the Drop net never retries (a second unlock on an
    /// already-released session would log a spurious advisory
    /// warning). An unlock failure surfaces as the rotation's error
    /// only when the steps themselves succeeded; a failed-steps error
    /// wins over it.
    async fn release(mut self) -> Result<(), CoreError> {
        self.armed = false;
        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(ROTATION_LOCK_KEY)
            .execute(&mut *self.conn)
            .await?;
        Ok(())
    }
}

impl Drop for RotationLockGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        use std::future::Future as _;

        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut unlock = std::pin::pin!(sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(ROTATION_LOCK_KEY)
            .execute(&mut *self.conn));
        let _ = unlock.as_mut().poll(&mut cx);
        // The connection is spent either way — see the struct docs.
    }
}

/// Mint a fresh database login credential, ALTER `role` to it in
/// VERIFIER form over `conn`, and seal the credential under the
/// volume's passphrase — the ONE home for the rotation step the setup
/// conversion, the api's per-unlock rotation, and the ui's recovery
/// re-seed all share. Returns the fresh credential so the caller can
/// reconnect with it.
///
/// The order (the crash-safe pending envelope — see the module docs):
/// `pg_advisory_lock(ROTATION_LOCK_KEY)` on `conn` → generate → write
/// `<envelope>.pending` (sealed, the same envelope format) → `ALTER
/// ROLE <role> PASSWORD '<verifier>'` → promote the pending by atomic
/// rename → unlock. The advisory lock is session-level on `conn` and
/// is released on every return path ([`RotationLockGuard`] — Ruling
/// 15); `conn` must be a DEDICATED connection, not a shared pool, so
/// the lock's session is exactly the rotation's.
///
/// The statement the ALTER sends never carries the plaintext — only
/// the verifier — and neither the errors nor any log line anywhere in
/// this flow carry credential material.
pub async fn rotate_db_credential(
    conn: &mut PgConnection,
    role: &str,
    envelope_path: &Path,
    passphrase: &[u8],
    generation: u64,
) -> Result<SecretBuf, CoreError> {
    if !is_safe_role_identifier(role) {
        return Err(CoreError::Config(format!(
            "the db login role name {role:?} is not a safe identifier"
        )));
    }
    // The envelope passphrase is operator text; the bridge only fails
    // on non-UTF-8 bytes, and the error names no material.
    let passphrase = std::str::from_utf8(passphrase)
        .map_err(|_| CoreError::Config("the volume passphrase is not valid UTF-8".to_string()))?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(ROTATION_LOCK_KEY)
        .execute(&mut *conn)
        .await?;
    let mut guard = RotationLockGuard { conn, armed: true };
    let outcome = rotate_steps(&mut guard, role, envelope_path, passphrase, generation).await;
    // The release is AWAITED on every path — Ok or Err — before the
    // rotation returns (Ruling 15: no result path may leak the session
    // lock).
    let release = guard.release().await;
    match (outcome, release) {
        (Ok(fresh), Ok(())) => Ok(fresh),
        (Err(err), _) => Err(err),
        (Ok(_), Err(err)) => Err(err),
    }
}

/// The rotation's payload steps, under the guard: generate, seal the
/// pending, ALTER, promote. The steps run in this exact order for the
/// crash windows the module docs pin.
async fn rotate_steps(
    guard: &mut RotationLockGuard<'_>,
    role: &str,
    envelope_path: &Path,
    passphrase: &str,
    generation: u64,
) -> Result<SecretBuf, CoreError> {
    let fresh = generate_db_password()?;
    let salt = fresh_scram_salt()?;
    let verifier = scram_verifier(&fresh, &salt, SCRAM_ITERATIONS);
    let pending = pending_path(envelope_path);
    KeyEnvelope::write_envelope(&pending, passphrase, &fresh, PROD_KDF_PARAMS, generation)?;
    alter_role_password(&mut *guard.conn, role, &verifier).await?;
    promote_pending(envelope_path)?;
    Ok(fresh)
}
