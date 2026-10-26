//! Argon2id hashing for user-chosen passwords.
//!
//! The `users.credential_hash` column stores the PHC string this module
//! produces. Bearer-token material is *not* hashed here: token digests use
//! plain SHA-256 (Task 8), because argon2id's slowness is only a virtue for
//! human-chosen secrets.
//!
//! Every argon2 pass runs inside a locked `ws-secmem` slot. argon2 is
//! memory-hard by design — the house parameters want 64 MiB of scratch —
//! and on the heap that scratch is swappable, dumpable and readable through
//! `/proc/<pid>/mem`, with the password's own key-dependent state written
//! all over it. There is no heap fallback: a slot is waited for, and an
//! `m_cost` the slot cannot hold is refused.
//!
//! Acquiring a slot **blocks the calling OS thread** (see
//! [`ws_secmem::SecMem::hash_slot`]), so async callers reach both functions
//! through `tokio::task::spawn_blocking` — which argon2's
//! multi-hundred-millisecond CPU burn already required.

use argon2::password_hash::phc::{Output, PasswordHash, Salt};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{rngs::SysRng, TryRng};
use ws_secmem::{SecMemError, SecretBuf};

use crate::error::AuthError;

/// Argon2id parameters, per the house calibration (`pm-auth/src/password.rs`,
/// OWASP-recommended): 64 MiB of memory, 3 passes, a single lane. The
/// `ws-secmem` password-hash slots are sized for exactly this `m_cost`.
const M_COST: u32 = 65536; // 64 MiB
const T_COST: u32 = 3; // 3 iterations
const P_COST: u32 = 1; // 1 thread

/// Salt length in bytes: the PHC string format's recommendation, and what
/// argon2's own encoder draws, so the strings this module writes stay the
/// same shape as the ones already stored.
const SALT_LEN: usize = 16;

/// Tag length in bytes: `Params::DEFAULT_OUTPUT_LEN`, which is what the stock
/// encoder produces for parameters that name no output length — the length
/// every `users.credential_hash` row already carries.
const OUTPUT_LEN: usize = 32;

/// The argon2 version this module computes, and the only one it will
/// recompute for a stored hash. `0x13` is 19 decimal, the `v=19` field.
const VERSION: Version = Version::V0x13;

/// Hash a plaintext password with Argon2id and a fresh random salt.
///
/// Returns the PHC string format hash suitable for storage. The string is
/// assembled here rather than by argon2's `PasswordHasher`, because that
/// trait allocates its own argon2 memory; the fields are the stock
/// encoder's, pinned by `a_hash_round_trips_and_matches_the_reference_encoder`.
///
/// # Errors
///
/// [`AuthError::Crypto`] if OS entropy is unavailable, protected memory
/// cannot be obtained, or argon2 refuses the inputs.
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    // A fresh salt per call, so two hashes of the same password differ.
    let mut salt = [0u8; SALT_LEN];
    SysRng.try_fill_bytes(&mut salt).map_err(|e| {
        AuthError::Crypto(format!("os entropy unavailable for the password salt: {e}"))
    })?;

    let params = Params::new(M_COST, T_COST, P_COST, Some(OUTPUT_LEN))
        .map_err(|e| AuthError::Crypto(format!("invalid argon2id parameters: {e}")))?;
    let tag = derive(password, &salt, params)?;

    let salt_field = Salt::new(&salt).map_err(encoding_failure)?;
    let tag_field = Output::new(&tag).map_err(encoding_failure)?;
    Ok(format!(
        "${}$v={}$m={M_COST},t={T_COST},p={P_COST}${salt_field}${tag_field}",
        Algorithm::Argon2id.as_str(),
        u32::from(VERSION),
    ))
}

/// Verify a plaintext password against a stored Argon2id PHC hash.
///
/// Returns `Ok(false)` — not an error — when the password is wrong; an error
/// means the stored hash itself is unusable. The comparison is
/// constant-time.
///
/// # Errors
///
/// [`AuthError::Crypto`] if the stored hash is malformed, names anything
/// other than argon2id v0x13, or asks for more memory than a locked slot
/// holds. A refused hash is refused *before* argon2 runs: the parameters
/// are checked against the slot first, and nothing is ever served from the
/// heap instead.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, AuthError> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| AuthError::Crypto(format!("invalid password hash format: {e}")))?;

    // Only argon2id v0x13 is recomputed. Computing argon2id for a hash that
    // names argon2i, argon2d or version 0x10 would answer a question nobody
    // asked — and always answer it "wrong password", which reads as a user
    // error rather than the stored-hash problem it is.
    if parsed.algorithm != Algorithm::Argon2id.ident() {
        return Err(AuthError::Crypto(format!(
            "stored password hash names {}, not argon2id",
            parsed.algorithm
        )));
    }
    // An absent `v=` field means argon2's default, which is 0x13 (the PHC
    // argon2 encoding treats the field as optional); any version that is
    // present and different is refused.
    if let Some(version) = parsed.version {
        if version != u32::from(VERSION) {
            return Err(AuthError::Crypto(format!(
                "stored password hash names argon2 version {version}, not 0x13"
            )));
        }
    }

    // The stored parameters are reused WHOLE — cost, tag length, and the
    // legacy `keyid`/`data` fields with them — so hashes minted under older
    // settings stay verifiable, within what a locked slot can hold. Taking
    // only the three costs would silently drop a field that feeds the
    // digest and turn a right password into a wrong one.
    let params = Params::try_from(&parsed)
        .map_err(|e| AuthError::Crypto(format!("invalid stored argon2id parameters: {e}")))?;
    let salt = parsed
        .salt
        .ok_or_else(|| AuthError::Crypto("stored password hash carries no salt".to_string()))?;
    let expected = parsed
        .hash
        .ok_or_else(|| AuthError::Crypto("stored password hash carries no tag".to_string()))?;

    let tag = derive(password, salt.as_ref(), params)?;

    // `phc::Output`'s `PartialEq` is its `CtEq` implementation, so this is a
    // constant-time comparison: the response time cannot be used to narrow
    // the right tag down byte by byte. The workspace's own argon2 stack
    // provides it; no separate constant-time crate is pulled in for it.
    let recomputed = Output::new(&tag).map_err(encoding_failure)?;
    Ok(recomputed == expected)
}

/// Run one argon2id pass in a locked password-hash slot, into protected
/// memory. `params` is used whole, so a caller verifying a stored hash
/// passes the stored parameters rather than a reconstruction of them.
///
/// Blocks until a slot frees. The returned [`SecretBuf`] lives in the
/// `memfd_secret` pool and is wiped on drop; the slot's scratch is wiped
/// when the guard drops at the end of this function.
fn derive(password: &str, salt: &[u8], params: Params) -> Result<SecretBuf, AuthError> {
    let mem = ws_secmem::global().map_err(protected_memory_failure)?;

    let output_len = params.output_len().unwrap_or(OUTPUT_LEN);
    // What argon2 will actually index: `m_cost` rounded to the lane/segment
    // geometry, and clamped up for an absurdly small `m_cost`. Sizing the
    // lease by this, rather than by the raw `m_cost`, is what makes the
    // refusal below exact.
    let blocks_needed = u32::try_from(params.block_count())
        .map_err(|_| AuthError::Crypto("the argon2id m_cost is out of range".to_string()))?;
    let hasher = Argon2::new(Algorithm::Argon2id, VERSION, params);

    // The slot comes first, then the arena. Both are finite pool resources,
    // so they are always taken in this order — a thread that waited for a
    // slot while holding arena space could deadlock against one holding a
    // slot and waiting for arena space.
    //
    // Acquiring the slot blocks the OS thread until one frees (a `Condvar`,
    // invisible to an async runtime) — callers are inside `spawn_blocking`.
    let mut slot = mem.hash_slot();
    // Refused here, before a single argon2 pass: an `m_cost` the slot
    // cannot hold has no heap fallback to fall back to.
    let scratch = slot
        .blocks(blocks_needed)
        .map_err(protected_memory_failure)?;
    let mut tag = mem.alloc(output_len).map_err(protected_memory_failure)?;
    hasher
        .hash_password_into_with_memory(password.as_bytes(), salt, &mut tag, scratch)
        .map_err(|e| AuthError::Crypto(format!("argon2id hashing failed: {e}")))?;
    Ok(tag)
}

/// Map a protected-memory failure into the auth vocabulary. `SecMemError`'s
/// own `Display` names the protection that failed and the knob to turn, and
/// carries no secret material by construction.
fn protected_memory_failure(error: SecMemError) -> AuthError {
    AuthError::Crypto(format!("protected memory for argon2id: {error}"))
}

/// Map a PHC field-encoding failure. The message names the field, never its
/// bytes.
fn encoding_failure(error: argon2::password_hash::phc::Error) -> AuthError {
    AuthError::Crypto(format!("the password hash could not be encoded: {error}"))
}
