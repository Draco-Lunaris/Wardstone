//! Secret-encryption helper: AEAD (XChaCha20-Poly1305) sealing of small
//! secrets at rest — today the TOTP and WebAuthn secrets, encrypted in the
//! `users` row, and the OIDC client secret, sealed in the provider
//! configuration row and opened only through the shared `to_auth_config`
//! conversion (its two consumers: the login flow's token exchange and
//! the saved-config probe) — with a key that exists only as a
//! protected-arena
//! reservation (minted at setup straight into
//! `secret-encryption.envelope`, opened at the unlock handshake),
//! analogous to the house's `pm-core/src/crypto.rs` helper.
//!
//! [`SecretBox::from_key`] takes the ALREADY-UNWRAPPED arena buffer.
//! [`SecretBox::seal`] encrypts with a fresh 24-byte OS-entropy nonce and
//! returns `(ciphertext, nonce)`; [`SecretBox::open`] decrypts, returning
//! the plaintext zeroized on drop.
//!
//! Error contract: key-volume io problems (the relay-nonce claim's
//! read/write/remove) are [`CoreError::Config`] — an operator/environment
//! problem; cryptographic failures (os-entropy exhaustion, AEAD
//! authentication failure on tampered or wrong-key ciphertext, wrong
//! nonce length) are [`CoreError::Crypto`]. No error message ever carries
//! key or plaintext material.

use std::fs;
use std::path::Path;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use rand::{rngs::SysRng, TryRng};
use ws_secmem::{SecMemError, SecretBuf};
use zeroize::{Zeroize, Zeroizing};

use crate::error::CoreError;

/// Key length in bytes (XChaCha20-Poly1305 key size): the
/// secret-encryption key and the passphrase-derived envelope KEK.
const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 extended-nonce length in bytes.
const NONCE_LEN: usize = 24;

/// Holds the 32-byte secret-encryption key in the process's protected
/// arena (a `ws_secmem::SecretBuf`: never swapped, never in a core dump,
/// volatilely wiped on drop) and seals secrets under fresh
/// XChaCha20-Poly1305 nonces.
///
/// Deliberately not `Clone` — a copy would be a second plaintext of the
/// same key, and the arena's whole point is that exactly one exists.
/// Shared custody is `Arc<SecretBox>`.
pub struct SecretBox {
    key: SecretBuf,
}

impl SecretBox {
    /// Construct from an ALREADY-UNWRAPPED key held in the protected
    /// arena (the sealed-at-rest unlock flow: the SecretBox key comes
    /// from its envelope under the operator passphrase-KEK and lives in
    /// the process's `memfd_secret` pool for the process's life, wiped on
    /// drop).
    ///
    /// The buffer must be exactly 32 bytes; a different length
    /// is refused at use time (seal/open fail with a typed crypto error),
    /// because the constructor is infallible by design — the unlock
    /// handshake has no recovery path a fallible form would serve.
    pub fn from_key(key: SecretBuf) -> Self {
        SecretBox { key }
    }

    /// Seal `plaintext` under a fresh 24-byte OS-entropy nonce, returning
    /// `(ciphertext, nonce)`. The ciphertext includes the appended
    /// Poly1305 authentication tag.
    pub fn seal(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CoreError> {
        let cipher = cipher_for(&self.key)?;
        let mut nonce = [0u8; NONCE_LEN];
        SysRng.try_fill_bytes(&mut nonce).map_err(|e| {
            CoreError::Crypto(format!("os entropy unavailable for the AEAD nonce: {e}"))
        })?;
        let ciphertext = cipher
            .encrypt(&XNonce::from(nonce), plaintext)
            .map_err(|_| CoreError::Crypto("secret sealing failed".to_string()))?;
        Ok((ciphertext, nonce.to_vec()))
    }

    /// Open a seal: decrypt `ciphertext` under `nonce`, with the plaintext
    /// zeroized on drop.
    ///
    /// A wrong key or tampered ciphertext/nonce fails AEAD authentication
    /// and surfaces as [`CoreError::Crypto`] — never as "garbage output".
    pub fn open(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        let cipher = cipher_for(&self.key)?;
        let nonce = XNonce::try_from(nonce).map_err(|_| {
            CoreError::Crypto(format!("AEAD nonce must be {NONCE_LEN} bytes").to_string())
        })?;
        let plaintext = cipher.decrypt(&nonce, ciphertext).map_err(|_| {
            CoreError::Crypto(
                "secret unsealing failed: wrong key or damaged ciphertext/nonce".to_string(),
            )
        })?;
        Ok(Zeroizing::new(plaintext))
    }
}

/// `len` OS-entropy bytes, hex-encoded: the relay nonce's material
/// (and any future random-string need). The OS source failing is a
/// typed error, never a panic.
pub fn random_hex(len: usize) -> Result<String, CoreError> {
    let mut bytes = vec![0u8; len];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| CoreError::Crypto(format!("os entropy unavailable: {e}")))?;
    Ok(hex::encode(bytes))
}

/// Mint a fresh one-time relay nonce into the RELAY DIR (Task 10, G1:
/// the claim is an authenticator, so it lives beside the api's Unix
/// socket in the host-/run relay directory — never the persistent keys
/// volume; the final review's F2, spec §10: the ui→api unlock call
/// must not be replayable by anything else on the box). Writing this
/// file IS the claim — only a relay-dir holder can mint — and each
/// mint REPLACES the previous claim, so a nonce captured from an
/// earlier relay attempt is dead the moment the ui re-offers the form.
/// The file is owner-only and crash-atomic like every other secret-
/// adjacent write; it is never sealed (it must be readable while the
/// instance is locked, and it carries no long-lived secret).
pub fn mint_relay_nonce(relay_dir: &Path) -> Result<String, CoreError> {
    let nonce = random_hex(32)?;
    write_private(&relay_dir.join(RELAY_NONCE_FILE), nonce.as_bytes())?;
    Ok(nonce)
}

/// Consume the relay nonce: `Ok(())` only when `nonce` matches the
/// relay dir's claim, and the match DELETES the file — one use, so a
/// captured POST is dead after the real unlock. A mismatch or a missing
/// claim is a typed refusal that leaves the file alone; the real
/// holder's next relay mints a fresh claim anyway. The nonce is 256
/// bits of OS entropy, not a long-lived secret — a plain comparison.
/// The CALLER serializes the check+delete (the api's unlock window):
/// two concurrent same-nonce POSTs must not both consume one claim.
pub fn consume_relay_nonce(relay_dir: &Path, nonce: &str) -> Result<(), CoreError> {
    let claim = relay_dir.join(RELAY_NONCE_FILE);
    let expected = fs::read_to_string(&claim).map_err(|e| key_io_err(&claim, e))?;
    if expected != nonce {
        return Err(CoreError::Crypto(
            "the relay nonce does not match the volume's claim".to_string(),
        ));
    }
    fs::remove_file(&claim).map_err(|e| key_io_err(&claim, e))?;
    Ok(())
}

/// Build an XChaCha20-Poly1305 cipher from the key bytes, which must be
/// exactly 32 long — a different length cannot come from a well-formed
/// key source and is refused as a typed crypto error rather than a
/// panic.
///
/// The transient `Key` copy is zeroized the moment the cipher has taken
/// its own; the cipher's retained copy is zeroized on drop via the
/// `chacha20poly1305` `zeroize` feature.
fn cipher_for(key: &[u8]) -> Result<XChaCha20Poly1305, CoreError> {
    let mut key = Key::try_from(key)
        .map_err(|_| CoreError::Crypto("secret-encryption key is not 32 bytes".to_string()))?;
    let cipher = XChaCha20Poly1305::new(&key);
    Zeroize::zeroize(&mut *key);
    Ok(cipher)
}

/// Map a protected-memory failure into the core vocabulary. `SecMemError`'s
/// own `Display` names the protection that failed and the knob to turn, and
/// carries no key or passphrase material by construction. Shared with
/// `dbcred`'s allocations (the generated login credential's protected
/// copy).
pub(crate) fn protected_memory_failure(error: SecMemError) -> CoreError {
    CoreError::Crypto(format!("protected memory for the master-key KDF: {error}"))
}

/// Write a file containing key material, mode 0600 on unix, and
/// crash-atomically: on unix the bytes land in a sibling `.tmp` file that
/// is fsynced and renamed over the destination (with a parent-directory
/// fsync after the rename), so a crash mid-write can never leave a
/// truncated key under the real name; a failed write removes the
/// temporary rather than leaving a stale copy of the raw key. A `.tmp`
/// suffix is safe here because the key path is a dedicated file.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), CoreError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let tmp = path.with_extension("tmp");
        let write = || -> Result<(), CoreError> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| key_io_err(path, e))?;
            file.write_all(bytes).map_err(|e| key_io_err(path, e))?;
            file.sync_all().map_err(|e| key_io_err(path, e))?;
            drop(file);
            set_permissions(&tmp)?;
            fs::rename(&tmp, path).map_err(|e| key_io_err(path, e))?;
            if let Some(parent) = path.parent() {
                fs::File::open(parent)
                    .and_then(|dir| dir.sync_all())
                    .map_err(|e| key_io_err(path, e))?;
            }
            Ok(())
        };
        let result = write();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes).map_err(|e| key_io_err(path, e))
    }
}

/// Force the exact 0600 permission bits (not umask-masked), unix only. A
/// key file that cannot be protected is fatal, never a warning.
#[cfg(unix)]
fn set_permissions(path: &Path) -> Result<(), CoreError> {
    use std::os::unix::fs::PermissionsExt;

    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms).map_err(|e| key_io_err(path, e))
}

/// Key-file io failures are configuration/environment problems.
fn key_io_err(path: &Path, e: std::io::Error) -> CoreError {
    CoreError::Config(format!(
        "secret-encryption key file {}: {e}",
        path.display()
    ))
}

/// The operator master passphrase, derived into a KEK, and the sealed
/// envelope file format (the sealed-at-rest design): every sensitive file
/// on the keys volume is an envelope — argon2id KDF parameters + a fresh
/// salt per write, the plaintext AEAD-encrypted under the derived key.
/// `write_envelope`/`open_envelope` are file-shaped and crash-atomic; the
/// KEK exists only in RAM for the process lifetime and is zeroized on
/// drop.
///
/// A wrong passphrase fails AEAD authentication and surfaces as
/// [`CoreError::Crypto`] — never garbage output; a missing/malformed
/// envelope is [`CoreError::Config`] where the path is the issue.
///
/// Version 2 adds the `generation` counter (Task 4b, the master-passphrase
/// change): every envelope names the passphrase epoch it was sealed in,
/// so a change that crashed mid-re-wrap is DETECTED (the generations
/// disagree) and its completion re-offered at the next unlock. Version-1
/// files predate the counter; there are none in the wild (the sealed
/// format ships with this change), so they refuse loudly instead of
/// silently defaulting.
pub const ENVELOPE_VERSION: u32 = 2;

/// The production KDF parameters: argon2id at 256 MiB / 3 passes targets
/// the ~1 s unlock latency budget while making off-box brute force meet
/// real cost. The parameters travel INSIDE each envelope, so a deployed
/// tuning change does not strand old envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

/// Production unlock parameters.
pub const PROD_KDF_PARAMS: KdfParams = KdfParams {
    m_cost: 262_144,
    t_cost: 3,
    p_cost: 1,
};

/// The sealed-volume file names — ONE home for the contract every process
/// shares (the binary's boot predicate, ws-web's setup conversion, and
/// ws-api's unlock builder all speak these exact names). They live here,
/// beside the envelope format itself, because ws-core is the one crate
/// all three consumers can see; re-exported where the historical homes
/// were (ws-web's setup module) so callers keep their paths.
pub const MASTER_ENVELOPE_FILE: &str = "master.envelope";
/// The JWT signing/verification pair, sealed as one JSON body.
pub const JWT_ENVELOPE_FILE: &str = "jwt-keys.envelope";
/// The secret-encryption key (the TOTP/OIDC SecretBox).
pub const SECRET_ENVELOPE_FILE: &str = "secret-encryption.envelope";
/// The CURRENT database credential: rotated and re-sealed at every
/// unlock, so a leaked credential dies at the next one.
pub const DB_CREDENTIAL_ENVELOPE_FILE: &str = "db-credential.envelope";
/// The one-time relay nonce's claim file (spec §10): the ui process
/// mints it into the RELAY DIR — the Unix socket's own directory
/// (`socket.parent()/relay-nonce`, Task 10: no second env var names it)
/// — and the api consumes it on the unlock relay. Never sealed itself
/// (it must be readable while the instance is locked) and never on the
/// persistent keys volume (G1: it is an authenticator, and the relay
/// dir is host-/run-backed).
pub const RELAY_NONCE_FILE: &str = "relay-nonce";

/// Percent-encode a URL userinfo component — the typed database
/// password being spliced into a connection URL: every byte outside the
/// RFC 3986 unreserved set `[A-Za-z0-9._~-]` becomes `%XX`, so a
/// password carrying URL-significant bytes (`@ : / % # ?` and friends)
/// cannot break the authority parse. Hand-rolled inline rather than a
/// new dependency — the same precedent as dbcred's base32. Unreserved
/// bytes map to themselves, so a generated base32 credential (`a-z2-7`)
/// encodes to itself bit-identically and every existing rotation and
/// restore flow is unchanged.
pub fn percent_encode_userinfo(component: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(component.len());
    for &byte in component.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'~' | b'-' => {
                out.push(byte as char)
            }
            _ => {
                out.push('%');
                out.push(HEX[usize::from(byte >> 4)] as char);
                out.push(HEX[usize::from(byte & 0x0f)] as char);
            }
        }
    }
    out
}

/// Substitute `password` into `url`'s `://user:password@host` authority —
/// inserting a `:password` when the URL carries none (the api's
/// password-less compose contract). The password splices in
/// PERCENT-ENCODED ([`percent_encode_userinfo`]): a typed password
/// carrying `@ : / % # ?` must not break the URL's own parse. The one
/// home for the parsing: the binary's boot rule, the ui's credential
/// unwrap, the api's unlock rotation, and the tests all speak this
/// exact shape. A URL with no `userinfo@` comes back unchanged (the
/// caller's error to raise).
pub fn substitute_db_password(url: &str, password: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let auth_start = scheme_end + 3;
    let Some(at) = url[auth_start..].find('@').map(|i| i + auth_start) else {
        return url.to_string();
    };
    let encoded = percent_encode_userinfo(password);
    match url[auth_start..at].rfind(':') {
        Some(colon_rel) => {
            let colon_abs = auth_start + colon_rel;
            format!("{}{}{}", &url[..=colon_abs], encoded, &url[at..])
        }
        None => format!("{}:{}{}", &url[..at], encoded, &url[at..]),
    }
}

/// The login role a `DATABASE_URL` authenticates as — the role whose
/// password the rotation ALTERs. Validated to the strict
/// alphanumeric+underscore shape ([`is_safe_role_identifier`]); a URL
/// with no `userinfo@` names no role to rotate. The one home for the
/// parse: the api's per-unlock rotation, the INIT conversion, and the
/// ui's recovery re-seed all speak this exact shape.
pub fn db_role_of(url: &str) -> Result<String, CoreError> {
    let Some(scheme_end) = url.find("://") else {
        return Err(CoreError::Config(
            "the database URL is not a URL".to_string(),
        ));
    };
    let auth_start = scheme_end + 3;
    let Some(at) = url[auth_start..].find('@').map(|i| i + auth_start) else {
        return Err(CoreError::Config(
            "the database URL carries no login role to rotate".to_string(),
        ));
    };
    let user_end = url[auth_start..at]
        .rfind(':')
        .map(|i| i + auth_start)
        .unwrap_or(at);
    let role = &url[auth_start..user_end];
    if !is_safe_role_identifier(role) {
        return Err(CoreError::Config(format!(
            "the database URL's login role {role:?} is not a safe identifier"
        )));
    }
    Ok(role.to_string())
}

/// The strict role-identifier shape every place that interpolates a
/// role name into SQL requires ([`db_role_of`] and `dbcred`'s ALTER):
/// non-empty ASCII alphanumeric + underscore — a role that cannot
/// escape its identifier position or a single-quoted literal.
pub(crate) fn is_safe_role_identifier(role: &str) -> bool {
    !role.is_empty() && role.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub struct KeyEnvelope {
    /// The derived key-encryption key, held in the process's
    /// `memfd_secret` pool: never swapped, never in a core dump, and not
    /// readable through `/proc/<pid>/mem`. Wiped when the envelope drops.
    kek: SecretBuf,
    salt: Vec<u8>,
    params: KdfParams,
}

impl KeyEnvelope {
    /// Derive the KEK from the passphrase with the stored salt + params.
    /// Deterministic per (passphrase, salt, params) — the envelope's own
    /// salt means every write re-randomizes.
    ///
    /// The argon2id pass runs in the pool's locked KDF slot, so neither the
    /// 256 MiB of memory-hard scratch nor the derived key ever touches the
    /// heap; there is no heap fallback, and an `m_cost` larger than the slot
    /// is refused.
    ///
    /// Acquiring the slot **blocks the calling OS thread** on a `Condvar`,
    /// which an async runtime can neither see nor work around, so an async
    /// caller must reach this through `tokio::task::spawn_blocking` — the
    /// ~1 s CPU burn already required that. Several callers do not yet:
    /// ws-web's setup conversion, ws-api's sealed shell and its master-key
    /// route still derive on a runtime thread. The later setup/boot/custody
    /// tasks of this plan own those call sites and move them; this task
    /// changes only where argon2's memory comes from.
    pub fn derive_kek(passphrase: &str, salt: &[u8], params: KdfParams) -> Result<Self, CoreError> {
        use argon2::{Algorithm, Argon2, Params, Version};
        let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
            .map_err(|_| CoreError::Crypto("argon2 parameters are out of range".to_string()))?;
        // What argon2 will actually index: `m_cost` rounded to the
        // lane/segment geometry. Leasing exactly that makes the
        // slot-too-small refusal exact rather than approximate.
        let blocks_needed = u32::try_from(argon_params.block_count())
            .map_err(|_| CoreError::Crypto("argon2 parameters are out of range".to_string()))?;

        let mem = ws_secmem::global().map_err(protected_memory_failure)?;
        // The slot comes first, then the arena. Neither order can deadlock
        // — the arena never waits, it refuses with `ArenaFull` — but the
        // slot is the resource with a queue behind it, and taking it first
        // means a thread parked on that queue is not also pinning arena
        // space for as long as it waits. Same order as ws-auth's password
        // hashing, so the two readers of the pool agree.
        let mut slot = mem.kdf_slot();
        let scratch = slot
            .blocks(blocks_needed)
            .map_err(protected_memory_failure)?;
        let mut kek = mem.alloc(KEY_LEN).map_err(protected_memory_failure)?;
        Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
            .hash_password_into_with_memory(passphrase.as_bytes(), salt, &mut kek, scratch)
            .map_err(|e| CoreError::Crypto(format!("the master-key derivation failed: {e}")))?;
        Ok(Self {
            kek,
            salt: salt.to_vec(),
            params,
        })
    }

    /// The KEK's bytes as the fixed-size array the AEAD helpers take, read
    /// straight out of protected memory — no copy. The length is
    /// [`KEY_LEN`] by construction ([`KeyEnvelope::derive_kek`] is the only
    /// constructor, and it reserves exactly that), so the error arm is a
    /// belt-and-braces check rather than a reachable path — and a check
    /// rather than an index, because the house style has no `unwrap`.
    fn kek_bytes(&self) -> Result<&[u8; KEY_LEN], CoreError> {
        <&[u8; KEY_LEN]>::try_from(&self.kek[..])
            .map_err(|_| CoreError::Crypto("the derived KEK is not 32 bytes".to_string()))
    }

    /// The envelope's recorded salt: the unlock re-derivation reads it from
    /// the envelope file itself; held here for wrap/unwrap callers.
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Read an envelope file's stored salt, KDF parameters, and generation
    /// WITHOUT opening it: the unlock's derive step and the mixed-state
    /// detection need them before the passphrase is known to be right
    /// (the derive itself is the check). A missing file is
    /// [`CoreError::Config`] naming the path; a file without a generation
    /// is malformed — the counter is load-bearing for the change flow,
    /// never an optional annotation.
    pub fn read_kdf_state(path: &Path) -> Result<(Vec<u8>, KdfParams, u64), CoreError> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let raw = fs::read(path)
            .map_err(|e| CoreError::Config(format!("key envelope {}: {e}", path.display())))?;
        let envelope: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|_| CoreError::Crypto("key envelope is not valid JSON".to_string()))?;
        let missing = || CoreError::Crypto("key envelope lacks KDF parameters".to_string());
        let salt = B64
            .decode(envelope["salt"].as_str().ok_or_else(missing)?)
            .map_err(|_| CoreError::Crypto("key envelope salt is not base64".to_string()))?;
        let m_cost = envelope["m_cost"].as_u64().ok_or_else(missing)? as u32;
        let t_cost = envelope["t_cost"].as_u64().ok_or_else(missing)? as u32;
        let p_cost = envelope["p_cost"].as_u64().ok_or_else(missing)? as u32;
        let generation = envelope["generation"]
            .as_u64()
            .ok_or_else(|| CoreError::Crypto("key envelope lacks a generation".to_string()))?;
        Ok((
            salt,
            KdfParams {
                m_cost,
                t_cost,
                p_cost,
            },
            generation,
        ))
    }

    /// The envelope's recorded generation: the passphrase epoch it was
    /// sealed in. The unlock reads the volume's generations to detect a
    /// change that crashed mid-re-wrap (they disagree); the change flow
    /// advances them all by one.
    pub fn read_generation(path: &Path) -> Result<u64, CoreError> {
        Ok(Self::read_kdf_state(path)?.2)
    }

    /// The envelope's recorded KDF parameters: the passphrase-change flow
    /// (Task 4b, the master-key rotation) re-wraps every envelope with the
    /// SAME parameters but a fresh salt under the new passphrase.
    pub fn params(&self) -> KdfParams {
        self.params
    }

    /// Write a sealed envelope file for `plaintext` under the passphrase:
    /// a fresh OS-entropy salt, the derivation, and a crash-atomic 0600
    /// write of the JSON form (version, KDF parameters, generation, salt,
    /// nonce, ciphertext — the plaintext's bytes appear NOWHERE in the
    /// file). The generation names the passphrase epoch (the conversion
    /// seals at 0, every completed change advances it by one, and the
    /// per-unlock rotation re-seals at the SAME generation it read).
    pub fn write_envelope(
        path: &Path,
        passphrase: &str,
        plaintext: &[u8],
        params: KdfParams,
        generation: u64,
    ) -> Result<(), CoreError> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let mut salt = [0u8; 16];
        SysRng.try_fill_bytes(&mut salt).map_err(|e| {
            CoreError::Crypto(format!("os entropy unavailable for the envelope salt: {e}"))
        })?;
        let kek = Self::derive_kek(passphrase, &salt, params)?;
        let (ciphertext, nonce) = seal_bytes(kek.kek_bytes()?, plaintext)?;
        let envelope = serde_json::json!({
            "version": ENVELOPE_VERSION,
            "kdf": "argon2id",
            "generation": generation,
            "m_cost": params.m_cost,
            "t_cost": params.t_cost,
            "p_cost": params.p_cost,
            "salt": B64.encode(salt),
            "nonce": B64.encode(nonce),
            "ciphertext": B64.encode(ciphertext),
        });
        write_private(path, envelope.to_string().as_bytes())
    }

    /// Open an envelope file with the passphrase: derive from the file's
    /// stored salt/params and AEAD-open — a wrong passphrase is a typed
    /// crypto failure, never partial output.
    pub fn open_envelope(path: &Path, passphrase: &str) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let raw = fs::read(path)
            .map_err(|e| CoreError::Config(format!("key envelope {}: {e}", path.display())))?;
        let envelope: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|_| CoreError::Crypto("key envelope is not valid JSON".to_string()))?;
        if envelope["version"].as_u64() != Some(u64::from(ENVELOPE_VERSION))
            || envelope["kdf"].as_str() != Some("argon2id")
        {
            return Err(CoreError::Crypto(format!(
                "key envelope {} has an unsupported version or KDF",
                path.display()
            )));
        }
        let params_missing = || CoreError::Crypto("key envelope lacks KDF parameters".to_string());
        let m_cost = envelope["m_cost"].as_u64().ok_or_else(params_missing)? as u32;
        let t_cost = envelope["t_cost"].as_u64().ok_or_else(params_missing)? as u32;
        let p_cost = envelope["p_cost"].as_u64().ok_or_else(params_missing)? as u32;
        let salt = B64
            .decode(envelope["salt"].as_str().ok_or_else(params_missing)?)
            .map_err(|_| CoreError::Crypto("key envelope salt is not base64".to_string()))?;
        let nonce = B64
            .decode(envelope["nonce"].as_str().ok_or_else(params_missing)?)
            .map_err(|_| CoreError::Crypto("key envelope nonce is not base64".to_string()))?;
        let ciphertext = B64
            .decode(envelope["ciphertext"].as_str().ok_or_else(params_missing)?)
            .map_err(|_| CoreError::Crypto("key envelope ciphertext is not base64".to_string()))?;
        let kek = Self::derive_kek(
            passphrase,
            &salt,
            KdfParams {
                m_cost,
                t_cost,
                p_cost,
            },
        )?;
        open_bytes(kek.kek_bytes()?, &nonce, &ciphertext)
    }

    /// Test support only: a copy accessor for the test suites' borrowed
    /// envelopes. Every production caller takes the KEK through
    /// [`KeyEnvelope::into_kek`] (the move, no copy) or the unlock
    /// handshake; no production caller is permitted here — one would
    /// re-open a second copy path out of the envelope and must not
    /// pass review quietly.
    ///
    /// The KEK as a fresh 32-byte reservation in the protected arena (a
    /// copy for a caller holding a borrowed envelope; the production
    /// custody paths move the buffer instead, via
    /// [`KeyEnvelope::into_kek`], adding no copy). The caller's buffer is
    /// wiped on drop; the envelope keeps its own.
    ///
    /// # Errors
    ///
    /// [`CoreError::Crypto`] if the protected arena cannot serve the
    /// copy (it never falls back to the heap).
    pub fn secrets(&self) -> Result<SecretBuf, CoreError> {
        let mem = ws_secmem::global().map_err(protected_memory_failure)?;
        mem.alloc_copy(&self.kek).map_err(protected_memory_failure)
    }

    /// The KEK moved out of the envelope into the caller's arena custody
    /// (e.g. the keystore conversion): the reservation transfers whole —
    /// no copy is made, and the move is infallible by construction
    /// ([`KeyEnvelope::derive_kek`] is the only constructor and reserves
    /// exactly [`KEY_LEN`] bytes).
    pub fn into_kek(self) -> SecretBuf {
        self.kek
    }
}

/// Re-wrap a volume's envelopes under a new master passphrase: the ONE
/// operation behind both the change route and the unlock page's
/// mixed-state completion (spec §5.7).
///
/// The generation counter is the whole trick. Every envelope names the
/// passphrase epoch it was sealed in; the MASTER envelope — written
/// last, the anchor rule — is always the volume's oldest, so a change
/// that crashed mid-re-wrap leaves the volume openable under the
/// passphrase the operator has been using all along: each envelope at
/// the master's generation opens under `current`, each already-advanced
/// one opens under `next`, and the re-wrap brings them all to one
/// generation under `next` — deterministically, whichever file the
/// crash interrupted.
///
/// All-or-nothing on the PASSPHRASE (every envelope is opened before
/// any is written: a wrong `current` re-wraps nothing); crash-atomic
/// per FILE (the envelope write's tmp+fsync+rename), so an IO death
/// mid-write leaves a completable mixed volume — the state this
/// function's mixed-window arm exists to finish. The master envelope is
/// written LAST, preserving the anchor rule for the next crash.
///
/// Returns the generation the volume now sits at (the master's old
/// generation + 1).
pub fn rewrap_volume(
    dir: &Path,
    files: &[&str],
    current: &str,
    next: &str,
) -> Result<u64, CoreError> {
    if !files.contains(&MASTER_ENVELOPE_FILE) {
        return Err(CoreError::Config(format!(
            "the re-wrap list omits {MASTER_ENVELOPE_FILE} — a volume cannot change its \
             passphrase without its anchor envelope"
        )));
    }
    let master_generation = KeyEnvelope::read_generation(&dir.join(MASTER_ENVELOPE_FILE))?;
    // Open everything first: a wrong `current` (or a wrong `next` against
    // the mixed window's advanced files) must re-wrap nothing.
    let mut opened = Vec::with_capacity(files.len());
    for file in files {
        let path = dir.join(file);
        let (_, params, generation) = KeyEnvelope::read_kdf_state(&path)?;
        let passphrase = if generation == master_generation {
            current
        } else if generation == master_generation + 1 {
            next
        } else {
            return Err(CoreError::Crypto(format!(
                "key envelope {file} holds generation {generation} against the volume's \
                 {master_generation} — the volume is inconsistent and cannot be re-wrapped"
            )));
        };
        let plaintext = KeyEnvelope::open_envelope(&path, passphrase)?;
        opened.push((*file, plaintext, params));
    }
    // Re-wrap under `next` at the advanced generation, master LAST.
    let advanced = master_generation + 1;
    for (file, plaintext, params) in opened
        .iter()
        .filter(|(file, _, _)| *file != MASTER_ENVELOPE_FILE)
    {
        KeyEnvelope::write_envelope(&dir.join(file), next, plaintext, *params, advanced)?;
    }
    if let Some((_, plaintext, params)) = opened
        .iter()
        .find(|(file, _, _)| *file == MASTER_ENVELOPE_FILE)
    {
        KeyEnvelope::write_envelope(
            &dir.join(MASTER_ENVELOPE_FILE),
            next,
            plaintext,
            *params,
            advanced,
        )?;
    }
    Ok(advanced)
}

/// AEAD-seal bytes under a KEK (fresh entropy nonce; the tag appended).
fn seal_bytes(kek: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CoreError> {
    let cipher = cipher_for(kek)?;
    let mut nonce = [0u8; NONCE_LEN];
    SysRng.try_fill_bytes(&mut nonce).map_err(|e| {
        CoreError::Crypto(format!("os entropy unavailable for the AEAD nonce: {e}"))
    })?;
    let ciphertext = cipher
        .encrypt(&XNonce::from(nonce), plaintext)
        .map_err(|_| CoreError::Crypto("envelope sealing failed".to_string()))?;
    Ok((ciphertext, nonce.to_vec()))
}

/// AEAD-open bytes under a KEK; the plaintext is zeroized on drop.
fn open_bytes(
    kek: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let cipher = cipher_for(kek)?;
    let nonce = XNonce::try_from(nonce).map_err(|_| {
        CoreError::Crypto(format!("AEAD nonce must be {NONCE_LEN} bytes").to_string())
    })?;
    let plaintext = cipher.decrypt(&nonce, ciphertext).map_err(|_| {
        CoreError::Crypto("the master passphrase is wrong or the envelope is damaged".to_string())
    })?;
    Ok(Zeroizing::new(plaintext))
}

/// A sealed volume's scan: which envelope files exist, and whether
/// their generations disagree — the mixed state a crashed passphrase
/// change leaves behind.
#[derive(Debug)]
pub struct VolumeScan {
    /// The envelope files present on the volume, master first.
    pub present: Vec<&'static str>,
    /// Whether any present envelope's generation disagrees with the
    /// master anchor's.
    pub mixed: bool,
}

/// Scan a sealed volume for its state. The MASTER envelope is the
/// anchor: its generation is the volume's passphrase epoch, and every
/// other present envelope must agree with it. An ABSENT envelope (the
/// JWT pair before the fresh install's first unlock) joins no
/// disagreement. A volume that cannot be read — no master envelope, a
/// damaged header, a v1 envelope that predates the generation field —
/// fails the scan loudly rather than misreading as clean; the callers
/// render their plain refusal surfaces and let the unlock name the
/// real condition.
pub fn scan_volume(dir: &Path) -> Result<VolumeScan, CoreError> {
    let anchor = KeyEnvelope::read_generation(&dir.join(MASTER_ENVELOPE_FILE))?;
    let mut present = Vec::new();
    let mut mixed = false;
    for file in [
        MASTER_ENVELOPE_FILE,
        SECRET_ENVELOPE_FILE,
        DB_CREDENTIAL_ENVELOPE_FILE,
        JWT_ENVELOPE_FILE,
    ] {
        let path = dir.join(file);
        if !path.exists() {
            continue; // an absent envelope is the fresh-install shape
        }
        if file != MASTER_ENVELOPE_FILE && KeyEnvelope::read_generation(&path)? != anchor {
            mixed = true;
        }
        present.push(file);
    }
    Ok(VolumeScan { present, mixed })
}

/// # Unit tests
///
/// The URL-significant password coverage (the fix round 1 defect): a
/// typed password containing URL-significant bytes was spliced RAW,
/// produced a malformed URL, and was answered as "the database rejected
/// that password" — a correct password refused with misleading copy.
/// The encode/decode pair and the splice now round trip.
#[cfg(test)]
mod tests {
    use super::*;

    /// Every URL-significant byte survives the splice and the parse.
    /// sqlx 0.8.6's `PgConnectOptions` exposes no password getter, so
    /// the decode side is proven the runtime way: sqlx's own URL parse
    /// percent-decodes the userinfo AT PARSE TIME, so its ACCEPTING
    /// the spliced URL (a raw `:` or `@` inside the password breaks
    /// the authority parse — the original defect) proves the bytes
    /// survive, and the userinfo slice — taken with the same authority
    /// convention the extractors speak — is pinned directly in its
    /// ENCODED form: `@ : / % # ?` percent-escape and the unreserved
    /// set passes through, all at once.
    #[test]
    fn a_url_significant_password_survives_the_splice_and_the_parse() {
        let password = "p@ss:wo%rd/?#x~._-Z9";
        let url = substitute_db_password(
            "postgres://wardstone:placeholder@localhost:5432/wardstone_test",
            password,
        );
        url.parse::<sqlx::postgres::PgConnectOptions>()
            .expect("the spliced URL parses as a Postgres connect URL");
        let authority = url.split("://").nth(1).expect("the scheme is present");
        let userinfo_end = authority.find('@').expect("the authority carries userinfo");
        let (user, encoded) = authority[..userinfo_end]
            .split_once(':')
            .expect("the userinfo carries a password");
        assert_eq!(user, "wardstone");
        assert_eq!(
            encoded, "p%40ss%3Awo%25rd%2F%3F%23x~._-Z9",
            "the encoder emits the exact percent-encoded form"
        );
    }

    /// The no-op property: a generated base32 credential (`a-z2-7`
    /// only) encodes to itself, so every existing rotation and restore
    /// flow is bit-identical.
    #[test]
    fn a_generated_base32_credential_encodes_to_itself() {
        let fresh = crate::dbcred::generate_db_password().expect("the generator runs");
        let text = std::str::from_utf8(&fresh).expect("the generated credential is ascii");
        assert!(
            text.bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)),
            "the generated credential is base32 a-z2-7"
        );
        assert_eq!(
            percent_encode_userinfo(text),
            text,
            "the encoder is a no-op on base32 credentials"
        );
    }

    /// Encoding is injective for the literal-`%` case: a `%` in the
    /// password becomes `%25` in the ENCODED form — a raw splice would
    /// have eaten it as an escape.
    #[test]
    fn a_literal_percent_is_injectively_encoded() {
        assert_eq!(percent_encode_userinfo("100%secure%"), "100%25secure%25");
    }
}
