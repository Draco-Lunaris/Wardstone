//! Secret-encryption helper: AEAD (XChaCha20-Poly1305) sealing of small
//! secrets at rest — today the TOTP and WebAuthn secrets, encrypted in the
//! `users` row with a key file created at setup under the keys volume,
//! analogous to the house's `pm-core/src/crypto.rs` helper.
//!
//! The key is the file's content: [`SecretBox::create`] generates 32
//! OS-entropy bytes and writes them mode 0600, crash-atomically (sibling
//! `.tmp`, fsync, rename), if the file is absent; [`SecretBox::load`] reads
//! and validates it (exactly 32 bytes). [`SecretBox::seal`] encrypts with a
//! fresh 24-byte OS-entropy nonce and returns `(ciphertext, nonce)`;
//! [`SecretBox::open`] decrypts, returning the plaintext zeroized on drop.
//!
//! Error contract: key-file problems (missing, unreadable, wrong length,
//! unwritable) are [`CoreError::Config`] — an operator/environment problem;
//! cryptographic failures (os-entropy exhaustion, AEAD authentication
//! failure on tampered or wrong-key ciphertext, wrong nonce length) are
//! [`CoreError::Crypto`]. No error message ever carries key or plaintext
//! material.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use rand::{rngs::SysRng, TryRng};
use zeroize::{Zeroize, Zeroizing};

use crate::error::CoreError;

/// Key length in bytes (XChaCha20-Poly1305 key size).
const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 extended-nonce length in bytes.
const NONCE_LEN: usize = 24;

/// Holds the 32-byte secret-encryption key (zeroized on drop) and seals
/// secrets under fresh XChaCha20-Poly1305 nonces.
#[derive(Clone)]
pub struct SecretBox {
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl SecretBox {
    /// Read the secret-encryption key from `<path>`: exactly
    /// [`KEY_LEN`] bytes.
    ///
    /// A missing or unreadable file, or a file of any other length, is
    /// [`CoreError::Config`] — a missing key file means setup did not run
    /// (or was lost), not an empty store the caller could bootstrap.
    pub fn load(path: &Path) -> Result<Self, CoreError> {
        let raw = match fs::read(path) {
            Ok(raw) => Zeroizing::new(raw),
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Err(CoreError::Config(format!(
                    "secret-encryption key file {} not found (run setup first)",
                    path.display()
                )));
            }
            Err(e) => {
                return Err(CoreError::Config(format!(
                    "secret-encryption key file {}: {e}",
                    path.display()
                )));
            }
        };
        if raw.len() != KEY_LEN {
            return Err(CoreError::Config(format!(
                "secret-encryption key file {} must be exactly {KEY_LEN} bytes, got {}",
                path.display(),
                raw.len()
            )));
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.as_mut().copy_from_slice(raw.as_slice());
        Ok(SecretBox { key })
    }

    /// Construct from an ALREADY-UNWRAPPED key (the sealed-at-rest unlock
    /// flow: the SecretBox key comes from its envelope under the operator
    /// passphrase-KEK and lives zeroized in RAM).
    pub fn from_key(key: Zeroizing<[u8; KEY_LEN]>) -> Self {
        SecretBox { key }
    }

    /// Guarantee a secret-encryption key exists: if the file is present,
    /// load and validate it (a second `create` must never mint a different
    /// key over data already sealed with the first); if it is absent,
    /// generate 32 OS-entropy bytes and write them mode 0600,
    /// crash-atomically.
    pub fn create(path: &Path) -> Result<Self, CoreError> {
        if path.exists() {
            return SecretBox::load(path);
        }
        let key = random_key()?;
        write_private(path, key.as_slice())?;
        Ok(SecretBox { key })
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

/// `len` OS-entropy bytes, hex-encoded: the DB-credential rotation's
/// fresh password material (and any future random-string need). The OS
/// source failing is a typed error, never a panic.
pub fn random_hex(len: usize) -> Result<String, CoreError> {
    let mut bytes = vec![0u8; len];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| CoreError::Crypto(format!("os entropy unavailable: {e}")))?;
    Ok(hex::encode(bytes))
}

/// Build an XChaCha20-Poly1305 cipher from the 32-byte key.
///
/// The transient `Key` copy is zeroized the moment the cipher has taken
/// its own; the cipher's retained copy is zeroized on drop via the
/// `chacha20poly1305` `zeroize` feature.
fn cipher_for(key: &[u8; KEY_LEN]) -> Result<XChaCha20Poly1305, CoreError> {
    let mut key = Key::try_from(key.as_slice())
        .map_err(|_| CoreError::Crypto("secret-encryption key is not 32 bytes".to_string()))?;
    let cipher = XChaCha20Poly1305::new(&key);
    Zeroize::zeroize(&mut *key);
    Ok(cipher)
}

/// 32 OS-entropy bytes for a fresh key file. The OS source failing is a
/// typed error, never a panic.
fn random_key() -> Result<Zeroizing<[u8; KEY_LEN]>, CoreError> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    SysRng.try_fill_bytes(key.as_mut()).map_err(|e| {
        CoreError::Crypto(format!(
            "os entropy unavailable for the secret-encryption key: {e}"
        ))
    })?;
    Ok(key)
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
pub const ENVELOPE_VERSION: u32 = 1;

/// The production KDF parameters: argon2id at 256 MiB / 3 passes targets
/// the ~1 s unlock latency budget while making off-box brute force meet
/// real cost. The parameters travel INSIDE each envelope, so a deployed
/// tuning change does not strand old envelopes.
#[derive(Debug, Clone, Copy)]
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

/// Substitute `password` into `url`'s `://user:password@host` authority —
/// inserting a `:password` when the URL carries none (the api's
/// password-less compose contract). The one home for the parsing: the
/// binary's boot rule, the ui's credential unwrap, the api's unlock
/// rotation, and the tests all speak this exact shape. A URL with no
/// `userinfo@` comes back unchanged (the caller's error to raise).
pub fn substitute_db_password(url: &str, password: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let auth_start = scheme_end + 3;
    let Some(at) = url[auth_start..].find('@').map(|i| i + auth_start) else {
        return url.to_string();
    };
    match url[auth_start..at].rfind(':') {
        Some(colon_rel) => {
            let colon_abs = auth_start + colon_rel;
            format!("{}{}{}", &url[..=colon_abs], password, &url[at..])
        }
        None => format!("{}:{}{}", &url[..at], password, &url[at..]),
    }
}

pub struct KeyEnvelope {
    kek: Zeroizing<[u8; 32]>,
    salt: Vec<u8>,
    params: KdfParams,
}

impl KeyEnvelope {
    /// Derive the KEK from the passphrase with the stored salt + params.
    /// Deterministic per (passphrase, salt, params) — the envelope's own
    /// salt means every write re-randomizes.
    pub fn derive_kek(passphrase: &str, salt: &[u8], params: KdfParams) -> Result<Self, CoreError> {
        use argon2::{Algorithm, Argon2, Params, Version};
        let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
            .map_err(|_| CoreError::Crypto("argon2 parameters are out of range".to_string()))?;
        let mut kek = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
            .hash_password_into(passphrase.as_bytes(), salt, kek.as_mut())
            .map_err(|e| CoreError::Crypto(format!("the master-key derivation failed: {e}")))?;
        Ok(Self {
            kek,
            salt: salt.to_vec(),
            params,
        })
    }

    /// The envelope's recorded salt: the unlock re-derivation reads it from
    /// the envelope file itself; held here for wrap/unwrap callers.
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Read an envelope file's stored salt + KDF parameters WITHOUT
    /// opening it: the unlock's derive step needs them before the
    /// passphrase is known to be right (the derive itself is the check).
    /// A missing file is [`CoreError::Config`] naming the path.
    pub fn read_kdf_params(path: &Path) -> Result<(Vec<u8>, KdfParams), CoreError> {
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
        Ok((
            salt,
            KdfParams {
                m_cost,
                t_cost,
                p_cost,
            },
        ))
    }

    /// The envelope's recorded KDF parameters: the passphrase-change flow
    /// (Task 4b, the master-key rotation) re-wraps every envelope with the
    /// SAME parameters but a fresh salt under the new passphrase.
    pub fn params(&self) -> KdfParams {
        self.params
    }

    /// Write a sealed envelope file for `plaintext` under the passphrase:
    /// a fresh OS-entropy salt, the derivation, and a crash-atomic 0600
    /// write of the JSON form (version, KDF parameters, salt, nonce,
    /// ciphertext — the plaintext's bytes appear NOWHERE in the file).
    pub fn write_envelope(
        path: &Path,
        passphrase: &str,
        plaintext: &[u8],
        params: KdfParams,
    ) -> Result<(), CoreError> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let mut salt = [0u8; 16];
        SysRng.try_fill_bytes(&mut salt).map_err(|e| {
            CoreError::Crypto(format!("os entropy unavailable for the envelope salt: {e}"))
        })?;
        let kek = Self::derive_kek(passphrase, &salt, params)?;
        let (ciphertext, nonce) = seal_bytes(&kek.kek, plaintext)?;
        let envelope = serde_json::json!({
            "version": ENVELOPE_VERSION,
            "kdf": "argon2id",
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
        open_bytes(&kek.kek, &nonce, &ciphertext)
    }

    /// The KEK as a 32-byte secret-encryption key: the SecretBox consumer
    /// (TOTP/OIDC seals) takes custody of it at unlock and zeroizes on
    /// drop.
    pub fn secrets(&self) -> Zeroizing<[u8; 32]> {
        self.kek.clone()
    }

    /// The KEK as its raw 32 bytes (for callers that re-wrap it into their
    /// own custody handling, e.g. the keystore conversion).
    pub fn into_kek(self) -> Zeroizing<[u8; 32]> {
        self.kek
    }
}

/// AEAD-seal bytes under a KEK (fresh entropy nonce; the tag appended).
fn seal_bytes(
    kek: &Zeroizing<[u8; 32]>,
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CoreError> {
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
    kek: &Zeroizing<[u8; 32]>,
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
