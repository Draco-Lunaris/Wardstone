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
