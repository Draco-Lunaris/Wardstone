//! Encrypted-at-rest key store for CA private keys (envelope encryption).
//!
//! One master key-encryption key (KEK, 32 random bytes in `master.key`,
//! mode 0600) protects every CA key file: [`KeyStore::store_ca_key`]
//! generates a fresh random 32-byte data-encryption key (DEK), encrypts the
//! DER private key with the DEK (XChaCha20-Poly1305), wraps the DEK with the
//! master KEK (XChaCha20-Poly1305), and writes a compact JSON envelope to
//! `ca/<ca_id>.key`. The DEK never touches disk unwrapped, and no key
//! material is ever formatted into an error message or written anywhere
//! outside the two AEAD layers. The CA id is authenticated as associated
//! data on the inner layer, so an envelope pasted into the wrong CA slot
//! fails decryption instead of silently loading the wrong key.
//!
//! The setup certificate's private key is stored the same way
//! ([`KeyStore::store_setup_key`]) under `<dir>/ca/setup.key`, with the
//! fixed literal `wardstone-setup-key/v1` — not a CA id — as its inner
//! associated data. The slot lives inside `ca/` with a `.key` suffix, so
//! it counts as a stored key towards `ensure_master_key`'s
//! populated-store guard: a store holding only a setup key never
//! silently gets a fresh master either.
//!
//! Error contract of [`KeyStore::load_ca_key`], so operators can tell key
//! loss from file damage:
//! - wrong master key (outer AEAD fails to authenticate) →
//!   [`CaError::WrongKey`]
//! - damaged store (truncated file, malformed JSON or base64, wrong nonce,
//!   DEK, or wrapped-DEK length, damaged inner ciphertext, envelope in the
//!   wrong CA slot, master key shorter than 32 bytes) → [`CaError::Corrupt`]
//! - no envelope file for `ca_id` → [`CaError::NotFound`]: deliberately a
//!   dedicated variant, because callers may bootstrap from "missing" but
//!   must never auto-recover from "corrupt" (damage needs an operator).
//! - master key missing while CA envelopes exist →
//!   [`CaError::Corrupt`]: `ensure_master_key` refuses to mint a fresh
//!   master over a populated store, which would silently orphan every
//!   stored key.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use rand::{rngs::SysRng, TryRng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CaError;

/// Master KEK length in bytes (XChaCha20-Poly1305 key size). Public
/// because the unlocked custody crosses crate boundaries: `ws-api`'s
/// AppState carries the unwrapped master in RAM for the sealed
/// instance's post-unlock service.
pub const MASTER_KEY_LEN: usize = 32;
/// Per-key DEK length in bytes (XChaCha20-Poly1305 key size).
const DEK_LEN: usize = 32;
/// XChaCha20-Poly1305 extended-nonce length in bytes.
const NONCE_LEN: usize = 24;
/// Poly1305 authentication-tag length appended to every ciphertext.
const TAG_LEN: usize = 16;
/// Envelope format version written (and accepted) by this build.
const ENVELOPE_VERSION: u8 = 1;
/// AEAD algorithm recorded in every envelope, so a future algorithm change
/// is detectable before any decryption is attempted.
const ENVELOPE_KEY_TYPE: &str = "xchacha20poly1305";
/// Subdirectory holding the per-CA key envelopes.
const CA_SUBDIR: &str = "ca";
/// Master KEK file name inside the keys directory.
const MASTER_FILE: &str = "master.key";
/// Setup-key envelope file name inside the `ca/` subdirectory.
const SETUP_FILE: &str = "setup.key";
/// Inner-layer associated data for the setup-key envelope. Deliberately
/// NOT a CA id: the setup key belongs to no CA.
const SETUP_KEY_AAD: &str = "wardstone-setup-key/v1";

/// On-disk envelope for one CA key. All binary fields are standard-alphabet
/// base64; field order in the written JSON matches this declaration.
///
/// Nothing here is secret on its own: `wrapped_dek`, the nonces, and
/// `ciphertext` are all stored in the clear by design (only the DEK wrap
/// and the inner AEAD provide secrecy).
#[derive(Serialize, Deserialize)]
struct Envelope {
    /// Envelope format version ([`ENVELOPE_VERSION`]).
    v: u8,
    /// DEK encrypted with the master KEK (XChaCha20-Poly1305).
    wrapped_dek: String,
    /// Nonce used to wrap the DEK with the master KEK.
    nonce_dek: String,
    /// DER private key encrypted with the DEK (XChaCha20-Poly1305).
    ciphertext: String,
    /// Nonce used for the inner encryption under the DEK.
    nonce_inner: String,
    /// AEAD algorithm identifier ([`ENVELOPE_KEY_TYPE`]).
    key_type: String,
}

/// The keys directory: owns the master KEK and every CA key envelope.
pub struct KeyStore {
    dir: PathBuf,
    /// Master-key custody: `Sealed` while the operator has not unlocked,
    /// the unlocked master (RAM-only) after the unlock handshake, or the
    /// legacy file-read mode for volumes created before the sealed
    /// design. Key operations answer [`CaError::Sealed`] while sealed.
    master: MasterCustody,
}

/// Where the master key currently lives for THIS keystore handle.
#[derive(Clone)]
enum MasterCustody {
    /// No master key is available in RAM: key operations refuse.
    Sealed,
    /// The legacy file-read mode: `master.key` exists as plaintext and is
    /// read per operation (pre-sealing stores; the conversion migrates
    /// away from it).
    LegacyFile,
    /// The unlocked master key, held zeroized in RAM.
    Unlocked(Zeroizing<[u8; 32]>),
}

impl KeyStore {
    /// Open (creating if missing) the keys directory and enforce mode 0700
    /// on unix.
    ///
    /// The mode is enforced on EVERY open, not only at creation: a
    /// pre-existing directory (volume restore, operator-created, backup
    /// restore) keeps whatever mode it had, and a 0755 keys directory
    /// leaves the master KEK and every CA private-key envelope
    /// world-readable — silently defeating the protection the format
    /// depends on. Tightening on every open is what makes the guarantee
    /// hold for a directory Wardstone did not create.
    ///
    /// The `ca/` subdirectory is tightened the same way whenever it
    /// already exists. It is NOT created here (it is created on the
    /// first key store, at mode 0700): a restored volume that already
    /// carries it gets the same narrowing as the parent, so the CA-id
    /// filenames are not exposed to local users.
    ///
    /// Does NOT generate the master key — call
    /// [`ensure_master_key`](Self::ensure_master_key) for that.
    ///
    /// Errors if the path is unusable: an unwritable parent, a regular file
    /// where a directory belongs, an unreadable directory, or a failure to
    /// set a directory mode all surface as [`CaError::Io`]. A keys
    /// directory that cannot be protected is a hard error, never a
    /// warning: continuing with a permissive directory would hand the
    /// master KEK to every local user.
    pub fn open(dir: &Path) -> Result<Self, CaError> {
        Self::with_mode(dir, MasterCustody::LegacyFile)
    }

    /// Open with NO master key in memory: every key operation answers
    /// [`CaError::Sealed`] until an unlock supplies the master
    /// ([`Self::open_unlocked`]).
    pub fn open_sealed(dir: &Path) -> Result<Self, CaError> {
        Self::with_mode(dir, MasterCustody::Sealed)
    }

    /// Open with the unlocked master key held zeroized in RAM (the
    /// unlocked-at-rest design: the envelope was opened at the unlock
    /// handshake; no master file is read here).
    pub fn open_unlocked(dir: &Path, master: Zeroizing<[u8; 32]>) -> Result<Self, CaError> {
        Self::with_mode(dir, MasterCustody::Unlocked(master))
    }

    fn with_mode(dir: &Path, master: MasterCustody) -> Result<Self, CaError> {
        if !dir.exists() {
            fs::create_dir_all(dir)?;
            #[cfg(unix)]
            set_permissions(dir, 0o700)?;
        }
        // Readability probe: actually open the directory (also rejects a
        // regular file sitting at the path with a typed io error).
        fs::read_dir(dir)?;
        // Tighten the mode on every open, for a directory that already
        // existed. The probe above has established that the path is a
        // readable directory, so this only ever narrows the permissions
        // — and a failure to do so is fatal rather than tolerated, because
        // an unprotected keys directory is a key disclosure.
        #[cfg(unix)]
        set_permissions(dir, 0o700)?;
        // The `ca/` subdirectory gets the same treatment when it is
        // already there (a restored volume). It is not created here.
        #[cfg(unix)]
        {
            let ca_dir = dir.join(CA_SUBDIR);
            if ca_dir.is_dir() {
                set_permissions(&ca_dir, 0o700)?;
            }
        }
        let mut keystore = KeyStore {
            dir: dir.to_path_buf(),
            master: MasterCustody::Sealed, // replaced by the caller's mode below
        };
        keystore.master = master;
        Ok(keystore)
    }

    /// The master key bytes as currently held (the legacy file read, the
    /// RAM custody, or a `Sealed` error for the locked state) — the test
    /// pins that the unlocked-from-envelope bytes match the legacy ones.
    pub fn master_key_bytes(&self) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, CaError> {
        self.read_master_key()
    }

    /// Path of the master KEK file (`<dir>/master.key`).
    pub fn master_key_path(&self) -> PathBuf {
        self.dir.join(MASTER_FILE)
    }

    /// The keys directory this store was opened on. `ws-web`'s setup flow
    /// derives sibling key-file paths from it (the secret-encryption key
    /// file lives under the same keys directory the keystore does —
    /// `ws_api::state::SECRET_KEY_FILE`), so the caller does not have to
    /// carry the directory separately from the store.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Guarantee that a master KEK exists: if the file is present, validate
    /// it (a file shorter than 32 bytes is [`CaError::Corrupt`]); if it is
    /// absent, generate 32 OS-entropy bytes and write them mode 0600.
    ///
    /// Refuses (Corrupt) to mint a fresh master while CA envelopes exist —
    /// that would silently orphan every stored key, turning the next load
    /// into `WrongKey` for data that was never wrong. Recovery from a lost
    /// master key is an explicit operator decision, not a bootstrap step.
    pub fn ensure_master_key(&mut self) -> Result<(), CaError> {
        let path = self.master_key_path();
        if path.exists() {
            // Validate by reading; the Zeroizing KEK drops (zeroized) at
            // the end of this statement.
            self.read_master_key()?;
            return Ok(());
        }
        if self.has_stored_keys()? {
            return Err(CaError::Corrupt);
        }
        let kek = random_bytes::<MASTER_KEY_LEN>()?;
        write_private(&path, kek.as_slice())?;
        Ok(())
    }

    /// Encrypt and store a CA private key under `<dir>/ca/<ca_id>.key`.
    ///
    /// A fresh random 32-byte DEK encrypts the DER key (XChaCha20-Poly1305,
    /// fresh random 24-byte nonce) with the CA id bound as associated data,
    /// and the master KEK wraps the DEK (XChaCha20-Poly1305, its own fresh
    /// nonce). The DEK exists only in memory between those two steps.
    /// Re-storing the same CA id replaces the envelope with a new DEK and
    /// fresh nonces.
    ///
    /// The master key must already exist ([`ensure_master_key`] or a
    /// previous run); storing without one is `Corrupt`, never a silent
    /// master generation.
    pub fn store_ca_key(&mut self, ca_id: &Uuid, der_private_key: &[u8]) -> Result<(), CaError> {
        self.store_envelope(&self.ca_key_path(ca_id), &aad_for(ca_id), der_private_key)
    }

    /// Store one envelope: the engine behind
    /// [`store_ca_key`](Self::store_ca_key) and
    /// [`store_setup_key`](Self::store_setup_key) alike. `aad` binds the
    /// plaintext to its slot; `path` is the envelope file (inside `ca/`,
    /// `.key` suffix — the directory layout `has_stored_keys` scans).
    fn store_envelope(
        &mut self,
        path: &Path,
        aad: &str,
        der_private_key: &[u8],
    ) -> Result<(), CaError> {
        if matches!(self.master, MasterCustody::Sealed) {
            return Err(CaError::Sealed);
        }
        let kek = self.read_master_key()?;
        let wrap = cipher_for(kek.as_slice())?;

        let dek = random_bytes::<DEK_LEN>()?;
        let nonce_dek = random_bytes::<NONCE_LEN>()?;
        let nonce_inner = random_bytes::<NONCE_LEN>()?;

        let inner = cipher_for(dek.as_slice())?;
        let ciphertext = inner
            .encrypt(
                &XNonce::from(*nonce_inner),
                Payload {
                    msg: der_private_key,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| CaError::Io(std::io::Error::other("aead encrypt failed")))?;
        let wrapped_dek = wrap
            .encrypt(&XNonce::from(*nonce_dek), dek.as_slice())
            .map_err(|_| CaError::Io(std::io::Error::other("aead encrypt failed")))?;

        let envelope = Envelope {
            v: ENVELOPE_VERSION,
            wrapped_dek: STANDARD.encode(wrapped_dek.as_slice()),
            nonce_dek: STANDARD.encode(nonce_dek.as_slice()),
            ciphertext: STANDARD.encode(ciphertext.as_slice()),
            nonce_inner: STANDARD.encode(nonce_inner.as_slice()),
            key_type: ENVELOPE_KEY_TYPE.to_owned(),
        };
        let json = serde_json::to_string(&envelope)
            .map_err(|_| CaError::Io(std::io::Error::other("envelope serialization failed")))?;

        let ca_dir = self.dir.join(CA_SUBDIR);
        if !ca_dir.exists() {
            fs::create_dir_all(&ca_dir)?;
        }
        // Tighten the subdirectory's mode on every store, exactly as
        // `open` tightens the parent: a restored volume leaves `ca/` at
        // whatever mode it had, and a world-readable `ca/` exposes the
        // CA-id filenames (the envelope files themselves are written
        // 0600, so this is consistency hardening rather than a key
        // disclosure). A failure to set the mode is a typed io error,
        // never a permissive directory.
        #[cfg(unix)]
        set_permissions(&ca_dir, 0o700)?;
        write_private(path, json.as_bytes())?;
        Ok(())
    }

    /// Load and decrypt the CA private key stored for `ca_id`, returning it
    /// zeroized-on-drop.
    ///
    /// Error contract (see module docs): outer AEAD failure — the master key
    /// does not match — is [`CaError::WrongKey`]; every damage signature
    /// (truncated file, malformed JSON or base64, wrong nonce, DEK, or
    /// wrapped-DEK length, unknown envelope version or algorithm, inner
    /// AEAD failure including an envelope sitting in the wrong CA slot) is
    /// [`CaError::Corrupt`]; a missing envelope is [`CaError::NotFound`].
    /// A failed load never writes anything.
    pub fn load_ca_key(&self, ca_id: &Uuid) -> Result<Zeroizing<Vec<u8>>, CaError> {
        self.load_envelope(&self.ca_key_path(ca_id), &aad_for(ca_id))
    }

    /// Load one envelope: the engine behind
    /// [`load_ca_key`](Self::load_ca_key) and
    /// [`load_setup_key`](Self::load_setup_key) alike.
    fn load_envelope(&self, path: &Path, aad: &str) -> Result<Zeroizing<Vec<u8>>, CaError> {
        // Fail-closed BEFORE reading any envelope file: a sealed store
        // refuses without disclosing whether the file even exists (the
        // NotFound-vs-Sealed distinction would leak existence to a sealed
        // caller).
        if matches!(self.master, MasterCustody::Sealed) {
            return Err(CaError::Sealed);
        }
        let raw = match fs::read(path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == ErrorKind::NotFound => return Err(CaError::NotFound),
            Err(e) => return Err(CaError::Io(e)),
        };
        let envelope: Envelope = serde_json::from_slice(&raw).map_err(|_| CaError::Corrupt)?;
        if envelope.v != ENVELOPE_VERSION || envelope.key_type != ENVELOPE_KEY_TYPE {
            return Err(CaError::Corrupt);
        }

        let kek = self.read_master_key()?;
        let wrap = cipher_for(kek.as_slice())?;
        let nonce_dek = decode_nonce(&envelope.nonce_dek)?;
        let wrapped_dek = STANDARD
            .decode(&envelope.wrapped_dek)
            .map_err(|_| CaError::Corrupt)?;
        // A well-formed wrapped DEK is exactly DEK_LEN + TAG_LEN bytes.
        // Rejecting any other length before decrypting keeps the error
        // contract airtight: structural damage is always Corrupt, so a
        // wrong master key can only ever surface as an authentication
        // failure.
        if wrapped_dek.len() != DEK_LEN + TAG_LEN {
            return Err(CaError::Corrupt);
        }

        // Outer layer: unwrap the DEK with the master KEK. The input is
        // now structurally valid, so an AEAD failure can only mean the KEK
        // does not match this store.
        let dek = match wrap.decrypt(&nonce_dek, wrapped_dek.as_slice()) {
            Ok(dek) => Zeroizing::new(dek),
            Err(_) => return Err(CaError::WrongKey),
        };
        let inner = cipher_for(dek.as_slice())?;

        let nonce_inner = decode_nonce(&envelope.nonce_inner)?;
        let ciphertext = STANDARD
            .decode(&envelope.ciphertext)
            .map_err(|_| CaError::Corrupt)?;
        let plaintext = match inner.decrypt(
            &nonce_inner,
            Payload {
                msg: ciphertext.as_slice(),
                aad: aad.as_bytes(),
            },
        ) {
            Ok(plaintext) => plaintext,
            Err(_) => return Err(CaError::Corrupt),
        };
        Ok(Zeroizing::new(plaintext))
    }

    /// Store the setup certificate's private key under
    /// `<dir>/ca/setup.key` as an envelope exactly like a CA key's: a
    /// fresh DEK, the inner AEAD binding the fixed associated-data
    /// literal (NOT a CA id), the DEK wrapped under the master KEK, the
    /// file written mode 0600. Re-storing replaces the envelope with a
    /// new DEK and fresh nonces.
    ///
    /// The file lives INSIDE the `ca/` directory `has_stored_keys` scans,
    /// so a store whose only key is the setup key is a populated store:
    /// [`ensure_master_key`](Self::ensure_master_key) refuses to mint a
    /// fresh master over it (`Corrupt`), exactly as it does over CA key
    /// envelopes. The master key must already exist, as for
    /// [`store_ca_key`](Self::store_ca_key).
    pub fn store_setup_key(&mut self, der: &[u8]) -> Result<(), CaError> {
        self.store_envelope(&self.setup_key_path(), SETUP_KEY_AAD, der)
    }

    /// Load and decrypt the setup certificate's private key. Error
    /// contract identical to [`load_ca_key`](Self::load_ca_key): an
    /// envelope that fails the inner AEAD (wrong slot, wrong master key,
    /// damage) is `Corrupt`/`WrongKey`; a missing envelope is
    /// [`CaError::NotFound`]. A failed load never writes anything.
    pub fn load_setup_key(&self) -> Result<Zeroizing<Vec<u8>>, CaError> {
        self.load_envelope(&self.setup_key_path(), SETUP_KEY_AAD)
    }

    /// Path of the setup-key envelope file (`<dir>/ca/setup.key`).
    pub fn setup_key_path(&self) -> PathBuf {
        self.dir.join(CA_SUBDIR).join(SETUP_FILE)
    }

    /// Path of the envelope file for `ca_id`.
    fn ca_key_path(&self, ca_id: &Uuid) -> PathBuf {
        self.dir.join(CA_SUBDIR).join(format!("{ca_id}.key"))
    }

    /// Read the master KEK: its first 32 bytes, zeroized on drop.
    ///
    /// A missing or too-short master file is `Corrupt` — this is only
    /// called from operations that require a master key to exist, so
    /// "absent" means the store is inconsistent, not empty.
    fn read_master_key(&self) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, CaError> {
        match &self.master {
            MasterCustody::Unlocked(kek) => Ok(kek.clone()),
            MasterCustody::Sealed => Err(CaError::Sealed),
            MasterCustody::LegacyFile => self.read_legacy_master_key(),
        }
    }

    /// The pre-sealing custody mode: the master KEK read per operation
    /// from the plaintext `master.key` file (0600).
    fn read_legacy_master_key(&self) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, CaError> {
        let raw = match fs::read(self.master_key_path()) {
            Ok(raw) => Zeroizing::new(raw),
            Err(e) if e.kind() == ErrorKind::NotFound => return Err(CaError::Corrupt),
            Err(e) => return Err(CaError::Io(e)),
        };
        if raw.as_slice().len() < MASTER_KEY_LEN {
            return Err(CaError::Corrupt);
        }
        let mut kek = Zeroizing::new([0u8; MASTER_KEY_LEN]);
        kek.as_mut()
            .copy_from_slice(&raw.as_slice()[..MASTER_KEY_LEN]);
        Ok(kek)
    }

    /// Whether at least one `*.key` envelope is present in `ca/` — CA key
    /// envelopes and the setup key alike (both live there with a `.key`
    /// suffix, so a store whose only key is the setup key counts as
    /// populated).
    /// An unreadable `ca/` directory is an error, never "no keys" —
    /// treating it as empty could authorize a master regeneration.
    fn has_stored_keys(&self) -> Result<bool, CaError> {
        let entries = match fs::read_dir(self.dir.join(CA_SUBDIR)) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(CaError::Io(e)),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => return Err(CaError::Io(e)),
            };
            if entry.file_name().to_string_lossy().ends_with(".key") {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Build an XChaCha20-Poly1305 cipher from a 32-byte key.
///
/// The transient `Key` copy is zeroized the moment the cipher has taken
/// its own; the cipher's retained copy is zeroized on drop via the
/// `chacha20poly1305` `zeroize` feature. A key that is not exactly 32
/// bytes long cannot come from a well-formed store and is `Corrupt`.
fn cipher_for(key_bytes: &[u8]) -> Result<XChaCha20Poly1305, CaError> {
    let mut key = Key::try_from(key_bytes).map_err(|_| CaError::Corrupt)?;
    let cipher = XChaCha20Poly1305::new(&key);
    Zeroize::zeroize(&mut *key);
    Ok(cipher)
}

/// Inner-layer associated data, binding an envelope to its CA slot: two
/// envelopes swapped between CAs fail decryption (as `Corrupt`) instead of
/// silently loading the wrong key. The setup key's slot is bound by the
/// fixed literal [`SETUP_KEY_AAD`] instead, which is why a setup envelope
/// in a CA slot (or vice versa) fails the same way.
fn aad_for(ca_id: &Uuid) -> String {
    format!("wardstone-ca-key/v1/{ca_id}")
}

/// `N` bytes of OS entropy in a zeroizing buffer. The OS source failing is
/// a typed io error, never a panic.
fn random_bytes<const N: usize>() -> Result<Zeroizing<[u8; N]>, CaError> {
    let mut bytes = Zeroizing::new([0u8; N]);
    SysRng
        .try_fill_bytes(bytes.as_mut())
        .map_err(std::io::Error::from)?;
    Ok(bytes)
}

/// Decode a base64 envelope nonce field; wrong length or alphabet is
/// `Corrupt` (the file does not describe a valid envelope).
fn decode_nonce(field: &str) -> Result<XNonce, CaError> {
    let bytes = STANDARD.decode(field).map_err(|_| CaError::Corrupt)?;
    XNonce::try_from(bytes.as_slice()).map_err(|_| CaError::Corrupt)
}

/// Write a file containing key-store material, mode 0600 on unix, and
/// crash-atomically: on unix the bytes land in a sibling `.tmp` file that
/// is fsynced and renamed over the destination, so a crash mid-write can
/// never leave a truncated envelope under the real name; the parent
/// directory is fsynced after the rename so the replacement itself is
/// durable, and a failed write removes the temporary rather than leaving
/// a stale `master.tmp` holding a second copy of the raw KEK.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), CaError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let tmp = path.with_extension("tmp");
        let write = || -> Result<(), CaError> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            set_permissions(&tmp, 0o600)?;
            fs::rename(&tmp, path)?;
            // Durability of the rename itself: without a parent-directory
            // fsync, a power cut after the caller returns could roll the
            // rename back — and with it the only copy of a CA private key.
            if let Some(parent) = path.parent() {
                fs::File::open(parent)?.sync_all()?;
            }
            Ok(())
        };
        let result = write();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes)?;
    }
    Ok(())
}

/// Force the exact permission bits (not umask-masked) on a path, unix only.
#[cfg(unix)]
fn set_permissions(path: &Path, mode: u32) -> Result<(), CaError> {
    use std::os::unix::fs::PermissionsExt;

    let perms = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use rand::{rngs::SysRng, TryRng};
    use uuid::Uuid;

    use super::{Envelope, KeyStore, TAG_LEN};
    use crate::error::CaError;

    /// Per-test temp dir under `std::env::temp_dir()`, unique per test name
    /// and process id. Any previous run's leftovers (e.g. after a kill) are
    /// swept away first so every test starts from a fresh, empty directory.
    fn temp_keys_dir(test_name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ws-ca-keystore-{test_name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// `N` OS-entropy bytes (rand 0.10: `SysRng` is the stateless OS
    /// interface; the old `OsRng` name is gone).
    fn random_bytes<const N: usize>() -> [u8; N] {
        let mut bytes = [0u8; N];
        SysRng
            .try_fill_bytes(&mut bytes)
            .expect("OS entropy unavailable");
        bytes
    }

    /// On-disk location of a CA's key envelope (keystore layout: `<dir>/ca/`).
    fn envelope_path(dir: &Path, ca_id: &Uuid) -> PathBuf {
        dir.join("ca").join(format!("{ca_id}.key"))
    }

    #[test]
    fn test_store_load_roundtrip() {
        let dir = temp_keys_dir("roundtrip");
        let mut ks = KeyStore::open(&dir).unwrap();
        ks.ensure_master_key().unwrap();
        let ca_id = Uuid::new_v4();
        let der = random_bytes::<32>();
        ks.store_ca_key(&ca_id, &der).unwrap();

        // The envelope is self-describing: version plus the four
        // base64-encoded AEAD fields.
        let raw = fs::read_to_string(envelope_path(&dir, &ca_id)).unwrap();
        let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(json["v"].as_u64(), Some(1));
        for field in ["wrapped_dek", "nonce_dek", "ciphertext", "nonce_inner"] {
            assert!(
                json[field].is_string(),
                "envelope field {field} must be a base64 string"
            );
        }

        let loaded = ks.load_ca_key(&ca_id).unwrap();
        assert_eq!(loaded.as_slice(), der.as_slice());
    }

    #[test]
    fn test_load_corrupt_file_fails_typed() {
        let dir = temp_keys_dir("corrupt");
        let mut ks = KeyStore::open(&dir).unwrap();
        ks.ensure_master_key().unwrap();
        let ca_id = Uuid::new_v4();
        ks.store_ca_key(&ca_id, &random_bytes::<32>()).unwrap();

        let path = envelope_path(&dir, &ca_id);
        let half = fs::metadata(&path).unwrap().len() / 2;
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(half)
            .unwrap();

        assert!(matches!(ks.load_ca_key(&ca_id), Err(CaError::Corrupt)));
    }

    #[test]
    fn test_decrypt_with_wrong_kek_fails_typed() {
        let dir = temp_keys_dir("wrong-kek");
        let mut ks = KeyStore::open(&dir).unwrap();
        ks.ensure_master_key().unwrap();
        let ca_id = Uuid::new_v4();
        let der = random_bytes::<32>();
        ks.store_ca_key(&ca_id, &der).unwrap();

        let path = envelope_path(&dir, &ca_id);
        let envelope_before = fs::read(&path).unwrap();
        fs::write(ks.master_key_path(), random_bytes::<32>()).unwrap();

        assert!(matches!(ks.load_ca_key(&ca_id), Err(CaError::WrongKey)));
        // A failed load must never rewrite or "repair" the key file.
        assert_eq!(fs::read(&path).unwrap(), envelope_before);
    }

    #[cfg(unix)]
    #[test]
    fn test_master_key_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_keys_dir("master-perms");
        let mut ks = KeyStore::open(&dir).unwrap();
        ks.ensure_master_key().unwrap();
        let mode = fs::metadata(ks.master_key_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn test_store_twice_rotates_nonces_and_still_loads() {
        let dir = temp_keys_dir("nonce-rotation");
        let mut ks = KeyStore::open(&dir).unwrap();
        ks.ensure_master_key().unwrap();
        let ca_id = Uuid::new_v4();
        let der = random_bytes::<32>();
        ks.store_ca_key(&ca_id, &der).unwrap();
        let first: Envelope =
            serde_json::from_str(&fs::read_to_string(envelope_path(&dir, &ca_id)).unwrap())
                .unwrap();
        ks.store_ca_key(&ca_id, &der).unwrap();
        let second: Envelope =
            serde_json::from_str(&fs::read_to_string(envelope_path(&dir, &ca_id)).unwrap())
                .unwrap();

        assert_ne!(first.nonce_dek, second.nonce_dek);
        assert_ne!(first.nonce_inner, second.nonce_inner);
        assert_eq!(ks.load_ca_key(&ca_id).unwrap().as_slice(), der.as_slice());
    }

    #[test]
    fn test_ensure_master_key_preserves_existing() {
        let dir = temp_keys_dir("preserve-master");
        let mut ks = KeyStore::open(&dir).unwrap();
        ks.ensure_master_key().unwrap();
        let first = fs::read(ks.master_key_path()).unwrap();
        ks.ensure_master_key().unwrap();
        let second = fs::read(ks.master_key_path()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 32);
    }

    #[test]
    fn test_short_master_key_fails_corrupt() {
        let dir = temp_keys_dir("short-master");
        let mut ks = KeyStore::open(&dir).unwrap();
        fs::write(ks.master_key_path(), [0u8; 31]).unwrap();
        assert!(matches!(ks.ensure_master_key(), Err(CaError::Corrupt)));
    }

    #[test]
    fn test_load_missing_envelope_not_found() {
        let dir = temp_keys_dir("missing");
        let mut ks = KeyStore::open(&dir).unwrap();
        ks.ensure_master_key().unwrap();
        let err = ks.load_ca_key(&Uuid::new_v4()).unwrap_err();
        assert!(matches!(err, CaError::NotFound));
    }

    #[cfg(unix)]
    #[test]
    fn test_keys_dir_created_0700() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_keys_dir("dir-perms");
        let _ks = KeyStore::open(&dir).unwrap();
        let mode = fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    /// A keys directory that ALREADY existed with a permissive mode is
    /// tightened on open, not only at creation.
    ///
    /// This is the regression guard for the "pre-existing directory
    /// keeps whatever mode it had" defect: a restored volume, an
    /// operator-created directory, or a backup restore could leave the
    /// keys directory at 0755, which makes the master KEK and every CA
    /// private-key envelope world-readable. The keystore must narrow
    /// the mode on EVERY open.
    ///
    /// The `ca/` subdirectory is covered too: a restored volume leaves it
    /// at whatever mode it had, and a world-readable `ca/` exposes the
    /// CA-id filenames to local users.
    #[cfg(unix)]
    #[test]
    fn test_existing_keys_dir_is_tightened_to_0700() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_keys_dir("dir-perms-existing");
        // Create the directory by hand at a permissive mode — the
        // situation the defect describes.
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o755,
            "the fixture must start permissive, or the test proves nothing"
        );

        // Open the keystore on it and store a CA key, so the directory
        // really is a live keys directory.
        let mut ks = KeyStore::open(&dir).unwrap();
        ks.ensure_master_key().unwrap();
        let ca_id = Uuid::new_v4();
        ks.store_ca_key(&ca_id, &random_bytes::<32>()).unwrap();

        // The mode is narrowed on the FIRST open...
        let mode = fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);

        // ...and stays narrowed when the directory is opened again, even
        // after an operator (or a restore) loosened it once more.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let _reopened = KeyStore::open(&dir).unwrap();
        let mode = fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "re-opening the keystore must re-tighten the keys directory"
        );

        // The `ca/` subdirectory is created at 0700 by the store...
        let ca_dir = dir.join("ca");
        let ca_mode = fs::metadata(&ca_dir).unwrap().permissions().mode();
        assert_eq!(ca_mode & 0o777, 0o700);

        // ...and a restored volume that left it permissive is re-tightened
        // by the next open, exactly like the parent directory.
        fs::set_permissions(&ca_dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            fs::metadata(&ca_dir).unwrap().permissions().mode() & 0o777,
            0o755,
            "the fixture must start permissive, or the test proves nothing"
        );
        let _reopened = KeyStore::open(&dir).unwrap();
        let ca_mode = fs::metadata(&ca_dir).unwrap().permissions().mode();
        assert_eq!(
            ca_mode & 0o777,
            0o700,
            "re-opening the keystore must re-tighten the ca/ subdirectory"
        );
    }

    #[test]
    fn test_swapped_envelope_fails_corrupt() {
        let dir = temp_keys_dir("swapped");
        let mut ks = KeyStore::open(&dir).unwrap();
        ks.ensure_master_key().unwrap();
        let ca_one = Uuid::new_v4();
        let ca_two = Uuid::new_v4();
        ks.store_ca_key(&ca_one, &random_bytes::<32>()).unwrap();
        ks.store_ca_key(&ca_two, &random_bytes::<32>()).unwrap();

        let path_one = envelope_path(&dir, &ca_one);
        let path_two = envelope_path(&dir, &ca_two);
        let env_one = fs::read(&path_one).unwrap();
        let env_two = fs::read(&path_two).unwrap();
        fs::write(&path_one, &env_two).unwrap();
        fs::write(&path_two, &env_one).unwrap();

        assert!(matches!(ks.load_ca_key(&ca_one), Err(CaError::Corrupt)));
        assert!(matches!(ks.load_ca_key(&ca_two), Err(CaError::Corrupt)));
    }

    #[test]
    fn test_ensure_master_key_refuses_when_ca_keys_exist() {
        let dir = temp_keys_dir("refuse-regen");
        let mut ks = KeyStore::open(&dir).unwrap();
        ks.ensure_master_key().unwrap();
        let ca_id = Uuid::new_v4();
        ks.store_ca_key(&ca_id, &random_bytes::<32>()).unwrap();

        fs::remove_file(ks.master_key_path()).unwrap();

        // Minting a fresh master here would silently orphan every stored
        // CA key (all future loads would fail with WrongKey); refuse.
        assert!(matches!(ks.ensure_master_key(), Err(CaError::Corrupt)));
    }

    #[test]
    fn test_wrong_wrapped_dek_length_fails_corrupt() {
        let dir = temp_keys_dir("dek-length");
        let mut ks = KeyStore::open(&dir).unwrap();
        ks.ensure_master_key().unwrap();
        let ca_id = Uuid::new_v4();
        ks.store_ca_key(&ca_id, &random_bytes::<32>()).unwrap();

        let path = envelope_path(&dir, &ca_id);
        let mut envelope: Envelope =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        // Valid base64 inside structurally sound JSON, but the wrong
        // length: damage, not a KEK mismatch.
        envelope.wrapped_dek = STANDARD.encode([0u8; TAG_LEN]);
        fs::write(&path, serde_json::to_string(&envelope).unwrap()).unwrap();

        assert!(matches!(ks.load_ca_key(&ca_id), Err(CaError::Corrupt)));
    }

    #[test]
    fn test_long_master_key_accepted() {
        let dir = temp_keys_dir("long-master");
        let mut ks = KeyStore::open(&dir).unwrap();
        fs::write(ks.master_key_path(), [0u8; 64]).unwrap();
        ks.ensure_master_key().unwrap();
        let ca_id = Uuid::new_v4();
        let der = random_bytes::<32>();
        ks.store_ca_key(&ca_id, &der).unwrap();
        assert_eq!(ks.load_ca_key(&ca_id).unwrap().as_slice(), der.as_slice());
    }
}
