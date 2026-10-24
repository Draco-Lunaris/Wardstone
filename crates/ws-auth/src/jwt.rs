//! Ed25519 (EdDSA) access-token issuing and validation, plus the on-disk
//! signing/verification key pair.
//!
//! The house keeps exactly two key files: the signing key's PEM (mode 0600)
//! and the verification key's PEM. `jsonwebtoken`'s `DecodingKey::from_ed_pem`
//! accepts only an Ed25519 *public*-key PEM — a private PKCS#8 PEM is rejected
//! with `InvalidKeyFormat` — so the private key cannot double as the
//! verification key and the two-file layout is required.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::Path;

use chrono::{Duration, Utc};
use ed25519_dalek::pkcs8::{EncodePublicKey, KeypairBytes};
use ed25519_dalek::SigningKey;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use pkcs8::{EncodePrivateKey, LineEnding};
use rand::{rngs::SysRng, TryRng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::error::AuthError;

/// The token algorithm: EdDSA over Curve25519 (Ed25519).
const TOKEN_ALGORITHM: Algorithm = Algorithm::EdDSA;

/// Access-token lifetime applied when claims are minted without an explicit
/// TTL (house default: 15 minutes).
pub const DEFAULT_ACCESS_TTL_SECS: i64 = 900;

/// Clock-skew tolerance for `exp` checks, in seconds (house value).
const CLOCK_SKEW_LEEWAY_SECS: u64 = 5;

/// The Ed25519 **private** key PEM inside the keys directory. Mode 0600.
const SIGNING_KEY_FILE: &str = "jwt-signing-key.pem";

/// The Ed25519 **public** key PEM inside the keys directory. jsonwebtoken's
/// decoder accepts only the public form, so the pair is stored separately.
const VERIFY_KEY_FILE: &str = "jwt-verify-key.pem";

/// Advisory lock against concurrent first-boot key generation, next to the
/// key pair on the shared keys volume (`JwtKeys::load_or_create` holds it
/// across the whole read-or-generate window, unix only).
#[cfg(unix)]
const KEY_LOCK_FILE: &str = "jwt-keys.lock";

/// Standard claims of a Wardstone access token.
///
/// The house's `sub: String` subject is carried as a typed field instead:
/// the plan diverges here so callers read `user_id` directly rather than
/// round-tripping a UUID through a string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    /// The authenticated user's id.
    pub user_id: Uuid,
    /// The user's display name (convenience for audit rows and logging).
    pub username: String,
    /// The role the user holds at mint time; enforcement reads capabilities
    /// by user id, not from this string.
    pub role: String,
    /// The refresh token's id — the session identity the audit row records.
    /// Set at login, when the refresh token is minted.
    pub sid: Option<Uuid>,
    /// Expiry (unix seconds).
    pub exp: i64,
    /// Issued-at (unix seconds).
    pub iat: i64,
    /// Unique token id.
    pub jti: String,
}

impl AccessClaims {
    /// Mint claims for `user_id`, valid for `ttl_secs` from now, carrying the
    /// refresh-token id the login flow has just minted (`sid`).
    pub fn new(
        user_id: Uuid,
        username: &str,
        role: &str,
        sid: Option<Uuid>,
        ttl_secs: i64,
    ) -> Self {
        let now = Utc::now();
        Self {
            user_id,
            username: username.to_owned(),
            role: role.to_owned(),
            sid,
            iat: now.timestamp(),
            exp: (now + Duration::seconds(ttl_secs)).timestamp(),
            jti: Uuid::new_v4().to_string(),
        }
    }
}

/// Claims carried by a refresh token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshClaims {
    /// The user the session belongs to.
    pub user_id: Uuid,
    /// Unique token id.
    pub jti: String,
    /// Expiry (unix seconds).
    pub exp: i64,
}

impl RefreshClaims {
    /// Mint refresh claims for `user_id`, valid for `ttl_secs` from now.
    pub fn new(user_id: Uuid, ttl_secs: i64) -> Self {
        Self {
            user_id,
            jti: Uuid::new_v4().to_string(),
            exp: (Utc::now() + Duration::seconds(ttl_secs)).timestamp(),
        }
    }
}

/// The Ed25519 key pair Wardstone signs access tokens with.
///
/// Never print this: the signing key's PEM is the authentication material and
/// `Debug` redacts it.
#[derive(Clone)]
pub struct JwtKeys {
    /// Ed25519 private key, PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`).
    pub signing_key_pem: String,
    /// Ed25519 public key, SPKI PEM (`-----BEGIN PUBLIC KEY-----`).
    pub verification_key_pem: String,
    /// Access-token lifetime in seconds, for claim minting by the login flow.
    pub ttl_secs: i64,
}

impl std::fmt::Debug for JwtKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtKeys")
            .field("signing_key_pem", &"<redacted>")
            .field("verification_key_pem", &self.verification_key_pem)
            .field("ttl_secs", &self.ttl_secs)
            .finish()
    }
}

impl JwtKeys {
    /// Load the key pair from `dir`, or — on a virgin volume — generate it.
    ///
    /// The binary loads the keys **before** the setup form exists, so a fresh
    /// volume must be able to produce the pair here: when `dir` does not
    /// exist it is created (mode 0700), and when both key files are absent a
    /// new Ed25519 pair is written into it. When both files are present they
    /// are proven to form one usable pair first (see
    /// [`assert_pair_usable`]), so every boot signs with the same key and a
    /// corrupted pair never silently pretends to authenticate.
    ///
    /// Concurrency is part of the deployment shape: the compose bundle's
    /// `ui` and `api` processes boot simultaneously and share the keys
    /// volume, so on unix every call holds an exclusive advisory lock on a
    /// sibling lockfile across the whole read-or-generate window. A taker
    /// that arrives mid-generation waits out the winner's complete two-file
    /// write instead of generating its own divergent pair over it — the
    /// collision that once left the deployed volume with a signing and a
    /// verification key from two different pairs (every then-issued token
    /// failed its own validation on first use). The lock is advisory:
    /// closing the file releases it, so a crashed holder cannot wedge the
    /// next boot.
    ///
    /// Exactly one of the two files present is a torn state (e.g. a restore
    /// that only carried the signing key). It is surfaced as a typed
    /// configuration error instead of being "healed": re-keying underneath
    /// live sessions would silently invalidate every outstanding token, and
    /// regenerating a mismatched verification key would disable *all*
    /// validation. The operator restores the missing file, or removes both
    /// to re-key.
    pub fn load_or_create(dir: &Path) -> Result<Self, AuthError> {
        let created = !dir.exists();
        if created {
            fs::create_dir_all(dir).map_err(|e| {
                AuthError::Config(format!(
                    "cannot create JWT key directory {}: {e}",
                    dir.display()
                ))
            })?;
            #[cfg(unix)]
            force_mode(dir, 0o700)?;
        }

        // Held for the remainder of the call; dropping the file releases
        // the lock before any result is built.
        #[cfg(unix)]
        let _creation_lock = lock_keys_dir(dir)?;

        let signing_key_pem = read_key_file(&dir.join(SIGNING_KEY_FILE))?;
        let verification_key_pem = read_key_file(&dir.join(VERIFY_KEY_FILE))?;

        match (signing_key_pem, verification_key_pem) {
            (Some(signing_key_pem), Some(verification_key_pem)) => {
                assert_pair_usable(&signing_key_pem, &verification_key_pem, dir)?;
                Ok(Self {
                    signing_key_pem,
                    verification_key_pem,
                    ttl_secs: DEFAULT_ACCESS_TTL_SECS,
                })
            }
            (None, None) => {
                let (signing_key_pem, verification_key_pem) = generate_key_pair()?;
                write_key_file(&dir.join(SIGNING_KEY_FILE), &signing_key_pem, 0o600)?;
                write_key_file(&dir.join(VERIFY_KEY_FILE), &verification_key_pem, 0o644)?;
                // Prove what was written forms the working pair — defense in
                // depth against a future write-path defect, at probe cost.
                assert_pair_usable(&signing_key_pem, &verification_key_pem, dir)?;
                Ok(Self {
                    signing_key_pem,
                    verification_key_pem,
                    ttl_secs: DEFAULT_ACCESS_TTL_SECS,
                })
            }
            _ => Err(AuthError::Config(format!(
                "incomplete JWT key pair in {}: '{}' and '{}' must both be present; \
                 restore the missing file, or remove both to re-key",
                dir.display(),
                SIGNING_KEY_FILE,
                VERIFY_KEY_FILE
            ))),
        }
    }
}

/// Advisory cross-process serialization for [`JwtKeys::load_or_create`]
/// (unix only): an exclusive, blocking file lock on `jwt-keys.lock` beside
/// the key pair. A file lock is tied to the open file description, so each
/// caller opens its own handle: concurrent callers block until the holder
/// closes its file, and a crashed holder's handle closes with it — no
/// stale-lock state can accumulate. The lockfile holds no bytes and is
/// never removed; deleting it would break mutual exclusion for a caller
/// holding a handle on the deleted inode.
#[cfg(unix)]
fn lock_keys_dir(dir: &Path) -> Result<fs::File, AuthError> {
    use std::os::unix::fs::OpenOptionsExt;

    let lock_path = dir.join(KEY_LOCK_FILE);
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|e| {
            AuthError::Config(format!(
                "cannot open the JWT keys lock file {}: {e}",
                lock_path.display()
            ))
        })?;
    force_mode(&lock_path, 0o600)?;
    file.lock().map_err(|e| {
        AuthError::Config(format!(
            "cannot acquire the exclusive JWT keys lock on {}: {e}",
            dir.display()
        ))
    })?;
    Ok(file)
}

/// Prove the on-disk (or freshly generated) two-file pair is **usable**: a
/// probe token signed with the signing PEM must decode under the
/// verification PEM. This is deliberately the same `jsonwebtoken` path the
/// runtime itself pays (`issue_access_token` → `validate_access_token`), so
/// the check certifies exactly the property the service depends on rather
/// than a structural stand-in for it.
///
/// The case it exists for: both files present, each individually intact,
/// but written by two different `load_or_create` callers — a concurrent
/// virgin-volume boot race on a shared keys volume. The mixed pair loads
/// without error, makes every freshly minted token fail its own
/// verification on first use, and turns the login flow into: issued → 401
/// on the identity fetch, forever. It is refused as a configuration error
/// carrying the recovery hint, mirroring the torn-state arm above; the
/// operators re-key deliberately per the documented procedure.
fn assert_pair_usable(
    signing_pem: &str,
    verification_pem: &str,
    dir: &Path,
) -> Result<(), AuthError> {
    let hint = format!("remove both from {} to re-key", dir.display());

    let encoding = EncodingKey::from_ed_pem(signing_pem.as_bytes()).map_err(|e| {
        AuthError::Config(format!(
            "the JWT signing key {} in {} does not parse as Ed25519 \
             PKCS#8 private key material ({e}); remove both to re-key",
            SIGNING_KEY_FILE,
            dir.display()
        ))
    })?;
    let decoding = DecodingKey::from_ed_pem(verification_pem.as_bytes()).map_err(|e| {
        AuthError::Config(format!(
            "the JWT verification key {} in {} does not parse as Ed25519 \
             public key material ({e}); remove both to re-key",
            VERIFY_KEY_FILE,
            dir.display()
        ))
    })?;

    let mut validation = Validation::new(TOKEN_ALGORITHM);
    validation.validate_exp = false;
    validation.required_spec_claims = HashSet::new();
    let probe_claims = serde_json::json!({ "pair-probe": true });
    let probe_token =
        encode(&Header::new(TOKEN_ALGORITHM), &probe_claims, &encoding).map_err(|e| {
            AuthError::Config(format!(
                "the JWT signing key {} in {} cannot sign a probe token ({e}); \
             remove both to re-key",
                SIGNING_KEY_FILE,
                dir.display()
            ))
        })?;
    if let Err(e) = decode::<serde_json::Value>(&probe_token, &decoding, &validation) {
        return Err(AuthError::Config(format!(
            "the JWT key pair in {} is mixed or invalid: a probe signed with \
             '{}' does not verify under '{}' ({e}); {hint}",
            dir.display(),
            SIGNING_KEY_FILE,
            VERIFY_KEY_FILE
        )));
    }
    Ok(())
}

/// Write BOTH PEMs as ONE sealed envelope (`jwt-keys.envelope`): the pair
/// travels under the operator's KeyEnvelope and exists on disk ONLY as
/// inert ciphertext. The legacy plaintext pair's re-key-by-deletion
/// recovery becomes a post-unlock operator action.
pub fn write_sealed(
    path: &Path,
    passphrase: &str,
    keys: &JwtKeys,
) -> Result<(), crate::error::AuthError> {
    let combined = serde_json::json!({
        "signing": keys.signing_key_pem.as_str(),
        "verification": keys.verification_key_pem,
    })
    .to_string();
    ws_core::crypto::KeyEnvelope::write_envelope(
        path,
        passphrase,
        combined.as_bytes(),
        ws_core::crypto::PROD_KDF_PARAMS,
    )
    .map_err(|e| crate::error::AuthError::Crypto(format!("jwt key envelope: {e}")))
}

/// Open the sealed pair from `path` with the passphrase.
///
/// A torn PAIR (one plaintext file present, or an envelope whose stored
/// JSON lost one half) is the same typed torn-state failure as ever —
/// sealing never heals what the loader refuses.
pub fn load_sealed(path: &Path, passphrase: &str) -> Result<JwtKeys, crate::error::AuthError> {
    let opened =
        ws_core::crypto::KeyEnvelope::open_envelope(path, passphrase).map_err(|e| match e {
            ws_core::error::CoreError::Crypto(m) if m.contains("master passphrase") => {
                crate::error::AuthError::Crypto(
                    "the master passphrase is wrong for the jwt key envelope".to_string(),
                )
            }
            ws_core::error::CoreError::Config(m) | ws_core::error::CoreError::Crypto(m) => {
                crate::error::AuthError::Config(format!(
                    "jwt key envelope {}: {}",
                    path.display(),
                    m
                ))
            }
            _ => crate::error::AuthError::Crypto(format!("jwt key envelope open failed: {e}")),
        })?;
    let body: serde_json::Value = serde_json::from_slice(&opened).map_err(|_| {
        crate::error::AuthError::Crypto(
            "the jwt key envelope payload is not valid JSON".to_string(),
        )
    })?;
    let signing = body["signing"].as_str().ok_or_else(|| {
        crate::error::AuthError::Crypto(
            "the jwt key envelope payload lacks the signing key".to_string(),
        )
    })?;
    let verification = body["verification"].as_str().ok_or_else(|| {
        crate::error::AuthError::Crypto(
            "the jwt key envelope payload lacks the verification key".to_string(),
        )
    })?;
    Ok(JwtKeys {
        signing_key_pem: signing.to_string(),
        verification_key_pem: verification.to_string(),
        ttl_secs: DEFAULT_ACCESS_TTL_SECS,
    })
}

/// Sign the given claims as a compact EdDSA JWT.
pub fn issue_access_token(claims: &AccessClaims, keys: &JwtKeys) -> Result<String, AuthError> {
    let key = EncodingKey::from_ed_pem(keys.signing_key_pem.as_bytes())
        .map_err(|e| AuthError::Crypto(format!("invalid JWT signing key: {e}")))?;
    encode(&Header::new(TOKEN_ALGORITHM), claims, &key)
        .map_err(|e| AuthError::Crypto(format!("access-token encoding failed: {e}")))
}

/// Validate a token's EdDSA signature and expiry, returning its claims.
pub fn validate_access_token(token: &str, keys: &JwtKeys) -> Result<AccessClaims, AuthError> {
    let key = DecodingKey::from_ed_pem(keys.verification_key_pem.as_bytes())
        .map_err(|e| AuthError::Crypto(format!("invalid JWT verification key: {e}")))?;
    let mut validation = Validation::new(TOKEN_ALGORITHM);
    validation.leeway = CLOCK_SKEW_LEEWAY_SECS;

    decode::<AccessClaims>(token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|e| match e.kind() {
            ErrorKind::ExpiredSignature => AuthError::TokenExpired,
            _ => AuthError::TokenInvalid,
        })
}

/// Draw a fresh Ed25519 key pair with the pinned `rand` 0.10's OS entropy.
///
/// [`SigningKey::generate`] is gated on ed25519-dalek's `rand_core` feature,
/// which needs rand_core 0.6 and does not compile against the workspace's
/// rand 0.10 — so the 32-byte seed is drawn directly and fed to
/// [`SigningKey::from_bytes`], with no rand_core version involved.
///
/// The private key is written as a PKCS#8 v1 PEM, byte-compatible with the
/// house's `openssl genpkey -algorithm ed25519` output, so a key generated
/// here and a key generated by the house's scripts are interchangeable;
/// the verification key is the matching SPKI PEM (`openssl pkey -pubout`).
fn generate_key_pair() -> Result<(String, String), AuthError> {
    let mut seed = [0u8; 32];
    SysRng.try_fill_bytes(&mut seed).map_err(|e| {
        AuthError::Crypto(format!("os entropy unavailable for the JWT key pair: {e}"))
    })?;

    let signing_key = SigningKey::from_bytes(&seed);
    let signing_pem = KeypairBytes {
        secret_key: seed,
        public_key: None,
    }
    .to_pkcs8_pem(LineEnding::LF)
    .map_err(|e| AuthError::Crypto(format!("signing-key encoding failed: {e}")))?
    .to_string();

    let verification_pem = signing_key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| AuthError::Crypto(format!("verification-key encoding failed: {e}")))?;

    seed.zeroize();
    Ok((signing_pem, verification_pem))
}

/// Read a key file, distinguishing "absent" (the virgin-volume case) from
/// "present but unreadable" and "present but empty".
fn read_key_file(path: &Path) -> Result<Option<String>, AuthError> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            if contents.trim().is_empty() {
                Err(AuthError::Config(format!(
                    "key file {} is empty",
                    path.display()
                )))
            } else {
                Ok(Some(contents))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(AuthError::Config(format!(
            "cannot read key file {}: {e}",
            path.display()
        ))),
    }
}

/// Write key material crash-atomically: the bytes land in a sibling `.tmp`
/// file that is fsynced and renamed over the destination (house pattern, from
/// ws-ca's keystore), so a crash mid-write can never leave a truncated key
/// under the real name, and the exact mode is forced rather than relying on
/// umask.
#[cfg(unix)]
fn write_key_file(path: &Path, contents: &str, mode: u32) -> Result<(), AuthError> {
    use std::os::unix::fs::OpenOptionsExt;

    let tmp = path.with_extension("tmp");
    let write = || -> Result<(), AuthError> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .map_err(|e| AuthError::Config(format!("cannot create {}: {e}", tmp.display())))?;
        file.write_all(contents.as_bytes())
            .map_err(|e| AuthError::Config(format!("cannot write {}: {e}", tmp.display())))?;
        file.sync_all()
            .map_err(|e| AuthError::Config(format!("cannot sync {}: {e}", tmp.display())))?;
        drop(file);
        force_mode(&tmp, mode)?;
        fs::rename(&tmp, path).map_err(|e| {
            AuthError::Config(format!("cannot rename into place {}: {e}", path.display()))
        })?;
        // Durability of the rename itself: without a parent-directory fsync,
        // a power cut could roll the rename back — and with it the only copy
        // of the signing key.
        if let Some(parent) = path.parent() {
            fs::File::open(parent)
                .and_then(|p| p.sync_all())
                .map_err(|e| {
                    AuthError::Config(format!(
                        "cannot sync key directory {}: {e}",
                        parent.display()
                    ))
                })?;
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
fn write_key_file(path: &Path, contents: &str, _mode: u32) -> Result<(), AuthError> {
    fs::write(path, contents)
        .map_err(|e| AuthError::Config(format!("cannot write {}: {e}", path.display())))
}

/// Force the exact permission bits (not umask-masked) on a path, unix only.
#[cfg(unix)]
fn force_mode(path: &Path, mode: u32) -> Result<(), AuthError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| {
        AuthError::Config(format!(
            "cannot set mode {mode:o} on {}: {e}",
            path.display()
        ))
    })
}
