//! Ed25519 (EdDSA) access-token issuing and validation, plus the on-disk
//! signing/verification key pair.
//!
//! The house keeps exactly two key files: the signing key's PEM (mode 0600)
//! and the verification key's PEM. `jsonwebtoken`'s `DecodingKey::from_ed_pem`
//! accepts only an Ed25519 *public*-key PEM — a private PKCS#8 PEM is rejected
//! with `InvalidKeyFormat` — so the private key cannot double as the
//! verification key and the two-file layout is required.

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
    /// are returned untouched, so every boot signs with the same key.
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

        let signing_key_pem = read_key_file(&dir.join(SIGNING_KEY_FILE))?;
        let verification_key_pem = read_key_file(&dir.join(VERIFY_KEY_FILE))?;

        match (signing_key_pem, verification_key_pem) {
            (Some(signing_key_pem), Some(verification_key_pem)) => Ok(Self {
                signing_key_pem,
                verification_key_pem,
                ttl_secs: DEFAULT_ACCESS_TTL_SECS,
            }),
            (None, None) => {
                let (signing_key_pem, verification_key_pem) = generate_key_pair()?;
                write_key_file(&dir.join(SIGNING_KEY_FILE), &signing_key_pem, 0o600)?;
                write_key_file(&dir.join(VERIFY_KEY_FILE), &verification_key_pem, 0o644)?;
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
