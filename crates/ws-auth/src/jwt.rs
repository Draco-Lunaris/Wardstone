//! Ed25519 (EdDSA) access-token issuing and validation, plus the key pair
//! that signs them.
//!
//! The signing half lives in the process's protected arena (`ws_secmem`:
//! never swapped, never in a core dump, volatilely wiped on drop) as
//! PKCS#8 DER — minted there by [`JwtKeys::generate`], parsed there from
//! the sealed envelope's payload, and fed to `EncodingKey::from_ed_der`
//! per mint.
//!
//! The pair's only on-disk form is the sealed envelope
//! (`jwt-keys.envelope`). `jsonwebtoken`'s `DecodingKey::from_ed_pem`
//! accepts only an Ed25519 *public*-key PEM — a private PKCS#8 PEM is
//! rejected with `InvalidKeyFormat` — so the envelope payload and the
//! in-memory verification half carry the public PEM form.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use chrono::{Duration, Utc};
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePublicKey, KeypairBytes};
use ed25519_dalek::SigningKey;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use pkcs8::{EncodePrivateKey, LineEnding};
use rand::{rngs::SysRng, TryRng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use ws_secmem::SecretBuf;
use zeroize::{Zeroize, Zeroizing};

use crate::error::AuthError;

/// The token algorithm: EdDSA over Curve25519 (Ed25519).
const TOKEN_ALGORITHM: Algorithm = Algorithm::EdDSA;

/// Access-token lifetime applied when the pair is loaded or minted without
/// an explicit TTL (house default: 15 minutes). Carried as `u64` — the
/// [`JwtKeys`] custody shape; the claim-minting arithmetic converts at its
/// own edge.
pub const DEFAULT_ACCESS_TTL_SECS: u64 = 900;

/// Clock-skew tolerance for `exp` checks, in seconds (house value).
const CLOCK_SKEW_LEEWAY_SECS: u64 = 5;

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
/// The signing half is the PKCS#8 DER private key held in the process's
/// protected arena (a `ws_secmem::SecretBuf`: never swapped, never in a
/// core dump, volatilely wiped on drop) — the authentication material
/// never sits on the heap. Never print any of it: `Debug` redacts BOTH
/// halves (the public PEM too — it names the instance's key, and a
/// rendered Debug must give nothing away).
///
/// Deliberately not `Clone` — a copy would be a second plaintext of the
/// signing key, and the arena's promise is that exactly one exists.
/// Shared custody is `Arc<JwtKeys>` (what `AppState` holds).
pub struct JwtKeys {
    /// Ed25519 private key, PKCS#8 DER, in the protected arena.
    pub signing_key: SecretBuf,
    /// Ed25519 public key, SPKI PEM (`-----BEGIN PUBLIC KEY-----`).
    pub verification_key_pem: String,
    /// Access-token lifetime in seconds, for claim minting by the login flow.
    pub ttl_secs: u64,
}

impl std::fmt::Debug for JwtKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtKeys")
            .field("signing_key", &"<redacted>")
            .field("verification_key_pem", &"<redacted>")
            .field("ttl_secs", &self.ttl_secs)
            .finish()
    }
}

impl JwtKeys {
    /// Mint a fresh Ed25519 pair for the sealed custody: the signing key
    /// is born straight into the protected arena as PKCS#8 DER (no PEM
    /// form and no plaintext file ever exists), and the public half is
    /// the matching SPKI PEM. The caller seals the pair with
    /// [`write_sealed`] under the volume's generation.
    ///
    /// The minted pair is proven usable by the sealed loaders before it
    /// is trusted ([`assert_pair_usable`]) — this constructor only draws
    /// the key material.
    pub fn generate(ttl_secs: u64) -> Result<Self, AuthError> {
        let (signing_der, verification_pem) = generate_der_and_verification_pem()?;
        let signing_key = arena_copy(signing_der.as_slice())?;
        Ok(JwtKeys {
            signing_key,
            verification_key_pem: verification_pem,
            ttl_secs,
        })
    }

    /// Build the pair from its PEM forms — the engine behind the sealed
    /// loaders' parse of the envelope payload (whose deployed format is
    /// PEM halves, unchanged). The
    /// signing PEM is parsed to its canonical PKCS#8 DER — deterministic
    /// per PEM, so the same PEM always yields the same DER — and copied
    /// into the protected arena; the public PEM is carried as-is.
    ///
    /// The pair is NOT probed here: every loader probes what it reads or
    /// writes ([`assert_pair_usable`]) before trusting it.
    pub fn from_pem_pair(
        signing_pem: &str,
        verification_pem: &str,
        ttl_secs: u64,
    ) -> Result<Self, AuthError> {
        let keypair = KeypairBytes::from_pkcs8_pem(signing_pem).map_err(|e| {
            AuthError::Crypto(format!(
                "the JWT signing key does not parse as Ed25519 PKCS#8 private key material: {e}"
            ))
        })?;
        let der = keypair.to_pkcs8_der().map_err(|e| {
            AuthError::Crypto(format!("the JWT signing key's DER encoding failed: {e}"))
        })?;
        let signing_key = arena_copy(der.as_bytes())?;
        Ok(JwtKeys {
            signing_key,
            verification_key_pem: verification_pem.to_owned(),
            ttl_secs,
        })
    }
}

/// Prove the pair is **usable**: a probe token signed with the signing
/// PEM must decode under the verification PEM. This is deliberately the
/// same `jsonwebtoken` path the runtime itself pays (`issue_access_token`
/// → `validate_access_token`), so the check certifies exactly the
/// property the service depends on rather than a structural stand-in for
/// it.
///
/// The case it exists for: a mixed pair — halves from two different mints
/// or epochs — loads without error, makes every freshly minted token fail
/// its own verification on first use, and turns the login flow into:
/// issued → 401 on the identity fetch, forever. It is refused as a typed
/// error at the load (or before the first seal), so the operators re-key
/// deliberately instead of booting on a key whose tokens fail their own
/// verification on first use.
fn assert_pair_usable(signing_pem: &str, verification_pem: &str) -> Result<(), AuthError> {
    let encoding = EncodingKey::from_ed_pem(signing_pem.as_bytes()).map_err(|e| {
        AuthError::Config(format!(
            "the JWT signing key does not parse as Ed25519 \
             PKCS#8 private key material ({e})"
        ))
    })?;
    let decoding = DecodingKey::from_ed_pem(verification_pem.as_bytes()).map_err(|e| {
        AuthError::Config(format!(
            "the JWT verification key does not parse as Ed25519 \
             public key material ({e})"
        ))
    })?;

    let mut validation = Validation::new(TOKEN_ALGORITHM);
    validation.validate_exp = false;
    validation.required_spec_claims = HashSet::new();
    let probe_claims = serde_json::json!({ "pair-probe": true });
    let probe_token =
        encode(&Header::new(TOKEN_ALGORITHM), &probe_claims, &encoding).map_err(|e| {
            AuthError::Config(format!(
                "the JWT signing key cannot sign a probe token ({e})"
            ))
        })?;
    if let Err(e) = decode::<serde_json::Value>(&probe_token, &decoding, &validation) {
        return Err(AuthError::Config(format!(
            "the JWT key pair is mixed or invalid: a probe signed with \
             the signing key does not verify under the verification key ({e})"
        )));
    }
    Ok(())
}

/// Copy bytes into the protected arena — the one boundary the JWT signing
/// key crosses into custody. The source stays the caller's to wipe; the
/// arena copy is wiped on drop.
fn arena_copy(bytes: &[u8]) -> Result<SecretBuf, AuthError> {
    let mem = ws_secmem::global()
        .map_err(|e| AuthError::Crypto(format!("protected memory for the JWT signing key: {e}")))?;
    mem.alloc_copy(bytes)
        .map_err(|e| AuthError::Crypto(format!("protected memory for the JWT signing key: {e}")))
}

/// The signing key's PEM form, derived from the arena DER copy. The
/// deployed envelope payload (and the legacy two-file layout) speak PEM,
/// so this is the one place the DER crosses back; the returned `String`
/// is ordinary heap memory a `String` cannot wipe, so it must never
/// outlive the single operation that needs it.
fn signing_pem_of(keys: &JwtKeys) -> Result<String, AuthError> {
    let keypair = KeypairBytes::from_pkcs8_der(&keys.signing_key).map_err(|e| {
        AuthError::Crypto(format!(
            "the JWT signing key does not parse as Ed25519 PKCS#8 private key material: {e}"
        ))
    })?;
    let pem = keypair.to_pkcs8_pem(LineEnding::LF).map_err(|e| {
        AuthError::Crypto(format!("the JWT signing key's PEM encoding failed: {e}"))
    })?;
    Ok(pem.to_string())
}

/// The envelope KDF takes the passphrase as UTF-8 (argon2's input is a
/// `&str`); the byte-shaped callers hand the relayed raw bytes through.
/// A non-UTF-8 passphrase is a typed configuration refusal — the
/// message names the condition, never the passphrase.
fn utf8_passphrase(passphrase: &[u8]) -> Result<&str, AuthError> {
    std::str::from_utf8(passphrase)
        .map_err(|_| AuthError::Config("the master passphrase is not valid UTF-8".to_string()))
}

/// Write BOTH PEMs as ONE sealed envelope (`jwt-keys.envelope`): the pair
/// travels under the operator's KeyEnvelope and exists on disk ONLY as
/// inert ciphertext. The `generation` is the volume's passphrase epoch
/// (a changed passphrase re-wraps this envelope at epoch + 1 like every
/// other).
///
/// The payload format — `{"signing": <PEM>, "verification": <PEM>}` — is
/// the deployed-volume contract and is UNCHANGED: the signing PEM is
/// derived here from the arena's DER copy, so an envelope written by an
/// earlier build opens byte for byte. The passphrase arrives as raw
/// bytes (the relay's shape); only its UTF-8 view feeds the KDF.
pub fn write_sealed(
    path: &Path,
    passphrase: &[u8],
    keys: &JwtKeys,
    generation: u64,
) -> Result<(), crate::error::AuthError> {
    let signing_pem = signing_pem_of(keys)?;
    let combined = serde_json::json!({
        "signing": signing_pem,
        "verification": keys.verification_key_pem,
    })
    .to_string();
    ws_core::crypto::KeyEnvelope::write_envelope(
        path,
        utf8_passphrase(passphrase)?,
        combined.as_bytes(),
        ws_core::crypto::PROD_KDF_PARAMS,
        generation,
    )
    .map_err(|e| crate::error::AuthError::Crypto(format!("jwt key envelope: {e}")))
}

/// Open the sealed pair from `path` with the passphrase.
///
/// A torn payload (an envelope whose stored JSON lost one half) is the
/// same typed torn-state failure as ever — sealing never heals what the
/// loader refuses.
pub fn load_sealed(path: &Path, passphrase: &[u8]) -> Result<JwtKeys, crate::error::AuthError> {
    let opened = ws_core::crypto::KeyEnvelope::open_envelope(path, utf8_passphrase(passphrase)?)
        .map_err(|e| match e {
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
    // The pair probe (F9, the final review): the same check run before
    // the first seal. Sealing must not launder a broken pair — an
    // envelope whose halves came from different pairs refuses HERE, at
    // the load, never boots with a key whose tokens fail their own
    // verification on first use.
    assert_pair_usable(signing, verification)?;
    JwtKeys::from_pem_pair(signing, verification, DEFAULT_ACCESS_TTL_SECS)
}

/// The sealed boot's load-or-create: open the envelope when it exists;
/// mint a fresh pair IN the protected arena and seal it as the envelope
/// when it does
/// not. A fresh password-less install has no plaintext pair to convert
/// (nothing ever minted one), so the pair is BORN sealed — no plaintext
/// file is ever written. The minted pair is proven usable before it is
/// sealed (the same probe the sealed open runs on what it reads).
/// The mint stamps the volume's `generation` (the unlock reads it from
/// the master envelope first), so a mid-change crash leaves no envelope
/// from a foreign epoch.
pub fn load_or_create_sealed(
    path: &Path,
    passphrase: &[u8],
    generation: u64,
) -> Result<JwtKeys, crate::error::AuthError> {
    let passphrase = utf8_passphrase(passphrase)?;
    if path.exists() {
        return load_sealed(path, passphrase.as_bytes());
    }
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| {
            AuthError::Config(format!(
                "cannot create JWT key directory {}: {e}",
                dir.display()
            ))
        })?;
        #[cfg(unix)]
        force_mode(&dir, 0o700)?;
    }
    // Mint straight into the protected arena — no signing-key PEM ever
    // exists on this path — then prove the pair usable (the same probe
    // the sealed open runs) before sealing it.
    let keys = JwtKeys::generate(DEFAULT_ACCESS_TTL_SECS)?;
    assert_pair_usable(&signing_pem_of(&keys)?, &keys.verification_key_pem)?;
    write_sealed(path, passphrase.as_bytes(), &keys, generation)?;
    Ok(keys)
}

/// Sign the given claims as a compact EdDSA JWT.
///
/// The `EncodingKey` is built from the arena's DER copy per mint and
/// dropped as soon as `encode` returns — jsonwebtoken's `EncodingKey`
/// derives `ZeroizeOnDrop`, so its own copy of the key is wiped on drop
/// (verified against the registry source for this task's zeroization
/// table). Holding the key material any longer than one mint would pin
/// an arena granule per outstanding token; building per mint keeps the
/// live custody exactly one reservation (the `JwtKeys` itself).
pub fn issue_access_token(claims: &AccessClaims, keys: &JwtKeys) -> Result<String, AuthError> {
    let key = EncodingKey::from_ed_der(&keys.signing_key);
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

/// Mint the signing key straight as PKCS#8 DER — the sealed custody's
/// form; no signing-key PEM ever exists on that path — plus the matching
/// verification SPKI PEM. The 32-byte seed is drawn from the pinned
/// `rand` 0.10's OS entropy and fed to [`SigningKey::from_bytes`]:
/// `SigningKey::generate` is gated on ed25519-dalek's `rand_core`
/// feature, which needs rand_core 0.6 and does not compile against the
/// workspace's rand 0.10. The DER travels in a zeroizing buffer until
/// `arena_copy` takes it into the pool.
fn generate_der_and_verification_pem() -> Result<(Zeroizing<Vec<u8>>, String), AuthError> {
    let mut seed = [0u8; 32];
    SysRng.try_fill_bytes(&mut seed).map_err(|e| {
        AuthError::Crypto(format!("os entropy unavailable for the JWT key pair: {e}"))
    })?;

    let signing_key = SigningKey::from_bytes(&seed);
    let keypair = KeypairBytes {
        secret_key: seed,
        public_key: None,
    };
    let der = keypair
        .to_pkcs8_der()
        .map_err(|e| AuthError::Crypto(format!("signing-key encoding failed: {e}")))?;

    let verification_pem = signing_key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| AuthError::Crypto(format!("verification-key encoding failed: {e}")))?;

    seed.zeroize();
    Ok((Zeroizing::new(der.as_bytes().to_vec()), verification_pem))
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
