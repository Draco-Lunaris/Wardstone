//! Root and sub-CA creation: key generation, certificate issuance, and
//! encrypted key storage in one step.
//!
//! [`create_root`] mints a self-signed trust anchor; [`create_sub_ca`]
//! mints an intermediate signed by an existing parent CA. Both generate a
//! fresh private key for the new CA (Ed25519, RSA-2048, or RSA-3072 per
//! [`KeyType`]), build the certificate per the pinned Wardstone CA
//! profile, store the private key in the [`KeyStore`] envelope format
//! under a fresh UUID, and return the PEM certificate plus the PKCS#8 DER
//! private key (zeroized on drop).
//!
//! # Certificate profile
//!
//! - Subject: `CN=<spec.subject>` (UTF8String) — the only DN attribute.
//! - Validity: `not_before` is midnight UTC one day before today (a
//!   one-day clock-skew margin); `not_after` is midnight UTC exactly the
//!   lifetime's day count later (root 10 years, sub-CA 5 years, leaf 30
//!   days, years counted as 365 days).
//! - Root: BasicConstraints `CA:TRUE` critical without pathlen; KeyUsage
//!   `digitalSignature | keyCertSign | cRLSign` critical.
//! - Sub-CA: BasicConstraints `CA:TRUE, pathlen:0` critical; KeyUsage
//!   `keyCertSign | cRLSign` critical; AuthorityKeyIdentifier copied from
//!   the parent's SubjectKeyIdentifier.
//! - SKI is rcgen's default (RFC 7093 method 1: truncated SHA-256 of the
//!   subject public key info); serial numbers are 16 fresh OS-entropy
//!   bytes, never rcgen's deterministic hash-derived default (`new_serial`
//!   documents why).
//!
//! # Key material handling
//!
//! Private keys exist in memory only inside [`Zeroizing`] buffers or the
//! internal [`ZeroizingKey`] wrapper, whose drop zeroizes rcgen's
//! serialized PKCS#8 copy on every exit path including `?` errors. At
//! rest the key appears only inside the keystore's two-layer AEAD
//! envelope. No error variant ever carries key material: `rsa` failures
//! are mapped through static, key-free messages.
//!
//! # `create_sub_ca` caller contract
//!
//! The caller supplies the parent's certificate PEM together with the
//! parent's DER private key (PKCS#8, as loaded from the keystore), and the
//! two must belong to the same CA: the child's issuer DN and AKI are taken
//! from the certificate while the signature is produced by the key, so a
//! mismatched pair would silently produce a broken chain.
//! [`create_sub_ca`] therefore verifies the key's public half against the
//! certificate's subject public key before signing and fails with
//! [`CaError::X509`] on mismatch.

use chrono::{Datelike, Utc};
use rand::{rngs::SysRng, TryRng};
use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    IsCa, Issuer, KeyPair, KeyUsagePurpose, PublicKeyData, SerialNumber, SignatureAlgorithm,
    SigningKey, PKCS_ECDSA_P256_SHA256, PKCS_ED25519,
};
use rsa::pkcs8::EncodePrivateKey;
use rsa::rand_core::{self, CryptoRng, RngCore};
use rsa::RsaPrivateKey;
use uuid::Uuid;
use x509_parser::asn1_rs::FromDer;
use x509_parser::pem::parse_x509_pem;
use x509_parser::x509::SubjectPublicKeyInfo;
use zeroize::{Zeroize, Zeroizing};

pub use ws_core::models::ca::KeyType;

use crate::error::CaError;
use crate::keystore::KeyStore;

/// Specification for one new CA.
#[derive(Debug, Clone)]
pub struct CaSpec {
    /// Operator-facing CA name (stored in the `cas` DB row by Plan 2's
    /// bootstrap; never written into the certificate).
    pub name: String,
    /// Subject common name written into the certificate.
    pub subject: String,
    /// Key algorithm for the generated private key.
    pub key_type: KeyType,
    /// Lifetime class (root / sub-CA / leaf) selecting the validity span.
    pub lifetime: CaLifetime,
}

/// Lifetime class of a Wardstone certificate: root = 10 years,
/// sub-CA = 5 years, leaf = 30 days (years counted as 365 days).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaLifetime {
    /// Self-signed trust anchor: 10 years.
    Root,
    /// Intermediate CA: 5 years.
    SubCa,
    /// End-entity certificate: 30 days.
    Leaf,
}

impl CaLifetime {
    /// Validity span for this lifetime class.
    pub fn duration(&self) -> chrono::Duration {
        match self {
            CaLifetime::Root => chrono::Duration::days(3650),
            CaLifetime::SubCa => chrono::Duration::days(1825),
            CaLifetime::Leaf => chrono::Duration::days(30),
        }
    }
}

/// A freshly created CA.
///
/// `private_key_der` holds the plaintext PKCS#8 DER — zeroized on drop —
/// and the exact same bytes are stored encrypted in the keystore under
/// `key_pair_id` (the `cas` DB row id in Plan 2).
#[derive(Debug, Clone)]
pub struct CreatedCa {
    /// UUID under which the private key is stored (`ca/<key_pair_id>.key`)
    /// and the future `cas.id`.
    pub key_pair_id: Uuid,
    /// PEM-encoded X.509 certificate.
    pub cert_pem: String,
    /// PKCS#8 DER private key (zeroized on drop).
    pub private_key_der: Zeroizing<Vec<u8>>,
}

/// Create a self-signed root CA per `spec`, storing its private key
/// encrypted in `keystore`.
///
/// The root is a trust anchor: BasicConstraints `CA:TRUE` (critical, no
/// pathlen), KeyUsage `digitalSignature | keyCertSign | cRLSign`
/// (critical), SKI per rcgen defaults. AKI is omitted, which RFC 5280
/// permits for self-signed certificates.
///
/// The keystore must already have a master key — call
/// [`KeyStore::ensure_master_key`] during bootstrap; per the keystore's
/// contract, storing without one fails with [`CaError::Corrupt`] rather
/// than silently generating a master.
pub fn create_root(spec: &CaSpec, keystore: &mut KeyStore) -> Result<CreatedCa, CaError> {
    let key_pair = ZeroizingKey(generate_key_pair(spec.key_type)?);
    // A root is self-signed: there is no issuer to clamp against.
    let mut params = base_params(spec, None)?;

    // Self-signed trust anchor: unconstrained CA (no pathlen).
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];

    let cert = params.self_signed(&key_pair)?;
    persist(&key_pair, cert, keystore)
}

/// Create a sub-CA signed by the parent CA (`parent_cert_pem` +
/// `parent_key_der`, see the module docs for the pairing contract),
/// storing the sub-CA's own private key encrypted in `keystore`.
///
/// The sub-CA is an issuing intermediate: BasicConstraints `CA:TRUE,
/// pathlen:0` (critical) — it may sign leaves but no further sub-CAs —
/// KeyUsage `keyCertSign | cRLSign` (critical, no digitalSignature), and
/// an AuthorityKeyIdentifier equal to the parent's SubjectKeyIdentifier.
///
/// The keystore must already have a master key — call
/// [`KeyStore::ensure_master_key`] during bootstrap; per the keystore's
/// contract, storing without one fails with [`CaError::Corrupt`] rather
/// than silently generating a master.
pub fn create_sub_ca(
    parent_cert_pem: &str,
    parent_key_der: &[u8],
    spec: &CaSpec,
    keystore: &mut KeyStore,
) -> Result<CreatedCa, CaError> {
    let parent_key = ZeroizingKey(KeyPair::try_from(parent_key_der)?);
    ensure_parent_key_matches_cert(parent_cert_pem, &parent_key)?;
    // The parent must be a CA that is ALLOWED to have a CA below it: a
    // non-CA parent, or one whose pathLenConstraint is 0, would produce
    // a chain that relying parties reject (RFC 5280 section 6.1.4).
    ensure_issuer_is_ca(parent_cert_pem)?;
    ensure_issuer_permits_sub_ca(parent_cert_pem)?;

    let issuer = Issuer::from_ca_cert_pem(parent_cert_pem, &parent_key)?;
    let key_pair = ZeroizingKey(generate_key_pair(spec.key_type)?);
    // The child must not outlive its issuer: cap the requested lifetime
    // at the parent's own expiry.
    let parent_not_after = issuer_not_after(parent_cert_pem)?;
    let mut params = base_params(spec, Some(ymd(&parent_not_after)))?;

    // Intermediate: pathlen 0 — may sign leaves but no further sub-CAs.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    // With an Issuer built from the parent certificate, the AKI this adds
    // equals the parent's SKI byte for byte.
    params.use_authority_key_identifier_extension = true;

    let cert = params.signed_by(&key_pair, &issuer)?;
    persist(&key_pair, cert, keystore)
}

/// The issuer-side facts a CA certificate carries, extracted once so the
/// CA-ness, path-length and validity checks all read the same parse.
struct IssuerFacts {
    /// `BasicConstraints.ca`.
    is_ca: bool,
    /// Whether the KeyUsage includes `keyCertSign` (a certificate with
    /// NO KeyUsage extension is unrestricted).
    key_cert_sign: bool,
    /// `BasicConstraints.pathLenConstraint`, when present.
    path_len_constraint: Option<u32>,
    /// The certificate's own `notAfter` instant.
    not_after: chrono::DateTime<chrono::Utc>,
}

/// Parse an issuer certificate and extract the facts the CA and leaf
/// paths need from it.
fn issuer_facts(issuer_cert_pem: &str) -> Result<IssuerFacts, CaError> {
    let (_, pem) = parse_x509_pem(issuer_cert_pem.as_bytes())
        .map_err(|_| CaError::X509("issuer certificate is not valid PEM".to_owned()))?;
    let cert = pem
        .parse_x509()
        .map_err(|_| CaError::X509("issuer certificate failed to parse".to_owned()))?;

    let basic = cert
        .basic_constraints()
        .map_err(|_| CaError::X509("issuer certificate extensions are malformed".to_owned()))?;
    let (is_ca, path_len_constraint) = match basic {
        Some(bc) => (bc.value.ca, bc.value.path_len_constraint),
        None => (false, None),
    };

    let key_usage = cert
        .key_usage()
        .map_err(|_| CaError::X509("issuer certificate extensions are malformed".to_owned()))?;
    // RFC 5280 section 4.2.1.3: the keyUsage extension restricts the
    // certificate's purposes ONLY when it is present; a certificate with
    // no keyUsage at all is unrestricted.
    let key_cert_sign = key_usage.map(|ku| ku.value.key_cert_sign()).unwrap_or(true);

    let not_after = chrono::DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
        .ok_or_else(|| CaError::X509("issuer certificate notAfter is out of range".to_owned()))?;

    Ok(IssuerFacts {
        is_ca,
        key_cert_sign,
        path_len_constraint,
        not_after,
    })
}

/// Require that the issuer certificate is a CA permitted to sign
/// certificates: `BasicConstraints.ca` must be true and the KeyUsage
/// must include `keyCertSign`.
///
/// An end-entity certificate is never a valid issuer: a leaf issued by
/// it produces a chain that relying parties reject ("invalid CA
/// certificate" / "key usage does not include certificate signing"), so
/// accepting one would mint a certificate that no verifier honours.
///
/// The KeyUsage check follows RFC 5280 section 4.2.1.3: a CA whose
/// keyUsage omits `keyCertSign` is not permitted to sign certificates.
/// A CA certificate with NO KeyUsage extension at all is treated as
/// unrestricted (the extension constrains purposes only when present).
///
/// Errors are typed [`CaError::X509`] with static messages — never any
/// key material.
pub(crate) fn ensure_issuer_is_ca(issuer_cert_pem: &str) -> Result<(), CaError> {
    let facts = issuer_facts(issuer_cert_pem)?;
    if !facts.is_ca {
        return Err(CaError::X509(
            "issuer certificate is not a CA (BasicConstraints CA:FALSE)".to_owned(),
        ));
    }
    if !facts.key_cert_sign {
        return Err(CaError::X509(
            "issuer certificate is not permitted to sign certificates (keyUsage lacks keyCertSign)"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Require that the issuer's `pathLenConstraint` permits another CA
/// below it.
///
/// RFC 5280 section 4.2.1.9: `pathLenConstraint` gives the maximum
/// number of non-self-issued intermediate certificates that may follow
/// this certificate in a valid certification path. A parent with
/// `pathLenConstraint` 0 may therefore have an end-entity below it, but
/// NOT another CA — issuing one would produce a chain the parent itself
/// forbids, and relying parties reject it ("path length constraint
/// exceeded").
///
/// A parent with NO pathLenConstraint (a root) permits any depth.
pub(crate) fn ensure_issuer_permits_sub_ca(issuer_cert_pem: &str) -> Result<(), CaError> {
    let facts = issuer_facts(issuer_cert_pem)?;
    if facts.path_len_constraint == Some(0) {
        return Err(CaError::X509(
            "issuer certificate's path length constraint does not permit another CA".to_owned(),
        ));
    }
    Ok(())
}

/// The issuing certificate's `notAfter` instant.
///
/// Shared by the CA and leaf paths: both clamp the certificate they
/// mint to the issuer's own expiry, so a certificate never outlives the
/// CA that issued it.
pub(crate) fn issuer_not_after(
    issuer_cert_pem: &str,
) -> Result<chrono::DateTime<chrono::Utc>, CaError> {
    Ok(issuer_facts(issuer_cert_pem)?.not_after)
}

/// A certificate's X.509 validity window, `(not_before, not_after)` —
/// the facts a caller storing a fresh CA (Plan 2's API writes the `cas`
/// row) reads from the CREATED certificate rather than re-deriving from
/// the engine's own validity arithmetic.
///
/// The engine computes the window itself (midnight-UTC skew margins,
/// issuer caps); this function merely reports what the certificate
/// actually carries, so the stored row can never disagree with the
/// issued structure.
pub fn certificate_validity(
    cert_pem: &str,
) -> Result<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>), CaError> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|_| CaError::X509("certificate is not valid PEM".to_owned()))?;
    let cert = pem
        .parse_x509()
        .map_err(|_| CaError::X509("certificate failed to parse".to_owned()))?;
    let not_before = chrono::DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0)
        .ok_or_else(|| CaError::X509("certificate notBefore is out of range".to_owned()))?;
    let not_after = chrono::DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
        .ok_or_else(|| CaError::X509("certificate notAfter is out of range".to_owned()))?;
    Ok((not_before, not_after))
}

/// Common [`CertificateParams`]: subject CN, validity window, fresh
/// OS-entropy serial, rcgen defaults for everything else (SKI
/// derivation; no SANs or extended key usages — CAs carry none).
///
/// `issuer_not_after` caps the certificate's `not_after` at the issuing
/// CA's own expiry: a child that outlives its issuer is a
/// self-inflicted outage for the whole remaining life of the chain.
fn base_params(spec: &CaSpec, issuer_not_after: Option<Ymd>) -> Result<CertificateParams, CaError> {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, spec.subject.clone());

    let (nb, na) = validity_window(&spec.lifetime, issuer_not_after)?;
    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.serial_number = Some(new_serial()?);
    params.not_before = date_time_ymd(nb.0, nb.1, nb.2);
    params.not_after = date_time_ymd(na.0, na.1, na.2);
    Ok(params)
}

/// A UTC calendar date as a `(year, month, day)` triple for
/// [`date_time_ymd`].
type Ymd = (i32, u8, u8);

/// Validity window as (year, month, day) triples for [`date_time_ymd`]:
/// `not_before` is midnight UTC one day before today (clock-skew margin),
/// `not_after` is midnight UTC exactly the lifetime's day count later, so
/// the parsed certificate spans exactly the pinned day count.
///
/// `issuer_not_after` caps `not_after` at the issuing CA's expiry date.
/// The cap is applied at DAY granularity: the CA profile puts both ends
/// at midnight UTC, and midnight of the issuer's own expiry date is
/// always at or before the issuer's exact `notAfter` instant, so the
/// clamped child never outlives its issuer.
///
/// When the cap leaves no valid window at all (the issuer already
/// expires before the child could become valid), the request is REFUSED
/// with a typed [`CaError::X509`] rather than minting a certificate
/// that is invalid the moment it exists.
fn validity_window(
    lifetime: &CaLifetime,
    issuer_not_after: Option<Ymd>,
) -> Result<(Ymd, Ymd), CaError> {
    let not_before = Utc::now() - chrono::Duration::days(1);
    let requested = not_before
        .checked_add_signed(lifetime.duration())
        .ok_or_else(|| CaError::X509("certificate validity window out of range".to_owned()))?;
    let nb = ymd(&not_before);
    let mut na = ymd(&requested);
    if let Some(cap) = issuer_not_after {
        if cap < na {
            na = cap;
        }
    }
    if na <= nb {
        return Err(CaError::X509(
            "the issuing CA certificate expires before the requested certificate could become \
             valid; no validity window is left to issue into"
                .to_owned(),
        ));
    }
    Ok((nb, na))
}

/// The UTC calendar date of `dt` as a (year, month, day) triple.
fn ymd(dt: &chrono::DateTime<Utc>) -> (i32, u8, u8) {
    (dt.year(), dt.month() as u8, dt.day() as u8)
}

/// Generate a fresh private key for `key_type`, PKCS#8-serialized.
///
/// Ed25519 keys are generated inside rcgen (ring). RSA keys are generated
/// with the pure-Rust `rsa` crate — rcgen's default ring backend can
/// parse and sign RSA but cannot generate it — exported as PKCS#8 DER and
/// imported back into rcgen, which detects the algorithm from the DER.
fn generate_key_pair(key_type: KeyType) -> Result<KeyPair, CaError> {
    match key_type {
        KeyType::Ed25519 => Ok(KeyPair::generate_for(&PKCS_ED25519)?),
        KeyType::Rsa2048 => Ok(generate_rsa(2048)?.0),
        KeyType::Rsa3072 => Ok(generate_rsa(3072)?.0),
        KeyType::EcdsaP256 => Ok(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?),
    }
}

/// Generate an RSA key of `bits` and import it into rcgen as PKCS#8 DER.
///
/// `pub(crate)`, and returning the PKCS#8 DER (in a [`Zeroizing`] buffer)
/// alongside the rcgen key pair: [`crate::leafkey::generate_leaf_key`]
/// shares exactly this helper and needs the plaintext DER for the
/// encrypted setup-key slot — re-serializing the pair instead would mint
/// a second plaintext copy the wrapper cannot reach.
///
/// Error mapping (no variant carries key material; `rsa`'s error Display
/// is static text): generation failure maps to [`CaError::Io`] — the
/// dominant cause is OS-entropy trouble, matching the variant's
/// "random source exhaustion" meaning; PKCS#8 encoding failure maps to
/// [`CaError::X509`]. The `rsa` private key zeroizes its secret
/// components on drop, and the intermediate PKCS#8 document is handled
/// inside [`Zeroizing`] buffers.
///
/// # Entropy failures
///
/// The randomness for this path comes from [`FallibleSysRng`], not from
/// `rsa`'s bundled `OsRng`. `rsa`'s `OsRng` implements the trait's
/// infallible `fill_bytes` by PANICKING on an entropy failure; the rest
/// of ws-ca uses rand 0.10's fallible `try_fill_bytes`, so the two
/// key-generation paths did not honour the same "never a panic"
/// property.
///
/// The upstream stack consumes randomness ONLY through that trait
/// method — `num-bigint-dig`'s `gen_prime` calls `fill_bytes` and
/// offers no error channel of its own. The adapter therefore makes
/// `fill_bytes` itself non-panicking and detects the failure
/// out-of-band: on an entropy failure it fills the buffer from a
/// deterministic fallback stream, records the failure, and the caller
/// below REFUSES the resulting key with a typed [`CaError::Io`]. The
/// key is dropped (and its secret components zeroized by `rsa`)
/// without ever reaching a certificate, the keystore, or a caller.
///
/// The residual upstream limitation is thus not a panic risk but a
/// *reporting* one: the failure is detected after `RsaPrivateKey::new`
/// returns rather than being returned from within it, because the
/// pinned `rsa`/`num-bigint-dig` stack has no fallible prime-generation
/// entry point. The observable behaviour for a caller — a typed error,
/// no key, no panic, and never a silently weak key — is what a
/// fallible API would give.
pub(crate) fn generate_rsa(bits: usize) -> Result<(KeyPair, Zeroizing<Vec<u8>>), CaError> {
    let mut rng = FallibleSysRng::new();
    let key = RsaPrivateKey::new(&mut rng, bits);
    if rng.degraded {
        // The OS entropy source failed during generation: the key was
        // built from the deterministic fallback stream and MUST NOT be
        // used. Drop it here (rsa zeroizes the secret components on
        // drop) and report the real cause.
        return Err(CaError::Io(std::io::Error::other(
            "rsa key generation failed: the operating system entropy source was unavailable",
        )));
    }
    let key = key.map_err(|e| {
        CaError::Io(std::io::Error::other(format!(
            "rsa key generation failed: {e}"
        )))
    })?;
    let pkcs8 = key
        .to_pkcs8_der()
        .map_err(|e| CaError::X509(format!("rsa key pkcs8 encoding failed: {e}")))?;
    let der = Zeroizing::new(pkcs8.as_bytes().to_vec());
    let key_pair = KeyPair::try_from(der.as_slice())?;
    Ok((key_pair, der))
}

/// Label embedded in the degraded-mode fallback seed. Public on purpose:
/// the fallback stream only exists to keep a broken-entropy run
/// terminating, and the key it produces is discarded before use, so the
/// seed's publicity is not a weakness.
const DEGRADED_SEED_LABEL: &[u8; 24] = b"wardstone-degraded-mode!";

/// Process-wide counter, so two degraded runs in the same process do not
/// fall back to the same stream.
static DEGRADED_SEED_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Seed for one instance's degraded-mode fallback stream: a fixed public
/// label plus a per-instance value derived from a process-wide counter
/// and the process id.
fn degraded_seed() -> [u8; 32] {
    let counter = DEGRADED_SEED_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid = u64::from(std::process::id());
    let mut seed = [0u8; 32];
    seed[..24].copy_from_slice(DEGRADED_SEED_LABEL);
    seed[24..].copy_from_slice(&(counter ^ pid.rotate_left(17)).to_le_bytes());
    seed
}

/// Adapter presenting rand 0.10's fallible OS entropy source
/// (`SysRng`) through the rand_core 0.6 traits that `rsa 0.9.10`
/// accepts (`RngCore` + `CryptoRng`).
///
/// `rsa::rand_core` is the re-export of rand_core 0.6 that `rsa` itself
/// depends on, so implementing these traits against it adds no new
/// dependency edge to the workspace.
///
/// # Why the fallback stream exists
///
/// The trait's infallible `fill_bytes` has no error channel, and
/// `num-bigint-dig`'s `gen_prime` — the only consumer of randomness in
/// `RsaPrivateKey::new` — calls exactly that method. `fill_bytes`
/// therefore must return *something*, and it must not panic. It fills
/// from a deterministic fallback stream and records the failure in
/// [`Self::degraded`]; the caller then refuses the key. The
/// alternative — panicking, as `rsa`'s own `OsRng` does — would turn
/// a broken kernel RNG into a process abort, and the alternative of
/// silently using the degraded key would mint a predictable CA key.
/// Both are worse than a typed error, which is what the caller
/// produces.
struct FallibleSysRng {
    /// Set when the OS entropy source failed at least once. The caller
    /// MUST refuse any key generated by an instance in this state.
    degraded: bool,
    /// Deterministic stream used only after an entropy failure. Seeded
    /// per instance so two degraded runs differ from each other.
    fallback: rand::rngs::StdRng,
    /// Bytes requested through the infallible `fill_bytes` path.
    /// Test-only: it proves that the upstream prime generation really
    /// consults THIS adapter (and not some other entropy source).
    #[cfg(test)]
    filled_bytes: u64,
}

impl FallibleSysRng {
    /// A fresh adapter over the OS entropy source.
    fn new() -> Self {
        Self {
            degraded: false,
            fallback: rand::SeedableRng::from_seed(degraded_seed()),
            #[cfg(test)]
            filled_bytes: 0,
        }
    }
}

impl RngCore for FallibleSysRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    /// Never panics. On an entropy failure it fills from the
    /// deterministic fallback stream and records the failure; the
    /// caller refuses the key.
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        #[cfg(test)]
        {
            self.filled_bytes += dest.len() as u64;
        }
        let mut sys = SysRng;
        if sys.try_fill_bytes(dest).is_err() {
            self.degraded = true;
            rand::Rng::fill_bytes(&mut self.fallback, dest);
        }
    }

    /// The fallible path: an entropy failure is reported as an error
    /// AND recorded in [`Self::degraded`]. The buffer is still filled
    /// (from the fallback stream) so that a caller which ignores the
    /// error still gets a defined, non-panicking buffer — but the
    /// recorded flag means the key is refused.
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        let mut sys = SysRng;
        match sys.try_fill_bytes(dest) {
            Ok(()) => Ok(()),
            Err(err) => {
                self.degraded = true;
                rand::Rng::fill_bytes(&mut self.fallback, dest);
                Err(rand_core::Error::new(std::io::Error::from(err)))
            }
        }
    }
}

impl CryptoRng for FallibleSysRng {}

/// Verify that `parent_key` is the private half of the subject public key
/// in `parent_cert_pem`, so a mismatched (cert, key) pair cannot silently
/// produce a broken chain.
///
/// Compares the parsed SubjectPublicKeyInfo fields (algorithm OID and key
/// bit string) rather than raw DER, so encoders that differ in
/// AlgorithmIdentifier padding still pair correctly. Any failure —
/// unparseable PEM, unparseable key, or a genuine mismatch — is
/// [`CaError::X509`] with a static message.
pub(crate) fn ensure_parent_key_matches_cert(
    parent_cert_pem: &str,
    parent_key: &ZeroizingKey,
) -> Result<(), CaError> {
    let (_, pem) = parse_x509_pem(parent_cert_pem.as_bytes())
        .map_err(|_| CaError::X509("parent certificate is not valid PEM".to_owned()))?;
    let parent_cert = pem
        .parse_x509()
        .map_err(|_| CaError::X509("parent certificate failed to parse".to_owned()))?;
    let key_spki_der = parent_key.subject_public_key_info();
    let (_, key_spki) = SubjectPublicKeyInfo::from_der(&key_spki_der)
        .map_err(|_| CaError::X509("parent key public info failed to parse".to_owned()))?;
    let cert_spki = parent_cert.public_key();
    if key_spki.algorithm.algorithm != cert_spki.algorithm.algorithm
        || key_spki.subject_public_key.data != cert_spki.subject_public_key.data
    {
        return Err(CaError::X509(
            "parent private key does not match the parent certificate".to_owned(),
        ));
    }
    Ok(())
}

/// Store the new CA's private key encrypted and assemble the return
/// value.
///
/// The key is written to the keystore before success is reported, so a
/// returned [`CreatedCa`] always implies an envelope exists under
/// `key_pair_id`. The keystore's master-key precondition applies: the
/// caller must have run [`KeyStore::ensure_master_key`] (or be reusing a
/// store that has one), since storing without a master key is
/// [`CaError::Corrupt`], never a silent master generation. If the store
/// fails, the error propagates and every in-memory copy of the key drops
/// zeroized.
fn persist(
    key_pair: &ZeroizingKey,
    cert: Certificate,
    keystore: &mut KeyStore,
) -> Result<CreatedCa, CaError> {
    let key_pair_id = new_key_pair_id()?;
    let private_key_der = Zeroizing::new(key_pair.serialize_der());
    keystore.store_ca_key(&key_pair_id, private_key_der.as_slice())?;
    Ok(CreatedCa {
        key_pair_id,
        cert_pem: cert.pem(),
        private_key_der,
    })
}

/// Fresh RFC 4122 v4 UUID from 16 bytes of OS entropy, typed: entropy
/// failure is [`CaError::Io`], never a panic (unlike [`Uuid::new_v4`],
/// which unwraps internally).
fn new_key_pair_id() -> Result<Uuid, CaError> {
    let mut bytes = Zeroizing::new([0u8; 16]);
    SysRng
        .try_fill_bytes(bytes.as_mut())
        .map_err(std::io::Error::from)?;
    Ok(uuid::Builder::from_random_bytes(*bytes).into_uuid())
}

/// Fresh certificate serial number: 16 bytes of OS entropy, typed (entropy
/// failure is [`CaError::Io`], never a panic). The serial is public
/// certificate content, so the bytes need no zeroization.
///
/// [`CertificateParams::serial_number`] is always set explicitly because
/// rcgen's default when it is unset is deterministic — SHA-256 of the
/// subject public key truncated to 20 bytes — so two certificates sharing
/// a key pair (e.g. any future renewal path) would collide, violating
/// RFC 5280 §4.1.2.2 per-issuer serial uniqueness and breaking revocation
/// keyed on (issuer, serial). Sixteen random bytes carry 128 bits of
/// entropy (above the CA/B Forum's 64-bit floor) within RFC 5280's
/// 20-octet bound; rcgen serializes the value with yasna's
/// positive-INTEGER writer, which prepends a leading zero octet when the
/// high bit is set, so raw random bytes always encode as a positive DER
/// INTEGER.
fn new_serial() -> Result<SerialNumber, CaError> {
    let mut bytes = [0u8; 16];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(std::io::Error::from)?;
    Ok(SerialNumber::from_slice(&bytes))
}

/// rcgen [`KeyPair`] that zeroizes rcgen's serialized PKCS#8 copy when
/// dropped, on every exit path (including `?` early returns). rcgen, with
/// its `zeroize` feature, provides a [`Zeroize`] impl for `KeyPair` but
/// registers no `Drop`, so without this wrapper the plaintext DER would
/// linger on the heap after signing. The signing traits delegate
/// unchanged.
///
/// `pub(crate)`: shared with [`crate::issue::sign_leaf_with`], which holds
/// the same zeroize-on-drop guarantee for the CA key while signing leaves.
pub(crate) struct ZeroizingKey(pub(crate) KeyPair);

impl std::ops::Deref for ZeroizingKey {
    type Target = KeyPair;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for ZeroizingKey {
    fn drop(&mut self) {
        Zeroize::zeroize(&mut self.0);
    }
}

impl PublicKeyData for ZeroizingKey {
    fn der_bytes(&self) -> &[u8] {
        self.0.der_bytes()
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.0.algorithm()
    }
}

impl SigningKey for ZeroizingKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.0.sign(msg)
    }
}

#[cfg(test)]
mod tests {
    use rsa::traits::PublicKeyParts;

    use super::{FallibleSysRng, RngCore};

    /// The adapter's `try_fill_bytes` is wired to the OS entropy
    /// source: it fills the whole buffer and reports success.
    #[test]
    fn test_fallible_sys_rng_fills_the_whole_buffer() {
        let mut rng = FallibleSysRng::new();
        let mut buf = [0u8; 64];
        rng.try_fill_bytes(&mut buf)
            .expect("OS entropy is available");
        assert_eq!(buf.len(), 64, "the whole buffer must be filled");
        assert!(
            buf.iter().any(|byte| *byte != 0),
            "a filled buffer must not be all zeros"
        );
        assert!(
            !rng.degraded,
            "a healthy entropy source must not be reported as degraded"
        );
    }

    /// The adapter does not repeat itself: two draws differ.
    #[test]
    fn test_fallible_sys_rng_does_not_repeat() {
        let mut rng = FallibleSysRng::new();
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        rng.try_fill_bytes(&mut first).unwrap();
        rng.try_fill_bytes(&mut second).unwrap();
        assert_ne!(
            first, second,
            "two draws from the entropy source must differ"
        );
    }

    /// The upstream prime generation really consults THIS adapter.
    ///
    /// `rsa::RsaPrivateKey::new` takes the RNG by `&mut`, and
    /// `num-bigint-dig`'s `gen_prime` calls the trait's infallible
    /// `fill_bytes` — so the bytes the adapter hands out are the bytes
    /// the RSA primes are drawn from. Counting the bytes requested
    /// through `fill_bytes` proves the wiring rather than assuming it.
    #[test]
    fn test_rsa_prime_generation_consults_the_adapter() {
        let mut rng = FallibleSysRng::new();
        // A small modulus keeps the test quick; the prime search still
        // draws randomness through the adapter.
        let key = rsa::RsaPrivateKey::new(&mut rng, 256).expect("generate a small RSA key");
        assert!(
            rng.filled_bytes > 0,
            "the RSA prime generation must draw randomness through the adapter"
        );
        assert!(
            !rng.degraded,
            "a healthy entropy source must not be reported as degraded"
        );
        // The key really is a 256-bit modulus, so the search ran.
        assert_eq!(key.n().bits(), 256);
    }
}
