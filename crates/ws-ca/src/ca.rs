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
    SigningKey, PKCS_ED25519,
};
use rsa::pkcs8::EncodePrivateKey;
use rsa::{rand_core::OsRng, RsaPrivateKey};
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
    let mut params = base_params(spec)?;

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

    let issuer = Issuer::from_ca_cert_pem(parent_cert_pem, &parent_key)?;
    let key_pair = ZeroizingKey(generate_key_pair(spec.key_type)?);
    let mut params = base_params(spec)?;

    // Intermediate: pathlen 0 — may sign leaves but no further sub-CAs.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    // With an Issuer built from the parent certificate, the AKI this adds
    // equals the parent's SKI byte for byte.
    params.use_authority_key_identifier_extension = true;

    let cert = params.signed_by(&key_pair, &issuer)?;
    persist(&key_pair, cert, keystore)
}

/// Common [`CertificateParams`]: subject CN, validity window, fresh
/// OS-entropy serial, rcgen defaults for everything else (SKI
/// derivation; no SANs or extended key usages — CAs carry none).
fn base_params(spec: &CaSpec) -> Result<CertificateParams, CaError> {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, spec.subject.clone());

    let (nb, na) = validity_window(&spec.lifetime)?;
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
fn validity_window(lifetime: &CaLifetime) -> Result<(Ymd, Ymd), CaError> {
    let not_before = Utc::now() - chrono::Duration::days(1);
    let not_after = not_before
        .checked_add_signed(lifetime.duration())
        .ok_or_else(|| CaError::X509("certificate validity window out of range".to_owned()))?;
    Ok((ymd(&not_before), ymd(&not_after)))
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
        KeyType::Rsa2048 => generate_rsa(2048),
        KeyType::Rsa3072 => generate_rsa(3072),
    }
}

/// Generate an RSA key of `bits` and import it into rcgen as PKCS#8 DER.
///
/// Error mapping (no variant carries key material; `rsa`'s error Display
/// is static text): generation failure maps to [`CaError::Io`] — the
/// dominant cause is OS-entropy trouble, matching the variant's
/// "random source exhaustion" meaning (note `rsa`'s `OsRng` panics on a
/// hard entropy failure; that is process-fatal territory); PKCS#8
/// encoding failure maps to [`CaError::X509`]. The `rsa` private key
/// zeroizes its secret components on drop, and the intermediate PKCS#8
/// document is handled inside [`Zeroizing`] buffers.
fn generate_rsa(bits: usize) -> Result<KeyPair, CaError> {
    let mut rng = OsRng;
    let key = RsaPrivateKey::new(&mut rng, bits).map_err(|e| {
        CaError::Io(std::io::Error::other(format!(
            "rsa key generation failed: {e}"
        )))
    })?;
    let pkcs8 = key
        .to_pkcs8_der()
        .map_err(|e| CaError::X509(format!("rsa key pkcs8 encoding failed: {e}")))?;
    let der = Zeroizing::new(pkcs8.as_bytes().to_vec());
    Ok(KeyPair::try_from(der.as_slice())?)
}

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
