//! Hand-rolled X.509 v2 CRL builder (RFC 5280 section 5.1).
//!
//! [`build_crl`] mints a minimal, standards-shaped CertificateList from a
//! CA certificate, its private key, and the caller's revocation list. The
//! DER is assembled directly from `der`'s ASN.1 value encoders (`Uint` for
//! INTEGERs, `UtcTime`/`GeneralizedTime` for times, `ObjectIdentifier`,
//! `Null`, `OctetString`, `BitString`) plus one local helper that wraps
//! already-encoded fragments into constructed TLVs (SEQUENCE and the
//! `[0]` crlExtensions wrapper) — the `der` crate's derive feature is
//! deliberately not used, per the pinned Task-7 ruling.
//!
//! # Shape of the emitted CRL
//!
//! - `version` v2: a bare `INTEGER 1` — the TBSCertList version field is
//!   a plain INTEGER, NOT the `[0]`-wrapped form certificates use
//!   (verified against stock OpenSSL's own CRL output with
//!   `openssl asn1parse`).
//! - `signature` and the outer signature algorithm: dispatched from the
//!   CA key — Ed25519 keys sign with id-Ed25519 (1.3.101.112, absent
//!   parameters per RFC 8410), RSA keys with sha256WithRSAEncryption
//!   (1.2.840.113549.1.1.11, NULL parameters).
//! - `issuer`: the CA certificate's subject Name TLV spliced verbatim, so
//!   the CRL issuer DN is byte-identical to the CA subject.
//! - `thisUpdate` is the build instant and `nextUpdate` is
//!   [`CrlSpec::next_update`] later; both encode as UTCTime within
//!   `der`'s 1970-2049 window and GeneralizedTime outside it (RFC 5280
//!   section 4.1.2.5).
//! - `revokedCertificates`: every entry in the order given. The serial is
//!   a minimal positive DER INTEGER (`Uint` strips leading zero bytes
//!   and its encoder re-adds the `0x00` sign octet when the high bit is
//!   set, matching what stock OpenSSL writes); `revocationDate` is the
//!   entry's own revocation instant (RFC 5280 section 5.1), not the
//!   build instant. A `None` reason emits no entry extension at all; a
//!   reason emits a single non-critical `reasonCode` (2.5.29.21)
//!   extension whose value is RFC 5280 section 5.3.1's ENUMERATED
//!   code. An empty `revocations` list omits the whole field.
//! - `crlExtensions`: exactly one non-critical `authorityKeyIdentifier`
//!   (2.5.29.35) whose keyIdentifier is the CA certificate's SKI — the
//!   extension is REQUIRED, so a CA cert without an SKI is a typed error.
//!   No CRL Number extension is emitted (CRL sequencing is Task 9's).
//!
//! # Key material handling
//!
//! The CA private key lives only inside the `pub(crate)` `ZeroizingKey`
//! wrapper shared with `crate::ca` (zeroized on drop, on every exit path
//! including `?` early returns), and the (certificate, key) pair is proven
//! to match before signing — the CRL's issuer DN and AKI come from the
//! certificate while the signature comes from the key, so a mismatched
//! pair would silently produce an unverifiable CRL. No error message
//! carries key material.

use base64::Engine as _;
use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use der::asn1::{
    AnyRef, BitString, GeneralizedTime, Null, ObjectIdentifier, OctetString, Uint, UtcTime,
};
use der::{Encode, Tag, TagNumber};
use rcgen::{KeyPair, SignatureAlgorithm, SigningKey, PKCS_ED25519, PKCS_RSA_SHA256};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::pem::parse_x509_pem;

use crate::ca::{ensure_parent_key_matches_cert, ZeroizingKey};
use crate::error::CaError;

/// id-Ed25519 (RFC 8410): the signature algorithm Ed25519 CA keys sign a
/// CRL with, written with absent parameters.
const OID_SIG_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// sha256WithRSAEncryption (RFC 4055): the signature algorithm RSA CA keys
/// sign a CRL with, written with NULL parameters.
const OID_SIG_SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// The CRL entry extension `reasonCode` (RFC 5280 section 5.3.1).
const OID_EXT_REASON_CODE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.21");

/// The crl extension `authorityKeyIdentifier` (RFC 5280 section 5.2.1).
const OID_EXT_AUTHORITY_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");

/// DER tag octet for SEQUENCE (universal 16, constructed).
const TAG_SEQUENCE: u8 = 0x30;

/// DER tag octet for the `[0]` context-specific constructed wrapper that
/// carries `crlExtensions` (EXPLICIT tagging, RFC 5280 section 5.1).
const TAG_EXTENSIONS: u8 = 0xa0;

/// Why a certificate was revoked, as carried in a CRL entry's `reasonCode`
/// extension (RFC 5280 section 5.3.1). The codes are the ENUMERATED
/// values; value 7 is unused by the RFC and therefore not represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlReason {
    /// Unspecified (0).
    Unspecified,
    /// Key compromise (1).
    KeyCompromise,
    /// CA compromise (2).
    CACompromise,
    /// Affiliation changed (3).
    AffiliationChanged,
    /// Superseded (4).
    Superseded,
    /// Cessation of operation (5).
    CessationOfOperation,
    /// Certificate hold (6).
    CertificateHold,
    /// Remove from CRL (8).
    RemoveFromCRL,
    /// Privilege withdrawn (9).
    PrivilegeWithdrawn,
    /// AA compromise (10).
    AaCompromise,
}

impl CrlReason {
    /// The RFC 5280 section 5.3.1 ENUMERATED value for this reason.
    pub fn as_code(&self) -> u8 {
        match self {
            CrlReason::Unspecified => 0,
            CrlReason::KeyCompromise => 1,
            CrlReason::CACompromise => 2,
            CrlReason::AffiliationChanged => 3,
            CrlReason::Superseded => 4,
            CrlReason::CessationOfOperation => 5,
            CrlReason::CertificateHold => 6,
            CrlReason::RemoveFromCRL => 8,
            CrlReason::PrivilegeWithdrawn => 9,
            CrlReason::AaCompromise => 10,
        }
    }
}

/// One revoked certificate in a [`CrlSpec`].
#[derive(Debug, Clone)]
pub struct RevocationEntry {
    /// Serial number of the revoked certificate, encoded as a minimal
    /// positive DER INTEGER.
    pub serial: u128,
    /// Revocation reason; `None` emits no entry extension at all.
    pub reason: Option<CrlReason>,
    /// When the certificate was revoked — the entry's `revocationDate`
    /// (RFC 5280 section 5.1). This is the instant the revocation
    /// happened, not the instant the CRL was built.
    pub revoked_at: DateTime<Utc>,
}

/// What one emitted CRL contains.
#[derive(Debug, Clone)]
pub struct CrlSpec {
    /// Revocations to list, in the order given.
    pub revocations: Vec<RevocationEntry>,
    /// How far out `nextUpdate` sits from the issue instant.
    pub next_update: Duration,
}

/// A built CRL: the PEM document plus the instants it was built with
/// (`next_update` = `issued_at` + [`CrlSpec::next_update`]).
#[derive(Debug, Clone)]
pub struct CrlFile {
    /// PEM-encoded X.509 v2 CRL (`-----BEGIN X509 CRL-----`).
    pub crl_pem: String,
    /// The `thisUpdate` instant (the build time).
    pub issued_at: DateTime<Utc>,
    /// The `nextUpdate` instant.
    pub next_update: DateTime<Utc>,
}

/// Build one X.509 v2 CRL signed by the given CA (see the module docs for
/// the emitted shape).
///
/// `ca_cert_pem` and `ca_key_der` must pair (checked, as in
/// `crate::ca::create_sub_ca`): the issuer DN and the AKI come from the
/// certificate while the signature comes from the key. Pinned
/// requirement: the output must parse with stock OpenSSL
/// (`openssl crl -in out.pem -noout -text` lists the revoked serials) and
/// its signature must verify (`openssl crl -in out.pem -CAfile ca.pem
/// -noout` prints `verify OK`).
///
/// Errors: malformed PEM/DER input or an out-of-range validity window is
/// [`CaError::X509`]; a signing key whose algorithm is neither Ed25519
/// nor RSA is [`CaError::UnsupportedKeyType`] (the algorithm name only,
/// never key material); signing failures are [`CaError::Rcgen`].
pub fn build_crl(ca_cert_pem: &str, ca_key_der: &[u8], spec: &CrlSpec) -> Result<CrlFile, CaError> {
    // CA side: load the key (zeroized on every exit path) and prove the
    // certificate/key pair belongs together before the issuer DN from the
    // certificate and the signature from the key are combined — the same
    // pairing contract as `crate::ca::create_sub_ca`.
    let ca_key = ZeroizingKey(KeyPair::try_from(ca_key_der)?);
    ensure_parent_key_matches_cert(ca_cert_pem, &ca_key)?;

    let (_, ca_pem_block) = parse_x509_pem(ca_cert_pem.as_bytes())
        .map_err(|_| CaError::X509("CA certificate is not valid PEM".to_owned()))?;
    let ca_cert = ca_pem_block
        .parse_x509()
        .map_err(|_| CaError::X509("CA certificate failed to parse".to_owned()))?;

    let issued_at = Utc::now();
    let next_update = issued_at
        .checked_add_signed(spec.next_update)
        .ok_or_else(|| CaError::X509("CRL next_update instant out of range".to_owned()))?;
    if next_update <= issued_at {
        return Err(CaError::X509(
            "CRL next_update must be after the issue instant".to_owned(),
        ));
    }

    let algorithm = algorithm_identifier(ca_key.algorithm())?;
    let this_update = time_tlv(&issued_at)?;
    let next_update_der = time_tlv(&next_update)?;
    // Version 2: the TBSCertList version is a bare INTEGER 1 (not the
    // [0]-tagged form certificates use — see the module docs).
    let version = Uint::new(&[1])
        .map_err(der_err)?
        .to_der()
        .map_err(der_err)?;

    let mut entries = Vec::with_capacity(spec.revocations.len());
    for entry in &spec.revocations {
        let serial = serial_tlv(entry.serial)?;
        // The entry's revocationDate is when the certificate was revoked
        // (RFC 5280 section 5.1), not when this CRL was built.
        let revocation_date = time_tlv(&entry.revoked_at)?;
        let mut content = [serial, revocation_date].concat();
        if let Some(reason) = entry.reason {
            // crlEntryExtensions: a SEQUENCE holding the reasonCode
            // extension (a `None` reason omits the field entirely).
            content.extend_from_slice(&tlv(TAG_SEQUENCE, &reason_extension_tlv(reason)?));
        }
        entries.push(tlv(TAG_SEQUENCE, &content));
    }

    let aki = authority_key_identifier_extension(&ski_bytes(&ca_cert)?)?;
    // crlExtensions is [0] EXPLICIT: the wrapper contains the Extensions
    // SEQUENCE, which holds exactly the AKI extension.
    let crl_extensions = tlv(TAG_EXTENSIONS, &tlv(TAG_SEQUENCE, &aki));

    let mut tbs = version;
    tbs.extend_from_slice(&algorithm);
    // Issuer DN: the CA subject Name TLV, spliced verbatim.
    tbs.extend_from_slice(ca_cert.subject().as_raw());
    tbs.extend_from_slice(&this_update);
    tbs.extend_from_slice(&next_update_der);
    if !entries.is_empty() {
        // revokedCertificates: SEQUENCE OF the entry TLVs (an empty list
        // omits the field).
        tbs.extend_from_slice(&tlv(TAG_SEQUENCE, &entries.concat()));
    }
    tbs.extend_from_slice(&crl_extensions);
    let tbs = tlv(TAG_SEQUENCE, &tbs);

    // Sign the TBSCertList and wrap the raw signature in a BIT STRING.
    let signature = ca_key.sign(&tbs)?;
    let signature = BitString::new(0, signature)
        .map_err(der_err)?
        .to_der()
        .map_err(der_err)?;

    let mut crl = tbs;
    crl.extend_from_slice(&algorithm);
    crl.extend_from_slice(&signature);
    let crl_der = tlv(TAG_SEQUENCE, &crl);

    Ok(CrlFile {
        crl_pem: crl_to_pem(&crl_der),
        issued_at,
        next_update,
    })
}

/// The CRL's `AlgorithmIdentifier` (RFC 5280 section 5.1), dispatched from
/// the signing key: Ed25519 keys sign with id-Ed25519 and absent
/// parameters (RFC 8410), RSA keys with sha256WithRSAEncryption and NULL
/// parameters. Anything else is a typed rejection naming the algorithm
/// only.
fn algorithm_identifier(algorithm: &SignatureAlgorithm) -> Result<Vec<u8>, CaError> {
    let (oid, null_params) = if algorithm == &PKCS_ED25519 {
        (OID_SIG_ED25519, false)
    } else if algorithm == &PKCS_RSA_SHA256 {
        (OID_SIG_SHA256_RSA, true)
    } else {
        return Err(CaError::UnsupportedKeyType(format!(
            "CRL signing is not supported for this CA key algorithm ({algorithm:?})"
        )));
    };

    let mut content = oid.to_der().map_err(der_err)?;
    if null_params {
        content.extend_from_slice(&Null.to_der().map_err(der_err)?);
    }
    Ok(tlv(TAG_SEQUENCE, &content))
}

/// A chrono instant as a `der::DateTime` (whole seconds; `der::DateTime`
/// carries no sub-second field, so the conversion truncates).
fn der_datetime(dt: &DateTime<Utc>) -> Result<der::DateTime, CaError> {
    let year = u16::try_from(dt.year())
        .map_err(|_| CaError::X509("CRL timestamp year is out of the DER range".to_owned()))?;
    der::DateTime::new(
        year,
        dt.month() as u8,
        dt.day() as u8,
        dt.hour() as u8,
        dt.minute() as u8,
        dt.second() as u8,
    )
    .map_err(|_| CaError::X509("CRL timestamp is not a valid DER date".to_owned()))
}

/// A `Time` CHOICE value (RFC 5280 section 4.1.2.5) as a full TLV:
/// UTCTime inside `der`'s 1970-2049 window, GeneralizedTime outside it
/// (RFC 5280 requires GeneralizedTime from 2050 on).
fn time_tlv(dt: &DateTime<Utc>) -> Result<Vec<u8>, CaError> {
    let converted = der_datetime(dt)?;
    match UtcTime::try_from(&converted) {
        Ok(utc_time) => Ok(utc_time.to_der().map_err(der_err)?),
        Err(_) => Ok(GeneralizedTime::from(&converted)
            .to_der()
            .map_err(der_err)?),
    }
}

/// A certificate serial as a minimal positive DER INTEGER: `Uint` strips
/// leading zero bytes and its encoder re-adds a `0x00` sign octet when the
/// value's high bit is set, so both the short form (`0x00ff…` encodes to 8
/// content bytes: 7 value bytes after the leading zero is stripped, plus
/// the sign octet) and the full-width high-bit form (`0x8000…01` encodes
/// to 17) match what stock OpenSSL writes.
fn serial_tlv(serial: u128) -> Result<Vec<u8>, CaError> {
    Uint::new(&serial.to_be_bytes())
        .map_err(der_err)?
        .to_der()
        .map_err(der_err)
}

/// One `Extension` (RFC 5280 section 4.1): `reasonCode` (2.5.29.21),
/// non-critical (the `critical` BOOLEAN defaults to FALSE and is omitted
/// in DER), with the value an OCTET STRING wrapping the RFC 5280 section
/// 5.3.1 ENUMERATED code.
fn reason_extension_tlv(reason: CrlReason) -> Result<Vec<u8>, CaError> {
    let enumerated = AnyRef::new(Tag::Enumerated, &[reason.as_code()])
        .map_err(der_err)?
        .to_der()
        .map_err(der_err)?;
    let value = OctetString::new(enumerated)
        .map_err(der_err)?
        .to_der()
        .map_err(der_err)?;
    let oid = OID_EXT_REASON_CODE.to_der().map_err(der_err)?;
    Ok(tlv(TAG_SEQUENCE, &[oid, value].concat()))
}

/// The CA certificate's SubjectKeyIdentifier bytes. The AKI crlExtension
/// is required and copies the CA SKI, so a certificate without an SKI
/// cannot produce a conforming CRL — a typed error, never a guess.
fn ski_bytes(cert: &X509Certificate<'_>) -> Result<Vec<u8>, CaError> {
    cert.iter_extensions()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(ki) => Some(ki.0.to_vec()),
            _ => None,
        })
        .ok_or_else(|| {
            CaError::X509(
                "CA certificate carries no SubjectKeyIdentifier; the CRL \
                 authorityKeyIdentifier extension requires it"
                    .to_owned(),
            )
        })
}

/// One `Extension`: `authorityKeyIdentifier` (2.5.29.35), non-critical,
/// value an OCTET STRING wrapping
/// `AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] KeyIdentifier }`
/// with the CA certificate's SKI as the keyIdentifier.
fn authority_key_identifier_extension(ski: &[u8]) -> Result<Vec<u8>, CaError> {
    let key_identifier = AnyRef::new(
        Tag::ContextSpecific {
            constructed: false,
            number: TagNumber(0),
        },
        ski,
    )
    .map_err(der_err)?
    .to_der()
    .map_err(der_err)?;
    let value = OctetString::new(tlv(TAG_SEQUENCE, &key_identifier))
        .map_err(der_err)?
        .to_der()
        .map_err(der_err)?;
    let oid = OID_EXT_AUTHORITY_KEY_ID.to_der().map_err(der_err)?;
    Ok(tlv(TAG_SEQUENCE, &[oid, value].concat()))
}

/// PEM-wrap the DER CRL (RFC 7468): the `X509 CRL` label stock OpenSSL
/// writes and expects, base64 at 64 characters per line.
fn crl_to_pem(der_bytes: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der_bytes);
    let mut pem = String::from("-----BEGIN X509 CRL-----\n");
    for line in encoded.as_bytes().chunks(64) {
        // Pure-ASCII base64; the lossy conversion never has to kick in.
        pem.push_str(&String::from_utf8_lossy(line));
        pem.push('\n');
    }
    pem.push_str("-----END X509 CRL-----\n");
    pem
}

/// Map a `der` encoding failure onto the typed error surface (the Display
/// text is the encoder's own; it never includes key material).
fn der_err(err: der::Error) -> CaError {
    CaError::X509(format!("CRL DER encoding failed: {err}"))
}

/// Append a DER TLV to `out`: the `tag` octet, the definite-form length
/// of `content` (minimal long form once it exceeds 127 bytes), then the
/// content itself.
fn push_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        // Long form: 0x80 | byte count, then the length big-endian with
        // its leading zero octets stripped. usize is at most u64-wide on
        // every supported platform, so the widening here is lossless.
        let be = (len as u64).to_be_bytes();
        let first = be.iter().position(|&b| b != 0).unwrap_or(8);
        out.push(0x80 | (8 - first) as u8);
        out.extend_from_slice(&be[first..]);
    }
    out.extend_from_slice(content);
}

/// A fresh DER TLV (tag, length, content) as owned bytes.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    push_tlv(&mut out, tag, content);
    out
}
