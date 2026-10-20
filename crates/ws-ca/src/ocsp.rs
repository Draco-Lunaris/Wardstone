//! Hand-rolled RFC 6960 OCSP response builder.
//!
//! [`build_ocsp_response`] mints a single-certificate OCSP response
//! (`OCSPResponse` carrying a `BasicOCSPResponse`) for one certificate
//! of one CA. The DER is assembled directly from `der`'s ASN.1 value
//! encoders plus one local helper that wraps already-encoded fragments
//! into constructed TLVs — the same approach as `crate::crl`, and for
//! the same reason: the `der` crate's derive feature is deliberately
//! not used, so the wire format is explicit and auditable.
//!
//! # Shape of the emitted response
//!
//! ```text
//! OCSPResponse ::= SEQUENCE {
//!     responseStatus         OCSPResponseStatus,   -- ENUMERATED 0 (successful)
//!     responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
//! ResponseBytes ::= SEQUENCE {
//!     responseType           OBJECT IDENTIFIER,      -- id-pkix-ocsp-basic
//!     response               OCTET STRING }          -- DER of BasicOCSPResponse
//! BasicOCSPResponse ::= SEQUENCE {
//!     tbsResponseData        ResponseData,
//!     signatureAlgorithm     AlgorithmIdentifier,
//!     signature              BIT STRING,
//!     certs                  [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
//! ```
//!
//! - `tbsResponseData` carries no `version` field: RFC 6960 section 4.2.1
//!   says the default version is v1 and the field MUST be absent when the
//!   version is v1.
//! - `responderID` is the `byName` [1] alternative, EXPLICIT, wrapping
//!   the CA certificate's subject Name TLV verbatim — the responder is
//!   the CA itself.
//! - `producedAt`, `thisUpdate`, `nextUpdate` and the revocation time
//!   are always `GeneralizedTime` (RFC 6960 section 4.2.2.1), never
//!   `UTCTime`.
//! - `certID` hashes the issuer with SHA-1 — the algorithm RFC 6960
//!   section 4.1.1 makes mandatory to implement — over the CA
//!   certificate's subject Name TLV bytes and over the raw subject
//!   public key bytes.
//! - `certStatus` is the RFC 6960 `CertStatus` CHOICE, IMPLICITly
//!   tagged: `good` is the empty [0] (`80 00`), `unknown` the empty [2]
//!   (`82 00`), and `revoked` the [1] alternative carrying a
//!   `revocationTime` and, when known, a `revocationReason` extension
//!   (the [0] EXPLICIT ENUMERATED of RFC 5280 section 5.3.1).
//! - `certs` carries the CA certificate itself, so a client that only
//!   has the response can still chain it (stock OpenSSL's
//!   `openssl ocsp -issuer` needs it).
//!
//! The response carries no `responseExtensions` and no nonce: the
//! builder implements the plain v1 response, and a nonce would have to
//! be echoed from the request, which this API does not take.
//!
//! # Key material handling
//!
//! The CA private key lives only inside the `pub(crate)` `ZeroizingKey`
//! wrapper shared with `crate::ca` (zeroized on drop, on every exit path
//! including `?` early returns), and the (certificate, key) pair is
//! proven to match before signing — the responder's name comes from the
//! certificate while the signature comes from the key, so a mismatched
//! pair would silently produce an unverifiable response. No error
//! message carries key material.

use chrono::{DateTime, Datelike, Timelike, Utc};
use der::asn1::{AnyRef, BitString, GeneralizedTime, Null, ObjectIdentifier, OctetString, Uint};
use der::{Encode, Tag};
use rcgen::{KeyPair, SignatureAlgorithm, SigningKey, PKCS_ED25519, PKCS_RSA_SHA256};
use sha1::{Digest, Sha1};
use x509_parser::certificate::X509Certificate;
use x509_parser::pem::parse_x509_pem;

use crate::ca::{ensure_parent_key_matches_cert, ZeroizingKey};
use crate::crl::CrlReason;
use crate::error::CaError;

/// The status an OCSP response reports — the same type the
/// `ocsp_responses` table stores, re-exported so callers need not depend
/// on `ws-core` for it.
pub use ws_core::models::ocsp::OcspStatus;

/// id-Ed25519 (RFC 8410): the signature algorithm Ed25519 CA keys sign
/// an OCSP response with, written with absent parameters.
const OID_SIG_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// sha256WithRSAEncryption (RFC 4055): the signature algorithm RSA CA
/// keys sign an OCSP response with, written with NULL parameters.
const OID_SIG_SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// id-sha1 (RFC 3279): the hash algorithm of the `certID` hashes —
/// RFC 6960 section 4.1.1 makes SHA-1 mandatory to implement.
const OID_HASH_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

/// id-pkix-ocsp-basic (RFC 6960): the `responseType` of the response
/// bytes — a `BasicOCSPResponse`.
const OID_PKIX_OCSP_BASIC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");

/// DER tag octet for SEQUENCE (universal 16, constructed).
const TAG_SEQUENCE: u8 = 0x30;

/// DER tag octet for the `[0]` context-specific constructed wrapper. It
/// carries three different things in this response, each in its own
/// structure: the `certs` list of the `BasicOCSPResponse`, the
/// `nextUpdate` of a `SingleResponse` (EXPLICIT GeneralizedTime), and
/// the `revocationReason` extension of a revoked status (EXPLICIT
/// ENUMERATED). The `responderID` byName uses the `[1]` tag.
const TAG_CONTEXT_0: u8 = 0xa0;

/// DER tag octet for the `[1]` context-specific constructed wrapper that
/// carries the `responderID` byName.
const TAG_CONTEXT_1: u8 = 0xa1;

/// DER tag octet for the `good` certStatus ([0] IMPLICIT, primitive).
const TAG_STATUS_GOOD: u8 = 0x80;

/// DER tag octet for the `revoked` certStatus ([1] IMPLICIT, constructed).
const TAG_STATUS_REVOKED: u8 = 0xa1;

/// DER tag octet for the `unknown` certStatus ([2] IMPLICIT, primitive).
const TAG_STATUS_UNKNOWN: u8 = 0x82;

/// What one OCSP response says about a certificate.
#[derive(Debug, Clone)]
pub struct OcspResponseSpec {
    /// The status to report.
    pub status: OcspStatus,
    /// When the answer was produced (`producedAt`).
    pub this_update: DateTime<Utc>,
    /// How long the answer stays valid (`nextUpdate`).
    pub next_update: DateTime<Utc>,
    /// The revocation instant, for a `revoked` answer (`None` for the
    /// other statuses). A `Revoked` answer without it is a typed error:
    /// the revocation date is never invented.
    pub revoked_at: Option<DateTime<Utc>>,
    /// The revocation reason, for a `revoked` answer whose reason is
    /// known (`None` emits no reason extension at all).
    pub reason: Option<CrlReason>,
}

/// Build one OCSP response for `serial` under the given CA.
///
/// `ca_cert_pem` and `ca_key_der` must pair (checked, as in
/// `crate::ca::create_sub_ca`): the responder name comes from the
/// certificate while the signature comes from the key. Pinned
/// requirement: the output must parse with stock OpenSSL
/// (`openssl ocsp -issuer ca.pem -cert leaf.pem -respin resp.der
/// -text` prints the status and `Response verify OK`).
///
/// Errors: malformed PEM/DER input is [`CaError::X509`]; a `Revoked`
/// answer without a revocation instant is [`CaError::X509`] (the
/// revocation date is never fabricated); a signing key whose algorithm is
/// neither Ed25519 nor RSA is [`CaError::UnsupportedKeyType`] (the
/// algorithm name only, never key material); signing failures are
/// [`CaError::Rcgen`].
pub fn build_ocsp_response(
    ca_cert_pem: &str,
    ca_key_der: &[u8],
    serial: u128,
    spec: &OcspResponseSpec,
) -> Result<Vec<u8>, CaError> {
    // CA side: load the key (zeroized on every exit path) and prove the
    // certificate/key pair belongs together before the responder name
    // from the certificate and the signature from the key are combined.
    let ca_key = ZeroizingKey(KeyPair::try_from(ca_key_der)?);
    ensure_parent_key_matches_cert(ca_cert_pem, &ca_key)?;

    let (_, ca_pem_block) = parse_x509_pem(ca_cert_pem.as_bytes())
        .map_err(|_| CaError::X509("CA certificate is not valid PEM".to_owned()))?;
    let ca_cert = ca_pem_block
        .parse_x509()
        .map_err(|_| CaError::X509("CA certificate failed to parse".to_owned()))?;

    let algorithm = algorithm_identifier(ca_key.algorithm())?;
    let tbs = tbs_response_data(&ca_cert, serial, spec)?;

    // Sign the ResponseData and wrap the raw signature in a BIT STRING.
    let signature = ca_key.sign(&tbs)?;
    let signature = BitString::new(0, signature)
        .map_err(der_err)?
        .to_der()
        .map_err(der_err)?;

    let mut basic = tbs;
    basic.extend_from_slice(&algorithm);
    basic.extend_from_slice(&signature);
    // certs [0] EXPLICIT SEQUENCE OF Certificate: the CA certificate
    // itself, so a client can chain the response without a separate
    // issuer file.
    basic.extend_from_slice(&tlv(TAG_CONTEXT_0, &tlv(TAG_SEQUENCE, ca_cert.as_raw())));
    let basic = tlv(TAG_SEQUENCE, &basic);

    // ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
    let response_bytes = tlv(
        TAG_SEQUENCE,
        &[
            OID_PKIX_OCSP_BASIC.to_der().map_err(der_err)?,
            OctetString::new(basic)
                .map_err(der_err)?
                .to_der()
                .map_err(der_err)?,
        ]
        .concat(),
    );

    // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, responseBytes [0] EXPLICIT }
    let mut response = AnyRef::new(Tag::Enumerated, &[0x00])
        .map_err(der_err)?
        .to_der()
        .map_err(der_err)?;
    response.extend_from_slice(&tlv(TAG_CONTEXT_0, &response_bytes));
    Ok(tlv(TAG_SEQUENCE, &response))
}

/// The `tbsResponseData` (RFC 6960 section 4.2.1): the responder, the
/// production instant, and the single-certificate `responses` list.
fn tbs_response_data(
    ca_cert: &X509Certificate<'_>,
    serial: u128,
    spec: &OcspResponseSpec,
) -> Result<Vec<u8>, CaError> {
    // responderID: byName [1] EXPLICIT Name — the CA certificate's
    // subject Name TLV, spliced verbatim.
    let responder = tlv(TAG_CONTEXT_1, ca_cert.subject().as_raw());

    let produced_at = generalized_time(&spec.this_update)?;
    let this_update = generalized_time(&spec.this_update)?;
    // nextUpdate is [0] EXPLICIT GeneralizedTime (RFC 6960 section
    // 4.2.1): the explicit tag wrapper is part of the definition, not a
    // convenience.
    let next_update = tlv(TAG_CONTEXT_0, &generalized_time(&spec.next_update)?);

    let single = single_response(ca_cert, serial, spec, this_update, next_update)?;

    let mut tbs = responder;
    tbs.extend_from_slice(&produced_at);
    tbs.extend_from_slice(&tlv(TAG_SEQUENCE, &single));
    Ok(tlv(TAG_SEQUENCE, &tbs))
}

/// One `SingleResponse` (RFC 6960 section 4.2.1): the `certID`, the
/// `certStatus`, and the validity window.
fn single_response(
    ca_cert: &X509Certificate<'_>,
    serial: u128,
    spec: &OcspResponseSpec,
    this_update: Vec<u8>,
    next_update: Vec<u8>,
) -> Result<Vec<u8>, CaError> {
    let cert_id = cert_id(ca_cert, serial)?;

    let status = match spec.status {
        OcspStatus::Good => vec![TAG_STATUS_GOOD, 0x00],
        OcspStatus::Unknown => vec![TAG_STATUS_UNKNOWN, 0x00],
        OcspStatus::Revoked => {
            // A revoked answer must carry the real revocation instant.
            // Falling back to the response's own production time would
            // publish a revocation date that never happened, so a
            // missing one is a typed error, never a fabrication.
            let revoked_at = spec.revoked_at.ok_or_else(|| {
                CaError::X509("a revoked OCSP response requires the revocation instant".to_owned())
            })?;
            let mut content = generalized_time(&revoked_at)?;
            if let Some(reason) = spec.reason {
                // revocationReason: [0] EXPLICIT ENUMERATED, the RFC 5280
                // section 5.3.1 code.
                let enumerated = AnyRef::new(Tag::Enumerated, &[reason.as_code()])
                    .map_err(der_err)?
                    .to_der()
                    .map_err(der_err)?;
                content.extend_from_slice(&tlv(TAG_CONTEXT_0, &enumerated));
            }
            tlv(TAG_STATUS_REVOKED, &content)
        }
    };

    let mut content = cert_id;
    content.extend_from_slice(&status);
    content.extend_from_slice(&this_update);
    content.extend_from_slice(&next_update);
    Ok(tlv(TAG_SEQUENCE, &content))
}

/// The `CertID` (RFC 6960 section 4.1.1): the hash algorithm, the two
/// issuer hashes, and the certificate's serial number.
fn cert_id(ca_cert: &X509Certificate<'_>, serial: u128) -> Result<Vec<u8>, CaError> {
    // AlgorithmIdentifier: sha-1 with NULL parameters (RFC 3279).
    let mut algorithm = OID_HASH_SHA1.to_der().map_err(der_err)?;
    algorithm.extend_from_slice(&Null.to_der().map_err(der_err)?);
    let algorithm = tlv(TAG_SEQUENCE, &algorithm);

    // issuerNameHash: SHA-1 over the CA certificate's subject Name TLV
    // bytes (header included).
    let name_hash = sha1(ca_cert.subject().as_raw());
    // issuerKeyHash: SHA-1 over the CA certificate's subject public key
    // bits — the raw key bytes, without the BIT STRING's unused-bits
    // octet.
    let key_hash = sha1(&ca_cert.public_key().subject_public_key.data);

    let name_hash = OctetString::new(name_hash)
        .map_err(der_err)?
        .to_der()
        .map_err(der_err)?;
    let key_hash = OctetString::new(key_hash)
        .map_err(der_err)?
        .to_der()
        .map_err(der_err)?;
    let serial = Uint::new(&serial.to_be_bytes())
        .map_err(der_err)?
        .to_der()
        .map_err(der_err)?;

    let mut content = algorithm;
    content.extend_from_slice(&name_hash);
    content.extend_from_slice(&key_hash);
    content.extend_from_slice(&serial);
    Ok(tlv(TAG_SEQUENCE, &content))
}

/// The response's `AlgorithmIdentifier`, dispatched from the signing key:
/// Ed25519 keys sign with id-Ed25519 and absent parameters (RFC 8410),
/// RSA keys with sha256WithRSAEncryption and NULL parameters. Anything
/// else is a typed rejection naming the algorithm only.
fn algorithm_identifier(algorithm: &SignatureAlgorithm) -> Result<Vec<u8>, CaError> {
    let (oid, null_params) = if algorithm == &PKCS_ED25519 {
        (OID_SIG_ED25519, false)
    } else if algorithm == &PKCS_RSA_SHA256 {
        (OID_SIG_SHA256_RSA, true)
    } else {
        return Err(CaError::UnsupportedKeyType(format!(
            "OCSP signing is not supported for this CA key algorithm ({algorithm:?})"
        )));
    };

    let mut content = oid.to_der().map_err(der_err)?;
    if null_params {
        content.extend_from_slice(&Null.to_der().map_err(der_err)?);
    }
    Ok(tlv(TAG_SEQUENCE, &content))
}

/// SHA-1 over `bytes` (the `certID` hash of RFC 6960 section 4.1.1).
fn sha1(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

/// A chrono instant as a `GeneralizedTime` (RFC 6960 section 4.2.2.1
/// uses GeneralizedTime for every time it defines), as a full TLV.
fn generalized_time(dt: &DateTime<Utc>) -> Result<Vec<u8>, CaError> {
    let year = u16::try_from(dt.year())
        .map_err(|_| CaError::X509("OCSP timestamp year is out of the DER range".to_owned()))?;
    let converted = der::DateTime::new(
        year,
        dt.month() as u8,
        dt.day() as u8,
        dt.hour() as u8,
        dt.minute() as u8,
        dt.second() as u8,
    )
    .map_err(|_| CaError::X509("OCSP timestamp is not a valid DER date".to_owned()))?;
    GeneralizedTime::from(&converted).to_der().map_err(der_err)
}

/// Map a `der` encoding failure onto the typed error surface (the Display
/// text is the encoder's own; it never includes key material).
fn der_err(err: der::Error) -> CaError {
    CaError::X509(format!("OCSP DER encoding failed: {err}"))
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
