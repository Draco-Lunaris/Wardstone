//! Leaf-certificate issuance from a certificate signing request.
//!
//! [`validate_csr`] answers "what is being requested" (algorithm name,
//! subject CN, SANs) with x509-parser only; [`sign_leaf_with`] is the
//! issuing primitive and enforces the pinned issuance contract before any
//! certificate is minted:
//!
//! 1. **The CSR's self-signature must verify** (proof-of-possession, the
//!    standard PKCS#10 check verified with x509-parser against the
//!    request's own public key) — a CSR whose signature does not verify is
//!    [`CaError::X509`], never issuance.
//! 2. **The leaf's public key is the CSR's public key**: the CSR's raw
//!    subjectPublicKeyInfo (algorithm OID set + key bits) is fed to rcgen
//!    verbatim, so the issued certificate carries exactly the requester's
//!    key, never a CA-generated one.
//! 3. **Unsupported key algorithms are typed rejections**: anything outside
//!    the supported set — Ed25519, ECDSA P-256/P-384, RSA ≥ 2048 bits —
//!    returns [`CaError::UnsupportedKeyType`] and never panics. The RSA
//!    floor is a key-size check on the parsed SPKI modulus (not the
//!    string name), so an RSA-1024 request is rejected even though RSA as
//!    a family is supported.
//!
//! Ordering note: the supported-algorithm gate runs *before* signature
//! verification. For some unsupported algorithms (Ed448, ECDSA P-521) the
//! verification backend cannot evaluate a signature at all, which would
//! surface as a generic [`CaError::X509`]; gating first keeps the pinned,
//! more precise rejection. Signature verification still guards every
//! algorithm that passes the gate, so no certificate is ever minted from
//! an unverified request.
//!
//! The serial is caller-supplied ([`LeafSpec::serial`]): never minted
//! here. Plan-2 bootstrap / Task-8 DB-backed allocation owns serial
//! uniqueness; issuance's job is to encode the given value unchanged.
//!
//! # Certificate profile (end-entity)
//!
//! Mirrors the CA profile of [`crate::ca`]: subject is a single
//! `CN=<common name>` (UTF8String) taken from the spec override or the
//! CSR's CN; SANs from [`LeafSpec::sans`] (DNS/IP/email); KeyUsage and
//! ExtendedKeyUsage exactly as requested (KeyUsage critical; both lists
//! refused when empty, because an ABSENT extension is more permissive
//! than any pinned list); BasicConstraints `CA:FALSE` critical; SKI per
//! rcgen's default; `not_before` is midnight UTC one day before today
//! (Task 5's clock-skew margin) and is computed here, never supplied by
//! the caller; `not_after = not_before + lifetime` — the spec's
//! `lifetime` is the certificate's SPAN. A leaf whose span reaches
//! beyond the issuing CA's `notAfter` is refused, never silently clamped
//! (Plan 1 clamped; a certificate that silently differs from its profile
//! is a policy violation invisible to the caller and the auditor).
//!
//! # Key material handling
//!
//! The CA private key lives only inside the `pub(crate)` `ZeroizingKey`
//! wrapper shared with [`crate::ca`] (zeroized on drop). The CSR's public
//! key is public certificate content. No error message ever carries key
//! material.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    PublicKeyData, SanType, SerialNumber, SignatureAlgorithm, PKCS_ECDSA_P256_SHA256,
    PKCS_ECDSA_P384_SHA384, PKCS_ED25519, PKCS_RSA_SHA256,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use x509_parser::asn1_rs::FromDer;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::pem::parse_x509_pem;
use x509_parser::x509::SubjectPublicKeyInfo;

use crate::ca::{
    ensure_issuer_is_ca, ensure_parent_key_matches_cert, issuer_not_after, ZeroizingKey,
};
use crate::error::CaError;
use crate::leafkey::LeafKeyType;

/// [`ws_core::models::rbac::KeyUsagePurpose`], re-exported: Wardstone's
/// ONE key-usage vocabulary. `ws-core` owns the enum (Task 2);
/// `ws-ca` re-exports it so profiles can name it through `ws-ca`
/// alone, and converts it to the engine's type at the boundary
/// ([`key_usage_to_rcgen`]).
pub use ws_core::models::rbac::KeyUsagePurpose;

/// One subject alternative name that a leaf may carry.
///
/// `Email` is reserved for the future S/MIME profile; it parses and
/// round-trips already so issued S/MIME certificates can reuse this type
/// without a breaking change, but no validation policy beyond charset
/// applies to it yet.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SanEntry {
    /// A DNS name (dNSName).
    Dns(String),
    /// An IP address (iPAddress), v4 or v6.
    Ip(IpAddr),
    /// An email address (rfc822Name). Reserved for the future S/MIME
    /// profile.
    Email(String),
}

/// One RFC 5280 extended key usage (EKU), as a leaf profile's `ekus`
/// list spells it and as the issuance engine receives it — the
/// snake_case house spelling, NOT the RFC's camelCase OID aliases
/// (which would spell `serverAuth`).
///
/// rcgen's enum has two more variants, `Any` (anyExtendedKeyUsage) and
/// `Other(Vec<u64>)`: deliberately absent here, because a profile cannot
/// express "usable for any purpose" or an unknown OID — a certificate
/// usable for anything is exactly what an ABSENT EKU extension means,
/// and an absent extension is precisely what [`sign_leaf_with`]'s
/// empty-list refusal exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtKeyUsagePurpose {
    /// TLS server authentication (`id-kp-serverAuth`).
    ServerAuth,
    /// TLS client authentication (`id-kp-clientAuth`).
    ClientAuth,
    /// Code signing (`id-kp-codeSigning`).
    CodeSigning,
    /// Email protection / S/MIME (`id-kp-emailProtection`).
    EmailProtection,
    /// OCSP response signing (`id-kp-OCSPSigning`).
    OcspSigning,
    /// Timestamping (`id-kp-timeStamping`).
    TimeStamping,
}

/// Every [`ExtKeyUsagePurpose`], for round-trip tests.
pub const ALL_EXT_KEY_USAGE_PURPOSES: &[ExtKeyUsagePurpose] = &[
    ExtKeyUsagePurpose::ServerAuth,
    ExtKeyUsagePurpose::ClientAuth,
    ExtKeyUsagePurpose::CodeSigning,
    ExtKeyUsagePurpose::EmailProtection,
    ExtKeyUsagePurpose::OcspSigning,
    ExtKeyUsagePurpose::TimeStamping,
];

impl ExtKeyUsagePurpose {
    /// The value a leaf profile stores in its `ekus` list (the TEXT[]
    /// element; plain snake_case — identical to the serde name, written
    /// once).
    pub fn as_str(&self) -> &'static str {
        match self {
            ExtKeyUsagePurpose::ServerAuth => "server_auth",
            ExtKeyUsagePurpose::ClientAuth => "client_auth",
            ExtKeyUsagePurpose::CodeSigning => "code_signing",
            ExtKeyUsagePurpose::EmailProtection => "email_protection",
            ExtKeyUsagePurpose::OcspSigning => "ocsp_signing",
            ExtKeyUsagePurpose::TimeStamping => "time_stamping",
        }
    }

    /// Fallible parse from the TEXT[] element value (house idiom;
    /// inherent rather than `FromStr` because there is no error type to
    /// carry).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        ALL_EXT_KEY_USAGE_PURPOSES
            .iter()
            .copied()
            .find(|e| e.as_str() == s)
    }
}

/// What a CSR requests, as reported by [`validate_csr`].
///
/// Purely informational (API-preview surface): `sign_leaf_with` re-parses
/// the CSR itself and pulls only subject and public key from it — the
/// leaf's SANs and key usages come from the caller's [`LeafSpec`], which
/// is the CA's policy decision, not the requester's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrInfo {
    /// Human-readable public-key algorithm name (`Ed25519`, `ECDSA
    /// P-256`, `ECDSA P-384`, `RSA`, ...) as pinned by
    /// [`supported_key_alg`]; unknown algorithms get their OID string.
    pub public_key_alg: String,
    /// The request's subject common name, when one is present.
    pub subject_cn: Option<String>,
    /// The SANs the request asks for (DNS, IP, email only — other
    /// GeneralName kinds the `SanEntry` model cannot express are omitted).
    pub sans: Vec<SanEntry>,
}

/// Policy for one leaf certificate, supplied by the caller.
///
/// The serial is caller-owned: Task-8's DB-backed allocation supplies it
/// in later plans; issuance never mints one. There is deliberately NO
/// `Default` derive: a derived default would yield empty `ekus` and
/// `key_usages` — exactly the lists [`sign_leaf_with`] refuses — and a
/// zero `lifetime` plus `serial = 0`, an illegal RFC 5280 serial.
#[derive(Debug, Clone)]
pub struct LeafSpec {
    /// Subject alternative names to place on the leaf. Comes from CA
    /// policy, not from the CSR's requested extensions.
    pub sans: Vec<SanEntry>,
    /// KeyUsage bits to place on the leaf (critical, exactly as given).
    /// MUST be non-empty: [`sign_leaf_with`] refuses an empty list,
    /// because an absent keyUsage extension is MORE permissive than any
    /// pinned list (RFC 5280 section 4.2.1.3 — without it the
    /// certificate is unrestricted).
    pub key_usages: Vec<KeyUsagePurpose>,
    /// ExtendedKeyUsage purposes to place on the leaf. MUST be
    /// non-empty, for the same reason (RFC 5280 section 4.2.1.12).
    pub ekus: Vec<ExtKeyUsagePurpose>,
    /// The key type the profile pins: the CSR's actual key algorithm
    /// must satisfy it — the exact algorithm for the non-RSA pins, the
    /// RSA family plus the pinned modulus floor for the RSA pins. Plan
    /// 2's setup page generates the leaf key from this same pin via
    /// [`crate::leafkey::generate_leaf_key`].
    pub key_type: LeafKeyType,
    /// The certificate's validity SPAN. `ws-ca` computes `not_before`
    /// (midnight UTC one day before today — the clock-skew margin)
    /// internally and sets `not_after = not_before + lifetime`, so a
    /// span, never an absolute instant: the caller cannot observe the
    /// internal `not_before`, and an absolute `not_after` would make the
    /// actual span depend on issuance time (up to a day off the
    /// profile's number). Whole seconds; a profile's `lifetime_days`
    /// maps 1:1 onto this field.
    pub lifetime: chrono::Duration,
    /// Subject common name override. `None` keeps the CSR's own CN. The
    /// final subject must be non-empty: a whitespace override over a
    /// CN-less request is a typed error, never a subject-less certificate.
    pub subject_cn: Option<String>,
    /// Caller-supplied serial number, encoded unchanged into the
    /// certificate.
    pub serial: u128,
}

/// A successfully issued leaf certificate.
#[derive(Debug, Clone)]
pub struct IssuedLeaf {
    /// PEM-encoded X.509 end-entity certificate.
    pub cert_pem: String,
    /// The exact [`LeafSpec::serial`] passed in (already in the
    /// certificate).
    pub serial: u128,
    /// Not-before instant (whole seconds, UTC).
    pub not_before: chrono::DateTime<chrono::Utc>,
    /// Not-after instant (whole seconds, UTC).
    pub not_after: chrono::DateTime<chrono::Utc>,
}

/// Human-readable subject-public-key-algorithm name for a parsed SPKI, as
/// consumed by [`supported_key_alg`].
///
/// Covers the Wardstone names exactly (`Ed25519`, `ECDSA P-256`, `ECDSA
/// P-384`, `RSA`); other EC curves report their parameter OID, other
/// algorithms their signature/key OIDs — everything outside the supported
/// set is rejected by name before any key is used.
fn alg_name(spki: &SubjectPublicKeyInfo<'_>) -> String {
    let alg_oid = &spki.algorithm.algorithm;
    if *alg_oid == x509_parser::oid_registry::OID_SIG_ED25519 {
        return "Ed25519".to_owned();
    }
    if *alg_oid == x509_parser::oid_registry::OID_SIG_ED448 {
        return "Ed448".to_owned();
    }
    if *alg_oid == x509_parser::oid_registry::OID_PKCS1_RSAENCRYPTION {
        return "RSA".to_owned();
    }
    if *alg_oid == x509_parser::oid_registry::OID_PKCS1_RSASSAPSS {
        return "RSA-PSS".to_owned();
    }
    if *alg_oid == x509_parser::oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY {
        // The curve lives in the algorithm parameters as an OID; an
        // explicitly-encoded curve or a missing parameter is its own
        // (unsupported) name.
        return match spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
        {
            Some(oid) if oid == x509_parser::oid_registry::OID_EC_P256 => "ECDSA P-256".to_owned(),
            Some(oid) if oid == x509_parser::oid_registry::OID_NIST_EC_P384 => {
                "ECDSA P-384".to_owned()
            }
            Some(oid) if oid == x509_parser::oid_registry::OID_NIST_EC_P521 => {
                "ECDSA P-521".to_owned()
            }
            Some(oid) => format!("EC curve OID {}", oid.to_id_string()),
            None => "EC (unnamed curve)".to_owned(),
        };
    }
    format!("OID {}", alg_oid.to_id_string())
}

/// Whether `alg` (a [`CsrInfo::public_key_alg`] /
/// [`alg_name`] string) names a key algorithm this CA will sign for.
///
/// Name-level only: the RSA family's 2048-bit floor is a key-size check
/// performed in [`sign_leaf_with`] on the parsed SPKI modulus, not here.
pub fn supported_key_alg(alg: &str) -> bool {
    matches!(alg, "Ed25519" | "ECDSA P-256" | "ECDSA P-384" | "RSA")
}

/// Decode a PEM-encoded PKCS#10 CSR into its DER bytes.
///
/// Kept separate from the DER parse so the decoded bytes are owned by the
/// caller and the parsed request can borrow them for the caller's whole
/// scope (a combined helper would have to leak or return the buffer).
pub(crate) fn decode_csr_pem(csr_pem: &str) -> Result<Vec<u8>, CaError> {
    let (_, pem) = parse_x509_pem(csr_pem.as_bytes())
        .map_err(|e| CaError::X509(format!("CSR is not valid PEM: {e}")))?;
    if pem.label != "CERTIFICATE REQUEST" {
        return Err(CaError::X509(format!(
            "PEM block is not a CSR (label {:?})",
            pem.label
        )));
    }
    Ok(pem.contents)
}

/// Parse PKCS#10 DER into a certification request, borrowing `der`.
pub(crate) fn parse_csr_der(der: &[u8]) -> Result<X509CertificationRequest<'_>, CaError> {
    let (_, csr) = X509CertificationRequest::from_der(der)
        .map_err(|e| CaError::X509(format!("CSR failed to parse as PKCS#10: {e}")))?;
    Ok(csr)
}

/// Validate a CSR structurally: parse, then report algorithm name, subject
/// CN and SANs.
///
/// Deliberately does *not* verify the request's signature — that is
/// [`sign_leaf_with`]'s pinned hard requirement, and
/// [`CsrInfo`] is the preview an API consumer sees before any issuance
/// decision. Malformed PEM or DER is [`CaError::X509`], never a panic.
pub fn validate_csr(csr_pem: &str) -> Result<CsrInfo, CaError> {
    let der = decode_csr_pem(csr_pem)?;
    let csr = parse_csr_der(&der)?;
    let spki = &csr.certification_request_info.subject_pki;
    let subject_cn = csr
        .certification_request_info
        .subject
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_owned);
    let sans = csr
        .requested_extensions()
        .into_iter()
        .flatten()
        .filter_map(|ext| match ext {
            x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => {
                Some(san.general_names.iter().filter_map(san_entry_from_general))
            }
            _ => None,
        })
        .flatten()
        .collect::<Vec<_>>();
    Ok(CsrInfo {
        public_key_alg: alg_name(spki),
        subject_cn,
        sans,
    })
}

/// Map a parsed [`GeneralName`] into a [`SanEntry`], dropping the
/// GeneralName kinds `SanEntry` cannot express (URI, directory names,
/// otherName, registered IDs) and IP octet lengths that are neither 4 nor
/// 16.
fn san_entry_from_general(name: &x509_parser::extensions::GeneralName<'_>) -> Option<SanEntry> {
    match name {
        x509_parser::extensions::GeneralName::DNSName(dns) => Some(SanEntry::Dns(dns.to_string())),
        x509_parser::extensions::GeneralName::RFC822Name(mail) => {
            Some(SanEntry::Email(mail.to_string()))
        }
        x509_parser::extensions::GeneralName::IPAddress(octets) => match octets.len() {
            4 => Some(SanEntry::Ip(IpAddr::V4(Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            )))),
            16 => {
                let bits: [u8; 16] = octets.to_vec().try_into().ok()?;
                Some(SanEntry::Ip(IpAddr::V6(Ipv6Addr::from(bits))))
            }
            _ => None,
        },
        _ => None,
    }
}

/// The CSR's public key as rcgen [`PublicKeyData`]: raw key bits plus the
/// matching static [`SignatureAlgorithm`], from which rcgen re-encodes the
/// leaf's subjectPublicKeyInfo (same OIDs, same bits — the pinned
/// "leaf carries the CSR's public key" contract).
struct CsrPublicKey {
    key_bits: Vec<u8>,
    signature_algorithm: &'static SignatureAlgorithm,
}

impl PublicKeyData for CsrPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.key_bits
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.signature_algorithm
    }
}

/// rcgen signing algorithm + subject key bits for a CSR public key whose
/// algorithm has passed the supported gate.
///
/// The SPKI's own OIDs are reproduced exactly by rcgen's SPKI writer for
/// each of these algorithms (Ed25519: id-Ed25519; P-256/P-384:
/// id-ecPublicKey + the curve OID; RSA: rsaEncryption + NULL), so the
/// issued leaf's SPKI equals the CSR's field-for-field.
fn csr_public_key_data(alg: &str, key_bits: &[u8]) -> Result<CsrPublicKey, CaError> {
    let signature_algorithm = match alg {
        "Ed25519" => &PKCS_ED25519,
        "ECDSA P-256" => &PKCS_ECDSA_P256_SHA256,
        "ECDSA P-384" => &PKCS_ECDSA_P384_SHA384,
        "RSA" => &PKCS_RSA_SHA256,
        // Unreachable through sign_leaf_with (the gate rejects every other
        // name); kept typed so a future caller cannot bypass the gate.
        other => {
            return Err(CaError::UnsupportedKeyType(format!(
                "CSR key algorithm {other} is not supported \
                 (supported: Ed25519, ECDSA P-256, ECDSA P-384, RSA)"
            )))
        }
    };
    Ok(CsrPublicKey {
        key_bits: key_bits.to_vec(),
        signature_algorithm,
    })
}

/// Convert Wardstone's ONE key-usage vocabulary onto the engine's type.
///
/// A free function on purpose: a method on [`KeyUsagePurpose`] would put
/// `rcgen` into `ws-core` (the crate that owns the enum), and an
/// `impl From<ws_core::KeyUsagePurpose> for rcgen::KeyUsagePurpose`
/// would violate the orphan rule (E0210).
pub fn key_usage_to_rcgen(k: KeyUsagePurpose) -> rcgen::KeyUsagePurpose {
    match k {
        KeyUsagePurpose::DigitalSignature => rcgen::KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment => rcgen::KeyUsagePurpose::KeyEncipherment,
        KeyUsagePurpose::DataEncipherment => rcgen::KeyUsagePurpose::DataEncipherment,
        KeyUsagePurpose::KeyAgreement => rcgen::KeyUsagePurpose::KeyAgreement,
        KeyUsagePurpose::KeyCertSign => rcgen::KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign => rcgen::KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::ContentCommitment => rcgen::KeyUsagePurpose::ContentCommitment,
        KeyUsagePurpose::EncipherOnly => rcgen::KeyUsagePurpose::EncipherOnly,
        KeyUsagePurpose::DecipherOnly => rcgen::KeyUsagePurpose::DecipherOnly,
    }
}

/// Convert Wardstone's EKU vocabulary onto the engine's type.
///
/// rcgen's enum has two extra variants, `Any` and `Other(Vec<u64>)`:
/// deliberately unreachable here — [`LeafSpec::ekus`] cannot express
/// "any purpose" or an unknown OID, so the conversion is a total match
/// over Wardstone's six variants and a future Wardstone variant fails
/// compilation here instead of silently not being encoded.
///
/// A free function, like [`key_usage_to_rcgen`] (same orphan-rule and
/// dependency-direction reasoning).
pub fn eku_to_rcgen(e: ExtKeyUsagePurpose) -> ExtendedKeyUsagePurpose {
    match e {
        ExtKeyUsagePurpose::ServerAuth => ExtendedKeyUsagePurpose::ServerAuth,
        ExtKeyUsagePurpose::ClientAuth => ExtendedKeyUsagePurpose::ClientAuth,
        ExtKeyUsagePurpose::CodeSigning => ExtendedKeyUsagePurpose::CodeSigning,
        ExtKeyUsagePurpose::EmailProtection => ExtendedKeyUsagePurpose::EmailProtection,
        ExtKeyUsagePurpose::OcspSigning => ExtendedKeyUsagePurpose::OcspSigning,
        ExtKeyUsagePurpose::TimeStamping => ExtendedKeyUsagePurpose::TimeStamping,
    }
}

/// Issue a leaf certificate from a CSR, signed by the CA whose certificate
/// and key are supplied (`ca_cert_pem` + `ca_key_der` must pair — they are
/// checked against each other, as in [`crate::ca::create_sub_ca`]).
///
/// See the module docs for the pinned issuance contract (verified
/// signature, CSR public key, typed unsupported-key rejection). Errors:
/// malformed inputs [`CaError::X509`]; unsupported keys
/// [`CaError::UnsupportedKeyType`]; rcgen failures [`CaError::Rcgen`].
/// The serial comes from `spec.serial` and is encoded unchanged.
pub fn sign_leaf_with(
    ca_cert_pem: &str,
    ca_key_der: &[u8],
    csr_pem: &str,
    spec: &LeafSpec,
) -> Result<IssuedLeaf, CaError> {
    // Profile obligations first, before any key is loaded or parsed: an
    // empty key-usage or EKU list would mint a certificate whose ABSENT
    // extension is MORE permissive than any pinned list (RFC 5280
    // sections 4.2.1.3 and 4.2.1.12 — without keyUsage the certificate
    // is unrestricted), so "no pins" can only be a caller bug, never a
    // profile. Refused with a typed error, never issued.
    if spec.key_usages.is_empty() {
        return Err(CaError::X509(
            "leaf keyUsage is empty: an absent keyUsage extension is more permissive than \
             any pinned list (RFC 5280 section 4.2.1.3); a leaf profile must pin at least \
             one key usage"
                .to_owned(),
        ));
    }
    if spec.ekus.is_empty() {
        return Err(CaError::X509(
            "leaf extendedKeyUsage is empty: an absent extendedKeyUsage extension is more \
             permissive than any pinned list (RFC 5280 section 4.2.1.12); a leaf profile \
             must pin at least one EKU"
                .to_owned(),
        ));
    }

    // Issuer side: load the CA key (zeroized on every exit path) and prove
    // the certificate/key pair belongs together before the issuer DN from
    // the certificate and the signature from the key are combined.
    let ca_key = ZeroizingKey(KeyPair::try_from(ca_key_der)?);
    ensure_parent_key_matches_cert(ca_cert_pem, &ca_key)?;
    // The issuer must be a CA permitted to sign certificates: an
    // end-entity certificate is never a valid issuer, and a leaf signed
    // by one produces a chain that relying parties reject ("invalid CA
    // certificate" / "key usage does not include certificate signing").
    ensure_issuer_is_ca(ca_cert_pem)?;
    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, &ca_key)?;

    // Request side: parse, then gate on the supported algorithm set (name
    // level plus the RSA key-size floor from the parsed modulus) before
    // anything else uses the key.
    let csr_der = decode_csr_pem(csr_pem)?;
    let csr = parse_csr_der(&csr_der)?;
    let spki = &csr.certification_request_info.subject_pki;
    let alg = alg_name(spki);
    let csr_rsa_bits = gate_supported_key(&alg, spki)?;
    // The profile's key-type pin: the CSR's key must satisfy it — the
    // exact algorithm for the non-RSA pins, the RSA family plus the
    // pinned modulus floor for the RSA pins. A different family, or a
    // weaker key under a stronger pin, is a typed rejection: issuing a
    // certificate whose key does not match its profile is a policy
    // violation.
    let (pinned_alg, pinned_rsa_bits) = spec.key_type.csr_constraint();
    if alg != pinned_alg {
        return Err(CaError::UnsupportedKeyType(format!(
            "CSR key algorithm {alg} does not match the profile-pinned leaf key type {} \
             (which requires {pinned_alg})",
            spec.key_type.as_str()
        )));
    }
    if let Some(min_bits) = pinned_rsa_bits {
        let bits = csr_rsa_bits.unwrap_or(0);
        if bits < min_bits {
            return Err(CaError::UnsupportedKeyType(format!(
                "CSR RSA key is {bits} bits; the profile pins leaf key type {} \
                 ({pinned_alg}) of at least {min_bits} bits",
                spec.key_type.as_str()
            )));
        }
    }

    // Pinned hard requirement: the requester's self-signature must verify
    // (proof of possession) before this CA signs for the key.
    csr.verify_signature()
        .map_err(|e| CaError::X509(format!("CSR signature verification failed: {e}")))?;

    // Subject: spec override wins; otherwise the CSR's own CN. The final
    // subject must be usable — an empty one is a typed failure, not a
    // subject-less certificate.
    let cn = match spec.subject_cn.as_deref().map(str::trim) {
        Some("") => {
            return Err(CaError::X509(
                "leaf subject is empty: subject_cn override must not be blank".to_owned(),
            ))
        }
        Some(cn) => cn.to_owned(),
        None => csr
            .certification_request_info
            .subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(str::trim)
            .filter(|cn| !cn.is_empty())
            .ok_or_else(|| {
                CaError::X509(
                    "leaf subject is empty: CSR carries no common name and no override was given"
                        .to_owned(),
                )
            })?
            .to_owned(),
    };
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);

    // The lifetime must be positive: a zero or negative span would issue
    // a certificate whose validity window never opens.
    if spec.lifetime.num_seconds() <= 0 {
        return Err(CaError::X509(format!(
            "leaf lifetime must be positive, but {} seconds was requested; not_after would \
             be at or before not_before",
            spec.lifetime.num_seconds()
        )));
    }
    // Validity: not_before is midnight UTC one day before today (Task 5's
    // clock-skew margin), computed HERE — the caller can never observe
    // it, which is why the spec carries a span — and not_after is exactly
    // `not_before + lifetime`: the span the profile asked for is the span
    // the certificate carries.
    //
    // A leaf whose span reaches beyond the issuing CA certificate's own
    // notAfter is REFUSED — a deliberate change from Plan 1, which
    // silently clamped not_after to the issuer's expiry and thereby
    // minted a certificate that silently differs from its profile,
    // invisible to both the caller and the auditor. The refusal names
    // both instants so the caller can shorten the profile's lifetime or
    // renew the CA.
    let (not_before, not_after) = validity_window(&spec.lifetime)?;
    let issuer_not_after = issuer_not_after(ca_cert_pem)?;
    if not_after.unix_timestamp() > issuer_not_after.timestamp() {
        return Err(CaError::X509(format!(
            "leaf not_after ({}) outlives the issuing CA certificate's notAfter ({}); \
             shorten the profile's lifetime or renew the CA",
            not_after.unix_timestamp(),
            issuer_not_after.timestamp()
        )));
    }

    // Public key: the CSR's own, verbatim (pinned requirement 2).
    let public_key = csr_public_key_data(&alg, &spki.subject_public_key.data)?;

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.not_before = not_before;
    params.not_after = not_after;
    // Serial from the caller, byte order fixed so the u128 round-trips.
    // Zero is rejected before encoding: RFC 5280 section 4.1.2.2 requires
    // serials to be positive, and yasna's writer would collapse 16 zero
    // bytes to a single octet — still zero, still non-positive.
    if spec.serial == 0 {
        return Err(CaError::X509(
            "leaf serial must be a positive integer (RFC 5280 section 4.1.2.2); serial 0 was supplied"
                .to_owned(),
        ));
    }
    params.serial_number = Some(SerialNumber::from_slice(&spec.serial.to_be_bytes()));
    // End-entity: explicit CA:FALSE BasicConstraints (critical), so the
    // issued profile is deterministic for CRL/chain consumers.
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = spec
        .key_usages
        .iter()
        .copied()
        .map(key_usage_to_rcgen)
        .collect();
    params.extended_key_usages = spec.ekus.iter().copied().map(eku_to_rcgen).collect();
    params.subject_alt_names = spec
        .sans
        .iter()
        .map(|san| match san {
            SanEntry::Dns(d) => Ok(SanType::DnsName(d.as_str().try_into()?)),
            SanEntry::Ip(ip) => Ok(SanType::IpAddress(*ip)),
            SanEntry::Email(e) => Ok(SanType::Rfc822Name(e.as_str().try_into()?)),
        })
        .collect::<Result<Vec<_>, rcgen::Error>>()?;

    let cert = params.signed_by(&public_key, &issuer)?;
    Ok(IssuedLeaf {
        cert_pem: cert.pem(),
        serial: spec.serial,
        not_before: chrono_datetime(not_before)?,
        not_after: chrono_datetime(not_after)?,
    })
}

/// Enforce the supported-algorithm gate: name level via
/// [`supported_key_alg`], plus RSA's >= 2048-bit floor read from the
/// parsed SPKI modulus. Everything else is a typed
/// [`CaError::UnsupportedKeyType`] naming the offending algorithm.
///
/// Returns the parsed RSA modulus size in bits when the key is RSA
/// (`None` otherwise), for the caller's profile key-type pin check.
fn gate_supported_key(
    alg: &str,
    spki: &SubjectPublicKeyInfo<'_>,
) -> Result<Option<usize>, CaError> {
    if !supported_key_alg(alg) {
        return Err(CaError::UnsupportedKeyType(format!(
            "CSR key algorithm {alg} is not supported \
             (supported: Ed25519, ECDSA P-256, ECDSA P-384, RSA >= 2048 bits)"
        )));
    }
    if alg != "RSA" {
        return Ok(None);
    }
    // x509-parser's RSAPublicKey::key_size() strips only a leading
    // zero byte, and a DER INTEGER prepends that sign octet exactly
    // when the modulus' MSB is set. A 2048-bit modulus has its MSB
    // set by definition, so it always reports exactly 2048. The
    // undercount only appears on a modulus of 2041-2047 bits, whose
    // MSB is clear and which therefore carries NO sign octet: it
    // reports 8 * 255 = 2040 and is over-rejected here. The check may
    // over-reject but never over-accept, and stays that way on
    // purpose; do not "fix" it into a permissive check.
    let bits = match spki.parsed() {
        Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => rsa.key_size(),
        // A SPKI the RSA parser cannot crack cannot be signed for.
        _ => 0,
    };
    if bits < 2048 {
        return Err(CaError::UnsupportedKeyType(format!(
            "CSR RSA key is {bits} bits; the minimum supported RSA key size is 2048 bits"
        )));
    }
    Ok(Some(bits))
}

/// Leaf validity window as rcgen [`OffsetDateTime`]s: `not_before` is
/// midnight UTC one day before today (the clock-skew margin, computed
/// here — the caller can never observe it, which is why the spec carries
/// a span), and `not_after` is exactly `not_before + lifetime`: the span
/// the profile asked for, to the second.
///
/// The positive-lifetime precondition is [`sign_leaf_with`]'s (it
/// rejects a non-positive span before calling this).
fn validity_window(
    lifetime: &chrono::Duration,
) -> Result<(OffsetDateTime, OffsetDateTime), CaError> {
    let nb_date = (chrono::Utc::now() - chrono::Duration::days(1)).date_naive();
    let nb_secs = nb_date
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| CaError::X509("invalid not_before midnight".to_owned()))?
        .and_utc()
        .timestamp();
    let na_secs = nb_secs
        .checked_add(lifetime.num_seconds())
        .ok_or_else(|| CaError::X509("certificate validity window is out of range".to_owned()))?;
    let nb = unix_secs_to_offset(nb_secs)?;
    let na = unix_secs_to_offset(na_secs)?;
    Ok((nb, na))
}

/// Whole Unix seconds to rcgen's [`OffsetDateTime`] (rcgen strips
/// sub-seconds when encoding, so callers' equality checks hold).
fn unix_secs_to_offset(secs: i64) -> Result<OffsetDateTime, CaError> {
    OffsetDateTime::from_unix_timestamp(secs)
        .map_err(|e| CaError::X509(format!("certificate validity instant out of range: {e}")))
}

/// rcgen [`OffsetDateTime`] back to a UTC chrono instant for the
/// [`IssuedLeaf`] fields (whole seconds both ways).
fn chrono_datetime(dt: OffsetDateTime) -> Result<chrono::DateTime<chrono::Utc>, CaError> {
    let secs = dt.unix_timestamp();
    chrono::DateTime::from_timestamp(secs, 0)
        .ok_or_else(|| CaError::X509("certificate validity instant out of range".to_owned()))
}
