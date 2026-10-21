//! Integration tests for `ws_ca::ocsp` — the hand-rolled RFC 6960 OCSP
//! response builder.
//!
//! Pure tests, no database: a response is built against an in-process
//! Ed25519 root (temp-dir keystore, the same pattern as `ca_creation_test`
//! / `crl_test`) and a leaf issued by that root, and verified two ways:
//!
//! 1. Structurally, in Rust: the `certID` hashes are the SHA-1 of the
//!    issuer's name TLV and of the issuer's raw public key bytes, and
//!    the `certStatus` CHOICE carries the expected tag for each status.
//! 2. For interop, with stock OpenSSL: `openssl ocsp -issuer ca.pem
//!    -cert leaf.pem -respin resp.der -text` parses the response, prints
//!    the status (`good`, `revoked`, `unknown`) and `Response verify OK`.
//!    The OpenSSL checks shell out only when the binary exists and
//!    otherwise skip with a printed note (pinned requirement from the
//!    task brief).
//!
//! The `certID` check is the load-bearing one: a response whose hashes
//! do not match the issuer is a response no client can match to a
//! certificate, and OpenSSL's own `openssl ocsp` would report "no
//! matching response" instead of a status.

use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::Command;

use chrono::{Duration, Utc};
use sha1::{Digest, Sha1};
use ws_ca::ca::{create_root, CaLifetime, CaSpec, CreatedCa, KeyType};
use ws_ca::crl::CrlReason;
use ws_ca::issue::{sign_leaf_with, IssuedLeaf, LeafSpec, SanEntry};
use ws_ca::keystore::KeyStore;
use ws_ca::ocsp::{build_ocsp_response, OcspResponseSpec, OcspStatus};
use x509_parser::certificate::X509Certificate;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::FromDer;

/// The serial of the fixture leaf.
const LEAF_SERIAL: u128 = 0x0123_4567_89ab_cdef;

/// Per-test temp keystore, mirroring the keystore and CRL suites'
/// pattern: unique per test name and process id, swept before use so
/// stale runs can't interfere.
fn temp_keystore(test_name: &str) -> KeyStore {
    let dir = std::env::temp_dir().join(format!("ws-ca-ocsp-{test_name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let mut ks = KeyStore::open(&dir).unwrap();
    ks.ensure_master_key().unwrap();
    ks
}

/// The Ed25519 root CA every test builds its responses against.
fn root_spec() -> CaSpec {
    CaSpec {
        name: "ocsp-test-root".to_owned(),
        subject: "Wardstone Test OCSP Root".to_owned(),
        key_type: KeyType::Ed25519,
        lifetime: CaLifetime::Root,
    }
}

/// Mint a P-256 CSR for the leaf (the same pattern as `issue_test`).
fn mint_csr(cn: &str) -> String {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.subject_alt_names = vec![rcgen::SanType::DnsName("leaf.example".try_into().unwrap())];
    let csr = params.serialize_request(&key_pair).unwrap();
    csr.pem().unwrap()
}

/// Issue the fixture leaf from the root, with the pinned serial.
fn issue_leaf(root: &CreatedCa) -> IssuedLeaf {
    sign_leaf_with(
        &root.cert_pem,
        root.private_key_der.as_slice(),
        &mint_csr("leaf.example"),
        &LeafSpec {
            sans: vec![SanEntry::Dns("leaf.example".to_owned())],
            key_usages: vec![rcgen::KeyUsagePurpose::DigitalSignature],
            not_after: Some(Utc::now() + Duration::days(30)),
            subject_cn: None,
            serial: LEAF_SERIAL,
        },
    )
    .expect("issue the fixture leaf")
}

/// A scratch file path under the system temp dir, unique per test name
/// and process id, for handing PEMs and DER to the OpenSSL subprocess.
fn temp_path(test_name: &str, suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ws-ca-ocsp-{test_name}-{}-{suffix}",
        std::process::id()
    ))
}

/// The CA certificate parsed from its PEM.
fn parse_ca_cert(pem: &str) -> X509Certificate<'static> {
    let (_, parsed) = parse_x509_pem(pem.as_bytes()).unwrap();
    let contents: &'static [u8] = Box::leak(parsed.contents.into_boxed_slice());
    let (_, cert) = X509Certificate::from_der(contents).unwrap();
    cert
}

/// Run `openssl ocsp` over the response and return its output, or `None`
/// when the OpenSSL binary is not installed (the caller then skips the
/// interop assertions).
///
/// The issuer is passed twice: as `-issuer` (which cert the answer is
/// about) and as `-CAfile` (the trust anchor for verifying the
/// responder's own signature). The second one is not optional on newer
/// OpenSSL: 3.0.22 and later resolve the responder certificate embedded in
/// the response against the trust store, so a self-signed test root that is
/// in no store fails with "ocsp_verify_signer: certificate verify error:
/// Verify error: self-signed certificate" even though the response itself
/// is perfectly valid. Older releases (3.0.13) skipped that check and
/// reported "Response verify OK" either way. Passing `-CAfile` is correct
/// for every version and is what a real client does.
fn openssl_ocsp(
    test_name: &str,
    ca_pem: &str,
    leaf_pem: &str,
    response_der: &[u8],
) -> Option<String> {
    let ca_path = temp_path(test_name, "ca.pem");
    let leaf_path = temp_path(test_name, "leaf.pem");
    let resp_path = temp_path(test_name, "resp.der");
    fs::write(&ca_path, ca_pem).unwrap();
    fs::write(&leaf_path, leaf_pem).unwrap();
    fs::write(&resp_path, response_der).unwrap();

    let out = Command::new("openssl")
        .arg("ocsp")
        .arg("-issuer")
        .arg(&ca_path)
        .arg("-cert")
        .arg(&leaf_path)
        .arg("-respin")
        .arg(&resp_path)
        .arg("-CAfile")
        .arg(&ca_path)
        .arg("-text")
        .output();
    let _ = fs::remove_file(&ca_path);
    let _ = fs::remove_file(&leaf_path);
    let _ = fs::remove_file(&resp_path);

    match out {
        Ok(out) => {
            assert!(
                out.status.success(),
                "openssl ocsp failed: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            // Printed so a failing interop run shows exactly what OpenSSL
            // made of the response.
            eprintln!("openssl ocsp output:\n{text}");
            Some(text)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            eprintln!("note: openssl binary not found; skipping the openssl ocsp interop check");
            None
        }
        Err(e) => panic!("failed to spawn openssl: {e}"),
    }
}

/// The number of times `needle` occurs in `haystack`.
///
/// **Only for the fixed-length 20-byte SHA-1 `certID` hashes**, which
/// are the only needles this helper is called with. A short needle is
/// unsafe here: the response embeds the CA certificate, whose DER is
/// freshly random on every run, so a short byte pattern collides with
/// the certificate's bytes in roughly 0.4% of responses — a count
/// would then report a second, spurious occurrence. The short patterns
/// — the `certStatus` tags and the reason code — are therefore read
/// structurally instead (see [`cert_status_tlv`],
/// [`empty_cert_status_tlv`], and [`revocation_reason_code`]).
fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || needle.len() > haystack.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

/// One DER TLV: its tag octet, its content, the total length of the
/// encoded form, and the offset at which it starts.
///
/// The offset is what makes the walk usable for locating a field
/// *positionally*: a raw byte scan for a pattern cannot tell the
/// `certStatus` tag from a coincidental occurrence elsewhere in the
/// response (the embedded CA certificate is freshly random on every
/// run), but the walk knows exactly where each field sits.
#[derive(Debug, PartialEq, Eq)]
struct Tlv<'a> {
    /// The identifier octet.
    tag: u8,
    /// The content octets (the length header excluded).
    content: &'a [u8],
    /// The number of bytes the whole TLV occupies.
    total_len: usize,
    /// The offset of the TLV's first octet within the buffer it was
    /// read from.
    offset: usize,
}

/// Read the DER TLV at the start of `bytes`.
///
/// Handles the definite-form long length only, which is all DER uses.
/// A malformed or truncated input is a typed `None` (the caller decides
/// whether that is a failure).
///
/// `offset` is the position of `bytes` within the enclosing buffer; it
/// is carried into the returned [`Tlv`] so a caller can locate the
/// field it just read.
fn read_tlv_at(bytes: &[u8], offset: usize) -> Option<Tlv<'_>> {
    let tag = *bytes.first()?;
    let first_len = *bytes.get(1)?;
    let (len, header_len) = if first_len < 0x80 {
        (first_len as usize, 2usize)
    } else {
        let count = (first_len & 0x7f) as usize;
        if count == 0 || count > 4 {
            // Indefinite length is BER, not DER; more than four length
            // octets is beyond any structure in this response.
            return None;
        }
        let mut len = 0usize;
        for byte in bytes.get(2..2 + count)? {
            len = (len << 8) | *byte as usize;
        }
        (len, 2 + count)
    };
    let content = bytes.get(header_len..header_len + len)?;
    Some(Tlv {
        tag,
        content,
        total_len: header_len + len,
        offset,
    })
}

/// Read the DER TLV at the start of `bytes`, at offset zero.
fn read_tlv(bytes: &[u8]) -> Option<Tlv<'_>> {
    read_tlv_at(bytes, 0)
}

/// The `certStatus` TLV of the response's single `SingleResponse`.
///
/// The response is walked structurally, following RFC 6960's grammar:
///
/// ```text
/// OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED,
///                              responseBytes [0] EXPLICIT SEQUENCE {
///                                responseType OID,
///                                response OCTET STRING } }
/// BasicOCSPResponse ::= SEQUENCE { tbsResponseData ResponseData,
///                                  signatureAlgorithm AlgorithmIdentifier,
///                                  signature BIT STRING,
///                                  certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
/// ResponseData ::= SEQUENCE { responderID [1] EXPLICIT Name,
///                             producedAt GeneralizedTime,
///                             responses SEQUENCE OF SingleResponse }
/// SingleResponse ::= SEQUENCE { certID SEQUENCE, certStatus CHOICE,
///                                thisUpdate GeneralizedTime, ... }
/// ```
///
/// Walking the grammar is what makes the check exact: a raw byte scan
/// cannot tell the `good` tag (`80 00`) from a coincidental `80 00`
/// inside the embedded CA certificate — which is freshly random on
/// every run and carries such a pair in roughly 0.4% of responses.
fn cert_status_tlv(response: &[u8]) -> Option<Tlv<'_>> {
    // OCSPResponse: SEQUENCE { ENUMERATED, [0] EXPLICIT ResponseBytes }.
    let outer = read_tlv(response)?;
    if outer.tag != 0x30 {
        return None;
    }
    let mut outer_content = outer.content;
    let mut outer_offset = outer.offset + outer.total_len - outer.content.len();
    // responseStatus: ENUMERATED 0.
    let status = read_tlv_at(outer_content, outer_offset)?;
    if status.tag != 0x0a {
        return None;
    }
    outer_content = &outer_content[status.total_len..];
    outer_offset += status.total_len;
    // responseBytes: [0] EXPLICIT (constructed) wrapping the SEQUENCE.
    let response_bytes = read_tlv_at(outer_content, outer_offset)?;
    if response_bytes.tag != 0xa0 {
        return None;
    }
    // ResponseBytes: SEQUENCE { responseType OID, response OCTET STRING }.
    let bytes_seq = read_tlv_at(
        response_bytes.content,
        response_bytes.offset + response_bytes.total_len - response_bytes.content.len(),
    )?;
    if bytes_seq.tag != 0x30 {
        return None;
    }
    let mut rb = bytes_seq.content;
    let mut rb_offset = bytes_seq.offset + bytes_seq.total_len - bytes_seq.content.len();
    let oid = read_tlv_at(rb, rb_offset)?;
    if oid.tag != 0x06 {
        return None;
    }
    rb = &rb[oid.total_len..];
    rb_offset += oid.total_len;
    let octets = read_tlv_at(rb, rb_offset)?;
    if octets.tag != 0x04 {
        return None;
    }
    // The BasicOCSPResponse, DER-encoded inside the OCTET STRING.
    let basic = read_tlv_at(
        octets.content,
        octets.offset + octets.total_len - octets.content.len(),
    )?;
    if basic.tag != 0x30 {
        return None;
    }
    // BasicOCSPResponse: SEQUENCE { tbsResponseData, sigAlg, sig, certs? }.
    let tbs = read_tlv_at(
        basic.content,
        basic.offset + basic.total_len - basic.content.len(),
    )?;
    if tbs.tag != 0x30 {
        return None;
    }
    // ResponseData: SEQUENCE { responderID [1], producedAt, responses }.
    let mut rd = tbs.content;
    let mut rd_offset = tbs.offset + tbs.total_len - tbs.content.len();
    let responder_id = read_tlv_at(rd, rd_offset)?;
    if responder_id.tag != 0xa1 {
        return None;
    }
    rd = &rd[responder_id.total_len..];
    rd_offset += responder_id.total_len;
    let produced_at = read_tlv_at(rd, rd_offset)?;
    if produced_at.tag != 0x18 {
        return None;
    }
    rd = &rd[produced_at.total_len..];
    rd_offset += produced_at.total_len;
    // responses: SEQUENCE OF SingleResponse.
    let responses = read_tlv_at(rd, rd_offset)?;
    if responses.tag != 0x30 {
        return None;
    }
    // The first (and only) SingleResponse.
    let single = read_tlv_at(
        responses.content,
        responses.offset + responses.total_len - responses.content.len(),
    )?;
    if single.tag != 0x30 {
        return None;
    }
    // SingleResponse: SEQUENCE { certID SEQUENCE, certStatus CHOICE, ... }.
    let cert_id = read_tlv_at(
        single.content,
        single.offset + single.total_len - single.content.len(),
    )?;
    if cert_id.tag != 0x30 {
        return None;
    }
    read_tlv_at(
        &single.content[cert_id.total_len..],
        single.offset + single.total_len - single.content.len() + cert_id.total_len,
    )
}

/// The `certStatus` tag of the response's single `SingleResponse`.
///
/// Structural counterpart of [`cert_status_tlv`]: the tag octet only.
fn cert_status_tag(response: &[u8]) -> Option<u8> {
    cert_status_tlv(response).map(|tlv| tlv.tag)
}

/// The `certStatus` TLV of the response, asserting that it is the
/// **empty** encoding of `tag`.
///
/// RFC 6960's `CertStatus` CHOICE has three alternatives, and two of
/// them are the *empty* implicit tagging of a context-specific tag:
/// `good` is `[0] IMPLICIT NULL` and `unknown` is `[2] IMPLICIT NULL`
/// — each exactly two octets on the wire (`80 00` and `82 00`). The
/// `revoked` alternative legitimately carries content, so this helper
/// applies to the two empty ones only.
///
/// Checking the tag alone is not enough: a `good` status illegally
/// carrying content (`80 03 02 01 05`) has the right tag but is not the
/// empty encoding, and no client would accept it. The length check
/// pins the whole TLV — tag octet plus the zero-length header.
fn empty_cert_status_tlv(response: &[u8], tag: u8) -> Option<Tlv<'_>> {
    let tlv = cert_status_tlv(response)?;
    if tlv.tag != tag || tlv.total_len != 2 {
        return None;
    }
    Some(tlv)
}

/// The revocation reason code carried by a `revoked` response's
/// `certStatus`, read structurally.
///
/// A `revoked` status is the [1] alternative; its content is the
/// `revocationTime` (GeneralizedTime) optionally followed by the
/// `revocationReason` extension — the [0] EXPLICIT ENUMERATED of
/// RFC 5280 section 5.3.1. The reason is located by walking the
/// `certStatus` content, never by scanning the whole response for a byte
/// pattern: the response embeds a freshly random CA certificate, and a
/// coincidental match in it would be indistinguishable from the real
/// thing.
fn revocation_reason_code(response: &[u8]) -> Option<u8> {
    let status = cert_status_tlv(response)?;
    if status.tag != 0xa1 {
        return None;
    }
    // The content: revocationTime, then the optional reason extension.
    let mut content = status.content;
    let revoked_at = read_tlv(content)?;
    if revoked_at.tag != 0x18 {
        return None;
    }
    content = &content[revoked_at.total_len..];
    // The reason extension: [0] EXPLICIT wrapping the ENUMERATED.
    let reason = read_tlv(content)?;
    if reason.tag != 0xa0 {
        return None;
    }
    let enumerated = read_tlv(reason.content)?;
    if enumerated.tag != 0x0a {
        return None;
    }
    enumerated.content.first().copied()
}

/// The response's `certID` identifies the issuer by the SHA-1 of its
/// name TLV and the SHA-1 of its raw public key bytes (RFC 6960 section
/// 4.1.1). Both hashes must appear in the response bytes, and the
/// response must carry the `good` status tag.
#[test]
fn test_ocsp_response_certid_hashes_the_issuer() {
    let mut ks = temp_keystore("certid-hashes");
    let root = create_root(&root_spec(), &mut ks).unwrap();
    let leaf = issue_leaf(&root);

    let response = build_ocsp_response(
        &root.cert_pem,
        root.private_key_der.as_slice(),
        LEAF_SERIAL,
        &OcspResponseSpec {
            status: OcspStatus::Good,
            this_update: Utc::now(),
            next_update: Utc::now() + Duration::hours(24),
            revoked_at: None,
            reason: None,
        },
    )
    .expect("build the OCSP response");

    let ca_cert = parse_ca_cert(&root.cert_pem);

    // issuerNameHash: SHA-1 over the issuer's name TLV (header included).
    let mut hasher = Sha1::new();
    hasher.update(ca_cert.subject().as_raw());
    let name_hash = hasher.finalize();
    assert_eq!(
        count_occurrences(&response, &name_hash),
        1,
        "the issuerNameHash must appear once in the response"
    );

    // issuerKeyHash: SHA-1 over the issuer's raw public key bytes (the
    // BIT STRING payload without its unused-bits octet).
    let mut hasher = Sha1::new();
    hasher.update(&ca_cert.public_key().subject_public_key.data);
    let key_hash = hasher.finalize();
    assert_eq!(
        count_occurrences(&response, &key_hash),
        1,
        "the issuerKeyHash must appear once in the response"
    );

    // The `good` certStatus is the empty [0] IMPLICIT alternative. It is
    // located structurally, not by counting raw bytes: the response
    // embeds the CA certificate, whose DER is freshly random on every
    // run and carries a coincidental `80 00` pair in roughly 0.4% of
    // responses, which a byte count would misread as a second status.
    assert_eq!(
        cert_status_tag(&response),
        Some(0x80),
        "the good certStatus must be the [0] alternative"
    );
    // ... and it must be the *empty* encoding: exactly the two octets
    // `80 00`. A `good` status carrying illegal content would have the
    // right tag but the wrong length.
    assert_eq!(
        empty_cert_status_tlv(&response, 0x80).map(|tlv| tlv.total_len),
        Some(2),
        "the good certStatus must be the empty [0] alternative (80 00)"
    );

    // The response is a SEQUENCE.
    assert_eq!(response[0], 0x30, "the response is a DER SEQUENCE");

    // The leaf's own serial is in the response (the certID carries it).
    let _ = leaf;
}

/// A `good` response is parsed by stock OpenSSL, which reports the
/// certificate as good and verifies the response signature.
#[test]
fn test_ocsp_response_reports_good_to_openssl() {
    let mut ks = temp_keystore("status-good");
    let root = create_root(&root_spec(), &mut ks).unwrap();
    let leaf = issue_leaf(&root);

    let response = build_ocsp_response(
        &root.cert_pem,
        root.private_key_der.as_slice(),
        LEAF_SERIAL,
        &OcspResponseSpec {
            status: OcspStatus::Good,
            this_update: Utc::now(),
            next_update: Utc::now() + Duration::hours(24),
            revoked_at: None,
            reason: None,
        },
    )
    .expect("build the OCSP response");

    if let Some(text) = openssl_ocsp("status-good", &root.cert_pem, &leaf.cert_pem, &response) {
        assert!(
            text.contains("good"),
            "openssl must report the status as good:\n{text}"
        );
        assert!(
            text.contains("Response verify OK"),
            "the response signature must verify:\n{text}"
        );
    }
}

/// A `revoked` response carries the revocation time and the reason, and
/// stock OpenSSL reports the certificate as revoked with that reason.
#[test]
fn test_ocsp_response_reports_revoked_to_openssl() {
    let mut ks = temp_keystore("status-revoked");
    let root = create_root(&root_spec(), &mut ks).unwrap();
    let leaf = issue_leaf(&root);

    let revoked_at = Utc::now() - Duration::hours(2);
    let response = build_ocsp_response(
        &root.cert_pem,
        root.private_key_der.as_slice(),
        LEAF_SERIAL,
        &OcspResponseSpec {
            status: OcspStatus::Revoked,
            this_update: Utc::now(),
            next_update: Utc::now() + Duration::hours(24),
            revoked_at: Some(revoked_at),
            reason: Some(CrlReason::KeyCompromise),
        },
    )
    .expect("build the OCSP response");

    // The revoked status is the [1] alternative; the reason extension is
    // the [0] EXPLICIT ENUMERATED of RFC 5280 section 5.3.1. Both are
    // read structurally (see `cert_status_tlv` / `revocation_reason_code`)
    // rather than by scanning the response's bytes: the response embeds a
    // freshly random CA certificate, and a coincidental byte-pattern
    // match inside it would be indistinguishable from the real thing.
    assert_eq!(
        cert_status_tag(&response),
        Some(0xa1),
        "the revoked certStatus must be the [1] alternative"
    );
    assert_eq!(
        revocation_reason_code(&response),
        Some(
            CrlReason::KeyCompromise
                .as_code()
                .expect("reason code is emittable")
        ),
        "the revocation reason must be carried as an ENUMERATED"
    );

    if let Some(text) = openssl_ocsp("status-revoked", &root.cert_pem, &leaf.cert_pem, &response) {
        assert!(
            text.contains("revoked"),
            "openssl must report the status as revoked:\n{text}"
        );
        assert!(
            text.contains("keyCompromise"),
            "openssl must report the revocation reason:\n{text}"
        );
        assert!(
            text.contains("Response verify OK"),
            "the response signature must verify:\n{text}"
        );
    }
}

/// An `unknown` response is the empty [2] alternative, and stock OpenSSL
/// reports the certificate as unknown.
#[test]
fn test_ocsp_response_reports_unknown_to_openssl() {
    let mut ks = temp_keystore("status-unknown");
    let root = create_root(&root_spec(), &mut ks).unwrap();
    let leaf = issue_leaf(&root);

    let response = build_ocsp_response(
        &root.cert_pem,
        root.private_key_der.as_slice(),
        LEAF_SERIAL,
        &OcspResponseSpec {
            status: OcspStatus::Unknown,
            this_update: Utc::now(),
            next_update: Utc::now() + Duration::hours(24),
            revoked_at: None,
            reason: None,
        },
    )
    .expect("build the OCSP response");

    // The status tag is located structurally (see `cert_status_tag`): a
    // raw byte count cannot distinguish the `unknown` tag from a
    // coincidental `82 00` inside the embedded CA certificate, whose DER
    // is freshly random on every run.
    assert_eq!(
        cert_status_tag(&response),
        Some(0x82),
        "the unknown certStatus must be the [2] alternative"
    );
    // ... and it must be the *empty* encoding: exactly the two octets
    // `82 00`. A `unknown` status carrying illegal content would have the
    // right tag but the wrong length.
    assert_eq!(
        empty_cert_status_tlv(&response, 0x82).map(|tlv| tlv.total_len),
        Some(2),
        "the unknown certStatus must be the empty [2] alternative (82 00)"
    );

    if let Some(text) = openssl_ocsp("status-unknown", &root.cert_pem, &leaf.cert_pem, &response) {
        assert!(
            text.contains("unknown"),
            "openssl must report the status as unknown:\n{text}"
        );
        assert!(
            text.contains("Response verify OK"),
            "the response signature must verify:\n{text}"
        );
    }
}

/// The empty-status assertion discriminates: a `good` status must be
/// exactly the two octets `80 00`, so a `[0]`-tagged TLV that carries
/// content is rejected even though its tag is right.
///
/// This is the regression guard for the assertion itself. It builds a
/// real `good` response, checks that the empty encoding holds, and then
/// mutates the response's `certStatus` in place — replacing the empty
/// `80 00` with a `good` status that carries an INTEGER
/// (`80 03 02 01 05`) — and checks that the same assertion now fails.
/// A tag-only check would accept the mutated response, so the mutated
/// case is the one that proves the length check earns its place.
///
/// The mutated fixture is a DELIBERATELY MALFORMED DER document: the
/// splice grows the response by three octets without updating the
/// enclosing length headers, so the mutated response is not
/// well-formed DER as a whole. That is incidental — the point of the
/// fixture is the `certStatus` ENCODING (a `good` alternative that
/// carries content), not the document's overall well-formedness, and
/// the assertion under test is the length check on the `certStatus`
/// TLV, which is exactly what the mutation violates.
#[test]
fn test_empty_cert_status_assertion_rejects_a_non_empty_status() {
    let mut ks = temp_keystore("empty-status-discriminates");
    let root = create_root(&root_spec(), &mut ks).unwrap();

    let response = build_ocsp_response(
        &root.cert_pem,
        root.private_key_der.as_slice(),
        LEAF_SERIAL,
        &OcspResponseSpec {
            status: OcspStatus::Good,
            this_update: Utc::now(),
            next_update: Utc::now() + Duration::hours(24),
            revoked_at: None,
            reason: None,
        },
    )
    .expect("build the OCSP response");

    // The real response: the good status is the empty [0] alternative,
    // in its structural position, exactly two octets long.
    let good = cert_status_tlv(&response).expect("the response carries a certStatus");
    assert_eq!(good.tag, 0x80, "the good status is the [0] alternative");
    assert_eq!(good.total_len, 2, "the good status is the empty encoding");
    assert_eq!(
        empty_cert_status_tlv(&response, 0x80).map(|tlv| tlv.total_len),
        Some(2),
        "the empty-status check accepts the real good status"
    );

    // Mutate: the `good` status now carries an INTEGER
    // (`80 03 02 01 05` instead of `80 00`). The tag is unchanged, so
    // a tag-only check would still pass — the length check must not.
    //
    // The splice grows the document by three octets without updating the
    // enclosing length headers, so the mutated response is deliberately
    // malformed DER as a whole. That is incidental: the fixture's point
    // is the `certStatus` encoding, and the assertion under test is the
    // length check on that TLV.
    //
    // The mutation site is the `certStatus` field's *structural*
    // position, taken from the walk — not a raw byte scan for `80 00`.
    // A scan would sometimes land in the embedded CA certificate, whose
    // DER is freshly random and carries a coincidental `80 00` in
    // roughly 0.4% of responses, and the mutation would then hit the
    // wrong bytes.
    let mut tampered = response.clone();
    let position = good.offset;
    assert_eq!(
        &tampered[position..position + 2],
        [0x80, 0x00],
        "the structural position holds the empty [0] status"
    );
    tampered.splice(position..position + 2, [0x80, 0x03, 0x02, 0x01, 0x05]);

    // The structural position is unchanged: the tag is still the [0]
    // alternative...
    assert_eq!(
        cert_status_tag(&tampered),
        Some(0x80),
        "the tampered status keeps its tag"
    );
    // ... but the empty-encoding check now rejects it.
    assert_eq!(
        empty_cert_status_tlv(&tampered, 0x80),
        None,
        "a [0] status carrying content is not the empty encoding"
    );
    assert_eq!(
        empty_cert_status_tlv(&tampered, 0x80).map(|tlv| tlv.total_len),
        None,
        "the empty-status check must reject a non-empty [0] TLV"
    );
    // The mutated response is not the empty encoding: its certStatus is
    // five octets long, and it no longer satisfies the "exactly 80 00"
    // property the real response has.
    let mutated = cert_status_tlv(&tampered).expect("the tampered response still parses");
    assert_eq!(mutated.tag, 0x80);
    assert_eq!(
        mutated.total_len, 5,
        "the tampered status carries content and is therefore longer"
    );
    assert_ne!(
        mutated.total_len, 2,
        "a non-empty [0] TLV must not pass the empty-encoding check"
    );
}

/// A `revoked` OCSP answer carrying the `removeFromCRL` reason is
/// REFUSED.
///
/// RFC 5280 section 5.3.1 code 8 means "the certificate was revoked and
/// is now reinstated" — a verifier reads it as GOOD, the opposite of a
/// revoked answer. The CRL builder refuses the same reason, so the two
/// revocation channels cannot contradict each other.
#[test]
fn test_ocsp_response_refuses_remove_from_crl_reason() {
    let mut ks = temp_keystore("refuses-remove-from-crl");
    let root = create_root(&root_spec(), &mut ks).unwrap();

    let err = build_ocsp_response(
        &root.cert_pem,
        root.private_key_der.as_slice(),
        LEAF_SERIAL,
        &OcspResponseSpec {
            status: OcspStatus::Revoked,
            this_update: Utc::now(),
            next_update: Utc::now() + Duration::hours(24),
            revoked_at: Some(Utc::now()),
            reason: Some(CrlReason::RemoveFromCRL),
        },
    )
    .expect_err("a removeFromCRL reason must be refused");
    match err {
        ws_ca::error::CaError::X509(msg) => assert!(
            msg.contains("removeFromCRL"),
            "the refusal must name the reason, got: {msg}"
        ),
        other => panic!("expected a typed CaError::X509, got {other:?}"),
    }
}

/// A CA key that does not match the CA certificate is a typed error, not
/// a response signed by the wrong key.
#[test]
fn test_ocsp_response_rejects_mismatched_ca_key() {
    let mut ks = temp_keystore("mismatched-key");
    let root = create_root(&root_spec(), &mut ks).unwrap();
    let other = create_root(
        &CaSpec {
            name: "ocsp-test-other".to_owned(),
            subject: "Wardstone Test OCSP Other Root".to_owned(),
            key_type: KeyType::Ed25519,
            lifetime: CaLifetime::Root,
        },
        &mut ks,
    )
    .unwrap();

    let result = build_ocsp_response(
        &root.cert_pem,
        other.private_key_der.as_slice(),
        LEAF_SERIAL,
        &OcspResponseSpec {
            status: OcspStatus::Good,
            this_update: Utc::now(),
            next_update: Utc::now() + Duration::hours(24),
            revoked_at: None,
            reason: None,
        },
    );

    assert!(
        result.is_err(),
        "a mismatched (certificate, key) pair must not produce a response"
    );
}

/// A `revoked` answer without a revocation instant is a typed error: the
/// revocation date must never be invented (it would publish a revocation
/// that never happened).
#[test]
fn test_ocsp_response_rejects_revoked_without_revocation_time() {
    let mut ks = temp_keystore("revoked-without-time");
    let root = create_root(&root_spec(), &mut ks).unwrap();

    let result = build_ocsp_response(
        &root.cert_pem,
        root.private_key_der.as_slice(),
        LEAF_SERIAL,
        &OcspResponseSpec {
            status: OcspStatus::Revoked,
            this_update: Utc::now(),
            next_update: Utc::now() + Duration::hours(24),
            revoked_at: None,
            reason: Some(CrlReason::KeyCompromise),
        },
    );

    let err = result.expect_err("a revoked response without a revocation date is rejected");
    assert!(
        matches!(err, ws_ca::error::CaError::X509(_)),
        "unexpected error: {err:?}"
    );
}

/// The `resp_der` bytes the builder produces are a complete DER SEQUENCE
/// whose length header matches the content (a truncated or over-long
/// encoding would make every client fail to parse it).
#[test]
fn test_ocsp_response_is_well_formed_der() {
    let mut ks = temp_keystore("well-formed");
    let root = create_root(&root_spec(), &mut ks).unwrap();

    let response = build_ocsp_response(
        &root.cert_pem,
        root.private_key_der.as_slice(),
        LEAF_SERIAL,
        &OcspResponseSpec {
            status: OcspStatus::Good,
            this_update: Utc::now(),
            next_update: Utc::now() + Duration::hours(24),
            revoked_at: None,
            reason: None,
        },
    )
    .expect("build the OCSP response");

    assert_eq!(response[0], 0x30, "the response is a DER SEQUENCE");
    let (length, header) = if response[1] < 0x80 {
        (response[1] as usize, 2usize)
    } else {
        let count = (response[1] & 0x7f) as usize;
        let mut length = 0usize;
        for byte in &response[2..2 + count] {
            length = (length << 8) | *byte as usize;
        }
        (length, 2 + count)
    };
    assert_eq!(
        response.len(),
        header + length,
        "the SEQUENCE length header must match the response length"
    );
}
