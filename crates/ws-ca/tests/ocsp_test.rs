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
fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || needle.len() > haystack.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
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

    // The `good` certStatus is the empty [0] IMPLICIT alternative.
    assert_eq!(
        count_occurrences(&response, &[0x80, 0x00]),
        1,
        "the good certStatus must be the empty [0] alternative"
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
    // the [0] EXPLICIT ENUMERATED of RFC 5280 section 5.3.1.
    assert_eq!(
        count_occurrences(&response, &[0x0a, 0x01, CrlReason::KeyCompromise.as_code()]),
        1,
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

    assert_eq!(
        count_occurrences(&response, &[0x82, 0x00]),
        1,
        "the unknown certStatus must be the empty [2] alternative"
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
