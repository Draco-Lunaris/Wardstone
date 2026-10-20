//! Integration tests for `ws_ca::issue` — leaf issuance from a CSR.
//!
//! Pure tests, no database: signing works against a temp-dir keystore and
//! an Ed25519 root created in-process (DB persistence of issued leaves is
//! Plan 2). Each test parses the issued certificate with x509-parser and
//! asserts the pinned issuance contract: verified CSR self-signature, the
//! CSR's own public key in the leaf, SAN/KU propagation, caller-supplied
//! serial roundtrip, and typed rejection of unsupported key algorithms.
//!
//! The bundled openssl fixtures are real, self-signature-verifying CSRs
//! (verified with `openssl req -verify` at generation time): P-521 and
//! Ed448 exercise whole unsupported algorithms, RSA-1024 the key-size
//! floor, and RSA-2048 a second encoder's interop with SANs.

use std::fs;
use std::net::IpAddr;

use chrono::SubsecRound;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::FromDer;

use ws_ca::ca::{create_root, CaLifetime, CaSpec, KeyType};
use ws_ca::error::CaError;
use ws_ca::issue::{supported_key_alg, validate_csr, LeafSpec, SanEntry};
use ws_ca::keystore::KeyStore;

/// A structurally valid CSR minted by OpenSSL with an unsupported key
/// algorithm (ECDSA P-521). Its self-signature verifies (proof of
/// possession, checked at fixture-generation time), so the rejection must
/// come from the supported-algorithm gate and be typed, never a panic.
const P521_CSR_PEM: &str = "\
-----BEGIN CERTIFICATE REQUEST-----
MIIBZDCByAIBADAjMSEwHwYDVQQDDBh1bnN1cHBvcnRlZC1wNTIxLmV4YW1wbGUw
gZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAAdk+fcXzQvU1wCVF7Gb+uiWtQkAmtD
9Q7Q6Fz3ozycwdwYItPjYc4i0Wn8P9dDOj/66kwjeYkzyB+vCVk7iJojewEg+5DP
+Lg28bYZ9TPOoCn5BYJB4nb0YKT9fu97KxgQHjx7UxGr6eEwRfNzpFwQ+kzMRp2w
xJLt842PFRv/ae0YJqAAMAoGCCqGSM49BAMCA4GKADCBhgJAKLJHl1QZi8wlUz5p
NaBcFyZqfkXBydjxZe8kLQMK6wyjrKiArWY5VnI+ENfMIXK11ZIEthouoRAOpKSL
HK2LBAJCAOFkH7MHVDRmd7oeUJl1xHtO31zzXrg6amuvoZ9It5AO4YLGs9FxupOu
/wMg+W6xHiwunPLn3rHqffasoD5B8G3h
-----END CERTIFICATE REQUEST-----
";

/// A structurally valid, self-signature-verifying CSR with an RSA-1024
/// key: inside ring's signature-verification range but below Wardstone's
/// 2048-bit floor, pinning the key-size half of the supported-algorithm
/// gate.
const RSA1024_CSR_PEM: &str = "\
-----BEGIN CERTIFICATE REQUEST-----
MIIBYTCBywIBADAiMSAwHgYDVQQDDBdsZWdhY3ktd2Vhay1yc2EuZXhhbXBsZTCB
nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAmpgiEcQYabxc3vphsar2HDQC0bK6
bD93t+pT6OrZvKM+lxkzwL5+ZBhJrGOPsTE9yrnmMvnuBpMhaoChsE3GhI6ihxSa
V+RHSk/Vw8vxqj7AL8hKtMgjpRJb5tjavwYWFTt83FFOr8uM1GGIIF10eE0DWM/m
j7Gv8LIiBfbCRmUCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4GBACZYK69ndOL/orxe
GHhNR/9GHyI9gtKUJcs13iSkFYYeOS0i9wLxvMvWtC01YHgAdFc3EiIf+Rxs1k/9
mx9YQuA9tqbUtEM4mQbK6HVMOMzoktU8rdoV6xjCBWGluqxXXF9cQmsN3yYtU0f/
qLFrqM4DUvqfouxAvRl7+LRtgr5P
-----END CERTIFICATE REQUEST-----
";

/// A structurally valid, self-signature-verifying CSR with an Ed448 key:
/// an unsupported algorithm whose signature ring cannot verify at all,
/// pinning that the algorithm gate runs before signature verification.
const ED448_CSR_PEM: &str = "\
-----BEGIN CERTIFICATE REQUEST-----
MIHuMHACAQAwJDEiMCAGA1UEAwwZdW5zdXBwb3J0ZWQtZWQ0NDguZXhhbXBsZTBD
MAUGAytlcQM6AEA1VyexP+DKI5Xuu9eTIT72A3pfHzvXRhqOZJ0og6cZGagbwjCZ
fnH7xfb0GoXIjHYI/NW2BmMMgKAAMAUGAytlcQNzAIj5C/OevAkwAGbQZgQYNOIn
+ciSmH0LIIvfCTzF4m0aS3hTVYrKMipxcbdwHh2zfdMWMZUVKJhTADd211wSqAcz
odftVsQ3N4/dNvbwES53+cIGL5Y0KDnfrzMm9OrELpb2HRvwxVbttW/j1nnqnyUJ
AA==
-----END CERTIFICATE REQUEST-----
";

/// A valid, self-signature-verifying OpenSSL CSR with an RSA-2048 key and
/// DNS + IP SANs: a second independent encoder, exercising the interop
/// path (rcgen-issued roots x openssl-requested leaves).
const RSA2048_SAN_CSR_PEM: &str = "\
-----BEGIN CERTIFICATE REQUEST-----
MIICljCCAX4CAQAwHjEcMBoGA1UEAwwTaW50ZXJvcC1yc2EuZXhhbXBsZTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ4/Q0bWaLug+jQzvazZsETWme1W
efuLtumsnnJBOfSgqxsj/BNnhY4VwRJzpW+8Yd1kVScL298mi8A4LdNRzFrwsJp4
wk2QgejugomMskGptSI8BLbNYPNxrzpYkWTV98H0Wgu/BtDXb3KlGhwQpGWfksNN
js1pVrIX6gI0Dsuvd9JJOH8rrqGqgB70APUHsMuhGDgafv7heq3D+RNof10QR7S/
O21sWD8hAJTjxSafDAnJ5xuSS28oMZ155+JxPgtYU6XxqzScvYMylTX151DFNBj3
LaNDgR6qVAS5w45Y+yxYEtiZw492FYhWTSER3Wv7pLzZxLyH8wRCsbW8BykCAwEA
AaAzMDEGCSqGSIb3DQEJDjEkMCIwIAYDVR0RBBkwF4IPaW50ZXJvcC5leGFtcGxl
hwQKAABNMA0GCSqGSIb3DQEBCwUAA4IBAQBORlpx8BMVwjQhanItwMTKTaDHWRNF
v8z7P00NHG2HBsSNMp+5B9aa7lD6vRlEvfpcPsfRNdak5dgXUWHcqgVhTg1TiuVL
0sxXTnkFg8HiVpm8VQqeTc5T+jo5eEQmqdipmG8lrwXwZ1QPY24dh7UINVmfYhGm
ypsP3kJLr1HF/p4DBxpb/Gnz5613SzowbnajpcHDtCZwGsI1dfxTwWOJJBoGLI1s
hOmyT3A3NyXBAUGZ7ioKrqPEBgXzgFX97fgp4kEuJhJA+m8jpYNUBsJgxzpVKTKb
y7WFhKvmfcqLCOv9pCnpmyPI5CULBKgFHKBXPVDWUezvopdYfaPTgcig
-----END CERTIFICATE REQUEST-----
";

/// Per-test temp keystore, mirroring the creation suite's pattern: unique
/// per test name and process id, swept before use so stale runs can't
/// interfere.
fn temp_keystore(test_name: &str) -> KeyStore {
    let dir = std::env::temp_dir().join(format!("ws-ca-issue-{test_name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let mut ks = KeyStore::open(&dir).unwrap();
    ks.ensure_master_key().unwrap();
    ks
}

/// An Ed25519 root created against `keystore` (Task 5's tested path).
fn ed25519_root(ks: &mut KeyStore) -> ws_ca::ca::CreatedCa {
    let spec = CaSpec {
        name: "root".to_owned(),
        subject: "Wardstone Test Root".to_owned(),
        key_type: KeyType::Ed25519,
        lifetime: CaLifetime::Root,
    };
    create_root(&spec, ks).unwrap()
}

/// Mint a P-256 CSR in-test with rcgen: optional subject CN + DNS/IP/email
/// SANs + digitalSignature | keyEncipherment key usages, self-signed.
/// `cn: None` produces a CSR with an empty subject (the degenerate input
/// the CN policy must reject).
fn mint_p256_csr(cn: Option<&str>, sans: &[SanEntry]) -> String {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();

    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    if let Some(cn) = cn {
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
    }
    params.subject_alt_names = sans
        .iter()
        .map(|san| match san {
            SanEntry::Dns(d) => rcgen::SanType::DnsName(d.as_str().try_into().unwrap()),
            SanEntry::Ip(ip) => rcgen::SanType::IpAddress(*ip),
            SanEntry::Email(e) => rcgen::SanType::Rfc822Name(e.as_str().try_into().unwrap()),
        })
        .collect();
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];

    let csr = params.serialize_request(&key_pair).unwrap();
    csr.pem().unwrap()
}

/// Parse a PEM certificate into an `X509Certificate` with a `'static`
/// lifetime (test-only leak of the DER bytes).
fn parse_cert(pem: &str) -> X509Certificate<'static> {
    let (_, parsed) = parse_x509_pem(pem.as_bytes()).unwrap();
    let contents: &'static [u8] = Box::leak(parsed.contents.into_boxed_slice());
    let (_, cert) = X509Certificate::from_der(contents).unwrap();
    cert
}

/// The parsed SAN `GeneralName`s of a certificate, or `None` when the
/// certificate carries no SAN extension at all.
fn cert_general_names<'a>(cert: &'a X509Certificate<'a>) -> Option<Vec<GeneralName<'a>>> {
    cert.iter_extensions()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => Some(san.general_names.clone()),
            _ => None,
        })
}

#[test]
fn test_validate_csr_malformed_fails_typed() {
    let err = validate_csr("not a pem").unwrap_err();
    assert!(
        matches!(err, CaError::X509(_)),
        "malformed PEM must map to CaError::X509, got {err:?}"
    );

    // A well-formed PEM block with a non-CSR label is also a typed X509
    // failure (the DER is not a CSR), not a panic or a success.
    let wrong_label = "-----BEGIN PUBLIC KEY-----\nMAA=\n-----END PUBLIC KEY-----\n";
    let err = validate_csr(wrong_label).unwrap_err();
    assert!(matches!(err, CaError::X509(_)), "got {err:?}");

    // Truncated DER inside a correct CERTIFICATE REQUEST envelope: parse
    // must still fail typed.
    let truncated =
        "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n";
    let err = validate_csr(truncated).unwrap_err();
    assert!(matches!(err, CaError::X509(_)), "got {err:?}");
}

#[test]
fn test_validate_csr_reports_alg_cn_sans() {
    let info = validate_csr(&mint_p256_csr(
        Some("requested-name.example"),
        &[SanEntry::Dns("svc.example".to_owned())],
    ))
    .unwrap();
    assert_eq!(info.public_key_alg, "ECDSA P-256");
    assert_eq!(info.subject_cn.as_deref(), Some("requested-name.example"));
    assert_eq!(info.sans, vec![SanEntry::Dns("svc.example".to_owned())]);

    // No SANs requested -> empty list, CN still reported.
    let info = validate_csr(&mint_p256_csr(Some("bare.example"), &[])).unwrap();
    assert_eq!(info.public_key_alg, "ECDSA P-256");
    assert_eq!(info.subject_cn.as_deref(), Some("bare.example"));
    assert!(info.sans.is_empty());

    // Email SANs are parsed through and preserved.
    let info = validate_csr(&mint_p256_csr(
        Some("mail.example"),
        &[SanEntry::Email("ops@example.org".to_owned())],
    ))
    .unwrap();
    assert_eq!(
        info.sans,
        vec![SanEntry::Email("ops@example.org".to_owned())]
    );

    // The bundled RSA-2048 fixture (openssl-minted): algorithm name, CN,
    // and both SAN kinds parsed from a foreign encoder.
    let info = validate_csr(RSA2048_SAN_CSR_PEM).unwrap();
    assert_eq!(info.public_key_alg, "RSA");
    assert_eq!(info.subject_cn.as_deref(), Some("interop-rsa.example"));
    assert_eq!(
        info.sans,
        vec![
            SanEntry::Dns("interop.example".to_owned()),
            SanEntry::Ip(IpAddr::from([10, 0, 0, 77])),
        ]
    );

    // supported_key_alg pins the supported set at the name level: the
    // three supported families are true, everything else false.
    assert!(supported_key_alg("Ed25519"));
    assert!(supported_key_alg("ECDSA P-256"));
    assert!(supported_key_alg("ECDSA P-384"));
    assert!(supported_key_alg("RSA"));
    assert!(!supported_key_alg("ECDSA P-521"));
    assert!(!supported_key_alg("Ed448"));
    assert!(!supported_key_alg("RSA-PSS"));
    assert!(!supported_key_alg("DSA"));
    assert!(!supported_key_alg("dilithium"));
    // Case matters: the names are the function's own canonical outputs.
    assert!(!supported_key_alg("rsa"));
    assert!(!supported_key_alg("ed25519"));

    // A valid but unsupported CSR still validates structurally — validate
    // and sign have deliberately different contracts.
    let info = validate_csr(P521_CSR_PEM).unwrap();
    assert_eq!(info.public_key_alg, "ECDSA P-521");
    assert_eq!(info.subject_cn.as_deref(), Some("unsupported-p521.example"));
    let info = validate_csr(RSA1024_CSR_PEM).unwrap();
    assert_eq!(info.public_key_alg, "RSA");
    let info = validate_csr(ED448_CSR_PEM).unwrap();
    assert_eq!(info.public_key_alg, "Ed448");
}

#[test]
fn test_issue_from_csr_rejects_unsupported_key() {
    let mut ks = temp_keystore("reject-unsupported");
    let root = ed25519_root(&mut ks);
    let spec = LeafSpec {
        sans: vec![SanEntry::Dns("ignored.example".to_owned())],
        key_usages: vec![rcgen::KeyUsagePurpose::DigitalSignature],
        not_after: None,
        subject_cn: None,
        serial: 1,
    };

    // P-521: known curve, unsupported family. Typed rejection, no panic,
    // and the message names the offending algorithm.
    let err =
        ws_ca::issue::sign_leaf_with(&root.cert_pem, &root.private_key_der, P521_CSR_PEM, &spec)
            .unwrap_err();
    assert!(
        matches!(err, CaError::UnsupportedKeyType(ref msg) if msg.contains("P-521")),
        "P-521 CSR must be UnsupportedKeyType naming the algorithm, got {err:?}"
    );

    // Ed448: structurally valid and self-signature-valid, but outside the
    // supported set and outside ring's verification range — the algorithm
    // gate must fire first and type the failure ourselves.
    let err =
        ws_ca::issue::sign_leaf_with(&root.cert_pem, &root.private_key_der, ED448_CSR_PEM, &spec)
            .unwrap_err();
    assert!(
        matches!(err, CaError::UnsupportedKeyType(ref msg) if msg.contains("Ed448")),
        "Ed448 CSR must be UnsupportedKeyType naming the algorithm, got {err:?}"
    );

    // RSA-1024: supported family (RSA) but below the 2048-bit floor. The
    // size half of the gate must also be UnsupportedKeyType (ring would
    // happily sign it; Wardstone refuses).
    let err = ws_ca::issue::sign_leaf_with(
        &root.cert_pem,
        &root.private_key_der,
        RSA1024_CSR_PEM,
        &spec,
    )
    .unwrap_err();
    assert!(
        matches!(err, CaError::UnsupportedKeyType(ref msg) if msg.contains("2048")),
        "RSA-1024 CSR must be UnsupportedKeyType citing the size floor, got {err:?}"
    );
}

#[test]
fn test_issue_from_csr_rejects_bad_signature() {
    let mut ks = temp_keystore("reject-bad-sig");
    let root = ed25519_root(&mut ks);

    // Take a valid, supported (P-256) CSR and flip the last base64 payload
    // character: byte count is unchanged, so every DER length prefix stays
    // intact and the structure still parses — only the signature bit
    // string content is corrupted. The pinned requirement is that the CA
    // verifies the CSR's self-signature before signing and fails typed.
    let csr = mint_p256_csr(Some("tampered.example"), &[]);
    let end = csr.rfind("-----END").unwrap();
    // The last *data* character before the PEM footer (skips base64 '='
    // padding): flipping it changes the CSR's final decoded byte, which
    // lives inside the signature bit string, while the DER's length
    // prefixes stay intact so the structure still parses.
    let payload = csr[..end].trim_end().trim_end_matches('=');
    let last_char_pos = payload.len() - 1;
    let ch = csr.as_bytes()[last_char_pos];
    assert!(
        !b"=\n\r".contains(&ch),
        "fixture sanity: flipped char is data"
    );
    let replacement = if ch == b'A' { 'B' } else { 'A' };
    let mut tampered = csr.clone();
    tampered.replace_range(last_char_pos..last_char_pos + 1, &replacement.to_string());
    assert_ne!(tampered, csr, "tamper must change the payload");

    let err = ws_ca::issue::sign_leaf_with(
        &root.cert_pem,
        &root.private_key_der,
        &tampered,
        &LeafSpec {
            sans: vec![],
            key_usages: vec![],
            not_after: None,
            subject_cn: None,
            serial: 1,
        },
    )
    .unwrap_err();
    assert!(
        matches!(err, CaError::X509(ref msg) if msg.contains("signature")),
        "a CSR whose self-signature does not verify must be X509 naming the \
         signature failure, got {err:?}"
    );
}

#[test]
fn test_issue_leaf_happy_path() {
    let mut ks = temp_keystore("happy-path");
    let root = ed25519_root(&mut ks);

    let sans = vec![
        SanEntry::Dns("svc.example".to_owned()),
        SanEntry::Ip(IpAddr::from([203, 0, 113, 7])),
    ];
    let csr = mint_p256_csr(Some("leaf-subject.example"), &sans);
    let serial: u128 = 0x0123_4567_89ab_cdef_0123_4567_89ab_cdef;
    let spec = LeafSpec {
        sans,
        key_usages: vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ],
        not_after: None,
        subject_cn: Some("leaf-subject.example".to_owned()),
        serial,
    };

    let issued =
        ws_ca::issue::sign_leaf_with(&root.cert_pem, &root.private_key_der, &csr, &spec).unwrap();

    assert!(issued.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert_eq!(issued.serial, serial, "serial must roundtrip unchanged");
    assert_eq!(
        issued.not_after - issued.not_before,
        chrono::Duration::days(30),
        "default leaf validity is exactly 30 days"
    );
    assert!(issued.not_before <= chrono::Utc::now() + chrono::Duration::minutes(5));

    let (_, root_pem) = parse_x509_pem(root.cert_pem.as_bytes()).unwrap();
    let root_cert = root_pem.parse_x509().unwrap();
    let cert = parse_cert(&issued.cert_pem);

    // The leaf is issued by the root, signed with the root's algorithm,
    // and the root's key actually verifies the leaf's signature.
    assert_eq!(cert.issuer(), root_cert.subject());
    assert_eq!(
        cert.signature_algorithm.algorithm.to_id_string(),
        "1.3.101.112",
        "an Ed25519 CA signs leaves with id-Ed25519"
    );
    root_cert
        .verify_signature(None)
        .expect("fixture root self-signature must verify");
    cert.verify_signature(Some(root_cert.public_key()))
        .expect("the root's public key must verify the leaf's signature");

    // The leaf's public key is the CSR's public key (a P-256 point).
    match cert.public_key().parsed().unwrap() {
        x509_parser::public_key::PublicKey::EC(ec) => assert_eq!(ec.key_size(), 256),
        other => panic!("expected an EC public key, got {other:?}"),
    }
    assert_eq!(
        cert.public_key().algorithm.algorithm.to_id_string(),
        "1.2.840.10045.2.1",
        "leaf SPKI must carry id-ecPublicKey"
    );

    // SANs propagated from the spec.
    let names = cert_general_names(&cert).expect("SAN extension present");
    assert_eq!(names.len(), 2, "expected DNS + IP SANs, got {names:?}");
    assert!(
        names
            .iter()
            .any(|n| matches!(n, GeneralName::DNSName(d) if d == &"svc.example")),
        "DNS SAN missing"
    );
    assert!(
        names
            .iter()
            .any(|n| matches!(n, GeneralName::IPAddress(ip) if *ip == [203u8, 0, 113, 7])),
        "IP SAN missing"
    );

    // Key usages exactly as requested (critical per Task 5's profile).
    let ku = cert.key_usage().unwrap().unwrap();
    assert!(ku.critical);
    assert!(ku.value.digital_signature());
    assert!(ku.value.key_encipherment());
    assert!(!ku.value.key_cert_sign(), "a leaf is not a CA");

    // Not a CA.
    let bc = cert.basic_constraints().unwrap().unwrap();
    assert!(!bc.value.ca);

    // Subject CN as specified.
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap();
    assert_eq!(cn, "leaf-subject.example");

    // Serial encodes back to exactly the caller-supplied u128.
    assert_eq!(
        cert.serial.to_bytes_be(),
        serial.to_be_bytes().to_vec(),
        "issued certificate serial must equal the spec serial"
    );

    // Parsed validity matches the returned timestamps exactly (both are
    // whole seconds) and spans 30 days.
    let validity = cert.validity();
    assert_eq!(
        validity.not_after.timestamp() - validity.not_before.timestamp(),
        30 * 86_400
    );
    assert_eq!(
        validity.not_before.timestamp(),
        issued.not_before.timestamp()
    );
    assert_eq!(validity.not_after.timestamp(), issued.not_after.timestamp());

    // Structural echo: validate_csr on the CSR agrees with what we issued.
    let info = validate_csr(&csr).unwrap();
    assert_eq!(info.public_key_alg, "ECDSA P-256");
    assert_eq!(info.subject_cn.as_deref(), Some("leaf-subject.example"));
}

#[test]
fn test_issue_leaf_respects_explicit_not_after_and_optional_cn() {
    let mut ks = temp_keystore("explicit-validity");
    let root = ed25519_root(&mut ks);

    let csr = mint_p256_csr(Some("minimal.example"), &[]);
    let not_after = (chrono::Utc::now() + chrono::Duration::days(7)).trunc_subsecs(0);
    let spec = LeafSpec {
        sans: vec![],
        key_usages: vec![rcgen::KeyUsagePurpose::DigitalSignature],
        not_after: Some(not_after),
        // subject_cn None: keep the CSR's own subject (minted with CN).
        subject_cn: None,
        serial: 42,
    };

    let issued =
        ws_ca::issue::sign_leaf_with(&root.cert_pem, &root.private_key_der, &csr, &spec).unwrap();
    assert_eq!(issued.serial, 42);
    // With an explicit not_after, the spec instant is honored exactly
    // (not_before is still the midnight skew margin, so the window is not
    // 7 days on the dot — the two endpoints are asserted individually).
    assert_eq!(issued.not_after.timestamp(), not_after.timestamp());
    assert!(issued.not_before <= chrono::Utc::now());

    let cert = parse_cert(&issued.cert_pem);
    // No SANs requested -> no SAN extension on the leaf.
    assert!(
        cert_general_names(&cert).is_none(),
        "leaf must not carry a SAN extension the CSR/spec never asked for"
    );

    // subject_cn None keeps the CSR's CN.
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap();
    assert_eq!(cn, "minimal.example");

    // The public key is still the CSR's (a P-256 point).
    match cert.public_key().parsed().unwrap() {
        x509_parser::public_key::PublicKey::EC(ec) => assert_eq!(ec.key_size(), 256),
        other => panic!("expected an EC public key, got {other:?}"),
    }
}

#[test]
fn test_issue_leaf_rejects_unusable_subject() {
    let mut ks = temp_keystore("cn-policy");
    let root = ed25519_root(&mut ks);
    let base = LeafSpec {
        sans: vec![],
        key_usages: vec![],
        not_after: None,
        subject_cn: None,
        serial: 7,
    };

    // CSR has a CN but the spec overrides it with whitespace: an empty
    // subject must not silently issue.
    let csr = mint_p256_csr(Some("has-cn.example"), &[]);
    let err = ws_ca::issue::sign_leaf_with(
        &root.cert_pem,
        &root.private_key_der,
        &csr,
        &LeafSpec {
            subject_cn: Some("   ".to_owned()),
            ..base.clone()
        },
    )
    .unwrap_err();
    assert!(
        matches!(err, CaError::X509(ref msg) if msg.contains("subject")),
        "blank subject_cn must be a typed X509 error, got {err:?}"
    );

    // CSR with an empty subject and no CN in the spec either: no usable
    // subject anywhere -> typed rejection, never an invalid certificate.
    let subject_less = mint_p256_csr(None, &[]);
    let err = ws_ca::issue::sign_leaf_with(
        &root.cert_pem,
        &root.private_key_der,
        &subject_less,
        &LeafSpec {
            subject_cn: None,
            ..base
        },
    )
    .unwrap_err();
    assert!(
        matches!(err, CaError::X509(ref msg) if msg.contains("subject")),
        "empty CSR subject with no override must be a typed X509 error, got {err:?}"
    );
}

#[test]
fn test_issue_leaf_serial_encodes_edge_values() {
    let mut ks = temp_keystore("serial-edges");
    let root = ed25519_root(&mut ks);
    let csr = mint_p256_csr(Some("serial.example"), &[]);
    let spec_for = |serial: u128| LeafSpec {
        sans: vec![],
        key_usages: vec![],
        not_after: None,
        subject_cn: None,
        serial,
    };

    // u128::MAX and 2^127: 16 bytes all set / high bit set — the case a
    // naive DER INTEGER writer would encode as negative. The positive
    // writer must prepend the 0x00 sign octet, and the parsed value still
    // round-trips to exactly the caller's serial. Smaller values (255)
    // cover the leading-zero-stripping path: DER canonicalizes to the
    // minimal positive encoding, so the parsed and re-encoded values must
    // compare equal, per-value, for every case.
    for serial in [
        u128::MAX,
        2u128.pow(127),
        u128::from(u8::MAX),
        0x0123_4567_89ab_cdef_0123_4567_89ab_cdef,
        u128::from(u16::MAX),
    ] {
        let issued = ws_ca::issue::sign_leaf_with(
            &root.cert_pem,
            &root.private_key_der,
            &csr,
            &spec_for(serial),
        )
        .unwrap();
        assert_eq!(issued.serial, serial);
        let cert = parse_cert(&issued.cert_pem);
        // The value must round-trip exactly (the raw octet count differs
        // for small serials: DER strips leading zeros and prepends the
        // sign octet only when the first data byte has its high bit set).
        assert_eq!(
            x509_parser::num_bigint::BigUint::from_bytes_be(&cert.serial.to_bytes_be()),
            x509_parser::num_bigint::BigUint::from(serial),
            "serial {serial} must round-trip through DER"
        );
        // RFC 5280 section 4.1.2.2: 20 octets at most — 17 for u128::MAX.
        assert!(cert.serial.to_bytes_be().len() <= 20);
    }

    // Serial 0 is not a positive integer (RFC 5280 section 4.1.2.2): it
    // must be a typed rejection, never an issued certificate.
    let err =
        ws_ca::issue::sign_leaf_with(&root.cert_pem, &root.private_key_der, &csr, &spec_for(0))
            .unwrap_err();
    assert!(
        matches!(err, CaError::X509(ref msg) if msg.contains("serial")),
        "serial 0 must be a typed X509 rejection, got {err:?}"
    );

    // Two consecutive issue calls share the CSR; the serials differ only
    // because the caller supplied different values (no minting here).
    let a =
        ws_ca::issue::sign_leaf_with(&root.cert_pem, &root.private_key_der, &csr, &spec_for(1000))
            .unwrap();
    let b =
        ws_ca::issue::sign_leaf_with(&root.cert_pem, &root.private_key_der, &csr, &spec_for(2000))
            .unwrap();
    assert_ne!(a.serial, b.serial);
}

#[test]
fn test_issue_leaf_keeps_csr_public_key_not_ca_key() {
    let mut ks = temp_keystore("key-binding");
    let root = ed25519_root(&mut ks);

    // Two CSRs with the same subject but different P-256 keys: the issued
    // leaf must contain the corresponding CSR's key, not the CA's or the
    // other request's.
    let csr_a = mint_p256_csr(Some("bind.example"), &[]);
    let csr_b = mint_p256_csr(Some("bind.example"), &[]);
    assert_ne!(csr_a, csr_b, "independent CSRs must differ");

    let issued_a = ws_ca::issue::sign_leaf_with(
        &root.cert_pem,
        &root.private_key_der,
        &csr_a,
        &LeafSpec {
            sans: vec![],
            key_usages: vec![],
            not_after: None,
            subject_cn: None,
            serial: 9001,
        },
    )
    .unwrap();

    let cert = parse_cert(&issued_a.cert_pem);

    // Parse the CSR that was actually signed and compare SPKI fields.
    let (_, csr_pem) = parse_x509_pem(csr_a.as_bytes()).unwrap();
    let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(
        csr_pem.contents.as_slice(),
    )
    .unwrap();
    let csr_spki = &csr.certification_request_info.subject_pki;

    assert_eq!(
        cert.public_key().algorithm.algorithm,
        csr_spki.algorithm.algorithm,
        "leaf and CSR SPKI algorithms must match"
    );
    assert_eq!(
        cert.public_key().subject_public_key.data,
        csr_spki.subject_public_key.data,
        "the leaf's public key must be the CSR's public key"
    );
    assert_ne!(
        cert.public_key().subject_public_key.data,
        root_cert_spki_public_bytes(&root.cert_pem),
        "the leaf must never embed the CA's own public key"
    );
}

/// The CA certificate's raw subject public key bits.
fn root_cert_spki_public_bytes(root_cert_pem: &str) -> Vec<u8> {
    let (_, pem) = parse_x509_pem(root_cert_pem.as_bytes()).unwrap();
    let cert = pem.parse_x509().unwrap();
    cert.public_key().subject_public_key.data.to_vec()
}
