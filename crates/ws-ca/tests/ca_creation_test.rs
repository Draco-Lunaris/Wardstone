//! Integration tests for `ws_ca::ca` — root and sub-CA creation.
//!
//! Pure tests, no database: creation works against a temp-dir keystore
//! (DB persistence of the created CA rows is Plan 2's bootstrap). Each test
//! parses the generated certificate with x509-parser and asserts the
//! pinned certificate shape: BasicConstraints, KeyUsage, validity window,
//! and (for sub-CAs) the AKI-to-parent-SKI link.

use std::fs;

use sha2::{Digest, Sha256};
use ws_ca::ca::{create_root, create_sub_ca, CaLifetime, CaSpec, KeyType};
use ws_ca::keystore::KeyStore;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::pem::parse_x509_pem;

/// Per-test temp keystore, mirroring the keystore suite's pattern: unique
/// per test name and process id, swept before use so stale runs can't
/// interfere.
fn temp_keystore(test_name: &str) -> KeyStore {
    let dir =
        std::env::temp_dir().join(format!("ws-ca-creation-{test_name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let mut ks = KeyStore::open(&dir).unwrap();
    ks.ensure_master_key().unwrap();
    ks
}

/// The certificate's SubjectKeyIdentifier bytes (parsed extension).
fn ski_bytes(cert: &X509Certificate<'_>) -> Vec<u8> {
    cert.iter_extensions()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(ki) => Some(ki.0.to_vec()),
            _ => None,
        })
        .expect("SubjectKeyIdentifier extension present")
}

/// The certificate's AuthorityKeyIdentifier keyIdentifier bytes.
fn aki_bytes(cert: &X509Certificate<'_>) -> Vec<u8> {
    cert.iter_extensions()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                aki.key_identifier.as_ref().map(|ki| ki.0.to_vec())
            }
            _ => None,
        })
        .expect("AuthorityKeyIdentifier extension with keyIdentifier present")
}

/// Whether the certificate's SubjectKeyIdentifier extension is marked
/// critical (RFC 5280 requires SKI to be non-critical).
fn ski_critical(cert: &X509Certificate<'_>) -> bool {
    cert.iter_extensions()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(_) => Some(ext.critical),
            _ => None,
        })
        .expect("SubjectKeyIdentifier extension present")
}

/// Pin the serial-number policy: a positive integer of at most 20 octets
/// (RFC 5280 §4.1.2.2) that is NOT rcgen's deterministic default — which,
/// when `CertificateParams::serial_number` is left unset, is SHA-256 of the
/// subject public key bits truncated to 20 bytes with the sign bit cleared
/// (verified against rcgen 0.14.10's `serialize_der_with_signer`). A
/// regressed serial reproduces that value exactly and fails here.
fn assert_random_serial(cert: &X509Certificate<'_>) {
    let serial = cert.serial.to_bytes_be();
    assert!(
        serial.iter().any(|&b| b != 0),
        "serial must be a positive integer"
    );
    assert!(
        serial.len() <= 20,
        "serial exceeds RFC 5280's 20-octet bound"
    );

    let spki = cert.public_key();
    let bits: &[u8] = &spki.subject_public_key.data;
    let mut legacy = Sha256::digest(bits).to_vec();
    legacy.truncate(20);
    legacy[0] &= 0x7f;
    let legacy = &legacy[legacy.iter().take_while(|&&b| b == 0).count()..];
    assert_ne!(
        serial.as_slice(),
        legacy,
        "serial is rcgen's public-key-derived default, not OS entropy"
    );
}

#[test]
fn test_create_root_ed25519_roundtrip() {
    let mut ks = temp_keystore("root-ed25519");
    let spec = CaSpec {
        name: "root".to_owned(),
        subject: "Wardstone Test Root".to_owned(),
        key_type: KeyType::Ed25519,
        lifetime: CaLifetime::Root,
    };
    let created = create_root(&spec, &mut ks).unwrap();

    // PEM shape
    assert!(created.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(created.cert_pem.contains("-----END CERTIFICATE-----"));

    let (_, pem) = parse_x509_pem(created.cert_pem.as_bytes()).unwrap();
    let cert = pem.parse_x509().unwrap();

    // Subject CN comes from spec.subject
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap();
    assert_eq!(cn, "Wardstone Test Root");

    // BasicConstraints CA:true, critical, unconstrained (root)
    let bc = cert.basic_constraints().unwrap().unwrap();
    assert!(bc.critical, "root BasicConstraints must be critical");
    assert!(bc.value.ca);
    assert_eq!(bc.value.path_len_constraint, None);

    // KeyUsage digitalSignature | keyCertSign | cRLSign, critical
    let ku = cert.key_usage().unwrap().unwrap();
    assert!(ku.critical);
    assert!(ku.value.digital_signature());
    assert!(ku.value.key_cert_sign());
    assert!(ku.value.crl_sign());

    // SKI is non-critical (RFC 5280), and the serial carries OS entropy —
    // the pin fails if the serial regresses to rcgen's key-derived default.
    assert!(!ski_critical(&cert), "root SKI must be non-critical");
    assert_random_serial(&cert);

    // The root really is Ed25519-signed (id-Ed25519)
    assert_eq!(
        cert.signature_algorithm.algorithm.to_id_string(),
        "1.3.101.112"
    );

    // Validity: exactly 10 years (3650 days) and currently in effect.
    // Both ends are midnight UTC, so the timestamp delta is exact.
    let validity = cert.validity();
    assert_eq!(
        validity.not_after.timestamp() - validity.not_before.timestamp(),
        3650 * 86_400
    );
    let now = chrono::Utc::now().timestamp();
    assert!(validity.not_before.timestamp() <= now);
    assert!(now <= validity.not_after.timestamp());

    // The key was stored encrypted under the returned key-pair id, and the
    // stored bytes are exactly the returned DER (roundtrip).
    let loaded = ks.load_ca_key(&created.key_pair_id).unwrap();
    assert_eq!(loaded.as_slice(), created.private_key_der.as_slice());
}

#[test]
fn test_create_sub_ca_signed_by_root() {
    let mut ks = temp_keystore("sub-ca");

    let root_spec = CaSpec {
        name: "root".to_owned(),
        subject: "Wardstone Test Root".to_owned(),
        key_type: KeyType::Ed25519,
        lifetime: CaLifetime::Root,
    };
    let root = create_root(&root_spec, &mut ks).unwrap();

    // The documented caller contract: load the parent key from the
    // keystore and pass its DER bytes next to the parent cert PEM.
    let parent_key = ks.load_ca_key(&root.key_pair_id).unwrap();

    let sub_spec = CaSpec {
        name: "issuing".to_owned(),
        subject: "Wardstone Issuing CA".to_owned(),
        key_type: KeyType::Ed25519,
        lifetime: CaLifetime::SubCa,
    };
    let sub = create_sub_ca(&root.cert_pem, parent_key.as_slice(), &sub_spec, &mut ks).unwrap();

    assert!(sub.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert_ne!(sub.key_pair_id, root.key_pair_id);

    let (_, root_pem) = parse_x509_pem(root.cert_pem.as_bytes()).unwrap();
    let root_cert = root_pem.parse_x509().unwrap();
    let (_, sub_pem) = parse_x509_pem(sub.cert_pem.as_bytes()).unwrap();
    let sub_cert = sub_pem.parse_x509().unwrap();

    // BasicConstraints CA:true pathlen:0, critical
    let bc = sub_cert.basic_constraints().unwrap().unwrap();
    assert!(bc.critical);
    assert!(bc.value.ca);
    assert_eq!(bc.value.path_len_constraint, Some(0));

    // KeyUsage keyCertSign | cRLSign, critical (no digitalSignature on sub-CAs)
    let ku = sub_cert.key_usage().unwrap().unwrap();
    assert!(ku.critical, "sub-CA KeyUsage must be critical");
    assert!(ku.value.key_cert_sign());
    assert!(ku.value.crl_sign());
    assert!(!ku.value.digital_signature());

    // SKI non-critical; serial carries OS entropy, not the key-derived default
    assert!(!ski_critical(&sub_cert), "sub-CA SKI must be non-critical");
    assert_random_serial(&sub_cert);

    // The sub-CA's AKI is the root's SKI (compare parsed extensions)
    assert_eq!(aki_bytes(&sub_cert), ski_bytes(&root_cert));

    // Issued by the root: issuer DN equals the root's subject DN
    assert_eq!(sub_cert.issuer(), root_cert.subject());

    // Sub-CA validity: exactly 5 years (1825 days)
    let validity = sub_cert.validity();
    assert_eq!(
        validity.not_after.timestamp() - validity.not_before.timestamp(),
        1825 * 86_400
    );

    // The sub-CA's own key is stored under its own id (roundtrip)
    let loaded = ks.load_ca_key(&sub.key_pair_id).unwrap();
    assert_eq!(loaded.as_slice(), sub.private_key_der.as_slice());
}

#[test]
fn test_create_root_rsa2048() {
    let mut ks = temp_keystore("root-rsa2048");
    let spec = CaSpec {
        name: "root".to_owned(),
        subject: "Wardstone RSA Root".to_owned(),
        key_type: KeyType::Rsa2048,
        lifetime: CaLifetime::Root,
    };
    let created = create_root(&spec, &mut ks).unwrap();

    assert!(created.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));

    let (_, pem) = parse_x509_pem(created.cert_pem.as_bytes()).unwrap();
    let cert = pem.parse_x509().unwrap();

    let bc = cert.basic_constraints().unwrap().unwrap();
    assert!(bc.critical);
    assert!(bc.value.ca);

    let ku = cert.key_usage().unwrap().unwrap();
    assert!(ku.value.key_cert_sign());
    assert!(ku.value.crl_sign());
    assert!(ku.value.digital_signature());

    // The same OS-entropy serial policy covers RSA roots (regression pin)
    assert_random_serial(&cert);

    // Really an RSA-2048 key: the parsed public key reports 2048 bits and
    // the certificate is signed with sha256WithRSAEncryption.
    match cert.public_key().parsed().unwrap() {
        x509_parser::public_key::PublicKey::RSA(rsa) => {
            assert_eq!(rsa.key_size(), 2048);
        }
        other => panic!("expected an RSA public key, got {other:?}"),
    }
    assert_eq!(
        cert.signature_algorithm.algorithm.to_id_string(),
        "1.2.840.113549.1.1.11"
    );

    // Key stored encrypted under the returned id (roundtrip)
    let loaded = ks.load_ca_key(&created.key_pair_id).unwrap();
    assert_eq!(loaded.as_slice(), created.private_key_der.as_slice());
}

#[test]
fn ca_lifetime_durations() {
    // Pinned durations: root 10 years, sub-CA 5 years, leaf 30 days,
    // counted as whole 365-day years.
    assert_eq!(CaLifetime::Root.duration().num_days(), 3650);
    assert_eq!(CaLifetime::SubCa.duration().num_days(), 1825);
    assert_eq!(CaLifetime::Leaf.duration().num_days(), 30);
}
