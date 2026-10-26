//! Integration tests for `ws_ca::ca` — root and sub-CA creation.
//!
//! Pure tests, no database: creation works against a temp-dir keystore
//! (DB persistence of the created CA rows is Plan 2's bootstrap). Each test
//! parses the generated certificate with x509-parser and asserts the
//! pinned certificate shape: BasicConstraints, KeyUsage, validity window,
//! and (for sub-CAs) the AKI-to-parent-SKI link.

use std::fs;

use chrono::Duration;
use sha2::{Digest, Sha256};
use ws_ca::ca::{create_root, create_sub_ca, CaLifetime, CaSpec, KeyType};
use ws_ca::error::CaError;
use ws_ca::issue::{ExtKeyUsagePurpose, KeyUsagePurpose};
use ws_ca::keystore::KeyStore;
use ws_ca::leafkey::LeafKeyType;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::pem::parse_x509_pem;

/// Per-test temp keystore, mirroring the keystore suite's pattern: unique
/// per test name and process id, swept before use so stale runs can't
/// interfere. The store is UNLOCKED (the seal-at-creation custody): the
/// master is minted straight into the protected arena — no plaintext
/// master file exists anywhere.
fn temp_keystore(test_name: &str) -> KeyStore {
    let dir =
        std::env::temp_dir().join(format!("ws-ca-creation-{test_name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let mem = ws_secmem::global().expect("the protected pool initializes");
    KeyStore::open_unlocked(
        &dir,
        mem.alloc_copy(&[7u8; 32])
            .expect("the arena holds the test master"),
    )
    .expect("open the unlocked test key store")
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
    let loaded = ks.unwrap_ca_key(&created.key_pair_id).unwrap();
    assert_eq!(&*loaded, created.private_key_der.as_slice());
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

    // The documented caller contract: the parent's certificate PEM and
    // its key-pair id travel together — `create_sub_ca` performs the
    // per-use unwrap of the parent key itself.

    let sub_spec = CaSpec {
        name: "issuing".to_owned(),
        subject: "Wardstone Issuing CA".to_owned(),
        key_type: KeyType::Ed25519,
        lifetime: CaLifetime::SubCa,
    };
    let sub = create_sub_ca(&root.cert_pem, &root.key_pair_id, &sub_spec, &mut ks).unwrap();

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
    let loaded = ks.unwrap_ca_key(&sub.key_pair_id).unwrap();
    assert_eq!(&*loaded, sub.private_key_der.as_slice());
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
    let loaded = ks.unwrap_ca_key(&created.key_pair_id).unwrap();
    assert_eq!(&*loaded, created.private_key_der.as_slice());
}

#[test]
fn ca_lifetime_durations() {
    // Pinned durations: root 10 years, sub-CA 5 years, leaf 30 days,
    // counted as whole 365-day years.
    assert_eq!(CaLifetime::Root.duration().num_days(), 3650);
    assert_eq!(CaLifetime::SubCa.duration().num_days(), 1825);
    assert_eq!(CaLifetime::Leaf.duration().num_days(), 30);
}

/// A sub-CA spec (the shape `create_sub_ca` is called with).
fn sub_spec() -> CaSpec {
    CaSpec {
        name: "issuing".to_owned(),
        subject: "Wardstone Issuing CA".to_owned(),
        key_type: KeyType::Ed25519,
        lifetime: CaLifetime::SubCa,
    }
}

/// A root CA spec.
fn root_spec() -> CaSpec {
    CaSpec {
        name: "root".to_owned(),
        subject: "Wardstone Test Root".to_owned(),
        key_type: KeyType::Ed25519,
        lifetime: CaLifetime::Root,
    }
}

/// An end-entity certificate (a leaf) and its key, used as an ILLEGAL
/// parent.
///
/// The leaf is issued by a root so that it is a real, well-formed
/// certificate with `BasicConstraints CA:FALSE` — exactly the shape
/// that must never be usable as an issuer.
fn end_entity_cert(ks: &mut KeyStore) -> (String, Vec<u8>) {
    use ws_ca::issue::{sign_leaf_with, LeafSpec, SanEntry};

    let root = create_root(&root_spec(), ks).unwrap();
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "not-a-ca.example");
    params.subject_alt_names = vec![rcgen::SanType::DnsName(
        "not-a-ca.example".try_into().unwrap(),
    )];
    let csr = params.serialize_request(&key_pair).unwrap();

    let issued = sign_leaf_with(
        &root.cert_pem,
        root.private_key_der.as_slice(),
        &csr.pem().unwrap(),
        &LeafSpec {
            sans: vec![SanEntry::Dns("not-a-ca.example".to_owned())],
            key_usages: vec![KeyUsagePurpose::DigitalSignature],
            ekus: vec![ExtKeyUsagePurpose::ServerAuth],
            key_type: LeafKeyType::EcdsaP256,
            lifetime: Duration::days(30),
            subject_cn: None,
            serial: 0x1234,
        },
    )
    .expect("issue the end-entity certificate");
    // The leaf's private key is the CSR's key (the leaf carries the
    // requester's key verbatim), so the caller's key pair is the one
    // that pairs with the issued certificate.
    (issued.cert_pem, key_pair.serialize_der())
}

/// A sub-CA under a parent whose `pathLenConstraint` is 0 is REFUSED.
///
/// The child would be stamped `CA:TRUE, pathlen:0` under a parent that
/// already forbids any CA below it, so the resulting chain violates the
/// parent's own constraint — relying parties reject it ("path length
/// constraint exceeded").
#[test]
fn test_create_sub_ca_under_pathlen_zero_parent_is_refused() {
    let mut ks = temp_keystore("sub-under-pathlen0");
    let root = create_root(&root_spec(), &mut ks).unwrap();
    let sub = create_sub_ca(&root.cert_pem, &root.key_pair_id, &sub_spec(), &mut ks).unwrap();

    // The sub-CA carries pathlen:0, so it may not have a CA below it.
    let (_, sub_pem) = parse_x509_pem(sub.cert_pem.as_bytes()).unwrap();
    let sub_cert = sub_pem.parse_x509().unwrap();
    assert_eq!(
        sub_cert
            .basic_constraints()
            .unwrap()
            .unwrap()
            .value
            .path_len_constraint,
        Some(0)
    );

    // A sub-sub-CA under it must be refused with a typed error.
    let err = create_sub_ca(&sub.cert_pem, &sub.key_pair_id, &sub_spec(), &mut ks)
        .expect_err("a pathlen-0 parent must not be allowed to create a sub-CA");
    match err {
        CaError::X509(msg) => assert!(
            msg.contains("path length constraint"),
            "the refusal must name the path length constraint, got: {msg}"
        ),
        other => panic!("expected a typed CaError::X509, got {other:?}"),
    }
}

/// A non-CA (end-entity) parent is REFUSED for sub-CA creation.
#[test]
fn test_create_sub_ca_under_non_ca_parent_is_refused() {
    let mut ks = temp_keystore("sub-under-non-ca");
    let (leaf_pem, leaf_key) = end_entity_cert(&mut ks);
    // The parent's key must live in the keystore for the per-use unwrap:
    // an end-entity's key stored under a fresh id carries the pairing
    // check, and the CA-ness refusal then fires on the real bytes.
    let leaf_key_id = uuid::Uuid::new_v4();
    ks.store_ca_key(&leaf_key_id, &leaf_key).unwrap();

    let err = create_sub_ca(&leaf_pem, &leaf_key_id, &sub_spec(), &mut ks)
        .expect_err("an end-entity parent must not be allowed to create a sub-CA");
    match err {
        CaError::X509(msg) => assert!(
            msg.contains("not a CA"),
            "the refusal must say the parent is not a CA, got: {msg}"
        ),
        other => panic!("expected a typed CaError::X509, got {other:?}"),
    }
}

/// A root parent (no pathLenConstraint) still permits a sub-CA, and so
/// does a parent with `pathLenConstraint >= 1`.
#[test]
fn test_create_sub_ca_permitted_parents_are_allowed() {
    let mut ks = temp_keystore("sub-permitted-parents");
    // A root has NO pathLenConstraint: any depth below it is permitted.
    let root = create_root(&root_spec(), &mut ks).unwrap();
    let sub = create_sub_ca(&root.cert_pem, &root.key_pair_id, &sub_spec(), &mut ks)
        .expect("a root parent must permit a sub-CA");
    assert!(sub.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));

    // A parent with pathLenConstraint >= 1 permits another CA too. The
    // Wardstone sub-CA profile stamps pathlen:0, so a pathlen>=1 parent
    // is minted here with rcgen directly to exercise the rule.
    let mut permissive = rcgen::CertificateParams::default();
    permissive
        .distinguished_name
        .push(rcgen::DnType::CommonName, "permissive.example");
    permissive.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(3));
    permissive.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let permissive_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let permissive_cert = permissive.self_signed(&permissive_key).unwrap();

    // The permissive parent's rcgen key must live in the keystore for the
    // per-use unwrap: stored under a fresh id, its bytes carry the
    // pairing check and the pathlen>=1 permission fires on the real cert.
    let permissive_key_id = uuid::Uuid::new_v4();
    ks.store_ca_key(&permissive_key_id, &permissive_key.serialize_der())
        .unwrap();
    let err = create_sub_ca(
        &permissive_cert.pem(),
        &permissive_key_id,
        &sub_spec(),
        &mut ks,
    );
    assert!(
        err.is_ok(),
        "a pathlen>=1 parent must permit a sub-CA, got {err:?}"
    );
}

/// A sub-CA's validity is CLAMPED to the parent's `notAfter`: a child
/// that outlives its issuer is a self-inflicted outage for the rest of
/// the chain's life.
///
/// The parent here is deliberately SHORT-LIVED (30 days, via
/// [`CaLifetime::Leaf`]) while the requested sub-CA lifetime is the
/// pinned 5 years, so the clamp actually bites. A parent whose window
/// comfortably exceeds the requested lifetime would make this assertion
/// vacuous: the clamp would be a no-op and the test would pass even with
/// the clamp removed. The test therefore also asserts that the child's
/// span is SHORTER than the requested one — which is only true if the
/// clamp ran.
#[test]
fn test_create_sub_ca_validity_is_clamped_to_parent_not_after() {
    let mut ks = temp_keystore("sub-clamped-validity");
    // A 30-day root: CA:TRUE and unconstrained (so it may issue a
    // sub-CA), but it expires long before the requested 5-year sub-CA.
    let short_lived_root_spec = CaSpec {
        name: "short-lived-root".to_owned(),
        subject: "Wardstone Short Lived Root".to_owned(),
        key_type: KeyType::Ed25519,
        lifetime: CaLifetime::Leaf,
    };
    let root = create_root(&short_lived_root_spec, &mut ks).unwrap();
    let sub = create_sub_ca(&root.cert_pem, &root.key_pair_id, &sub_spec(), &mut ks)
        .expect("create the sub-CA");

    let (_, root_pem) = parse_x509_pem(root.cert_pem.as_bytes()).unwrap();
    let root_cert = root_pem.parse_x509().unwrap();
    let (_, sub_pem) = parse_x509_pem(sub.cert_pem.as_bytes()).unwrap();
    let sub_cert = sub_pem.parse_x509().unwrap();

    // The fixture's premise: the parent really is short-lived, so the
    // clamp has something to do. Without this, the test could pass
    // vacuously.
    let parent_span =
        root_cert.validity().not_after.timestamp() - root_cert.validity().not_before.timestamp();
    let requested_span = CaLifetime::SubCa.duration().num_seconds();
    assert!(
        parent_span < requested_span,
        "the fixture parent must be short-lived ({parent_span}s) relative to the requested \
         sub-CA lifetime ({requested_span}s), or the clamp is a no-op"
    );

    // The clamp: the child's notAfter EQUALS the parent's, not merely
    // "<=" it. An unclamped child would carry the requested 5-year
    // window and outlive its issuer.
    assert_eq!(
        sub_cert.validity().not_after.timestamp(),
        root_cert.validity().not_after.timestamp(),
        "the sub-CA's notAfter must be clamped to the parent's"
    );

    // And the child's window is the parent's, not the requested one.
    let child_span =
        sub_cert.validity().not_after.timestamp() - sub_cert.validity().not_before.timestamp();
    assert!(
        child_span < requested_span,
        "the clamped sub-CA spans {child_span}s, which must be shorter than the requested \
         {requested_span}s"
    );
}

/// A CA:TRUE issuer whose KeyUsage is cRLSign only (no `keyCertSign`) is
/// REFUSED as a parent — for both sub-CA creation and leaf issuance.
///
/// RFC 5280 section 4.2.1.3: a CA whose keyUsage omits `keyCertSign` is
/// not permitted to sign certificates. The `BasicConstraints.ca` half of
/// that rule is covered by the non-CA-parent test; this one covers the
/// keyUsage half, which a refactor that dropped the keyUsage check (or
/// flipped the "no keyUsage extension means unrestricted" default) would
/// otherwise let through unnoticed.
#[test]
fn test_issuer_without_key_cert_sign_is_refused() {
    // A CA:TRUE certificate whose KeyUsage is cRLSign only.
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "crl-signer-only.example");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::CrlSign];
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = params.self_signed(&key).unwrap();

    // Assert the fixture's own properties, so the test cannot pass
    // vacuously (e.g. because rcgen silently added keyCertSign, or
    // because the certificate is not a CA at all).
    let (_, pem) = parse_x509_pem(cert.pem().as_bytes()).unwrap();
    let parsed = pem.parse_x509().unwrap();
    let basic = parsed.basic_constraints().unwrap().unwrap();
    assert!(
        basic.value.ca,
        "the fixture must be CA:TRUE, or it would be refused for the wrong reason"
    );
    let key_usage = parsed.key_usage().unwrap().unwrap();
    assert!(
        !key_usage.value.key_cert_sign(),
        "the fixture must NOT have keyCertSign, or it would be refused for the wrong reason"
    );
    assert!(key_usage.value.crl_sign());

    let mut ks = temp_keystore("issuer-without-key-cert-sign");

    // As a parent for a sub-CA: refused.
    // The fixture issuer's key must live in the keystore for the per-use
    // unwrap: stored under a fresh id, the pairing check passes on the
    // real bytes and the keyCertSign refusal fires on the real cert.
    let parent_key_id = uuid::Uuid::new_v4();
    ks.store_ca_key(&parent_key_id, &key.serialize_der())
        .unwrap();
    let err = create_sub_ca(&cert.pem(), &parent_key_id, &sub_spec(), &mut ks)
        .expect_err("an issuer without keyCertSign must not create a sub-CA");
    match err {
        CaError::X509(msg) => assert!(
            msg.contains("keyCertSign"),
            "the refusal must name the missing keyCertSign, got: {msg}"
        ),
        other => panic!("expected a typed CaError::X509, got {other:?}"),
    }

    // As an issuer for a leaf: refused.
    use ws_ca::issue::{sign_leaf_with, LeafSpec};
    let csr_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut csr_params = rcgen::CertificateParams::default();
    csr_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "victim.example");
    let csr = csr_params.serialize_request(&csr_key).unwrap();
    let err = sign_leaf_with(
        &cert.pem(),
        &key.serialize_der(),
        &csr.pem().unwrap(),
        &LeafSpec {
            sans: vec![],
            key_usages: vec![KeyUsagePurpose::DigitalSignature],
            ekus: vec![ExtKeyUsagePurpose::ServerAuth],
            key_type: LeafKeyType::EcdsaP256,
            lifetime: Duration::days(30),
            subject_cn: None,
            serial: 0x2468,
        },
    )
    .expect_err("an issuer without keyCertSign must not issue a leaf");
    match err {
        CaError::X509(msg) => assert!(
            msg.contains("keyCertSign"),
            "the refusal must name the missing keyCertSign, got: {msg}"
        ),
        other => panic!("expected a typed CaError::X509, got {other:?}"),
    }
}

/// An ECDSA P-256 root: generated natively in rcgen (the leaf-key path's
/// algorithm), self-signed with ecdsa-with-SHA256 (OID 1.2.840.10045.4.3.2,
/// parameters absent per RFC 5758), self-signature verifying through
/// x509-parser's ring backend, and the root's structural properties
/// identical to the Ed25519/RSA roots.
#[test]
fn test_create_root_ecdsa_p256() {
    let mut ks = temp_keystore("root-ecdsa-p256");
    let spec = CaSpec {
        name: "root".to_owned(),
        subject: "Wardstone Test Root ECDSA".to_owned(),
        key_type: KeyType::EcdsaP256,
        lifetime: CaLifetime::Root,
    };
    let created = create_root(&spec, &mut ks).unwrap();

    assert!(created.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    let (_, pem) = parse_x509_pem(created.cert_pem.as_bytes()).unwrap();
    let cert = pem.parse_x509().unwrap();

    assert_eq!(
        cert.signature_algorithm.algorithm.to_id_string(),
        "1.2.840.10045.4.3.2",
        "an ECDSA P-256 root signs itself with ecdsa-with-SHA256"
    );
    cert.verify_signature(None)
        .expect("the ECDSA root self-signature must verify");

    let bc = cert.basic_constraints().unwrap().unwrap();
    assert!(bc.critical, "root BasicConstraints must be critical");
    assert!(bc.value.ca);
    assert_eq!(bc.value.path_len_constraint, None);

    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|c| c.as_str().ok())
        .unwrap();
    assert_eq!(cn, "Wardstone Test Root ECDSA");

    assert!(!ski_critical(&cert), "root SKI must be non-critical");
    assert_random_serial(&cert);
}
