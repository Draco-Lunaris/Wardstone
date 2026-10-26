//! Integration tests for `ws_ca::crl` — the hand-rolled DER CRL builder.
//!
//! Pure tests, no database: a CRL is built from an in-process Ed25519 root
//! (temp-dir keystore, the same pattern as `ca_creation_test` /
//! `issue_test`) and verified three ways:
//!
//! 1. Structurally, with x509-parser: PEM label, version v2, issuer equal to
//!    the CA subject, every serial listed in order, reason-code entry
//!    extensions with the RFC 5280 codes, the AKI equal to the CA's SKI, no
//!    CRL Number extension, and `next_update` exactly 24h after
//!    `issued_at`.
//! 2. In Rust, with x509-parser's ring-backed `verify_signature` against
//!    the CA certificate's public key.
//! 3. For interop, with stock OpenSSL: `openssl crl -text` lists every
//!    serial and `openssl crl -CAfile` prints `verify OK`. The OpenSSL
//!    checks shell out only when the binary exists and otherwise skip with
//!    a printed note (pinned requirement from the task brief).
//!
//! OpenSSL renders CRL serials as uppercase hex with leading zero bytes
//! stripped, so the substring assertions lowercase the `-text` output
//! before matching the lowercase `format!("{serial:x}")` forms.

use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::Command;

use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::FromDer;
use x509_parser::revocation_list::CertificateRevocationList;
use x509_parser::x509::X509Version;

use ws_ca::ca::{create_root, CaLifetime, CaSpec, KeyType};
use ws_ca::crl::{build_crl, CrlReason, CrlSpec, RevocationEntry};
use ws_ca::keystore::KeyStore;

/// The three revoked serials the fixture CRL carries, exercising the DER
/// INTEGER encoding corners: a value whose u128 form has leading zero bytes
/// (`0x00ff…`; OpenSSL renders it without them — `FFABCD12345678`), a
/// 128-bit value with the high bit set (`0x8000…01`, which DER encodes with
/// a leading `0x00` sign octet), and a single-octet value.
const SERIALS: [u128; 3] = [
    0x00ff_abcd_1234_5678,
    0x8000_0000_0000_0000_0000_0000_0000_0001,
    0x42,
];

/// The reason fixture paired with each serial by index: no extension at
/// all, a reason extension, and a different reason code.
const REASONS: [Option<CrlReason>; 3] = [
    None,
    Some(CrlReason::KeyCompromise),
    Some(CrlReason::CessationOfOperation),
];

/// Per-test temp keystore, mirroring the keystore and creation suites'
/// pattern: unique per test name and process id, swept before use so stale
/// runs can't interfere. The store is UNLOCKED (the seal-at-creation
/// custody): the master is minted straight into the protected arena — no
/// plaintext master file exists anywhere.
fn temp_keystore(test_name: &str) -> KeyStore {
    let dir = std::env::temp_dir().join(format!("ws-ca-crl-{test_name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let mem = ws_secmem::global().expect("the protected pool initializes");
    KeyStore::open_unlocked(
        &dir,
        mem.alloc_copy(&[7u8; 32])
            .expect("the arena holds the test master"),
    )
    .expect("open the unlocked test key store")
}

/// The Ed25519 root CA every test builds its CRL against.
fn root_spec() -> CaSpec {
    CaSpec {
        name: "crl-test-root".to_owned(),
        subject: "Wardstone Test CRL Root".to_owned(),
        key_type: KeyType::Ed25519,
        lifetime: CaLifetime::Root,
    }
}

/// The revocation instant of the fixture entry at `index`: one fixed
/// instant, one hour apart per entry, so every entry carries a distinct
/// date that the test can pin against the value the fixture supplied
/// (RFC 5280 section 5.1: the entry's revocationDate is when the
/// certificate was revoked, not when the CRL was built).
fn revoked_at(index: usize) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-03-04T05:06:07Z")
        .expect("valid fixed test timestamp")
        .with_timezone(&chrono::Utc)
        + chrono::Duration::hours(index as i64)
}

/// The CRL fixture: three revocations, next update 24h out.
fn crl_spec() -> CrlSpec {
    CrlSpec {
        revocations: SERIALS
            .iter()
            .zip(REASONS.iter())
            .enumerate()
            .map(|(index, (&serial, &reason))| RevocationEntry {
                serial,
                reason,
                revoked_at: revoked_at(index),
            })
            .collect(),
        next_update: chrono::Duration::hours(24),
    }
}

/// The CA certificate's SubjectKeyIdentifier bytes (parsed extension).
fn ski_bytes(cert: &X509Certificate<'_>) -> Vec<u8> {
    cert.iter_extensions()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(ki) => Some(ki.0.to_vec()),
            _ => None,
        })
        .expect("SubjectKeyIdentifier extension present")
}

/// The CRL's AuthorityKeyIdentifier extension as (critical, keyIdentifier).
fn crl_aki(crl: &CertificateRevocationList<'_>) -> (bool, Vec<u8>) {
    crl.tbs_cert_list
        .iter_extensions()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(aki) => aki
                .key_identifier
                .as_ref()
                .map(|ki| (ext.critical, ki.0.to_vec())),
            _ => None,
        })
        .expect("CRL carries an AuthorityKeyIdentifier extension with keyIdentifier")
}

/// A scratch file path under the system temp dir, unique per test name and
/// process id, for handing PEMs to the OpenSSL subprocess.
fn temp_pem(test_name: &str, suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ws-ca-crl-{test_name}-{}-{suffix}.pem",
        std::process::id()
    ))
}

/// Build the fixture CRL: one call shared by both tests so they assert on
/// the same bytes.
fn build_fixture_crl(root: &ws_ca::ca::CreatedCa) -> ws_ca::crl::CrlFile {
    build_crl(&root.cert_pem, root.private_key_der.as_slice(), &crl_spec()).unwrap()
}

/// A CRL entry with the `removeFromCRL` reason is REFUSED.
///
/// RFC 5280 section 5.3.1 code 8 means "the certificate was revoked and
/// is now reinstated" — a verifier reads it as GOOD. Encoding it for an
/// entry that is still revoked would make the CRL say "not revoked"
/// while the database says `revoked`, and the CRL and the OCSP answer
/// would contradict each other. A revocation is terminal in this plan,
/// so the builder refuses the reason instead of emitting it.
#[test]
fn test_crl_refuses_remove_from_crl_reason() {
    let mut ks = temp_keystore("refuses-remove-from-crl");
    let root = create_root(&root_spec(), &mut ks).unwrap();

    let spec = CrlSpec {
        revocations: vec![RevocationEntry {
            serial: 0x42,
            reason: Some(CrlReason::RemoveFromCRL),
            revoked_at: revoked_at(0),
        }],
        next_update: chrono::Duration::hours(24),
    };

    let err = build_crl(&root.cert_pem, root.private_key_der.as_slice(), &spec)
        .expect_err("a removeFromCRL entry must be refused");
    match err {
        ws_ca::error::CaError::X509(msg) => assert!(
            msg.contains("removeFromCRL"),
            "the refusal must name the reason, got: {msg}"
        ),
        other => panic!("expected a typed CaError::X509, got {other:?}"),
    }
}

/// A CRL entry with serial 0 is REFUSED.
///
/// RFC 5280 section 4.1.2.2 requires serial numbers to be positive.
/// The DER `Uint` encoder would emit `INTEGER 0` for it — a negative
/// INTEGER under DER's two's-complement reading. The leaf issuance path
/// already rejects serial 0; the CRL builder must too.
#[test]
fn test_crl_refuses_serial_zero() {
    let mut ks = temp_keystore("refuses-serial-zero");
    let root = create_root(&root_spec(), &mut ks).unwrap();

    let spec = CrlSpec {
        revocations: vec![RevocationEntry {
            serial: 0,
            reason: Some(CrlReason::KeyCompromise),
            revoked_at: revoked_at(0),
        }],
        next_update: chrono::Duration::hours(24),
    };

    let err = build_crl(&root.cert_pem, root.private_key_der.as_slice(), &spec)
        .expect_err("a serial-0 entry must be refused");
    match err {
        ws_ca::error::CaError::X509(msg) => assert!(
            msg.contains("positive integer"),
            "the refusal must name the positivity requirement, got: {msg}"
        ),
        other => panic!("expected a typed CaError::X509, got {other:?}"),
    }
}

/// The built CRL carries every revoked serial in order, with the pinned
/// v2 structure: bare-INTEGER version, issuer byte-identical to the CA
/// subject, reason-code entry extensions, a non-critical AKI matching the
/// CA's SKI, no CRL Number extension, and `next_update` exactly 24h after
/// `issued_at`. Stock OpenSSL's `-text` rendering lists all three serials.
#[test]
fn test_crl_lists_all_serials() {
    let mut ks = temp_keystore("lists-all-serials");
    let root = create_root(&root_spec(), &mut ks).unwrap();
    let file = build_fixture_crl(&root);

    // PEM shape: the label OpenSSL writes and expects for CRLs.
    assert!(file.crl_pem.starts_with("-----BEGIN X509 CRL-----"));
    assert!(file.crl_pem.contains("-----END X509 CRL-----"));

    let (_, crl_pem_block) = parse_x509_pem(file.crl_pem.as_bytes()).unwrap();
    assert_eq!(crl_pem_block.label, "X509 CRL");
    let (_, crl) = CertificateRevocationList::from_der(&crl_pem_block.contents).unwrap();
    let (_, ca_pem_block) = parse_x509_pem(root.cert_pem.as_bytes()).unwrap();
    let ca_cert = ca_pem_block.parse_x509().unwrap();

    // Version 2 (a bare INTEGER 1, not the certificate-style [0] wrapper).
    assert_eq!(crl.version(), Some(X509Version::V2));

    // Issuer: the CA certificate's subject Name TLV, spliced verbatim.
    assert_eq!(crl.issuer().as_raw(), ca_cert.subject().as_raw());

    // Every serial, in the order given, as a minimal decimal string (the
    // BigUint Display matches u128 Display byte for byte).
    let listed: Vec<String> = crl
        .iter_revoked_certificates()
        .map(|entry| entry.serial().to_string())
        .collect();
    let expected: Vec<String> = SERIALS.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        listed, expected,
        "all three serials must be listed in order"
    );

    // Reason codes: RFC 5280 ENUMERATED values, non-critical, absent for a
    // None reason.
    let entries: Vec<_> = crl.iter_revoked_certificates().collect();
    for (entry, expected) in entries.iter().zip(REASONS.iter()) {
        match expected {
            None => {
                assert!(entry.reason_code().is_none());
                assert!(
                    entry.extensions().is_empty(),
                    "no entry extensions when the reason is None"
                );
            }
            Some(reason) => {
                let (critical, code) = entry.reason_code().expect("reason-code extension present");
                assert!(
                    !critical,
                    "reason-code entry extension must be non-critical"
                );
                assert_eq!(code.0, reason.as_code().expect("reason code is emittable"));
            }
        }
    }

    // Entry revocation dates are the instants the fixture supplied — the
    // moment each certificate was revoked, not the CRL's issue instant.
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(
            entry.revocation_date.timestamp(),
            revoked_at(index).timestamp(),
            "entry {index} must carry its own revocation date"
        );
    }

    // thisUpdate/nextUpdate: exactly `issued_at` and `issued_at + 24h`.
    assert_eq!(crl.last_update().timestamp(), file.issued_at.timestamp());
    let next = crl.next_update().expect("nextUpdate present");
    assert_eq!(
        next.timestamp(),
        (file.issued_at + chrono::Duration::hours(24)).timestamp()
    );

    // crlExtensions: exactly the AKI, non-critical, keyIdentifier equal to
    // the CA's SKI — and no CRL Number extension.
    let exts: Vec<&x509_parser::extensions::X509Extension<'_>> =
        crl.tbs_cert_list.iter_extensions().collect();
    assert_eq!(exts.len(), 1, "only the AKI crl extension is emitted");
    let (critical, aki) = crl_aki(&crl);
    assert!(!critical, "the AKI crl extension must be non-critical");
    assert_eq!(
        aki,
        ski_bytes(&ca_cert),
        "AKI keyIdentifier equals the CA SKI"
    );
    assert!(
        !exts
            .iter()
            .any(|ext| matches!(ext.parsed_extension(), ParsedExtension::CRLNumber(_))),
        "no CRL Number extension is emitted"
    );

    // Stock OpenSSL interop: `-text` lists every serial. OpenSSL prints
    // serials uppercase with leading zero bytes stripped, so lowercase the
    // output before matching the lowercase hex forms.
    let crl_path = temp_pem("lists-all-serials", "crl");
    fs::write(&crl_path, &file.crl_pem).unwrap();
    let out = Command::new("openssl")
        .arg("crl")
        .arg("-in")
        .arg(&crl_path)
        .arg("-noout")
        .arg("-text")
        .output();
    let _ = fs::remove_file(&crl_path);
    match out {
        Ok(out) if out.status.success() => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
            .to_lowercase();
            for serial in SERIALS {
                assert!(
                    text.contains(&format!("{serial:x}")),
                    "openssl -text must list serial {serial:x}:\n{text}"
                );
            }
        }
        Ok(out) => {
            panic!(
                "openssl crl -text failed: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            eprintln!("note: openssl binary not found; skipping the openssl -text serial check");
        }
        Err(e) => panic!("failed to spawn openssl: {e}"),
    }
}

/// The built CRL's signature verifies: in Rust via x509-parser's
/// ring-backed `verify_signature` against the CA certificate (runs even
/// when OpenSSL is absent), and with stock `openssl crl -CAfile`, which
/// must print `verify OK`.
#[test]
fn test_crl_openssl_verifies() {
    let mut ks = temp_keystore("openssl-verifies");
    let root = create_root(&root_spec(), &mut ks).unwrap();
    let file = build_fixture_crl(&root);

    // Rust-side verification against the CA certificate's public key.
    let (_, crl_pem_block) = parse_x509_pem(file.crl_pem.as_bytes()).unwrap();
    let (_, crl) = CertificateRevocationList::from_der(&crl_pem_block.contents).unwrap();
    let (_, ca_pem_block) = parse_x509_pem(root.cert_pem.as_bytes()).unwrap();
    let ca_cert = ca_pem_block.parse_x509().unwrap();
    crl.verify_signature(ca_cert.public_key())
        .expect("CRL signature must verify against the CA certificate");

    // Stock OpenSSL verification. `verify OK` goes to stdout on some
    // builds and stderr on others, so check both.
    let crl_path = temp_pem("openssl-verifies", "crl");
    let ca_path = temp_pem("openssl-verifies", "ca");
    fs::write(&crl_path, &file.crl_pem).unwrap();
    fs::write(&ca_path, &root.cert_pem).unwrap();
    let out = Command::new("openssl")
        .arg("crl")
        .arg("-in")
        .arg(&crl_path)
        .arg("-CAfile")
        .arg(&ca_path)
        .arg("-noout")
        .output();
    let _ = fs::remove_file(&crl_path);
    let _ = fs::remove_file(&ca_path);
    match out {
        Ok(out) => {
            assert!(
                out.status.success(),
                "openssl crl -CAfile failed: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                text.contains("verify OK"),
                "expected 'verify OK', got: {text}"
            );
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            eprintln!(
                "note: openssl binary not found; skipping the OpenSSL signature verification"
            );
        }
        Err(e) => panic!("failed to spawn openssl: {e}"),
    }
}

/// A CRL from an ECDSA P-256 CA: the signature algorithm is
/// ecdsa-with-SHA256 with parameters ABSENT (RFC 5758), the signature
/// verifies in Rust via x509-parser, and stock `openssl crl -CAfile`
/// prints `verify OK` when the binary exists — the same three layers as
/// the Ed25519 CRL above.
#[test]
fn test_crl_from_ecdsa_root_verifies() {
    let mut ks = temp_keystore("ecdsa-root");
    let root = create_root(
        &CaSpec {
            name: "crl-ecdsa-root".to_owned(),
            subject: "Wardstone Test CRL Root ECDSA".to_owned(),
            key_type: KeyType::EcdsaP256,
            lifetime: CaLifetime::Root,
        },
        &mut ks,
    )
    .unwrap();
    let file = build_crl(&root.cert_pem, root.private_key_der.as_slice(), &crl_spec())
        .expect("an ECDSA CA builds a CRL with no UnsupportedKeyType");

    // Rust-side verification against the CA certificate's public key.
    let (_, crl_pem_block) = parse_x509_pem(file.crl_pem.as_bytes()).unwrap();
    let (_, crl) = CertificateRevocationList::from_der(&crl_pem_block.contents).unwrap();
    assert_eq!(
        crl.signature_algorithm.algorithm.to_id_string(),
        "1.2.840.10045.4.3.2",
        "the CRL signature algorithm follows the ECDSA CA key"
    );
    assert!(
        crl.signature_algorithm.parameters.is_none(),
        "the ECDSA AlgorithmIdentifier must carry ABSENT parameters (RFC 5758 \
         forbids the NULL encoding)"
    );
    let (_, ca_pem_block) = parse_x509_pem(root.cert_pem.as_bytes()).unwrap();
    let ca_cert = ca_pem_block.parse_x509().unwrap();
    crl.verify_signature(ca_cert.public_key())
        .expect("CRL signature must verify against the ECDSA CA");

    // Stock OpenSSL verification, exactly the Ed25519 CRL's interop gate.
    let crl_path = temp_pem("ecdsa-root", "crl");
    let ca_path = temp_pem("ecdsa-root", "ca");
    fs::write(&crl_path, &file.crl_pem).unwrap();
    fs::write(&ca_path, &root.cert_pem).unwrap();
    let out = Command::new("openssl")
        .arg("crl")
        .arg("-in")
        .arg(&crl_path)
        .arg("-CAfile")
        .arg(&ca_path)
        .arg("-noout")
        .output();
    let _ = fs::remove_file(&crl_path);
    let _ = fs::remove_file(&ca_path);
    match out {
        Ok(out) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                out.status.success() && text.contains("verify OK"),
                "openssl must verify the ECDSA-signed CRL, got: {text}"
            );
        }
        Err(_) => println!("openssl absent: skipping the ECDSA CRL interop check"),
    }
}
