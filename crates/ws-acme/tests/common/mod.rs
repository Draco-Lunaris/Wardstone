//! Fixture keys and JWS construction helpers shared by the ws-acme
//! integration suites.
//!
//! Keys are minted AT TEST TIME with the host's openssl CLI (the house
//! fixture pattern — the same pipeline real ACME client key material
//! passes through), then loaded through jsonwebtoken's own PEM entry
//! points, so the suites exercise the exact `rust_crypto` signing and
//! verification backends the crate's production verification uses. One
//! `KeyFixture` per supported key family, cached per suite binary via
//! `OnceLock` so the RSA-2048 generation cost is paid at most once.

// Fixture helpers are shared across suites; not every suite drives every
// helper, so the per-binary dead-code warnings are noise.
#![allow(dead_code)]

use std::process::{Command, Stdio};
use std::sync::OnceLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use jsonwebtoken::{jwk::Jwk, Algorithm, EncodingKey};
use serde_json::{json, Value};

/// The protected-header `url` the happy-path requests bind to (and the
/// `expected_url` the verifications demand).
pub const DIRECTORY_URL: &str = "https://acme.wardstone.test/acme/new-order";

/// A key fixture: the private encoding key for signing fixtures, the
/// public JWK the tests embed or resolve, and the matching JOSE alg.
pub struct KeyFixture {
    pub encoding_key: EncodingKey,
    pub jwk: Value,
    pub alg: Algorithm,
}

/// Run openssl, stdout as text.
fn openssl_text(args: &[&str]) -> String {
    let out = Command::new("openssl")
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .expect("spawn openssl");
    assert!(out.status.success(), "openssl {args:?} failed");
    String::from_utf8(out.stdout).expect("openssl writes UTF-8 PEMs")
}

/// Run openssl with the PEM on stdin, stdout as bytes (used to re-serialize
/// a private key into the SPKI DER whose tail is the Ed25519 public key).
fn openssl_bytes_from_stdin(args: &[&str], input: &str) -> Vec<u8> {
    use std::io::Write as _;
    let mut child = Command::new("openssl")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn openssl");
    child
        .stdin
        .as_mut()
        .expect("piped stdin")
        .write_all(input.as_bytes())
        .expect("feed openssl");
    let out = child.wait_with_output().expect("wait for openssl");
    assert!(out.status.success(), "openssl {args:?} failed");
    out.stdout
}

impl KeyFixture {
    fn generate(kind: &str, algorithm: Algorithm) -> Self {
        let gen_args: &[&str] = match kind {
            "RSA2048" => &[
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ],
            "P256" => &[
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
            ],
            "P384" => &[
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-384",
            ],
            "ED25519" => &["genpkey", "-algorithm", "ed25519"],
            other => unreachable!("unknown fixture kind {other}"),
        };
        let pem = openssl_text(gen_args);
        let encoding_key = match kind {
            "RSA2048" => EncodingKey::from_rsa_pem(pem.as_bytes()),
            "P256" | "P384" => EncodingKey::from_ec_pem(pem.as_bytes()),
            "ED25519" => EncodingKey::from_ed_pem(pem.as_bytes()),
            _ => unreachable!("unknown fixture kind {kind}"),
        }
        .expect("openssl's PKCS#8 PEM parses as a JOSE key");
        let jwk = match kind {
            "ED25519" => {
                // jsonwebtoken's `Jwk::from_encoding_key` is `unimplemented!()`
                // for the Ed family, so the OKP JWK is built by hand: the
                // Ed25519 SPKI DER is the fixed 12-byte AlgorithmIdentifier
                // prefix followed by the 32-byte raw public key, so the key
                // is the DER's tail.
                let der = openssl_bytes_from_stdin(&["pkey", "-pubout", "-outform", "DER"], &pem);
                json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": B64URL.encode(&der[der.len() - 32..]),
                })
            }
            _ => serde_json::to_value(
                Jwk::from_encoding_key(&encoding_key, algorithm).expect("fixture JWK"),
            )
            .expect("JWK serializes"),
        };
        Self {
            encoding_key,
            jwk,
            alg: algorithm,
        }
    }
}

/// An RSA-2048 key, the RS256 fixture.
pub fn rsa2048() -> &'static KeyFixture {
    static KEY: OnceLock<KeyFixture> = OnceLock::new();
    KEY.get_or_init(|| KeyFixture::generate("RSA2048", Algorithm::RS256))
}

/// A P-256 EC key, the ES256 fixture.
pub fn p256() -> &'static KeyFixture {
    static KEY: OnceLock<KeyFixture> = OnceLock::new();
    KEY.get_or_init(|| KeyFixture::generate("P256", Algorithm::ES256))
}

/// A P-384 EC key, the ES384 fixture.
pub fn p384() -> &'static KeyFixture {
    static KEY: OnceLock<KeyFixture> = OnceLock::new();
    KEY.get_or_init(|| KeyFixture::generate("P384", Algorithm::ES384))
}

/// An Ed25519 OKP key, the EdDSA fixture.
pub fn ed25519() -> &'static KeyFixture {
    static KEY: OnceLock<KeyFixture> = OnceLock::new();
    KEY.get_or_init(|| KeyFixture::generate("ED25519", Algorithm::EdDSA))
}

/// A representative ACME request payload (this crate keeps payload
/// handling generic: any JSON object rides inside the JWS).
pub fn payload_object() -> Value {
    json!({
        "identifiers": [{ "type": "dns", "value": "wardstone.test" }]
    })
}

/// A well-formed protected header in the embedded-j style (new account).
pub fn embedded_header(alg: &str, key: &KeyFixture, nonce: &str) -> Value {
    json!({ "alg": alg, "jwk": key.jwk, "nonce": nonce, "url": DIRECTORY_URL })
}

/// A well-formed protected header in the kid style (existing account).
pub fn kid_header(alg: &str, kid: &str, nonce: &str) -> Value {
    json!({ "alg": alg, "kid": kid, "nonce": nonce, "url": DIRECTORY_URL })
}

/// A freshly minted nonce from a private ledger, ready for one request.
pub fn minted_nonce() -> String {
    ws_acme::NonceStore::new().mint()
}

/// Build a compact JWS over the header and payload under the fixture's
/// key. A `Value::Null` payload produces the empty (POST-as-GET) payload
/// segment, mirroring the wire form.
pub fn sign_jws(header: &Value, payload: &Value, key: &KeyFixture) -> String {
    let protected = B64URL.encode(header.to_string());
    let payload = match payload {
        Value::Null => String::new(),
        p => B64URL.encode(p.to_string()),
    };
    let signing_input = format!("{protected}.{payload}");
    let signature =
        jsonwebtoken::crypto::sign(signing_input.as_bytes(), &key.encoding_key, key.alg)
            .expect("fixture signature computes under the fixture key");
    format!("{protected}.{payload}.{signature}")
}

/// Replace the payload segment of a well-signed JWS with a re-encoded
/// different payload: the signature no longer covers what is asserted.
pub fn swap_payload(token: &str, payload: &Value) -> String {
    let mut parts: Vec<&str> = token.split('.').collect();
    let replacement = B64URL.encode(payload.to_string());
    parts[1] = &replacement;
    parts.join(".")
}

/// Corrupt the signature: flips the FIRST character of the signature
/// segment into the other member of a four-bit-safe pair, so the string
/// stays valid canonically-padded-free base64url while almost certainly no
/// longer matching the signature. (The FINAL characters sit in base64's
/// last group, where a flip can land in the non-canonical trailing bits and
/// fail the BASE64 decode — a `malformed` refusal — instead of the
/// signature verdict the trap is about; the base64 crate rejects trailing
/// bits that are not zero. The first character is a full 6-bit group: it
/// corrupts the top signature byte without ever touching the canonicality
/// of the segment.)
pub fn tamper_signature(token: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    let signature = parts[2];
    let mut chars = signature.chars();
    let first = chars.next().expect("a signature segment is non-empty");
    let replacement = if first == 'A' { 'B' } else { 'A' };
    format!(
        "{}.{}.{}{}",
        parts[0],
        parts[1],
        replacement,
        chars.as_str()
    )
}
