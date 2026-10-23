//! Fixture keys and ACME JWS construction helpers for the ws-api ACME
//! route suite — the ws-acme suite's `tests/common` pattern trimmed to the
//! client's side: test keys minted AT TEST TIME through the host openssl
//! CLI (so real ACME-client-shaped key material runs the same
//! `rust_crypto` signing backend), and compact-JWS builders that speak the
//! RFC 8555 protected-header shape (alg + jwk-or-kid + nonce + url).
//!
//! Key material is generated once per suite binary via `OnceLock`; a suite
//! signs requests as an ACME client would — one request per nonce, the
//! nonce fetched beforehand from the server's own `Replay-Nonce` answers.

// Shared helpers; not every test drives every one, so the per-binary
// dead-code warnings are noise.
#![allow(dead_code)]

use std::process::{Command, Stdio};
use std::sync::OnceLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey};
use serde_json::{json, Value};

/// A key fixture: the private encoding key for signing, the public JWK
/// the tests embed or resolve, the JOSE alg, and its wire name.
pub struct KeyFixture {
    pub encoding_key: EncodingKey,
    pub jwk: Value,
    pub alg: Algorithm,
    /// The JOSE `alg` header string for this key family.
    pub alg_name: &'static str,
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

/// Run openssl with the PEM on stdin, stdout as bytes (to re-serialize the
/// private key into the SPKI DER whose tail is the Ed25519 public key).
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
    fn generate(kind: &str, algorithm: Algorithm, alg_name: &'static str) -> Self {
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
            "ED25519" => &["genpkey", "-algorithm", "ed25519"],
            other => unreachable!("unknown fixture kind {other}"),
        };
        let pem = openssl_text(gen_args);
        let encoding_key = match kind {
            "RSA2048" => EncodingKey::from_rsa_pem(pem.as_bytes()),
            "P256" => EncodingKey::from_ec_pem(pem.as_bytes()),
            "ED25519" => EncodingKey::from_ed_pem(pem.as_bytes()),
            _ => unreachable!("unknown fixture kind {kind}"),
        }
        .expect("openssl's PKCS#8 PEM parses as a JOSE key");
        let jwk = match kind {
            "ED25519" => {
                // jsonwebtoken's `Jwk::from_encoding_key` is `unimplemented!()`
                // for the Ed family, so the OKP JWK is built by hand: the
                // Ed25519 SPKI DER is the fixed AlgorithmIdentifier prefix
                // followed by the 32-byte raw public key.
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
            alg_name,
        }
    }
}

/// An RSA-2048 key (RS256) — the account key most tests register.
pub fn rsa2048() -> &'static KeyFixture {
    static KEY: OnceLock<KeyFixture> = OnceLock::new();
    KEY.get_or_init(|| KeyFixture::generate("RSA2048", Algorithm::RS256, "RS256"))
}

/// A P-256 EC key (ES256) — the rollover target and the second IP's key.
pub fn p256() -> &'static KeyFixture {
    static KEY: OnceLock<KeyFixture> = OnceLock::new();
    KEY.get_or_init(|| KeyFixture::generate("P256", Algorithm::ES256, "ES256"))
}

/// An Ed25519 OKP key (EdDSA) — the third account key (the second peer's
/// rate-limit request).
pub fn ed25519() -> &'static KeyFixture {
    static KEY: OnceLock<KeyFixture> = OnceLock::new();
    KEY.get_or_init(|| KeyFixture::generate("ED25519", Algorithm::EdDSA, "EdDSA"))
}

/// What the protected header authenticates with: an existing account's
/// kid URL, or the embedded JWK (new-account style). `Bare` carries NEITHER
/// (a malformed request the verifier must refuse).
pub enum Identity {
    Kid(String),
    Jwk,
    /// NEITHER jwk nor kid — the "no key identified" refusal.
    Bare,
}

/// Missing-nonce case).
pub fn sign_with_header(key: &KeyFixture, header: &Value, payload: &Value) -> String {
    let protected = B64URL.encode(header.to_string());
    let payload_segment = match payload {
        Value::Null => String::new(),
        p => B64URL.encode(p.to_string()),
    };
    let signing_input = format!("{protected}.{payload_segment}");
    let signature =
        jsonwebtoken::crypto::sign(signing_input.as_bytes(), &key.encoding_key, key.alg)
            .expect("fixture signature computes under the fixture key");
    format!("{protected}.{payload_segment}.{signature}")
}

/// Sign a client request as RFC 8555 §6.2 puts it ON THE WIRE: the JWS
/// flattened JSON serialization (`{"protected","payload","signature"}` —
/// the JOSE floor verifies the compact form that these same three b64url
/// segments re-express). A `Value::Null` payload stays the empty
/// (POST-as-GET) payload segment, mirroring the wire form.
pub fn sign_acme_request(
    key: &KeyFixture,
    identity: &Identity,
    nonce: &str,
    url: &str,
    payload: &Value,
) -> String {
    let mut header = json!({ "alg": key.alg_name, "nonce": nonce, "url": url });
    match identity {
        Identity::Kid(kid) => header["kid"] = json!(kid),
        Identity::Jwk => header["jwk"] = key.jwk.clone(),
        Identity::Bare => {}
    }
    let compact = sign_with_header(key, &header, payload);
    serde_json::to_string(&inner_jws_object(&compact))
        .expect("the flattened envelope always serializes")
}

/// Build a client-side ACME request AS a compact JWS: a low-level builder
/// whose protected header carries the alg, the identity members, the
/// `nonce`, and the `url` the request binds to. A `Value::Null` payload
/// produces the empty (POST-as-GET) payload segment, mirroring the wire
/// form. NOTE: compact is the INTERNAL shape (the JOSE floor verifies it;
/// RFC 8555 puts the flattened JSON serialization on the wire — wrap with
/// `inner_jws_object` + serialize for on-wire bodies).

/// A signed-elsewhere JWS rendered as RFC 8555 §7.3.5's flattened JSON
/// serialization — the `{"protected","payload","signature"}` object the
/// OUTER key-change JWS carries as its payload.
pub fn inner_jws_object(compact: &str) -> Value {
    let mut parts = compact.split('.');
    let protected = parts.next().expect("a compact JWS has a protected");
    let payload = parts.next().expect("a compact JWS has a payload");
    let signature = parts.next().expect("a compact JWS has a signature");
    json!({ "protected": protected, "payload": payload, "signature": signature })
}

/// Corrupt the signature: flips the FIRST character of the signature
/// segment into the other member of a four-bit-safe pair. (The FINAL
/// characters sit in base64's last group, where a flip can land in the
/// non-canonical trailing bits and fail the BASE64 decode — a `malformed`
/// refusal — instead of the signature verdict the trap is about.)
pub fn tamper_signature(token: &str) -> String {
    let envelope: serde_json::Value = serde_json::from_str(token)
        .expect("the token is the RFC 8555 flattened JSON serialization");
    let signature = envelope["signature"]
        .as_str()
        .expect("the flattened envelope carries a signature field");
    let mut chars = signature.chars();
    let first = chars.next().expect("a signature field is non-empty");
    let replacement = if first == 'A' { 'B' } else { 'A' };
    let tampered_signature = format!("{}{}", replacement, chars.as_str());
    let mut envelope = envelope;
    envelope["signature"] = serde_json::Value::String(tampered_signature);
    serde_json::to_string(&envelope).expect("the tampered envelope serializes")
}
