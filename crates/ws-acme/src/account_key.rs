//! JWK-level account-key concerns: the RFC 7638 thumbprint and the
//! alg-key-family pinning table RFC 8555 clients are known to follow.
//! Both read the raw JWK object the client presented (embedded in the
//! protected header) or the account repo resolved (behind a `kid`) — no
//! codec struct in between, so a caller's `serde_json::Value` is enough.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::Algorithm;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::AcmeError;

/// The RFC 7638 JWK thumbprint: SHA-256 over the canonical form of the
/// JWK's required members — lexicographic member order, no whitespace —
/// presented unpadded base64url, exactly as the RFC's RSA worked example
/// pins it (pinned as a test against the RFC's own value).
///
/// Only the key type's REQUIRED members enter the hash (`e`,`kty`,`n` for
/// RSA; `crv`,`kty`,`x`,`y` for EC; `crv`,`kty`,`x` for OKP): optional
/// members a client happens to send (`alg`, `kid`, `use`) are ignored, so
/// the thumbprint is an identity of the key, not of one encoding of it.
pub fn thumbprint(jwk: &Value) -> Result<String, AcmeError> {
    let canonical = canonical_required_members(jwk)?;
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

/// The canonical JSON object of RFC 7638 section 3 step 1: only the key
/// type's required members, ordered lexicographically (the member orders
/// below are already the code-point order), no whitespace anywhere.
fn canonical_required_members(jwk: &Value) -> Result<String, AcmeError> {
    match string_member(jwk, "kty")? {
        "RSA" => Ok(format!(
            r#"{{"e":{},"kty":"RSA","n":{}}}"#,
            json_string(string_member(jwk, "e")?)?,
            json_string(string_member(jwk, "n")?)?,
        )),
        "EC" => Ok(format!(
            r#"{{"crv":{},"kty":"EC","x":{},"y":{}}}"#,
            json_string(string_member(jwk, "crv")?)?,
            json_string(string_member(jwk, "x")?)?,
            json_string(string_member(jwk, "y")?)?,
        )),
        "OKP" => Ok(format!(
            r#"{{"crv":{},"kty":"OKP","x":{}}}"#,
            json_string(string_member(jwk, "crv")?)?,
            json_string(string_member(jwk, "x")?)?,
        )),
        other => Err(AcmeError::Malformed(format!(
            "thumbprint supports RSA, EC and OKP keys, not {other:?}"
        ))),
    }
}

/// A JWK member that must be a string, or the malformed-key refusal.
fn string_member<'a>(jwk: &'a Value, name: &str) -> Result<&'a str, AcmeError> {
    jwk.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| AcmeError::Malformed(format!("JWK member {name:?} must be a string")))
}

/// A string as a JSON string literal. RFC 7638's canonical form quotes
/// every member value; JWK member values are base64url so escaping never
/// actually fires, but the quoting is done properly regardless of what the
/// client sent.
fn json_string(value: &str) -> Result<String, AcmeError> {
    serde_json::to_string(value)
        .map_err(|_| AcmeError::Malformed("member value cannot be canonicalized".to_owned()))
}

/// The one JOSE alg a JWK's key family may present — the alg-key pin:
/// RSA keys only RS256 (the pin is deliberately narrow: no PS256 until an
/// ACME client population asks for it), P-256 EC keys only ES256, P-384
/// EC keys only ES384, Ed25519 OKP keys only EdDSA. Anything else is
/// [`AcmeError::WrongAlgorithm`].
pub(crate) fn permitted_algorithm(key: &Value) -> Result<Algorithm, AcmeError> {
    let kty = key.get("kty").and_then(Value::as_str).unwrap_or("none");
    match kty {
        "RSA" => Ok(Algorithm::RS256),
        "EC" => match key.get("crv").and_then(Value::as_str).unwrap_or("none") {
            "P-256" => Ok(Algorithm::ES256),
            "P-384" => Ok(Algorithm::ES384),
            other => Err(AcmeError::WrongAlgorithm(format!(
                "EC curve {other:?} is not an ACME account-key curve"
            ))),
        },
        "OKP" => match key.get("crv").and_then(Value::as_str).unwrap_or("none") {
            "Ed25519" => Ok(Algorithm::EdDSA),
            other => Err(AcmeError::WrongAlgorithm(format!(
                "OKP curve {other:?} is not an ACME account-key curve"
            ))),
        },
        other => Err(AcmeError::WrongAlgorithm(format!(
            "key type {other:?} is not an ACME account key"
        ))),
    }
}
