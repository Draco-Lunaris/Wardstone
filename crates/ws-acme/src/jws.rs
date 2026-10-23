//! Compact-serialization JWS verification under RFC 8555's protected
//! header requirements.
//!
//! RFC 8555 section 6.2 makes the protected header carry everything the
//! request's authority is decided from — the alg, the account key (as an
//! embedded `jwk` for the new-account style or a `kid` URL otherwise),
//! the anti-replay `nonce`, and the `url` the client bound the JWS to —
//! and section 6.4 puts the request payload INSIDE the JWS, so verifying
//! one compact JWS is the whole admission gate of an ACME POST. This
//! module wires the order those checks may run in: shape first, key and
//! URL before trust, the nonce burned BEFORE the signature verdict (a
//! broken signature still spends the nonce — replays fail even if the
//! attacker keeps breaking their own signatures).
//!
//! jsonwebtoken is the codec below this: `crypto::verify` over the raw
//! compact segments. Every policy decision above it is first-party.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::{crypto, jwk::Jwk as CodecJwk, Algorithm, DecodingKey};
use serde::Deserialize;
use serde_json::Value;

use crate::account_key::permitted_algorithm;
use crate::error::AcmeError;

/// The JWS protected header's members RFC 8555 requires, as parsed from
/// the decoded first segment. Members this crate has no policy for are
/// ignored, not rejected.
#[derive(Debug, Deserialize)]
pub struct JwsHeader {
    /// The JOSE `alg` value, as the client spelled it.
    pub alg: String,
    /// The account-key URL, for the existing-account request style.
    #[serde(default)]
    pub kid: Option<String>,
    /// The embedded account key (public JWK), for the new-account style.
    #[serde(default)]
    pub jwk: Option<Value>,
    /// The anti-replay nonce the server minted.
    #[serde(default)]
    pub nonce: Option<String>,
    /// The `url` the client bound this JWS to (the request target).
    #[serde(default)]
    pub url: Option<String>,
}

/// A fully verified ACME request body: the parsed protected header, the
/// decoded payload, and the JWK the request was verified under.
#[derive(Debug)]
pub struct VerifiedJws {
    pub header: JwsHeader,
    pub payload: Value,
    pub key: Value,
}

/// Verify a compact-serialization JWS against the ACME floor's rules:
///
/// 1. exactly three dot-separated segments, each strictly unpadded
///    base64url, the first a JSON object with an `alg`;
/// 2. the key identified by an embedded `jwk` or a `kid` — never both
///    (`Malformed`), a resolvable `kid` (`NoSuchAccount` when the
///    resolver comes back empty), and never neither;
/// 3. the protected `url` equal to `expected_url` (`Malformed("url
///    mismatch")` otherwise — a JWS minted for one endpoint must not be
///    accepted at another);
/// 4. `alg` within the spoken set **and** matching the key's family (the
///    alg-key pin: [`WrongAlgorithm`](AcmeError::WrongAlgorithm)
///    otherwise);
/// 5. the nonce passing `nonce_check` — the ledger spends it here,
///    before the signature is even looked at, so a request whose
///    signature fails cannot be replayed with the same nonce;
/// 6. the payload (inside the JWS; the empty segment is the
///    POST-as-GET empty string, presented as [`Value::Null`]) decoding
///    to JSON;
/// 7. the signature verifying under the key.
pub fn verify_jws(
    raw: &str,
    resolve_kid: &dyn Fn(&str) -> Result<Option<Value>, AcmeError>,
    nonce_check: &dyn Fn(&str) -> bool,
    expected_url: &str,
) -> Result<VerifiedJws, AcmeError> {
    // (1) compact serialization shape: exactly three segments.
    let segments: Vec<&str> = raw.split('.').collect();
    if segments.len() != 3 {
        return Err(AcmeError::Malformed(
            "a JWS compact serialization is three dot-separated segments".to_owned(),
        ));
    }
    let (protected_b64, payload_b64, signature_b64) = (segments[0], segments[1], segments[2]);

    // (1) the protected header: unpadded base64url JSON with an `alg`.
    let header_bytes = b64url_segment(protected_b64, "protected header")?;
    let header: JwsHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| AcmeError::Malformed("protected header is not valid JSON".to_owned()))?;

    // (2) the signing key, identified exactly one way.
    let key = match (&header.jwk, &header.kid) {
        (Some(_), Some(_)) => {
            return Err(AcmeError::Malformed(
                "jwk and kid must not appear together in the protected header".to_owned(),
            ));
        }
        (Some(jwk), None) => jwk.clone(),
        (None, Some(kid)) => resolve_kid(kid)?.ok_or(AcmeError::NoSuchAccount)?,
        (None, None) => {
            return Err(AcmeError::Malformed(
                "neither jwk nor kid identifies the signing key".to_owned(),
            ));
        }
    };

    // (3) the url binding.
    match header.url.as_deref() {
        Some(url) if url == expected_url => {}
        Some(_) => {
            return Err(AcmeError::Malformed("url mismatch".to_owned()));
        }
        None => {
            return Err(AcmeError::Malformed(
                "protected header is missing its url".to_owned(),
            ));
        }
    }

    // (4) the alg-key pin: the alg must be one we speak AND the one its
    // key family permits.
    let alg = parse_alg(&header.alg)?;
    let permitted = permitted_algorithm(&key)?;
    if alg != permitted {
        return Err(AcmeError::WrongAlgorithm(format!(
            "{} is not permitted for a {} key",
            header.alg,
            key.get("kty").and_then(Value::as_str).unwrap_or("unknown"),
        )));
    }

    // (5) the anti-replay nonce — spent before the signature verdict, so
    // single-use holds regardless of how the verification comes out. An
    // absent nonce is the failure too: RFC 8555's protected header must
    // carry one, and without it there is nothing to spend.
    let nonce = header.nonce.as_deref().ok_or(AcmeError::BadNonce)?;
    if !nonce_check(nonce) {
        return Err(AcmeError::BadNonce);
    }

    // (6) the payload rides inside the JWS (RFC 8555 section 6.4); the
    // empty segment is the POST-as-GET empty string.
    let payload = if payload_b64.is_empty() {
        Value::Null
    } else {
        let payload_bytes = b64url_segment(payload_b64, "payload")?;
        serde_json::from_slice(&payload_bytes)
            .map_err(|_| AcmeError::Malformed("payload is not valid JSON".to_owned()))?
    };

    // (7) the signature: jsonwebtoken's raw verify over the signing
    // input exactly as it rode the wire. The signature segment is
    // alphabet-checked here so a padded or foreign one is a `Malformed`
    // request, not a failed verdict.
    if URL_SAFE_NO_PAD.decode(signature_b64).is_err() {
        return Err(AcmeError::Malformed(
            "signature is not unpadded base64url".to_owned(),
        ));
    }
    let signing_input = format!("{protected_b64}.{payload_b64}");
    let codec_jwk: CodecJwk = serde_json::from_value(key.clone())
        .map_err(|_| AcmeError::Malformed("signing key is not a usable JWK".to_owned()))?;
    let decoding_key = DecodingKey::from_jwk(&codec_jwk).map_err(|_| {
        AcmeError::Malformed("signing key is not usable for verification".to_owned())
    })?;
    let verified = crypto::verify(signature_b64, signing_input.as_bytes(), &decoding_key, alg)
        .map_err(|_| AcmeError::BadSignature)?;
    if !verified {
        return Err(AcmeError::BadSignature);
    }

    Ok(VerifiedJws {
        header,
        payload,
        key,
    })
}

/// Strictly decode one base64url segment: the unpadded alphabet only, no
/// padding tolerance (RFC 7515's base64url has none).
fn b64url_segment(segment: &str, name: &str) -> Result<Vec<u8>, AcmeError> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| AcmeError::Malformed(format!("{name} is not unpadded base64url")))
}

/// The algs this ACME floor speaks (RFC 8555 section 6.4's set for the
/// house's key families, plus ES384 for P-384 account keys). Everything
/// else — HMAC families included — is a rejected algorithm, not a
/// signature failure.
fn parse_alg(alg: &str) -> Result<Algorithm, AcmeError> {
    match alg {
        "RS256" => Ok(Algorithm::RS256),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "EdDSA" => Ok(Algorithm::EdDSA),
        other => Err(AcmeError::WrongAlgorithm(format!(
            "{other:?} is not an ACME request algorithm"
        ))),
    }
}
