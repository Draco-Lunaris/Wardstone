//! The RFC 7638 thumbprint suite: the RFC's own worked example pinned
//! byte-for-byte, tolerance of optional members, an OKP fixed vector, a
//! cross-implementation agreement check with jsonwebtoken's codec, and the
//! malformed-key refusals.

mod common;

use serde_json::{json, Value};

use ws_acme::{thumbprint, AcmeError};

/// RFC 7638 section 3.1's RSA JWK exactly as the RFC presents it (optionals
/// `alg` and `kid` included, display line-wrapping undone). The RFC's
/// canonical JSON is `{"e":"AQAB","kty":"RSA","n":"0vx7...DKgw"}` and its
/// stated SHA-256 thumbprint is `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`.
fn rfc7638_rsa_jwk() -> Value {
    json!({
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB",
        "alg": "RS256",
        "kid": "2011-04-29"
    })
}

#[test]
fn rfc7638_worked_example() {
    let jwk = rfc7638_rsa_jwk();
    assert_eq!(
        thumbprint(&jwk).expect("the RFC's key thumbprints"),
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
}

#[test]
fn extra_members_do_not_change_the_thumbprint() {
    // Same key with the optionals re-added/re-spelled and members in a
    // different insertion order: the thumbprint is a key identity.
    let mut jwk = rfc7638_rsa_jwk();
    jwk["use"] = json!("sig");
    jwk["extra"] = json!({"note": "irrelevant"});
    let reordered = json!({
        "kid": "2011-04-29",
        "alg": "RS256",
        "use": "sig",
        "e": "AQAB",
        "kty": "RSA",
        "n": jwk["n"]
    });
    let base = thumbprint(&rfc7638_rsa_jwk()).unwrap();
    assert_eq!(thumbprint(&jwk).unwrap(), base);
    assert_eq!(thumbprint(&reordered).unwrap(), base);
}

#[test]
fn okp_ed25519_thumbprint_fixed_vector() {
    // {"crv":"Ed25519","kty":"OKP","x":"2STL..."} -> SHA-256 -> this value
    // (derived and cross-checked against jsonwebtoken's own thumbprint).
    let jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "2STLgFek0PNLuWneXSvEXZHjbno7lSKsjhtOoTo5fgU"
    });
    assert_eq!(
        thumbprint(&jwk).expect("the OKP key thumbprints"),
        "MVvETdtdNRrk5ego5TeMmIxQ8STLEgIC2JrZu26L0So"
    );
}

#[test]
fn ec_thumbprint_agrees_with_the_jsonwebtoken_codec() {
    let key = common::p256();
    let mine = thumbprint(&key.jwk).expect("the fixture EC key thumbprints");
    let codec: jsonwebtoken::jwk::Jwk =
        serde_json::from_value(key.jwk.clone()).expect("fixture JWK parses");
    assert_eq!(
        mine,
        codec.thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256),
        "first-party thumbprint matches the codec's"
    );
}

#[test]
fn thumbprint_refuses_incomplete_keys() {
    let missing_e = json!({
        "kty": "RSA",
        "n": rfc7638_rsa_jwk()["n"]
    });
    let err = thumbprint(&missing_e).expect_err("RSA without e is not a key");
    assert!(matches!(err, AcmeError::Malformed(_)), "got {err:?}");

    let oct_key = json!({ "kty": "oct", "k": "c2VjcmV0" });
    let err = thumbprint(&oct_key).expect_err("symmetric keys are not ACME account keys");
    assert!(matches!(err, AcmeError::Malformed(_)), "got {err:?}");

    let non_string_member = json!({ "kty": "RSA", "n": 42, "e": "AQAB" });
    let err = thumbprint(&non_string_member).expect_err("a non-string member is malformed");
    assert!(matches!(err, AcmeError::Malformed(_)), "got {err:?}");
}
