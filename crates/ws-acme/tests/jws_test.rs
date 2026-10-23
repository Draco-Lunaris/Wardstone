//! The JWS verification suite: happy paths per key family, then the trap
//! tests — the alg-key pin, `jwk`+`kid` exclusivity, the `url` binding,
//! and the nonce discipline (single-use regardless of the signature
//! verdict).

mod common;

use serde_json::{json, Value};

use ws_acme::{verify_jws, AcmeError, NonceStore};

use common::{
    embedded_header, kid_header, minted_nonce, payload_object, rsa2048, sign_jws, swap_payload,
    tamper_signature, DIRECTORY_URL,
};

/// A kid resolver closure that hands back the fixture JWK for exactly one
/// known kid (the "account repo" stand-in).
fn resolve_fixture(jwk: Value) -> impl Fn(&str) -> Result<Option<Value>, AcmeError> {
    move |kid| {
        if kid == "kid-1" {
            Ok(Some(jwk.clone()))
        } else {
            Ok(None)
        }
    }
}

/// A resolver that fails, for propagating storage-level errors.
fn resolve_err() -> impl Fn(&str) -> Result<Option<Value>, AcmeError> {
    |_| Err(AcmeError::Malformed("resolver unavailable".to_owned()))
}

#[test]
fn rs256_kid_happy_path() {
    let store = NonceStore::new();
    let nonce = store.mint();
    let token = sign_jws(
        &kid_header("RS256", "kid-1", &nonce),
        &payload_object(),
        rsa2048(),
    );
    let verified = verify_jws(
        &token,
        &resolve_fixture(rsa2048().jwk.clone()),
        &|n| store.consume(n),
        DIRECTORY_URL,
    )
    .expect("a valid RS256 request verifies");
    assert_eq!(verified.header.alg, "RS256");
    assert_eq!(verified.header.kid.as_deref(), Some("kid-1"));
    assert_eq!(verified.payload, payload_object());
    assert_eq!(verified.key, rsa2048().jwk);
    assert!(
        !store.consume(&nonce),
        "verifying the request burned its nonce"
    );
}

#[test]
fn es256_embedded_jwk_happy_path() {
    let store = NonceStore::new();
    let nonce = store.mint();
    let token = sign_jws(
        &embedded_header("ES256", common::p256(), &nonce),
        &payload_object(),
        common::p256(),
    );
    let verified = verify_jws(&token, &|_| Ok(None), &|n| store.consume(n), DIRECTORY_URL)
        .expect("a valid ES256 request verifies");
    assert_eq!(verified.header.alg, "ES256");
    assert_eq!(verified.key, common::p256().jwk);
    assert_eq!(verified.payload, payload_object());
}

#[test]
fn es384_embedded_jwk_happy_path() {
    let store = NonceStore::new();
    let nonce = store.mint();
    let token = sign_jws(
        &embedded_header("ES384", common::p384(), &nonce),
        &payload_object(),
        common::p384(),
    );
    let verified = verify_jws(&token, &|_| Ok(None), &|n| store.consume(n), DIRECTORY_URL)
        .expect("a valid ES384 request verifies");
    assert_eq!(verified.key, common::p384().jwk);
}

#[test]
fn eddsa_embedded_jwk_happy_path() {
    let store = NonceStore::new();
    let nonce = store.mint();
    let token = sign_jws(
        &embedded_header("EdDSA", common::ed25519(), &nonce),
        &payload_object(),
        common::ed25519(),
    );
    let verified = verify_jws(&token, &|_| Ok(None), &|n| store.consume(n), DIRECTORY_URL)
        .expect("a valid EdDSA request verifies");
    assert_eq!(verified.key, common::ed25519().jwk);
    assert_eq!(verified.header.alg, "EdDSA");
}

#[test]
fn empty_payload_decodes_to_null() {
    // POST-as-GET (RFC 8555 section 6.3): the payload b64url-encodes the
    // empty string inside a perfectly signed request.
    let store = NonceStore::new();
    let nonce = store.mint();
    let token = sign_jws(
        &kid_header("RS256", "kid-1", &nonce),
        &Value::Null,
        rsa2048(),
    );
    let verified = verify_jws(
        &token,
        &resolve_fixture(rsa2048().jwk.clone()),
        &|n| store.consume(n),
        DIRECTORY_URL,
    )
    .expect("a POST-as-GET-style empty payload verifies");
    assert_eq!(verified.payload, Value::Null);
}

#[test]
fn jwk_header_with_kid_rejected() {
    let store = NonceStore::new();
    let nonce = store.mint();
    let mut header = embedded_header("RS256", rsa2048(), &nonce);
    header["kid"] = json!("kid-1");
    let token = sign_jws(&header, &payload_object(), rsa2048());
    let err = verify_jws(&token, &|_| Ok(None), &|n| store.consume(n), DIRECTORY_URL)
        .expect_err("a protected header with both jwk and kid is rejected");
    assert!(matches!(err, AcmeError::Malformed(_)), "got {err:?}");
}

#[test]
fn wrong_url_rejected() {
    let store = NonceStore::new();
    let nonce = store.mint();
    let mut header = embedded_header("RS256", rsa2048(), &nonce);
    header["url"] = json!("https://attacker.test/acme/new-order");
    let token = sign_jws(&header, &payload_object(), rsa2048());
    let err = verify_jws(&token, &|_| Ok(None), &|n| store.consume(n), DIRECTORY_URL)
        .expect_err("a JWS bound to a different url is rejected");
    match err {
        AcmeError::Malformed(message) => {
            assert!(message.contains("url mismatch"), "got {message:?}")
        }
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn missing_url_rejected() {
    let store = NonceStore::new();
    let nonce = store.mint();
    let mut header = embedded_header("RS256", rsa2048(), &nonce);
    header["url"] = Value::Null;
    let token = sign_jws(&header, &payload_object(), rsa2048());
    let err = verify_jws(&token, &|_| Ok(None), &|n| store.consume(n), DIRECTORY_URL)
        .expect_err("a protected header without url is rejected");
    assert!(matches!(err, AcmeError::Malformed(_)), "got {err:?}");
}

#[test]
fn missing_nonce_is_bad_nonce() {
    let store = NonceStore::new();
    let mut header = embedded_header("RS256", rsa2048(), &minted_nonce());
    header["nonce"] = Value::Null;
    let token = sign_jws(&header, &payload_object(), rsa2048());
    let err = verify_jws(&token, &|_| Ok(None), &|n| store.consume(n), DIRECTORY_URL)
        .expect_err("a protected header without nonce is a badNonce");
    assert!(matches!(err, AcmeError::BadNonce), "got {err:?}");
}

#[test]
fn replayed_nonce_is_bad_nonce() {
    let store = NonceStore::new();
    let nonce = store.mint();
    // Simulate the nonce having been spent on an earlier request.
    assert!(store.consume(&nonce));
    let token = sign_jws(
        &kid_header("RS256", "kid-1", &nonce),
        &payload_object(),
        rsa2048(),
    );
    let err = verify_jws(
        &token,
        &resolve_fixture(rsa2048().jwk.clone()),
        &|n| store.consume(n),
        DIRECTORY_URL,
    )
    .expect_err("a spent nonce cannot be replayed");
    assert!(matches!(err, AcmeError::BadNonce), "got {err:?}");
}

#[test]
fn tampered_signature_is_bad_signature_and_burns_the_nonce() {
    let store = NonceStore::new();
    let nonce = store.mint();
    let token = tamper_signature(&sign_jws(
        &kid_header("RS256", "kid-1", &nonce),
        &payload_object(),
        rsa2048(),
    ));
    let first = verify_jws(
        &token,
        &resolve_fixture(rsa2048().jwk.clone()),
        &|n| store.consume(n),
        DIRECTORY_URL,
    )
    .expect_err("a corrupted signature is refused");
    assert!(matches!(first, AcmeError::BadSignature), "got {first:?}");
    // The burned-nonce guarantee: the SAME request presented again —
    // signature still broken — must fail on its already-spent nonce, not
    // replay. The nonce was consumed BEFORE any signature verdict.
    let second = verify_jws(
        &token,
        &resolve_fixture(rsa2048().jwk.clone()),
        &|n| store.consume(n),
        DIRECTORY_URL,
    )
    .expect_err("the replay burns on the spent nonce");
    assert!(matches!(second, AcmeError::BadNonce), "got {second:?}");
}

#[test]
fn tampered_payload_is_bad_signature() {
    let store = NonceStore::new();
    let nonce = store.mint();
    let token = swap_payload(
        &sign_jws(
            &kid_header("RS256", "kid-1", &nonce),
            &payload_object(),
            rsa2048(),
        ),
        &json!({ "identifiers": [{ "type": "dns", "value": "attacker.test" }] }),
    );
    let err = verify_jws(
        &token,
        &resolve_fixture(rsa2048().jwk.clone()),
        &|n| store.consume(n),
        DIRECTORY_URL,
    )
    .expect_err("a payload the signature does not cover is refused");
    assert!(matches!(err, AcmeError::BadSignature), "got {err:?}");
}

#[test]
fn hs256_with_rsa_key_is_wrong_algorithm() {
    let store = NonceStore::new();
    let nonce = store.mint();
    // An RSA key presenting under HMAC's alg: rejected on the pin before
    // any signature work, so the signature segment here is arbitrary
    // base64url ("Zm9v" = "foo").
    let mut header = embedded_header("RS256", rsa2048(), &nonce);
    header["alg"] = json!("HS256");
    let token = sign_jws(&header, &payload_object(), rsa2048());
    let token = format!(
        "{}Zm9v",
        &token[..token.rfind('.').expect("3 segments") + 1]
    );
    let err = verify_jws(&token, &|_| Ok(None), &|n| store.consume(n), DIRECTORY_URL)
        .expect_err("HS256 is not an ACME request algorithm");
    assert!(matches!(err, AcmeError::WrongAlgorithm(_)), "got {err:?}");
}

#[test]
fn es256_with_rsa_key_is_wrong_algorithm() {
    let store = NonceStore::new();
    let nonce = store.mint();
    let mut header = embedded_header("RS256", rsa2048(), &nonce);
    header["alg"] = json!("ES256");
    let token = sign_jws(&header, &payload_object(), rsa2048());
    let err = verify_jws(&token, &|_| Ok(None), &|n| store.consume(n), DIRECTORY_URL)
        .expect_err("an RSA key may not claim ES256");
    assert!(matches!(err, AcmeError::WrongAlgorithm(_)), "got {err:?}");
}

#[test]
fn rs256_with_ec_key_is_wrong_algorithm() {
    let store = NonceStore::new();
    let nonce = store.mint();
    let mut header = embedded_header("RS256", common::p256(), &nonce);
    header["alg"] = json!("RS256");
    let token = sign_jws(&header, &payload_object(), common::p256());
    let err = verify_jws(&token, &|_| Ok(None), &|n| store.consume(n), DIRECTORY_URL)
        .expect_err("an EC key may not claim RS256");
    assert!(matches!(err, AcmeError::WrongAlgorithm(_)), "got {err:?}");
}

#[test]
fn rs256_with_okp_key_is_wrong_algorithm() {
    let store = NonceStore::new();
    let nonce = store.mint();
    let mut header = embedded_header("RS256", common::ed25519(), &nonce);
    header["alg"] = json!("RS256");
    let token = sign_jws(&header, &payload_object(), common::ed25519());
    let err = verify_jws(&token, &|_| Ok(None), &|n| store.consume(n), DIRECTORY_URL)
        .expect_err("an OKP key may not claim RS256");
    assert!(matches!(err, AcmeError::WrongAlgorithm(_)), "got {err:?}");
}

#[test]
fn es384_with_p256_key_is_wrong_algorithm() {
    let store = NonceStore::new();
    let nonce = store.mint();
    let mut header = embedded_header("ES384", common::p256(), &nonce);
    header["alg"] = json!("ES384");
    let token = sign_jws(&header, &payload_object(), common::p256());
    let err = verify_jws(&token, &|_| Ok(None), &|n| store.consume(n), DIRECTORY_URL)
        .expect_err("a P-256 key may not claim ES384");
    assert!(matches!(err, AcmeError::WrongAlgorithm(_)), "got {err:?}");
}

#[test]
fn unknown_kid_is_no_such_account() {
    let store = NonceStore::new();
    let nonce = store.mint();
    let token = sign_jws(
        &kid_header("RS256", "kid-does-not-exist", &nonce),
        &payload_object(),
        rsa2048(),
    );
    let err = verify_jws(&token, &|_| Ok(None), &|n| store.consume(n), DIRECTORY_URL)
        .expect_err("an unresolvable kid means the account is unknown");
    assert!(matches!(err, AcmeError::NoSuchAccount), "got {err:?}");
}

#[test]
fn resolver_error_is_propagated() {
    let store = NonceStore::new();
    let nonce = store.mint();
    let token = sign_jws(
        &kid_header("RS256", "kid-1", &nonce),
        &payload_object(),
        rsa2048(),
    );
    let err = verify_jws(&token, &resolve_err(), &|n| store.consume(n), DIRECTORY_URL)
        .expect_err("a failing resolver surfaces its own error");
    match err {
        AcmeError::Malformed(message) => {
            assert_eq!(message, "resolver unavailable")
        }
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn wrong_segment_count_rejected() {
    // Segment shape is checked before any of their contents: two or four
    // dot-separated pieces are not a compact serialization, whatever is
    // inside them.
    for raw in ["a.b", "a.b.c.d"] {
        let err = verify_jws(raw, &|_| Ok(None), &|_| true, DIRECTORY_URL)
            .expect_err("only three segments is a compact JWS");
        assert!(matches!(err, AcmeError::Malformed(_)), "got {err:?}");
    }
}

#[test]
fn non_b64url_segment_rejected() {
    // '+' and '=' are foreign to the unpadded base64url alphabet.
    let bad_header = "not+b64.e30.e30";
    let err = verify_jws(bad_header, &|_| Ok(None), &|_| true, DIRECTORY_URL)
        .expect_err("a header outside the base64url alphabet is malformed");
    assert!(matches!(err, AcmeError::Malformed(_)), "got {err:?}");

    // A structurally valid request whose SIGNATURE segment carries
    // padding: rejected before any signature work happens.
    let store = NonceStore::new();
    let nonce = store.mint();
    let valid = sign_jws(
        &kid_header("RS256", "kid-1", &nonce),
        &payload_object(),
        rsa2048(),
    );
    let mut segments: Vec<&str> = valid.split('.').collect();
    segments[2] = "e30===";
    let padded_sig = segments.join(".");
    let err = verify_jws(
        &padded_sig,
        &resolve_fixture(rsa2048().jwk.clone()),
        &|n| store.consume(n),
        DIRECTORY_URL,
    )
    .expect_err("a padded signature segment is malformed");
    assert!(matches!(err, AcmeError::Malformed(_)), "got {err:?}");
}
