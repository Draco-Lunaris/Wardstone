//! The RFC 8555 challenge arithmetic (Plan 4 Task 7): the key
//! authorization a client provisions (`token || '.' || base64url(account
//! key thumbprint)`, §8.3) and the DNS-01 TXT record value
//! (`base64url(SHA256(key authorization))`, §8.4). Pure string/hash
//! helpers on the protocol floor — no HTTP, no DNS, no routes. The ws-api
//! route layer computes the EXPECTED answers from these and verifies them
//! against its own outbound fetch/resolution; a client-supplied answer is
//! never consulted (the plan's anti-goal stands at the protocol floor
//! already: nothing here can ingest one).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

/// The RFC 8555 §8.3 key authorization: the challenge's token, a dot, and
/// the RFC 7638 thumbprint of the AUTHORIZING ACCOUNT's key (the JWK the
/// account registered with). Callers recompute this from the stored
/// challenge token and the account row's thumbprint — the same account key
/// that authenticated the request — so the expected answer can never be
/// substituted by the client for a key it does not control.
pub fn key_authorization(token: &str, account_key_thumbprint: &str) -> String {
    format!("{token}.{account_key_thumbprint}")
}

/// The RFC 8555 §8.4 DNS-01 record value: the unpadded base64url encoding
/// of SHA-256 over the ASCII bytes of the key authorization. The verifier
/// resolves TXT `_acme-challenge.<identifier>` and marks the challenge
/// valid when ANY record returned equals this value (§8.4: "if ... any
/// ... matches").
pub fn dns01_record_value(key_authorization: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(key_authorization.as_bytes()))
}

/// # Unit tests
#[cfg(test)]
mod tests {
    use super::{dns01_record_value, key_authorization};

    /// §8.3's concat shape, verbatim: token, dot, thumbprint.
    #[test]
    fn key_authorization_is_token_dot_thumbprint() {
        assert_eq!(
            key_authorization("the-token", "the-thumbprint"),
            "the-token.the-thumbprint"
        );
    }

    /// The DNS-01 record value over the RFC 8555 §8.4 example's token
    /// (`evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA`) dotted with the RFC
    /// 7638 §3.1 worked example's RSA thumbprint (`NzbLsXh8...GC9Xs`,
    /// pinned byte-for-byte by this crate's thumbprint suite). The
    /// expected base64url digest — and the hex underneath it, in the
    /// comment — were computed INDEPENDENTLY of this crate with the host's
    /// `sha256sum`/`base64` tools, so the vector pins the crate against an
    /// outside computation rather than against itself.
    #[test]
    fn dns01_record_value_matches_the_independently_computed_vector() {
        // sha256 hex 653471d42925d7eb4cd39a39cda8b34d3034c94cb90067ab78c
        // 8123560ba2e5f, base64url-encoded.
        assert_eq!(
            dns01_record_value(
                "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA\
                 .NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
            ),
            "ZTRx1Ckl1-tM05o5zaizTTA0yUy5AGereMgSNWC6Ll8"
        );
    }

    /// A changed token (one byte) changes the record value; a changed
    /// thumbprint changes it too — the value binds BOTH inputs, so an
    /// attacker cannot satisfy someone else's key with their own.
    #[test]
    fn dns01_record_value_binds_both_inputs() {
        let base = key_authorization("token-a", "thumbprint-a");
        let same = dns01_record_value(&base);
        assert_ne!(same, dns01_record_value("token-b.thumbprint-a"));
        assert_ne!(same, dns01_record_value("token-a.thumbprint-b"));
    }
}
