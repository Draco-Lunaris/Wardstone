//! The ws-acme error vocabulary. Typed but transport-free: ws-acme never
//! builds an HTTP response itself — the API layer's error table (Task 8)
//! maps each variant onto an ACME problem document (RFC 8555 section 8.3)
//! via [`AcmeError::problem_type`].

/// Everything the JOSE floor can reject a request with.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    /// The request is syntactically invalid: unparseable JWS, non-base64url
    /// segments, a protected header that is not JSON, `jwk`+`kid` together,
    /// or a `url` that does not match the request target.
    #[error("malformed request: {0}")]
    Malformed(String),

    /// The protected header carries no `nonce`, or the nonce is unknown,
    /// replayed, or expired — the RFC 8555 §8 'badNonce' case, where the
    /// client is expected to retry with a freshly minted nonce.
    #[error("bad or replayed anti-replay nonce")]
    BadNonce,

    /// The `kid` in the protected header resolved to no known account key.
    #[error("account does not exist")]
    NoSuchAccount,

    /// The JWS signature did not verify under the request's account key.
    #[error("JWS signature verification failed")]
    BadSignature,

    /// The JWS `alg` is not one this server speaks, or is not permitted
    /// for the key family presented (the alg-key pin: an RSA key may only
    /// appear with RS256, P-256/P-384 EC keys with ES256/ES384, and an
    /// Ed25519 OKP key with EdDSA).
    #[error("algorithm not permitted for this key: {0}")]
    WrongAlgorithm(String),

    /// The route exists but its backing machinery is not delivered yet
    /// (the ACME tasks land incrementally; unfinished routes return this
    /// instead of being routed nowhere).
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}

impl AcmeError {
    /// The ACME problem-document URN prefix (RFC 8555 section 8.3); every
    /// problem `type` this crate can emit lives under it.
    pub const PROBLEM_URN_PREFIX: &'static str = "urn:ietf:params:acme:error:";

    /// The problem-document type for this error, from the ACME error
    /// registry (`urn:ietf:params:acme:error:<slug>`). Status-code mapping
    /// stays with ws-api's error table; this is only the identity of the
    /// problem.
    ///
    /// [`NotImplemented`](AcmeError::NotImplemented) maps to
    /// `serverInternal`: the registry has no "not implemented" type, and an
    /// unfinished route is a server-side condition, not a client one.
    pub fn problem_type(&self) -> &'static str {
        match self {
            AcmeError::Malformed(_) => "urn:ietf:params:acme:error:malformed",
            AcmeError::BadNonce => "urn:ietf:params:acme:error:badNonce",
            AcmeError::NoSuchAccount => "urn:ietf:params:acme:error:accountDoesNotExist",
            AcmeError::BadSignature | AcmeError::WrongAlgorithm(_) => {
                "urn:ietf:params:acme:error:unauthorized"
            }
            AcmeError::NotImplemented(_) => "urn:ietf:params:acme:error:serverInternal",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AcmeError;

    #[test]
    fn problem_types_come_from_the_acme_registry() {
        const P: &str = AcmeError::PROBLEM_URN_PREFIX;
        assert_eq!(
            AcmeError::Malformed("x".to_owned()).problem_type(),
            format!("{P}malformed")
        );
        assert_eq!(AcmeError::BadNonce.problem_type(), format!("{P}badNonce"));
        assert_eq!(
            AcmeError::NoSuchAccount.problem_type(),
            format!("{P}accountDoesNotExist")
        );
        assert_eq!(
            AcmeError::BadSignature.problem_type(),
            format!("{P}unauthorized")
        );
        assert_eq!(
            AcmeError::WrongAlgorithm("RS256".to_owned()).problem_type(),
            format!("{P}unauthorized")
        );
        assert_eq!(
            AcmeError::NotImplemented("orders").problem_type(),
            format!("{P}serverInternal")
        );
    }
}
