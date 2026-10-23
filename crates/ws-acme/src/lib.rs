//! # ws-acme — the JOSE floor for Wardstone's ACME implementation
//!
//! Everything an RFC 8555 route stands on before any ACME machinery runs,
//! as one independent crate: compact-serialization JWS verification with
//! the protocol's protected-header requirements ([`verify_jws`]), the
//! anti-replay nonce ledger ([`NonceStore`]), RFC 7638 account-key
//! thumbprints ([`thumbprint`]), and the challenge verification
//! arithmetic (Task 7): the §8.3 key authorization and the §8.4 DNS-01
//! record value ([`key_authorization`], [`dns01_record_value`]).
//!
//! First-party where it matters: jsonwebtoken is used strictly as the JOSE
//! codec (raw `crypto::sign`/`crypto::verify` primitives over the compact
//! serialization), while every policy decision — which algorithms each key
//! family may use, `kid`+`jwk` exclusivity, nonce single-use regardless of
//! the signature verdict, the `url` binding — is this crate's own code.
//!
//! Nothing here knows about HTTP, routes, or databases: `verify_jws` takes
//! the raw request body plus three caller-supplied seams (kid resolution,
//! nonce checking, the expected URL), so the ACME tasks wire it onto the
//! API layer without this crate growing ws-core/ws-api dependencies (the
//! challenge arithmetic is likewise pure — the server-side fetch and DNS
//! resolution live behind ws-api's seams).

mod account_key;
mod challenge;
pub mod error;
mod jws;
mod nonce;

pub use account_key::thumbprint;
pub use challenge::{dns01_record_value, key_authorization};
pub use error::AcmeError;
pub use jws::{verify_jws, JwsHeader, VerifiedJws};
pub use nonce::NonceStore;
