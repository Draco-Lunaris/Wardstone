//! Pinnable leaf-key types and their generation.
//!
//! A leaf profile pins its key type ([`LeafKeyType`]); `ws_ca::issue`
//! checks a CSR's actual key algorithm against that pin, and Plan 2's
//! setup page generates the setup certificate's leaf key from the same
//! pin via [`generate_leaf_key`]. RSA keys are generated with the
//! pure-Rust `rsa` crate through [`crate::ca::generate_rsa`] — rcgen's
//! ring backend can parse and sign RSA but cannot generate it — while
//! Ed25519 and the ECDSA curves are generated inside rcgen.
//!
//! The `as_str()` spellings are exactly the values Plan 1's fixtures
//! already write into the `certificates.key_type` TEXT column
//! (`rsa2048`, `rsa3072`, `ecdsa-p256`, `ecdsa-p384`, `ed25519`), so
//! existing rows stay parseable, and the serde names equal the
//! `as_str()` values (explicit `#[serde(rename = "…")]` where the
//! spelling is not plain snake_case — `ecdsa-p256` has a hyphen).

use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::ca::generate_rsa;
use crate::error::CaError;

/// A key algorithm a leaf profile can pin, stored in the
/// `certificates.key_type` TEXT column as its serde name (`as_str`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LeafKeyType {
    /// RSA with a 2048-bit modulus.
    #[serde(rename = "rsa2048")]
    Rsa2048,
    /// RSA with a 3072-bit modulus.
    #[serde(rename = "rsa3072")]
    Rsa3072,
    /// ECDSA over NIST P-256.
    #[serde(rename = "ecdsa-p256")]
    EcdsaP256,
    /// ECDSA over NIST P-384.
    #[serde(rename = "ecdsa-p384")]
    EcdsaP384,
    /// Ed25519.
    #[serde(rename = "ed25519")]
    Ed25519,
}

/// Every [`LeafKeyType`], for round-trip tests.
pub const ALL_LEAF_KEY_TYPES: &[LeafKeyType] = &[
    LeafKeyType::Rsa2048,
    LeafKeyType::Rsa3072,
    LeafKeyType::EcdsaP256,
    LeafKeyType::EcdsaP384,
    LeafKeyType::Ed25519,
];

impl LeafKeyType {
    /// The value stored in the `certificates.key_type` TEXT column
    /// (`as_str` == serde name, written once).
    pub fn as_str(&self) -> &'static str {
        match self {
            LeafKeyType::Rsa2048 => "rsa2048",
            LeafKeyType::Rsa3072 => "rsa3072",
            LeafKeyType::EcdsaP256 => "ecdsa-p256",
            LeafKeyType::EcdsaP384 => "ecdsa-p384",
            LeafKeyType::Ed25519 => "ed25519",
        }
    }

    /// Fallible parse from the TEXT column value (house idiom; inherent
    /// rather than `FromStr` because there is no error type to carry).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        ALL_LEAF_KEY_TYPES.iter().copied().find(|k| k.as_str() == s)
    }

    /// The CSR algorithm name — as `ws_ca::issue`'s SPKI parser spells it —
    /// that this pin accepts, and the pinned RSA modulus size in bits
    /// (`None` for the non-RSA pins).
    ///
    /// The pin is an EXACT match, the RSA family included: a profile
    /// pinning `Rsa2048` rejects both an RSA-3072 and an RSA-4096 CSR,
    /// and an RSA-4096 key is not pinnable at all — the enum deliberately
    /// narrows the accepted set to the two supported sizes, so opening a
    /// floor under the pin would undo that narrowing. A CSR whose modulus
    /// size differs from the pin is refused: an issued certificate whose
    /// key contradicts the recorded profile is a policy violation
    /// invisible to the caller and the auditor, the same class the
    /// not_after clamp refusal exists to eliminate.
    pub(crate) fn csr_constraint(&self) -> (&'static str, Option<usize>) {
        match self {
            LeafKeyType::Rsa2048 => ("RSA", Some(2048)),
            LeafKeyType::Rsa3072 => ("RSA", Some(3072)),
            LeafKeyType::EcdsaP256 => ("ECDSA P-256", None),
            LeafKeyType::EcdsaP384 => ("ECDSA P-384", None),
            LeafKeyType::Ed25519 => ("Ed25519", None),
        }
    }
}

/// Generate a fresh leaf key of `key_type`: the rcgen key pair and its
/// PKCS#8 DER serialization (the exact bytes the caller is expected to
/// hand to [`crate::keystore::KeyStore::store_setup_key`] — or to sign a
/// CSR with before storing them).
///
/// RSA goes through [`crate::ca::generate_rsa`] (the `rsa` crate); the
/// other three algorithms are generated inside rcgen. The DER is the
/// plaintext PKCS#8 document: the brief pins the `Vec<u8>` return type
/// here because the caller encrypts these bytes immediately (keystore
/// envelope); a caller that keeps the pair in memory longer than one
/// statement should prefer the [`KeyPair`] half, which rcgen zeroizes.
pub fn generate_leaf_key(key_type: LeafKeyType) -> Result<(KeyPair, Zeroizing<Vec<u8>>), CaError> {
    match key_type {
        LeafKeyType::Rsa2048 => {
            let (key_pair, der) = generate_rsa(2048)?;
            Ok((key_pair, Zeroizing::new(der.to_vec())))
        }
        LeafKeyType::Rsa3072 => {
            let (key_pair, der) = generate_rsa(3072)?;
            Ok((key_pair, Zeroizing::new(der.to_vec())))
        }
        LeafKeyType::EcdsaP256 => generated_for(&PKCS_ECDSA_P256_SHA256),
        LeafKeyType::EcdsaP384 => generated_for(&PKCS_ECDSA_P384_SHA384),
        LeafKeyType::Ed25519 => generated_for(&PKCS_ED25519),
    }
}

/// Generate inside rcgen for one algorithm and return the pair with its
/// serialized PKCS#8 DER (rcgen's own plain copy; the pair's internal
/// serialization is dropped and zeroized via the `zeroize` feature).
fn generated_for(
    alg: &'static rcgen::SignatureAlgorithm,
) -> Result<(KeyPair, Zeroizing<Vec<u8>>), CaError> {
    let key_pair = KeyPair::generate_for(alg)?;
    let der = Zeroizing::new(key_pair.serialize_der());
    Ok((key_pair, der))
}

#[cfg(test)]
mod tests {
    use super::{generate_leaf_key, LeafKeyType, ALL_LEAF_KEY_TYPES};

    /// The stored spellings are exactly the values Plan 1's fixtures
    /// already write into `certificates.key_type` (the `ecdsa-p256` row
    /// spelling included) — a renamed spelling would orphan those rows.
    #[test]
    fn as_str_spelling_is_pinned() {
        assert_eq!(LeafKeyType::Rsa2048.as_str(), "rsa2048");
        assert_eq!(LeafKeyType::Rsa3072.as_str(), "rsa3072");
        assert_eq!(LeafKeyType::EcdsaP256.as_str(), "ecdsa-p256");
        assert_eq!(LeafKeyType::EcdsaP384.as_str(), "ecdsa-p384");
        assert_eq!(LeafKeyType::Ed25519.as_str(), "ed25519");
    }

    /// Every variant round-trips through `as_str`/`from_str`, the serde
    /// name equals `as_str()` (the plan's Global Constraint for
    /// TEXT-column enums — serde's plain snake_case would say
    /// `ecdsa_p256`, which must not happen), and the underscore/case
    /// spellings do not parse.
    #[test]
    fn serde_name_equals_as_str_and_from_str_round_trips() {
        for key_type in ALL_LEAF_KEY_TYPES {
            assert_eq!(LeafKeyType::from_str(key_type.as_str()), Some(*key_type));
            let json = serde_json::to_string(key_type).unwrap();
            assert_eq!(
                json,
                format!("{:?}", key_type.as_str()),
                "serde name must equal as_str exactly"
            );
            assert_eq!(
                serde_json::from_str::<LeafKeyType>(&json).unwrap(),
                *key_type
            );
        }
        // The near-miss spellings must not parse case- or separator-wise.
        assert_eq!(LeafKeyType::from_str("ecdsa_p256"), None);
        assert_eq!(LeafKeyType::from_str("rsa_2048"), None);
        assert_eq!(LeafKeyType::from_str("ECDSA-P256"), None);
        assert_eq!(LeafKeyType::from_str(""), None);
    }

    /// Every pinnable type generates a key, and the returned PKCS#8 DER
    /// re-imports into rcgen (the shape Plan 2's setup path depends on:
    /// store the DER, load it back as a usable key).
    #[test]
    fn every_type_generates_a_reimportable_key() {
        // Rsa2048 shares the `generate_rsa` helper's whole code path with
        // Rsa3072 (only the bit count differs); 3072-bit generation is
        // slow, so the fast 2048 one covers the path.
        for key_type in [
            LeafKeyType::Ed25519,
            LeafKeyType::EcdsaP256,
            LeafKeyType::EcdsaP384,
            LeafKeyType::Rsa2048,
        ] {
            let (key_pair, der) = generate_leaf_key(key_type).unwrap();
            // The DER is the SAME key the pair signs with: re-import it
            // and compare the public halves.
            let reimported = rcgen::KeyPair::try_from(der.as_slice())
                .unwrap_or_else(|e| panic!("{key_type:?}: DER must re-import, got {e}"));
            assert_eq!(
                key_pair.serialize_der(),
                reimported.serialize_der(),
                "{key_type:?}: the returned DER must serialize back to the pair"
            );
        }
    }
}
