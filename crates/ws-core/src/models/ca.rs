//! The certificate-authority domain model (`cas` rows) and its key type.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The key algorithm a CA was generated with, mirroring the `key_type` text
/// column. The column stores [`KeyType::as_str`]; rows read back through
/// [`KeyType::from_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    /// Ed25519 signature key.
    Ed25519,
    /// 2048-bit RSA key.
    Rsa2048,
    /// 3072-bit RSA key.
    Rsa3072,
}

impl KeyType {
    /// The value stored in the `key_type` column (`snake_case` variant name).
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyType::Ed25519 => "ed25519",
            KeyType::Rsa2048 => "rsa2048",
            KeyType::Rsa3072 => "rsa3072",
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error from parsing an unknown `key_type` column value into a
/// [`KeyType`] (via `FromStr`); carries the offending string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownKeyType(pub String);

impl fmt::Display for UnknownKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown key type: {:?}", self.0)
    }
}

impl std::error::Error for UnknownKeyType {}

impl FromStr for KeyType {
    type Err = UnknownKeyType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ed25519" => Ok(KeyType::Ed25519),
            "rsa2048" => Ok(KeyType::Rsa2048),
            "rsa3072" => Ok(KeyType::Rsa3072),
            other => Err(UnknownKeyType(other.to_string())),
        }
    }
}

/// One row of `cas`: a certificate authority owned by a tenant.
#[derive(Debug, Clone, PartialEq)]
pub struct CaModel {
    /// Primary key (chosen by the caller, not a database default).
    pub id: Uuid,
    /// Owning tenant (`tenants.id`, insert-time FK).
    pub tenant_id: Uuid,
    /// CA name, unique per tenant (`UNIQUE (tenant_id, name)`).
    pub name: String,
    /// Certificate subject DN string.
    pub subject: String,
    /// True for trust anchors; intermediates are false and set `parent_id`.
    pub is_root: bool,
    /// Issuing parent CA for intermediates, `None` for roots.
    pub parent_id: Option<Uuid>,
    /// Key algorithm, stored as `text` in the `key_type` column.
    pub key_type: KeyType,
    /// Certificate validity start.
    pub not_before: DateTime<Utc>,
    /// Certificate validity end.
    pub not_after: DateTime<Utc>,
    /// PEM-encoded certificate.
    pub cert_pem: String,
    /// Path of the file holding the (envelope-encrypted) private key.
    pub key_file: String,
    /// Row creation time (database `now()` default).
    pub created_at: DateTime<Utc>,
}

/// # Unit tests
#[cfg(test)]
mod tests {
    use super::{KeyType, UnknownKeyType};

    #[test]
    fn key_type_roundtrip() {
        assert_eq!(KeyType::Ed25519.as_str(), "ed25519");
        assert_eq!(KeyType::Rsa2048.as_str(), "rsa2048");
        assert_eq!(KeyType::Rsa3072.as_str(), "rsa3072");
        assert_eq!("rsa3072".parse::<KeyType>().unwrap(), KeyType::Rsa3072);
        let err = "bogus".parse::<KeyType>().unwrap_err();
        assert_eq!(err, UnknownKeyType("bogus".to_string()));
    }
}
