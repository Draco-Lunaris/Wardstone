//! The issued-certificate domain model (`certificates` rows) and its
//! lifecycle status.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Lifecycle state of an issued certificate, mirroring the `status` text
/// column (`active` | `revoked`). The column stores [`CertStatus::as_str`];
/// rows read back through [`CertStatus::from_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertStatus {
    /// Issued and not revoked.
    Active,
    /// Revoked (`revoked_at`/`revocation_reason` are set by the revoke).
    Revoked,
}

impl CertStatus {
    /// The value stored in the `status` column (`snake_case` variant name).
    pub fn as_str(&self) -> &'static str {
        match self {
            CertStatus::Active => "active",
            CertStatus::Revoked => "revoked",
        }
    }
}

impl fmt::Display for CertStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error from parsing an unknown `status` column value into a
/// [`CertStatus`] (via `FromStr`); carries the offending string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownCertStatus(pub String);

impl fmt::Display for UnknownCertStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown certificate status: {:?}", self.0)
    }
}

impl std::error::Error for UnknownCertStatus {}

impl FromStr for CertStatus {
    type Err = UnknownCertStatus;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(CertStatus::Active),
            "revoked" => Ok(CertStatus::Revoked),
            other => Err(UnknownCertStatus(other.to_string())),
        }
    }
}

/// One row of `certificates`: an issued leaf certificate owned by a tenant.
///
/// `serial` is the certificate's integer serial — stored in the
/// `serial bigint` column (the repository converts; a value beyond i64 is
/// a typed error, never a wrapping cast) and carried here as `u128` to
/// match the issuance layer (`ws_ca::issue::LeafSpec::serial`).
/// `serial_hex` is the same value as lowercase hex without leading zeros,
/// the form tools and humans read.
#[derive(Debug, Clone, PartialEq)]
pub struct CertificateModel {
    /// Primary key (chosen by the caller, not a database default).
    pub id: Uuid,
    /// Owning tenant (`tenants.id`, insert-time FK).
    pub tenant_id: Uuid,
    /// Issuing CA (`cas.id`, insert-time FK).
    pub ca_id: Uuid,
    /// Free-form profile label (a profiles table arrives in Plan 2).
    pub profile_name: String,
    /// Certificate subject DN string.
    pub subject: String,
    /// Serial number as an integer (the `serial bigint` column).
    pub serial: u128,
    /// Serial number as lowercase hex, no leading zeros.
    pub serial_hex: String,
    /// DNS subject-alternative names (the `san_dns text[]` column).
    pub san_dns: Vec<String>,
    /// IP subject-alternative names (the `san_ips inet[]` column).
    pub san_ips: Vec<IpAddr>,
    /// Key algorithm as stored text. Leaf key algorithms are wider than
    /// the CA [`crate::models::ca::KeyType`] enum (a leaf can be
    /// `ecdsa-p256`), so this stays a string.
    pub key_type: String,
    /// Certificate validity start.
    pub not_before: DateTime<Utc>,
    /// Certificate validity end.
    pub not_after: DateTime<Utc>,
    /// PEM-encoded certificate.
    pub cert_pem: String,
    /// Lifecycle state (the `status` column).
    pub status: CertStatus,
    /// When the certificate was revoked; `None` while active.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Why the certificate was revoked; `None` while active.
    pub revocation_reason: Option<String>,
    /// How the certificate entered the system (`manual` | `acme`).
    pub source: String,
    /// Row creation time (database `now()` default).
    pub created_at: DateTime<Utc>,
}

/// # Unit tests
#[cfg(test)]
mod tests {
    use super::{CertStatus, UnknownCertStatus};

    #[test]
    fn cert_status_roundtrip() {
        assert_eq!(CertStatus::Active.as_str(), "active");
        assert_eq!(CertStatus::Revoked.as_str(), "revoked");
        assert_eq!(
            "revoked".parse::<CertStatus>().unwrap(),
            CertStatus::Revoked
        );
        let err = "expired".parse::<CertStatus>().unwrap_err();
        assert_eq!(err, UnknownCertStatus("expired".to_string()));
    }
}
