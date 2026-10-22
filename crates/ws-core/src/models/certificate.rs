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

/// Why a certificate was revoked, mirroring the `revocation_reason` text
/// column. The stored value is [`RevocationReason::as_str`] — exactly the
/// nine RFC 5280 section 5.3.1 revocation names — and it is the contract
/// ws-worker's CRL/OCSP builders parse back into `CrlReason` reason
/// extensions: worker-side, ONLY these names publish an extension, so
/// the API accepts exactly these and never a free-text reason (free text
/// would be stored and then silently drop the published extension).
/// `remove_from_crl` is deliberately NOT representable here either: a
/// revocation is terminal in this plan (see the worker's own decoder).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    PrivilegeWithdrawn,
    AaCompromise,
}

impl RevocationReason {
    /// The value stored in the `revocation_reason` column — the exact
    /// name ws-worker's `reason_from_str` parses (serde's `snake_case`
    /// names are identical, so the wire and column spellings never
    /// diverge).
    pub fn as_str(&self) -> &'static str {
        match self {
            RevocationReason::Unspecified => "unspecified",
            RevocationReason::KeyCompromise => "key_compromise",
            RevocationReason::CaCompromise => "ca_compromise",
            RevocationReason::AffiliationChanged => "affiliation_changed",
            RevocationReason::Superseded => "superseded",
            RevocationReason::CessationOfOperation => "cessation_of_operation",
            RevocationReason::CertificateHold => "certificate_hold",
            RevocationReason::PrivilegeWithdrawn => "privilege_withdrawn",
            RevocationReason::AaCompromise => "aa_compromise",
        }
    }
}

impl fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error from parsing an unknown `revocation_reason` column value into a
/// [`RevocationReason`] (via `FromStr`); carries the offending string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationReasonParseError(pub String);

impl fmt::Display for RevocationReasonParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown revocation reason: {:?}", self.0)
    }
}

impl std::error::Error for RevocationReasonParseError {}

impl FromStr for RevocationReason {
    type Err = RevocationReasonParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unspecified" => Ok(RevocationReason::Unspecified),
            "key_compromise" => Ok(RevocationReason::KeyCompromise),
            "ca_compromise" => Ok(RevocationReason::CaCompromise),
            "affiliation_changed" => Ok(RevocationReason::AffiliationChanged),
            "superseded" => Ok(RevocationReason::Superseded),
            "cessation_of_operation" => Ok(RevocationReason::CessationOfOperation),
            "certificate_hold" => Ok(RevocationReason::CertificateHold),
            "privilege_withdrawn" => Ok(RevocationReason::PrivilegeWithdrawn),
            "aa_compromise" => Ok(RevocationReason::AaCompromise),
            other => Err(RevocationReasonParseError(other.to_string())),
        }
    }
}

/// One row of `certificates`: an issued leaf certificate owned by a tenant.
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
    /// The profile revision the certificate's policy is pinned to
    /// (`profile_revisions.id`, nullable insert-time FK). The authority
    /// for the certificate's policy; `None` for rows predating the
    /// profiles schema.
    pub profile_revision_id: Option<Uuid>,
    /// Free-form profile label, retained as the DISPLAY form of the
    /// profile (`profile_name` column; denormalised, not authoritative).
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
    /// Optional free-form revocation note (migration 010's
    /// `revocation_detail text NULL`). Stored verbatim alongside the
    /// reason; first-write-wins with the reason pair. `None` while
    /// active, or when the revoke carried no detail.
    pub revocation_detail: Option<String>,
    /// How the certificate entered the system (`manual` | `acme`).
    pub source: String,
    /// Row creation time (database `now()` default).
    pub created_at: DateTime<Utc>,
}

/// The composed filter of `CertificateRepo::list_filtered`. Every field
/// optional; a `None` field contributes no WHERE clause.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CertificateFilter {
    /// Match rows whose lifecycle status equals this (`active`/`revoked`).
    pub status: Option<CertStatus>,
    /// Match rows whose profile label equals this (the display form).
    pub profile_name: Option<String>,
    /// Match rows issued by this CA.
    pub ca_id: Option<Uuid>,
    /// Substring search across subject, serial hex, and DNS SANs.
    pub search: Option<String>,
}

/// The estate statistics the dashboard tiles read:
/// `GET /api/v1/certificates/statistics` (Plan 3 Task 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CertificateStatistics {
    /// Certificates whose status is `active`.
    pub active: u64,
    /// Certificates whose status is `revoked`.
    pub revoked: u64,
    /// Active certificates whose `not_after` falls before the caller's
    /// expiry horizon (the route pins now + 30 days).
    pub expiring_soon: u64,
}

/// # Unit tests
#[cfg(test)]
mod tests {
    use super::{CertStatus, RevocationReason, RevocationReasonParseError, UnknownCertStatus};

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

    /// `as_str` is the EXACT spelling ws-worker's `reason_from_str`
    /// parses (the CRL/OCSP reason-extension contract), the serde
    /// `snake_case` name is identical to it, and every serde spelling
    /// parses back via `FromStr`.
    #[test]
    fn revocation_reason_contract() {
        let expected = [
            (RevocationReason::Unspecified, "unspecified"),
            (RevocationReason::KeyCompromise, "key_compromise"),
            (RevocationReason::CaCompromise, "ca_compromise"),
            (RevocationReason::AffiliationChanged, "affiliation_changed"),
            (RevocationReason::Superseded, "superseded"),
            (
                RevocationReason::CessationOfOperation,
                "cessation_of_operation",
            ),
            (RevocationReason::CertificateHold, "certificate_hold"),
            (RevocationReason::PrivilegeWithdrawn, "privilege_withdrawn"),
            (RevocationReason::AaCompromise, "aa_compromise"),
        ];
        for (reason, stored) in expected {
            assert_eq!(reason.as_str(), stored);
            // serde serialization must equal the column spelling, so the
            // wire and stored forms never diverge.
            assert_eq!(
                serde_json::to_value(reason).unwrap(),
                serde_json::Value::String(stored.to_string())
            );
            assert_eq!(stored.parse::<RevocationReason>().unwrap(), reason);
        }
        // `remove_from_crl` (RFC 5280 code 8) stays unparsable: a
        // revocation is terminal, so a reinstatement reason is nonsense.
        let err = "remove_from_crl".parse::<RevocationReason>().unwrap_err();
        assert_eq!(
            err,
            RevocationReasonParseError("remove_from_crl".to_string())
        );
    }
}
