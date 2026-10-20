//! The OCSP-response domain model (`ocsp_responses` rows) and its
//! certificate status.
//!
//! One row is one OCSP response for one (CA, serial) pair, stamped with
//! the validity window the responder published it under (`this_update` /
//! `next_update`) and carrying the RFC 6960 response bytes verbatim in
//! `resp_der`. The response bytes are stored, never re-derived: a
//! responder's answer is a signed artifact, and re-encoding it later
//! would risk publishing something the CA never signed.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The status an OCSP response reports for a certificate, mirroring the
/// `status` text column of `ocsp_responses`. The column stores
/// [`OcspStatus::as_str`]; rows read back through [`OcspStatus::from_str`].
///
/// The three values are RFC 6960's `CertStatus` choices: `good`
/// (the `good` [0] alternative), `revoked` (the `revoked` [1]
/// alternative, carrying a revocation time) and `unknown` (the `unknown`
/// [2] alternative — the responder does not know about the certificate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcspStatus {
    /// The certificate is known and not revoked.
    Good,
    /// The certificate is revoked.
    Revoked,
    /// The responder has no knowledge of the certificate.
    Unknown,
}

impl OcspStatus {
    /// The value stored in the `status` column (snake_case variant name).
    pub fn as_str(&self) -> &'static str {
        match self {
            OcspStatus::Good => "good",
            OcspStatus::Revoked => "revoked",
            OcspStatus::Unknown => "unknown",
        }
    }
}

impl fmt::Display for OcspStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error from parsing an unknown `status` column value into an
/// [`OcspStatus`] (via `FromStr`); carries the offending string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownOcspStatus(pub String);

impl fmt::Display for UnknownOcspStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown ocsp status: {:?}", self.0)
    }
}

impl std::error::Error for UnknownOcspStatus {}

impl FromStr for OcspStatus {
    type Err = UnknownOcspStatus;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "good" => Ok(OcspStatus::Good),
            "revoked" => Ok(OcspStatus::Revoked),
            "unknown" => Ok(OcspStatus::Unknown),
            other => Err(UnknownOcspStatus(other.to_string())),
        }
    }
}

/// One row of `ocsp_responses`: a stored OCSP response for one
/// certificate of one CA.
///
/// `serial` is the certificate's integer serial — the column is
/// `bigint`, so the repository converts and a value beyond i64 is a
/// typed error, never a wrapping cast.
#[derive(Debug, Clone, PartialEq)]
pub struct OcspResponseModel {
    /// Primary key (chosen by the caller, not a database default).
    pub id: Uuid,
    /// The responding CA (`cas.id`, insert-time FK).
    pub ca_id: Uuid,
    /// The certificate's serial number (the `serial bigint` column).
    pub serial: i64,
    /// The status the response reports.
    pub status: OcspStatus,
    /// Start of the response's validity window (`thisUpdate`).
    pub this_update: DateTime<Utc>,
    /// End of the response's validity window (`nextUpdate`).
    pub next_update: DateTime<Utc>,
    /// The RFC 6960 response bytes, DER encoded.
    pub resp_der: Vec<u8>,
}

/// # Unit tests
#[cfg(test)]
mod tests {
    use super::{OcspStatus, UnknownOcspStatus};

    #[test]
    fn ocsp_status_roundtrip() {
        assert_eq!(OcspStatus::Good.as_str(), "good");
        assert_eq!(OcspStatus::Revoked.as_str(), "revoked");
        assert_eq!(OcspStatus::Unknown.as_str(), "unknown");
        assert_eq!(
            "revoked".parse::<OcspStatus>().unwrap(),
            OcspStatus::Revoked
        );
        let err = "expired".parse::<OcspStatus>().unwrap_err();
        assert_eq!(err, UnknownOcspStatus("expired".to_string()));
    }

    /// The serde representation is snake_case as pinned.
    #[test]
    fn serde_snake_case() {
        assert_eq!(
            serde_json::to_value(OcspStatus::Good).unwrap(),
            serde_json::json!("good")
        );
        assert_eq!(
            serde_json::to_value(OcspStatus::Unknown).unwrap(),
            serde_json::json!("unknown")
        );
    }
}
