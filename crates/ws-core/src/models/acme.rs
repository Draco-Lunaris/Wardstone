//! The ACME (RFC 8555) domain models (`acme_accounts`, `acme_orders`,
//! `acme_authorizations`, and `acme_challenges` rows) and their status
//! vocabularies, mirroring the house TEXT-enum idiom
//! (`crate::models::certificate::CertStatus`): each `as_str()` is exactly
//! the enum's serde spelling, the TEXT column stores `as_str()`, and rows
//! read back through `FromStr`.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// Lifecycle state of an ACME account, mirroring the `acme_accounts.status`
/// text column (`pending` | `valid` | `deactivated`). The column stores
/// [`AcmeAccountStatus::as_str`]; rows read back through
/// [`AcmeAccountStatus::from_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcmeAccountStatus {
    /// The account exists but is not yet usable (minted during a
    /// multi-stage flow; in v1 accounts are typically minted `valid`).
    Pending,
    /// Registered and usable (the `new-account` flow's normal outcome).
    Valid,
    /// Deactivated by the client; every action on it is refused.
    Deactivated,
}

impl AcmeAccountStatus {
    /// The value stored in the `status` column (`snake_case` variant name).
    pub fn as_str(&self) -> &'static str {
        match self {
            AcmeAccountStatus::Pending => "pending",
            AcmeAccountStatus::Valid => "valid",
            AcmeAccountStatus::Deactivated => "deactivated",
        }
    }
}

impl fmt::Display for AcmeAccountStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error from parsing an unknown `acme_accounts.status` value into an
/// [`AcmeAccountStatus`] (via `FromStr`); carries the offending string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownAcmeAccountStatus(pub String);

impl fmt::Display for UnknownAcmeAccountStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown acme account status: {:?}", self.0)
    }
}

impl std::error::Error for UnknownAcmeAccountStatus {}

impl FromStr for AcmeAccountStatus {
    type Err = UnknownAcmeAccountStatus;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(AcmeAccountStatus::Pending),
            "valid" => Ok(AcmeAccountStatus::Valid),
            "deactivated" => Ok(AcmeAccountStatus::Deactivated),
            other => Err(UnknownAcmeAccountStatus(other.to_string())),
        }
    }
}

/// Lifecycle state of an ACME order, mirroring the `acme_orders.status`
/// text column (`pending` | `ready` | `processing` | `valid` | `invalid`).
/// The column stores [`AcmeOrderStatus::as_str`]; rows read back through
/// [`AcmeOrderStatus::from_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcmeOrderStatus {
    /// Created; its authorizations are not yet all valid.
    Pending,
    /// All authorizations valid — the client may POST its CSR to
    /// `finalize`.
    Ready,
    /// The finalize has been accepted and the certificate is being
    /// produced.
    Processing,
    /// Finalized; `certificate_id` names the issued certificate.
    Valid,
    /// Failed (`error` says why) or abandoned past expiry.
    Invalid,
}

impl AcmeOrderStatus {
    /// The value stored in the `status` column (`snake_case` variant name).
    pub fn as_str(&self) -> &'static str {
        match self {
            AcmeOrderStatus::Pending => "pending",
            AcmeOrderStatus::Ready => "ready",
            AcmeOrderStatus::Processing => "processing",
            AcmeOrderStatus::Valid => "valid",
            AcmeOrderStatus::Invalid => "invalid",
        }
    }
}

impl fmt::Display for AcmeOrderStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error from parsing an unknown `acme_orders.status` value into an
/// [`AcmeOrderStatus`] (via `FromStr`); carries the offending string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownAcmeOrderStatus(pub String);

impl fmt::Display for UnknownAcmeOrderStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown acme order status: {:?}", self.0)
    }
}

impl std::error::Error for UnknownAcmeOrderStatus {}

impl FromStr for AcmeOrderStatus {
    type Err = UnknownAcmeOrderStatus;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(AcmeOrderStatus::Pending),
            "ready" => Ok(AcmeOrderStatus::Ready),
            "processing" => Ok(AcmeOrderStatus::Processing),
            "valid" => Ok(AcmeOrderStatus::Valid),
            "invalid" => Ok(AcmeOrderStatus::Invalid),
            other => Err(UnknownAcmeOrderStatus(other.to_string())),
        }
    }
}

/// Lifecycle state of an ACME authorization, mirroring the
/// `acme_authorizations.status` text column (`pending` | `valid` |
/// `invalid` | `expired` | `deactivated`). The column stores
/// [`AcmeAuthorizationStatus::as_str`]; rows read back through
/// [`AcmeAuthorizationStatus::from_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcmeAuthorizationStatus {
    /// Challenges not yet satisfied.
    Pending,
    /// Proven control of the identifier (while `expires_at` still allows).
    Valid,
    /// Validation failed or was abandoned in a failure state.
    Invalid,
    /// The validity window closed (minted as a bookkeeping transition).
    Expired,
    /// Withdrawn because its account was deactivated.
    Deactivated,
}

impl AcmeAuthorizationStatus {
    /// The value stored in the `status` column (`snake_case` variant name).
    pub fn as_str(&self) -> &'static str {
        match self {
            AcmeAuthorizationStatus::Pending => "pending",
            AcmeAuthorizationStatus::Valid => "valid",
            AcmeAuthorizationStatus::Invalid => "invalid",
            AcmeAuthorizationStatus::Expired => "expired",
            AcmeAuthorizationStatus::Deactivated => "deactivated",
        }
    }
}

impl fmt::Display for AcmeAuthorizationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error from parsing an unknown `acme_authorizations.status` value into an
/// [`AcmeAuthorizationStatus`] (via `FromStr`); carries the offending
/// string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownAcmeAuthorizationStatus(pub String);

impl fmt::Display for UnknownAcmeAuthorizationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown acme authorization status: {:?}", self.0)
    }
}

impl std::error::Error for UnknownAcmeAuthorizationStatus {}

impl FromStr for AcmeAuthorizationStatus {
    type Err = UnknownAcmeAuthorizationStatus;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(AcmeAuthorizationStatus::Pending),
            "valid" => Ok(AcmeAuthorizationStatus::Valid),
            "invalid" => Ok(AcmeAuthorizationStatus::Invalid),
            "expired" => Ok(AcmeAuthorizationStatus::Expired),
            "deactivated" => Ok(AcmeAuthorizationStatus::Deactivated),
            other => Err(UnknownAcmeAuthorizationStatus(other.to_string())),
        }
    }
}

/// The flavor of a validation challenge, mirroring the
/// `acme_challenges.challenge_type` text column. The stored spellings are
/// the RFC 8555 wire names — HYPHENATED (`http-01`, `dns-01`) — so plain
/// `rename_all = "snake_case"` would miss them (`http01`); each variant
/// carries an explicit `#[serde(rename)]` and the unit tests pin `as_str`
/// == the serde name for both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcmeChallengeType {
    /// `http-01` (RFC 8555 §8.3).
    #[serde(rename = "http-01")]
    Http01,
    /// `dns-01` (RFC 8555 §8.4).
    #[serde(rename = "dns-01")]
    Dns01,
}

impl AcmeChallengeType {
    /// The value stored in the `challenge_type` column — the RFC 8555
    /// wire spelling (hyphenated).
    pub fn as_str(&self) -> &'static str {
        match self {
            AcmeChallengeType::Http01 => "http-01",
            AcmeChallengeType::Dns01 => "dns-01",
        }
    }
}

impl fmt::Display for AcmeChallengeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error from parsing an unknown `acme_challenges.challenge_type` value
/// into an [`AcmeChallengeType`] (via `FromStr`); carries the offending
/// string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownAcmeChallengeType(pub String);

impl fmt::Display for UnknownAcmeChallengeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown acme challenge type: {:?}", self.0)
    }
}

impl std::error::Error for UnknownAcmeChallengeType {}

impl FromStr for AcmeChallengeType {
    type Err = UnknownAcmeChallengeType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "http-01" => Ok(AcmeChallengeType::Http01),
            "dns-01" => Ok(AcmeChallengeType::Dns01),
            other => Err(UnknownAcmeChallengeType(other.to_string())),
        }
    }
}

/// Lifecycle state of a validation challenge, mirroring the
/// `acme_challenges.status` text column (`pending` | `processing` |
/// `valid` | `invalid`). The column stores [`AcmeChallengeStatus::as_str`];
/// rows read back through [`AcmeChallengeStatus::from_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcmeChallengeStatus {
    /// Offered; not yet attempted.
    Pending,
    /// Validation in progress (minted for the synchronous
    /// verification's in-flight bookkeeping).
    Processing,
    /// Proven (an authorization with one `valid`/`invalid`-decided
    /// challenge set becomes valid/invalid accordingly).
    Valid,
    /// Attempt failed (`error` says why).
    Invalid,
}

impl AcmeChallengeStatus {
    /// The value stored in the `status` column (`snake_case` variant name).
    pub fn as_str(&self) -> &'static str {
        match self {
            AcmeChallengeStatus::Pending => "pending",
            AcmeChallengeStatus::Processing => "processing",
            AcmeChallengeStatus::Valid => "valid",
            AcmeChallengeStatus::Invalid => "invalid",
        }
    }
}

impl fmt::Display for AcmeChallengeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error from parsing an unknown `acme_challenges.status` value into an
/// [`AcmeChallengeStatus`] (via `FromStr`); carries the offending string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownAcmeChallengeStatus(pub String);

impl fmt::Display for UnknownAcmeChallengeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown acme challenge status: {:?}", self.0)
    }
}

impl std::error::Error for UnknownAcmeChallengeStatus {}

impl FromStr for AcmeChallengeStatus {
    type Err = UnknownAcmeChallengeStatus;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(AcmeChallengeStatus::Pending),
            "processing" => Ok(AcmeChallengeStatus::Processing),
            "valid" => Ok(AcmeChallengeStatus::Valid),
            "invalid" => Ok(AcmeChallengeStatus::Invalid),
            other => Err(UnknownAcmeChallengeStatus(other.to_string())),
        }
    }
}

/// One row of `acme_accounts`: a registered ACME client account owned by a
/// tenant. `jwk_thumbprint` is the account key's RFC 7638 thumbprint (the
/// account URL derives from it); `jwk` is the raw account-key JWK the
/// client embedded in its `new-account` JWS. Contact and ToS metadata are
/// informational; `status` is authoritative.
#[derive(Debug, Clone, PartialEq)]
pub struct AcmeAccountModel {
    /// Primary key (chosen by the caller, not a database default).
    pub id: Uuid,
    /// Owning tenant (`tenants.id`, insert-time FK).
    pub tenant_id: Uuid,
    /// The RFC 7638 thumbprint of the account key (`jwk_thumbprint` TEXT;
    /// unique per tenant).
    pub jwk_thumbprint: String,
    /// The raw account-key JWK (the `jwk jsonb` column).
    pub jwk: JsonValue,
    /// Lifecycle state (the `status` column).
    pub status: AcmeAccountStatus,
    /// When the client agreed to the terms of service; `None` when the
    /// instance publishes no ToS URL or the client has not agreed yet.
    pub tos_agreed_at: Option<DateTime<Utc>>,
    /// The contact the client offered (`contact` TEXT; a single stored
    /// value in v1 instead of the RFC's array).
    pub contact: Option<String>,
    /// Row creation time (database `now()` default).
    pub created_at: DateTime<Utc>,
}

/// One row of `acme_orders`: a certificate order placed by an ACME
/// account. `identifiers` is the raw RFC 8555 identifiers array; the
/// certificate (once issued) is linked by `certificate_id`.
#[derive(Debug, Clone, PartialEq)]
pub struct AcmeOrderModel {
    /// Primary key (chosen by the caller, not a database default).
    pub id: Uuid,
    /// Owning tenant (`tenants.id`, insert-time FK; also pinned equal to
    /// the account's tenant by `acme_orders_account_tenant_fk`).
    pub tenant_id: Uuid,
    /// Placing account (`acme_accounts.id`, insert-time FK).
    pub account_id: Uuid,
    /// Lifecycle state (the `status` column).
    pub status: AcmeOrderStatus,
    /// The certificate profile the order asked for (Wardstone extension
    /// field; the route validates it against the tenant's profiles).
    pub profile_name: String,
    /// The RFC 8555 `identifiers` array (the `identifiers jsonb` column),
    /// stored verbatim from the client's request as the order's authority
    /// for what it asked for.
    pub identifiers: JsonValue,
    /// The PKCS#10 CSR PEM from the client's `finalize` POST (`csr_pem`
    /// TEXT); `None` before finalize.
    pub csr_pem: Option<String>,
    /// Requested validity start; `None` when the client did not ask.
    pub not_before: Option<DateTime<Utc>>,
    /// Requested validity end; `None` when the client did not ask.
    pub not_after: Option<DateTime<Utc>>,
    /// The issued certificate (`certificates.id`); `None` until finalize.
    pub certificate_id: Option<Uuid>,
    /// Why the order failed (flattened problem text); `None` while alive.
    pub error: Option<String>,
    /// Order expiry, before which the order must be finalized.
    pub expires_at: DateTime<Utc>,
    /// Row creation time (database `now()` default).
    pub created_at: DateTime<Utc>,
}

/// One row of `acme_authorizations`: an identifier validation. Two shapes
/// share this table:
///
/// - **Order-scoped** rows (`order_id: Some`) belong to the one order that
///   demanded them and are listed in that order's `authorizations`.
/// - **REUSED** rows (`order_id: None`) belong to the account
///   ([`crate::repo::acme_repo::AcmeRepo::valid_authorization_for`] looks
///   up the newest `valid` account-level row on an identifier within the
///   reuse window), and an order-scoped row minted at reuse time points at
///   its account-level original through `reused_from`.
#[derive(Debug, Clone, PartialEq)]
pub struct AcmeAuthorizationModel {
    /// Primary key (chosen by the caller, not a database default).
    pub id: Uuid,
    /// Owning tenant (`tenants.id`, insert-time FK; also pinned equal to
    /// the account's tenant by `acme_authorizations_account_tenant_fk`).
    pub tenant_id: Uuid,
    /// Authorizing account (`acme_accounts.id`, insert-time FK).
    pub account_id: Uuid,
    /// The identifier this authorization validates (the RFC 8555
    /// identifier value — DNS names in v1 — stored flat as text).
    pub identifier: String,
    /// Lifecycle state (the `status` column).
    pub status: AcmeAuthorizationStatus,
    /// Authorization expiry; a `valid` row past its expiry no longer
    /// satisfies the reuse window (the lookup's `expires_at > now`).
    pub expires_at: DateTime<Utc>,
    /// The account-level authorization an order-scoped row reused
    /// (`acme_authorizations.id`); `None` for account-level and freshly
    /// minted rows.
    pub reused_from: Option<Uuid>,
    /// The order this authorization belongs to (`acme_orders.id`); `None`
    /// for REUSED account-level rows.
    pub order_id: Option<Uuid>,
    /// Row creation time (database `now()` default).
    pub created_at: DateTime<Utc>,
}

/// One row of `acme_challenges`: a validation challenge offered on an
/// authorization. Both flavors are minted per authorization (`http-01` and
/// `dns-01`); the client picks one by requesting validation on it.
#[derive(Debug, Clone, PartialEq)]
pub struct AcmeChallengeModel {
    /// Primary key (chosen by the caller, not a database default).
    pub id: Uuid,
    /// Owning tenant (`tenants.id`, insert-time FK; also pinned equal to
    /// the authorization's tenant by
    /// `acme_challenges_authorization_tenant_fk`).
    pub tenant_id: Uuid,
    /// The challenged authorization (`acme_authorizations.id`,
    /// insert-time FK).
    pub authorization_id: Uuid,
    /// The validation flavor (the `challenge_type` column).
    pub challenge_type: AcmeChallengeType,
    /// The challenge token (RFC 8555 §8.3; the `key_authorization`
    /// derives from token + account thumbprint).
    pub token: String,
    /// Lifecycle state (the `status` column).
    pub status: AcmeChallengeStatus,
    /// When the challenge was validated; `None` until it transitions out
    /// of `pending`.
    pub validated_at: Option<DateTime<Utc>>,
    /// Why the challenge failed validation (flattened problem text);
    /// `None` while alive.
    pub error: Option<String>,
    /// Row creation time (database `now()` default).
    pub created_at: DateTime<Utc>,
}

/// # Unit tests
#[cfg(test)]
mod tests {
    use super::{
        AcmeAccountStatus, AcmeAuthorizationStatus, AcmeChallengeStatus, AcmeChallengeType,
        AcmeOrderStatus, UnknownAcmeAccountStatus, UnknownAcmeAuthorizationStatus,
        UnknownAcmeChallengeStatus, UnknownAcmeChallengeType, UnknownAcmeOrderStatus,
    };

    /// Every ACME status/type enum satisfies the house TEXT-column
    /// contract (the CLAUDE.md convention): `as_str()` is EXACTLY the
    /// serialization serde produces (so the wire and stored forms never
    /// diverge), and the serde-produced spelling parses back via
    /// `FromStr`. Runs variant by variant over all five vocabularies.
    #[test]
    fn acme_status_as_str_is_the_serde_name_and_parses_back() {
        let account = [
            (AcmeAccountStatus::Pending, "pending"),
            (AcmeAccountStatus::Valid, "valid"),
            (AcmeAccountStatus::Deactivated, "deactivated"),
        ];
        let order = [
            (AcmeOrderStatus::Pending, "pending"),
            (AcmeOrderStatus::Ready, "ready"),
            (AcmeOrderStatus::Processing, "processing"),
            (AcmeOrderStatus::Valid, "valid"),
            (AcmeOrderStatus::Invalid, "invalid"),
        ];
        let authorization = [
            (AcmeAuthorizationStatus::Pending, "pending"),
            (AcmeAuthorizationStatus::Valid, "valid"),
            (AcmeAuthorizationStatus::Invalid, "invalid"),
            (AcmeAuthorizationStatus::Expired, "expired"),
            (AcmeAuthorizationStatus::Deactivated, "deactivated"),
        ];
        let challenge_type = [
            (AcmeChallengeType::Http01, "http-01"),
            (AcmeChallengeType::Dns01, "dns-01"),
        ];
        let challenge = [
            (AcmeChallengeStatus::Pending, "pending"),
            (AcmeChallengeStatus::Processing, "processing"),
            (AcmeChallengeStatus::Valid, "valid"),
            (AcmeChallengeStatus::Invalid, "invalid"),
        ];

        for (variant, stored) in account {
            assert_eq!(variant.as_str(), stored);
            assert_eq!(
                serde_json::to_value(variant).expect("serialize account status"),
                serde_json::Value::String(stored.to_string())
            );
            assert_eq!(
                stored.parse::<AcmeAccountStatus>().expect("parse back"),
                variant
            );
        }
        for (variant, stored) in order {
            assert_eq!(variant.as_str(), stored);
            assert_eq!(
                serde_json::to_value(variant).expect("serialize order status"),
                serde_json::Value::String(stored.to_string())
            );
            assert_eq!(
                stored.parse::<AcmeOrderStatus>().expect("parse back"),
                variant
            );
        }
        for (variant, stored) in authorization {
            assert_eq!(variant.as_str(), stored);
            assert_eq!(
                serde_json::to_value(variant).expect("serialize authorization status"),
                serde_json::Value::String(stored.to_string())
            );
            assert_eq!(
                stored
                    .parse::<AcmeAuthorizationStatus>()
                    .expect("parse back"),
                variant
            );
        }
        for (variant, stored) in challenge_type {
            assert_eq!(variant.as_str(), stored);
            assert_eq!(
                serde_json::to_value(variant).expect("serialize challenge type"),
                serde_json::Value::String(stored.to_string())
            );
            assert_eq!(
                stored.parse::<AcmeChallengeType>().expect("parse back"),
                variant
            );
        }
        for (variant, stored) in challenge {
            assert_eq!(variant.as_str(), stored);
            assert_eq!(
                serde_json::to_value(variant).expect("serialize challenge status"),
                serde_json::Value::String(stored.to_string())
            );
            assert_eq!(
                stored.parse::<AcmeChallengeStatus>().expect("parse back"),
                variant
            );
        }
    }

    /// Unknown stored spellings parse to the typed error carrying the
    /// offending string — one error type per enum.
    #[test]
    fn acme_status_unknown_values_parse_to_errors() {
        let err = "cancelled"
            .parse::<AcmeAccountStatus>()
            .expect_err("unknown");
        assert_eq!(err, UnknownAcmeAccountStatus("cancelled".to_string()));
        let err = "expired".parse::<AcmeOrderStatus>().expect_err("unknown");
        assert_eq!(err, UnknownAcmeOrderStatus("expired".to_string()));
        let err = "ready"
            .parse::<AcmeAuthorizationStatus>()
            .expect_err("unknown");
        assert_eq!(err, UnknownAcmeAuthorizationStatus("ready".to_string()));
        let err = "http01"
            .parse::<AcmeChallengeType>()
            .expect_err("the un-hyphenated spelling must not parse");
        assert_eq!(err, UnknownAcmeChallengeType("http01".to_string()));
        let err = "deactivated"
            .parse::<AcmeChallengeStatus>()
            .expect_err("unknown");
        assert_eq!(err, UnknownAcmeChallengeStatus("deactivated".to_string()));
    }
}
