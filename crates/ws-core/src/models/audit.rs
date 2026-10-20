//! The audit-log domain model (`audit_log` rows) and its actor types.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// Who performed an audited action, mirroring the `actor_type` text column
/// of `audit_log`. The column stores [`ActorType::as_str`]; rows read back
/// through [`ActorType::from_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    /// A human operator of the Wardstone web UI.
    User,
    /// An ACME client account.
    AcmeAccount,
    /// The Wardstone system itself (worker jobs, scheduler).
    System,
}

impl ActorType {
    /// The value stored in the `actor_type` column (`snake_case` variant
    /// name).
    pub fn as_str(&self) -> &'static str {
        match self {
            ActorType::User => "user",
            ActorType::AcmeAccount => "acme_account",
            ActorType::System => "system",
        }
    }
}

impl fmt::Display for ActorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error from parsing an unknown `actor_type` column value into an
/// [`ActorType`] (via `FromStr`); carries the offending string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownActorType(pub String);

impl fmt::Display for UnknownActorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown actor type: {:?}", self.0)
    }
}

impl std::error::Error for UnknownActorType {}

impl FromStr for ActorType {
    type Err = UnknownActorType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(ActorType::User),
            "acme_account" => Ok(ActorType::AcmeAccount),
            "system" => Ok(ActorType::System),
            other => Err(UnknownActorType(other.to_string())),
        }
    }
}

/// One row of `audit_log`: an append-only record of a security-relevant
/// event, scoped to a tenant.
///
/// Append-only is structural: `AuditRepo` exposes `record` and
/// `list_by_tenant` and nothing else, so no in-process path can amend or
/// remove a recorded entry. `created_at` is database-owned — `record` never
/// binds a client timestamp, so an entry cannot be backdated — and
/// `details` carries ids and action labels only, never key material.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AuditEntry {
    /// Primary key (chosen by the caller, not a database default).
    pub id: Uuid,
    /// Owning tenant (`tenants.id`, insert-time FK).
    pub tenant_id: Uuid,
    /// Who performed the action.
    pub actor_type: ActorType,
    /// Actor identifier as free text (user id, ACME account URL, worker
    /// name).
    pub actor_id: String,
    /// What happened (e.g. `ca_created`, `cert_issued`, `cert_revoked`,
    /// `crl_built`, `key_generated`).
    pub action: String,
    /// Kind of thing acted upon (e.g. `ca`, `certificate`, `crl`).
    pub target_type: String,
    /// Identifier of the thing acted upon, as free text.
    pub target_id: String,
    /// Structured context, ids and labels only. Never key material.
    pub details: JsonValue,
    /// When the event was recorded (database `now()` default; `record`
    /// ignores any client value for this field).
    pub created_at: DateTime<Utc>,
}

/// # Unit tests
#[cfg(test)]
mod tests {
    use super::{ActorType, UnknownActorType};

    #[test]
    fn actor_type_roundtrip() {
        assert_eq!(ActorType::User.as_str(), "user");
        assert_eq!(ActorType::AcmeAccount.as_str(), "acme_account");
        assert_eq!(ActorType::System.as_str(), "system");
        assert_eq!("user".parse::<ActorType>().unwrap(), ActorType::User);
        assert_eq!(
            "acme_account".parse::<ActorType>().unwrap(),
            ActorType::AcmeAccount
        );
        assert_eq!("system".parse::<ActorType>().unwrap(), ActorType::System);
        let err = "robot".parse::<ActorType>().unwrap_err();
        assert_eq!(err, UnknownActorType("robot".to_string()));
    }

    /// The serde representation is snake_case as pinned: the enum's variant
    /// names and the struct's field names serialize in snake_case form.
    #[test]
    fn serde_snake_case() {
        assert_eq!(
            serde_json::to_value(ActorType::AcmeAccount).unwrap(),
            serde_json::json!("acme_account")
        );
        let entry = super::AuditEntry {
            id: uuid::Uuid::nil(),
            tenant_id: uuid::Uuid::nil(),
            actor_type: ActorType::System,
            actor_id: "worker".to_string(),
            action: "crl_built".to_string(),
            target_type: "crl".to_string(),
            target_id: "crl-1".to_string(),
            details: serde_json::json!({}),
            created_at: chrono::DateTime::<chrono::Utc>::MIN_UTC,
        };
        let json = serde_json::to_value(entry).unwrap();
        assert!(json.get("actor_type").is_some(), "actor_type key expected");
        assert!(json.get("actor_id").is_some(), "actor_id key expected");
        assert!(
            json.get("target_type").is_some(),
            "target_type key expected"
        );
        assert!(json.get("target_id").is_some(), "target_id key expected");
        assert!(json.get("created_at").is_some(), "created_at key expected");
    }
}
