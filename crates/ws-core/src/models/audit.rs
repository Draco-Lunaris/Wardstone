//! The audit-log domain model (`audit_log` rows).
//!
//! The actor type on every row is the shared access vocabulary's
//! [`ActorType`], defined once in [`crate::models::rbac`] and re-exported
//! here — publicly, because `ws-worker` and `ws-core`'s own audit repo
//! name this path (`models::audit::ActorType`) — so an audit row's stored
//! actor type and an actor's own type can never disagree. The
//! [`AuthMethod`] re-export serves the same purpose for the row's
//! `auth_method` column: callers write the vocabulary's value and this
//! module's parse owns its decode.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

pub use crate::models::rbac::{ActorType, AuthMethod};

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
    /// How the actor authenticated (`auth_method` TEXT column, the
    /// [`AuthMethod`] spelling; the column is NOT NULL — every row names
    /// its method, and rows predating the column were backfilled by
    /// migration 009).
    pub auth_method: AuthMethod,
    /// For a human session actor, the browser session the action is
    /// attributed to (`session_id` column; `None` for machine actors,
    /// which have no revocable session).
    pub session_id: Option<Uuid>,
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

/// The audit-list filters `GET /api/v1/audit` composes (Plan 3 Task 2): a
/// filter axis applies only when its field is `Some`. A plain struct,
/// deliberately WITHOUT serde: the API's query struct owns the HTTP
/// deserialization and builds this handler-side, exactly like the
/// certificates' [`crate::models::certificate::CertificateFilter`].
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    /// Entries with `created_at` at or after this instant (inclusive).
    pub from: Option<DateTime<Utc>>,
    /// Entries with `created_at` at or before this instant (inclusive).
    pub to: Option<DateTime<Utc>>,
    /// Entries whose `action` equals this exactly (the action vocabulary:
    /// `ca_created`, `cert_issued`, `cert_revoked`, `crl_built`,
    /// `key_generated`, ...).
    pub action: Option<String>,
}

/// # Unit tests
#[cfg(test)]
mod tests {
    use super::{ActorType, AuthMethod};
    use crate::models::rbac::UnknownActorType;

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
            auth_method: AuthMethod::System,
            session_id: None,
            actor_id: "worker".to_string(),
            action: "crl_built".to_string(),
            target_type: "crl".to_string(),
            target_id: "crl-1".to_string(),
            details: serde_json::json!({}),
            created_at: chrono::DateTime::<chrono::Utc>::MIN_UTC,
        };
        let json = serde_json::to_value(entry).unwrap();
        assert!(json.get("actor_type").is_some(), "actor_type key expected");
        assert!(
            json.get("auth_method").is_some(),
            "auth_method key expected"
        );
        assert!(json.get("session_id").is_some(), "session_id key expected");
        assert!(json.get("actor_id").is_some(), "actor_id key expected");
        assert!(
            json.get("target_type").is_some(),
            "target_type key expected"
        );
        assert!(json.get("target_id").is_some(), "target_id key expected");
        assert!(json.get("created_at").is_some(), "created_at key expected");
    }
}
