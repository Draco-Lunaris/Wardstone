//! The shared access vocabulary: capabilities, roles, actor types, the one
//! actor type, and the role → capability bundles.
//!
//! This vocabulary lives in `ws-core` — not `ws-auth` — because `ws-core`
//! owns the schema that stores these values and `ws-auth` needs the same
//! types to resolve credentials; defining them in `ws-auth` would force
//! `ws-core → ws-auth` while `ws-auth → ws-core`, a Cargo cycle. `ws-auth`
//! re-exports this module instead.
//!
//! Every enum here is stored in a Postgres TEXT column, so the hand-written
//! [`as_str`](Capability::as_str) spellings are deliberate and load-bearing:
//! `as_str()` must return exactly the serde name — the two are the same
//! string, written once. Rows read back through the fallible `from_str`
//! parse (the house idiom, `Option`-returning).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::CoreError;

/// Every capability Wardstone knows, in fixed list order: the `Admin` role
/// bundle is exactly this list, so a new capability cannot be added without
/// a deliberate decision in [`role_capabilities`].
pub const ALL_CAPABILITIES: &[Capability] = &[
    Capability::Issue,
    Capability::GenerateLeafKey,
    Capability::ManageProfiles,
    Capability::ManageCas,
    Capability::ManageUsers,
    Capability::ManageApiTokens,
    Capability::ManageOneShotTokens,
    Capability::ExportCaKeys,
    Capability::ManageSystem,
    Capability::ReadCertificates,
    Capability::ReadCas,
    Capability::ReadProfiles,
    Capability::ReadAudit,
    Capability::ReadUsers,
    Capability::ReadServiceIdentities,
];

/// What an actor may do. Stored in TEXT columns as its serde (`snake_case`)
/// name; [`Capability::as_str`] returns exactly that string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Mint a leaf certificate under a CA profile.
    Issue,
    /// Generate a fresh leaf private key.
    GenerateLeafKey,
    /// Create, change, and delete CA certificate profiles.
    ManageProfiles,
    /// Create, change, and delete CAs.
    ManageCas,
    /// Create, change, and delete human users.
    ManageUsers,
    /// Create, revoke, and list API tokens.
    ManageApiTokens,
    /// Create and revoke one-shot tokens.
    ManageOneShotTokens,
    /// Export CA private keys (the most sensitive read).
    ExportCaKeys,
    /// Change system-wide settings.
    ManageSystem,
    /// List and read certificates.
    ReadCertificates,
    /// List and read CAs.
    ReadCas,
    /// List and read CA certificate profiles.
    ReadProfiles,
    /// Read the tenant's audit log.
    ReadAudit,
    /// Read non-credential user attributes.
    ReadUsers,
    /// List and read service identities.
    ReadServiceIdentities,
}

impl Capability {
    /// The value stored in the capability's TEXT column (`snake_case`
    /// variant name — identical to the serde name, written once).
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::Issue => "issue",
            Capability::GenerateLeafKey => "generate_leaf_key",
            Capability::ManageProfiles => "manage_profiles",
            Capability::ManageCas => "manage_cas",
            Capability::ManageUsers => "manage_users",
            Capability::ManageApiTokens => "manage_api_tokens",
            Capability::ManageOneShotTokens => "manage_one_shot_tokens",
            Capability::ExportCaKeys => "export_ca_keys",
            Capability::ManageSystem => "manage_system",
            Capability::ReadCertificates => "read_certificates",
            Capability::ReadCas => "read_cas",
            Capability::ReadProfiles => "read_profiles",
            Capability::ReadAudit => "read_audit",
            Capability::ReadUsers => "read_users",
            Capability::ReadServiceIdentities => "read_service_identities",
        }
    }

    /// Fallible parse from the TEXT column value: `None` for unknown
    /// strings (house idiom; inherent rather than `FromStr` because there
    /// is no error type to carry — the column stores these names, so an
    /// unknown value is just `None`).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        ALL_CAPABILITIES.iter().copied().find(|c| c.as_str() == s)
    }
}

/// The role of a human user, selecting its capability bundle via
/// [`role_capabilities`]. Stored in TEXT columns as its serde name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Every capability: the operator bootstrap account.
    Admin,
    /// Issue-oriented bundle: mint and read, no management.
    Issuer,
    /// Read-only bundle: certificates, CAs, profiles, audit.
    Viewer,
}

impl Role {
    /// The value stored in the `role` TEXT column (serde name).
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Issuer => "issuer",
            Role::Viewer => "viewer",
        }
    }

    /// Fallible parse from the TEXT column value (house idiom).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Role::Admin),
            "issuer" => Some(Role::Issuer),
            "viewer" => Some(Role::Viewer),
            _ => None,
        }
    }
}

/// Who performed an audited action, mirroring the `actor_type` text column
/// of `audit_log`. The column stores [`ActorType::as_str`]; rows read back
/// through `FromStr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    /// A human operator of the Wardstone web UI.
    User,
    /// A minted API-token credential.
    ApiToken,
    /// A minted one-shot token (carries `minted_by` attribution).
    OneShotToken,
    /// The Wardstone system itself (worker jobs, scheduler).
    System,
    /// An ACME client account.
    AcmeAccount,
}

impl ActorType {
    /// The value stored in the `actor_type` column (`snake_case` variant
    /// name).
    pub fn as_str(&self) -> &'static str {
        match self {
            ActorType::User => "user",
            ActorType::ApiToken => "api_token",
            ActorType::OneShotToken => "one_shot_token",
            ActorType::System => "system",
            ActorType::AcmeAccount => "acme_account",
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
            "api_token" => Ok(ActorType::ApiToken),
            "one_shot_token" => Ok(ActorType::OneShotToken),
            "system" => Ok(ActorType::System),
            "acme_account" => Ok(ActorType::AcmeAccount),
            other => Err(UnknownActorType(other.to_string())),
        }
    }
}

/// How an actor authenticated to Wardstone. Stored in TEXT columns as its
/// serde name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// A human user's browser session (JWT bound to a session id).
    Session,
    /// A long-lived API token.
    ApiToken,
    /// A single-use one-shot token.
    OneShot,
    /// The system itself (no external credential).
    System,
    /// An ACME client account (account key signature).
    AcmeAccount,
}

impl AuthMethod {
    /// The value stored in the `auth_method` TEXT column (serde name).
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthMethod::Session => "session",
            AuthMethod::ApiToken => "api_token",
            AuthMethod::OneShot => "one_shot",
            AuthMethod::System => "system",
            AuthMethod::AcmeAccount => "acme_account",
        }
    }

    /// Fallible parse from the TEXT column value (house idiom).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "session" => Some(AuthMethod::Session),
            "api_token" => Some(AuthMethod::ApiToken),
            "one_shot" => Some(AuthMethod::OneShot),
            "system" => Some(AuthMethod::System),
            "acme_account" => Some(AuthMethod::AcmeAccount),
            _ => None,
        }
    }
}

/// The capability bundle a role grants, as a static slice.
///
/// `Admin` is exactly [`ALL_CAPABILITIES`], so a capability added to the
/// enum is either granted to `Admin` here (in the list, a deliberate edit)
/// or absent from every bundle until someone decides otherwise. `Issuer`
/// and `Viewer` are read-tightened subsets per the profile plan.
pub fn role_capabilities(role: Role) -> &'static [Capability] {
    match role {
        Role::Admin => ALL_CAPABILITIES,
        Role::Issuer => &[
            Capability::Issue,
            Capability::ReadCertificates,
            Capability::ReadCas,
            Capability::ReadProfiles,
        ],
        Role::Viewer => &[
            Capability::ReadCertificates,
            Capability::ReadCas,
            Capability::ReadProfiles,
            Capability::ReadAudit,
        ],
    }
}

/// The one actor type Wardstone authenticates: a human in a browser
/// session, an API token, a one-shot token, the system itself, or an ACME
/// account. Everything that acts on Wardstone carries one of these, and
/// authorization is purely the capability check ([`Actor::can`],
/// [`Actor::require`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Actor {
    /// Which kind of actor this is (also what an audit row records).
    pub actor_type: ActorType,
    /// Actor identifier as free text (user id, token id, worker name,
    /// ACME account URL).
    pub actor_id: String,
    /// How the actor authenticated.
    pub auth_method: AuthMethod,
    /// The actor's capability set (resolved from a role bundle or a
    /// token's grant).
    pub capabilities: Vec<Capability>,
    /// The browser session id (human users only; binds the access token to
    /// a revocable session).
    pub session_id: Option<Uuid>,
    /// Owning tenant.
    pub tenant_id: Uuid,
    /// The human who minted a one-shot token (`None` for every other
    /// actor type), kept for audit attribution.
    pub minted_by: Option<String>,
}

impl Actor {
    /// Whether the actor holds `cap`.
    pub fn can(&self, cap: Capability) -> bool {
        self.capabilities.contains(&cap)
    }

    /// Require `cap`, mapping its absence to [`CoreError::Forbidden`].
    ///
    /// The error type is `CoreError`, not `ws-auth`'s `AuthError`: this
    /// lives in `ws-core`, which cannot name a `ws-auth` type without
    /// creating the cycle `ws-core → ws-auth → ws-core`. The API layer
    /// maps `Forbidden` to HTTP 403.
    pub fn require(&self, cap: Capability) -> Result<(), CoreError> {
        if self.can(cap) {
            Ok(())
        } else {
            Err(CoreError::Forbidden)
        }
    }
}

/// # Unit tests
#[cfg(test)]
mod tests {
    use super::{
        role_capabilities, Actor, ActorType, AuthMethod, Capability, Role, UnknownActorType,
        ALL_CAPABILITIES,
    };
    use crate::error::CoreError;

    #[test]
    fn capability_from_str_rejects_unknown() {
        assert_eq!(Capability::from_str("issue"), Some(Capability::Issue));
        assert_eq!(Capability::from_str("issue "), None);
        assert_eq!(Capability::from_str("Issue"), None);
    }

    #[test]
    fn every_capability_round_trips_through_as_str() {
        for cap in ALL_CAPABILITIES {
            assert_eq!(Capability::from_str(cap.as_str()), Some(*cap));
        }
    }

    #[test]
    fn admin_bundle_is_exactly_all_capabilities() {
        assert_eq!(role_capabilities(Role::Admin), ALL_CAPABILITIES);
    }

    #[test]
    fn require_absent_capability_is_forbidden() {
        let actor = Actor {
            actor_type: ActorType::System,
            actor_id: "worker".to_string(),
            auth_method: AuthMethod::System,
            capabilities: role_capabilities(Role::Viewer).to_vec(),
            session_id: None,
            tenant_id: uuid::Uuid::nil(),
            minted_by: None,
        };
        assert!(actor.can(Capability::ReadAudit));
        assert!(matches!(actor.require(Capability::ReadAudit), Ok(())));
        assert!(!actor.can(Capability::Issue));
        assert!(matches!(
            actor.require(Capability::Issue),
            Err(CoreError::Forbidden)
        ));
    }

    #[test]
    fn unknown_actor_type_from_str() {
        assert_eq!(
            "nope".parse::<ActorType>(),
            Err(UnknownActorType("nope".to_string()))
        );
    }
}
