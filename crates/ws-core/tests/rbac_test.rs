//! The shared access vocabulary: capability round-trips, role bundles, and
//! the actor capability checks (Plan 2 Task 2).
//!
//! The full variant lists are spelled out here so adding a capability,
//! role, actor type, or auth method forces a decision in this test — and,
//! through [`role_capabilities`], a decision about which role bundle gains
//! it.

use ws_core::error::CoreError;
use ws_core::models::audit;
use ws_core::models::rbac::{
    role_capabilities, Actor, ActorType, AuthMethod, Capability, Role, UnknownActorType,
};

/// Every capability variant, spelled out: `Admin` must hold exactly this
/// set, so a new capability cannot appear without its bundle being chosen.
const ALL_CAPABILITIES: &[Capability] = &[
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

const ALL_ROLES: &[Role] = &[Role::Admin, Role::Issuer, Role::Viewer];

/// The actor types, including the two Task-2 additions (`api_token`,
/// `one_shot_token`).
const ALL_ACTOR_TYPES: &[ActorType] = &[
    ActorType::User,
    ActorType::ApiToken,
    ActorType::OneShotToken,
    ActorType::System,
    ActorType::AcmeAccount,
];

const ALL_AUTH_METHODS: &[AuthMethod] = &[
    AuthMethod::Session,
    AuthMethod::ApiToken,
    AuthMethod::OneShot,
    AuthMethod::System,
    AuthMethod::AcmeAccount,
];

/// An actor with the given capabilities, for the `can`/`require` checks.
fn actor(caps: &[Capability]) -> Actor {
    Actor {
        actor_type: ActorType::User,
        actor_id: "u-1".to_string(),
        auth_method: AuthMethod::Session,
        capabilities: caps.to_vec(),
        session_id: None,
        tenant_id: uuid::Uuid::nil(),
        minted_by: None,
    }
}

#[test]
fn admin_holds_every_capability() {
    let admin = role_capabilities(Role::Admin);
    assert_eq!(admin.len(), ALL_CAPABILITIES.len());
    for cap in ALL_CAPABILITIES {
        assert!(admin.contains(cap), "Admin missing {cap:?}");
    }
}

#[test]
fn issuer_bundle() {
    let issuer = role_capabilities(Role::Issuer);
    assert!(issuer.contains(&Capability::Issue));
    assert!(issuer.contains(&Capability::ReadCertificates));
    assert!(issuer.contains(&Capability::ReadCas));
    assert!(issuer.contains(&Capability::ReadProfiles));
    assert!(!issuer.contains(&Capability::ManageProfiles));
    assert!(!issuer.contains(&Capability::ReadAudit));
}

#[test]
fn viewer_bundle() {
    let viewer = role_capabilities(Role::Viewer);
    assert!(viewer.contains(&Capability::ReadCertificates));
    assert!(viewer.contains(&Capability::ReadCas));
    assert!(viewer.contains(&Capability::ReadProfiles));
    assert!(viewer.contains(&Capability::ReadAudit));
    assert!(!viewer.contains(&Capability::Issue));
    assert!(!viewer.contains(&Capability::ManageCas));
}

#[test]
fn actor_can_reflects_the_capability_list() {
    let a = actor(&[Capability::Issue, Capability::ReadCertificates]);
    assert!(a.can(Capability::Issue));
    assert!(a.can(Capability::ReadCertificates));
    assert!(!a.can(Capability::ReadAudit));
    assert!(!a.can(Capability::ManageUsers));
}

#[test]
fn actor_require_returns_ok_for_a_present_capability() {
    let a = actor(&[Capability::ReadAudit]);
    assert!(matches!(a.require(Capability::ReadAudit), Ok(())));
}

#[test]
fn actor_require_returns_forbidden_for_an_absent_capability() {
    let a = actor(&[Capability::ReadAudit]);
    match a.require(Capability::Issue) {
        Err(err) => assert!(matches!(err, CoreError::Forbidden), "got {err:?}"),
        Ok(()) => panic!("require must not succeed for an absent capability"),
    }
}

#[test]
fn capability_as_str_matches_serde_and_round_trips() {
    for cap in ALL_CAPABILITIES {
        assert_eq!(
            serde_json::to_value(cap).unwrap(),
            serde_json::json!(cap.as_str()),
            "serde name of {cap:?}"
        );
        assert_eq!(Capability::from_str(cap.as_str()), Some(*cap));
    }
    assert_eq!(Capability::from_str("bogus"), None);
}

#[test]
fn role_as_str_matches_serde_and_round_trips() {
    for role in ALL_ROLES {
        assert_eq!(
            serde_json::to_value(role).unwrap(),
            serde_json::json!(role.as_str()),
            "serde name of {role:?}"
        );
        assert_eq!(Role::from_str(role.as_str()), Some(*role));
    }
    assert_eq!(Role::from_str("bogus"), None);
}

#[test]
fn actor_type_as_str_matches_serde_and_round_trips() {
    for actor_type in ALL_ACTOR_TYPES {
        assert_eq!(
            serde_json::to_value(actor_type).unwrap(),
            serde_json::json!(actor_type.as_str()),
            "serde name of {actor_type:?}"
        );
        assert_eq!(
            actor_type.as_str().parse::<ActorType>().ok(),
            Some(*actor_type)
        );
        assert_eq!(actor_type.as_str(), actor_type.to_string());
    }
    let err = "robot".parse::<ActorType>().unwrap_err();
    assert_eq!(err, UnknownActorType("robot".to_string()));
}

#[test]
fn auth_method_as_str_matches_serde_and_round_trips() {
    for method in ALL_AUTH_METHODS {
        assert_eq!(
            serde_json::to_value(method).unwrap(),
            serde_json::json!(method.as_str()),
            "serde name of {method:?}"
        );
        assert_eq!(AuthMethod::from_str(method.as_str()), Some(*method));
    }
    assert_eq!(AuthMethod::from_str("bogus"), None);
}

/// The audit module's `ActorType` is the same item (a public re-export of
/// the `rbac` definition), not a second enum: an audit row's `actor_type`
/// and an actor's `actor_type` can never disagree.
#[test]
fn audit_actor_type_is_the_rbac_enum() {
    let same: audit::ActorType = ActorType::System;
    assert_eq!(same, ActorType::System);
    assert_eq!(same.as_str(), "system");
}
