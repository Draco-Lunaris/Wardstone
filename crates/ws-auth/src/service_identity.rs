//! Service identities and the API tokens that represent them.
//!
//! A service identity is a machine identity (a scripted automation client)
//! minted by a human: `create_service_identity` mints a 256-bit random
//! token, stores ONLY its SHA-256 verifier hash (never the plaintext), and
//! returns the plaintext exactly once — after this call it cannot be
//! recovered, only revoked and re-minted. `authenticate_token` resolves a
//! presented plaintext back to an [`Actor`] carrying the identity's stored
//! capabilities, which becomes the request's authorization context.
//!
//! Review Focus item 1: **a token's capabilities can never exceed its
//! creator's**. A request naming a capability the minting actor lacks is a
//! typed [`AuthError::Forbidden`], not a silent narrowing — the operator
//! must see that the mint was refused, not receive a weaker token.
//!
//! Tokens are presented as `ws_at_` + the hex encoding of the minted raw
//! bytes (the house's token encoding, `pm-auth/src/refresh.rs:38-48`); the
//! stored `token_hash` is `hex(Sha256(raw_bytes))` — the house's
//! refresh-token verifier (`pm-auth/src/refresh.rs:46`), not argon2id,
//! whose slowness defends user-chosen passwords, not random 256-bit
//! material.

use chrono::{DateTime, SubsecRound, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

use ws_core::models::rbac::{Actor, ActorType, AuthMethod, Capability};
use ws_core::repo::credential_repo::CredentialRepo;

use crate::error::AuthError;
use crate::from_core_error;
use crate::opaque_token;

/// The prefix the client-visible plaintext carries.
pub const TOKEN_PREFIX: &str = "ws_at_";

/// A freshly minted service identity, as returned to the operator.
///
/// [`token`](ServiceIdentity::token) is the only copy of the plaintext that
/// will ever exist: storage holds just the verifier hash, so the caller
/// must deliver it to the service's owner immediately (and never log it —
/// Task 10's redaction contract).
pub struct ServiceIdentity {
    /// The identity row's id (also the resolved Actor's `actor_id`).
    pub id: Uuid,
    /// Owning tenant.
    pub tenant_id: Uuid,
    /// Human-chosen name.
    pub name: String,
    /// Free-form description.
    pub description: Option<String>,
    /// The plaintext token: `ws_at_` + hex, returned once.
    pub token: String,
    /// The capability grant the mint stored (the caller's requested list).
    pub capabilities: Vec<Capability>,
    /// Row creation time.
    pub created_at: DateTime<Utc>,
    /// Expiry instant; `None` — minting sets no TTL (an identity lives
    /// until revoked; expiring machine tokens are fabricated rows or a
    /// future mint-time TTL decision).
    pub expires_at: Option<DateTime<Utc>>,
}

/// Mint a service identity and its API token.
///
/// The token's capabilities must be a subset of `creator`'s — any request
/// naming a capability the creator lacks fails with [`AuthError::Forbidden`]
/// (the Review Focus item 1) and stores nothing. The mint is one data-
/// modifying CTE statement: the identity insert feeds its capability
/// insert (the house's one-statement atomicity idiom, as with
/// `RefreshTokenRepo::rotate`), so identity and grant commit together or
/// not at all under any executor, and a concurrent transaction never sees
/// a keyless identity.
///
/// `creator.actor_id` must be a user id (the id the JWT middleware
/// resolves); anything else is a caller bug surfaced as
/// [`AuthError::Config`].
pub async fn create_service_identity(
    executor: impl PgExecutor<'_>,
    name: &str,
    description: Option<&str>,
    capabilities: &[Capability],
    creator: &Actor,
    _repo: &CredentialRepo,
) -> Result<ServiceIdentity, AuthError> {
    // Review Focus item 1: every requested capability must already be held
    // by the minting actor. Refuse loudly rather than silently narrowing.
    if !capabilities.iter().all(|cap| creator.can(*cap)) {
        return Err(AuthError::Forbidden);
    }
    let created_by = Uuid::parse_str(&creator.actor_id).map_err(|_| {
        AuthError::Config(format!(
            "the minting actor is not a user id: {:?}",
            creator.actor_id
        ))
    })?;

    let (token, token_hash) = opaque_token::mint(TOKEN_PREFIX)?;
    let id = Uuid::new_v4();
    // Truncated to microseconds, the Postgres `timestamptz` resolution, so
    // the returned `created_at` is exactly the stored one (the nanosecond
    // tail would vanish in the roundtrip).
    let now = Utc::now().trunc_subsecs(6);
    let caps: Vec<String> = capabilities
        .iter()
        .map(|c| c.as_str().to_string())
        .collect();

    // One statement: the identity INSERT ... RETURNING feeds the capability
    // INSERT SELECT, so the two writes are atomic (see the doc comment).
    // `_repo` is accepted for the Task 10 handler surface's signature
    // symmetry; the mint itself needs no repo call.
    sqlx::query(
        "WITH new_identity AS ( \
             INSERT INTO service_identities (id, tenant_id, name, description, created_by, \
             token_hash, created_at, expires_at, revoked_at, last_used_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             RETURNING id \
         ) \
         INSERT INTO service_identity_capabilities (service_identity_id, capability) \
         SELECT id, cap FROM new_identity CROSS JOIN UNNEST($11::text[]) AS cap",
    )
    .bind(id)
    .bind(creator.tenant_id)
    .bind(name)
    .bind(description)
    .bind(created_by)
    .bind(&token_hash)
    .bind(now)
    .bind(Option::<DateTime<Utc>>::None)
    .bind(Option::<DateTime<Utc>>::None)
    .bind(Option::<DateTime<Utc>>::None)
    .bind(&caps)
    .execute(executor)
    .await
    .map_err(|e| from_core_error(e.into()))?;

    Ok(ServiceIdentity {
        id,
        tenant_id: creator.tenant_id,
        name: name.to_owned(),
        description: description.map(ToOwned::to_owned),
        token,
        capabilities: capabilities.to_vec(),
        created_at: now,
        expires_at: None,
    })
}

/// Resolve a presented token to its [`Actor`], or `None` when unknown,
/// revoked, expired — or forged (a malformed/foreign-prefixed plaintext
/// hashes to nothing; unauthenticated is not an error condition).
///
/// `executor` must be a shared executor (a pool reference): the resolution
/// makes two lookups — the identity by verifier hash, then its capability
/// grant — and a `&mut` executor cannot be reborrowed across both. The
/// grant lives in `service_identity_capabilities`, so the two reads are
/// inherently separate statements.
pub async fn authenticate_token(
    plaintext: &str,
    executor: impl PgExecutor<'_> + Copy,
    repo: &CredentialRepo,
) -> Result<Option<Actor>, AuthError> {
    let Some(token_hash) = opaque_token::parse(TOKEN_PREFIX, plaintext) else {
        return Ok(None);
    };
    let Some(identity) = repo
        .get_service_identity_by_hash(executor, &token_hash)
        .await
        .map_err(from_core_error)?
    else {
        return Ok(None);
    };
    if identity.revoked_at.is_some() {
        return Ok(None);
    }
    if identity
        .expires_at
        .is_some_and(|expires_at| expires_at < Utc::now())
    {
        return Ok(None);
    }
    let capabilities = repo
        .service_identity_capabilities(executor, identity.id)
        .await
        .map_err(from_core_error)?;

    Ok(Some(Actor {
        actor_type: ActorType::ApiToken,
        actor_id: identity.id.to_string(),
        auth_method: AuthMethod::ApiToken,
        capabilities,
        session_id: None,
        tenant_id: identity.tenant_id,
        minted_by: None,
    }))
}
