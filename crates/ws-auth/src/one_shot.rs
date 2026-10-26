//! One-shot tokens: single-use operator credentials for the token-gated
//! pull flow (the Task 10 pull endpoint, and the later CSR submission).
//!
//! Same token discipline as `service_identity` and `refresh`: a 32-byte
//! OS-random token, presented to the operator exactly once as `ws_ot_` +
//! hex (the house's encoding), stored **only** as `hex(Sha256(raw))` (the
//! house's verifier — a fast digest is right for random 256-bit material;
//! argon2id's slowness defends user-chosen passwords).
//!
//! The consume/claim split (the plan's Review Focus item 2, mirroring the
//! lookup/claim pin): [`consume_one_shot`] is lookup-only — it resolves a
//! presented plaintext to its [`Actor`] but never marks the token used, so
//! a stray bearer probing the endpoint cannot burn the operator's token.
//! [`claim_one_shot`] is the atomic consume: one conditional
//! `UPDATE … SET used_at = now() WHERE used_at IS NULL AND expires_at >
//! now() RETURNING …` (Task 5's `consume_one_shot_by_hash`), so the
//! database — not a read-then-write — enforces the single-use property and
//! two concurrent consumers cannot both succeed. Task 10's issuance
//! handler calls [`claim_one_shot`] inside the same transaction as the
//! certificate insert, so a consumed token either yields a certificate or
//! (rolled back) stays claimable.
//!
//! The token carries no profile scope: v1 has no profile ACLs, and the
//! resolved [`Actor`] holds exactly the [`Capability::Issue`] grant — the
//! pull/CSR flow's one privilege.

use chrono::{DateTime, Duration, SubsecRound, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

use ws_core::models::credential::OneShotTokenModel;
use ws_core::models::rbac::{Actor, ActorType, AuthMethod, Capability};
use ws_core::repo::credential_repo::CredentialRepo;

use crate::error::AuthError;
use crate::{from_core_error, opaque_token};

/// The prefix the client-visible plaintext carries.
pub const TOKEN_PREFIX: &str = "ws_ot_";

/// A freshly minted one-shot token, as returned to the operator.
///
/// [`token`](OneShotToken::token) is the only copy of the plaintext that
/// will ever exist: storage holds just the verifier hash, so the caller
/// must deliver it to the operator immediately (and never log it — Task
/// 10's redaction contract).
pub struct OneShotToken {
    /// The token row's id (also the resolved Actor's `actor_id`).
    pub id: Uuid,
    /// Owning tenant.
    pub tenant_id: Uuid,
    /// The plaintext token: `ws_ot_` + hex, returned once.
    pub token: String,
    /// Expiry instant; after this the token claims as `None`.
    pub expires_at: DateTime<Utc>,
}

/// Mint a one-shot token for the pull flow.
///
/// The token is 32 OS-random bytes, stored as `hex(Sha256(raw))` and
/// returned as `ws_ot_` + hex exactly once; `minted_by` attributes the
/// human who minted it (a row attribution, kept through consumption for
/// audit). `minted_by.actor_id` must be a user id (the id the JWT
/// middleware resolves); anything else is a caller bug surfaced as
/// [`AuthError::Config`].
///
/// Unlike a service identity, a one-shot token's capability set is not
/// chosen at mint time: the resolved Actor always carries exactly
/// [`Capability::Issue`] (see the module doc — no profile ACLs in v1), so
/// there is no capability grant to store and no over-privilege check here.
pub async fn mint_one_shot(
    executor: impl PgExecutor<'_>,
    tenant_id: Uuid,
    minted_by: &Actor,
    ttl: Duration,
    repo: &CredentialRepo,
) -> Result<OneShotToken, AuthError> {
    let minter = Uuid::parse_str(&minted_by.actor_id).map_err(|_| {
        AuthError::Config(format!(
            "the minting actor is not a user id: {:?}",
            minted_by.actor_id
        ))
    })?;

    let (token, token_hash) = opaque_token::mint(TOKEN_PREFIX)?;
    let id = Uuid::new_v4();
    // Truncated to microseconds, the Postgres `timestamptz` resolution, so
    // `created_at`/`expires_at` are exactly the values the row stores (the
    // nanosecond tail would vanish in the roundtrip).
    let created_at = Utc::now().trunc_subsecs(6);
    let expires_at = created_at + ttl;

    repo.insert_one_shot_token(
        executor,
        &OneShotTokenModel {
            id,
            tenant_id,
            minted_by: Some(minter),
            token_hash,
            created_at,
            expires_at: Some(expires_at),
            used_at: None,
        },
    )
    .await
    .map_err(from_core_error)?;

    Ok(OneShotToken {
        id,
        tenant_id,
        token,
        expires_at,
    })
}

/// The Actor a stored one-shot token resolves to.
///
/// Fixed shape: `actor_type = OneShotToken`, `auth_method = OneShot`,
/// exactly the [`Capability::Issue`] grant (no profile scope in v1), and
/// `minted_by` set to the human who minted the token — from the row, so
/// audit attribution survives even if the row was fabricated without one.
fn actor_of(model: &OneShotTokenModel) -> Actor {
    Actor {
        actor_type: ActorType::OneShotToken,
        actor_id: model.id.to_string(),
        auth_method: AuthMethod::OneShot,
        capabilities: vec![Capability::Issue],
        session_id: None,
        tenant_id: model.tenant_id,
        minted_by: model.minted_by.map(|user| user.to_string()),
    }
}

/// Whether the row is claimable per the repo's consume predicate:
/// `expires_at > now()`. The mint always sets an expiry, but the column is
/// nullable — and a NULL expiry must read as not-claimable here exactly as
/// the claim's SQL predicate reads it (`NULL > now()` is false), so the
/// two functions can never disagree.
fn live(model: &OneShotTokenModel) -> bool {
    model
        .expires_at
        .is_some_and(|expires_at| expires_at > Utc::now())
}

/// Resolve a presented one-shot token to its [`Actor`] — **lookup-only**.
///
/// This never marks the token used: that is `claim_one_shot`'s job, so a
/// stray bearer presenting the token to the wrong endpoint cannot burn it.
/// Returns `None` when the plaintext is malformed or foreign-prefixed,
/// unknown, already used, or expired (an unauthenticated credential is not
/// an error condition).
pub async fn consume_one_shot(
    plaintext: &str,
    executor: impl PgExecutor<'_>,
    repo: &CredentialRepo,
) -> Result<Option<Actor>, AuthError> {
    let Some(token_hash) = opaque_token::parse(TOKEN_PREFIX, plaintext) else {
        return Ok(None);
    };
    let Some(model) = repo
        .get_one_shot_by_hash(executor, &token_hash)
        .await
        .map_err(from_core_error)?
    else {
        return Ok(None);
    };
    if model.used_at.is_some() || !live(&model) {
        return Ok(None);
    }
    Ok(Some(actor_of(&model)))
}

/// Resolve a presented one-shot token to its [`Actor`] and consume it, in
/// ONE atomic statement.
///
/// The single-use property is the database's, not a read-then-write:
/// `consume_one_shot_by_hash` stamps `used_at = now()` only for a row
/// that is unused, live, and known — a row count of zero (already used,
/// expired, or unknown) collapses to `Ok(None)`, and two concurrent
/// consumers cannot both succeed. Task 10's issuance handler calls this
/// inside the same transaction as the certificate insert, so a claimed
/// token either ends up with a certificate or, rolled back, still
/// claimable.
pub async fn claim_one_shot(
    plaintext: &str,
    executor: impl PgExecutor<'_>,
    repo: &CredentialRepo,
) -> Result<Option<Actor>, AuthError> {
    let Some(token_hash) = opaque_token::parse(TOKEN_PREFIX, plaintext) else {
        return Ok(None);
    };
    let Some(model) = repo
        .consume_one_shot_by_hash(executor, &token_hash)
        .await
        .map_err(from_core_error)?
    else {
        return Ok(None);
    };
    Ok(Some(actor_of(&model)))
}
