//! Session refresh tokens: the house's opaque refresh-token flow
//! (`pm-auth/src/refresh.rs`), ported onto ws-core's [`RefreshTokenRepo`].
//!
//! Same token discipline as `service_identity`: 256 OS-random bytes,
//! presented to the client exactly once as `ws_rt_` + hex (the house's
//! encoding, `pm-auth/src/refresh.rs:38-48`), stored **only** as
//! `hex(Sha256(raw))` (the house's verifier, `pm-auth/src/refresh.rs:46`).
//! The plaintext returned by `rotate_refresh_token` replaces the old one:
//! rotation revokes the predecessor and stores the replacement in ONE
//! atomic statement (the repo's `rotate` CTE), so a client can never be
//! left holding a dead token whose replacement is not yet durable.
//!
//! The functions take `&PgPool` — the house's API shape — because each
//! multi-step operation is already internally atomic through the repo's
//! one-statement writes; nothing here needs a caller-supplied transaction.

use std::net::IpAddr;

use chrono::{DateTime, Duration, SubsecRound, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use ws_core::models::credential::RefreshTokenModel;
use ws_core::repo::refresh_repo::RefreshTokenRepo;

use crate::error::AuthError;
use crate::{from_core_error, opaque_token};

/// The prefix the client-visible plaintext carries.
pub const TOKEN_PREFIX: &str = "ws_rt_";

/// The refresh-token window: the house's one hour
/// (`pm-auth/src/refresh.rs`'s `INACTIVITY_TIMEOUT_HOURS`, matching
/// migration 007's column default).
pub const REFRESH_TTL_HOURS: i64 = 1;

/// A live refresh token, as returned to the client.
///
/// [`token`](RefreshToken::token) is the only copy of the plaintext that
/// will ever exist; storage holds just the verifier hash.
pub struct RefreshToken {
    /// The row's id — also `AccessClaims::sid`, the revocable session id.
    pub id: Uuid,
    /// Owning tenant.
    pub tenant_id: Uuid,
    /// Owning user.
    pub user_id: Uuid,
    /// The plaintext token: `ws_rt_` + hex, returned once.
    pub token: String,
    /// Issue time.
    pub issued_at: DateTime<Utc>,
    /// Expiry instant (issue time + the one-hour window; rotation restarts
    /// the window, which is how an active session stays alive).
    pub expires_at: DateTime<Utc>,
}

/// The model row a mint produces (shared by issue and rotate).
fn minted_model(
    tenant_id: Uuid,
    user_id: Uuid,
    user_agent: Option<&str>,
    ip_address: Option<IpAddr>,
) -> Result<(RefreshTokenModel, String), AuthError> {
    let (token, token_hash) = opaque_token::mint(TOKEN_PREFIX)?;
    // Truncated to microseconds, the Postgres `timestamptz` resolution, so
    // the issued/rotated token's `issued_at`/`expires_at` are exactly the
    // stored ones (the nanosecond tail would vanish in the roundtrip).
    let now = Utc::now().trunc_subsecs(6);
    let model = RefreshTokenModel {
        id: Uuid::new_v4(),
        tenant_id,
        user_id,
        token_hash,
        issued_at: now,
        last_used_at: now,
        expires_at: now + Duration::hours(REFRESH_TTL_HOURS),
        revoked: false,
        revoked_at: None,
        user_agent: user_agent.map(ToOwned::to_owned),
        ip_address,
    };
    Ok((model, token))
}

/// The client-facing shape of a stored row.
fn token_of(model: &RefreshTokenModel) -> RefreshToken {
    RefreshToken {
        id: model.id,
        tenant_id: model.tenant_id,
        user_id: model.user_id,
        // The plaintext is not in the model; each mint returns its own.
        token: String::new(),
        issued_at: model.issued_at,
        expires_at: model.expires_at,
    }
}

/// Issue a new refresh token for the given user and store it in the
/// database. Returns the raw (plaintext) token to be sent to the client —
/// the house's `issue` (`pm-auth/src/refresh.rs:60`), with the tenant the
/// window's rows are scoped to.
pub async fn issue_refresh_token(
    pool: &PgPool,
    tenant_id: Uuid,
    user_id: Uuid,
    user_agent: Option<&str>,
    ip_address: Option<IpAddr>,
    repo: &RefreshTokenRepo,
) -> Result<RefreshToken, AuthError> {
    let (model, token) = minted_model(tenant_id, user_id, user_agent, ip_address)?;
    repo.insert(pool, &model).await.map_err(from_core_error)?;
    let mut issued = token_of(&model);
    issued.token = token;
    Ok(issued)
}

/// Validate a presented refresh token without replacing it: `Some` (with
/// the owning user/tenant and the fresh window) while the token is live,
/// `None` when unknown, revoked, or expired — an unauthenticated credential
/// is not an error condition. A live presentation slides the window's
/// anchor (`last_used_at = now()`, the house's use-time update).
pub async fn authenticate_refresh_token(
    plaintext: &str,
    pool: &PgPool,
    repo: &RefreshTokenRepo,
) -> Result<Option<RefreshToken>, AuthError> {
    let Some(token_hash) = opaque_token::parse(TOKEN_PREFIX, plaintext) else {
        return Ok(None);
    };
    let Some(model) = repo
        .get_by_hash(pool, &token_hash)
        .await
        .map_err(from_core_error)?
    else {
        return Ok(None);
    };
    if model.revoked || model.expires_at < Utc::now() {
        return Ok(None);
    }
    repo.touch_last_used(pool, model.id)
        .await
        .map_err(from_core_error)?;
    Ok(Some(token_of(&model)))
}

/// Validate a refresh token, then rotate it (revoke old, issue new).
///
/// Returns the `(new token, user_id)` pair if valid — the house's `rotate`
/// (`pm-auth/src/refresh.rs:94`) — or `None` when unknown, revoked, or
/// expired. The two storage writes are the repo's one-statement CTE, so
/// the old token is never dead while the new one is missing.
pub async fn rotate_refresh_token(
    plaintext: &str,
    pool: &PgPool,
    user_agent: Option<&str>,
    ip_address: Option<IpAddr>,
    repo: &RefreshTokenRepo,
) -> Result<Option<(RefreshToken, Uuid)>, AuthError> {
    let Some(token_hash) = opaque_token::parse(TOKEN_PREFIX, plaintext) else {
        return Ok(None);
    };
    let Some(old) = repo
        .get_by_hash(pool, &token_hash)
        .await
        .map_err(from_core_error)?
    else {
        return Ok(None);
    };
    if old.revoked || old.expires_at < Utc::now() {
        return Ok(None);
    }

    let (replacement, token) = minted_model(old.tenant_id, old.user_id, user_agent, ip_address)?;
    repo.rotate(pool, &old, &replacement)
        .await
        .map_err(from_core_error)?;
    let mut issued = token_of(&replacement);
    issued.token = token;
    Ok(Some((issued, old.user_id)))
}

/// Revoke a refresh token by its raw value.
///
/// Idempotent in both failure modes, like the house's unconditional
/// `revoke`: an unknown or malformed plaintext revokes nothing, and a
/// repeat over an already-revoked token re-stamps `revoked_at` in place
/// (`RefreshTokenRepo::revoke`).
pub async fn revoke_refresh_token(
    plaintext: &str,
    pool: &PgPool,
    repo: &RefreshTokenRepo,
) -> Result<(), AuthError> {
    let Some(token_hash) = opaque_token::parse(TOKEN_PREFIX, plaintext) else {
        return Ok(());
    };
    let Some(model) = repo
        .get_by_hash(pool, &token_hash)
        .await
        .map_err(from_core_error)?
    else {
        return Ok(());
    };
    repo.revoke(pool, model.id).await.map_err(from_core_error)
}
