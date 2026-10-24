//! The credential domain models: refresh tokens, OIDC provider config,
//! service identities, and one-shot tokens.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// One row of `refresh_tokens`: a session-refresh bearer token, whose
/// hash is stored (never the token itself) and whose `last_used_at`
/// forms a sliding expiry window.
#[derive(Debug, Clone, PartialEq)]
pub struct RefreshTokenModel {
    /// Primary key (chosen by the caller).
    pub id: Uuid,
    /// Owning tenant (`tenants.id`, insert-time FK).
    pub tenant_id: Uuid,
    /// Owning user (`users.id`, insert-time FK, ON DELETE CASCADE).
    pub user_id: Uuid,
    /// Token verifier hash; the raw token value never reaches storage.
    pub token_hash: String,
    /// Issue time.
    pub issued_at: DateTime<Utc>,
    /// Last use time — the sliding expiry window's anchor.
    pub last_used_at: DateTime<Utc>,
    /// Expiry instant (schema default: issued + 1 hour).
    pub expires_at: DateTime<Utc>,
    /// Whether the token is revoked (rotation revokes its predecessor).
    pub revoked: bool,
    /// Revocation instant; `None` while unrevoked.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Client user agent at issue time.
    pub user_agent: Option<String>,
    /// Client address at issue time (the INET column).
    pub ip_address: Option<IpAddr>,
}

/// One row of `oidc_config`: the tenant's generic OIDC provider settings
/// (`tenant_id` is the row's primary key — exactly one provider per
/// tenant; configured presence is enablement).
#[derive(Debug, Clone, PartialEq)]
pub struct OidcConfigModel {
    /// Owning tenant; the primary key of the row.
    pub tenant_id: Uuid,
    /// Provider flavour (`keycloak` | `azure` | `custom`; the CHECK'd
    /// `provider_type` column).
    pub provider_type: String,
    /// Config display name.
    pub display_name: String,
    /// OIDC discovery document URL.
    pub discovery_url: String,
    /// OIDC client id.
    pub client_id: String,
    /// The client secret, TRANSIENT plaintext: populated only after
    /// unsealing for an outgoing token exchange (or by a legacy
    /// plaintext column row). At rest the row carries the sealed bytes
    /// ([`Self::client_secret_encrypted`]/[`Self::client_secret_nonce`]);
    /// an empty string means a public client.
    pub client_secret: String,
    /// The sealed client secret (threat-model G2): XChaCha20-Poly1305
    /// under the per-install SecretBox key, `None` for a public client.
    pub client_secret_encrypted: Option<Vec<u8>>,
    /// The AEAD nonce paired with [`Self::client_secret_encrypted`].
    pub client_secret_nonce: Option<Vec<u8>>,
    /// Redirect URI registered with the provider.
    pub redirect_uri: String,
    /// Requested scopes (space separated).
    pub scopes: String,
}

/// One row of `service_identities`: a machine identity minted from an
/// API token, whose capabilities live in `service_identity_capabilities`
/// (read and written via `CredentialRepo`).
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceIdentityModel {
    /// Primary key (chosen by the caller).
    pub id: Uuid,
    /// Owning tenant (`tenants.id`, insert-time FK).
    pub tenant_id: Uuid,
    /// Human-chosen name.
    pub name: String,
    /// Free-form description.
    pub description: Option<String>,
    /// The user who created it (`users.id` FK); `None` if that account
    /// was deleted afterward, at a known attribution cost.
    pub created_by: Option<Uuid>,
    /// Token verifier hash; the raw token value never reaches storage.
    pub token_hash: String,
    /// Row creation time.
    pub created_at: DateTime<Utc>,
    /// Expiry instant; `None` for a non-expiring identity.
    pub expires_at: Option<DateTime<Utc>>,
    /// Revocation instant; `None` while unrevoked.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Last use instant; `None` until first used.
    pub last_used_at: Option<DateTime<Utc>>,
}

/// One row of `one_shot_tokens`: a single-use operator token (`minted_by`
/// attributes it); its capabilities live in
/// `one_shot_token_capabilities`. Consumed atomically by
/// `CredentialRepo::consume_one_shot_by_hash`.
#[derive(Debug, Clone, PartialEq)]
pub struct OneShotTokenModel {
    /// Primary key (chosen by the caller).
    pub id: Uuid,
    /// Owning tenant (`tenants.id`, insert-time FK).
    pub tenant_id: Uuid,
    /// The user who minted the token (`users.id` FK); `None` if that
    /// account was deleted afterward.
    pub minted_by: Option<Uuid>,
    /// Token verifier hash; the raw token value never reaches storage.
    pub token_hash: String,
    /// Row creation time.
    pub created_at: DateTime<Utc>,
    /// Expiry instant; `None` for a non-expiring token.
    pub expires_at: Option<DateTime<Utc>>,
    /// Consumption instant; `None` until consumed. Set by the
    /// conditional single-statement consume, so two concurrent consumers
    /// cannot both succeed.
    pub used_at: Option<DateTime<Utc>>,
}
