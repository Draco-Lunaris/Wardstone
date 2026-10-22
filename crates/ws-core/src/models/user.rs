//! The human-user domain model (`users` rows).

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::models::rbac::Role;

/// One row of `users`: a human Wardstone account of one tenant.
///
/// The TOTP secret is stored sealed at rest: `totp_secret_encrypted` +
/// `totp_secret_nonce` carry the XChaCha20-Poly1305 ciphertext and nonce
/// written by `ws_core::crypto::SecretBox::seal`, never the plaintext.
#[derive(Debug, Clone, PartialEq)]
pub struct UserModel {
    /// Primary key (chosen by the caller or seeded by the database
    /// default; the repository binds the model's value).
    pub id: Uuid,
    /// Owning tenant (`tenants.id`, insert-time FK).
    pub tenant_id: Uuid,
    /// Login name, unique per tenant.
    pub username: String,
    /// Human-readable name (display only).
    pub display_name: String,
    /// Contact email, unique per tenant.
    pub email: String,
    /// The role selecting the capability bundle (the `role` TEXT column,
    /// decoded via [`Role::from_str`]).
    pub role: Role,
    /// How the account authenticates (`local`, `oidc`, ...; the
    /// `auth_provider` TEXT column).
    pub auth_provider: String,
    /// Argon2id password verification hash; `None` for SSO-only accounts.
    pub password_hash: Option<String>,
    /// Sealed TOTP secret (BYTEA column; plaintext never stored).
    pub totp_secret_encrypted: Option<Vec<u8>>,
    /// The AEAD nonce for [`UserModel::totp_secret_encrypted`].
    pub totp_secret_nonce: Option<Vec<u8>>,
    /// WebAuthn credential JSON payload, if registered.
    pub webauthn_credential: Option<JsonValue>,
    /// Whether a second factor is registered and enforced.
    pub mfa_enabled: bool,
    /// Azure AD object id for the tenant's Azure OIDC provider.
    pub azure_oid: Option<String>,
    /// Generic OIDC subject claim, unique per tenant.
    pub oidc_sub: Option<String>,
    /// Whether the account may log in (deactivation flips this, and
    /// deactivation is the only user-delete path).
    pub is_active: bool,
    /// The next login must change the password.
    pub force_password_reset: bool,
    /// Consecutive failed login count (lockout policy input).
    pub failed_login_attempts: i32,
    /// The login lockout instant, `None` when not locked.
    pub locked_until: Option<DateTime<Utc>>,
    /// Last successful login, `None` before the first.
    pub last_login_at: Option<DateTime<Utc>>,
    /// Row creation time.
    pub created_at: DateTime<Utc>,
    /// Row update time.
    pub updated_at: DateTime<Utc>,
}
