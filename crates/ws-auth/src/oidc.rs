//! Generic OIDC SSO (Keycloak, Azure AD, custom providers), ported in shape —
//! discovery → authorization redirect → code exchange → ID token verification —
//! from the house flow in `pm-web/src/routes/sso.rs`.
//!
//! The layering matches the house design, minus the HTTP handlers: this crate
//! owns discovery, the token-endpoint exchange, and signature verification of
//! the ID token against the provider's JWKS. Anything session-shaped (CSRF
//! state storage, the authorization-redirect URL with PKCE, user matching) is
//! the API layer's concern.
//!
//! Error mapping (AuthError has no provider-specific variants, so the
//! deployment-shaped failures land in `Config`):
//!
//! - `Config` — request transport failures, non-2xx replies, discovery/JWKS
//!   documents that are malformed or miss required fields, token responses
//!   without an `id_token` (usually a provider misconfiguration: no `openid`
//!   scope).
//! - `BadCredentials` — the token endpoint rejected the code/client (4xx).
//! - `TokenInvalid` — the ID token failed signature or claim verification.
//!   An unverified ID token is never turned into an identity.

use std::collections::HashSet;
use std::time::Duration;

/// PKCE (RFC 7636) S256 material for the authorization-code flow: the
/// verifier travels to the token endpoint, the challenge — the only
/// half that leaves the server before the code arrives — rides the
/// authorize URL. The S256 transform means the IdP never sees the
/// verifier and nothing but the verifier proves code ownership.
pub mod pkce {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use rand::{rngs::SysRng, TryRng};
    use sha2::{Digest, Sha256};
    use zeroize::Zeroize;

    /// Derive `(verifier, challenge)` from 32 bytes of entropy: the
    /// verifier is base64url (no pad) of the seed — 43 unreserved-charset
    /// characters (RFC 7636 §4.1) — and the challenge is
    /// base64url(SHA-256(verifier)) (§4.2's `S256`). The seed is
    /// zeroized before return; the challenge derives from the verifier
    /// alone, so the challenge can leave while the verifier stays.
    pub fn generate_verifier(mut seed: [u8; 32]) -> (String, String) {
        let verifier = URL_SAFE_NO_PAD.encode(seed);
        seed.zeroize();
        let digest = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(digest);
        (verifier, challenge)
    }

    /// Draw 32 bytes of OS entropy and produce `(verifier, challenge)`.
    pub fn mint_verifier() -> Result<(String, String), crate::error::AuthError> {
        let mut seed = [0u8; 32];
        SysRng.try_fill_bytes(&mut seed).map_err(|e| {
            crate::error::AuthError::Crypto(format!(
                "os entropy unavailable for the PKCE verifier: {e}"
            ))
        })?;
        Ok(generate_verifier(seed))
    }
}

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;

use crate::error::AuthError;

/// The per-call OIDC provider configuration, as the API layer decodes it from
/// the database row. The `client_secret` arrives in plaintext here — encryption
/// at rest is the caller's job (the house rows carry
/// `client_secret_encrypted` + `client_secret_nonce`, decrypted just before
/// the exchange; `pm-web/src/routes/sso.rs` `OidcConfig`).
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// `keycloak` | `azure` | `custom` (house vocabulary).
    pub provider_type: String,
    pub display_name: String,
    /// The provider's `/.well-known/openid-configuration` URL.
    pub discovery_url: String,
    pub client_id: String,
    /// Plaintext; decrypt the stored ciphertext just before use. An empty
    /// string is the house's "public client" convention and is omitted from
    /// the token request.
    pub client_secret: String,
    pub redirect_uri: String,
    /// Space-separated, must include `openid` for an ID token to come back.
    pub scopes: String,
}

/// The discovery document fields Wardstone consumes.
#[derive(Debug, Clone)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

/// The subject an ID token authenticates, extracted from signature-verified
/// claims only.
#[derive(Debug, Clone)]
pub struct OidcIdentity {
    /// The `sub` claim — or the Azure-specific `oid` fallback (house shape:
    /// `pm-web/src/routes/sso.rs` prefers `sub`, falls back to `oid`).
    pub subject: String,
    pub email: Option<String>,
    /// Whether the provider verified the email claim (Core Profile
    /// `email_verified`). Task 10's account-linking contract accepts an
    /// email match ONLY when the provider says it was verified — an
    /// unverified email is attacker-controllable for most providers.
    pub email_verified: Option<bool>,
    /// The `name` claim, falling back to `preferred_username`.
    pub display_name: Option<String>,
}

/// ID-token claims. Extra claims are tolerated (providers add many); only the
/// identity-bearing ones are decoded.
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: Option<String>,
    oid: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    preferred_username: Option<String>,
}

pub async fn discover(config: &OidcConfig) -> Result<OidcDiscovery, AuthError> {
    let client = http_client()?;
    let resp = client
        .get(&config.discovery_url)
        .send()
        .await
        .map_err(|e| AuthError::Config(format!("failed to fetch OIDC discovery document: {e}")))?;
    if !resp.status().is_success() {
        return Err(AuthError::Config(format!(
            "OIDC discovery endpoint returned HTTP {}",
            resp.status()
        )));
    }
    let doc: Value = resp.json().await.map_err(|e| {
        AuthError::Config(format!("OIDC discovery document is not valid JSON: {e}"))
    })?;

    let required = [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
    ];
    for field in required {
        check_discovery_field(&doc, field)?;
    }
    let str_field = |name: &str| {
        doc.get(name)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_default()
    };
    Ok(OidcDiscovery {
        issuer: str_field("issuer"),
        authorization_endpoint: str_field("authorization_endpoint"),
        token_endpoint: str_field("token_endpoint"),
        jwks_uri: str_field("jwks_uri"),
    })
}

fn check_discovery_field(doc: &Value, field: &str) -> Result<(), AuthError> {
    let present = doc
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    if present {
        Ok(())
    } else {
        Err(AuthError::Config(format!(
            "OIDC discovery document is missing '{field}'"
        )))
    }
}

pub async fn exchange_code(
    config: &OidcConfig,
    discovery: &OidcDiscovery,
    code: &str,
    state: &str,
    code_verifier: &str,
) -> Result<OidcIdentity, AuthError> {
    // `state` is the CSRF token the API layer validated (and atomically
    // consumed) against its session store before calling — the house checks it
    // by removing a DashMap entry at callback time
    // (`pm-web/src/routes/sso.rs`). ws-auth holds no session state, so it is
    // accepted here for call-site clarity and deliberately not re-validated.
    let _ = state;

    let client = http_client()?;
    let mut params: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", &config.redirect_uri),
        ("client_id", &config.client_id),
    ];
    // PKCE (RFC 7636 §4.6): the verifier the start route minted — the IdP
    // compares its S256 transform against the challenge from the authorize
    // URL, so only the flow that started the login can complete the grant.
    // House: an empty client_secret is a public client — omitted outright
    // rather than sent as an empty credential.
    if !config.client_secret.is_empty() {
        params.push(("client_secret", &config.client_secret));
    }
    params.push(("code_verifier", code_verifier));

    let resp = client
        .post(&discovery.token_endpoint)
        .form(&params)
        .send()
        .await
        .map_err(|e| AuthError::Config(format!("token exchange request failed: {e}")))?;

    // 4xx means the grant itself was rejected (invalid/expired/replayed code
    // or bad client credentials) — the credential-bearing variant. Provider
    // 5xx is a deployment problem, not a caller credential problem.
    if resp.status().is_client_error() {
        return Err(AuthError::BadCredentials);
    }
    if !resp.status().is_success() {
        return Err(AuthError::Config(format!(
            "OIDC token endpoint returned HTTP {}",
            resp.status()
        )));
    }

    let body: Value = resp
        .json()
        .await
        .map_err(|e| AuthError::Config(format!("OIDC token response is not valid JSON: {e}")))?;
    let id_token = body
        .get("id_token")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AuthError::Config(
                "OIDC token response carries no id_token (is the 'openid' scope granted?)"
                    .to_string(),
            )
        })?;

    let jwks = fetch_jwks(&discovery.jwks_uri).await?;
    identity_from_response(config, &discovery.issuer, id_token, &jwks).await
}

/// Verify the ID token's signature against the provider's JWKS and turn the
/// verified claims into an [`OidcIdentity`]. A token that fails verification
/// of any kind — unknown signing key, wrong issuer/audience, stale/expired,
/// missing subject — is an `Err`, never a best-effort identity.
///
/// Split out of [`exchange_code`] (which fetches the JWKS and calls this) so
/// verification is testable without the HTTP legs of the flow.
pub async fn identity_from_response(
    config: &OidcConfig,
    issuer: &str,
    id_token: &str,
    jwks: &Value,
) -> Result<OidcIdentity, AuthError> {
    let header = decode_header(id_token).map_err(|_| AuthError::TokenInvalid)?;
    let kid = header.kid.as_deref().ok_or(AuthError::TokenInvalid)?;

    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(AuthError::TokenInvalid)?;
    let jwk = keys
        .iter()
        .find(|k| k.get("kid").and_then(Value::as_str) == Some(kid))
        .ok_or(AuthError::TokenInvalid)?;

    // RS256 is what every supported provider (Keycloak, Azure AD) signs ID
    // tokens with by default; the house verification pins it too.
    if jwk.get("kty").and_then(Value::as_str) != Some("RSA") {
        return Err(AuthError::TokenInvalid);
    }
    let n = jwk
        .get("n")
        .and_then(Value::as_str)
        .ok_or(AuthError::TokenInvalid)?;
    let e = jwk
        .get("e")
        .and_then(Value::as_str)
        .ok_or(AuthError::TokenInvalid)?;
    let decoding_key =
        DecodingKey::from_rsa_components(n, e).map_err(|_| AuthError::TokenInvalid)?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.iss = Some(HashSet::from([issuer.to_string()]));
    validation.aud = Some(HashSet::from([config.client_id.clone()]));
    // House leeway — a minute of clock tolerance on iat/nbf.
    validation.leeway = 60;

    let claims: IdTokenClaims = decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|_| AuthError::TokenInvalid)?
        .claims;

    // Subject: `sub`, falling back to Azure's `oid` — the house order.
    let subject = claims
        .sub
        .filter(|s| !s.is_empty())
        .or_else(|| claims.oid.filter(|s| !s.is_empty()))
        .ok_or(AuthError::TokenInvalid)?;

    let display_name = claims
        .name
        .filter(|s| !s.is_empty())
        .or_else(|| claims.preferred_username.filter(|s| !s.is_empty()));

    Ok(OidcIdentity {
        subject,
        email: claims.email,
        email_verified: claims.email_verified,
        display_name,
    })
}

fn http_client() -> Result<reqwest::Client, AuthError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| AuthError::Config(format!("failed to build HTTP client: {e}")))
}

async fn fetch_jwks(jwks_uri: &str) -> Result<Value, AuthError> {
    let client = http_client()?;
    let resp = client
        .get(jwks_uri)
        .send()
        .await
        .map_err(|e| AuthError::Config(format!("JWKS fetch request failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(AuthError::Config(format!(
            "JWKS fetch returned HTTP {}",
            resp.status()
        )));
    }
    resp.json()
        .await
        .map_err(|e| AuthError::Config(format!("JWKS response is not valid JSON: {e}")))
}
