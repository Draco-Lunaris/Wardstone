//! The browser-session relay: the `/auth/ui` routes that make ONE opaque
//! cookie stand in for the JWT pair the browser never sees.
//!
//! - `POST /auth/ui/login` — relays ws-api's login; on the token pair it
//!   fetches the `/me` identity (never trusting the browser's view),
//!   stores the pair under a minted session id, and answers with the
//!   identity JSON + `Set-Cookie`. ws-api error bodies (401
//!   `mfa_required` included) pass through UNTOUCHED — the UI keys its
//!   TOTP step on the body's `code`, so the relay must not re-wrap them.
//! - `GET /auth/ui/oidc/{provider}/start` — pure redirect passthrough:
//!   ws-api mints the authorization URL (discovery + csrf state + the
//!   admin-configured `redirect_uri`, which points at ws-web's PUBLIC
//!   callback), and ws-web adds nothing.
//! - `GET /auth/ui/oidc/{provider}/callback` — full query passthrough; on
//!   the exchanged token pair, session minting exactly like login, then a
//!   `303` back to `/` with the cookie.
//! - `POST /auth/ui/logout` — relays the revocation with BOTH halves
//!   ws-api's handler demands (the stored access token as the bearer AND
//!   the stored refresh token in the body), kills the store entry, and
//!   clears the cookie. Idempotent: an unknown or missing session gets the
//!   same quiet 204. The CSRF marker rule guards this mutating
//!   cookie-carrying route exactly like the proxy guards `/api/v1`.
//!
//! [`rotate_once`] is the shared rotation critical section: the proxy's
//! injection path and logout's rotate-and-retry both run their one ws-api
//! refresh under the entry's per-session lock, so a session never has two
//! refreshes in flight and concurrent expired probes collapse into one.

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::proxy::{csrf_refusal, proxy_client, ProxyError};
use crate::session::store::{SessionEntry, SessionStore};
use crate::session::{build_session_cookie, build_session_cookie_clear, read_session_id};

/// The relay routes' shared state: the SAME `Arc<SessionStore>` the proxy
/// injection reads (one instance serves relay + injection — the pin), the
/// bounded client, and the API base URL.
#[derive(Clone)]
pub struct RelayState {
    pub(crate) store: Arc<SessionStore>,
    pub(crate) client: Option<reqwest::Client>,
    pub(crate) base: String,
}

/// The relay's router: the four `/auth/ui` routes, mounted by
/// [`crate::web_router_with_store`] at the same precedence as `/api/v1`
/// (before the SPA fallback).
pub fn relay_router(store: Arc<SessionStore>, api_base_url: &str) -> Router {
    let state = RelayState {
        store,
        // The same bounded construction as the proxy's client (connect +
        // total timeouts); a failed build fails closed per request, never
        // in the router constructor (its pinned signature is infallible).
        client: proxy_client().ok(),
        base: api_base_url.trim_end_matches('/').to_owned(),
    };
    Router::new()
        .route("/auth/ui/login", post(ui_login))
        .route("/auth/ui/logout", post(ui_logout))
        .route("/auth/ui/oidc/{provider}/start", get(ui_oidc_start))
        .route("/auth/ui/oidc/{provider}/callback", get(ui_oidc_callback))
        .with_state(state)
}

/// The relayed ws-api login body (the same shape ws-api's `LoginBody`
/// takes; `totp_code` simply travels when present). Serialized as-is to
/// ws-api and deserialized from the browser — both directions need it.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct UiLoginBody {
    pub username: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_code: Option<String>,
}

/// The token-pair wire shape ws-api's login/refresh/callback/rotation
/// responses carry.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct SessionTokensWire {
    pub access_token: String,
    pub refresh_token: String,
}

/// `POST /auth/ui/login` — the browser's login surface.
async fn ui_login(
    State(relay): State<RelayState>,
    headers: HeaderMap,
    Json(body): Json<UiLoginBody>,
) -> Result<Response, ProxyError> {
    if let Some(refusal) = csrf_refusal(&Method::POST, &headers) {
        return Ok(refusal);
    }
    let client = client_or_502(&relay)?;

    // Relay the login. ANY ws-api error status passes through UNTOUCHED
    // (status + body): 401 `mfa_required` is the UI's TOTP-step signal,
    // 403 the lockout, 401 the wrong password — the relay must not
    // re-wrap any of them.
    let upstream = client
        .post(format!("{}/api/v1/auth/login", relay.base))
        .json(&body)
        .send()
        .await
        .map_err(|err| ProxyError(err.to_string()))?;
    if !upstream.status().is_success() {
        return passthrough(upstream, true).await;
    }

    // The token pair lives here now. The identity is fetched from ws-api
    // with the fresh access token — the browser's own word is never
    // trusted with it.
    let tokens: SessionTokensWire = upstream.json().await.map_err(|err| {
        ProxyError(format!(
            "the API login response was not the token shape: {err}"
        ))
    })?;
    let identity = fetch_identity(&client, &relay.base, &tokens.access_token).await?;
    let entry = entry_from_identity(&identity, tokens.access_token.clone(), tokens.refresh_token)?;
    let session_id = relay.store.insert(entry).await;

    // The browser gets the identity, the cookie, and nothing else.
    Ok(login_response(
        identity,
        build_session_cookie(&session_id.to_string()),
    ))
}

/// `GET /auth/ui/oidc/{provider}/start` — pure redirect passthrough.
async fn ui_oidc_start(
    State(relay): State<RelayState>,
    Path(provider): Path<String>,
) -> Result<Response, ProxyError> {
    let client = client_or_502(&relay)?;
    let response = client
        .get(format!("{}/api/v1/auth/oidc/{provider}/start", relay.base))
        .send()
        .await
        .map_err(|err| ProxyError(err.to_string()))?;
    passthrough(response, false).await
}

/// `GET /auth/ui/oidc/{provider}/callback` — the provider bounces HERE
/// (the config's redirect_uri), the relay forwards the full query, and a
/// successful exchange becomes a session: `303` to `/` with the cookie.
async fn ui_oidc_callback(
    State(relay): State<RelayState>,
    Path(provider): Path<String>,
    uri: Uri,
) -> Result<Response, ProxyError> {
    let client = client_or_502(&relay)?;
    let mut target = format!("{}/api/v1/auth/oidc/{provider}/callback", relay.base);
    if let Some(query) = uri.query() {
        target.push('?');
        target.push_str(query);
    }
    let response = client
        .get(target)
        .send()
        .await
        .map_err(|err| ProxyError(err.to_string()))?;
    if !response.status().is_success() {
        return passthrough(response, true).await;
    }

    let tokens: SessionTokensWire = response.json().await.map_err(|err| {
        ProxyError(format!(
            "the API callback response was not the token shape: {err}"
        ))
    })?;
    let identity = fetch_identity(&client, &relay.base, &tokens.access_token).await?;
    let entry = entry_from_identity(&identity, tokens.access_token.clone(), tokens.refresh_token)?;
    let session_id = relay.store.insert(entry).await;

    Ok((
        [
            (header::LOCATION, "/".to_owned()),
            (
                header::SET_COOKIE,
                build_session_cookie(&session_id.to_string()),
            ),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        StatusCode::SEE_OTHER,
    )
        .into_response())
}

/// `POST /auth/ui/logout` — kill the session here AND its refresh token
/// on ws-api.
async fn ui_logout(
    State(relay): State<RelayState>,
    headers: HeaderMap,
) -> Result<Response, ProxyError> {
    if let Some(refusal) = csrf_refusal(&Method::POST, &headers) {
        return Ok(refusal);
    }
    let clear_cookie = build_session_cookie_clear();
    let no_content = || -> Response {
        (
            [(header::SET_COOKIE, clear_cookie.clone())],
            StatusCode::NO_CONTENT,
        )
            .into_response()
    };

    // Idempotency: no cookie, or a cookie with no live session — the same
    // quiet 204 with the clearing cookie (a browser retry after an unknown
    // session must land in the same place).
    let Some(session_id) = read_session_id(&headers) else {
        return Ok(no_content());
    };
    let Some(entry) = relay.store.get(session_id).await else {
        return Ok(no_content());
    };
    let client = client_or_502(&relay)?;

    // LOCK DISCIPLINE: the session's rotation_lock is held from here across
    // the re-read, the revocation relay, any rotate-and-retry, and the
    // store removal — logout and rotation serialize on the SAME per-session
    // lock, so a concurrent rotation can never rotate away the refresh
    // plaintext this revoke targets (an unlocked revoke could kill a
    // just-rotated-away generation and strand one LIVE refresh row whose
    // plaintext only ws-web's memory held). Mutex ordering is
    // rotation_lock -> store Mutex — the order every rotation path uses;
    // never the reverse.
    let _rotation_guard = entry.rotation_lock.lock().await;
    // The CURRENT generation, re-read under the lock: any interleaved
    // rotation already finished (it held this same lock), so the store's
    // newest pair is what the revoke must target — never this request's
    // possibly-stale snapshot (which `entry` still is).
    let Some(current) = relay.store.get(session_id).await else {
        return Ok(no_content());
    };

    // ws-api's logout demands BOTH halves: the session's bearer access
    // (its handler resolves the actor and binds the body's token to the
    // access token's sid) AND the refresh token in the body.
    let revoke = |access: &str, refresh: &str| {
        client
            .post(format!("{}/api/v1/auth/logout", relay.base))
            .header(header::AUTHORIZATION, format!("Bearer {access}"))
            .json(&json!({ "refresh_token": refresh }))
            .send()
    };
    let relayed = revoke(&current.access_token, &current.refresh_token).await;
    let relayed = match relayed {
        Ok(response) if response.status() == StatusCode::UNAUTHORIZED => {
            // The CURRENT access died mid-session (expired, or the sid
            // revoked elsewhere): refresh ONCE and retry with the fresh
            // pair — a logout must still revoke, not orphan the live row.
            // The rotation_lock is ALREADY held here, so the shared
            // `rotate_once` must NOT be called (it takes the same lock —
            // that would deadlock); `refresh_locked` performs the
            // identical ws-api exchange under the lock precondition.
            match refresh_locked(&relay.store, session_id, &current, &client, &relay.base).await {
                Some(tokens) => Some(
                    revoke(&tokens.access_token, &tokens.refresh_token)
                        .await
                        .map_err(|err| ProxyError(err.to_string()))?,
                ),
                // The refresh was refused (revoked/expired): there is no
                // live pair left to revoke server-side (the session was
                // removed by refresh_locked); the local logout proceeds.
                None => None,
            }
        }
        // Any other relayed answer (204 revoked, 400 already-unknown,
        // whatever ws-api says) counts: the local session ends regardless.
        Ok(response) => Some(response),
        // A transport failure is the ONE case that keeps the local
        // session: ws-api may be briefly unreachable, and a retained
        // session can be logged out again on retry (idempotently).
        Err(err) => return Err(ProxyError(err.to_string())),
    };
    drop(relayed);
    relay.store.remove(session_id).await;
    Ok(no_content())
}

// ---------------------------------------------------------------------------
// The shared rotation critical section
// ---------------------------------------------------------------------------

/// The outcome of one locked rotation attempt: the fresh ACCESS token to
/// proceed with (`refresh` is store-internal after the rotation — no
/// caller consumes it, the pair lives in the new generation), or `Died`
/// (the session was removed — refresh refused or the store entry vanished
/// under the lock).
pub(crate) enum RotationOutcome {
    Fresh { access: String },
    Died,
}

/// The rotation critical section, shared by the proxy's injection path and
/// (through [`refresh_locked`], under logout's OWN rotation-lock hold)
/// logout's rotate-and-retry. Under the entry's per-session lock:
///
/// 1. re-read the CURRENT generation — if its access token differs from
///    `observed_access`, another waiter already rotated: hand back ITS
///    fresh pair without a second ws-api refresh (the once-only pin);
/// 2. otherwise relay `POST /api/v1/auth/refresh` with the stored refresh
///    token (the only caller that holds the lock does this);
/// 3. on success, swap the new pair in as the next generation and return
///    it; on ANY failure (ws-api refusal, transport error, bad shape) the
///    session is REMOVED and `Died` returned — fail closed, the browser
///    is logged out rather than left holding a zombie session.
pub(crate) async fn rotate_once(
    store: &Arc<SessionStore>,
    session_id: Uuid,
    observed_entry: &Arc<SessionEntry>,
    observed_access: &str,
    client: &reqwest::Client,
    base: &str,
) -> RotationOutcome {
    let _rotation_guard = observed_entry.rotation_lock.lock().await;

    // Another waiter may have rotated for us while we waited on the lock.
    let Some(current) = store.get(session_id).await else {
        return RotationOutcome::Died;
    };
    if current.access_token != observed_access {
        return RotationOutcome::Fresh {
            access: current.access_token.clone(),
        };
    }

    // The lock holder relays the one refresh (refresh_locked takes the
    // lock as a PRECONDITION — we hold it; it can never re-take it).
    match refresh_locked(store, session_id, &current, client, base).await {
        Some(tokens) => RotationOutcome::Fresh {
            access: tokens.access_token,
        },
        None => RotationOutcome::Died,
    }
}

/// The ws-api refresh exchange, run with the CALLER holding the session's
/// rotation_lock (both `rotate_once`'s critical section and logout's locked
/// revoke land here). Relays `POST /api/v1/auth/refresh` with the stored
/// refresh plaintext; on success swaps the new pair in as the next
/// generation and returns it; on ANY failure (ws-api refusal, transport
/// error, bad shape) the session is REMOVED and `None` returned — fail
/// closed, the browser is logged out rather than left holding a zombie
/// session.
async fn refresh_locked(
    store: &Arc<SessionStore>,
    session_id: Uuid,
    current: &Arc<SessionEntry>,
    client: &reqwest::Client,
    base: &str,
) -> Option<SessionTokensWire> {
    let response = client
        .post(format!("{base}/api/v1/auth/refresh"))
        .json(&json!({ "refresh_token": current.refresh_token }))
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        Err(err) => {
            // A transient transport failure still kills the session:
            // fail closed (the browser retries from a fresh login; the
            // alternative — keeping an unrotatable session — is worse).
            tracing::warn!(error = %err, "the session refresh relay failed; killing the browser session");
            store.remove(session_id).await;
            return None;
        }
    };
    if !response.status().is_success() {
        tracing::warn!(
            status = %response.status(),
            "ws-api refused the session refresh; killing the browser session"
        );
        store.remove(session_id).await;
        return None;
    }
    let tokens: Result<SessionTokensWire, _> = response.json().await;
    match tokens {
        Ok(tokens) => {
            store
                .update_tokens(
                    session_id,
                    tokens.access_token.clone(),
                    tokens.refresh_token.clone(),
                )
                .await;
            Some(tokens)
        }
        Err(err) => {
            tracing::warn!(error = %err, "the refresh response was not the token shape; killing the browser session");
            store.remove(session_id).await;
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Relay plumbing
// ---------------------------------------------------------------------------

/// Fetch the `/me` identity with a fresh access token (server-side, after
/// login or the OIDC callback). Anything but a 200 JSON body is an
/// upstream misbehavior the relay surfaces as a 502 — a login whose
/// identity cannot be established must not mint a half-known session.
async fn fetch_identity(
    client: &reqwest::Client,
    base: &str,
    access: &str,
) -> Result<Bytes, ProxyError> {
    let response = client
        .get(format!("{base}/api/v1/auth/me"))
        .header(header::AUTHORIZATION, format!("Bearer {access}"))
        .send()
        .await
        .map_err(|err| ProxyError(err.to_string()))?;
    if !response.status().is_success() {
        return Err(ProxyError(format!(
            "the identity fetch after login failed with status {}",
            response.status()
        )));
    }
    response
        .bytes()
        .await
        .map_err(|err| ProxyError(err.to_string()))
}

/// Build the store entry from the `/me` identity bytes + the fresh token
/// pair. Only the identity fields the store records are read; the body
/// itself travels to the browser verbatim (no re-serialization, no shape
/// coupling).
fn entry_from_identity(
    identity: &Bytes,
    access_token: String,
    refresh_token: String,
) -> Result<SessionEntry, ProxyError> {
    let value: Value = serde_json::from_slice(identity)
        .map_err(|err| ProxyError(format!("the identity response was not JSON: {err}")))?;
    let tenant_id: Uuid = value
        .get("tenant_id")
        .and_then(Value::as_str)
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| ProxyError("the identity response carried no tenant_id".to_owned()))?;
    // Non-user actors (machine identities cannot log in through the UI,
    // but the shape allows it) keep empty display fields; the session
    // still works through injection.
    let username = value
        .get("username")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let role = value
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Ok(SessionEntry::new(
        tenant_id,
        username,
        role,
        access_token,
        refresh_token,
    ))
}

/// The login's response to the browser: the identity body VERBATIM (the
/// MeResponse shape arrives from ws-api untouched), the session cookie,
/// and `no-store` (an authenticated response must not be cached).
fn login_response(identity: Bytes, cookie: String) -> Response {
    (
        [
            (header::SET_COOKIE, cookie),
            (header::CACHE_CONTROL, "no-store".to_owned()),
            (header::CONTENT_TYPE, "application/json".to_owned()),
        ],
        identity,
    )
        .into_response()
}

/// Pass an upstream response through: status, Content-Type, Location (the
/// redirect case), and body verbatim. `no_store` adds the cache refusal —
/// for the auth responses whose bodies carry account/session decisions.
async fn passthrough(upstream: reqwest::Response, no_store: bool) -> Result<Response, ProxyError> {
    let status = upstream.status();
    let content_type = upstream.headers().get(header::CONTENT_TYPE).cloned();
    let location = upstream.headers().get(header::LOCATION).cloned();
    let payload = upstream
        .bytes()
        .await
        .map_err(|err| ProxyError(err.to_string()))?;
    let mut builder = Response::builder().status(status);
    if let Some(value) = content_type {
        builder = builder.header(header::CONTENT_TYPE, value);
    }
    if let Some(value) = location {
        builder = builder.header(header::LOCATION, value);
    }
    if no_store {
        builder = builder.header(header::CACHE_CONTROL, "no-store");
    }
    builder
        .body(Body::from(payload))
        .map_err(|err| ProxyError(format!("the relayed response broke: {err}")))
}

/// The relay's per-request client, fail-closed when the construction
/// failed at router build (the ProxyError 502 shape).
fn client_or_502(relay: &RelayState) -> Result<reqwest::Client, ProxyError> {
    relay
        .client
        .clone()
        .ok_or_else(|| ProxyError("the relay HTTP client could not be initialized".to_owned()))
}
