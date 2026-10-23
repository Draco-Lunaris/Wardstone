//! The ACME (RFC 8555) route surface: the directory, the new-nonce
//! endpoint, the account lifecycle (new-account incl. only-return-existing
//! and the ToS gate, account update, deactivation with its cascade, and
//! the atomic account-key rollover).
//!
//! This is JWS-machine traffic, mounted OUTSIDE `/api/v1` at `/acme`
//! (Plan-1-pinned URL shape): no bearer/session extractor ever touches it —
//! the sole authority for every request is [`ws_acme::verify_jws`] plus
//! RFC 8555's protected-header rules, and every response — success AND
//! failure — mints a fresh `Replay-Nonce` through the [`replay_nonce`]
//! middleware (a spent nonce fails its replay even when the request's
//! signature failed, which is `verify_jws`'s consume-before-verdict
//! discipline surfaced over HTTP).
//!
//! Tenancy (v1): the surface takes the tenant as a PATH segment
//! (`/acme/{tenant}/…`), resolved against the install's PRIMARY tenant
//! (the first created — the same ruling the login surface runs). A
//! mismatched segment is ONE 404 problem document ("unknown ACME tenant"),
//! never a cross-tenant read.
//!
//! Account identity: the account URL is
//! `{public_url}/acme/{tenant}/acct/{RFC 7638 thumbprint}` — the FULL
//! thumbprint as the final segment (the safer [call]: unambiguous, no
//! prefix collisions, and the kid URL then parses to a direct
//! thumbprint-keyed lookup). Every absolute URL is built from the
//! configured `public_url` — the `Host` header is NEVER consulted (the
//! spec's anti-goal stands; settlement 7).
//!
//! Problem documents: `{"type": "urn:ietf:params:acme:error:<slug>",
//! "detail", "status"}` with `Content-Type: application/problem+json`
//! ([`AcmeProblem`]). Payload handling beyond the JWS floor is deliberately
//! RFC-shaped and lenient about unknown members (external account binding
//! is accepted-and-ignored per the spec's non-goal).

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::header;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::PeerIpKeyExtractor;
use tower_governor::GovernorLayer;
use uuid::Uuid;
use ws_acme::{AcmeError, NonceStore};
use ws_core::error::CoreError;
use ws_core::models::acme::{AcmeAccountModel, AcmeAccountStatus};
use ws_core::models::rbac::{Actor, ActorType, AuthMethod};
use ws_core::models::tenant::Tenant;
use ws_core::repo::acme_repo::AcmeRepo;
use ws_core::repo::audit_repo::AuditRepo;
use ws_core::repo::tenant_repo::TenantRepo;

use crate::error::ApiError;
use crate::routes::audit_entry;
use crate::routes::auth::primary_tenant;
use crate::state::AppState;

/// The problem URN for the ToS gate — in the ACME error registry, though
/// [`ws_acme::AcmeError`] never carries it (the ToS gate is route-level
/// policy, not a JOSE-floor verdict).
const URN_USER_ACTION_REQUIRED: &str = "urn:ietf:params:acme:error:userActionRequired";

/// The problem URN for the `onlyReturnExisting` miss (RFC 8555 §7.3.3),
/// named here for the same reason as the ToS gate above.
const URN_ACCOUNT_DOES_NOT_EXIST: &str = "urn:ietf:params:acme:error:accountDoesNotExist";

/// The `Replay-Nonce` response header (RFC 8555 §6.5): every `/acme`
/// response — success and failure alike — carries a fresh one.
const REPLAY_NONCE: HeaderName = HeaderName::from_static("replay-nonce");

/// The ACME route tree, nested at `/acme` by the outer router: the
/// tenantless nonce endpoint (`GET /acme/new-nonce` — nonces are
/// tenant-independent) plus the per-tenant routes.
///
/// The new-account POST is the only route under the per-IP GCRA (the
/// Review-Focus-5 surface: unauthenticated enrollment abuse), wrapped in
/// the house auth-route idiom over `auth_rate_limit` — `None` disables the
/// layer (in-process tests: `ConnectInfo` does not exist for oneshot
/// requests, though the rate-limit TEST injects it — see
/// `tests/acme_test.rs`).
pub fn router(state: &AppState) -> Router<AppState> {
    let new_account = Router::new().route("/{tenant}/new-account", post(new_account));
    let new_account = match state.config.auth_rate_limit {
        Some(limit) => {
            // The auth.rs idiom verbatim: `finish()` fails only on a zero
            // burst or period (both caller-configured); a broken number is
            // a loudly-logged skip, never a panic.
            match GovernorConfigBuilder::<PeerIpKeyExtractor, _>::default()
                .per_millisecond(limit.per_millis)
                .burst_size(limit.burst)
                .finish()
            {
                Some(config) => new_account.layer(GovernorLayer::new(Arc::new(config))),
                None => {
                    tracing::error!(
                        per_millis = limit.per_millis,
                        burst = limit.burst,
                        "invalid ACME rate-limit configuration: per_millis and burst must \
                         be positive; new-account runs WITHOUT rate limiting"
                    );
                    new_account
                }
            }
        }
        None => new_account,
    };

    Router::new()
        .route("/new-nonce", get(new_nonce))
        .route("/{tenant}/directory", get(directory))
        .route("/{tenant}/acct/{account}", post(account_url))
        .route("/{tenant}/key-change", post(key_change))
        .merge(new_account)
        // Every /acme response — including the governor's 429s and every
        // problem document — mints a fresh Replay-Nonce here (layers added
        // later wrap everything earlier, governor included).
        .layer(axum::middleware::from_fn_with_state(
            state.nonces.clone(),
            replay_nonce,
        ))
        .with_state(state.clone())
}

/// The replay-nonce middleware: mint one fresh nonce per response into the
/// `Replay-Nonce` header. Both arms of every handler (and every layer the
/// handler sits under) flow through here, so the header is present on
/// success and failure alike.
async fn replay_nonce(
    State(nonces): State<Arc<NonceStore>>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&nonces.mint()) {
        headers.insert(REPLAY_NONCE, value);
    }
    response
}

/// `GET /acme/new-nonce` — the RFC 8555 §6.5 nonce endpoint: 204, no body,
/// a fresh `Replay-Nonce` (from the middleware), and `Cache-Control:
/// no-store`. axum routes HEAD here too and answers it bodyless.
async fn new_nonce() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `GET /acme/{tenant}/directory` — the RFC 8555 §7.1.1 directory object.
///
/// `newAuthz` is deliberately ABSENT in v1 (pre-authorization is not
/// offered). `newOrder`/`revokeCert` are named so the directory is
/// complete for real clients; those routes arrive with Tasks 6-8 and
/// answer problem documents until then — the directory's entries are URLs
/// the server chooses, not route-mount assertions. When `tos_url` is
/// configured the response carries the `Link: <tos>;rel="terms-of-service"`
/// header (the plan's pin).
async fn directory(
    State(state): State<AppState>,
    Path(tenant_name): Path<String>,
) -> Result<Response, AcmeProblem> {
    let tenant = resolve_tenant(&state, &tenant_name).await?;
    let base = public_base(&state)?;
    let tenant_base = format!("{base}/acme/{}", tenant.name);
    let directory = json!({
        "newNonce": format!("{base}/acme/new-nonce"),
        "newAccount": format!("{tenant_base}/new-account"),
        "newOrder": format!("{tenant_base}/new-order"),
        "revokeCert": format!("{tenant_base}/revoke-cert"),
        "keyChange": format!("{tenant_base}/key-change"),
    });
    let mut response = Json(directory).into_response();
    if let Some(tos) = state.config.acme.tos_url.as_ref() {
        if let Ok(value) = HeaderValue::from_str(&format!("<{tos}>;rel=\"terms-of-service\"")) {
            response.headers_mut().insert(header::LINK, value);
        }
    }
    Ok(response)
}

/// The new-account request payload (RFC 8555 §7.3): agreement flag,
/// only-return-existing, the contact array (a single stored value in v1),
/// and external account binding — which the spec lists as
/// accept-and-ignore, so it deserializes into an inert member.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewAccountPayload {
    terms_of_service_agreed: Option<bool>,
    #[serde(default)]
    only_return_existing: bool,
    contact: Option<Vec<String>>,
    /// External account binding is accept-and-IGNORED in v1 (the spec's
    /// non-goal): the member deserializes into an inert value so a client
    /// that still sends it is not refused, and nothing is ever read from
    /// it.
    #[allow(dead_code)]
    external_account_binding: Option<Value>,
}

/// The account-URL request payload (RFC 8555 §7.3.2): the account update
/// and deactivation members; an EMPTY payload is RFC POST-as-GET.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountPayload {
    status: Option<String>,
    terms_of_service_agreed: Option<bool>,
    contact: Option<Vec<String>>,
    #[serde(default)]
    only_return_existing: bool,
    /// External account binding is accept-and-IGNORED in v1 (the spec's
    /// non-goal): the member deserializes into an inert value so a client
    /// that still sends it is not refused, and nothing is ever read from
    /// it.
    #[allow(dead_code)]
    external_account_binding: Option<Value>,
}

/// `POST /acme/{tenant}/new-account` — the RFC 8555 §7.3 enrollment:
/// embedded-JWK JWS only (any `kid` is refused at this boundary), the
/// idempotency branch returning the existing account (200) with any
/// offered changes applied, the ToS gate minting a `pending` account under
/// a `userActionRequired` problem when configured, and per-IP GCRA above
/// the handler. A creation answers 201 with the account's `Location`.
async fn new_account(
    State(state): State<AppState>,
    Path(tenant_name): Path<String>,
    raw: Bytes,
) -> Result<Response, AcmeProblem> {
    let tenant = resolve_tenant(&state, &tenant_name).await?;
    let base = public_base(&state)?;
    let expected_url = format!("{base}/acme/{}/new-account", tenant.name);
    let raw = as_str(&raw)?;

    let jws = ws_acme::verify_jws(
        raw,
        // A new-account request MUST embed its key: a kid here names
        // nothing (the account is being created) and is a malformed
        // request, while a kid+jwk pair is refused inside verify_jws
        // itself (the Review-Focus-3 trap, re-pinned at this boundary).
        &|_kid: &str| {
            Err(AcmeError::Malformed(
                "a new-account request must embed its account key as a protected jwk, \
                 not a kid"
                    .to_owned(),
            ))
        },
        &|n| state.nonces.consume(n),
        &expected_url,
    )
    .map_err(AcmeProblem::from)?;
    let body: NewAccountPayload = serde_json::from_value(jws.payload).map_err(|_| {
        AcmeProblem::malformed("the new-account payload is not a valid request object")
    })?;
    let thumbprint = ws_acme::thumbprint(&jws.key).map_err(AcmeProblem::from)?;
    let account_url_str = format!("{base}/acme/{}/acct/{thumbprint}", tenant.name);

    // Idempotency: the same key in the SAME tenant already holds an
    // account → return it (200; never 201). With `onlyReturnExisting` the
    // request is a pure existence probe: the account comes back unchanged.
    if let Some(account) = AcmeRepo::new()
        .get_account(&state.pool, tenant.id, &thumbprint)
        .await?
    {
        if body.only_return_existing {
            return Ok(account_response(
                StatusCode::OK,
                &base,
                &tenant.name,
                &account,
            ));
        }
        match account.status {
            AcmeAccountStatus::Deactivated => {
                // RFC 8555 §7.3.7: deactivation is a one-way gate; the key
                // of a deactivated account cannot re-register.
                return Err(AcmeProblem::unauthorized(
                    "the account for this key is deactivated",
                ));
            }
            AcmeAccountStatus::Valid | AcmeAccountStatus::Pending => {
                let updated = update_contact_and_tos(
                    &state,
                    &tenant,
                    &account,
                    body.contact.as_ref(),
                    body.terms_of_service_agreed == Some(true),
                    &account_url_str,
                )
                .await?;
                return Ok(account_response(
                    StatusCode::OK,
                    &base,
                    &tenant.name,
                    &updated,
                ));
            }
        }
    }

    if body.only_return_existing {
        return Err(AcmeProblem {
            status: StatusCode::NOT_FOUND,
            type_urn: URN_ACCOUNT_DOES_NOT_EXIST,
            detail: "no account exists for the presented key".to_owned(),
            tos_link: None,
            location: None,
        });
    }

    let agreed = body.terms_of_service_agreed == Some(true);
    let tos_required = state.config.acme.tos_url.is_some();
    // The ToS gate: with a ToS published and the client not agreeing, the
    // account is minted `pending` (its status gate blocks orders later)
    // and the answer is a 403 `userActionRequired` problem carrying the
    // ToS Link. No ToS published → valid immediately (spec settlement 9:
    // no enforcement step).
    let status = if agreed || !tos_required {
        AcmeAccountStatus::Valid
    } else {
        AcmeAccountStatus::Pending
    };
    let account = AcmeAccountModel {
        id: Uuid::new_v4(),
        tenant_id: tenant.id,
        jwk_thumbprint: thumbprint.clone(),
        jwk: jws.key,
        status,
        tos_agreed_at: agreed.then(chrono::Utc::now),
        contact: body.contact.as_ref().and_then(|list| contact_of(list)),
        created_at: chrono::Utc::now(),
    };

    let mut tx = state.pool.begin().await?;
    match AcmeRepo::new().insert_account(&mut *tx, &account).await {
        Ok(()) => {}
        // The duplicate-key race (a concurrent registration with the same
        // key between the lookup and this insert): nothing was committed;
        // dropping the tx rolls it back, and the client retries into the
        // idempotency branch above.
        Err(CoreError::Duplicate) => {
            return Err(AcmeProblem::internal(
                "a concurrent registration raced this key; retry the request",
            ));
        }
        Err(err) => return Err(err.into()),
    }
    let actor = acme_actor(tenant.id, account_url_str.clone());
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &actor,
                "acme_account_created",
                "acme_account",
                &account.id.to_string(),
                json!({
                    "account_url": account_url_str,
                    "jwk_thumbprint": thumbprint,
                    "status": account.status.as_str(),
                    "tos_required": tos_required,
                }),
            ),
        )
        .await?;
    tx.commit().await?;

    if account.status == AcmeAccountStatus::Pending {
        return Err(AcmeProblem {
            status: StatusCode::FORBIDDEN,
            type_urn: URN_USER_ACTION_REQUIRED,
            detail: "you must agree to the terms of service \
                     (re-send the request with termsOfServiceAgreed)"
                .to_owned(),
            tos_link: state
                .config
                .acme
                .tos_url
                .as_ref()
                .map(|tos| format!("<{tos}>;rel=\"terms-of-service\"")),
            location: Some(account_url_str),
        });
    }
    Ok(account_response(
        StatusCode::CREATED,
        &base,
        &tenant.name,
        &account,
    ))
}

/// `POST /acme/{tenant}/acct/{account}` — the RFC 8555 §7.3.2 account
/// URL: POST-as-GET (empty payload) and `onlyReturnExisting` read the
/// account, a `contact` member updates it, `termsOfServiceAgreed` promotes
/// a `pending` account, and `status: "deactivated"` deactivates it with
/// the cascade (pending authorizations invalidated, open orders invalid).
/// The URL's final segment is the account key's FULL RFC 7638 thumbprint
/// (the [call]: unambiguous, directly thumbprint-keyed).
async fn account_url(
    State(state): State<AppState>,
    Path((tenant_name, account_thumb)): Path<(String, String)>,
    raw: Bytes,
) -> Result<Response, AcmeProblem> {
    let tenant = resolve_tenant(&state, &tenant_name).await?;
    let base = public_base(&state)?;
    let expected_url = format!("{base}/acme/{}/acct/{account_thumb}", tenant.name);
    let raw = as_str(&raw)?;

    // Pre-resolve the kid synchronously (the verifier's resolver is a sync
    // closure): peek the UNVERIFIED protected header, parse the kid URL —
    // it MUST be an account URL of THIS tenant built from the configured
    // public base, else it does not resolve (a kid from another tenant is
    // a lookup failure, never a cross-tenant account) — and fetch the key
    // material into a cache the closure reads.
    let peeked = peek_header(raw)?;
    let mut kid_keys: HashMap<String, Value> = HashMap::new();
    if let Some(kid) = peeked.kid.filter(|_| peeked.jwk.is_none()) {
        if let Some(thumb) = kid_thumbprint(&kid, &base, &tenant.name) {
            if let Some(account) = AcmeRepo::new()
                .get_account(&state.pool, tenant.id, &thumb)
                .await?
            {
                // Cached under THE KID STRING the closure reads.
                kid_keys.insert(kid, account.jwk);
            }
        }
    }

    let jws = ws_acme::verify_jws(
        raw,
        &|kid: &str| Ok(kid_keys.get(kid).cloned()),
        &|n| state.nonces.consume(n),
        &expected_url,
    )
    .map_err(AcmeProblem::from)?;

    // The account route authenticates with the kid only.
    if jws.header.jwk.is_some() {
        return Err(AcmeProblem::malformed(
            "an account request must authenticate with its kid, not an embedded jwk",
        ));
    }
    let kid = jws.header.kid.as_deref().ok_or_else(|| {
        AcmeProblem::malformed("an account request must name its account URL as a kid")
    })?;
    if kid != expected_url {
        return Err(AcmeProblem::malformed(
            "the kid does not name the requested account URL",
        ));
    }
    let account = AcmeRepo::new()
        .get_account(&state.pool, tenant.id, &account_thumb)
        .await?
        .ok_or(AcmeError::NoSuchAccount)
        .map_err(AcmeProblem::from)?;

    // The empty payload is RFC 8555's POST-as-GET: a plain read.
    if jws.payload.is_null() {
        return Ok(account_response(
            StatusCode::OK,
            &base,
            &tenant.name,
            &account,
        ));
    }
    let body: AccountPayload = serde_json::from_value(jws.payload)
        .map_err(|_| AcmeProblem::malformed("the account payload is not a valid request object"))?;
    if body.only_return_existing {
        return Ok(account_response(
            StatusCode::OK,
            &base,
            &tenant.name,
            &account,
        ));
    }

    // A deactivated account stays READABLE (the client must be able to see
    // the state it landed in, above) but refuses every mutation.
    if account.status == AcmeAccountStatus::Deactivated {
        return Err(AcmeProblem::unauthorized("the account is deactivated"));
    }

    // The status member: v1 supports exactly one update — deactivation
    // (with its cascade). Anything else is a malformed request.
    match body.status.as_deref() {
        Some("deactivated") => {
            let mut tx = state.pool.begin().await?;
            AcmeRepo::new()
                .update_account_status(
                    &mut *tx,
                    tenant.id,
                    account.id,
                    AcmeAccountStatus::Deactivated,
                )
                .await?;
            let (authorizations, orders) = AcmeRepo::new()
                .deactivation_cascade(&mut tx, tenant.id, account.id, "account deactivated")
                .await?;
            let actor = acme_actor(tenant.id, expected_url.clone());
            AuditRepo::new()
                .record(
                    &mut *tx,
                    &audit_entry(
                        &actor,
                        "acme_account_deactivated",
                        "acme_account",
                        &account.id.to_string(),
                        json!({
                            "account_url": expected_url,
                            "authorizations_invalidated": authorizations,
                            "orders_invalidated": orders,
                        }),
                    ),
                )
                .await?;
            tx.commit().await?;
            tracing::info!(
                account = %account.id,
                authorizations,
                orders,
                "acme account deactivated with its cascade"
            );
        }
        Some(other) => {
            return Err(AcmeProblem::malformed(format!(
                "the account status update {other:?} is not supported; only \
                 \"deactivated\" is"
            )));
        }
        None => {}
    }

    update_contact_and_tos(
        &state,
        &tenant,
        &account,
        body.contact.as_ref(),
        body.terms_of_service_agreed == Some(true),
        &expected_url,
    )
    .await?;

    let updated = AcmeRepo::new()
        .get_account_by_id(&state.pool, tenant.id, account.id)
        .await?
        .ok_or_else(|| AcmeProblem::internal("the account vanished during its update"))?;
    Ok(account_response(
        StatusCode::OK,
        &base,
        &tenant.name,
        &updated,
    ))
}

/// `POST /acme/{tenant}/key-change` — the RFC 8555 §7.3.5 account-key
/// rollover in ONE transaction, as TWO nested envelopes:
///
/// - the OUTER JWS is signed by the EXISTING (old) account key, AS that
///   account's `kid`, with a fresh anti-replay `nonce`, and its payload is
///   the INNER JWS in flattened JSON serialization
///   (`{"protected","payload","signature"}`);
/// - the INNER JWS is signed by the NEW key with that key's `jwk`
///   embedded, binds the SAME `url` (the key-change URL), and MUST OMIT
///   the `nonce` member — its payload is `{"account": <account URL>,
///   "oldKey": <the OLD key's JWK>}`.
///
/// The nonce gate: the OUTER's nonce is consumed (the anti-replay ledger
/// runs on the request as a whole); the inner's gate is non-consuming and
/// accepts exactly the nonce member's ABSENCE — a `nonce` that IS present
/// on the inner (the RFC's MUST NOT) is refused `badNonce` by the same
/// seam.
///
/// The swap keeps the account ROW ID, so every order/authorization
/// linkage survives; the old thumbprint — the old kid — stops resolving,
/// because the identity IS the key. The NEW account location comes back
/// in the response's `Location` header (under the new full-thumbprint
/// URL).
async fn key_change(
    State(state): State<AppState>,
    Path(tenant_name): Path<String>,
    raw: Bytes,
) -> Result<Response, AcmeProblem> {
    let tenant = resolve_tenant(&state, &tenant_name).await?;
    let base = public_base(&state)?;
    let expected_url = format!("{base}/acme/{}/key-change", tenant.name);
    let raw = as_str(&raw)?;

    // Pre-resolve the outer's kid (the OLD account URL) synchronously, the
    // same way the account route does: peek the UNVERIFIED protected
    // header, parse the kid against the tenant prefix, and cache the
    // stored key the verifier's resolver will answer with.
    let peeked = peek_header(raw)?;
    let mut kid_keys: HashMap<String, Value> = HashMap::new();
    if let Some(kid) = peeked.kid.filter(|_| peeked.jwk.is_none()) {
        if let Some(thumb) = kid_thumbprint(&kid, &base, &tenant.name) {
            if let Some(account) = AcmeRepo::new()
                .get_account(&state.pool, tenant.id, &thumb)
                .await?
            {
                kid_keys.insert(kid, account.jwk);
            }
        }
    }

    let outer = ws_acme::verify_jws(
        raw,
        &|kid: &str| Ok(kid_keys.get(kid).cloned()),
        &|n| state.nonces.consume(n),
        &expected_url,
    )
    .map_err(AcmeProblem::from)?;

    // The outer envelope authenticates AS the existing account: kid-carried
    // (an embedded jwk names nothing — the account keeps its identity while
    // changing keys).
    if outer.header.jwk.is_some() {
        return Err(AcmeProblem::malformed(
            "the outer key-change JWS must authenticate with its kid, not an embedded jwk",
        ));
    }
    let kid = outer.header.kid.as_deref().ok_or_else(|| {
        AcmeProblem::malformed("the outer key-change JWS must name its account URL as a kid")
    })?;

    // The outer's payload is the inner JWS in flattened JSON
    // serialization: {"protected", "payload", "signature"} — the same
    // base64url segments the compact form would carry.
    let members = outer.payload.as_object().ok_or_else(|| {
        AcmeProblem::malformed("the key-change payload must carry the inner JWS object")
    })?;
    let protected = json_string_member(members.get("protected"), "the inner JWS's protected")?;
    let payload = json_string_member(members.get("payload"), "the inner JWS's payload")?;
    let signature = json_string_member(members.get("signature"), "the inner JWS's signature")?;
    let inner_compact = format!("{protected}.{payload}.{signature}");

    // The inner JWS's payload names the account being rolled over and the
    // key being retired.
    let inner_payload_bytes = URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .map_err(|_| AcmeProblem::malformed("the inner JWS's payload is not valid base64url"))?;
    let inner_payload: Value = serde_json::from_slice(&inner_payload_bytes)
        .map_err(|_| AcmeProblem::malformed("the inner JWS's payload is not valid JSON"))?;
    let account_url_field = inner_payload
        .get("account")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AcmeProblem::malformed("the inner payload must name the account being updated")
        })?
        .to_owned();
    let old_key = inner_payload.get("oldKey").ok_or_else(|| {
        AcmeProblem::malformed("the inner payload must present the old key as oldKey")
    })?;
    // §7.3.5's bindings: the inner payload's account is the account the
    // OUTER authenticated as, and its `oldKey` is that account's
    // registered key (the very key the outer verified under).
    if account_url_field != kid {
        return Err(AcmeProblem::malformed(
            "the inner payload's account does not match the outer JWS's kid",
        ));
    }
    if old_key != &outer.key {
        return Err(AcmeProblem::malformed(
            "the inner payload's oldKey does not match the account's registered key",
        ));
    }

    // The inner envelope: signed by the NEW key with its `jwk` embedded
    // (a kid here names nothing), SAME url as the outer, and the
    // non-consuming nonce gate that accepts exactly the nonce member's
    // absence (§7.3.5: the inner MUST NOT carry one).
    let inner = ws_acme::verify_jws(
        &inner_compact,
        &|_kid: &str| {
            Err(AcmeError::Malformed(
                "the inner key-change JWS must embed the NEW account key as a \
                 protected jwk, not a kid"
                    .to_owned(),
            ))
        },
        &|n: &str| n.is_empty(),
        &expected_url,
    )
    .map_err(AcmeProblem::from)?;

    let old_thumb = kid_thumbprint(kid, &base, &tenant.name)
        .ok_or(AcmeError::NoSuchAccount)
        .map_err(AcmeProblem::from)?;
    let account = AcmeRepo::new()
        .get_account(&state.pool, tenant.id, &old_thumb)
        .await?
        .ok_or(AcmeError::NoSuchAccount)
        .map_err(AcmeProblem::from)?;
    if account.status == AcmeAccountStatus::Deactivated {
        return Err(AcmeProblem::unauthorized(
            "the account for this key is deactivated",
        ));
    }

    let new_thumb = ws_acme::thumbprint(&inner.key).map_err(AcmeProblem::from)?;
    let new_url = format!("{base}/acme/{}/acct/{new_thumb}", tenant.name);
    let mut tx = state.pool.begin().await?;
    AcmeRepo::new()
        .swap_account_key(&mut *tx, tenant.id, account.id, &inner.key, &new_thumb)
        .await
        .map_err(|err| match err {
            // The tenant already holds another account on the NEW key.
            CoreError::Duplicate => AcmeProblem::malformed(
                "the new account key is already registered to an account in this tenant",
            ),
            other => AcmeProblem::from(other),
        })?;
    let actor = acme_actor(tenant.id, new_url.clone());
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &actor,
                "acme_account_key_changed",
                "acme_account",
                &account.id.to_string(),
                json!({
                    "account_url": new_url,
                    "previous_account_url": kid,
                    "previous_thumbprint": old_thumb,
                    "new_thumbprint": new_thumb,
                }),
            ),
        )
        .await?;
    tx.commit().await?;

    let updated = AcmeRepo::new()
        .get_account_by_id(&state.pool, tenant.id, account.id)
        .await?
        .ok_or_else(|| AcmeProblem::internal("the account vanished during its key change"))?;
    Ok(account_response(
        StatusCode::OK,
        &base,
        &tenant.name,
        &updated,
    ))
}

/// The contact + ToS-agreement half of both account flows (new-account's
/// idempotency branch and the account URL): `contact` handling is
/// RFC 8555 §7.3.2-shaped — absent touches nothing, `[]` clears (an empty
/// contact array), `[uri]`-shaped stores the FIRST URI (v1 keeps a single
/// stored value); `tos_agreed` promotes a `pending` account to `valid` and
/// stamps `tos_agreed_at`. Any actual change lands under one
/// `acme_account_updated` audit row in the SAME transaction.
async fn update_contact_and_tos(
    state: &AppState,
    tenant: &Tenant,
    account: &AcmeAccountModel,
    contact: Option<&Vec<String>>,
    tos_agreed: bool,
    account_url_str: &str,
) -> Result<AcmeAccountModel, AcmeProblem> {
    let new_contact = contact.map(|list| contact_of(list));
    let contact_given = new_contact.is_some();
    if !contact_given && !tos_agreed {
        return Ok(account.clone());
    }
    let mut tx = state.pool.begin().await?;
    let mut changed = false;
    if let Some(desired) = new_contact {
        if desired != account.contact {
            AcmeRepo::new()
                .set_account_contact(&mut *tx, tenant.id, account.id, desired.as_deref())
                .await?;
            changed = true;
        }
    }
    if tos_agreed && account.status == AcmeAccountStatus::Pending {
        AcmeRepo::new()
            .update_account_status(&mut *tx, tenant.id, account.id, AcmeAccountStatus::Valid)
            .await?;
        AcmeRepo::new()
            .set_account_tos_agreed(&mut *tx, tenant.id, account.id, chrono::Utc::now())
            .await?;
        changed = true;
    }
    if changed {
        let actor = acme_actor(tenant.id, account_url_str.to_owned());
        AuditRepo::new()
            .record(
                &mut *tx,
                &audit_entry(
                    &actor,
                    "acme_account_updated",
                    "acme_account",
                    &account.id.to_string(),
                    json!({
                        "account_url": account_url_str,
                        "contact_updated": contact_given,
                        "tos_agreed": tos_agreed,
                    }),
                ),
            )
            .await?;
    }
    tx.commit().await?;
    AcmeRepo::new()
        .get_account_by_id(&state.pool, tenant.id, account.id)
        .await?
        .ok_or_else(|| AcmeProblem::internal("the account vanished during its update"))
}

/// The ACME problem document (RFC 8555 §8.3): the registry URN as `type`,
/// a human `detail`, the HTTP `status` echoed into the body, and the
/// `application/problem+json` content type. The ToS gate and the ToS-gate
/// account's Location ride the optional headers.
struct AcmeProblem {
    status: StatusCode,
    type_urn: &'static str,
    detail: String,
    /// `Link: <tos>;rel="terms-of-service"` for the ToS gate.
    tos_link: Option<String>,
    /// The `Location` the client should act on (the minted pending
    /// account's URL on the userActionRequired problem).
    location: Option<String>,
}

impl IntoResponse for AcmeProblem {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(json!({
                "type": self.type_urn,
                "detail": self.detail,
                "status": self.status.as_u16(),
            })),
        )
            .into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        if let Some(link) = self.tos_link {
            if let Ok(value) = HeaderValue::from_str(&link) {
                response.headers_mut().insert(header::LINK, value);
            }
        }
        if let Some(location) = self.location {
            if let Ok(value) = HeaderValue::from_str(&location) {
                response.headers_mut().insert(header::LOCATION, value);
            }
        }
        response
    }
}

impl AcmeProblem {
    /// A malformed request (400, registry `malformed`).
    fn malformed(detail: impl Into<String>) -> Self {
        AcmeProblem {
            status: StatusCode::BAD_REQUEST,
            type_urn: "urn:ietf:params:acme:error:malformed",
            detail: detail.into(),
            tos_link: None,
            location: None,
        }
    }

    /// Authorization failed (401, registry `unauthorized`).
    fn unauthorized(detail: impl Into<String>) -> Self {
        AcmeProblem {
            status: StatusCode::UNAUTHORIZED,
            type_urn: "urn:ietf:params:acme:error:unauthorized",
            detail: detail.into(),
            tos_link: None,
            location: None,
        }
    }

    /// A server-side condition (500, registry `serverInternal`): database
    /// failures and the unconfigured-public-URL degradation.
    fn internal(detail: impl Into<String>) -> Self {
        AcmeProblem {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            type_urn: "urn:ietf:params:acme:error:serverInternal",
            detail: detail.into(),
            tos_link: None,
            location: None,
        }
    }

    /// The ONE 404 problem document the wrong (or missing) tenant path
    /// earns — indistinguishable whether the segment named another tenant
    /// or no tenant exists at all (setup not run), and never a
    /// cross-tenant read.
    fn unknown_tenant() -> Self {
        AcmeProblem {
            status: StatusCode::NOT_FOUND,
            type_urn: "urn:ietf:params:acme:error:malformed",
            detail: "unknown ACME tenant".to_owned(),
            tos_link: None,
            location: None,
        }
    }
}

/// The `ws_acme` error vocabulary maps onto the same registry: the slug
/// comes from the crate's own `problem_type`, the status from the HTTP
/// semantics of what the error asserted (badNonce is a 400 the client
/// fixes by retrying; a signature or algorithm failure is 401).
impl From<AcmeError> for AcmeProblem {
    fn from(err: AcmeError) -> Self {
        let status = match &err {
            AcmeError::Malformed(_) => StatusCode::BAD_REQUEST,
            AcmeError::BadNonce => StatusCode::BAD_REQUEST,
            AcmeError::NoSuchAccount => StatusCode::NOT_FOUND,
            AcmeError::BadSignature | AcmeError::WrongAlgorithm(_) => StatusCode::UNAUTHORIZED,
            AcmeError::NotImplemented(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        AcmeProblem {
            status,
            type_urn: err.problem_type(),
            detail: err.to_string(),
            tos_link: None,
            location: None,
        }
    }
}

/// A database (or repo) failure is server-side: 500 `serverInternal`.
impl From<CoreError> for AcmeProblem {
    fn from(err: CoreError) -> Self {
        AcmeProblem::internal(format!("the acme route failed: {err}"))
    }
}

impl From<sqlx::Error> for AcmeProblem {
    fn from(err: sqlx::Error) -> Self {
        AcmeProblem::internal(format!("database error: {err}"))
    }
}

/// Resolve the request's tenant: the PATH segment must equal the install's
/// primary tenant (v1 tenancy — one tenant per install, same ruling as the
/// login surface). `ApiError::NotFound` from the primary-tenant lookup
/// (setup not run) folds into the same 404 problem doc as a mismatched
/// segment; a real database failure stays a 500.
async fn resolve_tenant(state: &AppState, path_tenant: &str) -> Result<Tenant, AcmeProblem> {
    let tenant = primary_tenant(&TenantRepo::new(), &state.pool)
        .await
        .map_err(|err| match err {
            ApiError::NotFound(_) => AcmeProblem::unknown_tenant(),
            other => AcmeProblem::internal(format!("tenant resolution failed: {other}")),
        })?;
    if tenant.name != path_tenant {
        return Err(AcmeProblem::unknown_tenant());
    }
    Ok(tenant)
}

/// The absolute URL base every ACME link is built from, with the trailing
/// slash normalized away. An UNCONFIGURED base is the deployment-choice
/// degradation: the routes keep serving, but anything that would build an
/// absolute URL answers `serverInternal` (the binary warns loudly at
/// boot).
fn public_base(state: &AppState) -> Result<String, AcmeProblem> {
    let url = state.config.acme.public_url.trim().trim_end_matches('/');
    if url.is_empty() {
        return Err(AcmeProblem::internal(
            "WARDSTONE_PUBLIC_URL is not configured: the server cannot build \
             absolute ACME URLs",
        ));
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(AcmeProblem::internal(
            "WARDSTONE_PUBLIC_URL must be an absolute http(s) URL",
        ));
    }
    Ok(url.to_owned())
}

/// Parse a kid URL into its account key's FULL RFC 7638 thumbprint:
/// `{base}/acme/{tenant}/acct/{thumbprint}` — anything else (a flatter
/// URL, a foreign tenant's, a name with a slash in the tail) does not
/// resolve here. This is the settlement-7 rule: kids are validated against
/// the CONFIGURED prefix, never the Host header.
fn kid_thumbprint(kid: &str, base: &str, tenant: &str) -> Option<String> {
    let prefix = format!("{base}/acme/{tenant}/acct/");
    let thumbprint = kid.strip_prefix(&prefix)?;
    if thumbprint.is_empty() || thumbprint.contains('/') {
        return None;
    }
    Some(thumbprint.to_owned())
}

/// The ACME audit actor (the spec's pinned shape): the ACCOUNT acts on
/// itself — no capability grant, no session, `minted_by` unset, its id the
/// account URL.
fn acme_actor(tenant_id: Uuid, account_url: String) -> Actor {
    Actor {
        actor_type: ActorType::AcmeAccount,
        actor_id: account_url,
        auth_method: AuthMethod::AcmeAccount,
        capabilities: Vec::new(),
        session_id: None,
        tenant_id,
        minted_by: None,
    }
}

/// The RFC 8555 account object (§7.3.2): `status` (same spellings as the
/// stored enum), `contact` (the stored single value rendered as the RFC's
/// one-element array — empty when unset), and the account's `orders`
/// listing URL (served by the orders tasks).
fn account_object(base: &str, tenant_name: &str, account: &AcmeAccountModel) -> Value {
    json!({
        "status": account.status.as_str(),
        "contact": account
            .contact
            .as_deref()
            .map(|contact| vec![contact.to_owned()])
            .unwrap_or_default(),
        "orders": format!("{base}/acme/{tenant_name}/acct/{}/orders", account.jwk_thumbprint),
    })
}

/// An account-object response with its `Location` header (the full
/// thumbprint URL — RFC 8555 §7.3.3 requires Location on every account
/// response, whatever the status).
fn account_response(
    status: StatusCode,
    base: &str,
    tenant_name: &str,
    account: &AcmeAccountModel,
) -> Response {
    let location = format!("{base}/acme/{tenant_name}/acct/{}", account.jwk_thumbprint);
    let mut response = (status, Json(account_object(base, tenant_name, account))).into_response();
    if let Ok(value) = HeaderValue::from_str(&location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

/// The contact a client offered, as the single stored value (v1): the
/// first non-empty URI, or `None` for an empty/cleared array.
fn contact_of(contact: &[String]) -> Option<String> {
    contact
        .iter()
        .map(|uri| uri.trim())
        .find(|uri| !uri.is_empty())
        .map(|uri| uri.to_owned())
}

/// A JSON-string member of a JWS-serialization object.
fn json_string_member<'a>(
    member: Option<&'a Value>,
    name: &'static str,
) -> Result<&'a str, AcmeProblem> {
    member
        .and_then(Value::as_str)
        .ok_or_else(|| AcmeProblem::malformed(format!("{name} must be a base64url string")))
}

/// The request body as text (the JWS compact serialization).
fn as_str(bytes: &Bytes) -> Result<&str, AcmeProblem> {
    std::str::from_utf8(bytes)
        .map_err(|_| AcmeProblem::malformed("the request body is not UTF-8 JWS text"))
}

/// The UNVERIFIED protected header's identity members, for the routes' kid
/// pre-resolution: the verifier's resolver is a sync closure and the DB is
/// async, so the route peeks the header FIRST (no verification — the
/// nonce is not spent here), eagerly fetches the candidate account's key
/// into a cache, and the closure then answers from memory. A kid that
/// fails the tenant-URL parse (or whose lookup misses) simply never lands
/// in the cache — the verifier reports the resolver's `None` as
/// `NoSuchAccount`, so an unresolvable or cross-tenant kid stays a 404
/// lookup failure, never a cross-tenant account.
#[derive(Debug, Deserialize)]
struct PeekedHeader {
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    jwk: Option<Value>,
}

/// Decode (WITHOUT verifying) the JWS protected header. The compact shape
/// is checked here too — a differing verdict would mean the pre-pass and
/// the verifier disagree about malformed requests.
fn peek_header(raw: &str) -> Result<PeekedHeader, AcmeProblem> {
    let mut segments = raw.split('.');
    let protected = segments.next();
    let second = segments.next();
    let _signature = segments.next();
    if protected.is_none() || second.is_none() || segments.next().is_some() {
        return Err(AcmeProblem::malformed(
            "a JWS compact serialization is three dot-separated segments",
        ));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(protected.unwrap_or_default())
        .map_err(|_| AcmeProblem::malformed("the protected header is not unpadded base64url"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| AcmeProblem::malformed("the protected header is not a valid JSON header"))
}
