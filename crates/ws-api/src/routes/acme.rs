//! The ACME (RFC 8555) route surface: the directory, the new-nonce
//! endpoint, the account lifecycle (new-account incl. only-return-existing
//! and the ToS gate, account update, deactivation with its cascade, the
//! atomic account-key rollover), and the order machine — new-order,
//! order polling (POST-as-GET), authorization objects — plus Task 7's
//! SYNCHRONOUS challenge verification: for every challenge POST the
//! server COMPUTES the expected answer (the stored token dotted with the
//! authenticating account's own RFC 7638 thumbprint) and checks it
//! against its own outbound HTTP fetch (HTTP-01) or DNS TXT resolution
//! (DNS-01) — a client-supplied answer is never an input (the RFC's
//! response fields are ignored wholesale). Task 8 closes the issuance
//! loop: finalize (RFC 8555 §7.4) delegates to the SAME issuance
//! machinery as the manual path (`issue_certificate_core`, the account
//! actor carrying exactly `issue`), the order's certificate URL serves
//! the leaf + chain via POST-as-GET (§7.4.2), and revoke-cert (§7.6) is
//! account-key JWS only — the certificate-key proof-of-possession
//! variant is declined per settlement D7 (`cert_key_pop_declined`).
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
//! The order machine (Task 6): `new-order` is a kid-carried POST whose
//! account must be `valid`; the order row, its freshly minted pending
//! authorizations (plus BOTH challenge flavors per authorization — the
//! client picks http-01 or dns-01), and the audit row commit in ONE
//! transaction with the deferred composite foreign keys' blessing. An
//! identifier whose account already holds a `valid` authorization inside
//! the REUSE WINDOW ([`AcmeRepo::valid_authorization_for`]: newest valid
//! account-level row, `expires_at > now`) is REUSED: the order's
//! `authorizations` array points at the EXISTING authorization URL and
//! Task 2's row design keeps that row's `order_id` NULL — an expired or
//! absent one mints a fresh pending authorization. The two-time shape
//! this task pins (Task 7 continues it): a PENDING authorization lives
//! the order's 7-day retry window; a VALID one gains its 30-day reuse
//! lifetime only when validation settles it (Task 7 stamps the new
//! `expires_at` there).
//!
//! Problem documents: `{"type": "urn:ietf:params:acme:error:<slug>",
//! "detail", "status"}` with `Content-Type: application/problem+json`
//! ([`AcmeProblem`]). Payload handling beyond the JWS floor is deliberately
//! RFC-shaped and lenient about unknown members (external account binding
//! is accepted-and-ignored per the spec's non-goal); order and
//! authorization reads are POST-as-GET only (the RFC's POST-with-empty-
//! payload), never unauthenticated GETs.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;

use axum::body::Bytes;
use axum::extract::{Path, Query, Request, State};
use axum::http::header;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::PeerIpKeyExtractor;
use tower_governor::GovernorLayer;
use uuid::Uuid;
use ws_acme::{AcmeError, NonceStore};
use ws_ca::issue::{validate_csr, CsrInfo, SanEntry};
use ws_core::error::CoreError;
use ws_core::models::acme::{
    AcmeAccountModel, AcmeAccountStatus, AcmeAuthorizationModel, AcmeAuthorizationStatus,
    AcmeChallengeModel, AcmeChallengeStatus, AcmeChallengeType, AcmeOrderModel, AcmeOrderStatus,
};
use ws_core::models::certificate::{CertStatus, CertificateModel, RevocationReason};
use ws_core::models::rbac::{Actor, ActorType, AuthMethod, Capability};
use ws_core::models::tenant::Tenant;
use ws_core::repo::acme_repo::{AcmeAccountWithOrders, AcmeRepo};
use ws_core::repo::audit_repo::AuditRepo;
use ws_core::repo::ca_repo::CaRepo;
use ws_core::repo::certificate_repo::CertificateRepo;
use ws_core::repo::profile_repo::ProfileRepo;
use ws_core::repo::tenant_repo::TenantRepo;

use crate::auth_middleware::AuthActor;
use crate::error::ApiError;
use crate::routes::audit_entry;
use crate::routes::auth::primary_tenant;
use crate::routes::certificates::{issue_certificate_core, IssueCertificateBody};
use crate::routes::ListQuery;
use crate::state::AppState;

/// The problem URN for the ToS gate — in the ACME error registry, though
/// [`ws_acme::AcmeError`] never carries it (the ToS gate is route-level
/// policy, not a JOSE-floor verdict).
const URN_USER_ACTION_REQUIRED: &str = "urn:ietf:params:acme:error:userActionRequired";

/// The problem URN for the `onlyReturnExisting` miss (RFC 8555 §7.3.3),
/// named here for the same reason as the ToS gate above.
const URN_ACCOUNT_DOES_NOT_EXIST: &str = "urn:ietf:params:acme:error:accountDoesNotExist";

/// The problem URN for an identifier the server refuses (RFC 8555 §8's
/// well-known registry entry): an identifier whose TYPE is not offered.
/// (The RFC also suggests naming the rejected identifier on a
/// `Link rel="up"` header; the plan's Task-6 pin keeps it to the detail
/// message naming the type — the identifier never enters the response
/// headers.)
const URN_REJECTED_IDENTIFIER: &str = "urn:ietf:params:acme:error:rejectedIdentifier";

/// The problem URN for an attempt paced out by the per-authorization
/// backoff (RFC 8555 §6.7's `rateLimited`; the pacing window lives in
/// [`crate::state::CHALLENGE_ATTEMPT_BACKOFF`]) and for a request the
/// per-account limiter (settlement D8) refuses.
const URN_RATE_LIMITED: &str = "urn:ietf:params:acme:error:rateLimited";

/// The problem URN for a finalize CSR the server cannot use against its
/// order (RFC 8555 §7.4's `badCSR`): PKCS#10 input that does not parse,
/// or a CSR whose requested identifiers differ from the order's.
const URN_BAD_CSR: &str = "urn:ietf:params:acme:error:badCSR";

/// The problem URN for a finalize (or certificate download) on an order
/// whose state does not admit it (RFC 8555 §7.4's `orderNotReady`) —
/// answered 403, per the RFC's own status pin for the finalize case.
const URN_ORDER_NOT_READY: &str = "urn:ietf:params:acme:error:orderNotReady";

/// The order machine's clock pins (settlement D5): an order lives 7 days,
/// and each freshly minted PENDING authorization shares that retry window.
/// The 30-day figure of the reuse window is NOT minted here — it is the
/// `expires_at` a VALID authorization gains when Task 7's verification
/// settles its identifier; the reuse lookup only checks `expires_at >
/// now` on `valid` account-level rows.
const ORDER_EXPIRY_DAYS: i64 = 7;
const PENDING_AUTHZ_EXPIRY_DAYS: i64 = 7;

/// A VALID authorization's NEW expiry, stamped by the challenge
/// verification when it settles the identifier: the 30-day REUSE WINDOW
/// the order constants' doc defers to this task.
const REUSE_WINDOW_DAYS: i64 = 30;

/// The default certificate profile of the Wardstone `profile` extension
/// member (the plan's pin): an order that offers no profile asks for the
/// setup-minted `web-server` profile.
const DEFAULT_ORDER_PROFILE: &str = "web-server";

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
        .route("/{tenant}/new-order", post(new_order))
        .route("/{tenant}/orders/{order}", post(order_url))
        .route("/{tenant}/orders/{order}/finalize", post(finalize_order))
        .route(
            "/{tenant}/orders/{order}/certificate",
            post(download_certificate),
        )
        .route("/{tenant}/revoke-cert", post(revoke_cert))
        .route("/{tenant}/authz/{authz}", post(authz_url))
        .route("/{tenant}/chall/{challenge}", post(challenge_url))
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

/// The new-order request payload (RFC 8555 §7.4) plus the Wardstone
/// extension. RFC 8555 has NO profile member (profile selection is the
/// ARI/drafts ground); the plan still pins orders to carry one, so the
/// extension lives on the payload as `profile` (a string naming a profile
/// of THIS tenant, defaulting to [`DEFAULT_ORDER_PROFILE`]) — the same
/// member name the profiles draft put in `newOrder`. The plan/brief text
/// spelled the member `profile_name`; BOTH spellings are accepted on
/// input (`profile` preferred, `profile_name` the fallback; sending both
/// with different values is `malformed`), and the order OBJECT carries
/// the single `profile` member.
///
/// `identifiers` is kept as the RAW `Value` (the model stores it verbatim
/// as the order's authority for what it asked for) and validated as a
/// whole; `notBefore`/`notAfter` are RFC 3339 strings per the spec.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewOrderPayload {
    identifiers: Value,
    /// The Wardstone profile extension member (see the struct doc).
    profile: Option<String>,
    /// The plan-text spelling of the same extension member (see the
    /// struct doc), accepted under BOTH spellings this repo's documents
    /// have used: `profileName` (this payload's camelCase members) and
    /// the plan text's verbatim `profile_name`. Secondary to `profile`.
    #[serde(alias = "profile_name")]
    profile_name: Option<String>,
    not_before: Option<String>,
    not_after: Option<String>,
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
    // Settlement D8's per-account pacing: the account update (and its
    // POST-as-GET read) rides the same bucket as every other
    // authenticated ACME POST (see [`check_account_rate_limit`]).
    check_account_rate_limit(&state, &account)?;

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
    // Settlement D8's per-account pacing (see [`check_account_rate_limit`]).
    check_account_rate_limit(&state, &account)?;

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

/// The kid-account prelude the order-machine routes share (new-order and
/// the two POST-as-GET reads): peek the UNVERIFIED protected header,
/// eagerly fetch the candidate account's key into the resolver cache (the
/// account route's idiom verbatim), verify the JWS (which spends the
/// nonce), refuse an embedded jwk, parse the kid against the CONFIGURED
/// tenant prefix, load the account, and gate it `valid` (pending accounts
/// have yet to agree to the ToS; deactivated accounts refuse every
/// action). A kid that is not a tenant-local account URL, or whose
/// lookup misses, is the 404 `accountDoesNotExist` lookup failure — never
/// a cross-tenant read.
///
/// Returns the account and the (possibly null) verified payload: the read
/// routes treat a null payload as RFC POST-as-GET; new-order refuses it
/// (a creation endpoint has no GET).
async fn authenticate_kid_account(
    state: &AppState,
    tenant: &Tenant,
    base: &str,
    request_url: &str,
    raw: &str,
) -> Result<(AcmeAccountModel, Value), AcmeProblem> {
    let peeked = peek_header(raw)?;
    let mut kid_keys: HashMap<String, Value> = HashMap::new();
    if let Some(kid) = peeked.kid.filter(|_| peeked.jwk.is_none()) {
        if let Some(thumbprint) = kid_thumbprint(&kid, base, &tenant.name) {
            if let Some(account) = AcmeRepo::new()
                .get_account(&state.pool, tenant.id, &thumbprint)
                .await?
            {
                kid_keys.insert(kid, account.jwk);
            }
        }
    }
    let jws = ws_acme::verify_jws(
        raw,
        &|kid: &str| Ok(kid_keys.get(kid).cloned()),
        &|n| state.nonces.consume(n),
        request_url,
    )
    .map_err(AcmeProblem::from)?;
    if jws.header.jwk.is_some() {
        return Err(AcmeProblem::malformed(
            "an order-machine request must authenticate with its account kid, \
             not an embedded jwk",
        ));
    }
    let kid = jws.header.kid.as_deref().ok_or_else(|| {
        AcmeProblem::malformed("an order-machine request must name its account URL as a kid")
    })?;
    let thumbprint = kid_thumbprint(kid, base, &tenant.name).ok_or_else(|| {
        AcmeProblem::malformed("the kid does not name an account URL of this tenant")
    })?;
    let account = AcmeRepo::new()
        .get_account(&state.pool, tenant.id, &thumbprint)
        .await?
        .ok_or(AcmeError::NoSuchAccount)
        .map_err(AcmeProblem::from)?;
    let status_problem = match account.status {
        AcmeAccountStatus::Valid => None,
        AcmeAccountStatus::Pending => {
            Some("the account is not yet valid (agree to the terms of service)")
        }
        AcmeAccountStatus::Deactivated => Some("the account is deactivated"),
    };
    if let Some(detail) = status_problem {
        return Err(AcmeProblem::unauthorized(detail));
    }
    // Settlement D8's per-account pacing (see [`check_account_rate_limit`]).
    check_account_rate_limit(state, &account)?;
    Ok((account, jws.payload))
}

/// Settlement D8's per-account gate (fix round 1): one credit of the
/// account's ACME bucket per authenticated POST — new-order, the
/// POST-as-GET reads (the order poll AND Task 8's certificate download),
/// every challenge trigger, the account update and key change, and
/// Task 8's finalize and revoke-cert ride the SAME bucket, spent here
/// where the account resolves, BEFORE any handler logic. The bucket's
/// rate limit is `AcmeConfig::acme_account_limit` — its OWN switch
/// (`WARDSTONE_ACME_ACCOUNT_LIMIT_DISABLED`), deliberately NOT the auth
/// disable (fix round 1: uuid keying does NOT collapse behind ws-web's
/// proxy, so the auth switch must never unlimit enrolled accounts);
/// new-account stays per-IP GCRA (no account exists to key on yet — the
/// middleware form cannot key on an identity that only exists after the
/// JWS verifies). A refusal is the RFC's rate-limited problem at 429.
fn check_account_rate_limit(
    state: &AppState,
    account: &AcmeAccountModel,
) -> Result<(), AcmeProblem> {
    if state.acme_accounts.try_consume(account.id) {
        Ok(())
    } else {
        Err(AcmeProblem {
            status: StatusCode::TOO_MANY_REQUESTS,
            type_urn: URN_RATE_LIMITED,
            detail: "the account has exceeded its ACME rate limit; retry later".to_owned(),
            tos_link: None,
            location: None,
        })
    }
}

/// `POST /acme/{tenant}/new-order` — the RFC 8555 §7.4 order machine's
/// front door, kid-carried by a `valid` account. The identifiers are
/// dns-only in v1 (a foreign type is the RFC's `rejectedIdentifier`,
/// naming the type in its detail). The profile must exist in the tenant —
/// a missing one is a 400 `malformed` problem naming it (the plan's Task-6
/// pin). The order row, each freshly minted pending authorization (the
/// 7-day retry window) with its BOTH-flavor challenge pair (http-01 +
/// dns-01: the client picks), and the audit row commit in ONE transaction
/// under the deferred composite foreign keys. An identifier the account
/// already holds a `valid` authorization for inside the REUSE WINDOW is
/// REUSED: the order's `authorizations` array points at the EXISTING
/// authorization URL and Task 2's reused row keeps its `order_id` NULL —
/// an expired or absent one mints a fresh pending authorization. Success
/// answers 201 with the order's `Location` and the pending order object.
async fn new_order(
    State(state): State<AppState>,
    Path(tenant_name): Path<String>,
    raw: Bytes,
) -> Result<Response, AcmeProblem> {
    let tenant = resolve_tenant(&state, &tenant_name).await?;
    let base = public_base(&state)?;
    let expected_url = format!("{base}/acme/{}/new-order", tenant.name);
    let raw = as_str(&raw)?;

    let (account, payload) =
        authenticate_kid_account(&state, &tenant, &base, &expected_url, raw).await?;

    // A POST-as-GET (the empty payload) names no order to read: new-order
    // is a CREATION endpoint, and the RFC gives it no GET.
    if payload.is_null() {
        return Err(AcmeProblem::malformed(
            "a new-order request requires an identifiers payload \
             (POST-as-GET does not apply)",
        ));
    }
    let body: NewOrderPayload = serde_json::from_value(payload).map_err(|_| {
        AcmeProblem::malformed("the new-order payload is not a valid request object")
    })?;
    let identifiers = dns_identifiers(&body.identifiers)?;

    // The Wardstone extension: `profile` (with the plan-text spelling
    // `profile_name` accepted underneath it; both present and disagreeing
    // is `malformed` — the request would otherwise silently order under
    // whichever one wins). The profile must be the tenant's.
    let profile_name = match (body.profile.as_deref(), body.profile_name.as_deref()) {
        (Some(a), Some(b)) if a != b => {
            return Err(AcmeProblem::malformed(
                "the profile and profile_name members carry different profiles; \
                 send exactly one",
            ));
        }
        (Some(a), _) => a,
        (None, Some(b)) => b,
        (None, None) => DEFAULT_ORDER_PROFILE,
    };
    ProfileRepo::new()
        .get_by_name(&state.pool, tenant.id, profile_name)
        .await?
        .ok_or_else(|| {
            AcmeProblem::malformed(format!(
                "the profile {profile_name:?} does not exist in this tenant"
            ))
        })?;

    let not_before = rfc3339_member(&body.not_before, "notBefore")?;
    let not_after = rfc3339_member(&body.not_after, "notAfter")?;
    if let (Some(before), Some(after)) = (not_before, not_after) {
        if after < before {
            return Err(AcmeProblem::malformed(
                "the notAfter member precedes notBefore",
            ));
        }
    }

    let now = Utc::now();
    let order = AcmeOrderModel {
        id: Uuid::new_v4(),
        tenant_id: tenant.id,
        account_id: account.id,
        status: AcmeOrderStatus::Pending,
        profile_name: profile_name.to_owned(),
        identifiers: body.identifiers.clone(),
        csr_pem: None,
        not_before,
        not_after,
        certificate_id: None,
        error: None,
        // The 7-day window: the finalization deadline AND the fresh
        // authorizations' pending retry window (see the constants).
        expires_at: now + chrono::Duration::days(ORDER_EXPIRY_DAYS),
        created_at: now,
    };

    // ONE transaction: the order, each minted authorization (with its
    // challenge pair), and the audit row. The deferred composite foreign
    // keys (migration 011) bless any statement order. The reuse lookup
    // reads this transaction's READ COMMITTED snapshot (T6-M2: the fix of
    // an earlier overclaim): a concurrent order on the same identifier is
    // INVISIBLE to this snapshot, so the two orders can BOTH MINT (each
    // keeps its own pending authorization — the rows coexist, every FK
    // holds, and the reuse window serves whichever settles first), and
    // both may equally REUSE the same already-valid row (a read-only hit).
    // No lock is added for this: minting extra pending rows is harmless,
    // and the reuse hit never mutates anything.
    let mut tx = state.pool.begin().await?;
    AcmeRepo::new().insert_order(&mut *tx, &order).await?;
    let mut authorization_urls = Vec::with_capacity(identifiers.len());
    let mut reused = Vec::with_capacity(identifiers.len());
    let mut minted = Vec::with_capacity(identifiers.len());
    for identifier in &identifiers {
        // The reuse window: the newest VALID account-level authorization
        // whose expiry is still in the future at `now`. A hit is reused
        // VERBATIM — the row keeps its own expiry and `order_id: NULL`.
        if let Some(existing) = AcmeRepo::new()
            .valid_authorization_for(&mut *tx, tenant.id, account.id, identifier, now)
            .await?
        {
            authorization_urls.push(authz_object_url(&base, &tenant.name, existing.id));
            reused.push(identifier.clone());
            continue;
        }
        let authorization = AcmeAuthorizationModel {
            id: Uuid::new_v4(),
            tenant_id: tenant.id,
            account_id: account.id,
            identifier: identifier.clone(),
            status: AcmeAuthorizationStatus::Pending,
            expires_at: now + chrono::Duration::days(PENDING_AUTHZ_EXPIRY_DAYS),
            reused_from: None,
            order_id: Some(order.id),
            created_at: now,
        };
        AcmeRepo::new()
            .insert_authorization(&mut *tx, &authorization)
            .await?;
        mint_challenge_pair(&mut tx, tenant.id, authorization.id, identifier, now).await?;
        authorization_urls.push(authz_object_url(&base, &tenant.name, authorization.id));
        minted.push(identifier.clone());
    }
    let account_url_str = format!(
        "{base}/acme/{}/acct/{}",
        tenant.name, account.jwk_thumbprint
    );
    let actor = acme_actor(tenant.id, account_url_str);
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &actor,
                "acme_order_created",
                "acme_order",
                &order.id.to_string(),
                json!({
                    "order_url": order_object_url(&base, &tenant.name, order.id),
                    "profile": profile_name,
                    "identifiers": identifiers,
                    "reused_authorization_count": reused.len(),
                    "minted_authorization_count": minted.len(),
                }),
            ),
        )
        .await?;
    tx.commit().await?;
    tracing::info!(
        order = %order.id,
        reused = reused.len(),
        minted = minted.len(),
        "acme order created"
    );

    Ok(order_response(
        StatusCode::CREATED,
        &base,
        &tenant.name,
        &order,
        Some(&authorization_urls),
    ))
}

/// `POST /acme/{tenant}/orders/{order}` — the order object's POST-as-GET
/// (RFC 8555 §7.4): kid-carried and account-scoped (a foreign order is
/// indistinguishable from a missing one — one 404 problem document, no
/// existence oracle). The body carries the object per status: always
/// `status`/`expires`/`identifiers`/`profile`/`finalize`, the
/// `authorizations` array while the order is pending or ready (re-derived
/// from the rows at poll time), the `certificate` URL once valid, and an
/// `error` problem document once invalid.
async fn order_url(
    State(state): State<AppState>,
    Path((tenant_name, order_id)): Path<(String, String)>,
    raw: Bytes,
) -> Result<Response, AcmeProblem> {
    let tenant = resolve_tenant(&state, &tenant_name).await?;
    let base = public_base(&state)?;
    let expected_url = format!("{base}/acme/{}/orders/{order_id}", tenant.name);
    let raw = as_str(&raw)?;

    let (account, _) = authenticate_kid_account(&state, &tenant, &base, &expected_url, raw).await?;
    let order_id =
        Uuid::parse_str(&order_id).map_err(|_| AcmeProblem::not_found("no such order"))?;
    let order = AcmeRepo::new()
        .get_order(&state.pool, tenant.id, order_id)
        .await?
        .filter(|order| order.account_id == account.id)
        .ok_or_else(|| AcmeProblem::not_found("no such order"))?;
    let account_url_str = format!(
        "{base}/acme/{}/acct/{}",
        tenant.name, account.jwk_thumbprint
    );
    let authorizations =
        order_authorization_urls(&state, &tenant, &base, &account_url_str, &order).await?;
    // The poll may have driven a PAST-EXPIRY pending authorization to its
    // expired self-transition (Task 7's wiring), which invalidates an
    // order-scoped one's order; re-read the row so the object speaks
    // as-of-now.
    let order = AcmeRepo::new()
        .get_order(&state.pool, tenant.id, order_id)
        .await?
        .filter(|order| order.account_id == account.id)
        .ok_or_else(|| AcmeProblem::not_found("no such order"))?;
    let authorizations = match order.status {
        AcmeOrderStatus::Pending | AcmeOrderStatus::Ready => authorizations,
        _ => None,
    };
    Ok(order_response(
        StatusCode::OK,
        &base,
        &tenant.name,
        &order,
        authorizations.as_deref(),
    ))
}

/// The order's `authorizations` URLs, identifier order, re-derived from
/// the rows at POLL time: an order-scoped row (minted FOR this order —
/// any status) first, else the account-level REUSED row the order was
/// pointed at when created (found through the same reuse-window lookup
/// the creation ran). `None` = the member is not carried for this order
/// status (processing/valid/invalid — the RFC allows omitting the
/// authorizations of an order past `pending`; a valid order speaks
/// through `certificate`, an invalid one through `error`).
///
/// A reused row that has since dropped out of the window (expired without
/// the order having been invalidated — no machinery does that until Task
/// 7) is OMITTED with a warn, never a 500: the array may only shorten for
/// an order that is about to be invalidated anyway.
async fn order_authorization_urls(
    state: &AppState,
    tenant: &Tenant,
    base: &str,
    account_url: &str,
    order: &AcmeOrderModel,
) -> Result<Option<Vec<String>>, AcmeProblem> {
    if !matches!(
        order.status,
        AcmeOrderStatus::Pending | AcmeOrderStatus::Ready
    ) {
        return Ok(None);
    }
    let identifiers = identifiers_of(&order.identifiers)?;
    let order_scoped = AcmeRepo::new()
        .list_authorizations_by_order(&state.pool, tenant.id, order.id)
        .await?;
    let now = Utc::now();
    let mut urls = Vec::with_capacity(identifiers.len());
    for identifier in &identifiers {
        if let Some(existing) = order_scoped
            .iter()
            .find(|authorization| &authorization.identifier == identifier)
        {
            // Task 7's poll-time wiring: a PENDING row past its 7-day
            // window transitions itself expired here (an order-scoped one
            // invalidates the order in the same transaction —
            // see expire_authorization_if_past).
            let existing =
                expire_authorization_if_past(state, tenant, base, account_url, existing.clone())
                    .await?;
            urls.push(authz_object_url(base, &tenant.name, existing.id));
            continue;
        }
        match AcmeRepo::new()
            .valid_authorization_for(&state.pool, tenant.id, order.account_id, identifier, now)
            .await?
        {
            Some(reused) => {
                let reused =
                    expire_authorization_if_past(state, tenant, base, account_url, reused).await?;
                urls.push(authz_object_url(base, &tenant.name, reused.id));
            }
            None => tracing::warn!(
                order = %order.id,
                identifier = %identifier,
                "an order's reused authorization left the reuse window; \
                 the authorizations array omits it until the order is invalidated"
            ),
        }
    }
    Ok(Some(urls))
}

// ---------------------------------------------------------------------------
// Finalize, certificate download, and revocation (Plan 4 Task 8): the
// issuance loop closes. Finalize delegates to the SAME issuance machinery
// as the manual path (`issue_certificate_core`) with the AcmeAccount
// actor carrying exactly the `issue` capability; the certificate URL
// serves the leaf + chain; revoke-cert is account-key JWS only (the
// cert-key proof-of-possession variant is declined per settlement D7).
// ---------------------------------------------------------------------------

/// `POST /acme/{tenant}/orders/{id}/finalize` — RFC 8555 §7.4's
/// finalization, kid-carried by a `valid` account, an order `ready`
/// required. The payload carries the CSR as the base64url-encoded DER
/// (`csr`); the route validates it (`ws_ca::validate_csr`), checks the
/// §7.4 CSR-vs-order identifier gate, and delegates to the SAME issuance
/// machinery the manual `POST /api/v1/certificates` path runs —
/// [`issue_certificate_core`] with
/// `IssueCertificateBody { profile_id: <the order's stored profile name
/// resolved by tenant>, subject_cn: <the CSR's CN, else the order's
/// primary identifier>, sans: <the order's identifiers VERBATIM>,
/// csr_pem: Some }`. The `sans` carry the raw `*.` wildcard strings —
/// exactly the shape the manual CSR path submits wildcards in: the
/// profile's SAN patterns match the stripped form (`san_is_permitted`),
/// and rcgen writes the wildcard dNSName. The server-key-generation path
/// is NOT an ACME surface: a payload without a usable CSR is refused
/// before any delegation (never routed to [`Capability::GenerateLeafKey`]
/// — `issue_certificate_core` only reaches it when `csr_pem.is_none()`).
///
/// State transitions: RFC 8555 §7.4 answers finalize-not-ready with 403
/// `orderNotReady`; on success this server issues SYNCHRONOUSLY inside
/// the request, so the `processing` mark is never persisted and the 200
/// response is the final `valid` order object carrying the `certificate`
/// member. The CSR, the issued certificate's id, and the `valid` status
/// commit together (the write-side contract).
async fn finalize_order(
    State(state): State<AppState>,
    Path((tenant_name, order_id)): Path<(String, String)>,
    raw: Bytes,
) -> Result<Response, AcmeProblem> {
    let tenant = resolve_tenant(&state, &tenant_name).await?;
    let base = public_base(&state)?;
    let expected_url = format!("{base}/acme/{}/orders/{order_id}/finalize", tenant.name);
    let raw = as_str(&raw)?;

    let (account, payload) =
        authenticate_kid_account(&state, &tenant, &base, &expected_url, raw).await?;
    let order_uuid =
        Uuid::parse_str(&order_id).map_err(|_| AcmeProblem::not_found("no such order"))?;
    let order = AcmeRepo::new()
        .get_order(&state.pool, tenant.id, order_uuid)
        .await?
        .filter(|order| order.account_id == account.id)
        .ok_or_else(|| AcmeProblem::not_found("no such order"))?;

    // §7.4: "A request to finalize an order will result in error if the
    // order is in the 'pending' or 'processing' state" — 403 with the
    // orderNotReady problem (the RFC's own status pin). A `valid` order
    // carries its certificate already; an `invalid` one is final.
    if order.status != AcmeOrderStatus::Ready {
        return Err(AcmeProblem {
            status: StatusCode::FORBIDDEN,
            type_urn: URN_ORDER_NOT_READY,
            detail: format!(
                "the order is {} and cannot be finalized; POST-as-GET it for its current state",
                order.status.as_str()
            ),
            tos_link: None,
            location: None,
        });
    }

    // The CSR member: RFC 8555 §7.4 — "the base64url-encoded version of
    // the DER format". A finalize POST-as-GET (the null payload) names
    // nothing to issue; the `csr` member is required and is a string.
    let csr_der = if payload.is_null() {
        return Err(AcmeProblem::malformed(
            "a finalize request requires a csr member (POST-as-GET does not apply)",
        ));
    } else {
        match payload.get("csr").and_then(Value::as_str) {
            Some(csr) => URL_SAFE_NO_PAD.decode(csr.as_bytes()).map_err(|_| {
                AcmeProblem::malformed("the finalize payload's csr member is not valid base64url")
            })?,
            None => {
                return Err(AcmeProblem::malformed(
                    "the finalize payload must carry the CSR as a base64url string in csr",
                ));
            }
        }
    };

    // The ws-ca parsers consume PEM; the wire carried headerless DER. A
    // CSR that does not parse as PKCS#10 is the §7.4 `badCSR` problem.
    let csr_pem = pem_encode(&csr_der, "CERTIFICATE REQUEST");
    let csr = validate_csr(&csr_pem).map_err(|err| AcmeProblem {
        status: StatusCode::BAD_REQUEST,
        type_urn: URN_BAD_CSR,
        detail: format!("the finalize CSR does not parse as a PKCS#10 request: {err}"),
        tos_link: None,
        location: None,
    })?;

    let identifiers = identifiers_of(&order.identifiers)?;

    // The RFC 8555 §7.4 gate the shared issuance core does NOT run (it
    // validates the request names against the profile, never the CSR
    // against the order): the CSR "MUST indicate the exact same set of
    // requested identifiers as the initial newOrder request". After a
    // badCSR the order STAYS `ready` (the RFC's SHOULD) — nothing has
    // been written yet.
    if !csr_identifiers_match(&csr, &identifiers) {
        return Err(AcmeProblem {
            status: StatusCode::BAD_REQUEST,
            type_urn: URN_BAD_CSR,
            detail: "the CSR's requested identifiers do not match the order's identifiers"
                .to_owned(),
            tos_link: None,
            location: None,
        });
    }

    // The order's stored profile name resolves through the Task-6 by-name
    // lookup, tenant-scoped — exactly what new-order validated. A profile
    // deleted between order creation and finalize is server-side damage
    // (new-order refused it while it existed): 500.
    let profile = ProfileRepo::new()
        .get_by_name(&state.pool, tenant.id, &order.profile_name)
        .await?
        .ok_or_else(|| {
            AcmeProblem::internal(format!(
                "the order's profile {:?} no longer exists",
                order.profile_name
            ))
        })?;

    // The subject CN: the CSR's own common name, else the order's primary
    // identifier. The profile's SAN policy (and the CN's) is enforced
    // INSIDE the shared issuance core on exactly the names the manual
    // path validates — [`validate_names`] — so a name outside the
    // profile's patterns yields the SAME message semantics the manual
    // path returns (a 400 problem whose detail is the policy message).
    let subject_cn = csr
        .subject_cn
        .clone()
        .unwrap_or_else(|| identifiers[0].clone());
    let body = IssueCertificateBody {
        profile_id: profile.id,
        subject_cn,
        sans: identifiers.clone(),
        csr_pem: Some(csr_pem.clone()),
    };

    // The delegation: the account actor carries EXACTLY the `issue`
    // capability (the Plan-4 settlement); [`issue_certificate_core`]
    // checks it internally for the CSR-bearing path and runs the
    // capability-checked profile/revision read, the name validation, the
    // CA choice, and the ONE transaction (CAS, serial, signing,
    // certificate insert, `cert_issued` audit) — with its built-in
    // bounded retry against a moved profile revision.
    let account_url_str = format!(
        "{base}/acme/{}/acct/{}",
        tenant.name, account.jwk_thumbprint
    );
    let actor = acme_issuing_actor(tenant.id, account_url_str);
    let issued =
        issue_certificate_core(&state, &actor, &body, Uuid::new_v4(), Uuid::new_v4(), None)
            .await
            .map_err(AcmeProblem::from)?;

    // The final stamp, ONE transaction: the CSR the request carried, the
    // issued certificate's id, and the `valid` status. A request that
    // fails before here (badCSR, policy refusal, server error) writes
    // nothing — the order stays `ready` for the client's retry, which is
    // also why the RFC's `processing` mark never needs a persistent row.
    let mut tx = state.pool.begin().await?;
    AcmeRepo::new()
        .set_order_csr(&mut *tx, tenant.id, order.id, &csr_pem)
        .await?;
    AcmeRepo::new()
        .update_order_status(
            &mut *tx,
            tenant.id,
            order.id,
            AcmeOrderStatus::Valid,
            Some(issued.certificate_id),
            None,
        )
        .await?;
    tx.commit().await?;
    tracing::info!(
        order = %order.id,
        certificate = %issued.certificate_id,
        "acme order finalized: certificate issued"
    );

    let finalized = AcmeRepo::new()
        .get_order(&state.pool, tenant.id, order.id)
        .await?
        .ok_or_else(|| AcmeProblem::internal("the order vanished during its finalize"))?;
    Ok(order_response(
        StatusCode::OK,
        &base,
        &tenant.name,
        &finalized,
        None,
    ))
}

/// The finalize CSR-vs-order gate (RFC 8555 §7.4): the CSR "MUST indicate
/// the exact same set of requested identifiers as the initial newOrder
/// request", each DNS identifier riding the requested subject's
/// commonName OR the subjectAltName extension. The comparison runs on
/// the WILDCARD-STRIPPED, case-folded forms (an order's `*.example.com`
/// is matched by a CSR SAN of `*.example.com` — the wildcard prefix is
/// not compared, matching the stripped-form semantics the profile's SAN
/// patterns apply to the issued names). Both directions are exact: every
/// order identifier must be carried by the CSR (SANs or CN), every CSR
/// SAN must be an order identifier, and the CSR's own CN (when present)
/// must be one as well — it becomes the issued subject. A CSR SAN of a
/// kind the dns-only order cannot express (IP, email) is a mismatch.
fn csr_identifiers_match(csr: &CsrInfo, identifiers: &[String]) -> bool {
    let normalize = |name: &str| name.strip_prefix("*.").unwrap_or(name).to_lowercase();
    if csr
        .sans
        .iter()
        .any(|entry| !matches!(entry, SanEntry::Dns(_)))
    {
        return false;
    }
    let csr_names: HashSet<String> = csr
        .sans
        .iter()
        .filter_map(|entry| match entry {
            SanEntry::Dns(name) => Some(normalize(name)),
            _ => None,
        })
        .collect();
    let cn = csr.subject_cn.as_deref().map(normalize);
    let order_names: HashSet<String> = identifiers.iter().map(|id| normalize(id)).collect();
    // Every CSR SAN is an order identifier...
    csr_names.iter().all(|name| order_names.contains(name))
        // ...the CN (when present) is one too...
        && match cn.as_deref() {
            Some(cn) => order_names.contains(cn),
            None => true,
        }
        // ...and every order identifier rides the CSR's SANs or CN.
        && identifiers
            .iter()
            .map(|id| normalize(id))
            .all(|id| csr_names.contains(&id) || cn.as_deref() == Some(id.as_str()))
}

/// Wrap DER bytes into a PEM body: the RFC 8555 finalize/revocation
/// members are headerless base64url DER, while the ws-ca parsers consume
/// PEM. The 64-character line wrapping is PEM's RFC 1421 form (the
/// base64 body is pure ASCII, so the byte chunks are whole characters).
fn pem_encode(der: &[u8], label: &str) -> String {
    let body = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in body.into_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(chunk));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

/// The DER bytes of one PEM body: everything between the label lines,
/// whitespace stripped, base64 (STANDARD alphabet) decoded. Unreadable
/// stored PEM is data-level damage (a 500), never a per-request refusal.
fn pem_to_der(pem: &str, label: &str) -> Result<Vec<u8>, AcmeProblem> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("-----"))
        .collect();
    STANDARD
        .decode(body.as_bytes())
        .map_err(|_| AcmeProblem::internal(format!("a stored {label} PEM body is corrupt")))
}

/// `POST /acme/{tenant}/orders/{id}/certificate` — the RFC 8555 §7.4.2
/// certificate download, kid-carried POST-as-GET (the same shape the
/// order and authorization reads share), account-scoped: a foreign order
/// is indistinguishable from a missing one. The plan pinned the URL
/// shape `GET /.../certificate`; the surface's JWS-floor posture (order
/// and authorization reads are POST-as-GET only, never unauthenticated
/// GETs) and §7.4.2's own rule — certificate URLs are fetched like every
/// other resource, with POST-as-GET — make the kid-carried POST the
/// serving method. The URL and the body follow the pin exactly: 200 with
/// `application/pem-certificate-chain`, the text body the LEAF
/// certificate first, then the issuing chain up to the root
/// ([`CaRepo::chain_to_root`] — the manual `/certificates/{id}/chain`
/// route's idiom). Order `valid` required: pending/ready/processing
/// answer the 403 `orderNotReady` problem; an `invalid` order answers
/// 403 with the RFC's most generic type and its RECORDED ERROR as the
/// detail (§7.4.2 registers no download failure shape; the order's own
/// error text is the authoritative part — the same rendering the order
/// object's `error` member uses).
async fn download_certificate(
    State(state): State<AppState>,
    Path((tenant_name, order_id)): Path<(String, String)>,
    raw: Bytes,
) -> Result<Response, AcmeProblem> {
    let tenant = resolve_tenant(&state, &tenant_name).await?;
    let base = public_base(&state)?;
    let expected_url = format!("{base}/acme/{}/orders/{order_id}/certificate", tenant.name);
    let raw = as_str(&raw)?;

    let (account, _payload) =
        authenticate_kid_account(&state, &tenant, &base, &expected_url, raw).await?;
    let order_uuid =
        Uuid::parse_str(&order_id).map_err(|_| AcmeProblem::not_found("no such order"))?;
    let order = AcmeRepo::new()
        .get_order(&state.pool, tenant.id, order_uuid)
        .await?
        .filter(|order| order.account_id == account.id)
        .ok_or_else(|| AcmeProblem::not_found("no such order"))?;
    match (&order.status, &order.error) {
        (AcmeOrderStatus::Valid, _) => {}
        (AcmeOrderStatus::Invalid, error) => {
            return Err(AcmeProblem {
                status: StatusCode::FORBIDDEN,
                type_urn: "urn:ietf:params:acme:error:serverInternal",
                detail: error
                    .clone()
                    .unwrap_or_else(|| "the order is invalid".to_owned()),
                tos_link: None,
                location: None,
            });
        }
        _ => {
            return Err(AcmeProblem {
                status: StatusCode::FORBIDDEN,
                type_urn: URN_ORDER_NOT_READY,
                detail: format!(
                    "the order is {} and carries no certificate yet; POST-as-GET it for \
                     its current state",
                    order.status.as_str()
                ),
                tos_link: None,
                location: None,
            });
        }
    }
    let certificate_id = order
        .certificate_id
        .ok_or_else(|| AcmeProblem::internal("a valid order's certificate row is missing"))?;
    let cert = CertificateRepo::new()
        .get(&state.pool, certificate_id)
        .await?
        .filter(|cert| cert.tenant_id == tenant.id)
        .ok_or_else(|| AcmeProblem::internal("a valid order's certificate row is missing"))?;
    let chain = {
        // One pooled connection serves the multi-statement walk (the
        // repos' executor convention; the walk re-checks the tenant per
        // hop).
        let mut conn = state.pool.acquire().await?;
        CaRepo::new()
            .chain_to_root(&mut conn, tenant.id, cert.ca_id)
            .await?
    };
    let mut body = cert.cert_pem.clone();
    body.extend(chain.iter().map(|ca| ca.cert_pem.as_str()));
    Ok((
        [(header::CONTENT_TYPE, "application/pem-certificate-chain")],
        body,
    )
        .into_response())
}

/// The revoke-cert request payload (RFC 8555 §7.6): the certificate as
/// the base64url-encoded DER, and the optional reason — kept RAW so an
/// unknown value can fall back to `unspecified` instead of failing the
/// whole payload parse (see [`acme_revocation_reason`]).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeCertPayload {
    /// The certificate to revoke — RFC 8555 §7.6's base64url-encoded DER
    /// ("headerless... different from PEM").
    certificate: String,
    /// The optional reason value, parsed by [`acme_revocation_reason`].
    #[serde(default)]
    reason: Option<Value>,
}

/// `POST /acme/{tenant}/revoke-cert` — RFC 8555 §7.6's revocation,
/// kid-carried by a `valid` account. The certificate member is the
/// base64url-encoded DER; the route resolves the certificate by matching
/// the presented DER against the certificate rows the ACCOUNT'S OWN
/// orders point at (the D7 authorization settlement: an account may
/// revoke only what IT issued via orders — unknown, another account's,
/// or another tenant's certificate all earn the ONE 401 `unauthorized`
/// problem, no existence oracle). The typed revoke runs through the SAME
/// machinery as the manual route (`CertificateRepo::revoke` writing the
/// reason name ws-worker's builders parse, one `cert_revoked` audit row
/// in the same transaction). Idempotency mirrors the manual route: an
/// already-revoked certificate answers problem-free 200 without a second
/// revoke or audit row (the RFC's `alreadyRevoked` problem is
/// deliberately not minted — the manual path's idempotent shape is the
/// pinned mirror).
///
/// Settlement D7: revocation by CERTIFICATE-key proof of possession is
/// DECLINED — an embedded-jwk JWS (no account kid) is refused before any
/// state read with the 400 `unauthorized` problem naming
/// `cert_key_pop_declined` (RFC 8555 §7.6 permits the cert-key variant;
/// the Plan-1 spec's settlement declines it for v1).
async fn revoke_cert(
    State(state): State<AppState>,
    Path(tenant_name): Path<String>,
    raw: Bytes,
) -> Result<Response, AcmeProblem> {
    let tenant = resolve_tenant(&state, &tenant_name).await?;
    let base = public_base(&state)?;
    let expected_url = format!("{base}/acme/{}/revoke-cert", tenant.name);
    let raw = as_str(&raw)?;

    // The cert-key PoP decline (settlement D7) fires BEFORE the
    // JWS-verifying prelude: an embedded jwk names no account, so the
    // decline is cheaper than any account resolution.
    let peeked = peek_header(raw)?;
    if peeked.jwk.is_some() {
        return Err(AcmeProblem {
            status: StatusCode::BAD_REQUEST,
            type_urn: "urn:ietf:params:acme:error:unauthorized",
            detail: "revocation by certificate-key proof of possession is declined \
                     (cert_key_pop_declined); sign the revocation request with the \
                     issuing account's key as the kid"
                .to_owned(),
            tos_link: None,
            location: None,
        });
    }

    let (account, payload) =
        authenticate_kid_account(&state, &tenant, &base, &expected_url, raw).await?;
    if payload.is_null() {
        return Err(AcmeProblem::malformed(
            "a revoke-cert request requires a certificate member (POST-as-GET does not apply)",
        ));
    }
    let body: RevokeCertPayload = serde_json::from_value(payload).map_err(|_| {
        AcmeProblem::malformed("the revoke-cert payload is not a valid request object")
    })?;
    let reason = acme_revocation_reason(&body.reason)?;
    let presented = URL_SAFE_NO_PAD
        .decode(body.certificate.as_bytes())
        .map_err(|_| {
            AcmeProblem::malformed(
                "the revoke-cert payload's certificate member is not valid base64url DER",
            )
        })?;

    // Ownership: match the presented DER against the certificates the
    // account's own orders issued (paged; a page whose rows carry no
    // certificate id simply skips). The DER comparison is byte-exact —
    // the wire certificate must BE the stored certificate, not merely
    // serialize to the same PEM.
    let mut owned: Option<CertificateModel> = None;
    let mut page = 0u32;
    while owned.is_none() {
        let orders = AcmeRepo::new()
            .list_orders_by_account(&state.pool, tenant.id, account.id, page, 100)
            .await?;
        if orders.is_empty() {
            break;
        }
        for order in orders {
            let Some(cert_id) = order.certificate_id else {
                continue;
            };
            let cert = CertificateRepo::new().get(&state.pool, cert_id).await?;
            if let Some(cert) = cert {
                if pem_to_der(&cert.cert_pem, "CERTIFICATE")? == presented {
                    owned = Some(cert);
                    break;
                }
            }
        }
        page += 1;
    }
    let Some(cert) = owned else {
        return Err(AcmeProblem::unauthorized(
            "the certificate is not one this account issued through an order",
        ));
    };

    // The manual route's idempotency shape, mirrored: an already-revoked
    // certificate changes nothing and writes no second audit row.
    if cert.status == CertStatus::Revoked {
        return Ok(StatusCode::OK.into_response());
    }

    let account_url_str = format!(
        "{base}/acme/{}/acct/{}",
        tenant.name, account.jwk_thumbprint
    );
    let mut tx = state.pool.begin().await?;
    CertificateRepo::new()
        .revoke(&mut *tx, cert.id, reason.as_str(), None)
        .await?;
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &acme_actor(tenant.id, account_url_str),
                "cert_revoked",
                "certificate",
                &cert.id.to_string(),
                json!({ "reason": reason.as_str(), "via": "acme" }),
            ),
        )
        .await?;
    tx.commit().await?;
    tracing::info!(certificate = %cert.id, "acme account revoked a certificate");
    // §7.6 success: 200 with an empty body (the Replay-Nonce rides the
    // middleware).
    Ok(StatusCode::OK.into_response())
}

/// The `reason` member mapping (RFC 8555 §7.6 → the Plan-3 typed
/// [`RevocationReason`] by NAME — the exact spellings `CertificateRepo::revoke`
/// stores and ws-worker's CRL/OCSP builders parse):
///
/// - absent → `unspecified` (the stored name; a reasonless revocation
///   is indistinguishable from an explicit one in v1 — the enum has no
///   absent option);
/// - the RFC's enumerated integers map by name: 0 unspecified, 1
///   keyCompromise, 2 caCompromise, 3 affiliationChanged, 4 superseded,
///   5 cessationOfOperation, 6 certificateHold, 8 privilegeWithdrawn,
///   9 aaCompromise;
/// - 7 and 10 — BOTH render `removeFromCrl` in RFC 8555's table (the
///   RFC carries the code twice) — are REFUSED with the `malformed`
///   problem naming it: a Wardstone revocation is terminal, there is no
///   reinstatement machinery to revoke-then-reinstate, and the worker
///   deliberately maps no `remove_from_crl` reason extension
///   (`ws_worker::jobs::reason_from_str`);
/// - any OTHER value (a non-integer member, a negative or >10 integer)
///   falls back to `unspecified`: an unknown reason is not a refusal —
///   the revocation proceeds without a typed reason beyond the
///   unspecified default (the brief's `unspecified` fallback; the RFC's
///   `badRevocationReason` was reserved for the KNOWN-but-unsupported
///   remove-from-CRL case, which this surface answers `malformed`
///   instead per the task settlement).
fn acme_revocation_reason(reason: &Option<Value>) -> Result<RevocationReason, AcmeProblem> {
    match reason.as_ref().and_then(Value::as_u64) {
        None | Some(0) => Ok(RevocationReason::Unspecified),
        Some(1) => Ok(RevocationReason::KeyCompromise),
        Some(2) => Ok(RevocationReason::CaCompromise),
        Some(3) => Ok(RevocationReason::AffiliationChanged),
        Some(4) => Ok(RevocationReason::Superseded),
        Some(5) => Ok(RevocationReason::CessationOfOperation),
        Some(6) => Ok(RevocationReason::CertificateHold),
        Some(8) => Ok(RevocationReason::PrivilegeWithdrawn),
        Some(9) => Ok(RevocationReason::AaCompromise),
        Some(7 | 10) => Err(AcmeProblem::malformed(
            "the remove-from-CRL revocation reason is not supported: revocations are \
             terminal in Wardstone",
        )),
        Some(_) => Ok(RevocationReason::Unspecified),
    }
}

/// The ACME account actor for the finalize delegation: the pinned actor
/// shape (the ACCOUNT acts on the surface) but carrying EXACTLY the
/// `issue` capability — the CSR-bearing issuance path's requirement that
/// [`issue_certificate_core`] checks internally (the Plan-4 settlement:
/// the ACME account never carries `generate_leaf_key`; a finalize
/// without a CSR never reaches that path). The account URL is the actor
/// id, so the `cert_issued` audit row the core writes attributes the
/// issuance to the account (`actor_type` `acme_account`).
fn acme_issuing_actor(tenant_id: Uuid, account_url: String) -> Actor {
    Actor {
        actor_type: ActorType::AcmeAccount,
        actor_id: account_url,
        auth_method: AuthMethod::AcmeAccount,
        capabilities: vec![Capability::Issue],
        session_id: None,
        tenant_id,
        minted_by: None,
    }
}

/// The dns value strings stored on an order's (validated, verbatim)
/// `identifiers` jsonb. An unreadable row is internal damage, not a
/// per-request condition.
fn identifiers_of(stored: &Value) -> Result<Vec<String>, AcmeProblem> {
    stored
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| {
                    entry
                        .get("value")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .collect()
        })
        .ok_or_else(|| AcmeProblem::internal("a stored order's identifiers are unreadable"))
}

/// `POST /acme/{tenant}/authz/{authz}` — the authorization object's
/// POST-as-GET (RFC 8555 §7.5.1): kid-carried, account-scoped (the same
/// 404 shape as the order read), rendering the stored status, the
/// identifier (a `*.`-prefixed wildcard row renders WITHOUT the prefix
/// and with `wildcard: true` — the RFC's authorization-object form; the
/// row stores the order's verbatim identifier), the expiry, and BOTH
/// challenge flavors with their absolute `chall` URLs.
async fn authz_url(
    State(state): State<AppState>,
    Path((tenant_name, authz_id)): Path<(String, String)>,
    raw: Bytes,
) -> Result<Response, AcmeProblem> {
    let tenant = resolve_tenant(&state, &tenant_name).await?;
    let base = public_base(&state)?;
    let expected_url = format!("{base}/acme/{}/authz/{authz_id}", tenant.name);
    let raw = as_str(&raw)?;

    let (account, _) = authenticate_kid_account(&state, &tenant, &base, &expected_url, raw).await?;
    let authz_id =
        Uuid::parse_str(&authz_id).map_err(|_| AcmeProblem::not_found("no such authorization"))?;
    let account_url_str = format!(
        "{base}/acme/{}/acct/{}",
        tenant.name, account.jwk_thumbprint
    );
    let authorization = AcmeRepo::new()
        .get_authorization(&state.pool, tenant.id, authz_id)
        .await?
        .filter(|authorization| authorization.account_id == account.id)
        .ok_or_else(|| AcmeProblem::not_found("no such authorization"))?;
    // Task 7's poll-time wiring: a PENDING row past its 7-day window
    // transitions itself expired right here (the object then speaks the
    // RFC's deadline state).
    let authorization =
        expire_authorization_if_past(&state, &tenant, &base, &account_url_str, authorization)
            .await?;
    let challenges = AcmeRepo::new()
        .list_challenges_by_authorization(&state.pool, tenant.id, authorization.id)
        .await?;
    Ok(Json(authz_object(
        &base,
        &tenant.name,
        &authorization,
        &challenges,
    ))
    .into_response())
}

// ---------------------------------------------------------------------------
// Challenge verification (Plan 4 Task 7): the server-side seams, the
// synchronous verdict, and the settlement transitions
// ---------------------------------------------------------------------------

use hickory_resolver::TokioResolver;

/// The HTTP-01 fetch seam (the server-side fetch of RFC 8555 §8.3): the
/// route builds the CANONICAL fetch URL from the stored row (identifier +
/// token) and hands it here; `Ok` carries the body for the exact-match
/// comparison, `Err` the flattened failure text the challenge error
/// records. Dyn-compatible over hand-boxed futures — no async-trait pin
/// is added for this (the house adds no pin it does not use).
pub trait ChallengeFetch: Send + Sync {
    fn fetch(&self, url: String) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>>;
}

/// The DNS-01 resolver seam (RFC 8555 §8.4): resolve the given (fully
/// qualified) name's TXT records; `Ok` carries the record strings — an
/// empty `Ok` IS the truth when no records exist (the NXDOMAIN shape) —
/// and `Err` the flattened failure text.
pub trait TxtResolver: Send + Sync {
    fn resolve_txt(
        &self,
        name: String,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send>>;
}

/// The production HTTP-01 fetcher: a reqwest client bounded to 10s TOTAL
/// per request, direct connections only — `no_proxy`, because the
/// environment's proxy variables are never trusted (the fetch must
/// originate from THIS server against the identifier's own origin; the
/// `Host` header rides from the URL, never a header the route reads).
pub struct Http01Fetcher {
    client: reqwest::Client,
}

impl Http01Fetcher {
    /// Build the bounded client (the whole-request budget: inside
    /// ws-web's 60s proxy timeout, well ahead of it).
    pub fn bounded() -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .no_proxy()
            .build()?;
        Ok(Http01Fetcher { client })
    }
}

impl ChallengeFetch for Http01Fetcher {
    fn fetch(&self, url: String) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>> {
        let client = self.client.clone();
        Box::pin(async move {
            let response = client
                .get(&url)
                .send()
                .await
                .map_err(|err| format!("the HTTP request to {url} failed: {err}"))?;
            let status = response.status();
            let body = response
                .text()
                .await
                .map_err(|err| format!("the HTTP response body fetch failed: {err}"))?;
            if !status.is_success() {
                return Err(format!("the HTTP request returned status {status}"));
            }
            Ok(body)
        })
    }
}

/// The production DNS-01 resolver: hickory over the system DNS
/// configuration (`/etc/resolv.conf` — the operator's own resolver, the
/// homelab reality the wildcard path serves).
pub struct TxtResolverHandle {
    resolver: TokioResolver,
}

impl TxtResolverHandle {
    /// Build over the system configuration; a failure carries the flat
    /// text the state layer logs before degrading closed.
    pub fn from_system_conf() -> Result<Self, String> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|err| format!("the system DNS configuration is unreadable: {err}"))?
            .build();
        Ok(TxtResolverHandle { resolver })
    }
}

impl TxtResolver for TxtResolverHandle {
    fn resolve_txt(
        &self,
        name: String,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send>> {
        let resolver = self.resolver.clone();
        Box::pin(async move {
            let lookup = resolver
                .txt_lookup(&name)
                .await
                .map_err(|err| format!("the TXT lookup for {name} failed: {err}"))?;
            Ok(lookup
                .iter()
                .map(|txt| {
                    // TXT records may split the value across
                    // character-strings; the RFC's value is the
                    // concatenation.
                    let bytes: Vec<u8> = txt
                        .txt_data()
                        .iter()
                        .flat_map(|segment| segment.iter())
                        .copied()
                        .collect();
                    String::from_utf8_lossy(&bytes).into_owned()
                })
                .collect())
        })
    }
}

/// The closed degradation (see
/// [`crate::state::VerificationDeps::production`]): every request fails
/// with the construction failure's text.
pub struct FailingFetcher(pub String);

impl ChallengeFetch for FailingFetcher {
    fn fetch(&self, _url: String) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>> {
        let detail = self.0.clone();
        Box::pin(async move { Err(detail) })
    }
}

/// The closed DNS-01 degradation (see
/// [`crate::state::VerificationDeps::production`]).
pub struct FailingTxtResolver(pub String);

impl TxtResolver for FailingTxtResolver {
    fn resolve_txt(
        &self,
        _name: String,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send>> {
        let detail = self.0.clone();
        Box::pin(async move { Err(detail) })
    }
}

/// The trigger payload of RFC 8555 §7.5.1: an (usually empty) JSON
/// object. The challenges of this document define NO response fields, so
/// the object is accepted and every member is IGNORED — deliberately not
/// a single member is deserialized. That is how a client cannot even
/// PRESENT a suggested answer on this route (`keyAuthorization` and
/// friends go nowhere): the expected value is computed server-side.
#[derive(Debug, Deserialize)]
struct ChallengePayload {}

/// `POST /acme/{tenant}/chall/{challenge}` — the RFC 8555 §7.5.1
/// challenge surface, kid-carried and account-scoped (the owning
/// authorization's account must match the kid; a foreign or missing
/// challenge is the usual one-404-no-oracle miss). The empty payload is
/// RFC POST-as-GET: a plain read of the challenge object. An object
/// payload triggers the SYNCHRONOUS verification (settlement D4): the
/// route computes the expected answer from the STORED token and the
/// authenticating account's own RFC 7638 thumbprint, fetches/resolves
/// server-side (HTTP-01: GET `http://<identifier>/.well-known/
/// acme-challenge/<token>` with the bounded, proxyless client; DNS-01:
/// TXT on `_acme-challenge.<identifier>`), then transitions the
/// challenge, authorization, and order in ONE transaction and responds
/// the challenge object as of that moment.
///
/// Lifecycle (settlement D6): unlimited re-POSTs while the authorization
/// is pending, paced by the per-authorization backoff (a refusal inside
/// the window touches nothing); a decided challenge answers its standing
/// object without re-verifying; an authorization past its 7-day pending
/// window transitions itself `expired` first, and further POSTs refuse
/// `unauthorized` — the §6.7 registry's closest type (there is no
/// `expired` URN; the expiry rides the detail).
///
/// The anti-goal stands by construction: §7.5.1's response fields are
/// ignored wholesale, and nothing on this route can ingest a
/// client-suggested answer — [`dns01` verification] compares the
/// DNS layer the server resolved and the `http-01` fetch the server
/// made.
async fn challenge_url(
    State(state): State<AppState>,
    Path((tenant_name, challenge_id)): Path<(String, String)>,
    raw: Bytes,
) -> Result<Response, AcmeProblem> {
    let tenant = resolve_tenant(&state, &tenant_name).await?;
    let base = public_base(&state)?;
    let expected_url = format!("{base}/acme/{}/chall/{challenge_id}", tenant.name);
    let raw = as_str(&raw)?;

    let (account, payload) =
        authenticate_kid_account(&state, &tenant, &base, &expected_url, raw).await?;
    let challenge_id =
        Uuid::parse_str(&challenge_id).map_err(|_| AcmeProblem::not_found("no such challenge"))?;
    let challenge = AcmeRepo::new()
        .get_challenge(&state.pool, tenant.id, challenge_id)
        .await?
        .ok_or_else(|| AcmeProblem::not_found("no such challenge"))?;
    let authorization = AcmeRepo::new()
        .get_authorization(&state.pool, tenant.id, challenge.authorization_id)
        .await?
        .filter(|authorization| authorization.account_id == account.id)
        .ok_or_else(|| AcmeProblem::not_found("no such challenge"))?;
    let account_url_str = format!(
        "{base}/acme/{}/acct/{}",
        tenant.name, account.jwk_thumbprint
    );
    let authorization =
        expire_authorization_if_past(&state, &tenant, &base, &account_url_str, authorization)
            .await?;

    // POST-as-GET: a plain read, no verification.
    if payload.is_null() {
        return Ok(challenge_response(
            StatusCode::OK,
            &base,
            &tenant.name,
            &challenge,
        ));
    }
    // The §7.5.1 trigger: everything the client sent beyond the JWS
    // envelope is a response-object member the RFC says to ignore — the
    // object is parsed for shape, the members are not.
    let _trigger: ChallengePayload = serde_json::from_value(payload)
        .map_err(|_| AcmeProblem::malformed("the challenge payload is not a JSON object"))?;

    // A VALID challenge answers its standing object: its verification
    // already ran, and §7.1.6's state machine offers no edge to undo or
    // repeat it.
    if challenge.status == AcmeChallengeStatus::Valid {
        return Ok(challenge_response(
            StatusCode::OK,
            &base,
            &tenant.name,
            &challenge,
        ));
    }
    // The authorization's lifecycle gates the trigger.
    match authorization.status {
        AcmeAuthorizationStatus::Pending => {}
        AcmeAuthorizationStatus::Valid => {
            // Fix round 1 (F1): §7.1.6's AUTHORIZATION state machine has
            // NO valid→invalid edge either. A trigger on any challenge of
            // a settled authorization — the still-pending dns-01 sibling
            // of an http-01 that just settled valid — must never run the
            // verifier again: one failed sibling attempt would otherwise
            // regress the authorization and invalidate its order.
            return Err(AcmeProblem::unauthorized(
                "the authorization is already valid; a challenge may no longer be verified",
            ));
        }
        AcmeAuthorizationStatus::Expired => {
            return Err(AcmeProblem::unauthorized("the authorization has expired"));
        }
        AcmeAuthorizationStatus::Invalid => {
            return Err(AcmeProblem::unauthorized("the authorization is invalid"));
        }
        AcmeAuthorizationStatus::Deactivated => {
            return Err(AcmeProblem::unauthorized(
                "the authorization is deactivated",
            ));
        }
    }
    // Settlement D5's pacing: the next attempt on this authorization is
    // one window after the last; a refusal inside the window touches
    // nothing (no processing mark, no fetch, no row write).
    if !state.verification.try_record_attempt(authorization.id) {
        return Err(AcmeProblem {
            status: StatusCode::BAD_REQUEST,
            type_urn: URN_RATE_LIMITED,
            detail: "another verification attempt on this authorization is inside its \
                     pacing window; retry shortly"
                .to_owned(),
            tos_link: None,
            location: None,
        });
    }

    // In-flight bookkeeping: `processing` until the verdict — a request
    // that dies mid-verification leaves the row `processing`, which
    // re-enters like a retry (§8.2's client-retry semantics).
    AcmeRepo::new()
        .update_challenge_status(
            &state.pool,
            tenant.id,
            challenge.id,
            AcmeChallengeStatus::Processing,
            None,
            None,
        )
        .await?;

    // The server-side verdict. The expected answer is COMPUTED here from
    // the STORED token and the AUTHENTICATING account's own thumbprint —
    // the key that signed this very request — and checked against the
    // origin the server itself reaches.
    let expected = ws_acme::key_authorization(&challenge.token, &account.jwk_thumbprint);
    let verdict = match challenge.challenge_type {
        AcmeChallengeType::Http01 => {
            // An http-01 row never exists for a wildcard identifier
            // (mint_challenge_pair mints DNS-01 alone there); the guard
            // is defense-in-depth against stray rows.
            if authorization.identifier.starts_with("*.") {
                Err("HTTP-01 cannot prove a wildcard identifier".to_owned())
            } else {
                let url = format!(
                    "http://{}/.well-known/acme-challenge/{}",
                    authorization.identifier, challenge.token
                );
                match state.verification.http_fetcher.fetch(url).await {
                    Ok(body) if body == expected => Ok(()),
                    Ok(_) => Err(format!(
                        "the key authorization served at /.well-known/acme-challenge/{} \
                         does not match the expected value",
                        challenge.token
                    )),
                    Err(detail) => Err(detail),
                }
            }
        }
        AcmeChallengeType::Dns01 => {
            // RFC 8555's wildcard rule: the TXT name uses the identifier
            // WITHOUT the `*.` prefix (the authorization row stores it
            // verbatim).
            let domain = authorization
                .identifier
                .strip_prefix("*.")
                .unwrap_or(&authorization.identifier);
            let name = format!("_acme-challenge.{domain}.");
            // §8.4: the record the server looks for is
            // base64url(SHA256(key authorization)) — computed here from
            // the same expected key authorization the http-01
            // exact-match uses.
            let record_value = ws_acme::dns01_record_value(&expected);
            match state
                .verification
                .txt_resolver
                .resolve_txt(name.clone())
                .await
            {
                Ok(records) if records.iter().any(|record| record == &record_value) => Ok(()),
                Ok(_) => Err(format!(
                    "no TXT record for {name} matches the expected value"
                )),
                Err(detail) => Err(detail),
            }
        }
    };

    let settled = settle_challenge(
        &state,
        &tenant,
        &base,
        &account_url_str,
        &challenge,
        &authorization,
        verdict,
    )
    .await?;
    Ok(challenge_response(
        StatusCode::OK,
        &base,
        &tenant.name,
        &settled,
    ))
}

/// The challenge object (RFC 8555 §8's data shape): type, url, token,
/// status — with `validated` (RFC 3339) once decided and, on a failure,
/// the `error` problem document (the registry's generic `serverInternal`
/// URN; the stored flat text is the detail).
fn challenge_object(base: &str, tenant_name: &str, challenge: &AcmeChallengeModel) -> Value {
    let mut object = json!({
        "type": challenge.challenge_type.as_str(),
        "url": format!("{base}/acme/{tenant_name}/chall/{}", challenge.id),
        "token": challenge.token,
        "status": challenge.status.as_str(),
    });
    if let Some(validated) = challenge.validated_at {
        object["validated"] = json!(validated.to_rfc3339_opts(SecondsFormat::Secs, true));
    }
    if let Some(error) = &challenge.error {
        object["error"] = json!({
            "type": "urn:ietf:params:acme:error:serverInternal",
            "detail": error,
        });
    }
    object
}

/// A challenge-object response (§7.5.1 answers the POST with the updated
/// challenge object; no Location header — the URL is already in hand).
fn challenge_response(
    status: StatusCode,
    base: &str,
    tenant_name: &str,
    challenge: &AcmeChallengeModel,
) -> Response {
    (status, Json(challenge_object(base, tenant_name, challenge))).into_response()
}

/// Task 7's poll-time obligation (the Task-6 review's carrying item): a
/// PENDING authorization past its 7-day window transitions ITSELF to
/// `expired` wherever the surface touches it — a POST-as-GET read, a
/// challenge trigger, an order poll — instead of the silent omission the
/// old poll documented. RFC 8555 §7.1.6: an order goes invalid when one
/// of its authorizations enters a final state other than valid, so an
/// order-scoped expired row invalidates its order under the
/// `acme_order_invalidated` audit row, in ONE transaction.
async fn expire_authorization_if_past(
    state: &AppState,
    tenant: &Tenant,
    base: &str,
    account_url: &str,
    mut authorization: AcmeAuthorizationModel,
) -> Result<AcmeAuthorizationModel, AcmeProblem> {
    if authorization.status != AcmeAuthorizationStatus::Pending
        || authorization.expires_at > Utc::now()
    {
        return Ok(authorization);
    }
    let mut tx = state.pool.begin().await?;
    AcmeRepo::new()
        .update_authorization_status(
            &mut *tx,
            tenant.id,
            authorization.id,
            AcmeAuthorizationStatus::Expired,
            None,
        )
        .await?;
    if let Some(order_id) = authorization.order_id {
        invalidate_order(
            &mut tx,
            tenant,
            base,
            order_id,
            &authorization,
            "the authorization expired",
            account_url,
        )
        .await?;
    }
    tx.commit().await?;
    tracing::warn!(
        authorization = %authorization.id,
        "an expired pending authorization transitioned itself at poll/POST time"
    );
    authorization.status = AcmeAuthorizationStatus::Expired;
    Ok(authorization)
}

/// The RFC 8555 §7.1.6 companion: an authorization that entered a final
/// non-valid state invalidates its order — when that order is not itself
/// `valid` (a regressed order would contradict the state machine) — with
/// the reason as the flattened `error`, under the `acme_order_invalidated`
/// audit row. Runs INSIDE the caller's transaction.
async fn invalidate_order(
    tx: &mut sqlx::PgConnection,
    tenant: &Tenant,
    base: &str,
    order_id: Uuid,
    authorization: &AcmeAuthorizationModel,
    reason: &str,
    account_url: &str,
) -> Result<(), AcmeProblem> {
    let order = AcmeRepo::new()
        .get_order(&mut *tx, tenant.id, order_id)
        .await?
        .ok_or_else(|| AcmeProblem::internal("an authorization's order vanished"))?;
    if order.status == AcmeOrderStatus::Valid {
        // A valid order cannot regress: its authorizations were all
        // settled `valid` long before any row could fall out from under
        // it.
        return Ok(());
    }
    let error = format!(
        "the authorization for {} failed: {reason}",
        authorization.identifier
    );
    AcmeRepo::new()
        .update_order_status(
            &mut *tx,
            tenant.id,
            order_id,
            AcmeOrderStatus::Invalid,
            None,
            Some(&error),
        )
        .await?;
    let actor = acme_actor(tenant.id, account_url.to_owned());
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &actor,
                "acme_order_invalidated",
                "acme_order",
                &order.id.to_string(),
                json!({
                    "order_url": order_object_url(base, &tenant.name, order.id),
                    "authorization": authorization.id.to_string(),
                    "identifier": authorization.identifier,
                    "error": error,
                }),
            ),
        )
        .await?;
    tracing::info!(
        order = %order.id,
        "acme order invalidated by an authorization's final state"
    );
    Ok(())
}

/// The ready companion: when the LAST of an order's authorizations
/// settles `valid`, the order is `ready` (RFC 8555 §7.1.6) —
/// transitioned only from `pending` (a ready order stays ready;
/// a processing/valid one is past this step; an invalid one never
/// re-readies). Runs INSIDE the caller's transaction.
async fn ready_order_when_all_authorizations_valid(
    tx: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    order_id: Uuid,
) -> Result<(), AcmeProblem> {
    let order = AcmeRepo::new()
        .get_order(&mut *tx, tenant_id, order_id)
        .await?
        .ok_or_else(|| AcmeProblem::internal("an authorization's order vanished"))?;
    if order.status != AcmeOrderStatus::Pending {
        return Ok(());
    }
    let authorizations = AcmeRepo::new()
        .list_authorizations_by_order(&mut *tx, tenant_id, order_id)
        .await?;
    if authorizations
        .iter()
        .all(|a| a.status == AcmeAuthorizationStatus::Valid)
    {
        AcmeRepo::new()
            .update_order_status(
                &mut *tx,
                tenant_id,
                order_id,
                AcmeOrderStatus::Ready,
                None,
                None,
            )
            .await?;
        tracing::info!(order = %order_id, "all authorizations valid: the acme order is ready");
    }
    Ok(())
}

/// The verdict transaction: the challenge's decision, the owning
/// authorization's transition (a `valid` stamps the 30-day REUSE WINDOW
/// as the fresh `expires_at`; an `invalid` is final), and the
/// order-scoped companions (ready / invalid + audit) commit in ONE
/// transaction. The route renders the row as of this moment — the refetch
/// follows the commit.
async fn settle_challenge(
    state: &AppState,
    tenant: &Tenant,
    base: &str,
    account_url: &str,
    challenge: &AcmeChallengeModel,
    authorization: &AcmeAuthorizationModel,
    verdict: Result<(), String>,
) -> Result<AcmeChallengeModel, AcmeProblem> {
    let now = Utc::now();
    let mut tx = state.pool.begin().await?;
    match verdict {
        Ok(()) => {
            AcmeRepo::new()
                .update_challenge_status(
                    &mut *tx,
                    tenant.id,
                    challenge.id,
                    AcmeChallengeStatus::Valid,
                    Some(now),
                    None,
                )
                .await?;
            AcmeRepo::new()
                .update_authorization_status(
                    &mut *tx,
                    tenant.id,
                    authorization.id,
                    AcmeAuthorizationStatus::Valid,
                    Some(now + chrono::Duration::days(REUSE_WINDOW_DAYS)),
                )
                .await?;
            if let Some(order_id) = authorization.order_id {
                ready_order_when_all_authorizations_valid(&mut tx, tenant.id, order_id).await?;
            }
        }
        Err(detail) => {
            AcmeRepo::new()
                .update_challenge_status(
                    &mut *tx,
                    tenant.id,
                    challenge.id,
                    AcmeChallengeStatus::Invalid,
                    Some(now),
                    Some(&detail),
                )
                .await?;
            AcmeRepo::new()
                .update_authorization_status(
                    &mut *tx,
                    tenant.id,
                    authorization.id,
                    AcmeAuthorizationStatus::Invalid,
                    None,
                )
                .await?;
            if let Some(order_id) = authorization.order_id {
                invalidate_order(
                    &mut tx,
                    tenant,
                    base,
                    order_id,
                    authorization,
                    &detail,
                    account_url,
                )
                .await?;
            }
        }
    }
    tx.commit().await?;
    tracing::info!(challenge = %challenge.id, "acme challenge settled");
    AcmeRepo::new()
        .get_challenge(&state.pool, tenant.id, challenge.id)
        .await?
        .ok_or_else(|| AcmeProblem::internal("the challenge vanished during its settlement"))
}

/// Mint the challenges of a freshly minted authorization (the plan's
/// Task-6 pin: BOTH flavors per PLAIN identifier — http-01 AND dns-01,
/// the client picks by requesting validation on one). The RFC 8555
/// wildcard rule (Task 7): http-01 cannot prove a wildcard identifier, so
/// a `*.`-prefixed authorization mints its DNS-01 challenge ALONE — an
/// http-01 row never exists for a wildcard.
async fn mint_challenge_pair(
    executor: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    authorization_id: Uuid,
    identifier: &str,
    now: DateTime<Utc>,
) -> Result<(), AcmeProblem> {
    let flavors: &[AcmeChallengeType] = if identifier.starts_with("*.") {
        &[AcmeChallengeType::Dns01]
    } else {
        &[AcmeChallengeType::Http01, AcmeChallengeType::Dns01]
    };
    for challenge_type in flavors {
        let challenge_type = *challenge_type;
        let challenge = AcmeChallengeModel {
            id: Uuid::new_v4(),
            tenant_id,
            authorization_id,
            challenge_type,
            token: mint_challenge_token(),
            status: AcmeChallengeStatus::Pending,
            validated_at: None,
            error: None,
            created_at: now,
        };
        AcmeRepo::new()
            .insert_challenge(&mut *executor, &challenge)
            .await?;
    }
    Ok(())
}
/// A challenge token: 32 OS-random bytes, unpadded base64url — the
/// `ws_acme::NonceStore::mint` idiom verbatim (a dead OS entropy source
/// is unrecoverable, so minting fails loudly rather than fabricating a
/// token).
fn mint_challenge_token() -> String {
    use rand::{rngs::SysRng, TryRng};
    let mut raw = [0u8; 32];
    if let Err(e) = SysRng.try_fill_bytes(&mut raw) {
        panic!("OS entropy source failed while minting an ACME challenge token: {e}");
    }
    URL_SAFE_NO_PAD.encode(raw)
}

/// The identifiers array's dns VALUE strings, in the order offered, under
/// v1's light validator. The type gate: `dns` only — any other type is
/// the RFC registry's `rejectedIdentifier` with the offending TYPE named
/// in the detail (the plan's pin; the identifier value itself never
/// enters the response — the RFC's `Link rel="up"` rendering of the
/// rejected identifier would leak it into headers it does not need to be
/// in). DNS shape: non-empty, no leading dot, optional `*.` wildcard
/// prefix (the RFC 8555 wildcard-authority form Task 10's e2e
/// exercises), no whitespace or slash. A repeated value is `malformed`.
fn dns_identifiers(identifiers: &Value) -> Result<Vec<String>, AcmeProblem> {
    let entries = identifiers
        .as_array()
        .ok_or_else(|| AcmeProblem::malformed("the identifiers member must be an array"))?;
    if entries.is_empty() {
        return Err(AcmeProblem::malformed(
            "the identifiers member must carry at least one identifier",
        ));
    }
    let mut values = Vec::with_capacity(entries.len());
    for entry in entries {
        let object = entry.as_object().ok_or_else(|| {
            AcmeProblem::malformed("each identifier must be an object with type and value")
        })?;
        let identifier_type = object
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| AcmeProblem::malformed("each identifier must carry a type string"))?;
        if identifier_type != "dns" {
            return Err(AcmeProblem {
                status: StatusCode::BAD_REQUEST,
                type_urn: URN_REJECTED_IDENTIFIER,
                detail: format!(
                    "the identifier type {identifier_type:?} is not supported; only \"dns\" is"
                ),
                tos_link: None,
                location: None,
            });
        }
        let value = object
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| AcmeProblem::malformed("each dns identifier must carry a value"))?;
        validate_dns_value(value)?;
        if values.contains(&value.to_owned()) {
            return Err(AcmeProblem::malformed(format!(
                "the identifiers member repeats {value:?}"
            )));
        }
        values.push(value.to_owned());
    }
    Ok(values)
}

/// The dns-value validator (see [`dns_identifiers`]): no full hostname
/// spec, but the EXACT charset a DNS name can carry — letters, digits,
/// hyphens, dots, plus the `*.` wildcard prefix the RFC 8555 wildcard
/// form needs. The charset is a trust boundary, not cosmetics: the
/// HTTP-01 verification builds its fetch URL from the identifier
/// (`http://<identifier>/.well-known/...`), and a character outside the
/// hostname set — userinfo `@`, a port `:`, query `?`/`#`, percent
/// escapes — would let an order shape the AUTHORITY of the server's
/// outbound fetch (fix round 1, F2). Everything outside the charset is
/// refused `malformed` at new-order.
fn validate_dns_value(value: &str) -> Result<(), AcmeProblem> {
    let refused = |why: &str| {
        AcmeProblem::malformed(format!(
            "the dns identifier {value:?} is not a valid DNS name: {why}"
        ))
    };
    if value.is_empty() {
        return Err(refused("it is empty"));
    }
    if value.starts_with('.') {
        return Err(refused("it has a leading dot"));
    }
    let domain = match value.strip_prefix("*.") {
        // The wildcard-authority form: the prefix must name a domain.
        Some(domain) => {
            if domain.is_empty() || domain.starts_with('.') {
                return Err(refused("the wildcard prefix names no domain"));
            }
            domain
        }
        // A plain name: nothing is stripped.
        None => value,
    };
    if !domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(refused(
            "it carries characters outside the DNS-name charset (letters, digits, hyphens, dots)",
        ));
    }
    Ok(())
}

/// Parse an optional RFC 3339 payload member (`notBefore`/`notAfter`).
fn rfc3339_member(
    member: &Option<String>,
    name: &str,
) -> Result<Option<DateTime<Utc>>, AcmeProblem> {
    member
        .as_deref()
        .map(|value| {
            DateTime::parse_from_rfc3339(value)
                .map(DateTime::<Utc>::from)
                .map_err(|_| {
                    AcmeProblem::malformed(format!(
                        "the {name} member is not an RFC 3339 timestamp"
                    ))
                })
        })
        .transpose()
}

/// The absolute URL of an order object (the `Location` handle).
fn order_object_url(base: &str, tenant_name: &str, order_id: Uuid) -> String {
    format!("{base}/acme/{tenant_name}/orders/{order_id}")
}

/// The absolute URL of an authorization object.
fn authz_object_url(base: &str, tenant_name: &str, authorization_id: Uuid) -> String {
    format!("{base}/acme/{tenant_name}/authz/{authorization_id}")
}

/// An order-object response: `status` (201 on creation with its
/// `Location`, 200 on POST-as-GET — same body, different shape on top).
fn order_response(
    status: StatusCode,
    base: &str,
    tenant_name: &str,
    order: &AcmeOrderModel,
    authorizations: Option<&[String]>,
) -> Response {
    let location = order_object_url(base, tenant_name, order.id);
    let mut response = (
        status,
        Json(order_object(base, tenant_name, order, authorizations)),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
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

    /// A resource that does not exist — or that exists but belongs to
    /// another account (one 404 problem document, no existence oracle).
    /// The registry's `malformed` slug at a 404 status, the shape the
    /// unknown-tenant reply already establishes.
    fn not_found(detail: impl Into<String>) -> Self {
        AcmeProblem {
            status: StatusCode::NOT_FOUND,
            type_urn: "urn:ietf:params:acme:error:malformed",
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

/// The REST error vocabulary of the shared issuance core
/// ([`crate::routes::certificates::issue_certificate_core`], which the
/// finalize route delegates to) maps onto the same registry the ACME
/// surface answers with — the error never reaches the wire in its `/api`
/// body shape. The profile-policy refusal keeps its message: the 400
/// `malformed` problem's detail IS the `not_permitted_by_profile`
/// message the manual path returns (the generic form, since the ACME
/// account carries no `read_profiles`).
impl From<ApiError> for AcmeProblem {
    fn from(err: ApiError) -> Self {
        match err {
            ApiError::BadRequest { message, .. } => AcmeProblem::malformed(message),
            ApiError::Unauthorized(m) | ApiError::UnauthorizedMfa(m) | ApiError::Forbidden(m) => {
                AcmeProblem::unauthorized(m)
            }
            ApiError::NotFound(m) => AcmeProblem::not_found(m),
            ApiError::Conflict(m) | ApiError::Internal(m) => AcmeProblem::internal(m),
            ApiError::RateLimited(_) => AcmeProblem {
                status: StatusCode::TOO_MANY_REQUESTS,
                type_urn: URN_RATE_LIMITED,
                detail: "the account has exceeded its ACME rate limit; retry later".to_owned(),
                tos_link: None,
                location: None,
            },
        }
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

/// The RFC 8555 §7.4 order object. `profile` is the Wardstone extension
/// member (see [`NewOrderPayload`]); `notBefore`/`notAfter` ride only
/// when the client asked; `authorizations` is carried only while the
/// order is pending or ready; `certificate` (Task 8's serving route) only
/// on a valid order that has one; `error` renders the stored failure text
/// as a problem document (the stored text carries no registry category,
/// so the wire type is the generic `serverInternal` URN and the detail
/// message is the authoritative part).
fn order_object(
    base: &str,
    tenant_name: &str,
    order: &AcmeOrderModel,
    authorizations: Option<&[String]>,
) -> Value {
    let mut object = json!({
        "status": order.status.as_str(),
        "expires": order.expires_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        "identifiers": &order.identifiers,
        "profile": order.profile_name,
        "finalize": format!("{base}/acme/{tenant_name}/orders/{}/finalize", order.id),
    });
    if let Some(not_before) = order.not_before {
        object["notBefore"] = json!(not_before.to_rfc3339_opts(SecondsFormat::Secs, true));
    }
    if let Some(not_after) = order.not_after {
        object["notAfter"] = json!(not_after.to_rfc3339_opts(SecondsFormat::Secs, true));
    }
    if let Some(urls) = authorizations {
        object["authorizations"] = json!(urls);
    }
    if order.status == AcmeOrderStatus::Valid && order.certificate_id.is_some() {
        object["certificate"] = json!(format!(
            "{base}/acme/{tenant_name}/orders/{}/certificate",
            order.id
        ));
    }
    if let Some(error) = &order.error {
        object["error"] = json!({
            "type": "urn:ietf:params:acme:error:serverInternal",
            "detail": error,
        });
    }
    object
}

/// The RFC 8555 §7.5.1 authorization object: status, identifier, expiry,
/// and the BOTH-flavor challenges with their absolute `chall` URLs (Task
/// 7's verification route). A `*.`-prefixed stored identifier renders
/// without the prefix and with `wildcard: true` (see [`authz_url`]).
fn authz_object(
    base: &str,
    tenant_name: &str,
    authorization: &AcmeAuthorizationModel,
    challenges: &[AcmeChallengeModel],
) -> Value {
    let wildcard = authorization.identifier.starts_with("*.");
    let identifier = authorization
        .identifier
        .strip_prefix("*.")
        .unwrap_or(&authorization.identifier);
    let mut object = json!({
        "status": authorization.status.as_str(),
        "identifier": { "type": "dns", "value": identifier },
        "expires": authorization.expires_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        "challenges": challenges
            .iter()
            .map(|challenge| {
                json!({
                    "type": challenge.challenge_type.as_str(),
                    "url": format!("{base}/acme/{tenant_name}/chall/{}", challenge.id),
                    "token": challenge.token,
                    "status": challenge.status.as_str(),
                })
            })
            .collect::<Vec<_>>(),
    });
    if wildcard {
        object["wildcard"] = json!(true);
    }
    object
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

// ===========================================================================
// The UI-facing REST projection (Plan 4 Task 10)
// ===========================================================================
//
// The operator's ordinary-REST window over the SAME rows the JWS machine
// surface above serves. This projection lives under `/api/v1/acme`
// (nested by `routes::router`) and reads through exactly the machinery
// Tasks 5-8 already built: the account rows, `list_orders_by_account`,
// `list_accounts_with_order_counts`, `get_order_by_certificate`, and
// `deactivation_cascade`. It is deliberately NOT protocol surface: no
// JWS, no nonces, no problem documents — every handler authenticates
// with the ordinary session/token bearer ([`AuthActor`]) and gates on a
// CAPABILITY (`read_acme` for reads, `manage_acme_accounts` for the
// deactivation, mirroring migration 012's seed). Errors are the house
// [`ApiError`] envelope; another tenant's account is a 404, exactly as
// indistinguishable as every other tenant-scoped route.
//
// The audit split, pinned by the plan: a deactivation through THIS
// surface records the CALLING USER as the audit actor (a human acted,
// through a capability the role granted) — the `AcmeAccount` actor shape
// above stays for the JWS-machine path, where the account key itself is
// the acting identity. The action name and target tuple
// (`acme_account_deactivated` on the `acme_account` row) are identical on
// both surfaces; the details carry `"surface": "rest"` so the log can
// tell the two entry points apart.

/// The REST projection's recent-orders window on an account detail: the
/// account detail serves the first page of `list_orders_by_account` at
/// this size (the full history pages through `GET /orders?account_id=`).
const REST_DETAIL_ORDERS_PAGE_SIZE: u32 = 20;

/// The REST projection's route tree, nested at `/api/v1/acme` by
/// [`crate::routes::router`]. Every handler resolves the actor's OWN
/// tenant (`auth.tenant_id`) — a browser session cannot name another
/// tenant the way the path-tenanted JWS surface can.
pub fn rest_router() -> Router<AppState> {
    Router::new()
        .route("/accounts", get(rest_list_accounts))
        .route("/accounts/{id}", get(rest_get_account))
        .route("/accounts/{id}/deactivate", post(rest_deactivate_account))
        .route("/orders", get(rest_list_orders))
}

/// One ACME account as the operator list answers it: the display-relevant
/// fields (the thumbprint IS the account's human-facing identity — it is
/// the kid URL's final segment — hence it rides alongside `contact`),
/// plus `orders_count` from [`AcmeAccountWithOrders`].
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AcmeAccountResponse {
    pub id: Uuid,
    pub jwk_thumbprint: String,
    pub status: String,
    pub tos_agreed_at: Option<DateTime<Utc>>,
    pub contact: Option<String>,
    pub created_at: DateTime<Utc>,
    pub orders_count: i64,
}

impl From<AcmeAccountWithOrders> for AcmeAccountResponse {
    fn from(row: AcmeAccountWithOrders) -> Self {
        let account = row.account;
        AcmeAccountResponse {
            id: account.id,
            jwk_thumbprint: account.jwk_thumbprint,
            status: account.status.as_str().to_string(),
            tos_agreed_at: account.tos_agreed_at,
            contact: account.contact,
            created_at: account.created_at,
            orders_count: row.orders_count,
        }
    }
}

/// One ACME order as the operator view answers it: lifecycle fields plus
/// the raw RFC 8555 `identifiers` array (stored verbatim, passed through
/// verbatim — the UI renders `type`/`value` pairs), the profile NAME (the
/// display label, matching the manual-path DTOs), and the issued
/// certificate pointer the UI links back through.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AcmeOrderResponse {
    pub id: Uuid,
    pub account_id: Uuid,
    pub status: String,
    pub profile_name: String,
    pub identifiers: Value,
    pub certificate_id: Option<Uuid>,
    pub error: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl From<&AcmeOrderModel> for AcmeOrderResponse {
    fn from(order: &AcmeOrderModel) -> Self {
        AcmeOrderResponse {
            id: order.id,
            account_id: order.account_id,
            status: order.status.as_str().to_string(),
            profile_name: order.profile_name.clone(),
            identifiers: order.identifiers.clone(),
            certificate_id: order.certificate_id,
            error: order.error.clone(),
            expires_at: order.expires_at,
            created_at: order.created_at,
        }
    }
}

/// The account detail: the list's fields plus the RECENT orders window
/// ([`REST_DETAIL_ORDERS_PAGE_SIZE`]).
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AcmeAccountDetailResponse {
    pub id: Uuid,
    pub jwk_thumbprint: String,
    pub status: String,
    pub tos_agreed_at: Option<DateTime<Utc>>,
    pub contact: Option<String>,
    pub created_at: DateTime<Utc>,
    pub orders: Vec<AcmeOrderResponse>,
}

/// The deactivation response: the account's new state and the two cascade
/// counts — how many pending authorizations were invalidated and how many
/// open orders were stamped invalid (0/0 on the idempotent repeat, which
/// writes no second audit row, mirroring the manual revoke's contract).
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AcmeDeactivateResponse {
    pub id: Uuid,
    pub status: String,
    pub authorizations_invalidated: u64,
    pub orders_invalidated: u64,
}

/// `GET /api/v1/acme/accounts` — the tenant's ACME accounts, one page,
/// `read_acme`, each row with its order count.
async fn rest_list_accounts(
    auth: AuthActor,
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<AcmeAccountResponse>>, ApiError> {
    auth.require(Capability::ReadAcme).map_err(ApiError::from)?;
    let rows = AcmeRepo::new()
        .list_accounts_with_order_counts(
            &state.pool,
            auth.tenant_id,
            query.page(),
            query.page_size(),
        )
        .await?;
    Ok(Json(
        rows.into_iter().map(AcmeAccountResponse::from).collect(),
    ))
}

/// `GET /api/v1/acme/accounts/{id}` — one account (`read_acme`) plus its
/// recent orders; another tenant's account is a 404.
async fn rest_get_account(
    auth: AuthActor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AcmeAccountDetailResponse>, ApiError> {
    auth.require(Capability::ReadAcme).map_err(ApiError::from)?;
    let account = AcmeRepo::new()
        .get_account_by_id(&state.pool, auth.tenant_id, id)
        .await?
        .ok_or_else(|| ApiError::NotFound("acme account not found".to_string()))?;
    let orders = AcmeRepo::new()
        .list_orders_by_account(
            &state.pool,
            auth.tenant_id,
            account.id,
            0,
            REST_DETAIL_ORDERS_PAGE_SIZE,
        )
        .await?;
    Ok(Json(AcmeAccountDetailResponse {
        id: account.id,
        jwk_thumbprint: account.jwk_thumbprint,
        status: account.status.as_str().to_string(),
        tos_agreed_at: account.tos_agreed_at,
        contact: account.contact,
        created_at: account.created_at,
        orders: orders.iter().map(AcmeOrderResponse::from).collect(),
    }))
}

/// `POST /api/v1/acme/accounts/{id}/deactivate` — `manage_acme_accounts`.
/// The one-way RFC 8555 §7.3.7 gate driven by a HUMAN: the account row
/// moves to `deactivated` and Task 5's cascade invalidates its pending
/// authorizations and open orders, all in ONE transaction with the audit
/// row (the calling USER as the actor — see the section doc). Idempotent
/// on an already-deactivated account (a no-op echo, no second audit row).
async fn rest_deactivate_account(
    auth: AuthActor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AcmeDeactivateResponse>, ApiError> {
    auth.require(Capability::ManageAcmeAccounts)
        .map_err(ApiError::from)?;
    let repo = AcmeRepo::new();
    let account = repo
        .get_account_by_id(&state.pool, auth.tenant_id, id)
        .await?
        .ok_or_else(|| ApiError::NotFound("acme account not found".to_string()))?;

    // Idempotency (the certificate-revoke route's shape): an already
    // deactivated account changes nothing and writes no second audit row.
    if account.status == AcmeAccountStatus::Deactivated {
        return Ok(Json(AcmeDeactivateResponse {
            id: account.id,
            status: account.status.as_str().to_string(),
            authorizations_invalidated: 0,
            orders_invalidated: 0,
        }));
    }

    // The same error text the JWS machine path stamps ("account
    // deactivated") so the two surfaces leave identical order rows; the
    // audit details tell them apart.
    let mut tx = state.pool.begin().await?;
    repo.update_account_status(
        &mut *tx,
        auth.tenant_id,
        account.id,
        AcmeAccountStatus::Deactivated,
    )
    .await?;
    let (authorizations, orders) = repo
        .deactivation_cascade(&mut tx, auth.tenant_id, account.id, "account deactivated")
        .await?;
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &auth.0,
                "acme_account_deactivated",
                "acme_account",
                &account.id.to_string(),
                json!({
                    "jwk_thumbprint": account.jwk_thumbprint,
                    "surface": "rest",
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
        "acme account deactivated via the REST surface"
    );
    Ok(Json(AcmeDeactivateResponse {
        id: account.id,
        status: AcmeAccountStatus::Deactivated.as_str().to_string(),
        authorizations_invalidated: authorizations,
        orders_invalidated: orders,
    }))
}

/// The `GET /api/v1/acme/orders` query axes: exactly one of `account_id`
/// (an account's orders, paged newest-first) or `certificate_id` (the one
/// order an issued certificate came from). Naming neither is a 400 — an
/// un-scoped tenant-wide order listing is not a shape this route offers.
#[derive(Debug, Deserialize, Default)]
pub struct AcmeOrdersQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    #[serde(default)]
    pub account_id: Option<Uuid>,
    #[serde(default)]
    pub certificate_id: Option<Uuid>,
}

/// `GET /api/v1/acme/orders` — `read_acme`; the orders of one account, or
/// the order behind one certificate ([`AcmeRepo::get_order_by_certificate`]
/// — `None` for a manually-issued or unknown certificate answers an EMPTY
/// list, an ordinary not-found state the UI renders, never an error).
async fn rest_list_orders(
    auth: AuthActor,
    State(state): State<AppState>,
    Query(query): Query<AcmeOrdersQuery>,
) -> Result<Json<Vec<AcmeOrderResponse>>, ApiError> {
    auth.require(Capability::ReadAcme).map_err(ApiError::from)?;
    let repo = AcmeRepo::new();
    let orders = if let Some(account_id) = query.account_id {
        repo.list_orders_by_account(
            &state.pool,
            auth.tenant_id,
            account_id,
            query.page.unwrap_or(0),
            query.page_size.unwrap_or(100),
        )
        .await?
    } else if let Some(certificate_id) = query.certificate_id {
        repo.get_order_by_certificate(&state.pool, auth.tenant_id, certificate_id)
            .await?
            .map(|order| vec![order])
            .unwrap_or_default()
    } else {
        return Err(ApiError::bad_request(
            "name either an account_id or a certificate_id of the orders to list",
        ));
    };
    Ok(Json(orders.iter().map(AcmeOrderResponse::from).collect()))
}
