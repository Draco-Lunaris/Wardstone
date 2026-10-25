//! The certificates routes: issuance (both paths), the one-shot pull,
//! revocation, and the reads.
//!
//! The two issuance paths are SEPARATE capabilities, not one
//! (the plan's route→capability table):
//!
//! | Path | Capability |
//! |---|---|
//! | `POST /api/v1/certificates` with `csr_pem` | `issue` |
//! | `POST /api/v1/certificates` without `csr_pem` | `generate_leaf_key` |
//!
//! An `Issuer` holds `issue` and must therefore be able to reach the CSR
//! path WITHOUT being able to reach the key-generation path — a single
//! capability row for the route would hide exactly that gap. The handler
//! inspects the body and checks the capability that path needs.
//!
//! # The audit write-side contract
//!
//! Every mutating handler opens ONE transaction, does its mutation and
//! its audit `record` inside it, and commits once — the entry and the
//! change commit together or not at all. `AuditRepo::record` takes the
//! executor (Task 6), and so do `serial::allocate_serial` (Task 8) and
//! `claim_one_shot` (Task 9), which is what makes the contract possible:
//! the serial the certificate carries, the certificate row, the one-shot
//! consumption, and the audit row all stand or fall together.
//!
//! # Redactions
//!
//! The key-generation response carries the private key exactly once
//! (server-side key generation: the client never holds it elsewhere). The
//! response is `Cache-Control: no-store`, and the access log records
//! method/path/status only — the body is never read by the log
//! middleware, so the key cannot leak through logging. The
//! `key_generated` audit details carry `profile_id` and `key_type` —
//! never the key.

use std::net::IpAddr;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use ws_ca::issue::{sign_leaf_with, ExtKeyUsagePurpose, IssuedLeaf, LeafSpec, SanEntry};
use ws_ca::keystore::KeyStore;
use ws_ca::leafkey::{generate_leaf_key, LeafKeyType};
use ws_ca::serial::allocate_serial;
use ws_core::error::CoreError;
use ws_core::models::ca::CaModel;
use ws_core::models::certificate::{
    CertStatus, CertificateFilter, CertificateModel, CertificateStatistics, RevocationReason,
};
use ws_core::models::profile::{ProfileModel, ProfileRevisionModel};
use ws_core::models::rbac::{Actor, ActorType, Capability, KeyUsagePurpose};
use ws_core::profile_match::san_is_permitted;
use ws_core::repo::audit_repo::AuditRepo;
use ws_core::repo::ca_repo::CaRepo;
use ws_core::repo::certificate_repo::CertificateRepo;
use ws_core::repo::credential_repo::CredentialRepo;
use ws_core::repo::profile_repo::ProfileRepo;

use crate::auth_middleware::AuthActor;
use crate::error::ApiError;
use crate::routes::{audit_entry, audit_entry_with_id, json_no_store};
use crate::state::AppState;

/// How many times the issuance attempts against a (possibly moved) profile
/// revision before giving up: bounded retries, then `Conflict`.
const MAX_ISSUE_ATTEMPTS: usize = 3;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(issue_certificate).get(list_certificates))
        .route("/pull", post(issue_certificate_one_shot))
        // Exact-match wins anyway, but the literal `/statistics` is pinned
        // BEFORE `/{id}` so the router reads in the order the routes nest.
        .route("/statistics", get(certificate_statistics))
        // The dashboard sieve's slim projection, same reason: the literal
        // `/slim` is registered BEFORE `/{id}` so `slim` is never read as
        // a certificate id.
        .route("/slim", get(list_certificates_slim))
        .route("/{id}", get(get_certificate))
        .route("/{id}/chain", get(get_certificate_chain))
        .route("/{id}/revoke", post(revoke_certificate))
}

/// The issuance request body. A body WITH `csr_pem` selects the CSR path
/// (capability `issue`); a body WITHOUT it selects the server-key-
/// generation path (capability `generate_leaf_key`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct IssueCertificateBody {
    pub profile_id: Uuid,
    pub subject_cn: String,
    /// The proposed subject alternative names (DNS names or IP literals).
    /// Empty is refused: proposing no names is a different artifact, not
    /// a subset of the profile.
    #[serde(default)]
    pub sans: Vec<String>,
    /// The PKCS#10 CSR for the CSR path; `None` selects the
    /// key-generation path.
    #[serde(default)]
    pub csr_pem: Option<String>,
}

/// The issuance response: the certificate PEM, its serial, and — on the
/// key-generation path ONLY — the private key, which appears exactly once
/// and is never returned by any read endpoint.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct IssuedCertificateResponse {
    pub certificate_id: Uuid,
    pub cert_pem: String,
    /// The decimal form of the serial number.
    pub serial: String,
    /// The lowercase-hex form, no leading zeros.
    pub serial_hex: String,
    /// The profile revision the certificate's policy is pinned to.
    pub profile_revision_id: Uuid,
    pub profile_name: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// The private key PEM — the key-generation path ONLY (`None` on the
    /// CSR path: the client generated that key and keeps it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_pem: Option<String>,
}

/// `POST /api/v1/certificates` — the dual-path issuance handler. The
/// response is `Cache-Control: no-store` (the key-generation path's
/// private key must never be cached; the CSR path's certificate is fine
/// to not cache too).
async fn issue_certificate(
    auth: AuthActor,
    State(state): State<AppState>,
    Json(body): Json<IssueCertificateBody>,
) -> Result<Response, ApiError> {
    let response =
        issue_certificate_core(&state, &auth.0, &body, Uuid::new_v4(), Uuid::new_v4(), None)
            .await?;
    Ok(json_no_store(response))
}

/// The issuance core: shared by the HTTP handler, the one-shot pull, the
/// Task-10 tests (the audit-collision and stale-revision cases drive it
/// directly), and the Task-8 ACME finalize path — which calls it with the
/// AcmeAccount actor carrying exactly `Issue`.
///
/// `cert_id` / `audit_id` are caller-chosen (the handler passes fresh
/// v4s; the tests pass a pre-existing audit id to force the audit insert
/// to fail with a duplicate primary key — the transaction must abort
/// leaving nothing behind). `expected_revision` pins the revision the
/// caller has validated against; `None` reads the profile's current
/// revision fresh.
///
/// The flow: capability check by path → profile/revision read → name
/// validation against that revision → CA choice and remaining-life
/// pre-check → ONE transaction (CAS re-affirmation of the revision,
/// serial allocation, signing, certificate insert, audit record) →
/// commit. If the revision moved under us, the transaction rolls back —
/// releasing the serial — and the bounded loop retries against the NEW
/// current revision.
pub async fn issue_certificate_core(
    state: &AppState,
    actor: &Actor,
    body: &IssueCertificateBody,
    cert_id: Uuid,
    audit_id: Uuid,
    mut expected_revision: Option<Uuid>,
) -> Result<IssuedCertificateResponse, ApiError> {
    let generating = body.csr_pem.is_none();
    let required = if generating {
        Capability::GenerateLeafKey
    } else {
        Capability::Issue
    };
    actor.require(required).map_err(ApiError::from)?;

    for _ in 0..MAX_ISSUE_ATTEMPTS {
        match issue_attempt(state, actor, body, cert_id, audit_id, expected_revision).await? {
            Some(response) => return Ok(response),
            // The revision moved: retry against the FRESH current revision
            // (the stale pin is dropped — re-pinning it would read the
            // same moved pointer forever).
            None => expected_revision = None,
        }
    }
    Err(ApiError::Conflict(
        "the profile revision kept moving; issuance retries were exhausted".to_string(),
    ))
}

/// One issuance attempt against the (possibly pinned) revision: the
/// direct path's pre-transaction steps — profile + revision read (via
/// the pool: the CAPABILITY-checked actor gates the tenant filter), name
/// validation, CA choice — then the transaction opened over the pool and
/// the shared [`issue_in_tx`] core, and the commit. Returns `Ok(None)`
/// when the revision moved under us (the caller retries against the
/// fresh current revision).
async fn issue_attempt(
    state: &AppState,
    actor: &Actor,
    body: &IssueCertificateBody,
    cert_id: Uuid,
    audit_id: Uuid,
    expected_revision: Option<Uuid>,
) -> Result<Option<IssuedCertificateResponse>, ApiError> {
    // The profile must exist in this tenant (another tenant's profile is
    // a 404 — never distinguishable from missing).
    let profile = ProfileRepo::new()
        .get_profile(&state.pool, body.profile_id)
        .await?
        .filter(|profile| profile.tenant_id == actor.tenant_id)
        .ok_or_else(|| ApiError::NotFound("profile not found".to_string()))?;

    // The revision to validate against: the caller's pinned one, or the
    // profile's current pointer.
    let revision = match expected_revision {
        Some(id) => ProfileRepo::new()
            .get_revision(&state.pool, id)
            .await?
            .filter(|revision| revision.profile_id == profile.id)
            .ok_or_else(|| ApiError::NotFound("profile revision not found".to_string()))?,
        None => ProfileRepo::new()
            .current_revision(&state.pool, profile.id)
            .await?
            .ok_or_else(|| {
                ApiError::NotFound(format!(
                    "profile {:?} has no current revision",
                    profile.name
                ))
            })?,
    };

    validate_names(&revision, actor, body)?;

    // The CA issues from the tenant's root (setup creates exactly one);
    // a tenant with no CA at all is a 404 — there is nothing to issue
    // from yet.
    let ca = choose_ca(&state.pool, actor.tenant_id).await?;

    // The transaction: the shared issuance core below, committed once
    // (the write-side contract). The keystore opens through the state's
    // custody — legacy file mode on a plaintext volume, the unlocked
    // RAM custody on a sealed instance.
    let keystore = state.keystore()?;
    let mut tx = state.pool.begin().await?;
    let Some(response) = issue_in_tx(
        &mut tx, keystore, &profile, &ca, &revision, body, actor, cert_id, audit_id,
    )
    .await?
    else {
        // The revision moved: the transaction rolls back (dropped below),
        // releasing nothing — the serial was never allocated.
        return Ok(None);
    };
    tx.commit().await?;

    Ok(Some(response))
}

/// The issuance core shared by BOTH paths — the direct `POST
/// /certificates` flow and the one-shot pull — called on the caller's
/// already-open transaction. The caller has finished its own pre-steps
/// (the direct path's capability check, profile/revision read and CA
/// choice; the pull path's `claim_one_shot` ON THE SAME TRANSACTION plus
/// its in-transaction profile re-read, so the CLAIMED actor's tenant
/// gates the read) and hands over the transaction the issuance must be
/// written on.
///
/// One shared piece because these steps stand or fall together on ONE
/// transaction:
///
/// 1. the CA remaining-life pre-check — the API's refusal is the one the
///    operator sees, and it names the profile's lifetime and the CA's
///    expiry (the engine refuses too, Task 7);
/// 2. the optimistic-concurrency re-affirmation (Task 5's conditional
///    write): repoint the profile to ITS OWN current revision — a no-op
///    write unless the pointer moved — so a concurrent profile edit
///    between the caller's read and this commit collapses to zero rows;
/// 3. Task 8's transactional serial allocation, so a rollback RELEASES
///    the serial instead of burning it;
/// 4. the CPU-bound signing leg inside `spawn_blocking` (the keystore is
///    opened inside the task; the transaction stays open meanwhile — a
///    slow signing merely extends it);
/// 5. the certificate insert and the audit record, committed together
///    (the write-side contract): `cert_issued` details carry the profile,
///    revision, serial and sans, with `minted_by` (the minting user's id)
///    present only when the actor carries it (the one-shot actor); the
///    key-generation path records `key_generated` instead, never the key.
///
/// The executor is `&mut sqlx::PgConnection`, not a generic
/// `impl PgExecutor<'_>`: the core runs SEVERAL statements on it, and an
/// `impl PgExecutor` parameter is consumed by the first query. `&mut
/// PgConnection` is also the one executor both callers can rebind a
/// transaction to (each passes `&mut *tx`, following the house repos' own
/// convention — `&mut Transaction` does not implement `PgExecutor` in
/// sqlx 0.8.6).
///
/// Returns `Ok(None)` when the conditional write reports a moved
/// revision: the caller's transaction drops (rollback — on the pull path
/// that also un-claims the one-shot, whose claim lives in THAT
/// transaction) and the caller's bounded retry loop re-reads the fresh
/// current revision.
#[allow(clippy::too_many_arguments)]
async fn issue_in_tx(
    exec: &mut sqlx::PgConnection,
    keystore: KeyStore,
    profile: &ProfileModel,
    ca: &CaModel,
    revision: &ProfileRevisionModel,
    body: &IssueCertificateBody,
    actor: &Actor,
    cert_id: Uuid,
    audit_id: Uuid,
) -> Result<Option<IssuedCertificateResponse>, ApiError> {
    // The issuance path pre-checks the CA's remaining life and refuses —
    // it never silently issues a shortened certificate. The engine
    // refuses too (Task 7), but the API's refusal is the one the operator
    // sees, and it names both the profile's lifetime and the CA's expiry.
    let lifetime = Duration::days(i64::from(revision.lifetime_days));
    if lifetime.num_seconds() <= 0 {
        return Err(ApiError::Internal(format!(
            "profile {:?} pins a non-positive lifetime",
            profile.name
        )));
    }
    if Utc::now() + lifetime > ca.not_after {
        return Err(ApiError::BadRequest {
            code: "ca_lifetime_exceeded",
            message: format!(
                "the profile's {}-day lifetime would run past the issuing CA certificate's \
                 expiry ({}); shorten the profile's lifetime or renew the CA",
                revision.lifetime_days,
                ca.not_after.to_rfc3339()
            ),
        });
    }

    let generating = body.csr_pem.is_none();

    // The conditional write (Task 5's `ProfileRepo::update`) is the
    // optimistic-concurrency point: repoint the profile to ITS OWN
    // current revision — a no-op write unless the pointer moved — so a
    // concurrent profile edit between our read and this commit collapses
    // to zero rows, and the issuance retries against the new revision
    // instead of recording a stale one. (The serial is not allocated
    // until after the CAS, so `None` releases nothing.)
    if let Err(e) = ProfileRepo::new()
        .update(&mut *exec, profile.id, Some(revision.id), revision.id)
        .await
    {
        // Only the revision-moved shape retries: the conditional write's
        // collapse to zero rows surfaces as `CoreError::Config` — the
        // exact case `update_profile` maps to its retry-able Conflict.
        // The caller's tx drops (rollback) and the loop re-reads the
        // fresh revision.
        if let ws_core::error::CoreError::Config(_) = e {
            return Ok(None);
        }
        // Any OTHER failure is a genuine database error: surface it
        // through the CoreError→ApiError mapping instead of masquerading
        // as a revision move and burning the retry budget on a 409.
        return Err(ApiError::from(e));
    }

    // Task 8's transactional serial allocation: the serial the certificate
    // will carry, allocated inside the issuance transaction, so a
    // rollback RELEASES the serial instead of burning it.
    let serial = allocate_serial(ca.id, ca.tenant_id, &mut *exec)
        .await
        .map_err(ApiError::from)?;

    // Signing is synchronous and CPU-bound (RSA key generation on the
    // key-generation path), so it runs inside `tokio::task::spawn_blocking`
    // — a slow keygen must not stall the runtime's worker threads. The
    // keystore custody moves into the task; the transaction stays open
    // meanwhile (a slow signing merely extends the transaction).
    let signed = spawn_signing(
        keystore,
        ca,
        revision,
        body.subject_cn.trim(),
        &body.sans,
        body.csr_pem.clone(),
        serial,
    )
    .await?;

    let cert = certificate_model(
        cert_id,
        ca,
        &profile.name,
        revision,
        body,
        &signed.issued,
        serial,
        // The certificate's recorded source follows the ACTOR that issued
        // it: the ACME account (Plan 4's finalize path) writes `acme`; the
        // bearer/session/one-shot actors write `manual` (the pull's minted
        // actor is a service identity, not an ACME account). Task 9/10's
        // UI links a certificate detail to its order off this value.
        if actor.actor_type == ActorType::AcmeAccount {
            "acme"
        } else {
            "manual"
        },
    );

    CertificateRepo::new().insert(&mut *exec, &cert).await?;

    // The audit entry commits WITH the certificate (the write-side
    // contract). The action vocabulary: `cert_issued` on the CSR path,
    // `key_generated` on the key-generation path — the details carry ids
    // and labels, never the key.
    let action = if generating {
        "key_generated"
    } else {
        "cert_issued"
    };
    let details = if generating {
        serde_json::json!({
            "profile_id": body.profile_id.to_string(),
            "key_type": revision.key_type,
        })
    } else {
        // cert_issued: profile + revision + serial + sans. `minted_by` is
        // how the human who minted a one-shot token is attributed; it is
        // present only when the actor carries it (the one-shot actor).
        let mut details = serde_json::json!({
            "profile_id": body.profile_id.to_string(),
            "profile_revision_id": revision.id.to_string(),
            "serial": serial.to_string(),
            "sans": body.sans,
        });
        if let Some(minted_by) = &actor.minted_by {
            details["minted_by"] = serde_json::json!(minted_by);
        }
        details
    };
    AuditRepo::new()
        .record(
            &mut *exec,
            &audit_entry_with_id(
                audit_id,
                actor,
                action,
                "certificate",
                &cert_id.to_string(),
                details,
            ),
        )
        .await?;

    Ok(Some(IssuedCertificateResponse {
        certificate_id: cert_id,
        cert_pem: signed.issued.cert_pem,
        serial: serial.to_string(),
        serial_hex: format!("{serial:x}"),
        profile_revision_id: revision.id,
        profile_name: profile.name.clone(),
        not_before: signed.issued.not_before,
        not_after: signed.issued.not_after,
        private_key_pem: signed.private_key_pem,
    }))
}

/// The CPU-bound signing leg, run inside `spawn_blocking`: load the
/// CA's key through the caller's keystore custody, and — when no CSR
/// was supplied — mint a fresh leaf key of the profile's pinned type
/// and wrap it in a CSR. The private-key PEM is present ONLY on the
/// key-generation path.
struct SignOutcome {
    issued: IssuedLeaf,
    private_key_pem: Option<String>,
}

/// Spawn the blocking signing leg and map its typed failure to `ApiError`.
async fn spawn_signing(
    keystore: KeyStore,
    ca: &CaModel,
    revision: &ProfileRevisionModel,
    subject_cn: &str,
    sans: &[String],
    csr_pem: Option<String>,
    serial: u128,
) -> Result<SignOutcome, ApiError> {
    let ca = ca.clone();
    let revision = revision.clone();
    let subject_cn = subject_cn.to_string();
    let sans = sans.to_vec();
    tokio::task::spawn_blocking(move || {
        let ca_key_der = keystore.load_ca_key(&ca.id).map_err(ApiError::from)?;

        let (csr_pem, private_key_pem) = match csr_pem {
            Some(csr_pem) => (csr_pem, None),
            None => {
                // The key-generation path: mint a fresh key of the
                // profile's pinned type and build the CSR the signing leg
                // consumes. The profile pins the exact key type — the
                // generated key is the pinned size by construction.
                let key_type = leaf_key_type(revision.key_type.as_str())?;
                let (key_pair, _der) = generate_leaf_key(key_type).map_err(ApiError::from)?;
                let pem = key_pair.serialize_pem();
                let csr = build_generated_csr(&key_pair, &subject_cn, &sans)?;
                (csr, Some(pem))
            }
        };

        let spec = leaf_spec(&revision, &subject_cn, &sans, serial)?;
        let issued =
            sign_leaf_with(&ca.cert_pem, &ca_key_der, &csr_pem, &spec).map_err(ApiError::from)?;
        Ok::<_, ApiError>(SignOutcome {
            issued,
            private_key_pem,
        })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("the signing task failed: {e}")))?
}

/// The profile's pinned leaf key type; an unknown stored value is data-
/// level damage (the profile revision's `key_type` column) — 500.
fn leaf_key_type(stored: &str) -> Result<LeafKeyType, ApiError> {
    LeafKeyType::from_str(stored).ok_or_else(|| {
        ApiError::Internal(format!("profile pins an unusable leaf key type {stored:?}"))
    })
}

/// Build the CSR for a server-generated leaf key: the requested subject CN
/// and SANs, self-signed with the generated key. The signing leg verifies
/// that self-signature, exactly like the CSR path's proof of possession.
fn build_generated_csr(
    key_pair: &rcgen::KeyPair,
    subject_cn: &str,
    sans: &[String],
) -> Result<String, ApiError> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, subject_cn);
    params.distinguished_name = dn;
    params.subject_alt_names = sans
        .iter()
        .map(|san| match san.parse::<IpAddr>() {
            Ok(ip) => Ok(SanType::IpAddress(ip)),
            Err(_) => Ok(SanType::DnsName(san.as_str().try_into()?)),
        })
        .collect::<Result<Vec<_>, rcgen::Error>>()
        .map_err(ws_ca::error::CaError::from)
        .map_err(ApiError::from)?;
    let csr = params
        .serialize_request(key_pair)
        .map_err(ws_ca::error::CaError::from)
        .map_err(ApiError::from)?;
    csr.pem()
        .map_err(ws_ca::error::CaError::from)
        .map_err(ApiError::from)
}

/// The leaf spec from the pinned revision: SANs from the request (the
/// names were validated), key usages and EKUs from the revision (an
/// unknown stored spelling is data damage — 500), the profile's lifetime
/// SPAN, the subject override, and the allocated serial.
fn leaf_spec(
    revision: &ProfileRevisionModel,
    subject_cn: &str,
    sans: &[String],
    serial: u128,
) -> Result<LeafSpec, ApiError> {
    let key_usages: Vec<_> = revision
        .key_usages
        .iter()
        .map(|usage| {
            KeyUsagePurpose::from_str(usage).ok_or_else(|| {
                ApiError::Internal(format!("profile pins an unknown key usage {usage:?}"))
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let ekus: Vec<_> = revision
        .eku
        .iter()
        .map(|eku| {
            ExtKeyUsagePurpose::from_str(eku)
                .ok_or_else(|| ApiError::Internal(format!("profile pins an unknown EKU {eku:?}")))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;

    Ok(LeafSpec {
        sans: sans
            .iter()
            .map(|name| match name.parse::<IpAddr>() {
                Ok(ip) => SanEntry::Ip(ip),
                Err(_) => SanEntry::Dns(name.clone()),
            })
            .collect(),
        key_usages,
        ekus,
        key_type: leaf_key_type(revision.key_type.as_str())?,
        lifetime: Duration::days(i64::from(revision.lifetime_days)),
        subject_cn: Some(subject_cn.to_string()),
        serial,
    })
}

/// The `certificates` row the issuance writes, from the engine's output.
/// The row's tenant is the CA's (the CA was chosen within the actor's
/// tenant), so no separate tenant argument is needed. `source` is the
/// issuing surface's label (`manual` for the API routes, `acme` for the
/// ACME finalize path — chosen by the ACTOR's type at the call site).
#[allow(clippy::too_many_arguments)]
fn certificate_model(
    id: Uuid,
    ca: &CaModel,
    profile_name: &str,
    revision: &ProfileRevisionModel,
    body: &IssueCertificateBody,
    issued: &IssuedLeaf,
    serial: u128,
    source: &str,
) -> CertificateModel {
    let san_dns: Vec<String> = body
        .sans
        .iter()
        .filter(|san| san.parse::<IpAddr>().is_err())
        .cloned()
        .collect();
    let san_ips: Vec<IpAddr> = body
        .sans
        .iter()
        .filter_map(|san| san.parse::<IpAddr>().ok())
        .collect();
    CertificateModel {
        id,
        tenant_id: ca.tenant_id,
        ca_id: ca.id,
        profile_revision_id: Some(revision.id),
        profile_name: profile_name.to_string(),
        subject: format!("CN={}", body.subject_cn.trim()),
        serial,
        serial_hex: format!("{serial:x}"),
        san_dns,
        san_ips,
        key_type: revision.key_type.clone(),
        not_before: issued.not_before,
        not_after: issued.not_after,
        cert_pem: issued.cert_pem.clone(),
        status: CertStatus::Active,
        revoked_at: None,
        revocation_reason: None,
        revocation_detail: None,
        source: source.to_string(),
        created_at: Utc::now(),
    }
}

/// Name validation against the pinned revision: the subject CN and EVERY
/// proposed SAN must be permitted (the subject is a permitted name too),
/// and the SAN list must be non-empty. An actor holding `ReadProfiles`
/// gets the specific message naming the failing constraint; anyone else
/// gets the generic "not permitted by policy" — and NO actor ever learns
/// the permitted set.
fn validate_names(
    revision: &ProfileRevisionModel,
    actor: &Actor,
    body: &IssueCertificateBody,
) -> Result<(), ApiError> {
    let subject_cn = body.subject_cn.trim();
    if subject_cn.is_empty() {
        return Err(ApiError::bad_request("subject_cn must not be blank"));
    }
    if body.sans.is_empty() {
        return Err(ApiError::bad_request(
            "at least one subject alternative name is required: proposing no names is a \
             different artifact, not a subset of the profile",
        ));
    }

    let specific = actor.can(Capability::ReadProfiles);
    for name in std::iter::once(subject_cn).chain(body.sans.iter().map(String::as_str)) {
        if name.trim().is_empty() {
            return Err(ApiError::bad_request(
                "subject alternative names must not be blank",
            ));
        }
        match san_is_permitted(&revision.san_patterns, name) {
            Ok(true) => {}
            Ok(false) => {
                let message = if specific {
                    // Specific for actors who may read the profile: it
                    // names the failing constraint and NEVER the set.
                    format!("name {name:?} is not permitted by this profile")
                } else {
                    // Generic for everyone else: a service identity can be
                    // granted `issue` WITHOUT `read_profiles` (a token's
                    // capabilities are chosen explicitly at creation and
                    // can be a narrow subset), and that actor must not
                    // learn the profile's contents.
                    "not permitted by policy".to_string()
                };
                return Err(ApiError::not_permitted_by_profile(message));
            }
            // A broken stored pattern is data-level damage: 500.
            Err(CoreError::Config(_)) => {
                return Err(ApiError::Internal(
                    "the profile's san patterns are corrupt".to_string(),
                ));
            }
            Err(e) => return Err(ApiError::from(e)),
        }
    }
    Ok(())
}

/// The tenant's issuing CA: its first root certificate authority (setup
/// creates exactly one), else its first CA. `None` is a 404 — nothing to
/// issue from yet.
async fn choose_ca(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<CaModel, ApiError> {
    let cas = CaRepo::new().list_by_tenant(pool, tenant_id).await?;
    let chosen = cas.iter().find(|ca| ca.is_root).or_else(|| cas.first());
    chosen.cloned().ok_or_else(|| {
        ApiError::NotFound("no certificate authority is available to issue from".to_string())
    })
}

/// `POST /api/v1/certificates/pull` — the token-gated one-shot pull.
///
/// Gated by a one-shot token in the Authorization header (an API token or
/// session JWT is NOT accepted — the route exists for the operator pull
/// flow). The token is CLAIMED inside the SAME transaction as the
/// certificate insert (Task 9's `claim_one_shot` — never the lookup-only
/// `consume_one_shot`), so a successfully claimed token either yields a
/// certificate or, rolled back, stays claimable.
async fn issue_certificate_one_shot(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<PullCertificateBody>,
) -> Result<Json<IssuedCertificateResponse>, ApiError> {
    // The pull route accepts ONLY one-shot tokens: any other credential
    // shape is 401 — a malformed one-shot is 401 without burning anything,
    // because the claim happens inside the issuance transaction.
    let token = bearer_token(&headers)
        .ok_or_else(|| ApiError::Unauthorized("missing Authorization bearer token".to_string()))?;
    if !token.starts_with(ws_auth::one_shot::TOKEN_PREFIX) {
        return Err(ApiError::Unauthorized(
            "the pull route is gated by a one-shot token (ws_ot_)".to_string(),
        ));
    }

    let response = pull_certificate(&state, token, &body, Uuid::new_v4(), Uuid::new_v4()).await?;
    Ok(Json(response))
}

/// The `Bearer <token>` value of the pull request's Authorization header.
fn bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
}

/// The pull body: everything on the CSR path — the client keeps the key
/// and presents its CSR.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PullCertificateBody {
    pub profile_id: Uuid,
    pub subject_cn: String,
    #[serde(default)]
    pub sans: Vec<String>,
    pub csr_pem: String,
}

/// The pull flow: one transaction per attempt — claim → profile/revision
/// read (inside the transaction, against the CLAIMED actor) → validation
/// → CA choice → the shared [`issue_in_tx`] core — with the same bounded
/// retry on a moved revision (any rollback un-claims the token: the claim
/// lives in THAT transaction).
pub async fn pull_certificate(
    state: &AppState,
    token: &str,
    body: &PullCertificateBody,
    cert_id: Uuid,
    audit_id: Uuid,
) -> Result<IssuedCertificateResponse, ApiError> {
    let issued = IssueCertificateBody {
        profile_id: body.profile_id,
        subject_cn: body.subject_cn.clone(),
        sans: body.sans.clone(),
        csr_pem: Some(body.csr_pem.clone()),
    };

    for _ in 0..MAX_ISSUE_ATTEMPTS {
        let mut tx = state.pool.begin().await?;

        // Task 9's atomic consume, inside the SAME transaction as the
        // certificate insert. A `None` claim is 401 — used, expired, or
        // unknown alike — and this is the ONLY place a presented one-shot
        // is claimed (the middleware's path is lookup-only).
        let actor = ws_auth::one_shot::claim_one_shot(token, &mut *tx, &CredentialRepo::new())
            .await
            .map_err(ApiError::from)?
            .ok_or_else(|| {
                ApiError::Unauthorized("one-shot token is unknown, used, or expired".to_string())
            })?;

        // The profile/revision re-read INSIDE the claim transaction: the
        // CLAIMED actor gates the tenant filter, and validation runs
        // against it too — the one-shot actor carries exactly the fixed
        // `Issue` grant (no `ReadProfiles`), so its naming errors are
        // generic: it must not learn the profile's contents.
        let profile = ProfileRepo::new()
            .get_profile(&mut *tx, body.profile_id)
            .await?
            .filter(|profile| profile.tenant_id == actor.tenant_id)
            .ok_or_else(|| ApiError::NotFound("profile not found".to_string()))?;
        let revision = ProfileRepo::new()
            .current_revision(&mut *tx, profile.id)
            .await?
            .ok_or_else(|| {
                ApiError::NotFound(format!(
                    "profile {:?} has no current revision",
                    profile.name
                ))
            })?;

        validate_names(&revision, &actor, &issued)?;

        let ca = choose_ca(&state.pool, actor.tenant_id).await?;

        // The shared issuance core on the claim-and-certificate
        // transaction: the CAS collapsing to zero rows — or any later
        // failure — rolls the transaction back, and the token claimed IN
        // it stays claimable. The keystore opens through the state's
        // custody before the transaction begins.
        let keystore = state.keystore()?;
        let Some(response) = issue_in_tx(
            &mut tx, keystore, &profile, &ca, &revision, &issued, &actor, cert_id, audit_id,
        )
        .await?
        else {
            continue; // tx drops → rollback → un-claim
        };
        tx.commit().await?;

        return Ok(response);
    }
    Err(ApiError::Conflict(
        "the profile revision kept moving; pull retries were exhausted".to_string(),
    ))
}

/// The `GET /api/v1/certificates` query: the shared paging fields plus the
/// filter keys, all optional. `status` parses through `CertStatus`; `ca`
/// must deserialize as a UUID.
#[derive(Debug, Deserialize, Default)]
pub struct CertificateListQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub status: Option<String>,
    /// The profile NAME filter (the display label).
    pub profile: Option<String>,
    /// The issuing CA id filter.
    #[serde(default)]
    pub ca: Option<Uuid>,
    /// Substring search across subject | serial_hex | certificate SANs.
    #[serde(default)]
    pub q: Option<String>,
}

impl CertificateListQuery {
    /// The defaults are the shared [`ListQuery`] ones: page 0, page size
    /// 100 (clamped repo-side at 500 by `ws_core::repo::paging`).
    pub fn page(&self) -> u32 {
        self.page.unwrap_or(0)
    }

    pub fn page_size(&self) -> u32 {
        self.page_size.unwrap_or(100)
    }
}

/// `GET /api/v1/certificates` — one page, `read_certificates`, through the
/// composed [`CertificateFilter`] (a filter axis applies only when its
/// query parameter is present). An unparseable `status` is a 400 — it never
/// silently degenerates to "no filter".
async fn list_certificates(
    auth: AuthActor,
    State(state): State<AppState>,
    Query(query): Query<CertificateListQuery>,
) -> Result<Json<Vec<CertificateResponse>>, ApiError> {
    auth.require(Capability::ReadCertificates)
        .map_err(ApiError::from)?;
    let status = match query.status.as_deref() {
        Some(raw) => Some(
            raw.parse::<CertStatus>()
                .map_err(|_| ApiError::bad_request("invalid status value"))?,
        ),
        None => None,
    };
    // The paging values are read BEFORE the filter consumes the query's
    // fields (a partial move would borrow back the struct after it).
    let (page, page_size) = (query.page(), query.page_size());
    let filter = CertificateFilter {
        status,
        profile_name: query.profile,
        ca_id: query.ca,
        search: query.q,
    };
    let certs = CertificateRepo::new()
        .list_filtered(&state.pool, auth.tenant_id, &filter, page, page_size)
        .await?
        .iter()
        .map(CertificateResponse::from_model)
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(certs))
}

/// `GET /api/v1/certificates/slim` query: the sieve's axes — `page`,
/// `page_size` (the shared paging; the dashboard pins 500, the repo clamp),
/// and `status`.
#[derive(Debug, Deserialize, Default)]
pub struct SlimListQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub status: Option<String>,
}

/// One slim certificate, as the dashboard sieve consumes it: the five
/// small fields, none of the full-row bulk (no PEM, no SANs).
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SlimCertificateResponse {
    pub id: Uuid,
    pub subject: String,
    pub serial_hex: String,
    pub not_after: DateTime<Utc>,
    pub status: String,
}

/// `GET /api/v1/certificates/slim` — `read_certificates`, the same gate the
/// full list sits behind; an unparseable `status` is a 400, like there.
/// Registered BEFORE `/{id}` so `slim` is never read as a certificate id.
async fn list_certificates_slim(
    auth: AuthActor,
    State(state): State<AppState>,
    Query(query): Query<SlimListQuery>,
) -> Result<Json<Vec<SlimCertificateResponse>>, ApiError> {
    auth.require(Capability::ReadCertificates)
        .map_err(ApiError::from)?;
    let status = match query.status.as_deref() {
        Some(raw) => Some(
            raw.parse::<CertStatus>()
                .map_err(|_| ApiError::bad_request("invalid status value"))?,
        ),
        None => None,
    };
    let rows = CertificateRepo::new()
        .list_slim(
            &state.pool,
            auth.tenant_id,
            status,
            query.page.unwrap_or(0),
            query.page_size.unwrap_or(100),
        )
        .await?
        .into_iter()
        .map(|row| SlimCertificateResponse {
            id: row.id,
            subject: row.subject,
            serial_hex: row.serial_hex,
            not_after: row.not_after,
            status: row.status.as_str().to_string(),
        })
        .collect();
    Ok(Json(rows))
}

/// `GET /api/v1/certificates/statistics` — the estate's headline counts,
/// `read_certificates`. The 30-day expiry horizon is pinned HERE (the repo
/// method stays pure): "expiring soon" means an ACTIVE certificate whose
/// `not_after` falls before now + 30 days.
async fn certificate_statistics(
    auth: AuthActor,
    State(state): State<AppState>,
) -> Result<Json<CertificateStatistics>, ApiError> {
    auth.require(Capability::ReadCertificates)
        .map_err(ApiError::from)?;
    let expiring_before = Utc::now() + Duration::days(30);
    let statistics = CertificateRepo::new()
        .statistics(&state.pool, auth.tenant_id, expiring_before)
        .await?;
    Ok(Json(statistics))
}

/// `GET /api/v1/certificates/{id}` — one certificate, `read_certificates`.
/// Another tenant's certificate is a 404.
async fn get_certificate(
    auth: AuthActor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<CertificateResponse>, ApiError> {
    auth.require(Capability::ReadCertificates)
        .map_err(ApiError::from)?;
    let cert = CertificateRepo::new()
        .get(&state.pool, id)
        .await?
        .filter(|cert| cert.tenant_id == auth.tenant_id)
        .ok_or_else(|| ApiError::NotFound("certificate not found".to_string()))?;
    Ok(Json(CertificateResponse::from_model(&cert)?))
}

/// The certificate read DTO (no key fields exist — the certificate PEM is
/// public certificate content, and a private key was never stored).
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CertificateResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub ca_id: Uuid,
    pub profile_revision_id: Option<Uuid>,
    pub profile_name: String,
    pub subject: String,
    pub serial_hex: String,
    pub san_dns: Vec<String>,
    pub san_ips: Vec<String>,
    pub key_type: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub cert_pem: String,
    pub status: String,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
    pub revocation_detail: Option<String>,
    pub source: String,
    pub created_at: DateTime<Utc>,
}

impl CertificateResponse {
    fn from_model(cert: &CertificateModel) -> Result<Self, ApiError> {
        // `status` arrives typed (the repo decodes it); an unknown stored
        // spelling never reaches this DTO.
        let status = cert.status.as_str().to_string();
        Ok(CertificateResponse {
            id: cert.id,
            tenant_id: cert.tenant_id,
            ca_id: cert.ca_id,
            profile_revision_id: cert.profile_revision_id,
            profile_name: cert.profile_name.clone(),
            subject: cert.subject.clone(),
            serial_hex: cert.serial_hex.clone(),
            san_dns: cert.san_dns.clone(),
            san_ips: cert.san_ips.iter().map(|ip| ip.to_string()).collect(),
            key_type: cert.key_type.clone(),
            not_before: cert.not_before,
            not_after: cert.not_after,
            cert_pem: cert.cert_pem.clone(),
            status,
            revoked_at: cert.revoked_at,
            revocation_reason: cert.revocation_reason.clone(),
            revocation_detail: cert.revocation_detail.clone(),
            source: cert.source.clone(),
            created_at: cert.created_at,
        })
    }
}

/// `POST /api/v1/certificates/{id}/revoke` — idempotent; writes ONE
/// `cert_revoked` audit row, in the same transaction as the revocation.
/// Revoking an already-revoked certificate is a no-op (no second audit
/// row; the response echoes the FIRST revoke's stored pair), and
/// revoking another tenant's certificate is a 404.
///
/// The reason is a TYPED [`RevocationReason`] — one of the nine RFC 5280
/// names whose exact spellings ws-worker's CRL/OCSP builders parse into
/// reason extensions. A missing or unknown name (a serde rejection on
/// the body) is the client's error: 400 `bad_request`, never axum's
/// default 422, whose body shape the SPA's error handling cannot read —
/// as is a detail over 2000 characters.
async fn revoke_certificate(
    auth: AuthActor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    body: Result<Json<RevokeBody>, JsonRejection>,
) -> Result<Json<RevokeResponse>, ApiError> {
    let Json(body) = body.map_err(|rejection| ApiError::BadRequest {
        code: "bad_request",
        message: rejection.body_text(),
    })?;
    auth.require(Capability::Issue).map_err(ApiError::from)?;

    // The detail is optional free text, stored verbatim; a longer one is
    // refused, never silently truncated.
    if let Some(detail) = &body.detail {
        if detail.chars().count() > 2000 {
            return Err(ApiError::bad_request(
                "the revocation detail must not exceed 2000 characters",
            ));
        }
    }

    let cert = CertificateRepo::new()
        .get(&state.pool, id)
        .await?
        .filter(|cert| cert.tenant_id == auth.tenant_id)
        .ok_or_else(|| ApiError::NotFound("certificate not found".to_string()))?;

    // Idempotency: an already-revoked certificate changes nothing and
    // writes no second audit row.
    if cert.status == CertStatus::Revoked {
        return Ok(Json(RevokeResponse {
            id,
            status: cert.status.as_str().to_string(),
            detail: cert.revocation_detail.clone(),
        }));
    }

    // The audit carries the typed reason NAME (the same string the worker
    // parses) and the detail key only when one was supplied.
    let mut details = serde_json::json!({ "reason": body.reason.as_str() });
    if let Some(detail) = &body.detail {
        details["detail"] = serde_json::json!(detail);
    }

    let mut tx = state.pool.begin().await?;
    CertificateRepo::new()
        .revoke(&mut *tx, id, body.reason.as_str(), body.detail.as_deref())
        .await?;
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &auth.0,
                "cert_revoked",
                "certificate",
                &id.to_string(),
                details,
            ),
        )
        .await?;
    tx.commit().await?;

    Ok(Json(RevokeResponse {
        id,
        status: "revoked".to_string(),
        detail: body.detail,
    }))
}

/// The revoke body: a typed reason (one of the nine RFC 5280 section
/// 5.3.1 names — the exact strings ws-worker's `reason_from_str` maps
/// into CRL/OCSP reason extensions) and an optional free-text detail
/// (≤ 2000 characters, stored verbatim in `certificates.revocation_detail`).
///
/// This REPLACES the old free-text `reason: String` body (a breaking
/// change to the Plan 2 API shape): a free-text reason had no CRL/OCSP
/// mapping worker-side, so revoking with one silently dropped the
/// published reason extension. The only consumers are this repo's
/// UI/e2e, updated in the same change.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RevokeBody {
    pub reason: RevocationReason,
    #[serde(default)]
    pub detail: Option<String>,
}

/// The revoke response: the certificate id, its status, and the stored
/// revocation detail echoed — the request's detail on the first revoke,
/// the FIRST revoke's stored value on an already-revoked no-op (the
/// round-trip contract the UI shows).
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RevokeResponse {
    pub id: Uuid,
    pub status: String,
    pub detail: Option<String>,
}

/// `GET /api/v1/certificates/{id}/chain` — `read_certificates`. The trust
/// chain the certificate verifies against, leaf-first: the certificate's
/// own PEM FIRST, then its issuing CA's chain up to the root, as one
/// concatenated PEM body (`application/x-pem-file`, the root-trust
/// route's idiom). Another tenant's certificate is a 404, and the chain
/// walk starts only from the tenant-checked certificate's own `ca_id`.
async fn get_certificate_chain(
    auth: AuthActor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    auth.require(Capability::ReadCertificates)
        .map_err(ApiError::from)?;
    let cert = CertificateRepo::new()
        .get(&state.pool, id)
        .await?
        .filter(|cert| cert.tenant_id == auth.tenant_id)
        .ok_or_else(|| ApiError::NotFound("certificate not found".to_string()))?;
    let chain = {
        // One pooled connection serves the multi-statement walk (the
        // repos' executor convention: several statements need a `&mut
        // PgConnection`); the walk re-checks the verified tenant per hop.
        let mut conn = state.pool.acquire().await?;
        CaRepo::new()
            .chain_to_root(&mut conn, auth.tenant_id, cert.ca_id)
            .await?
    };
    let mut body = cert.cert_pem.clone();
    body.extend(chain.iter().map(|ca| ca.cert_pem.as_str()));
    Ok(([(header::CONTENT_TYPE, "application/x-pem-file")], body).into_response())
}
