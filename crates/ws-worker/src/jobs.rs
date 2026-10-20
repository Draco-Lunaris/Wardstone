//! The worker's jobs.
//!
//! [`regen_crl_and_ocsp`] is the revocation-publishing job: for every CA
//! whose revocation list has grown since its latest CRL, it rebuilds the
//! CRL and publishes one OCSP response per revoked certificate. The
//! scheduler in [`crate::run_scheduler`] runs it on a fixed interval.

use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;
use ws_ca::ca::KeyType;
use ws_ca::crl::{build_crl, CrlReason, CrlSpec, RevocationEntry};
use ws_ca::keystore::KeyStore;
use ws_ca::ocsp::{build_ocsp_response, OcspResponseSpec, OcspStatus};
use ws_core::models::audit::{ActorType, AuditEntry};
use ws_core::models::ca::CaModel;
use ws_core::models::ocsp::OcspResponseModel;
use ws_core::repo::audit_repo::AuditRepo;
use ws_core::repo::certificate_repo::CertificateRepo;
use ws_core::repo::ocsp_repo::OcspRepo;

use crate::error::WorkerError;

/// How long a published CRL stays valid, and how long a published OCSP
/// response stays valid: 24 hours. A CRL's `nextUpdate` is the instant
/// after which relying parties must fetch a fresh one, and an OCSP
/// response's `nextUpdate` is the instant after which the answer is
/// stale; both are published with the same 24h horizon.
const VALIDITY: Duration = Duration::hours(24);

/// The audit action recorded for every rebuilt CRL.
const AUDIT_ACTION_CRL_BUILT: &str = "crl_built";

/// The audit actor id of the worker itself.
const AUDIT_ACTOR_ID: &str = "worker";

/// Rebuild the CRL and OCSP responses of every CA that has revocations
/// newer than its latest CRL, and return the number of CAs regenerated.
///
/// The trigger is "the revocation list grew": a CA whose latest CRL
/// already covers every revocation is left alone. The *content* of the
/// rebuilt CRL, however, is every certificate currently revoked for that
/// CA — not only the newly revoked ones. A CRL that listed only the
/// delta would drop the older revocations from the CA's latest CRL, so a
/// relying party fetching it would no longer see them: the published
/// CRL must always be the complete revocation list.
///
/// For each regenerated CA the job
///
/// 1. builds the CRL with `ws_ca::crl::build_crl` (24h validity),
/// 2. stores it in the `crls` table,
/// 3. builds one OCSP response per revoked certificate (status
///    `revoked`, 24h validity) and stores it through [`OcspRepo`], and
/// 4. records an `crl_built` audit entry for the CA.
///
/// One failing CA never stops the others: the failure is logged (with
/// the CA id) and the job continues with the next CA, so a CA whose key
/// is missing cannot keep every other CA's revocation list unpublished.
/// The first failure is nevertheless reported to the caller, so the
/// scheduler logs the job as failed and the next tick retries.
///
/// Errors: a missing or unreadable CA key, a DER/encoding failure, and
/// database failures all surface as typed [`WorkerError`]s — never a
/// panic, and never a partially written CRL row (the CRL is built in
/// full before any row is written).
pub async fn regen_crl_and_ocsp(pool: &PgPool, keystore: &KeyStore) -> Result<u64, WorkerError> {
    let cas = list_all_cas(pool).await?;
    let certs = CertificateRepo::new(pool);
    let ocsp = OcspRepo::new(pool);
    let audit = AuditRepo::new(pool);

    let mut regenerated = 0u64;
    let mut first_failure: Option<WorkerError> = None;
    for ca in cas {
        match regen_one_ca(pool, keystore, &ca, &certs, &ocsp, &audit).await {
            Ok(()) => regenerated += 1,
            Err(err) => {
                tracing::error!(ca_id = %ca.id, error = %err, "CRL/OCSP regeneration failed for CA");
                if first_failure.is_none() {
                    first_failure = Some(err);
                }
            }
        }
    }

    match first_failure {
        Some(err) => Err(err),
        None => Ok(regenerated),
    }
}

/// Regenerate one CA's CRL and OCSP responses, if its revocation list has
/// grown since its latest CRL.
async fn regen_one_ca(
    pool: &PgPool,
    keystore: &KeyStore,
    ca: &CaModel,
    certs: &CertificateRepo,
    ocsp: &OcspRepo,
    audit: &AuditRepo,
) -> Result<(), WorkerError> {
    // The latest CRL's issue instant is the watermark: revocations newer
    // than it are not yet published. With no CRL at all the watermark is
    // the epoch, so every revocation counts.
    let latest_crl = latest_crl_issued_at(pool, ca.id).await?;
    let since = latest_crl.unwrap_or(DateTime::UNIX_EPOCH);
    let new_revocations = certs.list_revoked_since(ca.id, since).await?;
    if new_revocations.is_empty() {
        return Ok(());
    }

    // The published CRL carries the complete revocation list.
    let all_revoked = certs
        .list_revoked_since(ca.id, DateTime::UNIX_EPOCH)
        .await?;
    let revocations = all_revoked
        .iter()
        .map(|cert| RevocationEntry {
            serial: cert.serial,
            reason: cert.revocation_reason.as_deref().and_then(reason_from_str),
            revoked_at: cert.revoked_at.unwrap_or_else(Utc::now),
        })
        .collect::<Vec<_>>();

    let ca_key = keystore.load_ca_key(&ca.id)?;
    let crl = build_crl(
        &ca.cert_pem,
        ca_key.as_slice(),
        &CrlSpec {
            revocations,
            next_update: VALIDITY,
        },
    )?;

    // The CRL row is written only after the whole CRL exists.
    sqlx::query(
        "INSERT INTO crls (id, ca_id, issued_at, next_update, crl_pem) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(ca.id)
    .bind(crl.issued_at)
    .bind(crl.next_update)
    .bind(&crl.crl_pem)
    .execute(pool)
    .await?;

    // One OCSP response per revoked certificate.
    for cert in &all_revoked {
        let revoked_at = cert.revoked_at.unwrap_or_else(Utc::now);
        let response = build_ocsp_response(
            &ca.cert_pem,
            ca_key.as_slice(),
            cert.serial,
            &OcspResponseSpec {
                status: OcspStatus::Revoked,
                this_update: crl.issued_at,
                next_update: crl.next_update,
                revoked_at: Some(revoked_at),
                reason: cert.revocation_reason.as_deref().and_then(reason_from_str),
            },
        )?;
        let serial = i64::try_from(cert.serial).map_err(|_| {
            WorkerError::Config(format!(
                "certificate serial {} exceeds the bigint serial column range",
                cert.serial
            ))
        })?;
        ocsp.insert(&OcspResponseModel {
            id: Uuid::new_v4(),
            ca_id: ca.id,
            serial,
            status: OcspStatus::Revoked,
            this_update: crl.issued_at,
            next_update: crl.next_update,
            resp_der: response,
        })
        .await?;
    }

    audit
        .record(&AuditEntry {
            id: Uuid::new_v4(),
            tenant_id: ca.tenant_id,
            actor_type: ActorType::System,
            actor_id: AUDIT_ACTOR_ID.to_owned(),
            action: AUDIT_ACTION_CRL_BUILT.to_owned(),
            target_type: "ca".to_owned(),
            target_id: ca.id.to_string(),
            details: json!({
                "ca_name": ca.name,
                "revoked": all_revoked.len(),
                "next_update": crl.next_update.to_rfc3339(),
            }),
            created_at: Utc::now(),
        })
        .await?;

    Ok(())
}

/// Every CA in the database, across all tenants.
///
/// `CaRepo` only lists a tenant's CAs, and the job must cover every
/// tenant's CAs, so the query lives here rather than in the repository
/// surface (which stays pinned).
async fn list_all_cas(pool: &PgPool) -> Result<Vec<CaModel>, WorkerError> {
    #[derive(sqlx::FromRow)]
    struct CaRow {
        id: Uuid,
        tenant_id: Uuid,
        name: String,
        subject: String,
        is_root: bool,
        parent_id: Option<Uuid>,
        key_type: String,
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
        cert_pem: String,
        key_file: String,
        created_at: DateTime<Utc>,
    }

    let rows: Vec<CaRow> = sqlx::query_as(
        "SELECT id, tenant_id, name, subject, is_root, parent_id, key_type, not_before, \
         not_after, cert_pem, key_file, created_at FROM cas ORDER BY id",
    )
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            let key_type = row
                .key_type
                .parse::<KeyType>()
                .map_err(|err| WorkerError::Config(format!("invalid CA key type: {err}")))?;
            Ok(CaModel {
                id: row.id,
                tenant_id: row.tenant_id,
                name: row.name,
                subject: row.subject,
                is_root: row.is_root,
                parent_id: row.parent_id,
                key_type,
                not_before: row.not_before,
                not_after: row.not_after,
                cert_pem: row.cert_pem,
                key_file: row.key_file,
                created_at: row.created_at,
            })
        })
        .collect()
}

/// The issue instant of a CA's latest CRL, or `None` when it has none.
async fn latest_crl_issued_at(
    pool: &PgPool,
    ca_id: Uuid,
) -> Result<Option<DateTime<Utc>>, WorkerError> {
    let latest: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT max(issued_at) FROM crls WHERE ca_id = $1")
            .bind(ca_id)
            .fetch_one(pool)
            .await?;
    Ok(latest)
}

/// Map a stored revocation reason string onto the RFC 5280 reason code
/// the OCSP response and the CRL entry carry.
///
/// The stored reasons are the snake_case names of [`CrlReason`] (for
/// example `key_compromise`); a reason this build does not know (a
/// value written by a newer release) is `None` — the response then
/// carries no reason extension, which RFC 6960 allows.
fn reason_from_str(reason: &str) -> Option<CrlReason> {
    match reason {
        "unspecified" => Some(CrlReason::Unspecified),
        "key_compromise" => Some(CrlReason::KeyCompromise),
        "ca_compromise" => Some(CrlReason::CACompromise),
        "affiliation_changed" => Some(CrlReason::AffiliationChanged),
        "superseded" => Some(CrlReason::Superseded),
        "cessation_of_operation" => Some(CrlReason::CessationOfOperation),
        "certificate_hold" => Some(CrlReason::CertificateHold),
        "remove_from_crl" => Some(CrlReason::RemoveFromCRL),
        "privilege_withdrawn" => Some(CrlReason::PrivilegeWithdrawn),
        "aa_compromise" => Some(CrlReason::AaCompromise),
        _ => None,
    }
}
