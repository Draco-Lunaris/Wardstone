//! The worker's jobs.
//!
//! [`regen_crl_and_ocsp`] is the revocation-publishing job: it makes the
//! CA's published revocation state match the database's truth — it
//! republishes a CA's CRL when the published one is missing, expired, or
//! lists a different set of revoked serials than the database does, and
//! it publishes an OCSP response for every revoked certificate whose
//! stored answer is missing or stale (an answer that predates the
//! revocation, or whose validity window has lapsed). A CA with no
//! revocations still publishes an empty CRL: a relying party must be
//! able to fetch a current document.
//!
//! A CA row whose key file is not in the key store is treated as a CA
//! that is not provisioned yet: when it owes nobody a document it is
//! skipped with a warning, and when relying parties depend on a document
//! of its the missing key is reported as a failure. The scheduler in
//! [`crate::run_scheduler`] runs it on a fixed interval.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;
use ws_ca::ca::KeyType;
use ws_ca::crl::{build_crl, CrlReason, CrlSpec, RevocationEntry};
use ws_ca::error::CaError;
use ws_ca::keystore::KeyStore;
use ws_ca::ocsp::{build_ocsp_response, OcspResponseSpec, OcspStatus};
use ws_core::models::audit::{ActorType, AuditEntry, AuthMethod};
use ws_core::models::ca::CaModel;
use ws_core::models::certificate::CertificateModel;
use ws_core::models::ocsp::OcspResponseModel;
use ws_core::repo::audit_repo::AuditRepo;
use ws_core::repo::certificate_repo::CertificateRepo;
use ws_core::repo::ocsp_repo::OcspRepo;
use ws_secmem::SecretBuf;
use x509_parser::prelude::FromDer;
use x509_parser::revocation_list::CertificateRevocationList;

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

/// The published CRL of one CA, as the database holds it.
struct PublishedCrl {
    /// The expiry instant (`next_update`): after it the CRL is stale and
    /// relying parties must fetch a new one.
    next_update: DateTime<Utc>,
    /// The PEM document.
    crl_pem: String,
}

/// A revoked certificate together with the instant it was revoked.
///
/// The revocation instant is not optional here: a revoked row without
/// one is data damage, and the job refuses to publish around it rather
/// than inventing a date.
#[derive(Debug, Clone)]
struct RevokedCert {
    /// The certificate row.
    cert: CertificateModel,
    /// When the certificate was revoked.
    revoked_at: DateTime<Utc>,
}

/// What the job decided to do for one CA.
enum CaPlan {
    /// Nothing to publish: the published CRL is current and every
    /// revoked certificate has a fresh OCSP answer.
    Nothing,
    /// The CRL must be (re)published, and/or OCSP answers are missing.
    Publish {
        /// Whether a new CRL row is needed.
        publish_crl: bool,
        /// The revoked certificates that need a fresh OCSP response.
        stale_ocsp: Vec<RevokedCert>,
    },
}

/// The source of one CA's unwrapped private key for a revocation batch:
/// the worker's seam over [`KeyStore`], so the job is generic over the
/// keystore and a test stand-in can count the unwraps.
///
/// Implementations hand out an arena reservation (wiped on drop); the
/// job is a batch signer — one of the two shapes allowed to hold an
/// unwrapped CA key across operations. Every other key use goes through
/// `KeyStore::with_ca_key`.
pub trait CaKeySource {
    /// Unwrap the CA private key for `ca_id` into the protected arena.
    fn unwrap_ca_key(&self, ca_id: &Uuid) -> Result<SecretBuf, CaError>;
}

impl CaKeySource for KeyStore {
    fn unwrap_ca_key(&self, ca_id: &Uuid) -> Result<SecretBuf, CaError> {
        KeyStore::unwrap_ca_key(self, ca_id)
    }
}

/// Make the published revocation state of every CA match the database's
/// truth, and return the number of CAs for which something was
/// published.
///
/// For each CA the job gathers the published CRL (the latest one, by
/// issue instant) and the database's currently revoked certificates, and
/// then decides:
///
/// - `crl_missing` — the CA has no published CRL at all;
/// - `crl_expired` — the published CRL's `next_update` is in the past;
/// - `content_differs` — the revoked serials listed in the published
///   CRL are not exactly the revoked serials in the database. The
///   comparison is made on the *content* of the published CRL (it is
///   parsed, never counted, never inferred from timestamps): a revocation
///   that is missing from the published CRL — for instance because it
///   was recorded with an older `revoked_at` than the CRL's issue
///   instant — must be republished, or it would be lost forever. A
///   published CRL that cannot be parsed is treated as differing, and the
///   condition is logged, because a corrupt published CRL has to be
///   republished;
/// - `ocsp_missing` — a revoked certificate has no OCSP response, or
///   its latest response predates the certificate's revocation, or that
///   response's validity window has lapsed: each of those answers is
///   stale and must be replaced.
///
/// A new CRL is published when the CRL conditions hold; an OCSP response
/// is published for every revoked certificate whose answer is missing.
/// The two are independent: an OCSP-only repair does not need a new CRL,
/// and a CRL refresh still ensures that every revoked certificate has an
/// OCSP answer.
///
/// The returned count is the number of CAs for which work was actually
/// done — a CRL published or an OCSP response written. A CA with
/// nothing to do is skipped and not counted.
///
/// Errors: a revoked certificate without a `revoked_at` is a typed
/// [`WorkerError::Config`] (the revocation date is never invented, and
/// the revocation is never silently dropped from the CRL); a CA whose key
/// is missing while it owes a document, a damaged CA key, a
/// DER/encoding failure, and database failures surface as typed
/// [`WorkerError`]s. One failing CA never stops the others: the failure
/// is logged (with the CA id) and the job continues with the next CA; the
/// first failure is nevertheless reported to the caller, so the scheduler
/// logs the job as failed and the next tick retries.
pub async fn regen_crl_and_ocsp<K: CaKeySource>(
    pool: &PgPool,
    keystore: &K,
) -> Result<u64, WorkerError> {
    let cas = list_all_cas(pool).await?;
    let certs = CertificateRepo::new();
    let ocsp = OcspRepo::new();
    let audit = AuditRepo::new();

    let mut published = 0u64;
    let mut first_failure: Option<WorkerError> = None;
    for ca in cas {
        match regen_one_ca(pool, keystore, &ca, &certs, &ocsp, &audit).await {
            Ok(true) => published += 1,
            Ok(false) => {}
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
        None => Ok(published),
    }
}

/// Publish what one CA needs, and report whether anything was published.
async fn regen_one_ca<K: CaKeySource>(
    pool: &PgPool,
    keystore: &K,
    ca: &CaModel,
    certs: &CertificateRepo,
    ocsp: &OcspRepo,
    audit: &AuditRepo,
) -> Result<bool, WorkerError> {
    let now = Utc::now();
    let published_crl = latest_crl(pool, ca.id).await?;
    let revoked_rows = certs
        .list_revoked_since(pool, ca.id, DateTime::UNIX_EPOCH)
        .await?;

    // A revoked certificate without a revocation instant is data-level
    // damage: the revocation date must never be invented, and the
    // revocation must never be silently dropped from the CRL. Fail
    // loudly, before anything is published for this CA.
    //
    // The damage is looked for with its own query: the repository's
    // `list_revoked_since` filters on `revoked_at >= since`, so a row
    // with a NULL revocation instant is invisible to it — exactly the
    // row that has to be caught.
    let damaged = revoked_without_date(pool, ca.id).await?;
    if damaged > 0 {
        return Err(WorkerError::Config(format!(
            "CA {} has {damaged} revoked certificate(s) without a revocation date",
            ca.id
        )));
    }

    // The revocation instants are taken here, once: a revoked row
    // without one is data damage, and the value is turned into a typed
    // error at the point where it is needed (never a panic).
    let revoked = revoked_rows
        .iter()
        .map(|cert| {
            Ok(RevokedCert {
                cert: cert.clone(),
                revoked_at: cert.revoked_at.ok_or_else(|| {
                    WorkerError::Config(format!(
                        "revoked certificate {} of CA {} has no revocation date",
                        cert.serial, ca.id
                    ))
                })?,
            })
        })
        .collect::<Result<Vec<_>, WorkerError>>()?;

    let plan = plan_for(pool, ca, &published_crl, &revoked, ocsp, now).await?;
    let CaPlan::Publish {
        publish_crl,
        stale_ocsp,
    } = plan
    else {
        return Ok(false);
    };

    // The CA's key is needed for both the CRL and the OCSP responses.
    //
    // A CA row whose key file is simply not there is a CA that is not
    // provisioned yet (its row was created before the key was stored,
    // or the worker points at a different key directory). Whether that
    // is a failure depends on what the CA owes:
    //
    // - It owes nothing (no revocations and no published CRL, so no
    //   relying party can be holding a document of its): the CA is
    //   skipped with a warning, not counted, and does not fail the
    //   job. Reporting a failure for it on every tick would be a
    //   permanent false alarm.
    // - It owes something (it has revocations, or it has a published
    //   CRL that relying parties depend on): the missing key is a real
    //   failure and is reported.
    //
    // Every other key error (a damaged key file, a master key that does
    // not match) is data damage, and is a failure in both cases.
    //
    // Exactly ONE unwrap per CA per tick: the arena reservation serves
    // the CRL and every OCSP response in this batch, and is wiped when
    // the batch ends — the batch-signer allowance.
    let ca_key = match keystore.unwrap_ca_key(&ca.id) {
        Ok(key) => key,
        Err(CaError::NotFound) => {
            if revoked.is_empty() && published_crl.is_none() {
                tracing::warn!(
                    ca_id = %ca.id,
                    "skipping a CA whose key is not in the key store and which owes no document"
                );
                return Ok(false);
            }
            return Err(WorkerError::Ca(CaError::NotFound));
        }
        Err(err) => return Err(WorkerError::Ca(err)),
    };

    if publish_crl {
        let revocations = revoked
            .iter()
            .map(|cert| RevocationEntry {
                serial: cert.cert.serial,
                reason: cert
                    .cert
                    .revocation_reason
                    .as_deref()
                    .and_then(reason_from_str),
                revoked_at: cert.revoked_at,
            })
            .collect::<Vec<_>>();

        let crl = build_crl(
            &ca.cert_pem,
            &ca_key,
            &CrlSpec {
                revocations,
                next_update: VALIDITY,
            },
        )?;

        // The CRL row is written only after the whole CRL exists. Its
        // `tenant_id` is the CA's own tenant: a CRL is published for a
        // CA, and a CA belongs to exactly one tenant.
        sqlx::query(
            "INSERT INTO crls (id, tenant_id, ca_id, issued_at, next_update, crl_pem) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::new_v4())
        .bind(ca.tenant_id)
        .bind(ca.id)
        .bind(crl.issued_at)
        .bind(crl.next_update)
        .bind(&crl.crl_pem)
        .execute(pool)
        .await?;

        audit
            .record(
                pool,
                &AuditEntry {
                    id: Uuid::new_v4(),
                    tenant_id: ca.tenant_id,
                    actor_type: ActorType::System,
                    auth_method: AuthMethod::System,
                    session_id: None,
                    actor_id: AUDIT_ACTOR_ID.to_owned(),
                    action: AUDIT_ACTION_CRL_BUILT.to_owned(),
                    target_type: "ca".to_owned(),
                    target_id: ca.id.to_string(),
                    details: json!({
                        "ca_name": ca.name,
                        "revoked": revoked.len(),
                        "next_update": crl.next_update.to_rfc3339(),
                    }),
                    created_at: Utc::now(),
                },
            )
            .await?;
    }

    // One OCSP response per certificate whose answer is missing or
    // stale. The response is published with its own window: the answer
    // is produced now and stays valid for 24 hours.
    for cert in &stale_ocsp {
        let this_update = now;
        let next_update = now
            .checked_add_signed(VALIDITY)
            .ok_or_else(|| WorkerError::Config("OCSP validity window out of range".to_owned()))?;
        let response = build_ocsp_response(
            &ca.cert_pem,
            &ca_key,
            cert.cert.serial,
            &OcspResponseSpec {
                status: OcspStatus::Revoked,
                this_update,
                next_update,
                revoked_at: Some(cert.revoked_at),
                reason: cert
                    .cert
                    .revocation_reason
                    .as_deref()
                    .and_then(reason_from_str),
            },
        )?;
        let serial = i64::try_from(cert.cert.serial).map_err(|_| {
            WorkerError::Config(format!(
                "certificate serial {} exceeds the bigint serial column range",
                cert.cert.serial
            ))
        })?;
        ocsp.insert(
            pool,
            &OcspResponseModel {
                id: Uuid::new_v4(),
                tenant_id: ca.tenant_id,
                ca_id: ca.id,
                serial,
                status: OcspStatus::Revoked,
                this_update,
                next_update,
                resp_der: response,
            },
        )
        .await?;
    }

    Ok(true)
}

/// Decide what one CA needs published.
async fn plan_for(
    pool: &PgPool,
    ca: &CaModel,
    published_crl: &Option<PublishedCrl>,
    revoked: &[RevokedCert],
    ocsp: &OcspRepo,
    now: DateTime<Utc>,
) -> Result<CaPlan, WorkerError> {
    // The OCSP answers that are missing or stale: a certificate with no
    // answer at all, one whose latest answer predates the revocation
    // (such an answer says "good" about a certificate that was already
    // revoked when it was made), or one whose validity window has
    // lapsed (a lapsed answer must not be served any more).
    let mut stale_ocsp = Vec::new();
    for cert in revoked {
        let serial = i64::try_from(cert.cert.serial).map_err(|_| {
            WorkerError::Config(format!(
                "certificate serial {} exceeds the bigint serial column range",
                cert.cert.serial
            ))
        })?;
        let latest = ocsp.get_latest(pool, ca.id, serial).await?;
        let needs_response = match latest {
            None => true,
            Some(response) => response.this_update < cert.revoked_at || response.next_update < now,
        };
        if needs_response {
            stale_ocsp.push(cert.clone());
        }
    }

    let publish_crl = match published_crl {
        // No published CRL at all: the CA must publish one, even when it
        // has revoked nothing. A relying party that fetches the CA's
        // CRL must receive a current document — "this CA has revoked
        // nothing" and "this CA has no CRL" must not be
        // indistinguishable — and RFC 5280 section 5's distribution
        // model assumes a periodically refreshed artifact.
        None => true,
        Some(crl) => {
            // The published CRL is expired.
            let expired = crl.next_update < now;
            // The published CRL must list exactly the database's revoked
            // serials. The comparison is made on the parsed content: a
            // CRL that cannot be parsed cannot be trusted, so it has to
            // be republished.
            let published_serials = match parse_crl_serials(&crl.crl_pem) {
                Some(serials) => serials,
                None => {
                    tracing::warn!(
                        ca_id = %ca.id,
                        "the published CRL could not be parsed; republishing"
                    );
                    return Ok(CaPlan::Publish {
                        publish_crl: true,
                        stale_ocsp,
                    });
                }
            };
            expired || published_serials != revoked_serials(revoked)
        }
    };

    if !publish_crl && stale_ocsp.is_empty() {
        return Ok(CaPlan::Nothing);
    }
    Ok(CaPlan::Publish {
        publish_crl,
        stale_ocsp,
    })
}

/// The set of revoked serials the database holds for a CA.
fn revoked_serials(revoked: &[RevokedCert]) -> BTreeSet<u128> {
    revoked.iter().map(|cert| cert.cert.serial).collect()
}

/// The set of revoked serials a published CRL lists, or `None` when the
/// published CRL cannot be parsed (a corrupt row, a truncated PEM).
///
/// The serials are compared as sets: the CRL's content decides whether
/// it is still current, never a timestamp and never a count.
fn parse_crl_serials(crl_pem: &str) -> Option<BTreeSet<u128>> {
    let (_, block) = x509_parser::pem::parse_x509_pem(crl_pem.as_bytes()).ok()?;
    let (_, crl) = CertificateRevocationList::from_der(&block.contents).ok()?;
    let mut serials = BTreeSet::new();
    for entry in crl.iter_revoked_certificates() {
        // The serial is a big integer; the decimal form is parsed back
        // into the u128 the rest of the code uses. A serial that does
        // not fit cannot be compared with the database's serials, so the
        // CRL is treated as unparsable.
        let serial = entry.serial().to_string().parse::<u128>().ok()?;
        serials.insert(serial);
    }
    Some(serials)
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

/// The number of a CA's revoked certificates that carry no revocation
/// instant — data damage the job refuses to publish around.
async fn revoked_without_date(pool: &PgPool, ca_id: Uuid) -> Result<i64, WorkerError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM certificates WHERE ca_id = $1 AND status = 'revoked' \
         AND revoked_at IS NULL",
    )
    .bind(ca_id)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// A CA's latest published CRL, or `None` when it has none.
async fn latest_crl(pool: &PgPool, ca_id: Uuid) -> Result<Option<PublishedCrl>, WorkerError> {
    #[derive(sqlx::FromRow)]
    struct CrlRow {
        next_update: DateTime<Utc>,
        crl_pem: String,
    }

    let row: Option<CrlRow> = sqlx::query_as(
        "SELECT next_update, crl_pem FROM crls WHERE ca_id = $1 \
         ORDER BY issued_at DESC LIMIT 1",
    )
    .bind(ca_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| PublishedCrl {
        next_update: row.next_update,
        crl_pem: row.crl_pem,
    }))
}

/// Map a stored revocation reason string onto the RFC 5280 reason code
/// the OCSP response and the CRL entry carry.
///
/// The stored reasons are the snake_case names of [`CrlReason`] (for
/// example `key_compromise`); a reason this build does not know (a
/// value written by a newer release) is `None` — the response then
/// carries no reason extension, which RFC 6960 allows.
///
/// `remove_from_crl` is deliberately NOT mapped: RFC 5280 section 5.3.1
/// code 8 means "revoked and now reinstated", so encoding it for a row
/// that is still `status='revoked'` would make the CRL and the OCSP
/// answer contradict the database. A revocation is terminal in this
/// plan, so a stored `remove_from_crl` yields no reason extension (the
/// entry still says "revoked") rather than a false "not revoked". The
/// CRL builder and the OCSP builder independently refuse the reason,
/// so the two channels cannot disagree even if one is reached through
/// a different path.
fn reason_from_str(reason: &str) -> Option<CrlReason> {
    match reason {
        "unspecified" => Some(CrlReason::Unspecified),
        "key_compromise" => Some(CrlReason::KeyCompromise),
        "ca_compromise" => Some(CrlReason::CACompromise),
        "affiliation_changed" => Some(CrlReason::AffiliationChanged),
        "superseded" => Some(CrlReason::Superseded),
        "cessation_of_operation" => Some(CrlReason::CessationOfOperation),
        "certificate_hold" => Some(CrlReason::CertificateHold),
        "remove_from_crl" => None,
        "privilege_withdrawn" => Some(CrlReason::PrivilegeWithdrawn),
        "aa_compromise" => Some(CrlReason::AaCompromise),
        _ => None,
    }
}
