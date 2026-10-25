//! Repository over the `certificates` table.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::error::CoreError;
use crate::models::certificate::{
    CertStatus, CertificateFilter, CertificateModel, CertificateStatistics,
};
use crate::repo::tenant_repo::map_unique;

/// Data access for [`CertificateModel`] rows.
///
/// Stateless by design: the repository holds no pool, and every method
/// takes `executor: impl PgExecutor<'_>` so a mutation and its audit row
/// can share one transaction (callers pass `&pool`, or `&mut *tx` inside a
/// transaction — `&mut Transaction` does not implement `PgExecutor` in
/// sqlx 0.8.6).
#[derive(Default)]
pub struct CertificateRepo;

/// Inline row shape for `sqlx::query_as` (house style: hand-mapped to the
/// model). `serial` is the raw `bigint` column; `status` is the raw text
/// column, decoded via `CertStatus::from_str`.
#[derive(sqlx::FromRow)]
struct CertificateRow {
    id: Uuid,
    tenant_id: Uuid,
    ca_id: Uuid,
    profile_revision_id: Option<Uuid>,
    profile_name: String,
    subject: String,
    serial: i64,
    serial_hex: String,
    san_dns: Vec<String>,
    san_ips: Vec<IpAddr>,
    key_type: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    cert_pem: String,
    status: String,
    revoked_at: Option<DateTime<Utc>>,
    revocation_reason: Option<String>,
    revocation_detail: Option<String>,
    source: String,
    created_at: DateTime<Utc>,
}

/// Inline row shape for the slim list (`sqlx::FromRow`): the five columns
/// the dashboard sieve reads, minus the PEM/SAN bulk that makes the full
/// row heavy. `status` is the raw text column, decoded via
/// `CertStatus::from_str` into [`SlimCertificate`].
#[derive(sqlx::FromRow)]
pub struct SlimCertificateRow {
    id: Uuid,
    subject: String,
    serial_hex: String,
    not_after: DateTime<Utc>,
    status: String,
}

/// The slim read model `CertificateRepo::list_slim` serves: the projection
/// the dashboard's expiring-soon sieve consumes (and the only thing it
/// needs), with no certificate PEM, SAN arrays, or revocation detail.
#[derive(Debug)]
pub struct SlimCertificate {
    pub id: Uuid,
    pub subject: String,
    pub serial_hex: String,
    pub not_after: DateTime<Utc>,
    pub status: CertStatus,
}

impl CertificateRepo {
    /// Build the (stateless) repository.
    ///
    /// The body is the plan's house shape verbatim
    /// (`Self::default()`), satisfied by the derived `Default`
    /// (`clippy::new_without_default` is an error here under the house
    /// rule); the allow silences the newer, contradicting
    /// `clippy::default_constructed_unit_structs` style lint, which the
    /// house shape deliberately does not adopt.
    #[allow(clippy::default_constructed_unit_structs)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a certificate row exactly as given (every field, `created_at`
    /// included: the model is authoritative, so `get` returns the same
    /// row). `serial` binds through the i64 column form; `status` binds
    /// its text representation; `profile_revision_id` binds nullable (the
    /// policy authority, `profile_name` the display label). A
    /// unique-violation on `(ca_id, serial)`
    /// becomes [`CoreError::Duplicate`].
    pub async fn insert(
        &self,
        executor: impl PgExecutor<'_>,
        cert: &CertificateModel,
    ) -> Result<(), CoreError> {
        let serial = serial_to_i64(cert.serial)?;
        sqlx::query(
            "INSERT INTO certificates (id, tenant_id, ca_id, profile_name, \
             profile_revision_id, subject, serial, \
             serial_hex, san_dns, san_ips, key_type, not_before, not_after, cert_pem, status, \
             revoked_at, revocation_reason, revocation_detail, source, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, \
             $17, $18, $19, $20)",
        )
        .bind(cert.id)
        .bind(cert.tenant_id)
        .bind(cert.ca_id)
        .bind(&cert.profile_name)
        .bind(cert.profile_revision_id)
        .bind(&cert.subject)
        .bind(serial)
        .bind(&cert.serial_hex)
        .bind(&cert.san_dns)
        .bind(&cert.san_ips)
        .bind(&cert.key_type)
        .bind(cert.not_before)
        .bind(cert.not_after)
        .bind(&cert.cert_pem)
        .bind(cert.status.as_str())
        .bind(cert.revoked_at)
        .bind(cert.revocation_reason.as_deref())
        .bind(cert.revocation_detail.as_deref())
        .bind(&cert.source)
        .bind(cert.created_at)
        .execute(executor)
        .await
        .map_err(map_unique)?;
        Ok(())
    }

    /// Fetch a certificate by id; `None` when absent.
    pub async fn get(
        &self,
        executor: impl PgExecutor<'_>,
        id: Uuid,
    ) -> Result<Option<CertificateModel>, CoreError> {
        let row: Option<CertificateRow> = sqlx::query_as(
            "SELECT id, tenant_id, ca_id, profile_name, profile_revision_id, subject, serial, \
             serial_hex, san_dns, san_ips, key_type, not_before, not_after, cert_pem, status, \
             revoked_at, revocation_reason, revocation_detail, source, created_at FROM certificates WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(executor)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into_model()?)),
            None => Ok(None),
        }
    }

    /// A tenant's certificates, one page at a time, latest expiry first
    /// (`not_after` DESC, `id` as the tiebreaker), LIMIT/OFFSET paging
    /// (`offset = page * page_size`) through the shared
    /// [`crate::repo::paging`] helper (clamped page size). The
    /// tiebreaker is load-bearing, not cosmetic: equal-`not_after` rows
    /// (two certificates from one issuance run share the expiry tick)
    /// would otherwise come back in unspecified order — an unstable
    /// listing AND a page-boundary hazard, where a tie row can appear
    /// on two pages or neither.
    pub async fn list_by_tenant(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        page: u32,
        page_size: u32,
    ) -> Result<Vec<CertificateModel>, CoreError> {
        let (limit, offset) = crate::repo::paging(page, page_size)?;
        let rows: Vec<CertificateRow> = sqlx::query_as(
            "SELECT id, tenant_id, ca_id, profile_name, profile_revision_id, subject, serial, \
             serial_hex, san_dns, san_ips, key_type, not_before, not_after, cert_pem, status, \
             revoked_at, revocation_reason, revocation_detail, source, created_at \
             FROM certificates WHERE tenant_id = $1 ORDER BY not_after DESC, id \
             LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(executor)
        .await?;

        rows.into_iter()
            .map(CertificateRow::try_into_model)
            .collect::<Result<Vec<_>, CoreError>>()
    }

    /// The expiry-monitoring query: a tenant's certificates whose
    /// `not_after` falls before `threshold`, active ones only, soonest
    /// first. The pinned comparison `not_after < threshold` deliberately
    /// has no lower bound on now: an active row whose `not_after` has
    /// already passed is exactly what a renewal monitor must surface.
    pub async fn list_expiring_before(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        threshold: DateTime<Utc>,
        page: u32,
        page_size: u32,
    ) -> Result<Vec<CertificateModel>, CoreError> {
        let (limit, offset) = crate::repo::paging(page, page_size)?;
        let rows: Vec<CertificateRow> = sqlx::query_as(
            "SELECT id, tenant_id, ca_id, profile_name, profile_revision_id, subject, serial, \
             serial_hex, san_dns, san_ips, key_type, not_before, not_after, cert_pem, status, \
             revoked_at, revocation_reason, revocation_detail, source, created_at \
             FROM certificates WHERE tenant_id = $1 AND status = 'active' \
             AND not_after < $2 ORDER BY not_after ASC LIMIT $3 OFFSET $4",
        )
        .bind(tenant_id)
        .bind(threshold)
        .bind(limit)
        .bind(offset)
        .fetch_all(executor)
        .await?;

        rows.into_iter()
            .map(CertificateRow::try_into_model)
            .collect::<Result<Vec<_>, CoreError>>()
    }

    /// The tenant's certificates through a composed filter, one page at a
    /// time, latest expiry first (`not_after` DESC, same as
    /// [`CertificateRepo::list_by_tenant`]), LIMIT/OFFSET paging through
    /// the shared [`crate::repo::paging`] helper.
    ///
    /// The WHERE clause composes ONLY the filter fields that are `Some`
    /// (`tenant_id` is always present); every value binds as a parameter —
    /// nothing is ever stringified into the SQL. The search needle binds
    /// ONCE (`$n`) and is reused at three placeholders: subject, serial
    /// hex, and the unnest-ed `san_dns` rows — LITERALLY (`%`, `_`, and `\`
    /// are escaped and the ILIKE clauses carry `ESCAPE '\'`, so the
    /// operator's `q` never widens into a wildcard).
    pub async fn list_filtered(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        filter: &CertificateFilter,
        page: u32,
        page_size: u32,
    ) -> Result<Vec<CertificateModel>, CoreError> {
        // Compose the SQL FIRST (nothing may re-borrow the string after the
        // query takes it), then bind in the same order the placeholders
        // were written. `format!` + `push_str` is infallible — the house
        // rule forbids `unwrap`/`expect` outside tests.
        let (limit, offset) = crate::repo::paging(page, page_size)?;
        let mut sql = String::from(
            "SELECT id, tenant_id, ca_id, profile_name, profile_revision_id, subject, serial, \
             serial_hex, san_dns, san_ips, key_type, not_before, not_after, cert_pem, status, \
             revoked_at, revocation_reason, revocation_detail, source, created_at \
             FROM certificates WHERE tenant_id = $1",
        );
        let mut next = 2usize; // the next placeholder's 1-based index

        if filter.status.is_some() {
            sql.push_str(&format!(" AND status = ${next}"));
            next += 1;
        }
        if filter.profile_name.is_some() {
            sql.push_str(&format!(" AND profile_name = ${next}"));
            next += 1;
        }
        if filter.ca_id.is_some() {
            sql.push_str(&format!(" AND ca_id = ${next}"));
            next += 1;
        }
        if filter.search.is_some() {
            sql.push_str(&format!(
                " AND (subject ILIKE ${next} ESCAPE '\\' OR serial_hex ILIKE ${next} \
                 ESCAPE '\\' OR EXISTS (SELECT 1 FROM unnest(san_dns) d \
                 WHERE d ILIKE ${next} ESCAPE '\\'))"
            ));
            // The pattern is ONE parameter slot (reused at its three
            // references) — it still advances the placeholder counter.
            next += 1;
        }
        sql.push_str(&format!(
            " ORDER BY not_after DESC LIMIT ${next} OFFSET ${}",
            next + 1
        ));

        let mut query = sqlx::query_as::<_, CertificateRow>(&sql).bind(tenant_id);
        if let Some(status) = &filter.status {
            query = query.bind(status.as_str());
        }
        if let Some(profile_name) = &filter.profile_name {
            query = query.bind(profile_name);
        }
        if let Some(ca_id) = filter.ca_id {
            query = query.bind(ca_id);
        }
        if let Some(search) = &filter.search {
            // One bind, reused at three placeholders — and the needle is
            // LITERAL: `%`, `_`, and `\` are escaped (backslash first, or
            // its own escape would unescape) so a metacharacter in the
            // operator's `q` matches itself instead of widening the search
            // into a prefix/substring wildcard. The `ESCAPE '\'` clause on
            // all three ILIKE references makes the pair agree.
            let escaped = search
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            query = query.bind(format!("%{escaped}%"));
        }
        let query = query.bind(limit).bind(offset);

        let rows = query.fetch_all(executor).await?;
        rows.into_iter()
            .map(CertificateRow::try_into_model)
            .collect::<Result<Vec<_>, CoreError>>()
    }

    /// The dashboard sieve's slim projection: a tenant's certificates as
    /// [`SlimCertificate`] rows — `(id, subject, serial_hex, not_after,
    /// status)`, nothing else — one page at a time, latest expiry first
    /// (`not_after DESC`, the same order [`CertificateRepo::list_by_tenant`]
    /// serves), LIMIT/OFFSET paging through the shared [`crate::repo::paging`]
    /// helper, and an optional equality filter on `status`. The value of
    /// the route is the COLUMNS: the sieve reads five small fields about
    /// up to 500 rows, so the query never drags `cert_pem` and the SAN
    /// arrays out of the database.
    pub async fn list_slim(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        status: Option<CertStatus>,
        page: u32,
        page_size: u32,
    ) -> Result<Vec<SlimCertificate>, CoreError> {
        let (limit, offset) = crate::repo::paging(page, page_size)?;
        let mut sql = String::from(
            "SELECT id, subject, serial_hex, not_after, status \
             FROM certificates WHERE tenant_id = $1",
        );
        let mut next = 2usize; // the next placeholder's 1-based index
        if status.is_some() {
            sql.push_str(&format!(" AND status = ${next}"));
            next += 1;
        }
        sql.push_str(&format!(
            " ORDER BY not_after DESC LIMIT ${next} OFFSET ${}",
            next + 1
        ));

        let mut query = sqlx::query_as::<_, SlimCertificateRow>(&sql).bind(tenant_id);
        if let Some(status) = &status {
            query = query.bind(status.as_str());
        }
        let rows = query.bind(limit).bind(offset).fetch_all(executor).await?;
        rows.into_iter()
            .map(|row| {
                Ok(SlimCertificate {
                    id: row.id,
                    subject: row.subject,
                    serial_hex: row.serial_hex,
                    not_after: row.not_after,
                    // An unknown stored spelling is data-level damage —
                    // the same typed refusal the full row model hands
                    // back, never a per-request string passthrough.
                    status: row.status.parse::<CertStatus>().map_err(|err| {
                        CoreError::Config(format!("invalid status in row: {err}"))
                    })?,
                })
            })
            .collect()
    }

    /// The estate's headline counts in ONE round trip: the `FILTER`ed
    /// `COUNT(*)` aggregates (active, revoked, and active-and-expiring
    /// before `expiring_before`) over the tenant's rows. Counts are never
    /// `NULL` and never negative; the `BIGINT` values arrive as `i64` and
    /// are converted typed.
    pub async fn statistics(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        expiring_before: DateTime<Utc>,
    ) -> Result<CertificateStatistics, CoreError> {
        let (active, revoked, expiring_soon) = sqlx::query_as::<_, (i64, i64, i64)>(
            "SELECT CAST(COUNT(*) FILTER (WHERE status = 'active') AS BIGINT), \
             CAST(COUNT(*) FILTER (WHERE status = 'revoked') AS BIGINT), \
             CAST(COUNT(*) FILTER (WHERE status = 'active' AND not_after < $1) AS BIGINT) \
             FROM certificates WHERE tenant_id = $2",
        )
        .bind(expiring_before)
        .bind(tenant_id)
        .fetch_one(executor)
        .await?;

        let count = |value: i64| -> Result<u64, CoreError> {
            u64::try_from(value)
                .map_err(|_| CoreError::Config("negative certificate count".to_string()))
        };
        Ok(CertificateStatistics {
            active: count(active)?,
            revoked: count(revoked)?,
            expiring_soon: count(expiring_soon)?,
        })
    }

    /// Revoke a certificate: `status='active'` rows flip to `revoked` with
    /// `revoked_at = now()` and the given reason and detail. The
    /// `AND status='active'` guard makes a double revoke structurally
    /// idempotent — a second call updates zero rows and still returns
    /// `Ok(())`, leaving `revoked_at` AND the FIRST call's reason/detail
    /// pair exactly where the first call set them. `reason` is a stored
    /// RFC 5280 name (`RevocationReason::as_str`, the spelling
    /// ws-worker's `reason_from_str` parses); `detail` is the optional
    /// free-form note stored verbatim alongside (migration 010).
    pub async fn revoke(
        &self,
        executor: impl PgExecutor<'_>,
        id: Uuid,
        reason: &str,
        detail: Option<&str>,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "UPDATE certificates SET status = 'revoked', revoked_at = now(), \
             revocation_reason = $2, revocation_detail = $3 \
             WHERE id = $1 AND status = 'active'",
        )
        .bind(id)
        .bind(reason)
        .bind(detail)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// One CA's revoked certificates with `revoked_at >= since` (the
    /// boundary is inclusive), ordered by `revoked_at` for stable output —
    /// the feed CRL building consumes.
    pub async fn list_revoked_since(
        &self,
        executor: impl PgExecutor<'_>,
        ca_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<Vec<CertificateModel>, CoreError> {
        let rows: Vec<CertificateRow> = sqlx::query_as(
            "SELECT id, tenant_id, ca_id, profile_name, profile_revision_id, subject, serial, \
             serial_hex, san_dns, san_ips, key_type, not_before, not_after, cert_pem, status, \
             revoked_at, revocation_reason, revocation_detail, source, created_at \
             FROM certificates WHERE ca_id = $1 AND status = 'revoked' \
             AND revoked_at >= $2 ORDER BY revoked_at",
        )
        .bind(ca_id)
        .bind(since)
        .fetch_all(executor)
        .await?;

        rows.into_iter()
            .map(CertificateRow::try_into_model)
            .collect::<Result<Vec<_>, CoreError>>()
    }
}

impl CertificateRow {
    /// Decode a row into the domain model, mapping `status` through
    /// `CertStatus::from_str` and `serial` back into the model's u128; an
    /// unknown stored status or an out-of-range serial is data-level
    /// damage and a [`CoreError::Config`], not a per-request failure.
    fn try_into_model(self) -> Result<CertificateModel, CoreError> {
        let status = self
            .status
            .parse::<CertStatus>()
            .map_err(|err| CoreError::Config(format!("invalid status in row: {err}")))?;
        let serial = u128::try_from(self.serial).map_err(|_| {
            CoreError::Config(format!(
                "certificate serial {} does not fit u128",
                self.serial
            ))
        })?;
        Ok(CertificateModel {
            id: self.id,
            tenant_id: self.tenant_id,
            ca_id: self.ca_id,
            profile_revision_id: self.profile_revision_id,
            profile_name: self.profile_name,
            subject: self.subject,
            serial,
            serial_hex: self.serial_hex,
            san_dns: self.san_dns,
            san_ips: self.san_ips,
            key_type: self.key_type,
            not_before: self.not_before,
            not_after: self.not_after,
            cert_pem: self.cert_pem,
            status,
            revoked_at: self.revoked_at,
            revocation_reason: self.revocation_reason,
            revocation_detail: self.revocation_detail,
            source: self.source,
            created_at: self.created_at,
        })
    }
}

/// The model's u128 serial as the `serial bigint` column value: a serial
/// beyond i64 is data-level damage and a typed [`CoreError::Config`],
/// never a wrapping cast or a panic.
fn serial_to_i64(serial: u128) -> Result<i64, CoreError> {
    i64::try_from(serial).map_err(|_| {
        CoreError::Config(format!(
            "certificate serial {serial} exceeds the bigint column range"
        ))
    })
}
