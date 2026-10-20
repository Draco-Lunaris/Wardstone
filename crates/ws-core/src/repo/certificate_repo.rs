//! Repository over the `certificates` table.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::CoreError;
use crate::models::certificate::{CertStatus, CertificateModel};
use crate::repo::tenant_repo::map_unique;

/// Data access for [`CertificateModel`] rows.
pub struct CertificateRepo {
    pool: PgPool,
}

/// Inline row shape for `sqlx::query_as` (house style: hand-mapped to the
/// model). `serial` is the raw `bigint` column; `status` is the raw text
/// column, decoded via `CertStatus::from_str`.
#[derive(sqlx::FromRow)]
struct CertificateRow {
    id: Uuid,
    tenant_id: Uuid,
    ca_id: Uuid,
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
    source: String,
    created_at: DateTime<Utc>,
}

impl CertificateRepo {
    /// Build a repository bound to the shared pool.
    pub fn new(pool: &PgPool) -> Self {
        CertificateRepo { pool: pool.clone() }
    }

    /// Insert a certificate row exactly as given (every field, `created_at`
    /// included: the model is authoritative, so `get` returns the same
    /// row). `serial` binds through the i64 column form; `status` binds
    /// its text representation; a unique-violation on `(ca_id, serial)`
    /// becomes [`CoreError::Duplicate`].
    pub async fn insert(&self, cert: &CertificateModel) -> Result<(), CoreError> {
        let serial = serial_to_i64(cert.serial)?;
        sqlx::query(
            "INSERT INTO certificates (id, tenant_id, ca_id, profile_name, subject, serial, \
             serial_hex, san_dns, san_ips, key_type, not_before, not_after, cert_pem, status, \
             revoked_at, revocation_reason, source, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, \
             $17, $18)",
        )
        .bind(cert.id)
        .bind(cert.tenant_id)
        .bind(cert.ca_id)
        .bind(&cert.profile_name)
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
        .bind(&cert.source)
        .bind(cert.created_at)
        .execute(&self.pool)
        .await
        .map_err(map_unique)?;
        Ok(())
    }

    /// Fetch a certificate by id; `None` when absent.
    pub async fn get(&self, id: Uuid) -> Result<Option<CertificateModel>, CoreError> {
        let row: Option<CertificateRow> = sqlx::query_as(
            "SELECT id, tenant_id, ca_id, profile_name, subject, serial, serial_hex, \
             san_dns, san_ips, key_type, not_before, not_after, cert_pem, status, revoked_at, \
             revocation_reason, source, created_at FROM certificates WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into_model()?)),
            None => Ok(None),
        }
    }

    /// A tenant's certificates, one page at a time, latest expiry first
    /// (`not_after` DESC), LIMIT/OFFSET paging (`offset = page *
    /// page_size`).
    pub async fn list_by_tenant(
        &self,
        tenant_id: Uuid,
        page: u32,
        page_size: u32,
    ) -> Result<Vec<CertificateModel>, CoreError> {
        let (limit, offset) = paging(page, page_size)?;
        let rows: Vec<CertificateRow> = sqlx::query_as(
            "SELECT id, tenant_id, ca_id, profile_name, subject, serial, serial_hex, \
             san_dns, san_ips, key_type, not_before, not_after, cert_pem, status, revoked_at, \
             revocation_reason, source, created_at \
             FROM certificates WHERE tenant_id = $1 ORDER BY not_after DESC \
             LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
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
        tenant_id: Uuid,
        threshold: DateTime<Utc>,
        page: u32,
        page_size: u32,
    ) -> Result<Vec<CertificateModel>, CoreError> {
        let (limit, offset) = paging(page, page_size)?;
        let rows: Vec<CertificateRow> = sqlx::query_as(
            "SELECT id, tenant_id, ca_id, profile_name, subject, serial, serial_hex, \
             san_dns, san_ips, key_type, not_before, not_after, cert_pem, status, revoked_at, \
             revocation_reason, source, created_at \
             FROM certificates WHERE tenant_id = $1 AND status = 'active' \
             AND not_after < $2 ORDER BY not_after ASC LIMIT $3 OFFSET $4",
        )
        .bind(tenant_id)
        .bind(threshold)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(CertificateRow::try_into_model)
            .collect::<Result<Vec<_>, CoreError>>()
    }

    /// Revoke a certificate: `status='active'` rows flip to `revoked` with
    /// `revoked_at = now()` and the given reason. The `AND status='active'`
    /// guard makes a double revoke structurally idempotent — a second call
    /// updates zero rows and still returns `Ok(())`, leaving `revoked_at`
    /// exactly where the first call set it.
    pub async fn revoke(&self, id: Uuid, reason: &str) -> Result<(), CoreError> {
        sqlx::query(
            "UPDATE certificates SET status = 'revoked', revoked_at = now(), \
             revocation_reason = $2 WHERE id = $1 AND status = 'active'",
        )
        .bind(id)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// One CA's revoked certificates with `revoked_at >= since` (the
    /// boundary is inclusive), ordered by `revoked_at` for stable output —
    /// the feed CRL building consumes.
    pub async fn list_revoked_since(
        &self,
        ca_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<Vec<CertificateModel>, CoreError> {
        let rows: Vec<CertificateRow> = sqlx::query_as(
            "SELECT id, tenant_id, ca_id, profile_name, subject, serial, serial_hex, \
             san_dns, san_ips, key_type, not_before, not_after, cert_pem, status, revoked_at, \
             revocation_reason, source, created_at \
             FROM certificates WHERE ca_id = $1 AND status = 'revoked' \
             AND revoked_at >= $2 ORDER BY revoked_at",
        )
        .bind(ca_id)
        .bind(since)
        .fetch_all(&self.pool)
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

/// LIMIT/OFFSET values for a page: `page_size` and `page * page_size`.
/// The u32-by-u32 product cannot overflow u64, so the multiply is plain;
/// the i64 conversion is still typed — an offset beyond i64 is a caller
/// bug surfaced as [`CoreError::Config`], never a silent wrap.
fn paging(page: u32, page_size: u32) -> Result<(i64, i64), CoreError> {
    let offset = u64::from(page) * u64::from(page_size);
    let offset = i64::try_from(offset)
        .map_err(|_| CoreError::Config(format!("page offset {offset} overflows")))?;
    Ok((i64::from(page_size), offset))
}
