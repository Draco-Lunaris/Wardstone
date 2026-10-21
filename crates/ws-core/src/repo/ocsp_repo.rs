//! Repository over the `ocsp_responses` table.
//!
//! The table stores the responder's signed answers verbatim: a row's
//! `resp_der` is the exact byte sequence a client received, so a later
//! read never re-encodes (and never accidentally re-signs) a response.
//! `get_latest` returns the most recently *published* answer for a
//! certificate — the one with the greatest `this_update` — which is the
//! answer a client should be given.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::CoreError;
use crate::models::ocsp::{OcspResponseModel, OcspStatus};
use crate::repo::tenant_repo::map_unique;

/// Data access for [`OcspResponseModel`] rows.
pub struct OcspRepo {
    pool: PgPool,
}

/// Inline row shape for `sqlx::query_as` (house style: hand-mapped to the
/// model). `status` is the raw text column, decoded via
/// `OcspStatus::from_str`.
#[derive(sqlx::FromRow)]
struct OcspResponseRow {
    id: Uuid,
    tenant_id: Uuid,
    ca_id: Uuid,
    serial: i64,
    status: String,
    this_update: DateTime<Utc>,
    next_update: DateTime<Utc>,
    resp_der: Vec<u8>,
}

impl OcspRepo {
    /// Build a repository bound to the shared pool.
    pub fn new(pool: &PgPool) -> Self {
        OcspRepo { pool: pool.clone() }
    }

    /// Insert one OCSP response row exactly as given. A
    /// unique-violation on `(ca_id, serial, this_update)` — the same
    /// response published twice — becomes [`CoreError::Duplicate`], never
    /// a silent overwrite.
    pub async fn insert(&self, response: &OcspResponseModel) -> Result<(), CoreError> {
        sqlx::query(
            "INSERT INTO ocsp_responses (id, tenant_id, ca_id, serial, status, this_update, \
             next_update, resp_der) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(response.id)
        .bind(response.tenant_id)
        .bind(response.ca_id)
        .bind(response.serial)
        .bind(response.status.as_str())
        .bind(response.this_update)
        .bind(response.next_update)
        .bind(&response.resp_der)
        .execute(&self.pool)
        .await
        .map_err(map_unique)?;
        Ok(())
    }

    /// The most recently published response for one certificate of one
    /// CA — the row with the greatest `this_update` — or `None` when the
    /// CA has never answered for that serial.
    pub async fn get_latest(
        &self,
        ca_id: Uuid,
        serial: i64,
    ) -> Result<Option<OcspResponseModel>, CoreError> {
        let row: Option<OcspResponseRow> = sqlx::query_as(
            "SELECT id, tenant_id, ca_id, serial, status, this_update, next_update, resp_der \
             FROM ocsp_responses WHERE ca_id = $1 AND serial = $2 \
             ORDER BY this_update DESC LIMIT 1",
        )
        .bind(ca_id)
        .bind(serial)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into_model()?)),
            None => Ok(None),
        }
    }
}

impl OcspResponseRow {
    /// Decode a row into the domain model, mapping `status` through
    /// `OcspStatus::from_str`; an unknown stored status is data-level
    /// damage and a [`CoreError::Config`], not a per-request failure.
    fn try_into_model(self) -> Result<OcspResponseModel, CoreError> {
        let status = self
            .status
            .parse::<OcspStatus>()
            .map_err(|err| CoreError::Config(format!("invalid status in row: {err}")))?;
        Ok(OcspResponseModel {
            id: self.id,
            tenant_id: self.tenant_id,
            ca_id: self.ca_id,
            serial: self.serial,
            status,
            this_update: self.this_update,
            next_update: self.next_update,
            resp_der: self.resp_der,
        })
    }
}
