//! Repository over the `cas` table.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::error::CoreError;
use crate::models::ca::{CaModel, KeyType};
use crate::repo::tenant_repo::map_unique;

/// How many CAs a leaf-to-root walk may visit: the depth bound that also
/// breaks a corrupt `parent_id` cycle.
const MAX_CHAIN_DEPTH: usize = 8;

/// Data access for [`CaModel`] rows.
///
/// Stateless by design: the repository holds no pool, and single-statement
/// methods take `executor: impl PgExecutor<'_>` so a mutation and its
/// audit row can share one transaction (callers pass `&pool`, or `&mut
/// *tx` inside a transaction — `&mut Transaction` does not implement
/// `PgExecutor` in sqlx 0.8.6). The exceptions are the multi-statement
/// walkers, which take `&mut sqlx::PgConnection` (see
/// [`CaRepo::chain_to_root`] for why).
#[derive(Default)]
pub struct CaRepo;

/// Inline row shape for `sqlx::query_as` (house style: hand-mapped to the
/// model). `key_type` is the raw text column, decoded via `KeyType::from_str`.
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

impl CaRepo {
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

    /// Insert a CA row exactly as given (`id`, `created_at`, every field: the
    /// model is authoritative — `created_at` is written explicitly rather
    /// than left to the `now()` default, so `get` returns the same row).
    /// `key_type` is bound via its text representation.
    pub async fn insert(
        &self,
        executor: impl PgExecutor<'_>,
        ca: &CaModel,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "INSERT INTO cas (id, tenant_id, name, subject, is_root, parent_id, key_type, \
             not_before, not_after, cert_pem, key_file, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(ca.id)
        .bind(ca.tenant_id)
        .bind(&ca.name)
        .bind(&ca.subject)
        .bind(ca.is_root)
        .bind(ca.parent_id)
        .bind(ca.key_type.as_str())
        .bind(ca.not_before)
        .bind(ca.not_after)
        .bind(&ca.cert_pem)
        .bind(&ca.key_file)
        .bind(ca.created_at)
        .execute(executor)
        .await
        .map_err(map_unique)?;
        Ok(())
    }

    /// Fetch a CA by id; `None` when absent.
    pub async fn get(
        &self,
        executor: impl PgExecutor<'_>,
        id: Uuid,
    ) -> Result<Option<CaModel>, CoreError> {
        let row: Option<CaRow> = sqlx::query_as(
            "SELECT id, tenant_id, name, subject, is_root, parent_id, key_type, \
             not_before, not_after, cert_pem, key_file, created_at \
             FROM cas WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(executor)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into_model()?)),
            None => Ok(None),
        }
    }

    /// All CAs owned by a tenant, ordered by name for stable output.
    pub async fn list_by_tenant(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
    ) -> Result<Vec<CaModel>, CoreError> {
        let rows: Vec<CaRow> = sqlx::query_as(
            "SELECT id, tenant_id, name, subject, is_root, parent_id, key_type, \
             not_before, not_after, cert_pem, key_file, created_at \
             FROM cas WHERE tenant_id = $1 ORDER BY name",
        )
        .bind(tenant_id)
        .fetch_all(executor)
        .await?;

        rows.into_iter()
            .map(CaRow::try_into_model)
            .collect::<Result<Vec<_>, CoreError>>()
    }

    /// CAs whose `parent_id` is the given CA, ordered by name.
    pub async fn children_of(
        &self,
        executor: impl PgExecutor<'_>,
        parent_id: Uuid,
    ) -> Result<Vec<CaModel>, CoreError> {
        let rows: Vec<CaRow> = sqlx::query_as(
            "SELECT id, tenant_id, name, subject, is_root, parent_id, key_type, \
             not_before, not_after, cert_pem, key_file, created_at \
             FROM cas WHERE parent_id = $1 ORDER BY name",
        )
        .bind(parent_id)
        .fetch_all(executor)
        .await?;

        rows.into_iter()
            .map(CaRow::try_into_model)
            .collect::<Result<Vec<_>, CoreError>>()
    }

    /// The chain from the named CA up to its trust anchor, leaf-first: the
    /// named CA itself first, then its parent's, up to the CA whose
    /// `parent_id` is `None`.
    ///
    /// The executor is `&mut sqlx::PgConnection`, not a generic
    /// `impl PgExecutor<'_>`: this walk runs SEVERAL statements on it, and
    /// an `impl PgExecutor` parameter is consumed by the first query (the
    /// house note on the certificates route's `issue_in_tx` core — callers
    /// pass `&mut *conn` on a pooled connection, or `&mut *tx` on a
    /// transaction).
    ///
    /// TENANT CHECK ON EVERY HOP: `tenant_id` is the actor's verified
    /// tenant (the routes pass the one they already established the
    /// starting CA against — the first hop re-checks it as
    /// defense-in-depth), and any CA whose row does not belong to it makes
    /// the walk refuse with [`CoreError::Config`]. Containment is already
    /// enforced twice elsewhere — the SCHEMA keeps a CA's parent in its
    /// tenant (`cas_parent_tenant_fk`, migration 008's composite
    /// `(parent_id, tenant_id)` foreign key on `cas` itself) and the API
    /// layer filters a sub-CA's named parent to the actor's tenant at
    /// `create_ca` — so this per-hop check is the third belt: a tampered or
    /// future-buggy write that slips both (or a future constraint change)
    /// cannot make the walk assemble another tenant's CA chain.
    ///
    /// A walk that has not reached a root within [`MAX_CHAIN_DEPTH`] hops
    /// (a corrupt `parent_id` loop in the data) is likewise
    /// [`CoreError::Config`] — data-level damage, not a per-request
    /// failure — and so is a missing mid-chain parent (a dangling
    /// `parent_id`): the walk refuses rather than silently truncating the
    /// chain it was asked to assemble.
    pub async fn chain_to_root(
        &self,
        executor: &mut sqlx::PgConnection,
        tenant_id: Uuid,
        ca_id: Uuid,
    ) -> Result<Vec<CaModel>, CoreError> {
        let mut chain = Vec::new();
        let mut current_id = ca_id;
        // `&mut *executor` reborrows the connection fresh for every hop.
        for _ in 0..MAX_CHAIN_DEPTH {
            let ca = self.get(&mut *executor, current_id).await?.ok_or_else(|| {
                CoreError::Config(format!("ca {current_id} is missing from its own chain"))
            })?;
            if ca.tenant_id != tenant_id {
                // Refuse on the id, not the row: the error never carries
                // the foreign CA's contents.
                return Err(CoreError::Config(format!(
                    "ca {current_id} is not in the requested tenant's chain"
                )));
            }
            let parent_id = ca.parent_id;
            chain.push(ca);
            match parent_id {
                None => return Ok(chain),
                Some(parent_id) => current_id = parent_id,
            }
        }
        Err(CoreError::Config(
            "ca chain exceeds depth or cycles".to_string(),
        ))
    }
}

impl CaRow {
    /// Decode a row into the domain model, mapping the `key_type` text through
    /// `KeyType::from_str`; an unknown stored value is a [`CoreError::Config`]
    /// (data-level corruption, not a per-request failure).
    fn try_into_model(self) -> Result<CaModel, CoreError> {
        let key_type = self
            .key_type
            .parse::<KeyType>()
            .map_err(|err| CoreError::Config(format!("invalid key_type in row: {err}")))?;
        Ok(CaModel {
            id: self.id,
            tenant_id: self.tenant_id,
            name: self.name,
            subject: self.subject,
            is_root: self.is_root,
            parent_id: self.parent_id,
            key_type,
            not_before: self.not_before,
            not_after: self.not_after,
            cert_pem: self.cert_pem,
            key_file: self.key_file,
            created_at: self.created_at,
        })
    }
}
