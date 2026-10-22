//! Repository over the ACME tables (migration 011): `acme_accounts`,
//! `acme_orders`, `acme_authorizations`, and `acme_challenges`.

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::error::CoreError;
use crate::models::acme::{
    AcmeAccountModel, AcmeAccountStatus, AcmeAuthorizationModel, AcmeAuthorizationStatus,
    AcmeChallengeModel, AcmeChallengeStatus, AcmeChallengeType, AcmeOrderModel, AcmeOrderStatus,
};
use crate::repo::tenant_repo::map_unique;

/// Data access for the ACME domain models ([`AcmeAccountModel`] and
/// friends).
///
/// Stateless by design: the repository holds no pool, and every method
/// takes `executor: impl PgExecutor<'_>` so a mutation and its audit row
/// can share one transaction (callers pass `&pool`, or `&mut *tx` inside a
/// transaction — `&mut Transaction` does not implement `PgExecutor` in
/// sqlx 0.8.6). Order/authorization/challenge minting runs in ONE
/// transaction by schema design (the composite foreign keys are deferred),
/// which is exactly what the executor-shaped methods admit.
#[derive(Default)]
pub struct AcmeRepo;

/// Inline row shape for `sqlx::query_as` (house style: hand-mapped);
/// `status`/`challenge_type` arrive as TEXT and decode through their
/// `FromStr`s (an unknown stored value is data-level damage and a
/// [`CoreError::Config`], not a per-request failure — the audit repo's
/// `try_into_model` idiom).
#[derive(sqlx::FromRow)]
struct AcmeAccountRow {
    id: Uuid,
    tenant_id: Uuid,
    jwk_thumbprint: String,
    jwk: JsonValue,
    status: String,
    tos_agreed_at: Option<DateTime<Utc>>,
    contact: Option<String>,
    created_at: DateTime<Utc>,
}

impl AcmeAccountRow {
    fn try_into_model(self) -> Result<AcmeAccountModel, CoreError> {
        let status = self
            .status
            .parse::<AcmeAccountStatus>()
            .map_err(|err| CoreError::Config(format!("invalid status in row: {err}")))?;
        Ok(AcmeAccountModel {
            id: self.id,
            tenant_id: self.tenant_id,
            jwk_thumbprint: self.jwk_thumbprint,
            jwk: self.jwk,
            status,
            tos_agreed_at: self.tos_agreed_at,
            contact: self.contact,
            created_at: self.created_at,
        })
    }
}

/// Inline row shape for an `acme_orders` row.
#[derive(sqlx::FromRow)]
struct AcmeOrderRow {
    id: Uuid,
    tenant_id: Uuid,
    account_id: Uuid,
    status: String,
    profile_name: String,
    identifiers: JsonValue,
    csr_pem: Option<String>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
    certificate_id: Option<Uuid>,
    error: Option<String>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

impl AcmeOrderRow {
    fn try_into_model(self) -> Result<AcmeOrderModel, CoreError> {
        let status = self
            .status
            .parse::<AcmeOrderStatus>()
            .map_err(|err| CoreError::Config(format!("invalid status in row: {err}")))?;
        Ok(AcmeOrderModel {
            id: self.id,
            tenant_id: self.tenant_id,
            account_id: self.account_id,
            status,
            profile_name: self.profile_name,
            identifiers: self.identifiers,
            csr_pem: self.csr_pem,
            not_before: self.not_before,
            not_after: self.not_after,
            certificate_id: self.certificate_id,
            error: self.error,
            expires_at: self.expires_at,
            created_at: self.created_at,
        })
    }
}

/// Inline row shape for an `acme_authorizations` row.
#[derive(sqlx::FromRow)]
struct AcmeAuthorizationRow {
    id: Uuid,
    tenant_id: Uuid,
    account_id: Uuid,
    identifier: String,
    status: String,
    expires_at: DateTime<Utc>,
    reused_from: Option<Uuid>,
    order_id: Option<Uuid>,
    created_at: DateTime<Utc>,
}

impl AcmeAuthorizationRow {
    fn try_into_model(self) -> Result<AcmeAuthorizationModel, CoreError> {
        let status = self
            .status
            .parse::<AcmeAuthorizationStatus>()
            .map_err(|err| CoreError::Config(format!("invalid status in row: {err}")))?;
        Ok(AcmeAuthorizationModel {
            id: self.id,
            tenant_id: self.tenant_id,
            account_id: self.account_id,
            identifier: self.identifier,
            status,
            expires_at: self.expires_at,
            reused_from: self.reused_from,
            order_id: self.order_id,
            created_at: self.created_at,
        })
    }
}

/// Inline row shape for an `acme_challenges` row.
#[derive(sqlx::FromRow)]
struct AcmeChallengeRow {
    id: Uuid,
    tenant_id: Uuid,
    authorization_id: Uuid,
    challenge_type: String,
    token: String,
    status: String,
    validated_at: Option<DateTime<Utc>>,
    error: Option<String>,
    created_at: DateTime<Utc>,
}

impl AcmeChallengeRow {
    fn try_into_model(self) -> Result<AcmeChallengeModel, CoreError> {
        let challenge_type = self
            .challenge_type
            .parse::<AcmeChallengeType>()
            .map_err(|err| CoreError::Config(format!("invalid challenge_type in row: {err}")))?;
        let status = self
            .status
            .parse::<AcmeChallengeStatus>()
            .map_err(|err| CoreError::Config(format!("invalid status in row: {err}")))?;
        Ok(AcmeChallengeModel {
            id: self.id,
            tenant_id: self.tenant_id,
            authorization_id: self.authorization_id,
            challenge_type,
            token: self.token,
            status,
            validated_at: self.validated_at,
            error: self.error,
            created_at: self.created_at,
        })
    }
}

const ACCOUNT_COLUMNS: &str = "SELECT id, tenant_id, jwk_thumbprint, jwk, status, \
     tos_agreed_at, contact, created_at FROM acme_accounts";
const ORDER_COLUMNS: &str = "SELECT id, tenant_id, account_id, status, profile_name, \
     identifiers, csr_pem, not_before, not_after, certificate_id, error, expires_at, \
     created_at FROM acme_orders";
const AUTHORIZATION_COLUMNS: &str = "SELECT id, tenant_id, account_id, identifier, status, \
     expires_at, reused_from, order_id, created_at FROM acme_authorizations";
const CHALLENGE_COLUMNS: &str = "SELECT id, tenant_id, authorization_id, challenge_type, \
     token, status, validated_at, error, created_at FROM acme_challenges";

impl AcmeRepo {
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

    /// Insert an ACME account row exactly as given (every field,
    /// `created_at` included). A repeat of an existing
    /// `(tenant_id, jwk_thumbprint)` is a typed [`CoreError::Duplicate`]
    /// — the routes map it to `new-account`'s return-the-existing-account
    /// flow. One insert-time foreign key (`account_id, tenant_id` ->
    /// `acme_accounts (id, tenant_id)`, deferred) pins the row to its
    /// account's tenant; children may only be minted in the SAME
    /// transaction as this row, or after it commits.
    pub async fn insert_account(
        &self,
        executor: impl PgExecutor<'_>,
        a: &AcmeAccountModel,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "INSERT INTO acme_accounts (id, tenant_id, jwk_thumbprint, jwk, status, \
             tos_agreed_at, contact, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(a.id)
        .bind(a.tenant_id)
        .bind(&a.jwk_thumbprint)
        .bind(&a.jwk)
        .bind(a.status.as_str())
        .bind(a.tos_agreed_at)
        .bind(&a.contact)
        .bind(a.created_at)
        .execute(executor)
        .await
        .map_err(map_unique)?;
        Ok(())
    }

    /// Fetch an account by its RFC 7638 thumbprint (the `new-account`
    /// idempotency lookup); `None` when absent. THE TENANT IS LOAD-BEARING:
    /// the same thumbprint may exist in two tenants, and the lookup may
    /// never cross the line.
    pub async fn get_account(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        jwk_thumbprint: &str,
    ) -> Result<Option<AcmeAccountModel>, CoreError> {
        let row: Option<AcmeAccountRow> = sqlx::query_as(&format!(
            "{ACCOUNT_COLUMNS} WHERE tenant_id = $1 AND jwk_thumbprint = $2"
        ))
        .bind(tenant_id)
        .bind(jwk_thumbprint)
        .fetch_optional(executor)
        .await?;
        row.map(AcmeAccountRow::try_into_model).transpose()
    }

    /// Fetch an account by id (the account-URL routes' ownership check);
    /// `None` when absent or not this tenant's.
    pub async fn get_account_by_id(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<AcmeAccountModel>, CoreError> {
        let row: Option<AcmeAccountRow> = sqlx::query_as(&format!(
            "{ACCOUNT_COLUMNS} WHERE tenant_id = $1 AND id = $2"
        ))
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(executor)
        .await?;
        row.map(AcmeAccountRow::try_into_model).transpose()
    }

    /// Set an account's lifecycle status (deactivation and the ToS flow's
    /// `pending` -> `valid` promotion). A missing account updates zero
    /// rows and stays `Ok` — existence is the caller's check; a repeated
    /// status is idempotent by construction.
    pub async fn update_account_status(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        id: Uuid,
        status: AcmeAccountStatus,
    ) -> Result<(), CoreError> {
        sqlx::query("UPDATE acme_accounts SET status = $3 WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .bind(status.as_str())
            .execute(executor)
            .await?;
        Ok(())
    }

    /// Insert an order row exactly as given (every field, `created_at`
    /// included). The composite foreign key
    /// `acme_orders_account_tenant_fk` is DEFERRABLE INITIALLY DEFERRED:
    /// the order and its authorizations mint in ONE transaction, in any
    /// statement order, and a cross-tenant pair is refused at COMMIT.
    pub async fn insert_order(
        &self,
        executor: impl PgExecutor<'_>,
        o: &AcmeOrderModel,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "INSERT INTO acme_orders (id, tenant_id, account_id, status, profile_name, \
             identifiers, csr_pem, not_before, not_after, certificate_id, error, \
             expires_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(o.id)
        .bind(o.tenant_id)
        .bind(o.account_id)
        .bind(o.status.as_str())
        .bind(&o.profile_name)
        .bind(&o.identifiers)
        .bind(&o.csr_pem)
        .bind(o.not_before)
        .bind(o.not_after)
        .bind(o.certificate_id)
        .bind(&o.error)
        .bind(o.expires_at)
        .bind(o.created_at)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Fetch an order by id (the order-URL routes' ownership check: the
    /// account URL carrying the kid must match `account_id`); `None` when
    /// absent or not this tenant's. THE TENANT IS LOAD-BEARING.
    pub async fn get_order(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<AcmeOrderModel>, CoreError> {
        let row: Option<AcmeOrderRow> =
            sqlx::query_as(&format!("{ORDER_COLUMNS} WHERE tenant_id = $1 AND id = $2"))
                .bind(tenant_id)
                .bind(id)
                .fetch_optional(executor)
                .await?;
        row.map(AcmeOrderRow::try_into_model).transpose()
    }

    /// An account's orders, one page at a time, newest first
    /// (`created_at DESC`, ties by `id` for stable output) — the
    /// account-URL's order listing. LIMIT/OFFSET through the shared
    /// [`crate::repo::paging`] helper (clamped page size).
    pub async fn list_orders_by_account(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        account_id: Uuid,
        page: u32,
        page_size: u32,
    ) -> Result<Vec<AcmeOrderModel>, CoreError> {
        let (limit, offset) = crate::repo::paging(page, page_size)?;
        let rows: Vec<AcmeOrderRow> = sqlx::query_as(&format!(
            "{ORDER_COLUMNS} WHERE tenant_id = $1 AND account_id = $2 \
             ORDER BY created_at DESC, id LIMIT $3 OFFSET $4"
        ))
        .bind(tenant_id)
        .bind(account_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(executor)
        .await?;
        rows.into_iter().map(AcmeOrderRow::try_into_model).collect()
    }

    /// The REUSE-WINDOW lookup: the newest `valid` ACCOUNT-LEVEL
    /// authorization (`order_id IS NULL`) on `identifier` whose
    /// `expires_at` still lies in the future at the caller's `now`.
    ///
    /// `now` is a parameter, not `now()` at the database: the route
    /// decides the window (30 days by plan pin) and tests inject the
    /// clock. `None` means "no valid reuse row" — the caller mints a new
    /// pending authorization. Newest first (`created_at DESC, id LIMIT 1`)
    /// so a re-validated identifier keeps extending the reused row's
    /// usability deterministically.
    pub async fn valid_authorization_for(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        account_id: Uuid,
        identifier: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AcmeAuthorizationModel>, CoreError> {
        let row: Option<AcmeAuthorizationRow> = sqlx::query_as(&format!(
            "{AUTHORIZATION_COLUMNS} \
             WHERE tenant_id = $1 AND account_id = $2 AND identifier = $3 \
               AND status = $4 AND order_id IS NULL AND expires_at > $5 \
             ORDER BY created_at DESC, id LIMIT 1"
        ))
        .bind(tenant_id)
        .bind(account_id)
        .bind(identifier)
        .bind(AcmeAuthorizationStatus::Valid.as_str())
        .bind(now)
        .fetch_optional(executor)
        .await?;
        row.map(AcmeAuthorizationRow::try_into_model).transpose()
    }

    /// Insert an authorization row exactly as given (every field,
    /// `created_at` included) — both shapes: an order-scoped row carries
    /// `order_id`, an account-level REUSED row carries `order_id: None`
    /// (and `reused_from` names the account-level original it was minted
    /// from). The composite foreign keys are deferred, so the order and
    /// its authorizations mint in ONE transaction in any statement order,
    /// and a cross-tenant pair is refused at COMMIT.
    pub async fn insert_authorization(
        &self,
        executor: impl PgExecutor<'_>,
        a: &AcmeAuthorizationModel,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "INSERT INTO acme_authorizations (id, tenant_id, account_id, identifier, \
             status, expires_at, reused_from, order_id, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(a.id)
        .bind(a.tenant_id)
        .bind(a.account_id)
        .bind(&a.identifier)
        .bind(a.status.as_str())
        .bind(a.expires_at)
        .bind(a.reused_from)
        .bind(a.order_id)
        .bind(a.created_at)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Insert a challenge row exactly as given (every field, `created_at`
    /// included). BOTH flavors (http-01 and dns-01) are minted per
    /// authorization; the client picks by requesting validation on one.
    /// The composite foreign key `acme_challenges_authorization_tenant_fk`
    /// is deferred, so the authorization and its challenges mint in ONE
    /// transaction, and a cross-tenant pair is refused at COMMIT.
    pub async fn insert_challenge(
        &self,
        executor: impl PgExecutor<'_>,
        c: &AcmeChallengeModel,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "INSERT INTO acme_challenges (id, tenant_id, authorization_id, challenge_type, \
             token, status, validated_at, error, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(c.id)
        .bind(c.tenant_id)
        .bind(c.authorization_id)
        .bind(c.challenge_type.as_str())
        .bind(&c.token)
        .bind(c.status.as_str())
        .bind(c.validated_at)
        .bind(&c.error)
        .bind(c.created_at)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Fetch a challenge by id (the challenge-URL routes' ownership
    /// check); `None` when absent or not this tenant's. THE TENANT IS
    /// LOAD-BEARING.
    pub async fn get_challenge(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<AcmeChallengeModel>, CoreError> {
        let row: Option<AcmeChallengeRow> = sqlx::query_as(&format!(
            "{CHALLENGE_COLUMNS} WHERE tenant_id = $1 AND id = $2"
        ))
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(executor)
        .await?;
        row.map(AcmeChallengeRow::try_into_model).transpose()
    }

    /// Set a challenge's validation outcome. A `valid` (or `invalid`)
    /// decision carries `validated_at = Some(...)` (the decision time) and
    /// `error` (`Some` for an `invalid` challenge's reason, `None` on
    /// success); `validated_at: None` is legal for the pre-validation
    /// `processing` bookkeeping. Repeated writes are last-write-wins: the
    /// routes treat a decided challenge as terminal upstream.
    pub async fn update_challenge_status(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        id: Uuid,
        status: AcmeChallengeStatus,
        validated_at: Option<DateTime<Utc>>,
        error: Option<&str>,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "UPDATE acme_challenges SET status = $3, validated_at = $4, error = $5 \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(status.as_str())
        .bind(validated_at)
        .bind(error)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Set an order's lifecycle status. The finalize path carries the
    /// issued certificate's id (`certificate_id`) on the `valid`
    /// transition; the invalidation path carries `error`. Both are
    /// SET-WHAT-YOU-PASS fields: pass `None` to leave them NULL (the
    /// `pending` -> `ready` promotion), pass `Some` to stamp them (the
    /// `valid`/`invalid` decisions). Repeated writes are last-write-wins;
    /// terminal transitions are the routes' state-machine duty.
    pub async fn update_order_status(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        id: Uuid,
        status: AcmeOrderStatus,
        certificate_id: Option<Uuid>,
        error: Option<&str>,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "UPDATE acme_orders SET status = $3, certificate_id = $4, error = $5 \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(status.as_str())
        .bind(certificate_id)
        .bind(error)
        .execute(executor)
        .await?;
        Ok(())
    }
}
