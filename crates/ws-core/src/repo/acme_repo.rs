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

/// An `acme_accounts` row joined with the count of the orders its account
/// placed (Plan 4 Task 10: the operator-visibility listing). The count is
/// EVERY order row the account owns, regardless of the order's status —
/// the operator asks "does this account have orders", not "how many are
/// alive" — and a `LEFT JOIN` keeps an orderless account in the listing at
/// zero.
#[derive(Debug, Clone, PartialEq)]
pub struct AcmeAccountWithOrders {
    /// The account row itself.
    pub account: AcmeAccountModel,
    /// How many `acme_orders` rows reference the account (any status).
    pub orders_count: i64,
}

/// Inline row shape for the accounts-with-order-counts join (see
/// [`AcmeRepo::list_accounts_with_order_counts`]): the account columns
/// verbatim plus the aggregate the `LEFT JOIN`'s `COUNT` computes. The
/// account fields replay through [`AcmeAccountRow`] so the two listings
/// decode the row exactly identically.
#[derive(sqlx::FromRow)]
struct AcmeAccountCountRow {
    id: Uuid,
    tenant_id: Uuid,
    jwk_thumbprint: String,
    jwk: JsonValue,
    status: String,
    tos_agreed_at: Option<DateTime<Utc>>,
    contact: Option<String>,
    created_at: DateTime<Utc>,
    orders_count: i64,
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

    /// Overwrite an account's contact (the account-update route; RFC 8555
    /// section 7.3.2). `None` clears the contact (an empty RFC `contact`
    /// array). A missing account updates zero rows and stays `Ok`.
    pub async fn set_account_contact(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        id: Uuid,
        contact: Option<&str>,
    ) -> Result<(), CoreError> {
        sqlx::query("UPDATE acme_accounts SET contact = $3 WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .bind(contact)
            .execute(executor)
            .await?;
        Ok(())
    }

    /// Stamp the ToS agreement (`tos_agreed_at`) — the ToS flow's
    /// promotion companion (`update_account_status` to `valid` carries the
    /// status change). Repeated writes are last-write-wins, so a client
    /// that re-agrees re-stamps the instant.
    pub async fn set_account_tos_agreed(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        id: Uuid,
        tos_agreed_at: DateTime<Utc>,
    ) -> Result<(), CoreError> {
        sqlx::query("UPDATE acme_accounts SET tos_agreed_at = $3 WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .bind(tos_agreed_at)
            .execute(executor)
            .await?;
        Ok(())
    }

    /// The account-key rollover (RFC 8555 section 7.3.6): overwrite the
    /// account row's key material with the NEW account key. THE ROW ID IS
    /// DELIBERATELY KEPT: orders and authorizations reference
    /// `acme_accounts.id`, so the atomic single-statement swap keeps every
    /// issued-certificate linkage intact, while the OLD thumbprint — the
    /// old kid's URL — stops resolving (the identity IS the key).
    /// A `Duplicate` here means the tenant already holds another account
    /// on the NEW key — the route maps it to a `malformed` problem
    /// document.
    pub async fn swap_account_key(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        id: Uuid,
        jwk: &JsonValue,
        jwk_thumbprint: &str,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "UPDATE acme_accounts SET jwk = $3, jwk_thumbprint = $4 \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(jwk)
        .bind(jwk_thumbprint)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// The deactivation cascade (spec settlement 9): a deactivated
    /// account's PENDING authorizations become `deactivated` and its OPEN
    /// (pending / ready / processing) orders become `invalid` with the
    /// given error text. Already-decided authorizations and issued
    /// certificates are untouched; the two returned counts are
    /// `(authorizations invalidated, orders invalidated)` for the routes'
    /// audit details. Repeated calls are no-ops (nothing left pending).
    ///
    /// Takes `&mut PgConnection` (a `&mut *tx` at the call sites) instead
    /// of the per-statement `impl PgExecutor`: the cascade runs TWO
    /// statements inside one transaction, and an `impl PgExecutor` param
    /// is consumed by the first `execute`.
    pub async fn deactivation_cascade(
        &self,
        executor: &mut sqlx::PgConnection,
        tenant_id: Uuid,
        account_id: Uuid,
        order_error: &str,
    ) -> Result<(u64, u64), CoreError> {
        let authorizations = sqlx::query(
            "UPDATE acme_authorizations SET status = $3 \
             WHERE tenant_id = $1 AND account_id = $2 AND status = $4",
        )
        .bind(tenant_id)
        .bind(account_id)
        .bind(AcmeAuthorizationStatus::Deactivated.as_str())
        .bind(AcmeAuthorizationStatus::Pending.as_str())
        .execute(&mut *executor)
        .await?
        .rows_affected();
        let orders = sqlx::query(
            "UPDATE acme_orders SET status = $3, error = $5 \
             WHERE tenant_id = $1 AND account_id = $2 \
               AND status IN ($4, $6, $7)",
        )
        .bind(tenant_id)
        .bind(account_id)
        .bind(AcmeOrderStatus::Invalid.as_str())
        .bind(AcmeOrderStatus::Pending.as_str())
        .bind(order_error)
        .bind(AcmeOrderStatus::Ready.as_str())
        .bind(AcmeOrderStatus::Processing.as_str())
        .execute(&mut *executor)
        .await?
        .rows_affected();
        Ok((authorizations, orders))
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

    /// The operator-visibility listing (Plan 4 Task 10): one page of the
    /// tenant's ACME accounts, newest first (`created_at DESC`, ties by
    /// `id`), each joined with the count of the orders its account placed
    /// ([`AcmeAccountWithOrders`]). LIMIT/OFFSET through the shared
    /// [`crate::repo::paging`] helper (clamped page size). THE TENANT IS
    /// LOAD-BEARING: the join's tenant predicate rides the `ON` clause so
    /// the COUNT can never pick up another tenant's order rows, and the
    /// top-level `WHERE` pins the listed accounts to the tenant alone.
    pub async fn list_accounts_with_order_counts(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        page: u32,
        page_size: u32,
    ) -> Result<Vec<AcmeAccountWithOrders>, CoreError> {
        let (limit, offset) = crate::repo::paging(page, page_size)?;
        let rows: Vec<AcmeAccountCountRow> = sqlx::query_as(
            "SELECT a.id, a.tenant_id, a.jwk_thumbprint, a.jwk, a.status, \
             a.tos_agreed_at, a.contact, a.created_at, COUNT(o.id) AS orders_count \
             FROM acme_accounts a \
             LEFT JOIN acme_orders o ON o.account_id = a.id AND o.tenant_id = a.tenant_id \
             WHERE a.tenant_id = $1 \
             GROUP BY a.id, a.tenant_id, a.jwk_thumbprint, a.jwk, a.status, \
                      a.tos_agreed_at, a.contact, a.created_at \
             ORDER BY a.created_at DESC, a.id LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(executor)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(AcmeAccountWithOrders {
                    account: AcmeAccountRow {
                        id: row.id,
                        tenant_id: row.tenant_id,
                        jwk_thumbprint: row.jwk_thumbprint,
                        jwk: row.jwk,
                        status: row.status,
                        tos_agreed_at: row.tos_agreed_at,
                        contact: row.contact,
                        created_at: row.created_at,
                    }
                    .try_into_model()?,
                    orders_count: row.orders_count,
                })
            })
            .collect()
    }

    /// The order an issued certificate came from (Plan 4 Task 10: the
    /// certificate-detail page's link back to its ACME order —
    /// `finalize` stamps `certificate_id`, so the lookup is
    /// certificate-keyed); `None` when the tenant holds no order on that
    /// certificate (a manually-issued or foreign certificate — the
    /// certificate id itself is NEVER cross-tenant here). THE TENANT IS
    /// LOAD-BEARING.
    pub async fn get_order_by_certificate(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        certificate_id: Uuid,
    ) -> Result<Option<AcmeOrderModel>, CoreError> {
        let row: Option<AcmeOrderRow> = sqlx::query_as(&format!(
            "{ORDER_COLUMNS} WHERE tenant_id = $1 AND certificate_id = $2"
        ))
        .bind(tenant_id)
        .bind(certificate_id)
        .fetch_optional(executor)
        .await?;
        row.map(AcmeOrderRow::try_into_model).transpose()
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

    /// Fetch an authorization by id (the authz-URL routes' ownership
    /// check: the account URL carrying the kid must match `account_id`);
    /// `None` when absent or not this tenant's. THE TENANT IS
    /// LOAD-BEARING.
    pub async fn get_authorization(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<AcmeAuthorizationModel>, CoreError> {
        let row: Option<AcmeAuthorizationRow> = sqlx::query_as(&format!(
            "{AUTHORIZATION_COLUMNS} WHERE tenant_id = $1 AND id = $2"
        ))
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(executor)
        .await?;
        row.map(AcmeAuthorizationRow::try_into_model).transpose()
    }

    /// The ORDER-SCOPED authorizations of one order, oldest first
    /// (`created_at`, `id` preserves the mint order deterministically) —
    /// the half of an order's `authorizations` array the order itself
    /// demanded. REUSED rows (`order_id IS NULL`) are NOT listed here:
    /// the routes find those per identifier through
    /// [`Self::valid_authorization_for`], since Task 2's design keeps a
    /// reused row's `order_id` NULL — no order owns the row it reused.
    pub async fn list_authorizations_by_order(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        order_id: Uuid,
    ) -> Result<Vec<AcmeAuthorizationModel>, CoreError> {
        let rows: Vec<AcmeAuthorizationRow> = sqlx::query_as(&format!(
            "{AUTHORIZATION_COLUMNS} WHERE tenant_id = $1 AND order_id = $2 \
             ORDER BY created_at, id"
        ))
        .bind(tenant_id)
        .bind(order_id)
        .fetch_all(executor)
        .await?;
        rows.into_iter()
            .map(AcmeAuthorizationRow::try_into_model)
            .collect()
    }

    /// Both of an authorization's challenge flavors, mint order preserved
    /// (`created_at`, `id`) — the authorization object's `challenges`
    /// array. THE TENANT IS LOAD-BEARING.
    pub async fn list_challenges_by_authorization(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        authorization_id: Uuid,
    ) -> Result<Vec<AcmeChallengeModel>, CoreError> {
        let rows: Vec<AcmeChallengeRow> = sqlx::query_as(&format!(
            "{CHALLENGE_COLUMNS} WHERE tenant_id = $1 AND authorization_id = $2 \
             ORDER BY created_at, id"
        ))
        .bind(tenant_id)
        .bind(authorization_id)
        .fetch_all(executor)
        .await?;
        rows.into_iter()
            .map(AcmeChallengeRow::try_into_model)
            .collect()
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

    /// Set an authorization's lifecycle status (Task 7's settlement
    /// transitions): the challenge route stamps `valid` (with the REUSE
    /// WINDOW's fresh `expires_at` — the 30-day account-level lifetime) or
    /// `invalid`, and the poll/POST paths stamp a pending row they found
    /// PAST its expiry as `expired`. `expires_at: Some` overwrites the
    /// stored expiry together with the status (set-what-you-pass);
    /// `None` leaves it untouched. A missing authorization updates zero
    /// rows and stays `Ok` — existence is the caller's ownership check.
    pub async fn update_authorization_status(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        id: Uuid,
        status: AcmeAuthorizationStatus,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "UPDATE acme_authorizations SET status = $3, \
             expires_at = COALESCE($4, expires_at) \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(status.as_str())
        .bind(expires_at)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Promote an order-scoped authorization to ACCOUNT-LEVEL
    /// (`order_id` NULL — the Task-2 row shape `valid_authorization_for`
    /// reuses): settlement D5's renewal criterion requires an ORGANICALLY
    /// settled row to be reusable by the account's NEXT order, and the
    /// lookup serves account-level rows only. Settlement (Task 7) runs
    /// this in the SAME transaction as the `valid` stamp, so a crash
    /// never leaves a half state — either both land or neither. A missing
    /// authorization updates zero rows and stays `Ok`; the caller guards
    /// the call to rows it JUST settled `valid` while they were
    /// order-scoped (an already account-level row must be left alone —
    /// there is no `order_id` to clear).
    pub async fn promote_authorization_to_account_level(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "UPDATE acme_authorizations SET order_id = NULL \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
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

    /// Record the CSR the finalize request carried on the order row (Plan 4
    /// Task 8): the `acme_orders.csr_pem` column stays NULL until the
    /// order's CSR is accepted, then holds the PEM the issuer signed. The
    /// caller runs this inside the SAME transaction as the `valid` status
    /// stamp (the finalize route's write-side contract: the CSR, the
    /// issued-certificate pointer, and the final status commit together or
    /// not at all). A missing id updates zero rows and stays `Ok` —
    /// existence is the caller's ownership check.
    pub async fn set_order_csr(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        id: Uuid,
        csr_pem: &str,
    ) -> Result<(), CoreError> {
        sqlx::query("UPDATE acme_orders SET csr_pem = $3 WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .bind(csr_pem)
            .execute(executor)
            .await?;
        Ok(())
    }
}
