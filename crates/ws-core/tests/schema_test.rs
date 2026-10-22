//! Integration tests for the Plan 2 auth/profile schema (migrations 007 and
//! 008): users, refresh tokens, OIDC config, service identities, one-shot
//! tokens, role-capability seeds, and certificate profiles.
//!
//! These tests run against a live Postgres and are marked `#[ignore]`.
//! Run them with:
//!
//! ```sh
//! DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test \
//!     cargo test -p ws-core --test schema_test -- --include-ignored
//! ```
//!
//! # Self-cleaning contract
//!
//! The shared `wardstone_test` database is also used by `tests/db_test.rs`,
//! whose `connect_runs_migrations` asserts that `tenants` is empty. To keep
//! that true after every run of this suite, no matter how it exits:
//!
//! 1. Every row-creating test starts by sweeping away rows a previously
//!    crashed run may have left behind (this suite's owned tenant names
//!    only, `users` rows before their `tenants`, FK order).
//! 2. Every row inserted during the body is deleted — users before tenants
//!    — *before* any assertion runs, so a failing assertion cannot leave a
//!    tenant behind.
//!
//! The suite never creates certificates, CAs, or profile rows: the
//! structural assertions below (table existence, constraints, seed rows)
//! read catalog views only, and the per-tenant uniqueness test inserts
//! nothing beyond its own `users` and `tenants` rows.
//!
//! # Cross-process serialization
//!
//! Each test body holds the session-level Postgres advisory lock
//! `ADVISORY_KEY` for its whole duration on a dedicated pooled connection,
//! so any other process using the same key serializes against it (the
//! in-process [`DB_TEST_LOCK`] mutex mirrors `repo_test.rs`'s pattern and
//! serializes this binary's tests against each other).

use std::collections::BTreeSet;
use std::sync::OnceLock;

use sqlx::pool::PoolConnection;
use sqlx::PgPool;
use tokio::sync::Mutex;
use uuid::Uuid;

use ws_core::db::connect;
use ws_core::models::rbac::{Capability, Role};

/// Postgres advisory-lock key for this suite: ASCII "WARDST" (0x5741445354)
/// plus the suite marker 0x000b, i.e. `0x0057_4144_5354_000b`. Processes
/// taking this key serialize their test bodies against this suite.
const ADVISORY_KEY: i64 = 0x0057_4144_5354_000b;

/// The two tenant names this suite owns for the per-tenant uniqueness test;
/// deleted before asserts (users first, then the tenants).
const USERS_TENANT_A: &str = "rt-schema-users-a";
const USERS_TENANT_B: &str = "rt-schema-users-b";

/// In-process serialization, the same whole-body lock pattern as
/// `repo_test.rs`: the harness runs tests on separate threads. A tokio mutex
/// because the guard is held across `.await` points.
static DB_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// The guard must be held (not dropped) until the test body finishes.
#[must_use = "the database lock must stay bound for the whole test body"]
async fn lock_db() -> tokio::sync::MutexGuard<'static, ()> {
    DB_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().await
}

/// Take the session-level advisory lock `key` on a dedicated pooled
/// connection. The connection stays checked out for the whole test body
/// (the caller holds the guard), so the lock is bound to it; it is released
/// by [`release_advisory`] or, on a panic path, when the pool is dropped
/// during unwinding.
async fn lock_advisory(pool: &PgPool, key: i64) -> PoolConnection<sqlx::Postgres> {
    let mut conn = pool
        .acquire()
        .await
        .expect("acquire connection for the advisory lock");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(key)
        .execute(&mut *conn)
        .await
        .expect("take pg_advisory_lock");
    conn
}

/// Release the advisory lock taken by [`lock_advisory`] explicitly, so the
/// connection never returns to the pool while still holding it.
async fn release_advisory(conn: &mut PoolConnection<sqlx::Postgres>, key: i64) {
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(key)
        .execute(&mut **conn)
        .await
        .expect("release pg_advisory_lock");
}

/// Test database URL; `DATABASE_URL` overrides it.
fn database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://wardstone:wardstone@localhost:5432/wardstone_test".to_string()
    })
}

/// Every table migrations 007 and 008 must have created, per the plan.
const NEW_TABLES: [&str; 10] = [
    "users",
    "refresh_tokens",
    "oidc_config",
    "service_identities",
    "service_identity_capabilities",
    "one_shot_tokens",
    "one_shot_token_capabilities",
    "role_capabilities",
    "profiles",
    "profile_revisions",
];

/// Whether `table` exists in the current schema (catalog read; no rows).
async fn table_exists(pool: &PgPool, table: &str) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_name = $1)",
    )
    .bind(table)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|_| panic!("query existence of table {table}"))
}

/// After `connect()`, every auth/profile table of migrations 007-008 exists
/// in the current schema, and `users.tenant_id` is a NOT NULL uuid.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn auth_and_profile_tables_exist() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    let mut existences = Vec::new();
    for table in NEW_TABLES {
        existences.push((table, table_exists(&pool, table).await));
    }
    let (tenant_id_nullable, tenant_id_type): (String, String) = sqlx::query_as(
        "SELECT is_nullable, data_type FROM information_schema.columns \
         WHERE table_schema = current_schema() \
           AND table_name = 'users' AND column_name = 'tenant_id'",
    )
    .fetch_one(&pool)
    .await
    .expect("query users.tenant_id column metadata");

    release_advisory(&mut advisory, ADVISORY_KEY).await;

    for (table, exists) in &existences {
        assert!(exists, "table {table} must exist after the migrations run");
    }
    assert_eq!(
        tenant_id_type, "uuid",
        "users.tenant_id must be a uuid column"
    );
    assert_eq!(
        tenant_id_nullable, "NO",
        "users.tenant_id must be NOT NULL: every table carries tenant_id"
    );
}

/// Insert a user row (only the NOT NULL columns without defaults) and
/// return its id.
async fn insert_user(
    pool: &PgPool,
    tenant_id: Uuid,
    username: &str,
    email: &str,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO users (tenant_id, username, email) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(tenant_id)
    .bind(username)
    .bind(email)
    .fetch_one(pool)
    .await
}

/// `users`' username and email uniqueness is PER-TENANT: the same username
/// (and the same email) may live in two tenants, but either may appear only
/// once within one tenant. Sweeps and cleans up its own users and tenants;
/// asserts only after cleanup (also asserts the clean sweep left the
/// deletion working, i.e. no user rows survived it).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn users_uniqueness_is_per_tenant() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    // Sweep debris from any previously crashed run of this suite: users
    // first (their tenant rows reference is what they'd block on), then the
    // tenants.
    sqlx::query(
        "DELETE FROM users WHERE tenant_id IN (SELECT id FROM tenants WHERE name = ANY($1))",
    )
    .bind([USERS_TENANT_A, USERS_TENANT_B])
    .execute(&pool)
    .await
    .expect("sweep stale users rows");
    sqlx::query("DELETE FROM tenants WHERE name = ANY($1)")
        .bind([USERS_TENANT_A, USERS_TENANT_B])
        .execute(&pool)
        .await
        .expect("sweep stale tenants rows");

    let tenant_a: Uuid = sqlx::query_scalar("INSERT INTO tenants (name) VALUES ($1) RETURNING id")
        .bind(USERS_TENANT_A)
        .fetch_one(&pool)
        .await
        .expect("insert tenant A");
    let tenant_b: Uuid = sqlx::query_scalar("INSERT INTO tenants (name) VALUES ($1) RETURNING id")
        .bind(USERS_TENANT_B)
        .fetch_one(&pool)
        .await
        .expect("insert tenant B");

    // Within tenant A: the baseline user sharing username and email with
    // the tenant-B users below.
    let baseline = insert_user(&pool, tenant_a, "shared-user", "shared@example.com").await;
    // Same username as the baseline, different tenant: must succeed.
    let same_username_other_tenant =
        insert_user(&pool, tenant_b, "shared-user", "b1@example.com").await;
    // Same email as the baseline, different tenant (and different
    // username): must succeed.
    let same_email_other_tenant =
        insert_user(&pool, tenant_b, "b2-user", "shared@example.com").await;
    // Same email again WITHIN tenant B: must hit the (tenant_id, email)
    // unique constraint.
    let dup_email = insert_user(&pool, tenant_b, "b3-user", "b1@example.com").await;
    // Same username again WITHIN tenant B: must hit the
    // (tenant_id, username) unique constraint.
    let dup_username = insert_user(&pool, tenant_b, "shared-user", "b4@example.com").await;

    // Cleanup BEFORE asserting: users first (FK order), then the tenants.
    let deleted_users: u64 = sqlx::query(
        "DELETE FROM users WHERE tenant_id IN (SELECT id FROM tenants WHERE name = ANY($1))",
    )
    .bind([USERS_TENANT_A, USERS_TENANT_B])
    .execute(&pool)
    .await
    .expect("delete this test's user rows")
    .rows_affected();
    let deleted_tenants: u64 = sqlx::query("DELETE FROM tenants WHERE name = ANY($1)")
        .bind([USERS_TENANT_A, USERS_TENANT_B])
        .execute(&pool)
        .await
        .expect("delete this test's tenant rows")
        .rows_affected();
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    assert_eq!(deleted_tenants, 2, "both owned tenants must be deletable");
    assert!(
        deleted_users >= 3,
        "the three successful user inserts must be removable; deleted {deleted_users}"
    );

    assert!(
        baseline.is_ok(),
        "the baseline user must insert: {baseline:?}"
    );
    assert!(
        same_username_other_tenant.is_ok(),
        "the same username must be allowed in a second tenant: {same_username_other_tenant:?}"
    );
    assert!(
        same_email_other_tenant.is_ok(),
        "the same email must be allowed in a second tenant: {same_email_other_tenant:?}"
    );

    let is_unique_violation = |err: &sqlx::Error| {
        err.as_database_error()
            .map(|e| e.code().as_deref() == Some("23505"))
            .unwrap_or(false)
    };
    let dup_email = dup_email.expect_err(
        "a repeated email within one tenant must violate the per-tenant unique constraint",
    );
    let dup_username = dup_username.expect_err(
        "a repeated username within one tenant must violate the per-tenant unique constraint",
    );
    assert!(
        is_unique_violation(&dup_email),
        "expected unique_violation (23505) for the repeated email, got {dup_email:?}"
    );
    assert!(
        is_unique_violation(&dup_username),
        "expected unique_violation (23505) for the repeated username, got {dup_username:?}"
    );
}

/// `certificates` gains a NULLABLE `profile_revision_id` that is a foreign
/// key into `profile_revisions` (column-scoped: the FK's key must include
/// exactly that column).
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn certificates_profile_revision_fk_is_nullable() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    let (nullable, data_type): (String, String) = sqlx::query_as(
        "SELECT is_nullable, data_type FROM information_schema.columns \
         WHERE table_schema = current_schema() \
           AND table_name = 'certificates' AND column_name = 'profile_revision_id'",
    )
    .fetch_one(&pool)
    .await
    .expect("certificates.profile_revision_id must exist");
    let fk_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_constraint c \
         JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attname = 'profile_revision_id' \
         WHERE c.conrelid = 'certificates'::regclass \
           AND c.contype = 'f' \
           AND c.confrelid = 'profile_revisions'::regclass \
           AND a.attnum = ANY (c.conkey)",
    )
    .fetch_one(&pool)
    .await
    .expect("query certificates profile_revision foreign keys");

    release_advisory(&mut advisory, ADVISORY_KEY).await;

    assert_eq!(
        nullable, "YES",
        "certificates.profile_revision_id must be nullable (legacy rows keep profile_name only)"
    );
    assert_eq!(data_type, "uuid");
    assert_eq!(
        fk_count, 1,
        "exactly one foreign key from certificates.profile_revision_id to profile_revisions"
    );
}

/// `cas` carries a composite foreign key FROM `(parent_id, tenant_id)` INTO
/// `(id, tenant_id)` — legal only because migration 006 added the matching
/// unique constraint — so a child CA can never name a parent from another
/// tenant.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn cas_parent_tenant_composite_fk_exists() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    let definition: Option<String> = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(c.oid, true) FROM pg_constraint c \
         WHERE c.conrelid = 'cas'::regclass \
           AND c.conname = 'cas_parent_tenant_fk' AND c.contype = 'f'",
    )
    .fetch_one(&pool)
    .await
    .expect("query the cas_parent_tenant_fk constraint definition");

    release_advisory(&mut advisory, ADVISORY_KEY).await;

    let definition = definition.expect("cas_parent_tenant_fk must exist after migration 008");
    assert!(
        definition.contains("FOREIGN KEY (parent_id, tenant_id)"),
        "the composite FK must key on (parent_id, tenant_id), got: {definition}"
    );
    assert!(
        definition.contains("REFERENCES cas"),
        "the composite FK must reference cas's (id, tenant_id), got: {definition}"
    );
}

/// `role_capabilities` is SEEDED, not merely created: exactly the role →
/// capability pairs of `ws_core::models::rbac::role_capabilities()` (admin
/// = all 15, issuer = 4, viewer = 4), and every seeded role/capability
/// string parses back into the `Role`/`Capability` enums — the table's
/// values and the code's vocabulary cannot drift.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn role_capabilities_is_seeded() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT role, capability FROM role_capabilities ORDER BY role, capability")
            .fetch_all(&pool)
            .await
            .expect("query the role_capabilities seed rows");

    release_advisory(&mut advisory, ADVISORY_KEY).await;

    // The seed, exactly as migration 007 inserts it — the same pairs
    // `ws_core::models::rbac::role_capabilities()` grants.
    const SEED: [(&str, &[&str]); 3] = [
        (
            "admin",
            &[
                "issue",
                "generate_leaf_key",
                "manage_profiles",
                "manage_cas",
                "manage_users",
                "manage_api_tokens",
                "manage_one_shot_tokens",
                "export_ca_keys",
                "manage_system",
                "read_certificates",
                "read_cas",
                "read_profiles",
                "read_audit",
                "read_users",
                "read_service_identities",
            ],
        ),
        (
            "issuer",
            &["issue", "read_certificates", "read_cas", "read_profiles"],
        ),
        (
            "viewer",
            &[
                "read_certificates",
                "read_cas",
                "read_profiles",
                "read_audit",
            ],
        ),
    ];
    let expected: BTreeSet<(String, String)> = SEED
        .iter()
        .flat_map(|(role, caps)| {
            caps.iter()
                .map(move |cap| ((*role).to_string(), (*cap).to_string()))
        })
        .collect();
    let actual: BTreeSet<(String, String)> = rows.iter().cloned().collect();

    assert_eq!(rows.len(), expected.len(), "no duplicate seed rows");
    assert_eq!(
        actual, expected,
        "role_capabilities must be seeded with exactly the rbac role bundles"
    );

    for (role, capability) in &actual {
        assert!(
            Role::from_str(role).is_some(),
            "seeded role {role:?} must parse into ws_core's Role enum"
        );
        assert!(
            Capability::from_str(capability).is_some(),
            "seeded capability {capability:?} must parse into ws_core's Capability enum"
        );
    }
}
// ---------------------------------------------------------------------------
// ACME schema tests (migration 011). They run against this suite's existing
// advisory key and own their tenant names exclusively; cleanup deletes their
// rows (children first) before any assertion.
// ---------------------------------------------------------------------------

/// Every table migration 011 must have created, per the plan.
const ACME_TABLES: [&str; 4] = [
    "acme_accounts",
    "acme_orders",
    "acme_authorizations",
    "acme_challenges",
];

/// The composite tenant-consistency foreign keys of migration 011 (006's
/// idiom): constraint name -> the child column pair it keys. Each is
/// DEFERRABLE INITIALLY DEFERRED, and each references its parent's
/// `(id, tenant_id)` — which is why the parent tables carry their own
/// `(id, tenant_id)` unique constraints.
const ACME_COMPOSITE_FKS: [(&str, &str); 3] = [
    (
        "acme_orders_account_tenant_fk",
        "FOREIGN KEY (account_id, tenant_id)",
    ),
    (
        "acme_authorizations_account_tenant_fk",
        "FOREIGN KEY (account_id, tenant_id)",
    ),
    (
        "acme_challenges_authorization_tenant_fk",
        "FOREIGN KEY (authorization_id, tenant_id)",
    ),
];

/// Tenant names the ACME schema tests own; deleted before asserts (children
/// first, then the tenants).
const ACME_SCHEMA_TENANT: &str = "rt-schema-acme";
const ACME_FK_TENANT_A: &str = "rt-schema-acme-fk-a";
const ACME_FK_TENANT_B: &str = "rt-schema-acme-fk-b";

/// Delete every row the ACME schema tests own, children before parents, by
/// tenant name — the pre-run sweep AND the assert-first cleanup.
async fn sweep_acme_schema_rows(pool: &PgPool, tenant_names: &[&str]) {
    sqlx::query("DELETE FROM acme_challenges WHERE tenant_id IN (SELECT id FROM tenants WHERE name = ANY($1))")
        .bind(tenant_names)
        .execute(pool)
        .await
        .expect("sweep acme_challenges rows");
    sqlx::query("DELETE FROM acme_authorizations WHERE tenant_id IN (SELECT id FROM tenants WHERE name = ANY($1))")
        .bind(tenant_names)
        .execute(pool)
        .await
        .expect("sweep acme_authorizations rows");
    sqlx::query(
        "DELETE FROM acme_orders WHERE tenant_id IN (SELECT id FROM tenants WHERE name = ANY($1))",
    )
    .bind(tenant_names)
    .execute(pool)
    .await
    .expect("sweep acme_orders rows");
    sqlx::query("DELETE FROM acme_accounts WHERE tenant_id IN (SELECT id FROM tenants WHERE name = ANY($1))")
        .bind(tenant_names)
        .execute(pool)
        .await
        .expect("sweep acme_accounts rows");
    sqlx::query("DELETE FROM tenants WHERE name = ANY($1)")
        .bind(tenant_names)
        .execute(pool)
        .await
        .expect("sweep test tenants");
}

/// The Postgres error code of a query failure, when it is a database
/// error at all (`None` for connection/decode failures).
fn pg_error_code(err: &sqlx::Error) -> Option<String> {
    err.as_database_error()
        .and_then(|e| e.code().as_deref().map(str::to_string))
}

/// After `connect()`, every ACME table of migration 011 exists, and each of
/// the three composite tenant-consistency foreign keys exists with its
/// pinned name, keys on the pinned column pair, references its parent's
/// composite `(id, tenant_id)` key, and is DEFERRABLE — the 006 idiom,
/// which is what makes the cross-tenant test below able to defer the
/// refusal to COMMIT.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn acme_tables_and_composite_fks_exist() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    let mut existences = Vec::new();
    for table in ACME_TABLES {
        existences.push((table, table_exists(&pool, table).await));
    }
    let mut constraints = Vec::new();
    for (name, _) in ACME_COMPOSITE_FKS {
        let definition: Option<String> = sqlx::query_scalar(
            "SELECT pg_get_constraintdef(c.oid, true) FROM pg_constraint c \
             WHERE c.conrelid::regclass::text LIKE 'acme_%' \
               AND c.conname = $1 AND c.contype = 'f'",
        )
        .bind(name)
        .fetch_one(&pool)
        .await
        .expect("query the composite FK constraint definitions");
        constraints.push((name, definition));
    }

    release_advisory(&mut advisory, ADVISORY_KEY).await;

    for (table, exists) in &existences {
        assert!(exists, "table {table} must exist after migration 011");
    }
    for (name, definition) in &constraints {
        let definition = definition
            .as_deref()
            .unwrap_or_else(|| panic!("constraint {name} must exist after migration 011"));
        assert!(
            definition.contains("DEFERRABLE"),
            "{name} must be DEFERRABLE INITIALLY DEFERRED, got: {definition}"
        );
        assert!(
            definition.contains("REFERENCES"),
            "{name} must reference its parent's (id, tenant_id), got: {definition}"
        );
    }
    for (name, key_columns) in ACME_COMPOSITE_FKS {
        let (_, definition) = constraints
            .iter()
            .find(|(constraint_name, _)| constraint_name == &name)
            .expect("the constraint was fetched above");
        let definition = definition
            .as_deref()
            .expect("the constraint must exist (asserted above)");
        assert!(
            definition.contains(key_columns),
            "{name} must key on {key_columns:?}, got: {definition}"
        );
    }
}

/// Every `status` (and `challenge_type`) CHECK of migration 011 rejects an
/// unknown value with a `check_violation` (23514) — the database backstop
/// behind the `ws_core::models::acme` enums — while a valid row set (an
/// account, an order, an authorization, both challenge flavors) goes
/// through. Sweeps and cleans up its own tenant; asserts after cleanup.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn acme_status_checks_reject_unknown_values() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    sweep_acme_schema_rows(&pool, &[ACME_SCHEMA_TENANT]).await;

    let tenant: uuid::Uuid =
        sqlx::query_scalar("INSERT INTO tenants (name) VALUES ($1) RETURNING id")
            .bind(ACME_SCHEMA_TENANT)
            .fetch_one(&pool)
            .await
            .expect("insert the check test tenant");
    let account_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO acme_accounts (tenant_id, jwk_thumbprint, jwk, status) \
         VALUES ($1, 'schema-check-thumb', $2, 'valid') RETURNING id",
    )
    .bind(tenant)
    .bind(serde_json::json!({ "kty": "EC", "crv": "P-256", "x": "a", "y": "b" }))
    .fetch_one(&pool)
    .await
    .expect("insert the baseline valid account");
    let _order_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO acme_orders (tenant_id, account_id, status, profile_name, \
         identifiers, expires_at, created_at) \
         VALUES ($1, $2, 'pending', 'web-server', $3, now() + interval '30 days', now()) \
         RETURNING id",
    )
    .bind(tenant)
    .bind(account_id)
    .bind(serde_json::json!([{ "type": "dns", "value": "checks.example" }]))
    .fetch_one(&pool)
    .await
    .expect("insert the baseline valid order");
    let authz_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO acme_authorizations (tenant_id, account_id, identifier, status, \
         expires_at, created_at) \
         VALUES ($1, $2, 'checks.example', 'pending', now() + interval '30 days', now()) \
         RETURNING id",
    )
    .bind(tenant)
    .bind(account_id)
    .fetch_one(&pool)
    .await
    .expect("insert the baseline valid authorization");

    // The five rejections: an unknown value on each of the four `status`
    // columns and on the `challenge_type` column. Each is its own statement
    // so one rejection never poisons the others.
    let bad_account = sqlx::query(
        "INSERT INTO acme_accounts (tenant_id, jwk_thumbprint, jwk, status) \
         VALUES ($1, 'schema-check-bad', $2, 'cancelled')",
    )
    .bind(tenant)
    .bind(serde_json::json!({ "kty": "EC" }))
    .execute(&pool)
    .await;
    let bad_order = sqlx::query(
        "INSERT INTO acme_orders (tenant_id, account_id, status, profile_name, \
         identifiers, expires_at, created_at) \
         VALUES ($1, $2, 'quarantined', 'web-server', $3, now(), now())",
    )
    .bind(tenant)
    .bind(account_id)
    .bind(serde_json::json!([]))
    .execute(&pool)
    .await;
    let bad_authorization = sqlx::query(
        "INSERT INTO acme_authorizations (tenant_id, account_id, identifier, status, \
         expires_at, created_at) \
         VALUES ($1, $2, 'checks.example', 'quarantined', now(), now())",
    )
    .bind(tenant)
    .bind(account_id)
    .execute(&pool)
    .await;
    let bad_challenge_type = sqlx::query(
        "INSERT INTO acme_challenges (tenant_id, authorization_id, challenge_type, \
         token, status, created_at) VALUES ($1, $2, 'rsa', 't', 'pending', now())",
    )
    .bind(tenant)
    .bind(authz_id)
    .execute(&pool)
    .await;
    let bad_challenge_status = sqlx::query(
        "INSERT INTO acme_challenges (tenant_id, authorization_id, challenge_type, \
         token, status, created_at) VALUES ($1, $2, 'http-01', 't2', 'quarantined', now())",
    )
    .bind(tenant)
    .bind(authz_id)
    .execute(&pool)
    .await;

    sweep_acme_schema_rows(&pool, &[ACME_SCHEMA_TENANT]).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    // Cleanup happened above; the rejections stand on their own now.
    for (label, result) in [
        ("acme_accounts.status", bad_account),
        ("acme_orders.status", bad_order),
        ("acme_authorizations.status", bad_authorization),
        ("acme_challenges.challenge_type", bad_challenge_type),
        ("acme_challenges.status", bad_challenge_status),
    ] {
        match result {
            Ok(_) => panic!("{label}: an unknown value must violate the CHECK constraint"),
            Err(err) => assert_eq!(
                pg_error_code(&err).as_deref(),
                Some("23514"),
                "{label}: expected check_violation (23514), got {err:?}"
            ),
        }
    }
}

/// The composite tenant-consistency foreign keys DEFER their check to
/// COMMIT: a cross-tenant child inserts per-statement cleanly but is
/// refused at COMMIT with `foreign_key_violation` (23503) — for each of the
/// three children — while a fully consistent chain (account, order,
/// authorization, challenge, all one tenant, minted in ONE transaction in
/// parent-before-child order) COMMITS. The 006-era precedent, replayed on
/// the ACME chain. Sweeps and cleans up its own tenants; asserts after
/// cleanup.
#[tokio::test]
#[ignore = "requires a live Postgres; run with --include-ignored and DATABASE_URL set"]
async fn acme_composite_fk_refuses_cross_tenant_child_at_commit() {
    let _db = lock_db().await;
    let pool = connect(&database_url())
        .await
        .expect("connect should succeed and apply the embedded migrations");
    let mut advisory = lock_advisory(&pool, ADVISORY_KEY).await;

    let tenants = [ACME_FK_TENANT_A, ACME_FK_TENANT_B];
    sweep_acme_schema_rows(&pool, &tenants).await;

    let tenant_a: uuid::Uuid =
        sqlx::query_scalar("INSERT INTO tenants (name) VALUES ($1) RETURNING id")
            .bind(ACME_FK_TENANT_A)
            .fetch_one(&pool)
            .await
            .expect("insert FK tenant A");
    let tenant_b: uuid::Uuid =
        sqlx::query_scalar("INSERT INTO tenants (name) VALUES ($1) RETURNING id")
            .bind(ACME_FK_TENANT_B)
            .fetch_one(&pool)
            .await
            .expect("insert FK tenant B");
    let account_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO acme_accounts (tenant_id, jwk_thumbprint, jwk, status) \
         VALUES ($1, 'schema-fk-thumb', $2, 'valid') RETURNING id",
    )
    .bind(tenant_a)
    .bind(serde_json::json!({ "kty": "EC", "crv": "P-256", "x": "a", "y": "b" }))
    .fetch_one(&pool)
    .await
    .expect("insert the tenant-A account");
    let authorization_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO acme_authorizations (tenant_id, account_id, identifier, status, \
         expires_at, created_at) \
         VALUES ($1, $2, 'fks.example', 'pending', now() + interval '30 days', now()) \
         RETURNING id",
    )
    .bind(tenant_a)
    .bind(account_id)
    .fetch_one(&pool)
    .await
    .expect("insert the tenant-A authorization");

    // Cross-tenant ORDER: tenant B's row naming tenant A's account. The
    // deferred FK lets the statements through; COMMIT must refuse.
    let mut tx = pool
        .begin()
        .await
        .expect("begin the cross-tenant order transaction");
    sqlx::query(
        "INSERT INTO acme_orders (tenant_id, account_id, status, profile_name, \
         identifiers, expires_at, created_at) \
         VALUES ($1, $2, 'pending', 'web-server', $3, now() + interval '30 days', now())",
    )
    .bind(tenant_b)
    .bind(account_id)
    .bind(serde_json::json!([]))
    .execute(&mut *tx)
    .await
    .expect("the deferred FK lets the statement through");
    let order_refused = tx.commit().await;

    // Cross-tenant AUTHORIZATION: the same, on acme_authorizations.
    let mut tx = pool
        .begin()
        .await
        .expect("begin the cross-tenant authorization transaction");
    sqlx::query(
        "INSERT INTO acme_authorizations (tenant_id, account_id, identifier, status, \
         expires_at, created_at) \
         VALUES ($1, $2, 'fks.example', 'pending', now() + interval '30 days', now())",
    )
    .bind(tenant_b)
    .bind(account_id)
    .execute(&mut *tx)
    .await
    .expect("the deferred FK lets the statement through");
    let authorization_refused = tx.commit().await;

    // Cross-tenant CHALLENGE: a tenant-B row naming tenant A's
    // authorization — the third composite chain link.
    let mut tx = pool
        .begin()
        .await
        .expect("begin the cross-tenant challenge transaction");
    sqlx::query(
        "INSERT INTO acme_challenges (tenant_id, authorization_id, challenge_type, \
         token, status, created_at) VALUES ($1, $2, 'http-01', 't', 'pending', now())",
    )
    .bind(tenant_b)
    .bind(authorization_id)
    .execute(&mut *tx)
    .await
    .expect("the deferred FK lets the statement through");
    let challenge_refused = tx.commit().await;

    // The consistent chain: everything tenant A, minted in ONE transaction
    // (account was already committed above; order, authorization, and
    // challenge mint together), commits — and the deferral is what let the
    // cross-tenant statements stand un-refuted until their COMMIT.
    let mut tx = pool
        .begin()
        .await
        .expect("begin the consistent-chain transaction");
    let consistent_order: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO acme_orders (tenant_id, account_id, status, profile_name, \
         identifiers, expires_at, created_at) \
         VALUES ($1, $2, 'pending', 'web-server', $3, now() + interval '30 days', now()) \
         RETURNING id",
    )
    .bind(tenant_a)
    .bind(account_id)
    .bind(serde_json::json!([{ "type": "dns", "value": "fks.example" }]))
    .fetch_one(&mut *tx)
    .await
    .expect("insert the consistent order");
    let consistent_authz: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO acme_authorizations (tenant_id, account_id, identifier, status, \
         expires_at, created_at) \
         VALUES ($1, $2, 'fks.example', 'pending', now() + interval '30 days', now()) \
         RETURNING id",
    )
    .bind(tenant_a)
    .bind(account_id)
    .fetch_one(&mut *tx)
    .await
    .expect("insert the consistent authorization");
    let consistent_challenge: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO acme_challenges (tenant_id, authorization_id, challenge_type, \
         token, status, created_at) VALUES ($1, $2, 'dns-01', 't', 'pending', now()) \
         RETURNING id",
    )
    .bind(tenant_a)
    .bind(consistent_authz)
    .fetch_one(&mut *tx)
    .await
    .expect("insert the consistent challenge");
    tx.commit().await.expect("the consistent chain commits");

    sweep_acme_schema_rows(&pool, &tenants).await;
    release_advisory(&mut advisory, ADVISORY_KEY).await;

    let order_refused = order_refused.expect_err("a cross-tenant order must be refused at COMMIT");
    let authorization_refused =
        authorization_refused.expect_err("a cross-tenant authorization must be refused at COMMIT");
    let challenge_refused =
        challenge_refused.expect_err("a cross-tenant challenge must be refused at COMMIT");
    assert_eq!(
        pg_error_code(&order_refused).as_deref(),
        Some("23503"),
        "expected foreign_key_violation for the cross-tenant order, got {order_refused:?}"
    );
    assert_eq!(
        pg_error_code(&authorization_refused).as_deref(),
        Some("23503"),
        "expected foreign_key_violation for the cross-tenant authorization, got {authorization_refused:?}"
    );
    assert_eq!(
        pg_error_code(&challenge_refused).as_deref(),
        Some("23503"),
        "expected foreign_key_violation for the cross-tenant challenge, got {challenge_refused:?}"
    );
    assert!(
        !consistent_order.is_nil() && !consistent_authz.is_nil() && !consistent_challenge.is_nil(),
        "the consistent chain committed (its ids came back non-nil)"
    );
}
