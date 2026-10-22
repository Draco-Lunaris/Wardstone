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
