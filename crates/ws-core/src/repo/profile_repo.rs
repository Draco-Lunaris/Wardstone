//! Repository over the `profiles` and `profile_revisions` tables.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::error::CoreError;
use crate::models::profile::{ProfileModel, ProfileRevisionModel};
use crate::repo::tenant_repo::map_unique;

/// Data access for [`ProfileModel`] and [`ProfileRevisionModel`] rows.
///
/// Stateless by design: the repository holds no pool, and every method
/// takes `executor: impl PgExecutor<'_>` so a mutation and its audit row
/// can share one transaction (callers pass `&pool`, or `&mut *tx` inside a
/// transaction — `&mut Transaction` does not implement `PgExecutor` in
/// sqlx 0.8.6).
#[derive(Default)]
pub struct ProfileRepo;

/// Inline row shape for `sqlx::query_as` (house style: hand-mapped).
#[derive(sqlx::FromRow)]
struct ProfileRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    description: Option<String>,
    current_revision_id: Option<Uuid>,
    created_at: DateTime<Utc>,
}

impl From<ProfileRow> for ProfileModel {
    fn from(row: ProfileRow) -> Self {
        ProfileModel {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            description: row.description,
            current_revision_id: row.current_revision_id,
            created_at: row.created_at,
        }
    }
}

/// Inline row shape for a `profile_revisions` row.
#[derive(sqlx::FromRow)]
struct RevisionRow {
    id: Uuid,
    profile_id: Uuid,
    revision: i32,
    name: String,
    key_type: String,
    key_usages: Vec<String>,
    eku: Vec<String>,
    lifetime_days: i32,
    san_patterns: Vec<String>,
    is_legacy: bool,
    created_at: DateTime<Utc>,
    actor_id: String,
}

impl From<RevisionRow> for ProfileRevisionModel {
    fn from(row: RevisionRow) -> Self {
        ProfileRevisionModel {
            id: row.id,
            profile_id: row.profile_id,
            revision: row.revision,
            name: row.name,
            key_type: row.key_type,
            key_usages: row.key_usages,
            eku: row.eku,
            lifetime_days: row.lifetime_days,
            san_patterns: row.san_patterns,
            is_legacy: row.is_legacy,
            created_at: row.created_at,
            actor_id: row.actor_id,
        }
    }
}

const PROFILE_COLUMNS: &str =
    "SELECT id, tenant_id, name, description, current_revision_id, created_at FROM profiles";
const REVISION_COLUMNS: &str = "SELECT id, profile_id, revision, name, key_type, key_usages, \
     eku, lifetime_days, san_patterns, is_legacy, created_at, actor_id FROM profile_revisions";

impl ProfileRepo {
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

    /// Insert a profile row exactly as given (every field, `created_at`
    /// included). The schema's `profiles_current_revision_fk` is
    /// DEFERRABLE INITIALLY DEFERRED: the row may carry `current_revision_id`
    /// pointing at a revision inserted later in the SAME transaction, and
    /// must carry `None` (or a revision of another committed profile) if
    /// no such insert follows. A unique-violation on `(tenant_id, name)`
    /// becomes [`CoreError::Duplicate`].
    pub async fn insert_profile(
        &self,
        executor: impl PgExecutor<'_>,
        p: &ProfileModel,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "INSERT INTO profiles (id, tenant_id, name, description, current_revision_id, \
             created_at) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(p.id)
        .bind(p.tenant_id)
        .bind(&p.name)
        .bind(&p.description)
        .bind(p.current_revision_id)
        .bind(p.created_at)
        .execute(executor)
        .await
        .map_err(map_unique)?;
        Ok(())
    }

    /// Insert an immutable profile revision exactly as given (every
    /// field). A repeat of an existing `(profile_id, revision)` pair is a
    /// typed [`CoreError::Duplicate`] — revisions never change, and the
    /// number is the caller's optimistic versioning handle.
    pub async fn insert_revision(
        &self,
        executor: impl PgExecutor<'_>,
        r: &ProfileRevisionModel,
    ) -> Result<(), CoreError> {
        sqlx::query(
            "INSERT INTO profile_revisions (id, profile_id, revision, name, key_type, \
             key_usages, eku, lifetime_days, san_patterns, is_legacy, created_at, actor_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(r.id)
        .bind(r.profile_id)
        .bind(r.revision)
        .bind(&r.name)
        .bind(&r.key_type)
        .bind(&r.key_usages)
        .bind(&r.eku)
        .bind(r.lifetime_days)
        .bind(&r.san_patterns)
        .bind(r.is_legacy)
        .bind(r.created_at)
        .bind(&r.actor_id)
        .execute(executor)
        .await
        .map_err(map_unique)?;
        Ok(())
    }

    /// Fetch a profile by id; `None` when absent.
    pub async fn get_profile(
        &self,
        executor: impl PgExecutor<'_>,
        id: Uuid,
    ) -> Result<Option<ProfileModel>, CoreError> {
        let row: Option<ProfileRow> = sqlx::query_as(&format!("{PROFILE_COLUMNS} WHERE id = $1"))
            .bind(id)
            .fetch_optional(executor)
            .await?;
        Ok(row.map(Into::into))
    }

    /// Fetch a profile revision by id; `None` when absent. Old revisions
    /// stay retrievable for as long as certificates reference them.
    pub async fn get_revision(
        &self,
        executor: impl PgExecutor<'_>,
        id: Uuid,
    ) -> Result<Option<ProfileRevisionModel>, CoreError> {
        let row: Option<RevisionRow> = sqlx::query_as(&format!("{REVISION_COLUMNS} WHERE id = $1"))
            .bind(id)
            .fetch_optional(executor)
            .await?;
        Ok(row.map(Into::into))
    }

    /// The profile revision the profile currently points at; `None` when
    /// the profile has no revision yet.
    pub async fn current_revision(
        &self,
        executor: impl PgExecutor<'_>,
        profile_id: Uuid,
    ) -> Result<Option<ProfileRevisionModel>, CoreError> {
        let row: Option<RevisionRow> = sqlx::query_as(
            // Qualified columns: the JOIN's second table (profiles) makes
            // the unqualified revision column list ambiguous.
            "SELECT r.id, r.profile_id, r.revision, r.name, r.key_type, r.key_usages, \
             r.eku, r.lifetime_days, r.san_patterns, r.is_legacy, r.created_at, r.actor_id \
             FROM profile_revisions r JOIN profiles p ON p.current_revision_id = r.id \
             WHERE p.id = $1",
        )
        .bind(profile_id)
        .fetch_optional(executor)
        .await?;
        Ok(row.map(Into::into))
    }

    /// A tenant's profiles, one page at a time, name order for stable
    /// output (the shared [`crate::repo::paging`] helper: LIMIT/OFFSET,
    /// clamped page size).
    pub async fn list_by_tenant(
        &self,
        executor: impl PgExecutor<'_>,
        tenant_id: Uuid,
        page: u32,
        page_size: u32,
    ) -> Result<Vec<ProfileModel>, CoreError> {
        let (limit, offset) = crate::repo::paging(page, page_size)?;
        let rows: Vec<ProfileRow> = sqlx::query_as(&format!(
            "{PROFILE_COLUMNS} WHERE tenant_id = $1 ORDER BY name LIMIT $2 OFFSET $3"
        ))
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(executor)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// All of a profile's revisions, ascending by revision number (the
    /// immutable history; revision 1 first).
    pub async fn list_revisions(
        &self,
        executor: impl PgExecutor<'_>,
        profile_id: Uuid,
    ) -> Result<Vec<ProfileRevisionModel>, CoreError> {
        let rows: Vec<RevisionRow> = sqlx::query_as(&format!(
            "{REVISION_COLUMNS} WHERE profile_id = $1 ORDER BY revision"
        ))
        .bind(profile_id)
        .fetch_all(executor)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// The optimistic-concurrency write: repoint the profile to
    /// `new_revision_id` ONLY while its current pointer still equals
    /// `expected_current_revision_id`. `IS NOT DISTINCT FROM` makes a
    /// `None` expected value (a profile that has no revision yet) a real
    /// expectation, so first-repoint races are protected exactly like
    /// later ones.
    ///
    /// `Ok(())` only when the row was affected; a zero-row update means
    /// the revision moved under the caller (or the profile is gone) and
    /// the caller must re-read and retry — a typed
    /// [`CoreError::Config`], never a silent overwrite.
    pub async fn update(
        &self,
        executor: impl PgExecutor<'_>,
        profile_id: Uuid,
        expected_current_revision_id: Option<Uuid>,
        new_revision_id: Uuid,
    ) -> Result<(), CoreError> {
        let result = sqlx::query(
            "UPDATE profiles SET current_revision_id = $2 \
             WHERE id = $1 AND current_revision_id IS NOT DISTINCT FROM $3",
        )
        .bind(profile_id)
        .bind(new_revision_id)
        .bind(expected_current_revision_id)
        .execute(executor)
        .await?;
        if result.rows_affected() == 0 {
            return Err(CoreError::Config(format!(
                "profile {profile_id} did not have the expected current revision \
                 (moved or absent); re-read and retry"
            )));
        }
        Ok(())
    }

    /// Replace the profile's `description` — the edit-path write the PUT
    /// route runs INSIDE the same revision transaction as the repoint, so
    /// a saved description and its revision commit or roll back together.
    ///
    /// The stored value is normalized here, in exactly one place: a blank
    /// or empty string is stored as NULL, so "no description" round-trips
    /// as `null` instead of a phantom `""` (the route's response echoes the
    /// STORED value, which makes the normalization observable). `None`
    /// clears the column too. A missing profile row updates zero rows and
    /// stays `Ok` — existence is the caller's check.
    pub async fn set_description(
        &self,
        executor: impl PgExecutor<'_>,
        id: Uuid,
        description: Option<&str>,
    ) -> Result<(), CoreError> {
        let description = description.map(str::trim).filter(|d| !d.is_empty());
        sqlx::query("UPDATE profiles SET description = $2 WHERE id = $1")
            .bind(id)
            .bind(description)
            .execute(executor)
            .await?;
        Ok(())
    }

    /// Delete a profile. `profile_revisions` rows go with it
    /// (ON DELETE CASCADE); a revision a certificate still references
    /// keeps the certificate's FK holding, so deletion of a referenced
    /// profile is refused by the database — the caller has to repoint or
    /// keep its certificates first.
    pub async fn delete(&self, executor: impl PgExecutor<'_>, id: Uuid) -> Result<(), CoreError> {
        sqlx::query("DELETE FROM profiles WHERE id = $1")
            .bind(id)
            .execute(executor)
            .await?;
        Ok(())
    }

    /// The delete-refusal check: whether ANY certificate row still
    /// references a revision of this profile (active or revoked — history
    /// matters in a CA, so a revoked certificate pins its policy just as
    /// hard as a live one). `true` means [`ProfileRepo::delete`] would hit
    /// the `certificates.profile_revision_id` foreign key at COMMIT.
    ///
    /// The deletion route calls this inside the SAME transaction as the
    /// delete and refuses with its 409 BEFORE attempting the delete,
    /// rather than mapping the commit-time `23503` elsewhere: a count-
    /// then-delete under one transaction's snapshot gives the
    /// deterministic refusal message, does not depend on which constraint
    /// fired, and never conflates a foreign-key violation from some other
    /// statement with "referenced by certificates". The foreign key stays
    /// the physical backstop for the commit-time race.
    pub async fn is_referenced(
        &self,
        executor: impl PgExecutor<'_>,
        profile_id: Uuid,
    ) -> Result<bool, CoreError> {
        let row: Option<(i32,)> = sqlx::query_as(
            "SELECT 1 FROM certificates c \
             JOIN profile_revisions r ON c.profile_revision_id = r.id \
             WHERE r.profile_id = $1 \
             LIMIT 1",
        )
        .bind(profile_id)
        .fetch_optional(executor)
        .await?;
        Ok(row.is_some())
    }
}
