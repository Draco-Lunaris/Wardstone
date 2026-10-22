//! Repository over the `role_capabilities` table — the runtime authority
//! for a role's capability bundle.

use sqlx::PgExecutor;

use crate::error::CoreError;
use crate::models::rbac::{role_capabilities, Capability, Role};

/// Data access for the `role_capabilities` table.
///
/// Stateless by design: the repository holds no pool, and every method
/// takes `executor: impl PgExecutor<'_>` (callers pass `&pool`, or
/// `&mut *tx` inside a transaction). The table is seeded by migration
/// 007, so a fresh database is never in a state where every role resolves
/// to no capabilities; this repo reads it and restores its defaults.
#[derive(Default)]
pub struct RoleRepo;

impl RoleRepo {
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

    /// A role's capability bundle, read from the `role_capabilities`
    /// table. The table is the runtime authority: an operator who edits
    /// it (e.g. to tighten or hand out one capability) changes what
    /// roles resolve to, where [`crate::models::rbac::role_capabilities`]
    /// is only the pin the seed is written from.
    ///
    /// An unknown stored spelling is data-level damage and a
    /// [`CoreError::Config`], not a silently narrower bundle.
    pub async fn capabilities_for_role(
        &self,
        executor: impl PgExecutor<'_>,
        role: Role,
    ) -> Result<Vec<Capability>, CoreError> {
        let raw: Vec<String> = sqlx::query_scalar(
            "SELECT capability FROM role_capabilities WHERE role = $1 ORDER BY capability",
        )
        .bind(role.as_str())
        .fetch_all(executor)
        .await?;

        raw.into_iter()
            .map(|c| {
                Capability::from_str(&c).ok_or_else(|| {
                    CoreError::Config(format!(
                        "invalid capability in role_capabilities row for \
                         {role:?}: {c:?}"
                    ))
                })
            })
            .collect()
    }

    /// Write the default bundles of
    /// [`crate::models::rbac::role_capabilities`] into the table, in ONE
    /// statement (parallel-array UNNEST, the two arrays pairwise
    /// aligned), idempotent via `ON CONFLICT (role, capability) DO
    /// NOTHING`: the migration seeds the table, and this method exists
    /// for an operator who edited it by hand and wants the defaults
    /// back — re-running never adds a second row for a pair already
    /// granted.
    pub async fn seed_role_capabilities(
        &self,
        executor: impl PgExecutor<'_>,
    ) -> Result<(), CoreError> {
        let mut roles: Vec<&str> = Vec::new();
        let mut caps: Vec<&str> = Vec::new();
        for role in [Role::Admin, Role::Issuer, Role::Viewer] {
            for cap in role_capabilities(role) {
                roles.push(role.as_str());
                caps.push(cap.as_str());
            }
        }

        sqlx::query(
            "INSERT INTO role_capabilities (role, capability) \
             SELECT r, c FROM UNNEST($1 ::text[], $2 ::text[]) AS t(r, c) \
             ON CONFLICT (role, capability) DO NOTHING",
        )
        .bind(&roles)
        .bind(&caps)
        .execute(executor)
        .await?;
        Ok(())
    }
}
