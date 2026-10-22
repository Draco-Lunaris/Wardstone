//! The certificate-profile routes: create (profile + first revision),
//! update (append a revision + repoint), and the reads.
//!
//! Route capabilities (the plan's table): the reads are `read_profiles`
//! and the mutations `manage_profiles`. The SAN patterns a profile
//! stores are validated with `ws_core::profile_match` — a `*.` pattern
//! (the fail-closed case Task 10 fixes) is refused at creation time, so
//! no profile with an open-ended wildcard ever reaches the issuance hot
//! path.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use ws_ca::issue::ExtKeyUsagePurpose;
use ws_core::models::profile::{ProfileModel, ProfileRevisionModel};
use ws_core::models::rbac::{Capability, KeyUsagePurpose};
use ws_core::profile_match::san_is_permitted;
use ws_core::repo::audit_repo::AuditRepo;
use ws_core::repo::profile_repo::ProfileRepo;

use crate::auth_middleware::AuthActor;
use crate::error::ApiError;
use crate::routes::{audit_entry, ListQuery};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_profile).get(list_profiles))
        .route(
            "/{id}",
            get(get_profile).put(update_profile).delete(delete_profile),
        )
        .route("/{id}/revisions", get(list_revisions))
}

/// The profile policy body (create carries `name`; update revises the
/// policy of an existing profile and keeps its name).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProfileBody {
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Leaf key type pin (`rsa2048`, `ecdsa-p256`, ...).
    pub key_type: String,
    /// Key usages as the shared vocabulary's spellings.
    #[serde(default)]
    pub key_usages: Vec<String>,
    /// Extended key usages as RFC 5280 snake_case names.
    #[serde(default)]
    pub eku: Vec<String>,
    /// Certificate lifetime in days.
    pub lifetime_days: i32,
    /// SAN patterns matched by `ws_core::profile_match`.
    #[serde(default)]
    pub san_patterns: Vec<String>,
}

/// One profile revision, as a DTO.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RevisionResponse {
    pub id: Uuid,
    pub profile_id: Uuid,
    pub revision: i32,
    pub name: String,
    pub key_type: String,
    pub key_usages: Vec<String>,
    pub eku: Vec<String>,
    pub lifetime_days: i32,
    pub san_patterns: Vec<String>,
    pub is_legacy: bool,
    pub actor_id: String,
    pub created_at: chrono::DateTime<Utc>,
}

impl RevisionResponse {
    pub fn of(revision: &ProfileRevisionModel) -> Self {
        RevisionResponse {
            id: revision.id,
            profile_id: revision.profile_id,
            revision: revision.revision,
            name: revision.name.clone(),
            key_type: revision.key_type.clone(),
            key_usages: revision.key_usages.clone(),
            eku: revision.eku.clone(),
            lifetime_days: revision.lifetime_days,
            san_patterns: revision.san_patterns.clone(),
            is_legacy: revision.is_legacy,
            actor_id: revision.actor_id.clone(),
            created_at: revision.created_at,
        }
    }
}

/// One profile and its current revision.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ProfileResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub current_revision: Option<RevisionResponse>,
    pub created_at: chrono::DateTime<Utc>,
}

/// Validate the policy fields of a create/update body: an unknown key
/// usage/EKU spelling, an unparsable SAN pattern (including the fail-
/// closed `*.`), a non-positive lifetime, or empty lists are 400s.
fn validate_policy(body: &ProfileBody) -> Result<(), ApiError> {
    if body.key_usages.is_empty() {
        return Err(ApiError::bad_request(
            "a profile must pin at least one key usage (an absent keyUsage extension is \
             MORE permissive than any pinned list)",
        ));
    }
    for usage in &body.key_usages {
        KeyUsagePurpose::from_str(usage)
            .ok_or_else(|| ApiError::bad_request(format!("unknown key usage {usage:?}")))?;
    }
    if body.eku.is_empty() {
        return Err(ApiError::bad_request(
            "a profile must pin at least one extended key usage (an absent EKU extension is \
             MORE permissive than any pinned list)",
        ));
    }
    for eku in &body.eku {
        ExtKeyUsagePurpose::from_str(eku)
            .ok_or_else(|| ApiError::bad_request(format!("unknown extended key usage {eku:?}")))?;
    }
    if body.lifetime_days < 1 {
        return Err(ApiError::bad_request(
            "a profile's lifetime must be at least one day",
        ));
    }
    if body.san_patterns.is_empty() {
        return Err(ApiError::bad_request(
            "a profile must pin at least one san pattern",
        ));
    }
    for pattern in &body.san_patterns {
        // A parse check needs a concrete name to test against; the ANSWER
        // is irrelevant here — only "does the pattern classify at all"
        // matters (`Ok` = parsable, `Err` = data damage). A `*.` pattern
        // (Task 10's fail-closed fix) lands here as a 400, never stored.
        san_is_permitted(std::slice::from_ref(pattern), "example.test").map_err(|_| {
            ApiError::bad_request(format!(
                "unparsable san pattern {pattern:?} (a wildcard must be exactly `*` or \
                 `*.<labels>`, and a CIDR must parse)"
            ))
        })?;
    }
    Ok(())
}

/// The revision row this body produces (create: revision 1; update: the
/// next number), with the acting actor recorded.
fn revision_for(
    body: &ProfileBody,
    profile_id: Uuid,
    profile_name: &str,
    revision_number: i32,
    actor_id: &str,
) -> Result<ProfileRevisionModel, ApiError> {
    Ok(ProfileRevisionModel {
        id: Uuid::new_v4(),
        profile_id,
        revision: revision_number,
        name: profile_name.to_string(),
        key_type: body.key_type.clone(),
        key_usages: body.key_usages.clone(),
        eku: body.eku.clone(),
        lifetime_days: body.lifetime_days,
        san_patterns: body.san_patterns.clone(),
        is_legacy: false,
        created_at: Utc::now(),
        actor_id: actor_id.to_string(),
    })
}

/// `POST /api/v1/profiles` — `manage_profiles`. Creates the profile and
/// its FIRST revision, pointing the profile at it inside one transaction
/// (the `profiles_current_revision_fk` is DEFERRABLE INITIALLY DEFERRED
/// for exactly this shape), and writes the `profile_created` audit row in
/// that same transaction.
async fn create_profile(
    auth: AuthActor,
    State(state): State<AppState>,
    Json(body): Json<ProfileBody>,
) -> Result<(StatusCode, Json<ProfileResponse>), ApiError> {
    auth.require(Capability::ManageProfiles)
        .map_err(ApiError::from)?;
    let name = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| ApiError::bad_request("a profile name is required"))?;
    validate_policy(&body)?;

    let profile_id = Uuid::new_v4();
    let revision = revision_for(&body, profile_id, name, 1, &auth.actor_id)?;

    let mut tx = state.pool.begin().await?;
    let repos = ProfileRepo::new();
    repos
        .insert_profile(
            &mut *tx,
            &ProfileModel {
                id: profile_id,
                tenant_id: auth.tenant_id,
                name: name.to_string(),
                description: body.description.clone(),
                current_revision_id: None,
                created_at: Utc::now(),
            },
        )
        .await?;
    repos.insert_revision(&mut *tx, &revision).await?;
    // Repoint: the deferrable FK makes profile+revision+pointer commit
    // atomically.
    repos
        .update(&mut *tx, profile_id, None, revision.id)
        .await?;
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &auth.0,
                "profile_created",
                "profile",
                &profile_id.to_string(),
                serde_json::json!({ "revision": 1 }),
            ),
        )
        .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(ProfileResponse {
            id: profile_id,
            tenant_id: auth.tenant_id,
            name: name.to_string(),
            description: body.description.clone(),
            current_revision: Some(RevisionResponse::of(&revision)),
            created_at: revision.created_at,
        }),
    ))
}

/// `PUT /api/v1/profiles/{id}` — `manage_profiles`. Appends a NEW
/// immutable revision and repoints `current_revision_id` with the
/// conditional write (Task 5): a concurrent edit elsewhere collapses the
/// repoint to zero rows and this request fails 409 (retry-safe — the
/// caller re-reads). The `profile_revised` audit row commits with the
/// repoint.
async fn update_profile(
    auth: AuthActor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<ProfileBody>,
) -> Result<Json<ProfileResponse>, ApiError> {
    auth.require(Capability::ManageProfiles)
        .map_err(ApiError::from)?;
    validate_policy(&body)?;

    let repos = ProfileRepo::new();
    let profile = repos
        .get_profile(&state.pool, id)
        .await?
        .filter(|profile| profile.tenant_id == auth.tenant_id)
        .ok_or_else(|| ApiError::NotFound("profile not found".to_string()))?;
    let current = repos
        .current_revision(&state.pool, id)
        .await?
        .ok_or_else(|| {
            ApiError::Conflict(format!(
                "profile {:?} has no revision to revise",
                profile.name
            ))
        })?;
    let revision = revision_for(
        &body,
        id,
        &profile.name,
        current.revision + 1,
        &auth.actor_id,
    )?;

    let mut tx = state.pool.begin().await?;
    repos.insert_revision(&mut *tx, &revision).await?;
    match repos
        .update(&mut *tx, id, Some(current.id), revision.id)
        .await
    {
        Ok(()) => {
            AuditRepo::new()
                .record(
                    &mut *tx,
                    &audit_entry(
                        &auth.0,
                        "profile_revised",
                        "profile",
                        &id.to_string(),
                        serde_json::json!({ "revision": revision.revision }),
                    ),
                )
                .await?;
        }
        Err(ws_core::error::CoreError::Config(_)) => {
            // The conditional write moved under us: a typed Conflict (the
            // caller retries), nothing recorded.
            return Err(ApiError::Conflict(
                "the profile was edited concurrently; re-read and retry".to_string(),
            ));
        }
        Err(e) => return Err(ApiError::from(e)),
    }
    tx.commit().await?;

    Ok(Json(ProfileResponse {
        id,
        tenant_id: auth.tenant_id,
        name: profile.name,
        description: body.description,
        current_revision: Some(RevisionResponse::of(&revision)),
        created_at: revision.created_at,
    }))
}

/// `DELETE /api/v1/profiles/{id}` — `manage_profiles`. Deletes the
/// profile (its `profile_revisions` rows go ON DELETE CASCADE) and writes
/// the `profile_deleted` audit row in the SAME transaction.
///
/// The refusal is an explicit pre-read, not a mapped foreign-key error:
/// while ANY certificate (active or revoked — history matters in a CA,
/// and a revoked certificate pins its policy revision the same as a live
/// one) references a revision of the profile, the deletion is refused
/// `409` with the fixed message, BEFORE the delete is attempted.
/// [`ProfileRepo::is_referenced`] runs inside the SAME transaction as the
/// delete, so a certificate issued concurrently is either visible to the
/// check or blocked behind its row locks; the `certificates`
/// `.profile_revision_id` foreign key that migration 008 carries stays
/// the physical backstop against a commit-time race (a violation there
/// surfaces as `CoreError::Database` → 500, a server-side data-shape
/// event, never a silent delete). Another tenant's profile is a 404,
/// indistinguishable from an absent one.
async fn delete_profile(
    auth: AuthActor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    auth.require(Capability::ManageProfiles)
        .map_err(ApiError::from)?;

    let mut tx = state.pool.begin().await?;
    let repos = ProfileRepo::new();
    // Tenant-scoped read inside the transaction: the name feeds the audit
    // row, and the tenant filter folds the 404s together.
    let profile = repos
        .get_profile(&mut *tx, id)
        .await?
        .filter(|profile| profile.tenant_id == auth.tenant_id)
        .ok_or_else(|| ApiError::NotFound("profile not found".to_string()))?;
    if repos.is_referenced(&mut *tx, id).await? {
        return Err(ApiError::Conflict(
            "profile is referenced by certificates and cannot be deleted".to_string(),
        ));
    }
    repos.delete(&mut *tx, id).await?;
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &auth.0,
                "profile_deleted",
                "profile",
                &id.to_string(),
                serde_json::json!({ "name": profile.name }),
            ),
        )
        .await?;
    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/profiles` — `read_profiles`.
async fn list_profiles(
    auth: AuthActor,
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<ProfileResponse>>, ApiError> {
    auth.require(Capability::ReadProfiles)
        .map_err(ApiError::from)?;
    let profiles = ProfileRepo::new()
        .list_by_tenant(&state.pool, auth.tenant_id, query.page(), query.page_size())
        .await?
        .into_iter()
        .map(|profile| ProfileResponse {
            id: profile.id,
            tenant_id: profile.tenant_id,
            name: profile.name,
            description: profile.description,
            current_revision: None,
            created_at: profile.created_at,
        })
        .collect();
    Ok(Json(profiles))
}

/// `GET /api/v1/profiles/{id}` — `read_profiles`; another tenant's
/// profile is a 404, and the response carries the CURRENT revision.
async fn get_profile(
    auth: AuthActor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ProfileResponse>, ApiError> {
    auth.require(Capability::ReadProfiles)
        .map_err(ApiError::from)?;
    let repos = ProfileRepo::new();
    let profile = repos
        .get_profile(&state.pool, id)
        .await?
        .filter(|profile| profile.tenant_id == auth.tenant_id)
        .ok_or_else(|| ApiError::NotFound("profile not found".to_string()))?;
    let current = repos.current_revision(&state.pool, id).await?;
    Ok(Json(ProfileResponse {
        id: profile.id,
        tenant_id: profile.tenant_id,
        name: profile.name,
        description: profile.description,
        current_revision: current.as_ref().map(RevisionResponse::of),
        created_at: profile.created_at,
    }))
}

/// `GET /api/v1/profiles/{id}/revisions` — `read_profiles`. The
/// immutable history, ascending.
async fn list_revisions(
    auth: AuthActor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<RevisionResponse>>, ApiError> {
    auth.require(Capability::ReadProfiles)
        .map_err(ApiError::from)?;
    let profile = ProfileRepo::new()
        .get_profile(&state.pool, id)
        .await?
        .filter(|profile| profile.tenant_id == auth.tenant_id)
        .ok_or_else(|| ApiError::NotFound("profile not found".to_string()))?;
    let revisions = ProfileRepo::new()
        .list_revisions(&state.pool, profile.id)
        .await?
        .iter()
        .map(RevisionResponse::of)
        .collect();
    Ok(Json(revisions))
}
