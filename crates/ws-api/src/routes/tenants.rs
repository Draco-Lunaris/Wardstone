//! The tenant-creation route: `POST /api/v1/tenants`, `manage_system`.
//!
//! The tenant is created AND seeded with its built-in default profiles
//! (`ws_core::models::profile::default_profiles`, Task 2's) inside ONE
//! transaction; the `tenant_created` audit row commits with it. The
//! audit entry is recorded under the ACTING actor's tenant (this is the
//! log the acting tenant reads), while its target is the new tenant's id.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use ws_core::models::profile::ProfileModel;
use ws_core::models::rbac::Capability;
use ws_core::repo::audit_repo::AuditRepo;
use ws_core::repo::profile_repo::ProfileRepo;
use ws_core::repo::tenant_repo::TenantRepo;

use crate::auth_middleware::AuthActor;
use crate::error::ApiError;
use crate::routes::audit_entry;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", post(create_tenant))
}

/// The create body: the tenant name, its default domain (the built-in
/// profiles' subject ground), and the domain CIDRs the profiles permit.
#[derive(Debug, Deserialize)]
pub struct CreateTenantBody {
    pub name: String,
    pub domain: String,
    #[serde(default)]
    pub domain_cidrs: Vec<String>,
}

/// The create response.
#[derive(Debug, Serialize)]
pub struct TenantCreated {
    pub id: Uuid,
    pub name: String,
    /// How many built-in default profiles were seeded (always 2: the
    /// `web-server` RSA and ECDSA pair).
    pub seeded_profiles: usize,
}

/// `POST /api/v1/tenants` — `manage_system`.
async fn create_tenant(
    auth: AuthActor,
    State(state): State<AppState>,
    Json(body): Json<CreateTenantBody>,
) -> Result<(StatusCode, Json<TenantCreated>), ApiError> {
    auth.require(Capability::ManageSystem)
        .map_err(ApiError::from)?;
    let name = body.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("a tenant name is required"));
    }
    let domain = body.domain.trim();
    if domain.is_empty() {
        return Err(ApiError::bad_request("a default domain is required"));
    }

    let templates = ws_core::models::profile::default_profiles(domain, &body.domain_cidrs);
    let repos = ProfileRepo::new();

    let mut tx = state.pool.begin().await?;
    let tenant = TenantRepo::new().insert(&mut *tx, name).await?;
    for template in &templates {
        let profile_id = Uuid::new_v4();
        repos
            .insert_profile(
                &mut *tx,
                &ProfileModel {
                    id: profile_id,
                    tenant_id: tenant.id,
                    name: template.name.clone(),
                    description: Some(format!("Built-in default profile for {domain}")),
                    current_revision_id: None,
                    created_at: Utc::now(),
                },
            )
            .await?;
        // The template fills its own revision number / id / created_at.
        let revision = template.template_for(profile_id, 1, Uuid::new_v4());
        repos.insert_revision(&mut *tx, &revision).await?;
        repos
            .update(&mut *tx, profile_id, None, revision.id)
            .await?;
    }
    AuditRepo::new()
        .record(
            &mut *tx,
            &audit_entry(
                &auth.0,
                "tenant_created",
                "tenant",
                &tenant.id.to_string(),
                serde_json::json!({}),
            ),
        )
        .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(TenantCreated {
            id: tenant.id,
            name: tenant.name,
            seeded_profiles: templates.len(),
        }),
    ))
}
