//! The first-run setup: the setup page (GET), the setup submit (POST),
//! the bootstrap transaction [`run_setup`], and the setup TLS certificate
//! ([`tls`]).
//!
//! # Mounting contract (the Review Focus item 5)
//!
//! The setup endpoint is NOT ROUTED once the tenant exists — not merely
//! refused. [`setup_router`] is mounted by [`crate::web_router`] only
//! while [`tenant_exists`] is false; with the tenant present the
//! composition mounts [`setup_unmounted_router`] instead — GET and POST
//! `/setup` are explicit, plain 404s, NOT left to the SPA fallback (which
//! would answer the extension-less path with the UI document, i.e. the
//! endpoint would not actually be unrouted). The binary (Task 12) and
//! this crate's own composition perform the same check at startup.
//!
//! # The TLS switch
//!
//! The setup page is HTTPS from the start, on the self-signed setup
//! certificate ([`tls::setup_certificate`]) whose SHA-256 fingerprint the
//! page displays so the operator verifies it out of band. Its SAN comes
//! from the instance configuration (`WARDSTONE_SERVER_HOSTNAME`, set
//! before the form is filled in), with the placeholder
//! [`tls::PLACEHOLDER_SAN`] when unset. At the end of setup the form's
//! `server_hostname` field is used for the CA-issued leaf that replaces
//! it: [`run_setup`] mints that leaf, stores its key envelope in the
//! keystore, and the process RESTARTS (exit with a success code, letting
//! the compose service's `restart: unless-stopped` bring it back up on
//! the CA-issued certificate) — a restart, not a hot reload.

pub mod page;
pub mod tls;

use std::path::PathBuf;

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;
use ws_ca::ca::{certificate_validity, create_root, CaLifetime, CaSpec, KeyType};
use ws_ca::error::CaError;
use ws_ca::issue::{sign_leaf_with, ExtKeyUsagePurpose, IssuedLeaf, LeafSpec, SanEntry};
use ws_ca::keystore::KeyStore;
use ws_ca::leafkey::{generate_leaf_key, LeafKeyType};
use ws_ca::serial::allocate_serial;
use ws_core::models::audit::AuditEntry;
use ws_core::models::ca::CaModel;
use ws_core::models::certificate::{CertStatus, CertificateModel};
use ws_core::models::profile::{default_profiles, ProfileModel};
use ws_core::models::rbac::{ActorType, AuthMethod, KeyUsagePurpose, Role};
use ws_core::models::user::UserModel;
use ws_core::profile_match::san_is_permitted;
use ws_core::repo::audit_repo::AuditRepo;
use ws_core::repo::ca_repo::CaRepo;
use ws_core::repo::certificate_repo::CertificateRepo;
use ws_core::repo::profile_repo::ProfileRepo;
use ws_core::repo::tenant_repo::TenantRepo;
use ws_core::repo::user_repo::UserRepo;
use zeroize::Zeroizing;

/// The one tenant a fresh Wardstone instance serves: setup creates it,
/// and the setup router is mounted only while it does not exist.
pub const DEFAULT_TENANT_NAME: &str = "default";

/// The route the setup page serves at (GET and POST).
pub const SETUP_ROUTE: &str = "/setup";

/// The subject common name of the root CA setup mints: the default domain
/// the operator chose — the identity the trust anchor anchors.
const ROOT_CA_NAME: &str = "root";

/// The actor every setup audit row carries: the system performing the
/// first-run bootstrap.
const SETUP_ACTOR: &str = "system:setup";

/// The setup form. The five fields the page collects (the plan pins the
/// shape): the admin account, the default domain of the built-in
/// profiles, the admin CIDRs, and the server's hostname — an explicit
/// setup field for the UI's own SAN, NOT derived from the default domain
/// and not the machine's hostname.
///
/// This struct IS the POST body (`Json<SetupFields>`), so it carries the
/// binding spec's serde casing attribute like every other JSON DTO.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SetupFields {
    /// The operator bootstrap account's login name (role: admin).
    pub admin_username: String,
    /// The admin's password, stored as an argon2id hash — never plaintext.
    pub admin_password: String,
    /// The default domain: the root CA's subject and the built-in
    /// profiles' base SAN pattern.
    pub default_domain: String,
    /// Networks from which an operator reached the setup form (carried
    /// into the built-in profiles' SAN patterns and the deployment
    /// config).
    pub admin_cidrs: Vec<String>,
    /// The server's own hostname: the SAN of the CA-issued leaf that
    /// replaces the setup certificate at the end of setup.
    pub server_hostname: String,
    /// The operator PASTES the setup certificate's SHA-256 fingerprint as
    /// shown in the SERVER'S CONSOLE LOG — not merely the page's display,
    /// which a page-level attacker controls. The window between a fresh
    /// boot and a completed setup is the setup-window takeover surface
    /// (threat-model G8): first-mover takes the CA, and the only defense
    /// in that window is the operator confirming they are talking to the
    /// instance whose console they administer.
    #[serde(default)] // a missing field is a blank paste: the required-field
    // check turns it into the house 400 envelope, not a serde 422.
    pub fingerprint_confirmation: String,
}

/// The state the setup handlers need: the pool, the keys directory (the
/// keystore and the secret-encryption key file live under it), the
/// SHA-256 fingerprint of the setup certificate the LISTENER serves (the
/// binary computes it when it mounts the setup page), and the configured
/// instance hostname the setup certificate is for.
#[derive(Clone, Debug)]
pub struct SetupState {
    /// The database pool.
    pub pool: PgPool,
    /// The keys directory (`WARDSTONE_KEYS_DIR`); [`KeyStore::open`] there
    /// per-POST keeps the handler free of mutable shared state.
    pub keys_dir: PathBuf,
    /// The setup certificate's SHA-256 fingerprint, displayed on the page.
    pub fingerprint: String,
    /// The hostname the setup certificate carries (`WARDSTONE_SERVER_HOSTNAME`
    /// or [`tls::PLACEHOLDER_SAN`]).
    pub hostname: String,
}

/// The setup page (GET) and the setup submit (POST) at [`SETUP_ROUTE`].
///
/// The caller decides whether to mount this router at all by checking
/// [`tenant_exists`] (see [`crate::web_router`] for the composition): the
/// mount — not a refusal — is what makes the setup endpoint disappear
/// once setup has run.
pub fn setup_router(state: SetupState) -> axum::Router {
    axum::Router::new()
        .route(
            SETUP_ROUTE,
            axum::routing::get(page::setup_page).post(page::submit_setup),
        )
        .with_state(state)
}

/// The unmount contract's OTHER branch: what [`crate::web_router`] mounts
/// when [`tenant_exists`] is true. `GET /setup` and `POST /setup` are
/// explicit, plain 404s — the exact shape the setup/e2e suites pin ("404,
/// not 403"), matching axum's own unrouted response (empty body).
///
/// The counterpart must be mounted EXPLICITLY, in the same if/else that
/// decides [`setup_router`] — either the setup routes or their 404s are
/// mounted, never neither. Left to ws-web's SPA fallback, the unmounted
/// `/setup` is an extension-less GET and would come back 200 + the index
/// document: the endpoint would not be unrouted, it would be impersonated
/// by the UI.
pub fn setup_unmounted_router() -> axum::Router {
    async fn setup_gone() -> axum::http::StatusCode {
        axum::http::StatusCode::NOT_FOUND
    }
    axum::Router::new().route(SETUP_ROUTE, axum::routing::get(setup_gone).post(setup_gone))
}

/// Whether the default tenant exists — the check the caller performs
/// before mounting [`setup_router`] (the Review Focus item 5: not routed
/// once the tenant exists).
pub async fn tenant_exists(pool: &PgPool) -> Result<bool, CaError> {
    let tenant = TenantRepo::new()
        .get_by_name(pool, DEFAULT_TENANT_NAME)
        .await
        .map_err(map_core)?;
    Ok(tenant.is_some())
}

/// The first-run bootstrap: everything a fresh instance needs, in the
/// order durability requires.
///
/// 1. The keystore master KEK (`ensure_master_key` generates when absent
///    on a virgin volume, refuses with `Corrupt` when keys exist).
/// 2. The secret-encryption key file (`secret-encryption.key` under the
///    keys directory, the [`ws_api::state::SECRET_KEY_FILE`] name) — the
///    TOTP secrets are encrypted under it, so it must exist before any
///    user can enrol.
/// 3. The root CA via ws-ca's `create_root`. **Its key envelope is stored
///    in the keystore BEFORE the DB transaction commits** — `create_root`
///    writes it before this function even opens one — because a
///    certificate row without its key is worse than an orphaned key file:
///    if the DB transaction rolls back, the key file remains but no CA
///    references it, and the next setup run overwrites it. Write the key
///    first, then commit the DB transaction.
/// 4. ONE DB transaction committing: the tenant, the root CA's `cas` row,
///    the admin user (argon2id hash), the two default profiles (with
///    their revision rows and the current-revision pointer), and the
///    audit entries — they stand or fall together.
/// 5. The server's own leaf, issued by the new root against the
///    built-in `web-server` profile with the form's `server_hostname` as
///    its SAN. The SAN is validated against the profile's `san_patterns`
///    (`validate_hostname_permitted`) inside the issuance transaction,
///    right before minting — the same check the setup page pre-flights
///    for its 400; a direct library caller's refusal surfaces as a
///    [`CaError::Worker`] and the transaction rolls back without minting.
///    Its serial is allocated inside its own issuance
///    transaction (so a rollback releases it, Task 8's contract), and its
///    private-key envelope is stored in the keystore BEFORE that
///    transaction commits, for the same reason as the root's key above.
/// 6. The leaf transaction also audits the completion of setup itself
///    (`setup_completed`), written right after the certificate insert —
///    exactly one row per completed setup.
pub async fn run_setup(
    fields: &SetupFields,
    pool: &PgPool,
    keystore: &mut KeyStore,
) -> Result<(), CaError> {
    ensure_fields(fields)?;

    keystore.ensure_master_key()?;

    ws_core::crypto::SecretBox::create(&keystore.dir().join(ws_api::state::SECRET_KEY_FILE))
        .map_err(map_core)?;

    // The root CA: keyed in the keystore first (see the step contract in
    // this function's docs), DB row follows inside the transaction.
    let spec = CaSpec {
        name: ROOT_CA_NAME.to_owned(),
        subject: fields.default_domain.clone(),
        // An ECDSA P-256 root: the browser-universal choice — every
        // mainstream browser verifies an ECDSA chain once the root is
        // imported, while an Ed25519 root cannot be trusted by
        // Chromium-family browsers AT ALL (the chain fails their verifier
        // with a no-bypass error even after import). Generation is instant
        // like Ed25519's (no RSA prime search), and the signatures are
        // small and fast.
        key_type: KeyType::EcdsaP256,
        lifetime: CaLifetime::Root,
    };
    let created = create_root(&spec, keystore)?;
    let (not_before, not_after) = certificate_validity(&created.cert_pem)?;

    let mut tx = pool.begin().await?;

    let tenant = TenantRepo::new()
        .insert(&mut *tx, DEFAULT_TENANT_NAME)
        .await
        .map_err(map_core)?;

    let root_ca = CaModel {
        id: created.key_pair_id,
        tenant_id: tenant.id,
        name: ROOT_CA_NAME.to_owned(),
        subject: spec.subject.clone(),
        is_root: true,
        parent_id: None,
        key_type: spec.key_type,
        not_before,
        not_after,
        cert_pem: created.cert_pem.clone(),
        // The keystore names the envelope file `ca/<key_pair_id>.key` under
        // the keys directory; the row stores that relative path (the same
        // convention ws-api's CA creation route uses).
        key_file: format!("ca/{}.key", created.key_pair_id),
        created_at: Utc::now(),
    };
    CaRepo::new()
        .insert(&mut *tx, &root_ca)
        .await
        .map_err(map_core)?;

    let password_hash = ws_auth::password::hash_password(&fields.admin_password)
        .map_err(|err| CaError::Worker(format!("setup: {err}")))?;
    let admin = UserModel {
        id: Uuid::new_v4(),
        tenant_id: tenant.id,
        username: fields.admin_username.clone(),
        display_name: fields.admin_username.clone(),
        email: format!("{}@{}", fields.admin_username, fields.default_domain),
        role: Role::Admin,
        auth_provider: "local".to_owned(),
        password_hash: Some(password_hash),
        totp_secret_encrypted: None,
        totp_secret_nonce: None,
        webauthn_credential: None,
        mfa_enabled: false,
        azure_oid: None,
        oidc_sub: None,
        is_active: true,
        force_password_reset: false,
        failed_login_attempts: 0,
        locked_until: None,
        last_login_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    UserRepo::new()
        .insert(&mut *tx, &admin)
        .await
        .map_err(map_core)?;

    // The two built-in default profiles. The `profiles.current_revision_id`
    // FK is DEFERRABLE INITIALLY DEFERRED, so the row is inserted pointing
    // at nothing, its revision 1 follows, and the pointer is set — all in
    // this one transaction.
    let mut revision_ids = std::collections::HashMap::new();
    for template in default_profiles(&fields.default_domain, &fields.admin_cidrs) {
        let profile_id = Uuid::new_v4();
        let profile = ProfileModel {
            id: profile_id,
            tenant_id: tenant.id,
            name: template.name.clone(),
            description: Some("created by the first-run setup".to_owned()),
            current_revision_id: None,
            created_at: Utc::now(),
        };
        let revision = template.template_for(profile_id, 1, Uuid::new_v4());
        revision_ids.insert(template.name.clone(), (profile_id, revision.id));
        ProfileRepo::new()
            .insert_profile(&mut *tx, &profile)
            .await
            .map_err(map_core)?;
        ProfileRepo::new()
            .insert_revision(&mut *tx, &revision)
            .await
            .map_err(map_core)?;
        ProfileRepo::new()
            .update(&mut *tx, profile_id, None, revision.id)
            .await
            .map_err(map_core)?;
    }

    // The audit entries commit WITH the bootstrap (the write-side
    // contract): the setup system actor, one entry per created thing.
    let audit = AuditRepo::new();
    audit
        .record(
            &mut *tx,
            &audit_entry(
                tenant.id,
                "tenant_created",
                "tenant",
                &tenant.id.to_string(),
                serde_json::json!({}),
            ),
        )
        .await
        .map_err(map_core)?;
    audit
        .record(
            &mut *tx,
            &audit_entry(
                tenant.id,
                "ca_created",
                "ca",
                &root_ca.id.to_string(),
                serde_json::json!({"key_type": root_ca.key_type.as_str(), "is_root": true}),
            ),
        )
        .await
        .map_err(map_core)?;
    audit
        .record(
            &mut *tx,
            &audit_entry(
                tenant.id,
                "user_created",
                "user",
                &admin.id.to_string(),
                serde_json::json!({"username": admin.username, "role": admin.role.as_str()}),
            ),
        )
        .await
        .map_err(map_core)?;
    for name in ["web-server", "web-server-ecdsa"] {
        let Some((profile_id, _)) = revision_ids.get(name) else {
            return Err(CaError::Worker(format!(
                "setup: the default profile {name:?} was not persisted"
            )));
        };
        audit
            .record(
                &mut *tx,
                &audit_entry(
                    tenant.id,
                    "profile_created",
                    "profile",
                    &profile_id.to_string(),
                    serde_json::json!({"name": name}),
                ),
            )
            .await
            .map_err(map_core)?;
    }

    tx.commit().await?;

    // The server's own leaf. Its policy comes from the built-in
    // `web-server` profile's persisted revision; its SAN/subject is the
    // form's `server_hostname`.
    let template = &default_profiles(&fields.default_domain, &fields.admin_cidrs)[0];
    let (_profile_id, revision_id) =
        revision_ids.get(&template.name).copied().ok_or_else(|| {
            CaError::Worker(format!(
                "setup: the default profile {:?} was not persisted",
                template.name
            ))
        })?;
    let serial_key_type = LeafKeyType::from_str(&template.key_type).ok_or_else(|| {
        CaError::X509(format!(
            "setup: the built-in web-server profile pins an unusable leaf key type {:?}",
            template.key_type
        ))
    })?;
    let key_usage_pin: Vec<KeyUsagePurpose> = template
        .key_usages
        .iter()
        .map(|usage| {
            KeyUsagePurpose::from_str(usage)
                .ok_or_else(|| CaError::X509(format!("setup: unknown key usage {usage:?}")))
        })
        .collect::<Result<Vec<_>, CaError>>()?;
    let eku_pin: Vec<ExtKeyUsagePurpose> = template
        .eku
        .iter()
        .map(|eku| {
            ExtKeyUsagePurpose::from_str(eku)
                .ok_or_else(|| CaError::X509(format!("setup: unknown EKU {eku:?}")))
        })
        .collect::<Result<Vec<_>, CaError>>()?;
    let sans = vec![san_entry(&fields.server_hostname)?];

    // One issuance transaction: the serial allocation inside it releases
    // on rollback (Task 8's contract), the signing leg is CPU-bound and
    // runs in spawn_blocking while the transaction stays open (the ws-api
    // issuance shape), and the key envelope lands in the keystore BEFORE
    // the certificate row commits (same ordering rationale as the root's
    // key: an orphaned key file is the lesser evil).
    let mut tx = pool.begin().await?;
    // Defense-in-depth (see `validate_hostname_permitted`'s "two checks"):
    // the setup page has already pre-checked this and would have answered
    // 400; a direct library caller gets the refusal here instead — inside
    // the issuance transaction, before anything is minted, as a `Worker`
    // error per `run_setup`'s pinned `CaError` vocabulary.
    validate_hostname_permitted(fields)
        .map_err(|message| CaError::Worker(format!("setup: {message}")))?;
    let serial = allocate_serial(root_ca.id, tenant.id, &mut *tx).await?;

    let ca_cert_pem = root_ca.cert_pem.clone();
    let ca_key_der = keystore.load_ca_key(&root_ca.id)?;
    let hostname = fields.server_hostname.clone();
    let sans_for_issuance = sans.clone();
    let lifetime = chrono::Duration::days(i64::from(template.lifetime_days));
    let issuance = tokio::task::spawn_blocking(
        move || -> Result<(IssuedLeaf, Zeroizing<Vec<u8>>), CaError> {
            // Zeroized on drop: the DER never leaves the wrapped buffer
            // between mint and envelope-write.
            let (key_pair, private_key_der) = generate_leaf_key(serial_key_type)?;
            // The CSR carries the requested subject CN and SANs,
            // self-signed with the generated key (proof of possession,
            // verified by the signing leg — the same contract as the
            // operator-supplied CSR path).
            let csr = server_csr(&hostname, &sans_for_issuance, &key_pair)?;
            let spec = LeafSpec {
                sans: sans_for_issuance,
                key_usages: key_usage_pin,
                ekus: eku_pin,
                key_type: serial_key_type,
                lifetime,
                subject_cn: Some(hostname),
                serial,
            };
            let issued = sign_leaf_with(&ca_cert_pem, &ca_key_der, &csr, &spec)?;
            Ok((issued, private_key_der))
        },
    )
    .await
    .map_err(|err| CaError::Worker(format!("setup: the leaf-issuance task failed: {err}")))??;
    let (issued, leaf_key_der) = issuance;

    let cert_id = Uuid::new_v4();
    // Key BEFORE row (see this function's docs): the envelope is on disk
    // before the certificate row can reference it.
    keystore.store_ca_key(&cert_id, &leaf_key_der)?;

    let certificate = CertificateModel {
        id: cert_id,
        tenant_id: tenant.id,
        ca_id: root_ca.id,
        profile_revision_id: Some(revision_id),
        profile_name: template.name.clone(),
        subject: format!("CN={}", fields.server_hostname),
        serial,
        serial_hex: format!("{serial:x}"),
        san_dns: sans
            .iter()
            .filter_map(|entry| match entry {
                SanEntry::Dns(dns) => Some(dns.clone()),
                _ => None,
            })
            .collect(),
        san_ips: sans
            .iter()
            .filter_map(|entry| match entry {
                SanEntry::Ip(ip) => Some(*ip),
                _ => None,
            })
            .collect(),
        key_type: template.key_type.clone(),
        not_before: issued.not_before,
        not_after: issued.not_after,
        cert_pem: issued.cert_pem.clone(),
        status: CertStatus::Active,
        revoked_at: None,
        revocation_reason: None,
        revocation_detail: None,
        source: "manual".to_owned(),
        created_at: Utc::now(),
    };
    CertificateRepo::new()
        .insert(&mut *tx, &certificate)
        .await
        .map_err(map_core)?;
    // The completion of setup itself, audited in the leaf transaction
    // right after the certificate insert: exactly one `setup_completed`
    // row per completed setup, the same system actor as the bootstrap
    // entries, target the tenant, details carrying what was configured.
    audit
        .record(
            &mut *tx,
            &audit_entry(
                tenant.id,
                "setup_completed",
                "setup",
                &tenant.id.to_string(),
                serde_json::json!({
                    "domain": fields.default_domain,
                    "admin_cidrs": fields.admin_cidrs,
                }),
            ),
        )
        .await
        .map_err(map_core)?;
    audit
        .record(
            &mut *tx,
            &audit_entry(
                tenant.id,
                "cert_issued",
                "certificate",
                &certificate.id.to_string(),
                serde_json::json!({
                    "profile": template.name,
                    "profile_revision_id": revision_id.to_string(),
                    "ca_id": root_ca.id.to_string(),
                    "serial_hex": certificate.serial_hex,
                    "san_dns": certificate.san_dns,
                    "san_ips": certificate
                        .san_ips
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>(),
                    "minted_by": "setup",
                }),
            ),
        )
        .await
        .map_err(map_core)?;
    tx.commit().await?;

    tracing::info!(
        "first-run setup complete; the UI process must restart to serve the CA-issued \
         certificate for {}",
        fields.server_hostname
    );
    Ok(())
}

/// Whether the form's `server_hostname` — the SAN of the leaf the CA will
/// issue for the UI — is permitted by the built-in `web-server` profile
/// revision setup is about to create (the Plan-2 I-3 gap: setup must not
/// mint an issued certificate its own profile would not issue).
///
/// The patterns come from [`default_profiles`] — a pure function of the
/// form's `default_domain` and `admin_cidrs`, no DB round-trip — because
/// at setup time no profile row exists yet: the `web-server` profile is
/// created BY this setup, and the built-in revision's patterns are exactly
/// what the leaf is minted under. [`san_is_permitted`] is the same
/// predicate the API's issuance path applies, so a hostname refused here
/// would equally be refused on any later issuance under the profile.
///
/// The refusal message carries the issuance path's specific wording shape
/// (`name "…" is not permitted by this profile`): the setup operator is
/// the admin who holds `read_profiles`, so the specific form — naming the
/// failing constraint, never the permitted set — is the right one.
///
/// # The two checks
///
/// - [`page::submit_setup`] pre-checks with this helper BEFORE
///   [`run_setup`] is called (nothing is committed yet) and maps a refusal
///   to [`page::SubmitError::BadRequest`] — a 400 for the form user.
/// - [`run_setup`] re-applies the same check inside the leaf-mint
///   transaction, right before minting, so a direct library caller (which
///   bypasses the page) is caught too; there the refusal is a
///   [`CaError::Worker`], and the issuance transaction rolls back without
///   minting.
///
/// A malformed pattern (e.g. a blank or ill-formed `admin_cidrs` entry,
/// which become SAN patterns too, or a malformed hostname literal) also
/// fails here, with [`san_is_permitted`]'s own message — at setup time
/// this is form damage, not stored-data corruption, so it takes the same
/// refusal path.
pub(crate) fn validate_hostname_permitted(fields: &SetupFields) -> Result<(), String> {
    // The built-in `web-server` profile is the first of the default
    // profiles and the one the setup leaf is minted under (see
    // `run_setup`'s leaf block).
    let template = &default_profiles(fields.default_domain.as_str(), &fields.admin_cidrs)[0];
    let refusal = |detail: String| {
        format!(
            "server_hostname is not permitted by the {} profile: {detail}",
            template.name
        )
    };
    match san_is_permitted(&template.san_patterns, fields.server_hostname.as_str()) {
        Ok(true) => Ok(()),
        Ok(false) => Err(refusal(format!(
            "name {:?} is not permitted by this profile",
            fields.server_hostname
        ))),
        Err(core) => Err(refusal(core.to_string())),
    }
}

/// The setup form's blank-field policy: the four identity fields must be
/// non-blank; CIDRs may be absent but not blank.
fn ensure_fields(fields: &SetupFields) -> Result<(), CaError> {
    let required = [
        ("admin_username", fields.admin_username.as_str()),
        ("admin_password", fields.admin_password.as_str()),
        ("default_domain", fields.default_domain.as_str()),
        ("server_hostname", fields.server_hostname.as_str()),
    ];
    for (name, value) in required {
        if value.trim().is_empty() {
            return Err(CaError::Worker(format!("setup: {name} must not be blank")));
        }
    }
    if fields.admin_cidrs.iter().any(|cidr| cidr.trim().is_empty()) {
        return Err(CaError::Worker(
            "setup: admin_cidrs entries must not be blank".to_owned(),
        ));
    }
    Ok(())
}

/// The CSR for the server-generated leaf key: the requested subject CN and
/// SANs, self-signed with the generated key (the same helper shape as
/// ws-api's server-key-generation path).
fn server_csr(
    subject_cn: &str,
    sans: &[SanEntry],
    key_pair: &rcgen::KeyPair,
) -> Result<String, CaError> {
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, subject_cn);
    params.distinguished_name = dn;
    params.subject_alt_names = sans
        .iter()
        .map(rcgen_san)
        .collect::<Result<Vec<_>, CaError>>()?;
    let csr = params.serialize_request(key_pair)?;
    Ok(csr.pem()?)
}

/// Map a [`SanEntry`] to its rcgen shape (the ws-api issuance path's
/// conversion).
fn rcgen_san(entry: &SanEntry) -> Result<rcgen::SanType, CaError> {
    Ok(match entry {
        SanEntry::Dns(dns) => rcgen::SanType::DnsName(dns.as_str().try_into()?),
        SanEntry::Ip(ip) => rcgen::SanType::IpAddress(*ip),
        SanEntry::Email(email) => rcgen::SanType::Rfc822Name(email.as_str().try_into()?),
    })
}

/// Map a hostname-or-CIDR string to a [`SanEntry`]: an IP address is an
/// `iPAddress`, anything else a DNS name (the ws-api issuance path's
/// convention).
fn san_entry(value: &str) -> Result<SanEntry, CaError> {
    Ok(match value.parse::<std::net::IpAddr>() {
        Ok(ip) => SanEntry::Ip(ip),
        Err(_) => SanEntry::Dns(value.to_owned()),
    })
}

/// The setup audit row: the system actor, the acting tenant's log.
fn audit_entry(
    tenant_id: Uuid,
    action: &str,
    target_type: &str,
    target_id: &str,
    details: serde_json::Value,
) -> AuditEntry {
    AuditEntry {
        id: Uuid::new_v4(),
        tenant_id,
        actor_type: ActorType::System,
        auth_method: AuthMethod::System,
        session_id: None,
        actor_id: SETUP_ACTOR.to_owned(),
        action: action.to_owned(),
        target_type: target_type.to_owned(),
        target_id: target_id.to_owned(),
        details,
        created_at: Utc::now(),
    }
}

/// Map ws-core storage failures onto the pinned `CaError` vocabulary of
/// [`run_setup`]. Plain database errors flow into `CaError::Db`; every
/// other ws-core condition (a duplicate tenant from a concurrent setup
/// run, a crypto/config failure) lands in the message-carrying `Worker`
/// bucket prefixed `setup:` — `CaError` is ws-ca's enum and carries no
/// setup-specific variant, and adding one would ripple into ws-api's
/// exhaustive conversion table.
fn map_core(err: ws_core::error::CoreError) -> CaError {
    match err {
        ws_core::error::CoreError::Database(db) => CaError::Db(db),
        other => CaError::Worker(format!("setup: {other}")),
    }
}
