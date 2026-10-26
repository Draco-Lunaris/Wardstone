//! The first-run setup: the setup page (GET), the setup submit (POST),
//! the seal-at-creation bootstrap transaction [`run_setup`], the
//! recovery re-seal [`recover_db_credential`], and the setup TLS surface
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
//! # Seal at creation (the design's D1)
//!
//! Every key a fresh install needs is generated in protected memory and
//! its FIRST write is its passphrase-sealed envelope — nothing is ever
//! minted in plaintext and converted later. The `master.envelope` is the
//! sealed marker, written LAST (the boot derives "sealed" from its
//! presence), the setup POST builds its own pool from the TYPED database
//! password (a wrong password writes nothing: no file, no row, not even
//! the keys directory), an existing install is refused before anything is
//! generated, the setup DB transaction commits only after the marker
//! lands, and the database credential rotation follows the commit — so
//! the api relay (the page's step, after the rotation) opens the rotated
//! credential.
//!
//! # The TLS switch
//!
//! The setup page is HTTPS from the start, on the self-signed setup
//! certificate ([`tls::setup_certificate`]) whose SHA-256 fingerprint the
//! page displays so the operator verifies it out of band. Its SAN comes
//! from the instance configuration (`WARDSTONE_SERVER_HOSTNAME`, set
//! before the form is filled in), with the placeholder
//! [`tls::PLACEHOLDER_SAN`] when unset. At the end of setup the form's
//! `server_hostname` field names the CA-issued leaf that replaces it:
//! [`run_setup`] mints that leaf sealed, and the page's TLS swap resumes
//! the listener onto it IN PLACE (the resume contract — no restart, no
//! re-listen).

pub mod page;
pub mod tls;

use std::path::{Path, PathBuf};

use chrono::Utc;
use rand::{rngs::SysRng, TryRng};
use sqlx::PgPool;
use uuid::Uuid;
use ws_ca::ca::{certificate_validity, create_root, CaLifetime, CaSpec, KeyType};
use ws_ca::error::CaError;
use ws_ca::issue::{sign_leaf_with, ExtKeyUsagePurpose, IssuedLeaf, LeafSpec, SanEntry};
use ws_ca::keystore::KeyStore;
use ws_ca::leafkey::{generate_leaf_key, LeafKeyType};
use ws_ca::serial::allocate_serial;
use ws_core::crypto::{db_role_of, substitute_db_password, KeyEnvelope, PROD_KDF_PARAMS};
use ws_core::error::CoreError;
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
use ws_secmem::{SecMemError, SecretBuf};
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
    /// The database login password the operator typed — the credential
    /// `DATABASE_URL`'s role carries TODAY (the compose bootstrap one,
    /// or the fresh one the db-volume-recovery runbook set). It is
    /// NEVER stored: setup connects with it exactly once, the rotation
    /// ALTERs the role to a fresh random credential, and the typed
    /// password dies with the zeroizing wrapper when the handler
    /// returns — the sealed envelope holds only the fresh one.
    #[serde(default)]
    pub db_password: Zeroizing<String>,
    /// The operator's master passphrase (entered twice on the page; the
    /// handler refuses a mismatch or a blank). At commit the setup flow
    /// wraps every plaintext key file into a passphrase-sealed envelope,
    /// rotates the DB credential under it, and DELETES the plaintext
    /// originals — the next boot is sealed and this passphrase is its
    /// unlock key. It exists on no disk and is not recoverable; the page
    /// says so.
    #[serde(default)]
    pub master_passphrase: String,
    #[serde(default)]
    pub master_passphrase_confirm: String,
}

/// The state the setup handlers need: the keys directory (the envelope
/// volume), the SHA-256 fingerprint of the setup certificate the
/// LISTENER serves (the binary computes it when it mounts the setup
/// page), the configured instance hostname, the reloadable TLS config
/// the commit swaps in place, the compose-internal api base URL, and
/// the instance's `DATABASE_URL` — the setup POST builds its OWN pool
/// from that URL plus the form's typed `db_password` (the D2 direction:
/// no boot-time database connection belongs to the setup surface at
/// all).
#[derive(Clone, Debug)]
pub struct SetupState {
    /// The keys directory (`WARDSTONE_KEYS_DIR`).
    pub keys_dir: PathBuf,
    /// The setup certificate's SHA-256 fingerprint, displayed on the page.
    pub fingerprint: String,
    /// The hostname the setup certificate carries (`WARDSTONE_SERVER_HOSTNAME`
    /// or [`tls::PLACEHOLDER_SAN`]).
    pub hostname: String,
    /// The reloadable TLS config: the setup commit swaps the listener onto
    /// the CA-issued leaf IN PLACE (the resume contract — the sealed design
    /// removed the self-exit restart, so this is how the leaf takes over).
    /// `None` in the tests (no listener to swap).
    pub tls_reload: Option<axum_server::tls_rustls::RustlsConfig>,
    /// The compose-internal api base URL: the setup commit relays the
    /// unlock to the api process once (the fresh-install flow — the
    /// api booted as the sealed shell and only the relay brings its
    /// full surface up).
    pub api_base_url: String,
    /// The instance's `DATABASE_URL`: its login role is the one the
    /// setup commit's credential rotation ALTERs (the External variant —
    /// a URL that does not use the compose default role must rotate ITS
    /// role). The same `db_role_of` derivation the api's unlock builder
    /// uses; the PASSWORD to connect with comes from the POST's typed
    /// `db_password` field, never from the URL itself.
    pub database_url: String,
}

/// The seal-at-creation setup's typed error vocabulary. No variant's
/// message ever carries key material, a passphrase, or a password.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    /// The database refused the TYPED password (Postgres `28P01`):
    /// nothing was generated or written — no file, no row. The page
    /// renders its wrong-password copy for this one.
    #[error("the database rejected that password")]
    DbRejected,
    /// The default tenant already exists (a restored database beside a
    /// fresh keys volume): the refusal ran BEFORE anything was generated
    /// or written. Renders the design's exact copy — restore the matching
    /// keys volume, or remove both volumes and run setup again.
    #[error(
        "the database already holds an install but the keys volume is \
         empty — restore the matching keys volume, or remove both \
         volumes and run setup again"
    )]
    InstallExists,
    /// The form failed its basic checks (blank fields, passphrase
    /// mismatch, a hostname the profile would not issue for).
    #[error("invalid setup form: {0}")]
    Validation(String),
    /// Key or certificate work failed inside ws-ca.
    #[error(transparent)]
    Ca(#[from] CaError),
    /// A ws-core failure (database, crypto, config). Messages never carry
    /// key material.
    #[error(transparent)]
    Core(#[from] CoreError),
}

/// What a completed setup hands its caller: the CA-issued leaf the
/// listener resumes onto, its private key in RAM custody (a ws-secmem
/// arena reservation — wiped when the caller drops it), and the
/// hostname the leaf was minted for.
#[derive(Debug)]
pub struct SetupOutcome {
    /// The CA-issued leaf certificate, PEM.
    pub leaf_cert_pem: String,
    /// The leaf's PKCS#8 DER private key, in the protected arena.
    pub leaf_key: SecretBuf,
    /// The form's `server_hostname` — the leaf's SAN.
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

/// The generation block's payload: the zeroizing originals of the master
/// and secret-encryption keys plus the admin's argon2id hash (the keys
/// live only until the arena copies take custody).
type GeneratedKeys = (
    Zeroizing<[u8; MASTER_KEY_LEN]>,
    Zeroizing<[u8; SECRET_BOX_KEY_LEN]>,
    String,
);

/// The first-run bootstrap (the seal-at-creation design's D1): everything
/// a fresh instance needs, sealed as it is created — no key ever exists
/// in plaintext on disk, and the volume's sealed state begins the moment
/// the POST succeeds.
///
/// The steps, in the exact durability order the design pins:
///
/// 1. Validate the form (including the typed `db_password` and the
///    confirmed master passphrase).
/// 2. Build the pool from the TYPED password — connect, run the
///    migrations, and refuse a Postgres `28P01`
///    ([`SetupError::DbRejected`]) BEFORE anything exists: no file, no
///    row, not even the keys directory.
/// 3. Refuse an existing install ([`SetupError::InstallExists`]) before
///    anything is generated or written: a restored database beside a
///    fresh keys volume must never be half-overwritten by a second
///    setup run.
/// 4. Generate everything in protected memory, the memory-hard legs
///    under `spawn_blocking` (Ruling 21: the admin's argon2id hash and
///    the key-envelope writes never park the async runtime): the master
///    key, the secret-encryption key, the JWT pair (born straight into
///    the protected arena), the root CA — whose key envelope is stored
///    in the keystore BEFORE anything else, under the in-memory master
///    (the AEAD leg needs no argon2; the key-before-row contract: a
///    certificate row without its key is worse than an orphaned key
///    file a crashed run overwrites) — and the server leaf.
/// 5. Write the non-master envelopes — `secret-encryption.envelope`,
///    then `jwt-keys.envelope`, then the leaf's keystore envelope inside
///    the issuance transaction. Each write is a crash-atomic replace, so
///    stray files from a crashed earlier attempt are simply overwritten.
/// 6. Write `master.envelope` LAST — the sealed marker — while the ONE
///    setup transaction (tenant, root CA row, admin, default profiles,
///    the leaf's certificate row, and every audit row, standing or
///    falling together) is still open, and THEN commit: a crash at any
///    earlier point leaves no tenant (the transaction rolls back) and
///    only overwritable strays; a crash after the marker leaves the
///    torn state the boot refuses loudly.
/// 7. Rotate the database credential (the URL's login role — F5) over a
///    dedicated connection and seal it at the volume's zeroth generation.
///    The `db-credential.envelope` lands AFTER the marker on purpose:
///    its absence is the D5 locked state the unlock's recovery arm
///    heals, never a torn volume. The api relay (the page's step, after
///    this rotation) therefore opens the rotated credential.
pub async fn run_setup(
    fields: &SetupFields,
    database_url: &str,
    keys_dir: &Path,
) -> Result<SetupOutcome, SetupError> {
    ensure_fields(fields)?;

    // The pool rides the TYPED password (never a boot-time credential —
    // the D2 direction: the setup POST is the only thing that knows it,
    // and the rotation below retires it). A wrong password refuses BEFORE
    // anything exists: no envelope, no keystore file, no tenant, no
    // profile, no cert row, not even the keys directory.
    let connect_url = substitute_db_password(database_url, &fields.db_password);
    let pool = match ws_core::db::connect(&connect_url).await {
        Ok(pool) => pool,
        Err(err) if db_rejected(&err) => return Err(SetupError::DbRejected),
        Err(err) => return Err(SetupError::Core(err)),
    };

    // An existing install refuses BEFORE anything is generated or
    // written (the router never mounts this surface once the tenant
    // exists; this check is the defense for direct library callers and
    // every racing window).
    if tenant_exists(&pool).await? {
        return Err(SetupError::InstallExists);
    }

    // The memory-hard generation legs run under spawn_blocking (Ruling
    // 21): fresh OS entropy for the master and secret-encryption keys,
    // and the admin's argon2id hash. The zeroizing stack originals live
    // only until the arena copies below (the master's survives into the
    // LAST envelope write, so the marker is sealed from the same custody
    // the keystore opened with).
    let admin_password = fields.admin_password.clone();
    let generated = tokio::task::spawn_blocking(move || -> Result<GeneratedKeys, SetupError> {
        let mut master = Zeroizing::new([0u8; MASTER_KEY_LEN]);
        let mut secret = Zeroizing::new([0u8; SECRET_BOX_KEY_LEN]);
        SysRng
            .try_fill_bytes(&mut master[..])
            .map_err(|e| SetupError::Core(CoreError::Crypto(format!("the os entropy: {e}"))))?;
        SysRng
            .try_fill_bytes(&mut secret[..])
            .map_err(|e| SetupError::Core(CoreError::Crypto(format!("the os entropy: {e}"))))?;
        let password_hash = ws_auth::password::hash_password(&admin_password)
            .map_err(|e| SetupError::Ca(CaError::Worker(format!("setup: the admin hash: {e}"))))?;
        Ok((master, secret, password_hash))
    })
    .await
    .map_err(|e| SetupError::Ca(CaError::Worker(format!("setup: the generation task: {e}"))))??;
    let (master, secret, password_hash) = generated;

    // The protected arena takes custody: the canonical copies of the
    // master (the keystore's unlocked custody) and the secret-encryption
    // key (its envelope write below) live in ws-secmem from here on.
    let mem = ws_secmem::global().map_err(arena_failure)?;
    let master_buf = mem.alloc_copy(&master[..]).map_err(arena_failure)?;
    let secret_buf = mem.alloc_copy(&secret[..]).map_err(arena_failure)?;

    // The JWT pair: generated straight into the arena, never a
    // plaintext anywhere.
    let jwt_keys = ws_auth::jwt::JwtKeys::generate(ws_auth::jwt::DEFAULT_ACCESS_TTL_SECS)
        .map_err(|e| SetupError::Ca(CaError::Worker(format!("setup: the jwt pair: {e}"))))?;

    // The keystore opens UNLOCKED: the master exists only in the
    // custodies above (the plaintext master mint the old flow wrote is
    // gone with this flow — the master's first and only write is its
    // envelope, below, LAST).
    let mut keystore = KeyStore::open_unlocked(keys_dir, master_buf)?;

    // The root CA: keyed in the keystore first (the key-before-row
    // contract), under the in-memory master — the FIRST file this flow
    // writes; a crash before the commit leaves it as a stray the next
    // run overwrites.
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
    let created = create_root(&spec, &mut keystore)?;
    let (not_before, not_after) = certificate_validity(&created.cert_pem)?;

    // The secret-encryption envelope — the FIRST thing ever written for
    // this key is its sealed envelope (the old flow wrote the plaintext
    // file and converted it later). Under spawn_blocking: the write is
    // an argon2 derivation (Ruling 21).
    {
        let path = keys_dir.join(SECRET_ENVELOPE_FILE);
        let passphrase = fields.master_passphrase.clone();
        tokio::task::spawn_blocking(move || -> Result<(), SetupError> {
            KeyEnvelope::write_envelope(&path, &passphrase, &secret_buf[..], PROD_KDF_PARAMS, 0)
                .map_err(SetupError::Core)
        })
        .await
        .map_err(|e| {
            SetupError::Ca(CaError::Worker(format!(
                "setup: the secret-encryption envelope task: {e}"
            )))
        })??;
    }

    // The JWT pair's envelope (the same spawn_blocking shape).
    {
        let path = keys_dir.join(JWT_ENVELOPE_FILE);
        let passphrase = fields.master_passphrase.clone();
        tokio::task::spawn_blocking(move || -> Result<(), SetupError> {
            ws_auth::jwt::write_sealed(&path, passphrase.as_bytes(), &jwt_keys, 0).map_err(|e| {
                SetupError::Ca(CaError::Worker(format!("setup: the jwt envelope: {e}")))
            })
        })
        .await
        .map_err(|e| {
            SetupError::Ca(CaError::Worker(format!(
                "setup: the jwt envelope task: {e}"
            )))
        })??;
    }

    // The ONE setup DB transaction: the tenant, the root CA's row, the
    // admin user (argon2id hash precomputed above), the two default
    // profiles (with their revision rows and the current-revision
    // pointer), the audit entries, and — further down — the server
    // leaf's certificate row and its own audits, all standing or
    // falling with ONE commit (after the master envelope write below).
    let mut tx = pool.begin().await.map_err(CaError::Db)?;

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

    // The admin's argon2id hash was minted in the generation block above
    // (Ruling 21: the memory-hard hash runs under spawn_blocking).
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
            return Err(SetupError::Ca(CaError::Worker(format!(
                "setup: the default profile {name:?} was not persisted"
            ))));
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

    // The leaf's issuance legs ride the SAME setup transaction (the
    // serial allocation releases on rollback, Task 8's contract; the
    // CPU-bound signing runs in spawn_blocking while the transaction
    // stays open, the ws-api issuance shape; the key envelope lands in
    // the keystore BEFORE the certificate row commits, the
    // key-before-row contract — and a pre-commit stray is simply
    // overwritten by the next run).
    // Defense-in-depth (see `validate_hostname_permitted`'s "two checks"):
    // the setup page has already pre-checked this and would have answered
    // 400; a direct library caller gets the refusal here instead — inside
    // the setup transaction, before anything is minted, as a
    // [`SetupError::Validation`], and the transaction rolls back without
    // minting.
    validate_hostname_permitted(fields).map_err(SetupError::Validation)?;
    let serial = allocate_serial(root_ca.id, tenant.id, &mut *tx).await?;

    let ca_cert_pem = root_ca.cert_pem.clone();
    // The root's key, unwrapped once for this issuance into the protected
    // arena — the serving-leaf mint rides the serving-key holder's
    // allowance, and the reservation wipes when the issuance completes.
    let ca_key_der = keystore.unwrap_ca_key(&root_ca.id)?;
    let hostname = fields.server_hostname.clone();
    let sans_for_issuance = sans.clone();
    let lifetime = chrono::Duration::days(i64::from(template.lifetime_days));
    // The leaf's private key is born straight into the protected arena:
    // the spawn_blocking generation copies its DER the moment it exists
    // (the Zeroizing original dies inside the closure), and the
    // reservation crosses out as the setup outcome's RAM custody.
    let issuance =
        tokio::task::spawn_blocking(move || -> Result<(IssuedLeaf, SecretBuf), CaError> {
            let (key_pair, private_key_der) = generate_leaf_key(serial_key_type)?;
            let private_key_der = Zeroizing::new(private_key_der);
            let leaf_key = ws_secmem::global()
                .and_then(|mem| mem.alloc_copy(&private_key_der))
                .map_err(|e| CaError::Worker(format!("setup: the leaf key arena: {e}")))?;
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
            Ok((issued, leaf_key))
        })
        .await
        .map_err(|err| CaError::Worker(format!("setup: the leaf-issuance task failed: {err}")))??;
    let (issued, leaf_key) = issuance;

    let cert_id = Uuid::new_v4();
    // Key BEFORE row (see this function's docs): the envelope is on disk
    // before the certificate row can reference it.
    keystore.store_ca_key(&cert_id, &leaf_key[..])?;

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
    // The master envelope LAST — the sealed marker: from this write on,
    // every future boot derives "sealed" from its presence. It is
    // written while the setup transaction is still open (see the doc's
    // step list): a crash before this write leaves no tenant and only
    // overwritable strays; a crash after it leaves the torn state the
    // boot refuses loudly. Under spawn_blocking (Ruling 21: the write is
    // an argon2 derivation).
    {
        let path = keys_dir.join(MASTER_ENVELOPE_FILE);
        let passphrase = fields.master_passphrase.clone();
        tokio::task::spawn_blocking(move || -> Result<(), SetupError> {
            KeyEnvelope::write_envelope(&path, &passphrase, &master[..], PROD_KDF_PARAMS, 0)
                .map_err(SetupError::Core)
        })
        .await
        .map_err(|e| {
            SetupError::Ca(CaError::Worker(format!(
                "setup: the master envelope task: {e}"
            )))
        })??;
    }

    // The commit: the tenant exists from exactly this line on.
    tx.commit().await.map_err(CaError::Db)?;

    // The DB credential rotation (the shared crash-safe
    // [`ws_core::dbcred::rotate_db_credential`]): fresh random, the
    // ALTER in verifier form over a dedicated connection, the pending
    // envelope promoted after the ALTER — sealed at the volume's
    // zeroth generation, AFTER the marker on purpose (its absence is
    // the D5 locked state the unlock's recovery arm heals, never a
    // torn volume). The rotation runs on the async path's own
    // connection: its internal envelope write is the one argon2
    // exception (the crash-safe rotation routine is shared with the
    // api's unlock and stays single-sourced; Ruling 21's
    // spawn_blocking mandate covers setup's OWN envelope writes, which
    // all block above). The typed bootstrap password retires with the
    // ALTER.
    let db_role = db_role_of(database_url)?;
    let mut conn = pool.acquire().await.map_err(CaError::Db)?;
    ws_core::dbcred::rotate_db_credential(
        &mut conn,
        &db_role,
        &keys_dir.join(DB_CREDENTIAL_ENVELOPE_FILE),
        fields.master_passphrase.as_bytes(),
        0,
    )
    .await?;

    tracing::info!(
        "first-run setup complete: every key was sealed as it was created; \
         the CA-issued certificate for {} is live",
        fields.server_hostname
    );
    Ok(SetupOutcome {
        leaf_cert_pem: issued.cert_pem,
        leaf_key,
        hostname: fields.server_hostname.clone(),
    })
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
/// - [`run_setup`] re-applies the same check inside the setup
///   transaction, right before minting, so a direct library caller (which
///   bypasses the page) is caught too; there the refusal is a
///   [`SetupError::Validation`], and the setup transaction rolls back
///   without minting.
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

/// The setup form's blank-field policy: the identity fields (including
/// the typed database password) must be non-blank; CIDRs may be absent
/// but not blank; the master passphrase is required and confirmed — the
/// whole bootstrap refuses before anything is generated or written.
fn ensure_fields(fields: &SetupFields) -> Result<(), SetupError> {
    let required = [
        ("admin_username", fields.admin_username.as_str()),
        ("admin_password", fields.admin_password.as_str()),
        ("default_domain", fields.default_domain.as_str()),
        ("server_hostname", fields.server_hostname.as_str()),
        ("db_password", fields.db_password.as_str()),
    ];
    for (name, value) in required {
        if value.trim().is_empty() {
            return Err(SetupError::Validation(format!("{name} must not be blank")));
        }
    }
    if fields.admin_cidrs.iter().any(|cidr| cidr.trim().is_empty()) {
        return Err(SetupError::Validation(
            "admin_cidrs entries must not be blank".to_owned(),
        ));
    }
    if fields.master_passphrase.trim().is_empty() {
        return Err(SetupError::Validation(
            "a master passphrase is required: it seals every key on this \
             instance and is not recoverable"
                .to_owned(),
        ));
    }
    if fields.master_passphrase != fields.master_passphrase_confirm {
        return Err(SetupError::Validation(
            "the master passphrase and its confirmation do not match".to_owned(),
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
/// [`tenant_exists`] (and, inside [`run_setup`], the row inserts whose
/// errors flow through the `Ca(#[from] CaError)` arm). Plain database
/// errors flow into `CaError::Db`; every
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

/// Finish a crashed seal (the final review's F3, the per-file
/// contract spec §3 pins): the old volume seal sealed the volume file
/// by file, and a crash mid-arm leaves two windows per family — an
/// envelope that landed while its plaintext original was never
/// deleted, or a plaintext that never wrapped at all. The sealed
/// boot's unlock heals both under the just-proven passphrase: the
/// envelope is authoritative (its presence deletes the stray
/// plaintext), an unwrapped plaintext wraps at the master envelope's
/// generation and deletes, and the JWT pair heals as ONE unit — a torn
/// pair seals as-is and the sealed loader refuses it loudly
/// (`ws_auth::jwt::load_sealed`'s pair probe), the documented re-key
/// runbook, never a silent boot on a key whose tokens fail their own
/// verification. Idempotent: a clean volume heals as a no-op.
///
/// The DB credential has no heal arm: its plaintext never lived on the
/// volume (the compose env held it) — the §8 recovery runbook's re-seed
/// owns that window. A volume WITHOUT the master envelope never reaches
/// the unlock (the boot serves it the setup page, or refuses it beside
/// a tenant); the heal refuses it rather than sealing anything against
/// a generation it cannot name.
///
/// [TRANSITIONAL — Task 6 removed the volume seal this heals (a volume
/// sealed at creation has no per-file crash windows to converge); the
/// function survives on its ONE remaining caller, the sealed boot's
/// unlock build, until Task 7's D2 boot rewrite drops that call and
/// deletes it together with `heal_one`.]
pub fn heal_keys_volume(keys_dir: &Path, passphrase: &str) -> Result<(), CaError> {
    let generation =
        ws_core::crypto::KeyEnvelope::read_generation(&keys_dir.join(MASTER_ENVELOPE_FILE))
            .map_err(|e| CaError::Worker(format!("the heal's anchor: {e}")))?;

    // The master family: the sealed boot's predicate guarantees the
    // envelope, so a leftover plaintext is a stray delete.
    let master_plaintext = keys_dir.join("master.key");
    if master_plaintext.exists() {
        std::fs::remove_file(&master_plaintext).map_err(CaError::Io)?;
        tracing::warn!("heal: a stray master key plaintext was deleted beside its envelope");
    }

    heal_one(
        passphrase,
        generation,
        &keys_dir.join(ws_api::state::SECRET_KEY_FILE),
        &keys_dir.join(SECRET_ENVELOPE_FILE),
    )?;

    // The JWT pair: one envelope, two plaintexts, one decision.
    let signing = keys_dir.join("jwt-signing-key.pem");
    let verify = keys_dir.join("jwt-verify-key.pem");
    if signing.exists() || verify.exists() {
        if keys_dir.join(JWT_ENVELOPE_FILE).exists() {
            for file in [&signing, &verify] {
                if file.exists() {
                    std::fs::remove_file(file).map_err(CaError::Io)?;
                    tracing::warn!("heal: a stray jwt plaintext was deleted beside its envelope");
                }
            }
        } else {
            let signing_pem = std::fs::read_to_string(&signing).unwrap_or_default();
            let verification_pem = std::fs::read_to_string(&verify).unwrap_or_default();
            // The pair wraps AS-IS, exactly as the seal does: `JwtKeys`
            // cannot represent a torn (invalid) pair, so the envelope
            // writer carries the verbatim combined JSON and the sealed
            // loader's pair probe refuses a torn pair loudly at boot
            // (the documented re-key runbook).
            let combined = serde_json::json!({
                "signing": signing_pem,
                "verification": verification_pem,
            })
            .to_string();
            ws_core::crypto::KeyEnvelope::write_envelope(
                &keys_dir.join(JWT_ENVELOPE_FILE),
                passphrase,
                combined.as_bytes(),
                ws_core::crypto::PROD_KDF_PARAMS,
                generation,
            )
            .map_err(|e| CaError::Worker(format!("the heal's jwt envelope: {e}")))?;
            for file in [&signing, &verify] {
                if file.exists() {
                    std::fs::remove_file(file).map_err(CaError::Io)?;
                }
            }
            tracing::warn!("heal: an unwrapped jwt pair was sealed at the volume's generation");
        }
    }
    Ok(())
}

/// One plaintext/envelope family's heal window: the envelope is
/// authoritative — present, it wins and the stray plaintext dies;
/// absent, the plaintext wraps at the volume's generation and the
/// original is deleted.
fn heal_one(
    passphrase: &str,
    generation: u64,
    plaintext: &Path,
    envelope: &Path,
) -> Result<(), CaError> {
    if envelope.exists() {
        if plaintext.exists() {
            std::fs::remove_file(plaintext).map_err(CaError::Io)?;
            tracing::warn!(
                "heal: a stray plaintext was deleted beside its envelope: {}",
                plaintext.display()
            );
        }
    } else if plaintext.exists() {
        let bytes = std::fs::read(plaintext).map_err(CaError::Io)?;
        ws_core::crypto::KeyEnvelope::write_envelope(
            envelope,
            passphrase,
            &bytes,
            ws_core::crypto::PROD_KDF_PARAMS,
            generation,
        )
        .map_err(|e| CaError::Worker(format!("the heal's envelope: {e}")))?;
        std::fs::remove_file(plaintext).map_err(CaError::Io)?;
        tracing::warn!(
            "heal: an unwrapped plaintext was sealed at the volume's generation: {}",
            plaintext.display()
        );
    }
    Ok(())
}

/// The master key length the keystore's unlocked custody requires (a
/// fresh install mints exactly this many OS-entropy bytes).
const MASTER_KEY_LEN: usize = 32;

/// The secret-encryption key length (`SecretBox`'s KEY_LEN).
const SECRET_BOX_KEY_LEN: usize = 32;

/// A Postgres `28P01` (invalid_password) refusal — the wrong-typed-
/// password signal the setup connect and the recovery connect share.
/// Never carries the password or any key material.
fn db_rejected(err: &CoreError) -> bool {
    matches!(
        err,
        CoreError::Database(db) if db.as_database_error().and_then(|e| e.code()).as_deref() == Some("28P01")
    )
}

/// Map a protected-arena failure onto the setup vocabulary (naming the
/// arena, never any material).
fn arena_failure(err: SecMemError) -> SetupError {
    SetupError::Core(CoreError::Crypto(format!("the protected key arena: {err}")))
}

/// The recovery re-seal (the sealed-at-rest spec's documented runbook):
/// an operator who lost the database credential deletes
/// `db-credential.envelope` from the keys volume, sets a fresh bootstrap
/// password (the old runbook's env URL — Task 7's unlock page replaces
/// that arm with a typed field), and reboots — the ui's unlock build
/// lands here, because the envelope's absence is the one thing that
/// distinguishes recovery from every healthy boot. The step is the
/// identical first-install one (the shared
/// [`ws_core::dbcred::rotate_db_credential`]): connect with the TYPED
/// password — never a stored one, which by construction no longer
/// exists — mint a random replacement, ALTER the login role to it in
/// verifier form, seal at the volume's generation. Returns the fresh
/// credential in RAM custody so the caller connects with it (the api
/// rotates again at its own unlock, exactly as on a healthy volume). A
/// stale `.pending` a crashed earlier rotation left behind is
/// overwritten by this rotation's own pending write and promote. A
/// refused typed password maps to [`SetupError::DbRejected`]; neither
/// password is ever logged or carried in an error.
pub async fn recover_db_credential(
    keys_dir: &Path,
    passphrase: &[u8],
    database_url: &str,
    typed_db_password: &[u8],
    generation: u64,
) -> Result<SecretBuf, SetupError> {
    use sqlx::Connection as _;

    let role = db_role_of(database_url)?;
    // The connection rides the TYPED password — substituted into the
    // instance's `DATABASE_URL`, never the URL's own embedded credential
    // (which may be stale or absent).
    let typed = std::str::from_utf8(typed_db_password).map_err(|_| {
        SetupError::Core(CoreError::Config(
            "the typed database password is not valid UTF-8".to_owned(),
        ))
    })?;
    let connect_url = substitute_db_password(database_url, typed);
    let mut conn = sqlx::PgConnection::connect(&connect_url)
        .await
        .map_err(|err| {
            let core = CoreError::Database(err);
            if db_rejected(&core) {
                SetupError::DbRejected
            } else {
                SetupError::Core(core)
            }
        })?;
    Ok(ws_core::dbcred::rotate_db_credential(
        &mut conn,
        &role,
        &keys_dir.join(DB_CREDENTIAL_ENVELOPE_FILE),
        passphrase,
        generation,
    )
    .await?)
}

/// The sealed-at-rest envelope names, re-exported from ws-core's single
/// home for the volume contract (the setup flow writes them; every
/// process's boot and unlock reads them).
pub use ws_core::crypto::{
    DB_CREDENTIAL_ENVELOPE_FILE, JWT_ENVELOPE_FILE, MASTER_ENVELOPE_FILE, SECRET_ENVELOPE_FILE,
};
