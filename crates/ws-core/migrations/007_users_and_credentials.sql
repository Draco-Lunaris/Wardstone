-- 007: users, credentials, and the auth side tables (Plan 2).
--
-- Ports the "house" auth schema (linux-patch-manager's
-- `001_initial_schema.sql`, `012_account_lockout.sql`, and
-- `014_oidc_provider.sql`) onto Wardstone's tenant-shaped core, with the
-- tenancy invariants applied: EVERY table here carries `tenant_id`, and
-- the house's GLOBAL uniqueness on `username`/`email`/`azure_oid` is
-- narrowed to PER-TENANT (`UNIQUE (tenant_id, ...)`), so a second tenant is
-- never blocked by another tenant's rows.
--
-- Deliberate differences from the house:
--   - `role` and `auth_provider` are TEXT, not enum types: Wardstone's
--     capability vocabulary (`ws_core::models::rbac`) must be able to
--     extend without a `CREATE TYPE` migration. The allowed spellings are
--     pinned by the code side's parse (`Role::from_str`, `AuthMethod`/
--     `OIDC provider types`) and by the `role_capabilities` seed below.
--   - No `user_groups`/`groups` tables. Wardstone v1 has roles, not
--     groups; the house's `user_groups` references a `groups` table
--     Wardstone does not have, and porting it verbatim would fail with
--     "relation groups does not exist".
--   - `users.totp_secret` becomes `totp_secret_encrypted` + `totp_secret_nonce`
--     (BYTEA): the TOTP secret is sealed at rest by `ws_core::crypto`
--     `SecretBox` (XChaCha20-Poly1305), storing ciphertext and nonce
--     separately.
--   - `oidc_config` is PER-TENANT (`tenant_id` is the primary key), not the
--     house's single row (`id INTEGER PRIMARY KEY CHECK (id = 1)`), so a
--     tenant chooses its own OIDC provider. The `enabled` and `updated_at`
--     bookkeeping columns of the house row are dropped; configured
--     presence is enablement.
--   - `one_shot_tokens.minted_by` and `service_identities.created_by`
--     attribute the minting/creating user (nullable: the referencing user
--     row may outlive deletion with the attribute lost, which is an
--     accepted attribution cost, as in the audit log).
--   - `role_capabilities` is created AND seeded: a fresh database is never
--     in a state where every role resolves to no capabilities. The seeded
--     values are exactly `ws_core::models::rbac::role_capabilities()` -- the
--     one place the bundles are defined.
--
-- The `audit_log` changes (actor/method columns) are NOT part of this
-- migration: they land in migration 009 together with the code that
-- satisfies them, so there is never a window where the schema demands a
-- column the insert path does not populate.
--
-- Lockout columns (`failed_login_attempts`, `locked_until`) are included in
-- the table definition directly (the house added them in its 012 migration
-- onto an installed base; Wardstone creates the table whole).
--
-- Indexes: uniqueness constraints give `users` its per-tenant lookup
-- indexes and `refresh_tokens`/the hash lookups theirs; the remaining
-- access paths ported or needed are `refresh_tokens` by user (sliding
-- expiry window) and the partial active-token sweep index from the house's
-- `001`, plus tenant-scoped listings for `service_identities` and
-- `one_shot_tokens`. `oidc_config`'s primary key is its tenant.

CREATE TABLE users (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             uuid NOT NULL REFERENCES tenants(id),
    username              TEXT NOT NULL,
    display_name          TEXT NOT NULL DEFAULT '',
    email                 TEXT NOT NULL,
    role                  TEXT NOT NULL DEFAULT 'issuer',
    auth_provider         TEXT NOT NULL DEFAULT 'local',
    password_hash         TEXT,
    totp_secret_encrypted BYTEA,
    totp_secret_nonce     BYTEA,
    webauthn_credential   JSONB,
    mfa_enabled           BOOLEAN NOT NULL DEFAULT FALSE,
    azure_oid             TEXT,
    oidc_sub              TEXT,
    is_active             BOOLEAN NOT NULL DEFAULT TRUE,
    force_password_reset  BOOLEAN NOT NULL DEFAULT FALSE,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until          TIMESTAMPTZ,
    last_login_at         TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, username),
    UNIQUE (tenant_id, email),
    UNIQUE (tenant_id, oidc_sub),
    UNIQUE (tenant_id, azure_oid)
);

-- Refresh tokens: the house shape (`001_initial_schema.sql`), plus
-- `tenant_id`. One-hour sliding window by default, updated on each use.
CREATE TABLE refresh_tokens (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL UNIQUE,
    issued_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 hour',
    revoked      BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at   TIMESTAMPTZ,
    user_agent   TEXT,
    ip_address   INET
);

CREATE INDEX refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX refresh_tokens_active_expiry ON refresh_tokens (expires_at)
    WHERE revoked = FALSE;

-- OIDC provider configuration, one row per tenant (the house's
-- `oidc_config` singleton, ported per-tenant).
CREATE TABLE oidc_config (
    tenant_id     uuid NOT NULL REFERENCES tenants(id) PRIMARY KEY,
    provider_type TEXT NOT NULL CHECK (provider_type IN ('keycloak', 'azure', 'custom')),
    display_name  TEXT NOT NULL DEFAULT '',
    discovery_url TEXT NOT NULL DEFAULT '',
    client_id     TEXT NOT NULL DEFAULT '',
    -- The confidential client's secret, sealed at rest under the
    -- instance master KEK (XChaCha20-Poly1305 via ws_core::crypto's
    -- SecretBox, the TOTP pair's storage shape); an ABSENT pair is the
    -- public-client convention (Keycloak) — the empty string never
    -- reaches storage.
    client_secret_ciphertext BYTEA,
    client_secret_nonce     BYTEA,
    redirect_uri  TEXT NOT NULL DEFAULT '',
    scopes        TEXT NOT NULL DEFAULT 'openid profile email'
);

CREATE TABLE service_identities (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    name         TEXT NOT NULL,
    description  TEXT,
    created_by   uuid REFERENCES users(id),
    token_hash   TEXT NOT NULL UNIQUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX service_identities_tenant ON service_identities (tenant_id);

CREATE TABLE service_identity_capabilities (
    service_identity_id uuid NOT NULL REFERENCES service_identities(id) ON DELETE CASCADE,
    capability          TEXT NOT NULL,
    PRIMARY KEY (service_identity_id, capability)
);

CREATE TABLE one_shot_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    minted_by  uuid REFERENCES users(id),
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    used_at    TIMESTAMPTZ
);

CREATE INDEX one_shot_tokens_tenant ON one_shot_tokens (tenant_id);

CREATE TABLE one_shot_token_capabilities (
    one_shot_token_id uuid NOT NULL REFERENCES one_shot_tokens(id) ON DELETE CASCADE,
    capability        TEXT NOT NULL,
    PRIMARY KEY (one_shot_token_id, capability)
);

CREATE TABLE role_capabilities (
    role       TEXT NOT NULL,
    capability TEXT NOT NULL,
    PRIMARY KEY (role, capability)
);

-- The seed: exactly `ws_core::models::rbac::role_capabilities()` --
-- `Admin` = `ALL_CAPABILITIES` (15), `Issuer` = read-tightened issue
-- bundle, `Viewer` = read-only bundle. Never edited in place afterward: a
-- bundle change is a new migration plus a matching change in the model.
INSERT INTO role_capabilities (role, capability) VALUES
  ('admin',  'issue'), ('admin', 'generate_leaf_key'), ('admin', 'manage_profiles'),
  ('admin',  'manage_cas'), ('admin', 'manage_users'), ('admin', 'manage_api_tokens'),
  ('admin',  'manage_one_shot_tokens'), ('admin', 'export_ca_keys'), ('admin', 'manage_system'),
  ('admin',  'read_certificates'), ('admin', 'read_cas'), ('admin', 'read_profiles'),
  ('admin',  'read_audit'), ('admin', 'read_users'), ('admin', 'read_service_identities'),
  ('issuer', 'issue'), ('issuer', 'read_certificates'), ('issuer', 'read_cas'), ('issuer', 'read_profiles'),
  ('viewer', 'read_certificates'), ('viewer', 'read_cas'), ('viewer', 'read_profiles'), ('viewer', 'read_audit');