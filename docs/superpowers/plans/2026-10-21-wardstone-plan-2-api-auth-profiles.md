# Wardstone API, Auth, and Certificate Profiles — Implementation Plan (Plan 2 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the CA engine a front door — the REST API, the authentication and authorization layer, certificate profiles as an enforced policy, and the first-run setup that creates the first CA — so Wardstone is usable by a home lab and scriptable by automation, with "who may issue what" decided by the database rather than by discretion.

**Architecture:** Extends the six-crate workspace Plan 1 built, plus a seventh crate for the binary. `ws-core` gains the shared access vocabulary (capabilities, roles, actor types) and the schema for users, credentials, and profiles; `ws-auth` gains the house auth pattern (JWT + refresh tokens, argon2id, TOTP, OIDC) and depends on `ws-core`; `ws-api` gains an axum REST surface over `/api/v1/`; `ws-web` gains the TLS front door that path-proxies the API and serves the first-run setup page; a new `wardstone` crate produces the single binary with its `ui`/`api` invocation modes. `ws-ca` gains EKU support, a leaf-key enum, a refusal instead of a silent clamp, and a keystore slot for the setup certificate.

**Dependency graph (acyclic — this is a hard constraint).** The full edge list:
`ws-ca → ws-core`; `ws-auth → ws-core`; `ws-api → ws-core, ws-auth, ws-ca`; `ws-web → ws-core, ws-auth, ws-api, ws-ca`; `wardstone → ws-core, ws-auth, ws-api, ws-web, ws-ca` (the binary opens the keystore, which is a `ws-ca` type); `ws-worker → ws-core, ws-ca`; and `ws-ca → ws-worker` as a **dev-dependency only** (pre-existing — the smoke test drives the worker, and Cargo permits a dev-dependency cycle).
**`ws-core` depends on nothing but `ws-ca` is not required by it — and `ws-core` must never depend on `ws-auth`, `ws-api`, or `ws-web`.** Anything `ws-core` needs from those crates moves into `ws-core` (or `ws-ca`) instead. In particular:
- The **access vocabulary** (`Capability`, `Role`, `ActorType`, `AuthMethod`, `Actor`) lives in `ws-core`, so `ws-auth` re-exports it rather than defining it.
- The **refusal type** `Actor::require` returns is `CoreError`, not `ws-auth`'s `AuthError` — `ws-core` cannot name a `ws-auth` type without closing the cycle. `AuthError` stays in `ws-auth` for its own flows, and `ws-api` maps it.
- The **built-in default profiles** (`default_profiles`) live in `ws-core`, so both `ws-api` and `ws-web` call the same function without either depending on the other.

**Tech Stack:** Rust (edition 2021, rust-version 1.85), axum + tower + tower-http, jsonwebtoken, argon2, totp-rs, reqwest, sqlx 0.8 (Postgres, numbered migrations, `REQUIRED_MIGRATION_COUNT`), rcgen 0.14.10, x509-parser 0.18.1, der 0.8.2, chacha20poly1305 0.11 (already pinned — used for the secret-encryption helper), sha2, sha1, tokio, uuid v4, chrono, serde/serde_json, tracing, thiserror.

**Spec:** `docs/superpowers/specs/2026-10-21-wardstone-plan-2-api-auth-profiles-design.md`

**Design record:** `docs/superpowers/plans/2026-10-21-wardstone-plan-2-brainstorm.md` (26 settled decisions; the spec is the authority where the two differ)

## Global Constraints

- Spec: "no third-party ACME library" — unchanged from Plan 1; no ACME crate in this plan.
- Spec: "every table carries `tenant_id`" — every table this plan adds carries it, and the two house columns with global uniqueness (`users.username`, `users.email`) are ported **per-tenant**.
- Spec: JSON casing discipline — `#[serde(rename_all = "snake_case")]` on every DTO/enum serialized to JSON, matched to sqlx renames. **Where an enum is stored in a TEXT column, `as_str()` must equal its serde name** — the two are the same string, written once.
- Spec: "the browser talks to `ws-web` only; ws-web path-proxies `/api/v1/*` to ws-api over an internal compose network. ws-api exposes no published ports to the LAN in the default bundle" — ws-api publishes no ports.
- Spec: "one binary, two invocation modes (`wardstone ui` / `wardstone api`) from the same image" — Task 12 produces that binary; Task 13's compose file runs it.
- House rule: `cargo fmt --all` clean, `clippy --workspace --all-targets -- -D warnings` clean, no `unwrap()`/`expect()` in library code (typed error enums instead).
- House rule: no AI co-author attribution in commits. Short conventional-commit subjects.
- Migration convention: every migration is a new numbered file; `REQUIRED_MIGRATION_COUNT` in `crates/ws-core/src/db.rs` bumps with each one. **Never edit an applied migration** — sqlx checksums migration files as SHA-384 over the raw bytes, so even a trailing-newline change breaks every deployed database. Note that `connect()` runs the migrations *before* the count check, so a count mismatch in a deployed database surfaces as `CoreError::Migration` after the migrations succeed.
- DB-gated tests are `#[ignore]`d and run with `-- --include-ignored` against a live Postgres. The test database is `postgres://wardstone:wardstone@localhost:5432/wardstone_test`.
- **Test-suite conventions** (from `crates/ws-core/tests/repo_test.rs:12-38`): every DB-gated suite takes a **unique advisory-lock key** from the `0x0057_4144_5354_00xx` family and **sweeps its own rows first** (FK order), because `db_test.rs` asserts `tenants` is empty after the suite runs. **The keys already in use are `0003` through `000a`** (verified by grep: `0003`, `0004`, `0005`, `0006`, `0007`, `0008`, `0009`, `000a` — `000a` is the tenant-FK lock in `repo_test.rs:93`). **This plan's new suites take, one key per suite, no reuse:** `000b` (Task 4, schema suite), `000c` (Task 5, ws-core repo additions), `000d` (Task 8, ws-auth service identity), `000e` (Task 9, ws-auth one-shot), `000f` (Task 10, ws-api), `0010` (Task 11, ws-web setup), `0011` (Task 14, e2e).

## Review Focus

The five input classes the spec implies that task tests may not cover, with the task that owns each test:

1. **An API token whose capabilities exceed its creator's** — a token can never carry a capability the delegating identity lacks, whatever the request asks for. Pinned in Task 8 (`test_api_token_capabilities_cannot_exceed_creator`).
2. **A one-shot token replayed** — it is single-use; the second use is refused, and the certificate is issued exactly once. Pinned in Task 9 (`test_one_shot_token_is_single_use`).
3. **A key delivered to a caller that is not the one who requested it** — the admin-only key-generation response carries the key exactly once, is never logged, and is never retrievable afterwards. Pinned in Task 10 (`test_generated_key_is_delivered_once_and_never_persisted`).
4. **An audit row written without its mutation, or a mutation without its row** — the entry and the change commit together or not at all. Pinned in Task 10 (`test_audit_row_and_mutation_commit_together`).
5. **The setup endpoint reachable after setup completed** — it is not merely refused, it is not routed. Pinned in Task 11 (`test_setup_endpoint_is_gone_after_setup`).

---

### Task 1: `ws-auth` foundations — argon2id passwords and Ed25519 JWT

**Files:**
- Create: `crates/ws-auth/Cargo.toml`
- Create: `crates/ws-auth/src/lib.rs`
- Create: `crates/ws-auth/src/error.rs`
- Create: `crates/ws-auth/src/jwt.rs`
- Create: `crates/ws-auth/src/password.rs`
- Modify: `Cargo.toml` (workspace dependencies)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `ws_auth::error::AuthError` — `#[derive(thiserror::Error)]`, variants: `BadCredentials`, `Forbidden`, `TokenInvalid`, `TokenExpired`, `MfaRequired`, `MfaInvalid`, `AccountLocked`, `AccountDisabled`, `RateLimited`, `NotFound`, `Config(String)`, `Crypto(String)`. **`Forbidden` exists so a missing capability maps to 403, not 401** — `BadCredentials` is 401.
  - `ws_auth::password::hash_password(&str) -> Result<String, AuthError>` — argon2id, PHC string format.
  - `ws_auth::password::verify_password(&str, &str) -> Result<bool, AuthError>`.
  - `ws_auth::jwt::AccessClaims` — `user_id: Uuid`, `username: String`, `role: String`, `sid: Option<Uuid>` (the refresh token's id — the session identity the audit row records), `exp: i64`, `iat: i64`, `jti: String`.
  - `ws_auth::jwt::RefreshClaims` — `user_id: Uuid`, `jti: String`, `exp: i64`.
  - `ws_auth::jwt::issue_access_token(&AccessClaims, &JwtKeys) -> Result<String, AuthError>`.
  - `ws_auth::jwt::validate_access_token(&str, &JwtKeys) -> Result<AccessClaims, AuthError>`.
  - `ws_auth::jwt::JwtKeys` — `signing_key_pem: String`, `verification_key_pem: String`, `ttl_secs: i64`. `JwtKeys::load_or_create(dir: &Path) -> Result<Self, AuthError>` — **reads the two key files if they exist, and generates them if they do not**: `<dir>/jwt-signing-key.pem` (the Ed25519 **private** key, mode 0600) and `<dir>/jwt-verify-key.pem` (the public key). The house keeps exactly these two files (its `scripts/setup.sh:154-159` and `docker/entrypoint.sh:180-183` generate the pair with `openssl genpkey` and `openssl pkey -pubout`), and **`jsonwebtoken`'s `DecodingKey::from_ed_pem` accepts only an Ed25519 *public*-key PEM** — a private PKCS#8 PEM is rejected with `InvalidKeyFormat` — so the verification key cannot be derived by the library and the two-file layout is the correct one. Generating the pair on first boot is what makes the setup page reachable at all: the binary loads the keys **before** the setup form exists, so the keys must be creatable on a virgin volume.
    **The generation mechanism: `ed25519-dalek` (with the `pkcs8` feature) plus `pkcs8`/`der`/`pem`.** `jsonwebtoken` has **no key-generation API** (verified: no keygen in the crate), and `rand` cannot produce an Ed25519 key. So `ws-auth` gains `ed25519-dalek` (feature `pkcs8`), `pkcs8`, and `pem` as dependencies: generate the keypair, write the private key as a PKCS#8 PEM (`<dir>/jwt-signing-key.pem`, mode 0600) and the public key as an SPKI PEM (`<dir>/jwt-verify-key.pem`). **Do not shell out to the `openssl` CLI** — that would add a runtime dependency on openssl being installed in the image, and the house's CLI approach is a deployment script, not a library.
    **Operational note to carry into the docs:** losing `jwt-verify-key.pem` invalidates every issued token (users re-login); losing both means new tokens are signed with a different key. Neither is a data-loss event — the CA keys are separate.

**Notes for the implementer:**
- The house pattern is `linux-patch-manager/crates/pm-auth` — read `jwt.rs` and `password.rs` first. The house uses Ed25519 keys in PEM form; keep that. The house's `AccessClaims` uses `sub: String`; this plan diverges with `user_id: Uuid` — the house's `AccessClaims::user_id()` helper is replaced by reading the field.
- The house hashes **refresh tokens with SHA-256** (`pm-auth/src/refresh.rs:11,46,100,153`), not argon2id, despite the migration's comment claiming otherwise. **SHA-256 is correct for bearer tokens** — argon2id's slowness is for user-chosen passwords.
- **Workspace dependencies to add:** `axum`, `tower`, `tower-http`, `jsonwebtoken`, `hmac`, `reqwest`, `totp-rs`, `governor`, `tower_governor`, `rustls`, `tokio-rustls`, `axum-server`, **`hex`**, **`ed25519-dalek`** (feature `pkcs8`), **`pkcs8`**, and **`pem`**. (**No `base32` crate** — `totp-rs` provides base32 encoding. **No `hmac` in the normal dependencies** — HMAC-SHA1 is used only by the TOTP *test* to compute a code, so `hmac` is a **dev-dependency** of `ws-auth`.) `argon2` (0.6.0), `sha2` (0.10.9), `base64` (0.23.1), `sha1`, `chacha20poly1305` (0.11.0), `sqlx`, `rand`, `uuid`, `chrono`, `serde`, `serde_json`, `thiserror`, and `zeroize` are **already pinned** — do not re-add them to `[workspace.dependencies]`, but `ws-auth/Cargo.toml` must reference the ones it uses with `workspace = true`: `argon2`, `base32`? (no — `totp-rs` provides base32), `chacha20poly1305`? (no — `ws-auth` does not encrypt; `ws-core`'s `SecretBox` does), `hex`, `jsonwebtoken`, `rand`, `serde`, `serde_json`, `sha2`, `thiserror`, `tokio`, `uuid`, `chrono`, `hmac`, `reqwest`, `totp-rs`, `ws-core`. The house pins `jsonwebtoken = { version = "10", features = ["rust_crypto"] }`, `totp-rs = { version = "5", features = ["gen_secret", "otpauth"] }`, and `hex = "0.4"` — match those.
- `ws-auth` gains a `ws-core` dependency in Task 2 (for the shared vocabulary); it is added to `ws-auth/Cargo.toml` in Task 2, not here.

- [ ] **Step 1: Write the failing tests**

In `crates/ws-auth/tests/jwt_test.rs`: an access token validates and carries its claims; a token signed by a different key is `TokenInvalid`; an expired token is `TokenExpired`; a tampered payload is `TokenInvalid`; `JwtKeys::load_or_create` on a missing directory **generates** the key pair, and a second call **returns the same keys** (it does not regenerate); the generated signing key file is mode 0600; a token signed with the loaded keys validates. In `crates/ws-auth/tests/password_test.rs`: `hash_password` then `verify_password` returns true for the right password and false for the wrong one; two hashes of the same password differ (salted); the hash is a PHC argon2id string.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ws-auth`
Expected: FAIL — `ws_auth` has no `jwt` or `password` module.

- [ ] **Step 3: Implement `ws-auth`**

`Cargo.toml` with the deps above; `error.rs` with `AuthError`; `password.rs` with argon2id (house pattern: `Argon2::default()` with `Algorithm::Argon2id`); `jwt.rs` with the Ed25519 signing/verification and the claims types.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ws-auth`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

`cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings`, then commit with subject `feat(ws-auth): argon2id passwords and Ed25519 JWT issuing/validation`.

---

### Task 2: `ws-core` — the shared access vocabulary and the secret-encryption helper

**Files:**
- Create: `crates/ws-core/src/models/rbac.rs`
- Create: `crates/ws-core/src/crypto.rs`
- Modify: `crates/ws-core/src/models/mod.rs`
- Modify: `crates/ws-core/src/lib.rs`
- Modify: `crates/ws-core/src/models/audit.rs` (the `ActorType` enum gains `ApiToken` and `OneShotToken`)
- Modify: `crates/ws-core/Cargo.toml` — **add `chacha20poly1305` (features `["zeroize"]`, as `ws-ca` does), `zeroize`, and `rand`**; `SecretBox` needs all three and `ws-core`'s manifest today has none of them.
- Modify: `crates/ws-core/src/error.rs` — `CoreError` gains a `Forbidden` variant.
- Modify: `crates/ws-auth/Cargo.toml` (add the `ws-core` dependency) and `crates/ws-auth/src/lib.rs` (re-export the vocabulary)
- Test: `crates/ws-core/tests/rbac_test.rs`

**Interfaces:**
- Consumes: nothing.
- Produces — **all of these live in `ws-core`, and `ws-auth` re-exports them** (this is what keeps the crate graph acyclic: `ws-core` must never depend on `ws-auth`):
  - `ws_core::models::rbac::Capability` — `#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]`, `#[serde(rename_all = "snake_case")]`, with `as_str()` returning **exactly** the serde name: `issue`, `generate_leaf_key`, `manage_profiles`, `manage_cas`, `manage_users`, `manage_api_tokens`, `manage_one_shot_tokens`, `export_ca_keys`, `manage_system`, `read_certificates`, `read_cas`, `read_profiles`, `read_audit`, `read_users`, `read_service_identities`. `from_str(&str) -> Option<Self>`.
  - `ws_core::models::rbac::Role` — `Admin`, `Issuer`, `Viewer`; `as_str()` = `admin`, `issuer`, `viewer`.
  - `ws_core::models::rbac::ActorType` — `User`, `ApiToken`, `OneShotToken`, `System`, `AcmeAccount`; `as_str()` = `user`, `api_token`, `one_shot_token`, `system`, `acme_account`. **This is the same enum as `ws_core::models::audit::ActorType` — define it ONCE (here) and have `models/audit.rs` re-export it PUBLICLY** (`pub use crate::models::rbac::ActorType;` — a private re-export would stop `crates/ws-worker/src/jobs.rs` and `crates/ws-core/src/repo/audit_repo.rs` from compiling), so the audit row and the actor never disagree. (`models/audit.rs` currently defines it; move the definition here and re-export.)
  - `ws_core::models::rbac::AuthMethod` — `Session`, `ApiToken`, `OneShot`, `System`, `AcmeAccount`; `as_str()` = `session`, `api_token`, `one_shot`, `system`, `acme_account`.
  - `ws_core::models::rbac::Actor` — the one actor type: `actor_type: ActorType`, `actor_id: String`, `auth_method: AuthMethod`, `capabilities: Vec<Capability>`, `session_id: Option<Uuid>`, `tenant_id: Uuid`, `minted_by: Option<String>` (the human who minted a one-shot token; `None` for other actors).
  - `ws_core::models::rbac::role_capabilities(role: Role) -> &'static [Capability]` — the bundles: `Admin` → **every** capability; `Issuer` → `[Issue, ReadCertificates, ReadCas, ReadProfiles]`; `Viewer` → `[ReadCertificates, ReadCas, ReadProfiles, ReadAudit]`.
  - `ws_core::models::rbac::Actor::can(&self, cap: Capability) -> bool`.
  - `ws_core::models::rbac::Actor::require(&self, cap: Capability) -> Result<(), CoreError>` — `Err(CoreError::Forbidden)` when the capability is absent. **It returns `CoreError`, not `ws-auth`'s `AuthError`** — `ws-core` cannot name a `ws-auth` type without creating the cycle `ws-core → ws-auth → ws-core`. `CoreError` gains a `Forbidden` variant for this.
  - `ws_core::crypto::SecretBox` — `seal(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8> /*nonce*/), CoreError>` and `open(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoreError>`, using **chacha20poly1305** (already a workspace pin) with a key read from a file. `SecretBox::load(path: &Path) -> Result<Self, CoreError>` reads a 32-byte key from `<path>`; `SecretBox::create(path: &Path) -> Result<Self, CoreError>` generates and writes it with mode 0600 if absent. The key file is the TOTP/WebAuthn secret-encryption key, created at setup under the keys volume.

**Notes for the implementer:**
- **Why the vocabulary lives in `ws-core`:** `ws-core`'s repositories store and return capabilities, roles, and actor types, and `ws-auth` needs those same types to resolve credentials. Putting them in `ws-auth` would make `ws-core → ws-auth` while `ws-auth → ws-core` — a Cargo cycle that does not build. `ws-core` is the schema owner, so it owns the vocabulary; `ws-auth` re-exports it.
- The house's `pm-auth/src/rbac.rs` has a flat `UserRole` enum with `is_admin()`/`can_write()`. Wardstone's certificate permissions are finer than write/read, so the shape is extended — but the house's `from_str -> Option<Self>` idiom and the `as_str` hand-written spelling (because the column is TEXT) are the pattern to follow.
- The TOTP secret is stored encrypted at rest, per the house (`pm-auth/src/session.rs:83-84` — `totp_secret_encrypted` + `totp_secret_nonce`). The house's helper lives in `pm-core/src/crypto.rs`; `ws-core` has no crypto module yet, so this plan adds one. The key file path is the same one the compose bundle mounts: `<keys dir>/secret-encryption.key`, created at setup.

- [ ] **Step 1: Write the failing tests**

In `crates/ws-core/tests/rbac_test.rs`: `Admin` holds every capability (assert the set equals the full enum list, so a new capability cannot be added without deciding admin's bundle); `Issuer` holds `Issue` but not `ManageProfiles`; `Viewer` holds `ReadAudit` but not `Issue`; `Actor::can` reflects the capability list; `Actor::require` returns `Err(CoreError::Forbidden)` for an absent capability and `Ok` for a present one; every `Capability`, `Role`, `ActorType`, and `AuthMethod` round-trips through `as_str`/`from_str`, **and each `as_str()` equals its serde name**. A separate `crates/ws-core/tests/crypto_test.rs`: `SecretBox::seal` then `open` round-trips; `open` with a tampered ciphertext is a typed error; `create` then `load` round-trips; the key file is mode 0600.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ws-core --test rbac_test`
Expected: FAIL — no `models::rbac` module.

- [ ] **Step 3: Implement the vocabulary, the crypto helper, and the re-export**

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ws-core`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

Subject: `feat(ws-core): capability vocabulary, actor types, and the secret-encryption helper`.

---

### Task 3: `ws-auth` — TOTP and OIDC SSO

**Files:**
- Create: `crates/ws-auth/src/mfa_totp.rs`
- Create: `crates/ws-auth/src/oidc.rs`
- Modify: `crates/ws-auth/src/lib.rs`
- Test: `crates/ws-auth/tests/mfa_totp_test.rs`

**Interfaces:**
- Consumes: Task 1's `AuthError`.
- Produces:
  - `ws_auth::mfa_totp::generate_secret() -> Result<String, AuthError>` — base32 secret, 20 bytes.
  - `ws_auth::mfa_totp::verify_code(&str /*username*/, &str /*secret*/, &str /*code*/) -> Result<bool, AuthError>` — the house signature (`pm-auth/src/mfa_totp.rs:52`).
  - `ws_auth::mfa_totp::provisioning_uri(&str /*issuer*/, &str /*username*/, &str /*secret*/) -> String` — `otpauth://totp/…`.
  - `ws_auth::oidc::OidcConfig` — `provider_type: String` (`keycloak` | `azure` | `custom`), `display_name: String`, `discovery_url: String`, `client_id: String`, `client_secret: String`, `redirect_uri: String`, `scopes: String`.
  - `ws_auth::oidc::OidcDiscovery` — `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `issuer`.
  - `ws_auth::oidc::discover(&OidcConfig) -> Result<OidcDiscovery, AuthError>` — fetches the discovery document over HTTP (**`reqwest`**).
  - `ws_auth::oidc::exchange_code(&OidcConfig, &OidcDiscovery, &str /*code*/, &str /*state*/) -> Result<OidcIdentity, AuthError>`.
  - `ws_auth::oidc::OidcIdentity` — `subject: String`, `email: Option<String>`, `display_name: Option<String>`.
  - `ws_auth::oidc::identity_from_response(...)` — **verifies the ID token's signature against the provider's JWKS** before returning an identity. An unverified ID token is not an identity.

**Notes for the implementer:**
- **There is no house OIDC module to port.** The house OIDC flow lives in `pm-web/src/routes/sso.rs` and `pm-core/src/models.rs` — different crates, and built against the house's Azure/Keycloak-specific models. Port the *shape* (discovery → authorization redirect → code exchange → ID token verification), not the code.
- **The house's `mfa_webauthn.rs` is a STUB** (`WebAuthnError::NotImplemented`, no verification functions). **WebAuthn is out of scope for this plan** — the spec's auth enumeration is "JWT + refresh tokens, argon2id password hashing, TOTP MFA, OIDC SSO, RBAC, and account lockout", which does not include WebAuthn, and there is no working house implementation to port. Do not create `mfa_webauthn.rs`; the `users.webauthn_credential` column may still be ported for schema compatibility, but no code path writes or reads it this plan.
- TOTP needs `totp-rs` (with `gen_secret` and `otpauth` features) and a base32 codec — both are workspace additions in Task 1.
- OIDC needs `reqwest` — also a Task 1 addition.
- A failed TOTP or WebAuthn assertion returns `Err` — never a panic, never a bool a caller might ignore.

- [ ] **Step 1: Write the failing tests**

In `crates/ws-auth/tests/mfa_totp_test.rs`: a secret is 32 base32 characters; `verify_code` accepts a code computed from the secret (compute it in-test, e.g. with `totp-rs` itself or an HMAC-SHA1 over the counter) and rejects a wrong code; `provisioning_uri` contains `otpauth://totp/` and the secret.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ws-auth --test mfa_totp_test`
Expected: FAIL — no `mfa_totp` module.

- [ ] **Step 3: Implement the two modules**

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ws-auth`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

Subject: `feat(ws-auth): TOTP MFA and generic OIDC SSO`.

---

### Task 4: `ws-core` schema — users, credentials, profiles (migrations 007–008)

**Files:**
- Create: `crates/ws-core/migrations/007_users_and_credentials.sql`
- Create: `crates/ws-core/migrations/008_profiles.sql`
- Modify: `crates/ws-core/src/db.rs` (`REQUIRED_MIGRATION_COUNT` 6 → 8)
- Test: `crates/ws-core/tests/schema_test.rs` (advisory lock `0x0057_4144_5354_000c`)

**Interfaces:**
- Consumes: nothing.
- Produces: the schema for every later task.

- [ ] **Step 1: Write the failing tests**

In `crates/ws-core/tests/schema_test.rs` (DB-gated, `#[ignore]`d, advisory lock `0x0057_4144_5354_000c`, sweeping its own rows): after `connect()`, `users`, `refresh_tokens`, `oidc_config`, `service_identities`, `service_identity_capabilities`, `one_shot_tokens`, `one_shot_token_capabilities`, `role_capabilities`, `profiles`, `profile_revisions` all exist; `users` has `tenant_id` and its `username`/`email` uniqueness is **per-tenant**; `certificates` has a nullable `profile_revision_id` FK; `cas` has a composite FK from `(parent_id, tenant_id)`; `role_capabilities` is seeded (not merely created). **The `audit_log` columns are NOT asserted here** — they land in Task 5's migration 009, so they are asserted in Task 5's suite.

- [ ] **Step 2: Run tests to verify they fail**

Run: `DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test cargo test -p ws-core --test schema_test -- --include-ignored`
Expected: FAIL — the tables do not exist.

- [ ] **Step 3: Write the migrations**

**007 — users and credentials.**
`users`:
```sql
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
```
Notes: the house's `username`/`email` are **globally** UNIQUE (`001_initial_schema.sql:87,89`); narrowed to per-tenant here. The house's `azure_oid` is globally UNIQUE — **narrowed to per-tenant as well**, so a second tenant is not blocked by another tenant's Azure id. The two lockout columns come from the house's `012_account_lockout.sql`, not `001`. `role` and `auth_provider` are **TEXT** (the house uses enum types; Wardstone uses text so the capability model can extend without a type migration). `oidc_sub` is the generic OIDC subject (the house added it in `014_oidc_provider.sql:20`); it is the stable identity — the email is not.

`refresh_tokens` (house shape from `001_initial_schema.sql:127-149`, with `tenant_id`): id, user_id, token_hash TEXT NOT NULL UNIQUE, issued_at, last_used_at, expires_at, revoked BOOLEAN NOT NULL DEFAULT FALSE, revoked_at, user_agent, ip_address INET.

`oidc_config` — the house table is a single row (`id INTEGER PRIMARY KEY CHECK (id = 1)`, `014_oidc_provider.sql:24`); ported **per-tenant**: `tenant_id uuid NOT NULL REFERENCES tenants(id) PRIMARY KEY`, `provider_type TEXT NOT NULL CHECK (provider_type IN ('keycloak','azure','custom'))`, display_name, discovery_url, client_id, client_secret, redirect_uri, scopes.

`service_identities`: id, tenant_id NOT NULL REFERENCES tenants(id), name TEXT NOT NULL, description TEXT, created_by uuid REFERENCES users(id), token_hash TEXT NOT NULL UNIQUE, created_at, expires_at, revoked_at, last_used_at.
`service_identity_capabilities`: service_identity_id uuid NOT NULL REFERENCES service_identities(id) ON DELETE CASCADE, capability TEXT NOT NULL, PRIMARY KEY (service_identity_id, capability).
`one_shot_tokens`: id, tenant_id NOT NULL REFERENCES tenants(id), minted_by uuid REFERENCES users(id), token_hash TEXT NOT NULL UNIQUE, created_at, expires_at, used_at.
`one_shot_token_capabilities`: one_shot_token_id uuid NOT NULL REFERENCES one_shot_tokens(id) ON DELETE CASCADE, capability TEXT NOT NULL, PRIMARY KEY (one_shot_token_id, capability).
`role_capabilities`: role TEXT NOT NULL, capability TEXT NOT NULL, PRIMARY KEY (role, capability).
**And 007 seeds it**, so a fresh database is never in a state where every role resolves to no capabilities:
```sql
INSERT INTO role_capabilities (role, capability) VALUES
  ('admin',  'issue'), ('admin', 'generate_leaf_key'), ('admin', 'manage_profiles'),
  ('admin',  'manage_cas'), ('admin', 'manage_users'), ('admin', 'manage_api_tokens'),
  ('admin',  'manage_one_shot_tokens'), ('admin', 'export_ca_keys'), ('admin', 'manage_system'),
  ('admin',  'read_certificates'), ('admin', 'read_cas'), ('admin', 'read_profiles'),
  ('admin',  'read_audit'), ('admin', 'read_users'), ('admin', 'read_service_identities'),
  ('issuer', 'issue'), ('issuer', 'read_certificates'), ('issuer', 'read_cas'), ('issuer', 'read_profiles'),
  ('viewer', 'read_certificates'), ('viewer', 'read_cas'), ('viewer', 'read_profiles'), ('viewer', 'read_audit');
```
The seeded values are exactly `ws_core::models::rbac::role_capabilities()` — the one place the bundles are defined.

**There is no `user_groups` table and no groups model in v1** — Wardstone v1 has roles, not groups. (The house's `user_groups` references a `groups` table Wardstone does not have; porting it verbatim would fail with "relation groups does not exist".)

**The `audit_log` changes are NOT in this migration.** They land in **Task 5's** migration
(`009_audit_auth_method.sql`), in the same task that changes the `AuditEntry` model and
the worker's insert — so the schema change and every code change that satisfies it
land together, and there is never a window where the database has a NOT NULL column
the code does not populate. The migration content is specified in Task 5.

**008 — profiles.**
```sql
CREATE TABLE profiles (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           uuid NOT NULL REFERENCES tenants(id),
    name                TEXT NOT NULL,
    description         TEXT,
    current_revision_id uuid,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);
CREATE TABLE profile_revisions (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id    uuid NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    revision      INTEGER NOT NULL,
    name          TEXT NOT NULL,
    key_type      TEXT NOT NULL,
    key_usages    TEXT[] NOT NULL,
    eku           TEXT[] NOT NULL,
    lifetime_days INTEGER NOT NULL,
    san_patterns  TEXT[] NOT NULL,
    is_legacy     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_id      TEXT NOT NULL,
    UNIQUE (profile_id, revision)
);
ALTER TABLE profiles
    ADD CONSTRAINT profiles_current_revision_fk
    FOREIGN KEY (current_revision_id) REFERENCES profile_revisions(id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE certificates
    ADD COLUMN profile_revision_id uuid NULL REFERENCES profile_revisions(id);
ALTER TABLE cas
    ADD CONSTRAINT cas_parent_tenant_fk
    FOREIGN KEY (parent_id, tenant_id) REFERENCES cas (id, tenant_id) DEFERRABLE INITIALLY DEFERRED;
```
The `cas` composite FK is well-founded: `cas` already carries `cas_id_tenant_key UNIQUE (id, tenant_id)` from migration 006.

**The legacy backfill for existing `certificates.profile_name` values** (in this same migration 008, since the column stays):
`certificates.profile_name` is `NOT NULL` today (`002_certificates_and_revocation.sql:21`) and holds free-form labels matching no profile. The backfill creates, per tenant, one `profiles` row named `legacy`, and **one `profile_revisions` row per distinct label** — numbered **1, 2, 3… in a deterministic order** (the uniqueness constraint is `(profile_id, revision)`, so every legacy revision needs its own number), each carrying the label as its `name` and `is_legacy = true`. The NOT NULL constraint columns are filled with **explicit values**, not defaults: `key_type = 'rsa2048'`, `key_usages = ARRAY['digital_signature','key_encipherment']`, `eku = ARRAY['server_auth']`, `lifetime_days = 30`, and `san_patterns` = `ARRAY['*']` — the schema has no per-tenant default domain to read (the domain lives only in a profile's pattern list and in the setup audit row), so the legacy revision uses the permissive form. The constraint set is never used for issuance — it exists so the row is complete and readable, and `is_legacy` marks it as such. `profiles.current_revision_id` points at the **highest-numbered** legacy revision. Every `certificates` row is repointed at the revision matching its label.

**The `certificates.profile_name` column is RETAINED** as a denormalised label. It is not dropped in this plan: dropping it requires a separate migration after the code stops referencing it, and the spec's Global Constraints forbid editing an applied migration. The authority for a certificate's policy is `profile_revision_id`; `profile_name` is display only. (Deferred to a later plan.)

**Migration count:** `REQUIRED_MIGRATION_COUNT` 6 → 8 (two new files).

- [ ] **Step 4: Run tests to verify they pass**

Run: `DATABASE_URL=... cargo test -p ws-core --test schema_test -- --include-ignored`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

Subject: `feat(db): users, credentials, profiles, and tenant-scoped audit columns`.

---

### Task 5: `ws-core` models, repositories, and the audit auth-method migration

**Files:**
- Create: `crates/ws-core/migrations/009_audit_auth_method.sql`
- Modify: `crates/ws-core/src/db.rs` (`REQUIRED_MIGRATION_COUNT` 8 → 9)
- Create: `crates/ws-core/src/models/user.rs`
- Create: `crates/ws-core/src/models/profile.rs`
- Create: `crates/ws-core/src/models/credential.rs`
- Modify: `crates/ws-core/src/models/mod.rs`
- Create: `crates/ws-core/src/repo/user_repo.rs`
- Create: `crates/ws-core/src/repo/profile_repo.rs`
- Create: `crates/ws-core/src/repo/credential_repo.rs`
- Create: `crates/ws-core/src/repo/role_repo.rs`
- Create: `crates/ws-core/src/repo/refresh_repo.rs`
- Create: `crates/ws-core/src/repo/oidc_repo.rs`
- Create: `crates/ws-core/src/profile_match.rs`
- Modify: `crates/ws-core/src/repo/mod.rs`
- Modify: `crates/ws-core/src/models/audit.rs` (`AuditEntry` gains `auth_method` and `session_id`; the `ActorType` definition and its `FromStr`/`UnknownActorType` error live in `models/rbac.rs` — Task 2's — and `models/audit.rs` re-exports them)
- Modify: `crates/ws-core/src/repo/audit_repo.rs` (binds the new columns)
- Modify: `crates/ws-core/src/models/certificate.rs` and `src/repo/certificate_repo.rs` (gain `profile_revision_id: Option<Uuid>`; keep `profile_name` as the display label)
- **Modify: every construction site of `AuditEntry` or `CertificateModel` in the workspace** — a grep for `AuditEntry {` and `CertificateModel {` returns roughly 8 and 7 hits (the counts include the `pub struct` definitions and some function signatures, so treat them as grep hits, not literal counts). The known sites include `crates/ws-worker/src/jobs.rs:294`, `crates/ws-ca/tests/smoke_test.rs:385` and `:530`, `crates/ws-worker/tests/scheduler_test.rs:199` and `:500`, `crates/ws-core/tests/repo_test.rs:617`, `crates/ws-core/src/models/audit.rs:131`, plus the `try_into_model` conversions in `audit_repo.rs` and `certificate_repo.rs`. **Grep for them** — the list is not closed, and each one is a hard compile error once the models gain fields.
- Test: extend `crates/ws-core/tests/repo_test.rs` (advisory lock `0x0057_4144_5354_000d`); create `crates/ws-core/tests/profile_match_test.rs`

**Interfaces:**
- Consumes: Task 4's schema; Task 2's `Capability`, `Role`, `ActorType`, `AuthMethod`, `Actor`, `SecretBox`.
- Produces:
  - **Migration `009_audit_auth_method.sql`** — the audit columns land HERE, with the code that populates them:
    ```sql
    ALTER TABLE audit_log ADD COLUMN auth_method TEXT NULL;
    ALTER TABLE audit_log ADD COLUMN session_id uuid NULL;
    UPDATE audit_log SET auth_method = CASE actor_type
        WHEN 'user' THEN 'session'
        WHEN 'system' THEN 'system'
        ELSE 'system' END
      WHERE auth_method IS NULL;
    ALTER TABLE audit_log ALTER COLUMN auth_method SET NOT NULL;
    ```
    The `CASE` covers **every** `actor_type` value the closed enum has (`user`, `acme_account`, `system`) — a partial backfill would leave rows NULL and the `SET NOT NULL` would abort the migration. `acme_account` maps to `system` until ACME lands (Plan 4). `session_id` stays **nullable** (null for machine actors) and needs no backfill.
  - `ws_core::models::credential::RefreshTokenModel` — id, tenant_id, user_id, token_hash, issued_at, last_used_at, expires_at, revoked, revoked_at, user_agent, ip_address.
  - `ws_core::models::credential::OidcConfigModel` — tenant_id, provider_type, display_name, discovery_url, client_id, client_secret, redirect_uri, scopes.
  - `ws_core::repo::refresh_repo::RefreshTokenRepo` — stateless, `RefreshTokenRepo::new()`. `insert`, `get_by_hash`, `rotate` (revoke the old, insert the new), `revoke`, `touch_last_used`, `purge_expired`.
  - `ws_core::repo::oidc_repo::OidcConfigRepo` — stateless, `OidcConfigRepo::new()`. `get(tenant_id)`, `upsert(config)`.
  - `ws_core::repo::user_repo::UserRepo` — **stateless**: `#[derive(Default)] pub struct UserRepo;` with `UserRepo::new() -> Self { Self::default() }` (a bare `new()` with no arguments trips `clippy::new_without_default`, and `clippy -D warnings` is a house rule). `insert(&self, executor: impl PgExecutor<'_>, u: &UserModel) -> Result<(), CoreError>`; `get_by_username(executor, tenant_id, username)`; `get_by_id(executor, id)`; `get_by_oidc_sub(executor, tenant_id, sub)`; `get_by_email(executor, tenant_id, email)`; `list_by_tenant(executor, tenant_id, page, page_size)`; `update_role(executor, id, role)`; `deactivate(executor, id)`; `record_failed_login(executor, id)`; `clear_failed_logins(executor, id)`; `lock_until(executor, id, until)`.
- Produces:
  - `ws_core::models::user::UserModel` — id, tenant_id, username, display_name, email, role, auth_provider, password_hash (Option), totp_secret_encrypted (Option), totp_secret_nonce (Option), webauthn_credential (Option), mfa_enabled, azure_oid (Option), oidc_sub (Option), is_active, force_password_reset, failed_login_attempts, locked_until (Option), last_login_at (Option), created_at, updated_at.
  - `ws_core::models::profile::ProfileModel` — id, tenant_id, name, description, current_revision_id (Option), created_at.
  - `ws_core::models::profile::ProfileRevisionModel` — id, profile_id, revision, name, key_type, key_usages (Vec<String>), eku (Vec<String>), lifetime_days (i32), san_patterns (Vec<String>), is_legacy, created_at, actor_id.
  - `ws_core::models::credential::ServiceIdentityModel` — id, tenant_id, name, description, created_by, token_hash, created_at, expires_at, revoked_at, last_used_at.
  - `ws_core::models::credential::OneShotTokenModel` — id, tenant_id, minted_by, token_hash, created_at, expires_at, used_at.
  - `ws_core::repo::user_repo::UserRepo` — **stateless**: `#[derive(Default)] pub struct UserRepo;` with `UserRepo::new() -> Self { Self::default() }` (a bare `new()` with no arguments trips `clippy::new_without_default`, and `clippy -D warnings` is a house rule). `insert(&self, executor: impl PgExecutor<'_>, u: &UserModel) -> Result<(), CoreError>`; `get_by_username(executor, tenant_id, username)`; `get_by_id(executor, id)`; `get_by_oidc_sub(executor, tenant_id, sub)`; `get_by_email(executor, tenant_id, email)`; `list_by_tenant(executor, tenant_id, page, page_size)`; `update_role(executor, id, role)`; `deactivate(executor, id)`; `record_failed_login(executor, id)`; `clear_failed_logins(executor, id)`; `lock_until(executor, id, until)`.
  - `ws_core::repo::profile_repo::ProfileRepo` — stateless, `ProfileRepo::new()`. `insert_profile(executor, p)`; `insert_revision(executor, r)`; `get_profile(executor, id)`; `get_revision(executor, id)`; `current_revision(executor, profile_id)`; `list_by_tenant(executor, tenant_id, page, page_size)`; `list_revisions(executor, profile_id)`; `update(executor, profile_id, new_revision) -> Result<(), CoreError>` — **the optimistic-concurrency write**: `UPDATE profiles SET current_revision_id = $new WHERE id = $id AND current_revision_id = $expected`, and `Ok(())` only when a row was affected — a zero-row update means the revision moved and the caller retries. `delete(executor, id)`.
  - `ws_core::repo::credential_repo::CredentialRepo` — stateless, `CredentialRepo::new()`. `insert_service_identity(executor, s)`; `get_service_identity_by_hash(executor, hash)`; `list_service_identities(executor, tenant_id, page, page_size)`; `revoke_service_identity(executor, id)`; `set_service_identity_capabilities(executor, id, caps)`; `service_identity_capabilities(executor, id)`; `insert_one_shot_token(executor, t)`; `get_one_shot_by_hash(executor, hash)`; **`consume_one_shot_by_hash(executor, hash) -> Result<Option<OneShotTokenModel>, CoreError>`** — the lookup-and-mark in ONE statement: `UPDATE one_shot_tokens SET used_at = now() WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() RETURNING id, tenant_id, minted_by, created_at, expires_at, used_at`. A row count of zero means the token was already used, expired, or unknown; one means this caller consumed it. **Two concurrent consumers cannot both succeed.**
  - `ws_core::models::profile::default_profiles(domain: &str, cidrs: &[String]) -> Vec<ProfileRevisionModel>` — the built-in profiles: `web-server` (key type `rsa2048`, key usages `digital_signature` + `key_encipherment`, EKU `server_auth`, lifetime 30 days) and `web-server-ecdsa` (key type `ecdsa-p256`, key usages `digital_signature`, EKU `server_auth`, lifetime 30 days), both with the SAN pattern list `[domain, *.domain, …cidrs]`. **The key usages are not optional** — Task 7 makes an empty list illegal, so a profile without them could issue nothing. Lives in `ws-core` so `ws-api` and `ws-web` can both call it without either depending on the other. **It lives in Task 5, not Task 2** — it returns `ProfileRevisionModel`, which Task 5 creates.
  - `ws_core::repo::role_repo::RoleRepo` — stateless, `#[derive(Default)] pub struct RoleRepo;` with `new()`. `capabilities_for_role(executor, role) -> Result<Vec<Capability>, CoreError>` — **reads the `role_capabilities` table**; this is the runtime authority. `seed_role_capabilities(executor) -> Result<(), CoreError>` — writes the bundles from `ws_core::models::rbac::role_capabilities()` and is **idempotent** (`ON CONFLICT (role, capability) DO NOTHING`).
    **The table is seeded by migration 007**, not by this method: the seed rows are part of the schema, so a fresh database is never in a state where every role resolves to no capabilities. `seed_role_capabilities()` remains available for an operator who edits the table by hand and wants to restore the defaults.
  - `ws_core::models::rbac::KeyUsagePurpose` — a **Wardstone** enum, not rcgen's: `DigitalSignature`, `KeyEncipherment`, `DataEncipherment`, `KeyAgreement`, `KeyCertSign`, `CrlSign`, `ContentCommitment`, `EncipherOnly`, `DecipherOnly`. `as_str()` returns **exactly** `digital_signature`, `key_encipherment`, `data_encipherment`, `key_agreement`, `key_cert_sign`, `crl_sign`, `content_commitment`, `encipher_only`, `decipher_only` (snake_case, matching the house style — the RFC 5280 aliases like `digitalSignature` are **not** used). `from_str`. **This is the ONLY key-usage enum in the workspace.** `ws-ca` re-exports it (`pub use ws_core::models::rbac::KeyUsagePurpose;`), so `LeafSpec.key_usages` is `Vec<ws_core::models::rbac::KeyUsagePurpose>` and the profile's `TEXT[]` and the engine's value come from one vocabulary with no translation between spellings or types.
    **The rcgen conversion is NOT a method on this enum.** `ws-core` does not depend on `rcgen` (that would put the schema crate under the CA engine's crypto dependency), and an `impl From<ws_core::…> for rcgen::KeyUsagePurpose` in `ws-ca` would violate the orphan rule (E0210 — the local type appears only as a trait parameter behind a foreign `Self`). The conversion is therefore a **free function in `ws-ca`**: `ws_ca::issue::key_usage_to_rcgen(k: ws_core::models::rbac::KeyUsagePurpose) -> rcgen::KeyUsagePurpose`.
  - `ws_core::repo::paging(page: u32, page_size: u32) -> Result<(i64, i64), CoreError>` — **the shared helper, created HERE** (Task 5 needs it for its `list_by_tenant` methods; Task 6 replaces Plan 1's two copies with it). It returns `(limit, offset)`, matching the two existing copies (`certificate_repo.rs:261-266` and `audit_repo.rs:129-134`, both ending `Ok((i64::from(page_size), offset))` and both called as `let (limit, offset) = paging(page, page_size)?;` then `LIMIT $2 OFFSET $3`). It **clamps `page_size` to a maximum of 500**, and the clamped value is used in **both** the limit and the offset. Conversion is via `i64::try_from`, returning `CoreError::Config` on overflow.
  - `ws_core::profile_match::san_is_permitted(patterns: &[String], san: &str) -> Result<bool, CoreError>` — **the pattern matcher**, and the only place SAN-permission logic lives. `san` is either a DNS name or an IP literal; the function parses it and matches it against the profile's pattern list:
    - A pattern that parses as an **IP literal** is an IP pattern; a pattern containing `/` is a **CIDR** pattern; anything else is a **DNS name** pattern.
    - A DNS pattern matches **exactly** that name (case-insensitively). `example.com` does not match `sub.example.com`.
    - A `*.` pattern matches **one or more** additional labels — `a.example.com` and `a.b.example.com` both match — but **not** `example.com` itself.
    - A CIDR pattern matches any IP in the range. Use `sqlx::types::ipnet::{Ipv4Net, Ipv6Net}` — these are re-exported by sqlx's `ipnet` feature, which ws-core already enables. **The `ipnet` crate itself is NOT a dependency of ws-core**; write `sqlx::types::ipnet::…`, not `ipnet::…`.
    - A bare `*` matches **any DNS name** — not an IP literal (an IP needs an explicit IP or CIDR pattern, or `0.0.0.0/0`).
    - An unparsable pattern is `CoreError::Config` (a broken stored pattern is a data error, not a silent mismatch).
    - The matcher is **pure and total** over `(patterns, san)` — no DB, no I/O — so it is exhaustively unit-testable.

**Notes for the implementer:**
- **Every repository is stateless and every method takes an executor** — `executor: impl PgExecutor<'_>`. The repositories hold no `PgPool`; the caller passes `&pool` or `&mut *tx`. This is what lets a mutation and its audit row share one transaction. The bound needs the explicit lifetime (`impl PgExecutor<'_>`) — a bare `impl PgExecutor` does not compile (E0726). And inside a transaction, pass **`&mut *tx`** (the deref to `&mut PgConnection`): `&mut Transaction` does not implement `PgExecutor` in sqlx 0.8.6.
- **Every stateless repository follows ONE shape** — `#[derive(Default)] pub struct XRepo;` with `pub fn new() -> Self { Self::default() }`. A unit struct with a no-argument `new()` and no `Default` trips `clippy::new_without_default`, which is an **error** under the house rule `clippy --workspace --all-targets -- -D warnings`. This applies to every new repo (`UserRepo`, `ProfileRepo`, `CredentialRepo`, `RoleRepo`, `RefreshTokenRepo`, `OidcConfigRepo`) **and** to Plan 1's five repos when Task 6 makes them stateless.
- `AuditRepo::record` binds an explicit column list, so it must bind `auth_method` (NOT NULL) and `session_id`. **The worker sets `auth_method: AuthMethod::System` at its audit write in THIS task** — the worker's `crl_built` write is one of the construction sites listed above, and it must be updated here, in the same task that makes the column NOT NULL. (Task 13 then only *asserts* the value; it does not change the call site.)
- The `users` table stores the TOTP secret **encrypted** with Task 2's `SecretBox` (`totp_secret_encrypted` + `totp_secret_nonce`, the house's column names). The helper is Task 2's; this task carries the two columns.

- [ ] **Step 1: Write the failing tests**

Extend `crates/ws-core/tests/repo_test.rs` (advisory lock `0x0057_4144_5354_000d`): a user inserts and reads back with its per-tenant uniqueness (a second tenant may reuse the same username and email); a failed login increments `failed_login_attempts` and sets `locked_until`; a profile inserts with a revision and `update` appends revision 2 and repoints `current_revision_id` while revision 1 remains retrievable; **`update` with a stale expected revision affects zero rows and returns an error** (the optimistic-concurrency property); a service identity stores capabilities and reads them back; a one-shot token is retrievable by hash, and **`consume_one_shot_by_hash` succeeds once and then returns `None`**; `RoleRepo::capabilities_for_role` returns the Task 2 bundles read from the table (which migration 007 seeded); `seed_role_capabilities` is idempotent; a refresh token round-trips and rotates; an OIDC config round-trips; an audit entry round-trips with `auth_method` and `session_id`; **the worker's `crl_built` row is written with `auth_method = 'system'`** and survives the NOT NULL constraint.

`paging()` (created in this task): `paging(0, 10)` returns `Ok((10, 0))` — **limit first, offset second**; `paging(0, 10_000)` returns `Ok((500, 0))` (clamped); `paging(0, u32::MAX)` returns `Ok((500, 0))`; `paging(2, 10)` returns `Ok((10, 20))` — the offset is `page * page_size`, so with the clamped page size it is `2 * 10 = 20`.

**In a new `crates/ws-core/tests/profile_match_test.rs`** (pure, not DB-gated) — the matcher's rules, exhaustively: `example.com` matches `example.com` but **not** `sub.example.com`; `*.example.com` matches `a.example.com` and `a.b.example.com` but **not** `example.com`; matching is case-insensitive (`EXAMPLE.com` matches `example.com`); `10.0.0.0/8` matches `10.1.2.3` but not `11.0.0.1`; the IP pattern `10.0.0.5` matches that address; a bare `*` matches any DNS name but **not** an IP literal; `0.0.0.0/0` matches every IPv4 address; an unparsable pattern is a typed error rather than a silent non-match.

- [ ] **Step 2: Run tests to verify they fail**

Run: `DATABASE_URL=... cargo test -p ws-core -- --include-ignored`
Expected: FAIL — the new modules do not exist.

- [ ] **Step 3: Implement the models and repositories**

- [ ] **Step 4: Run tests to verify they pass**

Run: `DATABASE_URL=... cargo test -p ws-core -- --include-ignored`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

Subject: `feat(db): user, profile, and credential models and repositories`.

---

### Task 6: `ws-core` — widen Plan 1's repositories to the executor shape and bound `paging`

**Files:**
- Modify: all five Plan 1 repositories (`tenant_repo.rs`, `ca_repo.rs`, `certificate_repo.rs`, `audit_repo.rs`, `ocsp_repo.rs`) — become **stateless** (`pub struct AuditRepo;`) with `AuditRepo::new()`, and every method takes `executor: impl PgExecutor<'_>`
- Modify: `crates/ws-core/src/repo/audit_repo.rs` and `crates/ws-core/src/repo/certificate_repo.rs` (the two existing `paging()` copies — `audit_repo.rs:129` and `certificate_repo.rs:261` — are replaced by Task 5's shared helper)
- Modify: `crates/ws-ca/src/serial.rs` (`allocate_serial` takes the executor)
- **Modify: every call site of the five repositories** — `crates/ws-core/tests/repo_test.rs`, `crates/ws-ca/tests/smoke_test.rs`, `crates/ws-worker/src/jobs.rs:137-139` (the repos are constructed at 137-139; 136 is `list_all_cas`), `crates/ws-worker/tests/scheduler_test.rs`. (`crates/ws-ca/tests/serial_test.rs` constructs no repository, but it **does** need editing for `allocate_serial`'s new signature.)
- Test: extend `crates/ws-core/tests/repo_test.rs`

**Interfaces:**
- Consumes: Task 5's executor-style repos and its shared `paging()` helper.
- Produces: every Plan 1 repo method now takes `executor: impl PgExecutor<'_>`.

**Notes for the implementer:**
- The repos' `pool: PgPool` field and `new(&PgPool)` constructors become dead once every method takes an executor — and `clippy -D warnings` (a house rule) fails on unused struct fields. **The repos become stateless**: `pub struct AuditRepo;` with `AuditRepo::new()`. Update every construction site (listed above) to `AuditRepo::new()` and pass `&pool` (or `&mut *tx`) at each call.
- `paging()`'s clamp is a **DoS fix**: `page_size` is currently an unbounded `u32`, so a caller could ask for four billion rows. The order of the returned tuple is `(limit, offset)` — **do not swap it**; the two existing call sites bind it that way.
- **`allocate_serial` inside a transaction.** Plan 1's implementation (`crates/ws-ca/src/serial.rs:87-116`) loops up to `MAX_ATTEMPTS`, re-drawing on a unique violation. **A unique violation aborts the enclosing Postgres transaction**, so the loop cannot run as written inside one. **Use `ON CONFLICT DO NOTHING` + a `rows_affected() == 0` check unconditionally** — that is correct both inside a transaction and outside it, and it needs no error to be raised. **Delete the now-unused `is_unique_violation` helper** (`serial.rs:161`): leaving it would be dead code, and `clippy -D warnings` is a house rule. (The alternative — keeping a separate in-transaction path — is impossible: once the signature takes a generic `executor: impl PgExecutor<'_>`, the function cannot tell a transaction from a pool.)
- **The correct invariant about burned serials:** when the serial INSERT is in the SAME transaction as the certificate INSERT, a rolled-back issuance **releases** the serial — it is not burned, and the next issuance may draw the same number. That is safe, because the earlier certificate was never issued. The old claim ("a rolled-back issuance burns a serial") was wrong; the safe property is that a serial is only ever attached to a certificate that actually exists, and the `(ca_id, serial)` uniqueness constraint still prevents two live certificates sharing a serial.

- [ ] **Step 1: Write the failing tests**

Extend `crates/ws-core/tests/repo_test.rs`: a repository method called with `&mut *tx` and one called with `&pool` both work (proving the generic executor); the two Plan 1 repos' `list_by_tenant` methods still return the right page after the widening. (`paging()`'s own tests live in Task 5, where the helper is created.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `DATABASE_URL=... cargo test -p ws-core --test repo_test -- --include-ignored`
Expected: FAIL — the Plan 1 repos are not yet stateless.

- [ ] **Step 3: Widen the repositories and the serial allocator**

- [ ] **Step 4: Run tests to verify they pass**

Run: `DATABASE_URL=... cargo test --workspace -- --include-ignored`
Expected: PASS — including the Plan 1 suites, which now call the widened methods.

- [ ] **Step 5: Lint and commit**

Subject: `refactor(db): stateless executor-agnostic repositories and a bounded paging helper`.

---

### Task 7: `ws-ca` engine changes — EKU, leaf keys, refusal, lifetime span, setup slot

**Files:**
- Modify: `crates/ws-ca/src/issue.rs` (`LeafSpec` gains `ekus`, `key_type`, and a `lifetime` span; refuses empty EKU and key-usage lists; refuses rather than clamps `not_after`)
- Create: `crates/ws-ca/src/leafkey.rs`
- Modify: `crates/ws-ca/src/lib.rs` (adds `pub mod leafkey;`)
- Modify: `crates/ws-ca/src/ca.rs` (leaf key generation for every pinnable algorithm)
- Modify: `crates/ws-ca/src/keystore.rs` (a setup-key slot; `has_stored_keys` counts it)
- Test: extend `crates/ws-ca/tests/issue_test.rs`; extend `crates/ws-ca/tests/ca_creation_test.rs` (**there is no `keystore_test.rs`** — the keystore tests live in `ca_creation_test.rs`, where `ensure_master_key` is already exercised)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `ws_ca::leafkey::LeafKeyType` — `Rsa2048`, `Rsa3072`, `EcdsaP256`, `EcdsaP384`, `Ed25519`. `as_str()` returns **exactly** `rsa2048`, `rsa3072`, `ecdsa-p256`, `ecdsa-p384`, `ed25519` — the same spellings Plan 1's test fixtures already write into `certificates.key_type` (`crates/ws-ca/tests/smoke_test.rs:540` writes `"ecdsa-p256"`), so existing rows stay parseable — and `from_str`. **The hyphenated spellings are not serde's snake_case** (`EcdsaP256` would serialize as `ecdsa_p256`), so this enum carries **explicit `#[serde(rename = "…")]` attributes** on each variant so that `as_str()` and the serde name stay identical, as the plan's Global Constraints require.
  - `ws_ca::leafkey::generate_leaf_key(LeafKeyType) -> Result<(rcgen::KeyPair, Vec<u8> /*PKCS#8 DER*/), CaError>` — the key and its DER. For RSA, the DER comes from the **existing** `generate_rsa` helper in `ca.rs` (the `rsa` crate — rcgen's ring backend cannot generate RSA); for Ed25519 and the ECDSA curves, from rcgen's `KeyPair::generate_for(&PKCS_ED25519 / &PKCS_ECDSA_P256_SHA256 / &PKCS_ECDSA_P384_SHA384)` and `key_pair.serialize_der()`.
  - `ws_ca::issue::ExtKeyUsagePurpose` — `ServerAuth`, `ClientAuth`, `CodeSigning`, `EmailProtection`, `OcspSigning`, `TimeStamping`. `as_str()` returns **exactly** `server_auth`, `client_auth`, `code_signing`, `email_protection`, `ocsp_signing`, `time_stamping` (snake_case, matching the house style — **not** the RFC 5280 OID aliases like `serverAuth`). `from_str`. The conversion to the engine's type is the free function `eku_to_rcgen` below.
  - `ws_ca::issue::LeafSpec` — `sans: Vec<SanEntry>`, `key_usages: Vec<KeyUsagePurpose>` (the re-exported `ws-core` enum), **`ekus: Vec<ExtKeyUsagePurpose>`**, **`key_type: LeafKeyType`**, **`lifetime: chrono::Duration`** (the certificate's **span**), `subject_cn: Option<String>`, `serial: u128`. The old `not_after: Option<DateTime<Utc>>` is **replaced** by `lifetime`.
  - `ws_ca::issue::KeyUsagePurpose` — **not a second enum**: `pub use ws_core::models::rbac::KeyUsagePurpose;` — a re-export of the one enum `ws-core` owns (Task 2). The conversion to the engine's type is the free function `ws_ca::issue::key_usage_to_rcgen(k: KeyUsagePurpose) -> rcgen::KeyUsagePurpose` (a method on the enum would put `rcgen` into `ws-core`, and an `impl From<…>` would violate the orphan rule).
  - `ws_ca::issue::eku_to_rcgen(e: ExtKeyUsagePurpose) -> rcgen::ExtendedKeyUsagePurpose` — a **free function**, like `key_usage_to_rcgen` (a method on the enum would put `rcgen` into `ws-core`; an `impl From<…>` would violate the orphan rule). rcgen 0.14.10's enum has the same variants plus `Any` and `Other(Vec<u64>)`; **omitting those two is deliberate** (a profile cannot express "any EKU" or an unknown OID), so the conversion is a total match over Wardstone's six variants.
  - `ws_ca::keystore::KeyStore::store_setup_key(&mut self, der: &[u8]) -> Result<(), CaError>` / `load_setup_key(&self) -> Result<Zeroizing<Vec<u8>>, CaError>` — the setup certificate's key, stored as an envelope **exactly like a CA key** (encrypted at rest under the master KEK), at `<dir>/ca/setup.key` — inside the directory `has_stored_keys` scans, with a `.key` suffix. Its envelope's associated data is **not** a CA id; it is the fixed literal `wardstone-setup-key/v1`.

**Notes for the implementer:**
- **The clamp becomes a refusal.** Plan 1 silently shortens a leaf's `not_after` to the issuing CA's `notAfter` (`crates/ws-ca/src/issue.rs:419-423`). Change it to a typed `CaError::X509` — a certificate that silently differs from its profile is a policy violation, and a silent shortening is invisible to both the caller and the auditor.
- **Lifetime is a span, and `ws-ca` owns the arithmetic.** Plan 1 computes `not_before` internally (midnight UTC one day before today — a deliberate clock-skew margin, `issue.rs:518`) and `not_after = not_before + lifetime` (`issue.rs:524-527`). Keep the margin, and keep the computation internal: `LeafSpec` carries a **`lifetime: chrono::Duration`**, and `ws-ca` computes `not_after = not_before + lifetime` itself. The caller **cannot** compute an absolute span end (it cannot see the internal `not_before`), and an absolute instant would make the span up to a day longer than the profile's number. The profile's `lifetime_days` maps 1:1 onto `LeafSpec.lifetime`.
- **Empty EKU and key-usage lists are illegal** — an absent extension is *more* permissive than `serverAuth` (RFC 5280 §4.2.1.3). `sign_leaf_with` refuses them with a typed error. This needs EKU support: `params.extended_key_usages`.
- `rcgen` 0.14.10 can generate P-256 and P-384 (`KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)` / `PKCS_ECDSA_P384_SHA384`); Plan 1's `generate_key_pair` (`ca.rs:387-392`) handles only Ed25519 and RSA. The RSA path keeps using the `rsa` crate.
- **`has_stored_keys` scans only `ca/` for `*.key`** (`keystore.rs:328-344`), and it is what stops `ensure_master_key` from minting a fresh master over an existing store (`keystore.rs:167-169` returns `Corrupt`). The setup key therefore **must** be inside that directory with a `.key` suffix — the plan commits to `<dir>/ca/setup.key`, not to extending the scan.
- **Every `LeafSpec` literal in Plan 1's suites needs the new fields** — a grep for `LeafSpec {` returns roughly 21 hits, across `crates/ws-ca/tests/issue_test.rs`, `crates/ws-ca/tests/smoke_test.rs`, `crates/ws-ca/tests/ca_creation_test.rs` (two, at ~:328 and ~:563), and `crates/ws-ca/tests/ocsp_test.rs` (one, at ~:82). **Grep for `LeafSpec {`** — the list is not closed. Do **not** derive `Default` on `LeafSpec`: a derived default would yield empty `ekus` and `key_usages` and a zero `lifetime` — exactly what this task refuses — plus `serial = 0`, an illegal RFC 5280 serial. Update each literal explicitly.

- [ ] **Step 1: Write the failing tests**

In `crates/ws-ca/tests/issue_test.rs`: a leaf with `ekus: [ExtKeyUsagePurpose::ServerAuth]` carries the EKU extension; a leaf with an empty `ekus` is refused with a typed error; a leaf with an empty `key_usages` is refused; a leaf whose requested lifetime reaches beyond the issuing CA's `notAfter` is **refused** (not silently clamped) with a typed error naming both instants; the issued leaf's span (`not_after − not_before`) equals the requested `lifetime` exactly; a P-256 CSR with `key_type: EcdsaP256` issues; a P-256 CSR against a profile pinning `Rsa2048` is refused. In `crates/ws-ca/tests/ca_creation_test.rs` (where the keystore tests live — **there is no `keystore_test.rs`**): `store_setup_key` then `load_setup_key` round-trips; **deleting `master.key` and calling `ensure_master_key` returns `CaError::Corrupt` rather than minting a fresh master** (the setup key is visible to `has_stored_keys`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ws-ca`
Expected: FAIL — no `leafkey` module, no EKU field, no setup slot.

- [ ] **Step 3: Implement the engine changes**

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ws-ca`
Expected: PASS — including Plan 1's existing issue and keystore suites.

- [ ] **Step 5: Lint and commit**

Subject: `feat(ws-ca): EKU support, pinnable leaf keys, refusal over silent clamp, setup key slot`.

---

### Task 8: `ws-auth` — service identities, API tokens, and refresh tokens

**Files:**
- Create: `crates/ws-auth/src/service_identity.rs`
- Create: `crates/ws-auth/src/refresh.rs`
- Modify: `crates/ws-auth/src/lib.rs`
- Test: `crates/ws-auth/tests/service_identity_test.rs` (DB-gated, advisory lock `0x0057_4144_5354_000d`)

**Interfaces:**
- Consumes: Task 2's vocabulary; Task 5's repos.
- Produces:
  - `ws_auth::service_identity::ServiceIdentity` — id, tenant_id, name, description, `token: String` (the plaintext, returned once), capabilities, created_at, expires_at.
  - `ws_auth::service_identity::create_service_identity(executor: impl PgExecutor<'_>, name: &str, description: Option<&str>, capabilities: &[Capability], creator: &Actor, repo: &CredentialRepo) -> Result<ServiceIdentity, AuthError>` — mints a 32-byte random token, stores **only its SHA-256 hash**, and returns the plaintext **once**. The two inserts (the identity and its capabilities) are **one transaction**. The token is presented to the client as **hex** (the house's encoding, `pm-auth/src/refresh.rs:45-50`) with the prefix `ws_at_`; the stored `token_hash` is `hex::encode(Sha256::digest(raw_bytes))`.
  - `ws_auth::service_identity::authenticate_token(plaintext: &str, executor, repo) -> Result<Option<Actor>, AuthError>` — hashes, looks up, checks revocation and expiry, and resolves an `Actor` with `actor_type = ApiToken`, `auth_method = ApiToken`, and the stored capabilities.
  - `ws_auth::refresh::RefreshToken` / `issue_refresh_token` / `rotate_refresh_token` / `revoke_refresh_token` / `authenticate_refresh_token` — the house `pm-auth/src/refresh.rs` API, hashed with SHA-256, presented as hex with the prefix `ws_rt_`.

**Notes for the implementer:**
- **A token's capabilities can never exceed its creator's** — the Review Focus item 1. `create_service_identity` must intersect the requested capabilities with the creator's own; a request naming a capability the creator lacks is a typed error, not a silent narrowing.
- The token plaintext is returned once and never stored. The API layer must not log it (Task 10's redaction).
- `ws-auth` now depends on `ws-core` (Task 2 added the edge). `ws-core` does **not** depend on `ws-auth`.

- [ ] **Step 1: Write the failing tests**

In `crates/ws-auth/tests/service_identity_test.rs`: a created service identity's stored hash is the SHA-256 of the returned token (never the token itself); the returned token carries the `ws_at_` prefix and is hex; `authenticate_token` with the right token yields an `Actor` with the stored capabilities and `actor_type = ApiToken`; a revoked token authenticates as `None`; an expired token authenticates as `None`; **requesting a capability the creator lacks is a typed error** (the Review Focus item).

- [ ] **Step 2: Run tests to verify they fail**

Run: `DATABASE_URL=... cargo test -p ws-auth --test service_identity_test -- --include-ignored`
Expected: FAIL — no `service_identity` module.

- [ ] **Step 3: Implement `service_identity.rs` and `refresh.rs`**

- [ ] **Step 4: Run tests to verify they pass**

Run: `DATABASE_URL=... cargo test -p ws-auth -- --include-ignored`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

Subject: `feat(ws-auth): service identities, API tokens, and refresh tokens`.

---

### Task 9: `ws-auth` — one-shot tokens

**Files:**
- Create: `crates/ws-auth/src/one_shot.rs`
- Modify: `crates/ws-auth/src/lib.rs`
- Test: `crates/ws-auth/tests/one_shot_test.rs` (DB-gated, advisory lock `0x0057_4144_5354_000e`)

**Interfaces:**
- Consumes: Task 5's `consume_one_shot_by_hash`; Task 2's vocabulary.
- Produces:
  - `ws_auth::one_shot::OneShotToken` — id, tenant_id, `token: String` (plaintext, once), expires_at.
  - `ws_auth::one_shot::mint_one_shot(executor, tenant_id: Uuid, minted_by: &Actor, ttl: chrono::Duration, repo: &CredentialRepo) -> Result<OneShotToken, AuthError>` — mints a 32-byte random token, stores only its SHA-256 hash, and returns the plaintext **once**. The token is presented as hex with the prefix `ws_ot_`.
  - `ws_auth::one_shot::consume_one_shot(plaintext: &str, executor, repo) -> Result<Option<Actor>, AuthError>` — **looks up only; it does not consume.** The consume-and-issue happens in the issuance handler (Task 10), so a stray bearer never burns a token. The returned `Actor` has `actor_type = OneShotToken`, `auth_method = OneShot`, the `Issue` capability, and **`minted_by` set to the human who minted it** (from the token row).
  - `ws_auth::one_shot::claim_one_shot(plaintext: &str, executor, repo) -> Result<Option<Actor>, AuthError>` — the **atomic** consume: `consume_one_shot_by_hash` in one statement, then the same `Actor` shape. Task 10's one-shot issuance handler calls this **inside the same transaction** as the certificate insert.

**Notes for the implementer:**
- The single-use property is enforced by the database, not by a read-then-write: `UPDATE one_shot_tokens SET used_at = now() WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() RETURNING …`. Two concurrent consumers cannot both succeed.
- The token carries **no profile scope** — there are no profile ACLs in v1.

- [ ] **Step 1: Write the failing tests**

In `crates/ws-auth/tests/one_shot_test.rs`: a minted token resolves to an `Actor` with `Issue` and `actor_type = OneShotToken`; **`claim_one_shot` succeeds once and the second claim returns `None`**; `consume_one_shot` (the lookup-only form) does **not** mark the token used, so a later `claim_one_shot` still succeeds; an expired token claims as `None`; the stored row holds a hash, not the token; `used_at` is set after a successful claim.

- [ ] **Step 2: Run tests to verify they fail**

Run: `DATABASE_URL=... cargo test -p ws-auth --test one_shot_test -- --include-ignored`
Expected: FAIL — no `one_shot` module.

- [ ] **Step 3: Implement `one_shot.rs`**

- [ ] **Step 4: Run tests to verify they pass**

Run: `DATABASE_URL=... cargo test -p ws-auth -- --include-ignored`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

Subject: `feat(ws-auth): single-use one-shot tokens for the token-gated pull flow`.

---

### Task 10: `ws-api` — the axum API and the audit write-side contract

**Files:**
- Create: `crates/ws-api/Cargo.toml`
- Create: `crates/ws-api/src/lib.rs`
- Create: `crates/ws-api/src/state.rs`
- Create: `crates/ws-api/src/error.rs`
- Create: `crates/ws-api/src/auth_middleware.rs`
- Create: `crates/ws-api/src/routes/{mod,auth,certificates,profiles,cas,audit,users,credentials,tenants,root_trust,health}.rs`
- Test: `crates/ws-api/tests/api_test.rs` (DB-gated, advisory lock `0x0057_4144_5354_000f`)

**Interfaces:**
- Consumes: Tasks 2, 5, 6, 7, 8, 9.
- Produces:
  - `ws_api::AppState` — pool, repos, `JwtKeys`, config (the setup hostname/SAN value, the keys dir, rate limits, the admin CIDRs collected at setup).
  - `ws_api::router(state: AppState) -> axum::Router` — the whole API, versioned under `/api/v1/`.
  - `ws_api::error::ApiError` — `#[derive(thiserror::Error)]` + `IntoResponse`. Status mapping: `BadRequest` 400, `Unauthorized` 401, `Forbidden` 403, `NotFound` 404, `Conflict` 409, `RateLimited` 429, `Internal` 500. The JSON body is `{"error": {"code": "...", "message": "..."}}` with `#[serde(rename_all = "snake_case")]`.
  - `ws_api::error::from_core_error(err: CoreError) -> ApiError` — the mapping table: `CoreError::Database` → `Internal` 500; `CoreError::Migration` → `Internal` 500; `CoreError::Duplicate` → `Conflict` 409; `CoreError::Forbidden` → `Forbidden` 403; **`CoreError::Config` → `Internal` 500** (a corrupt stored profile is a server-side data problem, not a client error).
  - `impl From<AuthError> for ApiError` — a **separate** conversion, because `AuthError` lives in `ws-auth` and cannot be produced by a function taking a `CoreError`: `AuthError::Forbidden` → `Forbidden` 403; `AuthError::BadCredentials`/`TokenInvalid`/`TokenExpired`/`MfaRequired`/`MfaInvalid` → `Unauthorized` 401; `AuthError::AccountLocked`/`AccountDisabled` → `Forbidden` 403; `AuthError::RateLimited` → `RateLimited` 429; `AuthError::NotFound` → `NotFound` 404; `AuthError::Config`/`Crypto` → `Internal` 500. **Every handler's `?` needs one of these two conversions** — `actor.require(...)` returns `CoreError::Forbidden`, and the auth flows return `AuthError`.
  - A rejected SAN (a name the profile does not permit) is `ApiError::BadRequest` 400 with the code `not_permitted_by_profile` — distinct from `Forbidden` 403, which means "you may not do this at all".
  - `ws_api::auth_middleware::AuthActor` — an axum extractor resolving the `Authorization: Bearer` header. It is a **newtype wrapper** `pub struct AuthActor(pub ws_core::models::rbac::Actor)` implementing `FromRequestParts`. The wrapper is necessary: axum's `FromRequestParts` is a foreign trait and `ws_core::models::rbac::Actor` is a foreign type, so implementing the extractor for it directly violates the orphan rule (E0117). The wrapper is the *only* thing in ws-api — the actor type itself remains single-sourced in `ws-core`, and `AuthActor` derefs to it.
  - `ws_api::routes::auth` — `POST /api/v1/auth/login` (username + password, plus a TOTP code when MFA is enabled; returns an access token and a refresh token; sets `AccessClaims.sid` to the refresh token's id), `POST /api/v1/auth/refresh` (rotates the refresh token), `POST /api/v1/auth/logout` (revokes it), `GET /api/v1/auth/me`, `POST /api/v1/auth/totp/enroll` (returns the secret and provisioning URI), `POST /api/v1/auth/totp/activate` (verifies the first code and stores the encrypted secret), `POST /api/v1/auth/totp/deactivate`, `GET /api/v1/auth/oidc/{provider}/start`, `GET /api/v1/auth/oidc/{provider}/callback` (the OIDC code exchange; the identity is matched by `oidc_sub`, else linked by verified email, else a new user is created).
  - `ws_api::routes::certificates::issue_certificate` — `POST /api/v1/certificates`. Body: `{ profile_id, subject_cn, sans: Vec<String>, csr_pem }` for the CSR path; `{ profile_id, subject_cn, sans }` for the admin-only server-key-generation path. Response: the certificate PEM, serial, and (generation path only) the private key.
  - `ws_api::routes::certificates::issue_certificate_one_shot` — `POST /api/v1/certificates/pull`, gated by a one-shot token in the `Authorization` header. Body: `{ profile_id, subject_cn, sans, csr_pem }`. It **claims the one-shot token and inserts the certificate in one transaction** (Task 9's `claim_one_shot`).
  - `ws_api::routes::certificates::revoke_certificate` — `POST /api/v1/certificates/{id}/revoke`, body `{ reason }`; idempotent; writes a `cert_revoked` audit row.
  - `ws_api::routes::profiles::create_profile` — `POST /api/v1/profiles`, gated by `manage_profiles`; creates the profile and its first revision.
  - `ws_api::routes::profiles::update_profile` — `PUT /api/v1/profiles/{id}`; appends a new revision and repoints `current_revision_id`, using the conditional write from Task 5.
  - `ws_api::routes::cas::create_ca` — `POST /api/v1/cas`, gated by `manage_cas`; creates a root or sub-CA (the CA's own key goes to the keystore), and writes the `ca_created` audit row.
  - `ws_api::routes::cas::export_ca_key` — `POST /api/v1/cas/{id}/export-key`, gated by `export_ca_keys` (admin-only). Returns the CA's private key **once** for backup; the server keeps its copy. Writes a `ca_key_exported` audit row. Redacted from logs; `Cache-Control: no-store`.
  - `ws_api::routes::root_trust::download_root_cert` — `GET /api/v1/root-trust/ca.crt`, gated by `read_cas`. Returns the CA **certificate** PEM — never the key.
  - `ws_api::routes::health` — `GET /healthz` (liveness) and `GET /metrics` (Prometheus text format).
  - `ws_api::routes::tenants::create_tenant` — `POST /api/v1/tenants`, gated by `manage_system`; creates a tenant **and seeds its built-in default profiles** by calling `ws_core::models::profile::default_profiles` (Task 2's).

  **The route → required capability table** (each entry is a test in Task 10's suite):

  | Route | Capability |
  |---|---|
  | `POST /api/v1/auth/login`, `/refresh`, `/oidc/*` | none (public) |
  | `GET /api/v1/auth/me` | any authenticated actor |
  | `GET /api/v1/certificates` | `read_certificates` |
  | `GET /api/v1/certificates/{id}` | `read_certificates` |
  | `POST /api/v1/certificates` — **CSR path** | `issue` |
  | `POST /api/v1/certificates` — **server-key-generation path** | `generate_leaf_key` (**admin-only**) |
  | `POST /api/v1/certificates/pull` | `issue` (one-shot token) |
  | `POST /api/v1/certificates/{id}/revoke` | `issue` |
  | `GET /api/v1/profiles` | `read_profiles` |
  | `GET /api/v1/profiles/{id}` | `read_profiles` |
  | `GET /api/v1/profiles/{id}/revisions` | `read_profiles` |
  | `POST /api/v1/profiles`, `PUT /api/v1/profiles/{id}` | `manage_profiles` |
  | `GET /api/v1/cas` | `read_cas` |
  | `POST /api/v1/cas` — create a CA | `manage_cas` (admin-only) |
  | `POST /api/v1/cas/{id}/export-key` | `export_ca_keys` (admin-only) |
  | `GET /api/v1/root-trust/ca.crt` | `read_cas` |
  | `GET /api/v1/audit` | `read_audit` |
  | `GET /api/v1/audit/export` | `read_audit` |
  | `GET /api/v1/users` | `read_users` |
  | `POST /api/v1/users` | `manage_users` |
  | `POST /api/v1/users/{id}/deactivate` | `manage_users` |
  | `POST /api/v1/auth/logout` | any authenticated actor (revokes **its own** refresh token) |
  | `POST /api/v1/auth/totp/enroll` | any authenticated actor (its own account) |
  | `POST /api/v1/auth/totp/activate` | any authenticated actor (its own account) |
  | `POST /api/v1/auth/totp/deactivate` | any authenticated actor (its own account) |
  | `GET /api/v1/service-identities` | `read_service_identities` |
  | `POST /api/v1/service-identities` | `manage_api_tokens` |
  | `POST /api/v1/service-identities/{id}/revoke` | `manage_api_tokens` |
  | `GET /api/v1/one-shot-tokens` | `read_service_identities` |
  | `POST /api/v1/one-shot-tokens` | `manage_one_shot_tokens` |
  | `POST /api/v1/tenants` | `manage_system` |
  | `GET /api/v1/healthz`, `/metrics` | none (public) |

  **Two routes are separate capabilities, not one.** `POST /api/v1/certificates` serves
  both the CSR path (`issue`) and the server-key-generation path
  (`generate_leaf_key`) — the handler inspects the body and checks the capability
  that path needs. An `Issuer` holds `issue` and must therefore be able to reach the
  CSR path **without** being able to reach the key-generation path; the table's two
  rows are what the test asserts, and a single row would hide that gap.

  **`POST /api/v1/cas`** creates a CA (root or sub-CA) and is gated by `manage_cas` —
  it is what writes the `ca_created` audit action. Without it the action vocabulary
  would name something nobody writes.

  **The audit action vocabulary** — the exact strings, used by every mutating handler and asserted by the tests:

  | Action | Written by | target_type / target_id | `details` keys |
  |---|---|---|---|
  | `ca_created` | CA creation (`POST /api/v1/cas`) | `ca` / the CA id | `key_type`, `is_root` |
  | `cert_issued` | issuance | `certificate` / the certificate id | `profile_id`, `profile_revision_id`, `serial`, `sans`, `minted_by` (the minting user's id, for a one-shot-issued certificate; absent otherwise) |
  | `key_generated` | the server-key-generation path | `certificate` / the certificate id | `profile_id`, `key_type` — **never the key** |
  | `cert_revoked` | revocation | `certificate` / the certificate id | `reason` |
  | `ca_key_exported` | CA key export | `ca` / the CA id | `reason` — **never the key** |
  | `profile_created` | profile creation | `profile` / the profile id | `revision` |
  | `profile_revised` | profile edit | `profile` / the profile id | `revision` |
  | `user_created` | user creation | `user` / the user id | `role` |
  | `service_identity_created` | service identity creation | `service_identity` / the id | `capabilities` |
  | `one_shot_token_minted` | one-shot minting | `one_shot_token` / the id | `expires_at` |
  | `tenant_created` | tenant creation | `tenant` / the tenant id | — |
  | `setup_completed` | the setup flow | `tenant` / the tenant id | `domain`, `admin_cidrs` |
  | `crl_built` | **the worker** (already in production since Plan 1) | `ca` / the CA id | `revoked_count` |
  | `session_revoked` | logout | `session` / the refresh token's id | — |
  | `mfa_enrolled` | TOTP enrolment | `user` / the user id | — |
  | `mfa_activated` | TOTP activation | `user` / the user id | — |
  | `mfa_deactivated` | TOTP deactivation | `user` / the user id | — |
  | `user_deactivated` | user deactivation | `user` / the user id | — |
  | `service_identity_revoked` | service identity revocation | `service_identity` / the id | — |

  **Every mutating handler appears in this table**, including the auth-session
  mutations (logout and the TOTP enrolment/activation/deactivation routes), which
  change state and therefore write an audit row in the same transaction.

  **`crl_built` is in the vocabulary** — the worker has written it since Plan 1, so the
  table is not a vocabulary without it. And **`minted_by`** in `cert_issued` is how the
  spec's "the human who minted the token" requirement is met: it is the minting
  user's id, rendered as its hyphenated uuid string, and it is present only for a
  one-shot-issued certificate.

**Notes for the implementer:**
- **The audit write-side contract.** Every mutating handler opens one transaction, does its mutation and its audit `record` inside it, and commits once — so the entry and the change commit together or not at all (the Review Focus item 4). `AuditRepo::record` takes the executor (Task 6), so this is possible.
- **Capability checks live in the handler**, not in a route layer: `actor.require(Capability::X)?` at the top of every mutating handler, using the route→capability table above. The house pattern puts `auth: AuthUser` in the signature and checks `is_admin()` inside (`pm-web/src/routes/settings.rs:195-205`).
- **Profile validation errors are specific for actors who may READ the profile, and generic otherwise**: an actor holding both `Issue` and `ReadProfiles` gets "name `foo.other.com` is not permitted by this profile"; anyone else gets a generic "not permitted by policy". The specific message names the failing constraint and **never dumps the permitted set**. (The generic branch is reachable: a service identity can be granted `issue` **without** `read_profiles`, because a token's capabilities are chosen explicitly at creation and can be a narrow subset — that actor reaches the validation, and must not learn the profile's contents.) An actor **without** `issue` is refused with 403 by the capability check *before* validation runs, so it never reaches this code at all. Use `ws_core::profile_match::san_is_permitted` (Task 5) for every proposed name **and for the subject CN** — the subject is a permitted name too, and an empty SAN list is refused (proposing no names is a different artifact, not a subset).
- **The issuance path validates against a specific profile revision and retries if it moved.** Read the profile's `current_revision_id`, validate against *that* revision's constraint set, and write the certificate carrying that revision id. If a concurrent edit has moved the revision, the conditional write (Task 5's `ProfileRepo::update`) reports zero rows affected, and the issuance **retries against the new revision** (bounded retries, then `ApiError::Conflict`).
- **The issuance path pre-checks the CA's remaining life** and refuses — it never silently issues a shortened certificate. The engine refuses too (Task 7), but the API's refusal is the one the operator sees, so it names both the profile's lifetime and the CA's expiry.
- **The key-generation response is redacted from logs and never cached** — `Cache-Control: no-store`, and the logging layer must not record the body. The same applies to the CA key export.
- The house pattern for rate limiting is `GovernorLayer` per router (`pm-web/src/lib.rs:177-181`); the `governor` and `tower_governor` crates are added in Task 1.
- **Bearer resolution order** (one header, three credential shapes): a value with three dot-separated segments is a JWT; a value starting `ws_at_` is an API token; a value starting `ws_ot_` is a one-shot token; anything else is 401. The one-shot token is **looked up but not claimed** by the extractor — only the pull handler claims it, so a stray bearer never burns a token.

- [ ] **Step 1: Write the failing tests**

In `crates/ws-api/tests/api_test.rs` (DB-gated): a request with no Authorization header is 401; a valid session token reaches the handler; a token with the wrong capability is **403** (not 401); a mutation writes exactly one audit row with the right `actor_type`, `auth_method`, and `action`; **a mutation whose audit insert fails leaves no mutation behind** (force the audit insert to fail by violating a constraint, then assert the certificate row does not exist); a profile that forbids a name rejects the request with the specific message for an `Issue` holder and the generic message for a non-issuer; a non-issuer calling the key-generation endpoint is 403; **the key-generation response carries the key exactly once, its audit row's `action` is `key_generated` with no key material in `details`, the response carries `Cache-Control: no-store`, no later read endpoint returns the key, and the key does not appear in the captured access log** (the Review Focus item 3); the one-shot pull endpoint issues exactly once and a second attempt with the same token is 401; a profile edit that moves the revision concurrently makes the issuance retry rather than record a stale revision; every route in the capability table refuses a token lacking its capability.

- [ ] **Step 2: Run tests to verify they fail**

Run: `DATABASE_URL=... cargo test -p ws-api --test api_test -- --include-ignored`
Expected: FAIL — no `ws_api` library.

- [ ] **Step 3: Implement the API**

- [ ] **Step 4: Run tests to verify they pass**

Run: `DATABASE_URL=... cargo test -p ws-api -- --include-ignored`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

Subject: `feat(ws-api): REST API with capability checks and transactional audit`.

---

### Task 11: `ws-web` — the TLS front door and the first-run setup page

**Files:**
- Create: `crates/ws-web/Cargo.toml`
- Create: `crates/ws-web/src/lib.rs`
- Create: `crates/ws-web/src/proxy.rs`
- Create: `crates/ws-web/src/setup/{mod,page,tls}.rs`
- Test: `crates/ws-web/tests/setup_test.rs` (DB-gated, advisory lock `0x0057_4144_5354_0010`)

**Interfaces:**
- Consumes: Task 10's router; Task 7's setup-key slot; Task 5's repos; **Task 7's `ws-ca` root-CA creation** (so `ws-web` depends on `ws-ca`).
- Produces:
  - `ws_web::proxy::api_router(api_base_url: &str) -> axum::Router` — path-proxies `/api/v1/*` to the API's base URL over the internal network, using `reqwest`. The API's own routes are not mounted in ws-web; only the proxy is.
  - `ws_web::setup::SetupFields` — `admin_username: String`, `admin_password: String`, `default_domain: String`, `admin_cidrs: Vec<String>`, `server_hostname: String`.
  - `ws_web::setup::setup_router(state: SetupState) -> axum::Router` — the setup page (GET) and the setup submit (POST). **Mounted only while the tenant does not exist** — the caller checks `tenant_exists(pool)` and mounts the router or does not.
  - `ws_web::setup::tls::setup_certificate(keystore: &mut KeyStore, san: &str) -> Result<(String /*PEM*/, String /*sha256 fingerprint hex*/), CaError>` — the self-signed certificate for the **configured SAN** (`server_hostname`), stored under the setup-key slot, with its SHA-256 fingerprint returned for display. The certificate is self-signed (the root CA does not exist yet), with the SAN from `SetupFields.server_hostname` when known, and a placeholder SAN otherwise.
  - `ws_web::setup::run_setup(fields: &SetupFields, pool: &PgPool, keystore: &mut KeyStore) -> Result<(), CaError>` — creates the tenant, the root CA (writing its key to the keystore), the admin user (argon2id hash), the two default profiles (via `ws_core::models::profile::default_profiles`), the **secret-encryption key** (`ws_core::crypto::SecretBox::create(<keys dir>/secret-encryption.key)` — the TOTP secrets are encrypted under it, so it must exist before any user can enrol), and the audit entries; then mints the server's own leaf from the new CA.

**Notes for the implementer:**
- **The setup endpoint is not routed once the tenant exists** (the Review Focus item 5) — not merely refused. The router is mounted conditionally, on a check of whether the default tenant exists.
- **The setup page is HTTPS from the start**, with the self-signed certificate whose SHA-256 fingerprint the page displays, so the operator verifies it out-of-band rather than clicking through a warning.
- The setup certificate's key lives in the keystore's **setup slot** (`ca/setup.key`, Task 7), and the keystore's master key is generated before it is stored (Plan 1's `ensure_master_key` generates when absent and refuses with `Corrupt` when keys exist; `store_ca_key` requires it to exist).
- The setup page collects: admin username, admin password, the default domain, the admin CIDRs, and **the server's hostname** (the explicit setup field for the UI's own SAN — not derived from the default domain, and not the machine's hostname).
- **The setup page's TLS certificate is generated once, before the setup form is filled in**, so its SAN comes from the instance configuration (`WARDSTONE_SERVER_HOSTNAME`), not from the form; the form's `server_hostname` field is used for the **CA-issued leaf** that replaces it at the end of setup. When the configuration value is unset, the setup certificate carries the placeholder SAN `wardstone-setup.local`.
- **The TLS switch at the end of setup is a process restart**, not a hot reload: the setup handler writes the CA-issued leaf to the keystore and signals the supervisor to restart the process, which comes up on the CA-issued certificate. (`axum-server` supports a graceful restart of the listener; the simplest correct implementation is to exit the process with a success code, letting the compose service's `restart: unless-stopped` bring it back — state the choice in the code.)
- **The setup transaction spans the DB and the keystore.** The root CA's key is written to the keystore *before* the DB transaction commits, because a certificate row without its key is worse than an orphaned key file: if the DB transaction rolls back, the key file remains but no CA references it, and the next setup run overwrites it. Write the key first, then commit the DB transaction. Say so in a comment.

- [ ] **Step 1: Write the failing tests**

In `crates/ws-web/tests/setup_test.rs` (DB-gated): with no tenant, the setup router is mounted and its GET returns the page (200); the POST creates the tenant, root CA, admin user, and the two default profiles, and the admin's password is stored as an argon2id hash (never plaintext); **after setup completes, the setup route is gone** — a request to it returns 404, not 403 (the Review Focus item 5); the setup certificate is self-signed, carries the configured SAN, and its fingerprint is stable across two calls; the default profiles have non-empty key usages and EKU lists.

- [ ] **Step 2: Run tests to verify they fail**

Run: `DATABASE_URL=... cargo test -p ws-web --test setup_test -- --include-ignored`
Expected: FAIL — no `ws_web` library.

- [ ] **Step 3: Implement `ws-web`**

- [ ] **Step 4: Run tests to verify they pass**

Run: `DATABASE_URL=... cargo test -p ws-web -- --include-ignored`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

Subject: `feat(ws-web): TLS front door, API proxy, and the first-run setup page`.

---

### Task 12: the `wardstone` binary — `ui` and `api` modes

**Files:**
- Create: `crates/wardstone/Cargo.toml`
- Create: `crates/wardstone/src/main.rs`
- Modify: `Cargo.toml` — **no change needed**: the workspace already globs `crates/*`, so the new crate is a member automatically

**Interfaces:**
- Consumes: Task 11's `ws-web`; Task 10's `ws-api`.
- Produces:
  - `wardstone` — a binary whose first argument selects the mode: `wardstone ui` (serve ws-web: the TLS listener, the API proxy, and the setup page) or `wardstone api` (serve ws-api's router). No argument, or an unknown one, prints a short usage message and exits non-zero.
  - Both modes read the same configuration from the environment: `DATABASE_URL` (required), `WARDSTONE_KEYS_DIR` (required; the keystore directory), `WARDSTONE_SERVER_HOSTNAME` (the setup certificate's SAN), `WARDSTONE_API_URL` (ws-web's proxy target; defaults to `http://ws-api:8080`), `WARDSTONE_BIND` (the listen address; defaults to `0.0.0.0:8443`).
  - `wardstone::main` is a thin dispatcher — the logic lives in `ws-web` and `ws-api`.

**Notes for the implementer:**
- The spec's anti-goal is that the UI and the API are **separate processes, independently restartable** — hence two modes, not one process with two listeners. The compose file (Task 13) runs them as two services.
- The binary owns the process lifecycle: it initializes the pool (`ws_core::db::connect`), loads **or creates** the JWT keys (`JwtKeys::load_or_create` — on a virgin volume the keys must exist before the setup page can be served), opens the keystore, and then serves.

- [ ] **Step 1: Write the failing test**

In `crates/wardstone/tests/cli_test.rs`: `wardstone` with no argument exits non-zero and prints a usage line naming `ui` and `api`; `wardstone bogus` does the same; `wardstone --help` exits zero and names both modes. (A binary's own exit behavior is testable by invoking the built binary; the house pattern for this is not established, so any reasonable approach is fine — `assert_cmd` is a new dependency, or the test can run the binary with `std::process::Command` and check the exit code and stderr.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p wardstone`
Expected: FAIL — no `wardstone` crate.

- [ ] **Step 3: Implement the binary**

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p wardstone`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

Subject: `feat(wardstone): single binary with ui and api invocation modes`.

---

### Task 13: the production compose bundle

**Files:**
- Create: `docker/compose.yml` (the production bundle)
- Create: `docker/README.md` (the two variants and the operations notes)
- Modify: `docker/compose.dev.yml` (one line: its header says the production file "arrives in a later plan" — update that once Task 13 lands)
- Modify: `crates/ws-worker/tests/scheduler_test.rs` (the regression assertion on the worker's `auth_method`)

**Interfaces:**
- Consumes: Task 12's binary.
- Produces: the production compose file.

**Notes for the implementer:**
- The worker's `auth_method` was already set in **Task 5** (the task that made the column NOT NULL). This task only *asserts* that value in a regression test.
- The compose file follows the spec: `ws-web` and `ws-api` are **separate services** running the same image with different commands (`wardstone ui` / `wardstone api`), plus a Postgres service. `ws-web` publishes the only port to the LAN; `ws-api` publishes **none** and is reached over the internal network. The keys volume is mounted at `/var/lib/wardstone/keys/` with the key files mode 0600, owned by the container user.
- **Two variants, one file:** the Bundled variant is the file as written (with its own Postgres service); the **External** variant is the same file with the Postgres service removed and `DATABASE_URL` pointed at an existing database. `docker/README.md` documents both, and documents that an External deployment may front `ws-api` directly behind their own reverse proxy.
- The environment contract: `DATABASE_URL`, `WARDSTONE_KEYS_DIR`, `WARDSTONE_SERVER_HOSTNAME`, `WARDSTONE_API_URL`, `WARDSTONE_BIND`.
- The existing `docker/compose.dev.yml` is the dev/test database and stays as it is (minus the one header line).

- [ ] **Step 1: Write the regression test**

Extend the worker suite (`crates/ws-worker/tests/scheduler_test.rs`): the worker's `crl_built` audit row is written with `auth_method = 'system'` and `actor_type = 'system'`, and the row survives the NOT NULL constraint. **This is a regression guard, not a red-first test** — the value was set in Task 5, so the test passes as written. (If it fails, Task 5's worker edit was wrong.)

- [ ] **Step 2: Write the compose bundle and its README**

- [ ] **Step 4: Run the full gate**

Run: `DATABASE_URL=... cargo test --workspace -- --include-ignored && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: PASS everywhere.

- [ ] **Step 5: Commit**

Subject: `feat(deploy): production compose bundle` — the worker's `auth_method` was set in Task 5, so this commit adds only the compose bundle and its README.

---

### Task 14: End-to-end API smoke test

**Files:**
- Create: `crates/ws-web/tests/e2e_test.rs`

**Interfaces:**
- Consumes: everything. `ws-web` gains `ws-api` as a **dev-dependency** (it already depends on it normally), so the test can mount both routers.

**Notes for the implementer:**
- **What a mismatch is, and what a bug is.** When the test fails, classify it:
  - a **mismatch** is a name, path, type, or signature that differs between two tasks' stated Interfaces — fix it by making the names agree, **in the task that produces the symbol**;
  - a **bug** is a behaviour that contradicts the stated Interfaces — fix it in the owning task and add a unit test there;
  - anything else (a missing feature, an unimplemented route) is a **gap** — stop and report it rather than changing another task's semantics.
  Never weaken the test, and never change a public behaviour that the owning task's own tests pin.

- [ ] **Step 1: Write the test**

One `#[tokio::test] #[ignore]` (advisory lock `0x0057_4144_5354_0011`): mount the setup router and the API router over a live pool; run setup (admin, domain, CIDRs, hostname); authenticate as the admin; create a profile; issue a leaf from a CSR; assert the certificate parses, is signed by the root, carries the profile's EKU and key usages, and its span equals the profile's lifetime exactly; revoke it; assert the audit trail shows `ca_created`, `cert_issued`, `cert_revoked` in order with the right `auth_method`; create a service identity, use it to issue a second leaf, and assert the audit row's `actor_type` is `api_token`; assert the setup route is gone.

- [ ] **Step 2: Run it, fixing mismatches in the owning task's code**

Run: `DATABASE_URL=... cargo test -p ws-web --test e2e_test -- --include-ignored`
Expected: initially FAIL if any interface mismatch exists between tasks — fix per the classification above, never by weakening the test; then PASS.

- [ ] **Step 3: Full-suite gate**

Run: `DATABASE_URL=... cargo test --workspace -- --include-ignored && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check`
Expected: PASS everywhere.

- [ ] **Step 4: Commit**

Subject: `test: end-to-end API, setup, and issuance smoke test`.
