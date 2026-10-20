# Wardstone Workspace, Core Data Layer, and CA Engine — Implementation Plan (Plan 1 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the Rust workspace, the Postgres data layer, and the CA engine (key generation, encrypted-at-rest storage, certificate/CRL issuance, revocation) as tested crates — everything the later API/ACME/UI plans build on.

**Architecture:** A Cargo workspace with six crates mirroring the house pattern: `ws-core` (domain models + sqlx/Postgres), `ws-ca` (CA engine), `ws-auth`, `ws-worker`, `ws-api`, `ws-web`, plus a `frontend/` directory (built by later plans, not this one). This plan delivers `ws-core` and `ws-ca`; the four app crates get stub-lib entries now so the workspace compiles as a whole. Keys are generated with rcgen, encrypted at rest with an age-style envelope (XChaCha20-Poly1305 DEK under a locally generated master KEK), and used to issue end-entity certs, sub-CA certs, and CRLs, with revocation tracked in Postgres.

**Tech Stack:** Rust (edition 2021, rust-version 1.85), rcgen (cert generation), x509-parser (cert reading), `der`/`x509-cert` (CRL/OCSP DER encoding), serde/serde_json, sqlx 0.8 (Postgres, numbered migrations, `REQUIRED_MIGRATION_COUNT`), tokio, uuid v4, chrono, chacha20poly1305, rand, argon2, zeroize, base64, tracing, thiserror.

**Spec:** `docs/superpowers/specs/2026-10-20-wardstone-ca-design.md`

## Global Constraints

- Spec: "no third-party ACME library" — no ACME crates in any plan. Certificate generation via rcgen is allowed; an ACME library is not.
- Spec: "Postgres via sqlx, numbered migrations with the house `REQUIRED_MIGRATION_COUNT` convention" — every migration adds one; the constant bumps every time a migration is added.
- Spec: JSON casing discipline — `#[serde(rename_all = "snake_case")]` on every DTO/enum serialized to JSON, matched to sqlx renames.
- Spec: ED25519 default CA key type; RSA 2048/3072 options.
- Spec: cert lifetimes — end-entity 30 days default, sub-CA 5 years, root 10 years; CRL 24h `nextUpdate`.
- Spec: keys encrypted at rest, auto-decrypt at startup, master KEK in a dedicated volume (`/var/lib/wardstone/keys/` at runtime; path is runtime config, Plan 2's concern), mode 0600, generated at first run, honest docs caveat about same-host storage.
- Spec: every table carries `tenant_id` (Option A tenancy; default tenant auto-created at bootstrap — bootstrap is Plan 2).
- House rule: `cargo fmt --all` clean, `clippy --all-targets -- -D warnings` clean, no `unwrap()`/`expect()` in library code (typed error enums instead).
- House rule: no AI co-author attribution in commits.
- Deployment target is Docker Compose only, but this plan ships crates and tests, not images.

## Review Focus

The five input classes the spec implies that task tests may not cover, with the task that owns each test:

1. **A CA key file that is corrupted/truncated** — key store must return a typed error (`CaError::Corrupt`), not panic or silently re-initialize. Pinned in Task 4 (`test_load_corrupt_file_fails_typed`).
2. **Wrong master KEK for an existing key file** (volume restored but key file from an older install) — decrypt must fail typed (`CaError::WrongKey`), never overwrite; re-init is an explicit destructive action elsewhere. Pinned in Task 4 (`test_decrypt_with_wrong_kek_fails_typed`).
3. **A CSR whose public-key algorithm Wardstone doesn't support** — issuance returns a typed rejection (`CaError::UnsupportedKeyType`), never a panic. Pinned in Task 6 (`test_issue_from_csr_rejects_unsupported_key`).
4. **Revoking an already-revoked serial** — must be idempotent: no error, no second revocation record. Pinned in Task 7 (`test_revoke_twice_is_idempotent`).
5. **A CRL built with multiple revocations, consumed by stock tooling** — must list every revoked serial and verify against the issuing CA in OpenSSL. Pinned in Task 7 (`test_crl_openssl_verifies`).

---

### Task 1: Cargo workspace skeleton

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `rust-toolchain.toml`
- Create: `crates/ws-core/Cargo.toml` + `src/lib.rs` (empty lib)
- Create: `crates/ws-ca/Cargo.toml` + `src/lib.rs` (empty lib)
- Create: `crates/ws-auth/Cargo.toml` + `src/lib.rs` (empty lib)
- Create: `crates/ws-worker/Cargo.toml` + `src/lib.rs` (empty lib)
- Create: `crates/ws-api/Cargo.toml` + `src/lib.rs` (empty lib)
- Create: `crates/ws-web/Cargo.toml` + `src/lib.rs` (empty lib)
- Create: `.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces: the six-crate workspace `wardstone` all later tasks extend; `rust-toolchain.toml` pinning the stable toolchain; `.gitignore` covering `/target`, `node_modules/`, `.env`, `/frontend/dist`.

- [ ] **Step 1: Create the workspace files**

Workspace `Cargo.toml` with `[workspace]` members = `["crates/*"]`, `[workspace.package]` (edition 2021, version 0.1.0, rust-version = "1.85"), and `[workspace.dependencies]` holding shared versions (serde, serde_json, sqlx 0.8 with `runtime-tokio` + `postgres` features, tokio full, uuid v4, chrono serde, rcgen, x509-parser, der, chacha20poly1305, rand, argon2, zeroize, base64, tracing, thiserror, anyhow). Each crate's `Cargo.toml` inherits via `version.workspace = true` and pulls deps with `dep.workspace = true`. Empty `src/lib.rs` in each crate. `rust-toolchain.toml` pinning current stable. `.gitignore` as listed.

- [ ] **Step 2: Verify the workspace compiles**

Run: `cargo check --workspace`
Expected: all six crates pass with zero errors.

- [ ] **Step 3: Lint the workspace**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean (empty libs).

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml rust-toolchain.toml crates/ .gitignore
git commit -m "chore: cargo workspace with six house-pattern crates"
```

---

### Task 2: sqlx Postgres pool + migration 001 (tenants, CAs, serials)

**Files:**
- Create: `crates/ws-core/src/error.rs`
- Create: `crates/ws-core/src/db.rs`
- Create: `crates/ws-core/migrations/001_init.sql`
- Create: `crates/ws-core/tests/db_test.rs` (DB tests marked `#[ignore]`; run via `cargo test -p ws-core -- --include-ignored` with `DATABASE_URL` set)
- Modify: `crates/ws-core/Cargo.toml`, `crates/ws-core/src/lib.rs` (pub mod error; pub mod db;)

**Interfaces:**
- Consumes: nothing (workspace from Task 1).
- Produces:
  - `ws_core::error::CoreError` — error enum (`Database(sqlx::Error)`, `Migration { expected: u16, found: u16 }`, `Duplicate`, `Config(String)`), `std::error::Error` via thiserror.
  - `ws_core::db::REQUIRED_MIGRATION_COUNT: u16` — set to 1 in this task; bumps with each migration.
  - `ws_core::db::connect(url: &str) -> Result<sqlx::PgPool, CoreError>` — pool (max 10 connections), runs embedded migrations, then verifies `SELECT count(*) FROM _sqlx_migrations` equals `REQUIRED_MIGRATION_COUNT`, returning `CoreError::Migration` on mismatch.
  - Migration 001 creates:
    - `tenants` (`id uuid pk default gen_random_uuid()`, `name text not null unique`, `created_at timestamptz not null default now()`)
    - `cas` (`id uuid pk`, `tenant_id uuid not null references tenants(id)`, `name text not null`, `subject text not null`, `is_root boolean not null`, `parent_id uuid null references cas(id)`, `key_type text not null`, `not_before timestamptz not null`, `not_after timestamptz not null`, `cert_pem text not null`, `key_file text not null`, `created_at timestamptz not null default now()`, unique `(tenant_id, name)`)
    - `used_serials` (`ca_id uuid references cas(id)`, `serial bigint not null`, `issued_at timestamptz not null default now()`, primary key `(ca_id, serial)`) — created now so Plan 2 doesn't renumber migrations; used by Task 8.
  - Table name for CA rows: **`cas`**.

- [ ] **Step 1: Write the failing tests**

In `tests/db_test.rs`: `connect_runs_migrations` — calls `ws_core::db::connect(&url)`, asserts `_sqlx_migrations` count equals `REQUIRED_MIGRATION_COUNT` (1), and asserts `tenants` exists and is empty (the default tenant is inserted by Plan 2's bootstrap, not here). And `migration_count_guard_rejects_stale_db` — manually deletes a `_sqlx_migrations` row, calls `connect` again, expects `CoreError::Migration { expected: 1, found: 0 }`. Both marked `#[ignore]` with a comment on how to run.

- [ ] **Step 2: Run tests to verify they fail**

Run: `DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test cargo test -p ws-core -- --include-ignored`
Expected: FAIL — unresolved `ws_core::db`.
Also run `cargo test -p ws-core` (no env): must compile and pass with zero tests — the CI-safe path.

- [ ] **Step 3: Implement `error.rs`, `db.rs`, migration 001**

`db.rs`: `PgPoolOptions::new().max_connections(10).connect(url)`, then `sqlx::migrate!("migrations").run(&pool)`, then the count guard. Migration SQL per the Interfaces block.

- [ ] **Step 4: Run tests to verify they pass**

Run: `DATABASE_URL=... cargo test -p ws-core -- --include-ignored`
Expected: PASS — both tests green.

- [ ] **Step 5: Commit**

```bash
git add crates/ws-core
git commit -m "feat(ws-core): pg pool, migration 001, migration-count guard"
```

---

### Task 3: Domain models + repositories (tenants, CAs)

**Files:**
- Create: `crates/ws-core/src/models/mod.rs`, `models/tenant.rs`, `models/ca.rs`
- Create: `crates/ws-core/src/repo/mod.rs`, `repo/tenant_repo.rs`, `repo/ca_repo.rs`
- Modify: `crates/ws-core/src/lib.rs` (pub mod models; pub mod repo;)
- Test: `crates/ws-core/tests/repo_test.rs` (ignored, DB-gated) + `#[cfg(test)]` unit tests in `models/ca.rs`

**Interfaces:**
- Consumes: `CoreError`, `connect()` from Task 2.
- Produces:
  - `ws_core::models::tenant::Tenant { pub id: Uuid, pub name: String, pub created_at: DateTime<Utc> }`
  - `ws_core::models::ca::KeyType` — enum `Ed25519 | Rsa2048 | Rsa3072` with `pub fn as_str(&self) -> &'static str` returning `"ed25519" | "rsa2048" | "rsa3072"`, `FromStr` (unknown string → error), `#[serde(rename_all = "snake_case")]`; DB column is `text`, bound via `as_str()` and mapped back via `FromStr` in row mapping.
  - `ws_core::models::ca::CaModel { pub id: Uuid, pub tenant_id: Uuid, pub name: String, pub subject: String, pub is_root: bool, pub parent_id: Option<Uuid>, pub key_type: KeyType, pub not_before: DateTime<Utc>, pub not_after: DateTime<Utc>, pub cert_pem: String, pub key_file: String, pub created_at: DateTime<Utc> }`, `#[derive(Debug, Clone, PartialEq)]`.
  - `ws_core::repo::tenant_repo::TenantRepo::new(pool: &PgPool)` with `pub async fn insert(&self, name: &str) -> Result<Tenant, CoreError>` (unique violation → `CoreError::Duplicate`), `pub async fn get_by_name(&self, name: &str) -> Result<Option<Tenant>, CoreError>`, `pub async fn list(&self) -> Result<Vec<Tenant>, CoreError>`.
  - `ws_core::repo::ca_repo::CaRepo::new(pool: &PgPool)` with `pub async fn insert(&self, ca: &CaModel) -> Result<(), CoreError>`, `pub async fn get(&self, id: Uuid) -> Result<Option<CaModel>, CoreError>`, `pub async fn list_by_tenant(&self, tenant_id: Uuid) -> Result<Vec<CaModel>, CoreError>`, `pub async fn children_of(&self, parent_id: Uuid) -> Result<Vec<CaModel>, CoreError>`.

- [ ] **Step 1: Write the failing tests**

(a) Unit tests in `models/ca.rs`: `key_type_roundtrip` — `KeyType::Ed25519.as_str() == "ed25519"`, `"rsa3072".parse::<KeyType>()` == `Rsa3072`, `"bogus".parse::<KeyType>()` is an error. (b) Integration tests in `tests/repo_test.rs` (ignored): `tenant_insert_get_roundtrip` (insert "default", get_by_name returns it; second insert of same name → `CoreError::Duplicate`), `ca_insert_get_list_roundtrip` (insert one root CA row; `get` returns it; `list_by_tenant` finds it; `children_of(root_id)` returns empty).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ws-core` then `DATABASE_URL=... cargo test -p ws-core -- --include-ignored`
Expected: FAIL — unresolved `ws_core::models::ca`.

- [ ] **Step 3: Implement models and repos**

Per Interfaces. House repo style: `sqlx::query_as` with an inline row struct per repo file, mapped to the model; `sqlx::Error::Database` with code `23505` → `CoreError::Duplicate`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `DATABASE_URL=... cargo test -p ws-core -- --include-ignored`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all`
Expected: clean.

```bash
git add crates/ws-core
git commit -m "feat(ws-core): domain models and repos for tenants and CAs"
```

---

### Task 4: Encrypted key store (master KEK + per-key DEK envelope)

**Files:**
- Create: `crates/ws-ca/src/error.rs`
- Create: `crates/ws-ca/src/keystore.rs`
- Modify: `crates/ws-ca/Cargo.toml`, `crates/ws-ca/src/lib.rs` (pub mod error; pub mod keystore;)
- Test: `#[cfg(test)]` unit tests inside `keystore.rs` (temp dirs under `std::env::temp_dir()`, process-unique subdirs)

**Interfaces:**
- Consumes: nothing from ws-core (pure in-crate; DB wiring is Plan 2's bootstrap).
- Produces:
  - `ws_ca::error::CaError` — flat thiserror enum: `Io(std::io::Error)`, `Corrupt`, `WrongKey`, `Rcgen(rcgen::Error)`, `X509(String)`, `UnsupportedKeyType(String)`, `Db(sqlx::Error)`, `Worker(String)`. `Corrupt` and `WrongKey` must be reachable from `load_ca_key`.
  - `ws_ca::keystore::KeyStore` — owns the keys directory:
    - `pub fn open(dir: &Path) -> Result<Self, CaError>` — creates dir 0700 if missing; typed error if unreadable; does NOT generate the master key.
    - `pub fn master_key_path(&self) -> PathBuf` — `dir/master.key`.
    - `pub fn ensure_master_key(&mut self) -> Result<(), CaError>` — generates a 32-byte random KEK, writes `master.key` mode 0600 (unix `PermissionsExt`); existing-but-short (<32 bytes) file → `Corrupt`.
    - `pub fn store_ca_key(&mut self, ca_id: &Uuid, der_private_key: &[u8]) -> Result<(), CaError>` — fresh random DEK encrypts the DER key (XChaCha20-Poly1305); master KEK wraps the DEK (XChaCha20-Poly1305); writes `dir/ca/<ca_id>.key` as compact JSON envelope `{"v":1,"wrapped_dek":<b64>,"nonce_dek":<b64>,"ciphertext":<b64>,"nonce_inner":<b64>,"key_type":<string>}` — the exact field set is the implementer's call as long as the file is self-describing for `load_ca_key`.
    - `pub fn load_ca_key(&self, ca_id: &Uuid) -> Result<Zeroizing<Vec<u8>>, CaError>` — reads envelope, unwraps DEK with master KEK, decrypts. Outer AEAD failure (KEK mismatch) → `WrongKey`; inner AEAD failure, malformed base64/JSON, or truncated file → `Corrupt`.
  - Deps added to ws-ca: `chacha20poly1305`, `rand`, `serde_json`, `base64`, `zeroize`.

- [ ] **Step 1: Write the failing tests**

In `keystore.rs` `#[cfg(test)]`:
- `test_store_load_roundtrip` — open in temp dir, `ensure_master_key`, store 32 random bytes, `load_ca_key` returns identical bytes.
- `test_load_corrupt_file_fails_typed` — store a key, truncate the envelope file to half length, `load_ca_key` → assert `matches!(err, CaError::Corrupt)`. (Truncate, not garbage-fill: `load` must distinguish outer AEAD failure (`WrongKey`) from inner-layer/malformed (`Corrupt`).)
- `test_decrypt_with_wrong_kek_fails_typed` — store a key; overwrite `master.key` with different 32 random bytes; `load_ca_key` → assert `matches!(err, CaError::WrongKey)`; also assert the envelope file was NOT modified by the failed load.
- `test_master_key_file_permissions` — unix; assert `mode() & 0o777 == 0o600` on `master.key`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ws-ca`
Expected: FAIL — unresolved `ws_ca::keystore`.

- [ ] **Step 3: Implement `error.rs` and `keystore.rs`**

Per Interfaces. `XChaCha20Poly1305` with 24-byte nonces from `rand`. `Zeroizing` for loaded private-key material; `Zeroize` on DEK/master buffers on drop.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ws-ca`
Expected: PASS — all four tests green.

- [ ] **Step 5: Commit**

```bash
git add crates/ws-ca
git commit -m "feat(ws-ca): encrypted-at-rest keystore with typed corrupt/wrong-key errors"
```

---

### Task 5: CA creation — root and sub-CA (rcgen) with encrypted storage

**Files:**
- Create: `crates/ws-ca/src/ca.rs`
- Modify: `crates/ws-ca/src/lib.rs` (pub mod ca;) and `crates/ws-ca/Cargo.toml` (add ws-core dep, rcgen, x509-parser, chrono)
- Test: `crates/ws-ca/tests/ca_creation_test.rs` (pure, no DB — creation works against a temp-dir keystore; DB persistence is Plan 2's bootstrap)

**Interfaces:**
- Consumes: `KeyStore` (Task 4); `ws_core::models::ca::KeyType` (**ws-ca depends on ws-core; never the reverse**).
- Produces:
  - `ws_ca::ca::CaSpec { pub name: String, pub subject: String, pub key_type: KeyType, pub lifetime: CaLifetime }`
  - `ws_ca::ca::CaLifetime` — enum `Root | SubCa | Leaf` with `pub fn duration(&self) -> chrono::Duration`: Root = 10 years, SubCa = 5 years, Leaf = 30 days.
  - `ws_ca::ca::CreatedCa { pub key_pair_id: Uuid, pub cert_pem: String, pub private_key_der: Zeroizing<Vec<u8>> }` — `key_pair_id` is the ca_id used for both the keystore file and (in Plan 2) the DB row.
  - `pub fn create_root(spec: &CaSpec, keystore: &mut KeyStore) -> Result<CreatedCa, CaError>` — generate key per `KeyType`; self-signed root: BasicConstraints `CA:true` critical, KeyUsage `keyCertSign | cRLSign` (+ `digitalSignature`), SKI/AKI per rcgen defaults; store key encrypted; return PEM + DER.
  - `pub fn create_sub_ca(parent_cert_pem: &str, parent_key_der: &[u8], spec: &CaSpec, keystore: &mut KeyStore) -> Result<CreatedCa, CaError>` — sub-CA cert signed by the parent (caller loads the parent key from the keystore and passes the DER bytes): BasicConstraints `CA:true, pathlen:0`, KeyUsage `keyCertSign | cRLSign`; store the sub-CA's own key encrypted; return PEM + DER.
  - `pub use ws_core::models::ca::KeyType;` re-exported from `ws_ca`.

- [ ] **Step 1: Write the failing tests**

In `tests/ca_creation_test.rs`:
- `test_create_root_ed25519_roundtrip` — Ed25519 root; assert PEM header `-----BEGIN CERTIFICATE-----`; parse with x509-parser: BasicConstraints CA:true present, KeyUsage includes keyCertSign; `keystore.load_ca_key(key_pair_id)` succeeds.
- `test_create_sub_ca_signed_by_root` — create root, then sub-CA; parse sub-CA cert: CA:true present, and sub-CA's AKI equals root's SKI (compare parsed extensions).
- `test_create_root_rsa2048` — RSA 2048 root succeeds and parses; KeyUsage keyCertSign present.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ws-ca`
Expected: FAIL — unresolved `ws_ca::ca`.

- [ ] **Step 3: Implement `ca.rs`**

rcgen 0.13 `CertificateParams`: subject CN from `spec.subject` via `DistinguishedName`; `IsCa::Ca(BasicConstraints::Unconstrained)` for root, `IsCa::Ca(BasicConstraints::Explicit(0))` for sub-CA; `KeyUsagePurpose::KeyCertSign | CrlSign | DigitalSignature`; validity from `CaLifetime::duration()`. Root via `params.self_signed(&key_pair)`; sub-CA via `params.signed_by(...)` with the issuer's `KeyPair` reconstructed from the parent DER (`rcgen::KeyPair::from_pkcs8`/`from_der` — exact API per rcgen 0.13). Key generation: Ed25519 via rcgen `KeyPair::generate()`; RSA 2048/3072 via the `rsa` crate (or rcgen's supported path) → PKCS#8 DER. Exact rcgen API shapes are the implementer's call within this pinned two-function design.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ws-ca`
Expected: PASS — including the RSA path.

- [ ] **Step 5: Commit**

```bash
git add crates/ws-ca
git commit -m "feat(ws-ca): root and sub-CA creation with encrypted keystore storage"
```

---

### Task 6: Leaf issuance from CSR + CSR validation

**Files:**
- Create: `crates/ws-ca/src/issue.rs`
- Modify: `crates/ws-ca/src/lib.rs` (pub mod issue;)
- Test: `crates/ws-ca/tests/issue_test.rs`

**Interfaces:**
- Consumes: `CaError` (Task 4); rcgen, x509-parser; `KeyType`.
- Produces:
  - `ws_ca::issue::SanEntry` — enum `Dns(String) | Ip(IpAddr) | Email(String)` (`Email` reserved for the future S/MIME profile; code-commented as such), `#[serde(rename_all = "snake_case")]`.
  - `ws_ca::issue::LeafSpec { pub sans: Vec<SanEntry>, pub key_usages: Vec<rcgen::KeyUsagePurpose>, pub not_after: Option<DateTime<Utc>>, pub subject_cn: Option<String> }`
  - `ws_ca::issue::CsrInfo { pub public_key_alg: String, pub subject_cn: Option<String>, pub sans: Vec<SanEntry> }`
  - `ws_ca::issue::IssuedLeaf { pub cert_pem: String, pub serial: u128, pub not_before: DateTime<Utc>, pub not_after: DateTime<Utc> }` (u128 serial; converted to rcgen's `SerialNumber` at the boundary)
  - `pub fn validate_csr(csr_pem: &str) -> Result<CsrInfo, CaError>` — x509-parser: PEM → `X509CertRequest`; malformed PEM/DER → `CaError::X509`; returns algorithm name, CN, SANs.
  - `pub fn sign_leaf_with(ca_cert_pem: &str, ca_key_der: &[u8], csr_pem: &str, spec: &LeafSpec) -> Result<IssuedLeaf, CaError>` — **pinned requirements: (1) the CSR's signature must verify before issuance; (2) the leaf's public key must be the CSR's public key; (3) key algorithms outside the supported set — Ed25519, ECDSA P-256/P-384, RSA ≥2048 — return `CaError::UnsupportedKeyType`, never panic.**
  - Supported-algorithm check helper: `pub fn supported_key_alg(alg: &str) -> bool`.

- [ ] **Step 1: Write the failing tests**

In `tests/issue_test.rs`:
- `test_validate_csr_malformed_fails_typed` — `validate_csr("not a pem")` → `matches!(err, CaError::X509(_))`, not a panic.
- `test_issue_from_csr_rejects_unsupported_key` — build a CSR with an unsupported key (an ECDSA P-521 CSR via the `p521` crate, or any valid-but-unsupported algorithm the implementer can generate; if none is practical, a garbage-but-parseable key works as long as it exercises the rejection path) and assert `sign_leaf_with` returns `CaError::UnsupportedKeyType`. The pinned requirement is: a CSR the CA cannot sign produces `UnsupportedKeyType`, never a panic.
- `test_issue_leaf_happy_path` — Ed25519 root from Task 5; build a P-256 CSR in-test with rcgen; `sign_leaf_with` returns PEM whose parsed SANs and public key match the CSR's; `not_after` is 30 days out (default `LeafSpec` with `not_after: None`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ws-ca`
Expected: FAIL — unresolved `ws_ca::issue`.

- [ ] **Step 3: Implement `issue.rs`**

`validate_csr` via x509-parser; algorithm from `SubjectPublicKeyInfo.algorithm`. `sign_leaf_with`: validate CSR (signature verification included — if rcgen's `CertificateParams` from-CSR path doesn't verify, verify via x509-parser's request-signature check before building params; verification is a pinned hard requirement). Build `CertificateParams` from CSR subject + SANs + CSR public key (`rcgen::KeyPair::from_der`-equivalent), sign with the CA key. Serial from `ws_ca::serial::allocate_serial`... **no — serial allocation (Task 8) is DB-backed; issuance here takes the serial as a parameter**: add `pub serial: u128` to `LeafSpec`. Corrected shape: `LeafSpec { sans, key_usages, not_after, subject_cn, serial: u128 }`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ws-ca`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/ws-ca
git commit -m "feat(ws-ca): leaf issuance from verified CSR with typed rejection of unsupported keys"
```

---

### Task 7: Certificate records, revocation, CRL builder

**Files:**
- Create: `crates/ws-core/migrations/002_certificates_and_revocation.sql`
- Create: `crates/ws-core/src/models/certificate.rs`
- Create: `crates/ws-core/src/repo/certificate_repo.rs`
- Create: `crates/ws-ca/src/crl.rs`
- Modify: `crates/ws-core/src/db.rs` (REQUIRED_MIGRATION_COUNT = 2), `models/mod.rs`, `repo/mod.rs`, `crates/ws-ca/src/lib.rs` (pub mod crl;)
- Test: extend `crates/ws-core/tests/repo_test.rs`; add `crates/ws-ca/tests/crl_test.rs`

**Interfaces:**
- Consumes: pool + repos (Tasks 2–3); `CaError`, keystore (Tasks 4–6).
- Produces:
  - Migration 002 creates:
    - `certificates` (`id uuid pk`, `tenant_id uuid not null references tenants(id)`, `ca_id uuid not null references cas(id)`, `profile_name text not null` (free-form label in v1; profiles table is Plan 2), `subject text not null`, `serial bigint not null`, `serial_hex text not null`, `san_dns text[] not null default '{}'`, `san_ips inet[] not null default '{}'`, `key_type text not null`, `not_before timestamptz not null`, `not_after timestamptz not null`, `cert_pem text not null`, `status text not null default 'active'` (`active`|`revoked`), `revoked_at timestamptz null`, `revocation_reason text null`, `source text not null` (`manual`|`acme`), `created_at timestamptz not null default now()`, unique `(ca_id, serial)`, index `(tenant_id, not_after)`, index `(tenant_id, status)`)
    - `crls` (`id uuid pk`, `ca_id uuid not null references cas(id)`, `issued_at timestamptz not null`, `next_update timestamptz not null`, `crl_pem text not null`, unique `(ca_id, issued_at)`)
  - `ws_core::models::certificate::CertStatus` — enum `Active | Revoked`, snake_case serde, `as_str()`.
  - `ws_core::models::certificate::CertificateModel` — matching the columns.
  - `ws_core::repo::certificate_repo::CertificateRepo::new(pool: &PgPool)`:
    - `pub async fn insert(&self, c: &CertificateModel) -> Result<(), CoreError>`
    - `pub async fn get(&self, id: Uuid) -> Result<Option<CertificateModel>, CoreError>`
    - `pub async fn list_by_tenant(&self, tenant_id: Uuid, page: u32, page_size: u32) -> Result<Vec<CertificateModel>, CoreError>` — server-side sort `not_after desc`, LIMIT/OFFSET.
    - `pub async fn list_expiring_before(&self, tenant_id: Uuid, threshold: DateTime<Utc>, page: u32, page_size: u32) -> Result<Vec<CertificateModel>, CoreError>` — `status='active' AND not_after < threshold ORDER BY not_after asc` (the expiry-monitoring query).
    - `pub async fn revoke(&self, id: Uuid, reason: &str) -> Result<(), CoreError>` — `UPDATE ... SET status='revoked', revoked_at=now(), revocation_reason=$2 WHERE id=$1 AND status='active'` — the `AND status='active'` makes double-revoke structurally idempotent (second call updates zero rows, returns `Ok(())`).
    - `pub async fn list_revoked_since(&self, ca_id: Uuid, since: DateTime<Utc>) -> Result<Vec<CertificateModel>, CoreError>` — feeds CRL building.
  - `ws_ca::crl::CrlReason` — enum mapping to RFC 5280 CRLReason: Unspecified=0, KeyCompromise=1, CACompromise=2, AffiliationChanged=3, Superseded=4, CessationOfOperation=5, CertificateHold=6, RemoveFromCRL=8, PrivilegeWithdrawn=9, AaCompromise=10; `pub fn as_code(&self) -> u8`.
  - `ws_ca::crl::RevocationEntry { pub serial: u128, pub reason: Option<CrlReason> }`
  - `ws_ca::crl::CrlSpec { pub revocations: Vec<RevocationEntry>, pub next_update: chrono::Duration }`
  - `ws_ca::crl::CrlFile { pub crl_pem: String, pub issued_at: DateTime<Utc>, pub next_update: DateTime<Utc> }`
  - `pub fn build_crl(ca_cert_pem: &str, ca_key_der: &[u8], spec: &CrlSpec) -> Result<CrlFile, CaError>` — pure function; **pinned requirement: the output must be parseable by stock OpenSSL (`openssl crl -in out.pem -noout -text` lists the revoked serials) and the signature must verify (`openssl crl -in out.pem -CAfile ca.pem -noout` prints `verify OK`).** Implementation: rcgen has no CRL support — encode TBSCertList via the `der` crate or `x509-cert`'s CRL types (implementer's call); sign with the CA key.

- [ ] **Step 1: Write the failing tests**

Extend `repo_test.rs`: `certificate_insert_get_roundtrip`; `test_revoke_twice_is_idempotent` — insert, revoke with "key_compromise", capture `revoked_at`, revoke again → `Ok(())` and `revoked_at` unchanged, `status` still `revoked`; `list_expiring_picks_up_upcoming` — insert three certs (expired, expiring in 5 days, expiring in 90 days); `list_expiring_before` with a 7-day threshold returns only the 5-day one, ascending. New `crl_test.rs`: `test_crl_lists_all_serials` — build a CRL from three entries; `openssl crl -text` output contains all three serial hex strings and `next_update` ≈ issued_at + 24h; `test_crl_openssl_verifies` — `openssl crl -CAfile ca.pem` prints `verify OK` (shell out to `openssl` only if the binary exists; skip with a printed note otherwise).

- [ ] **Step 2: Run tests to verify they fail**

Run: `DATABASE_URL=... cargo test -p ws-core -- --include-ignored` and `cargo test -p ws-ca`
Expected: FAIL — unresolved modules.

- [ ] **Step 3: Implement migration 002, models, repos, `crl.rs`**

Per Interfaces. Bump `REQUIRED_MIGRATION_COUNT` to 2.

- [ ] **Step 4: Run tests to verify they pass**

Run: both suites.
Expected: PASS — including OpenSSL verification when the binary is present.

- [ ] **Step 5: Commit**

```bash
git add crates/ws-core crates/ws-ca
git commit -m "feat: certificate records, structural-idempotent revocation, DER CRL builder"
```

---

### Task 8: Serial allocation + append-only audit log

**Files:**
- Create: `crates/ws-core/migrations/003_serials_and_audit.sql`
- Create: `crates/ws-core/src/models/audit.rs`
- Create: `crates/ws-core/src/repo/audit_repo.rs`
- Create: `crates/ws-ca/src/serial.rs`
- Modify: `crates/ws-core/src/db.rs` (REQUIRED_MIGRATION_COUNT = 3), mod files
- Test: extend `repo_test.rs`; add `crates/ws-ca/tests/serial_test.rs`

**Interfaces:**
- Consumes: `used_serials` table (migration 001); pool.
- Produces:
  - Migration 003 creates `audit_log` (`id uuid pk`, `tenant_id uuid not null`, `actor_type text not null` (`user`|`acme_account`|`system`), `actor_id text not null`, `action text not null` (e.g. `ca_created`, `cert_issued`, `cert_revoked`, `crl_built`, `key_generated`), `target_type text not null`, `target_id text not null`, `details jsonb not null default '{}'`, `created_at timestamptz not null default now()`, index `(tenant_id, created_at)`).
  - `ws_ca::serial::allocate_serial(ca_id: Uuid, pool: &PgPool) -> Result<u128, CaError>` — transactional: generate 16 random bytes → u128; INSERT into `used_serials`; on unique violation retry with fresh randomness, **max 8 attempts** (documented cap in a code comment; exceeded → `CaError::Worker("serial allocation exhausted")` or a dedicated variant). ws-ca takes sqlx as a dependency for `PgPool`/queries only — not ws-core models — keeping the dep graph acyclic.
  - `ws_core::models::audit::AuditEntry` — matching audit_log columns, snake_case serde.
  - `ws_core::repo::audit_repo::AuditRepo::new(pool: &PgPool)` with `pub async fn record(&self, entry: &AuditEntry) -> Result<(), CoreError>` and `pub async fn list_by_tenant(&self, tenant_id: Uuid, page: u32, page_size: u32) -> Result<Vec<AuditEntry>, CoreError>` (`created_at desc`, LIMIT/OFFSET). **No update or delete methods exist — append-only is structural.**

- [ ] **Step 1: Write the failing tests**

`serial_test.rs`: `test_serial_allocation_unique` — allocate 100 serials for one CA; all unique (HashSet len 100). Retry-on-collision can't be forced with random 128-bit serials; the 8-attempt cap is documented in code and covered by review. `repo_test.rs`: `test_audit_roundtrip` — record two `cert_issued` entries, `list_by_tenant` returns both (desc); a second `record` appends (two rows after two records — append-only demonstrated).

- [ ] **Step 2: Run tests to verify they fail**

Run: `DATABASE_URL=... cargo test -p ws-core -- --include-ignored` and `cargo test -p ws-ca`
Expected: FAIL — unresolved modules.

- [ ] **Step 3: Implement**

Per Interfaces. Bump `REQUIRED_MIGRATION_COUNT` to 3.

- [ ] **Step 4: Run tests to verify they pass**

Run: both suites.
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/ws-core crates/ws-ca
git commit -m "feat: transactional serial allocation and append-only audit log"
```

---

### Task 9: OCSP data path + worker scheduler

**Files:**
- Create: `crates/ws-core/migrations/004_ocsp.sql`
- Create: `crates/ws-core/src/models/ocsp.rs`
- Create: `crates/ws-core/src/repo/ocsp_repo.rs`
- Create: `crates/ws-worker/src/lib.rs` (real skeleton replacing stub), `crates/ws-worker/src/jobs.rs`, `crates/ws-worker/src/error.rs`
- Modify: `crates/ws-core/src/db.rs` (REQUIRED_MIGRATION_COUNT = 4), mod files, both Cargo.tomls
- Test: extend `repo_test.rs`; add `crates/ws-worker/tests/scheduler_test.rs`

**Interfaces:**
- Consumes: everything above.
- Produces:
  - Migration 004 creates `ocsp_responses` (`id uuid pk`, `ca_id uuid not null references cas(id)`, `serial bigint not null`, `status text not null` (`good`|`revoked`|`unknown`), `this_update timestamptz not null`, `next_update timestamptz not null`, `resp_der bytea not null`, unique `(ca_id, serial, this_update)`).
  - `ws_core::models::ocsp::OcspStatus` — `Good | Revoked | Unknown`, snake_case serde; `OcspResponseModel` matching columns.
  - `ws_core::repo::ocsp_repo::OcspRepo::new(pool: &PgPool)` with `pub async fn insert(&self, r: &OcspResponseModel) -> Result<(), CoreError>` and `pub async fn get_latest(&self, ca_id: Uuid, serial: i64) -> Result<Option<OcspResponseModel>, CoreError>` (latest by `this_update`).
  - `ws_worker::error::WorkerError` — thiserror wrapping `CoreError` and `CaError`.
  - `ws_worker::jobs::regen_crl_and_ocsp(pool: &PgPool) -> Result<u64, WorkerError>` — for each CA with revocations newer than the CA's latest CRL: rebuild CRL (Task 7) + OCSP responses (below), persist via repos + audit entries. Returns count of CAs regenerated.
  - `ws_worker::run_scheduler(pool: PgPool) -> !` — tokio interval loop (60s) calling `regen_crl_and_ocsp`; errors logged via `tracing`, never fatal.
  - OCSP DER builder: `ws_ca::ocsp::build_ocsp_response(ca_cert_pem: &str, ca_key_der: &[u8], serial: u128, status: OcspStatus, this_update: DateTime<Utc>, next_update: DateTime<Utc>) -> Result<Vec<u8>, CaError>` — RFC 6960 BasicOCSPResponse hand-encoded via `der`/`x509-cert` (same approach as CRL); **pinned requirement: `openssl ocsp -issuer ca.pem -cert leaf.pem -respin resp.der -text` parses and shows the status.**

- [ ] **Step 1: Write the failing tests**

`scheduler_test.rs` (DB-gated, ignored): `test_scheduler_regenerates_on_revocation` — insert cert + revoke via repos; run `regen_crl_and_ocsp(pool)` once; assert a `crls` row exists for the CA and `ocsp_responses.get_latest(ca_id, serial)` is `Revoked`. `repo_test.rs`: `test_ocsp_response_roundtrip` — insert, `get_latest` returns it.

- [ ] **Step 2: Run tests to verify they fail**

Run: `DATABASE_URL=... cargo test -p ws-worker -- --include-ignored` and `cargo test -p ws-core -- --include-ignored`
Expected: FAIL.

- [ ] **Step 3: Implement**

Per Interfaces. `REQUIRED_MIGRATION_COUNT` = 4. OpenSSL availability guard in the OCSP parse test: same skip-if-missing pattern as Task 7.

- [ ] **Step 4: Run tests to verify they pass**

Run: both suites.
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/ws-core crates/ws-ca crates/ws-worker
git commit -m "feat: OCSP response data path and worker scheduler with CRL/OCSP regen jobs"
```

---

### Task 10: End-to-end smoke + dev compose

**Files:**
- Create: `crates/ws-ca/tests/smoke_test.rs` (DB-gated, `#[ignore]`)
- Create: `docker/compose.dev.yml` (postgres:18-alpine, healthcheck, ephemeral volume — for local dev/test DB only; the production bundle is a later plan)

**Interfaces:**
- Consumes: all of the above.
- Produces: the proof that the pieces compose; `docker/compose.dev.yml` for `docker compose -f docker/compose.dev.yml up -d` giving a local Postgres for the DB-gated tests.

- [ ] **Step 1: Write the smoke test**

One `#[tokio::test] #[ignore]`: connect to a fresh DB; create default tenant; create an Ed25519 root + sub-CA (Tasks 5); build a P-256 CSR in-test; allocate serial (Task 8); issue a leaf (Task 6); persist cert row + audit entries; revoke with `key_compromise`; run `regen_crl_and_ocsp`; assert: CRL contains the serial (OpenSSL verify OK), latest OCSP response for the serial is `revoked` (OpenSSL parses), audit log shows `ca_created`, `cert_issued`, `cert_revoked` in order, and — simulating restart — drop the `KeyStore`, reopen the same dir, `load_ca_key(sub_ca_id)` still succeeds.

- [ ] **Step 2: Run it, fix surface-level interface mismatches in the owning task's code**

Run: `DATABASE_URL=... cargo test -p ws-ca --test smoke_test -- --include-ignored`
Expected: initially FAIL if any interface mismatch exists between tasks — fix mismatches in the owning task's code, never by weakening the test; then PASS.

- [ ] **Step 3: Full suite gate**

```bash
DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test \
  cargo test --workspace -- --include-ignored && \
  cargo clippy --workspace --all-targets -- -D warnings && \
  cargo fmt --all --check
```

Expected: PASS everywhere.

- [ ] **Step 4: Commit**

```bash
git add crates/ docker/
git commit -m "test: end-to-end CA forest smoke test with CRL/OCSP verification"
```

---

## Plans 2–4 preview (not in this plan)

- **Plan 2 — Bootstrap, profiles, auth, API, UI:** first-run wizard backend (default tenant, admin user, root creation via Task 5, self-issued UI cert), certificate profiles table + profile-aware issuance, ws-auth (JWT/argon2/TOTP/OIDC/RBAC per fw-auth pattern), ws-api REST skeleton + typed client.ts, frontend scaffold + auth pages, Root Trust page, compose bundle.
- **Plan 2's bootstrap consumes from this plan:** `ws_core::db::connect`, `TenantRepo::insert`, `CaRepo::insert` + `ws_ca::ca::{create_root, create_sub_ca}`, `KeyStore` (open/ensure_master_key/store_ca_key/load_ca_key), `ws_ca::issue::{validate_csr, sign_leaf_with}`, `ws_ca::serial::allocate_serial`, `ws_ca::crl::build_crl`, `AuditRepo::record`, `ws_worker::run_scheduler`.
- **Plan 3 — ACME:** in-crate RFC 8555 server (directory, newNonce, newAccount, newOrder, authz, challenges — DNS-01 provider interface + HTTP-01/TLS-ALPN-01, finalize via Task 6, revoke), subnet-allowlist middleware, per-profile challenge policy, tenant-scoped directories, ACME accounts as tenant-owned service identities.
- **Plan 4 — Monitoring, alerts, packaging:** expiry monitor → alert channels (webhook/SMTP/gotify-ntfy), dashboard API, production compose bundle (one binary, `ui`/`api` modes), image hardening (non-root, read-only rootfs), backup action, release CI.

## Self-Review

**1. Spec coverage (this plan's slice):** encrypted-at-rest keys + typed corrupt/wrong-key handling (Task 4), auto-decrypt with no boot prompts (Task 4 — load is unattended), master-key mechanics (Task 4; runtime volume path is Plan 2's config), multi-tier-capable CA model (Tasks 3, 5), ED25519 default + RSA options (Tasks 3, 5), lifetimes 30d/5y/10y + 24h CRL (Tasks 5–7), revocation + CRL + OCSP data path (Tasks 7–9), tenant-shaped schema from day one (Tasks 2, 7, 8, 9), append-only audit log (Task 8), worker scheduler (Task 9). Deliberately deferred to their owning plans: profiles, auth, API, ACME, UI, alerts, packaging — listed in the preview.

**2. Step scan:** every step is one action with a checkable result; implementer's-call notes are pinned by requirements ("must produce X, never panic", "openssl must verify") rather than code bodies. The Task 6 serial correction is applied in-document (`LeafSpec` carries `serial: u128`; `allocate_serial` stays DB-backed in Task 8).

**3. Type consistency:** `KeyType` defined once in ws-core, re-exported by ws-ca; `CertificateModel.serial: bigint` ↔ `IssuedLeaf.serial: u128` (i64/u128 conversion at the repo boundary, serial_hex for display); `CaError` flat enum used across keystore/ca/issue/crl/ocsp; `CoreError` for repos; `WorkerError` wraps both in ws-worker. Task numbering is sequential 1–10.

**4. Review Focus:** corrupt/truncated key file (Task 4), wrong KEK (Task 4), unsupported CSR key (Task 6), double-revoke (Task 7), CRL with multiple revocations consumed by OpenSSL (Task 7) — each has a named test in the owning task.

**5. Proportion:** the plan is signatures, test names, and pinned requirements — no code transcripts; length matches the ten-task build it describes.