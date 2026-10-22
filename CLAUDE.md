# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Status

Three of four planned plans are merged. Plan 1 (core CA — ws-core persistence, ws-ca engine, ws-worker jobs), Plan 2 (API, auth, profiles, first-run setup, deploy bundle), and Plan 3 (the web UI: server-side session relay in ws-web, embedded React/TS SPA at `ui/`, OIDC provider configuration, roles, typed revocation reasons) are complete and merged. **Plan 4 is ACME** (per the Plan 1/2 scope map). A follow-up queue from Plans 2-3 is catalogued in the PR #1/#2 descriptions and the archived SDD ledgers (session-store eviction, profile-description editing, deactivate/PATCH self-deactivation alignment, slim certificate list route for the dashboard sieve, LIKE escaping for `q`, a cross-suite test-DB serialization fence if that interference pattern recurs). A new plan starts with a brainstorm (`superpowers:brainstorming`), then a spec, then an implementation plan in `docs/superpowers/plans/`.

## Build, Lint, and Test

- Lint: `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` — both must be clean for every commit.
- Fast tests (no database): `cargo test --workspace`.
- DB-gated tests: `DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test cargo test --workspace -- --include-ignored` against a live Postgres with that database.
- One suite: `cargo test -p <crate> --test <suite_name> -- --include-ignored`.
- House style: no `unwrap()`/`expect()` outside `#[cfg(test)]` modules (typed error enums); short conventional-commit subjects; **no AI co-author attribution** in commits.

## DB-Gated Test Conventions (binding)

- Test DB: `postgres://wardstone:wardstone@localhost:5432/wardstone_test`.
- Every DB-gated suite takes a unique advisory-lock key from the `0x0057_4144_5354_00xx` family — **0003 through 0013 are taken** (`0012` = `ws-api oidc_test`, `0013` = `ws-web session_test`); the next free key is `0014`. Never reuse a key.
- Every suite sweeps its own rows (FK order) BEFORE each test and **DELETEs the rows it created at the END of each test** — `crates/ws-core/tests/db_test.rs` snapshots the tenant-name set before/after and proves `connect()` itself never seeds a tenant.
- Migration files in `crates/ws-core/migrations/` are ADD-ONLY: sqlx checksums them (SHA-384 over raw bytes), so editing an applied migration breaks every deployed database. Bump `REQUIRED_MIGRATION_COUNT` in `crates/ws-core/src/db.rs` when adding one; `connect()` runs migrations before the count check.

## Architecture

Crate graph (acyclic): `ws-core` (SQLx Postgres persistence: models, tenant-scoped tables, executor-agnostic stateless repos taking `&mut PgConnection`/executors — see `user_repo.rs` for the house idiom) ← `ws-ca` (engine: CSR validation, issuance/revocation, EKU, key-usage, pinned leaf keys with EXACT-size refusal, the `KeyStore` with master-key envelopes and the `ca/setup.key` slot, advisory-lock serial allocation) and `ws-auth` (argon2id, Ed25519 JWT with the two-file key pair, TOTP, generic OIDC SSO, service identities/API tokens/refresh tokens, lookup-only one-shot tokens) ← `ws-api` (axum REST `/api/v1/`: per-route capability checks, the CoreError→ApiError mapping table, transactional audit — a mutation and its audit row commit on the same transaction — GCRA rate limiting on auth routes) and `ws-web` (TLS front door via `axum-server`/ring, `/api/v1` path proxy with bounded timeouts, first-run setup page conditionally mounted only while the default tenant is absent; setup mints tenant/root CA/admin/two profiles/CA-issued leaf key-before-row and self-exits for a process-restart TLS switch) ← `wardstone` (single binary, `ui`/`api` modes; boot TLS resolves the newest `status=active AND profile_name="web-server"` certificate row + `keystore.load_ca_key(cert.id)`; torn state falls back to a fresh setup certificate with a WARN; an un-loadable active-leaf envelope is a hard boot failure). `ws-worker` runs post-issuance jobs (CRLs) against ws-ca. Plan 3 delivered the web UI (beyond setup); **Plan 4 adds ACME.**

- Token families by prefix: `ws_rt_` refresh, `ws_at_` API/service-identity tokens (`ws-at_`-shaped lookups are hash-only), `ws_ot_` one-shot (redeem ONLY at `POST /api/v1/certificates/pull`, which claims it inside the issuance transaction; any other route 401s a `ws_ot_` bearer without burning it).
- Deploy: `docker/compose.yml` (one image, `wardstone ui` + `wardstone api` + `db` Postgres; **only ws-web publishes 8443**; ws-api is portless by design; required envs fail loudly) and `docker/README.md` (JWT re-key recovery: remove BOTH `jwt-signing-key.pem` and `jwt-verify-key.pem` and restart; silent re-keying invalidates every token). The image contract is no ENTRYPOINT with the `wardstone` binary on PATH.

## Conventions That Differ From Tool Defaults

- Where an enum is stored in a TEXT column, `as_str()` must equal its serde name, and serialized DTOs use `#[serde(rename_all = "snake_case")]`.
- Workspace dependency pins live in the root `Cargo.toml` with an inline rationale comment at the pin site (each consuming task added only the pins it uses).
- `ws-web` selects the rustls `ring` provider explicitly — `aws-lc-rs` must never enter the graph (its build needs an absent C toolchain); verified via `cargo tree -e features -p ws-web`.

## Project Intent

From `README.md`: Wardstone is a self-hosted certificate authority with a web UI — simple enough for a homelab and hardened enough for production.

The "hardened enough for production" clause is a design constraint, not marketing copy: CA key handling, issuance/revoke flows, and the web UI's attack surface are security-sensitive, and choices in this space should be treated accordingly even in early scaffolding.