# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Status

**The four-plan roadmap is COMPLETE: Plans 1-4 are all merged.** Plan 4 delivered the first-party ACME server (RFC 8555, `ws-acme` crate; the `WS-ACME`/`ACME` capability pair; machine surface `/acme/<tenant>/…` behind the ws-web front door, UI visibility via `/api/v1/acme` REST). What remains is a **maintenance ledger** catalogued in the PR #1-#3 descriptions and the archived SDD ledgers: concurrent-finalize double-issue on a ready order, session-store idle-cap wording, profile-description edit freeze (server-side edit path does not exist), LIKE-metachar literal-search UX, ACME PoP revocation mode, and ~40 triaged deferred minors. (The cross-suite test-DB interference ruling was executed 2026-10-25: rotating suites fence with the process-local tokio mutex before the fixture connect, restore the shared role over the fixture's dedicated pre-rotation connection before any post-rotation read, and ws-web's `setup_test` carries a panic-safe Drop restore net — `a_fixture_dropped_mid_rotation_restores_the_shared_role` pins it; `e2e_test`/`sealed_test` still lack the Drop net.) A new plan starts with a brainstorm (`superpowers:brainstorming`), then a spec, then an implementation plan in `docs/superpowers/plans/`.

## Build, Lint, and Test

- Lint: `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` — both must be clean for every commit.
- Fast tests (no database): `cargo test --workspace`.
- DB-gated tests: `DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test cargo test --workspace -- --include-ignored` against a live Postgres with that database.
- One suite: `cargo test -p <crate> --test <suite_name> -- --include-ignored`.
- House style: no `unwrap()`/`expect()` outside `#[cfg(test)]` modules (typed error enums); short conventional-commit subjects; **no AI co-author attribution** in commits.

## DB-Gated Test Conventions (binding)

- Test DB: `postgres://wardstone:wardstone@localhost:5432/wardstone_test`.
- Every DB-gated suite takes a unique advisory-lock key from the `0x0057_4144_5354_00xx` family — **0003 through 0016 are taken** (`0014` = `ws-api acme_test`, `0015` = `ws-web acme_e2e_test`, `0016` = `ws-api sealed_test` — the other suites' assignments follow their `ADVISORY_KEY` comment); the next free key is `0017`. Never reuse a key.
- Every suite sweeps its own rows (FK order) BEFORE each test and **DELETEs the rows it created at the END of each test** — `crates/ws-core/tests/db_test.rs` snapshots the tenant-name set before/after and proves `connect()` itself never seeds a tenant.
- **Suites that rotate the shared `wardstone` role's password** (setup POSTs run the sealed-at-rest conversion; the api unlock builder rotates per unlock) MUST: take the process-local tokio-mutex fence BEFORE the fixture connect (the advisory lock cannot order the pre-lock connect); restore the role over the fixture's DEDICATED pre-rotation connection — never the pool, which may open a fresh connection exactly when the password is rotated — BEFORE any post-rotation DB read; and (the reference implementation: `ws-web tests/setup_test.rs`'s `RestoreNet` + `a_fixture_dropped_mid_rotation_restores_the_shared_role`) carry a panic-safe Drop net so a test unwinding mid-window cannot poison every later suite with misleading `28P01`s. A poisoned role resets with `sudo -n -u postgres psql -c "ALTER USER wardstone PASSWORD 'wardstone';"`.
- Migration files in `crates/ws-core/migrations/` are ADD-ONLY: sqlx checksums them (SHA-384 over raw bytes), so editing an applied migration breaks every deployed database. Bump `REQUIRED_MIGRATION_COUNT` in `crates/ws-core/src/db.rs` when adding one; `connect()` runs migrations before the count check.

## Architecture

Crate graph (acyclic): `ws-core` (SQLx Postgres persistence: models, tenant-scoped tables, executor-agnostic stateless repos taking `&mut PgConnection`/executors — see `user_repo.rs` for the house idiom) ← `ws-ca` (engine: CSR validation, issuance/revocation, EKU, key-usage, pinned leaf keys with EXACT-size refusal, the `KeyStore` with master-key envelopes and the `ca/setup.key` slot, advisory-lock serial allocation) and `ws-auth` (argon2id, Ed25519 JWT with the two-file key pair, TOTP, generic OIDC SSO, service identities/API tokens/refresh tokens, lookup-only one-shot tokens) ← `ws-api` (axum REST `/api/v1/`: per-route capability checks, the CoreError→ApiError mapping table, transactional audit — a mutation and its audit row commit on the same transaction — GCRA rate limiting on auth routes) and `ws-web` (TLS front door via `axum-server`/ring, `/api/v1` path proxy with bounded timeouts, first-run setup page conditionally mounted only while the default tenant is absent; setup mints tenant/root CA/admin/two profiles/CA-issued leaf key-before-row and self-exits for a process-restart TLS switch) ← `wardstone` (single binary, `ui`/`api` modes; boot TLS resolves the newest `status=active AND profile_name="web-server"` certificate row + `keystore.load_ca_key(cert.id)`; torn state falls back to a fresh setup certificate with a WARN; an un-loadable active-leaf envelope is a hard boot failure). `ws-worker` runs post-issuance jobs (CRLs) against ws-ca. **Plan 4 delivered ACME**: the `ws-acme` crate (first-party RFC 8555 — JWS verification with alg-key pinning, RFC 7638 thumbprints, the single-use nonce store; challenge arithmetic) served through `ws-api`'s `/acme/{tenant}/…` machine surface (JWS + `problem+json`; Replay-Nonce on every response) and visible via `/api/v1/acme` REST (`read_acme`/`manage_acme_accounts`); `/acme/*` and `/api/v1/*` both path-proxy through ws-web; per-IP enrollment GCRA at the ws-web edge, per-account limiter with `WARDSTONE_ACME_ACCOUNT_LIMIT_DISABLED`; `WARDSTONE_PUBLIC_URL` is the absolute-URL base (Host never trusted).

- Token families by prefix: `ws_rt_` refresh, `ws_at_` API/service-identity tokens (`ws-at_`-shaped lookups are hash-only), `ws_ot_` one-shot (redeem ONLY at `POST /api/v1/certificates/pull`, which claims it inside the issuance transaction; any other route 401s a `ws_ot_` bearer without burning it).
- Deploy: `docker/compose.yml` (one image, `wardstone ui` + `wardstone api` + `db` Postgres; **only ws-web publishes 8443**; ws-api is portless by design; required envs fail loudly) and `docker/README.md` (JWT re-key recovery: remove BOTH `jwt-signing-key.pem` and `jwt-verify-key.pem` and restart; silent re-keying invalidates every token). The image contract is no ENTRYPOINT with the `wardstone` binary on PATH.

## Conventions That Differ From Tool Defaults

- Where an enum is stored in a TEXT column, `as_str()` must equal its serde name, and serialized DTOs use `#[serde(rename_all = "snake_case")]`.
- Workspace dependency pins live in the root `Cargo.toml` with an inline rationale comment at the pin site (each consuming task added only the pins it uses).
- `ws-web` selects the rustls `ring` provider explicitly — `aws-lc-rs` must never enter the graph (its build needs an absent C toolchain); verified via `cargo tree -e features -p ws-web`.

## Project Intent

From `README.md`: Wardstone is a self-hosted certificate authority with a web UI — simple enough for a homelab and hardened enough for production.

The "hardened enough for production" clause is a design constraint, not marketing copy: CA key handling, issuance/revoke flows, and the web UI's attack surface are security-sensitive, and choices in this space should be treated accordingly even in early scaffolding.