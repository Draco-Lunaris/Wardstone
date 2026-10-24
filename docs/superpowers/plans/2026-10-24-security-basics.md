# Security Basics Implementation Plan (threat-model gaps, batches A–C)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** close the High/Medium grades of `docs/security/threat-model.md` §3 with the cheap standard fixes (batches A–C), leaving the custody decision (Tier 1 + boot rotation) as its own later piece.

**Architecture:** Batch A closes the OIDC flow (G3 PKCE-S256 + G2 lazy-seal of the client secret via the existing SecretBox); Batch B hardens ws-web/ws-api responses (G4 headers, G9 error envelopes, G12 body limit, G13 JSON 429); Batch C closes the smalls (G8 fingerprint gate, G6 healthchecks, G10 zeroization minors, G11 doc note).

**Spec:** `docs/security/threat-model.md` (grades + directions), facts in `docs/security/as-built-inventory.md`.

**Branch:** `fix/security-basics` (off main; PR per batch or one PR at the end).

## Global Constraints

- House gates per commit: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings` (`-p ws-core`/`-p ws-web` for the batch), `cargo test --workspace` + DB-gated suites (`DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test ... -- --include-ignored`, advisory keys: `ws-api` suites hold 0011/0012; next free 0016 if a NEW suite appears).
- Migrations ADD-ONLY (sqlx checksums); bump `REQUIRED_MIGRATION_COUNT` per addition.
- No `unwrap()`/`expect()` outside tests; typed errors; conventional commits; no AI attribution.
- TDD: every red watched.

---

## Batch A — OIDC closure

### Task A1: PKCE math (ws-auth)

**Files:** Modify `crates/ws-auth/src/oidc.rs` (new `pub mod pkce` or top-level fns — placed beside the OAuth client mechanics); tests in the file's test area or `tests/oidc_test.rs`.

**Interfaces:**
- Produces: `pub fn generate_verifier(seed: [u8; 32]) -> (String, String)` = `(verifier, challenge)` — verifier: base64url-no-pad of the 32 bytes (43 chars, RFC 7636 charset); challenge: `base64url(SHA-256(verifier))`, no padding. A random-seed wrapper `pub fn mint_verifier() -> Result<(String, String), AuthError>` over OS entropy.

- [ ] Red: unit test computes challenge independently (`sha2` is in ws-core, not ws-auth — compute via the same crate the impl uses or add the dependency as needed; assert 43-char verifier matches `[A-Za-z0-9_-]`, and challenge equals `b64url(SHA256(verifier))` recomputed in the test), plus mint path. Watch fail.
- [ ] Green: implement. Watch pass.
- [ ] Commit: `feat(ws-auth): PKCE S256 verifier/challenge generation`

### Task A2: PKCE through the flow (ws-api)

**Files:**
- Modify `crates/ws-api/src/state.rs` (`OidcPending` gains `code_verifier: String`; `mint` returns `{state, code_verifier, code_challenge}` — name the return type; `consume` returns `Option<(uuid::Uuid, String /*verifier*/)>`)
- Modify `crates/ws-api/src/routes/auth.rs` (start URL gains `code_challenge` + `code_challenge_method=S256`; callback passes the verifier into exchange)
- Modify `crates/ws-auth/src/oidc.rs::exchange_code` (new param `code_verifier: &str`; appended to the token POST form)
- Tests: unit tests in `state.rs`'s test module or near; `tests/api_test.rs` extends `oidc_start_mints_csrf_state`'s neighborhood (`code_challenge` visible only through a live-IdP test — check `tests/oidc_test.rs` for the loopback provider fixture and assert the authorize redirect carries `code_challenge`/`method`, and the fake token endpoint asserts `code_verifier` in the POSTed form).

- [ ] Red tests: pending-store round trip (mint→consume returns the verifier); exchange POST body carries `code_verifier` (loopback fixture). Watch fail.
- [ ] Green. Watch pass. Commit: `feat(ws-api,ws-auth): PKCE S256 through the authorization-code flow`

### Task A3: seal the OIDC client secret (G2)

**Files:**
- Create `crates/ws-core/migrations/013_oidc_client_secret_sealing.sql`: `ALTER TABLE oidc_config ADD COLUMN client_secret_encrypted BYTEA;` + `..._nonce BYTEA;` — the TEXT column stays as the LEGACY slot, cleared lazily; comment states the lazy-reseal contract. Bump `REQUIRED_MIGRATION_COUNT` in `crates/ws-core/src/db.rs` (→ 13).
- Modify `crates/ws-core/src/models/credential.rs` (`OidcConfigModel`: + `client_secret_encrypted: Option<Vec<u8>>`, `client_secret_nonce: Option<Vec<u8>>`; `client_secret` stays the transient plaintext field, doc-commented as such)
- Modify `crates/ws-core/src/repo/oidc_repo.rs` (`get`/`upsert` gain a `seal_key: &SecretBox` parameter; `get` performs the lazy legcy reseal (legacy text non-empty → seal → UPDATE → clear) with a WARN and a plaintext passthrough if unsealing is impossible — Ruling to ledger: loud over silent; `put_config`'s keep-stored path re-seals the unsealed value)
- Modify `crates/ws-api/src/routes/oidc.rs` (`get_config`/`put_config`/`test_config` load the SecretBox from `state.secret_key_path()` per request — the TOTP pattern; `oidc.rs` start/callback read the unsealed model)
- Tests: `crates/ws-api/tests/oidc_test.rs` — round trip (put with secret → columns non-null + text `''`+ get returns `client_secret_set: true`) and `None`-keeps path; legacy backfill: direct SQL insert of a plaintext row → `get` migrates it (columns populated, text cleared). RED → GREEN per test.

- [ ] Red: suite extensions. Watch fail (today's columns don't exist / plaintext remains).
- [ ] Green: migration + model + repo + routes. Watch pass (DB-gated suite + workspace fast).
- [ ] Commit: `feat(ws-core,ws-api): seal the OIDC client secret at rest (lazy legacy reseal)`

## Batch B — surface hardening (anchors from the inventory)

- **B1 G4 headers** (`crates/ws-web/src/ui.rs` + the fallback/setup paths): a layer setting `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` (or CSP `frame-ancestors 'none'` — CSP default-src story in ws-web may break the SPA; the minimal honest set: nosniff + frame-ancestors-only CSP + referrer; HSTS NOT set (there is no HTTP listener; CSP script-src needs the built asset hashes — out of this batch's budget; ledger as deferred with reason). Tests: ui.rs serves responses carrying the headers (extend `ui_serve_test.rs`).
- **B2 G9 500/502 envelopes**: ws-api `error.rs:241-244` — 500s map to a generic internal-error JSON envelope (no sqlx text); ws-proxy `proxy.rs:299-307` 502 → JSON `{"error":{"code":"bad_gateway"}}` shape matching the house envelope. Tests: error-mapping unit tests + a proxy 502 shape test.
- **B3 G12 body limit**: `DefaultBodyLimit::max(...)` on both routers (a documented house cap, e.g. 1 MiB — the largest legit body is an ACME finalize CSR; pin the chosen value in a test).
- **B4 G13 JSON 429**: the house JSON envelope replaces tower_governor's plain text (a governor error handler into `{"error":{"code":"rate_limited"...}}`; keeps the UI's parser contract). Test: the 429 body parses as the envelope.
- **B5 G6 healthchecks**: compose.yml gains a healthcheck per Wardstone service exercising their own healthz (ui: `wget --no-check-certificate -qO- https://127.0.0.1:8443/healthz`-style or an api-mode `wget http://ws-api:8080/api/v1/healthz`— ui's healthz exists? verify the surface; if the ui has none, point the healthcheck at the SPA root). Commit batch: `feat: surface hardening...`

## Batch C — the smalls

- **C1 G8 fingerprint gate**: the setup POST must carry `confirmation = <the displayed fingerprint>` (a new required field; the page's JS sends it — the page already displays the fingerprint; UI change in `page.rs`/the setup form + server-side compare in `setup/mod.rs` validation + tests in `setup_test.rs`: wrong/missing fingerprint → 400).
- **C2 G10 zeroization**: `certificates.rs:515` DER copy zeroized; JWT PEM `String` → kept but the issue path rebuilt from a `Zeroizing` field (bounded change; keep parity with tests).
- **C3 G11**: `webauthn_credential` documented reserved in the model/migration comment (no functional change).
- Commit batch: `feat: the small security closures...`

## Gates per batch + final

fmt / clippy / fast suite / DB-gated suites; then the whole-branch review (final-verifier), then PR(s) referencing the threat model grades.