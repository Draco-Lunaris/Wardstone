# Sealed-at-rest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Checkbox steps.

**Goal:** every sensitive file on the keys volume and every credential env becomes inert ciphertext until the operator unlocks the instance through the HTTPS front door; the unlock key exists on no disk.

**Architecture:** one passphrase-derived KEK (argon2id → AEAD) seals every
key/credential as an envelope on the keys volume. Both processes boot into a
`sealed` state guarded in-process (no restarts): the ui serves only the
unlock/init pages, the api answers `503 sealed`; the unlock POST (GCRA-limited) derives the KEK, opens the envelopes, relays the unlock to the api over the internal channel, and flips both guards to full service. The DB credential is generated at first unlock and rotated per unlock thereafter. Healthchecks are liveness (always 200 with a state field), so the restart policy never churns a sealed instance.

**Spec:** `docs/superpowers/specs/2026-10-24-sealed-at-rest-design.md` (owner-ratified; this plan implements it).

**Branch:** `feat/sealed-at-rest` (created off main).

## Global Constraints

- House gates per commit: fmt / clippy `-D warnings` / fast suite; DB-gated suites for storage-bearing tasks (`DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test ... --include-ignored`; advisory keys follow the family; next free `0016+`).
- Migrations ADD-ONLY + `REQUIRED_MIGRATION_COUNT` bump (only if any arise — none are expected: envelopes are FILES; the only DB-visible change is the rotated credential, which lives in postgres's own hash store).
- No `unwrap()`/`expect()` outside tests; typed errors; conventional commits; no AI attribution.
- TDD: every red watched; the owner's design is the spec of record — no mechanism substitution.
- The plaintext legacy files (`master.key`, `secret-encryption.key`, JWT PEMs) are **deleted after conversion**; until conversion they are read-only fallbacks (the lazy-upgrade pattern from the OIDC reseal).

**README.md updates are Batch 0** (owner-directed: the docs land with, not after, the code).

---

### Task 0: README.md + docker/README.md — the documented flow

**Files:**
- Modify: `README.md` (Quick start gains the unlock/init step in sequence; Security section states the sealed model plainly — ciphertext-only disks, what the passphrase protects, what is not defended (host-root, a stolen passphrase), passphrase-loss reality; Operations: the sealed state's healthcheck behavior, rotate-at-unlock, the conversion runbook)
- Modify: `docker/README.md` (env table: `WARDSTONE_DB_PASSWORD` re-typed as bootstrap-only; the sealed healthcheck semantics; the upgrade-conversion runbook)
- Create: `.env.example` (commented per the final contract)

**Interfaces:** documents describe the state machine Tasks 1–4 build; wording is reviewed against the spec §8 table verbatim.

- [ ] Step 1: draft the doc changes (before the code, per the owner's direction; they will be re-verified against the built behavior at Task 5).
- [ ] Step 2: commit — `docs: the sealed-at-rest flow in the guides (drafted ahead of the code)`
- *(Re-verification step in Task 5: align any drift the implementation causes.)*

### Task 1: the custody plumbing (`ws-core`)

**Files:**
- Modify: `crates/ws-core/src/crypto.rs` — add `KeyEnvelope`: `derive_kek(passphrase, salt) -> Zeroizing<[u8; 32]>` (argon2id; memory-hard params per spec §10), `seal(kek, plaintext) -> envelope bytes`, `open(kek, envelope) -> Zeroizing<Vec<u8>>`; an envelope file format `{ version, argon params, salt, nonce, ciphertext }`; crash-atomic file writes (the keystore tmp+rename pattern).
- Modify: `crates/ws-core/src/db.rs` — no change expected (no SQL migration planned).

**Interfaces:**
- Produces: `KeyEnvelope` usable by ws-ca (Tasks 2–3) to wrap `master.key`/`secret-encryption.key`/JWT PEM contents, and by wardstone's boot (Task 3) and unlock plumbing (Task 4).

- [ ] Red: `crypto_test.rs` round trip (right passphrase opens; wrong = typed `WrongPassphrase`-class error; tampered ciphertext fails AEAD; salt/params stored in the envelope; wrap of the SAME plaintext twice yields different ciphertext+nonce).
- [ ] Green: implement.
- [ ] Commit: `feat(ws-core): the passphrase-derived KeyEnvelope`

### Task 2: the sealed custody sweep (`ws-ca` + `ws-auth` custody consumers)

**Files:**
- Modify: `crates/ws-ca/src/keystore.rs` — the master KEK and the SecretBox key become `master.envelope`/`secret-encryption.envelope` consumers: on a KEK envelope present + opened, `ensure_master_key`/`create` paths load from envelope; **plaintext-legacy files are the LAZY fallback** (present-but-no-envelope → first unlock converts: wrap + delete plaintext — the OIDC reseal pattern); the envelopes' wrapped DEKs are unchanged.
- Modify: `crates/ws-ca/src/keystore.rs` — `store_setup_key` similarly (the locked-mode listener certificate is minted at INIT time — before envelopes exist for CA keys: this task may defer minting to the INIT page of Task 3, the spec §2 note).
- Modify: `crates/ws-auth/src/jwt.rs` — the PEM pair becomes `jwt-keys.envelope` (contents sealed; both files deleted after conversion; re-key stays an operator action post-unlock).

**Interfaces:**
- Consumes Task 1's KeyEnvelope; consumes `kek: &Zeroizing<[u8; 32]>` at open/wrap points.

- [ ] Red: round-trip tests per file (envelope present → loads; wrong KEK → typed failure; legacy plaintext + correct KEK → converts and deletes).
- [ ] Green. Watch pass.
- [ ] Commit: `feat(ws-ca,ws-auth): every custody file seals under the operator's KEK`

### Task 3: the sealed boot state machine (binary + ui + api)

**Files:**
- Modify: `crates/wardstone/src/main.rs` — boot constructs `SealedState` (Arc<RwLock>) as `Uninitialized` / `Sealed` / derived from the envelopes' presence; the TLS front door binds with the locked-mode certificate path; `run_ui`/`run_api` thread the guard into ws-web/ws-api.
- The post-unlock TLS identity swap rides the existing (unused) `serve_tls` ArcSwap path; the setup self-exit contract (`restart: true`) is replaced by the in-process swap + `resume: true` (spec §4).
- Modify: `crates/ws-web/src/lib.rs` + new `crates/ws-web/src/locked.rs` — the `locked_router`: serves `GET /` (init or unlock page by state) + the unlock POST + `GET /healthz` (200 + state field) + **503 on everything else**; `web_router` gains the guard and 503-s the sealed-material-dependent handlers until unlocked (sessions/JWT).
- Modify: `crates/ws-api/src/routes/health.rs` — `healthz` gains the state field; `crates/ws-api/src/lib.rs` — the api's guard flips `503 sealed` → service.
- Modify: `docker/compose.yml` — the `db` healthcheck → `pg_isready`; the ui/api healthchecks hit their own `healthz` (liveness-in-sealed = 200, so no restart churn); `ws-web` gains `WARDSTONE_DB_BOOTSTRAP_PASSWORD` (the ui is the sole seeding consumer), the api's env becomes the password-less `DATABASE_URL`.

- [ ] Red: boot-state unit tests (uninitialized → init page; sealed → unlock page; non-unlock routes 503; the flip is in-process; restart re-seals state; healthz 200-with-state) — `ws-web` sealed_page tests + `ws-api` health tests.
- [ ] Green. Commit: `feat(wardstone): the sealed boot state machine`

### Task 4: the unlock handshake + relay + rotation

**Files:**
- Modify: `crates/ws-web/src/locked.rs` — `POST /unlock {passphrase}`: GCRA-limited (new budget or the auth budget), argon2 derive, open, flip ui guard, relay to `POST /api/v1/internal/unlock` (a one-time nonce minted at page render to bind the relay; the internal hop carries the passphrase once — spec §5).
- Modify: `crates/ws-api/src/routes/mod.rs` + a new `internal.rs` — the relay endpoint, nonce-bound; on success: unwrap the DB credential (`db-credential.envelope`; absent on fresh installs → seeded via the ui INIT bootstrap per spec §4.3), rotate **unconditionally** (every unlock; no env knob — spec §5.6), build the pool, run `connect`'s migration step post-unlock, flip the api guard.
- Modify: `crates/wardstone/src/main.rs` — the boot DB connect waits for the flip (no DB at boot in sealed mode; the connect moves to unlock completion).
- `ws-worker` is OUT of scope (no deployed entry point — the spec §2 note states it); `connect` splits into connect-with-credential + the migration runner (migrations execute post-unlock).

- [ ] Red: harness tests — wrong passphrase flips nothing (typed error); correct flips both (the loopback relay covered); the relay nonce binds the one POST; DB-gated: rotation alters + re-seals + the old password stops connecting.
- [ ] Green. Commit: `feat: the unlock handshake — derive, open, relay, rotate`

### Task 4b: the master-passphrase change route (operator-managed rotation)

**Files:**
- Modify: `crates/ws-api/src/routes/mod.rs` + a `master_key.rs` route — `POST /api/v1/master-key {current, next}`, `ManageSystem`-gated, audited (`master_key_changed` — the audit row carries NO passphrases).
- Modify: the envelope layer (Task 1) — a `generation` field per envelope; the change sequence: verify `current` → derive the new KEK (fresh salt) → re-wrap every envelope, each write atomic → the params record replaced last. The mixed-state recovery per spec §5.7 (the next unlock offers completion when the generation counter is off).
- Modify: the ui admin surface — the SPA gains the change form (an authenticated admin section entry; the `unlocked` state carries the flag).

- [ ] Red: wrong `current` = typed failure (nothing re-wrapped); happy path re-wraps all + the next unlock uses only `next`; a simulated mid-change crash (partial re-wrap) leaves the mixed state detected at unlock and completable. Watch each fail first.
- [ ] Green. Commit: `feat: the master-passphrase change route (user-managed rotation)`

### Task 5: conversion + docs alignment + whole gates

**Files:**
- Modify: `crates/wardstone/src/main.rs` + ws-web locked.rs — the `Uninitialized` INIT page (set passphrase → convert plaintext legacy files → delete them → proceed to the setup wizard); the upgrade conversion runbook (existing volumes) driven by the same page.
- Re-verify: Task 0's drafted README/docker README against the built behavior; `.env.example` reflects the final contract.
- Whole gates: fmt / clippy / fast suite / DB-gated workspace; compose config validation; then the whole-branch final review, PR.

- [ ] Red: conversion test (plaintext files present → INIT → passphrases → envelopes exist + plaintext gone → reboot lands sealed → unlock works).
- [ ] Green. Commit: `feat: the conversion path and the documented sealed flow`

### Commit cadence & review

One commit per task; the final whole-branch review (the pinned verifier, per the security-basics precedent) → PR #, referencing this plan + the specs.