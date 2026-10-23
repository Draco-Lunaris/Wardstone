# Browser-Universal Root CA Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Setup mints an ECDSA P-256 root CA by default, so an imported root verifies in every mainstream browser with no interstitial.

**Architecture:** `KeyType` gains `EcdsaP256` (TEXT-column round-trip, no migration); `ws-ca` generates ECDSA CA keys through rcgen's native `PKCS_ECDSA_P256_SHA256` (the path leaf keys already exercise) and every signing surface — leaf issuance, CRL, OCSP — chooses its algorithm from the CA key; `ws-web`'s setup pins the default root to the new variant. Docs carry the browser-reality paragraph and the recovery paths for pre-change installs.

**Tech Stack:** Rust workspace (edition 2021, MSRV 1.89), rcgen 0.14 (`PKCS_ECDSA_P256_SHA256`), x509-parser 0.18 (ring-backed `verify_signature`), sqlx Postgres (TEXT columns, no migration), stock `openssl` CLI for interop self-tests (house precedent: `crl_test.rs:315`).

**Spec:** `docs/superpowers/specs/2026-10-23-browser-universal-root-ca-design.md` (builder-checked; ocsp.rs arm confirmed required).

## Global Constraints

- House lint gate: `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` clean for every commit.
- `KeyType::as_str()` must equal the serde name for every variant (house rule) — the new variant stores `"ecdsa_p256"` in the `key_type` TEXT column.
- No `unwrap()`/`expect()` outside `#[cfg(test)]`; typed error enums.
- Conventional-commit subjects; **no AI co-author attribution** in commits.
- Existing behavior is ADD-ONLY at every arm: Ed25519 and RSA paths compile and pass unchanged.
- Branch: `plan/browser-universal-ca`; DB-gated suites only with `DATABASE_URL=postgres://wardstone:wardstone@localhost:5432/wardstone_test ... --include-ignored` and their advisory-lock keys (`0x0057_4144_5354_00xx`; next free is `0016`).

## Review Focus

1. `from_str` near-misses (`"ecdsa"`, `"ecdsa_p_256"`, `"ECDSA_P256"`, `"p256"`) must be **rejected** — only the exact serde string parses. → Task 1 test.
2. The `crl.rs`/`ocsp.rs` AlgorithmIdentifier for an ECDSA CA must be **`ecdsa-with-SHA256` with ABSENT parameters** (RFC 5758 §3) — a NULL-parameters encoding (RSA-style) would be structurally valid DER but wrong DER. → Tasks 4–5 assert parsed parameters are empty.
3. An Ed25519 root keeps working exactly as before (no regression arm-swap by accident). → Task 2 keeps the pre-existing Ed25519 test passing untouched and asserts both.
4. After a fresh setup, the recorded key type must be **`ecdsa_p256`** end-to-end (row AND bootstrap audit), so wipe-and-re-setup observability stays truthful. → Task 6 DB-gated test.
5. Leaf issuance **from an ECDSA CA** must not fall into `UnsupportedKeyType` — the pin that algorithm-follows-key in issuance is real. → Task 3.

---

### Task 1: `KeyType::EcdsaP256` in ws-core

**Files:**
- Modify: `crates/ws-core/src/models/ca.rs:15-59` (enum arms, `as_str`, `FromStr`)
- Test: `crates/ws-core/src/models/ca.rs` (`#[cfg(test)] mod tests`, line 97)

**Interfaces:**
- Produces: `KeyType::EcdsaP256` with `as_str() -> "ecdsa_p256"`, `FromStr` accepting exactly `"ecdsa_p256"`; serde serializes to `ecdsa_p256` (derive + `snake_case`). All later tasks and the API parse path consume this.

- [ ] **Step 1: Write failing tests in the existing `mod tests`**

Extend the round-trip test there: `KeyType::EcdsaP256.as_str() == "ecdsa_p256"`; `serde_json::to_value(KeyType::EcdsaP256) == "ecdsa_p256"`; `"ecdsa_p256".parse::<KeyType>()` is `Ok(EcdsaP256)`; near-misses `"ecdsa"`, `"ECDSA_P256"`, `"p256"` are `Err(UnknownKeyType)`.

- [ ] **Step 2: Watch it fail**

Run: `cargo test -p ws-core --lib models::ca`
Expected: FAIL — the match in `as_str` is non-exhaustive ("non-exhaustive patterns") and the parse assertions miss.

- [ ] **Step 3: Implement**

Add the variant (doc comment: "ECDSA P-256 signature key."), the `as_str` arm, the `FromStr` arm. Derive-gated serde needs no change.

- [ ] **Step 4: Watch it pass**

Run: `cargo test -p ws-core --lib models::ca`
Expected: PASS. Then make the workspace compile: the other exhaustive matches over `KeyType` (`generate_key_pair`, the two `algorithm_identifier` dispatches) gain **explicit typed stubs** for `EcdsaP256` — an `UnsupportedKeyType` error naming itself and never a silent `_ =>` catch-all. Tasks 2, 4, and 5 replace those stubs, watched by their tests.

Run: `cargo check --workspace` — must compile.

- [ ] **Step 5: Commit**

```bash
git add crates/ws-core/src/models/ca.rs crates/ws-ca/src/ca.rs crates/ws-ca/src/crl.rs crates/ws-ca/src/ocsp.rs
git commit -m "feat(ws-core): EcdsaP256 joins the CA KeyType enum"
```

### Task 2: ECDSA CA key generation and root creation (ws-ca)

**Files:**
- Modify: `crates/ws-ca/src/ca.rs:407-417` (`generate_key_pair`; import `PKCS_ECDSA_P256_SHA256` beside `PKCS_ED25519`)
- Modify: `crates/ws-ca/src/ca.rs:6` module doc (arms list gains ECDSA)
- Test: `crates/ws-ca/tests/ca_creation_test.rs` (mirror the Ed25519 root test's fixture shape)

**Interfaces:**
- Consumes: `KeyType::EcdsaP256` (Task 1).
- Produces: `generate_key_pair(KeyType::EcdsaP256)` → rcgen `KeyPair` (native generation, no RSA-style DER import); `create_root`/`create_sub_ca` work for ECDSA unchanged in signature.

- [ ] **Step 1: Write failing test** — in `ca_creation_test.rs`: generate an ECDSA root (temp keystore dir, house fixture), parse `created.cert_pem` with x509-parser, assert the certificate's `signature_algorithm.oid` is `ecdsa-with-SHA256` (1.2.840.10045.4.3.2) and the public key parses as P-256; then `x509_parser::verify::verify_signature` of the cert against its own SPKI (house style, ring-backed, as `crl_test.rs:12` does for CRLs).
- [ ] **Step 2: Watch it fail** — `cargo test -p ws-ca --test ca_creation_test` → non-exhaustive match panic (the variant exists, generation doesn't).
- [ ] **Step 3: Implement** — add the arm: `KeyType::EcdsaP256 => Ok(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?)`; update the module-doc arms list at `ca.rs:6` and the `generate_key_pair` doc comment (Ed25519 line) truthfully.
- [ ] **Step 4: Watch it pass** — same command, PASS; existing Ed25519/RSA tests untouched and green.
- [ ] **Step 5: Commit**

```bash
git add crates/ws-ca/src/ca.rs crates/ws-ca/tests/ca_creation_test.rs
git commit -m "feat(ws-ca): ECDSA P-256 CA key generation and self-signed roots"
```

### Task 3: Leaf issuance from an ECDSA CA (ws-ca)

**Files:**
- Test: `crates/ws-ca/tests/issue_test.rs` (mirror the existing Ed25519-CA issuance test)

**Interfaces:**
- Consumes: Task 2's ECDSA root creation.
- Produces: a pinned regression — leaf issuance signs algorithm-follows-key with no `UnsupportedKeyType`.

- [ ] **Step 1: Write the test first** — issue one rsa2048 leaf and one ecdsa-p256 leaf from an ECDSA-P256 CA (the issuance fixtures exist in the suite); parse both, run x509-parser `verify_signature` against the CA's SPKI, and assert the SIGNATURE ALGORITHM of each leaf is `ecdsa-with-SHA256` (the CA signs, whatever the leaf key type is). Note in the doc comment: this is a behavior pin — if it passes against unchanged code, it still guards the algorithm-follows-key contract.
- [ ] **Step 2: Watch it** — `cargo test -p ws-ca --test issue_test`. If it FAILS with `UnsupportedKeyType` or a wrong algorithm, add the minimal signer-selection arm in `issue.rs` (follow how `create_root` gets its params); if it PASSES, the pin stands with no production change — record that in the commit message.
- [ ] **Step 3: Commit**

```bash
git add crates/ws-ca/tests/issue_test.rs  # plus issue.rs only if the pin forced an arm
git commit -m "test(ws-ca): leaf issuance from an ECDSA CA pins algorithm-follows-key"
```

### Task 4: CRL from an ECDSA CA (ws-ca)

**Files:**
- Modify: `crates/ws-ca/src/crl.rs:294-310` (`algorithm_identifier` dispatch) and the doc block above it; add the `ecdsa-with-SHA256` OID constant beside `OID_SIG_ED25519`.
- Test: `crates/ws-ca/tests/crl_test.rs` (mirror the Ed25519 CRL test's three-layer verification)

**Interfaces:**
- Consumes: Task 2's ECDSA root.
- Produces: `build_crl` accepts an ECDSA CA and emits `ecdsa-with-SHA256` with **absent** parameters.

- [ ] **Step 1: Failing test** — a CRL from an ECDSA CA: parse, assert the signature algorithm OID is `1.2.840.10045.4.3.2` with empty parameters; `x509_parser` `verify_signature` against the CA; interop: `openssl crl -in crl.pem -CAfile ca.pem -noout` prints `verify OK` (house pattern `crl_test.rs:315`).
- [ ] **Step 2: Watch it fail** — `cargo test -p ws-ca --test crl_test` → `UnsupportedKeyType("CRL signing is not supported for this CA key algorithm (Ecdsa P256)")`.
- [ ] **Step 3: Implement** — dispatch arm: `PKCS_ECDSA_P256_SHA256` → `(OID_SIG_ECDSA_SHA256, false)`; update the doc block (both files' `algorithm_identifier` doc comments live in twinned form — keep them consistent).
- [ ] **Step 4: Watch it pass**; then `cargo test -p ws-ca`.
- [ ] **Step 5: Commit**

```bash
git add crates/ws-ca/src/crl.rs crates/ws-ca/tests/crl_test.rs
git commit -m "feat(ws-ca): CRLs signed by ECDSA P-256 CAs (ecdsa-with-SHA256)"
```

### Task 5: OCSP response signing by an ECDSA CA (ws-ca)

**Files:**
- Modify: `crates/ws-ca/src/ocsp.rs:324-340` (`algorithm_identifier`; twin of the CRL dispatch)
- Test: `crates/ws-ca/tests/ocsp_test.rs` (mirror the Ed25519 OCSP response test)

**Interfaces:**
- Consumes: Task 2's ECDSA root.
- Produces: OCSP responses `Response verify OK` against an ECDSA CA.

- [ ] **Step 1: Failing test** — mint an OCSP response for a leaf issued from the ECDSA CA; assert `ecdsa-with-SHA256` with absent parameters; verify per the existing OCSP test's method (x509-parser `verify_signature`; `openssl ocsp -resp_text`/`-verify` only if the existing suite already drives the CLI).
- [ ] **Step 2: Watch it fail** — `cargo test -p ws-ca --test ocsp_test` → the OCSP-side `UnsupportedKeyType`.
- [ ] **Step 3: Implement** — the twin arm in `ocsp.rs::algorithm_identifier` + doc update.
- [ ] **Step 4: Watch it pass.**
- [ ] **Step 5: Commit**

```bash
git add crates/ws-ca/src/ocsp.rs crates/ws-ca/tests/ocsp_test.rs
git commit -m "feat(ws-ca): OCSP responses signed by ECDSA P-256 CAs"
```

### Task 6: Setup's default root becomes ECDSA P-256 (ws-web, DB-gated)

**Files:**
- Modify: `crates/ws-web/src/setup/mod.rs:218` (the root `CaSpec::key_type`) and the rationale comment above it
- Test: `crates/ws-web` setup suite (wherever the existing setup default-tenant test asserts the root row — follow its pattern)

**Interfaces:**
- Consumes: Tasks 1–2.
- Produces: the DB-gated, end-to-end proof of the mandate — a fresh setup records `key_type=ecdsa_p256` everywhere it records key types.

- [ ] **Step 1: Failing test** — in the setup suite, extend the test that runs setup against the test DB (advisory key per its header comment; sweep in FK order): after setup, read the `cas` row and assert `key_type == "ecdsa_p256"` and the bootstrap audit row's `key_type` JSON value likewise; then `openssl verify -CAfile <root.pem> <setup-leaf.pem>` proves the whole chain outside OpenSSL's own API. **Advisory key: take `0x0057_4144_5354_0016`** (next free) if this is a NEW suite; extend the existing suite otherwise.
- [ ] **Step 2: Watch it fail** — `cargo test -p ws-web --test setup_test -- --include-ignored` (suite name per the file that holds it) → `ed25519` != `ecdsa_p256`.
- [ ] **Step 3: Implement** — swap the pin at `setup/mod.rs:218` and rewrite the comment: ECDSA P-256 root — **the browser-universal default** (Chromium-family cannot verify Ed25519 chains even with the root imported); generation is instant like Ed25519; smallest signatures with widest verification.
- [ ] **Step 4: Watch it pass**; run both `cargo test -p ws-web --test setup_test -- --include-ignored` and, with the local Postgres available, `cargo test --workspace -- --include-ignored` if a DB is up (house memory: built-in fallback URL; `--include-ignored` after ONE `--`).
- [ ] **Step 5: Commit**

```bash
git add crates/ws-web/src/setup/mod.rs
git add crates/ws-web/tests/setup_test.rs   # or the suite file touched
git commit -m "feat(ws-web): fresh setups mint an ECDSA P-256 root CA"
```

### Task 7: Docs — the browser reality and the recovery paths

**Files:**
- Modify: `docker/README.md` (the "TLS trust." bullet, ~line 182) and its ops-notes
- Modify: `README.md` (ACME trust + Security sections)
- Modify: `docs/superpowers/specs/2026-10-23-browser-universal-root-ca-design.md` — no changes; the plan implements it.

- [ ] **Step 1: Write the docs** — the trust paragraphs state: fresh installs mint an ECDSA P-256 root trusted by every mainstream browser once imported; **an Ed25519 root cannot be trusted by Chromium-family browsers at all** (import escalates to `net::ERR_CERT_INVALID`, no bypass); installs created before this change recover by wiping and re-running setup (owner stance) or by minting an RSA-2048 CA and re-issuing the serving leaf when a wipe is impossible. Supersede the Plan-1 "root remains Ed25519-signed" language wherever stated (docker/README if present).
- [ ] **Step 2: Gate check** — docs only, but run the full gate once: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.
- [ ] **Step 3: Commit**

```bash
git add docker/README.md README.md
git commit -m "docs: the root CA is ECDSA P-256 by default; Ed25519 roots cannot win Chromium trust"
```

### Task 8: Whole-gate and PR

- [ ] `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and the DB-gated suites (`cargo test --workspace -- --include-ignored` with the local test Postgres up) all green.
- [ ] Push the branch; PR into `main` with the spec linked, the live-fault evidence, and the operator wipe-and-resetup note for the deployed instance.