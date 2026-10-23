# Design: browser-universal root CA (ECDSA P-256 default)

Date: 2026-10-23
Status: draft for approval

## Intent and why

After a fresh Wardstone setup, the operator must be able to install the
root certificate and browse the UI with **zero certificate errors or
warnings in every mainstream browser** — Chrome, Chromium, Brave, Edge,
Firefox, Safari. Today that fails structurally: the setup-minted root CA
is Ed25519 (the Plan 1 pin), and Chromium-family browsers cannot verify
Ed25519 certificate chains — with the root imported they escalate to
`net::ERR_CERT_INVALID` and offer **no bypass**, which is worse than the
untrusted-issuer interstitial. Verified live on the deployed instance
(root `key_type=ed25519`, subject `moon-dragon.us`; leaf RSA-2048;
Chrome and Brave both report `ERR_CERT_INVALID` after root import).

The mandate from the product owner (2026-10-23): after setup, the UI
works without errors or warnings in Chrome, Chromium, Brave, etc. — "this
current state is not acceptable."

## What "works" means (acceptance)

With the instance's root CA PEM imported into the browser/OS trust
store, browsing the UI over HTTPS shows a valid, uninterstitialed
session in each mainstream browser. (No self-hosted CA can pre-trust a
browser before it exists; the import is the one unavoidable operator
step. What must NOT happen: an error that persists *after* import, or a
no-bypass state.)

Existing deployments are explicitly NOT required to migrate in place:
the owner classifies current installs as throwaway dev/test setups
("wipe it at will"). The replacement story for live installs is
documented (below), not coded.

## Goals

1. The CA engine can create and operate **ECDSA P-256 CAs**: generation,
   root and sub-CA creation, leaf issuance signed by an ECDSA CA, CRL
   generation, OCSP response signing.
2. **Setup mints an ECDSA P-256 root by default** — the browser-universal
   choice — instead of Ed25519.
3. All existing key-type choices remain reachable: Ed25519, RSA-2048,
   RSA-3072 CAs stay available through `POST /api/v1/cas` for operators
   who explicitly want them; the CHANGE is the default, not the removal
   of options.
4. Docs state the consequence truthfully: an Ed25519 root cannot be
   trusted by Chromium-family browsers even when imported; the browser-
   universal recommendation is the new ECDSA default.

## Non-goals

- No database migration (key types live in TEXT columns via
  `as_str()`/`from_str`).
- No in-place re-key or "replace root" tooling for running installs.
- No ECDSA P-384 CA variant (P-384 exists for *leaf* keys; CAs gain
  P-256 only, keeping the smallest sensible surface).
- No changes to the ACME protocol surface (JWS keys are client-owned;
  ACME trust flows already documented).
- No changes to leaf key types or the two setup profiles.

## Constraints

- rcgen's `KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)` is the native
  ECDSA path — the same crate/algorithm the leaf generator already uses
  (`ws-ca/src/leafkey.rs:119`), so no new dependency and no RSA-style
  out-of-band key import is needed.
- `KeyType` round-trips through the `key_type` TEXT column as its
  serde `snake_case` name; the new variant's stored string must match
  its serde name exactly (house rule: `as_str()` equals serde name).
- The house lint gate (`cargo clippy --workspace --all-targets -- -D
  warnings`) and `cargo fmt --all -- --check` must stay clean; DB-gated
  suites take their advisory-lock keys as documented.

## The design

### 1. `ws-core::models::ca::KeyType` gains `EcdsaP256`

- New variant, serde name `ecdsa_p256`, `as_str()`/`from_str()` updated.
- Every match over KeyType must be updated (compile-enforced): CA key
  generation, any display/parse surfaces.

### 2. `ws-ca`: ECDSA P-256 as a first-class CA key algorithm

- `ca.rs::generate_ca_key` (or equivalent match at `ca.rs:413`) gains
  `KeyType::EcdsaP256 => KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)`
  — mirroring the Ed25519 arm, NOT the RSA import path.
- Self-signed root creation and `create_sub_ca` must emit and verify a
  P-256-signed chain end to end.
- `crl.rs::build_crl`'s algorithm pin (the `UnsupportedKeyType` arm at
  `crl.rs:300`): the CRL signature algorithm for an ECDSA CA is
  `ecdsa-with-SHA256`; the error-arm prose stays truthful. The existing
  self-test contract must hold: `openssl crl -verify` prints `verify OK`
  against an ECDSA CA.
- `issue.rs`: leaf issuance signed by an ECDSA CA — signature algorithm
  selection must follow the CA key (rcgen chooses by key type); the
  `UnsupportedKeyType` path must remain only for genuinely unsupported
  combinations.
- `ocsp.rs`: OCSP response signing by an ECDSA CA — confirmed needed for
  the builder check: `ocsp.rs` carries the same `algorithm_identifier`
  dispatch as the CRL path, so it gains the identical ECDSA arm.
- Wherever the engine names algorithms in error messages, ECDSA names
  itself rather than falling into "unsupported".

### 3. `ws-web::setup`: the default root becomes ECDSA P-256

- `setup/mod.rs:218` (`key_type: KeyType::Ed25519` in the root CA spec)
  becomes `KeyType::EcdsaP256`.
- The setup flow, its `{"key_type": ...}` bootstrap record and the two
  built-in profiles otherwise stay as they are; profiles pin LEAF key
  types (rsa2048 / ecdsa p-256), which do not change.
- The setup audit row at `setup/mod.rs:338` records the new key type
  naturally.

### 4. Tests (TDD; each behavior change has a watched failure first)

- `ws-core`: `KeyType` round-trip for the new variant (as_str matches
  serde name; from_str accepts `ecdsa_p256`, rejects junk).
- `ws-ca`: create an ECDSA-P256 root; verify the self-signature with
  openssl (`openssl verify -CAfile`); issue a leaf from it and verify
  the chain; build a CRL from the ECDSA CA and prove
  `openssl crl -verify OK`; OCSP response signed by the ECDSA CA
  verifies.
- `ws-api`: `POST /api/v1/cas` accepts `key_type: "ecdsa_p256"` and
  rejects other junk values unchanged.
- `ws-web` (DB-gated): a fresh setup's root CA row and bootstrap audit
  record `ecdsa_p256`; the setup-minted leaf chains and verifies under
  the new root.
- Existing Ed25519/RSA behavior: existing suites must pass untouched —
  this work ADDS an arm, it does not change old arms.

### 5. Migration-for-humans (documentation only)

- `docker/README.md` (trust section) and the root README's ACME/trust
  notes gain the browser-reality paragraph: ECDSA P-256 root = trusted
  by every mainstream browser once imported; **an Ed25519 root cannot be
  trusted by Chromium-family browsers at all** (import-then-fail, no
  bypass). Existing installs on Ed25519 roots recover by wiping and
  re-running setup (owner-approved stance), or by minting an RSA-2048
  CA and re-issuing the serving leaf from it when a wipe is impossible.
- The Plan-1 "root remains Ed25519-signed" ruling is superseded in
  prose wherever it is stated.

## Deployment note for the owner's own instance

After this lands: wipe the CT 242 volumes (`down -v` is fine — the owner
has authorized it), `up -d`, re-run the setup wizard, re-import the NEW
root everywhere (their workstation stores; CT 243's certbot host), and
Chrome/Brave/Chromium verify the UI with no interstitial. CT 243's ACME
account and its certificates are likewise disposable in that flow.

## Left to the builder

- Exact error-message vocabulary for the updated `UnsupportedKeyType`
  arms; function-level placement of the ECDSA sign-algorithm selection.
- OCSP arm test placement (the arm itself is confirmed required, per the
  builder check).
- Test placement per house layout (unit tests in-crate; DB-gated suites
  with advisory keys 0016+ if a new suite is warranted).