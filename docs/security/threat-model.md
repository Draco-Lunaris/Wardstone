# Wardstone Threat Model

Date: 2026-10-24 · Companion to [`as-built-inventory.md`](as-built-inventory.md)
(facts + citations; this document grades them and makes the decisions).
Status: **draft for owner review** — decision points are marked **[OWNER]** and
show my recommendation under the constraint set the owner has stated:

> Design constraints (owner-stated, standing): unattended boot required;
> must not be bound to a single machine (cluster/redeploy portability); no
> plaintext secrets at rest; multiple independent boundaries per asset, never
> one; and a complexity budget — a mechanism whose own complexity raises the
> mistake rate is rejected like a missing control.

---

## 1. What Wardstone is protecting (assets)

| # | Asset | Where it lives | Compromise means |
|---|-------|----------------|------------------|
| A1 | **CA private keys** (root, sub-CAs, server leaf) — total minting power over every tenant identity | envelopes at `keys/ca/*.key`, opened under the master KEK | envelope + master (one boundary today) |
| A2 | Root of trust derivation — whoever forges a root-level signer owns every future and (with existing certs) can re-sign histories visible to trusting clients | master KEK → CA keys | A1 |
| A3 | **TOTP secrets** (second factor) | DB, sealed under `secret-encryption.key` | sealed blob + that key (one boundary) |
| A4 | **Login credentials** (password hashes) | DB, argon2id | DB read + offline cracking resistance (argon2id) |
| A5 | **Session material** (access/refresh token pairs) | ws-web memory + ws-api DB rows (hashes) | ws-web memory read; refresh bearer theft |
| A6 | **ACME account keys** | client-held; server holds public JWK only | client machine |
| A7 | **Tenant DB** (certificates, audit chain, identities, config) | `wardstone-pgdata` | DB compromise |
| A8 | **OIDC client secret** (SSO identity) | DB **plaintext** (inventory G2) | DB read |
| A9 | Machine token raw material (`ws_at_`/`ws_ot_`) — exists once at mint | response body once; hash in DB | response capture; hash-only at rest |
| A10 | The **audit log** (who did what; tamper = forensic damage) | DB append rows | DB write access |

## 2. Adversaries

| # | Adversary | What they get today (controls in parentheses) |
|---|-----------|----------------------------------------------|
| U | **Unauthenticated LAN peer** — any host on the network the front door serves | TLS-only path; GCRA per-IP on credential surfaces; server-computed ACME challenges; public surface = SPA + the pre-auth endpoints (§B). What they cannot do: read anything, mint anything, without credentials or a challenge answer they don't control |
| D | **DB-read adversary** — someone copies `wardstone-pgdata` (snapshot, backup, container attach) | password hashes (argon2id), token hashes (irreversible), sealed TOTP blobs, **plaintext OIDC secrets (G2)**, cert PEMs (public), audit rows |
| K | **Keys-volume read adversary** — someone copies `wardstone-keys` | **everything**: master KEK + SecretBox key in plaintext beside every envelope/seal (G1). This single copy defeats envelopes AND the TOTP seal |
| P | **Container-escape / ws-process compromise** — code exec in one wardstone container | in-process keys in RAM; the keys dir (same as K); ws-web also holds every live session's token pair in memory; **no second process to stop at** (single-instance world, G5) |
| S | **Host-root on the wardstone node** (or an operator who is themselves) — full docker + filesystem control | everything on both volumes, both processes' memory (via docker exec), and the ability to persist tampering. Not defended today — **accepted** (see 6) |
| R | **Remote attacker via the ACME surface** — unauthenticated enrollment attempts | open enrollment bounded by server-computed challenge verification (a client can only win identifiers it controls); per-IP + per-account limiters; nonce replay blocked |
| I | **IdP-side / OAuth-flow attacker** (hostile redirect, stolen auth code, IdP compromise) | state CSRF store (single-use, 10 min); exact redirect pinning; JWKS-verified ID tokens; **no PKCE (G3)** |
| B | **Browser-side attacker** (XSS, clickjacking, CSRF) | tokens never in JS (the strongest control the product has); CSRF custom-header fail-closed; SameSite=Lax; **no CSP/frame-guard/nosniff (G4)** |

## 3. Control summary today (from the inventory, graded)

**The strong set (keep, and this is most of the product):**
- Enveloped, AAD-bound, 0600 crash-atomic key writes with refused remint;
  no private key ever in the DB (A1's *form* is right — A1's *custody* is not).
- argon2id passwords; hash-only token storage with mint-once plaintexts;
  TOTP sealed at rest in the DB (relative to the DB, the right choice).
- Token-free browser (A5's browser half), server-side sessions with rotation
  and fail-closed refresh; CSRF custom-header on mutating cookie requests.
- ACME's verifier-owned challenge model; JWS alg pinning; nonce replay block.
- Loud boot failures over silent heals everywhere (a real habit throughout).

**The gaps (inventory §E, now graded on effect):**

| Gap | Effect if used against you | Grade | Direction |
|-----|----------------------------|-------|-----------|
| G1 One-boundary custody | one volume copy = total CA compromise (K above) | **Critical** | §4 — the designed decision, once |
| G2 OIDC client secret plaintext | IdP impersonation/spoof of SSO config from a DB copy | **High** | seal with the existing SecretBox (columns + migration) — small, standard |
| G3 No PKCE | auth-code interception on hostile/LAN clients during the SSO window | **High** | implement PKCE (S256) — bounded, standard |
| G4 No security headers | XSS/frame/nosniff hardening absent; a UA-only gap | **High** (cheap) | baseline CSP + nosniff + frame-guard + referrer on ws-web responses; HSTS optional (TLS-only listener exists) |
| G7 Secret delivery = env vars only | credential leakage via history/`.env`-like stores; no cluster story | **High** | §4 (same decision as G1) |
| G8 Setup-window takeover | first-mover takes the CA on a shared LAN | **Medium** | require the displayed fingerprint as the setup POST's confirmation (it is already shown; turning it into a gate closes first-come takeover with no new surface) |
| G9 Error-text surfaces | fingerprinting/internal detail in 500/502 | **Medium** | generalize 500s + 502 envelope; keep 4xx specifics |
| G12/G13 Body limits + 429 shape | unbounded buffering; contract mismatch | **Medium / Low** | `DefaultBodyLimit` + JSON 429 |
| G5 Single-instance assumptions | restarts log users out; limiters reset (fail-open on poisoned locks) | **Medium → accepted for v1** with docs; poison paths to fail-*closed* instead (cheap) |
| G6 No HEALTHCHECK | blind orchestration recovery | **Low** | add to compose |
| G10 Zeroization minors | memory-resident key copies | **Low** | fix in the sweep of the same PRs |
| G11 Dead `webauthn_credential` column | confusion surface | **Low** | document as reserved or drop pre-1.0 |
| The `master.key`-beside-envelopes fact folds into G1; the JWT/files and live CT 242 facts fold into D. | | | |

## 4. [OWNER] The custody decision — once, designed

The recursion that every unattended system cannot avoid: a booting process
must get its keys from somewhere that no adversary-with-disk also holds; the
*anchor* must live outside the runtime. Removing the anchors this product has
rejected (human-per-boot, machine-bound TPM, plaintext file, open network)
leaves exactly three *simple* terminations. The owner picks the default; the
product supports tiers:

### Tier 1 — External KMS of record (recommended **production default**)
The master KEK lives in a dedicated key service — self-hosted Vault transit,
or a cloud KMS (AWS/GCP/Azure) for users who accept third-party trust.
Wardstone's code changes: a small, bounded client that, at boot,
authenticates (mTLS/static token held in one 0600 file the operator
provisions), fetches/wraps, and zeroizes — envelopes stay local.
- Unattended ✓ cluster-portable ✓ (any node with KMS reach) no-plaintext ✓
- Boundaries: KMS authn, envelope layer, network egress policy, audit.
- Complexity: one client, one config block; the KMS runs elsewhere.
- **My recommendation**: this is the only simple, standard, cluster-portable
  answer the constraints admit; every constraint-violating alternative we
  discussed was the complexity moving somewhere worse.

### Tier 2 — PKCS#11 / n-th HSM (CA-grade)
The signing key never leaves a network HSM (NetHSM class); Wardstone signs
through the device. Production-CA answer (this is how real CAs hold roots),
the strongest possible; adds an integration in ws-ca and requires hardware.
Unattended ✓ cluster ✓ (network-attached) no-plaintext ✓ — recommended as
the premium tier, not the default.

### Tier 0 — Operator-managed envelope (documented dev/quickstart tier)
Exactly today's behavior, but *documented as a tier with its boundary story*:
"one boundary: anyone with a copy of the keys volume owns the CA." The docs
stop implying more than that; the quick start stops teaching a password into
shell history and ships `.env.example` with the 0600 file pattern.

**DB credential dissolution (independent of tiers, one simple mechanism):**
the DB password stops existing at rest *anywhere* by becoming boot-rotated:
at every boot ws-api generates a fresh random credential in memory and
`ALTER`s the role (Postgres stores only its hash). The one-time bootstrap
secret is consumed at first init and deleted; `docker inspect` shows
nothing standing. The DB's HBA also carries the tenant-CA-bound
`clientcert=verify-full` option as the defense-in-depth tier. Boundaries:
identity-cert option + in-memory rotation + network isolation.

> **[OWNER]**: which custody tier is the standing default (1 / 2 / 0), and is
> boot-rotated DB credentials accepted?

## 5. Accepted risks (stated, not implied)

1. **Host-root on a node owns the instance.** Docker gives root-equivalent
   memory access; no runtime control defends against the operator's own
   platform. Mitigation lives OUTSIDE the product (host hardening, separate
   KMS custody, offline root ceremony) — the docs say so.
2. **Single-process v1**: restarts clear sessions/nonces/limiters (G5);
   docs state it; poison paths become fail-closed.
3. **In-memory keys while running**: any in-process attacker with memory read
   can use keys. This is the industry floor for software CA keys; Tier 2 is
   the answer when it matters.
4. **Setup-window trust** (G8) closes with the fingerprint gate; until then
   the window is stated in docs.
5. **The audit log is inside the same DB** as the data it attests (A10 vs
   A7): a DB-level writer can tamper history. Accepted for v1 with the
   one-KMS-boundary posture; the long-term answer (append-only/WORM export)
   is a roadmap item, not a v1 control.

## 6. Roadmap order that follows from the grades

1. **Small, standard, high-grade fixes first** (one PR each, TDD): G2 seal,
   G4 headers, G3 PKCE, G8 fingerprint gate, G6/G9/G12/G13/G10/G11 — the
   "basic overlooked risks" list shrinks to done.
2. **The custody decision implemented** per the [OWNER] answer (§4): the KMS
   client + boot-rotated DB credentials + `.env.example` + the honest tier
   docs.
3. **Whole-product scan** (the dedicated pipeline + adversarial judge) as the
   independent check over the result.

*A CA's root of trust may well deserve the CA-grade tier eventually; the
product earns it in the order above — every high-grade gap closed, custody
designed, then the independent audit.*