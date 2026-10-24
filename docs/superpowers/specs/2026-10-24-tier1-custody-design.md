# Design: Tier 1 custody — an external KMS of record, boot-rotated DB credentials, and the honest tier docs

Date: 2026-10-24 · Companion to [`docs/security/threat-model.md`](../../security/threat-model.md)
§4 (the owner's decisions: **Tier 1 default, boot-rotated DB credentials
accepted**) and [`as-built-inventory.md`](../../security/as-built-inventory.md)
(gap G1 = Critical: the plaintext master KEK beside everything it opens).
Status: **draft for owner approval**.

---

## 1. Intent — what "sealed" must mean after this

Today the keys volume holds **two plaintext root secrets** (`master.key` and
`secret-encryption.key`) beside every byte they protect. One copy of the
volume is the whole CA. After this design:

1. The keys volume holds **no plaintext CA-custody key material** — the
   master KEK, the SecretBox key, and every envelope they open live behind
   the custody provider. The ONE deliberate plaintext exception is the JWT
   session key pair: it is re-keyable at operator discretion with a cost
   of "every session logs out" (its documented recovery is deletion, not
   custody), so it stays a plaintext file — the docs state the exception
   and its reasoning instead of claiming more than is true.
2. **Tier 1** (the recommended production default): the custody provider is
   an **external KMS of record** — the reference implementation is
   **Vault transit** (self-hosted, homelab-realistic, network-uniform for
   clusters). Cloud KMS (AWS/GCP/Azure) is the same trait with another
   client — supported later, not in this pass.
3. **Tier 0** (dev/quickstart, retained and documented honestly): the
   local-file provider — exactly today's behavior, boundary story stated in
   the docs ("anyone with a copy of the keys volume owns the CA").
4. **The DB credential stops existing at rest** in any deployable tier: it
   is generated in memory at boot, rotated via `ALTER ROLE`, and persisted
   only as an **envelope** (Tier 0: under the file master; Tier 1: under
   the KMS). The one-time `POSTGRES_PASSWORD` bootstrap is consumed at
   first init and is thereafter irrelevant.

### The owner constraints this design must honor
(threat-model §4; verbatim): unattended boot; cluster/redreploy portability
(no machine-binding); no plaintext at rest; multiple independent
boundaries; and a complexity budget — no k-of-n fabric, no peer protocols.

## 2. Goals

1. A **key-custody provider abstraction** in `ws-ca`: the keystore's
   DEK-wrap/unwrap and the SecretBox key's protection route through it.
2. **Tier 1 provider: Vault transit** — the KEK never materializes in the
   wardstone process at all: the provider sends the DEK bytes to the
   transit endpoint for encrypt/decrypt. (The master never lives in RAM
   even — strictly stronger than "no plaintext at rest".)
3. **Tier 0 provider: the local file** — today's plaintext `master.key`
   path, byte-for-byte compatible (existing installs keep working with
   zero migration).
4. **Boot-rotated DB credential** per tier.
5. **`.env.example`** and the tier docs (the honest boundary story per
   tier, including "Tier 0 = one copy of the volume owns the CA").

## 3. Non-goals

- No PKCS#11/HSM (Tier 2 remains future; the trait is its seam).
- No cloud-KMS client in this pass (the trait anticipates it).
- No k-of-n/threshold machinery, no peer fabric.
- No schema migration for credentials (everything stays on the keys
  volume / DB as-is; the DB password columns are none — rotation is
  runtime-only).
- No Vault beyond transit (no KV storage of wardstone keys outside the
  instance: recovery stays an operator duty with the TWO volumes).

## 4. The design

### 4.1 The custody provider trait (`ws-ca`)

```rust
/// Master-key custody: WHERE does the CA engine's wrapping key come from,
/// and (for remote providers) can the plaintext ever exist in this
/// process at all?
pub trait MasterKeyProvider: Send + Sync {
    /// Wrap (encrypt) a 32-byte DEK. Local impls do the AEAD here;
    /// remote impls round-trip the bytes and return the KMS ciphertext.
    fn wrap_dek(&self, dek: &[u8; 32]) -> Result<WrappedDek, CaError>;
    /// Unwrap a WrappedDek produced by THIS provider's wrap.
    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Zeroizing<[u8; 32]>, CaError>;
    /// The provider's stable name (audit + envelope versioning).
    fn id(&self) -> &'static str;
}
```

- `WrappedDek` = provider-tagged ciphertext (+ provider `id`, KMS key
  name) — a **v2 envelope field**. Envelope v1 files (`key_type:
  "xchacha20poly1305"`, DEK wrapped under the file master) stay readable:
  the local provider is the v1 reader; a v2 envelope names its provider.
- **Tier 0 impl**: `FileMasterProvider` — reads `master.key` (0600),
  wraps/unwraps exactly today's XChaCha20 envelope in-process. Byte
  behavior identical to main today (all existing volumes open untouched).
- **Tier 1 impl**: `VaultTransitProvider` — config: `WARDSTONE_KMS_URL`
  (the transit base, e.g. `https://vault.internal:8200`),
  `WARDSTONE_KMS_KEY_NAME`, `WARDSTONE_KMS_TOKEN_FILE` (0600 token file,
  on the keys volume or operator-supplied). `wrap_dek` POSTs
  `/v1/transit/encrypt/{key}` (plaintext = base64(DEK)), `unwrap_dek`
  POSTs `/v1/transit/decrypt/{key}`; the KEK never enters the process.
  Vault's transit endpoint is bounded (key never exported; audit inside
  Vault). Token lifetime contract: on any 401/403 the client re-reads
  `WARDSTONE_KMS_TOKEN_FILE` ONCE and retries — the operator's renewal
  action is rotating that file (a long-TTL token or operator-managed
  rotation; AppRole and periodic re-auth are out of the complexity
  budget). A SECOND consecutive failure is the hard failure of §4.5.
- Construction lives in the binary boot: provider chosen by env
  (`WARDSTONE_KMS_URL` present ⇒ Tier 1; else Tier 0 with a logged
  boundary warning).

### 4.2 The SecretBox key, sealed

`secret-encryption.key` (the TOTP/OIDC SecretBox seal key — the other
plaintext root secret) becomes **`secret-encryption.envelope`**: the 32
bytes wrapped by the SAME provider. The runtime unwraps it per the
boot-rotation flow: SecretBox's per-request seal/open keeps working on the
unwrapped in-memory key (unwrapped once at boot, Zeroizing). Tier 0's
envelope wraps under the file master — matching today's single boundary,
documented as such; Tier 1's wraps under the KMS. The legacy plaintext
file stays a **readable fallback only for upgrade installs** (loaded once,
rewrapped, plaintext deleted — a boot-time lazy migration mirroring the
OIDC reseal).

### 4.3 Boot-rotated DB credentials

- New keys-volume file `db-credential.envelope` (wrapped by the provider).
- **Setup/first-boot** (human present, exactly once): seeding belongs to
  the ui — the only process alive while no tenant exists. Before the
  bootstrap commits, if `db-credential.envelope` is absent, the ui
  generates 32 random bytes, connects with the bootstrap credential
  (`WARDSTONE_DB_PASSWORD`, the compose `:?` var — its only consumer
  after the db container's own init), `ALTER ROLE wardstone PASSWORD
  '<random>'`, writes the envelope, stores NOTHING else. An api booting
  into a not-yet-seeded install falls back to READ-ONLY unwrap
  (if-else): envelope present → unwrap; absent → hard failure naming the
  missing envelope and the ui's seeding duty — the bootstrap password is
  never a standing api credential in Tier 1 (no silent fallback). The compose `.env`
  `WARDSTONE_DB_PASSWORD` thereby becomes a **bootstrap-only** value the
  operator may rotate-delete after setup (docs say so).
- **Every boot, and only in the `api` process**: `wardstone api` is the
  SOLE rotator. The `ui` process never rotates — its boot unwraps the
  credential read-only (two processes re-writing the DB credential at
  once would leave the loser holding a password that a concurrent
  rotation had just killed). The rotation runs under a new WARDST-family
  advisory lock (`0x0057_4144_5354_0016`) with the envelope RE-READ under
  the lock, so an api restart overlapping a redeploy cannot double-rotate:
  the winner's state is the loser's input. With
  `WARDSTONE_DB_ROTATE_ON_BOOT` set: unwrap the current credential,
  connect, generate a fresh in-memory password, `ALTER ROLE`, re-wrap,
  rewrite the envelope, continue. A stolen DB credential therefore dies
  at the next api restart even if the envelope leaked. The `ui`'s
  credential handling is unwrap-only and rotation-idempotent (it re-reads
  the envelope whenever its pool re-authenticates).
- `DATABASE_URL` semantics: Tier 0 keeps today's embedded-password URL
  (with the boot envelope taking precedence when present — the rotation
  flow owns the password from then on). Tier 1: `DATABASE_URL` MUST be
  password-less (`postgres://wardstone@db:5432/wardstone`) — a password in
  a Tier-1 URL fails the boot loudly (mixed-tier detection).
- Connection construction moves to a small `DbCredential` resolver in
  ws-core: env-or-envelope, with the two-tier rules in one place.

### 4.4 What the env contract becomes

| Variable | Tier | Meaning |
|---|---|---|
| `WARDSTONE_KMS_URL` | 1 | Vault base URL (transit namespace included) |
| `WARDSTONE_KMS_KEY_NAME` | 1 | The transit key name wardstone may use |
| `WARDSTONE_KMS_TOKEN_FILE` | 1 | 0600 Vault token file — REQUIRED, operator-provisioned **outside the keys volume** (no default path; see §5) |
| `WARDSTONE_KMS_CA_FILE` | 1 | optional PEM CA bundle for the KMS connection (self-hosted Vault usually serves from a private CA); default = system roots. `insecure-skip-verify` is deliberately ABSENT |
| `WARDSTONE_DB_ROTATE_ON_BOOT` | both, default **off** | the api's boot rotation; the Tier-1 bundled fragment sets it `true` explicitly; External-variant DBs opt in only once the role holds `ALTER` rights — a failing `ALTER` is a hard boot failure, so the docs make the grant a prerequisite |
| `DATABASE_URL` | 0 | today's URL (password embedded); Tier 1 forbids the password |
| `WARDSTONE_DB_PASSWORD` | compose/bootstrap | the one-time bundled-Postgres init password |
| `WARDSTONE_KEYS_DIR` | both | unchanged |

`.env.example` ships with these, commented per tier.

### 4.5 Failure postures (all loud, per the house habit)

- Tier 1 boot with an unreachable/unauthenticated KMS: hard boot failure
  naming the provider, the endpoint, and the HTTP verdict.
- Envelope provider mismatch (v1 file on a Tier 1 boot): hard failure with
  the upgrade hint (`seal-to-vault` below).
- An unwrap failure: `WrongKey`/`Corrupt` as today.
- DB rotation failure (cannot reach postgres WITH the unsealed credential):
  hard failure (the process cannot serve without DB anyway) — the rotation
  happens BEFORE the router mounts, consistent with the JWT-keys boot step.

### 4.6 The upgrade path (one-way, documented)

`wardstone keys seal-to-provider` (a CLI subcommand, Tier 0 volume →
whatever provider the env names): re-wraps every envelope + both keys
file + writes the DB credential envelope, deletes the plaintext files
(`master.key`, `secret-encryption.key`) — the operator's Tier 0 → Tier 1
upgrade is one command against a stopped instance (the CLI verifies the
store is not in use; both processes must be stopped). Reversibility =
restore from a Tier 0 backup; documented as such.

### 4.7 Tests (TDD throughout)

- Provider trait: Tier 0 wrap/unwrap round-trips v1 files byte-compatibly
  (existing keystore tests keep passing untouched).
- Tier 1: a loopback "vault" fixture (the house's spawn_server pattern)
  asserting the transit wire shapes (encrypt/decrypt round trip, the key
  name in the path, the token header) and failure shapes (403, 503).
- SecretBox envelope: unwrap-at-boot + legacy-plaintext lazy rewrap test.
- DB rotation: DB-gated — connect with a bootstrap password, rotate twice,
  prove the old password stops connecting and the envelope matches the
  new one.
- Tier rules: a Tier-1 `DATABASE_URL` with a password fails the boot
  loudly.
- `seal-to-provider`: round-trip a fixture volume, assert every plaintext
  file's absence afterward.

### 4.8 Docs

- `docker/README.md`: the tier section (both tiers' boundary stories told
  plainly, including Vault-side requirements: a transit key with export
  DISABLED, a policy allowing exactly encrypt/decrypt on that key, token
  TTL guidance) + the `seal-to-provider` upgrade runbook.
- `README.md`: the custody paragraph goes tier-aware.
- `.env.example` at the repo root (commented per tier).
- `docker/compose.tier1.yml` — an OVERRIDE FRAGMENT, not a second bundle:
  password-less `DATABASE_URL`, the KMS env block, `ROTATE_ON_BOOT=true`.
  The bundled `db` healthcheck switches to `pg_isready` (auth-independent
  — a rotated credential would otherwise fail the old `PGPASSWORD=`
  healthcheck and churn restarts). The default compose stays Tier-0
  shaped for the quickstart; the README's Tier 1 runbook composes with
  `-f docker/compose.yml -f docker/compose.tier1.yml`.

## 5. The boundary ledger after this design

| Tier | Boundaries between an attacker and A1 (CA keys) |
|---|---|
| 0 | keys-volume copy (ONE) |
| 1 | the KMS (policy + authn + network egress), the envelope files, the token TTL — **and** the operator-provisioned token living OUTSIDE the keys volume: a keys-volume copy alone is inert (decryption requires the KMS, and the credential to reach it is not on that volume). Cluster-portable: any node with KMS reach + the envelopes + the token is an instance |
| 2 (future) | hardware residency of the signing key itself |

The residual risk stated for Tier 1: the deployer's Vault deployment and
its token custody are in the trust chain; the token file is a real secret
(policy-scoped, TTL-managed) — the docs say to keep it off backups of the
keys volume.

## 6. Left to the builder

- The exact envelope v2 JSON shape (provider id, KMS ciphertext fields) and
  the v1-compat reading table.
- Vault request details (base64url shapes, key-version handling, lease
  headers) against the pinned reqwest stack.
- The `DbCredential` resolver's precise env precedence table.
- Test fixtures per §4.7.

## 7. [OWNER] points this spec already assumes from the threat model

- Tier 1 = the standing default; Tier 0 documented dev tier (stated, not
  implied); Tier 2 future.
- Boot-rotated DB credentials: accepted.
- Vault transit as the Tier-1 reference implementation (self-hosted): if
  the owner wants a DIFFERENT KMS of record (e.g. OpenBao-compatible or
  cloud-first), say so now — the trait anticipates it, but this pass
  builds and tests the one.