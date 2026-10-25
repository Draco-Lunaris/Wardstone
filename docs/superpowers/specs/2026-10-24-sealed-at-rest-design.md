# Design: Sealed-at-rest — the operator's key unlocks everything

Date: 2026-10-24 · Origin: the owner's design, developed in review of the
deploy docs (the DB password in plaintext during docker setup). The
problem statement **as ratified by the owner**:

> All sensitive material at rest is **inert ciphertext** until the operator
> unlocks the instance through the existing HTTPS front door. The unlock key
> exists nowhere on any disk. A sealed instance serves only the unlock
> surface.

Status: draft; the plan implements this alongside `2026-10-24-sealed-at-rest.md`
(same repository, includes the README.md updates).

---

## 1. The problem, stated in Wardstone's actual shape

Today the keys volume holds **plaintext root material** (`master.key`, the
SecretBox `secret-encryption.key`, the JWT key pair) beside everything they
open, and the compose contract puts the DB password into environment
variables whose copies land in shell history and in permanently stored
container configs. One copy of the volume is the whole CA.

After this design the volume holds only
**envelopes**: every sensitive file's bytes are ciphertext under a key that
is derived from the operator's **master passphrase** — which is entered
through the web UI over the existing TLS front door when the operator wants
the instance live, and never stored anywhere.

The model is deliberately the full-disk-encryption one, applied at the
application's seam instead of the block device: **an unlocked instance
possesses its keys in RAM; a sealed instance has nothing.**

## 2. What gets sealed (everything sensitive, per the owner's direction)

| Material | Today | After | Sealed as |
|---|---|---|---|
| CA keys + sub-CA keys + the setup-key slot | plaintext plaintext `master.key` beside XChaCha envelopes | one **KEK envelope** (the master key itself sealed) + the envelopes as-is | `master.envelope` — the wrapped KEK |
| SecretBox key (TOTP + OIDC secrets) | plaintext `secret-encryption.key` | sealed | `secret-encryption.envelope` |
| DB credential | `DATABASE_URL` plaintext password in env ×2 services + recorded container configs | the credential is **generated in memory at unlock, rotated per unlock/first-boot**, and persisted **only as an envelope** | `db-credential.envelope` |
| JWT signing PEM | plaintext file | sealed (**mint-at-unlock**: a fresh install never writes the plaintext pair — the first unlock mints straight into the envelope; re-key recovery is "delete `jwt-keys.envelope`", and the next unlock mints a fresh pair with every outstanding token invalid) | `jwt-keys.envelope` |
| OIDC client secret / TOTP secrets | sealed under SecretBox | unchanged mechanism; SecretBox's own key now comes from its envelope above | — |

Deliberately out of scope: the TLS **leaf/server certificates** (public
material — they must be servable pre-unlock to present the front door; only
their PRIVATE keys seal), and the host TLS/private material the listener
needs before unlock… see §4 (the listener uses a **self-issued "locked"
certificate** minted at first unlock: no CA keys online while sealed, and
an unambiguous visual state for the operator).

**After unlock, the TLS identity swaps IN-PROCESS.** The `serve_tls`
ArcSwap hot-reload path — present in the code and deliberately unused
until now — becomes load-bearing: at unlock (or at setup commit), the
process loads the CA-issued `web-server` leaf from the freshly opened
envelopes and swaps the listener's certificate without exiting. The
setup-era **self-exit restart contract is thereby REPLACED**: a restart
would re-seal the process by design, so `POST /setup {"restart": true}`
becomes `{"resume": true}` — the same in-process hand-off, with the docs
and the setup page updated to match. (The owner-facing change is stated
in the approval note rather than buried here: the restart-and-return flow
the guides describe today becomes unlock-and-continue.)
- The **`ws-worker` crate**: it has NO deployed entry point (absent from the
  binary's modes and from compose) — it is dormant code in every shipped
  shape, and sealing it is deferred until it actually ships. Stated here so
  "everything sensitive seals" remains truthful about what SHIPS.

## 3. The boot state machine

Both processes boot **sealed** unless the runtime already holds an unlocked
session (in-memory only; never written):

- **State derivation is keys-directory-only** (the sealed boot has no DB):
  `master.envelope` present → `Sealed`; absent with ANY legacy plaintext
  (`master.key` / `secret-encryption.key` / JWT PEMs) → `LegacyConversion`
  (the INIT page offers the one-time conversion — **per-file**, each
  present plaintext file wraps and deletes independently; a torn JWT pair
  is wrapped as-is with its loud torn-state error preserved post-unlock —
  conversion never heals what the loader refuses); absent and entirely
  clean → fresh run. The tenant-existence check moves to post-unlock
  routing (no DB at boot), so a legacy install with an existing tenant
  lands on the conversion page and then straight into service.
- **`Uninitialized`** (no KEK envelope exists; first run or fresh upgrade):
  the ui serves the **initialization page** over a self-issued locked-mode
  certificate: the operator sets the master passphrase (entered twice), the
  process derives the KEK (argon2id, memory-hard parameters), mints every
  sealed envelope — including the DB credentials bootstrap (below) — and
  proceeds to the existing setup wizard.
- **`Sealed`** (envelopes exist, runtime holds nothing): the ui serves the
  **unlock page** on the same listener; the api answers `503 sealed` on
  everything except the unlock handshake; compose healthchecks report
  live-but-sealed (see §6 — liveness stays 200 so the restart policy never
  churns a sealed instance).
- **`Unlocked`**: the operator submits the passphrase on the unlock page →
  the ui derives the KEK, unwraps its envelopes, **relays the unlock to the
  api** (§5), and both processes flip their guarded state to full service.
  The operator is then routed to the normal login.

Guards are **in-process state** (`Arc<RwLock<SealedState>>`): no restarts,
no router surgery — handlers that touch sealed material answer `503 sealed`
until the flip. The unlock key lives only in RAM; a process restart returns
the instance to `Sealed`.

## 4. The TLS front door while sealed

The listener must serve TLS *before* any CA material is unwrapped. It uses
the **setup certificate mechanism that already exists** (self-issued,
ECDSA P-256, minted at first unlock by the same `setup_certificate` path —
key wrapped with the KEK like everything else). An operator visiting a
sealed instance sees the already-familiar "proceed past the self-signed
certificate" step the setup page established; the lock page is visually
distinct — `<title>Wardstone — sealed</title>` — with a `GET /api-v1-sealed`
probe the SPA never confuses with a normal login failure.

## 5. The unlock handshake (the cross-process seam)

The browser POSTs `{passphrase}` to `POST /unlock` on the ui:

1. **GCRA**: the unlock route is a credential surface — per-IP rate limit
   with the house defaults, shared with the auth surface's budget. Wrong
   passphrases cost argon2 memory-hard compute **and** a bucket credit.
2. **Derive**: `kek = argon2id(passphrase, salt from the KEK envelope)`.
   A wrong passphrase fails the AEAD open silently (typed-error taxonomy —
   `wrong master key`, no user enumeration beyond that).
3. **Open locally**: the ui unwraps its envelopes (master, SecretBox, JWT).
4. **Relay to the api**: `POST /internal/unlock {passphrase}` over the
   compose-internal channel; the api performs the same derive/open,
   unwraps the DB credential, builds its pool, and flips its guard.
5. The internal hop carries the passphrase **once per unlock** over the
   compose-internal network — the same trust domain the API's own plaintext
   HTTP already occupies. Upgrading that hop to mTLS (the product can issue
   both processes' certificates) is listed as future hardening, not in this
   pass.
6. Rotation: at unlock, the api **rotates the DB credential** —
   unconditionally, every unlock (no env knob: the unlock cadence is
   operator-driven already, and each unlock retires any credential that
   leaked since the previous one — including the compose bootstrap, which
   the first unlock thereby retires as dead weight).
7. **Changing the master passphrase** (owner direction: rotation cadence
   is user-managed, on demand): an authenticated, capability-gated route
   accepts `{current, next}`. It verifies `current` by opening the master
   envelope under the present KEK, derives the new KEK from `next` with a
   fresh salt, and re-wraps **every** envelope (a crash-atomic sequence:
   each file atomic, the params file replaced last, and a **generation
   counter** per envelope so a partially-completed change is detected and
   its completion re-offered at the next unlock — the entry of `current`
   plus `next` again). Both generations stay openable during the mixed
   window by trying the entered passphrase against each envelope's own
   recorded salt; nothing becomes a silent public state. The route lives
   in the unlocked UI's admin section; wrong `current` = the house typed
   failure, no hint beyond that. Cadence: entirely the operator's.

**Failure postures** (all loud, house style): wrong passphrase → unlock
page re-renders with a typed error and no hint of *why* beyond that; KMS…
none — there is no external component; a broken envelope (corrupt) → boot
failure with the recovery hint; a half-written envelope mid-unlock → the
write path stays crash-atomic (tmp + fsync + rename, the keystore pattern).

## 6. Healthchecks and the restart policy

`/api/v1/healthz` and the ui's own `/healthz` (via the proxy? no — the ui
serves its OWN health endpoint in sealed mode) both return `200` with the
instance state **as a field** (`"state": "sealed"`) — **liveness is
unconditional**; the restart policy must never churn a sealed instance
(it is a correct state, not a crash). Readiness is surfaced separately in
the metric. The db container's healthcheck moves to `pg_isready`
(auth-independent), consistent with a rotated credential.

## 7. The upgrade path for existing installs

First boot after this deploys on an install with plaintext files: the
initialization page appears with a **one-time conversion** — the operator
sets the passphrase; the process wraps the existing plaintext files
(`master.key`, `secret-encryption.key`, the JWT pair) into envelopes,
generates/seals the new DB credential (`ALTER ROLE` from the
`DATABASE_URL`-provided connection), and **deletes the plaintext files**.
Existing volumes need no SQL migration (envelopes are files; the DB
password hash is postgres's own). `down`/`up` semantics and the backup
story are unchanged: **backups are now inert by construction** — restoring
without the passphrase yields an instance that boots to the locked page
and can do nothing (the docs state this as a feature, and name the
passphrase-loss consequence plainly: the instance is unrecoverable — root
and every identity re-issued or restored only from an offline backup pair
made while unlocked).

## 8. The env contract shrinks

`.env.example` ships:

- `WARDSTONE_SERVER_HOSTNAME` (unchanged),
- `WARDSTONE_KMS…` — **none**, there is no external component,
- `WARDSTONE_DB_PASSWORD` — **bootstrap only**: consumed once, at the
  bundled db's first init, and by the setup seeding path; never a standing
  credential (the rotation at first unlock retires it).

The compose `:?` requirements stay (the db container must init with
something), but the README now explains the credential's lifecycle
explicitly.

**`DATABASE_URL` in sealed mode is password-less** —
`postgres://wardstone@db:5432/wardstone` — and the api **substitutes the
envelope credential** into it at unlock (host/user/db remain env-defined);
a password-bearing URL on a sealed-mode boot fails loudly (mixed-mode
detection). **Migrations run at unlock** — the sealed boot has no database
connection by design, so `connect`'s migration step moves onto the
post-unlock path. **Seeding**: the ui INIT page consumes the bootstrap
(`WARDSTONE_DB_BOOTSTRAP_PASSWORD`, passed to the ui service ONLY — the
api never holds a bootstrap credential) to first-authenticate, `ALTER`,
and seal. **The recovery runbook** for a re-initialized db volume (the
envelope's rotated password now dead): stop the stack, delete
`db-credential.envelope` from the keys volume, set a fresh
`WARDSTONE_DB_PASSWORD`, boot — the unlock flow re-seeds through the
identical first-install path. The docs carry exactly this runbook.

- **Passphrase change**: the route requires `current` + `next`; wrong
  current is a typed failure; a completed change re-wraps every envelope
  and the NEXT unlock uses only the new passphrase; a simulated crash
  mid-change surfaces the incomplete-generation state at the next unlock
  and the completion flow works (DB-gated where envelopes touch files).

## 9. Tests (TDD; each red watched)

- KeyEnvelope: wrap/unwrap round trip under a derived KEK; wrong-passphrase
  failure is typed; crash-atomic writes preserved (the keystore pattern).
- Boot state machine: sealed ui serves ONLY the unlock/init page + 503 on
  the rest; the api serves 503 + the state field; the flip is in-process
  and immediate; a restart of the process re-seals.
- The unlock handshake: correct passphrase flips both processes (the
  loopback harness); wrong passphrase flips nothing; the GCRA limits the
  route; the api relay is exercised; unseal-after-relay covers the DB
  credential rotation (DB-gated).
- Healthchecks: liveness 200 while sealed; the state field flips; the db
  `pg_isready` contract.
- Sealed-mode listener: the locked certificate is served and the unlock
  page renders; the SPA fallback is NOT reachable while sealed.
- Upgrade conversion: a volume with plaintext files converts; the
  plaintext files are gone; the instance then boots sealed normally.
- README/docs: the quick start runs end-to-end on the documented commands
  (compose up → unlock/init → login), asserted by the docs task checklist.

## 10. Left to the builder

- Exact argon2id parameters (memory hardness vs the unlock latency budget —
  ~1 s per attempt is the target).
- The unlock page's exact copy/visual language.
- The relay endpoint's auth shape (the ui→api call must not be replayable
  by anything else on the internal network; a one-time nonce minted at the
  page render and bound to the GCRA bucket is the shape to pin).
- The DB seeding path when the compose db is not yet initialized (the
  `POSTGRES_PASSWORD` bootstraps initdb; the seeding `ALTER`s after).

## 11. The README.md and docker/README.md updates (plan Batch 0)

- The quick start gains the unlock step in sequence:
  `up -d` → open `https://<host>:8443/` → **set the master passphrase and
  the admin credentials in one flow** → the instance unlocks and restarts
  itself into service.
- The security section states the sealed model plainly: what is on the
  disks (ciphertext only), what the passphrase protects, what is NOT
  defended (host-root, a stolen passphrase), and the passphrase-loss
  reality (nothing is recoverable without it; the instance re-issues).
- The Operations section: the sealed state's healthcheck behavior, the
  rotate-on-unlock story, and the conversion runbook for pre-existing
  plaintext volumes.
- The env table: `WARDSTONE_DB_PASSWORD` re-typed as bootstrap-only.