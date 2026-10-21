# Wardstone Plan 2 — API, Auth, and Certificate Profiles — Design Document

**Status:** Draft for owner review. Not yet approved.

**Date:** 2026-10-21

**Companion documents:**
- [Wardstone — Design Document](2026-10-20-wardstone-ca-design.md) — the product design this
  implements. This document refines it where Plan 2 needs specifics; where the two
  disagree, this document records the change and why.
- [Plan 2 brainstorming record](../plans/2026-10-21-wardstone-plan-2-brainstorm.md) — the
  26 settled decisions and the reasoning behind each, with the builder-check corrections.
- [Plan 1 implementation plan](../plans/2026-10-20-wardstone-plan-1-core-ca.md) — the
  completed core-CA build this extends.

**Builds on:** Plan 1, merged to `main` at `e507e46` with the OpenSSL interop fixes
`fa3af0c` and `5740eb5`. Plan 1 delivered the CA engine (CA forest, leaf issuance,
encrypted keystore, CRL, OCSP, audit log, publishing worker, tenant-scoped schema) with
**no front door** — `ws-api`, `ws-web`, and `ws-auth` are empty stubs.

---

## Intent and Why

Plan 1 built a certificate authority that nobody can use without writing Rust. Plan 2
gives it a front door, and gives that front door a **trust boundary** that is designed
rather than retrofitted.

The reason this plan is the API and auth rather than the UI: Plan 1 shipped a lot of
security-relevant surface that nothing exercises, and **the API is where "who may issue
a certificate" gets decided**. Designing that before the UI avoids designing it twice.
It also makes Plan 2 independently useful — with durable API tokens for scripting, a
home labber can drive Wardstone with no UI at all.

**This plan also introduces the first-run setup**, because a CA with no way to create
its first CA is not a product. See [Setup](#setup) — the design there is materially
different from what the product spec assumed.

---

## Scope

**In scope:**

- `ws-auth` — users, sessions, TOTP MFA, RBAC as capability bundles, service identities.
- `ws-api` — the REST API over `/api/v1/`: certificates (including the token-gated
  one-shot issuance endpoint), CAs, profiles, audit, users, service identities,
  one-shot tokens, tenants, the root-trust download, and health.
- `ws-web` — the TLS front door: a path-proxy to `ws-api`, and the **first-run setup
  page** (the only UI in this plan).
- The **first-run setup** flow end to end, including the bootstrap TLS window.
- Certificate **profiles** as constraints, with append-only revisions.
- The audit **write-side contract** for every mutating API operation.
- The `docker/compose.dev.yml` companion: a **production compose bundle**.

**The one-shot issuance endpoint is in scope.** The step-ca-style flow — a target host
submits its own CSR against a single-use token — is an API endpoint, and the design
work around it (the `one_shot_tokens` table, the `one_shot_token` actor type, the
`one_shot` auth method) has no consumer without it. The *UI* for that flow is not in
scope, but the endpoint is.

**Out of scope (later plans):** the full web UI (dashboard, certificates browser, ACME
pages, users, alerts, settings, root-trust page); the ACME server; expiry monitoring and
alerting.

**The root-trust download IS in scope as an API endpoint** (it serves the CA's
certificate, not its key), gated by `read_cas`. The root-trust *page* is not.

**Two scoping calls, stated plainly for the owner to overrule:**

1. **The full house auth surface is in scope** — JWT + refresh tokens, argon2id password
   hashing, TOTP MFA, OIDC SSO, RBAC, and account lockout. The product spec commits to
   "auth should be like LHFM/LPM," and the house OIDC is generic (Keycloak/Azure/custom
   per `linux-patch-manager/migrations/014_oidc_provider.sql`), not Azure-locked — so it ports
   cleanly. Deferring SSO would ship a CA whose only authentication is a password.
2. **The production compose bundle is in scope.** Without it, the setup flow's TLS
   window cannot be demonstrated end to end, and "docker compose only" is the product
   spec's deployment commitment.

---

## Certificates and Profiles

### A profile IS the certificate's specification

A profile is **not** a template and **not** a ceiling to negotiate against. It is the
complete, exact statement of what a certificate issued under it may be. A request
proposes only the subject and the names.

| Dimension | Set by | Request may |
|---|---|---|
| SAN names | profile's pattern list (permitted set) | propose concrete names, each of which must match |
| Subject CN | profile's pattern list | propose it; it must match a pattern |
| Key algorithm | profile | not requestable |
| Key usages | profile (exact) | not requestable |
| Extended key usage | profile (exact) | not requestable |
| Lifetime | profile (exact span) | not requestable |

If you want a shorter lifetime, you create a different profile. A profile is therefore
a *complete specification*, and two profiles differing only in key type are genuinely
different artifacts with different key usages.

**What "lifetime" means, exactly.** A profile's lifetime is the certificate's **span**,
`not_after − not_before`. Plan 1 deliberately sets `not_before` to midnight UTC *one
day before* today as a clock-skew margin (`issue.rs:518-527`), so a certificate issued
today with a 30-day span expires 30 days after *yesterday's* midnight — 29 days of
remaining life. That margin is valuable (a client whose clock is slightly behind must
still accept the certificate), so it is **kept**. The profile's number is the span,
which is exact; the certificate simply starts a day early. The built-in profiles'
"30 days" therefore means a 30-day span, and the UI says so.

**The silent clamp becomes a refusal.** Plan 1 currently shortens a leaf's `not_after`
to the issuing CA's `notAfter` *silently* (`issue.rs:419-423`) — the caller is told
nothing, and the resulting certificate does not match its profile, which the exact
model forbids. This plan changes that: `sign_leaf_with` **refuses** with a typed error
instead of clamping, and the API pre-checks the same condition so the failure is
explained rather than merely reported. (A certificate that does not match its profile
is a policy violation; a silently shortened one is worse than a refusal, because
neither the caller nor the auditor can see it happened.)

**Consequences of the exact model:**

- There is no "is this requested usage in the profile's list" check to get subtly
  wrong. The profile's values are what the certificate gets.
- **Empty EKU and key-usage lists are illegal.** An absent extension is *more*
  permissive than `serverAuth` (RFC 5280 §4.2.1.3: absent = unrestricted), so a profile
  with an empty list would be a universal issuer. The profile validator forbids empty
  lists, and `sign_leaf_with` refuses them too. **This requires a change to Plan 1's
  engine** — `LeafSpec` has no EKU field today and `sign_leaf_with` never sets
  `params.extended_key_usages`.
- A profile is written for a key type: an ECDSA profile carries `digitalSignature`
  only; an RSA profile carries `digitalSignature` + `keyEncipherment`.

### Pattern list

A profile holds **one editable list** of patterns. Syntax distinguishes the types:

1. If the pattern parses as an **IP literal** → an IP pattern.
2. Else if it contains `/` → a **CIDR** pattern.
3. Else → a **DNS name** pattern.

*(The IP-literal check must come first: `10.0.0.5` contains neither `/` nor `:`, so a
naive "contains `/` or `:`" rule would misclassify a bare IPv4 address as a DNS name
and it could never match an IP SAN.)*

**Matching semantics:**

- Case-insensitive (DNS is).
- A DNS pattern matches **exactly** that name. `example.com` does not match
  `sub.example.com`.
- `*.example.com` matches any **single** additional label or more — `a.example.com`
  and `a.b.example.com` both match — but **not** `example.com` itself.
- A CIDR pattern matches any IP within the range.
- A bare `*` matches **any DNS name** (not IP SANs — an IP needs an explicit IP or CIDR
  pattern, or `0.0.0.0/0`).
- Every proposed name must match at least one pattern. Proposing **no** names is a
  different artifact, not a subset, and is rejected.

**Wildcards** need no separate "wildcards allowed" switch: a wildcard is permitted
iff the list contains a `*.` pattern. A separate switch would allow the contradictory
states ("wildcards: yes" with no wildcard patterns; "wildcards: no" with one present).

**The list is editable and extensible at any time.** A profile's pattern list is
edited in place (as a new revision, per below) whenever the operator needs to add a
name, a wildcard, a subnet, or a new domain — which is the common case, because real
homelabs grow: a new Kubernetes service, a new subnet, a split-horizon name pointing
at an internal host. **Nothing about the setup-time scoping is permanent**; the
bootstrap merely seeds a closed, sensible starting set.

### Revisions are append-only

An edit **inserts a new row** into `profile_revisions` (profile id, revision number, the
full constraint set, created_at, actor). The `profiles` row is the identity and points
at the current revision. A certificate records the **revision** it was issued under, and
that revision's constraint set is always retrievable.

**Why:** a CA's value proposition is being able to prove what it did and why. A profile
revision *is* the policy record — the thing a certificate was checked against. The
auditor's question is "what did the policy allow when this cert was issued?", and the
answer must be a lookup, not an inference from a counter and a jsonb blob.

**Cost, and it is bounded:** an edit is an insert; profiles are edited rarely, not per
issuance.

**Concurrency:** issuance reads the current revision and validates against it; the
insert carries the revision it validated against. A concurrent edit makes the write
fail its revision check, and the issuance **retries against the new revision**. This is
*strictly correct* rather than merely serialized — the certificate records the revision
it was actually validated against, whatever happened concurrently. (The detecting
conditional update does take a row lock, so the "no lock on the hot path" property holds
only partly; correctness is the reason to prefer it.)

### Built-in default profiles

The bootstrap creates the tenant's default profiles. They **cannot** be seeded by a
migration — the default tenant is created by setup at runtime, so no migration can
attach a tenant-scoped built-in to a tenant that does not exist yet (it would be an FK
failure, not a `connect()` refusal). Setup code creates them.

Two are created, differing only in key type (which is what the exact model makes
meaningful):

| Name | Key type | Key usages | EKU | Lifetime | SAN patterns |
|---|---|---|---|---|---|
| `web-server` | RSA-2048 | digitalSignature, keyEncipherment | serverAuth | 30 days | the setup domain, `*.domain`, the admin's IPs/CIDRs |
| `web-server-ecdsa` | ECDSA P-256 | digitalSignature | serverAuth | 30 days | the same |

The **SAN pattern list is bootstrap-scoped** (D3): the setup collects the operator's
domain and admin CIDRs, and the default profiles permit exactly those. This is
"closed but guided" — the same shape the product spec already chose for ACME CIDRs.

**Key type default is RSA-2048**, for two independent reasons: certbot's default key
type is RSA 2048, and WebCrypto does not implement Ed25519, so a browser-based CSR
generator could not produce one. (The *CA's* own key default is Ed25519 per the product
spec; the divergence is intentional and is documented, so it does not read as an
inconsistency.)

**The default set is meant to be easy, and improvable for production use** — an operator
who wants Ed25519, P-256, a different lifetime, or a different EKU creates profiles
with those values. The built-ins are not a constraint on the system.

**Per-tenant seeding:** a second tenant, which the product spec allows an admin to
create later, gets the same built-ins from the same tenant-creation path. So tenant
creation is in scope for this plan.

---

## Access Control

### Three roles, expressed as capability bundles

| Role | Capabilities |
|---|---|
| `admin` | **all** capabilities in the authoritative list below |
| `issuer` | `issue`, `read_certificates`, `read_cas`, `read_profiles` |
| `viewer` (compliance auditor) | `read_certificates`, `read_cas`, `read_profiles`, `read_audit` |

**Three roles, per the owner's model:** a full admin who can manage all system
config, a certificate-issuer level, and a compliance-auditor level. (An earlier draft
of the brainstorming record proposed a fourth `profile_mgr` role; it is folded into
`admin` here, and the issue/manage_profiles separation survives in the **capability**
model, where it still matters — see below.)

Capability set (the authoritative list):

`issue`, `generate_leaf_key`, `manage_profiles`, `manage_cas`, `manage_users`,
`manage_api_tokens`, `manage_one_shot_tokens`, `export_ca_keys`, `manage_system`,
`read_certificates`, `read_cas`, `read_profiles`, `read_audit`, `read_users`,
`read_service_identities`

**What each capability gates** (so none is a name without a meaning):

| Capability | Gates |
|---|---|
| `issue` | issuing a certificate against a profile (CSR path), **and revoking a certificate** |
| `generate_leaf_key` | the admin-only server-key-generation endpoint |
| `manage_profiles` | creating, editing (new revision), and deleting profiles |
| `manage_cas` | creating and managing CAs below the root |
| `manage_users` | creating, editing, and deactivating users; assigning roles |
| `manage_api_tokens` | creating, listing, and revoking **service identities** (API tokens) |
| `manage_one_shot_tokens` | minting and revoking one-shot tokens |
| `export_ca_keys` | exporting a CA's private key (backup) |
| `manage_system` | instance-level configuration: tenants, OIDC config, rate limits, the setup surface |
| `read_certificates` | reading the certificate list and individual certificates |
| `read_cas` | reading the CA list and CA details |
| `read_profiles` | reading profiles and their revisions |
| `read_audit` | reading and exporting the audit trail |
| `read_users` | reading the user list |
| `read_service_identities` | reading service identities |

**Roles are named bundles of capabilities; every endpoint checks a *capability*, not a
role.** Adding a role or a capability later touches one table, not every check in the
codebase. The house pattern is a flat enum with `is_admin()`/`can_write()`
(`pm-auth/src/rbac.rs`); Wardstone's certificate permissions are finer than
write/read, so the shape is extended.

**The table is read at request time.** A session carries only the user's role;
resolving a user's capabilities reads `role_capabilities`. The `role_capabilities()`
function is the **seed source** — the one place a bundle is defined — and
`seed_role_capabilities()` writes it idempotently. The Rust function is not the
runtime authority; the table is.

**The mapping lives in a table** (`role_capabilities`), not an enum column, because
per-token capability storage is required anyway and one storage model keeps the
concept in one place. A user's capabilities are those of their role; **a user cannot
hold capabilities beyond their role's bundle** in this plan. Service identities and
one-shot tokens store their capabilities the same way — in a table
(`service_identity_capabilities`, `one_shot_token_capabilities`) — so that the
"subset of the delegator" rule is enforceable at the storage layer rather than by
convention.

**`generate_leaf_key`, `manage_api_tokens`, `manage_one_shot_tokens`,
`export_ca_keys`, and `manage_system` are admin-only.** `generate_leaf_key` because
it is a strictly more powerful operation than `issue` (see
[Private key material](#private-key-material)); `export_ca_keys` because it releases
a CA's private key; the rest because they create actors or change instance-wide
behaviour.

**Note on the issue/manage_profiles separation:** with three roles, `admin` is the
only *human* holder of `manage_profiles` — so the two certificate permissions do not
split across human roles. They still split meaningfully at the **credential** level:
a service identity or one-shot token can be granted `issue` without
`manage_profiles`, and the API token's capabilities are chosen explicitly at creation
and can only be a subset of what the creating identity may delegate.

**Checks live in the handler**, not in a route layer — the house pattern already puts
`AuthUser` in the handler signature and checks `is_admin()` inside it, and a check in
the handler is *auditable* (a reviewer sees it two lines below the signature, rather
than having to trace the router). The weakness of this choice — a check can be
forgotten — is met by the convention that every mutating handler checks first, plus a
test enumerating the capability each route requires.

### Three authentication methods, one actor type

| Method | Who | Shape |
|---|---|---|
| **User session** | humans | JWT + refresh tokens, argon2id, TOTP MFA, OIDC SSO, lockout — the house pattern |
| **One-shot token** | the token-gated pull flow | single-use, expiring, no refresh, no session |
| **API token** | scripts and automation | long-lived bearer credential, stored hashed, revocable, scoped |

The one-shot flow is **not** a user session: a machine presents a bearer token once to
get one artifact. It is not bolted onto the session system.

**All three resolve to one `AuthActor` type**, carrying `capabilities`, `actor_type`,
`actor_id`, `auth_method`, and the session identity. Consequences: the capability
check is uniform across all three; the audit write is uniform, one code path, so
`actor_type` and `auth_method` are fields of the same type rather than special cases
at each call site; and the three methods differ in exactly one place — **how the actor
was resolved**.

**Where the type lives: `ws-core`.** The vocabulary — `Capability`, `Role`,
`ActorType`, `AuthMethod`, and the actor itself — is defined in `ws-core` (which
owns the schema and the repositories that store these values) and **re-exported by
`ws-auth`**. The alternative — defining them in `ws-auth` and having `ws-core` use
them — makes `ws-core → ws-auth` while `ws-auth → ws-core`, a Cargo cycle that does
not build. The spec's "the one `ActorType` enum in `ws-core/src/models/audit.rs`" is
honoured: the definition moves to `ws-core/src/models/rbac.rs` and `models/audit.rs`
re-exports it, so the audit row and the actor can never disagree.

### API tokens are first-class service identities

An API token is its own actor with its own capabilities, its own name and description
("terraform-deployer", "ansible-runner"), and its own row in the audit trail — **not** a
credential hanging off a person.

This mirrors the ACME actor model the product spec already commits to: "ACME accounts
are first-class service identities owned by a tenant — not UI users." A durable API
token is exactly that shape, and composing with the spec's model beats duplicating it.

**Why it decided it:** audit fidelity. An auditor asking "was this human-driven or
automated?" needs the answer *in the row*. A token tied to a user would write
`actor_type='user'` for both a click and a script, muddling "who is responsible" with
"what credential acted."

**A service identity is tied to a creator** (one nullable FK to the creating user) for
accountability — "who made this script identity" — while remaining its own actor in the
audit trail.

**A token's capabilities are chosen explicitly at creation** and can only be a subset
of what the creating identity may delegate — never more. Since only an admin can mint
a token, and an admin holds every capability, the rule is stated as the general
property it is: a token can never carry a capability its creator lacks.

**Token hashing:** the house's `refresh_tokens` precedent is **SHA-256, not Argon2id**
(`pm-auth/src/refresh.rs:11,46,100,153` — the migration's comment claiming Argon2id
is wrong). For a high-entropy random token, a KDF's deliberate slowness buys nothing —
SHA-256 of a 256-bit random token is the standard practice, and the token is not
guessable. **Ruling: SHA-256**, matching the house precedent. (Argon2id remains correct
for *passwords*, which are low-entropy and human-chosen.)

### The one-shot token's identity

A one-shot token is a bearer capability with **no user identity** — that is what makes
it one-shot. But something must authorise the CSR submission, and the audit trail must
say what.

**Ruling:** `actor_type` gains a `one_shot_token` value. The audit row records
`actor_type='one_shot_token'`, `actor_id` = the token's id, and in `details` the
**human who minted it** (so accountability is preserved without the token pretending
to be a person). The token is created by an admin holding
`manage_one_shot_tokens`, carries the `issue` capability, is stored hashed (SHA-256,
same as API tokens), and expires. It carries **no profile scope** — there are no
profile ACLs in v1 (see [Error contract](#error-contract)).

---

## Private key material

### The boundary

> The API never **stores** leaf private key material. The normal issuance path never
> **has** it. An admin-only endpoint may **generate** a leaf key, use it to sign, and
> return it once — never persisted. CA private keys are **exportable** for backup, and
> the server **retains** its copy.

**Why the normal path never has it:** for a leaf certificate the CA never needs the
leaf's private key. The CA's own key signs the certificate; the leaf's key is only
needed by whoever uses the certificate. So a client-generated CSR is signed against a
key the server never possesses.

**Why server-generated leaf keys are never persisted:** "handed out once and only once"
then stops being a rule the server must enforce and becomes a **structural fact** —
there is no second copy because there is no first copy. There is no key store to
protect, no copy to leak, and no re-export path. If the admin loses it, they re-issue,
which is the same contract as a lost API token.

**The capability split is meaningful, not cosmetic:** the non-admin `issue` path is one
where the server *provably* cannot leak a key, because it never had one.

### Never logged — three concrete obligations

Not intentions. Requirements:

1. The API's request/response logging **redacts** the key-bearing field. No access log
   line may contain key material.
2. Audit `details` carries ids and labels only (the schema already says "never key
   material"). The delivery gets its own action (`key_generated`) recording *that* a
   key was delivered, never the key.
3. Serialization or transport failure must **not** echo the body into an error
   message, and the response must not be cached.

### CA key export

Exportable for backup; the server keeps its copy. **Export is not a move.**

The exception, named explicitly: a root that only issues certificates to sub-CAs can
be genuinely taken offline, because the root CA server itself then has nothing left to
sign. In that specific case, making the whole CA offline is safer than merely exporting
its private key. The trade-off is that such a root cannot then be revoked by the system
that holds it — the revocation story for an offline root is trust-anchor removal, which
the product spec already covers with the root-trust page.

**The offline-root flow is not in this plan**; the export capability is.

---

## Audit

### The write-side contract

Every mutating API operation writes **exactly one** audit entry, **in the same
transaction** as the mutation. If the mutation commits, the entry exists; if the entry
fails, the mutation rolls back. That is what makes the trail *evidence* rather than a
log.

**Consequence, and it is real work:** the API needs a transaction-per-operation
discipline. Plan 1's repos each run their own statement, so this plan widens their
signatures.

**Writes only, not reads.** The trail stays a record of change, not a surveillance
record of normal operation. No sensitive-read exception is needed, because **no read
endpoint serves key material** — the one response that does carry a key is the
admin-only key *generation*, which is a mutation, and it is covered by the redaction
rules above.

**Plan 1 wrote only one audit entry in production** — the worker's `crl_built`. The
other actions (`ca_created`, `cert_issued`, `cert_revoked`, `key_generated`) existed
only in test fixtures. This plan is where the real writers land.

### Schema changes

`audit_log` gains:

- `actor_type` gains the value `one_shot_token` (it already has `user`,
  `acme_account`, `system`; `api_token` is added here). It is a text column with no
  CHECK constraint, so this is a value addition at the database level — **but the Rust
  `ActorType` enum (`ws-core/src/models/audit.rs:16-23`) is closed and its `from_str`
  rejects unknown strings**, so it gains two variants in the same change.
- **`auth_method`** — a first-class column, NOT NULL: one value per authentication
  method — `session`, `api_token`, `one_shot`, `acme_account`, and **`system`** for the
  worker's own writes. (The worker is an actor, not an authentication method, but its
  rows need a value inside the declared set, and `system` is the honest one.
  `acme_account` mirrors the `ActorType` value so the column set and the enum stay
  in step when ACME lands.)
- **Session identity** — its own column, nullable (null for machine actors). The house
  has no `sessions` table (only `refresh_tokens`), so the session id is the refresh
  token's id.

**`AuditRepo::record` and the `AuditEntry` model change with them.** `record` binds
an explicit column list (`audit_repo.rs:56-58`), so a `NOT NULL` column with no
default **breaks every existing insert** — including the worker's `crl_built` write,
which is the only production audit write in Plan 1. The worker therefore either
supplies `auth_method = 'system'` or the column carries a default; this plan has the
worker supply it explicitly, so the value is always deliberate.

**`details`** remains free-form jsonb for structured context — ids and labels only,
never key material. It is not used to reconstruct profile constraint sets (see
[Revisions](#revisions-are-append-only)).

---

## Setup

### The first-run setup page

The setup page is the **only** place the admin credential is ever established. The
user types the first admin's username and password into it, along with the default
domain and the admin CIDRs.

**No credential is generated by the system, printed to a log, written to a config file,
or delivered out of band.** A credential that exists in a log file or a plaintext file
leaks via log aggregation, backups, or `docker logs`. The password exists in plaintext
only in the request body, in flight, and is stored only as an argon2id hash.

### The bootstrap TLS window

The setup page is served by `ws-web` over **HTTPS with a self-signed certificate**,
generated at first boot, and **swapped for a certificate signed by the CA the setup
just created** when setup completes.

*(This overturns the product spec's "bootstrap TLS window" builder's call, which had
specified plain HTTP during setup. The spec rejected the self-signed alternative
because it "teaches users to click through TLS warnings on the very page where they'll
enter admin credentials." The counter-argument is stronger on the property that
matters: plain HTTP sends the admin password across the LAN **in cleartext**, and
anyone on the network can capture the first credential of the whole system — the one
that can then issue certificates. A browser warning is a one-time, *visible* signal; the
encryption is permanent.)*

**The fingerprint option:** the self-signed cert is generated with the configured SAN
(see below), and
the setup page displays its SHA-256 fingerprint so the operator can **verify** it
out-of-band — the same trust-on-first-use pattern the product spec already requires
for the step-ca token flow. The operator verifies the cert rather than clicking through
a warning.

**The setup cert's key** lives in the keystore under a **dedicated setup slot**,
encrypted at rest like every other key, never used to sign anything real. (Per-boot
regeneration was the alternative and is worse: the operator would re-verify a new
fingerprint on every restart, defeating the fingerprint-verification UX above.) This
extends `KeyStore` with a setup-key slot — its current API is CA-specific
(`store_ca_key(ca_id, der)` / `load_ca_key(ca_id)`).

**The setup slot must be counted by `has_stored_keys`.** That helper currently scans
**only** the `ca/` subdirectory for `*.key` files (`keystore.rs:328-344`), and it is
what stops `ensure_master_key` from minting a fresh master over an existing store
(`keystore.rs:167-169` — it returns `Corrupt` rather than orphaning the stored keys).
A setup slot outside that scan would silently defeat the guard: a lost master key plus
a present setup key would produce a *new* master and an undecryptable setup key —
precisely the failure the guard exists to prevent. **The setup key therefore lives
inside the scanned directory**, or `has_stored_keys` is extended to count it. Either
way this is a required change to Plan 1's keystore, not an optional one.

**The first-boot certificate's SAN.** The hostname is collected *on* the setup page, so
at first boot it is not yet known — the certificate cannot carry "the correct SAN"
before setup runs. **Ruling:** the first-boot self-signed certificate carries the SAN
from an instance-level configuration value (an environment variable naming the
server's hostname), falling back to a placeholder SAN when unset. The operator's
out-of-band verification is against the **fingerprint** in either case, which is the
mechanism above and does not depend on the name matching. Once setup has the
hostname, the real leaf is minted from the new CA and the listener switches to it.

**The setup surface is only live while unconfigured.** Once the tenant exists, the
setup endpoint is **not routed** — not merely refused.

### What setup does, in one transaction

Tenant → root CA → admin user (argon2id hash) → default profiles (the built-ins,
scoped to the domain and admin CIDRs) → audit entries.

**The UI's own TLS leaf** is minted from the new CA at the end of setup, and `ws-web`
switches to it. (This is where Plan 2's TLS story ends; the full UI's own
certificates are a later plan's concern.)

### Where the UI's hostname comes from

An **explicit setup field** — the server's hostname/SANs, alongside the default domain.
It is not derived from the default domain (a server called `wardstone.internal` may
serve `wardstone.lan`) and not from the machine's hostname (unreliable in containers).

### The setup page's shape in this plan

`ws-web` serves a **single-purpose first-run page** — not the full UI. It collects the
admin credentials, the default domain, the admin CIDRs, and the server hostname, and
shows the setup cert's fingerprint. The full UI arrives in a later plan and reuses the
same proxy wiring.

---

## Architecture

### Crate layout

One binary, two invocation modes, from the same image (`wardstone ui` / `wardstone
api`) — the product spec's call, and it keeps the anti-goal (one process's failure
taking down the other) while keeping one Dockerfile and one CI lane.

```
ws-auth    — users, sessions, TOTP, OIDC, RBAC/capabilities, service identities
ws-api     — the REST API (/api/v1/) and, later, ACME
ws-web     — TLS front door; path-proxies /api/v1/* to ws-api; serves the setup page
ws-core    — domain models, repos, migrations (extended)
ws-ca      — CA engine (extended: EKU support, leaf key generation, setup-key slot)
ws-worker  — background jobs (unchanged in this plan)
```

**`ws-web` publishes the only port to the LAN; `ws-api` publishes none.** Its only
front door is `ws-web`, over the internal compose network. This keeps one TLS listener
and no CORS, as the product spec requires. External-Postgres deployments may front
`ws-api` directly behind their own reverse proxy, documented in the compose variant.

### Transactions

**Repos take a generic executor** (`impl PgExecutor` / `&mut PgConnection`), so the
same method works against a pool or inside a transaction. This is sqlx's own idiom and
matches the house pattern, which already reaches for `&mut *tx` versus `&pool` at
different call sites.

*It is a signature change across Plan 1's five repos and `ws-ca` — not a pure
widening, as an earlier draft of this document claimed. Plan 1's repos each hold a
`PgPool` and execute against `&self.pool`; the executor becomes a parameter on every
method.*

**`allocate_serial` joins the issuance transaction.** A rolled-back issuance burns a
serial, which is acceptable and conservative — serials are never reused. Its signature
changes to take the executor.

### Issuing a certificate

The profile is validated against the **request**, and the CSR's own contents carry no
authority:

1. The request body proposes the **names** and the **subject CN**. Both must match the
   profile's pattern list.
2. The CSR is a **key carrier**. Its SAN extension and its CN are **ignored** — the
   body's values are used. (A CSR may request anything; only what the profile permits
   is certified.)
3. The CSR's key algorithm must equal the profile's pinned algorithm.
4. The profile's exact key usages, EKU, and lifetime are applied. The profile's
   lifetime must fit within the issuing CA's remaining life — the API **pre-checks and
   refuses** rather than silently issuing a shortened certificate, because a
   certificate that does not match its profile violates the exact model.
5. The serial is allocated in the same transaction.
6. The certificate row and the audit entry are written in the same transaction.

### Leaf key algorithms

Plan 1 has **no leaf key enum** — `certificates.key_type` is a bare `String` whose doc
comment notes leaf algorithms are wider than the CA `KeyType` enum. A profile needs a
pinnable leaf algorithm, so this plan introduces one:

`LeafKeyType { Rsa2048, Rsa3072, EcdsaP256, EcdsaP384, Ed25519 }`

**This deliberately narrows Plan 1's accepted set.** Today `supported_key_alg` accepts
**RSA ≥ 2048** — so an RSA-4096 CSR is accepted and issued. With a pinnable enum, no
profile can pin RSA-4096, so such a CSR is **rejected** ("no profile pins this key
type"). That is a narrowing, and it is a deliberate one: the alternative is an
unpinnable key type, which the exact model cannot express. The enum grows if the
operator needs it.

**The enum's string values are reconciled with the existing column.** The column
already holds Plan 1's free-form leaf algorithm strings (e.g. `"ecdsa-p256"`), so
`LeafKeyType::as_str()` uses exactly those spellings — `rsa2048`, `rsa3072`,
`ecdsa-p256`, `ecdsa-p384`, `ed25519` — and existing rows stay parseable. (Plan 1's
`CsrInfo.public_key_alg` uses a different vocabulary — `"RSA"`, `"ECDSA P-256"` — and
the validator maps between the two rather than storing the CSR's spelling.)

**A profile pins a specific algorithm, and the CSR's key must match it exactly** — so
a profile pinning RSA-2048 rejects an RSA-3072 CSR. (The CSR's RSA modulus size is
readable via x509-parser's `key_size()`, so this is checkable.)

**The admin-only generation path must be able to generate every pinnable algorithm**,
including P-256 — Plan 1's `generate_key_pair` handles only Ed25519 and RSA.

### Error contract

House convention: handlers return `impl IntoResponse` with a status code and a JSON
body, `#[serde(rename_all = "snake_case")]` matched to the sqlx renames (the product
spec flags this as a documented house bug class).

**Profile validation errors are specific for authorized issuers, generic for everyone
else.** The capability check runs first, so the split is by authorization:

- An actor with `issue` gets the specific reason — which constraint failed ("name
  `foo.other.com` is not permitted by this profile", "the CSR's key is Ed25519 but
  this profile requires RSA-2048"). This is the admin who needs to know why.
- Everyone else gets a generic "not permitted by policy" and learns nothing about the
  profile's contents.

**The specific error names which constraint failed and never dumps the permitted set**
— otherwise a caller could use error text to enumerate what a *different* profile
permits.

**There are no profile ACLs in v1.** The capability set is the only scoping mechanism,
so every `issue` holder can use every profile; the specific-vs-generic split is a UX
choice for all issuers, not a boundary.

**The subject CN is a permitted name too.** It is checked against the same pattern
list as the SANs — otherwise a certificate could carry a subject the profile does not
allow while its SANs look clean. Proposing **no** SANs is a different artifact, not
a subset, and is rejected.

### Rate limiting

The house pattern's `GovernorLayer` per router (the product spec requires rate limiting
enforced at both processes: auth limits in `ws-web`, ACME limits in `ws-api`).

---

## Schema

New tables for this plan:

- `users` — the house schema, ported, with `tenant_id` (the product spec: every table
  carries it), plus a `role`. The house `users` table also carries `email TEXT NOT
  UNIQUE`, `auth_provider NOT NULL DEFAULT 'local'`, `password_hash`,
  `totp_secret_encrypted` + `totp_secret_nonce` (the house's **current** spelling
  after `020_encrypt_secrets_at_rest.sql` — the TOTP secret is encrypted at rest
  under its own secret-encryption key), `webauthn_credential`, `mfa_enabled`,
  `azure_oid`, `oidc_sub`, `is_active`, `force_password_reset`,
  `failed_login_attempts`, `locked_until`, and `last_login_at` — the port keeps the
  columns the feature set needs. `role` and `auth_provider` are **TEXT** (the house
  uses enum types; text keeps the capability model extensible without a type
  migration). **The house's global uniqueness on `username` and `email` is
  narrowed to per-tenant** (`UNIQUE (tenant_id, username)`, `UNIQUE (tenant_id,
  email)`) — otherwise two tenants cannot both have an `admin@example.com`, which
  the product spec's tenancy shape explicitly allows. The house's globally-unique
  `azure_oid` is narrowed per-tenant for the same reason.

**WebAuthn is not implemented in this plan.** The auth surface this plan scopes is
"JWT + refresh tokens, argon2id password hashing, TOTP MFA, OIDC SSO, RBAC, and
account lockout" — WebAuthn is not on that list, and the house's `mfa_webauthn.rs`
is a **stub** with no verification functions to port. The `webauthn_credential`
column is ported for schema compatibility, but no code path writes or reads it.
- `refresh_tokens` — house port, with `tenant_id`.
- `oidc_config` — the house table is a **single-row** table
  (`id INTEGER PRIMARY KEY CHECK (id = 1)`, `linux-patch-manager/migrations/014_oidc_provider.sql:24`).
  Porting it per-tenant means dropping that check and keying it by `tenant_id`; the
  house `provider_type` check (`keycloak`/`azure`/`custom`) is kept.
- `service_identities` — API tokens: id, tenant_id, name, description, creator, token
  hash, created_at, expires_at, revoked_at, last_used_at.
- `service_identity_capabilities` — service_identity_id, capability.
- `one_shot_tokens` — id, tenant_id, minted_by, token hash, created_at, expires_at,
  used_at.
- `one_shot_token_capabilities` — one_shot_token_id, capability.
- `role_capabilities` — role, capability. The authoritative role→capability mapping.
- `profiles` — id, tenant_id, name, description, current revision.
- `profile_revisions` — id, profile_id, revision, the constraint set as **typed
  columns**, created_at, actor.

**There is no `user_groups` table in v1.** The house's `user_groups` references a
`groups` table Wardstone does not have, so porting it verbatim would fail with
"relation groups does not exist". Wardstone v1 has **roles, not groups**.

**No `setup_state` table.** Whether the tenant exists (a query on `tenants`) is the
marker — the spec's "or the equivalent marker" — and no agent should add a
`setup_state` table.

**The OIDC subject lives in `users.oidc_sub`**, unique per tenant. The house added
the same column for Keycloak/custom providers
(`linux-patch-manager/migrations/014_oidc_provider.sql:20`) because the *subject*,
not the email, is the stable identity — and the email is optional in an OIDC
identity. The callback's lookup rule is: match by `oidc_sub`; if absent, link by
verified email; if that fails too, create the user.

**Lockout is two columns, not a table.** The house `012_account_lockout.sql` adds
`failed_login_attempts INTEGER NOT NULL DEFAULT 0` and `locked_until TIMESTAMPTZ` to
`users` — ported as columns, not a separate `login_attempts` table.

`certificates.profile_name` (free-form text) **gains a sibling FK** to the
immutable revision row — the revision *is* the policy record, so pointing at it is
the honest representation, and the free-form column survives as a denormalised
display label. **The column is not dropped in this plan:** dropping it needs a
separate migration after the code stops referencing it, and the Global Constraints
forbid editing an applied migration. The drop is deferred to a later plan.

**Existing rows.** `certificates.profile_name` is `NOT NULL` and existing rows carry
free-form labels matching no profile. The FK is added **nullable**, and existing rows
are backfilled as follows:

- **One legacy profile per tenant**, named `legacy`, with a current revision.
- **One legacy revision per distinct free-form label** in that tenant, each carrying
  the label as its denormalised name. (One revision per *label*, not per tenant — a
  single per-tenant revision cannot hold more than one label, and distinct labels
  would be lost, contradicting "no row is lost".)
- Each legacy revision's **typed constraint set** is the permissive one (empty
  pattern list is not used; the list is set to the tenant's default domain scope
  where one exists, otherwise to `*`), with a `legacy` marker so it is never mistaken
  for a live policy. The point of the backfill is that the historical certificate is
  *attributable*, not that the legacy profile is usable for new issuance.
- Every existing `certificates` row is repointed at the revision matching its label.

The denormalised name column is kept on the revision row for display, so no label is
lost.

**The revision's constraint set is stored as typed columns, not a jsonb blob** — the
same reasoning that rejected jsonb for the audit log applies here.

### `audit_log` changes, and their backfills

`audit_log` already has rows in any deployment that has run the worker, and two
columns are being added. `ADD COLUMN ... NOT NULL` without a default fails on a
non-empty table, so the order matters:

- `auth_method` — add **nullable**, backfill from `actor_type` (existing rows are
  `system` writes from the worker, so `'system'` — which is in the declared value
  set), then `SET NOT NULL`.
- `session_id` — add **nullable** and left nullable. It is null for machine actors,
  so it needs no backfill and must not be `NOT NULL`.

`actor_type` is a plain `text NOT NULL` column with no CHECK, so the new values are a
data change — **but the Rust `ActorType` enum
(`ws-core/src/models/audit.rs:19-28`) is a closed enum whose `from_str` rejects
unknown strings**, so it gains two variants (`api_token`, `one_shot_token`) in the
same change.

Also in this plan:

- **`cas.parent_id` tenant consistency.** `cas` already carries
  `cas_id_tenant_key UNIQUE (id, tenant_id)` from Plan 1's migration 006, so
  `FOREIGN KEY (parent_id, tenant_id) REFERENCES cas (id, tenant_id) DEFERRABLE
  INITIALLY DEFERRED` closes it in the same idiom.
- **`page_size` is bounded.** It is currently an unbounded `u32` in the paging
  helpers — a DoS vector the moment an endpoint exposes it. One shared helper with a
  maximum (Plan 1's `paging()` is already duplicated between two repos, and this plan
  adds three more).

---

## Deployment

Docker Compose only, two variants, per the product spec:

- **Bundled** — Wardstone + Postgres in one compose file. The homelab quick-start.
- **External** — Wardstone pointing at an existing Postgres. The scalable path.

`ws-web` and `ws-api` run as separate services (separate processes, the anti-goal),
one image, two invocation modes. Postgres via sqlx with the house
`REQUIRED_MIGRATION_COUNT` convention.

---

## What's Left to the Builder

**Required changes to Plan 1's code** (these are not optional — the design depends on
them):

1. **`ws-ca`: add EKU support.** Extend `LeafSpec` with an EKU field; set
   `params.extended_key_usages` in `sign_leaf_with`.
2. **`ws-ca`: refuse empty EKU and empty key-usage lists** in `sign_leaf_with` (an
   absent extension is unrestricted).
3. **`ws-ca`: replace the silent not_after clamp with a typed refusal**
   (`issue.rs:419-423`), so a certificate can never silently differ from its profile.
4. **`ws-ca`: add a leaf key enum** and make the admin-only generation path support
   every pinnable algorithm, including P-256.
5. **`ws-ca`: extend `KeyStore` with a setup-key slot**, and make `has_stored_keys`
   count it (it currently scans only `ca/` for `*.key`), so a lost master key can
   never cause a fresh master to be minted over an existing setup key.
6. **`ws-core`: widen the repo methods to take a generic executor**, so a mutation and
   its audit entry can share one transaction.
7. **`ws-ca`: `allocate_serial` takes the executor** and joins the issuance
   transaction.
8. **`ws-core`: the `ActorType` enum gains `api_token` and `one_shot_token`**, since
   its `from_str` rejects unknown strings.
9. **`ws-core`: `audit_log` gains `auth_method` and `session_id`; `AuditRepo::record`
   binds the new column and `AuditEntry` gains the matching field.** The worker
   supplies `auth_method = 'system'` — without this, the worker's insert fails the
   `NOT NULL` constraint, and the worker's `crl_built` write is the only production
   audit write Plan 1 has.
10. **`ws-worker`: supply `auth_method = 'system'`** on its audit write.
11. **`ws-core`: bound `page_size`** in the two existing `paging()` helpers
    (`audit_repo.rs:129`, `certificate_repo.rs:261`), which are duplicated today.

**Genuinely deferrable:**

- The exact REST route list and DTO shapes (the capability and validation rules above
  determine them).
- The migration numbering and the exact DDL.
- The house port's details: which `pm-auth` modules are ported verbatim, which are
  adapted for `tenant_id` and the capability model.
- The setup page's markup and the exact field order.
- The audit action vocabulary and the `details` jsonb shape.
- The rate limits per endpoint.

## Open Questions

None. Every question raised in the brainstorming pass and the builder check is
answered in this document.

**Resolved during drafting, recorded so the reasoning is not lost:**

- *The setup key and the master key.* `ensure_master_key` generates the master key
  when it is absent and no keys are stored yet (`keystore.rs:159-173`), and
  `store_ca_key` *requires* the master key to exist already (`keystore.rs:187-189`).
  So the sequence is coherent: generate the master key, store the setup certificate's
  key in the setup slot under it, then setup creates the root and stores the root's key
  in the same keystore. The master key's generation happens exactly once, before the
  setup key is stored.
- *OIDC configuration scope.* **Per-tenant.** The house `oidc_config` is a single-row
  table (`CHECK (id = 1)`); porting it per-tenant means dropping that check and keying
  it by `tenant_id`, consistent with the product spec's "every table carries
  `tenant_id`".

## Decisions Attributed

**Human's calls (2026-10-20, original spec):** tenancy shape Option A; single-tenant
default; in-crate ACME; manual + ACME both; revocation + CRL + OCSP in v1; auth like
LHFM/LPM; docker compose only; root trust distribution; no AI co-author attribution in
commits.

**Human's calls (2026-10-21, this plan):** profiles are constraints rather than
templates; the default profile is bootstrap-scoped; profiles are editable and
extensible after bootstrap; profile edits are revisioned; three RBAC roles — a full
admin who can manage all system config, a certificate-issuer level, and a
compliance-auditor level — with `issue` and `manage_profiles` as separate
certificate permissions; the API never touches private key material on the normal
path; server-generated leaf keys are admin-only, never persisted, handed out once; CA
keys are exportable with the server keeping its copy (offline root named as the
exception); the audit log records writes, not reads; auth method is a first-class
column; three authentication methods with API tokens as first-class service
identities tied to a creator; the profile is exact rather than a ceiling; the
first-run setup happens on a setup page with no credential in any log or file; the
setup page is served over HTTPS with a self-signed cert, swapped at completion; Plan
2 is trust-boundary first; the profile pins the leaf key algorithm with an RSA-2048
default; **the full house auth surface (including OIDC SSO) is in scope**; **tenant
creation is in scope**; **`ws-web` — not `ws-api` — serves the setup page**, and Plan 2
mints the server's own TLS leaf from the new CA at the end of setup.

**Builder's calls (this plan):** the capability names and what each gates; the
role→capability mapping living in a table; the pattern-matching semantics (single
wildcard label depth, case-insensitive, bare `*` for DNS names only); the profile's
lifetime being the *span* with the one-day clock-skew margin kept; the silent clamp
becoming a refusal; SHA-256 for bearer-token hashing; optimistic concurrency for
profile revisions; typed columns for the revision's constraint set; the one-shot token's
`actor_type` and its lack of a profile scope; the one-shot issuance endpoint being in
scope; the setup key's keystore slot and the `has_stored_keys` requirement; the
first-boot certificate's SAN coming from configuration; the leaf-key enum's names and
its deliberate narrowing of Plan 1's accepted set; the API's error shape; the
production compose bundle being in scope; OIDC configuration being per-tenant; the
`auth_method` / `session_id` backfills; the `profile_name` → FK backfill.

**Builder's calls (this plan), flagged for the owner to overrule:** the built-in
default profiles' exact content (two profiles — `web-server` on RSA-2048 and
`web-server-ecdsa` on P-256, both 30-day spans, `serverAuth`, scoped to the setup
domain and admin CIDRs); the subject CN being subject to the profile's pattern list
like every other name; the leaf-key enum's member set.
