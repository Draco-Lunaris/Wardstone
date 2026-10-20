# Wardstone — Design Document

**Date:** 2026-10-20
**Status:** Approved by the human, 2026-10-20
**Repo:** github.com/Draco-Lunaris/Wardstone

## Intent and Why

Wardstone is a self-hosted certificate authority with a web UI — simple enough for a
homelab to depend on, hardened enough for production. It exists because public ACME
solved the *external* half of TLS: a homelab's HAProxy pulls an official certificate
for its public domain automatically. But no public CA issues certificates for internal
names, so internal systems fall back to self-signed certificates and every client shows
TLS errors. Wardstone is the internal equivalent of that public CA: an authority the
network actually trusts, so internal systems get certificates issued and renewed as
automatically as the external ones.

**Success moment:** a browser hits an internal service and the padlock is green with
zero warnings, and a certificate renewed overnight without anyone touching anything.
**Failure moment:** the admin had to read RFC 8555 or step-ca documentation to get
there.

The author's own homelab is the first deployment, but this is a public project from day
one — it must work on *anyone's* network, with common public and private systems, not
just the author's specific infrastructure.

## Audience (in priority order)

1. **Homelabbers** — a `docker compose up` experience, a handful to a few dozen hosts,
   near-zero maintenance.
2. **Small business** — 50–200 endpoints, may run on real VMs with an external
   Postgres.
3. **Larger production** — only if the quality earns it.

Everything that follows is tuned so audience #1 succeeds without knowing CA internals,
while leaving the doors open for #2 and #3.

## Goals

- Single-command Docker Compose deployment for a homelab; compose for every audience
  (no bare `docker run` deployment story).
- Issue and renew certificates for internal systems without TLS errors.
- Full in-crate ACME (RFC 8555) server implementation — **no third-party ACME
  library**. *(human's call)*
- Manual issuance from the web UI as a first-class path alongside ACME. *(human's call)*
- Revocation, CRL, and OCSP. *(human's call)*
- Active expiry monitoring: UI alerts + outbound alert delivery (webhook, email,
  gotify/ntfy — *builder's call on the exact channel list*).
- Root-trust distribution page: download the root certificate with per-platform
  install instructions and helper scripts. *(human's call)*
- Multi-tenant CA hosting as a **capability**: one instance can host multiple roots,
  each with their own sub-roots. *(human's call)*
- First-run wizard: asks only the config questions needed, then deploys clean. *(human's call)*

## Non-goals (v1)

- No push delivery of certificates to clients — clients renew themselves via standard
  ACME clients; Wardstone never pushes. *(human's call)*
- No agent installed on target hosts (this is not the LHFM pull-agent model).
- Postgres is the only database — no SQLite/embedded option. *(human's call)*
- No SSO beyond the OIDC support inherited from the house auth pattern.

## Anti-goals

- Requiring the user to understand PKI internals (sub-CAs, extension OIDs) to get a
  working certificate — the guided bootstrap must hide all of it.
- A blocked 3am restart: requiring a human to enter a passphrase at boot.
- One process's failure taking down the other: the human UI and the API/ACME server
  run as **separate processes**, independently restartable, so neither blocks the
  other. *(human's call)*

## Certificates: types and issuance scope

- **v1:** server/TLS certificates.
- **Later additions:** client certificates (mTLS between services), S/MIME,
  code-signing — each arrives as a new *certificate profile* (a named bundle of key
  usages, extensions, lifetime), so the mechanism is the profile, not special-cased
  code. *(human's call)*
- **Profile schema in v1** *(builder's call)*: the table carries the general fields from
  day one — key usages, EKU list, lifetime, SAN constraints (allowed DNS patterns,
  wildcard policy, IP allowlist), and per-profile challenge requirements (none /
  DNS-01 / DNS-01+HTTP-01). S/MIME and code-signing become a new EKU + key-usage combo
  plus a UI preset — a data change, not a code change. In v1 the UI offers a server-cert
  preset and an advanced editor; future types are additive rows.
- **ACME JWS/JWK algorithms** *(builder's call)*: ACME account keys accept **ES256/ES384
  and RS256** per RFC 8555 §7; the CA's own signing-key default (ED25519) is separate
  from client JWK algorithms and the two must not be conflated. Cert *content* keys
  (the leaf public keys in CSRs) are accepted across the common set the client tools
  generate — ECDSA P-256/P-384, Ed25519, RSA 2048+.

## CA Model

Wardstone manages a forest of CAs. The simplest valid instance is a **single
self-signed root that signs end-entity certificates directly** — that is the default
homelab shape, and the guided bootstrap produces exactly that. Multi-tier is a
**capability, not a default**: a user who chooses can grow to an offline-eligible root
plus issuing sub-CAs, multiple roots, and multiple tenants (multiple roots, each with
their own sub-CA tiers). The data model and UI support one-to-many tiers and CAs from
the start; a beginner never has to know what a sub-CA is. *(human's call: capability
not requirement)*

**Key generation defaults:** ED25519 default; RSA 2048/3072 options. *(builder's call)*

**Key storage:**

- Keys encrypted at rest (envelope-encryption scheme, age/libsodium style — *builder's
  call on exact scheme*), with automatic decryption at startup from a protected key
  file so restarts come back fully functional with no passphrase prompt.
- Hardware-token storage backend (YubiKey / secure element) exists as an opt-in,
  **non-default** option. *(human's call)*
- **Master key mechanics** *(builder's call)*: the key-encryption key lives in a
  dedicated compose volume (`/var/lib/wardstone/keys/`), generated by Wardstone at
  first run, mode 0600, owned by the container user. The backup bundle includes it
  with loud warnings. **Honest tradeoff, stated in the docs:** with the master key on
  the same host as the ciphertext, at-rest encryption defends against file-copy
  exposure (a stolen volume, an over-shared backup), not against full host compromise.
  Real at-rest hardening is the opt-in hardware backend.

**Bootstrap:** first-run wizard names the CA, asks only what's needed, then Wardstone
issues its own UI TLS certificate from its own CA — full clean self-issued TLS from
first boot, no plain-HTTP deployment story. *(human's call)*

**The bootstrap TLS window** *(builder's call)*: the wizard itself has to be reachable
before the CA exists. Sequence: on first boot, ws-web serves the wizard over
**plain HTTP on the LAN, bound to a setup port, for the setup session only**; the
wizard collects hostname/SANs + admin CIDRs + admin credentials; Wardstone then
creates the root, issues its own leaf, and **restarts ws-web onto HTTPS only** — the
HTTP listener is gone from that point on. The UI displays a prominent "you are in
setup over plain HTTP" banner during the window. The alternative (self-signed cert
generated before the wizard) was rejected because it teaches users to click through
TLS warnings on the very page where they'll enter admin credentials.

## ACME Server

- Full RFC 8555 implementation in-crate, no external ACME library. *(human's call)*
- Endpoints at the RFC 8555 `/acme/<tenant>/directory` shape.
- **Challenges:**
  - DNS-01 — required capability, minimum bar for policy.
  - HTTP-01 — optional per policy.
  - TLS-ALPN-01 — supported (builder's call to include for client compatibility).
- **Client authorization** is a **pluggable interface**; subnet-allowlisting is the
  built-in method. Additional methods can be added later (the project is public, so
  others' needs will differ). *(human's call on shape)*
- **Default policy: closed but guided** *(builder's call)* — the first-run wizard
  prompts for the allowed CIDRs, and the default install rejects ACME traffic from
  outside them (denials logged to the audit trail and surfaced on the Dashboard as
  suspicious-attempt alerts). An open install is possible by setting `0.0.0.0/0`, but
  it is never the default.
- **ACME actor model** *(builder's call)*: ACME accounts are first-class *service
  identities* owned by a tenant — not UI users. An account is registered (key ID +
  JWK), optionally bound to one or more profiles, and all orders/authorizations are
  attributed to it. UI users administer accounts; accounts never act as humans.
- **Validation policy is per-client-profile and selectively enforceable:** e.g. an
  HAProxy profile may request names with no challenge, a web-server profile requires
  DNS-01 + HTTP-01, a service-machine profile requires DNS-01 only. *(human's call)*
- **DNS-01 solvers** implement a generic provider interface. Initial provider list:
  Technitium, PowerDNS, Cloudflare, Route53, RFC 2136. *(builder's call on list; human's
  constraint: must not be single-provider)*
- Renewal is client-driven: clients run their own ACME clients (certbot, lego, acme.sh,
  HAProxy hooks). Wardstone answers ACME; it never pushes. *(human's call)*

## Manual Issuance

- Issue from the UI against a chosen profile, delivering a PEM download in the browser.
- **Plus** a step-ca-style one-time-token flow: the target host pulls its own
  certificate once from a token-gated endpoint. *(human's call)*
- **Token flow mechanics** *(builder's call)*: the target host submits a **CSR** — its
  private key never leaves the host (the step-ca bootstrap-token shape). The one-time
  token is single-use with an expiry. The initial HTTPS connection to submit the CSR is
  verified by a **SHA-256 fingerprint of Wardstone's leaf cert pinned in the wizard UI**
  (trust-on-first-use), which the wizard displays next to the copy-paste curl command.

## Revocation

- Revocation UI + CRL + OCSP included in v1. *(human's call)*
- **Honest scope of OCSP** *(builder's call)*: browsers don't check end-entity OCSP for
  a CA they don't know, so the load-bearing v1 artifacts are the **CRL** (published at
  a stable URL, referenced from issued certs) and a **working OCSP responder** for
  clients that do check (non-browser tooling). ACME clients can revoke per RFC 8555
  §7.6. Browser-side enforcement is explicitly out of scope — the root-trust page's
  instructions are the enforcement story for browsers.
- Expiry monitoring is active: a dashboard element and alerting on certificates nearing
  expiry whose owning client hasn't renewed, plus failed ACME renewal and suspicious
  ACME attempt alerts (bad-actor visibility). *(human's call)*

## Certificate Lifetimes *(builder's calls)*

- End-entity: **30 days default**, profile-adjustable up to 398 days. Short default +
  automated renewal mirrors the public-CA world and keeps the renewal loop exercised.
- Sub-CA: **5 years** default.
- Root: **10 years** default. **Root-trust caveat in docs:** some OS trust stores cap
  anchors accepted as *newly added* around 398-day cert validity — that cap applies to
  the leaf certs it issues, not the anchor's own age; the root-trust page explains
  re-adding an anchor and pinning guidance for long-lived roots.
- CRL: regenerated by the worker, **24-hour `nextUpdate`**. OCSP: 24-hour signing window.

## Web UI

House stack (mirrors Linux-Patch-Manager / Linux-Host-Firewall-Manager):

- React 19, Vite, MUI 7 + Emotion, react-router-dom, Zustand, axios, vitest.
- Page-per-domain routing; typed `client.ts` API contract; server-side sorting and
  pagination (never client-side on a paginated slice); MUI Autocomplete for long
  option lists.

**Pages:** Dashboard, Certificates, ACME (accounts/clients/orders), Certificate
Profiles, CAs, Users, Audit Log, Alerts, Settings, Root Trust (download root cert +
per-platform install instructions and scripts).

**Dashboard:** certificate count, upcoming expirations, recent activity, system
health, and alerts — failed ACME renewals and suspicious attempts.

## Auth

House pattern (LHFM `fw-auth`):

- Multiple named users. *(human's call)*
- JWT + refresh tokens, argon2 password hashing, TOTP MFA, OIDC SSO, RBAC, account
  lockout. *(human's call: "auth should be like LHFM/LPM")*
- **Tenancy shape — Option A** *(human's call, 2026-10-20)*: single-tenant instance by
  default, tenant-shaped schema from day one. One default tenant is auto-created at
  bootstrap; every table carries `tenant_id`; an admin can create a second root/tenant
  later with its own ACME directory. No tenant-membership UI, no per-tenant role
  management, no tenant switching in v1. Homelabbers never see the word "tenant."

## Deployment

- **Docker Compose only.** Two variants: *(human's call)*
  - **Bundled:** Wardstone + Postgres in one compose file — the homelab quick-start.
  - **External:** Wardstone pointing at an existing Postgres — the scalable path.
- Postgres via sqlx, numbered migrations with the house `REQUIRED_MIGRATION_COUNT`
  convention.
- The data layer is designed with future scaling in mind (indexing, pagination, no
  client-side filtering of large sets). *(human's call)*

## Architecture (builder's calls, unless noted)

- Rust workspace, crates split by concern mirroring the house pattern:
  - `ws-web` — the human UI server (axum; serves the SPA)
  - `ws-api` — the API + ACME server (axum; separate process per the anti-goal)
  - `ws-core` — domain models + DB access (sqlx/Postgres)
  - `ws-ca` — CA engine (in-crate ACME, signing, CRL/OCSP)
  - `ws-auth` — JWT/argon2/TOTP/OIDC/RBAC
  - `ws-worker` — background jobs: expiry scanner, alert delivery, CRL regeneration
- **Binary split mechanics** *(builder's call)*: **one binary, two invocation modes**
  (`wardstone ui` / `wardstone api`) from the same image — distinct processes per the
  anti-goal, but one Dockerfile, one build, one CI lane. A dedicated compose service
  runs each mode.
- **Browser-to-API wiring** *(builder's call)*: the browser talks to **ws-web only**;
  ws-web path-proxies `/api/v1/*` and `/acme/*` to ws-api over an internal compose
  network. ws-api exposes no published ports to the LAN in the default bundle — its
  only front door is ws-web. External-Postgres/scalable deployments may front ws-api
  directly behind their own reverse proxy, documented in the compose variant. ACME
  clients on the network reach `/acme/*` through ws-web's published HTTPS port. This
  keeps one TLS listener, no CORS, and rate limiting enforced at both processes (auth
  limits in ws-web, ACME limits in ws-api).
- REST/JSON API versioned under `/api/v1/`; `#[serde(rename_all = "snake_case")]`
  JSON casing matched to sqlx renames (documented house bug class).
- Audit log for every privileged action, append-only.
- Observability: `tracing` structured logs, `/healthz`, Prometheus `/metrics`.
- Backup: documented `pg_dump` + key-file procedure, plus a UI "Download backup" action.
- Hardening defaults: HTTPS-only from first boot (self-issued), security headers, rate
  limiting on auth and ACME endpoints, non-root container user, read-only rootfs in
  compose.

## What's Left to the Builder

- Exact envelope-encryption scheme for key storage.
- Initial DNS-01 provider list beyond the constraint of "generic interface."
- Alert channel list beyond webhook/email/gotify-ntfy.
- Crate layout details and binary split mechanics (resolved: one binary, two modes;
  ws-web path-proxies to ws-api).
- Testing strategy (unit + containerized integration tests, house `just itest`
  pattern).
- CI shape (releases-only, mirroring the house projects).
- The visual theme specifics of the UI beyond the MUI 7 house pattern.

## Open Questions

None — all resolved. Multi-tenancy v1 scope settled as Option A (single-tenant
instance by default, tenant-shaped schema from day one) by the human, 2026-10-20.

## Decisions Attributed

- **Human's calls** (marked inline): in-crate ACME; manual + ACME both; revocation +
  CRL/OCSP; multi-tenant capability; multi-tier capability-not-default; encrypted
  key auto-recovery; hardware-token opt-in; client-driven renewal; subnet primary
  client-auth with pluggable shape; per-profile validation flexibility; generic
  DNS-01 provider interface; manual download + one-time tokens; multiple named users
  with house auth; Postgres only; compose-only deployment with two variants; separate
  UI and API processes; self-issued TLS bootstrap + first-run wizard; active expiry
  alerts; root-trust distribution page; server/TLS first with profile-grown types.
- **Builder's calls** (marked inline): ED25519 default key type; TLS-ALPN-01 support;
  initial DNS provider list; alert channels; tenancy shape; crate layout; observability;
  backup procedure; testing/CI; theme specifics.