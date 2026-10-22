# Wardstone Plan 4 — ACME (First-Party RFC 8555 Server) — Design

Status: proposed design (brainstorm skipped per operator instruction "skip the questions and just start"; operator's one stated input: **"mostly homelab machines"**. Choices marked **[call]** are the executor's. Binding authority: this document once approved. Repo state: `main` at `ad865e2` (Plans 1-3 merged).

## Intent and Why

Wardstone's README promises a certificate authority "simple enough for a homelab and hardened enough for production." Certificates are issued by hand today (the UI/API flows of Plan 3). Plan 4 completes the roadmap: **the homelab machines renew automatically** — the operator points `certbot`, `caddy`, or `acme.sh` at their own CA (`--server https://wardstone.home.test/acme/directory`) and Wardstone speaks RFC 8555 ACMEv2 natively: accounts, orders, authorizations, challenges, issuance, revocation — **first-party protocol handling, no ACME crate** (the spec's standing constraint, honored exactly as "no third-party ACME library").

The maintenance queue from Plans 2-3 rides in this plan as early tidy tasks **[call: fold, don't split]** — Plan 4 is the final planned plan, and a separate maintenance plan would be ceremony.

## Goals

1. A working **ACMEv2 (RFC 8555) server**: directory, new-nonce, new-account (incl. only-return-existing + terms-of-service update), account update/deactivation, account-key rollover (key-change), new-order, order poll, authorizations, challenges (HTTP-01, DNS-01), finalize (CSR), certificate download, certificate revocation, revoke-account. Nonces (Replay-Nonce) issued and enforced; JWS verified — `embedded JWK` (new account) and `kid` (established) flavors; RS256/ES256/EdDSA per the house's existing signing primitives.
2. **First-party JOSE**: JWS parsing/verification built with the workspace's existing crypto (jsonwebtoken's algorithms for verification is acceptable as a LIBRARY primitive — the constraint bans an ACME protocol crate, not a JOSE primitive the house already ships; [call] below).
3. Challenges the homelab reality supports: **HTTP-01** (the CA fetches `http://<ident>/.well-known/acme-challenge/<token>` from the machine — the operator's machines are network-reachable from the CA, per "mostly homelab") and **DNS-01** (the CA resolves `_acme-challenge.<ident>` TXT via a native DNS resolver — this is also the wildcard path, which HTTP-01 cannot serve).
4. ACME identity wired end-to-end: the dormant `ActorType::AcmeAccount`/`AuthMethod::AcmeAccount` variants become real — accounts are tenant-scoped rows, orders/authorizations are tenant-scoped rows, and every mutation lands in the audit log with the ACME actor shape.
5. The **UI sees ACME as day-to-day**: an accounts section (list, deactivate, view orders) and per-order detail on the certificates pages — same capability model (a new `manage_acme_accounts`/`read_acme` capability pair), admin-gated.
6. The maintenance queue lands: session-store idle eviction, profile-description editing (server-side), deactivate/PATCH policy alignment, the slim certificate list route, LIKE escaping for `q`, and (conditionally) the test-DB serialization fence.
7. The compose bundle exposes the ACME surface through the existing front door (ws-web path-proxies `/acme/*` to ws-api like `/api/v1/*` — cookieless, JWS-bearer-authenticated; ws-api remains portless).

## Non-Goals

- TLS-ALPN-01 challenge (the three-way handshake variant; HTTP-01 + DNS-01 cover the homelab and wildcard space) — deferred with the same wording Plan 1 used for offline-root.
- ARI/renewal-info (RFC draft) and renewal-policy management.
- External account binding beyond accepting-and-ignoring (v1: not required; a no-op ack if sent).
- Multiple CAs / intermediate hierarchies via ACME (orders issue from the tenant's root CA exactly as manual issuance does — same `choose_ca` rule as the Plan 2 API).
- Public-internet operability: the CA is assumed reachable from the operator's machines (homelab), not that it must be internet-exposed. No port-forwarding guidance beyond what the compose bundle already does.
- An ACME **client** (Wardstone is the server; the operator's certbot is the client).
- Offline-root flow and expiry monitoring (still deferred, same as Plans 1-3).

## Anti-Goals (failure even if everything works)

- **Trusting client-supplied challenge results**: the CA must verify HTTP-01/DNS-01 from its own connection/resolution, never from data the client posts. A malicious client cannot self-authorize an identifier.
- **Trusting `Host`/forwarded headers** for identifier binding or challenge URLs.
- **A third-party ACME crate** anywhere in the dependency graph.
- **Divergent issuance policy**: an ACME-issued certificate obeys the SAME profile constraints (key type, lifetime, SAN patterns, key usages) the manual path enforces — `not_permitted_by_profile` refusals apply identically.
- **Un-nonce'd replay**: any request that can mutate state without a fresh, single-use Replay-Nonce is a failure.

## Constraints

- Spec lineage: "no third-party ACME library" (Plans 1/2 Global Constraint, unchanged). JOSE primitives may reuse the existing `jsonwebtoken` workspace pin (already a workspace dependency for ws-auth's JWTs) — the ban is on ACME-protocol machinery, not on a JOSE codec **[call]**.
- Browser talks to ws-web only; ws-api publishes NO ports — `/acme/*` rides the same ws-web front door (path-proxied, JWS-authenticated; the BROWSER session cookie plays no part in ACME auth).
- House rules: fmt/clippy/no-unwrap-in-library/typed errors/conventional commits/no AI trailers; serde snake_case + `as_str()` == serde name on TEXT-stored enums; DB-gated suites: **next free advisory key `0014`** (0003-0013 taken), sweep-first, delete-at-end; migrations ADD-ONLY (011 next).
- `aws-lc-rs` never enters the graph.
- The existing issuance machinery is the ONLY issuance path: ACME finalize goes through the same ws-ca engine + profile validation (Task Plan-2's `issue_in_tx` idiom), same audit vocabulary family (`cert_issued` with actor_type `acme_account`).
- Challenge verification is rate-limited and error-isolated: a challenge that cannot be verified fails the authorization, not the server.

## Architecture — How It Gets Made

### Crate shape **[call]**

A new `ws-acme` crate (protocol only: RFC 8555 types, JWS verification, nonce store, challenge-state machine) alongside `ws-wauth`-style siblings, consumed by `ws-api` (which mounts `/acme/*` routes and owns persistence via `ws-core` repos). `ws-ca` remains the only issuer; `ws-acme` never signs directly — finalize delegates to the existing `issue_in_tx` path with an ACME actor. `ws-web` gains the `/acme/*` proxy prefix (cookieless passthrough with the existing bounded-timeout client).

### Persistence **[call]**

Migration 011 adds tenant-scoped `acme_accounts` (JWK thumbprint key id, status pending/valid/deactivated, TOS-agreed, contact), `acme_orders` (status pending/ready/processing/valid/invalid, profile_name, identifiers, csr, certificate_id on completion), and `acme_authorizations` + `acme_challenges` (identifier, token, challenge type, status, validated-at, error) — all FK'd per tenant with the 006-style composite-consistency constraints where children reference CAs/certificates. Nonces live in-memory (single-instance deployment; a restart simply re-nonces). `REQUIRED_MIGRATION_COUNT` → 11.

### Trust and verification **[call]**

- **Account auth**: the JWK thumbprint (RFC 7638) IS the account key id; `kid` URLs are tenant-scoped account URLs (`/acme/acct/<id>`). Deactivated accounts reject every order; pending accounts reject orders until TOS agreement.
- **Challenge verification**: HTTP-01 — the server makes its own outbound GET to `http://<ident>/.well-known/acme-challenge/<token>` (reqwest, bounded timeout, NO proxy headers, Host header = the identifier); DNS-01 — the server resolves TXT `_acme-challenge.<ident>` via a native resolver (std/`hickory-resolver`? [building detail — left to the plan, with a std-resolver default]) and hashes the TXT payload per RFC: the challenge response is `base64url(SHA256(keyAuthorization))` — the server computes the EXPECTED value from its stored token + the account's JWK thumbprint, so clients cannot hand it the answer.
- Wildcards: DNS-01 only (DNS-01 covers `*.domain` — one authorization per identifier; wildcard orders carry the base domain authorization per RFC 8555 §7.4).
- Multi-perspective validation (MPIC) is out (a CA/Browser-Forum concept for public WebPKI; v1 is the operator's own eyes).

### Issuance path

Finalize → CSR validated through the SAME `validate_names` + profile constraints as the manual path, profile selection via the order's `profile` field **[call: an order carries `profile_name` (Wardstone extension field on the order object; default `web-server`); the profile must exist in the tenant — profiles are NOT auto-created by ACME]** → `issue_in_tx` with `Actor{actor_type: AcmeAccount, auth_method: AcmeAccount, actor_id: account-url}` → certificate ID returned; `/certificate/<id>` serves the PEM chain (leaf + chain from Task 3's chain assembly).

### UI surface

`GET /api/v1/acme/accounts` + orders list/detail under a `read_acme` capability; deactivate under `manage_acme_accounts`; audit rows land in the existing `role_capabilities` seed (migration 007's table gains the new capabilities → **migration 012 seeds them into the Admin role and the seed-test set-check updates** — the pinned set-equality test in repo_test must track ALL_CAPABILITIES). The certificates pages link ACME-issued certificates back to their orders.

### Maintenance-queue tasks (early in the plan, before ACME tasks)

1. session-store idle eviction (background sweeper or lazy eviction on get **[builder's call]**, homelab scale).
2. server-side profile-description editing (a new PUT semantics or a dedicated route — the v1 UI already freezes the field honestly; this task makes it editable).
3. deactivate/PATCH self-deactivation policy alignment (one aligning commit per the Plan-3 ruling).
4. slim certificate list route for the dashboard sieve (`?fields=slim` or a dedicated route **[builder's call]**).
5. LIKE escaping for `q` (escape `%`/`_`/`\` — literal search; the UI never needs wildcard semantics from the operator).
6. the test-DB serialization fence — executed ONLY if its interference pattern has recurred (standing Plan-3 ruling); otherwise the last item is dropped with the ruling noted.

## What's Left to the Builder

- Task decomposition, TDD matrices, the RFC conformance test approach (certbot/`pebble`-style conformance via REAL certbot integration in an e2e? [builder's call: an e2e with real `certbot --dry-run`-shaped flow is the homelab success criterion; `openssl`-based JWS fixtures for unit tests]).
- The exact JOSE verification code shape (jsonwebtoken's raw-JWS entry points vs hand-built compact-serialization verification atop it).
- The DNS resolver dependency choice and its workspace-pin economics.
- Error-response vocabulary for ACME (`urn:ietf:params:acme:error:*` problem+json documents).
- UI component shapes for the accounts/orders pages.

## Builder-Check Settlements (binding, 2026-10-22)

The builder check raised ten questions; nine are settled as executor rulings grounded in the prior specs, one is escalated to the operator (see the end of this section):

1. **Tenant shape — Plan 1's URL wins:** directories and kid URLs keep the Plan-1-pinned `/acme/<tenant>/…` shape (this doc's success criterion originally showed a flat `/acme/directory` — corrected). v1 operates on the setup tenant (same ruling as Plan 3's login pinning); the tenant segment makes kid-to-wrong-tenant a lookup failure by construction. `acme_accounts` PK is `(tenant_id, jwk_thumbprint)`.
2. **ACME actor grant:** status-gated (pending refuses orders; deactivated refuses everything) + the fixed-stored-grant pattern mirroring one-shot tokens — the AcmeAccount Actor carries exactly `[Issue]`; per-account profile allowlists (Plan 1's optional binding) stay a follow-up. The anti-goal is enforced by the profile constraints being the SAME validators the manual path runs.
3. **Verification model:** synchronous in-request verification (homelab scale; inside ws-web's 60s proxy timeout; certbot polls via POST-as-GET); ws-worker keeps CRLs only.
4. **Authorization reuse:** per `(account, identifier)` reuse with a 30-day valid window; non-reused identifiers mint fresh authorizations; the renewal success criterion reuses.
5. **Retry discipline:** unlimited re-POSTs while an authorization is pending (expiry ≈ 7 days); an order invalidates when any authorization invalidates; verification attempts back off per-authorization.
6. **ACME revocation:** account-key JWS only in v1; certificate-key proof-of-possession declined with the RFC-sanctioned error (a follow-up if ever needed); `certbot revoke` with the account key is the success-criterion path.
7. **Absolute URLs:** a configured `WARDSTONE_PUBLIC_URL` env (compose) constructs every absolute URL and validates kid prefixes — Host is never trusted (anti-goal stands).
8. **Rate limits:** new-account = per-IP GCRA at ws-api (machinery exists); authenticated ACME = per-account; challenge attempts back off per-authorization.
9. **Deactivation cascade + ToS:** deactivating an account invalidates its PENDING authorizations and blocks new orders; issued certificates are unaffected (revocation is separate). ToS is optional via `WARDSTONE_ACME_TOS_URL` (unset → the directory omits the ToS Link; no enforcement step).

### The operator decision (settled 2026-10-22)

**Open enrollment on reachable networks, v1** — the operator chose the recommended default: any LAN-reachable machine may create an ACME account and enroll. Control surfaces: challenge proof of identifier control, the profile SAN patterns, and the per-account status gate. The CIDR allowlist and operator pre-registration are recorded follow-ups (the first-line options if Wardstone ever faces a less-trusted network).

## Success

From a homelab machine: `certbot certonly --standalone --server https://wardstone:<port>/acme/<tenant>/directory -d host.home.test` completes interactively (account creation → order → HTTP-01 → issuance), the certificate downloads with the full chain, renewal re-runs without operator action (authorization reuse applies), a `*.home.test` wildcard issues via DNS-01 against the operator's DNS, and the UI shows the account, the order, and the issued certificate with audit rows attributing `acme_account`. Revocation of an ACME certificate via the API or `certbot revoke` (account key) works. `certbot revoke` with the certificate key receives the RFC-sanctioned decline in v1. No point in any of that can bypass the manual path's policy checks.