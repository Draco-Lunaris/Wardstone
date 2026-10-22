# Wardstone Plan 3 — Web UI (Day-to-Day Certificate Operations) — Design

Status: proposed design (brainstorm skipped per operator instruction "go ahead and just start"; choices below marked **[call]** are the executor's, made on the operator's one stated priority). Binding authority: this document once approved. Repo state: `main` at `22dcc32` (Plan 1 + Plan 2 merged).

## Intent and Why

`README.md` promises "a self-hosted certificate authority with a web UI." Today the only browser-facing surface is the first-run setup page; every other operation is HTTP-by-hand or CLI. Plan 3 is the operator's daily screen: **issue, inspect, revoke, download — the day-to-day certificate work first; administration only where it cannot be avoided.**

The operator's own words set the priority: **"mostly day-to-day cert work; admin only where it can't be avoided."** Everything below is bent around that line: if a screen or endpoint does not serve the daily loop, it stays out unless leaving it out would break the daily loop.

## Goals

1. The daily loop lives in the browser: see the certificate estate (list, search, filter by status/profile/expiry), inspect one certificate in detail, issue from a pasted CSR or a server-generated key, revoke with a reason, download PEM and chain.
2. Trust-chain service: view roots/intermediates, download the trust chain, see the current CRL and OCSP responder locations.
3. SSO actually works: the operator can configure the OIDC provider **through the product** (Plan 2 shipped the login flow but left the provider table unconfigurable — SSO was dead code in deployment).
4. One-shot pull tokens and service-identity API tokens can be minted from the UI for machines that pull by token.
5. The browser never holds a token: no JWT, refresh token, or API token is ever readable by page JavaScript, and no admin console sprawl distracts from the daily loop.
6. The four correctness gaps parked from Plan 2's whole-branch review get their minimum fix *in this plan* where the daily loop touches them (tenant resolution at login, setup-leaf SAN validation, rate-limit placement, and the OIDC-config API surface — the largest).

## Non-Goals

- ACME server (Plan 4's scope).
- Multi-tenant administration: tenant create/delete UI, tenant switching, per-tenant theming. v1 stays single-tenant-by-default in UX (the API's tenant concept remains, but the UI targets the setup tenant).
- Certificate renewal automation, expiry notifications/alerts, email/webhook integration.
- Import/export beyond PEM/chain download (no bulk CSV, no PKCS#12 export in v1).
- A general admin console: no tenant CRUD screens, no audit-log search beyond date/status filter, no dark-mode/visual polish beyond a clean usable baseline.
- Sweeping the 23 deferred minors: only the explicit list in "Backend work" rides along.

## Anti-Goals (failure even if every feature works)

- **Tokens in JS**: storing any bearer, JWT, refresh, or API token in `localStorage`, `sessionStorage`, or a cookie JavaScript can read.
- **Second trust boundary**: the browser talking to ws-api directly, or ws-web granting the SPA any privilege humans don't have.
- **Admin sprawl**: a UI whose first screen is user management — the daily loop must be the front door.
- **Client-side cryptography**: browsers generating keys or performing any CA operation; all key material and signing stay server-side (this is already the API's shape; the UI must not weaken it).

## Constraints

- The browser talks to `ws-web` only; `ws-web` path-proxies `/api/v1/*` to ws-api over the internal compose network; ws-api publishes no ports (Plan 2 Global Constraint, unchanged).
- House code rules: `cargo fmt` clean, `clippy --workspace --all-targets -- -D warnings` clean, no `unwrap()`/`expect()` in library code; serialized DTOs `#[serde(rename_all = "snake_case")]`; short conventional commits, no AI co-author trailers.
- New DB-gated suite (if any) takes advisory key `0x0057_4144_5354_0012` (0003–0011 taken); sweep-first, delete-at-end; migrations ADD-ONLY with `REQUIRED_MIGRATION_COUNT` bumped if needed (none expected in this plan).
- `aws-lc-rs` never enters the graph (ring provider pinned).
- Existing UI precedent: the setup page is server-rendered strings with hostile-input escaping. It stays unchanged.

## Architecture — How It Gets Made

### Stack **[call]**

- Frontend: **React + TypeScript, built by Vite, served as prebuilt static assets by ws-web at `/`** (SPA fallback for all non-`/api` routes: `index.html` + hashed asset files shipped inside the ws-web binary via `include_dir![...]`, so the single-binary/two-modes image contract is untouched). Rationale: the setup page proves server-side strings work for exactly one form; a dashboard's stateful interactivity (filters, modals, issued-once downloads) needs a component layer, and a prebuilt bundle keeps ws-web dependency-light — still only TLS + static files + proxy, no templating engine in the runtime.
- Frontend build is a build-time concern: `wardstone`'s developer flow runs `npm ci && npm run build` in `ui/` (new workspace member folder, NOT a Rust crate) producing `ui/dist/`; ws-web embeds it. CI/dev parity: a small documented dev-server mode (`vite dev` proxying to a local ws-web) so frontend iteration does not require rebuilds.
- State: no new state layer beyond the server's. TanStack Query or plain fetch hooks **[builder's call]** — the plan's task list will pick; nothing client-side owns truth.

### Session and the token boundary — the key security choice **[call]**

The SPA calls the same `/api/v1` surface as any API client, but ws-web stops being a dumb proxy for the three auth endpoints:

1. **Relay, not in-process** **[call]**: ws-web reaches login/OIDC-exchange by HTTP to ws-api over the internal network — the same proxy pattern every other `/api/v1` call uses. The two processes stay independently restartable (the setup self-exit contract depends on that), login/OIDC state (JWT keys, secret-encryption key, OIDC CSRF-state store) stays local to the ws-api process it already lives in, and only the *session presentation layer* is ws-web's. The OIDC provider's `redirect_uri` points at **ws-web's public callback route**; ws-web relays the callback to ws-api, whose CSRF state round-trips through the browser untouched.
2. **Login**: the SPA POSTs `POST /auth/ui/login` (a ws-web-owned route that relays to ws-api's login/OIDC-exchange). On success ws-web sets `wardstone_session` — an `HttpOnly`, `Secure`, `SameSite=Lax` cookie carrying the **refresh token only**, plus a short-lived *server-side* in-memory access-token cache keyed by the cookie's ID. The response body carries **no token material** — who the user is and their role, nothing else.
3. **Every proxied request**: ws-web injects `Authorization: Bearer <access>` from its in-memory cache before forwarding. On expiry it mints a fresh access token server-side using the cookie's refresh token through ws-auth's rotation semantics and **re-sets the cookie with the rotated replacement** before transparently retrying the proxied request once.
4. **Rotation is serialized per session** **[call]**: refresh rotation is one-shot (the presented token dies when used), so two concurrent expired-access probes could race and one — holding a now-revoked token — would die into a spurious 401 ("random logout" in the second tab). ws-web keeps a per-session lock (keyed by cookie/session id) around the mint-and-set-cookie step, so concurrent requests await one rotation; losers read the fresh cache, never the dead token. The session is **sliding**: rotation restarts the refresh-token window (existing ws-auth semantics), so a session lives exactly as long as it is used at least once per the refresh-token TTL, and dies by inactivity — never by an absolute wall-clock cap.
5. **Logout**: ws-web revokes the refresh token (existing revoke route), clears the cookie, drops the cache. Logout-all is the existing all-devices revoke, exposed as a button.
6. **CSRF posture**: the cookie is `SameSite=Lax` and ws-web only ever *injects* Authorization server-side; a cross-site form POST to any `/api/v1/*` path arrives without an Authorization header and is rejected by ws-api (401). Mutations additionally require the `X-Requested-With: wardstone-ui` header — checked by ws-web, not the API — as a cheap second layer.
7. **MFA challenge** **[call]**: the login error for a needed second factor gains a structured error code **`mfa_required`** (replacing distinguishable-only-by-message-string); the UI's login form keys its TOTP step off that code. OIDC login is a redirect to the provider's authorization endpoint via ws-web (`GET /auth/ui/oidc/start`) with the callback returning to the UI. Provider config comes from the new API below.
8. Direct `api` mode deployments (no UI) keep the existing token login exactly as shipped; nothing changes for them.

### UI map **[call, first-pass; the plan refines]**

- `/login` — password form (+ TOTP when challenged), OIDC button (hidden until a provider is configured).
- `/` — dashboard: counts (active/revoked/expiring ≤30d), recent audit (last 20), quick links.
- `/certificates` — list: filter by status/profile/issuer, free-text search on SAN/common name/serial; pagination consistent with the API's bounded paging.
- `/certificates/new` — two tabs: **paste CSR** (pick profile → validated server-side; policy refusals shown verbatim), **generate** (pick profile, server creates key + certificate; download PEM + key exactly once with the one-time-download semantics the API already has).
- `/certificates/:id` — parsed summary (issuer, subject, SANs, serial, validity window, key type/size, profile + revision, status), revoke with reason (typed reasons + free-text), download PEM / chain / both.
- `/profiles` — read-only list + detail (key usages, EKUs, SAN patterns, lifetime). Editing happens in admin.
- `/cas` — trust store view: roots/intermediates, download trust chain, CRL current + thisUpdate/nextUpdate, OCSP URLs.
- `/tokens` — machine credentials for the pull flow: mint one-shot token (copy-once display), list/revoke service identities, mint API token (copy-once).
- `/audit` — read-only, newest-first (the API's export contract), date + action filter.
- `/admin` — compact section, only the four things the daily loop needs: **OIDC provider config** (issuer/client-id/secret/callback; test button), **profiles** (create/edit/delete — delete refuses while referenced), **users** (list, role assign, deactivate — plus the role-assignment endpoint that does not exist yet), **service identities** (already reachable via /tokens; admin duplicates nothing).

### Read-side API work — the UI's data needs are backend features **[call]**

The UI map promises list filtering/searching, dashboard counts, audit filters, CRL visibility, and chain download. The shipped API supports none of them (list is bare page/size; audit page/size; CRLs sit in a table with no route; root-trust serves no chain). Because every list is server-paged and clamped, client-side filtering cannot deliver these features — so **they are first-class backend tasks in this plan, not UI work**: filtered/searchable certificate listing (status, profile, issuer, free-text over SAN/common name/serial), dashboard aggregate counts (active/revoked/expiring ≤30d), audit date+action filters, a CRL retrieval route (with `thisUpdate`/`nextUpdate` metadata), and trust-chain assembly+download.

### Backend work this plan (the parked gaps, minimum surface)

1. **OIDC provider config CRUD** (`manage_system`): routes + repository wiring to the *existing* `oidc_config` table and model (Plan 2's OIDC login flow already reads it); validation (issuer URL reachable? no — config validates syntax; a "test discovery" endpoint does the live check); audit rows for changes. Un-deadens SSO.
2. **Profile deletion** (`manage_profiles`): `DELETE /api/v1/profiles/:id`. **[call] Refusal rule:** refuse while ANY certificate row references the profile (active or not — history matters in a CA) with a specific 409 message; delete only unreferenced profiles. Soft-archive is explicitly rejected as unnecessary indirection.
3. **User role assignment + edit** (`manage_users`): `PATCH /api/v1/users/:id` (role, active flag), replacing nothing that exists (create/deactivate remain). Audit row actor/role change included.
4. **Login tenant resolution** (fixes Plan 2 I-2): login/OIDC resolve **the setup tenant explicitly** — the tenant created by first-run setup — via a pinned marker (the setup audit row's tenant, resolved once and cached), not "alphabetically first by name." Single-tenant v1 semantics; per-request tenant selection is a follow-up plan item, documented.
5. **Setup-leaf SAN validation** (fixes I-3): `run_setup` validates `server_hostname` against the built-in `web-server` profile's SAN patterns and fails setup with the specific message (consistent with the issuance path) instead of issuing a certificate its own profile forbids.
6. **Rate limiter placement** (fixes I-1): since ws-web now terminates login, the **[call] auth rate limiter moves to ws-web's `/auth/ui/*` routes** keyed on the real client IP (ws-web sees the browser directly — its serving shape gains `into_make_service_with_connect_info` so `ConnectInfo` exists), with sane defaults; and **ws-api's auth-route GCRA gains an explicit disable switch for UI-fronted deployments** — otherwise the compose deployment funnels every operator's login through ws-api's one loopback bucket (burst 20, refill 1/500ms) and collectively throttles all of them. Compose sets the disable; direct `api`-mode deployments keep the existing behavior unchanged. The Plan 2 shared-bucket caveat then only describes the direct-token path for non-auth routes — documented, not re-shaped in v1.
7. **`setup_completed` audit row** written at the end of `run_setup` (the vocabulary entry Plan 2 never wrote), with the planned details keys.
8. **Revocation reasons become typed** — the worker already parses `revocation_reason` as a `CrlReason` snake_case name, so free text silently drops the reason from published CRLs and OCSP responses **[call]**: the revoke endpoint takes a **typed reason** (the existing CRL reason enum, `as_str` == serde name) stored in `revocation_reason`, plus an optional free-text **`revocation_detail`** in a new nullable column (add-only migration), which the UI presents as "reason (dropdown) + detail (optional)". The worker reads the typed column as the enum it already expects.
9. **Rides-along cheap fixes** from the deferred-minor census (each is one small commit): missing `#[serde(rename_all = "snake_case")]` on the wire DTOs; `pem_from_der` `from_utf8_lossy` cleanup; the `issue_attempt` update-error conflated with retry; login's unknown-user timing (dummy argon2 verify); trailing newlines in `docker/`; README note on why the compose network intentionally has egress (OIDC cannot work with `internal: true`). **Explicitly excluded:** the `internal: true` flag itself (would break OIDC egress — documented never-do).

### What's left to the builder

- Task decomposition, per-task TDD matrices, and the review plan (superpowers:writing-plans next, per the established pipeline).
- The visual system: typography, spacing, and component look **[builder's call]** within the constraint "clean and boring; the data is the design." No UI framework beyond React + a small utility-CSS baseline unless the builder argues one in the plan.
- Exact i18n stance (v1: English strings hardcoded **[call]**), error-toast patterns, table virtualization (not needed at homelab scale).
- The e2e story for the UI layer (the Rust e2e keeps covering the API; UI-level end-to-end via the existing binary boot in tests is a builder decision — the plan will pin one).

## Success

An operator completes issue → inspect → revoke → download without opening a terminal, in under a minute per certificate; SSO login works against a provider configured in the product; a `grep` of the served JS bundle finds no token-shaped strings; admin screens are reachable but never the front door; the browser's devtools Network tab shows zero `Authorization` headers readable by page code.