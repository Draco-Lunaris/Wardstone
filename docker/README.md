# Wardstone — the production compose bundle

`compose.yml` in this directory is the production deployment: one Wardstone
image running **two** deliberately separate processes plus a Postgres
service.

| Service   | Command          | Purpose                                                     | LAN exposure          |
|-----------|------------------|-------------------------------------------------------------|-----------------------|
| `ws-web`  | `wardstone ui`   | The TLS front door: first-run setup page, the unlock page while sealed, CA-issued leaf afterwards, `/api/v1` proxy in every phase | **the only published port** (`8443`) |
| `ws-api`  | `wardstone api`  | The REST surface, plain HTTP, internal network only          | none (Global Constraint) |
| `db`      | Postgres 18      | The bundled database (Bundled variant only)                  | none                  |

The two Wardstone services are separate processes on purpose: independently
restartable. The API keeps serving while the UI restarts onto a re-issued
leaf; the browser never talks to `ws-api` directly — `ws-web` path-proxies
`/api/v1/*` to it over the internal compose network (`WARDSTONE_API_URL`,
default `http://ws-api:8080`, spelled out in the file).

## The two variants

### Bundled (the file as written)

Wardstone plus its own Postgres. The database volume (`wardstone-pgdata`)
holds the CA's certificates, CRLs, OCSP responses, audit log, tenants, and
users; the keys volume (`wardstone-keys`) holds the cryptographic material —
the master key, the CA key envelopes, the setup slot, the JWT key pair, and
the secret-encryption key. Once setup completes, every one of those lives
on the volume ONLY as a passphrase-sealed envelope (sealed at rest; the
plaintext originals are deleted). **The keys are never in the database and
the database never contains private keys**: backing up the instance means
backing up BOTH volumes, and restoring one without the other yields an
instance that boots but cannot sign (or one that is meaningless on its
own).

Setup:

```sh
WARDSTONE_SERVER_HOSTNAME=ca.example.test \
WARDSTONE_DB_PASSWORD=<strong password> \
docker compose -f docker/compose.yml up -d
```

Both `:?` variables are required on purpose: an unset hostname would serve
the setup certificate with a placeholder SAN, and an unset password would
make the bundled Postgres guessable.

First run: browse `https://<host>:8443/` and accept the freshly minted
self-signed setup certificate (its SHA-256 fingerprint is displayed on the
page for out-of-band verification). Fill the setup form — **set the master
passphrase first** (it seals every key on the instance, is stored nowhere,
and cannot be recovered: keep it in your password manager), then the admin
username and password, default domain, optional admin CIDRs, and the
server hostname. A successful POST answers
`{"status": "ok", "resume": true}`: the conversion wraps every key file
into a passphrase-sealed envelope, rotates the database credential under
the same passphrase, and the ui **resumes in place** — the listener swaps
onto the CA-issued `web-server` leaf over the same 8443 port, no restart,
no re-typing. The api process comes up through the same commit (the ui
relays the unlock to it once). `POST /setup` returns 404 from then on (the
setup routes unmount once a tenant exists), and every later boot starts
on the unlock page: enter the master passphrase and the instance resumes.

### External (your database, optional own reverse proxy)

The External variant is the same file with the Postgres service removed and
`DATABASE_URL` pointed at an existing database:

1. Copy `compose.yml` to a private file (e.g. `compose.external.yml`).
2. Remove the whole `db` service block, the `wardstone-pgdata` volume
   definition, both `db:` entries under `depends_on`, and the
   `wardstone-pgdata:` entry under `volumes:`.
3. Replace both services' `DATABASE_URL` with your own connection URL —
   and keep the sealed-at-rest asymmetry the shipped file models: the
   **ui's** URL carries a login role and password (the bootstrap
   credential for the seeding boot; setup's conversion rotates the role's
   password away), while the **api's** URL stays password-less (role and
   host only). A password-carrying api URL is not a convenience: on a
   fresh volume it flips the api onto the legacy unsealed boot (the
   pre-sealing behavior), which is exactly what the sealed model retires.
   The role, database, and extensions Wardstone requires are created by
   the migrations on first connect, not by an image entrypoint.
4. Drop `WARDSTONE_DB_PASSWORD` from the required variables — it was only
   the bundled Postgres' password.

An External deployment may also front `ws-api` directly behind its own
reverse proxy instead of stopping at `ws-web`. Two caveats belong to that
choice, spelled out because they are easy to miss:

- `ws-api` serves **plain HTTP** by design (TLS is the front door's job).
  A proxy fronting it MUST terminate or provide TLS itself, and the
  connection between proxy and `ws-api` crosses networks that see plaintext.
- Wardstone's rate limiting keys on the **direct TCP peer address** (axum's
  `ConnectInfo`); there is no `X-Forwarded-For` trust and none is planned.
  Behind an L7 proxy that re-origins connections, every client collapses
  onto the proxy's address — the limiter still protects the process, but it
  is per-proxy, not per-client. A transparent TCP path (e.g. L4 proxying or
  a proxy joining the compose `internal` network with port forwarding that
  preserves the source address) keeps per-client limiting intact.

To front `ws-api` directly, add a `ports:` block (or attach your proxy's
network) in **your copy** of the file — the shipped file publishes nothing
for it, deliberately.

## The UI and SSO login

**Login.** Browse `https://<host>:8443/` and sign in with the admin account.
The SPA posts `/auth/ui/login` — ws-web's session relay, one of the five
`/auth/ui` routes — which relays ws-api's login, stores the token pair
SERVER-side under an opaque `wardstone_session` cookie (HttpOnly; the browser
never sees a token), and answers with the identity. MFA accounts pass a TOTP
step: ws-api's error bodies pass through the relay untouched, so the UI's
TOTP prompt keys on the same machine-readable code. `POST /auth/ui/logout`
ends the session.

**SSO (OIDC) setup.** In the UI's Admin section, SSO provider tab, configure
one provider: provider type, discovery URL, client id, client secret (empty
string = public client), scopes, and the redirect URI. The redirect URI is
always the PUBLIC callback on ws-web:

    https://<host>/auth/ui/oidc/<provider>/callback

ws-api mints the authorization URL (fetching the IdP's discovery document and
minting the CSRF state) against that registered redirect, and the
`/auth/ui/oidc/{provider}/callback` relay completes the exchange into a
session. Before committing values to the IdP, the discovery-test route
probes a SAVED configuration or an override payload. After configuration,
the login page reads `GET /auth/ui/config`, which relays ws-api's PUBLIC
`GET /api/v1/oidc/config/status` flag (is SSO configured, and for which
provider) — that is what renders the "Sign in with SSO" button before any
session exists; the flag is readable without credentials by design.

**Rate-limiter placement.** Per-client-IP GCRA covers the credential
surfaces the public edge serves, with the house defaults (one credit per
500 ms, burst 20 per IP — the same burst/refill vocabulary in every
variant):

- **Bundled UI-fronted deployment** (`wardstone ui` publishes the only
  port): ws-web limits BOTH its `/auth/ui/*` relay routes AND the proxied
  credential pair `POST /api/v1/auth/login` and `POST /api/v1/auth/refresh`
  AND the proxied enrollment endpoint `POST /acme/<tenant>/new-account` —
  so password spraying, TOTP guessing, and enrollment abuse stay
  per-client limited even though ws-api's own per-IP limiter is off
  (below). Other `/api/v1/*` paths — the machine-token (`ws_at_`/`ws_ot_`)
  flows — are NOT limited at this edge, and neither is the rest of
  `/acme/*` (see "The ACME surface" below for who limits THOSE).
- **Direct API deployment** (clients, or a transparent-TCP proxy, hit
  `ws-api` itself): ws-api's own auth-route GCRA (login, refresh, OIDC
  start/callback) applies.

ws-api's limiter keys on its direct TCP peer; in a UI-fronted deployment
every proxied login arrives from ONE loopback IP, so that limiter would
throttle ALL operators collectively. The bundled compose therefore sets
`WARDSTONE_AUTH_RATE_LIMIT_DISABLED=true` on the `api` service — an
`api`-mode switch only (the `ui` mode never reads it, and ws-web's
front-door limiter stays on regardless of it). Where BOTH limiters run
(a `ui` deployment that leaves the switch off), the effective per-client
limit is the tighter of the two buckets — defense in depth, never a gap.
Only where clients hit ws-api directly (an External variant fronting it
with a transparent-TCP proxy) is the switch meaningful at all. The ACME
per-account limiter is a SEPARATE knob (`WARDSTONE_ACME_ACCOUNT_LIMIT_DISABLED`)
that the auth switch does not reach: it keys on the ACCOUNT id, which
does not collapse behind the proxy, so it stays armed — ON by default,
in the bundled deployment included.

**Egress: the compose network must NOT be `internal: true`.** ws-api performs
OIDC egress — the discovery fetch and the token exchange are made by the
`api` process over the IdP's public URL. Marking the compose network
`internal: true` would cut that off and break both SSO setup and SSO login.
NEVER apply `internal: true` to this bundle's network.

## The ACME surface (certbot and other RFC 8555 clients)

The front door also exposes ws-api's ACME (RFC 8555) server under `/acme`:
ws-web forwards every `/acme*` request VERBATIM to the api process — the
same path proxying as `/api/v1`, so the ACME response headers
(`Replay-Nonce`, `Location`, `Link`) and the `application/problem+json`
problem bodies cross untouched. There are no cookies and no CSRF marker on
this surface: ACME is JWS machine traffic whose sole authority is the
account key (a request that happens to carry a browser session cookie is
forwarded exactly as sent, never resolved or injected).

**The directory URL** — what certbot's `--server` (or any RFC 8555
client's server URL) takes:

    https://<host>/acme/<tenant>/directory

`<tenant>` is the install's PRIMARY tenant name (the first one created at
setup; a mismatched segment answers one `unknown ACME tenant` 404 problem
document, never a cross-tenant read). Every URL the directory contains is
built ABSOLUTE from `WARDSTONE_PUBLIC_URL` — the value must be the public
URL the ACME client actually dials. The bundled compose derives it as
`https://$WARDSTONE_SERVER_HOSTNAME`, which is correct while the front
door is reached at the standard HTTPS port on that hostname; when certbot
dials a non-standard port (this bundle publishes 8443) or a different
public name, override `WARDSTONE_PUBLIC_URL` to exactly that base.

**TLS trust.** The front door serves the CA-issued `web-server` leaf,
signed by Wardstone's own CA. The machine running certbot must trust THAT
CA (its root certificate in the client's trust store, or leaf pinning), or
the directory fetch fails TLS verification before any ACME exchange
starts.

The root is an **ECDSA P-256 key by default** (setups from 2026-10-23
onward), which every mainstream browser — Chrome, Chromium, Brave, Edge,
Firefox, Safari — verifies once the root is imported. **An Ed25519 root
cannot be trusted by Chromium-family browsers at all**: with the root
imported they fail the chain with `net::ERR_CERT_INVALID` and offer no
bypass (verified live). Setups created before the ECDSA default minted an
Ed25519 root; such an install recovers either by wiping and re-running
setup (fresh volumes, new root, re-import the new root everywhere
including every ACME client's trust store) or, where a wipe is
impossible, by minting an RSA-2048 CA (`POST /api/v1/cas`,
`key_type=rsa2048`) and re-issuing the front door's `web-server` leaf
from it.

**Open enrollment and rate limiting.** Any ACME client that can reach the
front door may enroll: new-account is authorized by the requester's own
JWS key, and issuance stays bounded by server-computed http-01/dns-01
challenge verification — a client-supplied answer is never an input, so
an enrolled key can only win certificates for identifiers it actually
controls. The limiting posture: ws-web runs the per-client-IP GCRA on
`POST /acme/<tenant>/new-account` — the one unauthenticated mutating
endpoint — keyed on the real client address the TLS listener sees; at
THIS edge keying by account identity is impossible (the identity exists
only after the JWS verifies), so every other `/acme*` request forwards
un-limited here. ws-api carries the per-ACCOUNT limiter: every
authenticated ACME POST (new-order, the POST-as-GET reads, challenge
triggers, finalize, revoke-cert, account update, key change) spends one
credit from the account's bucket — keyed on the ACCOUNT ID, which does
NOT collapse behind the proxy, so it works unchanged in every variant:
one credit per 500 ms, burst 20 by default, tuned by the
`WARDSTONE_RATE_LIMIT_*` pair. That limiter's switch is
`WARDSTONE_ACME_ACCOUNT_LIMIT_DISABLED` (only `1`/`true` disable; any
other non-blank value fails the boot loudly) — deliberately NOT the auth
switch above, so disabling the auth limiter never silently unlimits
enrolled accounts. The bundled UI-fronted deployment therefore covers
the ACME surface at BOTH corners: ws-web's per-client GCRA on
enrollment, and ws-api's per-account limiter (ON — this bundle sets
neither `ACME_ACCOUNT_LIMIT_DISABLED` nor per-account envs). The buckets
refill in-process and a restart refills them; the limiters are not a
security boundary — the server-computed challenge verification is.

## The image and the keys volume

`compose.yml` does not build anything: the image named by
`${WARDSTONE_IMAGE:-wardstone:latest}` is supplied by the release flow. The
release flow IS in this repo now: `docker/Dockerfile` carries the image
definition, and CI (`.github/workflows/docker-image.yml`) builds and pushes
`ghcr.io/draco-lunaris/wardstone` on every push to `main` (`latest` + a
sha tag). A deploy therefore needs only `docker compose pull && up` with
`WARDSTONE_IMAGE=ghcr.io/draco-lunaris/wardstone:latest` in `.env` — the
pull requires `docker login ghcr.io` (or package visibility set to
public). The bundle's contract with
that image is:

1. The image declares **no ENTRYPOINT**; the `wardstone` binary is installed
   on the container's PATH, and each service overrides the WHOLE command —
   both words — via `command: ["wardstone", "ui"]` /
   `command: ["wardstone", "api"]`. The missing-entrypoint half of the
   contract is load-bearing, not style: an image with
   `ENTRYPOINT ["/usr/local/bin/wardstone"]` would let compose APPEND the
   command list, making argv `wardstone wardstone ui`, and the binary's mode
   dispatch (exact match on `argv[1]`) would fail the boot into a usage
   error — i.e. a restart-policy crash loop.
2. The image runs as a **non-root** user (`wardstone`, a fixed uid), and
   that user **owns `/var/lib/wardstone/keys`** in the image, so an empty
   named volume first mounted there inherits the correct ownership. The
   `wardstone` process then writes its key files itself: the JWT signing
   key with mode **0600**, the keystore envelopes likewise, all owned by
   the container user — never world-readable, never root-owned.
3. `wardstone-keys` is a named volume mounted at `/var/lib/wardstone/keys`
   on **both** Wardstone services. Whichever process boots first finds a
   complete volume: on a legacy (pre-sealing) volume the `ui` process
   creates the JWT key pair if absent, and on a sealed volume the pair
   mints at the FIRST UNLOCK — straight into its envelope, so plaintext
   never exists (the `api` process reads the pair for token signing after
   its own unlock).

## Environment contract

Per service (the binary's contract, one variable at a time):

| Variable                    | `ws-web` | `ws-api` | Meaning |
|-----------------------------|----------|----------|---------|
| `DATABASE_URL`              | set (role + bootstrap password) | set (**password-less**) | The Postgres connection URL. The ui's password is the bootstrap credential, read only by the seeding boot; the api's URL names the role to authenticate as, and every credential it uses comes from the db-credential envelope at unlock |
| `WARDSTONE_KEYS_DIR`        | `/var/lib/wardstone/keys` | same | The keystore directory (shared volume) |
| `WARDSTONE_SERVER_HOSTNAME` | required | required | The setup certificate's SAN; also the API's domain context |
| `WARDSTONE_API_URL`         | `http://ws-api:8080` | ignored | The `ui` proxy's target |
| `WARDSTONE_BIND`            | `0.0.0.0:8443` | `0.0.0.0:8080` | The listen address (one variable, per-service values) |
| `WARDSTONE_PUBLIC_URL`      | ignored | optional | The absolute URL base every ACME (RFC 8555) URL is built from — unset, the ACME routes answer `serverInternal` problem documents |
| `WARDSTONE_ACME_ACCOUNT_LIMIT_DISABLED` | ignored | optional switch | `1`/`true` disables the ACME per-account rate limiter; any other non-blank value fails the boot |

Compose-level:

| Variable                  | Required | Meaning |
|---------------------------|----------|---------|
| `WARDSTONE_SERVER_HOSTNAME` | yes (`:?`) | Interpolated into both services |
| `WARDSTONE_DB_PASSWORD`     | yes (`:?`, Bundled only) | The bundled Postgres' **bootstrap** password: initializes the database and seeds the ui's seeding boot. Setup's conversion rotates the `wardstone` role's password under the master passphrase, retiring this value as a login credential for good (the db's own healthcheck is auth-independent for exactly this reason) — it remains required only because the bundled `db` service and the fresh-install ui are built from it |
| `WARDSTONE_IMAGE`           | no (default `wardstone:latest`) | Override the image; the e2e harness points it at a local build |
| `WARDSTONE_PUBLIC_URL`      | no (default `https://$WARDSTONE_SERVER_HOSTNAME`) | The ACME URL base; override when certbot reaches the front door on a non-standard port or a different public name |

## Operations notes

**The `ws-web` service MUST keep `restart: unless-stopped`.** With the
sealed-at-rest model the ui process does NOT self-exit: setup completes
with an in-process hand-off (`{"resume": true}` — the listener swaps onto
the CA-issued leaf via the hot-reload path), and every container restart
lands the instance on the **locked page** awaiting the operator's master
passphrase. A locked instance is a correct state, not a crash — its
healthcheck stays 200 (liveness) while gated. The restart policy is what
carries the leaf re-issue flow and what brings the stack back after host
reboots (where it waits locked, as designed: enter the master passphrase
to resume).

**Locked instances are a state, not a failure.** After any container
restart the instance serves the locked page until the operator enters the
master passphrase. The `ws-web`/`ws-api` healthchecks stay 200 while
locked (liveness, with the current state in the response), so the restart
policy never churns a sealed instance; the database's own healthcheck is
`pg_isready` (auth-independent — the rotated credential is none of the
healthcheck's business).

**Converting an existing (pre-sealing) install** — the first boot after
upgrading shows the initialization page instead of the unlock page when
plaintext key files are found: set your master passphrase there, and the
conversion wraps every plaintext file into an envelope **and deletes the
plaintext originals**. Verify before you convert that your backups of the
keys volume are current: after conversion those backups open nothing
until they are made again *from the unlocked instance* — inert backups are
the feature, but a passphrase lost with no unlocked backup is a
re-issued-identities restart, not a restored one.

**Changing the master passphrase** — in the unlocked UI's admin section:
enter the current passphrase and the new one; every envelope re-wraps
under a fresh key and the change is audited. A partially-completed change
(the process dies mid-rotation) leaves envelopes across two generations
that BOTH open with THEIR passphrases — the next unlock offers to finish
the change; nothing sits in a silent mixed state.

**Lost or broken JWT key material is a hard stop, with a recovery that costs
every session.** The processes deliberately do NOT heal it by re-keying on
their own, because a silent re-key would invalidate every outstanding
token while looking perfectly normal.

- **On a sealed volume** (every install after setup): the pair lives only
  in `jwt-keys.envelope`. A corrupt envelope fails the unlock loudly —
  the full surface never comes up, and anything the attempt already
  completed (the per-unlock DB-credential rotation) stays committed and
  consistent for the next unlock to re-read. Recovery, documented and
  loud:
  1. `docker compose -f docker/compose.yml stop ws-web ws-api`
  2. Remove the envelope from the keys volume
     (`docker run --rm -v wardstone-keys:/keys alpine rm /keys/jwt-keys.envelope`)
  3. `docker compose -f docker/compose.yml up -d`, then unlock.

  The next unlock mints a fresh pair **straight into a new envelope** —
  plaintext never exists on the volume — and **every outstanding access
  and refresh token is now invalid**; every user must log in again.
- **On a legacy (pre-conversion) volume**: the pair is still
  `jwt-signing-key.pem` / `jwt-verify-key.pem`, validated as a *pair* at
  load — a mixed one fails the boot with this recovery hint instead of
  issuing tokens nothing can verify. Remove BOTH pem files with the
  services stopped and restart; both are re-created on the next boot with
  the same every-token-invalid cost. (Converting the install retires this
  path: the conversion deletes the pems and the envelope world above
  takes over.)

**Rate limiting is always-on across the credential surfaces, keyed per
client IP, tunable — but the coverage is never optional.** The `api`
process limits its public auth routes (login, refresh, OIDC
start/callback) with GCRA: one credit per 500 ms, burst 20 per IP — the
house defaults, applied without any configuration. In the bundled
UI-fronted deployment the compose switches THAT limiter off
(`WARDSTONE_AUTH_RATE_LIMIT_DISABLED=true` on the `api` service) because
every proxied login arrives from one loopback IP — and the front door
(`ws-web`) then carries the per-client GCRA instead, on `/auth/ui/*` AND
the proxied `POST /api/v1/auth/login` / `/auth/refresh` pair. The
environment overrides `WARDSTONE_RATE_LIMIT_PER_MILLIS` and
`WARDSTONE_RATE_LIMIT_BURST` tune both limiters; the shipped bundle
intentionally sets neither. A zero or unparsable value is a **boot
failure**, not a silent un-limited listener.

**Admin CIDRs (v1 status).** The setup form's admin CIDR list takes its
effect through the two built-in certificate profiles created during setup:
the CIDRs become allowed SAN patterns of the `web-server` /
`web-server-ecdsa` profile revisions, persisted in the database, and the API
enforces them at issuance time. The `api` process itself boots with an empty
in-process `admin_cidrs` value: no ws-api code in v1 reads it, so there is
nothing for the ui→api handoff to deliver yet. If a future plan gives the
API a runtime reader for that field (e.g. a network allow-check), the
handoff lands with it — likely as an env or DB-backed value, decided then.

**Restart policies:** every service in the bundle is `unless-stopped`. That
is required on `ws-web` (above) and is the correct production posture on
`ws-api` and `db` — a boot failure (e.g. an unparsable override, the typed
JWT error above) shows up as a visible crash loop with the reason on stderr
under `docker compose logs`, not as a silently unstarted service.

**Never run `down -v` against the production bundle.** It deletes
`wardstone-pgdata` (the CA's records) along with everything else. `down`
alone keeps both named volumes; `compose.yml`'s volumes are fixed names
(`wardstone-keys`, `wardstone-pgdata`) so redeploys reattach to them.

## Validation

`docker compose config` is the intended check:

```sh
WARDSTONE_SERVER_HOSTNAME=ca.example.test \
WARDSTONE_DB_PASSWORD=x \
docker compose -f docker/compose.yml config --quiet
```

(On hosts without docker, this bundle was validated structurally — YAML
parse plus a services/volumes/ports contract check; see Task 13's report
for the exact evidence.)
