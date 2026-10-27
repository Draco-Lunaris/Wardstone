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
the master key, the CA key envelopes, the JWT key pair, the
secret-encryption key, and the database credential. **Sealed at
creation**: every key's FIRST write is its passphrase-sealed envelope
(the setup flow mints straight into them), so no plaintext key file ever
exists on the volume — and the database credential, rotated at every
unlock, lives only in `db-credential.envelope`. **The keys are never in
the database and the database never contains private keys**: backing up
the instance means backing up BOTH volumes, and restoring one without
the other does not yield a half-working instance — the mismatch is
refused loudly (by the setup POST when the database holds an install
beside an empty keys volume; by the unlock POST — a fatal 409 — when
a sealed keys volume has no install behind it).

Setup:

```sh
WARDSTONE_SERVER_HOSTNAME=ca.example.test \
docker compose -f docker/compose.yml up -d
```

The `:?` variable is required on purpose: an unset hostname would serve
the setup certificate with a placeholder SAN. There is no database
password variable at all: the bundled database has no password, ever —
its `wardstone` role is born passwordless, and the first-run setup
takes the role over through a peer-authenticated door and disarms the
door at completion (the walkthrough below). A stale non-empty
`WARDSTONE_DB_PASSWORD` left in an upgraded `.env` refuses the boot
loudly — delete the variable and run again (the env table below).

**The operator pre-step (once per host boot).** The bundle's two local
links — the database socket directory and the unlock relay's — are bind
mounts of directories on the docker HOST's `/run` (tmpfs: wiped at every
reboot), and `up` fails loudly when they are absent. Create them before
the first `up` and again after every host reboot:

```sh
install -d -m 0770 -o 70 -g 70 /run/wardstone/pg
install -d -m 0770 -o 10001 -g 10001 /run/wardstone/relay
```

(`70` is the db image's postgres uid — it creates the 0770 database
socket that the Wardstone services traverse via `group_add`; `10001` is
the Wardstone image's fixed uid, which owns the relay directory.)

**The bundle layout: deploy the whole `docker/` directory.** The
deployment is not `compose.yml` alone: the db service bind-mounts the
files under `docker/postgres/` by relative path — the pinned
`pg_hba.conf` (the setup door, the app's SCRAM line, the recovery peer
line) and `pg_ident.conf` (the recovery map), the entrypoint wrapper
`db-entrypoint.sh`, and the init script `init/10-ws-setup-role.sh`
that arms the setup role on a virgin volume. Copy `docker/` as a unit
so `compose.yml` and `postgres/` stay side by side, and run compose
from there. A directory holding only `compose.yml` is the documented
failure shape: `pull && up` does not complain about the missing
`./postgres/*` bind sources — docker auto-creates each absent one as
an EMPTY directory, and the db then fatal-loops (its wrapper and hba
are empty directories, so postgres cannot start; the restart policy
churns the container forever). If a fresh deploy's db never comes
healthy, check the layout first. On a virgin volume `up` completes the
database's init by itself: the wrapper bridges the image's default
socket path onto the shared directory so the stock entrypoint's init
phase runs, and the init script arms the door. The operator's only
first-run acts are the `/run` pre-step above and the setup form below.

First run: browse `https://<host>:8443/` and accept the freshly minted
self-signed setup certificate (its SHA-256 fingerprint is displayed on the
page for out-of-band verification). Fill the setup form — **set the master
passphrase first** (it seals every key on the instance, is stored nowhere,
and cannot be recovered: keep it in your password manager), then the admin
username and password, default domain, optional admin CIDRs, and the
server hostname. There is no database field. The bundled database has no
password at all — setup takes over the role through the peer-authenticated
door and disarms the door at completion. The door is the `ws_setup` role
the init script armed (login, superuser, no password): it authenticates
only by process identity over the shared socket, so during the pre-setup
window the ui's own container identity is the door's key — no password can
open it, no other uid passes it, and the accepted bound is that the door
grants a subset of what the same uid receives seconds later (it is the
container you are typing the master passphrase and the admin password
into). On commit the flow mints a fresh random database credential, takes
the `wardstone` role over through the door, and seals that one under the
master passphrase; the completion tail then disarms the door (`ws_setup`
becomes unable to start a session and stays that way until the recovery
runbook re-arms it). A successful
POST answers
`{"status": "ok", "resume": true}`: every key has been minted straight
into its passphrase-sealed envelope (`master.envelope` written LAST — it
is the sealed marker), the database credential is rotated under the same
passphrase, and the ui **resumes in place** — the listener swaps
onto the CA-issued `web-server` leaf over the same 8443 port, no restart,
no re-typing. The api process comes up through the same commit (the ui
relays the unlock to it once). `POST /setup` returns 404 from then on (the
setup routes unmount once a tenant exists), and every later boot starts
on the unlock page: enter the master passphrase and the instance resumes.

**The container-uid contract: no `userns-remap`.** The bundle's peer
authentication — the unlock relay's, and now the setup door's — assumes
a container's uid IS the host's uid: the host-side `/run` directories
are owned by `70` and `10001` exactly as the pre-step creates them, and
the door resolves the connecting process by that same uid. A daemon with
`userns-remap` enabled breaks the assumption — the unlock relay already
required the same — and the bundle does not support it.

### External (your database, optional own reverse proxy)

The External variant is the same file with the Postgres service removed and
`DATABASE_URL` pointed at an existing database:

1. Copy `compose.yml` to a private file (e.g. `compose.external.yml`).
2. Remove the whole `db` service block, the `wardstone-pgdata` volume
   definition, both `db:` entries under `depends_on`, and the
   `wardstone-pgdata:` entry under `volumes:`.
3. Replace both services' `DATABASE_URL` with your own connection URL —
   **password-less in BOTH services** (a URL carrying a password is
   refused at boot: the credential lives only in the sealed keys volume
   or, on a fresh install, the setup page's database-password field).
   A TCP URL is an external link and MUST carry BOTH
   `sslmode=verify-full` and `sslrootcert=<path>` — mount your CA
   bundle read-only and point the path at its in-container location;
   the boot refuses a half-verified TLS link and names whichever
   protection is missing. A unix-socket URL (database on the same
   host) is a local link and needs no TLS keys. The role, database,
   and extensions Wardstone requires are created by the migrations on
   first connect, not by an image entrypoint; set the login role's
   password with your own superuser — a SCRAM verifier from
   `wardstone db-verifier` works and keeps plaintext out of your shell
   history, with the printed password then typed at the setup page.
4. `WARDSTONE_DB_PASSWORD` stops being a required variable the moment
   the db service is gone — it was only the bundled Postgres' bootstrap
   password. An external `.env` keeps it only as the home of the
   verifier (below).

**The database password: prefer a SCRAM verifier.** A plaintext password
works, but the recommended bootstrap is the verifier minted by
`wardstone db-verifier` — nothing plaintext is stored (Postgres keeps
the verifier as-is; only the password behind it logs in). The mint
initializes the same protected arena the servers use, so give it the
same memlock headroom:

```sh
docker run --rm --ulimit memlock=536870912:536870912 \
  ${WARDSTONE_IMAGE:-wardstone:latest} wardstone db-verifier
```

prints a fresh 52-character `password:`, its `verifier:`, and the hint.
Put ONLY the verifier in `.env`, single-quoted as `WARDSTONE_DB_PASSWORD`
(verifiers carry `$`, `=`, and `/`, which compose would otherwise
interpolate — never the plaintext). The `password:` value is what the
setup page's database-password field takes on first run.
`--password-stdin` hashes a password you choose (reads one line from
stdin, prints only the verifier).

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
   `wardstone` processes then write the volume's files themselves: every
   file is a passphrase-sealed envelope written by the setup flow, the
   per-unlock credential rotation (including the recovery runbook's
   re-seal), the admin surface's passphrase change and its completion
   rewrap, or a root/sub-CA created through the unlocked api, all
   owned by the container user — never world-readable, never
   root-owned, and never a plaintext key.
3. `wardstone-keys` is a named volume mounted at `/var/lib/wardstone/keys`
   on **both** Wardstone services. Before setup the volume is
   legitimately EMPTY — the first-run boot touches neither database nor
   volume (the setup page is served over a RAM-only certificate, and the
   setup POST is the first thing that ever dials the database) — and at
   the setup commit every key appears straight as its sealed envelope,
   `master.envelope` written last as the sealed marker. On a sealed
   volume the JWT pair is only ever READ: the `api` loads it from
   `jwt-keys.envelope` after its own unlock, and a missing envelope is a
   loud refusal, never a mint (see the JWT section below).

## Environment contract

Per service (the binary's contract, one variable at a time):

| Variable                    | `ws-web` | `ws-api` | Meaning |
|-----------------------------|----------|----------|---------|
| `DATABASE_URL`              | set (**password-less**) | set (**password-less**) | The Postgres connection URL — the bundled form is the shared-socket link `postgres://wardstone@%2Frun%2Fwardstone%2Fpg/wardstone` (the db binds no TCP at all). A password in EITHER URL is refused at boot; a TCP (external) URL must carry `sslmode=verify-full` + `sslrootcert`. On a fresh External install the setup page's database-password field supplies the credential (the bundled form has no field — the peer door does the takeover); after setup every credential comes from the db-credential envelope at unlock |
| `WARDSTONE_KEYS_DIR`        | `/var/lib/wardstone/keys` | same | The keystore directory (shared volume) |
| `WARDSTONE_SERVER_HOSTNAME` | required | required | The setup certificate's SAN; also the API's domain context |
| `WARDSTONE_API_URL`         | `http://ws-api:8080` | ignored | The `ui` proxy's target |
| `WARDSTONE_RELAY_SOCKET`    | `/run/wardstone/relay/relay.sock` (dials) | same (binds) | The unlock relay's Unix socket: the ui relays the master passphrase to the api over it once per unlock; the api binds it mode 0600 and admits only its own uid (`SO_PEERCRED`) — no network listener carries the relay |
| `WARDSTONE_BIND`            | `0.0.0.0:8443` | `0.0.0.0:8080` | The listen address (one variable, per-service values) |
| `WARDSTONE_PUBLIC_URL`      | ignored | optional | The absolute URL base every ACME (RFC 8555) URL is built from — unset, the ACME routes answer `serverInternal` problem documents |
| `WARDSTONE_ACME_ACCOUNT_LIMIT_DISABLED` | ignored | optional switch | `1`/`true` disables the ACME per-account rate limiter; any other non-blank value fails the boot |

Compose-level:

| Variable                  | Required | Meaning |
|---------------------------|----------|---------|
| `WARDSTONE_SERVER_HOSTNAME` | yes (`:?`) | Interpolated into both services |
| `WARDSTONE_DB_PASSWORD`     | obsolete (Bundled) | The bundled database has no password — setup takes over the role through the peer-authenticated door, so ANY non-empty value is refused loudly at boot: delete the variable from `.env` and run again. Pre-2026-10-27 bundles used it as the bundled Postgres' bootstrap password, so an upgraded `.env` may still carry it. An External deployment keeps the variable as the home of its SCRAM verifier (the External section) |
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

**The db log's healthcheck probe lines are expected noise.** That
auth-independent healthcheck dials the shared socket on a schedule and
carries no credential, so its probes leave refused-connection lines in
the database's log: the periodic `FATAL: the database system is starting
up` refusals while the server boots, and the auth-refused probe lines
once it is up. They are noise from a working healthcheck, not a fault —
do not "fix" them by handing the healthcheck a credential; the design
is credential-free on purpose.

**An interrupted setup** — the seal and the install commit together:
the ONE setup transaction (tenant, root CA, admin, profiles, the serving
leaf) commits only after `master.envelope` — written LAST — lands, so a
crash before the marker leaves NO tenant (the transaction rolls back;
only overwritable strays remain) and the next boot serves the setup page
again. A crash after the marker but before the commit is the one torn
state: a sealed volume whose database holds no tenant, and the unlock
POST answers it with the fatal refusal (`setup was interrupted after
sealing — remove both volumes and run setup again`) rather than
half-serve. The reverse mismatch is refused by the setup POST itself
(`the database already holds an install but the keys volume is empty —
restore the matching keys volume, or remove both volumes and run setup
again`). The credential takeover's crash windows are the variant's:
the bundled arm rotates the role BEFORE the tenant work, so a crash
between the takeover and the commit leaves only overwritable strays —
the door is still armed, the next boot serves the setup page again, and
the re-run completes passwordlessly through it, no wipe needed. The
bundled completion tail then disarms the door, so a crash after the
commit but before the disarm leaves a WORKING instance with the door
armed — run the bundled recovery runbook's disarm command once (below).
The external arm keeps its order (the typed credential's rotation
follows the commit), so a crash after the commit but before the
credential rotation remains the external variant's one deliberately
healable window: the unlock page grows its database-password field and
the external runbook below re-seals. There
is nothing to keep on an instance that never finished setup: remove both
volumes (`docker compose -f docker/compose.yml down -v`) and run setup
again.

**Changing the master passphrase** — in the unlocked UI's admin section:
enter the current passphrase and the new one; every envelope re-wraps
under a fresh key and the change is audited. A partially-completed change
(the process dies mid-rotation) leaves envelopes across two generations
that BOTH open with THEIR passphrases — the next unlock offers to finish
the change; nothing sits in a silent mixed state.

**Lost database credential (the recovery runbook).** The database
credential is random, rotated at every unlock, and shown nowhere — but its
envelope is the ONE file on the keys volume whose absence the unlock flow
is BUILT to heal: the unlock page detects the absent
`db-credential.envelope` and offers the variant's heal — the External
variant grows a database-password field (the typed value connects and
rotates once, nothing stored), the bundled variant grows NO field and
names this runbook instead. No `.env` edit is part of this runbook. Bring
the instance to its locked page (it is already there after any restart;
`docker compose -f docker/compose.yml restart ws-web ws-api` if it is
not), then follow your variant.

**Bundled — the door does the takeover.** The unlock page's bundled
lede names this runbook; there is no password field, because the
instance re-seals the credential itself through the setup door:

1. Re-arm the door — one command covers both shapes it can be found
   in: a fresh cluster, where the role exists but a finished setup
   disarmed it, and an upgraded cluster from before 2026-10-27, where
   the init script that creates the role never ran:
   `docker compose -f docker/compose.yml exec -T -u postgres db psql -h /run/wardstone/pg -U wardstone -d postgres -c "SELECT 'CREATE ROLE ws_setup LOGIN SUPERUSER' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ws_setup')\gexec" -c "ALTER ROLE ws_setup LOGIN"`
   The `-h /run/wardstone/pg` is load-bearing: the db binds no TCP and
   its socket lives only at the pinned directory. `exec -u postgres`
   runs psql as the db container's `postgres` system user, which the
   pinned ident map peer-resolves onto the `wardstone` role — no
   password is involved anywhere in the command.
2. Reload the unlock page — the bundled lede is there, no password
   field — and unlock with the master passphrase. The ui re-enters
   through the re-armed door, rotates the role onto a fresh random
   credential, re-seals the envelope, and closes the door again; the
   re-arm was single-use. Unlocking before the re-arm answers with the
   same refusal naming this runbook's re-arm step — the instance stays
   up and sealed; re-arm and unlock again.

The door's disarm is its own command, for the loud refusals that name
it (setup or a heal reporting the door did not close — both leave a
working instance with the door armed):

`docker compose -f docker/compose.yml exec -T -u postgres db psql -h /run/wardstone/pg -U wardstone -d postgres -c "ALTER ROLE ws_setup NOLOGIN"`

**External — the typed re-seal.** The unlock page grows its
database-password field; the typed value is used once to connect and
rotate, and nothing is stored:

1. Mint fresh login material — `docker run --rm --ulimit
   memlock=536870912:536870912 ${WARDSTONE_IMAGE:-wardstone:latest}
   wardstone db-verifier` prints a 52-character password and its SCRAM
   verifier (or pipe a password you choose into
   `wardstone db-verifier --password-stdin` and get only the verifier).
2. Install the VERIFIER on the database side — your own superuser runs
   the ALTER. Postgres stores the verifier as-is; the plaintext behind
   it is what logs in.
3. Remove the stale envelope from the keys volume — `docker run --rm -v
   wardstone-keys:/keys alpine rm /keys/db-credential.envelope` (skip
   this if it is already gone: the field appears for an absent
   envelope).
4. Reload the unlock page (the database-password field is there now) and
   unlock with the master passphrase plus the minted password.

Either way the ui connects with the fresh credential exactly once,
rotates the role to a fresh random credential, and seals it under the
master passphrase; the api then rotates it again at its own unlock,
exactly as on a healthy volume — what the runbook supplied was
single-use and is already retired (the external typed password, or the
bundled re-arm, now closed behind the heal). No other key material is
touched and the master passphrase is unchanged.

**Lost or broken JWT key material is a hard stop — there is no
in-product re-key.** The processes deliberately do NOT heal it by
re-keying on their own, because a silent re-key would invalidate every
outstanding token while looking perfectly normal. On a sealed volume
(every install after setup) the pair lives only in `jwt-keys.envelope`,
and the api's unlock REFUSES a missing one — a sealed volume always
carries it (setup writes it before the sealed marker) — with the typed
`jwt_envelope_missing` refusal. On a consistent volume it is checked
BEFORE any secret is unwrapped or the database is touched, so a failed
attempt leaves zero side effects (no rotation ran, nothing re-sealed);
the one pre-gate write is the passphrase-change completion, which
re-wraps a half-finished volume's present envelopes first, and the
refusal comes after that re-wrap. A corrupt envelope fails the
unlock loudly the same way. Recovery, documented and loud:

1. Restore the keys volume from a backup of the sealed instance —
   restoring BOTH volumes together (the same backup) is a consistent
   pair and unlocks as-is; restoring the keys volume alone leaves its
   `db-credential.envelope` older than the database role's current
   password (every unlock rotates it), so run the database-credential
   recovery runbook above once, then unlock.
2. With no backup of the keys volume there is no recovery: wipe BOTH
   volumes (`docker compose -f docker/compose.yml down -v`) and run
   setup again — a fresh key pair, a fresh root CA, and re-import of
   the new root everywhere it was trusted.

Either way **every outstanding access and refresh token is invalid**;
every user must log in again.

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
docker compose -f docker/compose.yml config --quiet
```

(On hosts without docker, this bundle was validated structurally — YAML
parse plus a services/volumes/ports contract check.)
