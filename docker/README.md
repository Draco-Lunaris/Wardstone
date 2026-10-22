# Wardstone — the production compose bundle

`compose.yml` in this directory is the production deployment: one Wardstone
image running **two** deliberately separate processes plus a Postgres
service.

| Service   | Command          | Purpose                                                     | LAN exposure          |
|-----------|------------------|-------------------------------------------------------------|-----------------------|
| `ws-web`  | `wardstone ui`   | The TLS front door: first-run setup page, CA-issued leaf afterwards, `/api/v1` proxy in every phase | **the only published port** (`8443`) |
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
the master KEK, the CA key envelopes, the setup slot, the JWT key pair, and
the secret-encryption key file. **The keys are never in the database and the
database never contains private keys**: backing up the instance means backing
up BOTH volumes, and restoring one without the other yields an instance that
boots but cannot sign (or one that is meaningless on its own).

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
page for out-of-band verification). Fill the setup form — admin username and
password, default domain, optional admin CIDRs, the server hostname. A
successful POST answers `{"status": "ok", "restart": true}`; the `ui`
process then **exits on purpose with code 0**, and the `restart:
unless-stopped` policy brings it back serving the CA-issued `web-server`
leaf over the same 8443 port. `POST /setup` returns 404 from then on (the
setup routes unmount once a tenant exists).

### External (your database, optional own reverse proxy)

The External variant is the same file with the Postgres service removed and
`DATABASE_URL` pointed at an existing database:

1. Copy `compose.yml` to a private file (e.g. `compose.external.yml`).
2. Remove the whole `db` service block, the `wardstone-pgdata` volume
   definition, both `db:` entries under `depends_on`, and the
   `wardstone-pgdata:` entry under `volumes:`.
3. Replace both services' `DATABASE_URL` with your own connection URL
   (no `${...}` interpolation needed; the Postgres user, database, and
   extensions Wardstone requires are created by the migrations on first
   connect, not by an image entrypoint).
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

## The image and the keys volume

`compose.yml` does not build anything: the image named by
`${WARDSTONE_IMAGE:-wardstone:latest}` is supplied by the release flow — the
Dockerfile itself is out of this bundle's scope. The bundle's contract with
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
   complete keystore: the `ui` process explicitly creates the JWT key pair
   if absent, and the `api` process reads it for token signing.

## Environment contract

Per service (the binary's contract, one variable at a time):

| Variable                    | `ws-web` | `ws-api` | Meaning |
|-----------------------------|----------|----------|---------|
| `DATABASE_URL`              | set      | set      | The Postgres connection URL |
| `WARDSTONE_KEYS_DIR`        | `/var/lib/wardstone/keys` | same | The keystore directory (shared volume) |
| `WARDSTONE_SERVER_HOSTNAME` | required | required | The setup certificate's SAN; also the API's domain context |
| `WARDSTONE_API_URL`         | `http://ws-api:8080` | ignored | The `ui` proxy's target |
| `WARDSTONE_BIND`            | `0.0.0.0:8443` | `0.0.0.0:8080` | The listen address (one variable, per-service values) |

Compose-level:

| Variable                  | Required | Meaning |
|---------------------------|----------|---------|
| `WARDSTONE_SERVER_HOSTNAME` | yes (`:?`) | Interpolated into both services |
| `WARDSTONE_DB_PASSWORD`     | yes (`:?`, Bundled only) | The bundled Postgres' password |
| `WARDSTONE_IMAGE`           | no (default `wardstone:latest`) | Override the image; the e2e harness points it at a local build |

## Operations notes

**The `ws-web` service MUST keep `restart: unless-stopped`.** The `ui`
process self-exits (exit code 0) when the setup flow completes — that is the
documented `{"restart": true}` contract, not a crash — and only a restart
policy brings it back onto the CA-issued leaf. A `no` policy would leave a
freshly set-up instance serving nothing. The same policy is what carries the
leaf re-issue flow (a re-issued leaf takes over on the next restart; TLS
configuration is built at boot).

**Lost or broken JWT key files are a hard stop, with a recovery that costs
every session.** A missing or corrupt `jwt-signing-key.pem` /
`jwt-verify-key.pem` in the keys volume blocks startup with a typed error;
the processes deliberately do NOT heal it by re-keying on their own, because
a silent re-key would invalidate every outstanding token while looking
perfectly normal. Recovery, documented and loud:

1. `docker compose -f docker/compose.yml stop ws-web ws-api`
2. Remove BOTH files from the keys volume
   (`docker run --rm -v wardstone-keys:/keys alpine rm /keys/jwt-signing-key.pem /keys/jwt-verify-key.pem`)
3. `docker compose -f docker/compose.yml up -d`

Both files are re-created on the next boot; **every outstanding access and
refresh token is now invalid** and every user must log in again. Verify the
new fingerprint before proceeding if you have out-of-band key pinning.

**Rate limiting is always-on, keyed per client IP, and tunable — but never
disablable.** The `api` process limits the public auth routes (login,
refresh, OIDC start/callback) with GCRA: one credit per 500 ms, burst 20 per
IP — the house defaults, applied without any configuration. The environment
overrides `WARDSTONE_RATE_LIMIT_PER_MILLIS` and `WARDSTONE_RATE_LIMIT_BURST`
may tune them; the shipped bundle intentionally does not set either. A zero
or unparsable value is a **boot failure**, not a silent un-limited listener.

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