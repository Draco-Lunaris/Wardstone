# Wardstone

A self-hosted certificate authority with a web UI, simple enough for a homelab and hardened enough for production.

Wardstone is a complete private PKI you can stand up in an afternoon: a web
UI for people, an ACME server (RFC 8555) for machines, and a multi-tenant
CA engine underneath — issuance, revocation, CRLs, and OCSP responses —
with every private key stored encrypted-at-rest outside the database.

## Features

- **Multi-tenant CA** — tenants are the unit of isolation; every
  certificate, CRL, and OCSP row is tenant-scoped and enforced at the
  schema level, not by convention.
- **Issuance on profiles** — built-in `web-server` (RSA-2048 and ECDSA
  P-256 variants) and custom profiles; each carries its allowed SAN
  patterns, key types, and validity. Issue from the UI, from the REST
  API, or from any RFC 8555 client.
- **Revocation** — RFC 5280 reasons, CRL generation on a schedule,
  OCSP response records.
- **ACME server (RFC 8555)** — a first-party implementation: directory,
  account lifecycle with key change, new-order, `http-01`/`dns-01`
  challenges verified by the server (never from client input), finalize,
  POST-as-GET reads, and `revoke-cert` (see
  [ACME for machines](#acme-for-machines)).
- **Web UI** — a first-run setup wizard that mints the tenant, root CA,
  admin, and the built-in profiles from one form, then swaps the
  self-signed setup certificate for a CA-issued leaf in place (no
  restart) and seals every key under the master passphrase you set —
  each key's first write is its sealed envelope, so no plaintext key
  file ever exists.
- **Accounts and auth** — local accounts (argon2id), TOTP multi-factor,
  generic OIDC single sign-on, role-based capabilities, service API
  tokens, and one-shot pull tokens for scripted certificate retrieval.
- **Session model that keeps secrets out of the browser** — the front
  door stores the token pair server-side under an HttpOnly cookie; the
  browser never holds a token.
- **Rate limiting where credentials meet the network** — per-client-IP
  GCRA on the auth surfaces and per-account limiting on the ACME volume,
  always on, tunable, and loud when misconfigured.
- **Transactional audit** — every mutation and its audit row commit on
  the same database transaction.

## Quick start (docker compose)

The compose bundle is the supported deployment: one Wardstone image
running the UI front door (`ws-web`) and the REST API (`ws-api`) as two
separate processes, plus a bundled Postgres. The database and the two
processes' unlock relay ride Unix sockets in directories bind-mounted
from the host's `/run` (tmpfs), so once per host boot — before `up` —
create them (the bundle refuses to start without them, loudly):

```sh
install -d -m 0770 -o 70 -g 70 /run/wardstone/pg
install -d -m 0770 -o 10001 -g 10001 /run/wardstone/relay
```

Then:

```sh
WARDSTONE_SERVER_HOSTNAME=ca.example.test \
WARDSTONE_DB_PASSWORD=<strong password> \
WARDSTONE_IMAGE=ghcr.io/draco-lunaris/wardstone:latest \
docker compose -f docker/compose.yml up -d
```

The first two variables are required by design — an unset hostname would
serve the setup certificate with a placeholder SAN, and an unset password
would make the bundled Postgres guessable. **`WARDSTONE_DB_PASSWORD` is a
bootstrap-only value**: it initializes the bundled database, and the
first-run setup page reads it once (its database-password field) and
retires it as a login credential for good — setup rotates the database
role's password under your master passphrase, and every unlock rotates
it again. A plaintext value works; the recommended form is the SCRAM
verifier minted by `wardstone db-verifier` (single-quoted in `.env` —
see the [production manual](docker/README.md)). The image publish requires
the GitHub package to be public
(or an existing `docker login ghcr.io`).
`WARDSTONE_IMAGE=wardstone:latest` is the default when you build locally.

**First run.** Browse `https://<host>:8443/`, accept the freshly minted
self-signed setup certificate (its SHA-256 fingerprint is displayed on
the page for out-of-band verification), and fill the setup form: **set
your master passphrase** (the key that seals every sensitive file on the
instance — it exists nowhere on any disk, and it is not recoverable,
store it in your password manager), then the admin username and password,
default domain, optional admin CIDRs, the server hostname, and the
database password — the login credential the database role carries today
(for the bundled database, the value behind `WARDSTONE_DB_PASSWORD`; if
you minted a verifier, the password printed beside it). Setup connects
with it exactly once, rotates the role to a fresh random credential, and
seals that one under the master passphrase — the typed password is never
stored. The UI
process **resumes in place** serving the CA-issued TLS leaf — no restart,
no re-typing. Sign in with the admin account you just created — `POST
/setup` now returns 404 forever.

**Sealed boots.** Every container restart returns the instance to the
locked page: enter your master passphrase on it and the instance resumes
where it left off. While sealed the database is unreachable, the keys are
ciphertext on disk, and the only thing the front door serves is the
unlock page — that is the design, not an outage.

**First certificate.** Two paths, both open on the same instance:

- From the UI: pick a profile, request a certificate — the row, the key
  envelope, and the audit entry land in one transaction.
- From certbot (or any RFC 8555 client): point `--server` at
  `https://<host>/acme/<tenant>/directory`. The client machine must trust
  Wardstone's root CA. See [ACME for machines](#acme-for-machines).

## ACME for machines

The front door serves the ACME surface at the same address as the UI.
The directory URL carries your primary tenant (the one setup created):

    https://<host>/acme/<tenant>/directory

Enrollment is open to any ACME client that can reach the front door —
new-account is authorized by the client's own JWS key, and issuance stays
bounded by server-computed challenge verification, so a key can only win
a certificate for identifiers it actually controls.

Two things to prepare:

1. **Trust.** The front door's TLS leaf is signed by Wardstone's own CA
   — an **ECDSA P-256 root**, which every mainstream browser verifies
   once imported (Chromium-family browsers cannot verify Ed25519 chains,
   so the default is deliberately browser-universal). Import the root
   certificate (downloadable from the UI) into every machine that talks
   ACME here, or those clients stop at TLS verification.
2. **URL base.** ACME URLs are built absolute from the
   `WARDSTONE_PUBLIC_URL` setting — compose defaults it to
   `https://$WARDSTONE_SERVER_HOSTNAME`, which is right when clients dial
   the standard HTTPS port on that name. If they reach a different port
   or name, set the variable to that base.
3. **Profile/key-type pairing.** Issue on the profile that matches the
   client's CSR key: certbot 4.x requests ECDSA keys by default, while
   the setup-created default profile pins RSA-2048 — pass
   `--key-type rsa` to certbot, or enroll on the ECDSA variant profile.

## Architecture in brief

One binary, two modes, one deployment shape:

| Service   | Command          | Role                                                                    | Exposure        |
|-----------|------------------|-------------------------------------------------------------------------|-----------------|
| `ws-web`  | `wardstone ui`   | TLS front door: setup page (pre-setup), the `/api/v1` proxy, the `/acme/*` relay, session surface. Only port published. | `:8443` |
| `ws-api`  | `wardstone api`  | REST + ACME wire protocol, plain HTTP, internal networks only            | none            |
| `db`      | Postgres 18      | Bundled database (swap for your own in the External variant)             | none            |

The Rust workspace behind them is layered so trust flows one way:
`ws-core` (SQLx Postgres persistence) ← `ws-ca` (issuance engine,
keystore) and `ws-auth` (argon2id, Ed25519 JWT, TOTP, OIDC, tokens) ←
`ws-api` (REST) and `ws-web` (TLS front door, setup, session relay) ←
the `wardstone` binary that boots both modes.

**Keys and records live apart on purpose.** The database volume holds the
CA's records; the keys volume holds the key material — master KEK, CA key
envelopes, the JWT key pair, the secret-encryption key. The database
never contains private keys. Back up both volumes together; restoring
one without the other yields an instance that boots but cannot sign.

## Configuration

The binary reads only the environment. The variables the two modes
share:

| Variable | Required | Meaning |
|----------|----------|---------|
| `DATABASE_URL` | yes | Postgres connection URL. Refused if it carries a password (the credential lives in the sealed envelope — or, on a fresh install, the setup page's database-password field). A TCP URL (an external database) must carry BOTH `sslmode=verify-full` and `sslrootcert=<CA-bundle path>`; a unix-socket URL is the bundled local link |
| `WARDSTONE_KEYS_DIR` | yes | The keystore directory (compose mounts it as a shared volume) |
| `WARDSTONE_SERVER_HOSTNAME` | compose: yes | The setup certificate's SAN and the API's domain context |
| `WARDSTONE_API_URL` | no | The UI's proxy target (default `http://ws-api:8080`) |
| `WARDSTONE_BIND` | no | Listen address (UI `0.0.0.0:8443`, API `0.0.0.0:8080`) |
| `WARDSTONE_RELAY_SOCKET` | no | The unlock relay's Unix socket (compose: `/run/wardstone/relay/relay.sock`): the ui relays the master passphrase to the api over it once per unlock; the api binds it mode 0600 and admits only its own uid (`SO_PEERCRED`) — no network listener carries the relay |
| `WARDSTONE_PUBLIC_URL` | no | Absolute URL base for every ACME URL (unset → the ACME routes degrade to `serverInternal` problems) |
| `WARDSTONE_RATE_LIMIT_PER_MILLIS` / `_BURST` | no | GCRA tuning (defaults: 1 credit per 500 ms, burst 20; a zero or unparsable value fails the boot) |
| `WARDSTONE_AUTH_RATE_LIMIT_DISABLED` | no | API-only switch for the UI-fronted deployment shape (the UI's own limiter never reads it) |
| `WARDSTONE_ACME_ACCOUNT_LIMIT_DISABLED` | no | API-only switch for the per-ACME-account limiter (independent of the auth switch on purpose) |

An External variant (your own Postgres, optionally your own reverse
proxy) is the same file with the `db` service removed — the exact steps
and the reverse-proxy caveats are in
[`docker/README.md`](docker/README.md#the-two-variants).

## Operations notes

The short list every operator should know; the full manual — variants,
SSO setup, rate-limiter placement, image contract, recovery procedures —
is [`docker/README.md`](docker/README.md).

- **Keep `restart: unless-stopped` on `ws-web`.** Setup completes with an
  in-place resume (the listener swaps onto the CA-issued leaf, no exit);
  the policy is what carries the stack through host reboots, crashes, and
  redeploys — every restart lands the instance on the unlock page, where
  the master passphrase resumes it.
- **Never `docker compose down -v`** against an instance you care about:
  it deletes the keys volume along with the database volume. Plain `down`
  keeps both named volumes.
- **Lost or broken JWT key material is a loud stop, not a heal.** The
  processes refuse to silently re-key (that would invalidate every
  outstanding token while looking normal): a missing or corrupt
  `jwt-keys.envelope` fails the unlock loudly — checked before any
  secret is unwrapped or the database touched — and there is no
  in-product re-key. Recovery is restoring the keys volume from a
  backup (with the database-credential runbook from the manual if the
  restored envelope predates the role's current password), or wiping
  both volumes and running setup again; either way every outstanding
  token is invalid and everyone logs in again
  ([`docker/README.md`](docker/README.md) carries the full procedure).
- **Verify with `docker compose config`** before an upgrade; the compose
  file is the deployment contract.

## Building from source

Wardstone builds with a stable Rust toolchain (MSRV 1.89, pinned
`stable` via `rust-toolchain.toml`):

```sh
cargo build --release --bin wardstone
```

The React UI (`ui/`) is built in and committed (`ui/dist` embeds into the
binary via `include_dir!`); if you change UI source:

```sh
cd ui && npm ci && npm run build
```

Tests and the lint gate every commit passes:

```sh
cargo test --workspace                                   # fast suite, no database
cargo test --workspace -- --include-ignored              # + DB-gated suites
DATABASE_URL=postgres://...  cargo test --workspace -- --include-ignored
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

The DB-gated suites need a live Postgres (they take advisory locks on
the shared `wardstone_test` database and restore their own state).
See [`CLAUDE.md`](CLAUDE.md) for the working conventions, and
[`docs/superpowers/`](docs/superpowers/) for the specs and plans behind
the current shape. To build the release image that CI publishes to
`ghcr.io/draco-lunaris/wardstone`:

```sh
docker build -f docker/Dockerfile -t wardstone:local .
```

## Documentation

| Document | Contents |
|----------|----------|
| [`docker/README.md`](docker/README.md) | The production manual: variants, env contract, SSO, ACME and rate-limit placement, image contract, recovery procedures |
| [`CLAUDE.md`](CLAUDE.md) | Working conventions for contributors (crate graph, test rules, lint gate) |
| [`docs/superpowers/`](docs/superpowers/) | Design specs and implementation plans the code was built from |

## Security

Key handling, issuance flows, and the web UI are security-sensitive by
nature; the design treats them accordingly. The headline control is
**sealed at rest, sealed at creation**: every sensitive file on the
instance (the CA key envelopes, the JWT key pair, the second-factor
seals, the database credential) is ciphertext under a key derived from
**your master passphrase** — entered at the HTTPS front door when you
unlock the instance, existing nowhere on any disk — and no plaintext
key file ever exists either: the first-run setup mints every key
straight into its sealed envelope, and the database credential is
rotated and re-sealed at every unlock. A sealed instance is a correct
state, not an outage (the liveness endpoints answer 200 with the
current state while locked); the disk copy of a running instance is
inert until unlocked; a database copy carries no plaintext secrets. In
RAM the unlocked keys live in a kernel-locked arena (`ws-secmem`):
`memfd_secret(2)` pages that are never swapped, never written to core
dumps, and invisible to `ptrace` and `/proc/<pid>/mem`.

The stated residuals, plainly: a **host-root** attacker on the running
instance reads unlocked memory (no software defends that); a **stolen
passphrase** defeats the seal (keep it in your password manager, not on
the same machine); and **losing the passphrase** loses the instance —
its identities are re-issued from the offline root you control. Within
RAM the residual is library-level key hygiene, verified per
dependency: most of the tree's signing crypto wipes its key material by
construction — the RustCrypto ECDSA keys (P-256/P-384) and
jsonwebtoken's signing handles are zeroized on drop, `rsa`'s `Drop`
wipes the private primes and precomputed values, the XChaCha20-Poly1305
cipher (its zeroize feature pinned on) and ed25519-dalek (zeroize in its
defaults) wipe their key material, and the arena volatile-wipes every
buffer on drop. Two named exceptions: `ring` — the SCRAM verifier
derivation and rcgen's signing backend — retains un-wiped key copies
inside its own objects for the process's life (the surrounding
Wardstone buffers are wiped; ring's internal copies are not), and any
secret that crosses an HTTP request — an OIDC token exchange's form
body, a bearer header — is serialized into ordinary heap buffers for
that request's lifetime (at-rest custody stays arena-only). One upstream
habit to know: sqlx logs an unrecognized `DATABASE_URL` query
parameter's key AND value at WARN, and turning statement logging off
does not cover connect-time parameter logging — so never put a
credential in a query parameter; no Wardstone URL carries one
(credentials ride the URL's userinfo, which is never logged). Further
hardening habits (no forwarded-for trust, server-computed challenge
verification, tokens never in browser state, tenancy enforced in the
schema) ride along underneath.

### Hardening the host

Wardstone does not change host settings; the protected-memory design
assumes these operator-side habits:

- **Kernel 5.14+ with `memfd_secret` enabled** — the arena's syscall;
  the boot names the cause if the kernel refuses it (too old, disabled
  on the kernel command line, or blocked by a seccomp profile).
- **A memlock budget of 512 MiB (536870912 bytes)** for both Wardstone
  services — the compose bundle sets it; in an unprivileged LXC the
  host must pass it through (`lxc.prlimit.memlock: 536870912`).
- **`kernel.yama.ptrace_scope` = 3, or at least 2**, on the machine
  running the containers — the hypervisor host in the LXC case.
- **Swap encrypted or disabled** — defence in depth: arena pages never
  swap, but ordinary process memory can.
- **Keep Docker's default seccomp profile** — it permits
  `memfd_secret` (verified on Docker 29.9.2 / containerd 242); a
  custom profile must allow the syscall explicitly.
- The session store holds at most **1,024 concurrent sessions** —
  beyond that the least-recently-touched session is evicted and its
  tokens wiped — and every session dies with its process.
Please report potential vulnerabilities privately through GitHub's
private vulnerability reporting rather than a public issue.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).