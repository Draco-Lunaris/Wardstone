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
  self-signed setup certificate for a CA-issued leaf on restart.
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
separate processes, plus a bundled Postgres.

```sh
WARDSTONE_SERVER_HOSTNAME=ca.example.test \
WARDSTONE_DB_PASSWORD=<strong password> \
WARDSTONE_IMAGE=ghcr.io/draco-lunaris/wardstone:latest \
docker compose -f docker/compose.yml up -d
```

The first two variables are required by design — an unset hostname would
serve the setup certificate with a placeholder SAN, and an unset password
would make the bundled Postgres guessable. **`WARDSTONE_DB_PASSWORD` is a
bootstrap-only value**: it initializes the bundled database and seeds the
first credential, and the first unlock of the instance retires it (a fresh
in-memory credential is rotated into place and sealed under your master
passphrase). The image publish requires the GitHub package to be public
(or an existing `docker login ghcr.io`).
`WARDSTONE_IMAGE=wardstone:latest` is the default when you build locally.

**First run.** Browse `https://<host>:8443/`, accept the freshly minted
self-signed setup certificate (its SHA-256 fingerprint is displayed on
the page for out-of-band verification), and fill the setup form: **set
your master passphrase** (the key that seals every sensitive file on the
instance — it exists nowhere on any disk, and it is not recoverable,
store it in your password manager), then the admin username and password,
default domain, optional admin CIDRs, and the server hostname. The UI
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
| `DATABASE_URL` | yes | Postgres connection URL |
| `WARDSTONE_KEYS_DIR` | yes | The keystore directory (compose mounts it as a shared volume) |
| `WARDSTONE_SERVER_HOSTNAME` | compose: yes | The setup certificate's SAN and the API's domain context |
| `WARDSTONE_API_URL` | no | The UI's proxy target (default `http://ws-api:8080`) |
| `WARDSTONE_BIND` | no | Listen address (UI `0.0.0.0:8443`, API `0.0.0.0:8080`) |
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

- **Keep `restart: unless-stopped` on `ws-web`.** The setup flow ends
  with a deliberate clean exit (code 0) and relies on the restart policy
  to return on the CA-issued leaf; the same policy carries every TLS
  re-issue.
- **Never `docker compose down -v`** against an instance you care about:
  it deletes the keys volume along with the database volume. Plain `down`
  keeps both named volumes.
- **Lost or broken JWT key files are a loud stop, not a heal.** The
  processes refuse to silently re-key (that would invalidate every
  outstanding token while looking normal); the documented recovery
  removes both `jwt-*.pem` files with the services stopped and restarts.
  Since the pair is validated as a *pair* at load, a mixed one (e.g. from
  two processes racing on a fresh volume) now fails the boot with the
  same recovery hint instead of issuing tokens nothing can verify.
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
**sealed at rest**: every sensitive file on the instance (the CA key
envelopes, the session-key pair, the second-factor seals, the database
credential) is ciphertext under a key derived from **your master
passphrase** — entered at the HTTPS front door when you unlock the
instance, existing nowhere on any disk. A sealed instance is correctly
unhealthy while locked; the disk copy of a running instance is inert
until unlocked; a database copy carries no plaintext secrets. The stated
residuals, plainly: a **host-root** attacker on the running instance
reads unlocked memory (no software defends that); a **stolen passphrase**
defeats the seal (keep it in your password manager, not on the same
machine); and **losing the passphrase** loses the instance — its
identities are re-issued from the offline root you control. Further
hardening habits (no forwarded-for trust, server-computed challenge
verification, tokens never in browser state, tenancy enforced in the
schema) ride along underneath.
Please report potential vulnerabilities privately through GitHub's
private vulnerability reporting rather than a public issue.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).