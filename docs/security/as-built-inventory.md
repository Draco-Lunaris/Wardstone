# Wardstone — Security As-Built Inventory

Date: 2026-10-24 · Scope: what actually ships (main as of PR #8, `df4929f`) and,
where noted, the deployed instance on CT 242. Every line is a fact with a
`file:line` citation; **no grades** — grading belongs to the threat model this
document feeds. Absences are facts too.

## A. Secret material and custody (as built)

| Secret | Created by | At rest | Location | Mode |
|---|---|---|---|---|
| Master KEK | `KeyStore::ensure_master_key`, 32 OS-entropy bytes, refuses to remint over a populated store | **plaintext 32 bytes** | `<keys_dir>/master.key` | 0600, crash-atomic |
| SecretBox key | setup's `SecretBox::create`, 32 OS-entropy bytes | **plaintext 32 bytes** | `<keys_dir>/secret-encryption.key` | 0600, crash-atomic |
| CA / leaf / setup private keys | `create_root`/`create_sub_ca`/`sign_leaf_with`(CSR-keyed: none stored) | **envelope-encrypted**: JSON envelope, DEK-wrapped under master KEK, inner XChaCha20-Poly1305 AAD-bound to `wardstone-ca-key/v1/{id}` / setup slot | `<keys_dir>/ca/<id>.key`, `ca/setup.key` | 0600 |
| JWT key pair | `JwtKeys::load_or_create` (flock-serialized, pair-consistency-checked at load) | `jwt-signing-key.pem` plaintext PKCS#8 / `jwt-verify-key.pem` SPKI | keys dir | 0600 / 0644 |
| TOTP secrets | enroll flow | **sealed**: single-layer XChaCha under SecretBox key, ciphertext+nonce columns | `users.totp_secret_encrypted/_nonce` | — |
| Passwords | argon2id (64 MiB, t=3, p=1, v=19, per-hash salt) | PHC string (never plaintext) | `users.password_hash` | — |
| Refresh / API-token / one-shot raw material | `opaque_token`: 32 OS bytes, hex(SHA-256) stored, raw zeroized, plaintext returned once | verifier hash only | `*_tokens.token_hash` | — |
| OIDC **client secret** | operator config via UI | **plaintext TEXT** | `oidc_config.client_secret` | — |
| ACME accounts | client-held JWS keys | **nothing server-side**: public JWK + thumbprint only | `acme_accounts` | — |
| ACME nonces | per-response, 32 OS bytes | memory only (single-use, 60 min TTL, 4096 cap) | ws-api AppState | — |

Custody properties worth stating exactly:
- **No private-key bytes exist in any DB column**; `cas.key_file` is a relative
  path only (`001_init.sql`; `ws-web/src/setup/mod.rs:246-249`).
- Envelope error contract: AEAD failure `WrongKey`, structural `Corrupt`
  (`keystore.rs:283-341`); the outer DEK-wrap carries **no AAD** while the
  inner layer does (`keystore.rs:441-443`).
- Key-generation issuance returns the plaintext leaf PEM **once** in the
  response (`no-store`) and stores nothing (`certificates.rs:514-518`); the
  intermediate DER copy is dropped there **without zeroization**
  (`certificates.rs:515`).
- The **CA private key is exportable in plaintext** by design:
  `POST /api/v1/cas/{id}/export-key`, admin-only, `no-store`, audit rows the
  reason but not the key (`cas.rs:245-288`).
- JWT signing PEM lives in memory as a plain process-lifetime `String` (Debug
  redacted; not `Zeroizing`) (`jwt.rs:126-143`).
- A sealed (populated) store refuses a silent master remint
  (`keystore.rs:177-195, 404-419`).
- **THE CUSTODY CENTER: two plaintext root secrets sit on the same single
  volume/directory as the ciphertext they open** — `master.key` and
  `secret-encryption.key` are 0600 files beside every envelope and every
  sealed blob. Directory 0700, re-tightened at every open
  (`keystore.rs:129-157`). Envelope encryption here therefore provides
  **one** boundary (the directory + its two files), not layered custody.

## B. Request surfaces and boundaries (as built)

Exposure:
- Only `ws-web` publishes a port (`8443:8443`); `ws-api` is **portless by
  design**; one shared bridge network `wardstone-internal`, deliberately NOT
  `internal: true` (OIDC egress requirement) (`compose.yml:113, 172-176,
  240-243`; `docker/README.md:150-154`). Any container attached to this
  network can reach `ws-api` and `db` on it.
- `X-Forwarded-For`: not read **and not written** anywhere; rate limiting keys
  on the direct TCP peer only (grep: zero matches; `docker/README.md:77-83`).

Public (pre-authentication) surface on ws-web: the SPA; `/setup` (GET+POST)
while the default tenant is absent, replaced with explicit plain-404 routers
after (`setup/mod.rs:126-151`); `GET /auth/ui/config`; both OIDC relay GET
routes; `POST /acme/{tenant}/new-account`. Unauthenticated on ws-api: login,
refresh, OIDC start/callback, `GET /oidc/config/status`, `/acme`
new-nonce/directory (JWS-authenticated beyond that), and **`/metrics` +
`/healthz` at the API's own root — ws-web does not proxy these, so they are
reachable only on the internal network** (`health.rs:21-39`;
`routes/mod.rs:72-74`).

Session model:
- Cookie `wardstone_session`: opaque UUID, `HttpOnly; Secure; SameSite=Lax;
  Path=/`, browser-session lifetime (`store.rs:158-166`; `session/mod.rs:50-60`).
- Server-side store: in-memory HashMap; access+refresh tokens live ONLY server
  side; rotation on staleness and on 401 with one locked retry, fail-closed;
  idle eviction 6 h lazy (`store.rs:119-139`; `proxy.rs:357-431`).
- No token material ever reaches JS; the SPA uses no web storage at all
  (`ui/src/lib/auth.tsx:1-16`; grep zero matches).
- CSRF: `x-requested-with: wardstone-ui` required on mutating requests when a
  session cookie is presented; fail-closed 403 (`proxy.rs:516-573`).

Rate limiting:
- GCRA per client IP: ws-web limits `/auth/ui/*`, the proxied
  login+refresh pair, and `POST /acme/{tenant}/new-account`; ws-api limits its
  public auth routes; defaults 1 credit/500 ms, burst 20; the
  `WARDSTONE_AUTH_RATE_LIMIT_DISABLED` switch is api-only; broken values fail
  the boot loudly (`proxy.rs:102-131`; `relay.rs:98-124`; `main.rs:365-459`);
  the bundled deployment sets the api switch `true` because per-IP limiting
  collapses behind the proxy (`compose.yml:157`).
- ACME per-account token bucket: in-memory; **a poisoned lock fails open**
  (`state.rs:336-392`). The in-process challenge-verification pacing
  (5 s/authorization) also fails open when its lock is poisoned
  (`state.rs:316-333`).

ACME:
- JWS: compact-internal/flattened-wire; `jwk`/`kid` mutual exclusion; alg↔key
  family pinning (RS256/ES256/ES384/EdDSA; HMAC rejected before anything);
  nonce consumed before the signature verdict (`jws.rs:80-190`).
- Challenges: the expected key authorization is server-computed from the
  stored token + the account thumbprint; http-01 is an exact-match server-side
  GET (no proxy-env trust); dns-01 compares TXT against
  `base64url(SHA256(keyAuthz))` (`acme.rs:2422-2477`).
- Enrollment is open to any reachable client, bounded by server-computed
  verification; the ToS gate is opt-in via `WARDSTONE_ACME_TOS_URL`
  (`docker/README.md:201-226`; `acme.rs:453-464`).
- PKCE: **absent from the OIDC SSO flow entirely** — the workspace's only
  occurrence of "PKCE" is a doc-comment (`oidc.rs:8`; grep:
  `code_challenge`/`code_verifier` zero matches).

## C. HTTP hardening absences (facts)

None of the following is set anywhere (grep across ws-api, ws-web, ui/, the
embedded `index.html`): `Content-Security-Policy`; `Strict-Transport-Security`
/HSTS; `X-Frame-Options` or any frame-guard; `X-Content-Type-Options`;
`Referrer-Policy`; `Permissions-Policy`. No CORS layer exists — ws-api is
same-origin-friendly by absence, not by enforcement.
Body limits: no `DefaultBodyLimit` middleware anywhere; request bodies buffer
into memory subject to axum's framework default (`proxy.rs:466`;
`acme.rs:369`). The 429 body is tower_governor's plain text (the UI maps it to
`rate_limited`; `ui/src/lib/api.ts:13-48`); 502 bodies carry the raw
`ProxyError` string (`proxy.rs:299-307`); REST 500s include sqlx error text
(`error.rs:241-244`).

## D. Deployment posture (as shipped; CT 242 where marked)

- Image: non-root fixed-uid `wardstone` owning the keys dir; **no
  ENTRYPOINT** (the compose command contract); no HEALTHCHECK on either
  Wardstone service (db has one) (`Dockerfile:1-30`; `compose.yml:213-239`).
- Restart policy `unless-stopped` on all three — load-bearing for setup's
  self-exit (`compose.yml:78-84`; `docker/README.md:271-279`).
- Volumes: `wardstone-keys` (both Wardstone services) + `wardstone-pgdata`;
  `down` keeps them, `down -v` destroys both (`compose.yml:114-121, 200-212`;
  `docker/README.md:341-344`).
- Secret env contract: `WARDSTONE_DB_PASSWORD` + `WARDSTONE_SERVER_HOSTNAME`
  required via `:?`; `DATABASE_URL` embeds the password; **no `.env.example`
  exists in the repo**, and the READMEs' quick start teaches the
  command-line-password form (shell-history exposure) with no secrets-file
  guidance (`compose.yml:29-31, 90, 99, 144, 171, 198`;
  `docker/README.md:236-242`).
- CT 242 (live, 2026-10-24): `.env` 0600 root:root; keys dir 0700; both
  containers run as `wardstone`; network `internal=false`; the keys volume
  holds both plaintext root secrets + 0600 envelopes + the JWT files and the
  flock lock file (0600, 0 bytes); setup-key envelope replaced wholesale per
  setup mint; the post-setup leaf is ECDSA-signed by the ECDSA P-256 root
  minted after PR #8.
- Dev compose: throwaway Postgres, `wardstone/wardstone`, ports bound to
  127.0.0.1, `fsync=off` — explicitly dev-only (`compose.dev.yml:34-99`).
- Backup/restore story: "backing up the instance means backing up BOTH
  volumes; restoring one without the other yields an instance that boots but
  cannot sign" (`docker/README.md:23-30`) — restores are documented as
  whole-instance operations only.

## E. Register of gaps (facts, ungraded)

1. **One-boundary custody**: the master KEK and the SecretBox key live
   plaintext on the same volume as everything they open — envelope and seal
   encryption currently buy one boundary (the keys directory), not layers.
   There is no deployment mode today that separates them.
2. **OIDC client secret stored plaintext**; migration `007`'s own comment
   books the sealing as "Task 5's" and no later migration shipped it
   (`007_users_and_credentials.sql:115-130`).
3. **PKCE absent** from the OIDC authorization flow.
4. **The security-header set is empty** (CSP, HSTS, nosniff, frame-guard,
   referrer, permissions — none set; CORS unenforced).
5. **Single-instance assumptions** in all in-memory components (session
   store, OIDC state store, ACME nonce store, account/pacing limiters): a
   restart logs every user out and clears nonces; multi-replica deployments
   are not supported and some pieces fail open on poison (`state.rs:184-187,
   316-392`).
6. **No HEALTHCHECK** on the Wardstone services (compose orchestration
   health is blind to them; the db healthcheck gates only itself).
7. **Secret delivery**: required secrets arrive via env interpolation;
   the quick-start pattern puts the DB password into shell history as a
   side effect; no secrets-file convention exists in the product
   (`main.rs:143-146` reads only env).
8. **Setup-window takeover**: while the default tenant is absent, `/setup`
   is unauthenticated — on a shared LAN, first-mover takes the CA. The
   fingerprint display is the only out-of-band check (`setup/page.rs:174-245`).
9. **Error-text surfaces**: 502 = raw `ProxyError` string; REST 500 =
   sqlx text; ACME detail strings are specific enough to fingerprint the
   failure point (`proxy.rs:299-307`; `error.rs:241-244`).
10. **In-memory zeroization gaps (minor)**: the key-gen leaf DER copy
    dropped unzeroized (`certificates.rs:515`); JWT signing PEM a lifetime
    `String` (`jwt.rs:126-133`); CA export-key returns plaintext PEM by
    design (`cas.rs:245-288`).
11. **Dead schema member**: `users.webauthn_credential` column exists with no
    implementation anywhere (`007:66`).
12. **Body limits unset** (framework default only).
13. The 429 body is plain text (the SPA special-cases it) — contract
    mismatch with the JSON envelope everywhere else (`api.ts:13-48`).

## F. Recently fixed in this working period (for context)

- JWT pair integrity: pair-consistency proof at load + flock serialization
  (mixed-pair boot refusal) — `jwt.rs:229-326`.
- Boot TLS walk: ACME/client-key leaves are skipped with a WARN instead of
  crash-looping the ui (`main.rs:726-783`).
- The setup root CA is ECDSA P-256 by default (browser-universal trust).