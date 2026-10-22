# Wardstone UI

The SPA that ws-web serves from the instance root (`ui_router`). The **built
bundle (`dist/`) is committed to git**: ws-web embeds exactly that directory
into the binary with `include_dir` at compile time, so release builds never
need Node. `node_modules/` is the only thing ignored here.

## Rebuilding the committed bundle

```sh
npm install
npm run build
```

Then **commit the updated `dist/`** (including the new hashed file names under
`dist/assets/`). The Rust test suite reads `dist/assets/` for the committed
hashed bundle (`ws-web/tests/ui_serve_test.rs`), so a rebuilt-but-uncommitted
dist keeps that suite green locally only until someone rebuilds again —
the committed copy is the contract.

Vite is pinned (`base: "/"`, `outDir: "dist"`) in `vite.config.ts`; the
embedding path comes from the ws-web crate
(`crates/ws-web/src/ui.rs`, `include_dir!("$CARGO_MANIFEST_DIR/../ui/dist")`).

## Developing against a running ws-web

`npm run dev` starts Vite on its own port and proxies `/api` (the proxied
API) and `/auth` (the session relay) to a running ws-web front door
(`UI_PROXY_TARGET`, default `https://127.0.0.1:8443` — ws-web is TLS-only,
so the proxy runs with `secure: false` against the self-signed setup
certificate). The SPA sees a same-origin server either way: the session
cookie flows, and no cross-origin story exists anywhere in the client.

## Tests

```sh
npm run test        # vitest run (jsdom); ui/src/**/*.test.ts(x)
npm run build       # tsc --noEmit (zero TS errors is the contract) + vite build
```

## The public auth-config route (`GET /auth/ui/config`)

The login page's SSO button is driven by `GET /auth/ui/config`, a PUBLIC
relay route added in Task 14 (`crates/ws-web/src/session/relay.rs`):
ws-web relays `GET /api/v1/oidc/config` upstream and answers
`{"oidc_configured": bool, "provider": string|null}` — a 200 maps to
`true` (carrying the row's `provider_type` as the `provider` label,
because ws-api resolves `/auth/ui/oidc/{provider}/start` against exactly
that label), ANY other status to `false`. The flag is safe to expose: it
never carries `redirect_uri`, `client_id`, discovery URLs, or secrets.

Documented decision: ws-api gates `GET /api/v1/oidc/config` behind
`manage_system`, so an unauthenticated probe gets an upstream 401 (not
404) — which on the login page is always the case. The route therefore
reads `false` until ws-api gains a public config-status surface (a ws-api
task, not this relay's): the mapping is in place and tested (200 / 404 /
401 stubs in `crates/ws-web/tests/ui_config_test.rs`), so relaxing
ws-api's gate turns the SSO button on with no client-side change.