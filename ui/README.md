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
(`crates/ws-web/src/ui.rs`, `include_dir!("$CARGO_MANIFEST_DIR/../../ui/dist")`).

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
relay route (`crates/ws-web/src/session/relay.rs`, `session::relay::ui_config`):
ws-web relays `GET /api/v1/oidc/config/status` — ws-api's PUBLIC status
surface (`crates/ws-api/src/routes/oidc.rs::config_status`; no capability
gate and no auth extractor, because the caller is by definition
unauthenticated) — and answers `{"oidc_configured": bool, "provider":
string|null}`: a 200 maps `{"configured": bool, "provider_type": ...}`
onto the UI's field names, any other status fails CLOSED to
`false`/`null` (hide the button, never show one that cannot work). The
flag never carries `client_id`, `redirect_uri`, discovery URLs, or
secrets — only the boolean and the provider-type label the start route
resolves. (Fix round 1: the original probe hit the ManageSystem-gated
`GET /api/v1/oidc/config` and its 401 read as `false` forever — the
public status route IS the fix.)