import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The Wardstone UI build. `outDir: "dist"` (the default, pinned here so the
// ws-web embed contract — `$CARGO_MANIFEST_DIR/../../ui/dist` — is explicit) and
// `base: "/"` (the UI is served from the instance root by ws-web's ui_router;
// hashed assets under /assets/* get their immutable cache headers from the
// Rust side, not from a base-path rewrite).
//
// `npm run dev` proxies the server paths (`/api` — the proxied API — and
// `/auth` — the session relay) to a running ws-web instance: the dev server
// is same-origin as far as the SPA is concerned, so the cookie flows and
// apiFetch never needs a cross-origin story. ws-web serves TLS only (its
// self-signed setup certificate by default), hence `secure: false`.

// The front door under development: the `wardstone` binary's default bind
// (`0.0.0.0:8443`); override here per environment with UI_PROXY_TARGET.
const PROXY_TARGET = process.env.UI_PROXY_TARGET ?? "https://127.0.0.1:8443";

export default defineConfig({
  base: "/",
  plugins: [react()],
  build: {
    outDir: "dist",
  },
  server: {
    proxy: {
      "/api": { target: PROXY_TARGET, secure: false },
      "/auth": { target: PROXY_TARGET, secure: false },
    },
  },
  test: {
    environment: "jsdom",
  },
});