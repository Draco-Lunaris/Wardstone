import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The Wardstone UI build. `outDir: "dist"` (the default, pinned here so the
// ws-web embed contract — `$CARGO_MANIFEST_DIR/../ui/dist` — is explicit) and
// `base: "/"` (the UI is served from the instance root by ws-web's ui_router;
// hashed assets under /assets/* get their immutable cache headers from the
// Rust side, not from a base-path rewrite).
export default defineConfig({
  base: "/",
  plugins: [react()],
  build: {
    outDir: "dist",
  },
});