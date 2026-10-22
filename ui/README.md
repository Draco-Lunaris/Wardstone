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