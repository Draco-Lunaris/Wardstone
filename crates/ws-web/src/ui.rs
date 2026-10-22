//! The embedded single-page application: the committed, built `ui/dist`
//! bundle included into the binary at compile time and routed by this
//! module.
//!
//! The embed is the whole point of the committed-bundle policy: `ui/dist`
//! (see `ui/README.md`) is git-committed, so the binary that a release
//! image builds from source serves exactly the UI that was reviewed and
//! committed — and the build itself needs no Node toolchain. The macro
//! path resolves from ws-web's manifest directory, which makes the embed
//! `$CARGO_MANIFEST_DIR/../../ui/dist` — the workspace root's `ui/dist`.
//!
//! # Routing contract
//!
//! [`ui_router`] is mounted by [`crate::web_router`] as the composed
//! router's FALLBACK — the axum mechanism that runs only when no earlier
//! route matched (`Router::fallback_service`, holding [`ui_router`]'s own
//! route tree). That gives the precedence the suite pins, in order:
//!
//! 1. the API surface (`/api/v1/*`, [`crate::proxy`]) — never masked;
//! 2. the setup surface (mounted only while no tenant exists);
//! 3. this router: `/`, `/assets/{path}`, and the SPA fallback.
//!
//! Within the fallback, the rules are:
//!
//! - `GET /` serves `index.html` (`text/html; charset=utf-8`,
//!   `Cache-Control: no-cache` — always revalidated, because the hashed
//!   asset names it references change with every rebuild);
//! - `GET /assets/{*path}` serves the embedded hashed asset with a
//!   content type derived from its extension and the immutable cache
//!   header (`public, max-age=31536000, immutable` — Vite's content-hash
//!   names make the body permanent); a miss is a plain 404;
//! - any other GET on a path WITHOUT an extension serves `index.html`
//!   (client-side SPA routing: `/certificates` is a UI route, not a
//!   file); a GET on a path WITH an extension (or a non-GET method,
//!   which no SPA route produces) is a plain 404 — a mistyped asset link
//!   must 404, not masquerade as the document.

use std::path::Path;

use axum::extract::Path as PathArg;
use axum::http::{header, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use include_dir::{include_dir, Dir};

/// The embedded built SPA: the exact `$CARGO_MANIFEST_DIR/../../ui/dist`
/// directory git holds (see the module docs). A compile-time embed —
/// rebuilding the binary re-reads it.
static UI_DIST: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../ui/dist");

/// The response cache header on `index.html`: revalidate every time, so a
/// new deploy's changed hashed-asset references are picked up (the assets
/// themselves are immutable).
const INDEX_CACHE_CONTROL: &str = "no-cache";

/// The response cache header on hashed assets: never revalidated.
const ASSET_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

/// The SPA router: `GET /`, `GET /assets/{*path}`, and the SPA fallback.
/// Mounted as the composed front-door router's fallback service (see the
/// module docs for the precedence this implements).
pub fn ui_router() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/assets/{*path}", get(asset))
        .fallback(spa_fallback)
}

/// `GET /` — the SPA document.
async fn index() -> Response {
    serve_index_html()
}

/// `GET /assets/{*path}` — one embedded hashed asset, content-typed by
/// extension, served with the immutable cache header. A path that embeds
/// no such file is a plain 404.
async fn asset(PathArg(path): PathArg<String>) -> Response {
    match UI_DIST.get_file(format!("assets/{path}")) {
        Some(file) => (
            [
                (header::CONTENT_TYPE, content_type(&path)),
                (header::CACHE_CONTROL, ASSET_CACHE_CONTROL),
            ],
            file.contents(),
        )
            .into_response(),
        None => not_found(),
    }
}

/// The SPA fallback: index.html for GET paths without an extension (the
/// client routes them), a plain 404 for extension paths (a missing asset
/// must not masquerade as the document) and non-GET methods.
async fn spa_fallback(method: Method, uri: Uri) -> Response {
    if method != Method::GET {
        return not_found();
    }
    if has_extension(uri.path()) {
        return not_found();
    }
    serve_index_html()
}

/// The `index.html` response (shared by `GET /` and the SPA fallback).
fn serve_index_html() -> Response {
    match UI_DIST.get_file("index.html") {
        Some(file) => (
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CACHE_CONTROL, INDEX_CACHE_CONTROL),
            ],
            file.contents(),
        )
            .into_response(),
        // Unreachable against the committed bundle (ui/dist/index.html is
        // part of the embed contract), but a fail-closed plain 404 beats a
        // panic if the embed dir is ever built empty.
        None => not_found(),
    }
}

/// The plain 404 the router serves for anything that is not a real SPA
/// route or asset.
fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found\n").into_response()
}

/// Does `path` end in a file extension? The SPA fallback's discriminator:
/// no extension = a client route (/certificates), an extension = a file
/// request (/assets/index-….js), which must 404 when the file is absent.
/// A trailing dot is not an extension (empty extensions are not treated
/// as one).
fn has_extension(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    match Path::new(name).extension().and_then(|ext| ext.to_str()) {
        Some(ext) => !ext.is_empty(),
        None => false,
    }
}

/// The content type of an asset path, by extension (the mapping the task
/// pins; anything else is an opaque octet stream).
fn content_type(path: &str) -> &'static str {
    match Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
    {
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "html" => "text/html; charset=utf-8",
        "map" => "application/json",
        _ => "application/octet-stream",
    }
}

/// # Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_discriminator_separates_routes_from_files() {
        assert!(!has_extension("/"), "the root is a route");
        assert!(!has_extension("/certificates"), "a client route");
        assert!(
            !has_extension("/certificates/42/download"),
            "deep client route"
        );
        assert!(
            !has_extension("/trailing."),
            "a trailing dot is not an extension"
        );
        assert!(has_extension("/missing.js"), "a file request");
        assert!(has_extension("/a/b/c.svg"), "a nested file request");
    }

    #[test]
    fn content_types_match_the_pinned_map() {
        assert_eq!(
            content_type("index-abc.js"),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(content_type("x.css"), "text/css; charset=utf-8");
        assert_eq!(content_type("logo.svg"), "image/svg+xml");
        assert_eq!(content_type("y.html"), "text/html; charset=utf-8");
        assert_eq!(content_type("z.map"), "application/json");
        assert_eq!(content_type("w.xyz"), "application/octet-stream");
        assert_eq!(content_type("no-ext"), "application/octet-stream");
    }

    /// The embed contract: the committed bundle's index.html and every
    /// `.js` bundle committed under `ui/dist/assets` are inside the
    /// binary, looked up by PATH — the exact lookup the router performs.
    /// (Not `Dir::files()`: in include_dir 0.7 it is not recursive, this
    /// suite's earlier red herring; `get_file` is.)
    #[test]
    fn embedded_dir_is_complete() {
        assert!(
            UI_DIST.get_file("index.html").is_some(),
            "the committed ui/dist/index.html must be embedded"
        );
        let assets_dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ui/dist/assets");
        let mut js_assets = 0;
        for entry in std::fs::read_dir(&assets_dir).expect("read the committed assets dir") {
            let path = entry.expect("entry in the committed assets dir").path();
            if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("js") {
                js_assets += 1;
                let name = path
                    .file_name()
                    .expect("file name")
                    .to_str()
                    .expect("UTF-8");
                let embedded = format!("assets/{name}");
                assert!(
                    UI_DIST.get_file(&embedded).is_some(),
                    "{embedded} is committed but not embedded"
                );
            }
        }
        assert!(
            js_assets >= 1,
            "at least one hashed JS asset must be embedded"
        );
    }
}
