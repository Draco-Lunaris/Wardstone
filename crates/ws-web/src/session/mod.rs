//! Browser-session plumbing between ws-web and the proxied API: the
//! session cookie's wire form, and reading the session id back out of an
//! incoming request's headers.
//!
//! Task 11 shipped the cookie helpers. Task 12 wires the session store
//! (`store`) and the `/auth/ui` relay routes (`relay`) around them: the
//! JWT pair a browser session owns lives ONLY in ws-web's memory (entries
//! die on restart — strictly tighter than any cookie-carries-token
//! shape), the cookie's opaque id is minted at login, `Authorization` is
//! injected on every proxied request, rotation runs through one locked
//! ws-api refresh, and logout revokes server-side and clears.

pub mod relay;
pub mod store;

pub use relay::{relay_router, RelayState};
pub use store::{SessionEntry, SessionStore, MAX_SESSIONS};

use axum::http::{header, HeaderMap};
use uuid::Uuid;

/// The session cookie's name: the single token ws-api's login handler
/// sets (through the proxy) and every later browser request carries.
pub const SESSION_COOKIE: &str = "wardstone_session";

/// The CSRF protection header's NAME (`X-Requested-With`): a cookie-carrying
/// mutating request MUST carry it (see [`crate::proxy`]'s rule — the proxy
/// refuses such requests without it, which is what protects ws-web's
/// session cookies from cross-site form posts, the browser's cookies being
/// attached to cross-site requests automatically).
pub const CSRF_HEADER_NAME: &str = "x-requested-with";

/// The CSRF protection header's required VALUE: a fixed marker the Wardstone
/// UI sets on every mutating fetch (an empty-looking token still proves the
/// request was made from the UI's own JavaScript, not a cross-site form).
pub const CSRF_HEADER_VALUE: &str = "wardstone-ui";

/// Build the `Set-Cookie` VALUE for a login (the header line minus its
/// name): `wardstone_session=<id>; HttpOnly; Secure; SameSite=Lax; Path=/`.
///
/// - `HttpOnly` — the session id is unreadable to page JavaScript (the CSRF
///   marker header, not the cookie, is what user JS authenticates with);
/// - `Secure` — ws-web only ever serves HTTPS (TLS from the very first
///   request, setup page included);
/// - `SameSite=Lax` — top-level cross-site navigations keep the cookie but
///   cross-site subrequests/fetches drop it; Lax preserves the login for
///   ordinary navigation without granting it to cross-site mutations
///   (belt to the CSRF header's suspenders);
/// - `Path=/` — every part of the served SPA talks through the same proxy.
pub fn build_session_cookie(session_id: &str) -> String {
    format!("{SESSION_COOKIE}={session_id}; HttpOnly; Secure; SameSite=Lax; Path=/")
}

/// Build the `Set-Cookie` VALUE for a logout: the same cookie with an
/// empty value and `Max-Age=0` — the wire form that makes the browser drop
/// it immediately, keeping the four flags so the deletion behaves exactly
/// like the setting did.
pub fn build_session_cookie_clear() -> String {
    format!("{SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/")
}

/// Read the session id a request presents: the first
/// `wardstone_session=<uuid>` cookie among the request's `Cookie` headers.
///
/// Hand-parsed per the plan's call — one cookie name, no jar semantics: the
/// Cookie header is `name=value` pairs joined with `;` (optionally
/// whitespace around the joins), which is all a browser's own header
/// produces. Anything that is not a well-formed pair for
/// [`SESSION_COOKIE`] holding a parseable `Uuid` is simply not a session:
/// the `None` caller flow treats it as unauthenticated.
pub fn read_session_id(headers: &HeaderMap) -> Option<Uuid> {
    for cookie_header in headers.get_all(header::COOKIE) {
        let Ok(pairs) = cookie_header.to_str() else {
            // A Cookie header not expressible as UTF-8 is not the browser's.
            continue;
        };
        for pair in pairs.split(';') {
            let pair = pair.trim();
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if name.trim() != SESSION_COOKIE {
                continue;
            }
            if let Ok(id) = Uuid::parse_str(value.trim()) {
                return Some(id);
            }
        }
    }
    None
}

/// # Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    fn headers(cookie: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(
            header::COOKIE,
            header::HeaderValue::from_str(cookie).unwrap(),
        );
        map
    }

    #[test]
    fn cookie_build_has_the_pinned_attributes() {
        let id = "0199d1c3-7a1b-7000-8000-000000000001";
        assert_eq!(
            build_session_cookie(id),
            format!("{SESSION_COOKIE}={id}; HttpOnly; Secure; SameSite=Lax; Path=/")
        );
        // The logout form: empty value, Max-Age=0, same flags.
        assert_eq!(
            build_session_cookie_clear(),
            format!("{SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/")
        );
    }

    #[test]
    fn read_session_id_round_trips_and_refuses_garbage() {
        let id = uuid::Uuid::new_v4();
        let map = headers(&build_session_cookie(&id.to_string()));
        assert_eq!(read_session_id(&map), Some(id));
        // With other cookies alongside it.
        let mixed = format!(
            "theme=dark; {}; consent=yes",
            build_session_cookie(&id.to_string())
        );
        assert_eq!(read_session_id(&headers(&mixed)), Some(id));

        assert_eq!(
            read_session_id(&headers("theme=dark")),
            None,
            "no session cookie"
        );
        assert_eq!(
            read_session_id(&headers(&format!("{SESSION_COOKIE}=not-a-uuid"))),
            None,
            "malformed value"
        );
        assert_eq!(
            read_session_id(&headers(&format!("{SESSION_COOKIE}=abc"))),
            None,
            "short garbage value"
        );
        assert_eq!(read_session_id(&HeaderMap::new()), None, "no Cookie header");
    }
}
