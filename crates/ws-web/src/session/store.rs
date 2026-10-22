//! The server-side session store: where ws-web keeps the JWT pair a
//! browser session owns, so the browser NEVER does.
//!
//! One entry per logged-in browser, keyed by the minted session `Uuid` —
//! the cookie's opaque value. The store's memory IS the session: entries
//! die on ws-web restart (the design refinement over a
//! cookie-carries-refresh-token shape, controller-approved: strictly
//! tighter — a stolen cookie dies with the process that minted it).
//!
//! # The generation-replacement design (the once-only rotation pin)
//!
//! Entries live as `Arc<SessionEntry>` so a reader can hold one across
//! `await`s, but token rotation must MUTATE. Both work through
//! replacement: [`SessionStore::update_tokens`] swaps the entry for a new
//! generation — cloning the immutable identity fields and, crucially,
//! the SAME `Arc` holding [`SessionEntry::rotation_lock`], so the
//! per-session lock's identity survives every generation (waiters spawned
//! against generation N serialize against the rotation of generation N+1).
//!
//! The rotation critical section (see [`crate::session::relay`]'s
//! `rotate_once`) then only needs the lock + the store: acquire the
//! rotation lock, re-read the CURRENT generation from the map, and (only
//! if the observed stale tokens are still the current ones) relay the one
//! refresh. Two concurrent expired probes therefore collapse into exactly
//! one ws-api refresh call — the second waiter re-reads the rotated
//! generation and skips its own refresh.
//!
//! `default_access_ttl` is the seam: every `insert`/`update_tokens` stamps
//! `access_expires_at = now + ttl`, so `Duration::ZERO` makes every stored
//! access token instantly stale — the tests' always-rotate mode (the real
//! binary pins 15 minutes, matching ws-api's JWT lifetime).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use uuid::Uuid;

/// One logged-in browser session's server-side record.
///
/// The identity fields (`tenant_id`, `username`, `role`) are fixed at
/// login; the token fields are replaced whole by
/// [`SessionStore::update_tokens`] (never mutated in place — an `Arc`
/// snapshot a reader holds is always internally consistent). No `Debug`
/// derive: the token fields are secrets, and a stray log line must never
/// be able to print one.
pub struct SessionEntry {
    /// The tenant the login resolved against (identity, fixed at insert).
    pub tenant_id: Uuid,
    /// The account name from the `/me` identity fetch (fixed at insert).
    pub username: String,
    /// The account role from the `/me` identity fetch (fixed at insert).
    pub role: String,
    /// The access token injected into proxied requests.
    pub access_token: String,
    /// ws-web's local expiry bookkeeping: past this instant the proxy
    /// rotates proactively (the ws-api JWT's own `exp` is the authority
    /// behind it — this stamp is the cheaper first check).
    pub access_expires_at: Instant,
    /// The refresh token, alive ONLY here (never in a cookie, never in a
    /// response body).
    pub refresh_token: String,
    /// The per-session rotation lock under an `Arc` so generations share
    /// ONE lock identity (see the module docs). Taking it serializes the
    /// session's refresh critical sections — including logout's
    /// rotate-and-retry.
    pub rotation_lock: Arc<Mutex<()>>,
}

impl SessionEntry {
    /// Assemble an entry from a login's identity + token pair. The expiry
    /// stamp is left "now" (already stale) — only the store's
    /// [`SessionStore::insert`]/`update_tokens` know the store's TTL, and
    /// they stamp it themselves, which keeps the TTL in exactly one place.
    pub fn new(
        tenant_id: Uuid,
        username: String,
        role: String,
        access_token: String,
        refresh_token: String,
    ) -> Self {
        SessionEntry {
            tenant_id,
            username,
            role,
            access_token,
            access_expires_at: Instant::now(),
            refresh_token,
            rotation_lock: Arc::new(Mutex::new(())),
        }
    }
}

/// The store: one `HashMap` behind one async mutex, entries as shared
/// generations. Reads take the guard briefly and clone the `Arc` — cheap,
/// and consistent with the replacement discipline above.
pub struct SessionStore {
    /// The access lifetime stamped on every insert and rotation (the
    /// binary pins [`crate::DEFAULT_SESSION_TTL`]; tests use `ZERO`).
    default_access_ttl: Duration,
    sessions: Mutex<HashMap<Uuid, Arc<SessionEntry>>>,
}

impl SessionStore {
    pub fn new(default_access_ttl: Duration) -> Self {
        SessionStore {
            default_access_ttl,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// The access lifetime this store stamps on entries (the rotation
    /// callers need it only via `update_tokens`, but tests and diagnostics
    /// read it too).
    pub fn default_access_ttl(&self) -> Duration {
        self.default_access_ttl
    }

    /// Insert a fresh session; returns the minted session id — the cookie
    /// value (opaque: a v4 `Uuid` carries no token material).
    pub async fn insert(&self, mut entry: SessionEntry) -> Uuid {
        entry.access_expires_at = Instant::now() + self.default_access_ttl;
        let id = Uuid::new_v4();
        self.sessions.lock().await.insert(id, Arc::new(entry));
        id
    }

    /// The current generation of a session's entry, or `None` once
    /// removed (logout, or a rotation failure killed it). The clone is the
    /// shared handle: lock identity travels with it.
    pub async fn get(&self, id: Uuid) -> Option<Arc<SessionEntry>> {
        self.sessions.lock().await.get(&id).cloned()
    }

    /// End a session (logout, or a rotation's failure). Removing an
    /// already-removed id is a no-op.
    pub async fn remove(&self, id: Uuid) {
        self.sessions.lock().await.remove(&id);
    }

    /// Swap in a fresh token pair as a new generation: the identity fields
    /// and the rotation lock's `Arc` carry over, the expiry stamp resets
    /// to `now + default_access_ttl`. A no-op if the session was removed.
    pub async fn update_tokens(&self, id: Uuid, access_token: String, refresh_token: String) {
        let mut sessions = self.sessions.lock().await;
        if let Some(old) = sessions.get(&id) {
            let replacement = SessionEntry {
                tenant_id: old.tenant_id,
                username: old.username.clone(),
                role: old.role.clone(),
                access_token,
                access_expires_at: Instant::now() + self.default_access_ttl,
                refresh_token,
                rotation_lock: Arc::clone(&old.rotation_lock),
            };
            sessions.insert(id, Arc::new(replacement));
        }
    }

    /// Mark the CURRENT generation's expiry as `now` without touching its
    /// tokens — the next proxied request takes the rotation path even
    /// though the (real, 15-minute) JWT is still valid. A test seam: the
    /// session_test suite drives the rotation machinery deterministically
    /// (no waiting on the real clock). Unused by the product code.
    pub async fn force_expire(&self, id: Uuid) {
        let mut sessions = self.sessions.lock().await;
        if let Some(old) = sessions.get(&id) {
            let replacement = SessionEntry {
                tenant_id: old.tenant_id,
                username: old.username.clone(),
                role: old.role.clone(),
                access_token: old.access_token.clone(),
                access_expires_at: Instant::now(),
                refresh_token: old.refresh_token.clone(),
                rotation_lock: Arc::clone(&old.rotation_lock),
            };
            sessions.insert(id, Arc::new(replacement));
        }
    }
}

/// # Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> SessionEntry {
        SessionEntry::new(
            Uuid::new_v4(),
            "admin".to_owned(),
            "admin".to_owned(),
            "access-token".to_owned(),
            "ws_rt_refresh".to_owned(),
        )
    }

    /// `insert` stamps the TTL and mints the id the cookie carries; the
    /// entry comes back through `get`.
    #[tokio::test]
    async fn insert_stamps_ttl_and_get_round_trips() {
        let store = SessionStore::new(Duration::from_secs(900));
        let id = store.insert(entry()).await;
        let fresh = store.get(id).await.expect("the inserted session");
        assert!(
            fresh.access_expires_at > Instant::now(),
            "the TTL is stamped"
        );
        assert_eq!(fresh.username, "admin");
        assert!(fresh.refresh_token.starts_with("ws_rt_"));
    }

    /// `update_tokens` replaces the generation: new tokens, reset expiry,
    /// but the SAME rotation lock identity — the once-only rotation pin
    /// depends on waiters across generations sharing one lock.
    #[tokio::test]
    async fn update_tokens_rotates_the_generation_and_keeps_one_lock() {
        let store = SessionStore::new(Duration::from_secs(900));
        let id = store.insert(entry()).await;
        let first = store.get(id).await.expect("the first generation");
        store
            .update_tokens(id, "access-2".to_owned(), "ws_rt_2".to_owned())
            .await;
        let second = store.get(id).await.expect("the second generation");
        assert_eq!(second.access_token, "access-2");
        assert_eq!(second.refresh_token, "ws_rt_2");
        assert!(
            second.access_expires_at > Instant::now(),
            "the expiry resets"
        );
        assert!(
            Arc::ptr_eq(&first.rotation_lock, &second.rotation_lock),
            "generations share ONE rotation lock identity"
        );
        let _ = first.rotation_lock.lock().await; // the old handle still locks
    }

    /// `remove` (and removing again) leaves the store without the entry.
    #[tokio::test]
    async fn remove_is_idempotent() {
        let store = SessionStore::new(Duration::from_secs(900));
        let id = store.insert(entry()).await;
        store.remove(id).await;
        assert!(store.get(id).await.is_none());
        store.remove(id).await; // no panic, no resurrection
        assert!(store.get(id).await.is_none());
    }

    /// The test seam: `force_expire` stamps the current generation stale
    /// without disturbing the tokens.
    #[tokio::test]
    async fn force_expire_marks_the_generation_stale() {
        let store = SessionStore::new(Duration::from_secs(900));
        let id = store.insert(entry()).await;
        store.force_expire(id).await;
        let expired = store.get(id).await.expect("the session survives");
        assert!(
            expired.access_expires_at <= Instant::now(),
            "the expiry stamp is now past"
        );
        assert_eq!(expired.refresh_token, "ws_rt_refresh", "tokens untouched");
    }

    /// The ZERO-ttl seam: an insert is instantly stale — the always-rotate
    /// mode the concurrency tests run under.
    #[tokio::test]
    async fn zero_ttl_inserts_are_instantly_stale() {
        let store = SessionStore::new(Duration::ZERO);
        let id = store.insert(entry()).await;
        let stale = store.get(id).await.expect("the inserted session");
        assert!(
            stale.access_expires_at <= Instant::now(),
            "ZERO ttl means the entry is never fresh"
        );
    }
}
