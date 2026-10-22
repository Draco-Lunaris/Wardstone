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
    /// The instant of the session's last TOUCH (login insert, a token
    /// rotation, or a `get` that found it live) — the idle-eviction clock's
    /// reference. One more immutable generation field: replaced whenever a
    /// generation is replaced, never mutated in place, so a snapshot a
    /// reader holds stays internally consistent.
    pub last_touched: Instant,
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
            last_touched: Instant::now(),
            refresh_token,
            rotation_lock: Arc::new(Mutex::new(())),
        }
    }
}

/// The store's clock: `Instant::now` in the product; an injected closure in
/// the tests, so the idle-window math is driven deterministically (no
/// wall-clock sleeps anywhere).
type NowFn = Arc<dyn Fn() -> Instant + Send + Sync>;

/// The store: one `HashMap` behind one async mutex, entries as shared
/// generations. Reads take the guard briefly and clone the `Arc` — cheap,
/// and consistent with the replacement discipline above.
///
/// Entries carry TWO clocks: the rotation stamp (`access_expires_at`, the
/// proxy's proactive-rotation first check) and the idle stamp
/// (`last_touched`), from which [`SessionStore::get`] evicts — an entry
/// nobody has touched for longer than `idle_eviction_after` is dropped the
/// next time anything reads the store (forgotten browser tabs' server-held
/// refresh tokens do not accumulate in memory until restart; ws-api's
/// refresh token itself stays valid — stateless revocation — so eviction
/// is memory hygiene, not revocation).
pub struct SessionStore {
    /// The access lifetime stamped on every insert and rotation (the
    /// binary pins [`crate::DEFAULT_SESSION_TTL`]; tests use `ZERO`).
    default_access_ttl: Duration,
    /// The idle window: a `last_touched` older than this (as of the clock
    /// the store reads) makes the entry evictable. The binary pins
    /// [`crate::DEFAULT_IDLE_EVICTION`]; tests that need sessions to
    /// survive pass a far-future window.
    idle_eviction_after: Duration,
    now: NowFn,
    sessions: Mutex<HashMap<Uuid, Arc<SessionEntry>>>,
}

impl SessionStore {
    pub fn new(default_access_ttl: Duration, idle_eviction_after: Duration) -> Self {
        SessionStore {
            default_access_ttl,
            idle_eviction_after,
            now: Arc::new(Instant::now),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// The eviction-clock seam (test-only): swap the real clock for an
    /// injected closure, so the idle-window behavior is testable without a
    /// single wall-clock sleep.
    #[cfg(test)]
    pub fn with_now_fn(mut self, now: NowFn) -> Self {
        self.now = now;
        self
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
        entry.access_expires_at = (self.now)() + self.default_access_ttl;
        entry.last_touched = (self.now)();
        let id = Uuid::new_v4();
        self.sessions.lock().await.insert(id, Arc::new(entry));
        id
    }

    /// The current generation of a session's entry, or `None` once removed
    /// (logout, a rotation failure, or IDLE EVICTION). The clone is the
    /// shared handle: lock identity travels with it.
    ///
    /// The read is also the eviction point, and the touch: under ONE guard
    /// hold, every entry whose `last_touched` has aged beyond the idle
    /// window is dropped, then the requested entry — if it survived — is
    /// replaced by a fresh generation stamped `last_touched = now` (the
    /// same replacement discipline as `update_tokens`; the rotation lock's
    /// `Arc` travels over). Every read therefore reaps forgotten sessions
    /// store-wide, which is WHY this store needs no spawned interval
    /// sweeper: an entry is reclaimed by whatever read happens next, and
    /// an operator UI's traffic provides those reads. Choosing the sweeper
    /// anyway would buy no earlier reclamation than the next request, and
    /// would add a background task to await on shutdown.
    pub async fn get(&self, id: Uuid) -> Option<Arc<SessionEntry>> {
        let mut sessions = self.sessions.lock().await;
        let now = (self.now)();
        // A clock earlier than `last_touched` cannot happen in the product
        // (`duration_since` saturates) and reads as zero idle time.
        sessions
            .retain(|_, entry| now.duration_since(entry.last_touched) <= self.idle_eviction_after);
        let old = sessions.get(&id)?;
        let touched = SessionEntry {
            tenant_id: old.tenant_id,
            username: old.username.clone(),
            role: old.role.clone(),
            access_token: old.access_token.clone(),
            access_expires_at: old.access_expires_at,
            last_touched: now,
            refresh_token: old.refresh_token.clone(),
            rotation_lock: Arc::clone(&old.rotation_lock),
        };
        let touched = Arc::new(touched);
        sessions.insert(id, Arc::clone(&touched));
        Some(touched)
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
                access_expires_at: (self.now)() + self.default_access_ttl,
                // The rotation counts as a touch: a session actively
                // rotating can never idle out while it rotates.
                last_touched: (self.now)(),
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
                access_expires_at: (self.now)(),
                // `force_expire` is bookkeeping, not a session touch: the
                // idle clock keeps its previous stamp.
                last_touched: old.last_touched,
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
        let store = SessionStore::new(Duration::from_secs(900), Duration::from_secs(86400));
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
        let store = SessionStore::new(Duration::from_secs(900), Duration::from_secs(86400));
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
        let store = SessionStore::new(Duration::from_secs(900), Duration::from_secs(86400));
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
        let store = SessionStore::new(Duration::from_secs(900), Duration::from_secs(86400));
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
        let store = SessionStore::new(Duration::ZERO, Duration::from_secs(60));
        let id = store.insert(entry()).await;
        let stale = store.get(id).await.expect("the inserted session");
        assert!(
            stale.access_expires_at <= Instant::now(),
            "ZERO ttl means the entry is never fresh"
        );
    }

    // # Idle eviction (the injected-clock seam)

    /// A virtual clock the eviction tests drive: the closure the store
    /// reads returns whatever instant the test last set, so the idle-window
    /// math never waits on the real clock.
    fn virtual_clock() -> (Arc<std::sync::Mutex<Instant>>, NowFn) {
        let clock = Arc::new(std::sync::Mutex::new(Instant::now()));
        let reader = Arc::clone(&clock);
        let now: NowFn = Arc::new(move || *reader.lock().unwrap());
        (clock, now)
    }

    /// An entry nobody has touched for longer than the idle window is GONE
    /// at the next get — the LAZY eviction this store chose over a spawned
    /// interval sweeper: every read walks the whole map once, so a session
    /// forgotten by its browser is reaped by any other session's next
    /// request (an operator UI's traffic provides those reads), and no
    /// background task exists to size, shut down, or await.
    #[tokio::test]
    async fn get_evicts_an_entry_idle_beyond_the_window() {
        let (clock, now) = virtual_clock();
        let store =
            SessionStore::new(Duration::from_secs(900), Duration::from_secs(60)).with_now_fn(now);
        let id = store.insert(entry()).await;
        assert!(store.get(id).await.is_some(), "fresh at t0");
        *clock.lock().unwrap() += Duration::from_secs(61);
        assert!(
            store.get(id).await.is_none(),
            "61s of idle beyond the 60s window is evicted"
        );
    }

    /// A get that finds the entry LIVE is itself a touch: the idle clock
    /// re-anchors, so an actively-read session never idles out even when
    /// its access token stays fresh enough to need no rotation.
    #[tokio::test]
    async fn get_touches_and_defers_the_idle_deadline() {
        let (clock, now) = virtual_clock();
        let store =
            SessionStore::new(Duration::from_secs(900), Duration::from_secs(60)).with_now_fn(now);
        let id = store.insert(entry()).await;
        *clock.lock().unwrap() += Duration::from_secs(50);
        assert!(store.get(id).await.is_some(), "inside the window at 50s");
        // The 50s read was a touch: the deadline moved to t0+50+60.
        *clock.lock().unwrap() += Duration::from_secs(50); // t0+100
        assert!(
            store.get(id).await.is_some(),
            "the earlier get re-anchored the idle clock"
        );
        *clock.lock().unwrap() += Duration::from_secs(70); // t0+170
        assert!(
            store.get(id).await.is_none(),
            "past the re-anchored window it evicts again"
        );
    }

    /// A rotation is a touch of its own: a session that keeps rotating
    /// (the always-rotate mode) never idles out mid-rotation, and the
    /// rotated generation starts its idle window fresh.
    #[tokio::test]
    async fn rotation_counts_as_a_touch() {
        let (clock, now) = virtual_clock();
        let store = SessionStore::new(Duration::ZERO, Duration::from_secs(60)).with_now_fn(now);
        let id = store.insert(entry()).await;
        *clock.lock().unwrap() += Duration::from_secs(70);
        store
            .update_tokens(id, "access-2".to_owned(), "ws_rt_2".to_owned())
            .await;
        assert!(
            store.get(id).await.is_some(),
            "the rotation re-anchored the idle clock"
        );
        *clock.lock().unwrap() += Duration::from_secs(70); // t0+140
        assert!(
            store.get(id).await.is_none(),
            "it idles out again from the rotation's stamp"
        );
    }
}
