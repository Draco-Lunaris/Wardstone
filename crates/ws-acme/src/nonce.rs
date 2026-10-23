//! The ACME anti-replay nonce store (RFC 8555 section 6.5): every
//! authenticated ACME request repeats a `Replay-Nonce` the server minted,
//! as the JWS protected header's `nonce` member, and the server must
//! refuse any nonce it has already accepted — however valid the signature
//! on top of it is. A minted nonce that is never presented is harmless;
//! one that is presented twice fails the second time.
//!
//! Discipline:
//!
//! - `mint` draws 32 OS-random bytes with the house `rand` 0.10 `SysRng`
//!   (the ws-auth opaque-token seeding idiom) and presents them unpadded
//!   base64url.
//! - `consume` is the single-use ledger: it removes the nonce if present
//!   (true) and reports a miss otherwise (false).
//! - The store is bounded: at most [`NONCE_CAP`] live entries; a mint that
//!   would exceed the cap evicts the oldest entry (an unexpired-but-
//!   unspent nonce dropped this way merely fails its later replay).
//! - Nonces expire 60 minutes after minting ([`NONCE_TTL_SECS`]); expired
//!   entries are purged as a prefix sweep on each `mint`/`consume`, so the
//!   expiry clock never needs a background task.
//! - The expiry clock is the house `with_now_fn` seam (the ws-web session
//!   store's pattern): `SystemTime` in the product, an injected closure in
//!   unit tests, no wall-clock sleeps anywhere.
//! - No zeroize on the raw bytes: a nonce is a public protocol value — it
//!   travels back to the server inside the client's next request header —
//!   not credential material like ws-auth's opaque tokens.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::{rngs::SysRng, TryRng};

/// How long a minted nonce stays consumable: 60 minutes. ACME clients
/// mint-and-use within one request round-trip; the window exists so the
/// bounded store cannot fill with nonces nobody will ever spend (RFC 8555
/// sets no lifetime; this is the house's session-window scale).
const NONCE_TTL_SECS: u64 = 60 * 60;

/// The live-entry cap. 4096 covers an ACME client population issuing in
/// bursts far beyond homelab scale while keeping the ledger a few hundred
/// kilobytes at worst.
const NONCE_CAP: usize = 4096;

/// One live nonce's ledger entry.
struct Entry {
    nonce: String,
    minted_at: u64,
}

/// The store's clock: unix seconds via `SystemTime` in the product; an
/// injected closure in the tests (the house `with_now_fn` seam), so
/// expiry behavior is driven deterministically.
type NowFn = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The anti-replay ledger. Cheap to clone into route state (`NonceStore`
/// holds only the mutex and the clock seam); `send`+`sync` throughout.
pub struct NonceStore {
    entries: Mutex<VecDeque<Entry>>,
    now_fn: NowFn,
}

impl NonceStore {
    /// A fresh, empty ledger running on the real clock (unix seconds).
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(VecDeque::new()),
            now_fn: Arc::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or_default()
            }),
        }
    }

    /// Mint a fresh nonce: 32 OS-random bytes, unpadded base64url (43
    /// characters). Registered in the ledger under the minting instant.
    pub fn mint(&self) -> String {
        let mut raw = [0u8; 32];
        if let Err(e) = SysRng.try_fill_bytes(&mut raw) {
            // The pinned signature is infallible, and a dead OS entropy
            // source is unrecoverable: minting must fail loudly.
            panic!("OS entropy source failed while minting an ACME nonce: {e}");
        }
        let nonce = URL_SAFE_NO_PAD.encode(raw);
        let minted_at = (self.now_fn)();
        let mut guard = self.lock();
        purge_expired(&mut guard, minted_at);
        guard.push_back(Entry {
            nonce: nonce.clone(),
            minted_at,
        });
        while guard.len() > NONCE_CAP {
            guard.pop_front();
        }
        nonce
    }

    /// The single-use ledger: `true` exactly once per minted nonce;
    /// `false` for unknown, replayed, or expired nonces.
    pub fn consume(&self, nonce: &str) -> bool {
        let now = (self.now_fn)();
        let mut guard = self.lock();
        purge_expired(&mut guard, now);
        match guard.iter().position(|e| e.nonce == nonce) {
            Some(position) => {
                guard.remove(position);
                true
            }
            None => false,
        }
    }

    /// The expiration-clock seam (test-only), mirroring ws-web's session
    /// store: swap the real clock for an injected closure so expiry is
    /// testable without a single wall-clock sleep.
    #[cfg(test)]
    pub fn with_now_fn(mut self, now_fn: NowFn) -> Self {
        self.now_fn = now_fn;
        self
    }

    /// Lock the ledger, carrying a poisoned mutex's guard through (the
    /// poisoning would only record a panic mid-ledger-update; the entries
    /// themselves stay structurally valid).
    fn lock(&self) -> MutexGuard<'_, VecDeque<Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Default for NonceStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Drop expired ledger entries. Entries sit in minting order and the clock
/// only moves forward, so expired entries are always a prefix of the queue.
fn purge_expired(entries: &mut VecDeque<Entry>, now: u64) {
    while let Some(front) = entries.front() {
        if now.saturating_sub(front.minted_at) >= NONCE_TTL_SECS {
            entries.pop_front();
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex as StdMutex};

    /// A clock the test can move: the closure reads a shared counter.
    fn movable_clock() -> (Arc<StdMutex<u64>>, NowFn) {
        let now = Arc::new(StdMutex::new(1_700_000_000u64));
        let reader = Arc::clone(&now);
        let now_fn: NowFn =
            Arc::new(move || *reader.lock().unwrap_or_else(PoisonError::into_inner));
        (now, now_fn)
    }

    #[test]
    fn expired_nonce_is_not_consumable() {
        let (now, now_fn) = movable_clock();
        let store = NonceStore::new().with_now_fn(now_fn);
        let nonce = store.mint();
        *now.lock().unwrap_or_else(PoisonError::into_inner) += NONCE_TTL_SECS + 1;
        assert!(!store.consume(&nonce), "a nonce past its expiry is refused");
    }

    #[test]
    fn nonce_survives_to_one_minute_before_expiry() {
        let (now, now_fn) = movable_clock();
        let store = NonceStore::new().with_now_fn(now_fn);
        let nonce = store.mint();
        *now.lock().unwrap_or_else(PoisonError::into_inner) += NONCE_TTL_SECS - 1;
        assert!(store.consume(&nonce), "a nonce inside its window works");
    }

    #[test]
    fn expiry_uses_the_minting_instant_per_entry() {
        let (now, now_fn) = movable_clock();
        let store = NonceStore::new().with_now_fn(now_fn);
        let early = store.mint();
        *now.lock().unwrap_or_else(PoisonError::into_inner) += 1_800;
        let late = store.mint();
        // 1800s after minting: the early nonce is inside its window.
        assert!(store.consume(&early));
        // 3600s later the late nonce's own window (it started at +1800s)
        // is over, even though only one tick separates them on the shared
        // clock: each entry runs on its own minting instant.
        *now.lock().unwrap_or_else(PoisonError::into_inner) += NONCE_TTL_SECS;
        assert!(!store.consume(&late));
    }
}
