//! The nonce-store suite over the public API: minted shape, single-use,
//! and the bounded ledger's oldest-eviction. (Expiry is driven through the
//! `with_now_fn` seam in the crate's internal unit tests — integration
//! suites get the real clock, which nobody waits on here.)

use ws_acme::NonceStore;

#[test]
fn mint_is_unpadded_urlsafe_and_unique() {
    let store = NonceStore::new();
    let a = store.mint();
    let b = store.mint();
    assert_ne!(a, b, "two mints never collide");
    // 32 bytes -> exactly 43 unpadded base64url characters.
    assert_eq!(a.len(), 43, "{a}");
    assert!(
        a.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "{a} is not unpadded base64url"
    );
}

#[test]
fn consume_is_single_use() {
    let store = NonceStore::new();
    let nonce = store.mint();
    assert!(store.consume(&nonce), "first presentation wins");
    assert!(!store.consume(&nonce), "second presentation is a replay");
    assert!(!store.consume(&nonce), "replays keep failing");
}

#[test]
fn unknown_nonce_is_rejected() {
    let store = NonceStore::new();
    assert!(!store.consume("not-a-minted-nonce"));
    let nonce = store.mint();
    assert!(
        !store.consume(&format!("{nonce}x")),
        "a mutated nonce is unknown"
    );
}

#[test]
fn cap_evicts_the_oldest_nonce() {
    let store = NonceStore::new();
    let oldest = store.mint();
    let second = store.mint();
    let mut newest = String::new();
    for _ in 0..4095 {
        newest = store.mint();
    }
    // 4097 mints push the ledger one past its cap, evicting the front.
    assert!(!store.consume(&oldest), "the oldest nonce was evicted");
    assert!(store.consume(&second), "the second-oldest survives");
    assert!(store.consume(&newest), "the newest survives");
    assert!(!store.consume(&newest), "survival is not double-usage");
}
