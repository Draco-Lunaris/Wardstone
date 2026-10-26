//! Task 5 (the seal-at-creation plan): the arena-custody tests.
//!
//! - A SEALED store must never read or write a plaintext `master.key`:
//!   a stray plaintext left on the volume is opened past, untouched and
//!   unused, and every custody operation on the sealed store refuses
//!   with [`CaError::Sealed`] rather than deriving anything from it.
//! - The per-use CA-key unwrap ([`KeyStore::with_ca_key`]) hands the
//!   envelope's plaintext DER to the caller's closure inside the
//!   protected arena and WIPES the arena region when the closure
//!   returns — the bytes the closure saw read as zero afterwards, read
//!   back through ws-secmem's read-only `peek_for_test` accessor (a
//!   test-only path, enabled solely via this crate's dev-dependency).

use std::fs;
use std::path::PathBuf;

use uuid::Uuid;
use ws_ca::error::CaError;
use ws_ca::keystore::KeyStore;

/// A fresh directory per test: unique per test name and process id,
/// swept before use so a stale run cannot interfere (the house pattern).
fn temp_keystore_dir(test_name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("ws-ca-keystore-{test_name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// A sealed store never reads or writes a plaintext master key: a stray
/// `master.key` (a half-converted install, an operator's backup) is
/// opened past untouched, and both storing and unwrapping refuse with
/// [`CaError::Sealed`] — the stray file is never the source of anything.
#[test]
fn open_sealed_never_reads_or_writes_a_plaintext_master() {
    let dir = temp_keystore_dir("sealed-strays-past-a-plaintext-master");
    fs::create_dir_all(&dir).expect("create the keys directory");
    let stray = dir.join("master.key");
    let stray_bytes: &[u8] = b"a stray plaintext master a sealed store must ignore";
    fs::write(&stray, stray_bytes).expect("plant the stray plaintext master");

    let mut sealed = KeyStore::open_sealed(&dir).expect("the sealed store opens over the stray");
    assert_eq!(
        fs::read(&stray).expect("the stray file still exists"),
        stray_bytes,
        "opening sealed never touches the stray plaintext master"
    );

    let stray_id = Uuid::new_v4();
    let err = sealed.store_ca_key(&stray_id, b"a-private-key-der");
    assert!(
        matches!(err, Err(CaError::Sealed)),
        "a sealed store refuses to store a CA key, got {err:?}"
    );
    let err = sealed.unwrap_ca_key(&stray_id);
    assert!(
        matches!(err, Err(CaError::Sealed)),
        "a sealed store refuses to unwrap a CA key without ever reading the stray: {err:?}"
    );
    assert_eq!(
        fs::read(&stray).expect("the stray file still exists"),
        stray_bytes,
        "the sealed store wrote nothing through its refusals"
    );
}

/// The per-use unwrap wipes after use: `with_ca_key` unwraps the
/// envelope into the protected arena, hands the plaintext DER to the
/// closure, and wipes the arena region on return — the region the
/// closure saw reads as zero afterwards, read back through the
/// test-only `peek_for_test` accessor.
#[test]
fn with_ca_key_wipes_after_use() {
    let dir = temp_keystore_dir("with-ca-key-wipes-after-use");
    let pool = ws_secmem::global().expect("the protected arena initialises");
    let master = pool
        .alloc_copy(&[0x5c; ws_ca::keystore::MASTER_KEY_LEN])
        .expect("the master key is copied into the arena");
    let mut keystore = KeyStore::open_unlocked(&dir, master)
        .expect("the unlocked store opens with its master in the arena");

    let ca_id = Uuid::new_v4();
    let der: &[u8] = b"a-ca-private-key-der-the-closure-must-see";
    keystore
        .store_ca_key(&ca_id, der)
        .expect("the CA key is stored");

    let mut seen = std::ptr::null::<u8>();
    let seen_len = keystore
        .with_ca_key(&ca_id, |key| {
            assert_eq!(key, der, "the closure sees the stored DER");
            seen = key.as_ptr();
            Ok::<usize, CaError>(key.len())
        })
        .expect("with_ca_key unwraps and hands the key to the closure");

    let region = pool
        .peek_for_test(seen, seen_len)
        .expect("the arena region is inside the protected mapping");
    assert!(
        region.iter().all(|byte| *byte == 0),
        "the arena region reads zero after the closure returns: {region:?}"
    );
}
