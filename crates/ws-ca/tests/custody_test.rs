//! The sealed-at-rest custody tests: the master-key residency modes
//! (RAM-unlocked, sealed) and the sealed fail-closed behavior.

use std::fs;
use std::path::PathBuf;

use ws_ca::error::CaError;
use ws_ca::keystore::KeyStore;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ws-ca-custody-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

fn cheap_params() -> ws_core::crypto::KdfParams {
    ws_core::crypto::KdfParams {
        m_cost: 8192,
        t_cost: 2,
        p_cost: 1,
    }
}

/// The sealed store refuses every key operation with the typed variant —
/// the fail-closed default of the sealed-at-rest design.
#[test]
fn sealed_store_refuses_key_operations() -> Result<(), CaError> {
    let dir = temp_dir("sealed");
    let ks = KeyStore::open_sealed(&dir)?;
    let err = ks.unwrap_ca_key(&uuid::Uuid::new_v4()).unwrap_err();
    assert!(
        matches!(err, CaError::Sealed),
        "a sealed store must answer Sealed, got {err:?}"
    );
    Ok(())
}

/// The unlocked mode carries the master in RAM: no master.key is read,
/// written, or present on disk at all — the store works with the key
/// ONLY in memory.
#[test]
fn unlocked_ram_mode_serves_without_any_master_file() -> Result<(), CaError> {
    let dir = temp_dir("unlocked");
    let master = ws_core::crypto::KeyEnvelope::derive_kek(
        "passphrase",
        b"0123456789abcdef0123456789abcdef",
        cheap_params(),
    )
    .unwrap();
    let kek = master.into_kek();
    let mut ks = KeyStore::open_unlocked(&dir, kek)?;
    let ca_id = uuid::Uuid::new_v4();
    let ca_bytes = b"ram-custody-ca-key".to_vec();
    ks.store_ca_key(&ca_id, &ca_bytes).unwrap();
    assert_eq!(&*ks.unwrap_ca_key(&ca_id).unwrap(), ca_bytes.as_slice());
    // NO plaintext master.key exists after the unlock-time conversion —
    // store_ca_key in unlocked mode must not have written one.
    assert!(
        !dir.join("master.key").exists(),
        "the unlocked keystore must not materialize a plaintext master.key"
    );
    Ok(())
}
