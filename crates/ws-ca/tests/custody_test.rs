//! The sealed-at-rest custody tests: the three master-key residency modes
//! (legacy file, RAM-unlocked, sealed), the conversion (legacy plaintext →
//! envelope, the plaintext deleted), and the sealed fail-closed behavior.

use std::fs;
use std::path::PathBuf;

use ws_ca::error::CaError;
use ws_ca::keystore::KeyStore;
use ws_core::crypto::KeyEnvelope;
use zeroize::Zeroizing;

const LEGACY_ENVELOPE: &str = "master.envelope";

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

/// The LEGACY file-read mode reproduces the pre-sealing behavior: a
/// plaintext master.key beside CA envelopes loads them exactly as before
/// (the conversion is opt-in, never forced).
#[test]
fn legacy_file_mode_keeps_the_existing_store_working() -> Result<(), CaError> {
    let dir = temp_dir("legacy");
    let mut ks = KeyStore::open(&dir)?;
    ks.ensure_master_key().unwrap();
    let ca_bytes = b"a-ca-private-key-der".to_vec();
    let ca_id = uuid::Uuid::new_v4();
    ks.store_ca_key(&ca_id, &ca_bytes).unwrap();
    assert_eq!(
        ks.load_ca_key(&ca_id).unwrap().as_slice(),
        ca_bytes.as_slice()
    );
    Ok(())
}

/// The sealed store refuses every key operation with the typed variant —
/// the fail-closed default of the sealed-at-rest design.
#[test]
fn sealed_store_refuses_key_operations() -> Result<(), CaError> {
    let dir = temp_dir("sealed");
    let ks = KeyStore::open_sealed(&dir)?;
    let err = ks.load_ca_key(&uuid::Uuid::new_v4()).unwrap_err();
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
    let kek_zeroizing = master.into_kek();
    let mut ks = KeyStore::open_unlocked(&dir, kek_zeroizing)?;
    let ca_id = uuid::Uuid::new_v4();
    let ca_bytes = b"ram-custody-ca-key".to_vec();
    ks.store_ca_key(&ca_id, &ca_bytes).unwrap();
    assert_eq!(
        ks.load_ca_key(&ca_id).unwrap().as_slice(),
        ca_bytes.as_slice()
    );
    // NO plaintext master.key exists after the unlock-time conversion —
    // store_ca_key in unlocked mode must not have written one.
    assert!(
        !dir.join("master.key").exists(),
        "the unlocked keystore must not materialize a plaintext master.key"
    );
    Ok(())
}

/// The conversion: a legacy plaintext master.key wraps into a KeyEnvelope
/// file and the plaintext original is DELETED — the disk then holds only
/// the inert envelope, and the unlocked keystore runs from the envelope's
/// key bytes.
#[test]
fn conversion_wraps_the_legacy_master_and_deletes_the_plaintext() -> Result<(), CaError> {
    let dir = temp_dir("convert");
    {
        let mut ks = KeyStore::open(&dir)?;
        ks.ensure_master_key().unwrap();
    }
    let master = fs::read(dir.join("master.key")).unwrap();
    let master_env = dir.join(LEGACY_ENVELOPE);
    KeyEnvelope::write_envelope(
        &master_env,
        "the-operator-passphrase",
        &master,
        cheap_params(),
    )
    .unwrap();
    fs::remove_file(dir.join("master.key")).unwrap();

    // The unlocked keystore then runs from the ENVELOPE: open with the
    // passphrase, take custody of the SAME key bytes, and load an
    // existing envelope.
    let opened = KeyEnvelope::open_envelope(&master_env, "the-operator-passphrase").unwrap();
    let mut key = [0u8; 32];
    key.copy_from_slice(&opened);
    let ks = KeyStore::open_unlocked(&dir, Zeroizing::new(key))?;
    assert_eq!(
        ks.master_key_bytes().unwrap().as_slice(),
        master.as_slice(),
        "unlocked-from-envelope == the legacy plaintext key"
    );
    Ok(())
}
