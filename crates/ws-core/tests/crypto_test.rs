//! KeyEnvelope tests: the operator master passphrase derives a KEK that
//! seals sensitive files as inert ciphertext envelopes. No database — pure
//! crypto + temp files.

use std::fs;
use std::path::PathBuf;

use ws_core::crypto::KeyEnvelope;
use ws_core::error::CoreError;

/// Low-cost KDF params: the production unlock targets ~1 s (argon2id with
/// heavy memory); the tests assert the crypto, not the wall clock.
fn cheap_params() -> ws_core::crypto::KdfParams {
    ws_core::crypto::KdfParams {
        m_cost: 8192,
        t_cost: 2,
        p_cost: 1,
    }
}

fn temp_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ws-core-envelope-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir.join(format!("{name}.envelope"))
}

#[test]
fn envelope_roundtrip_opens_with_the_right_passphrase_only() {
    let path = temp_path("roundtrip");
    let plaintext = b"the-ca-master-key-bytes";

    KeyEnvelope::write_envelope(
        &path,
        "a-long-correct-passphrase",
        plaintext,
        cheap_params(),
        0,
    )
    .expect("seal the envelope");

    // The file carries NO plaintext: the sensitive bytes are absent from
    // the on-disk form.
    let raw = fs::read_to_string(&path).unwrap();
    assert!(
        !raw.contains("the-ca-master-key-bytes"),
        "the envelope file must not contain the plaintext"
    );
    assert!(raw.contains("\"ciphertext\""), "the envelope is structured");

    // The right passphrase opens; a wrong one is a typed failure.
    let opened = KeyEnvelope::open_envelope(&path, "a-long-correct-passphrase")
        .expect("the right passphrase opens the envelope");
    assert_eq!(&*opened, plaintext);

    let err = KeyEnvelope::open_envelope(&path, "a-long-wrong-passphrase").unwrap_err();
    assert!(
        matches!(err, CoreError::Crypto(_)),
        "a wrong passphrase is a typed crypto failure, got {err:?}"
    );
}

#[test]
fn envelope_salts_are_fresh_per_write() {
    let a = temp_path("salt-a");
    let b = temp_path("salt-b");
    KeyEnvelope::write_envelope(&a, "same-passphrase", b"same-bytes", cheap_params(), 0).unwrap();
    KeyEnvelope::write_envelope(&b, "same-passphrase", b"same-bytes", cheap_params(), 0).unwrap();

    let raw_a = fs::read_to_string(&a).unwrap();
    let raw_b = fs::read_to_string(&b).unwrap();
    assert_ne!(
        raw_a, raw_b,
        "two envelopes of the same plaintext must differ (fresh salt + nonce)"
    );
}

#[test]
fn envelope_open_is_in_memory_only() {
    let path = temp_path("zeroize");
    KeyEnvelope::write_envelope(&path, "another-passphrase", b"payload", cheap_params(), 0)
        .unwrap();
    let opened = KeyEnvelope::open_envelope(&path, "another-passphrase")
        .expect("the right passphrase opens");
    assert_eq!(&*opened, b"payload");
}

#[test]
fn kek_derive_is_deterministic_per_salt_and_params() {
    let a = KeyEnvelope::derive_kek("passphrase-1", b"salt-salt-salt-salt", cheap_params())
        .unwrap()
        .into_kek();
    let b = KeyEnvelope::derive_kek("passphrase-1", b"salt-salt-salt-salt", cheap_params())
        .unwrap()
        .into_kek();
    let c = KeyEnvelope::derive_kek("passphrase-2", b"salt-salt-salt-salt", cheap_params())
        .unwrap()
        .into_kek();
    assert_eq!(&*a, &*b, "same passphrase+salt+params derive the same KEK");
    assert_ne!(&*a, &*c, "a different passphrase derives a different KEK");
}

/// The DB-URL password substitution replaces exactly the password and
/// leaves everything else byte-identical — and inserts a password into a
/// URL that carried none (the api's password-less compose contract).
#[test]
fn db_password_substitution_is_surgical() {
    let url = "postgres://wardstone:old-secret@db:5432/wardstone";
    let substituted = ws_core::crypto::substitute_db_password(url, "new-credential");
    assert_eq!(
        substituted, "postgres://wardstone:new-credential@db:5432/wardstone",
        "only the password changes"
    );
    let bare = "postgres://wardstone@db:5432/wardstone";
    assert_eq!(
        ws_core::crypto::substitute_db_password(bare, "inserted"),
        "postgres://wardstone:inserted@db:5432/wardstone",
        "a password-less URL gains one"
    );
    let weird = "not-a-url";
    assert_eq!(
        ws_core::crypto::substitute_db_password(weird, "x"),
        weird,
        "a non-URL passes through"
    );
}

// --- Task 4b: the generation counter + the volume re-wrap ---

/// A volume directory holding the four standard envelopes — the shape the
/// passphrase-change flow operates on.
fn temp_volume(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ws-core-volume-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// The four standard envelope names, master first for readability (the
/// re-wrap's own write order puts master LAST — the anchor rule).
const VOLUME_FILES: [&str; 4] = [
    ws_core::crypto::MASTER_ENVELOPE_FILE,
    ws_core::crypto::SECRET_ENVELOPE_FILE,
    ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE,
    ws_core::crypto::JWT_ENVELOPE_FILE,
];

fn seal_volume(dir: &std::path::Path, passphrase: &str, generation: u64) {
    for (i, file) in VOLUME_FILES.iter().enumerate() {
        KeyEnvelope::write_envelope(
            &dir.join(file),
            passphrase,
            format!("volume-payload-{i}").as_bytes(),
            cheap_params(),
            generation,
        )
        .expect("seal the volume envelope");
    }
}

#[test]
fn envelope_generation_roundtrips_through_the_file() {
    let path = temp_path("generation");
    KeyEnvelope::write_envelope(&path, "a-passphrase", b"bytes", cheap_params(), 7)
        .expect("seal with an explicit generation");

    assert_eq!(
        KeyEnvelope::read_generation(&path).expect("the generation reads back"),
        7,
        "the written generation survives the file"
    );
    let (_, params, generation) = KeyEnvelope::read_kdf_state(&path).unwrap();
    assert_eq!(generation, 7);
    assert_eq!(params, cheap_params(), "the KDF parameters ride along");
}

#[test]
fn envelope_format_two_requires_a_generation() {
    // A version-1 file (the pre-generation format) refuses at open — the
    // format bump is loud, never a silent default.
    let v1 = temp_path("format-v1");
    let legacy = serde_json::json!({
        "version": 1, "kdf": "argon2id", "m_cost": 8192, "t_cost": 2, "p_cost": 1,
        "salt": "AA==", "nonce": "AA==", "ciphertext": "AA=="
    });
    fs::write(&v1, legacy.to_string()).unwrap();
    let err = KeyEnvelope::open_envelope(&v1, "any-passphrase").unwrap_err();
    assert!(
        matches!(err, CoreError::Crypto(_)),
        "a v1 envelope refuses loudly, got {err:?}"
    );

    // A version-2 file missing the generation field refuses at the state
    // read — the counter is load-bearing for the mixed-state detection,
    // not an optional annotation.
    let bare = temp_path("format-bare");
    let sealed = serde_json::json!({
        "version": 2, "kdf": "argon2id", "m_cost": 8192, "t_cost": 2, "p_cost": 1,
        "salt": "AA==", "nonce": "AA==", "ciphertext": "AA=="
    });
    fs::write(&bare, sealed.to_string()).unwrap();
    let err = KeyEnvelope::read_kdf_state(&bare).unwrap_err();
    assert!(
        matches!(err, CoreError::Crypto(_)),
        "a v2 envelope without a generation is malformed, got {err:?}"
    );
}

#[test]
fn rewrap_volume_reseals_every_envelope_under_the_next_passphrase() {
    let dir = temp_volume("happy");
    seal_volume(&dir, "the-current-passphrase", 0);

    let new_generation = ws_core::crypto::rewrap_volume(
        &dir,
        &VOLUME_FILES,
        "the-current-passphrase",
        "the-next-passphrase",
    )
    .expect("the change re-wraps the volume");

    assert_eq!(
        new_generation, 1,
        "a completed change advances the generation"
    );
    for (i, file) in VOLUME_FILES.iter().enumerate() {
        let opened = KeyEnvelope::open_envelope(&dir.join(file), "the-next-passphrase")
            .expect("the next passphrase opens every re-wrapped envelope");
        assert_eq!(
            &*opened,
            format!("volume-payload-{i}").as_bytes(),
            "the payload survives the re-wrap"
        );
        assert_eq!(KeyEnvelope::read_generation(&dir.join(file)).unwrap(), 1);
        let err =
            KeyEnvelope::open_envelope(&dir.join(file), "the-current-passphrase").unwrap_err();
        assert!(
            matches!(err, CoreError::Crypto(_)),
            "the retired passphrase no longer opens {file}"
        );
    }
}

#[test]
fn rewrap_volume_with_a_wrong_current_touches_nothing() {
    let dir = temp_volume("wrong-current");
    seal_volume(&dir, "the-current-passphrase", 3);

    let err = ws_core::crypto::rewrap_volume(
        &dir,
        &VOLUME_FILES,
        "a-wrong-current-passphrase",
        "the-next-passphrase",
    )
    .unwrap_err();
    assert!(
        matches!(err, CoreError::Crypto(_)),
        "a wrong current passphrase is a typed crypto failure, got {err:?}"
    );

    for (i, file) in VOLUME_FILES.iter().enumerate() {
        let opened = KeyEnvelope::open_envelope(&dir.join(file), "the-current-passphrase")
            .expect("a refused change leaves every envelope untouched");
        assert_eq!(&*opened, format!("volume-payload-{i}").as_bytes());
        assert_eq!(
            KeyEnvelope::read_generation(&dir.join(file)).unwrap(),
            3,
            "a refused change advances nothing"
        );
    }
}

#[test]
fn rewrap_volume_completes_a_mixed_volume_from_a_crashed_change() {
    let dir = temp_volume("mixed");
    seal_volume(&dir, "the-current-passphrase", 0);
    // A crashed change re-wrapped the jwt + db-credential envelopes under
    // the next passphrase at generation 1 and died before the rest
    // (master is written LAST, so the anchor is still the old one).
    for file in [
        ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE,
        ws_core::crypto::JWT_ENVELOPE_FILE,
    ] {
        let index = VOLUME_FILES.iter().position(|f| *f == file).unwrap();
        KeyEnvelope::write_envelope(
            &dir.join(file),
            "the-next-passphrase",
            format!("volume-payload-{index}").as_bytes(),
            cheap_params(),
            1,
        )
        .expect("simulate the crashed change's partial re-wrap");
    }

    let new_generation = ws_core::crypto::rewrap_volume(
        &dir,
        &VOLUME_FILES,
        "the-current-passphrase",
        "the-next-passphrase",
    )
    .expect("the completion finishes what the crash started");

    assert_eq!(
        new_generation, 1,
        "the completion converges on the crashed change's generation"
    );
    for (i, file) in VOLUME_FILES.iter().enumerate() {
        let opened = KeyEnvelope::open_envelope(&dir.join(file), "the-next-passphrase")
            .expect("every envelope now opens under the next passphrase");
        assert_eq!(&*opened, format!("volume-payload-{i}").as_bytes());
        assert_eq!(KeyEnvelope::read_generation(&dir.join(file)).unwrap(), 1);
    }
}

#[test]
fn rewrap_volume_refuses_an_inconsistent_volume() {
    // master AHEAD of its envelope set: the anchor invariant (master
    // written last) is violated, so the generations cannot be reconciled.
    let dir = temp_volume("ahead");
    seal_volume(&dir, "the-current-passphrase", 0);
    KeyEnvelope::write_envelope(
        &dir.join(ws_core::crypto::MASTER_ENVELOPE_FILE),
        "the-next-passphrase",
        b"volume-payload-0",
        cheap_params(),
        1,
    )
    .unwrap();
    let err = ws_core::crypto::rewrap_volume(
        &dir,
        &VOLUME_FILES,
        "the-next-passphrase",
        "another-passphrase",
    )
    .unwrap_err();
    assert!(
        matches!(err, CoreError::Crypto(_)),
        "a volume whose anchor ran ahead refuses the re-wrap, got {err:?}"
    );
    for file in VOLUME_FILES.iter() {
        let passphrase = if *file == ws_core::crypto::MASTER_ENVELOPE_FILE {
            "the-next-passphrase"
        } else {
            "the-current-passphrase"
        };
        KeyEnvelope::open_envelope(&dir.join(file), passphrase)
            .expect("the refused re-wrap changed nothing");
    }
}

#[test]
fn scan_volume_reports_a_clean_volume_consistent() {
    // The all-four shape (a converted volume) and the fresh-install
    // shape (three files — the JWT pair mints at the first unlock)
    // are BOTH consistent: the absent envelope joins no disagreement.
    let dir = temp_volume("scan-clean");
    seal_volume(&dir, "the-master-passphrase", 0);
    let scan = ws_core::crypto::scan_volume(&dir).expect("the scan reads a clean volume");
    assert!(!scan.mixed, "a volume at one generation is not mixed");
    assert_eq!(
        scan.present, VOLUME_FILES,
        "the scan reports every present envelope"
    );

    fs::remove_file(dir.join(ws_core::crypto::JWT_ENVELOPE_FILE)).unwrap();
    let scan = ws_core::crypto::scan_volume(&dir).expect("the scan reads the fresh-install shape");
    assert!(!scan.mixed, "an absent envelope is not a mixed state");
    assert_eq!(
        scan.present,
        VOLUME_FILES[..3].to_vec(),
        "the scan names only the files that exist"
    );
}

#[test]
fn scan_volume_detects_the_mixed_state() {
    // The crashed change's aftermath: the db-credential envelope
    // advanced ahead of the master anchor (master is written LAST).
    let dir = temp_volume("scan-mixed");
    seal_volume(&dir, "the-current-passphrase", 0);
    KeyEnvelope::write_envelope(
        &dir.join(ws_core::crypto::DB_CREDENTIAL_ENVELOPE_FILE),
        "the-next-passphrase",
        b"volume-payload-2",
        cheap_params(),
        1,
    )
    .unwrap();
    let scan = ws_core::crypto::scan_volume(&dir).expect("the scan reads the mixed volume");
    assert!(scan.mixed, "a generation disagreement is the mixed state");
    assert_eq!(
        scan.present, VOLUME_FILES,
        "the scan still names every present envelope"
    );
}

#[test]
fn scan_volume_fails_loudly_when_it_cannot_read_the_volume() {
    // No master envelope: there is no anchor to scan against (the
    // unsealed shape). A damaged envelope: its generation cannot be
    // named, and a silent false would misread a broken volume as a
    // clean one — both refuse instead.
    let dir = temp_volume("scan-empty");
    ws_core::crypto::scan_volume(&dir).expect_err("a volume without an anchor cannot be scanned");

    seal_volume(&dir, "the-master-passphrase", 0);
    fs::write(
        dir.join(ws_core::crypto::SECRET_ENVELOPE_FILE),
        b"not an envelope",
    )
    .unwrap();
    ws_core::crypto::scan_volume(&dir).expect_err("a damaged envelope fails the scan loudly");
}

#[test]
fn relay_nonce_is_single_use_and_lives_only_in_the_volume() {
    // F2 (the final review): spec §10 — the ui→api unlock relay must
    // not be replayable by anything else on the internal network. The
    // one-time nonce is a claim FILE in the shared keys volume: only a
    // volume holder can mint it, the api refuses an internal unlock
    // POST whose nonce does not match the file, and the matching
    // consume deletes the file — a captured POST is dead after the
    // real unlock, while the ui's next relay mints a fresh claim.
    let dir = temp_volume("relay-nonce");
    let nonce = ws_core::crypto::mint_relay_nonce(&dir).expect("mint the relay nonce");
    assert_eq!(nonce.len(), 64, "random_hex(32) is 64 hex characters");
    let claim = dir.join(ws_core::crypto::RELAY_NONCE_FILE);
    assert_eq!(
        fs::read_to_string(&claim).expect("the claim lands in the volume"),
        nonce,
        "the file IS the claim the api compares against"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&claim).unwrap().permissions().mode() & 0o777,
            0o600,
            "the claim file is owner-only"
        );
    }
    // A fresh mint replaces the claim: the previous nonce is dead even
    // before the api ever consumes it.
    let fresh = ws_core::crypto::mint_relay_nonce(&dir).expect("re-mint");
    assert_ne!(fresh, nonce, "each mint is a fresh claim");
    assert!(ws_core::crypto::consume_relay_nonce(&dir, &nonce).is_err());
    assert!(
        claim.exists(),
        "a refused nonce keeps the claim for its holder"
    );
    // The matching nonce consumes the claim: the one-time semantics.
    ws_core::crypto::consume_relay_nonce(&dir, &fresh).expect("consume the live nonce");
    assert!(!claim.exists(), "the successful match deletes the claim");
    assert!(
        ws_core::crypto::consume_relay_nonce(&dir, &fresh).is_err(),
        "a consumed nonce cannot replay"
    );
}

#[test]
fn derive_kek_matches_the_heap_reference() {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = cheap_params();
    let salt = b"a-sixteen-byte!!";

    // The locked-slot derivation must agree, byte for byte, with argon2's
    // own heap-allocating `hash_password_into` at the same parameters: the
    // envelopes already written to keys volumes have to keep opening.
    let mut reference = [0u8; 32];
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .expect("the reference argon2id parameters");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
        .hash_password_into(b"the operator master passphrase", salt, &mut reference)
        .expect("the heap reference derives");

    let derived = KeyEnvelope::derive_kek("the operator master passphrase", salt, params)
        .expect("derive in the locked KDF slot");

    assert_eq!(
        derived.secrets().as_slice(),
        reference.as_slice(),
        "the locked-slot KEK must equal argon2's heap output at the same parameters"
    );
    assert_eq!(
        derived.salt(),
        salt,
        "the envelope's salt is carried through"
    );
    assert_eq!(
        derived.params(),
        params,
        "the parameters are carried through"
    );

    // A different passphrase derives a different KEK (the derivation is not
    // accidentally keyed on the salt alone).
    let other = KeyEnvelope::derive_kek("a different master passphrase", salt, params)
        .expect("derive in the locked KDF slot");
    assert_ne!(other.secrets().as_slice(), reference.as_slice());
}
