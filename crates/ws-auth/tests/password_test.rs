//! Argon2id password hashing tests: round trip, wrong password, salted
//! hashes, and the PHC string format the `users.credential_hash` column
//! stores.

use ws_auth::password::{hash_password, verify_password};

#[test]
fn hash_then_verify_accepts_the_right_password() {
    let hash = hash_password("correct horse battery staple").unwrap();
    assert!(verify_password("correct horse battery staple", &hash).unwrap());
}

#[test]
fn verify_rejects_a_wrong_password() {
    let hash = hash_password("correct horse battery staple").unwrap();
    assert!(!verify_password("wrong horse", &hash).unwrap());
}

#[test]
fn hashes_of_the_same_password_differ() {
    let a = hash_password("same password").unwrap();
    let b = hash_password("same password").unwrap();
    assert_ne!(a, b, "each hash must carry a fresh salt");
}

#[test]
fn hash_is_a_phc_argon2id_string() {
    let hash = hash_password("same password").unwrap();
    assert!(
        hash.starts_with("$argon2id$"),
        "the stored credential must be a PHC argon2id string, got {hash}"
    );
}
