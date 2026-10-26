//! Argon2id password hashing tests: round trip, wrong password, salted
//! hashes, the PHC string format the `users.credential_hash` column
//! stores, and the locked-slot guarantee — argon2's 64 MiB of scratch must
//! come from the `memfd_secret` pool, never from the heap.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use ws_auth::error::AuthError;
use ws_auth::password::{hash_password, verify_password};

/// A single allocation at least this large is argon2's scratch arriving on
/// the heap: the house parameters want 64 MiB (verification of a crafted
/// PHC string could ask for more), while nothing else on the hashing path
/// allocates more than a PHC string's worth of bytes.
const ARGON2_SCRATCH_FLOOR: usize = 1_048_576;

thread_local! {
    /// The largest single allocation served to THIS thread since the last
    /// reset. Thread-local so the tests cargo runs in parallel cannot
    /// pollute each other's measurement.
    static LARGEST_ALLOCATION: Cell<usize> = const { Cell::new(0) };
}

/// The system allocator, watched. It changes no allocation behaviour; it
/// only records the high-water mark of a single request, which is what
/// separates "argon2 ran in a locked slot" from "argon2 allocated 64 MiB".
struct WatchfulAlloc;

// SAFETY: every method forwards to `System` with the layout and pointer it
// was given, so the allocator contract is `System`'s. The recording side
// effect touches only a `Cell<usize>` in a const-initialised thread-local,
// which allocates nothing and registers no destructor, so it cannot
// re-enter the allocator.
unsafe impl GlobalAlloc for WatchfulAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
}

fn record(size: usize) {
    // During thread teardown the thread-local is gone; the measurement
    // windows below are all inside a running test, so dropping those
    // samples costs nothing.
    let _ = LARGEST_ALLOCATION.try_with(|largest| largest.set(largest.get().max(size)));
}

/// Runs `body` and reports the largest single heap allocation it caused on
/// this thread.
fn largest_allocation_during<T>(body: impl FnOnce() -> T) -> (T, usize) {
    LARGEST_ALLOCATION.with(|largest| largest.set(0));
    let value = body();
    let seen = LARGEST_ALLOCATION.with(Cell::get);
    (value, seen)
}

#[global_allocator]
static ALLOCATOR: WatchfulAlloc = WatchfulAlloc;

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

#[test]
fn hash_carries_the_house_calibration() {
    let hash = hash_password("same password").unwrap();
    // The house's calibrated cost (pm-auth/src/password.rs): 64 MiB of
    // memory, 3 iterations, 1 lane — pinned so it cannot quietly weaken.
    assert!(
        hash.contains("m=65536"),
        "64 MiB memory cost must be pinned in the PHC params, got {hash}"
    );
    assert!(
        hash.contains("t=3") && hash.contains("p=1"),
        "3 iterations and 1 lane must be pinned in the PHC params, got {hash}"
    );
}

#[test]
fn a_hash_round_trips_and_matches_the_reference_encoder() {
    let password = "correct horse battery staple";

    let ours = hash_password(password).expect("hash in a locked slot");
    assert!(
        verify_password(password, &ours).expect("verify our own hash"),
        "a hash must verify against the password that produced it"
    );

    // Format compatibility, both ways. The PHC string is built by hand now,
    // so the encoder's output must stay byte-shaped exactly like the stock
    // one's — otherwise the credential hashes already in `users` stop
    // verifying, or the ones written from here stop being readable by any
    // other argon2 implementation.
    let reference = reference_hash(password);
    assert!(
        verify_password(password, &reference).expect("verify a stock-encoder hash"),
        "a hash minted by argon2's own encoder must verify through the locked-slot path"
    );
    assert!(
        !verify_password("not the password", &reference).expect("verify a stock-encoder hash"),
        "a wrong password against a stock-encoder hash is false, not an error"
    );

    let (ours_fields, reference_fields): (Vec<&str>, Vec<&str>) =
        (ours.split('$').collect(), reference.split('$').collect());
    assert_eq!(
        ours_fields.len(),
        reference_fields.len(),
        "our PHC string must have the stock encoder's field count: {ours} vs {reference}"
    );
    assert_eq!(
        &ours_fields[..4],
        &reference_fields[..4],
        "algorithm, version and parameter fields must match the stock encoder"
    );
    assert_eq!(
        ours_fields[4].len(),
        reference_fields[4].len(),
        "the salt must be encoded at the stock encoder's length"
    );
    assert_eq!(
        ours_fields[5].len(),
        reference_fields[5].len(),
        "the hash must be encoded at the stock encoder's length"
    );
}

/// A hash from argon2's own heap-allocating PHC encoder: the independent
/// reference the locked-slot path is pinned against. Test-only — production
/// code never allocates argon2 memory.
fn reference_hash(password: &str) -> String {
    use argon2::password_hash::PasswordHasher;
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(65536, 3, 1, None).expect("the house argon2id parameters");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password(password.as_bytes())
        .expect("the stock encoder hashes")
        .to_string()
}

#[test]
fn a_phc_with_a_cost_above_the_slot_is_refused() {
    let password = "a password worth refusing for";
    let hash = hash_password(password).expect("hash in a locked slot");

    // 128 MiB: twice the password-hash slot. There is no heap fallback, so
    // this is refused rather than served — and refused BEFORE argon2 runs,
    // which the allocation high-water mark below proves (a heap run would
    // have asked for 128 MiB in one go).
    let oversized = hash.replacen("m=65536", "m=131072", 1);
    assert!(
        oversized.contains("m=131072"),
        "the fixture must carry the oversized cost: {oversized}"
    );

    let (outcome, largest) = largest_allocation_during(|| verify_password(password, &oversized));
    let error = outcome.expect_err("an m_cost above the locked slot must be refused");
    assert!(
        matches!(error, AuthError::Crypto(_)),
        "an unusable stored hash is a crypto error, got {error:?}"
    );
    assert!(
        !error.to_string().contains(password),
        "no error message may carry the password: {error}"
    );
    assert!(
        largest < ARGON2_SCRATCH_FLOOR,
        "the refusal must come before argon2 runs, but a {largest}-byte allocation was served"
    );

    // Neither a different argon2 variant nor another version is quietly
    // computed as if it were argon2id v0x13.
    for wrong in [
        hash.replacen("$argon2id$", "$argon2i$", 1),
        hash.replacen("$argon2id$", "$argon2d$", 1),
        hash.replacen("v=19", "v=16", 1),
    ] {
        let outcome = verify_password(password, &wrong);
        let error = match outcome {
            Err(error) => error,
            Ok(answer) => {
                panic!("only argon2id v0x13 may be recomputed, but {wrong} was answered {answer}")
            }
        };
        assert!(
            matches!(error, AuthError::Crypto(_)),
            "a foreign algorithm or version is a crypto error, got {error:?}"
        );
    }
}

#[test]
fn password_hashing_never_allocates_argon2_memory_on_the_heap() {
    // The pool's one-time mapping and the first PHC round trip happen
    // outside the measurement window: this test is about argon2's scratch,
    // not about startup.
    let warm = hash_password("warm the one-time paths").expect("warm-up hash");
    assert!(verify_password("warm the one-time paths", &warm).expect("warm-up verify"));

    let password = "a password worth 64 MiB of scratch";
    let (hash, hashing_largest) = largest_allocation_during(|| hash_password(password));
    let hash = hash.expect("hash in a locked slot");
    assert!(
        hashing_largest < ARGON2_SCRATCH_FLOOR,
        "hash_password must take its scratch from the locked pool, but a \
         {hashing_largest}-byte heap allocation was served"
    );

    let (verified, verify_largest) = largest_allocation_during(|| verify_password(password, &hash));
    assert!(verified.expect("verify in a locked slot"));
    assert!(
        verify_largest < ARGON2_SCRATCH_FLOOR,
        "verify_password must take its scratch from the locked pool, but a \
         {verify_largest}-byte heap allocation was served"
    );
}
