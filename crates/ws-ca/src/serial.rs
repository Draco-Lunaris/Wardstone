//! DB-backed transactional serial allocation against the `used_serials`
//! table (migration 001).
//!
//! [`allocate_serial`] draws 16 bytes of OS entropy, shapes them into a
//! bigint-legal positive serial, and persists the value with a single
//! atomic INSERT (one statement = one implicit transaction) before
//! returning it — the transactional contract: a serial is yielded only
//! after it persisted, and a serial whose INSERT failed is never handed
//! out. The `used_serials` primary key `(ca_id, serial)` is the
//! uniqueness enforcement: per-CA (RFC 5280 §4.1.2.2 per-issuer serial
//! uniqueness), so a serial used by one CA can never be handed to another
//! CA, and two concurrent allocations for the same CA cannot both commit
//! the same draw — the loser's INSERT errors, not overwrite.
//!
//! # Serial range
//!
//! The serial columns (`used_serials.serial`, `certificates.serial`) are
//! Postgres `bigint` = i64, so the raw 16-byte draw is masked to the low
//! 63 bits (`& i64::MAX as u128`): every allocation is positive, fits the
//! column exactly (`i64::try_from` then cannot fail — the conversion is
//! still typed, so a future mask change fails loudly rather than wrap),
//! and within RFC 5280's bound. The mask costs one bit of entropy: a draw
//! carries 63 random bits, marginally below the CA/Browser Forum's 64-bit
//! entropy floor for publicly trusted certs — accepted for Wardstone v1
//! (internal CA) because the per-CA uniqueness table makes collisions
//! structurally impossible to persist (~2^-63 per draw), and the table is
//! recorded serial bookkeeping regardless. A draw of all-zero bits
//! is invalid (RFC 5280 §4.1.2.2 requires a positive serial) and is
//! treated as a collision: the draw is discarded and retried with fresh
//! randomness.
//!
//! # Retry cap
//!
//! On a unique violation (another committed allocation drew the same
//! value for the same CA) the loop retries with fresh randomness, at most
//! [`MAX_ATTEMPTS`] attempts total — with 63-bit draws the collision
//! probability is ~2^-63 per draw, so 8 attempts failing outright is
//! beyond astronomical and signals something pathological (e.g. a table
//! seeded with near-all values in tests); exhaustion is a typed
//! [`CaError::Worker`], never a panic or infinite loop.

use rand::{rngs::SysRng, TryRng};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::CaError;

/// Maximum allocation attempts per call: the first INSERT plus
/// `MAX_ATTEMPTS - 1` retries on unique violations / zero draws. The cap
/// and its exhaustion error are the documented, pinned behavior (see the
/// module-level retry discussion); a 9th attempt is never made.
const MAX_ATTEMPTS: u32 = 8;

/// Mask shaping a raw 16-byte draw into a bigint-legal serial: the low 63
/// bits only, so the value is positive (top bit clear) and always fits
/// the i64 serial column.
const SERIAL_MASK: u128 = i64::MAX as u128;

/// Allocate one fresh serial number for `ca`, persisting it in
/// `used_serials` before returning it.
///
/// `ca_id` scopes the allocation: the unique key is `(ca_id, serial)`, so
/// two CAs draw from independent spaces (RFC 5280 per-issuer uniqueness)
/// and cross-CA reuse is legal and expected.
///
/// Errors: [`CaError::Io`] on OS-entropy failure (typed, never a panic —
/// `SysRng::try_fill_bytes` is the pinned idiom), [`CaError::Db`] on
/// database failure other than a unique violation, and
/// [`CaError::Worker`]="serial allocation exhausted after 8 attempts" if
/// `MAX_ATTEMPTS` draws all collided.
pub async fn allocate_serial(ca_id: Uuid, pool: &PgPool) -> Result<u128, CaError> {
    // Attempt loop: each iteration is one complete generate+persist cycle.
    // No transaction is held open across attempts — the INSERT is a single
    // statement and atomically commits or not on its own; the retry
    // guarantee is that a serial is returned only after a committed INSERT.
    for _attempt in 1..=MAX_ATTEMPTS {
        let serial = draw_serial()?;
        // Serial 0 is not a legal RFC 5280 serial; treat it as a collision
        // and retry with fresh randomness (discard the draw, never return 0).
        if serial.value() != 0 {
            let insert = sqlx::query("INSERT INTO used_serials (ca_id, serial) VALUES ($1, $2)")
                .bind(ca_id)
                .bind(serial.as_i64()?)
                .execute(pool)
                .await;
            match insert {
                Ok(_) => return Ok(serial.0),
                Err(err) if is_unique_violation(&err) => continue, // retried draw
                Err(err) => return Err(CaError::Db(err)),
            }
        }
    }
    Err(CaError::Worker(
        "serial allocation exhausted after 8 attempts".to_owned(),
    ))
}

/// One 16-byte OS-entropy draw, masked to a positive 63-bit serial.
///
/// Entropy failure is [`CaError::Io`] (pinned typed-error idiom from
/// `ca.rs`'s `new_serial`; `SysRng` never panics through `try_fill_bytes`).
struct Serial(u128);

impl Serial {
    /// The masked serial value.
    fn value(&self) -> u128 {
        self.0
    }

    /// The serial as the i64 the `bigint` columns store. The mask makes
    /// success the only outcome in practice, but the conversion stays
    /// typed: if the mask is ever loosened, an out-of-range draw fails
    /// loudly here instead of wrapping the column value.
    fn as_i64(&self) -> Result<i64, CaError> {
        i64::try_from(self.0).map_err(|_| {
            CaError::Worker(format!(
                "allocated serial {:#x} exceeds the bigint serial column range (mask bug?)",
                self.0
            ))
        })
    }
}

/// Draw 16 fresh OS-entropy bytes and mask to `SERIAL_MASK` (positive,
/// i64-ranged).
fn draw_serial() -> Result<Serial, CaError> {
    let mut bytes = [0u8; 16];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(std::io::Error::from)?;
    // Mask BEFORE the integer conversion: the top bit (and above the low
    // 63 bits generally) is cleared, so the u128 value is i64-ranged and
    // positive.
    let value = u128::from_be_bytes(bytes) & SERIAL_MASK;
    Ok(Serial(value))
}

/// Whether `err` is Postgres unique-constraint violation 23505, the retry
/// trigger for the allocation loop. Local helper: ws-ca owns its sqlx
/// dependency surface and does not use ws-core's `map_unique` (models must
/// not leak across this boundary).
fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(
        err,
        sqlx::Error::Database(db_err) if db_err.code().as_deref() == Some("23505")
    )
}
