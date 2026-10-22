//! DB-backed transactional serial allocation against the `used_serials`
//! table (migration 001).
//!
//! [`allocate_serial`] draws 16 bytes of OS entropy, shapes them into a
//! bigint-legal positive serial, and persists the value with a single
//! atomic INSERT before returning it — the transactional contract: a
//! serial is yielded only after it persisted, and a serial whose INSERT
//! failed is never handed out. The INSERT runs on the CALLER's executor:
//! a call that holds a transaction (`&mut *tx`) allocates inside it, so
//! the serial INSERT commits or rolls back together with everything else
//! the caller writes (the certificate row and its audit entry in the
//! issuance shape). Two properties follow. First, a rolled-back issuance
//! RELEASES the serial it drew — `used_serials` keeps no row — so the
//! serial is never burned; that is safe because the certificate it was
//! drawn for was never issued, and a serial is only ever attached to a
//! certificate that actually exists. Second, the `used_serials` primary
//! key `(ca_id, serial)` still enforces uniqueness **per CA** across live
//! allocations — RFC 5280 §4.1.2.2 per-issuer serial uniqueness, the same
//! semantics as `certificates UNIQUE (ca_id, serial)`: two CAs draw from
//! independent spaces, cross-CA serial reuse is legal and expected, and
//! two concurrent allocations for the same CA cannot both hold the same
//! draw.
//!
//! # Collision handling inside a transaction
//!
//! The loser of a concurrent same-CA draw is NOT reported by a raised
//! error: the INSERT is `ON CONFLICT DO NOTHING`, so an already-taken
//! serial affects zero rows and the caller redraws with fresh randomness.
//! A plain INSERT that raised its unique violation would instead ABORT
//! the enclosing Postgres transaction — the loop could not retry inside
//! one at all, and the caller's issuance work would be lost either way.
//! `ON CONFLICT DO NOTHING` is correct both inside a transaction and
//! outside it, and it needs no error to be raised.
//!
//! # Executor shape (sqlx 0.8.6)
//!
//! The executor parameter is an `impl PgExecutor`: callers pass `&pool`,
//! or `&mut *tx` inside a transaction (`&mut Transaction` does not
//! implement `PgExecutor` in sqlx 0.8.6). The retry loop must run several
//! statements against ONE executor, and sqlx 0.8.6's `Executor` trait —
//! implemented for `&Pool` and `&mut PgConnection` only, with no
//! reborrowing blanket impl — consumes the executor on every call. The
//! sqlx-documented shape for that is the `Acquire` pattern: the function
//! acquires the executor's connection ONCE (`executor.acquire()` — for a
//! pool, a pooled connection checked out for the loop's duration; for a
//! transaction, the caller's own connection, re-borrowed) and runs every
//! attempt against `&mut *conn`. The `Acquire` bound and the named
//! `impl Future + Send + 'a` return are sqlx's documented workaround for
//! the trait's lifetime-generalization limit; callers are unaffected —
//! `allocate_serial(...).await` reads exactly as before.
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
//! On a collision (another committed or in-flight live allocation drew
//! the same value for the same CA, detected as a zero-row INSERT) the
//! loop retries with fresh randomness, at most [`MAX_ATTEMPTS`] attempts
//! total — with 63-bit draws the collision probability is ~2^-63 per
//! draw, so 8 attempts failing outright is beyond astronomical and
//! signals something pathological (e.g. a table seeded with near-all
//! values in tests); exhaustion is a typed [`CaError::Worker`], never a
//! panic or infinite loop.
//!
//! # Tenancy
//!
//! The `used_serials` row carries the owning `tenant_id` (migration 005
//! makes every table tenant-attributable). The caller supplies it: the
//! CA a serial is drawn for belongs to exactly one tenant, and the
//! caller is the one that knows which. ws-ca reads no `cas` row to find
//! out, so an allocation costs one INSERT and no extra query.

use rand::{rngs::SysRng, TryRng};
use sqlx::{Acquire, PgExecutor, Postgres};
use std::future::Future;
use uuid::Uuid;

use crate::error::CaError;

/// Maximum allocation attempts per call: the first INSERT plus
/// `MAX_ATTEMPTS - 1` retries on collisions (a zero-row INSERT: another
/// live allocation holds the draw, or the impossible all-zero draw). The
/// cap and its exhaustion error are the documented, pinned behavior (see
/// the module-level retry discussion); a 9th attempt is never made.
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
/// `tenant_id` is the owning tenant of the CA. The `used_serials` row
/// carries it (migration 005 makes every table tenant-attributable), so
/// the row can be attributed to a tenant without a lookup: the caller
/// knows which tenant owns the CA. ws-ca deliberately does not read
/// ws-core's model surface, and a `cas` lookup here would put a query on
/// every allocation.
///
/// The `executor` carries the connection the INSERT runs on: `&pool`
/// outside a transaction, `&mut *tx` inside one — the issuance shape,
/// where the serial INSERT shares the certificate's transaction, and a
/// rollback of the issuance releases the serial rather than burning it
/// (see the module docs).
///
/// Errors: [`CaError::Io`] on OS-entropy failure (typed, never a panic —
/// `SysRng::try_fill_bytes` is the pinned idiom), [`CaError::Db`] on
/// database failure, and [`CaError::Worker`]="serial allocation exhausted
/// after 8 attempts" if `MAX_ATTEMPTS` draws all collided. A collision is
/// deliberately NOT an error (see the module docs): the zero-row INSERT
/// is read from the result and the loop redraws.
pub fn allocate_serial<'a, 'c>(
    ca_id: Uuid,
    tenant_id: Uuid,
    executor: impl PgExecutor<'c> + Acquire<'c, Database = Postgres> + Send + 'a,
) -> impl Future<Output = Result<u128, CaError>> + Send + 'a {
    async move {
        // One connection for every attempt: sqlx 0.8.6 consumes an
        // executor per statement (see the module docs), so the retry loop
        // runs on the connection acquired from the executor once — for a
        // pool a checked-out pooled connection, for a transaction the
        // caller's own connection (the serial INSERT then commits or
        // rolls back with the caller's work).
        let mut conn = executor.acquire().await?;

        // Attempt loop: each iteration is one complete generate+persist
        // cycle. No transaction is held open across attempts — for the
        // pool path each INSERT is a single statement and atomically
        // commits or not on its own; in the transaction path the caller's
        // transaction is already open and owns the outcome. The retry
        // guarantee is that a serial is returned only after a INSERT that
        // actually wrote a row.
        for _attempt in 1..=MAX_ATTEMPTS {
            let serial = draw_serial()?;
            // Serial 0 is not a legal RFC 5280 serial; treat it as a
            // collision and retry with fresh randomness (discard the
            // draw, never return 0).
            if serial.value() != 0 {
                // ON CONFLICT DO NOTHING, not a bare INSERT: a draw that
                // another live allocation already holds affects zero rows
                // and is redrawn below. No error is raised — a plain
                // INSERT's unique violation would abort the enclosing
                // transaction, making the loop unretryable inside one.
                let insert = sqlx::query(
                    "INSERT INTO used_serials (tenant_id, ca_id, serial) VALUES ($1, $2, $3) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(tenant_id)
                .bind(ca_id)
                .bind(serial.as_i64()?)
                .execute(&mut *conn)
                .await?;
                if insert.rows_affected() == 0 {
                    continue; // the draw is taken: redraw with fresh randomness
                }
                return Ok(serial.0);
            }
        }
        Err(CaError::Worker(
            "serial allocation exhausted after 8 attempts".to_owned(),
        ))
    }
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
