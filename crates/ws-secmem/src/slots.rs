//! Locked argon2 slots.
//!
//! argon2 is memory-hard by design: a single KDF pass at `m_cost = 262144`
//! wants 256 MiB of scratch, and on the heap that scratch is swappable,
//! dumpable and visible to anything that can read the process. The pool
//! therefore pre-reserves fixed sub-ranges of the secret mapping — one KDF
//! slot and two password-hash slots — and every argon2 call borrows one.
//!
//! The slots are a fixed resource, so acquiring one *blocks* rather than
//! failing: a burst of password hashes queues instead of spilling 64 MiB of
//! scratch onto the heap. Only an `m_cost` the slot cannot hold is refused.

use std::sync::{Condvar, Mutex, PoisonError};

use argon2::Block;
use zeroize::Zeroize;

use crate::arena::{Pool, GRAIN};
use crate::SecMemError;

/// Which of the pool's two slot sets a guard holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SlotKind {
    Kdf,
    Hash,
}

/// A fixed set of equally sized slots inside the pool.
pub(crate) struct SlotSet {
    /// Offset of slot 0 within the mapping.
    base: usize,
    /// Usable bytes per slot.
    slot_bytes: usize,
    /// Indices of the currently free slots.
    free: Mutex<Vec<usize>>,
    /// Signalled whenever a slot is returned.
    released: Condvar,
}

impl SlotSet {
    pub(crate) fn new(base: usize, slot_bytes: usize, count: usize) -> Self {
        SlotSet {
            base,
            slot_bytes,
            free: Mutex::new((0..count).collect()),
            released: Condvar::new(),
        }
    }

    /// Blocks until a slot is free, then takes it.
    fn acquire(&self) -> usize {
        // The critical sections here only push to and pop from a `Vec`, so
        // nothing can unwind while the lock is held; a poisoned lock still
        // guards a consistent free list.
        let mut free = self.free.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some(index) = free.pop() {
                return index;
            }
            free = self
                .released
                .wait(free)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn release(&self, index: usize) {
        let mut free = self.free.lock().unwrap_or_else(PoisonError::into_inner);
        free.push(index);
        drop(free);
        self.released.notify_one();
    }
}

/// An exclusive lease on one argon2 slot.
///
/// Dropping it wipes whatever was handed out and wakes the next waiter.
///
/// Acquiring one **blocks the calling OS thread** on a `Condvar`, which an
/// async runtime cannot see or work around; async callers must acquire and use
/// the guard inside `tokio::task::spawn_blocking`. A guard held across an
/// `.await` would also keep a scarce slot out of circulation for as long as
/// that future is parked, so it is meant to live for exactly one synchronous
/// argon2 call.
pub struct SlotGuard<'a> {
    pool: &'a Pool,
    kind: SlotKind,
    index: usize,
    /// High-water mark, in bytes, of what [`SlotGuard::blocks`] handed out.
    /// Only that prefix can hold argon2 state, so only it needs wiping.
    handed: usize,
}

impl<'a> SlotGuard<'a> {
    pub(crate) fn acquire(pool: &'a Pool, kind: SlotKind) -> Self {
        let set = Self::set_of(pool, kind);
        let index = set.acquire();
        SlotGuard {
            pool,
            kind,
            index,
            handed: 0,
        }
    }

    fn set_of(pool: &Pool, kind: SlotKind) -> &SlotSet {
        match kind {
            SlotKind::Kdf => &pool.kdf,
            SlotKind::Hash => &pool.hash,
        }
    }

    fn set(&self) -> &SlotSet {
        Self::set_of(self.pool, self.kind)
    }

    /// Offset of this slot within the mapping.
    fn offset(&self) -> usize {
        let set = self.set();
        set.base + self.index * set.slot_bytes
    }

    /// The slot's scratch memory as argon2 blocks, for an `m_cost` of
    /// `m_cost_kib` KiB.
    ///
    /// argon2's `Block` is exactly 1 KiB, so the slice is `m_cost_kib` blocks
    /// long. Pass it straight to `Argon2::hash_password_into_with_memory`.
    ///
    /// # Errors
    ///
    /// [`SecMemError::SlotTooSmall`] if `m_cost_kib` exceeds the slot. The
    /// pool is sized for Wardstone's fixed argon2 parameters, so this is a
    /// programming error, not a runtime condition — it is reported rather
    /// than allocated around.
    pub fn blocks(&mut self, m_cost_kib: u32) -> Result<&mut [Block], SecMemError> {
        let need = (m_cost_kib as usize)
            .checked_mul(Block::SIZE)
            .ok_or(SecMemError::SlotTooSmall)?;
        if need > self.set().slot_bytes {
            return Err(SecMemError::SlotTooSmall);
        }

        let ptr = self.pool.ptr_at(self.offset());
        debug_assert_eq!(
            ptr as usize % align_of::<Block>(),
            0,
            "slot bases are {GRAIN}-byte aligned by construction"
        );
        self.handed = self.handed.max(need);

        // SAFETY: the slot set leased slot `index` to this guard alone, so no
        // other view into `[offset, offset + need)` exists, and `&mut self`
        // proves this guard hands out only one view at a time. The range lies
        // inside the mapping (`need <= slot_bytes`), the pool outlives `'a`,
        // the base is 64-byte aligned (a page-aligned mapping plus
        // granule-aligned sub-ranges) which satisfies `align_of::<Block>()`,
        // and `Mapping::probe` zeroed the whole pool, so every byte is an
        // initialised `Block` — `Block` is a `[u64; 128]`, for which every bit
        // pattern is valid.
        Ok(unsafe { std::slice::from_raw_parts_mut(ptr.cast::<Block>(), m_cost_kib as usize) })
    }
}

impl Drop for SlotGuard<'_> {
    fn drop(&mut self) {
        if self.handed > 0 {
            let ptr = self.pool.ptr_at(self.offset());
            // SAFETY: as for `blocks`, over the high-water prefix this guard
            // handed out; any view it returned has been dropped, because
            // `blocks` borrows `self` mutably.
            let used = unsafe { std::slice::from_raw_parts_mut(ptr, self.handed) };
            used.zeroize();
        }
        self.set().release(self.index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_set_leases_each_slot_once() {
        let set = SlotSet::new(0, 1024, 2);
        let first = set.acquire();
        let second = set.acquire();
        assert_ne!(first, second, "two leases must be different slots");
        set.release(first);
        assert_eq!(set.acquire(), first, "a returned slot is leased again");
    }

    #[test]
    fn a_waiter_wakes_when_a_slot_is_returned() {
        use std::sync::Arc;
        use std::time::Duration;

        let set = Arc::new(SlotSet::new(0, 1024, 1));
        let held = set.acquire();

        let waiter = {
            let set = Arc::clone(&set);
            std::thread::spawn(move || set.acquire())
        };

        std::thread::sleep(Duration::from_millis(50));
        set.release(held);
        assert_eq!(waiter.join().expect("waiter"), held);
    }
}
