//! Bounded lock-free MPMC queue, safe for MPSC use.
//!
//! Backs the per-binding redirect inbox on `BindingLiveState` (see `umem.rs`):
//! N producer workers push redirected `TxRequest`s; the owner worker drains.
//! Prior to #706 this was a `Mutex<VecDeque<TxRequest>>` which serialised
//! every producer against every other producer *and* against the owner's
//! drain; the contention injected µs-scale jitter into TCP inter-arrival
//! timing on redirected flows and drove the bimodal cwnd pattern in #704.
//!
//! Algorithm: Dmitry Vyukov's bounded MPMC with per-slot sequence numbers
//! (<https://www.1024cores.net/home/lock-free-algorithms/queues/bounded-mpmc-queue>).
//! We only take the MPSC subset — all `pop` callers must be the owner worker
//! — so correctness needs only the weaker single-consumer invariant. Using
//! the MPMC algorithm keeps the push side trivially lock-free with one CAS
//! per slot acquire.
//!
//! Overflow semantics: `push` returns `Err(val)` when the ring is full. The
//! caller in `BindingLiveState` treats that as drop-newest and bumps the
//! `redirect_inbox_overflow_drops` / `tx_errors` counters. This replaces the
//! prior drop-oldest (pop-front-then-push-back) behaviour; drop-newest is
//! preferable under contention because older queued packets are closer to
//! being serviced by the owner and evicting them extends tail latency.

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Slot<T> {
    seq: AtomicUsize,
    val: UnsafeCell<MaybeUninit<T>>,
}

/// Force a field onto its own 64-byte cache line. Producers CAS `head`
/// while the owner worker advances `tail`; without this padding the two
/// atomics would share a line and every producer operation would
/// invalidate the consumer's cached view of `tail` (and vice versa),
/// which re-introduces exactly the kind of cross-core coherence traffic
/// the lock-free conversion is trying to eliminate.
#[repr(align(64))]
struct CachePadded<T>(T);

pub(super) struct MpscInbox<T> {
    slots: Box<[Slot<T>]>,
    mask: usize,
    /// Producer cursor. Advanced via CAS by any pushing thread. On its
    /// own cache line to avoid false sharing with `tail`.
    head: CachePadded<AtomicUsize>,
    /// Consumer cursor. Advanced only by the single consumer (the owner
    /// worker for this binding). Exposed atomically so producers and the
    /// `is_empty` / `len` helpers can observe it. On its own cache line
    /// to avoid false sharing with `head`.
    tail: CachePadded<AtomicUsize>,
}

// Safety: the queue is designed to be shared across producer threads and
// the consumer thread. `T: Send` is sufficient — values transit between
// threads but each value is owned by exactly one thread at a time via
// the head/tail sequencing.
unsafe impl<T: Send> Send for MpscInbox<T> {}
unsafe impl<T: Send> Sync for MpscInbox<T> {}

impl<T> MpscInbox<T> {
    /// Create a queue with capacity rounded up to the next power of two
    /// (minimum 2 slots).
    pub(super) fn new(capacity_hint: usize) -> Self {
        let cap = capacity_hint.max(2).next_power_of_two();
        let slots = (0..cap)
            .map(|i| Slot {
                seq: AtomicUsize::new(i),
                val: UnsafeCell::new(MaybeUninit::uninit()),
            })
            .collect::<Box<[_]>>();
        Self {
            slots,
            mask: cap - 1,
            head: CachePadded(AtomicUsize::new(0)),
            tail: CachePadded(AtomicUsize::new(0)),
        }
    }

    #[inline]
    pub(super) fn capacity(&self) -> usize {
        self.mask + 1
    }

    /// Approximate occupancy. Non-linearisable: producers may have
    /// claimed a slot (advanced `head`) without yet publishing a value,
    /// and the consumer may have consumed a value without readers seeing
    /// the updated `tail`. Safe for observability and soft-cap gating.
    #[cfg_attr(not(test), allow(dead_code))]
    #[inline]
    pub(super) fn len(&self) -> usize {
        let head = self.head.0.load(Ordering::Relaxed);
        let tail = self.tail.0.load(Ordering::Relaxed);
        head.wrapping_sub(tail)
    }

    #[inline]
    pub(super) fn is_empty(&self) -> bool {
        self.head.0.load(Ordering::Relaxed) == self.tail.0.load(Ordering::Relaxed)
    }

    /// Multi-producer push. Returns `Err(val)` when the ring is full.
    pub(super) fn push(&self, val: T) -> Result<(), T> {
        let mut pos = self.head.0.load(Ordering::Relaxed);
        loop {
            // SAFETY: `pos & mask` is in range because `mask = cap - 1`
            // and `cap = slots.len()`.
            let slot = unsafe { self.slots.get_unchecked(pos & self.mask) };
            let seq = slot.seq.load(Ordering::Acquire);
            let diff = (seq as isize).wrapping_sub(pos as isize);
            if diff == 0 {
                // Slot ready for this producer at `pos`. Try to claim.
                match self.head.0.compare_exchange_weak(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // SAFETY: we own the slot until we publish via
                        // `seq.store(pos+1, Release)`; no other thread
                        // can read or write the value until then.
                        unsafe {
                            (*slot.val.get()).write(val);
                        }
                        slot.seq
                            .store(pos.wrapping_add(1), Ordering::Release);
                        return Ok(());
                    }
                    Err(actual) => pos = actual,
                }
            } else if diff < 0 {
                // seq is behind pos — consumer hasn't finished with the
                // slot that currently lives at `pos & mask`. Queue full.
                return Err(val);
            } else {
                // Another producer claimed this slot first; refresh and retry.
                pos = self.head.0.load(Ordering::Relaxed);
            }
        }
    }

    /// Single-consumer pop.
    ///
    /// SAFETY: must not be called concurrently with itself. The helper's
    /// contract is that only the owner worker for a binding pops from its
    /// inbox.
    pub(super) unsafe fn pop(&self) -> Option<T> {
        let pos = self.tail.0.load(Ordering::Relaxed);
        // SAFETY: `pos & mask` is in range.
        let slot = unsafe { self.slots.get_unchecked(pos & self.mask) };
        let seq = slot.seq.load(Ordering::Acquire);
        let diff = (seq as isize).wrapping_sub(pos.wrapping_add(1) as isize);
        if diff == 0 {
            // Slot holds a value published at sequence `pos+1`.
            // SAFETY: by the single-consumer invariant we are the only
            // reader, and the producer already wrote the value before
            // releasing the slot via `seq.store(pos+1, Release)`.
            let val = unsafe { (*slot.val.get()).assume_init_read() };
            // Republish slot for the next pass: producer looking at this
            // slot at position `pos + cap` will see `seq == pos + cap`
            // and be cleared to claim it.
            slot.seq.store(
                pos.wrapping_add(self.mask).wrapping_add(1),
                Ordering::Release,
            );
            self.tail
                .0
                .store(pos.wrapping_add(1), Ordering::Release);
            Some(val)
        } else {
            // seq behind pos+1: no value yet at this tail position.
            None
        }
    }
}

impl<T> Drop for MpscInbox<T> {
    fn drop(&mut self) {
        // SAFETY: &mut self gives us exclusive access, so the single-
        // consumer invariant holds trivially.
        while unsafe { self.pop() }.is_some() {}
    }
}

#[cfg(test)]
#[path = "mpsc_inbox_tests.rs"]
mod tests;
