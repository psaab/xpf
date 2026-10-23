//! #15956: sharded live-flow map (Phase-2 of #2852).
//!
//! `live_by_flow` was the residual bottleneck: one
//! `Mutex<PortAllocatorLiveState>` serialized every new-flow
//! alloc/release (measured p50 391ns @M=1 -> 12,928ns @M=8, ~59%
//! contended @M=8). The flow map now lives in 16 shards keyed by
//! FxHash of the flow key; persistent-lease / ownership / GC state
//! stays in the retained `live` mutex (not on the non-persistent
//! new-flow hot path).
//!
//! Cap exactness (fold 2): the shared ADMISSION counter is the
//! one atomic every new-slot path must win before inserting —
//! `admit_one` does `fetch_add(1)` and rolls back when the
//! result exceeds `max_tracked_flows`, so two paths on
//! DIFFERENT shards (e.g. a displaced restore and a fast-path
//! insert, both at cap-1) cannot both pass a `len()` check and
//! overshoot. Replacements of an existing key consume no slot
//! and never touch the counter. `len()` (the exact tracked
//! count, bumped only on actual insert/remove under a shard
//! lock) remains the value `live_flow_count` reports; the
//! admission counter is >= it by at most the in-flight admits
//! between `fetch_add` and insert, each of which either lands
//! or rolls back. Never overshoots, never falsely exhausts
//! once in-flight admits settle (#4676 F4).
//! Holder-mask mutation stays under the shard write lock.
//! Lock order: the retained `live` mutex (`RwLock`) is only ever
//! taken BEFORE a shard, never while holding one, and writers
//! hold the one shard for their flow across the whole admission
//! (reuse check, cap check, wire-identity/owner publish, insert)
//! so a same-flow race cannot slip between check and insert.
//! std Mutex is not reentrant, so a shard guard must never be
//! re-acquired for the same flow while one is held, and a helper
//! that inserts/removes under the shard must be given the held
//! guard (the `*_in_shard` forms), never let to lock again.
//! Read-only `live` consumers (notably the non-persistent
//! new-flow admission check) take the `RwLock` read guard, so
//! distinct new flows proceed concurrently; only lease/index
//! writers serialize on the write guard.

use super::LiveAllocation;
use crate::nat::SourceNatFlowKey;
use rustc_hash::FxHashMap;
use std::hash::Hasher;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

pub(in crate::nat::allocator) const LIVE_SHARDS: usize = 16;

pub(in crate::nat::allocator) fn live_shard_index(flow: &SourceNatFlowKey) -> usize {
    let mut hasher = rustc_hash::FxHasher::default();
    std::hash::Hash::hash(flow, &mut hasher);
    (hasher.finish() as usize) & (LIVE_SHARDS - 1)
}

// Visible to `nat::` (not just the allocator) so the cfg(test)
// `debug_hold_flow_shard` guard type can be named by nat tests.
#[derive(Debug, Default)]
pub(in crate::nat) struct LiveFlowShard {
    pub(in crate::nat::allocator) map: FxHashMap<SourceNatFlowKey, LiveAllocation>,
}

// The map type legacy code names as `live.live_by_flow`. Every
// method delegates to exactly one shard (or all shards for
// len/iter/clear), preserving the old FxHashMap semantics.
#[derive(Debug)]
pub(in crate::nat::allocator) struct LiveFlowMap {
    pub(in crate::nat::allocator) shards: Vec<Mutex<LiveFlowShard>>,
    pub(in crate::nat::allocator) count: AtomicUsize,
    /// Fold 2: shared atomic admission counter (see module doc).
    /// Incremented ONLY by `admit_one`, decremented ONLY by a
    /// successful record removal (`remove_in_shard`) or an
    /// `unadmit_one` rollback of an admission whose insert
    /// never landed.
    admission: AtomicUsize,
}

impl Default for LiveFlowMap {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveFlowMap {
    pub(in crate::nat::allocator) fn new() -> Self {
        Self {
            shards: (0..LIVE_SHARDS)
                .map(|_| Mutex::new(LiveFlowShard::default()))
                .collect(),
            count: AtomicUsize::new(0),
            admission: AtomicUsize::new(0),
        }
    }

    /// Current admission-counter value (test seam: proves the
    /// counter settles back to the tracked count, never leaks).
    pub(in crate::nat::allocator) fn admission_count(&self) -> usize {
        self.admission.load(Ordering::Relaxed)
    }


    /// Fold 2: atomically claim one tracked-flow slot against
    /// `max_tracked`. `fetch_add` first; if the claim takes the
    /// counter PAST the cap, roll it back and refuse. Two
    /// racers on different shards at cap-1: exactly one wins.
    /// The winner MUST insert the record promptly (same lock
    /// discipline as its caller) — removal of the admitted
    /// record is the release (see `remove_in_shard`).
    pub(in crate::nat::allocator) fn admit_one(&self, max_tracked: usize) -> bool {
        if self.admission.fetch_add(1, Ordering::Relaxed) >= max_tracked {
            self.admission.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// Fold 2: roll back a successful `admit_one` whose insert
    /// did NOT land (caller abandoned the admission). Exactly
    /// one rollback per admit; never call after the record was
    /// inserted (its removal releases instead).
    pub(in crate::nat::allocator) fn unadmit_one(&self) {
        self.admission.fetch_sub(1, Ordering::Relaxed);
    }

    pub(in crate::nat::allocator) fn shard_guard<'a>(
        &'a self,
        flow: &SourceNatFlowKey,
    ) -> MutexGuard<'a, LiveFlowShard> {
        self.shards[live_shard_index(flow)]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn write_shard(
        &self,
        flow: &SourceNatFlowKey,
    ) -> MutexGuard<'_, LiveFlowShard> {
        self.shard_guard(flow)
    }

    pub(in crate::nat::allocator) fn get(
        &self,
        flow: &SourceNatFlowKey,
    ) -> Option<LiveAllocation> {
        self.shard_guard(flow).map.get(flow).copied()
    }

    pub(in crate::nat::allocator) fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// Exact-cap admission under a HELD shard guard (fold 2):
    /// replacing an existing key consumes no slot and always
    /// succeeds; a NEW key must first win the shared atomic
    /// admission counter (`admit_one`), so racers on different
    /// shards at cap-1 cannot both insert. Returns false (cap
    /// reached) without inserting.
    pub(in crate::nat::allocator) fn try_insert_in_shard(
        &self,
        shard: &mut LiveFlowShard,
        flow: SourceNatFlowKey,
        alloc: LiveAllocation,
        max_tracked: usize,
    ) -> bool {
        if shard.map.contains_key(&flow) {
            shard.map.insert(flow, alloc);
            return true;
        }
        if !self.admit_one(max_tracked) {
            return false;
        }
        self.insert_admitted_in_shard(shard, flow, alloc);
        true
    }

    /// Insert a NEW key whose tracked-flow slot was ALREADY
    /// claimed via `admit_one` by the caller (fold 3: paths that
    /// must admit before creating lease state). Bumps only the
    /// tracked count — the admission slot is the caller's claim,
    /// released when this record is removed. Must not be used
    /// for a key already present (that is a replacement and
    /// would strand the caller's claim).
    pub(in crate::nat::allocator) fn insert_admitted_in_shard(
        &self,
        shard: &mut LiveFlowShard,
        flow: SourceNatFlowKey,
        alloc: LiveAllocation,
    ) {
        let prev = shard.map.insert(flow, alloc);
        debug_assert!(prev.is_none(), "admitted insert must be a new key");
        if prev.is_none() {
            self.count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Counted shard write guard for the #4800 telemetry pair:
    /// callers that previously went through `lock_live()` for a
    /// flow-only critical section use this so acquisitions and
    pub(in crate::nat::allocator) fn write_shard_counted<'a>(
        &'a self,
        flow: &SourceNatFlowKey,
        acquisitions: &std::sync::atomic::AtomicU64,
        contended: &std::sync::atomic::AtomicU64,
    ) -> MutexGuard<'a, LiveFlowShard> {
        acquisitions.fetch_add(1, Ordering::Relaxed);
        let shard = &self.shards[live_shard_index(flow)];
        match shard.try_lock() {
            Ok(g) => return g,
            Err(std::sync::TryLockError::Poisoned(p)) => return p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {}
        }
        contended.fetch_add(1, Ordering::Relaxed);
        shard.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(in crate::nat::allocator) fn insert_in_shard(
        &self,
        shard: &mut LiveFlowShard,
        flow: SourceNatFlowKey,
        alloc: LiveAllocation,
    ) -> Option<LiveAllocation> {
        let prev = shard.map.insert(flow, alloc);
        if prev.is_none() {
            self.count.fetch_add(1, Ordering::Relaxed);
        }
        prev
    }

    /// Remove under a HELD shard guard: removing an actual
    /// record releases BOTH the tracked count and the admission
    /// slot it was admitted with (fold 2 pairing).
    pub(in crate::nat::allocator) fn remove_in_shard(
        &self,
        shard: &mut LiveFlowShard,
        flow: &SourceNatFlowKey,
    ) -> Option<LiveAllocation> {
        let prev = shard.map.remove(flow);
        if prev.is_some() {
            self.count.fetch_sub(1, Ordering::Relaxed);
            self.admission.fetch_sub(1, Ordering::Relaxed);
        }
        prev
    }

    pub(in crate::nat::allocator) fn get_in_shard(
        &self,
        shard: &LiveFlowShard,
        flow: &SourceNatFlowKey,
    ) -> Option<LiveAllocation> {
        shard.map.get(flow).copied()
    }

    /// Holder-mask drop under a HELD shard guard (#6211 F2
    /// semantics in `drop_holder_locked`): returns true when
    /// other holders remain and the record must survive.
    pub(in crate::nat::allocator) fn drop_holder_in_shard(
        &self,
        shard: &mut LiveFlowShard,
        flow: &SourceNatFlowKey,
        existing: LiveAllocation,
        holder_bit: u128,
    ) -> bool {
        if existing.holders == 0 {
            return false;
        }
        let remaining = existing.holders & !holder_bit;
        if remaining == 0 {
            return false;
        }
        if let Some(slot) = shard.map.get_mut(flow) {
            slot.holders = remaining;
        }
        true
    }
    /// Raw shard write guard for sites that held the old single
    /// mutex across a `get_mut` block (holder OR + read). The
    /// guard is the exact analogue of the old `&mut` borrow:
    /// same-flow atomicity, no cross-flow serialization.
    pub(in crate::nat::allocator) fn get_mut_shard(
        &self,
        flow: &SourceNatFlowKey,
    ) -> MutexGuard<'_, LiveFlowShard> {
        self.write_shard(flow)
    }


    /// Snapshot of all entries (cold paths: retire_worker, snapshot
    /// debug walks). Takes each shard read lock in index order.
    pub(in crate::nat::allocator) fn entries(
        &self,
    ) -> Vec<(SourceNatFlowKey, LiveAllocation)> {
        let mut out = Vec::new();
        for shard in &self.shards {
            let guard = shard.lock().unwrap_or_else(|e| e.into_inner());
            out.extend(guard.map.iter().map(|(k, v)| (*k, *v)));
        }
        out
    }
}

