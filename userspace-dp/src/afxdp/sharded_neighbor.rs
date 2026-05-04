//! #949 PR1: sharded mutex for the dynamic neighbor cache.
//!
//! Replaces the single `Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>`
//! with `Arc<ShardedNeighborMap>` — 64 cache-line-padded shards. Reduces
//! cache-line bouncing on the hot path: every flow-cache miss does a
//! neighbor lookup that previously contended on one mutex.
//!
//! ## Design
//!
//! - 64 shards (`NUM_SHARDS = 64`). Standard choice; matches `dashmap`.
//! - Shard hash mixes FxHash output with a Knuth multiplier so the
//!   shard index is decorrelated from `hashbrown`'s internal bucket
//!   selection (which uses high hash bits).
//! - Cache-line padding via `#[repr(align(64))]` ensures adjacent
//!   shards do not share cache lines (false-sharing prevention).
//! - Bulk operations via `BulkShardGuard`: locks all 64 shards in
//!   shard-index order. Deadlock-free as long as every other caller
//!   that wants more than one shard also locks in ascending order.
//! - Poison policy: `lock().unwrap_or_else(|e| e.into_inner())`.
//!   Workers DO have a `catch_unwind` supervisor as of #925 Phase 1
//!   (`spawn_supervised_worker` in `coordinator/mod.rs`), and #925
//!   Phase 2 surfaces panics on Prometheus
//!   (`xpf_userspace_worker_dead`). But a poisoned `Mutex` here is
//!   operationally worse than a stale MAC for the *surviving* threads:
//!   `NeighborEntry` is plain `[u8; 6]` with no invariants to corrupt,
//!   so the safer choice is to recover-from-poison and keep forwarding.

use super::types::{FastMap, NeighborEntry};
use rustc_hash::FxHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};

pub(super) const NUM_SHARDS: usize = 64;

/// One mutex-guarded shard, padded to 64 bytes so adjacent shards do
/// not share cache lines.
#[repr(align(64))]
pub(super) struct PaddedShard(Mutex<FastMap<(i32, IpAddr), NeighborEntry>>);

impl PaddedShard {
    fn new() -> Self {
        Self(Mutex::new(FastMap::default()))
    }
}

/// 64-shard mutex map for the dynamic neighbor cache.
pub(crate) struct ShardedNeighborMap {
    shards: [PaddedShard; NUM_SHARDS],
}

/// Shard index for a key. The Knuth multiplier `0x9E3779B97F4A7C15`
/// (the 64-bit golden ratio) spreads entropy into the HIGH bits of
/// the product, so we extract the top `log2(NUM_SHARDS) = 6` bits
/// rather than the low bits. This decorrelates shard selection from
/// `hashbrown`'s internal SwissTable bucket selection (which also
/// uses high hash bits) by feeding it a freshly-rotated hash, and it
/// produces a uniform distribution for adversarial input patterns
/// like `/24` LANs (constant ifindex + sequential last octet).
const SHARD_BITS: u32 = NUM_SHARDS.trailing_zeros();

fn shard_idx(key: &(i32, IpAddr)) -> usize {
    let mut hasher = FxHasher::default();
    key.hash(&mut hasher);
    let h = hasher.finish();
    let mixed = h.wrapping_mul(0x9E3779B97F4A7C15);
    (mixed >> (64 - SHARD_BITS)) as usize
}

impl ShardedNeighborMap {
    pub(crate) fn new() -> Self {
        Self {
            shards: std::array::from_fn(|_| PaddedShard::new()),
        }
    }

    fn lock_shard(
        &self,
        idx: usize,
    ) -> MutexGuard<'_, FastMap<(i32, IpAddr), NeighborEntry>> {
        match self.shards[idx].0.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Get a copy of the entry for `key`, if present.
    pub(crate) fn get(&self, key: &(i32, IpAddr)) -> Option<NeighborEntry> {
        self.lock_shard(shard_idx(key)).get(key).copied()
    }

    /// Insert (or overwrite) `key → val`. Unit-returning.
    pub(crate) fn insert(&self, key: (i32, IpAddr), val: NeighborEntry) {
        self.lock_shard(shard_idx(&key)).insert(key, val);
    }

    /// Remove `key` if present. Unit-returning.
    pub(crate) fn remove(&self, key: &(i32, IpAddr)) {
        self.lock_shard(shard_idx(key)).remove(key);
    }

    /// Insert `key → val` and return whether the cache changed.
    /// Returns `false` if the key already existed with the same MAC.
    /// Mirrors `neighbor::update_dynamic_neighbor` semantics.
    pub(crate) fn insert_if_changed(
        &self,
        key: (i32, IpAddr),
        val: NeighborEntry,
    ) -> bool {
        let mut shard = self.lock_shard(shard_idx(&key));
        if shard.get(&key).map(|existing| existing.mac) == Some(val.mac) {
            return false;
        }
        shard.insert(key, val);
        true
    }

    /// Remove `key` if present and return whether it was actually
    /// removed. Mirrors `neighbor::remove_dynamic_neighbor` semantics.
    pub(crate) fn remove_if_present(&self, key: &(i32, IpAddr)) -> bool {
        self.lock_shard(shard_idx(key)).remove(key).is_some()
    }

    /// Lock every shard in shard-index order and run the closure with
    /// access to all of them. Used for atomic-vs-readers bulk
    /// operations: replace, clear, multi-key insert.
    ///
    /// Deadlock-free as long as every other caller that wants more
    /// than one shard locks in ascending shard-index order.
    ///
    /// **Non-reentrant**: the closure MUST NOT call any other method
    /// on the same `ShardedNeighborMap` (or any of its `Arc` clones) —
    /// every shard is already locked, so a per-key call would
    /// self-deadlock waiting on a shard the same thread holds.
    pub(crate) fn with_all_shards<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&mut BulkShardGuard<'_>) -> R,
    {
        // Lock all 64 shards in ascending order. Use a Vec then convert
        // to a fixed-size array because MutexGuard doesn't impl Default,
        // ruling out `array::from_fn`.
        let mut guards: Vec<MutexGuard<'_, FastMap<(i32, IpAddr), NeighborEntry>>> =
            Vec::with_capacity(NUM_SHARDS);
        for i in 0..NUM_SHARDS {
            guards.push(self.lock_shard(i));
        }
        let mut bulk = BulkShardGuard {
            guards: guards.try_into().ok().expect("exactly NUM_SHARDS guards pushed"),
        };
        f(&mut bulk)
    }

    /// Total entry count summed across shards. Locks all shards in
    /// order. Used by `coordinator::dynamic_neighbor_status`.
    pub(crate) fn len(&self) -> usize {
        self.with_all_shards(|bulk| bulk.total_len())
    }

    /// True iff the map has zero entries across all shards.
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// True iff `key` is present in its shard.
    pub(crate) fn contains_key(&self, key: &(i32, IpAddr)) -> bool {
        self.lock_shard(shard_idx(key)).contains_key(key)
    }
}

impl Default for ShardedNeighborMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Holds all 64 shard `MutexGuard`s so a bulk closure can mutate
/// across shards safely. Provides key-routed `insert`/`remove` plus
/// raw shard iteration for `clear` and friends.
pub(crate) struct BulkShardGuard<'a> {
    guards: [MutexGuard<'a, FastMap<(i32, IpAddr), NeighborEntry>>; NUM_SHARDS],
}

impl<'a> BulkShardGuard<'a> {
    /// Insert `key → val` into the appropriate shard.
    pub(crate) fn insert(&mut self, key: (i32, IpAddr), val: NeighborEntry) {
        let i = shard_idx(&key);
        self.guards[i].insert(key, val);
    }

    /// Remove `key` from the appropriate shard.
    pub(crate) fn remove(&mut self, key: &(i32, IpAddr)) {
        let i = shard_idx(key);
        self.guards[i].remove(key);
    }

    /// Iterate every shard's underlying map mutably. Used for
    /// shard-wide operations like `clear`.
    pub(crate) fn each_shard_mut(
        &mut self,
    ) -> impl Iterator<Item = &mut FastMap<(i32, IpAddr), NeighborEntry>> {
        self.guards.iter_mut().map(|g| &mut **g)
    }

    /// Sum of `len()` across all shards.
    pub(crate) fn total_len(&self) -> usize {
        self.guards.iter().map(|g| g.len()).sum()
    }
}

#[cfg(test)]
#[path = "sharded_neighbor_tests.rs"]
mod tests;

