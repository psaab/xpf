//! #17269: the one cross-worker sharded-lock container.
//!
//! Before this module the crate hand-rolled the same shape eight times
//! (dynamic neighbours, steering owners, tuple gate, SNAT live flows,
//! PMech directory, punt-seed directory, and the two fragment maps) and
//! the copies drifted: some padded their shards, some did not; some
//! carried a compile-time power-of-two guard, some did not; placement
//! ranged over the keyed hot-path hash, an unkeyed `FxHasher`, and a
//! fixed-seed `DefaultHasher`. The newest copy (#15956, the SNAT live
//! map) re-introduced all three defects at once: unpadded shards, no
//! power-of-two guard, and an unkeyed shard index — the exact placement
//! class #12794 had already fixed in the copies it named.
//!
//! `ShardedMap<K, V, N>` is the shared shard storage and placement function:
//!
//! - `N` shards, each a `PaddedShard` (`#[repr(align(128))]`), so each
//!   shard starts on a 128-byte boundary and cannot share a 64-byte cache
//!   line with its neighbors.
//! - `N >= 2 && N.is_power_of_two()` is a compile-time obligation of every
//!   monomorphisation: mask-based selection is only total for powers of two.
//! - Placement uses the process-keyed `HotPathSeededState` and is stable
//!   within a process. The specialized fragment maps keep their independent
//!   domain seeds (#12602), feeding their existing coarse digest through
//!   the shared `keyed_shard_index` implementation.
//!
//! The shard cell is generic over the lock type: callers retain their
//! existing `Mutex`/`RwLock`, poison policy, counted acquisition, and
//! ascending multi-shard lock order. This keeps behavior local while the
//! padding, array sizing, compile-time guard, and ordinary keyed index have
//! one definition.
//!
//! Zero-cost note: the shard array is inline (no `Vec` indirection) and
//! construction is `array::from_fn`; `shard_index_for` and shard accessors
//! are inline.

use crate::hot_hash_seed::{HotPathSeededState, keyed_shard_index};
use std::hash::{BuildHasher, Hash};
use std::marker::PhantomData;
use std::sync::{Mutex, MutexGuard};

/// One cache-line-isolated cell storing the consumer's lock value.
///
/// This is the single definition point for shard padding in the crate:
/// every sharded cross-worker container stores its shards as
/// `[PaddedShard<_>; N]` (via [`ShardedMap`]).
#[repr(align(128))]
pub(crate) struct PaddedShard<T> {
    inner: T,
}

impl<T> PaddedShard<T> {
    #[inline]
    pub(crate) fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Access the consumer's lock, preserving its local poison/try-lock policy.
    #[inline]
    pub(crate) fn get(&self) -> &T {
        &self.inner
    }
}

impl<T> PaddedShard<Mutex<T>> {
    /// Poison-tolerant lock (the crate default, `sync_util` shape).
    #[inline]
    pub(crate) fn lock(&self) -> MutexGuard<'_, T> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl<T: Default> Default for PaddedShard<T> {
    #[inline]
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for PaddedShard<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PaddedShard").field(&self.inner).finish()
    }
}

/// Compile-time-guarded keyed placement for an ordinary key.
#[inline]
pub(crate) fn shard_index_with_seed<K: Hash + ?Sized, const N: usize>(
    key: &K,
    seed: u64,
) -> usize {
    let () = ShardedMap::<(), (), N>::GUARD;
    (HotPathSeededState::new(seed).hash_one(key) as usize) & (N - 1)
}

/// Compile-time-guarded keyed placement for a caller-folded digest.
#[inline]
pub(crate) fn shard_index_from_hash<const N: usize>(hash: u64, seed: u64, domain: u64) -> usize {
    let () = ShardedMap::<(), (), N>::GUARD;
    keyed_shard_index(hash, seed, domain, N)
}

/// N cache-padded shards storing each consumer's per-shard value.
///
/// `K` is the map key type used by `shard_index_for`; `V` retains each
/// consumer's lock/value implementation (usually a lock around one bucket).
pub(crate) struct ShardedMap<K, V, const N: usize> {
    shards: [PaddedShard<V>; N],
    seed: u64,
    key: PhantomData<fn(&K)>,
}

impl<K, V, const N: usize> ShardedMap<K, V, N> {
    const GUARD: () = assert!(
        N >= 2 && N.is_power_of_two(),
        "ShardedMap shard count must be a power of two >= 2 (mask-based shard selection)"
    );

    /// Shards over the process-global hot-path seed.
    pub(crate) fn new() -> Self
    where
        V: Default,
    {
        Self::with_seed(crate::hot_hash_seed::hot_path_hash_seed())
    }

    /// Shards over an explicit seed (tests pin placement; specialized
    /// fragment maps can retain their own seeds via `shard_index_from_hash`).
    pub(crate) fn with_seed(seed: u64) -> Self
    where
        V: Default,
    {
        // Touch the const assert even on paths that never hash.
        let () = Self::GUARD;
        Self {
            shards: std::array::from_fn(|_| PaddedShard::default()),
            seed,
            key: PhantomData,
        }
    }

    /// Shards initialized by the consumer's lock/value constructor.
    pub(crate) fn with_seed_and(seed: u64, make: impl FnMut() -> V) -> Self {
        let () = Self::GUARD;
        let mut make = make;
        Self {
            shards: std::array::from_fn(|_| PaddedShard::new(make())),
            seed,
            key: PhantomData,
        }
    }

    /// The common shard-placement function: keyed hot-path hash of `key`,
    /// masked to `N`. Deterministic within a process, as required for
    /// sorted multi-shard locking.
    #[inline]
    pub(crate) fn shard_index_for(&self, key: &K) -> usize
    where
        K: Hash,
    {
        shard_index_with_seed::<K, N>(key, self.seed)
    }

    /// The shard cell for `key`.
    #[inline]
    pub(crate) fn shard_for(&self, key: &K) -> &PaddedShard<V>
    where
        K: Hash,
    {
        &self.shards[self.shard_index_for(key)]
    }

    /// The shard cell at `index` (bulk/iteration paths that already
    /// hold an index; ascending order is the caller's lock discipline).
    #[inline]
    pub(crate) fn shard_at(&self, index: usize) -> &PaddedShard<V> {
        &self.shards[index]
    }

    /// All shard cells, in index order.
    #[inline]
    pub(crate) fn shards(&self) -> &[PaddedShard<V>; N] {
        &self.shards
    }

    /// Shard count (`N`), for caps and test fixtures.
    #[inline]
    pub(crate) const fn shard_count(&self) -> usize {
        N
    }
}

impl<K, V: Default, const N: usize> Default for ShardedMap<K, V, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V: std::fmt::Debug, const N: usize> std::fmt::Debug for ShardedMap<K, V, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardedMap")
            .field("shards", &self.shards)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn shard_padding_is_128_byte_aligned() {
        assert_eq!(core::mem::align_of::<PaddedShard<Mutex<()>>>(), 128);
        assert!(core::mem::size_of::<PaddedShard<Mutex<()>>>() >= 128);
        assert_eq!(
            core::mem::align_of::<PaddedShard<std::sync::RwLock<()>>>(),
            128
        );
    }

    #[test]
    fn shard_index_is_in_range_and_stable_for_a_seed() {
        let map = ShardedMap::<u64, Mutex<HashMap<u64, u64>>, 16>::with_seed(42);
        for key in 0..1024u64 {
            let idx = map.shard_index_for(&key);
            assert!(idx < 16, "shard index {idx} out of range");
            assert_eq!(idx, map.shard_index_for(&key), "placement must be stable");
        }
        assert_eq!(map.shard_count(), 16);
    }

    #[test]
    fn shard_index_uses_the_keyed_hash_not_a_fixed_one() {
        let a = ShardedMap::<u64, Mutex<HashMap<u64, u64>>, 16>::with_seed(1);
        let b = ShardedMap::<u64, Mutex<HashMap<u64, u64>>, 16>::with_seed(2);
        let moved = (0..256u64).any(|k| a.shard_index_for(&k) != b.shard_index_for(&k));
        assert!(moved, "different seeds must reshuffle placement");
    }

    #[test]
    fn shards_hold_independent_values() {
        let map = ShardedMap::<u64, Mutex<HashMap<u64, u64>>, 16>::with_seed(7);
        for key in 0..256u64 {
            map.shard_for(&key).lock().insert(key, key * 10);
        }
        let total: usize = map.shards().iter().map(|s| s.lock().len()).sum();
        assert_eq!(total, 256);
        for key in 0..256u64 {
            assert_eq!(map.shard_for(&key).lock().get(&key), Some(&(key * 10)));
        }
    }

}

