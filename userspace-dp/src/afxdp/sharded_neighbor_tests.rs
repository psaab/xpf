// Tests for afxdp/sharded_neighbor.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep sharded_neighbor.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "sharded_neighbor_tests.rs"]` from sharded_neighbor.rs.

use super::*;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

fn entry(mac_byte: u8) -> NeighborEntry {
    NeighborEntry { mac: [mac_byte; 6] }
}

fn key_v4(ifindex: i32, last_octet: u8) -> (i32, IpAddr) {
    (ifindex, IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)))
}

/// #5147: two v4 neighbor keys guaranteed to live in DIFFERENT shards. A MAC
/// change on one bumps only its shard's epoch, so the other's stays put —
/// the per-neighbor isolation the map-wide-thrash fix provides.
fn keys_in_distinct_shards() -> ((i32, IpAddr), (i32, IpAddr)) {
    let base = key_v4(7, 1);
    let base_shard = ShardedNeighborMap::shard_index(&base);
    for octet in 2..=255u8 {
        let cand = key_v4(7, octet);
        if ShardedNeighborMap::shard_index(&cand) != base_shard {
            return (base, cand);
        }
    }
    panic!("no distinct-shard key pair found among /24 last octets");
}

#[test]
fn get_returns_inserted_value() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    map.insert(k, entry(0xAB));
    assert_eq!(map.get(&k), Some(entry(0xAB)));
}

#[test]
fn get_returns_none_for_missing_key() {
    let map = ShardedNeighborMap::new();
    assert_eq!(map.get(&key_v4(7, 99)), None);
}

#[test]
fn remove_clears_entry() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    map.insert(k, entry(0xAB));
    map.remove(&k);
    assert_eq!(map.get(&k), None);
}

#[test]
fn remove_if_present_returns_true_when_existing_false_when_absent() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    map.insert(k, entry(0xAB));
    assert!(map.remove_if_present(&k));
    assert!(!map.remove_if_present(&k));
}

#[test]
fn insert_if_changed_returns_true_on_first_insert() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    assert!(map.insert_if_changed(k, entry(0xAB)));
}

#[test]
fn insert_if_changed_returns_false_on_same_mac() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    map.insert(k, entry(0xAB));
    assert!(!map.insert_if_changed(k, entry(0xAB)));
}

#[test]
fn insert_if_changed_returns_true_on_mac_change() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    map.insert(k, entry(0xAB));
    assert!(map.insert_if_changed(k, entry(0xCD)));
    assert_eq!(map.get(&k), Some(entry(0xCD)));
}

#[test]
fn len_sums_across_shards() {
    let map = ShardedNeighborMap::new();
    for i in 0..200u8 {
        map.insert(key_v4(7, i), entry(i));
    }
    assert_eq!(map.len(), 200);
}

#[test]
fn with_all_shards_clear_via_each_shard_mut() {
    let map = ShardedNeighborMap::new();
    for i in 0..50u8 {
        map.insert(key_v4(7, i), entry(i));
    }
    map.with_all_shards(|bulk| {
        for shard in bulk.each_shard_mut() {
            shard.clear();
        }
    });
    assert_eq!(map.len(), 0);
}

#[test]
fn with_all_shards_atomic_replace() {
    let map = ShardedNeighborMap::new();
    // Pre-populate with 5 keys.
    let old_keys: Vec<_> = (0..5u8).map(|i| key_v4(7, i)).collect();
    for &k in &old_keys {
        map.insert(k, entry(0x11));
    }
    // Atomic replace: remove old keys, insert new ones with different
    // MAC. All under one with_all_shards call.
    let new_pairs: Vec<_> = (10..15u8).map(|i| (key_v4(7, i), entry(0x22))).collect();
    map.with_all_shards(|bulk| {
        for &k in &old_keys {
            bulk.remove(&k);
        }
        for (k, v) in &new_pairs {
            bulk.insert(*k, *v);
        }
    });
    for &k in &old_keys {
        assert_eq!(map.get(&k), None);
    }
    for (k, v) in &new_pairs {
        assert_eq!(map.get(k), Some(*v));
    }
}

#[test]
fn padded_shard_align_at_least_64() {
    assert!(std::mem::align_of::<PaddedShard>() >= 64);
}

/// Distribution test: /24 LAN with constant ifindex. Real-world
/// pattern that previously could collide if shard hash were
/// correlated with FastMap inner hash.
///
/// With N=256 keys and K=64 shards, ideal = 4 keys/shard. Even a
/// perfect uniform-random hash gives a maximum bin around 9-11
/// with high probability (max-of-binomial); we accept ≤ 3× ideal
/// (12) to filter only obviously-correlated hashes.
#[test]
fn shard_distribution_ipv4_24_constant_ifindex() {
    for &seed in SHARD_SEEDS_7752 {
    let mut counts = [0usize; NUM_SHARDS];
    for last in 0..=255u8 {
        counts[shard_idx_with(seed, &key_v4(7, last))] += 1;
    }
    let max = *counts.iter().max().unwrap();
    assert!(
        max <= 12,
        "shard distribution too skewed under seed {:#x}: {:?} (max {})",
        seed,
        counts,
        max
    );
    }
}

/// Distribution test: /16 LAN, varying second-to-last octet.
#[test]
fn shard_distribution_ipv4_16() {
    for &seed in SHARD_SEEDS_7752 {
    let mut counts = [0usize; NUM_SHARDS];
    for second_last in 0..=255u16 {
        for last in 0..=15u16 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, second_last as u8, last as u8));
            counts[shard_idx_with(seed, &(7, ip))] += 1;
        }
    }
    // 4096 keys, 64 shards → ideal 64/shard. Acceptance: max ≤ 2× ideal.
    let max = *counts.iter().max().unwrap();
    assert!(
        max <= 128,
        "shard distribution too skewed under seed {:#x}: max {} (ideal 64)",
        seed,
        max
    );
    }
}

/// Distribution test: IPv6 SLAAC-like pattern (varying last 8 bytes).
#[test]
fn shard_distribution_ipv6_slaac() {
    for &seed in SHARD_SEEDS_7752 {
    let mut counts = [0usize; NUM_SHARDS];
    for i in 0..256u32 {
        for j in 0..16u32 {
            let ip = IpAddr::V6(Ipv6Addr::new(
                0xfe80,
                0,
                0,
                0,
                0xabcd,
                0xef01,
                (i & 0xFFFF) as u16,
                (j & 0xFFFF) as u16,
            ));
            counts[shard_idx_with(seed, &(7, ip))] += 1;
        }
    }
    // 4096 keys, 64 shards → ideal 64/shard. Acceptance: max ≤ 2× ideal.
    let max = *counts.iter().max().unwrap();
    assert!(
        max <= 128,
        "ipv6 shard distribution too skewed under seed {:#x}: max {} (ideal 64)",
        seed,
        max
    );
    }
}

/// Poison policy: a thread that panics while holding the shard
/// lock leaves it poisoned. The next caller must continue working
/// (`into_inner` recovery) rather than propagate a poison panic.
#[test]
fn poison_recovered_via_into_inner() {
    use std::sync::Arc;
    use std::thread;

    let map = Arc::new(ShardedNeighborMap::new());
    let k = key_v4(7, 42);
    map.insert(k, entry(0xAB));

    // Force a poison: spawn a thread that locks the shard then panics.
    let map_clone = Arc::clone(&map);
    let _ = thread::spawn(move || {
        let _g = map_clone.shards[shard_idx(&k)].0.lock().unwrap();
        panic!("intentional poison");
    })
    .join();

    // After the thread panicked, the shard is poisoned. Our get()
    // must NOT propagate the poison — it must use into_inner and
    // return the existing entry.
    assert_eq!(map.get(&k), Some(entry(0xAB)));
}

/// Concurrency stress: 8 worker threads each doing 1000 per-key
/// insert/get/remove ops on disjoint key ranges, while one
/// "replace" thread periodically calls `with_all_shards` to do an
/// atomic bulk replace. Verifies no deadlock under interleaving
/// (the deadlock-freedom invariant: bulk locks shards 0..63 in
/// order; per-key holds at most one shard at a time, so no cycle).
#[test]
fn concurrent_per_key_with_bulk_replace_no_deadlock() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let map = Arc::new(ShardedNeighborMap::new());
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    // 8 per-key worker threads on disjoint ifindex ranges.
    for tid in 0..8u8 {
        let map = Arc::clone(&map);
        let stop = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            let mut iter = 0u32;
            while !stop.load(Ordering::Relaxed) {
                let key = (
                    (tid as i32) * 1000 + (iter % 100) as i32,
                    IpAddr::V4(Ipv4Addr::new(10, tid, (iter / 256) as u8, iter as u8)),
                );
                let _ = map.insert_if_changed(key, entry(tid));
                let _ = map.get(&key);
                if iter & 7 == 0 {
                    let _ = map.remove_if_present(&key);
                }
                iter = iter.wrapping_add(1);
            }
        }));
    }

    // One bulk thread doing atomic bulk replaces. If a deadlock
    // existed, this thread would block forever waiting for a
    // per-key shard lock that another thread blocks on.
    let map_bulk = Arc::clone(&map);
    let stop_bulk = Arc::clone(&stop);
    handles.push(thread::spawn(move || {
        while !stop_bulk.load(Ordering::Relaxed) {
            map_bulk.with_all_shards(|bulk| {
                for i in 0..16u8 {
                    bulk.insert(
                        (9999, IpAddr::V4(Ipv4Addr::new(10, 99, 99, i))),
                        entry(0xFF),
                    );
                }
            });
            thread::sleep(Duration::from_micros(100));
        }
    }));

    // Run for ~200 ms.
    thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().expect("worker panicked");
    }
    // Map remains usable.
    assert!(map.len() > 0);
}

// ── #3048/#5147: PER-SHARD neighbor MAC-change epoch ──────────────────
// The worker flow cache stamps the epoch of the SPECIFIC shard its
// resolved next-hop lives in (`FlowCacheEntry::neighbor_shard`) and
// re-reads that one slot on every fast-path hit. A shard's epoch MUST
// advance only on a genuine MAC CHANGE to a neighbor IN THAT SHARD, so a
// stale cached dst_mac is evicted; it MUST NOT advance on a first insert
// or a same-MAC refresh, and a change to a neighbor in a DIFFERENT shard
// MUST leave this shard's epoch untouched (#5147 — the old single global
// epoch let one neighbor's MAC flap invalidate every cached flow).
// Reverting any `bump_shard_epoch` makes the corresponding "change bumps"
// assertion fail (RED); the isolation test fails if a change bumps a
// shard other than its own.

#[test]
fn mac_change_epoch_starts_at_zero() {
    let map = ShardedNeighborMap::new();
    assert_eq!(map.mac_change_epoch_for(&key_v4(7, 42)), 0);
}

#[test]
fn mac_change_epoch_not_bumped_on_first_insert() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    // A brand-new neighbor: no cached flow can reference a MAC that did
    // not previously exist, so the shard epoch must stay put.
    assert!(map.insert_if_changed(k, entry(0xAB)));
    assert_eq!(map.mac_change_epoch_for(&k), 0);
}

#[test]
fn mac_change_epoch_not_bumped_on_same_mac_refresh() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    assert!(map.insert_if_changed(k, entry(0xAB)));
    // The common case: a periodic ARP/NDP refresh re-learning the SAME
    // MAC must not bump the shard epoch (else that shard's cached flows
    // flush on every neighbor refresh and the fast-path hit rate collapses).
    assert!(!map.insert_if_changed(k, entry(0xAB)));
    assert_eq!(map.mac_change_epoch_for(&k), 0);
}

#[test]
fn mac_change_epoch_bumped_on_mac_change() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    assert!(map.insert_if_changed(k, entry(0xAB)));
    assert_eq!(map.mac_change_epoch_for(&k), 0);
    // Genuine MAC change (gateway VRRP failover / NIC swap): this
    // neighbor's shard epoch MUST advance so the worker fast path evicts
    // cached descriptors holding the old dst_mac. Fail-on-revert guard for
    // insert_if_changed's bump_shard_epoch.
    assert!(map.insert_if_changed(k, entry(0xCD)));
    assert_eq!(map.mac_change_epoch_for(&k), 1);
    // A subsequent same-MAC refresh does not advance it further.
    assert!(!map.insert_if_changed(k, entry(0xCD)));
    assert_eq!(map.mac_change_epoch_for(&k), 1);
    // Another distinct change bumps again.
    assert!(map.insert_if_changed(k, entry(0xEF)));
    assert_eq!(map.mac_change_epoch_for(&k), 2);
}

#[test]
fn mac_change_epoch_isolated_per_shard_across_neighbors() {
    // #5147: the core targeted-invalidation guard. A MAC change on
    // neighbor A bumps ONLY A's shard epoch; an unrelated neighbor B in a
    // different shard is untouched. Under the old single global epoch this
    // test would go RED (B's read would advance too), which is exactly the
    // map-wide cache-thrash / DoS this fixes.
    let map = ShardedNeighborMap::new();
    let (a, b) = keys_in_distinct_shards();
    map.insert_if_changed(a, entry(0x11));
    map.insert_if_changed(b, entry(0x22));
    assert_eq!(map.mac_change_epoch_for(&a), 0);
    assert_eq!(map.mac_change_epoch_for(&b), 0);
    // Change A's MAC: A's shard advances, B's does not.
    map.insert_if_changed(a, entry(0x99));
    assert_eq!(map.mac_change_epoch_for(&a), 1);
    assert_eq!(
        map.mac_change_epoch_for(&b),
        0,
        "an unrelated neighbor's shard must not advance on A's MAC change (#5147)"
    );
    // Change B's MAC: B's shard advances, A's stays at its own value.
    map.insert_if_changed(b, entry(0x88));
    assert_eq!(map.mac_change_epoch_for(&b), 1);
    assert_eq!(map.mac_change_epoch_for(&a), 1);
}

#[test]
fn mac_change_epoch_confirmed_resolver_first_insert_no_bump() {
    use std::sync::atomic::AtomicU64;
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    let generation = AtomicU64::new(5);
    // Resolver servicing a missing next-hop: prior == None, no bump.
    assert!(map.insert_confirmed_if_unchanged(k, entry(0xAB), &generation, 5));
    assert_eq!(map.mac_change_epoch_for(&k), 0);
}

#[test]
fn mac_change_epoch_confirmed_resolver_bumps_on_change() {
    use std::sync::atomic::AtomicU64;
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    let generation = AtomicU64::new(5);
    assert!(map.insert_confirmed_if_unchanged(k, entry(0xAB), &generation, 5));
    assert_eq!(map.mac_change_epoch_for(&k), 0);
    // A confirmed re-resolution observing a different MAC must bump,
    // matching the monitor path. Fail-on-revert guard for the resolver.
    assert!(map.insert_confirmed_if_unchanged(k, entry(0xCD), &generation, 5));
    assert_eq!(map.mac_change_epoch_for(&k), 1);
    // Same MAC re-confirm does not bump.
    assert!(map.insert_confirmed_if_unchanged(k, entry(0xCD), &generation, 5));
    assert_eq!(map.mac_change_epoch_for(&k), 1);
}

#[test]
fn mac_change_epoch_bulk_replace_bumps_on_mac_change() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    // Seed an existing neighbor (e.g. the gateway) at MAC 0xAB.
    map.insert(k, entry(0xAB));
    assert_eq!(map.mac_change_epoch_for(&k), 0);
    // The Go control-plane snapshot push (apply_manager_neighbors with
    // NeighborReplace: true) removes the old key and re-inserts the same
    // key with a DIFFERENT MAC — the VRRP-failover gateway MAC change
    // that overflowed the in-process monitor. The bulk path snapshots
    // the prior MAC BEFORE the remove, detects the change, and bumps.
    // Fail-on-revert guard for bulk_replace_neighbors: neutralizing its
    // fetch_add makes this assertion go RED.
    let remove = [k];
    let insert = [(7, k.1, entry(0xCD))];
    map.bulk_replace_neighbors(&remove, &insert);
    assert_eq!(map.get(&k), Some(entry(0xCD)));
    assert_eq!(map.mac_change_epoch_for(&k), 1);
}

#[test]
fn mac_change_epoch_bulk_replace_no_bump_on_same_mac() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    map.insert(k, entry(0xAB));
    assert_eq!(map.mac_change_epoch_for(&k), 0);
    // A pure refresh: the snapshot re-learns the SAME MAC for every key.
    // Even though replace removes then re-inserts, the prior-MAC snapshot
    // (taken before the remove) equals the incoming MAC, so this shard's
    // epoch must NOT advance — otherwise steady-state Go snapshot pushes
    // would flush that shard's cached flows. This case must stay GREEN
    // when the bump is neutralized.
    let remove = [k];
    let insert = [(7, k.1, entry(0xAB))];
    map.bulk_replace_neighbors(&remove, &insert);
    assert_eq!(map.get(&k), Some(entry(0xAB)));
    assert_eq!(map.mac_change_epoch_for(&k), 0);
}

#[test]
fn mac_change_epoch_bulk_replace_no_bump_on_brand_new_keys() {
    let map = ShardedNeighborMap::new();
    // A snapshot that only ADDS neighbors with no prior entry: no cached
    // flow can hold a stale MAC for a neighbor that did not exist, so the
    // epoch stays put even though the set membership changed.
    let insert: Vec<_> = (0..5u8).map(|i| (7, key_v4(7, i).1, entry(0x22))).collect();
    map.bulk_replace_neighbors(&[], &insert);
    assert_eq!(map.len(), 5);
    for i in 0..5u8 {
        assert_eq!(map.mac_change_epoch_for(&key_v4(7, i)), 0);
    }
}

#[test]
fn mac_change_epoch_bulk_replace_bumps_each_changed_shard_once() {
    let map = ShardedNeighborMap::new();
    // #5147: two neighbors in DISTINCT shards both change MAC in one
    // snapshot push. Each changed neighbor bumps its OWN shard exactly once
    // — not a single shared global epoch — so an unrelated cached flow
    // (resolved to a third shard) survives.
    let (k1, k2) = keys_in_distinct_shards();
    map.insert(k1, entry(0x11));
    map.insert(k2, entry(0x22));
    let remove = [k1, k2];
    let insert = [(k1.0, k1.1, entry(0x99)), (k2.0, k2.1, entry(0x88))];
    map.bulk_replace_neighbors(&remove, &insert);
    assert_eq!(map.mac_change_epoch_for(&k1), 1);
    assert_eq!(map.mac_change_epoch_for(&k2), 1);
}

#[test]
fn mac_change_epoch_confirmed_resolver_epoch_reject_no_bump() {
    use std::sync::atomic::AtomicU64;
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    let generation = AtomicU64::new(5);
    map.insert_confirmed_if_unchanged(k, entry(0xAB), &generation, 5);
    // A monitor event advanced the generation between the resolver's GET
    // and its insert: the insert is rejected entirely, so no MAC is
    // written and the epoch must not move.
    generation.store(6, std::sync::atomic::Ordering::Release);
    assert!(!map.insert_confirmed_if_unchanged(k, entry(0xCD), &generation, 5));
    assert_eq!(map.mac_change_epoch_for(&k), 0);
    assert_eq!(map.get(&k), Some(entry(0xAB)));
}

// ── #3169: RX source-MAC data-path learn (learn_pair_if_changed) ─────
// The fifth neighbor-MAC write path. learn_dynamic_neighbor routes its
// #949 pair-write through learn_pair_if_changed, which must follow the
// same per-shard epoch semantics as the other four paths: a genuine MAC
// change on an existing dynamic neighbor bumps that neighbor's shard epoch
// (so a flow-cache dst_mac resolved via the dynamic_neighbors fallback is
// evicted), while a first sighting and a same-MAC re-learn do not.

#[test]
fn mac_change_epoch_rx_learn_no_bump_on_first_sighting() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    // A brand-new RX-learned neighbor: no cached flow can hold a stale
    // MAC for a neighbor that did not exist, so the epoch stays put.
    map.learn_pair_if_changed(&[k], entry(0xAB));
    assert_eq!(map.get(&k), Some(entry(0xAB)));
    assert_eq!(map.mac_change_epoch_for(&k), 0);
}

#[test]
fn mac_change_epoch_rx_learn_no_bump_on_same_mac_relearn() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    map.learn_pair_if_changed(&[k], entry(0xAB));
    // A re-learn of the SAME source MAC (the steady-state case) must not
    // bump, else every RX packet from a known source would flush the
    // flow cache. This case must stay GREEN when the bump is neutralized.
    map.learn_pair_if_changed(&[k], entry(0xAB));
    assert_eq!(map.mac_change_epoch_for(&k), 0);
}

#[test]
fn mac_change_epoch_rx_learn_bumps_on_mac_change() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    map.learn_pair_if_changed(&[k], entry(0xAB));
    assert_eq!(map.mac_change_epoch_for(&k), 0);
    // An RX-learned MAC change for an existing dynamic neighbor (the
    // pair_write_needed gate fires on `current != Some(src_mac)`, not
    // just first sighting). lookup_neighbor_entry falls back to this map
    // for unresolved fast-path next-hops, so the epoch MUST advance to
    // evict the stale cached dst_mac (#3169). Fail-on-revert guard for
    // learn_pair_if_changed: neutralizing its fetch_add makes this RED.
    map.learn_pair_if_changed(&[k], entry(0xCD));
    assert_eq!(map.get(&k), Some(entry(0xCD)));
    assert_eq!(map.mac_change_epoch_for(&k), 1);
    // A subsequent same-MAC re-learn does not advance it further.
    map.learn_pair_if_changed(&[k], entry(0xCD));
    assert_eq!(map.mac_change_epoch_for(&k), 1);
}

#[test]
fn mac_change_epoch_rx_learn_pair_bumps_each_key_shard() {
    let map = ShardedNeighborMap::new();
    // #5147: the #949 pair-write installs the same MAC under the physical
    // and the resolved logical (VLAN sub-) ifindex, which hash to
    // independent shards. Seed both, then change the MAC on both in one
    // learn: each key's own shard epoch must advance (a flow resolved via
    // either ifindex must be evicted), rather than one shared global epoch.
    let phys = key_v4(7, 42);
    let logical = key_v4(99, 42);
    map.learn_pair_if_changed(&[phys, logical], entry(0xAB));
    assert_eq!(map.mac_change_epoch_for(&phys), 0);
    assert_eq!(map.mac_change_epoch_for(&logical), 0);
    map.learn_pair_if_changed(&[phys, logical], entry(0xCD));
    assert_eq!(map.get(&phys), Some(entry(0xCD)));
    assert_eq!(map.get(&logical), Some(entry(0xCD)));
    // Each changed key bumps its own shard (>= 1 covers the case where the
    // two ifindexes happen to hash to the same shard).
    assert!(map.mac_change_epoch_for(&phys) >= 1);
    assert!(map.mac_change_epoch_for(&logical) >= 1);
}

// ---------------------------------------------------------------------------
// #5673 (codex-review M02): aggregate cap on dynamically learned neighbors.
//
// Source-address learning runs on RX (`stage_parse_flow_and_learn`, stage
// 7+8) BEFORE the screen/policy admission stages, so an attacker on an
// untrusted segment can stream packets carrying distinct spoofed L3 sources
// and — without passing any policy check — grow this shared map with one
// entry per fake source (unbounded memory) while every genuine first-sighting
// insert takes the 64-shard `with_all_shards` bulk lock (all-shard CPU DoS).
// The per-shard cap (`MAX_DYNAMIC_NEIGHBORS_PER_SHARD`) bounds the aggregate
// to `MAX_DYNAMIC_NEIGHBORS`; the uniform Knuth-mixed shard hash keeps a
// spoofed `/8`/`/24` flood spread ~evenly so the per-shard bound is the
// aggregate bound. These tests overflow ONE shard (many distinct spoofed
// sources hashing to it) — the cheap, exact way to exercise the cap gate.
// ---------------------------------------------------------------------------

/// `count` distinct, learnable unicast v4 keys that all hash to
/// `target_shard`. `10.0.0.0/8` is a unicast block that
/// `neighbor_ip_is_learnable` accepts, and filtering by `shard_index` lets a
/// test overflow a single shard cheaply instead of flooding all 64.
fn keys_in_shard(target_shard: usize, count: usize) -> Vec<(i32, IpAddr)> {
    let mut out = Vec::with_capacity(count);
    let mut i: u32 = 0;
    while out.len() < count {
        let k = (7, IpAddr::V4(Ipv4Addr::from(0x0A00_0000u32.wrapping_add(i))));
        if ShardedNeighborMap::shard_index(&k) == target_shard {
            out.push(k);
        }
        i = i
            .checked_add(1)
            .expect("exhausted the v4 space searching for shard keys");
    }
    out
}

/// #5673 fail-on-revert (transit-source arm). Flood the map through
/// `learn_pair_if_changed` — the arm the RX transit-source learn
/// (`learn_dynamic_neighbor`) uses — with more distinct spoofed sources than
/// one shard's cap allows. The shard (and thus the map, since every key hashes
/// here) must stay bounded at `MAX_DYNAMIC_NEIGHBORS_PER_SHARD`.
///
/// PARENT-RED: neutralize the cap gate in `learn_pair_if_changed` — the
/// `bulk.len_for(key) >= MAX_DYNAMIC_NEIGHBORS_PER_SHARD` comparison (make it
/// never true, e.g. `>= usize::MAX`, which still compiles). Then `blocked` is
/// always false, every distinct source is inserted, and
/// `map.len() <= MAX_DYNAMIC_NEIGHBORS_PER_SHARD` fails RED as a clean
/// assertion (the shard grows to the full flood). Target-count for that exact
/// comparison: 1.
#[test]
fn spoofed_source_flood_via_learn_pair_bounded_by_cap() {
    let map = ShardedNeighborMap::new();
    let over = MAX_DYNAMIC_NEIGHBORS_PER_SHARD + 64;
    let keys = keys_in_shard(0, over);
    for k in &keys {
        map.learn_pair_if_changed(&[*k], entry(0x11));
    }
    // All keys hash to shard 0, so the whole map lives there: len == shard len.
    assert!(
        map.len() <= MAX_DYNAMIC_NEIGHBORS_PER_SHARD,
        "spoofed-source flood grew the shard to {} entries, past the {}-per-shard \
         cap (the #5673 pre-policy neighbor-map DoS)",
        map.len(),
        MAX_DYNAMIC_NEIGHBORS_PER_SHARD,
    );
    // Non-vacuous: every distinct-key call either inserted (len) or was
    // refused (drop) — nothing is a same-MAC no-op — so the two partition the
    // flood exactly. Proves the cap actually fired on this run.
    assert!(
        map.learn_cap_drops() > 0,
        "cap refused nothing — the flood never reached the bound",
    );
    assert_eq!(
        map.learn_cap_drops() as usize + map.len(),
        over,
        "every spoofed learn must be exactly one of inserted-or-refused",
    );
}

/// #5673 fail-on-revert (ARP/NDP arm). The RX ARP-reply / NDP-NA data-path
/// learn (`stage_link_layer_classify`) inserts through `insert_if_changed`;
/// an attacker can flood distinct learnable source IPs there too, and both
/// arms share this map. The per-shard cap bounds that arm as well.
///
/// PARENT-RED: neutralize the cap gate in `insert_if_changed` — the
/// `shard.len() >= MAX_DYNAMIC_NEIGHBORS_PER_SHARD` comparison (make it never
/// true). Then every new key inserts and
/// `map.len() <= MAX_DYNAMIC_NEIGHBORS_PER_SHARD` fails RED. Target-count for
/// that exact comparison: 1.
#[test]
fn spoofed_source_flood_via_insert_if_changed_bounded_by_cap() {
    let map = ShardedNeighborMap::new();
    let over = MAX_DYNAMIC_NEIGHBORS_PER_SHARD + 64;
    let keys = keys_in_shard(0, over);
    for k in &keys {
        map.insert_if_changed(*k, entry(0x22));
    }
    assert!(
        map.len() <= MAX_DYNAMIC_NEIGHBORS_PER_SHARD,
        "ARP/NDP-arm flood grew the shard to {} entries, past the {}-per-shard cap",
        map.len(),
        MAX_DYNAMIC_NEIGHBORS_PER_SHARD,
    );
    assert!(
        map.learn_cap_drops() > 0,
        "cap refused nothing on the ARP/NDP arm",
    );
}

/// #5673 control: the cap is scoped to GROWTH, not a blanket block. A
/// legitimate source learned on a fresh map is admitted and resolvable, and —
/// critically — an UPDATE (a real MAC failover) to an already-learned
/// neighbor is NEVER refused even when its shard is completely full of spoofed
/// entries. Without this scoping the cap would regress legitimate learning and
/// silently drop a gateway MAC failover.
#[test]
fn learned_source_admitted_and_update_survives_full_shard() {
    let map = ShardedNeighborMap::new();
    let over = MAX_DYNAMIC_NEIGHBORS_PER_SHARD + 64;
    let keys = keys_in_shard(0, over);

    // The first key is a legitimate learn; it lands and is resolvable.
    let legit = keys[0];
    map.learn_pair_if_changed(&[legit], entry(0xAA));
    assert_eq!(map.get(&legit), Some(entry(0xAA)), "legit learn must be admitted");

    // Fill the rest of the shard with a spoofed flood until it caps.
    for k in &keys[1..] {
        map.learn_pair_if_changed(&[*k], entry(0x11));
    }
    assert!(
        map.len() <= MAX_DYNAMIC_NEIGHBORS_PER_SHARD,
        "shard must be bounded",
    );
    assert!(map.learn_cap_drops() > 0, "flood must have hit the cap");
    assert_eq!(
        map.get(&legit),
        Some(entry(0xAA)),
        "the legit neighbor learned first must survive the flood (never evicted)",
    );

    // Its gateway MAC now changes (VRRP failover). This is an UPDATE to an
    // existing key, not growth, so the full shard must NOT refuse it.
    let drops_before = map.learn_cap_drops();
    map.learn_pair_if_changed(&[legit], entry(0xBB));
    assert_eq!(
        map.get(&legit),
        Some(entry(0xBB)),
        "MAC failover on an already-learned neighbor must survive a full shard",
    );
    assert_eq!(
        map.learn_cap_drops(),
        drops_before,
        "an update to an existing neighbor must not count as a cap refusal",
    );
}

/// #5673: the per-shard cap only refuses a NEW key when the target shard is
/// actually at `MAX_DYNAMIC_NEIGHBORS_PER_SHARD` — a single learn on an empty
/// map is never refused, and `get_with_capacity` reports "room" for it. Guards
/// against an off-by-one that would make the cap reject from the first packet.
#[test]
fn get_with_capacity_reports_room_on_empty_shard() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 123);
    let (entry_before, at_cap) = map.get_with_capacity(&k);
    assert_eq!(entry_before, None, "key absent on a fresh map");
    assert!(!at_cap, "an empty shard must report room, not at-capacity");
    assert!(
        map.insert_if_changed(k, entry(0x33)),
        "a single learn on an empty map must be admitted, not cap-refused",
    );
    assert_eq!(map.learn_cap_drops(), 0, "no refusal for a below-cap learn");
}

/// #5673: `get_with_capacity` is the signal the RX-learn caller
/// (`learn_dynamic_neighbor`) uses to skip the 64-shard bulk lock for a
/// spoofed-source flood — it must report `(absent, at_cap=true)` for a NEW key
/// once its shard is full, and keep reporting an EXISTING key's entry so the
/// caller still treats a MAC update as an update (not growth). Fill the shard
/// with the plain `insert` (which does not enforce the cap) so this exercises
/// the reporting path, not the insert gate.
#[test]
fn get_with_capacity_reports_at_cap_on_full_shard() {
    let map = ShardedNeighborMap::new();
    let keys = keys_in_shard(0, MAX_DYNAMIC_NEIGHBORS_PER_SHARD + 1);
    for k in &keys[..MAX_DYNAMIC_NEIGHBORS_PER_SHARD] {
        map.insert(*k, entry(0x44));
    }
    // A NEW key in the now-full shard: (absent, at_cap) — the caller reads this
    // as "all-new-at-cap" and skips the bulk lock.
    let fresh = keys[MAX_DYNAMIC_NEIGHBORS_PER_SHARD];
    let (fresh_entry, fresh_at_cap) = map.get_with_capacity(&fresh);
    assert_eq!(fresh_entry, None, "the fresh key is not yet learned");
    assert!(fresh_at_cap, "a full shard must report at-capacity for a new key");
    // An EXISTING key in the same full shard still reports its entry, so the
    // caller does NOT treat it as all-new (an update is not growth).
    let (existing_entry, existing_at_cap) = map.get_with_capacity(&keys[0]);
    assert_eq!(existing_entry, Some(entry(0x44)), "existing key still readable at cap");
    assert!(existing_at_cap, "shard is full regardless of the probed key's presence");
}

/// #7752: fixed seeds for the distribution tests.
///
/// The shard hash is seeded per process, so running the distribution tests
/// against the LIVE seed would make them non-deterministic — and their bounds
/// are statistical (the /24 case accepts max <= 12 where a perfect uniform hash
/// gives 9-11 "with high probability"), so a random seed would eventually flake
/// on a legitimate outlier and be debugged as a hash regression.
///
/// Fixed seeds keep them deterministic AND strengthen them: uniformity is now
/// asserted across several seeds rather than the single mapping that happened
/// to be compiled in. A failure names the seed, so a red is reproducible from
/// the message alone.
const SHARD_SEEDS_7752: &[u64] = &[
    0,
    1,
    0x9E37_79B9_7F4A_7C15,
    0xDEAD_BEEF_CAFE_F00D,
    0xFFFF_FFFF_FFFF_FFFF,
    0x0123_4567_89AB_CDEF,
];

/// #7752: the seed must actually change the shard mapping.
///
/// This is the cell that fails if someone deletes the `write_u64(seed)` from
/// `shard_idx_with` — without it every seed produces an identical assignment
/// and the per-process seeding becomes decorative while every other test here
/// stays green. The distribution tests above cannot see that: a mapping can be
/// perfectly uniform and completely predictable, which is exactly the state
/// this issue was filed about.
///
/// Asserted over a key SET rather than one key, because two seeds can of course
/// agree on any single key (1 in 64). Two seeds agreeing on all 256 keys of a
/// /24 does not happen by chance.
#[test]
fn the_seed_changes_the_shard_mapping_7752() {
    let assignment = |seed: u64| -> Vec<usize> {
        (0..=255u8)
            .map(|last| shard_idx_with(seed, &key_v4(7, last)))
            .collect()
    };

    let base = assignment(SHARD_SEEDS_7752[0]);
    for &seed in &SHARD_SEEDS_7752[1..] {
        assert_ne!(
            base,
            assignment(seed),
            "seed {seed:#x} produced the SAME shard assignment as seed {:#x} \
             across all 256 keys of a /24 — the seed is not reaching the hash, \
             so an attacker can still precompute a shard-targeting address set \
             (#7752)",
            SHARD_SEEDS_7752[0]
        );
    }
}

/// #7752: the live per-process seed is wired into `shard_idx`, and the mapping
/// is stable within a process.
///
/// Stability is not incidental — `shard_idx` selects which mutex guards a key
/// and which `shard_mac_epochs` slot it reads. A key that moved shards mid-run
/// would take the wrong lock.
///
/// This cannot assert WHICH shard a key lands in (the seed is random by
/// design), so it asserts the two properties that survive that: same key ->
/// same shard, always; and the live path agrees with `shard_idx_with` fed the
/// live seed, which is what proves `shard_idx` did not quietly grow a second
/// implementation.
#[test]
fn the_process_seed_is_wired_and_stable_7752() {
    let k = key_v4(7, 42);
    let first = shard_idx(&k);
    for _ in 0..1000 {
        assert_eq!(shard_idx(&k), first, "shard_idx is not stable for one key");
    }
    assert_eq!(
        first,
        shard_idx_with(*SHARD_SEED, &k),
        "shard_idx disagrees with shard_idx_with(*SHARD_SEED, ..) — the live \
         path is no longer the seeded path (#7752)"
    );
    assert!(first < NUM_SHARDS, "shard index {first} out of range");
}

// #9071: the two BULK insert paths bumped only the shard epoch, never the
// insert generation, while the three per-key paths bumped both.
//
// The consumer is #7156's poll-loop gate: a full resolution pass runs only when
// `neigh_generation != binding.last_neigh_generation`. So a neighbour learned
// through the netlink bulk sync or the #1787 RX source-MAC transit learn never
// woke that pass, and the buffered packet for that hop waited for the
// RESOLUTION_RECHECK_INTERVAL_NS backstop instead.
//
// The epoch and the generation answer DIFFERENT questions and neither
// substitutes for the other: the epoch invalidates cached flows resolved to one
// shard, the generation tells the poll loop a resolution pass is worth running
// at all. This case asserts BOTH move, so a later "the epoch already covers it"
// simplification reds.
#[test]
fn bulk_paths_bump_the_insert_generation_9071() {
    let m = ShardedNeighborMap::new();

    // POSITIVE CONTROL first: a per-key path bumps. If it does not, the
    // assertions below are measuring a counter nothing moves.
    let before = m.insert_generation();
    m.insert_if_changed(key_v4(3, 1), entry(0x11));
    assert!(
        m.insert_generation() > before,
        "the per-key path must bump the insert generation; without that control \
         every assertion below is about a dead counter"
    );

    // bulk_replace_neighbors — the netlink sync path.
    let before = m.insert_generation();
    m.bulk_replace_neighbors(&[], &[(3, key_v4(3, 2).1, entry(0x22))]);
    assert!(
        m.insert_generation() > before,
        "bulk_replace_neighbors did not bump the insert generation, so #7156's \
         poll-loop gate never fires for a neighbour learned by the netlink sync \
         and its buffered packet waits for the recheck backstop"
    );

    // learn_pair_if_changed — the #1787 RX source-MAC transit learn.
    let before = m.insert_generation();
    m.learn_pair_if_changed(&[key_v4(3, 3)], entry(0x33));
    assert!(
        m.insert_generation() > before,
        "learn_pair_if_changed did not bump the insert generation"
    );
}

// NARROWNESS: a bulk call that installs NOTHING must not bump either. A
// generation that advances on every call is the same as one that never
// advances — the gate fires every sweep and #7156's optimisation is gone.
#[test]
fn empty_bulk_calls_do_not_bump_the_generation_9071() {
    let m = ShardedNeighborMap::new();

    // Establish the counter moves at all, so a flat reading below is a
    // property of the empty call rather than of the fixture.
    let start = m.insert_generation();
    m.bulk_replace_neighbors(&[], &[(3, key_v4(3, 9).1, entry(0x99))]);
    assert!(m.insert_generation() > start, "fixture: a real bulk insert must bump");

    let before = m.insert_generation();
    m.bulk_replace_neighbors(&[], &[]);
    m.learn_pair_if_changed(&[], entry(0x44));
    assert_eq!(
        m.insert_generation(),
        before,
        "an empty bulk call bumped the generation; a counter that advances on \
         every call makes the poll-loop gate fire every sweep, which is the \
         optimisation #7156 added removed"
    );
}

// ---------------------------------------------------------------------------
// #9893 — atomic Override=0 CAS for NDP-NA learns.
//
// The sequential cells below drive `insert_ndp_na_if_override_allows`
// directly and pin the map contract (refusal vs insert, side-effect
// discipline); the barrier-synchronized concurrency cells after them pin
// atomicity itself (a sequential test cannot observe the TOCTOU window).
// The stage cell in poll_stages_tests pins sequential end-to-end
// preservation through the CAS path (pre-seed, classify, assert kept).
// ---------------------------------------------------------------------------

#[test]
fn ndp_cas_override0_refuses_live_differing_mac_9893() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    map.insert(k, entry(0xAB));
    let gen_before = map.insert_generation();
    let drops_before = map.learn_cap_drops();
    let epoch_before = map.mac_change_epoch_for(&k);
    assert_eq!(
        map.insert_ndp_na_if_override_allows(k, entry(0xCD), false),
        None,
        "Override=0 must refuse a live differing LLA"
    );
    assert_eq!(
        map.get(&k),
        Some(entry(0xAB)),
        "the refusal must leave the live entry untouched"
    );
    assert_eq!(
        map.insert_generation(),
        gen_before,
        "a CAS refusal must not bump the insert generation"
    );
    assert_eq!(
        map.learn_cap_drops(),
        drops_before,
        "a CAS refusal must not count as a cap drop"
    );
    assert_eq!(
        map.mac_change_epoch_for(&k),
        epoch_before,
        "a CAS refusal must not bump the shard MAC-change epoch (no cached \
         flow holds a stale MAC for an entry that did not change)"
    );
}

#[test]
fn ndp_cas_override1_overwrites_live_differing_mac_9893() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    map.insert(k, entry(0xAB));
    assert_eq!(
        map.insert_ndp_na_if_override_allows(k, entry(0xCD), true),
        Some(true),
        "Override=1 (legit §7.2.6 LLA change) must overwrite"
    );
    assert_eq!(map.get(&k), Some(entry(0xCD)));
}

#[test]
fn ndp_cas_override0_first_insert_and_same_mac_refresh_9893() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    // First-time Override=0 learn creates.
    assert_eq!(
        map.insert_ndp_na_if_override_allows(k, entry(0xAB), false),
        Some(true),
        "first-time Override=0 learn must create the entry"
    );
    assert_eq!(map.get(&k), Some(entry(0xAB)));
    // Same-MAC Override=0 refresh is a no-change Some(false), not a refusal.
    assert_eq!(
        map.insert_ndp_na_if_override_allows(k, entry(0xAB), false),
        Some(false),
        "same-MAC Override=0 refresh must succeed as no-change"
    );
}

#[test]
fn ndp_cas_override1_same_mac_is_no_change_9893() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    map.insert(k, entry(0xAB));
    assert_eq!(
        map.insert_ndp_na_if_override_allows(k, entry(0xAB), true),
        Some(false),
        "same-MAC Override=1 must be no-change, matching insert_if_changed"
    );
}

#[test]
fn insert_if_changed_still_overwrites_unconditionally_9893() {
    // The generic RX-learn leg still delegates with override=true: a differing
    // MAC always overwrites, preserving the pre-#9893 behavior outside ARP.
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    map.insert(k, entry(0xAB));
    assert!(
        map.insert_if_changed(k, entry(0xCD)),
        "insert_if_changed must still overwrite a differing MAC"
    );
    assert_eq!(map.get(&k), Some(entry(0xCD)));
}

#[test]
fn arp_solicited_probe_evidence_is_one_shot_and_expires_10704() {
    let map = ShardedNeighborMap::new();
    let key = key_v4(7, 42);
    let probe_at = 1_000_000;

    map.record_neighbor_probe(key, probe_at);
    assert!(
        map.take_arp_reply_solicited(&key, probe_at + ARP_SOLICITED_WINDOW_NS),
        "a reply at the solicited-window boundary is accepted"
    );
    assert!(
        !map.take_arp_reply_solicited(&key, probe_at + ARP_SOLICITED_WINDOW_NS),
        "one probe authorizes exactly one reply"
    );

    map.record_neighbor_probe(key, probe_at);
    assert!(
        !map.take_arp_reply_solicited(&key, probe_at + ARP_SOLICITED_WINDOW_NS + 1),
        "expired solicitation evidence must not authorize an overwrite"
    );
}

#[test]
fn arp_reply_cas_requires_solicitation_for_mac_override_10704() {
    let map = ShardedNeighborMap::new();
    let key = key_v4(7, 42);
    map.insert(key, entry(0xAB));
    let gen_before = map.insert_generation();
    let epoch_before = map.mac_change_epoch_for(&key);

    assert_eq!(
        map.insert_arp_reply_if_solicited_allows(key, entry(0xCD), false),
        None,
        "an unsolicited ARP reply must not override a live differing MAC"
    );
    assert_eq!(map.get(&key), Some(entry(0xAB)));
    assert_eq!(map.insert_generation(), gen_before);
    assert_eq!(map.mac_change_epoch_for(&key), epoch_before);
    assert_eq!(
        map.insert_arp_reply_if_solicited_allows(key, entry(0xCD), true),
        Some(true),
        "a solicited ARP reply must be able to converge a real MAC change"
    );
    assert_eq!(map.get(&key), Some(entry(0xCD)));
    assert_ne!(map.mac_change_epoch_for(&key), epoch_before);
}

// ---------------------------------------------------------------------------
// #9893 concurrency: the TOCTOU window the CAS closes, pinned three ways.
//
// A sequential test can never observe the window — `get` then
// `insert_if_changed` back-to-back behaves exactly like the CAS when no
// peer mutates between them. These cells force (hazard pin) or hammer
// (invariant pins) the interleave a sequential test cannot produce.
// ---------------------------------------------------------------------------

#[test]
fn ndp_separated_check_then_write_loses_update_9893() {
    use std::sync::Barrier;
    // HAZARD PIN (not the contract): replicates the pre-#9893 call-site
    // pattern — `get` (check) then `insert_if_changed` (write) across two
    // locks, using the same public primitives — with barriers forcing a
    // peer insert into the window. The racer checked empty, the peer
    // landed, the racer's deferred write clobbered it. This asserts the
    // buggy outcome to document what the window costs; production must
    // never do this — the CAS invariant cells below assert the peer always
    // wins under the same shape.
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 99);
    let cas_mac = entry(0xCA);
    let peer_mac = entry(0xBE);
    // Barriers live outside the scope so they outlive the spawned threads.
    let checked = Barrier::new(2);
    let peer_in = Barrier::new(2);
    std::thread::scope(|s| {
        s.spawn(|| {
            // Old-pattern check leg (Override=0): proceed unless a live
            // differing MAC already exists. Observes empty here.
            let blocked = map.get(&k).is_some_and(|e| e.mac != cas_mac.mac);
            checked.wait(); // open the window: peer inserts now
            peer_in.wait(); // peer done; racer writes (too late)
            if !blocked {
                map.insert_if_changed(k, cas_mac);
            }
        });
        checked.wait();
        map.insert(k, peer_mac); // legitimate peer learn lands in the window
        peer_in.wait();
    });
    assert_eq!(
        map.get(&k),
        Some(cas_mac),
        "hazard pin: separated check-then-write clobbers the peer insert \
         that landed in the window (the pre-#9893 lost update)"
    );
}

#[test]
fn ndp_cas_concurrent_peer_insert_never_lost_9893() {
    use std::sync::Barrier;
    // CAS INVARIANT under concurrency: an Override=0 CAS racing an
    // unconditional peer insert on an empty key can never clobber the peer.
    // Either order is correct — CAS-first means the peer overwrites it,
    // peer-first means the CAS observes the peer under its write lock and
    // refuses — so the final entry is ALWAYS the peer MAC. This holds
    // deterministically for the single-lock CAS every iteration; a separated
    // check-then-write fails it whenever the peer lands in the window (the
    // hazard cell above forces that interleave deterministically; this
    // hammer makes it overwhelmingly likely within the iteration budget).
    const ITERS: i32 = 300;
    let map = ShardedNeighborMap::new();
    let cas_mac = entry(0xCA);
    let peer_mac = entry(0xBE);
    let start = Barrier::new(2);
    let settled = Barrier::new(2);
    std::thread::scope(|s| {
        s.spawn(|| {
            for i in 0..ITERS {
                let k = key_v4(2000 + i, 42);
                start.wait();
                let _ = map.insert_ndp_na_if_override_allows(k, cas_mac, false);
                settled.wait();
            }
        });
        for i in 0..ITERS {
            let k = key_v4(2000 + i, 42);
            start.wait();
            map.insert(k, peer_mac);
            settled.wait();
        }
    });
    for i in 0..ITERS {
        let k = key_v4(2000 + i, 42);
        assert_eq!(
            map.get(&k),
            Some(peer_mac),
            "iter {i}: a concurrent Override=0 CAS must never clobber the \
             peer insert (atomic CAS always loses correctly to unconditional)"
        );
    }
}

#[test]
fn ndp_cas_empty_race_exactly_one_winner_9893() {
    use std::sync::{Barrier, Mutex};
    // CAS INVARIANT for the creation race: N Override=0 racers with distinct
    // MACs on an empty key — exactly one observes empty and inserts
    // (`Some(true)`); every other observes the winner under its write lock
    // and refuses (`None`, never `Some(false)` — no racer ever sees its own
    // MAC present). Deterministic for the single-lock CAS; a separated
    // check-then-write lets every racer that checked before the first write
    // insert, yielding multiple winners.
    const THREADS: usize = 8;
    const ITERS: i32 = 50;
    let map = ShardedNeighborMap::new();
    let results = Mutex::new(vec![vec![None; THREADS]; ITERS as usize]);
    let start = Barrier::new(THREADS);
    let settled = Barrier::new(THREADS);
    std::thread::scope(|s| {
        for tid in 0..THREADS {
            let map = &map;
            let results = &results;
            let start = &start;
            let settled = &settled;
            s.spawn(move || {
                let my_mac = entry(0xA0 + tid as u8);
                for i in 0..ITERS {
                    let k = key_v4(3000 + i, 77);
                    start.wait();
                    let r = map.insert_ndp_na_if_override_allows(k, my_mac, false);
                    results.lock().unwrap()[i as usize][tid] = r;
                    settled.wait();
                }
            });
        }
    });
    let results = results.lock().unwrap();
    for i in 0..ITERS {
        let k = key_v4(3000 + i, 77);
        let winners: Vec<usize> = (0..THREADS)
            .filter(|tid| results[i as usize][*tid] == Some(true))
            .collect();
        assert_eq!(
            winners.len(),
            1,
            "iter {i}: exactly one racer must win the empty-key race, got {}",
            winners.len()
        );
        for tid in 0..THREADS {
            if tid != winners[0] {
                assert_eq!(
                    results[i as usize][tid], None,
                    "iter {i} tid {tid}: losers must refuse (None), never no-change"
                );
            }
        }
        assert_eq!(
            map.get(&k),
            Some(entry(0xA0 + winners[0] as u8)),
            "iter {i}: the final entry must be the single winner's MAC"
        );
    }
}
