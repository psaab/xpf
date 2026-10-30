// #18533 round 2: every admitted flow-cache hit runs the post-admission
// source-neighbor learn. A fresh duplicate of the last learn under the same
// published forwarding snapshot now returns before the on-link scan, the
// owned-IP probes and the VLAN-alias resolve; everything that can change the
// learn's outcome — a neighbor MAC replacement or removal (epoch), a new
// forwarding snapshot, the coalescing interval, a different source MAC —
// still takes the full path.
//
// Split out as a sibling `#[path]` test module loaded from afxdp/mod.rs.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;

const LEARN_IFINDEX: i32 = 24;
const MAC_A: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const MAC_B: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];

fn learn_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100))
}

fn full_learns() -> u64 {
    super::neighbor_dispatch::POST_ADMISSION_FULL_LEARNS_FOR_TEST.with(|count| count.get())
}

fn admitted(
    state: &ForwardingState,
    neighbors: &Arc<ShardedNeighborMap>,
    dedup: &mut LearnedNeighborDedup,
    mac: [u8; 6],
    now_ns: u64,
) {
    let meta = UserspaceDpMeta {
        ingress_ifindex: LEARN_IFINDEX as u32,
        ..UserspaceDpMeta::default()
    };
    super::neighbor_dispatch::learn_dynamic_neighbor_after_admission(
        meta,
        learn_ip(),
        mac,
        now_ns,
        dedup,
        state,
        neighbors,
    );
}

fn published_state(epoch: u64) -> ForwardingState {
    let mut state = build_forwarding_state(&nat_snapshot());
    state.publish_epoch = epoch;
    state
}

fn mac_of(neighbors: &ShardedNeighborMap) -> Option<[u8; 6]> {
    neighbors.get(&(LEARN_IFINDEX, learn_ip())).map(|entry| entry.mac)
}

/// The steady state: after one learn, admitted duplicates under the same
/// published snapshot return before the full path.
#[test]
fn fresh_duplicate_skips_the_full_learn_18533() {
    let state = published_state(3);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let mut dedup = LearnedNeighborDedup::default();
    let start = full_learns();
    admitted(&state, &neighbors, &mut dedup, MAC_A, 100);
    assert_eq!(full_learns() - start, 1, "the first packet learns");
    assert_eq!(mac_of(&neighbors), Some(MAC_A), "premise: the admitted source was learned");
    assert_eq!(dedup.forwarding_epoch, 3, "the stored state names its snapshot");
    admitted(&state, &neighbors, &mut dedup, MAC_A, 200);
    admitted(&state, &neighbors, &mut dedup, MAC_A, 300);
    assert_eq!(full_learns() - start, 1, "fresh duplicates skip the full path");
}

/// A removal bumps the neighbor epoch: the next admitted packet takes the
/// full path and re-learns the neighbor at once.
#[test]
fn neighbor_removal_relearns_on_the_next_packet_18533() {
    let state = published_state(3);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let mut dedup = LearnedNeighborDedup::default();
    admitted(&state, &neighbors, &mut dedup, MAC_A, 100);
    neighbors.remove(&(LEARN_IFINDEX, learn_ip()));
    assert_eq!(mac_of(&neighbors), None, "premise: removed");
    let start = full_learns();
    admitted(&state, &neighbors, &mut dedup, MAC_A, 200);
    assert_eq!(full_learns() - start, 1, "an epoch change takes the full path");
    assert_eq!(mac_of(&neighbors), Some(MAC_A), "the removed neighbor is re-learned");
}

/// A different source MAC is a different key: the full path runs and, as
/// before, refuses to replace the live binding (#10854); the stored state
/// stays on the original MAC, which is still fresh.
#[test]
fn new_source_mac_takes_the_full_path_18533() {
    let state = published_state(3);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let mut dedup = LearnedNeighborDedup::default();
    admitted(&state, &neighbors, &mut dedup, MAC_A, 100);
    let start = full_learns();
    admitted(&state, &neighbors, &mut dedup, MAC_B, 200);
    assert_eq!(full_learns() - start, 1, "a new source MAC takes the full path");
    assert_eq!(mac_of(&neighbors), Some(MAC_A), "a transit packet still cannot replace the binding");
    admitted(&state, &neighbors, &mut dedup, MAC_A, 300);
    assert_eq!(full_learns() - start, 1, "the refused change left the fresh state");
}

/// A new published snapshot invalidates the stored derivations: the next
/// packet takes the full path, which re-confirms them and re-names the
/// state, so the one after is fresh again.
#[test]
fn new_snapshot_takes_the_full_path_then_is_fresh_18533() {
    let mut state = published_state(3);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let mut dedup = LearnedNeighborDedup::default();
    admitted(&state, &neighbors, &mut dedup, MAC_A, 100);
    state.publish_epoch = 4;
    let start = full_learns();
    admitted(&state, &neighbors, &mut dedup, MAC_A, 200);
    assert_eq!(full_learns() - start, 1, "a new snapshot takes the full path");
    assert_eq!(dedup.forwarding_epoch, 4, "the re-confirmed state names the new snapshot");
    admitted(&state, &neighbors, &mut dedup, MAC_A, 300);
    assert_eq!(full_learns() - start, 1, "and is fresh again under it");
}

/// The coalescing interval still bounds the shortcut.
#[test]
fn expired_interval_takes_the_full_path_18533() {
    let refresh_ns = super::sharded_neighbor::RX_LEARNED_NEIGHBOR_REFRESH_INTERVAL_NS;
    let state = published_state(3);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let mut dedup = LearnedNeighborDedup::default();
    admitted(&state, &neighbors, &mut dedup, MAC_A, 100);
    let start = full_learns();
    let expired = dedup.last_refresh_ns + refresh_ns;
    admitted(&state, &neighbors, &mut dedup, MAC_A, expired);
    assert_eq!(full_learns() - start, 1, "an expired interval takes the full path");
}

/// An unpublished snapshot (fixtures, mutated in place) never shortcuts.
#[test]
fn unpublished_snapshot_never_shortcuts_18533() {
    let state = published_state(0);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let mut dedup = LearnedNeighborDedup::default();
    let start = full_learns();
    admitted(&state, &neighbors, &mut dedup, MAC_A, 100);
    admitted(&state, &neighbors, &mut dedup, MAC_A, 200);
    admitted(&state, &neighbors, &mut dedup, MAC_A, 300);
    assert_eq!(full_learns() - start, 3, "epoch 0 is never trusted");
}
