// Tests for afxdp/flow_cache.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep flow_cache.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "flow_cache_tests.rs"]` from flow_cache.rs.

use super::*;
use crate::test_zone_ids::*;
use crate::{FirewallFilterSnapshot, FirewallTermSnapshot, InterfaceSnapshot};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicU32;

use crate::ip_proto::{PROTO_TCP, PROTO_UDP};

fn make_key() -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 50, 200)),
        src_port: 45678,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    }
}

fn make_descriptor() -> RewriteDescriptor {
    RewriteDescriptor {
        dst_mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
        fabric_redirect: false,
        tx_vlan_id: 0,
        ether_type: 0x0800,
        rewrite_src_ip: None,
        rewrite_dst_ip: None,
        rewrite_src_port: None,
        rewrite_dst_port: None,
        ip_csum_delta: 0,
        l4_csum_delta: 0,
        egress_ifindex: 6,
        tx_ifindex: 6,
        target_binding_index: None,
        input_filter_log: None,
        input_filter_counters: crate::filter::CachedFilterCounters::default(),
        tx_selection: CachedTxSelectionDescriptor::default(),
        nat64: false,
        nptv6: false,
        apply_nat_on_fabric: false,
    }
}

fn make_resolution(disposition: ForwardingDisposition) -> ForwardingResolution {
    ForwardingResolution {
        disposition,
        local_ifindex: 0,
        egress_ifindex: 6,
        tx_ifindex: 6,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
        neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x01, 0x01]),
        tx_vlan_id: 0,
    }
}

fn make_decision(disposition: ForwardingDisposition) -> SessionDecision {
    SessionDecision {
        resolution: make_resolution(disposition),
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn make_metadata(owner_rg_id: i32) -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_TRUST_ZONE_ID,
        egress_zone: TEST_UNTRUST_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    }
}

fn make_meta(protocol: u8) -> UserspaceDpMeta {
    UserspaceDpMeta {
        protocol,
        addr_family: libc::AF_INET as u8,
        ingress_ifindex: 7,
        tcp_flags: 0x10, // ACK only
        ..Default::default()
    }
}

fn make_entry(
    key: crate::session::SessionKey,
    stamp: FlowCacheStamp,
    owner_rg_id: i32,
) -> FlowCacheEntry {
    FlowCacheEntry {
        key,
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        descriptor: make_descriptor(),
        decision: make_decision(ForwardingDisposition::ForwardCandidate),
        metadata: make_metadata(owner_rg_id),
        stamp,
        observed_bytes: 0,
        last_used_epoch: 0,
        neighbor_mac_epoch: 0,
        // #5147: default to no dynamic-neighbor dependency; tests that
        // exercise MAC-change eviction set `neighbor_shard` explicitly.
        neighbor_shard: NEIGHBOR_SHARD_NONE,
    }
}

fn default_rg_epochs() -> [AtomicU32; MAX_RG_EPOCHS] {
    std::array::from_fn(|_| AtomicU32::new(0))
}

// ----------------------------------------------------------------
// (a) Cache hit — same binding, matching stamp
// ----------------------------------------------------------------
#[test]
fn cache_hit_with_matching_stamp() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let key = make_key();
    let stamp = FlowCacheStamp {
        config_generation: 5,
        fib_generation: 3,
        owner_rg_id: 1,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    cache.insert(make_entry(key.clone(), stamp, 1));

    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 5,
        fib_generation: 3,
    };
    let hit = cache.lookup(&key, lookup, 0, &rg_epochs);
    assert!(hit.is_some(), "expected cache hit with matching stamp");
    assert_eq!(cache.hits, 1);
    assert_eq!(cache.misses, 0);
}

// #5139 FAIL-ON-REVERT: two VLAN units co-parented on ONE physical interface
// (same physical ingress ifindex) with the SAME 5-tuple have DISTINCT logical
// (VLAN-selecting) ingress ifindexes. A flow-cache entry stamped by VLAN A must
// NOT be replayed for VLAN B — the logical ifindex selects the security
// zone-pair, so aliasing them fail-OPENs cross-zone policy/NAT. VLAN B must MISS
// and fall to the slow-path zone-pair policy. Reverting the lookup identity to
// the physical parent (dropping the `logical_ingress_ifindex` discriminator)
// makes VLAN B HIT VLAN A's entry → the `is_none()` assertion below goes RED.
#[test]
fn coparented_vlan_same_5tuple_distinct_logical_ifindex_misses_5139() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let key = make_key();
    let stamp = FlowCacheStamp {
        config_generation: 5,
        fib_generation: 3,
        owner_rg_id: 1,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    const PHYS_PARENT: i32 = 7; // one physical interface (the aliasing parent)
    const VLAN_A_LOGICAL: i32 = 100; // e.g. reth0.50 logical unit
    const VLAN_B_LOGICAL: i32 = 101; // e.g. reth0.80 logical unit — SAME parent

    // VLAN A caches its decision: physical parent 7, logical unit 100.
    let mut entry_a = make_entry(key.clone(), stamp, 1);
    entry_a.ingress_ifindex = PHYS_PARENT;
    entry_a.logical_ingress_ifindex = VLAN_A_LOGICAL;
    cache.insert(entry_a);

    // VLAN B: SAME physical parent, SAME 5-tuple, DIFFERENT logical unit.
    let vlan_b_lookup = FlowCacheLookup {
        ingress_ifindex: PHYS_PARENT,
        logical_ingress_ifindex: VLAN_B_LOGICAL,
        config_generation: 5,
        fib_generation: 3,
    };
    assert!(
        cache.lookup(&key, vlan_b_lookup, 0, &rg_epochs).is_none(),
        "co-parented VLAN B (logical {VLAN_B_LOGICAL}) must MISS VLAN A's entry \
         (logical {VLAN_A_LOGICAL}) — else cross-zone policy/NAT replay (#5139)"
    );

    // Control: VLAN A's OWN lookup (same logical) still HITS — the cache works
    // per-VLAN; only the co-parented sibling is isolated. This proves the miss
    // above is the logical discriminator, not a set/stamp coincidence.
    let vlan_a_lookup = FlowCacheLookup {
        ingress_ifindex: PHYS_PARENT,
        logical_ingress_ifindex: VLAN_A_LOGICAL,
        config_generation: 5,
        fib_generation: 3,
    };
    assert!(
        cache.lookup(&key, vlan_a_lookup, 0, &rg_epochs).is_some(),
        "VLAN A's own flow must still hit its cached entry"
    );
}

#[test]
fn cache_hit_accumulates_observed_bytes() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let key = make_key();
    let stamp = FlowCacheStamp {
        config_generation: 5,
        fib_generation: 3,
        owner_rg_id: 0,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    cache.insert(make_entry(key.clone(), stamp, 0));

    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 5,
        fib_generation: 3,
    };
    assert!(
        cache
            .lookup_counted(&key, lookup, 0, &rg_epochs, 1500)
            .is_some()
    );
    assert!(
        cache
            .lookup_counted(&key, lookup, 0, &rg_epochs, 900)
            .is_some()
    );

    let (_active_count, rows, _cos_counts, _truncated) = cache.active_flow_debug_entries(8);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].observed_bytes, 2400);
}

// ----------------------------------------------------------------
// (b) Stale config generation → miss
// ----------------------------------------------------------------
#[test]
fn stale_config_generation_causes_miss() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let key = make_key();
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: 0,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    cache.insert(make_entry(key.clone(), stamp, 0));

    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 2, // newer than entry's 1
        fib_generation: 1,
    };
    let hit = cache.lookup(&key, lookup, 0, &rg_epochs);
    assert!(hit.is_none(), "expected miss on stale config_generation");
    assert_eq!(cache.misses, 1);
}

// ----------------------------------------------------------------
// (c) Stale FIB generation → miss
// ----------------------------------------------------------------
#[test]
fn stale_fib_generation_causes_miss() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let key = make_key();
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 5,
        owner_rg_id: 0,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    cache.insert(make_entry(key.clone(), stamp, 0));

    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 1,
        fib_generation: 6, // newer than entry's 5
    };
    let hit = cache.lookup(&key, lookup, 0, &rg_epochs);
    assert!(hit.is_none(), "expected miss on stale fib_generation");
    assert_eq!(cache.misses, 1);
}

// ----------------------------------------------------------------
// (d) Stale RG epoch → miss
// ----------------------------------------------------------------
#[test]
fn stale_rg_epoch_causes_miss() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let key = make_key();
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: 1,
        owner_rg_epoch: 3,
        owner_rg_lease_until: 0,
    };
    // Set current epoch to match so the insert is "valid" at that moment.
    rg_epochs[1].store(3, Ordering::Relaxed);
    cache.insert(make_entry(key.clone(), stamp, 1));

    // Bump RG 1 epoch to 4 — simulates failover/demotion.
    rg_epochs[1].store(4, Ordering::Relaxed);

    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 1,
        fib_generation: 1,
    };
    let hit = cache.lookup(&key, lookup, 0, &rg_epochs);
    assert!(hit.is_none(), "expected miss on stale RG epoch");
    assert_eq!(cache.misses, 1);
    // Stale RG epoch also triggers eviction of the entry.
    assert_eq!(cache.evictions, 1);
}

// ----------------------------------------------------------------
// (e) Unrelated RG epoch bump does not cause miss
// ----------------------------------------------------------------
#[test]
fn unrelated_rg_epoch_bump_still_hits() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let key = make_key();
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: 1,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    cache.insert(make_entry(key.clone(), stamp, 1));

    // Bump RG 2 — unrelated to the entry's owner RG 1.
    rg_epochs[2].store(99, Ordering::Relaxed);

    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 1,
        fib_generation: 1,
    };
    let hit = cache.lookup(&key, lookup, 0, &rg_epochs);
    assert!(hit.is_some(), "expected hit — only unrelated RG was bumped");
    assert_eq!(cache.hits, 1);
    assert_eq!(cache.misses, 0);
}

// ----------------------------------------------------------------
// (#2466) Out-of-range owner RG (>= MAX_RG_EPOCHS) is stamped against
// the node-level rg_epochs[0] edge and invalidates immediately on a
// node-level epoch bump — instead of stamping a literal epoch 0 that no
// per-RG bump ever moves (the pre-#2466 delayed-invalidation gap).
//
// FAIL-ON-REVERT: with the old `owner < MAX_RG_EPOCHS` capture guard the
// stamp would record epoch 0 and the lookup guard would skip the epoch
// re-check for the out-of-range owner, so the cached decision would
// survive the bump (hit, not miss) and these asserts would fail.
// ----------------------------------------------------------------
#[test]
fn out_of_range_owner_rg_stamps_node_level_epoch() {
    let rg_epochs = default_rg_epochs();
    // Node-level edge starts at 5.
    rg_epochs[0].store(5, Ordering::Relaxed);
    // High slot (if it existed) is some other value — must be ignored.
    let stamp = FlowCacheStamp::capture(
        1,
        1,
        16, // RG 16 — out of the fixed 16-entry table (0..15)
        &BTreeMap::new(),
        &rg_epochs,
    );
    assert_eq!(
        stamp.owner_rg_epoch, 5,
        "out-of-range owner RG must capture the node-level rg_epochs[0] edge"
    );
}

#[test]
fn out_of_range_owner_rg_invalidates_on_node_level_bump() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let key = make_key();
    // Stamp captured against node-level rg_epochs[0] == 3 for RG 16.
    rg_epochs[0].store(3, Ordering::Relaxed);
    let stamp = FlowCacheStamp::capture(1, 1, 16, &BTreeMap::new(), &rg_epochs);
    assert_eq!(stamp.owner_rg_id, 16);
    assert_eq!(stamp.owner_rg_epoch, 3);
    cache.insert(make_entry(key.clone(), stamp, 16));

    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 1,
        fib_generation: 1,
    };
    // Fresh: still matches the node-level edge -> hit.
    assert!(
        cache.lookup(&key, lookup, 0, &rg_epochs).is_some(),
        "expected hit before any node-level epoch bump"
    );

    // Node-level transition (any RG activation/demotion bumps rg_epochs[0]).
    rg_epochs[0].store(4, Ordering::Relaxed);
    let hit = cache.lookup(&key, lookup, 0, &rg_epochs);
    assert!(
        hit.is_none(),
        "expected immediate miss: out-of-range owner RG must invalidate on the node-level epoch bump"
    );
    assert_eq!(cache.evictions, 1);
}

// No-regression: an in-range RG (e.g. RG 2) still invalidates on its OWN
// per-RG bump exactly as before, and is NOT invalidated by an unrelated
// node-level rg_epochs[0] bump.
#[test]
fn in_range_owner_rg_unchanged_by_node_level_bump() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let key = make_key();
    rg_epochs[2].store(7, Ordering::Relaxed);
    let stamp = FlowCacheStamp::capture(1, 1, 2, &BTreeMap::new(), &rg_epochs);
    assert_eq!(
        stamp.owner_rg_epoch, 7,
        "in-range owner RG must capture its own per-RG epoch slot"
    );
    cache.insert(make_entry(key.clone(), stamp, 2));

    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 1,
        fib_generation: 1,
    };
    // A node-level (rg_epochs[0]) bump must NOT touch an in-range owner.
    rg_epochs[0].store(99, Ordering::Relaxed);
    assert!(
        cache.lookup(&key, lookup, 0, &rg_epochs).is_some(),
        "in-range owner RG must ignore an unrelated node-level epoch bump"
    );

    // Its own per-RG bump still evicts.
    rg_epochs[2].store(8, Ordering::Relaxed);
    assert!(
        cache.lookup(&key, lookup, 0, &rg_epochs).is_none(),
        "in-range owner RG must still invalidate on its own per-RG epoch bump"
    );
    assert_eq!(cache.evictions, 1);
}

#[test]
fn expired_owner_rg_lease_causes_miss_without_epoch_bump() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let key = make_key();
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: 1,
        owner_rg_epoch: 7,
        owner_rg_lease_until: 50,
    };
    rg_epochs[1].store(7, Ordering::Relaxed);
    cache.insert(make_entry(key.clone(), stamp, 1));

    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 1,
        fib_generation: 1,
    };
    let hit = cache.lookup(&key, lookup, 51, &rg_epochs);
    assert!(hit.is_none(), "expected miss after HA lease expiry");
    assert_eq!(cache.evictions, 1);
}

#[test]
fn expired_owner_rg_lease_causes_miss_for_out_of_range_rg() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let key = make_key();
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: MAX_RG_EPOCHS as i32 + 4,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 50,
    };
    cache.insert(make_entry(key.clone(), stamp, stamp.owner_rg_id));

    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 1,
        fib_generation: 1,
    };
    let hit = cache.lookup(&key, lookup, 51, &rg_epochs);
    assert!(
        hit.is_none(),
        "expected miss after HA lease expiry even for out-of-range owner RG"
    );
    assert_eq!(cache.evictions, 1);
}

// ----------------------------------------------------------------
// (f) Non-cacheable dispositions rejected by should_cache
// ----------------------------------------------------------------
#[test]
fn non_cacheable_dispositions_rejected() {
    let meta = make_meta(PROTO_TCP);
    let non_cacheable = [
        ForwardingDisposition::NoRoute,
        ForwardingDisposition::MissingNeighbor,
        ForwardingDisposition::HAInactive,
        ForwardingDisposition::PolicyDenied,
        ForwardingDisposition::LocalDelivery,
    ];
    for disposition in non_cacheable {
        let decision = make_decision(disposition);
        assert!(
            !FlowCacheEntry::should_cache(meta, decision),
            "expected should_cache=false for {:?}",
            disposition,
        );
    }
}

// ----------------------------------------------------------------
// (g) ForwardCandidate is cacheable
// ----------------------------------------------------------------
#[test]
fn forward_candidate_is_cacheable() {
    let meta_tcp = make_meta(PROTO_TCP);
    let meta_udp = make_meta(PROTO_UDP);
    let decision = make_decision(ForwardingDisposition::ForwardCandidate);

    assert!(
        FlowCacheEntry::should_cache(meta_tcp, decision),
        "TCP ForwardCandidate should be cacheable",
    );
    assert!(
        FlowCacheEntry::should_cache(meta_udp, decision),
        "UDP ForwardCandidate should be cacheable",
    );
}

// ----------------------------------------------------------------
// (g-extra) NAT64 stays non-cacheable; NPTv6 IS cacheable (#2652)
// ----------------------------------------------------------------
#[test]
fn nat64_not_cacheable() {
    let meta = make_meta(PROTO_TCP);

    // NAT64 is a version-changing translation (header rebuild) the in-place
    // descriptor fast path cannot express — it must stay on the generic path.
    let mut nat64_decision = make_decision(ForwardingDisposition::ForwardCandidate);
    nat64_decision.nat.nat64 = true;
    assert!(
        !FlowCacheEntry::should_cache(meta, nat64_decision),
        "NAT64 should not be cacheable",
    );
}

#[test]
fn nptv6_is_cacheable() {
    // #2652: NPTv6 is a same-family IPv6 prefix rewrite that is
    // checksum-neutral by RFC 6296, so the descriptor fast path reproduces it
    // byte-for-byte. It MUST now be admitted to the flow cache. Use a v6 meta
    // so the eligibility predicate (UDP / established-TCP) and the v6 family
    // match the NPTv6 dst rewrite below.
    let meta = UserspaceDpMeta {
        protocol: PROTO_TCP,
        addr_family: libc::AF_INET6 as u8,
        ingress_ifindex: 7,
        tcp_flags: 0x10, // ACK only
        ..Default::default()
    };

    let mut nptv6_decision = make_decision(ForwardingDisposition::ForwardCandidate);
    nptv6_decision.nat.nptv6 = true;
    nptv6_decision.nat.rewrite_dst = Some(IpAddr::V6(std::net::Ipv6Addr::new(
        0xfd00, 0, 0, 0, 0, 0, 0, 0x1234,
    )));
    assert!(
        FlowCacheEntry::should_cache(meta, nptv6_decision),
        "NPTv6 should be cacheable (#2652)",
    );

    // Fail-on-revert guard: if the `!decision.nat.nptv6` exclusion is
    // reinstated in `should_cache`, this assertion flips to false.
}

// ----------------------------------------------------------------
// (h) from_forward_decision round-trip
// ----------------------------------------------------------------
#[test]
fn from_forward_decision_round_trip() {
    let rg_epochs = default_rg_epochs();
    let key = make_key();
    let flow = SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key.clone(),
    };
    let meta = UserspaceDpMeta {
        protocol: PROTO_TCP,
        addr_family: libc::AF_INET as u8,
        ingress_ifindex: 7,
        tcp_flags: 0x10,
        config_generation: 10,
        fib_generation: 3,
        ..Default::default()
    };
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 10,
        fib_generation: 3,
    };
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 6,
        tx_ifindex: 6,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1))),
        neighbor_mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x01, 0x01]),
        tx_vlan_id: 50,
    }, nat: NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 8))),
        rewrite_dst: None,
        rewrite_src_port: Some(1024),
        rewrite_dst_port: None,
        nat64: false,
        nptv6: false,
    }, install_table_domain: 0, install_table_check: 0 };
    let ingress_zone = Some(3);

    // ForwardingState needs egress entry so owner_rg_for_resolution can
    // look up the redundancy_group for egress_ifindex=6.
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        6,
        EgressInterface {
            bind_ifindex: 6,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
            zone_id: TEST_TRUST_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 1, 1)),
            primary_v6: None,
        },
    );

    let entry = FlowCacheEntry::from_forward_decision(
        &flow,
        meta,
        validation,
        decision,
        1,
        ingress_zone.clone(),
        Some(7),
        None,
        crate::filter::CachedFilterCounters::default(),
        &forwarding,
        &BTreeMap::from([(
            1,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: 95,
                lease: HAForwardingLease::ActiveUntil(100),
            },
        )]),
        false,
        &rg_epochs,
        // #3918: pre-resolve neighbor_mac_epoch snapshot (0 = none).
        0,
    );
    let entry = entry.expect("should produce a cache entry for ForwardCandidate");

    // Key and ingress match input.
    assert_eq!(entry.key, key);
    assert_eq!(entry.ingress_ifindex, 7);

    // Decision round-trips exactly.
    assert_eq!(entry.decision, decision);

    // Descriptor carries the resolution's MAC/VLAN/ifindex data.
    assert_eq!(
        entry.descriptor.dst_mac,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    );
    assert_eq!(
        entry.descriptor.src_mac,
        [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01]
    );
    assert_eq!(entry.descriptor.tx_vlan_id, 50);
    assert_eq!(entry.descriptor.egress_ifindex, 6);
    assert_eq!(entry.descriptor.tx_ifindex, 6);
    assert_eq!(entry.descriptor.target_binding_index, Some(7));
    assert_eq!(entry.descriptor.ether_type, 0x0800);
    assert_eq!(
        entry.descriptor.fabric_redirect,
        decision.resolution.disposition == ForwardingDisposition::FabricRedirect
    );

    // NAT rewrite fields propagated.
    assert_eq!(
        entry.descriptor.rewrite_src_ip,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 8))),
    );
    assert_eq!(entry.descriptor.rewrite_dst_ip, None);
    assert_eq!(entry.descriptor.rewrite_src_port, Some(1024));
    assert_eq!(entry.descriptor.rewrite_dst_port, None);
    assert!(!entry.descriptor.nat64);
    assert!(!entry.descriptor.nptv6);
    assert!(!entry.descriptor.apply_nat_on_fabric);

    // Stamp matches validation + RG epoch.
    assert_eq!(entry.stamp.config_generation, 10);
    assert_eq!(entry.stamp.fib_generation, 3);
    assert_eq!(entry.stamp.owner_rg_id, 1); // from egress RG
    assert_eq!(entry.stamp.owner_rg_epoch, 0); // rg_epochs all start at 0
    assert_eq!(entry.stamp.owner_rg_lease_until, 100);

    // Metadata carries ingress zone and owner RG.
    assert_eq!(entry.metadata.ingress_zone, TEST_TRUST_ZONE_ID);
    assert_eq!(entry.metadata.owner_rg_id, 1);
    assert!(!entry.metadata.fabric_ingress);
}

// ----------------------------------------------------------------
// (h-family) #963 PR-A: from_forward_decision refuses to *cache*
// descriptors whose decision.nat carries IPs of a different family
// than meta.addr_family. The fast-path apply (apply_rewrite_descriptor)
// would silently skip IP NAT in that case while still applying port
// NAT and a port-only checksum delta — a forwarding-correctness bug.
//
// Note on scope: the generic path's NAT helpers (apply_nat_ipv4 /
// apply_nat_ipv6) also gate IP NAT on family-match, so the first
// packet still gets its IP NAT silently skipped on either path. What
// PR-A buys is preventing the bug from *persisting* in the cache and
// re-firing on every subsequent packet. Refusing to cache here
// forces the flow back through policy on the next miss, giving the
// upstream NAT pipeline another chance to produce a family-
// consistent decision.
// ----------------------------------------------------------------

/// Build the standard test inputs for a NAT44-shaped FlowCacheEntry.
///
/// Returns (flow, meta, validation, decision, forwarding, ha_state)
/// configured for a v4 session through egress ifindex 6 in RG 1.
/// Tests can mutate `decision.nat` to introduce mismatches.
fn make_v4_round_trip_inputs() -> (
    SessionFlow,
    UserspaceDpMeta,
    ValidationState,
    SessionDecision,
    ForwardingState,
    BTreeMap<i32, HAGroupRuntime>,
) {
    let key = make_key();
    let flow = SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key,
    };
    let meta = UserspaceDpMeta {
        protocol: PROTO_TCP,
        addr_family: libc::AF_INET as u8,
        ingress_ifindex: 7,
        tcp_flags: 0x10,
        config_generation: 10,
        fib_generation: 3,
        ..Default::default()
    };
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 10,
        fib_generation: 3,
    };
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 6,
        tx_ifindex: 6,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1))),
        neighbor_mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x01, 0x01]),
        tx_vlan_id: 50,
    }, nat: NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 8))),
        rewrite_dst: None,
        rewrite_src_port: Some(1024),
        rewrite_dst_port: None,
        nat64: false,
        nptv6: false,
    }, install_table_domain: 0, install_table_check: 0 };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        6,
        EgressInterface {
            bind_ifindex: 6,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
            zone_id: TEST_TRUST_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 1, 1)),
            primary_v6: None,
        },
    );
    let ha_state = BTreeMap::from([(
        1,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: 95,
            lease: HAForwardingLease::ActiveUntil(100),
        },
    )]);
    (flow, meta, validation, decision, forwarding, ha_state)
}

#[test]
fn from_forward_decision_skips_cache_for_dscp_matched_output_filter() {
    let rg_epochs = default_rg_epochs();
    let (flow, mut meta, validation, decision, mut forwarding, ha_state) =
        make_v4_round_trip_inputs();
    meta.dscp = 0;
    forwarding.filter_state = crate::filter::parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "wan-drop-ef".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-ef-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                dscp_values: vec![46],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
        &[InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: decision.resolution.egress_ifindex,
            filter_output_v4: "wan-drop-ef".into(),
            ..Default::default()
        }],
        "",
        "",
    ).expect("filter state compiles");

    let entry = FlowCacheEntry::from_forward_decision(
        &flow,
        meta,
        validation,
        decision,
        1,
        Some(TEST_TRUST_ZONE_ID),
        Some(7),
        None,
        crate::filter::CachedFilterCounters::default(),
        &forwarding,
        &ha_state,
        false,
        &rg_epochs,
        // #3918: pre-resolve neighbor_mac_epoch snapshot (0 = none).
        0,
    );

    assert!(
        entry.is_none(),
        "DSCP-matched output filters depend on per-packet state outside \
         the flow-cache key",
    );
}

#[test]
fn from_forward_decision_skips_cache_for_dscp_matched_input_filter() {
    let rg_epochs = default_rg_epochs();
    let (flow, mut meta, validation, decision, mut forwarding, ha_state) =
        make_v4_round_trip_inputs();
    meta.dscp = 0;
    forwarding.filter_state = crate::filter::parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "lan-drop-ef".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-ef-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                dscp_values: vec![46],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
        &[InterfaceSnapshot {
            name: "reth1.0".into(),
            ifindex: meta.ingress_ifindex as i32,
            filter_input_v4: "lan-drop-ef".into(),
            ..Default::default()
        }],
        "",
        "",
    ).expect("filter state compiles");

    let entry = FlowCacheEntry::from_forward_decision(
        &flow,
        meta,
        validation,
        decision,
        1,
        Some(TEST_TRUST_ZONE_ID),
        Some(7),
        None,
        crate::filter::CachedFilterCounters::default(),
        &forwarding,
        &ha_state,
        false,
        &rg_epochs,
        // #3918: pre-resolve neighbor_mac_epoch snapshot (0 = none).
        0,
    );

    assert!(
        entry.is_none(),
        "DSCP-matched input filters depend on per-packet state outside \
         the flow-cache key",
    );
}

// #2362: a per-packet L4 (tcp-flags / is-fragment / icmp-type / icmp-code)
// input filter must decline the flow-cache for the same reason DSCP does —
// the condition varies per packet within a 5-tuple flow.
#[test]
fn from_forward_decision_skips_cache_for_per_packet_l4_input_filter() {
    let rg_epochs = default_rg_epochs();
    let (flow, meta, validation, decision, mut forwarding, ha_state) = make_v4_round_trip_inputs();
    forwarding.filter_state = crate::filter::parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "lan-drop-syn".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-syn".into(),
                protocols: vec!["tcp".into()],
                action: "discard".into(),
                tcp_flags: Some(0x02),
                ..Default::default()
            }],
        }],
        &[],
        &[InterfaceSnapshot {
            name: "reth1.0".into(),
            ifindex: meta.ingress_ifindex as i32,
            filter_input_v4: "lan-drop-syn".into(),
            ..Default::default()
        }],
        "",
        "",
    ).expect("filter state compiles");

    let entry = FlowCacheEntry::from_forward_decision(
        &flow,
        meta,
        validation,
        decision,
        1,
        Some(TEST_TRUST_ZONE_ID),
        Some(7),
        None,
        crate::filter::CachedFilterCounters::default(),
        &forwarding,
        &ha_state,
        false,
        &rg_epochs,
        // #3918: pre-resolve neighbor_mac_epoch snapshot (0 = none).
        0,
    );

    assert!(
        entry.is_none(),
        "tcp-flags-matched input filters depend on per-packet state outside \
         the flow-cache key (#2362)",
    );
}

#[test]
fn from_forward_decision_skips_cache_for_per_packet_l4_output_filter() {
    let rg_epochs = default_rg_epochs();
    let (flow, meta, validation, decision, mut forwarding, ha_state) = make_v4_round_trip_inputs();
    forwarding.filter_state = crate::filter::parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "wan-drop-frag".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-frag".into(),
                action: "discard".into(),
                is_fragment: true,
                ..Default::default()
            }],
        }],
        &[],
        &[InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: decision.resolution.egress_ifindex,
            filter_output_v4: "wan-drop-frag".into(),
            ..Default::default()
        }],
        "",
        "",
    ).expect("filter state compiles");

    let entry = FlowCacheEntry::from_forward_decision(
        &flow,
        meta,
        validation,
        decision,
        1,
        Some(TEST_TRUST_ZONE_ID),
        Some(7),
        None,
        crate::filter::CachedFilterCounters::default(),
        &forwarding,
        &ha_state,
        false,
        &rg_epochs,
        // #3918: pre-resolve neighbor_mac_epoch snapshot (0 = none).
        0,
    );

    assert!(
        entry.is_none(),
        "is-fragment-matched output filters depend on per-packet state outside \
         the flow-cache key (#2362)",
    );
}

// ============================================================
// #1431 cache-invariant runbook reference tests
//
// These two tests are the canonical "this is what a new
// cache-sensitive per-packet match field's flow-cache gate test
// should look like" references for the runbook in
// userspace-dp/src/filter/README.md
// "Cache-key invariants for per-packet match fields (#1431)".
//
// They re-exercise the DSCP gate (already covered by the bespoke
// tests `from_forward_decision_skips_cache_for_dscp_matched_output_filter`
// and `from_forward_decision_skips_cache_for_dscp_matched_input_filter`
// above in this file), but in an explicitly
// runbook-shaped layout: build a snapshot with the cache-sensitive
// match field on a terminal action, bind it to the relevant
// interface direction, drive `FlowCacheEntry::from_forward_decision`,
// and assert the cache declines insertion.
//
// When a future PR adds a new cache-sensitive match field
// (tcp_flags, fragment, ihl, tos lower bits / ECN, icmp_type,
// flex_match, etc.), clone the pattern below — substitute the
// new match field's snapshot field and the per-interface
// has_<X>_match set the snapshot compiler populated. The flow-
// cache home is `afxdp/`, not `filter/`, because
// `FlowCacheEntry::from_forward_decision` is `pub(super)`-scoped
// to `afxdp::flow_cache`.
// ============================================================

#[test]
fn dscp_input_gate_blocks_flow_cache_insertion_via_runbook_pattern() {
    let rg_epochs = default_rg_epochs();
    let (flow, mut meta, validation, decision, mut forwarding, ha_state) =
        make_v4_round_trip_inputs();
    // Step 1: pick a DSCP value the term will NOT match — the
    // first-packet decision must be allowed to enter the cache
    // path so the gate, not the term, is what blocks insertion.
    meta.dscp = 0;
    // Step 2: build a realistic snapshot whose terminal action
    // depends on a per-packet field outside the cache key.
    // For DSCP this is `dscp_values`; future fields would
    // substitute their own snapshot field.
    forwarding.filter_state = crate::filter::parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "lan-runbook-input".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-ef-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                dscp_values: vec![46],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
        &[InterfaceSnapshot {
            name: "reth1.0".into(),
            ifindex: meta.ingress_ifindex as i32,
            // Step 3: bind the filter as an INPUT filter on the
            // ingress interface. Since #6236 PR-2B the
            // `interface_input_filter_has_dscp_match` accessor reads the
            // `has_dscp_match_terms` flag off the per-interface fast map
            // (FilterState.iface_filter_v4_fast) — the parallel has_dscp_match
            // set was deleted.
            filter_input_v4: "lan-runbook-input".into(),
            ..Default::default()
        }],
        "",
        "",
    ).expect("filter state compiles");

    // Step 4: drive FlowCacheEntry::from_forward_decision and
    // confirm the gate at flow_cache.rs:297-309 declined
    // insertion via interface_input_filter_has_dscp_match.
    let entry = FlowCacheEntry::from_forward_decision(
        &flow,
        meta,
        validation,
        decision,
        1,
        Some(TEST_TRUST_ZONE_ID),
        Some(7),
        None,
        crate::filter::CachedFilterCounters::default(),
        &forwarding,
        &ha_state,
        false,
        &rg_epochs,
        // #3918: pre-resolve neighbor_mac_epoch snapshot (0 = none).
        0,
    );

    assert!(
        entry.is_none(),
        "input-bound DSCP-matched filters must decline flow-cache \
         insertion — see #1431 runbook in filter/README.md",
    );
}

#[test]
fn dscp_output_gate_blocks_flow_cache_insertion_via_runbook_pattern() {
    let rg_epochs = default_rg_epochs();
    let (flow, mut meta, validation, decision, mut forwarding, ha_state) =
        make_v4_round_trip_inputs();
    meta.dscp = 0;
    // Step 1-2 identical to the input variant — build a
    // snapshot whose terminal action depends on DSCP.
    // Step 3 (changed from input): bind the filter as an
    // OUTPUT filter on the egress interface. The compiler
    // populates FilterState.iface_filter_out_v4_fast and the
    // has_dscp_match aggregate is observed by
    // interface_output_filter_has_dscp_match.
    forwarding.filter_state = crate::filter::parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "wan-runbook-output".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-ef-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                dscp_values: vec![46],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        &[],
        &[InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: decision.resolution.egress_ifindex,
            filter_output_v4: "wan-runbook-output".into(),
            ..Default::default()
        }],
        "",
        "",
    ).expect("filter state compiles");

    // Step 4: same gate, different lookup —
    // interface_output_filter_has_dscp_match consults
    // iface_filter_out_v{4,6}_fast.has_dscp_match_terms (a fast
    // map lookup plus aggregate flag, not a HashSet).
    let entry = FlowCacheEntry::from_forward_decision(
        &flow,
        meta,
        validation,
        decision,
        1,
        Some(TEST_TRUST_ZONE_ID),
        Some(7),
        None,
        crate::filter::CachedFilterCounters::default(),
        &forwarding,
        &ha_state,
        false,
        &rg_epochs,
        // #3918: pre-resolve neighbor_mac_epoch snapshot (0 = none).
        0,
    );

    assert!(
        entry.is_none(),
        "output-bound DSCP-matched filters must decline flow-cache \
         insertion — see #1431 runbook in filter/README.md",
    );
}

/// Build a self-consistent v6-meta + v6-NAT scenario for the
/// mirror-image mismatch test (v4 rewrite_dst on v6 meta). Separate
/// from `make_v4_round_trip_inputs` so the v6 test doesn't have to
/// mutate seven fields off the v4 fixture.
fn make_v6_round_trip_inputs() -> (
    SessionFlow,
    UserspaceDpMeta,
    ValidationState,
    SessionDecision,
    ForwardingState,
    BTreeMap<i32, HAGroupRuntime>,
) {
    use std::net::Ipv6Addr;
    let src_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
    let dst_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3));
    let key = crate::session::SessionKey {
        src_ip,
        dst_ip,
        src_port: 49000,
        dst_port: 443,
        protocol: PROTO_TCP,
        addr_family: libc::AF_INET6 as u8,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let flow = SessionFlow {
        src_ip,
        dst_ip,
        forward_key: key,
    };
    let meta = UserspaceDpMeta {
        protocol: PROTO_TCP,
        addr_family: libc::AF_INET6 as u8,
        ingress_ifindex: 7,
        tcp_flags: 0x10,
        config_generation: 10,
        fib_generation: 3,
        ..Default::default()
    };
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 10,
        fib_generation: 3,
    };
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 6,
        tx_ifindex: 6,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
        neighbor_mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x01, 0x01]),
        tx_vlan_id: 50,
    }, nat: NatDecision {
        rewrite_src: None,
        rewrite_dst: None,
        rewrite_src_port: None,
        rewrite_dst_port: None,
        nat64: false,
        nptv6: false,
    }, install_table_domain: 0, install_table_check: 0 };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        6,
        EgressInterface {
            bind_ifindex: 6,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
            zone_id: TEST_TRUST_ZONE_ID,
            redundancy_group: 1,
            primary_v4: None,
            primary_v6: Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        },
    );
    let ha_state = BTreeMap::from([(
        1,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: 95,
            lease: HAForwardingLease::ActiveUntil(100),
        },
    )]);
    (flow, meta, validation, decision, forwarding, ha_state)
}

/// Helper: invoke `from_forward_decision` with the standard knobs
/// the family-guard tests use. Pulls 9 of the 11 args out of the
/// per-test boilerplate so the test bodies can focus on the v4/v6
/// inputs and the assertion.
fn try_build_entry(
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    validation: ValidationState,
    decision: SessionDecision,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
) -> Option<FlowCacheEntry> {
    let rg_epochs = default_rg_epochs();
    FlowCacheEntry::from_forward_decision(
        flow,
        meta,
        validation,
        decision,
        1,
        Some(3),
        Some(7),
        None,
        crate::filter::CachedFilterCounters::default(),
        forwarding,
        ha_state,
        false,
        &rg_epochs,
        // #3918: pre-resolve neighbor_mac_epoch snapshot (0 = none).
        0,
    )
}

#[test]
fn from_forward_decision_matching_family_returns_some() {
    // Sanity: the standard v4 inputs (V4 meta + V4 NAT) build a cache
    // entry. Companion to the negative tests below so a future
    // refactor that breaks the constructor is obviously the cause and
    // not an unrelated input change.
    let (flow, meta, validation, decision, forwarding, ha_state) = make_v4_round_trip_inputs();
    let entry = try_build_entry(&flow, meta, validation, decision, &forwarding, &ha_state);
    assert!(
        entry.is_some(),
        "matching-family v4 NAT should be cacheable"
    );
}

#[test]
fn from_forward_decision_preserves_input_filter_log_for_cached_hits() {
    let (flow, meta, validation, decision, forwarding, ha_state) = make_v4_round_trip_inputs();
    let rg_epochs = default_rg_epochs();
    let input_log = CachedInputFilterLog {
        log_match: crate::filter::FilterLogMatch {
            filter_id: 17,
            term_id: 23,
            action: crate::filter::FilterAction::Accept,
        },
        ingress_zone_id: 7,
    };

    let entry = FlowCacheEntry::from_forward_decision(
        &flow,
        meta,
        validation,
        decision,
        1,
        Some(3),
        Some(7),
        Some(input_log),
        crate::filter::CachedFilterCounters::default(),
        &forwarding,
        &ha_state,
        false,
        &rg_epochs,
        // #3918: pre-resolve neighbor_mac_epoch snapshot (0 = none).
        0,
    )
    .expect("cacheable entry");

    assert_eq!(entry.descriptor.input_filter_log, Some(input_log));
}

// The next four tests verify the family guard from both build modes.
// The guard is `debug_assert!(false, ...)` then `return None`, so the
// observable behavior differs by build mode:
//
// - Debug build: `debug_assert!` fires; the panic propagates up and
//   the test passes via `#[should_panic]`.
// - Release build: `debug_assert!` is stripped; the function returns
//   `None`; the test passes via `assert!(entry.is_none())`.
//
// Each mismatch case is split into two `#[cfg(...)]`-gated test
// functions so each build mode runs exactly the assertion that
// applies to it. This avoids the trap of `#[cfg_attr(debug_assertions,
// should_panic)]` on a single test, where the release-mode
// `assert!(entry.is_none())` would only ever execute under
// `cargo test --release` — easy to miss in a project without a
// CI release-test step.

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "RewriteDescriptor af-mismatch")]
fn from_forward_decision_rejects_v6_rewrite_src_on_v4_meta_debug() {
    let (flow, meta, validation, mut decision, forwarding, ha_state) = make_v4_round_trip_inputs();
    decision.nat.rewrite_src = Some(IpAddr::V6(std::net::Ipv6Addr::new(
        0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
    )));
    // Expected to panic via debug_assert! before reaching this assert.
    let _ = try_build_entry(&flow, meta, validation, decision, &forwarding, &ha_state);
}

#[cfg(not(debug_assertions))]
#[test]
fn from_forward_decision_rejects_v6_rewrite_src_on_v4_meta_release() {
    let (flow, meta, validation, mut decision, forwarding, ha_state) = make_v4_round_trip_inputs();
    decision.nat.rewrite_src = Some(IpAddr::V6(std::net::Ipv6Addr::new(
        0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
    )));
    let entry = try_build_entry(&flow, meta, validation, decision, &forwarding, &ha_state);
    assert!(
        entry.is_none(),
        "V6 rewrite_src on a V4 session must not be cacheable"
    );
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "RewriteDescriptor af-mismatch")]
fn from_forward_decision_rejects_v4_rewrite_dst_on_v6_meta_debug() {
    let (flow, meta, validation, mut decision, forwarding, ha_state) = make_v6_round_trip_inputs();
    decision.nat.rewrite_dst = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)));
    let _ = try_build_entry(&flow, meta, validation, decision, &forwarding, &ha_state);
}

#[cfg(not(debug_assertions))]
#[test]
fn from_forward_decision_rejects_v4_rewrite_dst_on_v6_meta_release() {
    let (flow, meta, validation, mut decision, forwarding, ha_state) = make_v6_round_trip_inputs();
    decision.nat.rewrite_dst = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)));
    let entry = try_build_entry(&flow, meta, validation, decision, &forwarding, &ha_state);
    assert!(
        entry.is_none(),
        "V4 rewrite_dst on a V6 session must not be cacheable"
    );
}

// The previous four tests cover (V6 src, V4 meta) and (V4 dst, V6 meta).
// The next four cover the other two slot/family combinations so a
// future refactor that drops the `slot_ok(&nat.rewrite_dst)` (or
// `slot_ok(&nat.rewrite_src)`) check from the helper can't
// accidentally validate only one slot without a test failing.
// Per Copilot round-2 review on PR #1134.

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "RewriteDescriptor af-mismatch")]
fn from_forward_decision_rejects_v6_rewrite_dst_on_v4_meta_debug() {
    let (flow, meta, validation, mut decision, forwarding, ha_state) = make_v4_round_trip_inputs();
    decision.nat.rewrite_dst = Some(IpAddr::V6(std::net::Ipv6Addr::new(
        0x2001, 0xdb8, 0, 0, 0, 0, 0, 4,
    )));
    let _ = try_build_entry(&flow, meta, validation, decision, &forwarding, &ha_state);
}

#[cfg(not(debug_assertions))]
#[test]
fn from_forward_decision_rejects_v6_rewrite_dst_on_v4_meta_release() {
    let (flow, meta, validation, mut decision, forwarding, ha_state) = make_v4_round_trip_inputs();
    decision.nat.rewrite_dst = Some(IpAddr::V6(std::net::Ipv6Addr::new(
        0x2001, 0xdb8, 0, 0, 0, 0, 0, 4,
    )));
    let entry = try_build_entry(&flow, meta, validation, decision, &forwarding, &ha_state);
    assert!(
        entry.is_none(),
        "V6 rewrite_dst on a V4 session must not be cacheable"
    );
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "RewriteDescriptor af-mismatch")]
fn from_forward_decision_rejects_v4_rewrite_src_on_v6_meta_debug() {
    let (flow, meta, validation, mut decision, forwarding, ha_state) = make_v6_round_trip_inputs();
    decision.nat.rewrite_src = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8)));
    let _ = try_build_entry(&flow, meta, validation, decision, &forwarding, &ha_state);
}

#[cfg(not(debug_assertions))]
#[test]
fn from_forward_decision_rejects_v4_rewrite_src_on_v6_meta_release() {
    let (flow, meta, validation, mut decision, forwarding, ha_state) = make_v6_round_trip_inputs();
    decision.nat.rewrite_src = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8)));
    let entry = try_build_entry(&flow, meta, validation, decision, &forwarding, &ha_state);
    assert!(
        entry.is_none(),
        "V4 rewrite_src on a V6 session must not be cacheable"
    );
}

#[cfg(not(debug_assertions))]
#[test]
fn from_forward_decision_rejects_junk_addr_family_release() {
    // PR-A robustness: addr_family that's neither AF_INET nor
    // AF_INET6 (e.g. uninitialised stack memory) must not slip
    // through the guard. Codex round-1 review found that the
    // earlier `want_v4 = addr_family == AF_INET` formulation
    // accepted V6 IPs for any non-AF_INET value, including junk.
    // The fix is the explicit three-arm match in
    // `nat_family_matches_addr_family`. This test pins that
    // behavior in release builds (debug builds also panic via
    // debug_assert! before reaching the assertion, but the panic
    // message identifies the same code path).
    let (flow, mut meta, validation, mut decision, forwarding, ha_state) =
        make_v4_round_trip_inputs();
    meta.addr_family = 99; // junk value, not AF_INET / AF_INET6
    decision.nat.rewrite_src = Some(IpAddr::V6(std::net::Ipv6Addr::new(
        0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
    )));
    let entry = try_build_entry(&flow, meta, validation, decision, &forwarding, &ha_state);
    assert!(
        entry.is_none(),
        "junk addr_family must reject the descriptor regardless of NAT slot families"
    );
}

// ----------------------------------------------------------------
// (h-extra) from_forward_decision returns None for non-cacheable
// ----------------------------------------------------------------
#[test]
fn from_forward_decision_returns_none_for_non_cacheable() {
    let rg_epochs = default_rg_epochs();
    let key = make_key();
    let flow = SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key,
    };
    let meta = make_meta(PROTO_TCP);
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 1,
        fib_generation: 1,
    };
    // NoRoute is not cacheable.
    let decision = make_decision(ForwardingDisposition::NoRoute);
    let forwarding = ForwardingState::default();

    let entry = FlowCacheEntry::from_forward_decision(
        &flow,
        meta,
        validation,
        decision,
        0,
        None,
        None,
        None,
        crate::filter::CachedFilterCounters::default(),
        &forwarding,
        &BTreeMap::new(),
        false,
        &rg_epochs,
        // #3918: pre-resolve neighbor_mac_epoch snapshot (0 = none).
        0,
    );
    assert!(entry.is_none(), "NoRoute should not produce a cache entry");
}

#[test]
fn fabric_redirect_cache_entry_uses_flow_owner_rg_for_epoch_invalidation() {
    let rg_epochs = default_rg_epochs();
    let key = make_key();
    let flow = SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key.clone(),
    };
    let meta = make_meta(PROTO_TCP);
    let validation = ValidationState {
        snapshot_installed: true,
        config_generation: 1,
        fib_generation: 1,
    };
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::FabricRedirect,
        local_ifindex: 0,
        egress_ifindex: 21,
        tx_ifindex: 21,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
        neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
        src_mac: Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]),
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 };
    let mut forwarding = ForwardingState::default();
    forwarding.fabrics.push(FabricLink {
        parent_ifindex: 21,
        overlay_ifindex: 101,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        up: true,
    });
    forwarding.egress.insert(
        6,
        EgressInterface {
            bind_ifindex: 6,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_TRUST_ZONE_ID,
            redundancy_group: 2,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );

    let entry = FlowCacheEntry::from_forward_decision(
        &flow,
        meta,
        validation,
        decision,
        2,
        Some(3),
        Some(3),
        None,
        crate::filter::CachedFilterCounters::default(),
        &forwarding,
        &BTreeMap::from([(
            2,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: 10,
                lease: HAForwardingLease::ActiveUntil(20),
            },
        )]),
        true,
        &rg_epochs,
        // #3918: pre-resolve neighbor_mac_epoch snapshot (0 = none).
        0,
    )
    .expect("fabric redirect entry");

    assert_eq!(entry.stamp.owner_rg_id, 2);
    assert_eq!(entry.metadata.owner_rg_id, 2);
    assert!(entry.descriptor.fabric_redirect);
    assert_eq!(entry.descriptor.target_binding_index, Some(3));
}

// ----------------------------------------------------------------
// #918: 4-way set-associative LRU tests
// ----------------------------------------------------------------

/// Synthesize a key whose `set_index()` matches `target_set` so
/// tests can exercise the full set-collision pipeline rather than
/// rely on harness chance.
fn key_in_set(target_set: usize, salt: u16) -> crate::session::SessionKey {
    // Iterate src_port until we land in `target_set`. FxHasher is
    // deterministic, so this terminates in O(SETS) on average.
    // Inclusive range covers the full 16-bit port space.
    for port in salt..=u16::MAX {
        let key = crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 50, 200)),
            src_port: port,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        };
        if FlowCache::set_index(&key, 7) == target_set {
            return key;
        }
    }
    panic!("could not find key in set {target_set}");
}

#[test]
fn flow_cache_4way_no_eviction_under_4_distinct_keys_in_same_set() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: 0,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    let target_set = 42;
    let mut keys = Vec::new();
    let mut salt = 0u16;
    while keys.len() < 4 {
        let key = key_in_set(target_set, salt);
        salt = key.src_port + 1;
        if !keys.iter().any(|k: &crate::session::SessionKey| k == &key) {
            keys.push(key);
        }
    }
    for key in &keys {
        cache.insert(make_entry(key.clone(), stamp, 0));
    }
    assert_eq!(
        cache.collision_evictions, 0,
        "4 distinct keys in same set must not collision-evict"
    );
    // All 4 lookups should hit.
    for key in &keys {
        let lookup = FlowCacheLookup {
            ingress_ifindex: 7,
            logical_ingress_ifindex: 7,
            config_generation: 1,
            fib_generation: 1,
        };
        assert!(cache.lookup(key, lookup, 0, &rg_epochs).is_some());
    }
}

#[test]
fn flow_cache_4way_lru_evicts_oldest_on_5th_insert() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: 0,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    let target_set = 99;
    let mut keys = Vec::new();
    let mut salt = 0u16;
    while keys.len() < 5 {
        let key = key_in_set(target_set, salt);
        salt = key.src_port + 1;
        if !keys.iter().any(|k: &crate::session::SessionKey| k == &key) {
            keys.push(key);
        }
    }
    // Insert 4 keys (set fills).
    for key in &keys[..4] {
        cache.insert(make_entry(key.clone(), stamp, 0));
    }
    assert_eq!(cache.collision_evictions, 0);
    // Insert 5th: must collision-evict the LRU (= keys[0], inserted first).
    cache.insert(make_entry(keys[4].clone(), stamp, 0));
    assert_eq!(cache.collision_evictions, 1);
    // keys[0] must be gone, keys[1..=4] present.
    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 1,
        fib_generation: 1,
    };
    assert!(
        cache.lookup(&keys[0], lookup, 0, &rg_epochs).is_none(),
        "LRU way (keys[0]) must have been evicted"
    );
    for key in &keys[1..=4] {
        assert!(
            cache.lookup(key, lookup, 0, &rg_epochs).is_some(),
            "remaining 4 keys must still hit"
        );
    }
}

#[test]
fn flow_cache_4way_lookup_promotes_to_mru() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: 0,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    let target_set = 200;
    let mut keys = Vec::new();
    let mut salt = 0u16;
    while keys.len() < 5 {
        let key = key_in_set(target_set, salt);
        salt = key.src_port + 1;
        if !keys.iter().any(|k: &crate::session::SessionKey| k == &key) {
            keys.push(key);
        }
    }
    // Insert 4 keys (now LRU-order: keys[0] = LRU, keys[3] = MRU).
    for key in &keys[..4] {
        cache.insert(make_entry(key.clone(), stamp, 0));
    }
    // Look up keys[0] — should promote it to MRU.
    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 1,
        fib_generation: 1,
    };
    assert!(cache.lookup(&keys[0], lookup, 0, &rg_epochs).is_some());
    // Insert 5th: now keys[1] is LRU (since keys[0] was promoted).
    cache.insert(make_entry(keys[4].clone(), stamp, 0));
    assert_eq!(cache.collision_evictions, 1);
    assert!(
        cache.lookup(&keys[0], lookup, 0, &rg_epochs).is_some(),
        "keys[0] was promoted, must still be in cache"
    );
    assert!(
        cache.lookup(&keys[1], lookup, 0, &rg_epochs).is_none(),
        "keys[1] became LRU after the promotion, must have been evicted"
    );
}

#[test]
fn flow_cache_4way_invalidate_clears_only_matching_way() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: 0,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    let target_set = 300;
    let mut keys = Vec::new();
    let mut salt = 0u16;
    while keys.len() < 4 {
        let key = key_in_set(target_set, salt);
        salt = key.src_port + 1;
        if !keys.iter().any(|k: &crate::session::SessionKey| k == &key) {
            keys.push(key);
        }
    }
    for key in &keys {
        cache.insert(make_entry(key.clone(), stamp, 0));
    }
    cache.invalidate_slot(&keys[1], 7);
    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 1,
        fib_generation: 1,
    };
    assert!(
        cache.lookup(&keys[1], lookup, 0, &rg_epochs).is_none(),
        "invalidated key must miss"
    );
    for (i, key) in keys.iter().enumerate() {
        if i == 1 {
            continue;
        }
        assert!(
            cache.lookup(key, lookup, 0, &rg_epochs).is_some(),
            "non-invalidated keys must still hit"
        );
    }
}

/// Codex+Gemini R2 follow-up: explicitly exercise the §3.4.2
/// dedup-on-insert path. Insert stale-generation entry, then
/// fresh-generation entry with the same key — the existing way
/// must be replaced and promoted to MRU rather than allocating
/// a new way.
#[test]
fn flow_cache_4way_dedup_replaces_existing_and_promotes() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let key = make_key();
    let stale_stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: 0,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    let fresh_stamp = FlowCacheStamp {
        config_generation: 2, // bumped
        fib_generation: 1,
        owner_rg_id: 0,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    cache.insert(make_entry(key.clone(), stale_stamp, 0));
    // Re-insert with fresh stamp via insert(): dedup path replaces
    // the existing way, no eviction counted.
    let evictions_before = cache.evictions;
    cache.insert(make_entry(key.clone(), fresh_stamp, 0));
    assert_eq!(
        cache.evictions, evictions_before,
        "dedup-replace must not increment evictions counter"
    );
    // Lookup at fresh generation must hit (proves the entry was
    // overwritten with fresh data, not the stale entry that would
    // have been evicted on lookup).
    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 2,
        fib_generation: 1,
    };
    assert!(
        cache.lookup(&key, lookup, 0, &rg_epochs).is_some(),
        "fresh-stamp lookup must hit after dedup-replace"
    );
}

/// Codex+Gemini R2 follow-up: verify the LRU permutation is
/// always a permutation of [0,1,2,3] across any sequence of
/// inserts/lookups/invalidates. Catches off-by-one shift errors.
#[test]
fn flow_cache_4way_lru_permutation_invariant_holds() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: 0,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    let target_set = 500;
    let mut keys = Vec::new();
    let mut salt = 0u16;
    while keys.len() < 6 {
        let key = key_in_set(target_set, salt);
        salt = key.src_port + 1;
        if !keys.iter().any(|k: &crate::session::SessionKey| k == &key) {
            keys.push(key);
        }
    }
    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 1,
        fib_generation: 1,
    };
    // Hammer the set with mixed inserts/lookups/invalidates.
    for (i, key) in keys.iter().enumerate() {
        cache.insert(make_entry(key.clone(), stamp, 0));
        if i % 2 == 0 {
            let _ = cache.lookup(key, lookup, 0, &rg_epochs);
        }
        if i == 4 {
            cache.invalidate_slot(&keys[0], 7);
        }
    }
    // Verify lru[target_set] is a permutation of [0,1,2,3].
    let row = cache.lru[target_set];
    let mut sorted = row;
    sorted.sort();
    assert_eq!(
        sorted,
        [0u8, 1, 2, 3],
        "lru row must be a permutation of [0,1,2,3], got {row:?}"
    );
}

// ----------------------------------------------------------------
// (#1219) Active-flow epoch counter + count_active_flows
// ----------------------------------------------------------------

#[test]
fn count_active_flows_starts_at_zero() {
    let cache = FlowCache::new();
    assert_eq!(cache.count_active_flows(), 0);
}

#[test]
fn count_active_flows_excludes_never_touched_entries() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: 0,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    let key = make_key();
    // Insert without lookup → last_used_epoch stays 0 → not active.
    cache.insert(make_entry(key.clone(), stamp, 0));
    let _ = &rg_epochs; // silence unused warning if scoping shifts
    assert_eq!(cache.count_active_flows(), 0);
}

#[test]
fn count_active_flows_marks_recently_hit() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: 0,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    let key = make_key();
    cache.insert(make_entry(key.clone(), stamp, 0));
    // Advance to epoch 1 so a hit stamps with 1, not 0.
    cache.tick_advance_epoch();
    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 1,
        fib_generation: 1,
    };
    assert!(cache.lookup(&key, lookup, 0, &rg_epochs).is_some());
    // Same epoch → active.
    assert_eq!(cache.count_active_flows(), 1);
}

#[test]
fn active_flow_debug_entries_include_worker_join_keys() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: 0,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    let key = make_key();
    let mut entry = make_entry(key.clone(), stamp, 0);
    entry.decision.nat.rewrite_src = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)));
    entry.decision.nat.rewrite_src_port = Some(62000);
    entry.descriptor.tx_selection.queue_id = Some(4);
    entry.descriptor.tx_selection.dscp_rewrite = Some(46);
    cache.insert(entry);
    cache.tick_advance_epoch();
    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 1,
        fib_generation: 1,
    };
    assert!(cache.lookup(&key, lookup, 0, &rg_epochs).is_some());

    let (active_count, rows, cos_counts, truncated) = cache.active_flow_debug_entries(8);
    assert_eq!(active_count, 1);
    assert!(!truncated);
    assert_eq!(cos_counts.len(), 1);
    assert_eq!(cos_counts[0].ifindex, 6);
    assert_eq!(cos_counts[0].queue_id, 4);
    assert_eq!(cos_counts[0].active_flow_count, 1);
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.ingress_ifindex, 7);
    assert_eq!(row.egress_ifindex, 6);
    assert_eq!(row.tx_ifindex, 6);
    assert_eq!(row.session_key.src_port, 45678);
    assert_eq!(row.session_key.dst_port, 443);
    assert_eq!(row.forward_wire_key.src_ip, "198.51.100.10");
    assert_eq!(row.forward_wire_key.src_port, 62000);
    assert_eq!(row.reverse_canonical_key.src_port, 443);
    assert_eq!(row.reverse_canonical_key.dst_port, 45678);
    assert_eq!(row.cos_queue_id, Some(4));
    assert_eq!(row.dscp_rewrite, Some(46));
    assert_eq!(row.age_epochs, 0);
    assert_eq!(row.observed_bytes, 0);
}

#[test]
fn active_flow_debug_entries_report_truncation_without_losing_count() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: 0,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    let key = make_key();
    cache.insert(make_entry(key.clone(), stamp, 0));
    cache.tick_advance_epoch();
    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 1,
        fib_generation: 1,
    };
    assert!(cache.lookup(&key, lookup, 0, &rg_epochs).is_some());

    let (active_count, rows, cos_counts, truncated) = cache.active_flow_debug_entries(0);
    assert_eq!(active_count, 1);
    assert!(rows.is_empty());
    assert!(cos_counts.is_empty());
    assert!(truncated);
}

#[test]
fn active_flow_debug_entries_count_cos_queues_without_row_limit_loss() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: 0,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };

    for (idx, queue_id) in [4u8, 4, 5].into_iter().enumerate() {
        let mut key = make_key();
        key.src_port = 45678 + idx as u16;
        let mut entry = make_entry(key.clone(), stamp, 0);
        entry.descriptor.tx_selection.queue_id = Some(queue_id);
        cache.insert(entry);
        cache.tick_advance_epoch();
        let lookup = FlowCacheLookup {
            ingress_ifindex: 7,
            logical_ingress_ifindex: 7,
            config_generation: 1,
            fib_generation: 1,
        };
        assert!(cache.lookup(&key, lookup, 0, &rg_epochs).is_some());
    }

    let (active_count, rows, cos_counts, truncated) = cache.active_flow_debug_entries(1);
    assert_eq!(active_count, 3);
    assert_eq!(rows.len(), 1, "debug rows obey the requested limit");
    assert!(truncated);
    assert_eq!(cos_counts.len(), 2);
    assert_eq!(cos_counts[0].ifindex, 6);
    assert_eq!(cos_counts[0].queue_id, 4);
    assert_eq!(cos_counts[0].active_flow_count, 2);
    assert_eq!(cos_counts[1].ifindex, 6);
    assert_eq!(cos_counts[1].queue_id, 5);
    assert_eq!(cos_counts[1].active_flow_count, 1);
}

#[test]
fn count_active_flows_ages_out_after_window() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: 0,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    let key = make_key();
    cache.insert(make_entry(key.clone(), stamp, 0));
    cache.tick_advance_epoch();
    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 1,
        fib_generation: 1,
    };
    assert!(cache.lookup(&key, lookup, 0, &rg_epochs).is_some());
    assert_eq!(cache.count_active_flows(), 1);
    // Advance 10 epochs → outside window → entry no longer active.
    for _ in 0..10 {
        cache.tick_advance_epoch();
    }
    assert_eq!(cache.count_active_flows(), 0);
    // One more lookup re-stamps and reactivates.
    assert!(cache.lookup(&key, lookup, 0, &rg_epochs).is_some());
    assert_eq!(cache.count_active_flows(), 1);
}

#[test]
fn count_active_flows_handles_epoch_wraparound() {
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: 0,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    let key = make_key();
    cache.insert(make_entry(key.clone(), stamp, 0));
    // Force current_epoch near u16::MAX so the next advance wraps.
    // tick_advance_epoch skips 0 (sentinel), so the sequence near the
    // top is: MAX-1 → MAX → 1 → 2 (not 0).
    cache.current_epoch = u16::MAX - 1;
    cache.tick_advance_epoch(); // u16::MAX
    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 1,
        fib_generation: 1,
    };
    assert!(cache.lookup(&key, lookup, 0, &rg_epochs).is_some());
    // Now wrap: u16::MAX → wrapping_add(1) = 0, skipped → 1 → 2.
    cache.tick_advance_epoch(); // skips 0, becomes 1
    cache.tick_advance_epoch(); // 2
    // last_used_epoch was u16::MAX; current is 2; wrapping_sub
    // gives 2 - u16::MAX wrapping = 3. Within 10-epoch window → active.
    assert_eq!(cache.count_active_flows(), 1);
}

#[test]
fn tick_advance_epoch_skips_zero_sentinel() {
    // Verify that tick_advance_epoch never produces epoch == 0, which
    // is the "never touched" sentinel used by count_active_flows.
    let mut cache = FlowCache::new();
    cache.current_epoch = u16::MAX;
    cache.tick_advance_epoch(); // would be 0 without the skip
    assert_ne!(
        cache.current_epoch, 0,
        "epoch 0 is reserved sentinel and must never be produced by tick_advance_epoch"
    );
    assert_eq!(cache.current_epoch, 1);
}

#[test]
fn count_active_flows_entry_at_epoch_max_not_confused_with_sentinel() {
    // An entry stamped at u16::MAX (valid epoch) must be counted as
    // active immediately after wraparound to epoch 1 (age = 2 epochs,
    // within the 10-epoch window). It must NOT be confused with the
    // 0 sentinel.
    let rg_epochs = default_rg_epochs();
    let mut cache = FlowCache::new();
    let stamp = FlowCacheStamp {
        config_generation: 1,
        fib_generation: 1,
        owner_rg_id: 0,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    let key = make_key();
    cache.insert(make_entry(key.clone(), stamp, 0));
    cache.current_epoch = u16::MAX;
    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 1,
        fib_generation: 1,
    };
    assert!(cache.lookup(&key, lookup, 0, &rg_epochs).is_some());
    // stamp is u16::MAX, not 0 → survives the sentinel check
    cache.tick_advance_epoch(); // skips 0 → 1
    assert_eq!(
        cache.count_active_flows(),
        1,
        "entry at epoch MAX must be active after 1-tick advance"
    );
}

// ----------------------------------------------------------------
// (#1741) u16 epoch-wrap ghost resurrection — the production scan
// must sentinel-clear out-of-window stamps so dead entries can never
// re-enter the active window at the 65535-tick wrap. These four tests
// pin the bug shape found in the research round (deterministic repro:
// pre-fix, a dead entry resurrected for exactly ACTIVE_WINDOW_EPOCHS
// ticks per cycle, first at tick 65519).
// ----------------------------------------------------------------

fn issue_1741_stamp_and_lookup() -> (FlowCache, crate::session::SessionKey, FlowCacheLookup) {
    let cache = FlowCache::new();
    let key = make_key();
    let lookup = FlowCacheLookup {
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        config_generation: 5,
        fib_generation: 3,
    };
    (cache, key, lookup)
}

fn issue_1741_stamp() -> FlowCacheStamp {
    FlowCacheStamp {
        config_generation: 5,
        fib_generation: 3,
        owner_rg_id: 1,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    }
}

/// Single stamped entry, then idle across the full u16 wrap with the
/// production scan running every tick (as it does at the single
/// production call site). Pre-fix this resurrected 10 times starting
/// at tick 65519; post-fix the count must stay 0 forever.
#[test]
fn issue_1741_epoch_wrap_dead_entry_never_resurrects() {
    let rg_epochs = default_rg_epochs();
    let (mut cache, key, lookup) = issue_1741_stamp_and_lookup();
    cache.insert(make_entry(key.clone(), issue_1741_stamp(), 1));
    assert!(cache.lookup(&key, lookup, 0, &rg_epochs).is_some());
    // Flow dies; entry persists (no FIN/GC eviction of cache entries).
    let mut resurrections = 0u32;
    for tick in 0..70_000u32 {
        cache.tick_advance_epoch();
        let (active, _, _, _) = cache.active_flow_debug_entries(8);
        // The entry legitimately stays active for the remainder of the
        // window right after its last hit; only count post-window hits.
        if tick >= u32::from(ACTIVE_WINDOW_EPOCHS) && active != 0 {
            resurrections += 1;
        }
    }
    assert_eq!(
        resurrections, 0,
        "dead entry re-entered the active window across the u16 wrap"
    );
}

/// Production clean client-initiated close choreography (iperf3 shape):
/// data ACKs stamp; the FIN takes the slow path and re-INSERTS the
/// entry (sentinel-cleared); the final pure ACK fast-path hit re-stamps
/// nonzero. The closed flow must then never count again across the
/// wrap. Pre-fix: 10 resurrections per cycle.
#[test]
fn issue_1741_clean_close_choreography_never_ghosts() {
    let rg_epochs = default_rg_epochs();
    let (mut cache, key, lookup) = issue_1741_stamp_and_lookup();
    // Established: insert + data-ACK hits.
    cache.insert(make_entry(key.clone(), issue_1741_stamp(), 1));
    assert!(cache.lookup(&key, lookup, 0, &rg_epochs).is_some());
    cache.tick_advance_epoch();
    assert!(cache.lookup(&key, lookup, 0, &rg_epochs).is_some());
    // Client FIN: slow-path re-insert replaces the entry with the
    // last_used_epoch = 0 sentinel (dedup-on-insert path).
    cache.insert(make_entry(key.clone(), issue_1741_stamp(), 1));
    assert_eq!(
        cache.count_active_flows(),
        0,
        "FIN re-insert must sentinel-clear the stamp"
    );
    // Final client ACK (pure ACK, packet_eligible): fast-path hit
    // re-stamps nonzero.
    assert!(cache.lookup(&key, lookup, 0, &rg_epochs).is_some());
    assert_eq!(cache.count_active_flows(), 1, "final ACK re-stamps");
    // Fully closed; idle across the wrap with the production scan.
    let mut resurrections = 0u32;
    for tick in 0..70_000u32 {
        cache.tick_advance_epoch();
        let (active, _, _, _) = cache.active_flow_debug_entries(8);
        if tick >= u32::from(ACTIVE_WINDOW_EPOCHS) && active != 0 {
            resurrections += 1;
        }
    }
    assert_eq!(
        resurrections, 0,
        "clean-closed (FIN + final ACK) flow resurrected across the wrap"
    );
}

/// Window boundary: age ACTIVE_WINDOW_EPOCHS - 1 is counted and NOT
/// clamped; age ACTIVE_WINDOW_EPOCHS is uncounted AND sentinel-cleared
/// by the same scan.
#[test]
fn issue_1741_window_boundary_counts_age_9_clamps_age_10() {
    let rg_epochs = default_rg_epochs();
    let (mut cache, key, lookup) = issue_1741_stamp_and_lookup();
    cache.insert(make_entry(key.clone(), issue_1741_stamp(), 1));
    assert!(cache.lookup(&key, lookup, 0, &rg_epochs).is_some());
    let stamped_epoch = cache.current_epoch;
    // Advance to age = ACTIVE_WINDOW_EPOCHS - 1: still counted, stamp intact.
    for _ in 0..(ACTIVE_WINDOW_EPOCHS - 1) {
        cache.tick_advance_epoch();
        let (active, _, _, _) = cache.active_flow_debug_entries(8);
        assert_eq!(active, 1, "in-window entry must stay counted");
    }
    let stamp_after_window = cache
        .entries
        .iter()
        .flatten()
        .map(|entry| entry.last_used_epoch)
        .next()
        .expect("entry present");
    assert_eq!(
        stamp_after_window, stamped_epoch,
        "in-window stamp must not be clamped"
    );
    // One more tick: age = ACTIVE_WINDOW_EPOCHS -> uncounted + cleared.
    cache.tick_advance_epoch();
    let (active, _, _, _) = cache.active_flow_debug_entries(8);
    assert_eq!(active, 0, "age == window must be uncounted");
    let stamp_after_expiry = cache
        .entries
        .iter()
        .flatten()
        .map(|entry| entry.last_used_epoch)
        .next()
        .expect("entry still cached (clamp must not evict)");
    assert_eq!(
        stamp_after_expiry, 0,
        "expired stamp must be sentinel-cleared"
    );
}

/// A clamped entry is not evicted: a later fast-path hit re-stamps it,
/// it counts as active again, and its accumulated observed_bytes
/// telemetry is preserved across the clamp.
#[test]
fn issue_1741_clamped_entry_recoverable_by_hit() {
    let rg_epochs = default_rg_epochs();
    let (mut cache, key, lookup) = issue_1741_stamp_and_lookup();
    cache.insert(make_entry(key.clone(), issue_1741_stamp(), 1));
    assert!(
        cache
            .lookup_counted(&key, lookup, 0, &rg_epochs, 1500)
            .is_some()
    );
    // Age out + clamp.
    for _ in 0..(ACTIVE_WINDOW_EPOCHS + 2) {
        cache.tick_advance_epoch();
        let _ = cache.active_flow_debug_entries(8);
    }
    let (active, _, _, _) = cache.active_flow_debug_entries(8);
    assert_eq!(active, 0);
    // Returning flow: hit re-stamps; counted again; bytes preserved.
    let hit = cache
        .lookup_counted(&key, lookup, 0, &rg_epochs, 900)
        .expect("clamped entry must still be a cache hit");
    assert_eq!(
        hit.observed_bytes, 2400,
        "observed_bytes preserved across clamp"
    );
    let (active, rows, _, _) = cache.active_flow_debug_entries(8);
    assert_eq!(active, 1, "re-hit entry counts as active again");
    assert_eq!(rows.len(), 1);
}

// ----------------------------------------------------------------
// (z) #2363: admission gate is symmetric with the lookup gate.
//
// The flow-cache LOOKUP path is gated by `packet_eligible` (UDP, or
// established-TCP pure ACK). Before #2363 the INSERTION path was NOT:
// a TCP control segment (SYN/SYN-ACK/FIN/RST) that produced a
// ForwardCandidate decision would seed a cache entry, and a later pure
// ACK on the same 5-tuple would then take the cache fast path and skip
// the session lookup that observes/advances TCP closing state. The fix
// folds `Self::packet_eligible(meta)` into `should_cache` so admission
// and lookup share a single eligibility predicate.
//
// Fail-on-revert: removing the `packet_eligible` gate from
// `should_cache` makes the SYN/SYN-ACK/FIN+ACK/RST+ACK rows below flip
// to cacheable -> these asserts go red.
// ----------------------------------------------------------------

/// Build a v4 TCP meta carrying the given raw `tcp_flags`.
fn make_tcp_meta_flags(tcp_flags: u8) -> UserspaceDpMeta {
    UserspaceDpMeta {
        protocol: PROTO_TCP,
        addr_family: libc::AF_INET as u8,
        ingress_ifindex: 7,
        tcp_flags,
        ..Default::default()
    }
}

#[test]
fn should_cache_admits_only_packet_eligible_segments() {
    use crate::tcp_flags::{TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN};
    let decision = make_decision(ForwardingDisposition::ForwardCandidate);

    // (flags, label, expected_cacheable)
    let tcp_cases: [(u8, &str, bool); 6] = [
        (TCP_SYN, "SYN", false),
        (TCP_SYN | TCP_ACK, "SYN-ACK", false),
        (TCP_FIN | TCP_ACK, "FIN+ACK", false),
        (TCP_RST | TCP_ACK, "RST+ACK", false),
        (TCP_ACK, "ACK", true),
        (TCP_PSH | TCP_ACK, "PSH+ACK", true),
    ];
    for (flags, label, want) in tcp_cases {
        let meta = make_tcp_meta_flags(flags);
        assert_eq!(
            FlowCacheEntry::should_cache(meta, decision),
            want,
            "TCP {label} (flags={flags:#x}) should_cache mismatch (want cacheable={want})",
        );
        // packet_eligible is the SSOT the lookup path uses; assert the
        // two predicates agree for every TCP case.
        assert_eq!(
            FlowCacheEntry::packet_eligible(meta),
            want,
            "TCP {label}: packet_eligible must match should_cache admission",
        );
    }

    // UDP is always eligible regardless of the (ignored) tcp_flags byte.
    let udp = UserspaceDpMeta {
        protocol: PROTO_UDP,
        addr_family: libc::AF_INET as u8,
        ingress_ifindex: 7,
        tcp_flags: 0,
        ..Default::default()
    };
    assert!(
        FlowCacheEntry::should_cache(udp, decision),
        "UDP ForwardCandidate must remain cacheable (no over-gate)",
    );
}

#[test]
fn from_forward_decision_declines_tcp_control_segments() {
    use crate::tcp_flags::{TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN};
    // Control segments must NOT seed a cache entry; steady-state
    // ACK/PSH+ACK still build one. Fail-on-revert: dropping the
    // packet_eligible gate makes the first three rows return Some.
    let control: [(u8, &str); 4] = [
        (TCP_SYN, "SYN"),
        (TCP_SYN | TCP_ACK, "SYN-ACK"),
        (TCP_FIN | TCP_ACK, "FIN+ACK"),
        (TCP_RST | TCP_ACK, "RST+ACK"),
    ];
    for (flags, label) in control {
        let (flow, mut meta, validation, decision, forwarding, ha_state) =
            make_v4_round_trip_inputs();
        meta.tcp_flags = flags;
        let entry = try_build_entry(&flow, meta, validation, decision, &forwarding, &ha_state);
        assert!(
            entry.is_none(),
            "TCP {label} control segment must not seed a flow-cache entry",
        );
    }

    // Steady-state data still caches (no over-gate on PSH+ACK).
    for (flags, label) in [(TCP_ACK, "ACK"), (TCP_PSH | TCP_ACK, "PSH+ACK")] {
        let (flow, mut meta, validation, decision, forwarding, ha_state) =
            make_v4_round_trip_inputs();
        meta.tcp_flags = flags;
        let entry = try_build_entry(&flow, meta, validation, decision, &forwarding, &ha_state);
        assert!(
            entry.is_some(),
            "established-TCP {label} must still be cacheable",
        );
    }
}

#[test]
fn flow_cache_not_populated_by_control_segment_via_insertion_site() {
    use crate::tcp_flags::{TCP_ACK, TCP_FIN, TCP_RST};
    // Mirror the production insertion site (poll_descriptor/mod.rs ~2607):
    //   if let Some(entry) = from_forward_decision(..) { flow_cache.insert(entry) }
    // A FIN/RST slow-path packet must leave the worker-owned flow cache
    // untouched; a subsequent pure-ACK on the same 5-tuple must be the one
    // that seeds the entry. Fail-on-revert: without the packet_eligible
    // gate, the FIN/RST insert below populates the cache and the first
    // assert goes red.
    let lookup_for = |meta: UserspaceDpMeta, validation: ValidationState, key: &_| {
        let _ = key;
        FlowCacheLookup {
            ingress_ifindex: meta.ingress_ifindex as i32,
            logical_ingress_ifindex: meta.ingress_ifindex as i32,
            config_generation: validation.config_generation,
            fib_generation: validation.fib_generation,
        }
    };

    for control_flags in [TCP_FIN | TCP_ACK, TCP_RST | TCP_ACK] {
        let mut cache = FlowCache::new();
        let rg_epochs = default_rg_epochs();
        let (flow, mut meta, validation, decision, forwarding, ha_state) =
            make_v4_round_trip_inputs();
        let key = flow.forward_key.clone();
        let lookup = lookup_for(meta, validation, &key);

        // Control segment: production gate declines, nothing inserted.
        meta.tcp_flags = control_flags;
        if let Some(entry) =
            try_build_entry(&flow, meta, validation, decision, &forwarding, &ha_state)
        {
            cache.insert(entry);
        }
        assert!(
            cache.lookup(&key, lookup, 0, &rg_epochs).is_none(),
            "control segment (flags={control_flags:#x}) must not populate flow_cache",
        );

        // Follow-up pure ACK on the same tuple: now it caches.
        meta.tcp_flags = TCP_ACK;
        if let Some(entry) =
            try_build_entry(&flow, meta, validation, decision, &forwarding, &ha_state)
        {
            cache.insert(entry);
        }
        assert!(
            cache.lookup(&key, lookup, 0, &rg_epochs).is_some(),
            "established pure-ACK follow-up must seed the flow_cache entry",
        );
    }
}

// ---- #2364: seeded flow-cache set index ------------------------------

    /// Build N distinct v4 5-tuples differing only in src_port. These are
    /// trivially attacker-constructible (one source, one ephemeral range).
    fn adversarial_keys(n: u16) -> Vec<crate::session::SessionKey> {
        (0..n)
            .map(|i| crate::session::SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 40000u16.wrapping_add(i),
                dst_port: 443,
                            discriminator: Default::default(),
                            routing_domain: 0,
            })
            .collect()
    }

    /// Set distribution = the multiset of set indices for a key list under
    /// a given seed. Equal vectors ⇒ identical mapping.
    fn set_distribution(seed: u64, keys: &[crate::session::SessionKey]) -> Vec<usize> {
        keys.iter()
            .map(|k| FlowCache::set_index_seeded(seed, k, 7))
            .collect()
    }

    #[test]
    fn set_index_is_stable_within_one_seed() {
        // Cache-consistency invariant: a given flow must map to the SAME
        // set every time within one process, or lookup/insert disagree
        // and the cache silently misses. Repeat many times under a fixed
        // seed and demand byte-identical results.
        let keys = adversarial_keys(64);
        let seed = 0x0123_4567_89AB_CDEF;
        let first = set_distribution(seed, &keys);
        for _ in 0..256 {
            assert_eq!(
                first,
                set_distribution(seed, &keys),
                "set_index must be stable for a fixed seed (cache consistency)"
            );
        }
    }

    #[test]
    fn set_index_distribution_depends_on_seed() {
        // Hardening invariant: the set mapping is NOT an externally
        // probeable pure function of the 5-tuple. Two different process
        // seeds must produce a DIFFERENT set distribution for the SAME
        // attacker key set — so an offline attacker cannot precompute a
        // colliding key set. (With the unseeded `FxHasher::default()` the
        // distribution is seed-independent and this assertion fails —
        // fail-on-revert.)
        let keys = adversarial_keys(128);
        let ref_seed = 0xA5A5_0000_C3C3_FFFFu64;
        let reference = set_distribution(ref_seed, &keys);

        // Scan seeds for a divergence. Under a uniform hash the chance
        // that an entire 128-element distribution matches the reference by
        // accident is ~ (1/1024)^? — vanishingly small per seed; one
        // differing seed is essentially guaranteed immediately. Bound the
        // loop so a TRULY seed-independent hash (the reverted state) makes
        // this test FAIL rather than hang.
        let mut diverged = false;
        for seed in 1u64..4096u64 {
            if seed == ref_seed {
                continue;
            }
            if set_distribution(seed, &keys) != reference {
                diverged = true;
                break;
            }
        }
        assert!(
            diverged,
            "flow-cache set distribution did not change across {} seeds — \
             set_index is seed-independent (unseeded FxHash regression, #2364)",
            4095
        );
    }

    #[test]
    fn set_index_seed_reshuffles_collision_set() {
        // Concrete attack framing: take the keys that all land in ONE set
        // under seed A, then show that under seed B they no longer all
        // share a set. Proves the per-boot reseed defeats a precomputed
        // single-set flood. Use a large enough key pool that some set is
        // guaranteed to hold >=2 keys (4096 keys into 1024 sets ⇒ mean 4
        // per set, max well above 2 under any reasonable hash).
        let keys = adversarial_keys(4096);
        let seed_a = 0xDEAD_BEEF_CAFE_BABEu64;
        // Find the most-populated set under seed A.
        let mut counts: std::collections::BTreeMap<usize, Vec<crate::session::SessionKey>> =
            std::collections::BTreeMap::new();
        for k in &keys {
            counts
                .entry(FlowCache::set_index_seeded(seed_a, k, 7))
                .or_default()
                .push(k.clone());
        }
        let (_, hot_set_keys) = counts
            .into_iter()
            .max_by_key(|(_, v)| v.len())
            .expect("at least one set");
        assert!(
            hot_set_keys.len() >= 2,
            "test precondition: need >=2 keys colliding in one set under seed A"
        );
        // Under a different seed, those same keys must NOT all collide in
        // a single set (otherwise the reseed bought nothing).
        let seed_b = seed_a ^ 0xFFFF_FFFF_FFFF_FFFF;
        let distinct_under_b: std::collections::BTreeSet<usize> = hot_set_keys
            .iter()
            .map(|k| FlowCache::set_index_seeded(seed_b, k, 7))
            .collect();
        assert!(
            distinct_under_b.len() > 1,
            "keys colliding in one set under seed A still all collide under seed B — \
             reseed did not break the precomputed flood (#2364)"
        );
    }

// ── #3048/#5147: cached dst_mac eviction on the flow's OWN neighbor ────
// End-to-end at the flow-cache layer: a descriptor is stamped with the
// per-shard MAC-change epoch of its OWN next-hop neighbor at insert. The
// worker fast path keeps the entry while that shard's epoch is unchanged
// (same-MAC refresh) and evicts it once the neighbor table records a
// genuine MAC change to THIS neighbor. This is the #5147 over-eviction
// guard IN REVERSE — it proves the targeted scheme still evicts on a real
// change to the flow's own neighbor (preserving #3048). Reverting the
// `bump_shard_epoch` in ShardedNeighborMap::insert_if_changed leaves the
// shard epoch at 0 after the change → neighbor_mac_epoch_stale() returns
// false → the stale dst_mac persists → this test goes RED.
#[test]
fn cached_descriptor_evicted_only_on_neighbor_mac_change() {
    use crate::afxdp::sharded_neighbor::ShardedNeighborMap;
    use crate::afxdp::types::NeighborEntry;
    use std::net::Ipv4Addr;

    let neighbors = ShardedNeighborMap::new();
    let nh = (6i32, IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1)));
    // Resolve the gateway with its initial MAC (first insert — no bump).
    neighbors.insert_if_changed(nh, NeighborEntry { mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01] });

    // Build a cached forwarding descriptor and stamp it against the flow's
    // OWN next-hop shard exactly as poll_descriptor / from_forward_decision
    // do at insert time (shard of `nh`, that shard's current epoch).
    let stamp = FlowCacheStamp {
        config_generation: 5,
        fib_generation: 3,
        owner_rg_id: 1,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    let mut entry = make_entry(make_key(), stamp, 1);
    entry.neighbor_shard = ShardedNeighborMap::shard_index(&nh) as u16;
    entry.neighbor_mac_epoch = neighbors.mac_change_epoch_for(&nh);

    // Steady state: a same-MAC ARP/NDP refresh must NOT evict the entry.
    neighbors.insert_if_changed(nh, NeighborEntry { mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01] });
    assert!(
        !entry.neighbor_mac_epoch_stale(&neighbors),
        "same-MAC refresh must not evict the cached descriptor (#3048)"
    );

    // Gateway VRRP failover: the flow's OWN neighbor MAC changes. The cached
    // dst_mac is now stale and the entry MUST be evicted so the next packet
    // re-resolves the current MAC (#3048 preserved under the #5147 scheme).
    neighbors.insert_if_changed(nh, NeighborEntry { mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x99] });
    assert!(
        entry.neighbor_mac_epoch_stale(&neighbors),
        "a MAC change to the flow's own neighbor must evict its stale dst_mac (#3048)"
    );
}

// ── #5147: TARGETED invalidation — an unrelated neighbor's MAC change ──
// must NOT evict a cached flow using a different neighbor. This is the
// primary fail-on-revert guard for the map-wide-thrash / DoS fix: under
// the old single global epoch BOTH flows stamped and compared the ONE
// counter, so changing neighbor A's MAC advanced it and evicted F_b too —
// the `!f_b...` assertion below would go RED. With per-shard epochs, A's
// change bumps only A's shard, leaving F_b (a different shard) a cache
// hit. It exercises the REAL primitives (ShardedNeighborMap per-shard
// bump + shard_index stamping + neighbor_mac_epoch_stale).
#[test]
fn unrelated_neighbor_mac_change_does_not_evict_cached_flow() {
    use crate::afxdp::sharded_neighbor::ShardedNeighborMap;
    use crate::afxdp::types::NeighborEntry;
    use std::net::Ipv4Addr;

    let neighbors = ShardedNeighborMap::new();

    // Two neighbors A and B guaranteed to live in DIFFERENT shards, so a
    // change to one cannot touch the other's shard epoch.
    let (na, nb) = {
        let a = (6i32, IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1)));
        let base_shard = ShardedNeighborMap::shard_index(&a);
        let mut b = None;
        for octet in 2..=254u8 {
            let cand = (6i32, IpAddr::V4(Ipv4Addr::new(172, 16, 50, octet)));
            if ShardedNeighborMap::shard_index(&cand) != base_shard {
                b = Some(cand);
                break;
            }
        }
        (a, b.expect("distinct-shard neighbor B exists"))
    };
    neighbors.insert_if_changed(na, NeighborEntry { mac: [0xaa, 0, 0, 0, 0, 0x01] });
    neighbors.insert_if_changed(nb, NeighborEntry { mac: [0xbb, 0, 0, 0, 0, 0x02] });

    let stamp = FlowCacheStamp {
        config_generation: 5,
        fib_generation: 3,
        owner_rg_id: 1,
        owner_rg_epoch: 0,
        owner_rg_lease_until: 0,
    };
    // F_a depends on neighbor A; F_b on neighbor B.
    let mut f_a = make_entry(make_key(), stamp, 1);
    f_a.neighbor_shard = ShardedNeighborMap::shard_index(&na) as u16;
    f_a.neighbor_mac_epoch = neighbors.mac_change_epoch_for(&na);
    let mut f_b = make_entry(make_key(), stamp, 1);
    f_b.neighbor_shard = ShardedNeighborMap::shard_index(&nb) as u16;
    f_b.neighbor_mac_epoch = neighbors.mac_change_epoch_for(&nb);

    // Neighbor A's MAC flaps (an on-link sender alternating one IP's MAC).
    neighbors.insert_if_changed(na, NeighborEntry { mac: [0xaa, 0, 0, 0, 0, 0x99] });

    // F_a (uses A) is invalidated → re-resolves.
    assert!(
        f_a.neighbor_mac_epoch_stale(&neighbors),
        "a MAC change to A must evict a flow that uses A (#3048)"
    );
    // F_b (uses B) is STILL a cache hit — NOT evicted. RED under the old
    // global epoch (the map-wide-thrash defect).
    assert!(
        !f_b.neighbor_mac_epoch_stale(&neighbors),
        "a MAC change to an UNRELATED neighbor A must NOT evict a flow that \
         uses neighbor B (#5147 targeted invalidation)"
    );
}

// ── #3918: resolve→stamp TOCTOU (re-opens the #3048 stale-MAC blackhole) ──
// poll_descriptor resolves the next-hop neighbor MAC, then builds + stamps a
// flow-cache entry with the neighbor mac_change_epoch. The stamp MUST use the
// epoch SNAPSHOTTED BEFORE the resolve — not a fresh read at stamp time. If a
// VRRP gateway failover REPLACES the gateway MAC in the window between the
// resolve (which read the OLD MAC) and the stamp, a post-resolve read captures
// the NEW epoch and stamps it onto the cached OLD dst_mac: the entry's epoch
// then EQUALS the live epoch, so `neighbor_mac_epoch_stale` returns false, the
// stale dst_mac is served on every fast-path hit, and traffic blackholes to
// the dead gateway until the entry ages out.
//
// The fix threads the pre-resolve snapshot into `from_forward_decision`
// (`neighbor_mac_epoch` value param) so the constructor cannot re-read the live
// epoch. This test models the interleaved failover with the real primitives
// (ShardedNeighborMap.insert_if_changed's genuine mac_change_epoch bump +
// FlowCacheEntry.neighbor_mac_epoch_stale) and asserts the pre-resolve stamp is
// correctly treated stale. RED-ON-REVERT: reverting the fix (dropping the param
// + re-reading mac_change_epoch() at stamp time, i.e. AFTER the failover bump
// modeled here) makes the stamped epoch equal the live epoch -> not stale ->
// the blackhole; the explicit post-resolve-read contrast below encodes exactly
// that failing state.
#[test]
fn flow_cache_stamps_pre_resolve_epoch_survives_interleaved_gateway_failover() {
    use crate::afxdp::sharded_neighbor::ShardedNeighborMap;
    use crate::afxdp::types::NeighborEntry;

    let neighbors = ShardedNeighborMap::new();
    // The next-hop MUST match the round-trip decision's resolved next-hop
    // (`egress_ifindex=6`, `next_hop=10.0.1.1`) so `from_forward_decision`
    // stamps THIS neighbor's shard and the failover below bumps that same
    // shard.
    let nh = (6i32, IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)));
    // Gateway resolved with its pre-failover MAC (first insert — no bump).
    neighbors.insert_if_changed(nh, NeighborEntry { mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01] });

    // poll_descriptor snapshots EVERY shard's epoch BEFORE resolving the
    // neighbor MAC (the resolved shard is not yet known).
    let pre_resolve_snapshot = neighbors.snapshot_shard_epochs();

    // ── Interleaved VRRP gateway failover ──
    // A kernel ARP/NDP update REPLACES the gateway MAC AFTER the resolve read
    // the old MAC but BEFORE the flow-cache entry is stamped. This advances the
    // neighbor's shard epoch past the pre-resolve snapshot.
    neighbors.insert_if_changed(nh, NeighborEntry { mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x99] });
    assert_ne!(
        pre_resolve_snapshot.epoch_for(&nh),
        neighbors.mac_change_epoch_for(&nh),
        "the interleaved failover must advance the neighbor's shard epoch past \
         the pre-resolve snapshot (otherwise the test proves nothing)"
    );

    // Build + stamp the flow-cache entry exactly as poll_descriptor does after
    // the resolve: it stamps the resolved shard's PRE-RESOLVE snapshot value
    // (`neighbor_mac_epoch` param), NOT a fresh post-resolve read.
    let (flow, meta, validation, decision, forwarding, ha_state) = make_v4_round_trip_inputs();
    let rg_epochs = default_rg_epochs();
    let entry = FlowCacheEntry::from_forward_decision(
        &flow,
        meta,
        validation,
        decision,
        1,
        Some(3),
        Some(7),
        None,
        crate::filter::CachedFilterCounters::default(),
        &forwarding,
        &ha_state,
        false,
        &rg_epochs,
        pre_resolve_snapshot.epoch_for(&nh), // #3918: pre-resolve shard value
    )
    .expect("v4 round-trip decision is cacheable");

    // On the NEXT fast-path hit the entry's stamped (pre-failover) shard epoch
    // != the current live shard epoch -> treated STALE -> evicted + re-resolved
    // to the new MAC. This is the fix.
    assert!(
        entry.neighbor_mac_epoch_stale(&neighbors),
        "an entry stamped with the pre-resolve shard epoch must be stale after an \
         interleaved gateway-MAC failover so the stale dst_mac is re-resolved (#3918)"
    );

    // Contrast: the pre-#3918 behavior read the epoch AFTER the resolve (i.e.
    // after the failover bump modeled above). That post-resolve shard value
    // EQUALS the current live shard epoch, so the stale entry looks FRESH and is
    // never evicted — the blackhole. Encoding it here makes the revert's failure
    // mode explicit and guards against a regression that re-reads at stamp time.
    let post_resolve_snapshot = neighbors.snapshot_shard_epochs();
    let buggy_entry = FlowCacheEntry::from_forward_decision(
        &flow,
        meta,
        validation,
        decision,
        1,
        Some(3),
        Some(7),
        None,
        crate::filter::CachedFilterCounters::default(),
        &forwarding,
        &ha_state,
        false,
        &rg_epochs,
        post_resolve_snapshot.epoch_for(&nh),
    )
    .expect("v4 round-trip decision is cacheable");
    assert!(
        !buggy_entry.neighbor_mac_epoch_stale(&neighbors),
        "a POST-resolve stamp (the pre-#3918 bug) looks fresh after failover — \
         this is the stale-MAC blackhole the fix closes (#3918)"
    );
}

// #3918 companion: the normal (no-interleave) resolve must still cache and
// serve. A pre-resolve epoch snapshot taken with no intervening MAC change
// equals the live epoch on the next hit, so the entry is NOT evicted — the fix
// must not spuriously flush steady-state flows.
#[test]
fn flow_cache_normal_resolve_caches_and_serves_neighbor_mac() {
    use crate::afxdp::sharded_neighbor::ShardedNeighborMap;
    use crate::afxdp::types::NeighborEntry;

    let neighbors = ShardedNeighborMap::new();
    // Match the round-trip decision's resolved next-hop (egress_ifindex=6,
    // next_hop=10.0.1.1) so the stamped shard matches the mutated neighbor.
    let nh = (6i32, IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)));
    neighbors.insert_if_changed(nh, NeighborEntry { mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01] });

    // Snapshot pre-resolve; NO failover interleaves.
    let pre_resolve_snapshot = neighbors.snapshot_shard_epochs();

    let (flow, meta, validation, decision, forwarding, ha_state) = make_v4_round_trip_inputs();
    let rg_epochs = default_rg_epochs();
    let entry = FlowCacheEntry::from_forward_decision(
        &flow,
        meta,
        validation,
        decision,
        1,
        Some(3),
        Some(7),
        None,
        crate::filter::CachedFilterCounters::default(),
        &forwarding,
        &ha_state,
        false,
        &rg_epochs,
        pre_resolve_snapshot.epoch_for(&nh),
    )
    .expect("v4 round-trip decision is cacheable");

    // A same-MAC refresh does not advance the shard epoch, so the entry stays
    // fresh.
    neighbors.insert_if_changed(nh, NeighborEntry { mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01] });
    assert!(
        !entry.neighbor_mac_epoch_stale(&neighbors),
        "a normal resolve with no interleaved MAC change must serve the cached \
         entry, not spuriously evict it (#3918)"
    );
}

// ── #5147 review MAJOR: TUNNEL-egress flows must key the MAC-change shard on
// the OUTER neighbor ifindex, not the logical tunnel egress_ifindex ──
// A GRE/WireGuard flow resolves its dst_mac from the OUTER transport neighbor,
// which the kernel keys (and `insert_if_changed` bumps) under
// `(outer.egress_ifindex, outer_next_hop)`. But the flow-cache entry stamps a
// `neighbor_shard`; if it derives that shard from the LOGICAL tunnel
// `egress_ifindex` (gr-/wg-, != the outer ifindex), the stamped shard never
// advances on the outer gateway's MAC change -> `neighbor_mac_epoch_stale`
// stays false forever -> the cached descriptor serves the dead gateway MAC
// until idle timeout (a #3048 stale-MAC blackhole reintroduced for tunnels by
// the naive per-shard #5147 change). The fix keys the shard on
// `outer_neighbor_ifindex(.., None, ..)`, which returns the outer ifindex for a
// tunnel and `egress_ifindex` for a direct resolution.
//
// RED-ON-REVERT: this test pins the flow_cache `neighbor_shard` STAMP site
// (it sets the resolve-time `neighbor_mac_epoch = 0` directly, so it does not
// exercise the poll_descriptor pre-resolve epoch-snapshot site). Reverting the
// flow_cache stamp to `decision.resolution.egress_ifindex` makes
// `entry.neighbor_shard` the LOGICAL (362) shard, so (1) the structural assert
// fails (shard != outer shard) and (2) the behavioral assert fails (a bump on
// the OUTER shard leaves the logical shard's epoch untouched -> not stale -> no
// eviction). The poll_descriptor epoch-snapshot site is keyed identically by
// construction (the same `outer_neighbor_ifindex(.., None, ..)` call on the
// same `&decision.resolution`); an independent fail-on-revert test for that
// second site is a follow-up (#5147 review nit).
#[test]
fn tunnel_flow_cache_keys_mac_change_shard_on_outer_neighbor_not_logical_ifindex() {
    use crate::afxdp::sharded_neighbor::ShardedNeighborMap;
    use crate::afxdp::types::NeighborEntry;

    // GRE state: tunnel endpoint 1 -> logical ifindex 362 (gr-0-0-0), outer
    // transport egress ifindex 12 (reth0.80 VLAN subif). See
    // forwarding/tests.rs resolve_tunnel_outer_returns_outer_l3_egress.
    let forwarding =
        crate::afxdp::forwarding_build::build_forwarding_state(
            &crate::afxdp::test_fixtures::native_gre_snapshot(true),
        );

    // A cacheable v4 forward decision, retargeted as a TUNNEL egress: keep its
    // resolved next-hop + neighbor_mac + ForwardCandidate disposition, but mark
    // it tunnel endpoint 1 with the LOGICAL egress ifindex (362) — exactly what
    // resolve_tunnel_forwarding_resolution produces.
    let (flow, meta, validation, mut decision, _direct_forwarding, ha_state) =
        make_v4_round_trip_inputs();
    decision.resolution.tunnel_endpoint_id = 1;
    decision.resolution.egress_ifindex = 362;
    let nh = decision
        .resolution
        .next_hop
        .expect("a cacheable forward decision carries a resolved next-hop");

    // The neighbor's ACTUAL key ifindex is the OUTER transport ifindex (12),
    // NOT the logical tunnel egress (362).
    let outer_if =
        crate::afxdp::forwarding::outer_neighbor_ifindex(&forwarding, None, &decision.resolution);
    assert_eq!(
        outer_if, 12,
        "outer_neighbor_ifindex must resolve tunnel endpoint 1 to its OUTER \
         transport ifindex (12), not the logical tunnel egress (362)"
    );
    let outer_shard = ShardedNeighborMap::shard_index(&(outer_if, nh)) as u16;
    let logical_shard = ShardedNeighborMap::shard_index(&(362, nh)) as u16;
    assert_ne!(
        outer_shard, logical_shard,
        "test precondition: the outer (12) and logical (362) ifindexes must hash \
         to DIFFERENT shards for this next-hop, else the test cannot distinguish \
         the bug from the fix"
    );

    let rg_epochs = default_rg_epochs();
    // Stamp the pre-resolve epoch as 0 (a fresh map's baseline); the entry
    // derives its neighbor_shard internally via outer_neighbor_ifindex.
    let entry = FlowCacheEntry::from_forward_decision(
        &flow,
        meta,
        validation,
        decision,
        1,
        Some(3),
        Some(7),
        None,
        crate::filter::CachedFilterCounters::default(),
        &forwarding,
        &ha_state,
        false,
        &rg_epochs,
        0, // #3918 pre-resolve shard epoch (outer shard baseline == 0)
    )
    .expect("a tunnel ForwardCandidate decision is cacheable");

    // STRUCTURAL: the entry stamps the OUTER neighbor's shard, not the logical.
    assert_eq!(
        entry.neighbor_shard, outer_shard,
        "a tunnel flow must stamp the OUTER neighbor's shard (ifindex {outer_if}); \
         stamping the logical tunnel egress ifindex (362) means the flow never \
         evicts on the outer gateway's MAC change (#5147 review MAJOR / #3048)"
    );
    assert_ne!(
        entry.neighbor_shard, logical_shard,
        "the stamped shard must NOT be the logical tunnel egress shard"
    );

    // BEHAVIORAL: a MAC change on the OUTER neighbor evicts the tunnel flow.
    let neighbors = ShardedNeighborMap::new();
    assert!(
        !entry.neighbor_mac_epoch_stale(&neighbors),
        "a freshly-stamped entry (epoch 0) is not stale against a fresh map"
    );
    // First insert = no bump; a REPLACE with a different MAC bumps the OUTER
    // neighbor's shard (the gateway VRRP-failover event).
    neighbors.insert_if_changed(
        (outer_if, nh),
        NeighborEntry { mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01] },
    );
    neighbors.insert_if_changed(
        (outer_if, nh),
        NeighborEntry { mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x99] },
    );
    assert!(
        entry.neighbor_mac_epoch_stale(&neighbors),
        "the tunnel flow MUST be evicted after its OUTER gateway's MAC change — \
         keying the shard on the logical egress ifindex leaves the logical shard's \
         epoch untouched by the outer bump, so the stale dst_mac would be served \
         forever (#5147 review MAJOR)"
    );
}
