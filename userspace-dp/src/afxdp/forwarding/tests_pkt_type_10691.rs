use super::*;
use crate::afxdp::test_fixtures::{nat_snapshot, nat_snapshot_with_fabric};
use crate::afxdp::tests_support::{
    gre_to_self_snapshot,
    TEST_LAN_MAC, build_txn_tcp_syn_frame_v4, build_txn_tcp_syn_frame_v6, txn_ha_state,
    txn_meta_v4, txn_meta_v6, txn_run_descriptor,
};

const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 102);
const SERVER: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const CLIENT_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0559, 0x8585, 0xef00, 0, 0, 0, 0x102);
const SERVER_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);

fn run_lan_transit_10691(
    snapshot: &ConfigSnapshot,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dst_mac: [u8; 6],
) -> (BatchCounters, DebugPollCounters, usize, Vec<u64>) {
    let forwarding = build_forwarding_state(snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let frame = build_txn_tcp_syn_frame_v4(
        CLIENT,
        SERVER,
        40_000,
        443,
        TCP_FLAG_SYN,
        dst_mac,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let (batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        ha_state,
        &frame,
        meta,
    );
    (batch, dbg, sessions.len(), binding.scratch.scratch_recycle)
}

fn run_lan_transit_v6_10691(
    snapshot: &ConfigSnapshot,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dst_mac: [u8; 6],
) -> (BatchCounters, DebugPollCounters, usize, Vec<u64>) {
    let forwarding = build_forwarding_state(snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let frame = build_txn_tcp_syn_frame_v6(
        CLIENT_V6,
        SERVER_V6,
        40_000,
        443,
        dst_mac,
    );
    let meta = txn_meta_v6(24, frame.len());
    let (batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        ha_state,
        &frame,
        meta,
    );
    (batch, dbg, sessions.len(), binding.scratch.scratch_recycle)
}

fn peer_owns_wan_rg_10691() -> BTreeMap<i32, HAGroupRuntime> {
    let mut ha_state = txn_ha_state();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    ha_state.insert(
        1,
        HAGroupRuntime {
            active: false,
            watchdog_timestamp: now_secs,
            lease: HAForwardingLease::Inactive,
        },
    );
    ha_state
}

/// Group MACs are accepted at the pre-L3 MAC guard for ARP, multicast, and
/// local-delivery classification. That is not permission to transit unicast-IP
/// traffic: unlike a PACKET_HOST control, L2 broadcast/multicast IPv4 unicast
/// must drop before it can create a session or reach a direct forward.
///
/// FAIL-ON-REVERT: removing the transit packet-type gate forwards both group
/// cases (and installs sessions), turning these assertions RED.
#[test]
fn non_host_l2_group_unicast_ipv4_drops_before_direct_forward_10691() {
    let snapshot = nat_snapshot();
    let ha_state = txn_ha_state();

    let (host_batch, host_dbg, host_sessions, _) =
        run_lan_transit_10691(&snapshot, &ha_state, TEST_LAN_MAC);
    assert_eq!(host_batch.validated_packets, 1);
    assert_eq!(host_dbg.tx, 1, "PACKET_HOST control must transit");
    assert_eq!(host_sessions, 2, "control installs forward/reverse sessions");

    for (label, dst_mac) in [
        ("broadcast", [0xff; 6]),
        ("multicast", [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]),
    ] {
        let (batch, dbg, sessions, recycled) =
            run_lan_transit_10691(&snapshot, &ha_state, dst_mac);
        assert_eq!(batch.validated_packets, 1, "{label} fixture must arrive");
        assert_eq!(batch.dst_mac_dropped, 0, "{label} reaches L3 disposition");
        assert_eq!(dbg.tx, 0, "{label} unicast-IP transit must not transmit");
        assert_eq!(dbg.forward, 0, "{label} must not enter forward accounting");
        assert_eq!(sessions, 0, "{label} must not install forward/reverse sessions");
        assert_eq!(recycled, vec![128], "{label} must recycle its input frame");
    }
}

/// The packet-type gate applies to unicast IP of either family while leaving
/// the existing PACKET_HOST transit path unchanged.
///
/// FAIL-ON-REVERT: removing the gate forwards the L2-broadcast IPv6 unicast.
#[test]
fn non_host_l2_group_unicast_ipv6_drops_before_direct_forward_10691() {
    let snapshot = nat_snapshot();
    let ha_state = txn_ha_state();

    let (host_batch, host_dbg, host_sessions, _) =
        run_lan_transit_v6_10691(&snapshot, &ha_state, TEST_LAN_MAC);
    assert_eq!(host_batch.validated_packets, 1);
    assert_eq!(host_dbg.tx, 1, "PACKET_HOST IPv6 control must transit");
    assert_eq!(host_sessions, 2);

    let (batch, dbg, sessions, recycled) =
        run_lan_transit_v6_10691(&snapshot, &ha_state, [0xff; 6]);
    assert_eq!(batch.validated_packets, 1, "fixture must arrive");
    assert_eq!(batch.dst_mac_dropped, 0, "frame reaches L3 disposition");
    assert_eq!(dbg.tx, 0, "L2-broadcast IPv6 unicast must not transmit");
    assert_eq!(dbg.forward, 0);
    assert_eq!(sessions, 0);
    assert_eq!(recycled, vec![128]);
}

/// FAIL-ON-REVERT: a peer-owned egress resolves to FabricRedirect. Without
/// the packet-type gate, the L2-broadcast copy is relayed to the fabric and
/// creates a second delivery on the owning node.
#[test]
fn non_host_l2_group_unicast_ip_drops_before_fabric_redirect_10691() {
    let snapshot = nat_snapshot_with_fabric();
    let ha_state = peer_owns_wan_rg_10691();
    let (batch, dbg, sessions, recycled) =
        run_lan_transit_10691(&snapshot, &ha_state, [0xff; 6]);
    assert_eq!(batch.validated_packets, 1, "fixture must arrive");
    assert_eq!(batch.dst_mac_dropped, 0, "frame reaches L3 disposition");
    assert_eq!(dbg.tx, 0, "non-PACKET_HOST must not be fabric-relayed");
    assert_eq!(dbg.forward, 0, "dropped copy must not enter forward accounting");
    assert_eq!(sessions, 0, "dropped copy must not install a session");
    assert_eq!(recycled, vec![128], "dropped frame must be recycled");
}

/// A flow-cache hit must not make a later L2-group-received copy eligible for
/// forwarding. The ACK controls make the third packet hit the established-flow
/// cache fast path rather than merely resolving the session again.
///
/// FAIL-ON-REVERT: removing the cached-hit gate lets the group ACK TX and
/// accounts it against the established session.
#[test]
fn non_host_l2_group_unicast_ip_drops_on_cached_hit_10691() {
    let forwarding = build_forwarding_state(&nat_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let make_frame = |dst_mac, tcp_flags| {
        build_txn_tcp_syn_frame_v4(
            CLIENT,
            SERVER,
            40_000,
            443,
            tcp_flags,
            dst_mac,
        )
    };

    let syn = make_frame(TEST_LAN_MAC, TCP_FLAG_SYN);
    let syn_meta = txn_meta_v4(24, TCP_FLAG_SYN, syn.len() as u16);
    let (syn_batch, syn_dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &syn,
        syn_meta,
    );
    assert_eq!(syn_batch.validated_packets, 1);
    assert_eq!(syn_dbg.tx, 1, "PACKET_HOST SYN must establish the session");
    assert_eq!(sessions.len(), 2);

    let ack = make_frame(TEST_LAN_MAC, crate::tcp_flags::TCP_ACK);
    let ack_meta = txn_meta_v4(24, crate::tcp_flags::TCP_ACK, ack.len() as u16);
    let (ack_batch, ack_dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &ack,
        ack_meta,
    );
    assert_eq!(ack_batch.validated_packets, 1);
    assert_eq!(ack_dbg.tx, 1, "PACKET_HOST ACK must be cacheable");
    assert_eq!(
        crate::afxdp::tests_support::txn_flow_cache_entries(&binding),
        1,
        "the established ACK must seed the flow-cache entry"
    );

    let group_ack = make_frame([0xff; 6], crate::tcp_flags::TCP_ACK);
    let group_ack_meta = txn_meta_v4(24, crate::tcp_flags::TCP_ACK, group_ack.len() as u16);
    let (group_batch, group_dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &group_ack,
        group_ack_meta,
    );
    assert_eq!(group_batch.validated_packets, 1);
    assert_eq!(group_batch.dst_mac_dropped, 0);
    assert_eq!(
        binding.flow.flow_cache.hits, 1,
        "the group ACK must reach the established-flow cache hit path"
    );
    assert_eq!(group_dbg.tx, 0, "flow-cache hit must not forward non-PACKET_HOST");
    assert_eq!(group_dbg.forward, 0);
    assert_eq!(sessions.len(), 2, "dropped copy must not create sessions");
    assert_eq!(binding.scratch.scratch_recycle, vec![128]);
}

#[test]
fn non_host_l2_group_unicast_ip_drops_on_session_hit_10691() {
    let forwarding = build_forwarding_state(&nat_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let host_frame = build_txn_tcp_syn_frame_v4(
        CLIENT,
        SERVER,
        40_000,
        443,
        TCP_FLAG_SYN,
        TEST_LAN_MAC,
    );
    let host_meta = txn_meta_v4(24, TCP_FLAG_SYN, host_frame.len() as u16);
    let (host_batch, host_dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &host_frame,
        host_meta,
    );
    assert_eq!(host_batch.validated_packets, 1);
    assert_eq!(host_dbg.tx, 1, "PACKET_HOST control must establish the session");
    assert_eq!(sessions.len(), 2);

    let group_frame = build_txn_tcp_syn_frame_v4(
        CLIENT,
        SERVER,
        40_000,
        443,
        TCP_FLAG_SYN,
        [0xff; 6],
    );
    let group_meta = txn_meta_v4(24, TCP_FLAG_SYN, group_frame.len() as u16);
    let (group_batch, group_dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &group_frame,
        group_meta,
    );
    assert_eq!(group_batch.validated_packets, 1);
    assert_eq!(group_batch.dst_mac_dropped, 0);
    assert_eq!(group_dbg.tx, 0, "session hit must not forward non-PACKET_HOST");
    assert_eq!(sessions.len(), 2, "dropped copy must not mutate sessions");
    assert_eq!(binding.scratch.scratch_recycle, vec![128]);
}

#[test]
fn l2_group_classifier_only_matches_unicast_ip_destination_10691() {
    let forwarding = build_forwarding_state(&nat_snapshot());
    let meta_for = |frame: &[u8]| txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let make_frame = |destination| {
        build_txn_tcp_syn_frame_v4(
            CLIENT,
            destination,
            40_000,
            443,
            TCP_FLAG_SYN,
            [0xff; 6],
        )
    };

    let unicast = make_frame(SERVER);
    assert!(ingress_l2_group_unicast_ip(
        &forwarding,
        &unicast,
        meta_for(&unicast),
    ));

    let multicast = make_frame(Ipv4Addr::new(224, 0, 0, 1));
    assert!(!ingress_l2_group_unicast_ip(
        &forwarding,
        &multicast,
        meta_for(&multicast),
    ));

    let limited_broadcast = make_frame(Ipv4Addr::BROADCAST);
    assert!(!ingress_l2_group_unicast_ip(
        &forwarding,
        &limited_broadcast,
        meta_for(&limited_broadcast),
    ));

    let directed_broadcast = make_frame(Ipv4Addr::new(10, 0, 61, 255));
    assert!(!ingress_l2_group_unicast_ip(
        &forwarding,
        &directed_broadcast,
        meta_for(&directed_broadcast),
    ));

    let frame_v6 = build_txn_tcp_syn_frame_v6(
        CLIENT_V6,
        SERVER_V6,
        40_000,
        443,
        [0xff; 6],
    );
    assert!(ingress_l2_group_unicast_ip(
        &forwarding,
        &frame_v6,
        txn_meta_v6(24, frame_v6.len()),
    ));
}

/// A permitted group-MAC unicast packet must not enter the pending-neighbor
/// replay queue: once the next hop resolves, retry must still produce no TX.
///
/// FAIL-ON-REVERT: without `MissingNeighbor` in the common L2 disposition gate,
/// the initial packet is seeded and buffered, then replay enqueues a TX.
#[test]
fn non_host_l2_group_unicast_missing_neighbor_drops_before_replay_10966() {
    let mut snapshot = gre_to_self_snapshot();
    snapshot.neighbors.clear();
    let mut forwarding = build_forwarding_state(&snapshot);
    let dst = Ipv4Addr::new(10, 0, 61, 50);
    assert_eq!(
        lookup_forwarding_for_ip(&forwarding, IpAddr::V4(dst)),
        ForwardingDisposition::MissingNeighbor,
        "fixture must route through an unresolved neighbor"
    );

    let ha_state = txn_ha_state();
    let mut bindings = vec![BindingWorker::new_for_mirror_test(0, 0, 24, 0)];
    bindings[0].interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let frame = build_txn_tcp_syn_frame_v4(
        CLIENT,
        dst,
        40_000,
        443,
        TCP_FLAG_SYN,
        [0xff; 6],
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let (batch, dbg) = txn_run_descriptor(
        &mut bindings[0],
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(batch.validated_packets, 1, "fixture must arrive");
    assert_eq!(batch.dst_mac_dropped, 0, "frame must reach L3 disposition");
    assert_eq!(dbg.tx, 0, "unresolved next hop cannot TX synchronously");
    let pending_count_before_resolution = bindings[0].pending_neigh.len();

    // Simulate the neighbor becoming reachable, then run the real deferred
    // retry path. The fixed gate leaves no group frame available to replay.
    forwarding.neighbors.insert(
        (24, IpAddr::V4(dst)),
        NeighborEntry {
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        },
    );
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut shared_recycles = Vec::new();
    let area = bindings[0].umem.area() as *const MmapArea;
    let (left, rest) = bindings.split_at_mut(0);
    let (binding, right) = rest.split_first_mut().expect("ingress binding");
    let mut retry_counters = BatchCounters::default();
    crate::afxdp::neighbor_dispatch::retry_pending_neigh(
        binding,
        left,
        0,
        right,
        &lookup,
        &mirror_targets,
        &forwarding,
        &dynamic_neighbors,
        None,
        123_000_000_100,
        // SAFETY: the pointer comes from this binding's Rc-backed UMEM; this
        // test is single-threaded and the split borrows are disjoint.
        unsafe { &*area },
        &mut shared_recycles,
        None,
        &mut retry_counters,
    );

    let retry_tx_requests: usize = bindings
        .iter()
        .map(|binding| {
            binding.tx_pipeline.pending_tx_prepared.len()
                + binding.tx_pipeline.pending_tx_local.len()
        })
        .sum();
    assert_eq!(
        retry_tx_requests, 0,
        "resolved-neighbor retry must not enqueue a transmit"
    );
    assert_eq!(
        bindings[0].pending_neigh.len(),
        0,
        "group frame must not remain in the pending-neighbor queue"
    );
    assert_eq!(
        pending_count_before_resolution, 0,
        "group frame must be dropped before it can be queued"
    );
    assert_eq!(sessions.len(), 0, "group frame must not seed a session");
    assert_eq!(
        bindings[0].scratch.scratch_recycle,
        vec![128],
        "the dropped group frame must be recycled"
    );
}
