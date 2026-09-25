//! #10689: transit must refuse source classes the Linux router refuses, even
//! under an explicit `application any` permit. Every RED cell exercises the
//! actual descriptor/poll path and proves the packet arrived with a usable
//! forward route; zero TX and zero forward/reverse sessions are the invariant.

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::NeighborSnapshot;
use crate::session::{SessionMetadata, SessionOrigin};
use crate::test_zone_ids::{TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const TRANSIT_V4_DST: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 200);
const TRANSIT_V6_DST: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0559, 0x8585, 0x0080, 0, 0, 0, 0x0200);
const LAN_V4_SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 100);
const LAN_V6_SRC: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0559, 0x8585, 0xef00, 0, 0, 0, 0x0102);

fn forwarding_10689() -> ForwardingState {
    let mut snapshot = nat_snapshot();
    // Keep the permit-any route path independent of NAT fragment handling.
    snapshot.source_nat_rules.clear();
    snapshot.neighbors.extend([
        NeighborSnapshot {
            interface: "ge-0-0-0.80".to_string(),
            ifindex: 12,
            family: "inet".to_string(),
            ip: TRANSIT_V4_DST.to_string(),
            mac: "00:aa:bb:cc:dd:ee".to_string(),
            state: "reachable".to_string(),
            router: false,
            link_local: false,
            ..Default::default()
        },
        NeighborSnapshot {
            interface: "ge-0-0-0.80".to_string(),
            ifindex: 12,
            family: "inet6".to_string(),
            ip: TRANSIT_V6_DST.to_string(),
            mac: "00:aa:bb:cc:dd:ef".to_string(),
            state: "reachable".to_string(),
            router: false,
            link_local: false,
            ..Default::default()
        },
    ]);
    build_forwarding_state(&snapshot)
}

fn run_v4_source_10689(source: Ipv4Addr) {
    let forwarding = forwarding_10689();
    assert_eq!(
        lookup_forwarding_resolution(&forwarding, IpAddr::V4(TRANSIT_V4_DST)).disposition,
        ForwardingDisposition::ForwardCandidate,
        "fixture must have a live transit route independent of source class"
    );
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let frame = build_txn_tcp_syn_frame_v4(
        source,
        TRANSIT_V4_DST,
        54321,
        443,
        TCP_FLAG_SYN,
        TEST_LAN_MAC,
    );
    let mut meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    meta.flow_src_addr[..4].copy_from_slice(&source.octets());
    meta.flow_dst_addr[..4].copy_from_slice(&TRANSIT_V4_DST.octets());
    meta.flow_src_port = 54321;
    meta.flow_dst_port = 443;
    let (batch, debug) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );
    assert_martian_source_drop_10689(&sessions, &binding, &batch, &debug);
}

fn run_v4_flowless_source_10689(source: Ipv4Addr, missing_neighbor: bool) {
    let forwarding = if missing_neighbor {
        let mut snapshot = nat_snapshot();
        snapshot.source_nat_rules.clear();
        snapshot.neighbors.clear();
        build_forwarding_state(&snapshot)
    } else {
        forwarding_10689()
    };
    let expected = if missing_neighbor {
        ForwardingDisposition::MissingNeighbor
    } else {
        ForwardingDisposition::ForwardCandidate
    };
    assert_eq!(
        lookup_forwarding_resolution(&forwarding, IpAddr::V4(TRANSIT_V4_DST)).disposition,
        expected,
        "fragment fixture must reach the intended transit disposition"
    );

    let mut frame = frag_v4_transit_frame(TEST_LAN_MAC);
    frame[26..30].copy_from_slice(&source.octets());
    let mut meta = frag_v4_transit_meta();
    meta.flow_src_addr[..4].copy_from_slice(&source.octets());
    meta.flow_dst_addr[..4].copy_from_slice(&TRANSIT_V4_DST.octets());

    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let (batch, debug) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );
    assert_martian_source_drop_10689(&sessions, &binding, &batch, &debug);
}

#[test]
fn transit_drops_ipv4_unspecified_source_10689() {
    run_v4_source_10689(Ipv4Addr::UNSPECIFIED);
}

#[test]
fn transit_drops_flowless_ipv4_unspecified_source_10689() {
    run_v4_flowless_source_10689(Ipv4Addr::UNSPECIFIED, false);
}

#[test]
fn transit_drops_flowless_ipv4_unspecified_before_missing_neighbor_10689() {
    run_v4_flowless_source_10689(Ipv4Addr::UNSPECIFIED, true);
}

fn run_v6_source_10689(source: Ipv6Addr) {
    let forwarding = forwarding_10689();
    assert_eq!(
        lookup_forwarding_resolution(&forwarding, IpAddr::V6(TRANSIT_V6_DST)).disposition,
        ForwardingDisposition::ForwardCandidate,
        "fixture must have a live transit route independent of source class"
    );
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let frame = build_txn_tcp_syn_frame_v6(
        source,
        TRANSIT_V6_DST,
        54321,
        443,
        TEST_LAN_MAC,
    );
    let mut meta = txn_meta_v6(24, frame.len());
    meta.flow_src_addr = source.octets();
    meta.flow_dst_addr = TRANSIT_V6_DST.octets();
    meta.flow_src_port = 54321;
    meta.flow_dst_port = 443;
    let (batch, debug) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );
    assert_martian_source_drop_10689(&sessions, &binding, &batch, &debug);
}

fn assert_martian_source_drop_10689(
    sessions: &SessionTable,
    binding: &BindingWorker,
    batch: &BatchCounters,
    debug: &DebugPollCounters,
) {
    assert_eq!(debug.rx, 1, "descriptor must reach the poll path");
    assert_eq!(batch.metadata_packets, 1, "metadata must parse");
    assert_eq!(batch.validated_packets, 1, "packet must pass validation");
    assert_eq!(batch.screen_drops, 0, "RED cell must not pass via another screen");
    assert_eq!(debug.no_route, 0, "test must not pass through a missing route");
    assert_eq!(debug.policy_deny, 0, "nat_snapshot has an any/any permit");
    assert_eq!(debug.tx, 0, "martian source must not be transmitted");
    assert_eq!(debug.forward, 0, "martian source must not forward");
    assert_eq!(batch.session_creates, 0, "no forward/reverse pair may be created");
    assert_eq!(sessions.len(), 0, "no forward or reverse session may remain");
    assert_eq!(binding.pending_neigh.len(), 0, "martian must not enter neighbor retry");
    assert!(
        binding.scratch.scratch_forwards.is_empty(),
        "martian must not queue a forward"
    );
}

macro_rules! v4_martian_source_cell_10689 {
    ($name:ident, $source:expr) => {
        #[test]
        fn $name() {
            run_v4_source_10689($source);
        }
    };
}

macro_rules! v6_martian_source_cell_10689 {
    ($name:ident, $source:expr) => {
        #[test]
        fn $name() {
            run_v6_source_10689($source);
        }
    };
}

v6_martian_source_cell_10689!(
    transit_drops_ipv6_multicast_source_10689,
    "ff02::1".parse().unwrap()
);
v6_martian_source_cell_10689!(transit_drops_ipv6_loopback_source_10689, Ipv6Addr::LOCALHOST);
v6_martian_source_cell_10689!(
    transit_drops_ipv6_unspecified_source_10689,
    Ipv6Addr::UNSPECIFIED
);
v6_martian_source_cell_10689!(
    transit_drops_ipv6_link_local_source_10689,
    "fe80::1".parse().unwrap()
);

v4_martian_source_cell_10689!(
    transit_drops_ipv4_this_network_source_10689,
    Ipv4Addr::new(0, 0, 0, 1)
);
v4_martian_source_cell_10689!(transit_drops_ipv4_loopback_source_10689, Ipv4Addr::LOCALHOST);
v4_martian_source_cell_10689!(
    transit_drops_ipv4_link_local_source_10689,
    Ipv4Addr::new(169, 254, 1, 2)
);
v4_martian_source_cell_10689!(
    transit_drops_ipv4_multicast_source_10689,
    Ipv4Addr::new(224, 0, 0, 1)
);
v4_martian_source_cell_10689!(
    transit_drops_ipv4_limited_broadcast_source_10689,
    Ipv4Addr::BROADCAST
);
v4_martian_source_cell_10689!(
    transit_drops_ipv4_reserved_source_10689,
    Ipv4Addr::new(240, 0, 0, 1)
);
v4_martian_source_cell_10689!(
    transit_drops_ipv4_directed_broadcast_source_10689,
    Ipv4Addr::new(10, 0, 61, 255)
);

#[test]
fn transit_martian_source_gate_drops_preexisting_session_hit_10689() {
    let forwarding = forwarding_10689();
    let source = Ipv4Addr::LOCALHOST;
    let destination = TRANSIT_V4_DST;
    let forward_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(source),
        dst_ip: IpAddr::V4(destination),
        src_port: 54321,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let resolution = lookup_forwarding_resolution(&forwarding, IpAddr::V4(destination));
    assert_eq!(resolution.disposition, ForwardingDisposition::ForwardCandidate);
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        forward_key,
        SessionDecision {
            resolution,
            nat: NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        },
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: 24,
            ingress_vlan_id: 0,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        TCP_FLAG_SYN,
    ));
    assert_eq!(sessions.len(), 1, "fixture must seed the forward session");

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let frame = build_txn_tcp_syn_frame_v4(
        source,
        destination,
        54321,
        443,
        TCP_FLAG_SYN,
        TEST_LAN_MAC,
    );
    let mut meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    meta.flow_src_addr[..4].copy_from_slice(&source.octets());
    meta.flow_dst_addr[..4].copy_from_slice(&destination.octets());
    meta.flow_src_port = 54321;
    meta.flow_dst_port = 443;
    let (batch, debug) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &txn_ha_state(),
        &frame,
        meta,
        true,
    );

    assert_eq!(debug.rx, 1, "descriptor must reach the poll path");
    assert_eq!(batch.validated_packets, 1);
    assert_eq!(debug.session_hit, 1, "pre-existing pair must actually hit");
    assert_eq!(debug.tx, 0, "martian source session hit must not transmit");
    assert_eq!(debug.forward, 0);
    assert_eq!(batch.session_creates, 0);
    assert_eq!(sessions.len(), 1, "drop must not remove unrelated conntrack state");
}

#[test]
fn transit_martian_source_gate_covers_flowless_ipv6_fragment_10689() {
    let source: Ipv6Addr = "ff02::1".parse().unwrap();
    let destination = TRANSIT_V6_DST;
    let payload = [0x82, 0x35, 0x01, 0xbb, 0, 0, 0, 0];
    let mut frame = vec![
        0x02, 0xbf, 0x72, 0x01, 0x00, 0x01, 0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5, 0x86, 0xdd,
    ];
    let mut ipv6 = [0u8; 40];
    ipv6[0] = 0x60;
    ipv6[4..6].copy_from_slice(&16u16.to_be_bytes());
    ipv6[6] = 44;
    ipv6[7] = 64;
    ipv6[8..24].copy_from_slice(&source.octets());
    ipv6[24..40].copy_from_slice(&destination.octets());
    frame.extend_from_slice(&ipv6);
    frame.extend_from_slice(&[PROTO_TCP, 0, 0, 8, 0x10, 0x20, 0x30, 0x40]);
    frame.extend_from_slice(&payload);

    let forwarding = forwarding_10689();
    assert_eq!(
        lookup_forwarding_resolution(&forwarding, IpAddr::V6(destination)).disposition,
        ForwardingDisposition::ForwardCandidate,
        "fixture must have a live transit route independent of source class"
    );
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let mut meta = txn_meta_v6(24, frame.len());
    meta.l4_offset = 62;
    meta.flow_src_addr = source.octets();
    meta.flow_dst_addr = destination.octets();
    meta.flow_src_port = 33333;
    meta.flow_dst_port = 443;
    let (batch, debug) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &txn_ha_state(),
        &frame,
        meta,
        true,
    );
    assert_martian_source_drop_10689(&sessions, &binding, &batch, &debug);
}

#[test]
fn ordinary_unicast_sources_still_transit_under_any_permit_10689() {
    let forwarding = forwarding_10689();
    let ha_state = txn_ha_state();
    let mut binding_v4 = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding_v4.interface = Arc::<str>::from("reth1.0");
    let mut sessions_v4 = SessionTable::new();
    let frame_v4 = build_txn_tcp_syn_frame_v4(
        LAN_V4_SRC,
        TRANSIT_V4_DST,
        54321,
        443,
        TCP_FLAG_SYN,
        TEST_LAN_MAC,
    );
    let mut meta_v4 = txn_meta_v4(24, TCP_FLAG_SYN, frame_v4.len() as u16);
    meta_v4.flow_src_addr[..4].copy_from_slice(&LAN_V4_SRC.octets());
    meta_v4.flow_dst_addr[..4].copy_from_slice(&TRANSIT_V4_DST.octets());
    meta_v4.flow_src_port = 54321;
    meta_v4.flow_dst_port = 443;
    let (batch_v4, debug_v4) = txn_run_descriptor_checked(
        &mut binding_v4,
        &mut sessions_v4,
        &forwarding,
        &ha_state,
        &frame_v4,
        meta_v4,
        true,
    );
    assert_eq!(debug_v4.tx, 1, "ordinary IPv4 unicast source still forwards");
    assert_eq!(debug_v4.forward, 1);
    assert_eq!(batch_v4.session_creates, 2);
    assert_eq!(sessions_v4.len(), 2);

    let mut binding_v6 = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding_v6.interface = Arc::<str>::from("reth1.0");
    let mut sessions_v6 = SessionTable::new();
    let frame_v6 = build_txn_tcp_syn_frame_v6(
        LAN_V6_SRC,
        TRANSIT_V6_DST,
        54321,
        443,
        TEST_LAN_MAC,
    );
    let mut meta_v6 = txn_meta_v6(24, frame_v6.len());
    meta_v6.flow_src_addr = LAN_V6_SRC.octets();
    meta_v6.flow_dst_addr = TRANSIT_V6_DST.octets();
    meta_v6.flow_src_port = 54321;
    meta_v6.flow_dst_port = 443;
    let (batch_v6, debug_v6) = txn_run_descriptor_checked(
        &mut binding_v6,
        &mut sessions_v6,
        &forwarding,
        &ha_state,
        &frame_v6,
        meta_v6,
        true,
    );
    assert_eq!(debug_v6.tx, 1, "ordinary IPv6 unicast source still forwards");
    assert_eq!(debug_v6.forward, 1);
    assert_eq!(batch_v6.session_creates, 2);
    assert_eq!(sessions_v6.len(), 2);
}
