//! #11413: transit destinations outside unicast must not reach TX under an
//! application-any permit. Each martian cell proves a real FIB transit route
//! existed before driving the descriptor path and verifies the drop counter.

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::session::{SessionMetadata, SessionOrigin};
use crate::test_zone_ids::{TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const TRANSIT_V4_SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 100);
const TRANSIT_V4_CONTROL_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 42);
const TRANSIT_V6_SRC: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0559, 0x8585, 0xef00, 0, 0, 0, 0x0102);
const TRANSIT_V6_CONTROL_DST: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0x1234, 0, 0, 0, 0, 0x0042);

fn forwarding_11413() -> ForwardingState {
    let mut snapshot = nat_snapshot();
    snapshot.source_nat_rules.clear();
    build_forwarding_state(&snapshot)
}

fn assert_transit_destination_drop_11413(
    sessions: &SessionTable,
    binding: &BindingWorker,
    batch: &BatchCounters,
    debug: &DebugPollCounters,
) {
    assert_eq!(debug.rx, 1, "descriptor must reach the poll path");
    assert_eq!(batch.validated_packets, 1, "packet must pass validation");
    assert_eq!(
        debug.no_route, 0,
        "martian destination must have a FIB route"
    );
    assert_eq!(debug.policy_deny, 0, "nat_snapshot permits any/any transit");
    assert_eq!(debug.tx, 0, "martian destination must not be transmitted");
    assert_eq!(
        debug.forward, 0,
        "martian destination must not be forwarded"
    );
    assert_eq!(
        batch.martian_dropped, 1,
        "martian destination must be counted"
    );
    assert_eq!(
        batch.session_creates, 0,
        "no forward/reverse pair may be created"
    );
    assert_eq!(
        sessions.len(),
        0,
        "no forward or reverse session may remain"
    );
    assert_eq!(
        binding.pending_neigh.len(),
        0,
        "martian must not enter neighbor retry"
    );
    assert!(
        binding.scratch.scratch_forwards.is_empty(),
        "martian must not queue a forward"
    );
}

fn run_v4_destination_11413(destination: Ipv4Addr) {
    let forwarding = forwarding_11413();
    assert_eq!(
        lookup_forwarding_resolution(&forwarding, IpAddr::V4(destination)).disposition,
        ForwardingDisposition::ForwardCandidate,
        "fixture must provide a live default-route transit path for {destination}"
    );
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let frame = build_txn_tcp_syn_frame_v4(
        TRANSIT_V4_SRC,
        destination,
        54321,
        443,
        TCP_FLAG_SYN,
        TEST_LAN_MAC,
    );
    let mut meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    meta.flow_src_addr[..4].copy_from_slice(&TRANSIT_V4_SRC.octets());
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
    assert_transit_destination_drop_11413(&sessions, &binding, &batch, &debug);
}

fn run_v6_destination_11413(destination: Ipv6Addr) {
    let forwarding = forwarding_11413();
    assert_eq!(
        lookup_forwarding_resolution(&forwarding, IpAddr::V6(destination)).disposition,
        ForwardingDisposition::ForwardCandidate,
        "fixture must provide a live default-route transit path for {destination}"
    );
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let frame = build_txn_tcp_syn_frame_v6(TRANSIT_V6_SRC, destination, 54321, 443, TEST_LAN_MAC);
    let mut meta = txn_meta_v6(24, frame.len());
    meta.flow_src_addr = TRANSIT_V6_SRC.octets();
    meta.flow_dst_addr = destination.octets();
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
    assert_transit_destination_drop_11413(&sessions, &binding, &batch, &debug);
}

macro_rules! v4_martian_destination_cell_11413 {
    ($name:ident, $destination:expr) => {
        #[test]
        fn $name() {
            run_v4_destination_11413($destination);
        }
    };
}

v4_martian_destination_cell_11413!(
    transit_drops_ipv4_multicast_destination_11413,
    Ipv4Addr::new(224, 0, 0, 1)
);
v4_martian_destination_cell_11413!(
    transit_drops_ipv4_limited_broadcast_destination_11413,
    Ipv4Addr::BROADCAST
);
v4_martian_destination_cell_11413!(
    transit_drops_ipv4_loopback_destination_11413,
    Ipv4Addr::LOCALHOST
);
v4_martian_destination_cell_11413!(
    transit_drops_ipv4_reserved_destination_11413,
    Ipv4Addr::new(240, 0, 0, 1)
);

#[test]
fn transit_drops_ipv6_multicast_destination_11413() {
    run_v6_destination_11413("ff02::1".parse().unwrap());
}

#[test]
fn transit_martian_destination_gate_drops_preexisting_session_hit_11413() {
    let forwarding = forwarding_11413();
    let source = TRANSIT_V4_SRC;
    let destination = TRANSIT_V4_CONTROL_DST;
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
    let translated_destination = Ipv4Addr::LOCALHOST;
    let resolution = lookup_forwarding_resolution(&forwarding, IpAddr::V4(translated_destination));
    assert_eq!(
        resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    let mut nat = NatDecision::default();
    nat.rewrite_dst = Some(IpAddr::V4(translated_destination));
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        forward_key,
        SessionDecision {
            resolution,
            nat,
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
    assert_eq!(
        sessions.len(),
        1,
        "fixture must seed a live forward session"
    );

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let frame =
        build_txn_tcp_syn_frame_v4(source, destination, 54321, 443, TCP_FLAG_SYN, TEST_LAN_MAC);
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
    assert_eq!(debug.rx, 1);
    assert_eq!(
        batch.martian_dropped, 1,
        "the existing session's translated destination must be gated"
    );
    assert_eq!(debug.tx, 0, "martian destination session must not transmit");
    assert_eq!(debug.forward, 0);

    assert_eq!(sessions.len(), 1, "drop must preserve the live session");
}

#[test]
fn transit_martian_destination_gate_covers_flowless_fragment_11413() {
    let forwarding = forwarding_11413();
    let destination = Ipv4Addr::new(224, 0, 0, 1);
    assert_eq!(
        lookup_forwarding_resolution(&forwarding, IpAddr::V4(destination)).disposition,
        ForwardingDisposition::ForwardCandidate,
        "fragment fixture must reach a live transit disposition"
    );

    let mut frame = frag_v4_transit_frame(TEST_LAN_MAC);
    frame[30..34].copy_from_slice(&destination.octets());
    let mut meta = frag_v4_transit_meta();
    meta.flow_dst_addr[..4].copy_from_slice(&destination.octets());
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let (batch, debug) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &txn_ha_state(),
        &frame,
        meta,
        true,
    );
    assert_transit_destination_drop_11413(&sessions, &binding, &batch, &debug);
}

#[test]
fn ordinary_unicast_destinations_still_transit_under_any_permit_11413() {
    let forwarding = forwarding_11413();
    for (source, destination) in [
        (
            IpAddr::V4(TRANSIT_V4_SRC),
            IpAddr::V4(TRANSIT_V4_CONTROL_DST),
        ),
        (
            IpAddr::V6(TRANSIT_V6_SRC),
            IpAddr::V6(TRANSIT_V6_CONTROL_DST),
        ),
    ] {
        assert_eq!(
            lookup_forwarding_resolution(&forwarding, destination).disposition,
            ForwardingDisposition::ForwardCandidate,
            "unicast control destination must use the default transit route"
        );
        match (source, destination) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
                binding.interface = Arc::<str>::from("reth1.0");
                let mut sessions = SessionTable::new();
                let frame =
                    build_txn_tcp_syn_frame_v4(src, dst, 54321, 443, TCP_FLAG_SYN, TEST_LAN_MAC);
                let mut meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
                meta.flow_src_addr[..4].copy_from_slice(&src.octets());
                meta.flow_dst_addr[..4].copy_from_slice(&dst.octets());
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
                assert_eq!(
                    debug.tx, 1,
                    "ordinary IPv4 unicast destination still forwards"
                );
                assert_eq!(debug.forward, 1);
                assert_eq!(batch.martian_dropped, 0);
                assert_eq!(batch.session_creates, 2);
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
                binding.interface = Arc::<str>::from("reth1.0");
                let mut sessions = SessionTable::new();
                let frame = build_txn_tcp_syn_frame_v6(src, dst, 54321, 443, TEST_LAN_MAC);
                let mut meta = txn_meta_v6(24, frame.len());
                meta.flow_src_addr = src.octets();
                meta.flow_dst_addr = dst.octets();
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
                assert_eq!(
                    debug.tx, 1,
                    "ordinary IPv6 unicast destination still forwards"
                );
                assert_eq!(debug.forward, 1);
                assert_eq!(batch.martian_dropped, 0);
                assert_eq!(batch.session_creates, 2);
            }
            _ => unreachable!("source and destination families match"),
        }
    }
}
