//! #19132 (fold cycle 2): the #1377 source-NAT fail-closed contract, proven
//! by BEHAVIOR. A text scan of the failure arms could not prove termination:
//! a terminator under a condition, a commented-out one, or an extra match arm
//! on a closing-brace line all passed it (Codex on b7c, then b7e). These cells
//! drive real packets and a real fragment retry instead:
//!   - the normal new-session path: a SYN whose source-NAT pool can allocate
//!     nothing is counted (`nat_alloc_fail`), recycled exactly once, and
//!     neither forwarded, transmitted nor installed;
//!   - the missing-neighbor seed: the same, and it is not parked either;
//!   - the flowless-fragment retry: a source-NAT decision that errors yields
//!     `Drop`, never `Unchanged` (an untranslated tail) or `Translate`.
//! Each cell has a control (a working pool, or an egress with an address)
//! that takes the other outcome, so a cell cannot pass on a fixture that never
//! reaches the failure.

use super::poll_descriptor::frag_assoc::{retry_flowless_fragment_nat, RetryFlowlessFragmentNat};
use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::SourceNATRuleSnapshot;

const FRAME_ADDR: u64 = 128; // where txn_run_descriptor places the frame

fn pool_rule(port_low: u16, port_high: u16) -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        name: "pool-19132".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_addresses: vec!["203.0.113.10".to_string()],
        port_low,
        port_high,
        ..Default::default()
    }
}

fn meta_v4_19132(src: Ipv4Addr, dst: Ipv4Addr, frame_len: usize) -> UserspaceDpMeta {
    let mut meta = txn_meta_v4(24, TCP_FLAG_SYN, frame_len as u16);
    meta.flow_src_addr[..4].copy_from_slice(&src.octets());
    meta.flow_dst_addr[..4].copy_from_slice(&dst.octets());
    meta.flow_src_port = 12345;
    meta.flow_dst_port = 443;
    meta
}

struct Outcome {
    batch: BatchCounters,
    dbg: DebugPollCounters,
    sessions: usize,
    recycled: usize,
    parked: bool,
}

/// One lan->wan SYN through the real poll path, against `rule`, with the next
/// hop resolved (`neighbors`) or not.
fn drive_syn_19132(rule: SourceNATRuleSnapshot, neighbors: bool) -> Outcome {
    let mut snapshot = nat_snapshot();
    if !neighbors {
        snapshot.neighbors.clear();
    }
    snapshot.source_nat_rules = vec![rule];
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let (src, dst) = (Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(8, 8, 8, 8));
    let frame = build_txn_tcp_syn_frame_v4(src, dst, 12345, 443, TCP_FLAG_SYN, TEST_LAN_MAC);
    let (batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta_v4_19132(src, dst, frame.len()),
        true,
    );
    assert_eq!(dbg.rx, 1, "anti-vacuity: the descriptor never reached the poll body");
    Outcome {
        batch,
        dbg,
        sessions: sessions.len(),
        recycled: binding.scratch.scratch_recycle.iter().filter(|a| **a == FRAME_ADDR).count(),
        parked: !binding.pending_neigh.is_empty(),
    }
}

/// The fail-closed shape: counted, recycled once, and nothing else happened.
fn assert_dropped_19132(o: &Outcome, path: &str) {
    assert_eq!(o.batch.nat_alloc_fail, 1, "{path}: the source-NAT failure must be recorded");
    assert_eq!(o.recycled, 1, "{path}: the frame must be recycled exactly once");
    assert_eq!(o.dbg.forward, 0, "{path}: a packet with no source translation must not be forwarded");
    assert_eq!(o.dbg.tx, 0, "{path}: nothing may be transmitted");
    assert_eq!(o.dbg.session_create, 0, "{path}: no session may be created");
    assert_eq!(o.sessions, 0, "{path}: no session may be installed");
    assert!(!o.parked, "{path}: the frame must not be parked for neighbor resolution");
}

#[test]
fn normal_path_source_nat_failure_drops_the_packet_19132() {
    // Control: a working pool forwards this very packet.
    let ok = drive_syn_19132(pool_rule(5000, 5099), true);
    assert_eq!(ok.batch.nat_alloc_fail, 0, "control: a working pool must not fail");
    assert_eq!(ok.dbg.forward, 1, "control: with a working pool the SYN is forwarded");
    // An empty port range: every allocation fails at the composer.
    let failed = drive_syn_19132(pool_rule(5000, 4999), true);
    assert_eq!(failed.dbg.missing_neigh, 0, "fixture: the normal path, not the seed");
    assert_dropped_19132(&failed, "normal new-session path");
}

#[test]
fn missing_neighbor_seed_source_nat_failure_drops_the_packet_19132() {
    // Control: a working pool seeds (session installed, frame parked).
    let ok = drive_syn_19132(pool_rule(5000, 5099), false);
    assert!(ok.dbg.missing_neigh >= 1, "control: the fixture takes the MissingNeighbor arm");
    assert_eq!(ok.batch.nat_alloc_fail, 0, "control: a working pool must not fail");
    assert!(ok.sessions >= 1 || ok.parked, "control: a working pool seeds the flow");
    let failed = drive_syn_19132(pool_rule(5000, 4999), false);
    assert!(failed.dbg.missing_neigh >= 1, "fixture: the MissingNeighbor seed arm");
    assert_dropped_19132(&failed, "missing-neighbor seed");
}

/// A forwarding state for the fragment retry: one lan->wan rule (`rule`) and
/// an egress (ifindex 2) with or without an IPv4 address.
fn frag_forwarding_19132(rule: SourceNATRuleSnapshot, egress_v4: Option<Ipv4Addr>) -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&[rule]);
    forwarding.egress.insert(
        2,
        crate::afxdp::EgressInterface {
            bind_ifindex: 2,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: 2,
            redundancy_group: 0,
            primary_v4: egress_v4,
            primary_v6: None,
        },
    );
    forwarding.zone_id_to_name.insert(1, "lan".into());
    forwarding.zone_id_to_name.insert(2, "wan".into());
    forwarding
}

fn retry_udp_tail_19132(forwarding: &ForwardingState) -> RetryFlowlessFragmentNat {
    let src_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99));
    let flow = SessionFlow {
        src_ip,
        dst_ip,
        forward_key: crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_UDP,
            src_ip,
            dst_ip,
            src_port: 0,
            dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    };
    let meta = UserspaceDpMeta {
        protocol: PROTO_UDP,
        addr_family: libc::AF_INET as u8,
        l3_offset: 14,
        l4_offset: 34,
        ingress_ifindex: 1,
        ..UserspaceDpMeta::default()
    };
    retry_flowless_fragment_nat(forwarding, &flow, meta, None, None, 1, 2, 2, 0, 0)
}

#[test]
fn flowless_fragment_source_nat_error_drops_19132() {
    let interface_rule = SourceNATRuleSnapshot {
        name: "iface-19132".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..Default::default()
    };
    // Control (the Ok arm): interface SNAT with an egress address rewrites the
    // tail's source address.
    let ok = retry_udp_tail_19132(&frag_forwarding_19132(interface_rule.clone(), Some(Ipv4Addr::new(192, 0, 2, 2))));
    assert!(
        matches!(ok, RetryFlowlessFragmentNat::Translate { .. }),
        "control: interface SNAT with an egress address must translate the tail"
    );
    // The error arms, from two different failures: interface SNAT with no
    // egress address (InterfaceNoEgressAddress), and a pool rule, which
    // cannot port-map a non-first fragment (NonFirstFragment).
    for (label, forwarding) in [
        ("interface SNAT, no egress address", frag_forwarding_19132(interface_rule, None)),
        ("pool SNAT on a non-first fragment", frag_forwarding_19132(pool_rule(5000, 5099), Some(Ipv4Addr::new(192, 0, 2, 2)))),
    ] {
        let got = retry_udp_tail_19132(&forwarding);
        assert!(
            matches!(got, RetryFlowlessFragmentNat::Drop),
            "{label}: a source-NAT error must drop the tail, not pass it untranslated or translate it"
        );
    }
}
