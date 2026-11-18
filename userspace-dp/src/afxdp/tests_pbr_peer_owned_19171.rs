//! #19171 fold 1 (codex-e P2-1): the reverse PBR re-selection on a session
//! hit. When an established reverse's route identity changes (its PBR term was
//! removed, so the native table is selected, or retargeted to another
//! instance), the poll path re-resolves the reply's destination in the newly
//! selected table. That is a raw FIB lookup. Since #19171 a peer-owned
//! connected prefix answers it with the peer-owned interface, so the answer
//! must be judged (HA, then the fabric-arrival composition) before it is
//! persisted or used. Unjudged, it transmitted on the inactive interface or
//! probed its neighbor.
//!
//! Shape: the client 10.66.0.2 sits behind `reth3.0` (ifindex 26, RG3,
//! peer-owned, 10.66.0.0/24). The reply from 172.16.80.200 hits the stored
//! reverse, whose install table was `blue` (the old PBR target).

use super::test_fixtures::nat_snapshot_with_fabric;
use super::tests_split_rg_failback_18531::rg;
use super::tests_support::*;
use super::*;
use crate::test_zone_ids::*;
use crate::{
    FirewallFilterSnapshot, FirewallTermSnapshot, InterfaceAddressSnapshot, InterfaceSnapshot,
    NeighborSnapshot,
};

const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 2);
const SERVER: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 200);
const WAN_UNIT: i32 = 12;
const PEER_UNIT: i32 = 26;
const FABRIC_PARENT: i32 = 21;
const STAMPED_GENERATION: u64 = 6;
const LIVE_GENERATION: u64 = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Selection {
    /// The PBR term is gone: the native table is selected.
    Removed,
    /// The term now steers to instance `red`, which holds the peer-owned unit.
    Retargeted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arrival {
    Direct,
    FabricLink,
}

fn address(cidr: &str) -> InterfaceAddressSnapshot {
    InterfaceAddressSnapshot {
        family: "inet".into(),
        address: cidr.into(),
        ..Default::default()
    }
}

fn snapshot(selection: Selection, neighbor: bool) -> crate::ConfigSnapshot {
    let mut snapshot = nat_snapshot_with_fabric();
    snapshot.generation = LIVE_GENERATION;
    snapshot.fib_generation = 9;
    snapshot.default_policy = "permit".into();
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "blue0".into(),
        zone: "lan".into(),
        routing_instance: "blue".into(),
        linux_name: "blue0".into(),
        ifindex: 101,
        addresses: vec![address("10.250.0.1/24")],
        ..Default::default()
    });
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "reth3.0".into(),
        zone: "lan".into(),
        routing_instance: if selection == Selection::Retargeted { "red".into() } else { String::new() },
        linux_name: "ge-0-0-3".into(),
        ifindex: PEER_UNIT,
        redundancy_group: 3,
        connected_rg_peer_owned: true,
        hardware_addr: "02:bf:72:03:00:01".into(),
        addresses: vec![address("10.66.0.1/24")],
        ..Default::default()
    });
    if neighbor {
        snapshot.neighbors.push(NeighborSnapshot {
            interface: "ge-0-0-3".into(),
            ifindex: PEER_UNIT,
            family: "inet".into(),
            ip: CLIENT.to_string(),
            mac: "02:00:19:17:10:02".into(),
            state: "reachable".into(),
            router: false,
            link_local: false,
            ..Default::default()
        });
    }
    let term = match selection {
        // An accept term that steers nothing: the native table is selected.
        Selection::Removed => FirewallTermSnapshot {
            name: "accept-reply".into(),
            source_addresses: vec![format!("{SERVER}/32")],
            protocols: vec!["tcp".into()],
            action: "accept".into(),
            ..Default::default()
        },
        Selection::Retargeted => FirewallTermSnapshot {
            name: "steer-reply-red".into(),
            source_addresses: vec![format!("{SERVER}/32")],
            protocols: vec!["tcp".into()],
            routing_instance: "red".into(),
            action: "accept".into(),
            ..Default::default()
        },
    };
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "edge-in".into(),
        family: "inet".into(),
        terms: vec![term],
    }];
    for iface in snapshot.interfaces.iter_mut() {
        if iface.ifindex == WAN_UNIT || iface.ifindex == FABRIC_PARENT {
            iface.filter_input_v4 = "edge-in".into();
        }
    }
    snapshot
}

fn sessions_with_blue_reverse() -> SessionTable {
    let forward_key = crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(CLIENT),
        dst_ip: IpAddr::V4(SERVER),
        src_port: 12345,
        dst_port: 5201,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let reverse_key = crate::session::reverse_session_key(&forward_key, NatDecision::default());
    let metadata = |is_reverse: bool| SessionMetadata {
        forward_wire_alias_origin: false,
        ingress_zone: if is_reverse { TEST_WAN_ZONE_ID } else { TEST_LAN_ZONE_ID },
        egress_zone: if is_reverse { TEST_LAN_ZONE_ID } else { TEST_WAN_ZONE_ID },
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        forward_ingress_vlan_id: None,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
        nat_scope_ifindex: None,
    };
    let resolution = |egress: i32, next_hop: Ipv4Addr| ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: egress,
        tx_ifindex: egress,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(next_hop)),
        neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
        tx_vlan_id: 0,
        source_ifindex: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    };
    let (blue_domain, blue_check) = crate::session::install_table_identity("blue");
    let mut sessions = SessionTable::new();
    sessions.set_filter_revalidation_gen(STAMPED_GENERATION);
    assert!(sessions.install_with_protocol_with_origin(
        forward_key,
        SessionDecision {
            resolution: resolution(WAN_UNIT, SERVER),
            nat: NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        },
        metadata(false),
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        0,
    ));
    assert!(sessions.install_with_protocol_with_origin(
        reverse_key,
        SessionDecision {
            resolution: resolution(101, CLIENT),
            nat: NatDecision::default(),
            install_table_domain: blue_domain,
            install_table_check: blue_check,
        },
        metadata(true),
        SessionOrigin::ReverseFlow,
        122_000_000_000,
        PROTO_TCP,
        0,
    ));
    sessions
}

#[derive(Debug)]
struct Seen {
    session_hit: u64,
    /// `(disposition, target_ifindex)` of each queued forward.
    forwards: Vec<(ForwardingDisposition, i32)>,
    missing_neigh: u64,
}

fn reply(selection: Selection, neighbor: bool, arrival: Arrival) -> Seen {
    let forwarding = build_forwarding_state(&snapshot(selection, neighbor));
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([
        (1, rg(true, now_secs)),
        (2, rg(true, now_secs)),
        (3, rg(false, now_secs)),
    ]);
    let (ingress, dst_mac) = match arrival {
        Arrival::Direct => (WAN_UNIT, [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
        Arrival::FabricLink => (FABRIC_PARENT, [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
    };
    let mut frame = build_txn_tcp_syn_frame_v4(SERVER, CLIENT, 5201, 12345, crate::tcp_flags::TCP_ACK, dst_mac);
    if arrival == Arrival::FabricLink {
        let [_, _, hi, lo] = forwarding.zone_name_to_id["wan"].to_be_bytes();
        frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    }
    let mut meta = txn_meta_v4(ingress as u32, crate::tcp_flags::TCP_ACK, frame.len() as u16);
    meta.config_generation = LIVE_GENERATION;
    if arrival == Arrival::Direct {
        meta.ingress_vlan_id = 80;
    }
    meta.flow_src_addr[..4].copy_from_slice(&SERVER.octets());
    meta.flow_dst_addr[..4].copy_from_slice(&CLIENT.octets());
    meta.flow_src_port = 5201;
    meta.flow_dst_port = 12345;
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, ingress, 0);
    binding.interface = Arc::<str>::from(if arrival == Arrival::Direct { "ge-0-0-0.80" } else { "ge-0-0-0" });
    let mut sessions = sessions_with_blue_reverse();
    let (_batch, dbg) = txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);
    Seen {
        session_hit: dbg.session_hit,
        forwards: binding
            .scratch
            .scratch_forwards
            .iter()
            .map(|forward| (forward.decision.resolution.disposition, forward.target_ifindex))
            .collect(),
        missing_neigh: dbg.missing_neigh,
    }
}

/// RED before fold 1. A direct (WAN) arrival: the re-selected route names the
/// peer-owned unit; judged, it becomes the fabric redirect to the owner. Never
/// a TX on the peer-owned unit, never a neighbor probe on it. With and without
/// the client's neighbor, for a removed and a retargeted PBR term.
#[test]
fn reverse_pbr_reselection_onto_a_peer_owned_prefix_crosses_the_fabric_19171() {
    for selection in [Selection::Removed, Selection::Retargeted] {
        for neighbor in [true, false] {
            let seen = reply(selection, neighbor, Arrival::Direct);
            let ctx = format!("{selection:?} neighbor={neighbor}: {seen:?}");
            assert_eq!(seen.session_hit, 1, "the reply hits the reverse ({ctx})");
            assert!(
                seen.forwards.iter().all(|(_, target)| *target != PEER_UNIT),
                "never TX on the peer-owned unit ({ctx})"
            );
            assert_eq!(seen.missing_neigh, 0, "never a neighbor probe on it ({ctx})");
            assert_eq!(
                seen.forwards,
                vec![(ForwardingDisposition::FabricRedirect, FABRIC_PARENT)],
                "the judged route crosses the fabric to the owner ({ctx})"
            );
        }
    }
}

/// RED before fold 1. A fabric-link arrival of the same reply: the judged
/// route is HAInactive and is NOT redirected back (anti-loop), so nothing is
/// sent, and nothing is probed.
#[test]
fn reverse_pbr_reselection_on_a_fabric_link_arrival_is_refused_19171() {
    for selection in [Selection::Removed, Selection::Retargeted] {
        for neighbor in [true, false] {
            let seen = reply(selection, neighbor, Arrival::FabricLink);
            let ctx = format!("{selection:?} neighbor={neighbor}: {seen:?}");
            assert!(seen.forwards.is_empty(), "a fabric-link arrival is refused, never sent ({ctx})");
            assert_eq!(seen.missing_neigh, 0, "and never probes ({ctx})");
        }
    }
}
