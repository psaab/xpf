//! #19171 (raw-lookup census U1): WireGuard transit is judged on its SELECTED
//! peer's outer egress.
//!
//! The session-level WireGuard gate keys on the decision's outer next hop. A
//! transit decision resolves the endpoint row's unspecified destination, so
//! that next hop is the default gateway (here 172.16.80.1 on the active WAN,
//! RG1), not the route to the peer AllowedIPs selects. Since #19171 a
//! peer-owned connected prefix answers the peer route with the peer-owned
//! interface. So a peer endpoint inside one (here 10.66.0.50 behind
//! `reth3.0`, ifindex 26, RG3) passed the gate and was transmitted on an
//! interface this node does not own.
//!
//! Judged, an inactive RG3 makes the packet HAInactive, so the poll path's HA
//! net carries it to the owner over the fabric on a direct arrival and refuses
//! it on a fabric-link arrival. A cached decision is evicted the same way.

use super::test_fixtures::{nat_snapshot_with_fabric, v5, wg_outer_mtu_snapshot};
use super::tests_split_rg_failback_18531::rg;
use super::tests_support::*;
use super::*;
use crate::{InterfaceAddressSnapshot, InterfaceSnapshot, NeighborSnapshot};

const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 102);
/// Inside the peer's AllowedIPs 10.123.0.0/24.
const INNER_DST: Ipv4Addr = Ipv4Addr::new(10, 123, 0, 9);
const PEER_ENDPOINT: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 50);
const LAN_UNIT: i32 = 24;
const PEER_UNIT: i32 = 26;
const FABRIC_PARENT: i32 = 21;
const WG_LOGICAL: i32 = 400;

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

fn forwarding() -> ForwardingState {
    let mut snapshot = nat_snapshot_with_fabric();
    snapshot.default_policy = "permit".into();
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "wg0.0".into(),
        zone: "wan".into(),
        linux_name: "wg0".into(),
        ifindex: WG_LOGICAL,
        mtu: 1420,
        tunnel: true,
        addresses: vec![address("10.123.0.1/24")],
        ..Default::default()
    });
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "reth3.0".into(),
        zone: "lan".into(),
        linux_name: "ge-0-0-3".into(),
        ifindex: PEER_UNIT,
        mtu: 1500,
        redundancy_group: 3,
        connected_rg_peer_owned: true,
        hardware_addr: "02:bf:72:03:00:01".into(),
        addresses: vec![address("10.66.0.1/24")],
        ..Default::default()
    });
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "ge-0-0-3".into(),
        ifindex: PEER_UNIT,
        family: "inet".into(),
        ip: PEER_ENDPOINT.to_string(),
        mac: "02:00:19:17:10:50".into(),
        state: "reachable".into(),
        router: false,
        link_local: false,
        ..Default::default()
    });
    let mut endpoint = wg_outer_mtu_snapshot().tunnel_endpoints.remove(0);
    endpoint.zone = "wan".into();
    endpoint.wg_peers[0].wg_endpoint = format!("{PEER_ENDPOINT}:51820");
    snapshot.tunnel_endpoints = vec![endpoint];
    // `v5` derives each pushed interface's egress zone, as for the base fixture.
    build_forwarding_state(&v5(snapshot))
}

fn forward_key() -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(CLIENT),
        dst_ip: IpAddr::V4(INNER_DST),
        src_port: 40000,
        dst_port: 5201,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// The stored WireGuard transit decision exactly as the FIB answers it: the
/// logical tunnel egress, with the default gateway as its outer next hop.
fn wg_decision(forwarding: &ForwardingState) -> SessionDecision {
    let resolution = lookup_forwarding_resolution_in_table_with_dynamic(
        forwarding,
        &Arc::new(ShardedNeighborMap::default()),
        IpAddr::V4(INNER_DST),
        None,
    )
    .resolution;
    assert_eq!(
        (
            resolution.disposition,
            resolution.egress_ifindex,
            resolution.tunnel_endpoint_id
        ),
        (ForwardingDisposition::ForwardCandidate, WG_LOGICAL, 1),
        "FIXTURE: the inner destination routes into the WireGuard tunnel"
    );
    assert_eq!(
        resolution.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
        "FIXTURE: the decision's outer next hop is the default gateway, not the peer route"
    );
    SessionDecision {
        resolution,
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn ha(rg3_active: bool) -> BTreeMap<i32, HAGroupRuntime> {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    BTreeMap::from([
        (1, rg(true, now_secs)),
        (2, rg(true, now_secs)),
        (3, rg(rg3_active, now_secs)),
    ])
}

/// One client packet into the tunnel (a SYN opens the flow through the
/// new-flow path; later ACKs hit its session, then the flow cache). Returns
/// `(disposition, target)` of each queued forward.
fn send(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    binding: &mut BindingWorker,
    sessions: &mut SessionTable,
    arrival: Arrival,
    tcp_flags: u8,
) -> Vec<(ForwardingDisposition, i32)> {
    let dst_mac = match arrival {
        Arrival::Direct => TEST_LAN_MAC,
        Arrival::FabricLink => [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
    };
    let mut frame = build_txn_tcp_syn_frame_v4(CLIENT, INNER_DST, 40000, 5201, tcp_flags, dst_mac);
    if arrival == Arrival::FabricLink {
        let [_, _, hi, lo] = forwarding.zone_name_to_id["lan"].to_be_bytes();
        frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, hi, lo]);
    }
    let ingress = match arrival {
        Arrival::Direct => LAN_UNIT,
        Arrival::FabricLink => FABRIC_PARENT,
    };
    let mut meta = txn_meta_v4(ingress as u32, tcp_flags, frame.len() as u16);
    meta.flow_src_addr[..4].copy_from_slice(&CLIENT.octets());
    meta.flow_dst_addr[..4].copy_from_slice(&INNER_DST.octets());
    meta.flow_src_port = 40000;
    meta.flow_dst_port = 5201;
    binding.scratch.scratch_forwards.clear();
    let (_batch, dbg, exceptions) = txn_run_descriptor_capturing_exceptions(
        binding, sessions, forwarding, ha_state, &frame, meta,
    );
    // Shown only when a cell fails: where the packet went.
    eprintln!(
        "{arrival:?}: rx={} session_hit={} session_miss={} forward={} no_route={} missing_neigh={} \
         policy_deny={} ha_inactive={} no_egress_binding={} build_fail={} disposition_other={} \
         frame_build_none={} foreign_authority_drops={} local={} recycled={} exceptions={exceptions:?}",
        dbg.rx,
        dbg.session_hit,
        dbg.session_miss,
        dbg.forward,
        dbg.no_route,
        dbg.missing_neigh,
        dbg.policy_deny,
        dbg.ha_inactive,
        dbg.no_egress_binding,
        dbg.build_fail,
        dbg.disposition_other,
        dbg.frame_build_none,
        dbg.foreign_authority_drops,
        dbg.local,
        binding.scratch.scratch_recycle.len(),
    );
    binding
        .scratch
        .scratch_forwards
        .iter()
        .map(|forward| {
            (
                forward.decision.resolution.disposition,
                forward.target_ifindex,
            )
        })
        .collect()
}

fn binding_for(arrival: Arrival) -> BindingWorker {
    let (ingress, name) = match arrival {
        Arrival::Direct => (LAN_UNIT, "reth1.0"),
        Arrival::FabricLink => (FABRIC_PARENT, "ge-0-0-0"),
    };
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, ingress, 0);
    binding.interface = Arc::<str>::from(name);
    binding
}

/// The helper's truth table on the same state: the selected peer's egress is
/// the peer-owned unit, so the result follows RG3, and nothing else.
#[test]
fn wg_selected_peer_inactive_rg_follows_the_selected_peers_egress_19171() {
    let forwarding = forwarding();
    let decision = wg_decision(&forwarding);
    let frame = build_txn_tcp_syn_frame_v4(
        CLIENT,
        INNER_DST,
        40000,
        5201,
        crate::tcp_flags::TCP_ACK,
        TEST_LAN_MAC,
    );
    let meta = txn_meta_v4(
        LAN_UNIT as u32,
        crate::tcp_flags::TCP_ACK,
        frame.len() as u16,
    );
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let judged = |decision: &SessionDecision, ha_state: &BTreeMap<i32, HAGroupRuntime>| {
        crate::afxdp::frame::wg_transit_selected_peer_inactive_rg(
            decision,
            &forwarding,
            ha_state,
            now_secs,
            &frame,
            meta.addr_family,
            meta.l3_offset,
            None,
        )
    };
    assert_eq!(
        crate::afxdp::frame::wg_transit_egress_physical_egress_ifindex(
            &decision,
            &forwarding,
            &frame,
            meta.addr_family,
            meta.l3_offset,
            None,
        ),
        Some(PEER_UNIT),
        "FIXTURE: the selected peer's outer egress is the peer-owned unit"
    );
    assert_eq!(judged(&decision, &ha(false)), Some(3), "RG3 inactive here");
    assert_eq!(judged(&decision, &ha(true)), None, "RG3 active here");
    assert_eq!(
        judged(&decision, &BTreeMap::new()),
        None,
        "standalone: no gate"
    );
    let mut plain = decision;
    plain.resolution.tunnel_endpoint_id = 0;
    assert_eq!(
        judged(&plain, &ha(false)),
        None,
        "a non-tunnel decision is not judged here"
    );
    let mut redirect = decision;
    redirect.resolution.disposition = ForwardingDisposition::FabricRedirect;
    assert_eq!(
        judged(&redirect, &ha(false)),
        None,
        "a non-forwardable decision is not judged here"
    );
}

const SYN: u8 = crate::tcp_flags::TCP_SYN;
const ACK: u8 = crate::tcp_flags::TCP_ACK;

/// RED before the census fix. A direct arrival with RG3 inactive crosses the
/// fabric to the owner; it is never sent on the peer-owned unit. The control
/// (RG3 active here) sends it on that unit, proving the shape.
#[test]
fn wg_transit_to_a_peer_owned_peer_endpoint_crosses_the_fabric_19171() {
    let forwarding = forwarding();
    let _ = wg_decision(&forwarding);
    for (rg3_active, want) in [
        (true, (ForwardingDisposition::ForwardCandidate, PEER_UNIT)),
        (
            false,
            (ForwardingDisposition::FabricRedirect, FABRIC_PARENT),
        ),
    ] {
        let mut binding = binding_for(Arrival::Direct);
        let mut sessions = SessionTable::new();
        let seen = send(
            &forwarding,
            &ha(rg3_active),
            &mut binding,
            &mut sessions,
            Arrival::Direct,
            SYN,
        );
        assert_eq!(
            seen,
            vec![want],
            "RG3 active here = {rg3_active}: active sends on the selected peer's unit, \
             inactive crosses the fabric to the owner"
        );
    }
}

/// RED before the census fix. The same flow arriving on the fabric link is
/// refused when RG3 is inactive here (anti-loop): nothing is sent. The control
/// (RG3 active here) proves a fabric arrival does reach the forward.
#[test]
fn wg_transit_to_a_peer_owned_peer_endpoint_on_a_fabric_link_arrival_is_refused_19171() {
    let forwarding = forwarding();
    for rg3_active in [true, false] {
        let mut binding = binding_for(Arrival::FabricLink);
        let mut sessions = SessionTable::new();
        let seen = send(
            &forwarding,
            &ha(rg3_active),
            &mut binding,
            &mut sessions,
            Arrival::FabricLink,
            SYN,
        );
        if rg3_active {
            assert_eq!(
                seen,
                vec![(ForwardingDisposition::ForwardCandidate, PEER_UNIT)],
                "control: a fabric arrival with RG3 active here is sent on the peer's unit"
            );
        } else {
            assert!(
                seen.is_empty(),
                "RG3 inactive: a fabric-link arrival is refused, got {seen:?}"
            );
        }
    }
}

/// RED before the census fix. A WireGuard decision cached while RG3 was active
/// here is evicted once RG3 goes inactive, and the packet crosses the fabric.
/// Unjudged, the cache kept serving the peer-owned unit: its revalidation
/// judges only the default gateway's RG.
#[test]
fn a_cached_wg_transit_decision_is_evicted_when_the_selected_peers_rg_departs_19171() {
    let forwarding = forwarding();
    let mut binding = binding_for(Arrival::Direct);
    let mut sessions = SessionTable::new();
    let active = (ForwardingDisposition::ForwardCandidate, PEER_UNIT);
    assert_eq!(
        send(
            &forwarding,
            &ha(true),
            &mut binding,
            &mut sessions,
            Arrival::Direct,
            SYN
        ),
        vec![active]
    );
    assert_eq!(
        send(
            &forwarding,
            &ha(true),
            &mut binding,
            &mut sessions,
            Arrival::Direct,
            ACK
        ),
        vec![active]
    );
    assert_eq!(
        txn_flow_cache_entries(&binding),
        1,
        "FIXTURE: the first ACK seeds the flow cache"
    );
    assert_eq!(
        send(
            &forwarding,
            &ha(false),
            &mut binding,
            &mut sessions,
            Arrival::Direct,
            ACK
        ),
        vec![(ForwardingDisposition::FabricRedirect, FABRIC_PARENT)],
        "RG3 departed: the cached decision is evicted and the packet crosses the fabric"
    );
}
