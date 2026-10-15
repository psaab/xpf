// native-GRE encap/decap, inner/outer ECN combination, and local-origin tunnel TX.
//
// Split out of afxdp/frame/tests.rs (#4840) as a sibling `#[path]` test
// module loaded from afxdp/frame/mod.rs. Pure code motion: every #[test]
// fn is moved verbatim; shared test-support helpers live in
// afxdp/frame/tests_support.rs.
#![allow(unused_imports)]

use super::super::test_fixtures::*;
use super::*;
use crate::event_stream::DataplaneEventRateLimitConfig;
use crate::event_stream::codec::DataplaneEventKind;
use crate::test_zone_ids::*;
use crate::{FirewallFilterSnapshot, FirewallTermSnapshot, ThreeColorPolicerSnapshot};
use super::tests_support::*;

fn native_gre_host_inbound_snapshot() -> crate::protocol::snapshot::ConfigSnapshot {
    let mut snapshot = native_gre_snapshot(true);
    let wan = snapshot
        .zones
        .iter_mut()
        .find(|zone| zone.name == "wan")
        .expect("native GRE fixture has a wan zone");
    // #11054: exercise inner decap semantics only after the outer GRE packet
    // has passed the real ingress host-inbound gate.
    wan.host_inbound_configured = true;
    wan.host_inbound_system_services.push("gre".to_string());
    snapshot
}


#[test]
fn native_gre_logical_egress_retains_zone_without_mac() {
    let state = build_forwarding_state(&native_gre_pbr_snapshot(true));
    let egress = state.egress.get(&362).expect("logical tunnel egress");
    assert_eq!(egress.zone_id, TEST_SFMIX_ZONE_ID);
    assert_eq!(egress.primary_v4, Some(Ipv4Addr::new(10, 255, 192, 42)));
}


#[test]
fn owner_rg_for_resolution_uses_native_gre_endpoint_group() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    // #4446: the GRE inner interface lives in the sfmix routing-instance, so
    // its connected /30 (which owns the tunnel peer 10.255.192.41) is in
    // sfmix.inet.0. Resolve in that table to reach the tunnel — a default
    // (inet.0) lookup no longer sees the sfmix-scoped connected prefix
    // (table-scoped inference; mirrors the #2388 lookup filter).
    let resolved = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &Default::default(),
        IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
        Some("sfmix.inet.0"),
    )
    .resolution;
    assert_eq!(resolved.tunnel_endpoint_id, 1);
    assert_eq!(owner_rg_for_resolution(&state, resolved), 1);
}


#[test]
fn native_gre_decap_maps_inner_packet_to_logical_tunnel_ingress() {
    let state = build_forwarding_state(&native_gre_host_inbound_snapshot());
    let inner = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 255, 192, 41),
        Ipv4Addr::new(10, 255, 192, 42),
        63,
    );
    let outer = build_ipv6_gre_frame(
        &inner[14..],
        "2602:ffd3:0:2::7".parse().unwrap(),
        "2001:559:8585:80::8".parse().unwrap(),
        None,
    );
    let packet = try_native_gre_decap_from_frame(&outer, native_gre_outer_meta(), &state)
        .expect("native gre decap");
    assert_eq!(packet.meta.ingress_ifindex, 362);
    assert_eq!(packet.meta.addr_family, libc::AF_INET as u8);
    assert_eq!(packet.meta.protocol, PROTO_ICMP);
    assert_eq!(packet.meta.l3_offset, 14);
    assert_eq!(&packet.frame[12..14], &[0x08, 0x00]);
    assert_eq!(&packet.frame[26..30], &[10, 255, 192, 41]);
    assert_eq!(&packet.frame[30..34], &[10, 255, 192, 42]);
}


#[test]
fn native_gre_decap_combines_outer_ce_into_inner_ecn() {
    // #2315 RFC 6040 §4.2: an outer CE over an ECN-capable inner must
    // upgrade the inner ECN to CE at decap, and the inner IPv4 header
    // checksum must remain valid after the TOS change.
    let state = build_forwarding_state(&native_gre_host_inbound_snapshot());
    // Inner DSCP EF (46) + ECT(0) (0b10).
    let inner_tos = (46u8 << 2) | 0b10;
    let inner = inner_v4_frame_with_tos(
        Ipv4Addr::new(10, 255, 192, 41),
        Ipv4Addr::new(10, 255, 192, 42),
        63,
        inner_tos,
    );
    let mut outer = build_ipv6_gre_frame(
        &inner[14..],
        "2602:ffd3:0:2::7".parse().unwrap(),
        "2001:559:8585:80::8".parse().unwrap(),
        None,
    );
    set_outer_ipv6_ecn(&mut outer, 0b11); // outer CE

    let packet = try_native_gre_decap_from_frame(&outer, native_gre_outer_meta(), &state)
        .expect("decap must forward (legal CE upgrade)");
    // Inner emerges in the synthetic frame at offset 14 (eth) + 1 (TOS).
    let inner_tos_out = packet.frame[15];
    assert_eq!(
        inner_tos_out & 0x03,
        0b11,
        "inner ECN must be upgraded to CE"
    );
    assert_eq!(inner_tos_out >> 2, 46, "inner DSCP (EF) must be preserved");
    // Fail-on-revert: the CE bit MUST be set — the pre-#2315 copy-only
    // path could never produce this (it never touched the inner ECN).
    assert_ne!(inner_tos_out & 0x03, 0b10, "ECN must change from ECT(0)");
    // Inner IPv4 header checksum (synthetic frame[14..34]) must be valid.
    assert_eq!(
        checksum16(&packet.frame[14..34]),
        0,
        "inner IPv4 header checksum must be recomputed after the CE upgrade"
    );
}


#[test]
fn native_gre_decap_drops_illegal_outer_ce_over_not_ect_inner() {
    // #2315 RFC 6040 §4.2: outer CE over a Not-ECT inner is the illegal
    // combination — decap must DROP (return None).
    let state = build_forwarding_state(&native_gre_host_inbound_snapshot());
    let inner = inner_v4_frame_with_tos(
        Ipv4Addr::new(10, 255, 192, 41),
        Ipv4Addr::new(10, 255, 192, 42),
        63,
        (46u8 << 2) | 0b00, // Not-ECT
    );
    let mut outer = build_ipv6_gre_frame(
        &inner[14..],
        "2602:ffd3:0:2::7".parse().unwrap(),
        "2001:559:8585:80::8".parse().unwrap(),
        None,
    );
    set_outer_ipv6_ecn(&mut outer, 0b11); // outer CE

    assert!(
        try_native_gre_decap_from_frame(&outer, native_gre_outer_meta(), &state).is_none(),
        "outer CE over a Not-ECT inner must be dropped (§4.2)"
    );
}


#[test]
fn native_gre_decap_leaves_inner_unchanged_when_outer_not_congested() {
    // Outer Not-ECT must leave the inner ECN/DSCP and checksum exactly
    // as they arrived (no spurious mutation on the common case).
    let state = build_forwarding_state(&native_gre_host_inbound_snapshot());
    let inner_tos = (10u8 << 2) | 0b01; // DSCP 10 + ECT(1)
    let inner = inner_v4_frame_with_tos(
        Ipv4Addr::new(10, 255, 192, 41),
        Ipv4Addr::new(10, 255, 192, 42),
        63,
        inner_tos,
    );
    let outer = build_ipv6_gre_frame(
        &inner[14..],
        "2602:ffd3:0:2::7".parse().unwrap(),
        "2001:559:8585:80::8".parse().unwrap(),
        None,
    );
    // build_ipv6_gre_frame writes outer TC = 0 (Not-ECT) — no mutation.
    let packet = try_native_gre_decap_from_frame(&outer, native_gre_outer_meta(), &state)
        .expect("decap forwards");
    assert_eq!(
        packet.frame[15], inner_tos,
        "outer Not-ECT must leave the inner TOS byte verbatim"
    );
    assert_eq!(
        checksum16(&packet.frame[14..34]),
        0,
        "inner checksum unchanged and valid"
    );
}


#[test]
fn build_forwarded_frame_from_frame_encapsulates_native_gre() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let inner =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(8, 8, 8, 8), 64);
    let inner_meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 11,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: (inner.len() - 14) as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        flow_src_addr: {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&[10, 0, 61, 102]);
            addr
        },
        flow_dst_addr: {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&[8, 8, 8, 8]);
            addr
        },
        flow_src_port: 0x1234,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: lookup_forwarding_resolution_v4(
            &state,
            None,
            Ipv4Addr::new(8, 8, 8, 8),
            "sfmix.inet.0",
            0,
            true,
            None,
        )
        .resolution,
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let built = build_forwarded_frame_from_frame(
        &inner,
        inner_meta,
        &decision,
        &state,
        false,
        Some((0x1234, 0)),
    )
    .expect("encapsulated gre frame");
    assert_eq!(&built[12..16], &[0x81, 0x00, 0x00, 0x50]);
    assert_eq!(&built[16..18], &[0x86, 0xdd]);
    assert_eq!(&built[22..24], &[0x00, 0x20]);
    assert_eq!(built[24], PROTO_GRE);
    assert_eq!(built[25], 64);
    assert_eq!(&built[60..62], &[0x08, 0x00]);
    assert_eq!(built[70], 63);
    assert_eq!(&built[74..78], &[10, 0, 61, 102]);
    assert_eq!(&built[78..82], &[8, 8, 8, 8]);
}


#[test]
fn local_origin_tunnel_tx_request_encapsulates_raw_ip_for_active_owner() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    // #1881: the loop now loads HA state once per iteration and
    // passes the map down — the builder takes &BTreeMap directly.
    let ha_state = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let packet = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 255, 192, 42),
        Ipv4Addr::new(10, 255, 192, 41),
        64,
    );
    let ike_exchanges = crate::afxdp::forwarding::IkeExchangeTable::new();
    let plan = build_local_origin_tunnel_tx_request(
        &packet[14..],
        1,
        &state,
        &ha_state,
        &dynamic_neighbors,
        &ike_exchanges,
    )
    .expect("local-origin tunnel tx request");
    assert_eq!(plan.tx_ifindex, 6);
    assert_eq!(&plan.tx_request.bytes[12..16], &[0x81, 0x00, 0x00, 0x50]);
    assert_eq!(&plan.tx_request.bytes[16..18], &[0x86, 0xdd]);
    assert_eq!(plan.tx_request.bytes[24], PROTO_GRE);
    assert_eq!(&plan.tx_request.bytes[60..62], &[0x08, 0x00]);
    assert_eq!(&plan.tx_request.bytes[74..78], &[10, 255, 192, 42]);
    assert_eq!(&plan.tx_request.bytes[78..82], &[10, 255, 192, 41]);
    assert_eq!(
        plan.session_entry
            .as_ref()
            .expect("owned local-origin source must publish")
            .key
            .protocol,
        PROTO_ICMP
    );
}

#[test]
fn local_origin_tunnel_tx_request_accepts_owned_ipv6_in_tunnel_instance() {
    let mut snapshot = native_gre_snapshot(true);
    let gre = snapshot
        .interfaces
        .iter_mut()
        .find(|iface| iface.name == "gr-0/0/0.0")
        .expect("GRE interface");
    gre.addresses.push(crate::InterfaceAddressSnapshot {
        family: "inet6".to_string(),
        address: "2001:db8:255:192::42/64".to_string(),
        scope: 0,
    });
    snapshot.routes.push(crate::RouteSnapshot {
        table: "sfmix.inet6.0".to_string(),
        family: "inet6".to_string(),
        destination: "::/0".to_string(),
        next_hop_weights: vec![],
        next_hops: vec!["2001:db8:255:192::41".to_string()],
        discard: false,
        next_table: String::new(),
        preference: 0,
        rule_priority: 0,
        mtu: 0,
    });
    let state = build_forwarding_state(&snapshot);
    let src = "2001:db8:255:192::42".parse::<Ipv6Addr>().unwrap();
    assert!(
        state.local_tables_v6.get(&src).is_some_and(|tables| {
            tables.contains("sfmix.inet6.0")
        }),
        "precondition: GRE interface IPv6 is owned in sfmix.inet6.0"
    );
    let ha_state = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let packet = build_icmpv6_echo_frame(
        src,
        "2001:db8:255:192::41".parse().unwrap(),
        64,
        128,
        0x3179,
    );
    let ike_exchanges = crate::afxdp::forwarding::IkeExchangeTable::new();
    let plan = build_local_origin_tunnel_tx_request(
        &packet[14..],
        1,
        &state,
        &ha_state,
        &dynamic_neighbors,
        &ike_exchanges,
    )
    .expect("owned IPv6 source in tunnel instance must transmit");
    assert!(
        plan.session_entry.is_some(),
        "owned IPv6 source must receive a TunOrigin session"
    );
}
/// #13179: nonlocal TUN input has no policy/screen decision at this path and
/// therefore must be rejected rather than transported as unadjudicated GRE.
#[test]
fn local_origin_tunnel_nonlocal_source_is_dropped_13179() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let ha_state = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let packet = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 123, 0, 5),
        Ipv4Addr::new(10, 255, 192, 41),
        64,
    );
    let ike_exchanges = crate::afxdp::forwarding::IkeExchangeTable::new();
    let err = build_local_origin_tunnel_tx_request(
        &packet[14..],
        1,
        &state,
        &ha_state,
        &dynamic_neighbors,
        &ike_exchanges,
    )
    .expect_err("nonlocal source must not bypass zone policy");
    assert!(err.contains("local_tunnel_source_not_owned_in_routing_instance"));
}
const LOCAL_IKE_INITIATOR_SPI_10518: u64 = 0x5152_5354_5556_5758;

fn local_origin_ike_v4_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    const IPV4_HEADER_LEN: usize = 20;
    const UDP_HEADER_LEN: usize = 8;
    const IKE_HEADER_LEN: usize = 28;
    let total_len = IPV4_HEADER_LEN + UDP_HEADER_LEN + IKE_HEADER_LEN;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = PROTO_UDP;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    packet[20..22].copy_from_slice(&500u16.to_be_bytes());
    packet[22..24].copy_from_slice(&500u16.to_be_bytes());
    packet[24..26].copy_from_slice(&((UDP_HEADER_LEN + IKE_HEADER_LEN) as u16).to_be_bytes());
    packet[28..36].copy_from_slice(&LOCAL_IKE_INITIATOR_SPI_10518.to_be_bytes());
    packet[44..48].copy_from_slice(&[0x00, 0x20, 0x22, 0x08]);
    let ip_checksum = checksum16(&packet[..IPV4_HEADER_LEN]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    packet
}

/// #10518: the ownership gate must not suppress the existing local-IKE seed
/// needed by firewall-initiated exchanges.
#[test]
fn local_origin_tunnel_owned_ike_seeds_before_encapsulation_10518() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let src = Ipv4Addr::new(10, 255, 192, 42);
    let dst = Ipv4Addr::new(10, 255, 192, 41);
    let packet = local_origin_ike_v4_packet(src, dst);
    let ha_state = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ike_exchanges = crate::afxdp::forwarding::IkeExchangeTable::new();
    let plan = build_local_origin_tunnel_tx_request(
        &packet,
        1,
        &state,
        &ha_state,
        &dynamic_neighbors,
        &ike_exchanges,
    )
    .expect("owned IKE initiation must remain encap-able");

    assert_eq!(ike_exchanges.len(), 1);
    assert!(ike_exchanges.matches(
        &crate::afxdp::forwarding::IkeExchangeKey::new(
            LOCAL_IKE_INITIATOR_SPI_10518,
            IpAddr::V4(dst),
            IpAddr::V4(src),
        ),
        monotonic_nanos(),
    ));
    assert_eq!(
        plan.session_entry
            .as_ref()
            .expect("owned IKE source must publish")
            .key
            .protocol,
        PROTO_UDP
    );
    assert!(plan.reverse_session_entry.is_some());
}

/// #13179: non-owned TUN IKE traffic must not be transmitted or seeded.
#[test]
fn local_origin_tunnel_nonlocal_ike_is_dropped_without_seed_13179() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let packet = local_origin_ike_v4_packet(
        Ipv4Addr::new(10, 123, 0, 5),
        Ipv4Addr::new(10, 255, 192, 41),
    );
    let ha_state = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ike_exchanges = crate::afxdp::forwarding::IkeExchangeTable::new();
    let err = build_local_origin_tunnel_tx_request(
        &packet,
        1,
        &state,
        &ha_state,
        &dynamic_neighbors,
        &ike_exchanges,
    )
    .expect_err("nonlocal IKE source must not bypass zone policy");
    assert!(err.contains("local_tunnel_source_not_owned_in_routing_instance"));
    assert_eq!(ike_exchanges.len(), 0);
}

/// #13179: nonlocal IPv6 TUN traffic is likewise rejected before GRE TX.
#[test]
fn local_origin_tunnel_nonlocal_v6_is_dropped_13179() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let packet = build_icmpv6_echo_frame(
        "2001:db8:1234::5".parse().unwrap(),
        "2001:db8:1234::41".parse().unwrap(),
        64,
        128,
        0x1051,
    );
    let ha_state = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ike_exchanges = crate::afxdp::forwarding::IkeExchangeTable::new();
    let err = build_local_origin_tunnel_tx_request(
        &packet[14..],
        1,
        &state,
        &ha_state,
        &dynamic_neighbors,
        &ike_exchanges,
    )
    .expect_err("nonlocal IPv6 source must not bypass zone policy");
    assert!(err.contains("local_tunnel_source_not_owned_in_routing_instance"));
}

/// #13179: a transit packet cannot reach the local tunnel's shared publish
/// path; the owned control still produces both TunOrigin session halves.
#[test]
fn local_origin_tunnel_rejects_nonlocal_before_shared_publication_13179() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let ha_state = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let indexes = SharedSessionOwnerRgIndexes::default();
    let packet = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 123, 0, 5),
        Ipv4Addr::new(10, 255, 192, 41),
        64,
    );
    let err = build_local_origin_tunnel_tx_request(
        &packet[14..],
        1,
        &state,
        &ha_state,
        &dynamic_neighbors,
        &crate::afxdp::forwarding::IkeExchangeTable::new(),
    )
    .expect_err("nonlocal source must be dropped before publication");
    assert!(err.contains("local_tunnel_source_not_owned_in_routing_instance"));

    let owned_packet = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 255, 192, 42),
        Ipv4Addr::new(10, 255, 192, 41),
        64,
    );
    let owned_plan = build_local_origin_tunnel_tx_request(
        &owned_packet[14..],
        1,
        &state,
        &ha_state,
        &dynamic_neighbors,
        &crate::afxdp::forwarding::IkeExchangeTable::new(),
    )
    .expect("owned source must produce a publishable plan");
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let mut local_sessions = FastMap::default();
    let mut local_sessions_last_prune_ns = 0;
    maybe_enqueue_local_tunnel_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &indexes,
        &worker_commands,
        &mut local_sessions,
        &mut local_sessions_last_prune_ns,
        &owned_plan,
    );
    assert_eq!(shared_sessions.lock().expect("shared sessions").len(), 2);
    assert_eq!(local_sessions.len(), 1);
}


// #6224: the LOCAL-ORIGIN (host-outbound) GRE encapsulation path runs no
// security policy / application match — `resolve_tunnel_forwarding_resolution`
// is route/next-hop/neighbor resolution only, and Junos runs no security
// policy on firewall-self-originated traffic. There is therefore no admitting
// application to source a per-application `inactivity_timeout_ns` from (nor an
// admitting policy for `policy_id` / the hit-counter handle). The correct value
// is `None`, so `session_timeout_ns` ages the session on the GLOBAL
// per-protocol timeout. This pins that contract: it goes RED if a future change
// stamps a bogus per-app timeout (or a non-zero policy attribution) onto this
// path — the exact mis-"fix" the #6224 stale comment invited. The reverse
// companion is checked for consistency: it inherits the forward's `None`
// (#5153/#6223 builder), so both halves stay on the global timeout — this is
// NOT the #5153 forward-has-value / reverse-hardcoded-None inconsistency.
#[test]
fn local_origin_tunnel_session_uses_global_timeout_no_policy_match_6224() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let ha_state = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let packet = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 255, 192, 42),
        Ipv4Addr::new(10, 255, 192, 41),
        64,
    );
    let ike_exchanges = crate::afxdp::forwarding::IkeExchangeTable::new();
    let plan = build_local_origin_tunnel_tx_request(
        &packet[14..],
        1,
        &state,
        &ha_state,
        &dynamic_neighbors,
        &ike_exchanges,
    )
    .expect("local-origin tunnel tx request");
    let session = plan
        .session_entry
        .as_ref()
        .expect("owned local-origin source must publish");

    // Forward half: no admitting application/policy on the local-origin path.
    assert_eq!(
        session.metadata.inactivity_timeout_ns, None,
        "local-origin GRE session must age on the global per-protocol timeout \
         (no admitting application to source a per-app idle timeout)"
    );
    assert_eq!(
        session.metadata.policy_id, 0,
        "local-origin GRE session runs no policy match (no admitting policy ID)"
    );
    assert!(
        session.metadata.policy_counter.is_none(),
        "local-origin GRE session runs no policy match (no hit-counter handle)"
    );

    // Reverse companion: consistent with the forward half (both None). NOT the
    // #5153 shape (forward real value / reverse hardcoded None).
    let reverse = plan
        .reverse_session_entry
        .as_ref()
        .expect("active owner synthesizes a reverse companion");
    assert!(reverse.metadata.is_reverse);
    assert_eq!(
        reverse.metadata.inactivity_timeout_ns, None,
        "reverse companion inherits the forward half's global timeout"
    );
}


#[test]
fn local_origin_tunnel_tx_request_rejects_inactive_owner() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let packet = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 255, 192, 42),
        Ipv4Addr::new(10, 255, 192, 41),
        64,
    );
    let ike_exchanges = crate::afxdp::forwarding::IkeExchangeTable::new();
    let err = build_local_origin_tunnel_tx_request(
        &packet[14..],
        1,
        &state,
        &ha_state,
        &dynamic_neighbors,
        &ike_exchanges,
    )
    .expect_err("inactive owner should not originate tunnel traffic");
    assert!(err.contains("ha_inactive"), "unexpected error: {err}");
}

/// #13179 (D6-03): an unzoned GRE tunnel (egress_zone_id == 0) must never
/// transmit local-origin traffic or mint TunOrigin sessions. Reverting the
/// zone gate in build_local_origin_tunnel_tx_request makes this Ok(..) -> RED.
#[test]
fn local_origin_tunnel_unzoned_gre_fails_closed_13179() {
    let mut snapshot = native_gre_snapshot(true);
    for iface in snapshot.interfaces.iter_mut() {
        if iface.name == "gr-0/0/0.0" {
            iface.zone = String::new();
            iface.egress_zone = String::new();
        }
    }
    for ep in snapshot.tunnel_endpoints.iter_mut() {
        ep.zone = String::new();
    }
    let state = build_forwarding_state(&snapshot);
    assert_eq!(
        state.egress_zone_id(362),
        0,
        "precondition: gr-0/0/0.0 must be unzoned"
    );
    let ha_state = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let packet = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 255, 192, 42),
        Ipv4Addr::new(10, 255, 192, 41),
        64,
    );
    let ike_exchanges = crate::afxdp::forwarding::IkeExchangeTable::new();
    let err = build_local_origin_tunnel_tx_request(
        &packet[14..],
        1,
        &state,
        &ha_state,
        &dynamic_neighbors,
        &ike_exchanges,
    )
    .expect_err("unzoned GRE tunnel must fail closed");
    assert!(
        err.contains("local_tunnel_unzoned_egress"),
        "unexpected error: {err}"
    );
}

/// #13179 (D6-03): cross-VRF source must not mint TunOrigin. The tunnel lives
/// in sfmix (sfmix.inet.0); 2001:559:8585:80::8 is owned only in inet6.0 /
/// default via reth0.80, not by the tunnel's instance. Global
/// owns_configured_ip would admit it; table-scoped ownership must not.
#[test]
fn local_origin_tunnel_cross_vrf_source_no_tun_session_13179() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let src = std::net::IpAddr::V6("2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap());
    assert!(
        state.owns_configured_ip(src),
        "precondition: src globally owned (would mint pre-fix)"
    );
    // Inner v4 packet whose src is tunnel-local would be self-originated;
    // instead use a v6 inner packet sourced from the WAN address.
    let ha_state = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ike_exchanges = crate::afxdp::forwarding::IkeExchangeTable::new();
    let packet = build_icmpv6_echo_frame(
        "2001:559:8585:80::8".parse().unwrap(),
        "2001:db8:255:192::41".parse().unwrap(),
        64,
        128,
        0x3179,
    );
    let err = build_local_origin_tunnel_tx_request(
        &packet[14..],
        1,
        &state,
        &ha_state,
        &dynamic_neighbors,
        &ike_exchanges,
    )
    .expect_err("cross-VRF source must not transmit through this tunnel");
    assert!(
        err.contains("local_tunnel_source_not_owned_in_routing_instance"),
        "unexpected error: {err}"
    );
    assert_eq!(ike_exchanges.len(), 0, "foreign-VRF IKE must not seed");
}


#[test]
fn build_forwarded_frame_from_frame_encapsulates_native_gre_after_ipv4_snat() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let inner = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(10, 255, 192, 41),
        64,
    );
    let inner_meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 5,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: (inner.len() - 14) as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        flow_src_addr: {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&[10, 0, 61, 102]);
            addr
        },
        flow_dst_addr: {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&[10, 255, 192, 41]);
            addr
        },
        flow_src_port: 0x1234,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision { resolution: lookup_forwarding_resolution_v4(&state,
    None,
    Ipv4Addr::new(10, 255, 192, 41),
    "sfmix.inet.0",
    0,
    true,
    None,).resolution, nat: NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(10, 255, 192, 42))),
        ..NatDecision::default()
    }, install_table_domain: 0, install_table_check: 0 };
    let built = build_forwarded_frame_from_frame(
        &inner,
        inner_meta,
        &decision,
        &state,
        false,
        Some((0x1234, 0)),
    )
    .expect("encapsulated native gre frame with snat");
    assert_eq!(&built[12..16], &[0x81, 0x00, 0x00, 0x50]);
    assert_eq!(&built[16..18], &[0x86, 0xdd]);
    assert_eq!(built[24], PROTO_GRE);
    assert_eq!(&built[74..78], &[10, 255, 192, 42]);
    assert_eq!(&built[78..82], &[10, 255, 192, 41]);
}


#[test]
fn build_forwarded_frame_from_frame_recomputes_tcp_checksum_for_native_gre_snat() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let src_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(10, 255, 192, 41);
    let snat_ip = Ipv4Addr::new(10, 255, 192, 42);
    let src_port = 50420u16;
    let dst_port = 5201u16;

    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x30, 0x12, 0x34, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x01, // ack
        0x50, 0x18, 0x20, 0x00, // data offset/flags/window
        0x18, 0x29, 0x00, 0x00, // intentionally bogus partial/offload checksum + urg
        b't', b'e', b's', b't', b'd', b'a', b't', b'a',
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 5,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_addr: {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&src_ip.octets());
            addr
        },
        flow_dst_addr: {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&dst_ip.octets());
            addr
        },
        flow_src_port: src_port,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision { resolution: lookup_forwarding_resolution_v4(&state, None, dst_ip, "sfmix.inet.0", 0, true, None).resolution, nat: NatDecision {
        rewrite_src: Some(IpAddr::V4(snat_ip)),
        ..NatDecision::default()
    }, install_table_domain: 0, install_table_check: 0 };
    let built = build_forwarded_frame_from_frame(
        &frame,
        meta,
        &decision,
        &state,
        false,
        Some((src_port, dst_port)),
    )
    .expect("encapsulated native gre frame with tcp snat");
    let inner = &built[62..];
    assert_eq!(&inner[12..16], &snat_ip.octets());
    assert_eq!(&inner[16..20], &dst_ip.octets());
    assert!(tcp_checksum_ok_ipv4(inner));
}


#[test]
fn build_forwarded_frame_from_frame_clamps_tcp_mss_for_native_gre() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let src_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(10, 255, 192, 41);
    let src_port = 44028u16;
    let dst_port = 5201u16;

    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x2c, 0x12, 0x34, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x00,
        0x00,
        0x00,
        0x01, // seq
        0x00,
        0x00,
        0x00,
        0x00, // ack
        0x60,
        TCP_FLAG_SYN,
        0xfa,
        0xf0, // data offset / flags / window
        0x00,
        0x00,
        0x00,
        0x00, // checksum + urg
        0x02,
        0x04,
        0x05,
        0xb4, // MSS 1460
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 5,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 58,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        flow_src_addr: {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&src_ip.octets());
            addr
        },
        flow_dst_addr: {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&dst_ip.octets());
            addr
        },
        flow_src_port: src_port,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: lookup_forwarding_resolution_v4(&state, None, dst_ip, "sfmix.inet.0", 0, true, None).resolution,
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let built = build_forwarded_frame_from_frame(
        &frame,
        meta,
        &decision,
        &state,
        false,
        Some((src_port, dst_port)),
    )
    .expect("encapsulated native gre frame with tcp syn");
    let inner = &built[62..];
    assert_eq!(&inner[40..44], &[0x02, 0x04, 0x05, 0x88]);
    assert!(tcp_checksum_ok_ipv4(inner));
}
