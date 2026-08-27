// metadata-relative L3 trimming, session-flow parsing/tuple preference, forwarding-lookup, tunnel-route resolution, and PBR routing-instance reject/discard/accept.
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

#[test]
fn trim_l3_payload_uses_frame_length_metadata_relative_to_l3_offset_without_parsing_header() {
    let mut frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2), 64);
    let wire_len = frame.len();
    frame[14] = 0;
    frame.extend_from_slice(&[0u8; 8]);
    let raw_payload = &frame[14..];
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        pkt_len: wire_len as u16,
        addr_family: libc::AF_INET as u8,
        ..UserspaceDpMeta::default()
    };

    assert_eq!(trim_l3_payload(raw_payload, meta).len(), wire_len - 14);
}


#[test]
fn trim_l3_payload_uses_vlan_frame_length_metadata_relative_to_l3_offset_without_parsing_header() {
    let mut frame = build_icmp_echo_frame_v4_vlan(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        64,
        80,
    );
    let wire_len = frame.len();
    frame[18] = 0;
    frame.extend_from_slice(&[0u8; 8]);
    let raw_payload = &frame[18..];
    let meta = UserspaceDpMeta {
        l3_offset: 18,
        pkt_len: wire_len as u16,
        addr_family: libc::AF_INET as u8,
        ..UserspaceDpMeta::default()
    };

    assert_eq!(trim_l3_payload(raw_payload, meta).len(), wire_len - 18);
}


#[test]
fn trim_l3_payload_excludes_ethernet_slack_beyond_ip_declared_len_5149() {
    // #5149: the L4 checksum on the tunnel-forced recompute path must cover
    // ONLY the bytes inside the IP-declared datagram length (IPv4 total_len),
    // never trailing Ethernet slack (NIC min-frame zero-pad or appended
    // bytes). GRE/WireGuard encap transmits only the IP-declared inner length,
    // so a checksum that covered slack would be verified by the peer over
    // bytes no longer present -> the peer DROPS the packet.
    //
    // Construct an L3 frame whose IP total_len (40 = 20 IP + 20 TCP) is SHORTER
    // than the backing slice, which carries 12 bytes of trailing slack. The
    // metadata reports pkt_len == the FULL slack-inclusive backing length, so
    // the pre-fix metadata-led `trim_l3_payload` returned the slack-inclusive
    // suffix. The fix makes the IP-declared length authoritative.
    const IHL: usize = 20;
    const DECLARED_LEN: usize = 40; // 20 IP + 20 TCP, no slack
    const SLACK: usize = 12;
    let src = Ipv4Addr::new(10, 0, 0, 1);
    let dst = Ipv4Addr::new(10, 0, 0, 2);

    let mut raw_payload = Vec::new();
    // IPv4 header (20 bytes): version 4 / IHL 5, total_len = 40, proto TCP.
    raw_payload.extend_from_slice(&[0x45, 0x00]);
    raw_payload.extend_from_slice(&(DECLARED_LEN as u16).to_be_bytes());
    raw_payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // id + flags/frag
    raw_payload.extend_from_slice(&[64, PROTO_TCP, 0x00, 0x00]); // ttl, proto, hdr csum=0
    raw_payload.extend_from_slice(&src.octets());
    raw_payload.extend_from_slice(&dst.octets());
    // TCP header (20 bytes): ports, seq/ack, data-offset 5 + ACK, window, csum=0.
    raw_payload.extend_from_slice(&40000u16.to_be_bytes()); // src port
    raw_payload.extend_from_slice(&443u16.to_be_bytes()); // dst port
    raw_payload.extend_from_slice(&1u32.to_be_bytes()); // seq
    raw_payload.extend_from_slice(&2u32.to_be_bytes()); // ack
    raw_payload.extend_from_slice(&[0x50, 0x10]); // data offset 5, ACK
    raw_payload.extend_from_slice(&64u16.to_be_bytes()); // window
    raw_payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // csum=0, urg=0
    assert_eq!(raw_payload.len(), DECLARED_LEN);
    // Trailing Ethernet slack — NON-zero so it perturbs any checksum computed
    // over it (0xEE, not 0-pad, to make the divergence unambiguous).
    raw_payload.extend_from_slice(&[0xEEu8; SLACK]);
    assert_eq!(raw_payload.len(), DECLARED_LEN + SLACK);

    // Metadata reports the FULL slack-inclusive length — the exact condition
    // under which the pre-fix code returned the slack-inclusive suffix.
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        pkt_len: raw_payload.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };

    // RED-on-revert (target-count 1): the trimmed extent — which is exactly the
    // extent the tunnel-forced `recompute_l4_checksum_ipv4` checksums — must be
    // the IP-declared length (40), NOT the slack-inclusive metadata length (52).
    // Reverting `trim_l3_payload` to metadata-led returns 52 and this fails.
    let trimmed = trim_l3_payload(raw_payload.as_slice(), meta);
    assert_eq!(
        trimmed.len(),
        DECLARED_LEN,
        "trim_l3_payload must trim to the IP-declared datagram length (40), \
         excluding the {SLACK}-byte Ethernet slack — the checksummed extent"
    );

    // Mechanism proof #1: a checksum computed over the trimmed (declared)
    // extent VALIDATES for the peer, who receives only the declared datagram
    // after encap trims to the inner IP length.
    let mut declared = trimmed.to_vec();
    recompute_l4_checksum_ipv4(&mut declared, IHL, PROTO_TCP, true)
        .expect("recompute over declared extent");
    assert_eq!(
        checksum16_ipv4(src, dst, PROTO_TCP, &declared[IHL..]),
        0,
        "the peer validates the TCP checksum over the declared datagram"
    );

    // Mechanism proof #2 (the #5149 bug): a checksum computed over the
    // slack-inclusive extent does NOT validate when the peer checks only the
    // declared datagram it actually received — this is the remote drop.
    let mut slack_inclusive = raw_payload.clone();
    recompute_l4_checksum_ipv4(&mut slack_inclusive, IHL, PROTO_TCP, true)
        .expect("recompute over slack-inclusive extent");
    assert_ne!(
        checksum16_ipv4(src, dst, PROTO_TCP, &slack_inclusive[IHL..DECLARED_LEN]),
        0,
        "a slack-covering checksum fails the peer's declared-datagram verification"
    );
}

#[test]
fn parse_session_flow_reparses_vlan_ipv4_reply_without_meta_offsets() {
    let frame = vlan_icmp_reply_frame();
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        l3_offset: 14,
        l4_offset: 34,
        ..UserspaceDpMeta::default()
    };
    let flow = parse_session_flow(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
    )
    .expect("flow");
    assert_eq!(flow.src_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    assert_eq!(flow.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
    assert_eq!(flow.forward_key.src_port, 0x1234);
    assert_eq!(flow.forward_key.dst_port, 0);
}


#[test]
fn parse_session_flow_prefers_tuple_stamped_in_metadata() {
    // #3290: the metadata pseudo-port is preferred over the frame-derived
    // identifier, but ONLY for an identifier-bearing ICMP query type whose
    // type byte the gate can validate in the frame. The frame here is a
    // legitimate ICMPv4 Echo Request (type 8) whose ON-WIRE identifier is
    // 0x1234; the shim stamped a DIFFERENT pseudo-port (0x4321) in metadata.
    // The gate (`meta_icmp_identifier_bearing`) reads the echo type byte from
    // the frame, admits the flow, and the stamped metadata tuple wins because
    // the metadata and frame IPs agree. (The pre-#3290 form of this test used a
    // 0xaa garbage frame with offsets=0 and relied on the metadata pseudo-port
    // being trusted with NO frame validation — exactly the fake-session vector
    // #3290 closes; that path is now correctly flowless and is covered by the
    // non-query/control ICMP regression tests in inspect_tests.rs.)
    let frame = build_icmp_echo_frame_v4(
        Ipv4Addr::new(172, 16, 80, 200),
        Ipv4Addr::new(172, 16, 80, 8),
        64,
    );
    let mut area = MmapArea::new(256).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let mut meta = valid_meta();
    meta.l3_offset = 14;
    meta.l4_offset = 34;
    // Distinct from the frame's on-wire identifier (0x1234) so a pass proves
    // the STAMPED metadata tuple is preferred, not the frame-derived one.
    meta.flow_src_port = 0x4321;
    let flow = parse_session_flow(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
    )
    .expect("flow");
    assert_eq!(flow.src_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    assert_eq!(flow.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
    assert_eq!(flow.forward_key.src_port, 0x4321);
    assert_eq!(flow.forward_key.dst_port, 0);
}


#[test]
fn parse_session_flow_prefers_frame_tuple_when_metadata_disagrees() {
    let frame = vlan_icmp_reply_frame();
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let mut meta = valid_meta();
    meta.l3_offset = 18;
    meta.l4_offset = 38;
    meta.flow_src_addr[..4].copy_from_slice(&[10, 0, 61, 102]);
    meta.flow_dst_addr[..4].copy_from_slice(&[172, 16, 80, 200]);
    meta.flow_src_port = 0xbeef;
    meta.flow_dst_port = 0;
    let flow = parse_session_flow(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
    )
    .expect("flow");
    assert_eq!(flow.src_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    assert_eq!(flow.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
    assert_eq!(flow.forward_key.src_port, 0x1234);
    assert_eq!(flow.forward_key.dst_port, 0);
}


#[test]
fn parse_session_flow_prefers_ipv6_metadata_ports_when_frame_ports_disagree() {
    let src_ip: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src");
    let dst_ip: Ipv6Addr = "2001:559:8585:80::200".parse().expect("dst");
    let src_port = 50662u16;
    let dst_port = 5201u16;
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0u8; 6]);
    frame.extend_from_slice(&[0u8; 6]);
    frame.extend_from_slice(&0x8100u16.to_be_bytes());
    frame.extend_from_slice(&80u16.to_be_bytes());
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&[0x60, 0, 0, 0, 0, 20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, 0x10, 0, 64, 0, 0, 0, 0]);

    let mut area = MmapArea::new(512).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        l3_offset: 18,
        l4_offset: 58,
        payload_offset: 78,
        flow_src_port: 1026,
        flow_dst_port: dst_port,
        flow_src_addr: src_ip.octets(),
        flow_dst_addr: dst_ip.octets(),
        ..UserspaceDpMeta::default()
    };
    let flow = parse_session_flow(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
    )
    .expect("flow");
    assert_eq!(flow.src_ip, IpAddr::V6(src_ip));
    assert_eq!(flow.dst_ip, IpAddr::V6(dst_ip));
    assert_eq!(flow.forward_key.src_port, 1026);
    assert_eq!(flow.forward_key.dst_port, dst_port);
}


#[test]
fn parse_session_flow_reparses_ipv6_when_metadata_l4_offset_is_bad() {
    let src_ip: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src");
    let dst_ip: Ipv6Addr = "2001:559:8585:80::200".parse().expect("dst");
    let src_port = 50662u16;
    let dst_port = 5201u16;
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0u8; 6]);
    frame.extend_from_slice(&[0u8; 6]);
    frame.extend_from_slice(&0x8100u16.to_be_bytes());
    frame.extend_from_slice(&80u16.to_be_bytes());
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&[0x60, 0, 0, 0, 0, 20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, 0x10, 0, 64, 0, 0, 0, 0]);

    let mut area = MmapArea::new(512).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        l3_offset: 18,
        l4_offset: 22,
        payload_offset: 78,
        flow_src_port: 1025,
        flow_dst_port: dst_port,
        flow_src_addr: src_ip.octets(),
        flow_dst_addr: dst_ip.octets(),
        ..UserspaceDpMeta::default()
    };
    let flow = parse_session_flow(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
    )
    .expect("flow");
    assert_eq!(flow.src_ip, IpAddr::V6(src_ip));
    assert_eq!(flow.dst_ip, IpAddr::V6(dst_ip));
    // When IPs match, parse_session_flow prefers metadata ports over
    // frame-parsed ports (metadata is stamped by BPF before any DMA
    // corruption). The meta port (1025) wins over the frame port (50662).
    assert_eq!(flow.forward_key.src_port, 1025);
    assert_eq!(flow.forward_key.dst_port, dst_port);
}


#[test]
fn forwarding_lookup_prefers_local_delivery() {
    let mut snapshot = forwarding_snapshot(true);
    snapshot.source_nat_rules.clear();
    let state = build_forwarding_state(&snapshot);
    assert_eq!(
        lookup_forwarding_for_ip(&state, IpAddr::V4(Ipv4Addr::new(172, 16, 50, 8))),
        ForwardingDisposition::LocalDelivery
    );
    assert_eq!(
        lookup_forwarding_for_ip(
            &state,
            IpAddr::V6("2001:559:8585:50::8".parse().expect("ipv6")),
        ),
        ForwardingDisposition::LocalDelivery
    );
}


#[test]
fn forwarding_lookup_requires_neighbor_for_forward_candidate() {
    let good = build_forwarding_state(&forwarding_snapshot(true));
    assert_eq!(
        lookup_forwarding_for_ip(&good, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(
        lookup_forwarding_for_ip(
            &good,
            IpAddr::V6("2606:4700:4700::1111".parse().expect("ipv6")),
        ),
        ForwardingDisposition::ForwardCandidate
    );

    let missing_neighbor = build_forwarding_state(&forwarding_snapshot(false));
    assert_eq!(
        lookup_forwarding_for_ip(&missing_neighbor, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),),
        ForwardingDisposition::MissingNeighbor
    );
}


#[test]
fn tunnel_route_resolves_to_logical_tunnel_and_physical_tx() {
    let state = build_forwarding_state(&native_gre_snapshot(true));
    let resolved = lookup_forwarding_resolution_v4(
        &state,
        None,
        Ipv4Addr::new(8, 8, 8, 8),
        "sfmix.inet.0",
        0,
        true,
        None,
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 362);
    assert_eq!(resolved.tx_ifindex, 6);
    assert_eq!(resolved.tunnel_endpoint_id, 1);
    assert_eq!(
        resolved.next_hop,
        Some(IpAddr::V6("2001:559:8585:80::1".parse().expect("outer nh")))
    );
    assert_eq!(
        resolved.neighbor_mac,
        Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
    assert_eq!(resolved.src_mac, Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]));
    assert_eq!(resolved.tx_vlan_id, 80);
}


#[test]
fn tunnel_route_preserves_logical_egress_on_outer_neighbor_miss() {
    let state = build_forwarding_state(&native_gre_snapshot(false));
    let resolved = lookup_forwarding_resolution_v4(
        &state,
        None,
        Ipv4Addr::new(8, 8, 8, 8),
        "sfmix.inet.0",
        0,
        true,
        None,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::MissingNeighbor);
    assert_eq!(resolved.egress_ifindex, 362);
    assert_eq!(resolved.tx_ifindex, 6);
    assert_eq!(resolved.tunnel_endpoint_id, 1);
    assert_eq!(resolved.src_mac, Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]));
    assert_eq!(resolved.tx_vlan_id, 80);
}


#[test]
fn ingress_filter_routing_instance_steers_flow_into_native_gre_table() {
    let state = build_forwarding_state(&native_gre_pbr_snapshot(true));
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
            src_port: 0,
            dst_port: 0,
        },
    };
    let meta = UserspaceDpMeta {
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..Default::default()
    };
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    // #4392: an accept (non-drop) routing-instance term still forwards via the
    // override table — RouteOverride::Table, not Drop.
    let RouteOverride::Table(override_table) =
        ingress_route_table_override(&state, &[], meta, &flow, None, Some(&event_handle), 99, None)
    else {
        panic!("accept routing-instance term must forward via override table");
    };
    assert_eq!(override_table, "sfmix.inet.0");
    let filter_event = event_rx
        .try_recv()
        .expect("filter-log event")
        .decode_dataplane_event()
        .expect("filter-log payload");
    assert_eq!(filter_event.kind, DataplaneEventKind::FilterLog);
    assert_eq!(filter_event.filter_id, 0);
    assert_eq!(filter_event.term_id, 0);
    assert_eq!(filter_event.reason, FilterLogSource::Pbr.wire_reason());
    assert_eq!(filter_event.ingress_zone_id, TEST_LAN_ZONE_ID);
    assert_eq!(filter_event.egress_zone_id, 0);
    let resolved = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &Default::default(),
        flow.dst_ip,
        Some(override_table.as_str()),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 362);
    assert_eq!(resolved.tx_ifindex, 6);
    assert_eq!(resolved.tunnel_endpoint_id, 1);
}

// #4392: a PBR `from { ... } then { routing-instance X; reject | discard; }`
// term is a DENY, not a forward. Before the fix the routing-instance override
// was applied unconditionally and the packet was FORWARDED into VRF X (a VRF
// leak + false audit). The drop action must now gate the override:
// reject/discard -> RouteOverride::Drop; accept-only -> RouteOverride::Table.


#[test]
fn pbr_routing_instance_reject_or_discard_drops_not_forwards_v4() {
    // Flowless (sink-less) path: a reject/discard PBR term must DROP, never
    // return an override table to forward into. RED-on-revert: the pre-fix code
    // returns Some("sfmix.inet.0") == RouteOverride::Table, forwarding the deny.
    let flow = pbr_v4_flow();
    let meta = pbr_v4_meta();
    for action in ["reject", "discard"] {
        let state = build_forwarding_state(&native_gre_pbr_action_snapshot(action));
        let result = ingress_route_table_override(&state, &[], meta, &flow, None, None, 0, None);
        assert!(
            matches!(result, RouteOverride::Drop),
            "v4 PBR `then routing-instance sfmix; {action}` must DROP, not forward"
        );
    }
}


#[test]
fn pbr_routing_instance_reject_or_discard_drops_not_forwards_v6() {
    let flow = pbr_v6_flow();
    let meta = pbr_v6_meta();
    for action in ["reject", "discard"] {
        let state = build_forwarding_state(&native_gre_pbr_action_snapshot(action));
        let result = ingress_route_table_override(&state, &[], meta, &flow, None, None, 0, None);
        assert!(
            matches!(result, RouteOverride::Drop),
            "v6 PBR `then routing-instance sfmix; {action}` must DROP, not forward"
        );
    }
}


#[test]
fn pbr_routing_instance_accept_still_forwards_no_regression() {
    // An accept-only routing-instance term (no drop action) must STILL steer
    // the route lookup into the override table — normal PBR is unchanged.
    let state = build_forwarding_state(&native_gre_pbr_action_snapshot(""));

    let v4 = ingress_route_table_override(
        &state,
        &[],
        pbr_v4_meta(),
        &pbr_v4_flow(),
        None,
        None,
        0,
        None,
    );
    match v4 {
        RouteOverride::Table(table) => assert_eq!(table, "sfmix.inet.0"),
        _ => panic!("accept v4 routing-instance term must forward via sfmix.inet.0"),
    }

    let v6 = ingress_route_table_override(
        &state,
        &[],
        pbr_v6_meta(),
        &pbr_v6_flow(),
        None,
        None,
        0,
        None,
    );
    match v6 {
        RouteOverride::Table(table) => assert_eq!(table, "sfmix.inet6.0"),
        _ => panic!("accept v6 routing-instance term must forward via sfmix.inet6.0"),
    }
}


#[test]
fn pbr_routing_instance_reject_synthesizes_reply_on_session_miss() {
    // Flow-backed session-miss path: a `reject` PBR term supplies a reject sink,
    // so the drop synthesizes an RST/ICMP reply exactly like a non-PBR
    // `then reject`. Drive the TX-frame budget to 0 so the reply attempt is
    // OBSERVABLE via `filter_reject_reply_budget_drops` without needing a valid
    // egress/neighbor — the budget gate is reached only for a BUILDABLE reply,
    // so a bump proves the reply was actually synthesized and attempted.
    let state = build_forwarding_state(&native_gre_pbr_action_snapshot("reject"));
    let frame = build_ipv4_tcp_frame(
        Ipv4Addr::new(10, 0, 61, 100),
        Ipv4Addr::new(10, 255, 192, 41),
        49152,
        443,
        1,
        0,
        TCP_FLAG_SYN,
    );
    let meta = UserspaceDpMeta {
        ingress_ifindex: 5,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        pkt_len: frame.len() as u16,
        ..Default::default()
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
            src_port: 49152,
            dst_port: 443,
        },
    };
    let mut pipeline = pbr_reject_tx_pipeline(0);
    let mut counters = crate::afxdp::BatchCounters::default();
    let result = ingress_route_table_override(
        &state,
        &frame,
        meta,
        &flow,
        None,
        None,
        0,
        Some(PbrRejectSink {
            tx_pipeline: &mut pipeline,
            ingress_ifindex: 5,
            counters: &mut counters,
        }),
    );
    assert!(
        matches!(result, RouteOverride::Drop),
        "session-miss reject PBR term must DROP"
    );
    assert_eq!(
        counters.filter_reject_reply_budget_drops, 1,
        "a reject reply must be synthesized and attempted on the session-miss path"
    );

    // No-regression: an accept-only term with a sink attempts NO reply.
    let accept_state = build_forwarding_state(&native_gre_pbr_action_snapshot(""));
    let mut accept_pipeline = pbr_reject_tx_pipeline(0);
    let mut accept_counters = crate::afxdp::BatchCounters::default();
    let accept = ingress_route_table_override(
        &accept_state,
        &frame,
        meta,
        &flow,
        None,
        None,
        0,
        Some(PbrRejectSink {
            tx_pipeline: &mut accept_pipeline,
            ingress_ifindex: 5,
            counters: &mut accept_counters,
        }),
    );
    assert!(
        matches!(accept, RouteOverride::Table(_)),
        "accept routing-instance term must forward"
    );
    assert_eq!(
        accept_counters.filter_reject_reply_budget_drops, 0,
        "an accept PBR term must NOT synthesize a reject reply"
    );
}

// ---------------------------------------------------------------------------
// #4499 E7 — PBR routing-instance override + NAT64 cross-family translation.
// The PBR steer runs on the ORIGINAL IPv6 flow (poll_descriptor/mod.rs L1685),
// yielding `vrf1.inet6.0`; the route lookup for the NAT64-TRANSLATED IPv4
// destination is then performed IN that override table (L1733 threads
// `route_table_override.as_deref()`), and `canonical_route_table`
// re-canonicalizes `vrf1.inet6.0` -> `vrf1.inet.0` for the v4 destination. So
// the PBR override SURVIVES the NAT64 translation and the translated IPv4 dst
// lands in vrf1 — never leaking to the base `inet.0` table. Previously
// UNCOVERED: no test combined a PBR routing-instance override with NAT64.
// ---------------------------------------------------------------------------


#[test]
fn pbr_override_survives_nat64_translation_no_vrf_leak() {
    let state = build_forwarding_state(&pbr_nat64_snapshot());
    let neighbors = Arc::new(ShardedNeighborMap::new());

    let src_v6: Ipv6Addr = "2001:db8:61::100".parse().unwrap();
    // 192.0.2.7 embedded in 64:ff9b::/96 => 64:ff9b::c000:0207.
    let dst_v6: Ipv6Addr = "64:ff9b::c000:0207".parse().unwrap();
    let flow = SessionFlow {
        src_ip: IpAddr::V6(src_v6),
        dst_ip: IpAddr::V6(dst_v6),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: crate::ip_proto::PROTO_ICMPV6,
            src_ip: IpAddr::V6(src_v6),
            dst_ip: IpAddr::V6(dst_v6),
            src_port: 0,
            dst_port: 0,
        },
    };
    let meta = UserspaceDpMeta {
        ingress_ifindex: 5,
        addr_family: libc::AF_INET6 as u8,
        protocol: crate::ip_proto::PROTO_ICMPV6,
        ..Default::default()
    };

    // 1) PBR steer runs on the ORIGINAL IPv6 flow -> the v6 override table.
    let RouteOverride::Table(override_table) =
        ingress_route_table_override(&state, &[], meta, &flow, None, None, 0, None)
    else {
        panic!("a v6 PBR source term must steer the flow into the override table");
    };
    assert_eq!(
        override_table, "vrf1.inet6.0",
        "the PBR override is selected on the v6 flow, so it is the v6 table"
    );

    // 2) NAT64 classifies the synthetic v6 destination -> embedded IPv4 host.
    let dst_v4 = match state.nat64.classify_ipv6_dest(dst_v6) {
        crate::nat64::Nat64Match::MatchReady { dst_v4, .. } => dst_v4,
        _ => panic!("the NAT64 prefix must match the synthetic destination"),
    };
    assert_eq!(dst_v4, Ipv4Addr::new(192, 0, 2, 7));

    // 3) Route lookup for the TRANSLATED IPv4 destination using the v6-flow
    //    override table — exactly what the poll loop threads. The v4 lookup
    //    re-canonicalizes `vrf1.inet6.0` -> `vrf1.inet.0`, so the override
    //    SURVIVES the cross-family NAT64 translation: the dst lands in vrf1.
    let resolved = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        IpAddr::V4(dst_v4),
        Some(override_table.as_str()),
    );
    assert_eq!(
        resolved.egress_ifindex, 20,
        "the translated IPv4 dst must resolve in vrf1 (the PBR override survives NAT64)"
    );

    // 4) No-leak control: the base `inet.0` table has NO route for the
    //    vrf1-only translated dst, so a lookup that IGNORED the PBR override
    //    (used the base table) could never reach vrf1's egress 20.
    let leaked = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        IpAddr::V4(dst_v4),
        Some("inet.0"),
    );
    assert_ne!(
        leaked.egress_ifindex, 20,
        "the base table must NOT resolve the vrf1-only translated dst (no VRF leak)"
    );

    // 5) Control: PBR steer to vrf1 for a v6 destination with NO NAT64 prefix
    //    (no translation) — the override still selects `vrf1.inet6.0` and the
    //    untranslated v6 dst resolves in vrf1.
    let plain_dst_v6: Ipv6Addr = "2001:db8:dd::200".parse().unwrap();
    assert!(
        matches!(
            state.nat64.classify_ipv6_dest(plain_dst_v6),
            crate::nat64::Nat64Match::NoPrefixMatch
        ),
        "a non-prefix v6 dst is not NAT64-translated"
    );
    let plain_flow = SessionFlow {
        src_ip: IpAddr::V6(src_v6),
        dst_ip: IpAddr::V6(plain_dst_v6),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: crate::ip_proto::PROTO_ICMPV6,
            src_ip: IpAddr::V6(src_v6),
            dst_ip: IpAddr::V6(plain_dst_v6),
            src_port: 0,
            dst_port: 0,
        },
    };
    let RouteOverride::Table(plain_table) =
        ingress_route_table_override(&state, &[], meta, &plain_flow, None, None, 0, None)
    else {
        panic!("the v6 PBR term must steer the untranslated v6 flow too");
    };
    assert_eq!(plain_table, "vrf1.inet6.0");
    let plain_resolved = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        IpAddr::V6(plain_dst_v6),
        Some(plain_table.as_str()),
    );
    assert_eq!(
        plain_resolved.egress_ifindex, 20,
        "the untranslated v6 dst lands in vrf1.inet6.0"
    );
}

// ---------------------------------------------------------------------------
// #4499 H1 — output filter on the PBR egress (no output-filter bypass via PBR).
// The per-interface OUTPUT filter is keyed by the egress ifindex alone
// (filter/engine/eval.rs `iface_filter_out_v4_fast.get(&ifindex)`). After PBR
// selects the override table and the route lookup returns the vrf1 egress, the
// output filter that governs the forwarded/reflected packet is THAT egress's
// filter — not the base egress's. Pins that a PBR-steered flow cannot bypass an
// output filter by egressing a different interface.
// ---------------------------------------------------------------------------


#[test]
fn pbr_egress_output_filter_applied_not_base_egress_no_bypass() {
    let state = build_forwarding_state(&pbr_output_filter_snapshot());
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let src = Ipv4Addr::new(10, 0, 61, 100);
    let dst = Ipv4Addr::new(192, 0, 2, 7);
    let flow = SessionFlow {
        src_ip: IpAddr::V4(src),
        dst_ip: IpAddr::V4(dst),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(src),
            dst_ip: IpAddr::V4(dst),
            src_port: 40000,
            dst_port: 80,
        },
    };
    let meta = UserspaceDpMeta {
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..Default::default()
    };

    // PBR steers the flow into vrf1.
    let RouteOverride::Table(table) =
        ingress_route_table_override(&state, &[], meta, &flow, None, None, 0, None)
    else {
        panic!("the PBR term must steer the flow into vrf1");
    };
    assert_eq!(table, "vrf1.inet.0");

    // The PBR route lookup egresses vrf1's interface (20); the base table would
    // have egressed a DIFFERENT interface (30). The two egresses differ, so
    // WHICH egress filter is applied is load-bearing.
    let pbr = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        IpAddr::V4(dst),
        Some(table.as_str()),
    );
    let base = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &neighbors,
        IpAddr::V4(dst),
        Some("inet.0"),
    );
    assert_eq!(pbr.egress_ifindex, 20, "PBR selects the vrf1 egress");
    assert_eq!(base.egress_ifindex, 30, "the base egress is a DIFFERENT interface");

    // The output filter that governs the packet is the PBR-selected egress's
    // (20) — it DENIES tcp/80. The base egress (30) filter PERMITS it, so
    // evaluating the base filter would be an output-filter bypass.
    let extra = crate::filter::TermMatchExtra::default();
    let pbr_verdict = crate::filter::evaluate_interface_output_filter_counted(
        &state.filter_state,
        pbr.egress_ifindex,
        false,
        IpAddr::V4(src),
        IpAddr::V4(dst),
        PROTO_TCP,
        40000,
        80,
        0,
        extra,
        1500,
    );
    assert_eq!(
        pbr_verdict.action,
        crate::filter::FilterAction::Discard,
        "the PBR-selected egress output filter must DENY tcp/80"
    );

    let base_verdict = crate::filter::evaluate_interface_output_filter_counted(
        &state.filter_state,
        base.egress_ifindex,
        false,
        IpAddr::V4(src),
        IpAddr::V4(dst),
        PROTO_TCP,
        40000,
        80,
        0,
        extra,
        1500,
    );
    assert_eq!(
        base_verdict.action,
        crate::filter::FilterAction::Accept,
        "the base egress would have PERMITTED tcp/80 (the bypass this test guards against)"
    );

    // Control: a permit on the PBR egress forwards — tcp/443 is NOT denied by
    // the PBR egress's deny-80 filter.
    let allowed = crate::filter::evaluate_interface_output_filter_counted(
        &state.filter_state,
        pbr.egress_ifindex,
        false,
        IpAddr::V4(src),
        IpAddr::V4(dst),
        PROTO_TCP,
        40000,
        443,
        0,
        extra,
        1500,
    );
    assert_eq!(
        allowed.action,
        crate::filter::FilterAction::Accept,
        "a permit on the PBR egress forwards (deny-80 only denies port 80)"
    );
}

