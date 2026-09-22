// ICMP reject/unreachable generation and ICMP-in-error NAT reversal (v4 + v6).
//
// Split out of afxdp/tests.rs (#4840) as a sibling `#[path]` test module
// loaded from afxdp/mod.rs. Pure code motion: every #[test] fn is moved
// verbatim; shared test-support helpers live in afxdp/tests_support.rs.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::worker::WorkerTxPipeline;
use super::*;
use crate::test_zone_ids::*;
use crate::xsk_ffi::IfInfo;
use crate::{
    ClassOfServiceSnapshot, CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot,
    CoSForwardingClassSnapshot, CoSIEEE8021ClassifierEntrySnapshot, CoSIEEE8021ClassifierSnapshot,
    CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot, CoSSchedulerSnapshot,
    DestinationNATRuleSnapshot, FirewallFilterSnapshot, FirewallTermSnapshot,
    InterfaceAddressSnapshot, NeighborSnapshot, PolicyRuleSnapshot, RouteSnapshot,
    SourceNATRuleSnapshot, StaticNATRuleSnapshot, ThreeColorPolicerSnapshot, ZoneSnapshot,
};
use super::tests_support::*;

/// The reject path now routes through the same gate: an inbound ICMP
/// error still draws no reject reply, and a non-first fragment is
/// suppressed there too (#2237 unifies the two error generators).
#[test]
fn reject_unreachable_routes_through_shared_gate() {
    let client = Ipv4Addr::new(10, 0, 61, 102);
    let server = Ipv4Addr::new(1, 1, 1, 1);
    let fwd = reject_egress_forwarding(Some(Ipv4Addr::new(10, 0, 61, 1)), None);
    // Multicast destination — suppressed (was NOT covered by the old
    // inline reject checks, only the new shared gate catches it).
    let mcast = build_udp_frame_v4_full([0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb], client, Ipv4Addr::new(224, 0, 0, 251), 64);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    };
    assert!(
        build_reject_icmp_unreachable(
            &mcast,
            meta,
            5,
            &fwd,
            crate::filter::RejectMessage::ADMIN_PROHIBITED,
        ).is_none(),
        "reject path must suppress a multicast destination via the shared gate"
    );
    // A plain unicast UDP reject still works.
    let unicast = build_udp_frame_v4_full([0x00, 0x25, 0x90, 0x12, 0x34, 0x56], client, server, 64);
    assert!(
        build_reject_icmp_unreachable(
            &unicast,
            meta,
            5,
            &fwd,
            crate::filter::RejectMessage::ADMIN_PROHIBITED,
        ).is_some(),
        "reject path still replies to a normal unicast packet"
    );
}


/// #2242: the ICMPv6 error builder must quote enough of the invoking
/// packet to reach the transport header even when IPv6 extension headers
/// push it past byte 48, and the total error must stay within the IPv6
/// minimum MTU (1280).
#[test]
fn icmp_error_v6_quote_includes_transport_header_behind_ext_headers() {
    let client: Ipv6Addr = "2001:559:8585:ef00::102".parse().unwrap();
    let server: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
    // Build an inbound IPv6 packet: base header (next=Hop-by-Hop 0) +
    // a Hop-by-Hop ext header (8 bytes) + a Destination-Options ext
    // header (8 bytes) + UDP header. The UDP header therefore starts at
    // L3-relative offset 40 + 8 + 8 = 56 (> 48), so the OLD fixed-48
    // quote would have stopped inside the second ext header.
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]); // dst mac
    frame.extend_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]); // src mac
    frame.extend_from_slice(&[0x86, 0xdd]);
    let l3 = frame.len();
    // payload_len = HBH(8) + DstOpt(8) + UDP(8) = 24; next-header 0 (HBH).
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 24, 0, 1]);
    frame.extend_from_slice(&client.octets());
    frame.extend_from_slice(&server.octets());
    // Hop-by-Hop options: next-header = 60 (Dest-Opts), hdr-ext-len 0
    // (=> 8 bytes total), then 6 pad bytes.
    frame.extend_from_slice(&[60, 0, 1, 4, 0, 0, 0, 0]);
    // Destination-Options: next-header = UDP, hdr-ext-len 0, 6 pad bytes.
    frame.extend_from_slice(&[PROTO_UDP, 0, 1, 4, 0, 0, 0, 0]);
    // UDP header: src 0xABCD, dst 0x0035 (53), len 8, csum 0.
    let udp_off = frame.len();
    frame.extend_from_slice(&[0xAB, 0xCD, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]);
    let udp_rel = udp_off - l3; // L3-relative offset of UDP header
    assert!(udp_rel > 48, "fixture must place transport past byte 48");

    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: udp_off as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    };
    let fwd = icmp_suppress_forwarding();
    let out =
        build_local_time_exceeded_v6(&frame, meta, 5, &fwd).expect("build v6 TE with ext headers");
    // Quoted invoking packet starts after [Eth tag?][outer IPv6 40][ICMPv6
    // hdr 8]. Untagged egress => Eth 14 + IPv6 40 + ICMPv6 8 = 62.
    let quote_start = 62;
    // The quote must reach the UDP header (at L3-relative udp_rel) and
    // carry its ports.
    let q_udp = quote_start + udp_rel;
    assert!(
        out.len() >= q_udp + 4,
        "quote must include the transport header (len {} < {})",
        out.len(),
        q_udp + 4
    );
    assert_eq!(
        u16::from_be_bytes([out[q_udp], out[q_udp + 1]]),
        0xABCD,
        "quoted UDP source port must survive (transport header reached)"
    );
    assert_eq!(
        u16::from_be_bytes([out[q_udp + 2], out[q_udp + 3]]),
        0x0035,
        "quoted UDP dest port must survive"
    );
    // Total ICMPv6 error datagram (from outer IPv6 onward) <= 1280.
    let v6_total = out.len() - quote_start + 40 + 8; // outer IPv6 + ICMPv6 hdr + quote
    let _ = v6_total;
    // Equivalent bound: everything after the Ethernet header.
    assert!(
        out.len() - 14 <= 1280,
        "ICMPv6 error must not exceed the IPv6 minimum MTU"
    );
}


/// #2242: a large invoking IPv6 packet is quoted up to the 1232-byte cap
/// (not truncated to 48), keeping the total error within 1280.
#[test]
fn icmp_error_v6_quote_bounded_to_min_mtu() {
    let client: Ipv6Addr = "2001:559:8585:ef00::102".parse().unwrap();
    let server: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]);
    frame.extend_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.extend_from_slice(&[0x86, 0xdd]);
    let l3 = frame.len();
    // 2000-byte UDP payload after the UDP header => invoking packet is
    // much larger than 1232.
    let udp_payload = 2000usize;
    let payload_len = 8 + udp_payload; // UDP hdr + data
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
    frame.extend_from_slice(&[PROTO_UDP, 64]);
    frame.extend_from_slice(&client.octets());
    frame.extend_from_slice(&server.octets());
    frame.extend_from_slice(&[0xAB, 0xCD, 0x00, 0x35]);
    frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.resize(l3 + 40 + payload_len, 0);

    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: (l3 + 40) as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    };
    let fwd = icmp_suppress_forwarding();
    let out = build_local_time_exceeded_v6(&frame, meta, 5, &fwd).expect("build large v6 TE");
    // Untagged egress: Eth 14 + outer IPv6 40 + ICMPv6 hdr 8 = 62 prefix.
    let quote_start = 62;
    let quote_len = out.len() - quote_start;
    assert_eq!(
        quote_len, 1232,
        "large invoking packet quoted up to the 1232-byte min-MTU cap"
    );
    assert!(
        out.len() - 14 <= 1280,
        "ICMPv6 error must not exceed the IPv6 minimum MTU"
    );
}

// --- #2089 reject ICMP-unreachable builder tests ---


#[test]
fn reject_icmp_unreachable_v4_is_type3_code13_admin_prohibited() {
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_udp_frame_v4(client_ip, dst_ip);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    };
    let forwarding = reject_egress_forwarding(Some(Ipv4Addr::new(10, 0, 61, 1)), None);
    let out = build_reject_icmp_unreachable(
        &frame,
        meta,
        5,
        &forwarding,
        crate::filter::RejectMessage::ADMIN_PROHIBITED,
    )
        .expect("reject ICMP unreachable v4");
    // MAC reflect: reply dst = inbound src (client).
    assert_eq!(&out[0..6], &[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]);
    // IP: src = firewall ingress primary, dst = client.
    assert_eq!(
        Ipv4Addr::new(out[26], out[27], out[28], out[29]),
        Ipv4Addr::new(10, 0, 61, 1)
    );
    assert_eq!(Ipv4Addr::new(out[30], out[31], out[32], out[33]), client_ip);
    // ICMP type 3 (dest unreachable), code 13 (admin prohibited).
    assert_eq!(out[34], 3);
    assert_eq!(out[35], 13);
}


#[test]
fn reject_icmp_unreachable_v6_is_type1_code1_admin_prohibited() {
    let client_ip: Ipv6Addr = "2001:559:8585:ef00::102".parse().unwrap();
    let dst_ip: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
    // Reuse the echo-frame helper (ICMPv6 echo request = a query, not an
    // error) so the suppression guard does NOT fire: a rejected query
    // gets an unreachable.
    let frame = build_icmp_echo_frame_v6(client_ip, dst_ip, 64, crate::afxdp::tests_support::TEST_LAN_MAC);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };
    let forwarding = reject_egress_forwarding(None, Some("2001:559:8585:ef00::1".parse().unwrap()));
    let out = build_reject_icmp_unreachable(
        &frame,
        meta,
        5,
        &forwarding,
        crate::filter::RejectMessage::ADMIN_PROHIBITED,
    )
        .expect("reject ICMPv6 unreachable v6");
    // ICMPv6 type 1 (dest unreachable), code 1 (admin prohibited).
    assert_eq!(out[54], 1);
    assert_eq!(out[55], 1);
}


#[test]
fn reject_icmp_unreachable_suppressed_for_inbound_icmp_error() {
    // An inbound ICMPv4 error (type 3) must NOT draw a reject reply.
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    let mut frame = build_icmp_echo_frame_v4(client_ip, dst_ip, 64, crate::afxdp::tests_support::TEST_LAN_MAC);
    // Rewrite the ICMP type byte (at l4_offset = 34) to 3 (dest unreach).
    frame[34] = 3;
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let forwarding = reject_egress_forwarding(Some(Ipv4Addr::new(10, 0, 61, 1)), None);
    assert!(
        build_reject_icmp_unreachable(
            &frame,
            meta,
            5,
            &forwarding,
            crate::filter::RejectMessage::ADMIN_PROHIBITED,
        ).is_none(),
        "must not reply to an inbound ICMP error"
    );
    // Direct guard checks.
    assert!(reject_icmp_reply_suppressed(PROTO_ICMP, 3));
    assert!(reject_icmp_reply_suppressed(PROTO_ICMP, 11));
    assert!(!reject_icmp_reply_suppressed(PROTO_ICMP, 8)); // echo request: reply
    assert!(reject_icmp_reply_suppressed(PROTO_ICMPV6, 1));
    assert!(reject_icmp_reply_suppressed(PROTO_ICMPV6, 127));
    assert!(!reject_icmp_reply_suppressed(PROTO_ICMPV6, 128)); // echo request: reply
    assert!(!reject_icmp_reply_suppressed(PROTO_UDP, 0));
}

// --- ICMP error NAT reversal tests ---


#[test]
fn icmp_te_nat_reversal_v4_rewrites_outer_dst_and_embedded_src() {
    // Scenario: client 10.0.61.102 -> server 1.1.1.1, SNAT'd to 172.16.80.8
    // Router 10.0.0.1 sends ICMP Time Exceeded back to 172.16.80.8
    // NAT reversal: outer dst 172.16.80.8 -> 10.0.61.102,
    //               embedded src 172.16.80.8 -> 10.0.61.102
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;

    let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(snat_ip)),
            rewrite_src_port: Some(snat_port),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(client_ip),
        original_src_port: client_port,
        original_dst: IpAddr::V4(server_ip),
        original_dst_port: 80,
        embedded_proto: PROTO_TCP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 5,
            tx_ifindex: 5,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(client_ip)),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_UNTRUST_ZONE_ID,
            egress_zone: TEST_TRUST_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        outbound_snat: false,
    };

    let result = build_nat_reversed_icmp_error_v4(&frame, meta, &icmp_match)
        .expect("should build NAT-reversed frame");
    assert_eq!(result[22], 63, "same-family IPv4 reversal decrements TTL");
    let mut expired_frame = frame.clone();
    expired_frame[14 + 8] = 1;
    expired_frame[14 + 10..14 + 12].copy_from_slice(&[0, 0]);
    let expired_csum = checksum16(&expired_frame[14..34]);
    expired_frame[14 + 10..14 + 12].copy_from_slice(&expired_csum.to_be_bytes());
    assert!(
        build_nat_reversed_icmp_error_v4(&expired_frame, meta, &icmp_match).is_none(),
        "same-family IPv4 reversal drops TTL<=1"
    );
    let mut fabric_meta = meta;
    fabric_meta.meta_flags |= FABRIC_INGRESS_FLAG;
    let mut fabric_frame = frame.clone();
    fabric_frame[14 + 8] = 1;
    fabric_frame[14 + 10..14 + 12].copy_from_slice(&[0, 0]);
    let fabric_csum = checksum16(&fabric_frame[14..34]);
    fabric_frame[14 + 10..14 + 12].copy_from_slice(&fabric_csum.to_be_bytes());
    let fabric_result = build_nat_reversed_icmp_error_v4(
        &fabric_frame,
        fabric_meta,
        &icmp_match,
    )
    .expect("fabric-ingress reversal must preserve peer-decremented TTL");
    assert_eq!(
        fabric_result[22], 1,
        "fabric-ingress reversal must not decrement TTL again"
    );


    // Verify Ethernet header
    assert_eq!(&result[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst MAC
    assert_eq!(&result[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]); // src MAC
    assert_eq!(&result[12..14], &[0x08, 0x00]); // ethertype IPv4

    // Verify outer IP dst is now the original client
    let outer_dst = Ipv4Addr::new(result[30], result[31], result[32], result[33]);
    assert_eq!(
        outer_dst, client_ip,
        "outer IP dst should be original client"
    );

    // Verify outer IP src is still the router
    let outer_src = Ipv4Addr::new(result[26], result[27], result[28], result[29]);
    assert_eq!(outer_src, router_ip, "outer IP src should remain router");

    // Verify embedded IP src is now the original client
    // Embedded IP starts at: eth(14) + outer_ip(20) + icmp_hdr(8) = 42
    let emb_ip_start = 42;
    let emb_src = Ipv4Addr::new(
        result[emb_ip_start + 12],
        result[emb_ip_start + 13],
        result[emb_ip_start + 14],
        result[emb_ip_start + 15],
    );
    assert_eq!(emb_src, client_ip, "embedded src should be original client");

    // Verify embedded dst is still the server
    let emb_dst = Ipv4Addr::new(
        result[emb_ip_start + 16],
        result[emb_ip_start + 17],
        result[emb_ip_start + 18],
        result[emb_ip_start + 19],
    );
    assert_eq!(emb_dst, server_ip, "embedded dst should remain server");

    // Verify embedded TCP src port is now the original client port
    let emb_l4_start = emb_ip_start + 20; // IHL=5, so 20 bytes
    let emb_port = u16::from_be_bytes([result[emb_l4_start], result[emb_l4_start + 1]]);
    assert_eq!(
        emb_port, client_port,
        "embedded src port should be original"
    );

    // Verify outer IP checksum is valid
    let outer_ihl = ((result[14] & 0x0f) as usize) * 4;
    let ip_csum_check = checksum16(&result[14..14 + outer_ihl]);
    assert_eq!(ip_csum_check, 0, "outer IP checksum should be valid (0)");

    // Verify outer ICMP checksum is valid
    let icmp_start = 14 + outer_ihl;
    let icmp_csum_check = checksum16(&result[icmp_start..]);
    assert_eq!(
        icmp_csum_check, 0,
        "outer ICMP checksum should be valid (0)"
    );

    // Verify embedded IP checksum is valid
    let emb_ihl = ((result[emb_ip_start] & 0x0f) as usize) * 4;
    let emb_ip_csum_check = checksum16(&result[emb_ip_start..emb_ip_start + emb_ihl]);
    assert_eq!(
        emb_ip_csum_check, 0,
        "embedded IP checksum should be valid (0)"
    );
}


#[test]
fn icmp_te_nat_reversal_v4_with_port_snat() {
    // Same as above but verifying UDP port reversal specifically
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_port: u16 = 50000;
    let client_port: u16 = 5353;

    let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, snat_port, 53, PROTO_UDP);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(snat_ip)),
            rewrite_src_port: Some(snat_port),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(client_ip),
        original_src_port: client_port,
        original_dst: IpAddr::V4(server_ip),
        original_dst_port: 53,
        embedded_proto: PROTO_UDP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 5,
            tx_ifindex: 5,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(client_ip)),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_UNTRUST_ZONE_ID,
            egress_zone: TEST_TRUST_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        outbound_snat: false,
    };

    let result = build_nat_reversed_icmp_error_v4(&frame, meta, &icmp_match)
        .expect("should build NAT-reversed frame");

    // Verify embedded UDP src port is now the original client port
    let emb_ip_start = 42; // eth(14) + outer_ip(20) + icmp_hdr(8)
    let emb_l4_start = emb_ip_start + 20;
    let emb_port = u16::from_be_bytes([result[emb_l4_start], result[emb_l4_start + 1]]);
    assert_eq!(
        emb_port, client_port,
        "embedded UDP src port should be original"
    );

    // Verify all checksums
    let ip_csum_check = checksum16(&result[14..34]);
    assert_eq!(ip_csum_check, 0, "outer IP checksum should be valid");
    let icmp_csum_check = checksum16(&result[34..]);
    assert_eq!(icmp_csum_check, 0, "outer ICMP checksum should be valid");
}


#[test]
fn icmp_dest_unreach_nat_reversal_v4() {
    // ICMP Destination Unreachable (type 3, code 1) with embedded TCP
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);

    // Build ICMP Destination Unreachable frame manually
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    let ip_start = frame.len();

    // Embedded IP+TCP
    let mut embedded = Vec::new();
    embedded.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    embedded.extend_from_slice(&snat_ip.octets());
    embedded.extend_from_slice(&server_ip.octets());
    let emb_total = (20 + 8) as u16;
    embedded[2..4].copy_from_slice(&emb_total.to_be_bytes());
    embedded.extend_from_slice(&40000u16.to_be_bytes()); // src port (SNAT'd)
    embedded.extend_from_slice(&80u16.to_be_bytes()); // dst port
    embedded.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq
    embedded[10..12].copy_from_slice(&[0, 0]);
    let emb_ip_csum = checksum16(&embedded[..20]);
    embedded[10..12].copy_from_slice(&emb_ip_csum.to_be_bytes());

    // ICMP type=3 (Dest Unreach), code=1 (Host Unreachable)
    let mut icmp = Vec::new();
    icmp.extend_from_slice(&[3, 1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    icmp.extend_from_slice(&embedded);
    icmp[2..4].copy_from_slice(&[0, 0]);
    let icmp_csum = checksum16(&icmp);
    icmp[2..4].copy_from_slice(&icmp_csum.to_be_bytes());

    // Outer IP
    let outer_total = (20 + icmp.len()) as u16;
    frame.extend_from_slice(&[0x45, 0x00]);
    frame.extend_from_slice(&outer_total.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x02, 0x00, 0x00, 64, PROTO_ICMP, 0x00, 0x00]);
    frame.extend_from_slice(&router_ip.octets());
    frame.extend_from_slice(&snat_ip.octets());
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&[0, 0]);
    let ip_csum = checksum16(&frame[ip_start..ip_start + 20]);
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_csum.to_be_bytes());
    frame.extend_from_slice(&icmp);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };

    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(snat_ip)),
            rewrite_src_port: Some(40000),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(client_ip),
        original_src_port: 12345,
        original_dst: IpAddr::V4(server_ip),
        original_dst_port: 80,
        embedded_proto: PROTO_TCP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 5,
            tx_ifindex: 5,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(client_ip)),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_UNTRUST_ZONE_ID,
            egress_zone: TEST_TRUST_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        outbound_snat: false,
    };

    let result = build_nat_reversed_icmp_error_v4(&frame, meta, &icmp_match)
        .expect("should build NAT-reversed frame");

    // Verify outer IP dst is client
    let outer_dst = Ipv4Addr::new(result[30], result[31], result[32], result[33]);
    assert_eq!(outer_dst, client_ip);

    // Verify ICMP type/code NOT modified
    assert_eq!(result[34], 3, "ICMP type must remain Dest Unreach");
    assert_eq!(result[35], 1, "ICMP code must remain Host Unreachable");

    // Verify checksums
    let ip_csum_check = checksum16(&result[14..34]);
    assert_eq!(ip_csum_check, 0);
    let icmp_csum_check = checksum16(&result[34..]);
    assert_eq!(icmp_csum_check, 0);
}

// === #3112: embedded-DESTINATION reversal for DNAT/static-NAT ===


#[test]
fn icmp_dnat_reversal_v4_rewrites_embedded_dst_and_outer_src() {
    // Scenario: client C -> public P:80, DNAT to private S:8080. The
    // server S returns an ICMP error quoting the packet it received
    // (src=C, dst=S:8080), with outer src=S, outer dst=C. For the client
    // to match the error to the session it opened to P:80, the embedded
    // destination must be un-DNAT'd S:8080 -> P:80 and the outer source
    // rewritten S -> P. (#3112)
    let client_c = Ipv4Addr::new(10, 0, 61, 102);
    let public_p = Ipv4Addr::new(203, 0, 113, 9);
    let private_s = Ipv4Addr::new(10, 0, 90, 50);
    let client_port: u16 = 51000;
    let public_port: u16 = 80;
    let private_port: u16 = 8080;

    // build_icmp_te_frame_v4(outer_src, outer_dst, embedded_dst,
    //   embedded_src_port, embedded_dst_port, proto): the "snat_ip"
    // parameter doubles as outer-dst AND embedded-src, which for the DNAT
    // return is the client.
    let frame = build_icmp_te_frame_v4(
        private_s,    // outer src = server that emitted the error
        client_c,     // outer dst + embedded src = client
        private_s,    // embedded dst = the DNAT'd private server
        client_port,  // embedded src port
        private_port, // embedded dst port (the DNAT'd port)
        PROTO_TCP,
    );

    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_dst: Some(IpAddr::V4(private_s)),
            rewrite_dst_port: Some(private_port),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(client_c),
        original_src_port: client_port,
        original_dst: IpAddr::V4(public_p),
        original_dst_port: public_port,
        embedded_proto: PROTO_TCP,
        resolution: icmp_err_resolution_v4(client_c),
        metadata: icmp_err_metadata(),
        outbound_snat: false,
    };

    let result = build_nat_reversed_icmp_error_v4(&frame, icmp_err_meta_v4(), &icmp_match)
        .expect("should build NAT-reversed frame");

    // Outer src is now the public address the client used.
    let outer_src = Ipv4Addr::new(result[26], result[27], result[28], result[29]);
    assert_eq!(outer_src, public_p, "outer src must be un-DNAT'd to public P");
    // Outer dst is still the client.
    let outer_dst = Ipv4Addr::new(result[30], result[31], result[32], result[33]);
    assert_eq!(outer_dst, client_c, "outer dst stays the client");

    let emb = 42; // eth(14)+outer ip(20)+icmp(8)
    let emb_src = Ipv4Addr::new(result[emb + 12], result[emb + 13], result[emb + 14], result[emb + 15]);
    assert_eq!(emb_src, client_c, "embedded src (client) unchanged");
    let emb_dst = Ipv4Addr::new(result[emb + 16], result[emb + 17], result[emb + 18], result[emb + 19]);
    assert_eq!(emb_dst, public_p, "embedded dst must be un-DNAT'd to public P");

    // Embedded transport ports: src unchanged (no SNAT), dst un-DNAT'd.
    let emb_l4 = emb + 20;
    assert_eq!(
        u16::from_be_bytes([result[emb_l4], result[emb_l4 + 1]]),
        client_port,
        "embedded src port unchanged"
    );
    assert_eq!(
        u16::from_be_bytes([result[emb_l4 + 2], result[emb_l4 + 3]]),
        public_port,
        "embedded dst port must be un-DNAT'd to the public port"
    );

    // All checksums valid.
    assert_eq!(checksum16(&result[14..34]), 0, "outer IP checksum");
    assert_eq!(checksum16(&result[34..]), 0, "outer ICMP checksum");
    assert_eq!(checksum16(&result[emb..emb + 20]), 0, "embedded IP checksum");
}


#[test]
fn icmp_static_nat_reversal_v4_rewrites_embedded_dst() {
    // Static 1:1 inbound: client C -> public P, statically mapped to
    // private S (IP-only, no port translation). The embedded dst must be
    // rewritten S -> P; ports are unchanged (original_dst_port == the
    // embedded dst port, so the gated dst-port write is a no-op).
    let client_c = Ipv4Addr::new(10, 0, 61, 102);
    let public_p = Ipv4Addr::new(198, 51, 100, 7);
    let private_s = Ipv4Addr::new(10, 0, 90, 51);
    let client_port: u16 = 52000;
    let server_port: u16 = 443;

    let frame = build_icmp_te_frame_v4(
        private_s,
        client_c,
        private_s,
        client_port,
        server_port,
        PROTO_TCP,
    );

    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            // static 1:1 reverses dst only (IP), no port DNAT.
            rewrite_dst: Some(IpAddr::V4(private_s)),
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(client_c),
        original_src_port: client_port,
        original_dst: IpAddr::V4(public_p),
        original_dst_port: server_port, // unchanged port -> no-op
        embedded_proto: PROTO_TCP,
        resolution: icmp_err_resolution_v4(client_c),
        metadata: icmp_err_metadata(),
        outbound_snat: false,
    };

    let result = build_nat_reversed_icmp_error_v4(&frame, icmp_err_meta_v4(), &icmp_match)
        .expect("should build NAT-reversed frame");

    let outer_src = Ipv4Addr::new(result[26], result[27], result[28], result[29]);
    assert_eq!(outer_src, public_p, "outer src un-NAT'd to public P");
    let emb = 42;
    let emb_dst = Ipv4Addr::new(result[emb + 16], result[emb + 17], result[emb + 18], result[emb + 19]);
    assert_eq!(emb_dst, public_p, "embedded dst un-NAT'd to public P");
    let emb_l4 = emb + 20;
    assert_eq!(
        u16::from_be_bytes([result[emb_l4 + 2], result[emb_l4 + 3]]),
        server_port,
        "embedded dst port unchanged (IP-only static NAT)"
    );
    assert_eq!(checksum16(&result[14..34]), 0);
    assert_eq!(checksum16(&result[34..]), 0);
    assert_eq!(checksum16(&result[emb..emb + 20]), 0);
}


#[test]
fn icmp_snat_only_reversal_v4_leaves_destination_untouched() {
    // Regression guard (#3112 fail-on-revert pair): with NO destination
    // NAT (rewrite_dst == None), the destination-side rewrites are gated
    // OFF — outer src, embedded dst, and embedded dst port stay exactly
    // as on the wire, even when original_dst is (deliberately) bogus.
    // This is the byte-identical SNAT-only path.
    let router = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;

    let frame = build_icmp_te_frame_v4(router, snat_ip, server_ip, snat_port, 80, PROTO_TCP);

    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(snat_ip)),
            rewrite_src_port: Some(snat_port),
            // rewrite_dst stays None -> destination rewrite must not fire.
            ..NatDecision::default()
        },
        original_src: IpAddr::V4(client_ip),
        original_src_port: client_port,
        // Deliberately bogus values: must be ignored because no dst NAT.
        original_dst: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
        original_dst_port: 65000,
        embedded_proto: PROTO_TCP,
        resolution: icmp_err_resolution_v4(client_ip),
        metadata: icmp_err_metadata(),
        outbound_snat: false,
    };

    let result = build_nat_reversed_icmp_error_v4(&frame, icmp_err_meta_v4(), &icmp_match)
        .expect("should build NAT-reversed frame");

    // Outer src stays the router (NOT the bogus original_dst).
    let outer_src = Ipv4Addr::new(result[26], result[27], result[28], result[29]);
    assert_eq!(outer_src, router, "SNAT-only: outer src untouched");
    let emb = 42;
    let emb_dst = Ipv4Addr::new(result[emb + 16], result[emb + 17], result[emb + 18], result[emb + 19]);
    assert_eq!(emb_dst, server_ip, "SNAT-only: embedded dst untouched");
    let emb_l4 = emb + 20;
    assert_eq!(
        u16::from_be_bytes([result[emb_l4 + 2], result[emb_l4 + 3]]),
        80,
        "SNAT-only: embedded dst port untouched"
    );
    // Source-side reversal still applies (unchanged behaviour).
    let emb_src = Ipv4Addr::new(result[emb + 12], result[emb + 13], result[emb + 14], result[emb + 15]);
    assert_eq!(emb_src, client_ip, "SNAT-only: source still reversed");
    assert_eq!(
        u16::from_be_bytes([result[emb_l4], result[emb_l4 + 1]]),
        client_port
    );
    assert_eq!(checksum16(&result[14..34]), 0);
    assert_eq!(checksum16(&result[34..]), 0);
    assert_eq!(checksum16(&result[emb..emb + 20]), 0);
}


#[test]
fn icmpv6_te_nat_reversal_v6_rewrites_outer_dst_and_embedded_src() {
    let router_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let snat_ip: Ipv6Addr = "2001:db8:1::100".parse().unwrap();
    let client_ip: Ipv6Addr = "fd00::102".parse().unwrap();
    let server_ip: Ipv6Addr = "2001:db8:2::1".parse().unwrap();
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;

    let frame = build_icmpv6_te_frame(router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };

    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6(snat_ip)),
            rewrite_src_port: Some(snat_port),
            ..NatDecision::default()
        },
        original_src: IpAddr::V6(client_ip),
        original_src_port: client_port,
        original_dst: IpAddr::V6(client_ip),
        original_dst_port: client_port,
        embedded_proto: PROTO_TCP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 5,
            tx_ifindex: 5,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(client_ip)),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_UNTRUST_ZONE_ID,
            egress_zone: TEST_TRUST_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        outbound_snat: false,
    };

    let result = build_nat_reversed_icmp_error_v6(&frame, meta, &icmp_match)
        .expect("should build NAT-reversed ICMPv6 frame");
    assert_eq!(result[21], 63, "same-family IPv6 reversal decrements hop-limit");
    let mut expired_frame = frame.clone();
    expired_frame[14 + 7] = 1;
    assert!(
        build_nat_reversed_icmp_error_v6(&expired_frame, meta, &icmp_match).is_none(),
        "same-family IPv6 reversal drops hop-limit<=1"
    );
    let mut fabric_meta = meta;
    fabric_meta.meta_flags |= FABRIC_INGRESS_FLAG;
    let mut fabric_frame = frame.clone();
    fabric_frame[14 + 7] = 1;
    let fabric_result = build_nat_reversed_icmp_error_v6(
        &fabric_frame,
        fabric_meta,
        &icmp_match,
    )
    .expect("fabric-ingress reversal must preserve peer-decremented hop-limit");
    assert_eq!(
        fabric_result[21], 1,
        "fabric-ingress reversal must not decrement hop-limit again"
    );

    // Verify Ethernet header
    assert_eq!(&result[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst MAC
    assert_eq!(&result[12..14], &[0x86, 0xdd]); // ethertype IPv6

    // Verify outer IPv6 dst is now the original client (bytes 24..40 in IPv6)
    let outer_dst_bytes: [u8; 16] = result[38..54].try_into().unwrap();
    let outer_dst = Ipv6Addr::from(outer_dst_bytes);
    assert_eq!(
        outer_dst, client_ip,
        "outer IPv6 dst should be original client"
    );

    // Verify outer IPv6 src is still the router (bytes 8..24 in IPv6)
    let outer_src_bytes: [u8; 16] = result[22..38].try_into().unwrap();
    let outer_src = Ipv6Addr::from(outer_src_bytes);
    assert_eq!(outer_src, router_ip, "outer IPv6 src should remain router");

    // Verify embedded IPv6 src is now the original client
    // Embedded IPv6 starts at: eth(14) + outer_ipv6(40) + icmpv6_hdr(8) = 62
    let emb_ip_start = 62;
    let emb_src_bytes: [u8; 16] = result[emb_ip_start + 8..emb_ip_start + 24]
        .try_into()
        .unwrap();
    let emb_src = Ipv6Addr::from(emb_src_bytes);
    assert_eq!(
        emb_src, client_ip,
        "embedded IPv6 src should be original client"
    );

    // Verify embedded dst is still the server
    let emb_dst_bytes: [u8; 16] = result[emb_ip_start + 24..emb_ip_start + 40]
        .try_into()
        .unwrap();
    let emb_dst = Ipv6Addr::from(emb_dst_bytes);
    assert_eq!(emb_dst, server_ip, "embedded IPv6 dst should remain server");

    // Verify embedded TCP src port
    let emb_l4_start = emb_ip_start + 40;
    let emb_port = u16::from_be_bytes([result[emb_l4_start], result[emb_l4_start + 1]]);
    assert_eq!(
        emb_port, client_port,
        "embedded src port should be original"
    );

    // Verify ICMPv6 checksum is valid
    let icmp6_start = 54; // eth(14) + ipv6(40)
    let src_v6 = Ipv6Addr::from(outer_src_bytes);
    let dst_v6 = Ipv6Addr::from(outer_dst_bytes);
    let icmp6_data = &result[icmp6_start..];
    // Zero checksum and recompute
    let mut icmp6_copy = icmp6_data.to_vec();
    icmp6_copy[2] = 0;
    icmp6_copy[3] = 0;
    let expected_csum = checksum16_ipv6(src_v6, dst_v6, PROTO_ICMPV6, &icmp6_copy);
    let actual_csum = u16::from_be_bytes([icmp6_data[2], icmp6_data[3]]);
    assert_eq!(
        actual_csum, expected_csum,
        "ICMPv6 checksum should be valid"
    );
}


#[test]
fn icmpv6_dnat66_reversal_v6_rewrites_embedded_dst_and_outer_src() {
    // DNAT66: client C -> public P:443, mapped to internal S:8443. The
    // returning ICMPv6 error from S quotes (src=C, dst=S:8443) with outer
    // src=S, outer dst=C. The embedded dst must be un-NAT'd S:8443 ->
    // P:443 and the outer source rewritten S -> P, with a valid ICMPv6
    // checksum (pseudo-header over the rewritten outer addresses). (#3112)
    let client_c: Ipv6Addr = "fd00::102".parse().unwrap();
    let public_p: Ipv6Addr = "2001:db8:cafe::1".parse().unwrap();
    let internal_s: Ipv6Addr = "fd00:90::50".parse().unwrap();
    let client_port: u16 = 51000;
    let public_port: u16 = 443;
    let internal_port: u16 = 8443;

    // build_icmpv6_te_frame(outer_src, outer_dst+embedded_src,
    //   embedded_dst, embedded_src_port, embedded_dst_port, proto).
    let frame = build_icmpv6_te_frame(
        internal_s,
        client_c,
        internal_s,
        client_port,
        internal_port,
        PROTO_TCP,
    );

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };

    let icmp_match = EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_dst: Some(IpAddr::V6(internal_s)),
            rewrite_dst_port: Some(internal_port),
            ..NatDecision::default()
        },
        original_src: IpAddr::V6(client_c),
        original_src_port: client_port,
        original_dst: IpAddr::V6(public_p),
        original_dst_port: public_port,
        embedded_proto: PROTO_TCP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 5,
            tx_ifindex: 5,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(client_c)),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        },
        metadata: icmp_err_metadata(),
        outbound_snat: false,
    };

    let result = build_nat_reversed_icmp_error_v6(&frame, meta, &icmp_match)
        .expect("should build NAT-reversed ICMPv6 frame");

    // Outer src un-NAT'd to public P (bytes 22..38), outer dst stays C.
    let outer_src = Ipv6Addr::from(<[u8; 16]>::try_from(&result[22..38]).unwrap());
    assert_eq!(outer_src, public_p, "outer IPv6 src un-NAT'd to public P");
    let outer_dst = Ipv6Addr::from(<[u8; 16]>::try_from(&result[38..54]).unwrap());
    assert_eq!(outer_dst, client_c, "outer IPv6 dst stays the client");

    let emb = 62; // eth(14)+outer(40)+icmp6(8)
    let emb_src = Ipv6Addr::from(<[u8; 16]>::try_from(&result[emb + 8..emb + 24]).unwrap());
    assert_eq!(emb_src, client_c, "embedded src (client) unchanged");
    let emb_dst = Ipv6Addr::from(<[u8; 16]>::try_from(&result[emb + 24..emb + 40]).unwrap());
    assert_eq!(emb_dst, public_p, "embedded dst un-NAT'd to public P");

    let emb_l4 = emb + 40;
    assert_eq!(
        u16::from_be_bytes([result[emb_l4], result[emb_l4 + 1]]),
        client_port,
        "embedded src port unchanged"
    );
    assert_eq!(
        u16::from_be_bytes([result[emb_l4 + 2], result[emb_l4 + 3]]),
        public_port,
        "embedded dst port un-NAT'd to the public port"
    );

    // ICMPv6 checksum valid over the rewritten outer pseudo-header.
    let icmp6_start = 54;
    let mut icmp6_copy = result[icmp6_start..].to_vec();
    icmp6_copy[2] = 0;
    icmp6_copy[3] = 0;
    let expected = {
        let c = checksum16_ipv6(outer_src, outer_dst, PROTO_ICMPV6, &icmp6_copy);
        if c == 0 { 0xffff } else { c }
    };
    let actual = u16::from_be_bytes([result[icmp6_start + 2], result[icmp6_start + 3]]);
    assert_eq!(actual, expected, "ICMPv6 checksum valid after dst reversal");
}


/// #1838 §5.7: an ICMPv6 error whose OUTER packet carries an extension
/// header. The NAT match is ext-aware (reads the ICMP type at
/// meta.l4_offset), so this input matched — and the old fixed-40
/// builder then wrote the embedded un-NAT and the checksum recompute
/// inside the outer hop-by-hop header. With the shared offset helper
/// the un-NAT lands at the real offsets and the output verifies.
#[test]
fn icmpv6_te_nat_reversal_outer_ext_header_lands_at_real_offsets() {
    let router_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let snat_ip: Ipv6Addr = "2001:db8:1::100".parse().unwrap();
    let client_ip: Ipv6Addr = "fd00::102".parse().unwrap();
    let server_ip: Ipv6Addr = "2001:db8:2::1".parse().unwrap();
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;

    let frame = build_icmpv6_te_frame_ext(
        router_ip,
        snat_ip,
        server_ip,
        snat_port,
        80,
        true,
        None,
        &[],
    );
    // Outer L4 (ICMPv6) at eth(14) + IPv6(40) + hop-by-hop(8) = 62.
    let meta = icmpv6_te_meta(62);
    let icmp_match = icmpv6_te_match_fixture(snat_ip, client_ip, snat_port, client_port);

    let result = build_nat_reversed_icmp_error_v6(&frame, meta, &icmp_match)
        .expect("should build NAT-reversed ICMPv6 frame for outer-ext error");

    // Outer dst rewritten to the original client.
    let outer_dst = Ipv6Addr::from(<[u8; 16]>::try_from(&result[38..54]).unwrap());
    assert_eq!(outer_dst, client_ip);
    // Hop-by-hop bytes untouched (the old fixed-40 builder scribbled
    // the embedded src into them).
    assert_eq!(
        &result[54..62],
        &frame[54..62],
        "outer extension header must not be modified"
    );
    // Embedded IPv6 src is the original client at the REAL offset:
    // eth(14) + outer(40) + hbh(8) + icmp6(8) = 70.
    let emb_ip_start = 70;
    let emb_src =
        Ipv6Addr::from(<[u8; 16]>::try_from(&result[emb_ip_start + 8..emb_ip_start + 24]).unwrap());
    assert_eq!(emb_src, client_ip, "embedded src restored at real offset");
    // Embedded TCP src port restored.
    let emb_l4 = emb_ip_start + 40;
    assert_eq!(
        u16::from_be_bytes([result[emb_l4], result[emb_l4 + 1]]),
        client_port,
        "embedded src port restored at real offset"
    );
    // ICMPv6 checksum recomputed with the CORRECT coverage (from the
    // real icmp_offset 48, upper-layer length = len - 48): receiver
    // verification over the stored checksum folds to zero.
    let outer_src = Ipv6Addr::from(<[u8; 16]>::try_from(&result[22..38]).unwrap());
    assert_eq!(
        checksum16_ipv6(outer_src, outer_dst, PROTO_ICMPV6, &result[62..]),
        0,
        "ICMPv6 checksum must verify with ext-aware coverage"
    );
}


/// #1838 §5.7 (Codex r2): a quoted NON-FIRST fragment has no L4
/// header — the builder must not write "ports" into its payload
/// bytes. A quoted FIRST/atomic fragment does carry the L4 header
/// after the fragment header — the restore must land there.
#[test]
fn icmpv6_te_nat_reversal_embedded_fragment_handling() {
    let router_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let snat_ip: Ipv6Addr = "2001:db8:1::100".parse().unwrap();
    let client_ip: Ipv6Addr = "fd00::102".parse().unwrap();
    let server_ip: Ipv6Addr = "2001:db8:2::1".parse().unwrap();
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;
    let emb_ip_start = 62; // eth(14) + outer(40) + icmp6(8)

    // Non-first fragment (offset bits nonzero): embedded address is
    // still restored (offset-independent), but the fragment header and
    // the quoted payload bytes after it are byte-identical to input —
    // no port write lands in payload.
    let frame = build_icmpv6_te_frame_ext(
        router_ip,
        snat_ip,
        server_ip,
        snat_port,
        80,
        false,
        Some(0x0008), // fragment offset 1, M=0
        &[],
    );
    let meta = icmpv6_te_meta(54);
    let icmp_match = icmpv6_te_match_fixture(snat_ip, client_ip, snat_port, client_port);
    let result = build_nat_reversed_icmp_error_v6(&frame, meta, &icmp_match)
        .expect("builder still produces the error frame");
    let emb_src =
        Ipv6Addr::from(<[u8; 16]>::try_from(&result[emb_ip_start + 8..emb_ip_start + 24]).unwrap());
    assert_eq!(emb_src, client_ip, "address restore is offset-independent");
    assert_eq!(
        &result[emb_ip_start + 40..],
        &frame[emb_ip_start + 40..],
        "non-first fragment: fragment header + payload bytes untouched"
    );

    // First/atomic fragment (offset 0): the L4 header follows the
    // fragment header — the port restore lands at emb_ip + 48.
    let frame = build_icmpv6_te_frame_ext(
        router_ip,
        snat_ip,
        server_ip,
        snat_port,
        80,
        false,
        Some(0x0001), // offset 0, M=1 (first fragment)
        &[],
    );
    let result = build_nat_reversed_icmp_error_v6(&frame, meta, &icmp_match)
        .expect("builder produces the error frame");
    let emb_l4 = emb_ip_start + 48;
    assert_eq!(
        u16::from_be_bytes([result[emb_l4], result[emb_l4 + 1]]),
        client_port,
        "first/atomic fragment: port restored after the fragment header"
    );
}


/// #1838 §5.7 (Codex r2 medium 2): the builder's final ICMPv6 checksum
/// recompute canonicalizes a computed 0x0000 to 0xFFFF — representation
/// assertion on the STORED field (a verify-style oracle accepts both
/// encodings of one's-complement zero and cannot see this).
#[test]
fn icmpv6_te_nat_reversal_computed_zero_checksum_stored_as_ffff() {
    let router_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let snat_ip: Ipv6Addr = "2001:db8:1::100".parse().unwrap();
    let client_ip: Ipv6Addr = "fd00::102".parse().unwrap();
    let server_ip: Ipv6Addr = "2001:db8:2::1".parse().unwrap();
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;
    let icmp6_start = 54; // eth(14) + outer IPv6(40)

    // Pass 1: zero balancing word → read the stored checksum C1.
    // stored C1 = !fold(S) where S is the coverage sum with the
    // checksum field zeroed; setting the balancer to C1 makes
    // fold(S + C1) = 0xFFFF, i.e. a raw computed checksum of 0.
    let meta = icmpv6_te_meta(54);
    let icmp_match = icmpv6_te_match_fixture(snat_ip, client_ip, snat_port, client_port);
    let frame = build_icmpv6_te_frame_ext(
        router_ip,
        snat_ip,
        server_ip,
        snat_port,
        80,
        false,
        None,
        &[0, 0],
    );
    let pass1 = build_nat_reversed_icmp_error_v6(&frame, meta, &icmp_match).expect("pass 1 builds");
    let c1 = u16::from_be_bytes([pass1[icmp6_start + 2], pass1[icmp6_start + 3]]);

    // Pass 2: balancer = C1 forces the recomputed sum to zero.
    let frame = build_icmpv6_te_frame_ext(
        router_ip,
        snat_ip,
        server_ip,
        snat_port,
        80,
        false,
        None,
        &c1.to_be_bytes(),
    );
    let result =
        build_nat_reversed_icmp_error_v6(&frame, meta, &icmp_match).expect("pass 2 builds");

    // Prove the raw recompute over the output is genuinely zero…
    let outer_src = Ipv6Addr::from(<[u8; 16]>::try_from(&result[22..38]).unwrap());
    let outer_dst = Ipv6Addr::from(<[u8; 16]>::try_from(&result[38..54]).unwrap());
    let mut icmp6_zeroed = result[icmp6_start..].to_vec();
    icmp6_zeroed[2] = 0;
    icmp6_zeroed[3] = 0;
    assert_eq!(
        checksum16_ipv6(outer_src, outer_dst, PROTO_ICMPV6, &icmp6_zeroed),
        0,
        "balancing word must force the raw computed checksum to zero"
    );
    // …and the STORED field is the canonical 0xFFFF encoding.
    assert_eq!(
        u16::from_be_bytes([result[icmp6_start + 2], result[icmp6_start + 3]]),
        0xffff,
        "computed-zero ICMPv6 checksum must be stored as 0xFFFF"
    );
}


#[test]
fn icmpv6_te_nptv6_reverse_lookup_restores_internal_client() {
    let router_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let external_client: Ipv6Addr = "2602:fd41:70:100::102".parse().unwrap();
    let internal_client: Ipv6Addr = "fd35:1940:27:100::102".parse().unwrap();
    let server_ip: Ipv6Addr = "2607:f8b0:4005:814::200e".parse().unwrap();
    let echo_id: u16 = 0x8234;

    let frame = build_icmpv6_te_frame(
        router_ip,
        external_client,
        server_ip,
        echo_id,
        0,
        PROTO_ICMPV6,
    );

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };

    let mut forwarding = ForwardingState::default();
    forwarding.nptv6 = Nptv6State::from_snapshots(&[crate::Nptv6RuleSnapshot {
        name: "nptv6-test".to_string(),
        from_zone: "wan".to_string(),
        internal_prefix: "fd35:1940:0027::/48".to_string(),
        external_prefix: "2602:fd41:0070::/48".to_string(),
    }]);

    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 24,
        tx_ifindex: 24,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V6(internal_client)),
        neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
        tx_vlan_id: 0,
    }, nat: NatDecision {
        rewrite_src: Some(IpAddr::V6(external_client)),
        rewrite_dst: None,
        rewrite_src_port: None,
        rewrite_dst_port: None,
        nat64: false,
        nptv6: true,
    }, install_table_domain: 0, install_table_check: 0 };
    let metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    };
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_ICMPV6,
            src_ip: IpAddr::V6(internal_client),
            dst_ip: IpAddr::V6(server_ip),
            src_port: echo_id,
            dst_port: 0,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        decision,
        metadata,
        1_000_000,
        PROTO_ICMPV6,
        0,
    ));

    let neighbors = Arc::new(ShardedNeighborMap::new());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let icmp_match = try_embedded_icmp_nat_match_from_frame(
        &frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    ).into_option()
    .expect("should match embedded ICMPv6 error");

    assert_eq!(icmp_match.original_src, IpAddr::V6(internal_client));
    assert_eq!(icmp_match.original_src_port, echo_id);
    assert!(icmp_match.nat.nptv6);
    assert_eq!(
        icmp_match.nat.rewrite_src,
        Some(IpAddr::V6(external_client))
    );
}

/// #6227 item 6, RED-on-revert: on a VLAN trunk carrying two logical units in
/// TWO DIFFERENT zones, the NPTv6 reverse (inbound) lookup for an embedded
/// ICMP error must gate on the packet's LOGICAL unit's zone, not the
/// physical parent's inherited (first-unit) zone.
///
/// Fixture: physical ifindex 11 carries unit 12 (VLAN 50, "zone-a" — created
/// first, so ifindex_to_zone_id[11] inherits "zone-a" per
/// `forwarding_build/interfaces.rs`) and unit 13 (VLAN 80, "zone-b").
/// The ICMPv6 Time-Exceeded error arrives on the PHYSICAL ifindex 11, VLAN 80
/// (unit 13 / "zone-b"'s traffic). The NPTv6 rule is scoped `from_zone:
/// "zone-b"` ONLY, so translation must be evaluated against "zone-b" — the
/// logical unit's zone — not "zone-a", which the buggy physical-ifindex
/// lookup would produce.
///
/// The installed session carries NO NAT decision (`NatDecision::default()`),
/// deliberately: a recorded per-session `rewrite_src` would let
/// `lookup_forward_nat_across_scopes`'s `reverse_translated_index` alias find
/// the session by its OWN stored reverse mapping, masking this bug (as it
/// does in `icmpv6_te_nptv6_reverse_lookup_restores_internal_client` above,
/// which resolves via that alias regardless of the local zone lookup). Here
/// the ONLY path to the session is the zone-gated `nptv6.translate_inbound`
/// feeding `embedded_key`, so a wrong zone means NO session is found at all
/// (`try_embedded_icmp_nat_match_from_frame` returns `NoMatch`) instead of
/// merely returning the wrong `original_src`.
///
/// Reverting the `resolve_ingress_logical_ifindex` call in
/// `icmp_embed/nat_match_v6.rs` (back to keying `ifindex_to_zone_id` on the
/// raw `meta.ingress_ifindex`) turns this RED: the lookup evaluates
/// "zone-a", the from-"zone-b" rule does not match, translation fails, and
/// the `.expect(...)` below panics.
#[test]
fn icmpv6_te_nptv6_reverse_lookup_uses_logical_vlan_unit_zone_not_physical_parent() {
    let router_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let internal_client: Ipv6Addr = "fd35:1940:27:100::102".parse().unwrap();
    let server_ip: Ipv6Addr = "2607:f8b0:4005:814::200e".parse().unwrap();
    let echo_id: u16 = 0x8235;

    const PHYSICAL_IFINDEX: i32 = 11;
    const UNIT_A_IFINDEX: i32 = 12; // VLAN 50, "zone-a" — the first unit, so
                                     // the physical parent inherits ITS zone.
    const UNIT_B_IFINDEX: i32 = 13; // VLAN 80, "zone-b" — the traffic's real
                                     // unit; must NOT be shadowed by zone-a.
    const ZONE_A_ID: u16 = 41;
    const ZONE_B_ID: u16 = 42;

    let nptv6 = Nptv6State::from_snapshots(&[crate::Nptv6RuleSnapshot {
        name: "nptv6-zone-b".to_string(),
        from_zone: "zone-b".to_string(),
        internal_prefix: "fd35:1940:0027::/48".to_string(),
        external_prefix: "2602:fd41:0070::/48".to_string(),
    }]);
    // Derive the on-wire external address from `internal_client` via the
    // OUTBOUND direction rather than hand-picking both addresses: NPTv6's
    // checksum-neutral adjustment (RFC 6296 §3.7) rewrites the word AFTER the
    // prefix unless the prefix pair happens to be checksum-neutral, so a
    // hand-picked (internal, external) pair is not guaranteed to be each
    // other's actual translation — computing it here guarantees the inbound
    // reverse (exercised below) is a true round trip.
    let mut external_client = internal_client;
    assert!(
        nptv6.translate_outbound(&mut external_client, "zone-b"),
        "test setup: internal_client must translate outbound under zone-b"
    );

    let frame = build_icmpv6_te_frame(
        router_ip,
        external_client,
        server_ip,
        echo_id,
        0,
        PROTO_ICMPV6,
    );

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ingress_ifindex: PHYSICAL_IFINDEX as u32,
        ingress_vlan_id: 80, // unit B's VLAN.
        ..UserspaceDpMeta::default()
    };

    let mut forwarding = ForwardingState::default();
    // Unit A installed first: the physical parent inherits ITS zone.
    forwarding
        .ifindex_to_zone_id
        .insert(UNIT_A_IFINDEX, ZONE_A_ID);
    forwarding
        .ifindex_to_zone_id
        .insert(PHYSICAL_IFINDEX, ZONE_A_ID);
    // Unit B installed second: per forwarding_build/interfaces.rs, the parent
    // entry is NOT overwritten once set (first-unit-wins), so
    // ifindex_to_zone_id[PHYSICAL_IFINDEX] stays "zone-a".
    forwarding
        .ifindex_to_zone_id
        .insert(UNIT_B_IFINDEX, ZONE_B_ID);
    forwarding
        .zone_id_to_name
        .insert(ZONE_A_ID, "zone-a".to_string());
    forwarding
        .zone_id_to_name
        .insert(ZONE_B_ID, "zone-b".to_string());
    forwarding
        .ingress_logical_ifindex
        .insert((PHYSICAL_IFINDEX, 50), UNIT_A_IFINDEX);
    forwarding
        .ingress_logical_ifindex
        .insert((PHYSICAL_IFINDEX, 80), UNIT_B_IFINDEX);
    forwarding.nptv6 = nptv6;

    // No recorded NAT decision on the session: the ONLY way to find it is the
    // zone-gated NPTv6 reverse translation feeding `embedded_key` (see the
    // doc comment above for why a recorded `rewrite_src` would mask the bug
    // via the `reverse_translated_index` alias).
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 24,
        tx_ifindex: 24,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V6(internal_client)),
        neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 };
    let metadata = SessionMetadata {
        ingress_zone: ZONE_B_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_ifindex: UNIT_B_IFINDEX as u32,
        ingress_vlan_id: 80,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    };
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_ICMPV6,
            src_ip: IpAddr::V6(internal_client),
            dst_ip: IpAddr::V6(server_ip),
            src_port: echo_id,
            dst_port: 0,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        decision,
        metadata,
        1_000_000,
        PROTO_ICMPV6,
        0,
    ));

    let neighbors = Arc::new(ShardedNeighborMap::new());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let icmp_match = try_embedded_icmp_nat_match_from_frame(
        &frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    ).into_option()
    .expect(
        "must resolve the embedded ICMPv6 error via the LOGICAL vlan unit's \
         zone (zone-b), not the physical parent's inherited zone-a",
    );

    assert_eq!(icmp_match.original_src, IpAddr::V6(internal_client));
    assert_eq!(icmp_match.original_src_port, echo_id);
}

#[test]
fn icmpv6_te_prefers_reverse_session_resolution_for_client_return_path() {
    let router_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let external_client: Ipv6Addr = "2602:fd41:70:100::102".parse().unwrap();
    let internal_client: Ipv6Addr = "fd35:1940:27:100::102".parse().unwrap();
    let server_ip: Ipv6Addr = "2607:f8b0:4005:814::200e".parse().unwrap();
    let echo_id: u16 = 0x8234;

    let frame = build_icmpv6_te_frame(
        router_ip,
        external_client,
        server_ip,
        echo_id,
        0,
        PROTO_ICMPV6,
    );

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };

    let mut forwarding = ForwardingState::default();
    forwarding.nptv6 = Nptv6State::from_snapshots(&[crate::Nptv6RuleSnapshot {
        name: "nptv6-test".to_string(),
        from_zone: "wan".to_string(),
        internal_prefix: "fd35:1940:0027::/48".to_string(),
        external_prefix: "2602:fd41:0070::/48".to_string(),
    }]);

    let forward_key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        src_ip: IpAddr::V6(internal_client),
        dst_ip: IpAddr::V6(server_ip),
        src_port: echo_id,
        dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let forward_decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 11,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V6(server_ip)),
        neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
        tx_vlan_id: 80,
    }, nat: NatDecision {
        rewrite_src: Some(IpAddr::V6(external_client)),
        rewrite_dst: None,
        rewrite_src_port: None,
        rewrite_dst_port: None,
        nat64: false,
        nptv6: true,
    }, install_table_domain: 0, install_table_check: 0 };
    let forward_metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    };

    let reverse_key = reverse_session_key(&forward_key, forward_decision.nat);
    let reverse_resolution = ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 24,
        tx_ifindex: 24,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V6(internal_client)),
        neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
        tx_vlan_id: 0,
    };
    let reverse_decision = SessionDecision { resolution: reverse_resolution, nat: forward_decision.nat.reverse(
        forward_key.src_ip,
        forward_key.dst_ip,
        forward_key.src_port,
        forward_key.dst_port,
    ), install_table_domain: 0, install_table_check: 0 };
    let reverse_metadata = SessionMetadata {
        ingress_zone: TEST_WAN_ZONE_ID,
        egress_zone: TEST_LAN_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: true,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    };

    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol(
        forward_key.clone(),
        forward_decision,
        forward_metadata,
        1_000_000,
        PROTO_ICMPV6,
        0,
    ));
    assert!(sessions.install_with_protocol(
        reverse_key,
        reverse_decision,
        reverse_metadata,
        1_000_000,
        PROTO_ICMPV6,
        0,
    ));

    let neighbors = Arc::new(ShardedNeighborMap::new());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let icmp_match = try_embedded_icmp_nat_match_from_frame(
        &frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    ).into_option()
    .expect("should match embedded ICMPv6 error");

    assert_eq!(icmp_match.original_src, IpAddr::V6(internal_client));
    assert_eq!(
        icmp_match.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(icmp_match.resolution.egress_ifindex, 24);
    assert_eq!(icmp_match.resolution.tx_ifindex, 24);
    assert_eq!(
        icmp_match.resolution.neighbor_mac,
        Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
}

