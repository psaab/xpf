// injected-frame length clamping, TCP MSS clamp (all-tcp / gre-in), and extension-header inspection walkers.
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

/// #1881 staleness-pin companion (plan §9 test 1): the local-origin
/// builder follows WHATEVER state it is given — with the loop now
/// tracking the shared forwarding ArcSwap, a destination edit reaches
/// the very next packet. Pre-#1881 the loop held a spawn-time clone,
/// so the old-state encap below is exactly what a stale thread kept
/// emitting until restart.
#[test]
fn local_origin_tunnel_tx_request_follows_supplied_state_destination() {
    let state_old = build_forwarding_state(&native_gre_snapshot(true));
    let mut snapshot_new = native_gre_snapshot(true);
    snapshot_new.tunnel_endpoints[0].destination = "2602:ffd3:0:2::9".to_string();
    let state_new = build_forwarding_state(&snapshot_new);
    let ha_state = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let packet = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 255, 192, 42),
        Ipv4Addr::new(10, 255, 192, 41),
        64,
    );
    // Outer IPv6 destination: eth(14) + vlan(4) + 24 = offset 42..58.
    let ike_exchanges = crate::afxdp::forwarding::IkeExchangeTable::new();
    let plan_old = build_local_origin_tunnel_tx_request(
        &packet[14..],
        1,
        &state_old,
        &ha_state,
        &dynamic_neighbors,
        &ike_exchanges,
    )
    .expect("old-state plan");
    assert_eq!(plan_old.tx_request.bytes[57], 0x07, "old outer destination");
    let plan_new = build_local_origin_tunnel_tx_request(
        &packet[14..],
        1,
        &state_new,
        &ha_state,
        &dynamic_neighbors,
        &ike_exchanges,
    )
    .expect("new-state plan");
    assert_eq!(
        plan_new.tx_request.bytes[57], 0x09,
        "destination edit reaches the encap as soon as the thread \
         loads the rotated state"
    );
}

// #2443: inject packet-length bound + u16 wire-length backstop tests.


#[test]
fn inject_ipv4_normal_length_builds() {
    let egress = inject_test_egress(0);
    let frame = build_injected_ipv4(
        &inject_req(128),
        [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        Ipv4Addr::new(172, 16, 80, 8),
        Ipv4Addr::new(172, 16, 80, 200),
        4660,
        &egress,
    )
    .expect("normal injected IPv4 frame builds");
    // Eth(14) + IPv4(20) + ICMP(8) + payload >= 16.
    assert!(frame.len() >= 14 + 20 + 8 + 16);
    // The on-wire IPv4 total-length field must equal the actual L3 length
    // (frame minus the 14-byte eth header). This is the consistency
    // invariant the `as u16` wrap would violate.
    let wire_total = u16::from_be_bytes([frame[16], frame[17]]) as usize;
    assert_eq!(wire_total, frame.len() - 14, "IPv4 total-length consistent");
}


#[test]
fn inject_ipv4_at_max_builds_and_is_bounded() {
    let egress = inject_test_egress(0);
    let frame = build_injected_ipv4(
        &inject_req(crate::afxdp::MAX_INJECT_PACKET_LENGTH),
        [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        Ipv4Addr::new(172, 16, 80, 8),
        Ipv4Addr::new(172, 16, 80, 200),
        4660,
        &egress,
    )
    .expect("at-max injected IPv4 frame builds");
    assert!(frame.len() <= crate::afxdp::MAX_INJECT_PACKET_LENGTH as usize);
    let wire_total = u16::from_be_bytes([frame[16], frame[17]]) as usize;
    assert_eq!(wire_total, frame.len() - 14, "IPv4 total-length consistent at max");
}


#[test]
fn inject_ipv4_giant_length_clamped_no_wire_wrap() {
    // A length far above the maximum (and above u16) must NOT produce a
    // huge buffer and must NOT write a wrapped wire length. With the
    // #2443 fix the builder clamps target_len to MAX_INJECT_PACKET_LENGTH
    // and writes a consistent total-length. Fail-on-revert: removing the
    // `.min(MAX_INJECT_PACKET_LENGTH)` clamp lets target_len reach
    // 100_000, payload_len > u16, and the `u16::try_from` backstop then
    // returns Err (so this `.expect` panics) — OR, if `as u16` is also
    // restored, the wire field wraps and the consistency assert below
    // fails. Either revert is caught.
    let egress = inject_test_egress(0);
    let frame = build_injected_ipv4(
        &inject_req(100_000),
        [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        Ipv4Addr::new(172, 16, 80, 8),
        Ipv4Addr::new(172, 16, 80, 200),
        4660,
        &egress,
    )
    .expect("giant length must be clamped, not rejected by the builder");
    assert!(
        frame.len() <= crate::afxdp::MAX_INJECT_PACKET_LENGTH as usize,
        "giant injected frame must be bounded by MAX_INJECT_PACKET_LENGTH, got {}",
        frame.len()
    );
    let wire_total = u16::from_be_bytes([frame[16], frame[17]]) as usize;
    assert_eq!(
        wire_total,
        frame.len() - 14,
        "IPv4 total-length must match the bounded frame (no u16 wrap)"
    );
}


#[test]
fn inject_ipv6_giant_length_clamped_no_wire_wrap() {
    let egress = inject_test_egress(0);
    let frame = build_injected_ipv6(
        &inject_req(100_000),
        [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 8),
        Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 0x200),
        4660,
        &egress,
    )
    .expect("giant length must be clamped, not rejected by the builder");
    assert!(
        frame.len() <= crate::afxdp::MAX_INJECT_PACKET_LENGTH as usize,
        "giant injected IPv6 frame must be bounded, got {}",
        frame.len()
    );
    // IPv6 payload-length field is at eth(14) + 4..6.
    let wire_plen = u16::from_be_bytes([frame[18], frame[19]]) as usize;
    assert_eq!(
        wire_plen,
        frame.len() - 14 - 40,
        "IPv6 payload-length must match the bounded frame (no u16 wrap)"
    );
}

// =====================================================================
// #2486: per-context TCP MSS clamp enforcement (all-tcp / gre-in).
//
// Before #2486 only tunnel EGRESS clamped; `all-tcp` and `gre-in` were
// accepted at commit and carried on the wire but never enforced. The
// gre-in gap was a silent full-MSS blackhole on the GRE return path.
// These tests prove the per-packet context selection in `select_tcp_mss`
// (forwarding/mod.rs) reaches the clamp at frame build, and fail on
// revert of either the all-tcp wiring or the gre-in marker plumbing.
// =====================================================================


#[test]
fn all_tcp_clamps_plain_forwarded_ipv4_syn() {
    let src = Ipv4Addr::new(10, 0, 1, 102);
    let dst = Ipv4Addr::new(10, 0, 2, 200);
    let frame = build_ipv4_tcp_syn_with_mss(src, dst, 40000, 5201, 1460);
    let forwarding = ForwardingState {
        tcp_mss_all_tcp: 1400,
        ..ForwardingState::default()
    };
    let built = build_forwarded_frame_from_frame(
        &frame,
        plain_meta_v4(40000, 5201, 0),
        &plain_forward_decision_v4(dst),
        &forwarding,
        false,
        None,
    )
    .expect("plain forward build");
    assert_eq!(
        built_ipv4_mss(&built),
        1400,
        "all-tcp must clamp a plain forwarded IPv4 SYN with MSS 1460 -> 1400"
    );
    let inner = &built[14..];
    assert!(tcp_checksum_ok_ipv4(inner), "clamped v4 TCP checksum valid");
}


#[test]
fn all_tcp_clamps_plain_forwarded_ipv6_syn() {
    let src: Ipv6Addr = "2001:559:8585:bf01::102".parse().unwrap();
    let dst: Ipv6Addr = "2001:559:8585:bf02::200".parse().unwrap();
    let frame = build_ipv6_tcp_syn_with_mss(src, dst, 40000, 5201, 1440);
    let forwarding = ForwardingState {
        tcp_mss_all_tcp: 1380,
        ..ForwardingState::default()
    };
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        flow_src_port: 40000,
        flow_dst_port: 5201,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 11,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V6(dst)),
        neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 };
    let built = build_forwarded_frame_from_frame(&frame, meta, &decision, &forwarding, false, None)
        .expect("plain forward v6 build");
    assert_eq!(
        built_ipv6_mss(&built),
        1380,
        "all-tcp must clamp a plain forwarded IPv6 SYN with MSS 1440 -> 1380"
    );
}


#[test]
fn all_tcp_leaves_smaller_mss_unchanged() {
    let src = Ipv4Addr::new(10, 0, 1, 102);
    let dst = Ipv4Addr::new(10, 0, 2, 200);
    // Advertised MSS 1200 is already below the 1400 all-tcp clamp.
    let frame = build_ipv4_tcp_syn_with_mss(src, dst, 40000, 5201, 1200);
    let forwarding = ForwardingState {
        tcp_mss_all_tcp: 1400,
        ..ForwardingState::default()
    };
    let built = build_forwarded_frame_from_frame(
        &frame,
        plain_meta_v4(40000, 5201, 0),
        &plain_forward_decision_v4(dst),
        &forwarding,
        false,
        None,
    )
    .expect("plain forward build");
    assert_eq!(
        built_ipv4_mss(&built),
        1200,
        "all-tcp must NOT raise an MSS already below the clamp"
    );
}


#[test]
fn all_tcp_leaves_non_syn_untouched() {
    let src = Ipv4Addr::new(10, 0, 1, 102);
    let dst = Ipv4Addr::new(10, 0, 2, 200);
    let mut frame = build_ipv4_tcp_syn_with_mss(src, dst, 40000, 5201, 1460);
    // Clear the SYN flag -> ACK-only segment (0x10); the "MSS option" bytes
    // are now just leftover option bytes but the clamp must skip non-SYN
    // entirely.
    const TCP_ACK_FLAG: u8 = 0x10;
    frame[14 + 20 + 13] = TCP_ACK_FLAG;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("recsum");
    let forwarding = ForwardingState {
        tcp_mss_all_tcp: 1400,
        ..ForwardingState::default()
    };
    let mut meta = plain_meta_v4(40000, 5201, 0);
    meta.tcp_flags = TCP_ACK_FLAG;
    let built = build_forwarded_frame_from_frame(
        &frame,
        meta,
        &plain_forward_decision_v4(dst),
        &forwarding,
        false,
        None,
    )
    .expect("plain forward build");
    assert_eq!(
        built_ipv4_mss(&built),
        1460,
        "all-tcp must not clamp a non-SYN segment"
    );
}


#[test]
fn all_tcp_no_op_when_unset() {
    // No all-tcp configured -> MSS must pass through unchanged on the
    // plain forward path (regression guard against an accidental clamp).
    let src = Ipv4Addr::new(10, 0, 1, 102);
    let dst = Ipv4Addr::new(10, 0, 2, 200);
    let frame = build_ipv4_tcp_syn_with_mss(src, dst, 40000, 5201, 1460);
    let built = build_forwarded_frame_from_frame(
        &frame,
        plain_meta_v4(40000, 5201, 0),
        &plain_forward_decision_v4(dst),
        &ForwardingState::default(),
        false,
        None,
    )
    .expect("plain forward build");
    assert_eq!(built_ipv4_mss(&built), 1460, "no clamp when all-tcp unset");
}


#[test]
fn gre_in_clamps_decapped_ingress_syn() {
    // An inbound GRE-decapped SYN (marked GRE_DECAP_INGRESS_FLAG by the
    // decap stage) clamps to the gre-in value. Reverting the marker
    // plumbing (clear meta_flags) makes this fail -> fail-on-revert for
    // the gre-in HIGH part.
    let src = Ipv4Addr::new(10, 0, 1, 102);
    let dst = Ipv4Addr::new(10, 0, 2, 200);
    let frame = build_ipv4_tcp_syn_with_mss(src, dst, 40000, 5201, 1460);
    let forwarding = ForwardingState {
        tcp_mss_gre_in: 1360,
        ..ForwardingState::default()
    };
    let meta = plain_meta_v4(40000, 5201, GRE_DECAP_INGRESS_FLAG);
    let built = build_forwarded_frame_from_frame(
        &frame,
        meta,
        &plain_forward_decision_v4(dst),
        &forwarding,
        false,
        None,
    )
    .expect("gre-in forward build");
    assert_eq!(
        built_ipv4_mss(&built),
        1360,
        "gre-in must clamp a GRE-decapped ingress SYN 1460 -> 1360"
    );
}


#[test]
fn gre_in_marker_required_for_gre_in_clamp() {
    // Same gre-in config but WITHOUT the decap marker: the packet is a
    // plain forward, so gre-in must NOT apply (and all-tcp is unset).
    // This pins that the gre-in clamp is gated on the marker, not just on
    // the config value being present.
    let src = Ipv4Addr::new(10, 0, 1, 102);
    let dst = Ipv4Addr::new(10, 0, 2, 200);
    let frame = build_ipv4_tcp_syn_with_mss(src, dst, 40000, 5201, 1460);
    let forwarding = ForwardingState {
        tcp_mss_gre_in: 1360,
        ..ForwardingState::default()
    };
    let built = build_forwarded_frame_from_frame(
        &frame,
        plain_meta_v4(40000, 5201, 0),
        &plain_forward_decision_v4(dst),
        &forwarding,
        false,
        None,
    )
    .expect("plain forward build");
    assert_eq!(
        built_ipv4_mss(&built),
        1460,
        "gre-in must require the GRE_DECAP_INGRESS_FLAG marker"
    );
}


#[test]
fn gre_in_falls_back_to_all_tcp() {
    // A GRE-decapped SYN with no gre-in but an all-tcp value falls back
    // to all-tcp (all-tcp is the universal fallback).
    let src = Ipv4Addr::new(10, 0, 1, 102);
    let dst = Ipv4Addr::new(10, 0, 2, 200);
    let frame = build_ipv4_tcp_syn_with_mss(src, dst, 40000, 5201, 1460);
    let forwarding = ForwardingState {
        tcp_mss_all_tcp: 1410,
        ..ForwardingState::default()
    };
    let meta = plain_meta_v4(40000, 5201, GRE_DECAP_INGRESS_FLAG);
    let built = build_forwarded_frame_from_frame(
        &frame,
        meta,
        &plain_forward_decision_v4(dst),
        &forwarding,
        false,
        None,
    )
    .expect("gre-in fallback build");
    assert_eq!(
        built_ipv4_mss(&built),
        1410,
        "gre-in with no gre-in value falls back to all-tcp"
    );
}


/// #4517: all five `inspect` IPv6 ext-header walkers must traverse the
/// exotic-but-length-prefixed extension headers (Mobility 135, HIP 139,
/// Shim6 140, experimental 253/254) exactly like Hop-by-Hop/DestOpt, so a
/// chain that hides the L4/fragment status behind one of them is still
/// resolved. Before #4517 the walkers stopped at type 135/139/140 (the
/// terminal `_` arm) and reported proto=135 with no L4 — an ext-header
/// IDS evasion where the screens and forwarding never saw the SYN.
///
/// RED-on-revert: against the pre-#4517 `0 | 43 | 60` arms
/// `packet_rel_l4_offset_and_protocol` returns `(48, 135)` (STOPS at the
/// Mobility header, proto=135, no L4) instead of `(64, 6)`, and
/// `ipv6_is_any_fragment` returns `false` (never reaches the Fragment
/// header) — both assertions flip.
#[test]
fn inspect_walkers_traverse_exotic_length_prefixed_ext_headers() {
    const HOP: u8 = 0;
    const MOBILITY: u8 = 135;
    const HIP: u8 = 139;
    const SHIM6: u8 = 140;
    const FRAGMENT: u8 = 44;
    const ESP: u8 = 50;
    const TCP: u8 = 6;
    // A 20-byte TCP header with the SYN flag set at byte 13.
    let mut tcp = [0u8; 20];
    tcp[13] = 0x02; // SYN
    tcp[12] = 0x50; // data offset = 5 words

    // Chain: base → HOP → MOBILITY → FRAGMENT(offset 0, first fragment) → TCP.
    // Offsets: base 40 + HOP 8 + MOBILITY 8 + FRAGMENT 8 = 64 → TCP.
    let pkt = v6_eh_chain(
        &[(HOP, None), (MOBILITY, None), (FRAGMENT, Some(0x0001))],
        TCP,
        &tcp,
    );
    assert_eq!(
        packet_rel_l4_offset(&pkt, libc::AF_INET6 as u8),
        Some(64),
        "packet_rel_l4_offset must walk past MOBILITY to the TCP header"
    );
    assert_eq!(
        packet_rel_l4_offset_and_protocol(&pkt, libc::AF_INET6 as u8),
        Some((64, TCP)),
        "the meta walker must resolve proto=TCP past MOBILITY, not proto=135"
    );
    assert!(
        !ipv6_is_non_first_fragment(&pkt),
        "MF=1, offset=0 → this is the FIRST fragment (carries the L4)"
    );
    assert!(
        ipv6_is_any_fragment(&pkt),
        "a Fragment header behind MOBILITY must still count as a fragment"
    );
    // frame_l4_offset takes a full frame (with the 14-byte L2 header).
    let mut frame = vec![0u8; 14];
    frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&pkt);
    assert_eq!(
        frame_l4_offset(&frame, libc::AF_INET6 as u8),
        Some(14 + 64),
        "frame_l4_offset must agree with the packet-relative walkers"
    );

    // A NON-FIRST fragment behind MOBILITY: offset>0 → no L4 here, but it
    // is still a fragment. Both fragment predicates must agree.
    let nonfirst = v6_eh_chain(
        &[(HOP, None), (MOBILITY, None), (FRAGMENT, Some(0x0009))], // off=1, MF=1
        TCP,
        &tcp,
    );
    assert!(
        ipv6_is_non_first_fragment(&nonfirst),
        "offset>0 behind MOBILITY → non-first fragment"
    );
    assert!(ipv6_is_any_fragment(&nonfirst), "still any-fragment");

    // HIP and Shim6 chains resolve the real TCP just like MOBILITY.
    for exotic in [HIP, SHIM6] {
        let p = v6_eh_chain(&[(HOP, None), (exotic, None)], TCP, &tcp);
        assert_eq!(
            packet_rel_l4_offset_and_protocol(&p, libc::AF_INET6 as u8),
            Some((56, TCP)),
            "HIP/Shim6 (type {exotic}) must be walked as a generic EH"
        );
    }

    // ESP (50) is NOT walked (encrypted, non-walkable): the walk STOPS at
    // the ESP header and surfaces proto=50 at its offset — it must never be
    // parsed as a generic EH.
    let esp = v6_eh_chain(&[(HOP, None), (ESP, None)], TCP, &tcp);
    assert_eq!(
        packet_rel_l4_offset_and_protocol(&esp, libc::AF_INET6 as u8),
        Some((48, ESP)),
        "ESP must terminate the walk (proto=50), not be walked"
    );

    // A genuine TCP with no extension headers is unaffected.
    let plain = v6_eh_chain(&[], TCP, &tcp);
    assert_eq!(
        packet_rel_l4_offset_and_protocol(&plain, libc::AF_INET6 as u8),
        Some((40, TCP)),
        "no-EH TCP resolves at the base-header end"
    );
}


/// #9032: a native-GRE LOCAL-ORIGIN session must be published with the tunnel's
/// routing domain, not 0.
///
/// #7160 made `routing_domain` part of session identity and stamped it at what
/// its own comment calls "THE single site that populates
/// `SessionKey.routing_domain` for a received frame" — inside the AF_XDP
/// descriptor loop. This producer reads packets off the TUN and never reaches
/// that site, so `parse_session_flow_from_bytes` left the domain at 0 and the
/// session went onto the HA sync wire under domain 0, a different identity from
/// the one the SAME flow gets when it arrives on a wire.
#[test]
fn local_origin_tunnel_session_carries_the_routing_domain_9032() {
    let mut snapshot = native_gre_snapshot(true);
    for iface in snapshot.interfaces.iter_mut() {
        iface.routing_domain = 7;
    }
    let state = build_forwarding_state(&snapshot);
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
    .expect("local-origin plan");

    assert_eq!(
        plan.session_entry
            .as_ref()
            .expect("owned local-origin source must publish")
            .key
            .routing_domain,
        7,
        "the PUBLISHED local-origin session key must carry the tunnel's routing \
         domain. Publishing it under 0 gives the same flow a different identity \
         from the wire path, which stamps the real domain (#9032/#7160)"
    );
}

/// CONTROL: a deployment with NO routing instances must stay bit-identical.
///
/// `ingress_routing_domain` short-circuits on `!has_routing_domains`, so the
/// stamp must be a no-op here. Without this row, a stamp that hard-coded any
/// non-zero value would satisfy the cell above while changing the published key
/// on every ordinary box.
#[test]
fn local_origin_tunnel_session_domain_is_zero_without_routing_instances_9032() {
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
    .expect("local-origin plan");

    assert_eq!(
        plan.session_entry
            .as_ref()
            .expect("owned local-origin source must publish")
            .key
            .routing_domain,
        0,
        "with no routing-instance membership the published key must stay at \
         domain 0 — pre-#7160 bit-identical"
    );
}

// =====================================================================
// #9954 STEP-0 (RED on master): the generic in-place TX rewrite — the
// path taken whenever ingress and egress bindings share a UMEM (the
// default mlx5 grouping) — threads no MSS clamp, so a configured
// `tcp-mss all-tcp` is silently inert there. These cells drive a SYN
// with MSS 1460 through `rewrite_forwarded_frame_in_place` and assert
// the issue's acceptance value (1300). On master they FAIL with the
// MSS still 1460; the fix adds the clamp and they go GREEN.
// The forwarding binding documents the defect shape: the configured value
// must be selected before entering the in-place rewrite.
// =====================================================================

#[test]
fn all_tcp_clamps_in_place_v4_syn_9954() {
    let src = Ipv4Addr::new(10, 0, 1, 102);
    let dst = Ipv4Addr::new(10, 0, 2, 200);
    let frame = build_ipv4_tcp_syn_with_mss(src, dst, 40000, 5201, 1460);
    let forwarding = ForwardingState {
        tcp_mss_all_tcp: 1300,
        ..ForwardingState::default()
    };
    let meta = plain_meta_v4(40000, 5201, 0);
    let decision = plain_forward_decision_v4(dst);
    let selected_tcp_mss = select_tcp_mss(&forwarding, &decision, &meta.into());
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let rewrite_result = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        false,
        None,
        selected_tcp_mss,
    )
    .expect("in-place rewrite");
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("rewritten frame");
    assert_eq!(
        built_ipv4_mss(out),
        1300,
        "#9954: in-place path must clamp v4 SYN MSS 1460 -> 1300 \
         (all-tcp configured)"
    );
    assert!(
        tcp_checksum_ok_ipv4(&out[14..]),
        "#9954: in-place v4 MSS clamp must preserve TCP checksum"
    );
}

#[test]
fn all_tcp_clamps_in_place_v6_syn_9954() {
    let src: Ipv6Addr = "2001:559:8585:bf01::102".parse().unwrap();
    let dst: Ipv6Addr = "2001:559:8585:bf02::200".parse().unwrap();
    let frame = build_ipv6_tcp_syn_with_mss(src, dst, 40000, 5201, 1460);
    let forwarding = ForwardingState {
        tcp_mss_all_tcp: 1300,
        ..ForwardingState::default()
    };
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        flow_src_port: 40000,
        flow_dst_port: 5201,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(dst)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let selected_tcp_mss = select_tcp_mss(&forwarding, &decision, &meta.into());
    let rewrite_result = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &decision,
        false,
        None,
        selected_tcp_mss,
    )
    .expect("in-place rewrite");
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("rewritten frame");
    assert_eq!(
        built_ipv6_mss(out),
        1300,
        "#9954: in-place path must clamp v6 SYN MSS 1460 -> 1300 \
         (all-tcp configured)"
    );
    assert!(
        tcp_checksum_ok_ipv6(&out[14..]),
        "#9954: in-place v6 MSS clamp must preserve TCP checksum"
    );
}
