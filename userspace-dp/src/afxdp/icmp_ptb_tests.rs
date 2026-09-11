// #2301 egress-MTU PTB tests. Exercise the decision + the ICMP
// Frag-Needed / Packet-Too-Big builders directly:
//   - oversized forwarded non-TCP IPv4 DF -> Frag-Needed (type 3 code 4)
//     with the correct next-hop MTU and the quoted original packet,
//   - oversized forwarded IPv6 -> Packet Too Big (type 2 code 0) with MTU,
//   - in-MTU frames -> Forward (no PTB),
//   - non-DF oversized IPv4 -> ForwardOversizeNoDf (forwarded, no PTB; #9328),
//   - RFC suppression: non-first fragment + inbound ICMP error -> no PTB.

use super::*;

const PTB_IFINDEX: i32 = 24;
const EGRESS_SRC_MAC: [u8; 6] = [0x02, 0xbf, 0x72, 0x00, 0x00, 0x01];
const SENDER_MAC: [u8; 6] = [0x00, 0x25, 0x90, 0x12, 0x34, 0x56];
const FW_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

fn forwarding_with_egress(mtu: usize) -> ForwardingState {
    let mut state = ForwardingState::default();
    state.egress.insert(
        PTB_IFINDEX,
        EgressInterface {
            bind_ifindex: 0,
            vlan_id: 0,
            mtu,
            src_mac: EGRESS_SRC_MAC,
            zone_id: 0,
            redundancy_group: 0,
            primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
            primary_v6: Some("2001:559:8585:80::8".parse().expect("v6")),
        },
    );
    state
}

/// Build an inbound IPv4 UDP packet with `payload_len` UDP payload bytes
/// (total L3 = 20 + 8 + payload). `df` sets the Don't-Fragment bit.
fn inbound_v4_udp(payload_len: usize, df: bool) -> (Vec<u8>, UserspaceDpMeta) {
    let mut frame = Vec::new();
    frame.extend_from_slice(&FW_MAC);
    frame.extend_from_slice(&SENDER_MAC);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    let l3 = frame.len();
    let total_len = (20 + 8 + payload_len) as u16;
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x01]); // ID
    let flags_frag = if df { 0x4000u16 } else { 0x0000u16 };
    frame.extend_from_slice(&flags_frag.to_be_bytes());
    frame.extend_from_slice(&[64, 17, 0x00, 0x00]); // TTL, proto UDP, csum
    frame.extend_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets()); // src
    frame.extend_from_slice(&Ipv4Addr::new(172, 16, 80, 200).octets()); // dst
    let ip_csum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&ip_csum.to_be_bytes());
    // UDP header.
    frame.extend_from_slice(&49152u16.to_be_bytes());
    frame.extend_from_slice(&5201u16.to_be_bytes());
    frame.extend_from_slice(&((8 + payload_len) as u16).to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend(std::iter::repeat(0xABu8).take(payload_len));

    let meta = UserspaceDpMeta {
        ingress_ifindex: PTB_IFINDEX as u32,
        l3_offset: l3 as u16,
        l4_offset: (l3 + 20) as u16,
        addr_family: libc::AF_INET as u8,
        protocol: 17,
        ..UserspaceDpMeta::default()
    };
    (frame, meta)
}

/// Build an inbound IPv6 UDP packet with `payload_len` UDP payload bytes.
fn inbound_v6_udp(payload_len: usize) -> (Vec<u8>, UserspaceDpMeta) {
    let mut frame = Vec::new();
    frame.extend_from_slice(&FW_MAC);
    frame.extend_from_slice(&SENDER_MAC);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    let l3 = frame.len();
    let payload = (8 + payload_len) as u16; // UDP header + data
    frame.push(0x60); // version 6
    frame.extend_from_slice(&[0x00, 0x00, 0x00]); // TC/flow
    frame.extend_from_slice(&payload.to_be_bytes());
    frame.push(17); // next header UDP
    frame.push(64); // hop limit
    frame.extend_from_slice(
        &"2001:559:8585:bf01::20"
            .parse::<Ipv6Addr>()
            .unwrap()
            .octets(),
    ); // src
    frame.extend_from_slice(
        &"2001:559:8585:80::200"
            .parse::<Ipv6Addr>()
            .unwrap()
            .octets(),
    ); // dst
       // UDP header.
    frame.extend_from_slice(&49152u16.to_be_bytes());
    frame.extend_from_slice(&5201u16.to_be_bytes());
    frame.extend_from_slice(&((8 + payload_len) as u16).to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend(std::iter::repeat(0xCDu8).take(payload_len));

    let meta = UserspaceDpMeta {
        ingress_ifindex: PTB_IFINDEX as u32,
        l3_offset: l3 as u16,
        l4_offset: (l3 + 40) as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: 17,
        ..UserspaceDpMeta::default()
    };
    (frame, meta)
}

#[test]
fn oversized_v4_df_udp_emits_frag_needed() {
    // L3 = 20 + 8 + 1500 = 1528 > 1400 MTU, DF set.
    let (frame, meta) = inbound_v4_udp(1500, true);
    let l3 = meta.l3_offset as usize;
    let mtu = 1400usize;
    let decision = forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, mtu);
    let next_hop_mtu = match decision {
        EgressMtuDecision::EmitPacketTooBig { next_hop_mtu } => next_hop_mtu,
        other => panic!("expected EmitPacketTooBig, got {other:?}"),
    };
    assert_eq!(
        next_hop_mtu, 1400,
        "advertised MTU must equal the egress MTU"
    );

    assert!(
        !ptb_reply_suppressed(&frame, meta, l3, &ForwardingState::default()),
        "a plain UDP frame must not be suppressed"
    );

    let fwd = forwarding_with_egress(mtu);
    let out = build_frag_needed_v4(&frame, meta, PTB_IFINDEX, &fwd, next_hop_mtu)
        .expect("frag-needed must build");

    // L2: reflected (dst = inbound src), src = egress MAC, EtherType IPv4.
    assert_eq!(&out[0..6], &SENDER_MAC, "reflected dst MAC = inbound src");
    assert_eq!(&out[6..12], &EGRESS_SRC_MAC, "src MAC = egress");
    assert_eq!(&out[12..14], &[0x08, 0x00]);
    // Outer IPv4: src = ingress primary, dst = original src, proto ICMP.
    assert_eq!(out[14], 0x45);
    assert_eq!(out[23], PROTO_ICMP, "outer protocol must be ICMP");
    assert_eq!(
        &out[26..30],
        &Ipv4Addr::new(172, 16, 80, 8).octets(),
        "src = ingress primary"
    );
    assert_eq!(
        &out[30..34],
        &Ipv4Addr::new(198, 51, 100, 20).octets(),
        "dst = original sender"
    );
    // ICMP: type 3 code 4, next-hop MTU in bytes 6..8 of the ICMP message.
    let icmp = 14 + 20;
    assert_eq!(out[icmp], 3, "ICMP type 3 (Dest Unreachable)");
    assert_eq!(out[icmp + 1], 4, "ICMP code 4 (Frag Needed and DF Set)");
    assert_eq!(
        u16::from_be_bytes([out[icmp + 6], out[icmp + 7]]),
        1400,
        "next-hop MTU in the ICMP unused word"
    );
    // ICMP checksum is valid (computed over the whole ICMP message -> 0).
    assert_eq!(checksum16(&out[icmp..]), 0, "ICMP checksum must verify");
    // Quoted packet: the original IPv4 header (first byte 0x45) follows the
    // 8-byte ICMP header.
    assert_eq!(out[icmp + 8], 0x45, "quoted original IPv4 header present");
}

#[test]
fn oversized_v6_udp_emits_packet_too_big() {
    // L3 = 40 + 8 + 1300 = 1348 > 1280 MTU.
    let (frame, meta) = inbound_v6_udp(1300);
    let l3 = meta.l3_offset as usize;
    let mtu = 1280usize;
    let decision = forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, mtu);
    let next_hop_mtu = match decision {
        EgressMtuDecision::EmitPacketTooBig { next_hop_mtu } => next_hop_mtu,
        other => panic!("expected EmitPacketTooBig, got {other:?}"),
    };
    assert_eq!(next_hop_mtu, 1280);

    let fwd = forwarding_with_egress(mtu);
    let out = build_packet_too_big_v6(&frame, meta, PTB_IFINDEX, &fwd, next_hop_mtu as u32)
        .expect("packet-too-big must build");

    assert_eq!(&out[0..6], &SENDER_MAC);
    assert_eq!(&out[6..12], &EGRESS_SRC_MAC);
    assert_eq!(&out[12..14], &[0x86, 0xdd]);
    // Outer IPv6: version 6, next header ICMPv6.
    assert_eq!(out[14] & 0xf0, 0x60);
    assert_eq!(out[14 + 6], PROTO_ICMPV6, "outer next header ICMPv6");
    let icmp = 14 + 40;
    assert_eq!(out[icmp], 2, "ICMPv6 type 2 (Packet Too Big)");
    assert_eq!(out[icmp + 1], 0, "ICMPv6 code 0");
    assert_eq!(
        u32::from_be_bytes([out[icmp + 4], out[icmp + 5], out[icmp + 6], out[icmp + 7]]),
        1280,
        "MTU in the 32-bit ICMPv6 PTB field"
    );
    // Quoted original IPv6 header (version 6) follows the 8-byte header.
    assert_eq!(
        out[icmp + 8] & 0xf0,
        0x60,
        "quoted original IPv6 header present"
    );
    // The reply must not exceed the IPv6 minimum MTU (RFC 4443 §3.2).
    assert!(out.len() - 14 <= 1280, "reply L3 size <= 1280");
}

#[test]
fn in_mtu_v4_forwards_unchanged() {
    // L3 = 20 + 8 + 1000 = 1028 <= 1500 MTU. No PTB.
    let (frame, meta) = inbound_v4_udp(1000, true);
    let l3 = meta.l3_offset as usize;
    assert_eq!(
        forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, 1500),
        EgressMtuDecision::Forward,
        "in-MTU frame must forward unchanged"
    );
}

#[test]
fn in_mtu_v6_forwards_unchanged() {
    let (frame, meta) = inbound_v6_udp(600);
    let l3 = meta.l3_offset as usize;
    assert_eq!(
        forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, 1500),
        EgressMtuDecision::Forward
    );
}

#[test]
fn oversized_v4_without_df_forwards() {
    // Oversized but DF clear: no PTB, because the sender did not set DF (the
    // #2301 decision). What then happens to it is `ForwardOversizeNoDf`.
    //
    // #9328 SPLIT WHAT THIS CELL WAS ASSERTING. The claim above is unchanged
    // and still holds: the frame is FORWARDED and no PTB is emitted, because
    // ICMP Fragmentation-Needed is meaningful only to a sender that set DF and
    // this one did not. What the cell ALSO pinned, silently, was that the
    // outcome is INDISTINGUISHABLE from a frame that fits — both were the same
    // `Forward` value, so the dispatcher booked an oversize submission as
    // `enqueue_ok` + `tx_bytes_total` with no exception, and an operator
    // investigating a downstream loss saw a healthy counter.
    //
    // That half was not a decision anyone took; it was the absence of a
    // distinction. The variant is now separate, the behaviour is not.
    //
    // #9395 then DECIDED the behaviour: "still FORWARD" is the chosen policy,
    // not a placeholder (see `ForwardOversizeNoDf`).
    let (frame, meta) = inbound_v4_udp(1500, false);
    let l3 = meta.l3_offset as usize;
    let decision = forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, 1400);
    assert_eq!(
        decision,
        EgressMtuDecision::ForwardOversizeNoDf,
        "non-DF oversized IPv4 must still FORWARD (no PTB — the sender did not \
         set DF and would not act on one), but it must be distinguishable from \
         a frame that fits so the dispatcher can record it"
    );
    assert_ne!(
        decision,
        EgressMtuDecision::EmitPacketTooBig { next_hop_mtu: 1400 },
        "PTB-storming a DF-clear flow is the regression #2301's Forward branch \
         exists to avoid; #9328 adds an exception record, not a PTB"
    );

    // CONTROL: a frame that FITS is still the plain `Forward`, or the new
    // variant would be indistinguishable in the other direction and the
    // exception would fire on every healthy forward.
    let (small, small_meta) = inbound_v4_udp(1000, false);
    assert_eq!(
        forwarded_egress_mtu_decision(
            &small,
            small_meta.l3_offset as usize,
            small_meta.addr_family,
            1400
        ),
        EgressMtuDecision::Forward,
        "an in-MTU DF-clear frame must remain plain Forward"
    );
}

#[test]
fn no_egress_mtu_known_forwards() {
    // mtu == 0 means no egress entry known -> never invent a smaller MTU.
    let (frame, meta) = inbound_v4_udp(1500, true);
    let l3 = meta.l3_offset as usize;
    assert_eq!(
        forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, 0),
        EgressMtuDecision::Forward
    );
}

#[test]
fn next_hop_mtu_floored_at_protocol_minimum() {
    // A pathologically tiny egress MTU must never advertise below the
    // IPv6 minimum (1280) / IPv4 floor (68).
    let (v6_frame, v6_meta) = inbound_v6_udp(1300);
    let l3 = v6_meta.l3_offset as usize;
    match forwarded_egress_mtu_decision(&v6_frame, l3, v6_meta.addr_family, 100) {
        EgressMtuDecision::EmitPacketTooBig { next_hop_mtu } => {
            assert_eq!(next_hop_mtu, 1280, "v6 advertised MTU floored at 1280");
        }
        other => panic!("expected PTB, got {other:?}"),
    }
}

#[test]
fn non_first_fragment_v4_is_suppressed() {
    // A non-first fragment has no transport header to quote/key.
    let (mut frame, meta) = inbound_v4_udp(1500, true);
    let l3 = meta.l3_offset as usize;
    // Set fragment offset != 0, DF clear, MF set: a non-first fragment.
    // flags+frag word at l3+6..l3+8: MF (0x2000) | frag offset 185.
    let frag_word: u16 = 0x2000 | 185;
    frame[l3 + 6..l3 + 8].copy_from_slice(&frag_word.to_be_bytes());
    let ip_csum = {
        frame[l3 + 10..l3 + 12].copy_from_slice(&[0, 0]);
        checksum16(&frame[l3..l3 + 20])
    };
    frame[l3 + 10..l3 + 12].copy_from_slice(&ip_csum.to_be_bytes());
    assert!(
        ptb_reply_suppressed(&frame, meta, l3, &ForwardingState::default()),
        "non-first fragment must be suppressed"
    );
}

#[test]
fn inbound_icmp_error_is_suppressed() {
    // An oversized inbound ICMPv4 *error* (type 3) must not generate a
    // fresh PTB -> avoid error loops / amplification (RFC 792).
    let mut frame = Vec::new();
    frame.extend_from_slice(&FW_MAC);
    frame.extend_from_slice(&SENDER_MAC);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    let l3 = frame.len();
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&28u16.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, PROTO_ICMP, 0x00, 0x00]);
    frame.extend_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets());
    frame.extend_from_slice(&Ipv4Addr::new(172, 16, 80, 200).octets());
    let ip_csum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&ip_csum.to_be_bytes());
    let l4 = frame.len();
    // ICMP type 3 (Destination Unreachable) — an error message.
    frame.extend_from_slice(&[3, 1, 0, 0, 0, 0, 0, 0]);
    let meta = UserspaceDpMeta {
        ingress_ifindex: PTB_IFINDEX as u32,
        l3_offset: l3 as u16,
        l4_offset: l4 as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    assert!(
        ptb_reply_suppressed(&frame, meta, l3, &ForwardingState::default()),
        "inbound ICMP error must be suppressed"
    );
    // Counter-factual: an inbound ICMP *echo request* (query, type 8) is
    // NOT suppressed — proving the gate is type-specific, not all-ICMP.
    let mut echo = frame.clone();
    echo[l4] = 8; // echo request
    let echo_meta = UserspaceDpMeta {
        l4_offset: l4 as u16,
        ..meta
    };
    assert!(
        !ptb_reply_suppressed(&echo, echo_meta, l3, &ForwardingState::default()),
        "an inbound ICMP echo request is a query, not suppressed"
    );
}

/// #2314: rewrite the IPv4 destination of a built inbound frame (and fix
/// the IP header checksum) so it heads to `dst`. The egress-MTU decision
/// and `ptb_reply_suppressed` both read the destination off the frame.
fn set_v4_dst(frame: &mut [u8], l3: usize, dst: Ipv4Addr) {
    frame[l3 + 16..l3 + 20].copy_from_slice(&dst.octets());
    frame[l3 + 10..l3 + 12].copy_from_slice(&[0, 0]);
    let csum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&csum.to_be_bytes());
}

/// #2314: rewrite the IPv6 destination of a built inbound frame.
fn set_v6_dst(frame: &mut [u8], l3: usize, dst: Ipv6Addr) {
    frame[l3 + 24..l3 + 40].copy_from_slice(&dst.octets());
}

/// #2314: an oversized DF IPv4 datagram destined to a 224.0.0.0/4
/// multicast address must NOT generate a PTB (RFC 1812 §4.3.2.7) — a
/// multicast flood must not be amplified into an ICMP backscatter storm.
/// The original is still dropped by the caller (decision still fires).
#[test]
fn ptb_suppressed_for_v4_multicast_dst() {
    let (mut frame, meta) = inbound_v4_udp(1500, true);
    let l3 = meta.l3_offset as usize;
    set_v4_dst(&mut frame, l3, Ipv4Addr::new(239, 1, 2, 3));
    assert!(
        ptb_reply_suppressed(&frame, meta, l3, &ForwardingState::default()),
        "IPv4 multicast destination must suppress the PTB"
    );
}

/// #2314: an oversized DF IPv4 datagram destined to the limited
/// broadcast 255.255.255.255 must NOT generate a PTB.
#[test]
fn ptb_suppressed_for_v4_limited_broadcast_dst() {
    let (mut frame, meta) = inbound_v4_udp(1500, true);
    let l3 = meta.l3_offset as usize;
    set_v4_dst(&mut frame, l3, Ipv4Addr::new(255, 255, 255, 255));
    assert!(
        ptb_reply_suppressed(&frame, meta, l3, &ForwardingState::default()),
        "IPv4 limited broadcast destination must suppress the PTB"
    );
}

/// #2411: an oversized DF IPv4 datagram destined to a SUBNET-DIRECTED
/// broadcast (all-ones host of a connected prefix, e.g. 10.0.1.255 for
/// 10.0.1.0/24) must NOT generate a PTB (RFC 1812 §4.3.2.7). The
/// directed broadcast is a plain unicast to the limited-broadcast test,
/// so this exercises the connected-prefix lookup. Fails (PTB built) if
/// the `dest_is_directed_broadcast` check is removed.
#[test]
fn ptb_suppressed_for_v4_directed_broadcast_dst() {
    let (mut frame, meta) = inbound_v4_udp(1500, true);
    let l3 = meta.l3_offset as usize;
    set_v4_dst(&mut frame, l3, Ipv4Addr::new(10, 0, 1, 255));
    let mut fwd = forwarding_with_egress(1400);
    fwd.connected_v4.push(ConnectedRouteV4 {
        prefix: crate::prefix::PrefixV4::from_net("10.0.1.0/24".parse().expect("cidr")),
        ifindex: PTB_IFINDEX,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    assert!(
        ptb_reply_suppressed(&frame, meta, l3, &fwd),
        "IPv4 subnet-directed broadcast must suppress the PTB"
    );
    // Note: `build_frag_needed_v4` does NOT itself consult the
    // suppression gate (it would happily build a frame for a directed
    // broadcast). The dispatch path (`tx/dispatch/mod.rs`) only calls the
    // builder behind `if !ptb_reply_suppressed(..)`, so the gate above IS
    // the call-site invariant — asserting `build_frag_needed_v4(..)
    // .is_none()` here would be WRONG (the builder builds; the gate is
    // what stops the send). The gate assertion fails on a stubbed-false
    // `dest_is_directed_broadcast`, which is the regression we guard.
}

/// #2411 anti-over-suppress: a normal unicast HOST inside the same
/// connected subnet must STILL generate the PTB; only the all-ones host
/// is the directed broadcast.
#[test]
fn ptb_still_generated_for_unicast_in_connected_subnet() {
    let (mut frame, meta) = inbound_v4_udp(1500, true);
    let l3 = meta.l3_offset as usize;
    set_v4_dst(&mut frame, l3, Ipv4Addr::new(10, 0, 1, 42));
    let mut fwd = forwarding_with_egress(1400);
    fwd.connected_v4.push(ConnectedRouteV4 {
        prefix: crate::prefix::PrefixV4::from_net("10.0.1.0/24".parse().expect("cidr")),
        ifindex: PTB_IFINDEX,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    assert!(
        !ptb_reply_suppressed(&frame, meta, l3, &fwd),
        "a unicast host inside a connected subnet must NOT suppress the PTB"
    );
}

/// #2487: an oversized DF IPv4 datagram whose SOURCE is a SUBNET-DIRECTED
/// broadcast (all-ones host of a connected prefix, e.g. 10.0.1.255 for
/// 10.0.1.0/24) must NOT generate a PTB (RFC 1812 §4.3.2.7). The PTB is
/// addressed to the trigger's source, so a directed-broadcast source
/// would emit the PTB to that directed broadcast (Smurf backscatter). The
/// limited-broadcast test in `source_is_invalid_for_icmp_error` only
/// catches 255.255.255.255. Fails (PTB allowed) if the
/// `src_is_directed_broadcast` check is removed.
#[test]
fn ptb_suppressed_for_v4_directed_broadcast_src() {
    let (mut frame, meta) = inbound_v4_udp(1500, true);
    let l3 = meta.l3_offset as usize;
    set_v4_src(&mut frame, l3, Ipv4Addr::new(10, 0, 1, 255));
    let mut fwd = forwarding_with_egress(1400);
    fwd.connected_v4.push(ConnectedRouteV4 {
        prefix: crate::prefix::PrefixV4::from_net("10.0.1.0/24".parse().expect("cidr")),
        ifindex: PTB_IFINDEX,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    assert!(
        ptb_reply_suppressed(&frame, meta, l3, &fwd),
        "IPv4 subnet-directed broadcast SOURCE must suppress the PTB"
    );
}

/// #2487 anti-over-suppress: a normal unicast HOST source inside the same
/// connected subnet must STILL generate the PTB; only the all-ones host
/// is the directed broadcast.
#[test]
fn ptb_still_generated_for_unicast_src_in_connected_subnet() {
    let (mut frame, meta) = inbound_v4_udp(1500, true);
    let l3 = meta.l3_offset as usize;
    set_v4_src(&mut frame, l3, Ipv4Addr::new(10, 0, 1, 42));
    let mut fwd = forwarding_with_egress(1400);
    fwd.connected_v4.push(ConnectedRouteV4 {
        prefix: crate::prefix::PrefixV4::from_net("10.0.1.0/24".parse().expect("cidr")),
        ifindex: PTB_IFINDEX,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    assert!(
        !ptb_reply_suppressed(&frame, meta, l3, &fwd),
        "a unicast host source inside a connected subnet must NOT suppress the PTB"
    );
}

/// #2314: an oversized IPv6 datagram destined to ff00::/8 multicast must
/// NOT generate a Packet-Too-Big (RFC 4443 §2.4(e)).
#[test]
fn ptb_suppressed_for_v6_multicast_dst() {
    let (mut frame, meta) = inbound_v6_udp(1300);
    let l3 = meta.l3_offset as usize;
    set_v6_dst(&mut frame, l3, "ff02::1".parse().expect("v6 mcast"));
    assert!(
        ptb_reply_suppressed(&frame, meta, l3, &ForwardingState::default()),
        "IPv6 multicast destination must suppress the PTB"
    );
}

/// #2314 fail-closed contract: an unknown / unexpected addr_family (e.g.
/// 0, or a non-IP family) must be treated as "could not classify" and
/// suppress the error — the documented fail-closed posture. Fails if the
/// predicate's default arm is reverted to `false` (fail open).
#[test]
fn dest_predicate_fails_closed_on_unknown_family() {
    // A plain IPv4 unicast packet body — only the addr_family argument is
    // bogus, proving the suppression comes from the family arm, not the
    // bytes (those bytes classify as unicast under AF_INET).
    let (frame, meta) = inbound_v4_udp(64, true);
    let l3 = meta.l3_offset as usize;
    let packet = &frame[l3..];
    assert!(
        dest_is_multicast_or_broadcast(0, packet),
        "addr_family 0 (unknown) must fail closed -> suppress"
    );
    assert!(
        dest_is_multicast_or_broadcast(libc::AF_UNIX as u8, packet),
        "a non-IP addr_family must fail closed -> suppress"
    );
    // Sanity: the same bytes under AF_INET are NOT suppressed (unicast),
    // so the suppression above is the family arm, not the destination.
    assert!(
        !dest_is_multicast_or_broadcast(libc::AF_INET as u8, packet),
        "the same unicast bytes under AF_INET must NOT be suppressed"
    );
}

/// #2314 fail-on-revert: a NORMAL unicast destination must STILL generate
/// the PTB. If the multicast/broadcast guard is reverted this test still
/// passes; it pairs with the suppression tests above so that reverting the
/// guard turns those three red.
#[test]
fn ptb_still_generated_for_v4_unicast_dst() {
    let (frame, meta) = inbound_v4_udp(1500, true);
    let l3 = meta.l3_offset as usize;
    // The default destination 172.16.80.200 is plain unicast.
    assert!(
        !ptb_reply_suppressed(&frame, meta, l3, &ForwardingState::default()),
        "a unicast destination must NOT suppress the PTB"
    );
    let fwd = forwarding_with_egress(1400);
    assert!(
        build_frag_needed_v4(&frame, meta, PTB_IFINDEX, &fwd, 1400).is_some(),
        "unicast PTB must build"
    );
}

/// #2325: rewrite the link-layer (L2) destination MAC of a built frame so
/// the trigger is delivered to a group/broadcast MAC. The PTB L2 gate
/// reads the destination off the first 6 frame bytes.
fn set_l2_dst(frame: &mut [u8], mac: [u8; 6]) {
    frame[0..6].copy_from_slice(&mac);
}

/// #2325: a frame with a UNICAST L3 destination but a MULTICAST L2
/// destination MAC (the group I/G bit set) must NOT generate a PTB
/// (RFC 1812 §4.3.2.7 / RFC 4443 §2.4(e) — a datagram delivered as a
/// link-layer multicast must not produce an ICMP error). Fails if the
/// L2 gate is reverted (the L3 destination here is plain unicast, so the
/// #2314 L3 gate alone would let this through).
#[test]
fn ptb_suppressed_for_l2_multicast_dst() {
    let (mut frame, meta) = inbound_v4_udp(1500, true);
    let l3 = meta.l3_offset as usize;
    // 01:00:5e:... is the IPv4-multicast MAC range; the low bit of the
    // first octet (0x01) is the IEEE group bit.
    set_l2_dst(&mut frame, [0x01, 0x00, 0x5e, 0x01, 0x02, 0x03]);
    assert!(
        ptb_reply_suppressed(&frame, meta, l3, &ForwardingState::default()),
        "L2 multicast (group bit) destination must suppress the PTB"
    );
}

/// #2325: a frame delivered to the L2 broadcast MAC (all-FF) must NOT
/// generate a PTB even though its L3 destination is unicast. Fails if the
/// L2 gate is reverted.
#[test]
fn ptb_suppressed_for_l2_broadcast_dst() {
    let (mut frame, meta) = inbound_v4_udp(1500, true);
    let l3 = meta.l3_offset as usize;
    set_l2_dst(&mut frame, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    assert!(
        ptb_reply_suppressed(&frame, meta, l3, &ForwardingState::default()),
        "L2 broadcast destination must suppress the PTB"
    );
}

/// #2325: the same gate on IPv6 — a unicast L3 destination delivered to a
/// multicast L2 MAC (e.g. 33:33:... IPv6-multicast range) must suppress.
#[test]
fn ptb_suppressed_for_l2_multicast_dst_v6() {
    let (mut frame, meta) = inbound_v6_udp(1300);
    let l3 = meta.l3_offset as usize;
    set_l2_dst(&mut frame, [0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);
    assert!(
        ptb_reply_suppressed(&frame, meta, l3, &ForwardingState::default()),
        "L2 multicast (33:33:..) destination must suppress the IPv6 PTB"
    );
}

/// #2325 fail-on-revert pair: a UNICAST L3 destination delivered to a
/// UNICAST L2 MAC must STILL generate the PTB. Pairs with the L2
/// suppression tests above so reverting the L2 gate turns those red while
/// this one stays green (proving the suppression is the L2 gate, not the
/// frame bytes).
#[test]
fn ptb_still_generated_for_l2_unicast_dst() {
    let (mut frame, meta) = inbound_v4_udp(1500, true);
    let l3 = meta.l3_offset as usize;
    // A plain unicast MAC: low bit of the first octet clear.
    set_l2_dst(&mut frame, [0x02, 0xbf, 0x72, 0x00, 0x00, 0x09]);
    assert!(
        !ptb_reply_suppressed(&frame, meta, l3, &ForwardingState::default()),
        "unicast L2 + unicast L3 destination must NOT suppress the PTB"
    );
    let fwd = forwarding_with_egress(1400);
    assert!(
        build_frag_needed_v4(&frame, meta, PTB_IFINDEX, &fwd, 1400).is_some(),
        "unicast L2/L3 PTB must build"
    );
}

/// #2325: direct unit test of the shared `l2_dst_is_group_or_broadcast`
/// helper — the IEEE group (I/G) bit is the low bit of the first octet;
/// broadcast (all-FF) is a group address. Unicast MACs (even bit clear)
/// are not group/broadcast. Fails if the helper's bit test is reverted.
#[test]
fn l2_dst_group_broadcast_helper() {
    // Unicast: low bit of first octet clear.
    assert!(!l2_dst_is_group_or_broadcast(&[
        0x02, 0xbf, 0x72, 0x00, 0x00, 0x01
    ]));
    assert!(!l2_dst_is_group_or_broadcast(&[
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    ]));
    // IPv4 multicast MAC range (01:00:5e:..): group bit set.
    assert!(l2_dst_is_group_or_broadcast(&[
        0x01, 0x00, 0x5e, 0x01, 0x02, 0x03
    ]));
    // IPv6 multicast MAC range (33:33:..): group bit set (0x33 & 0x01).
    assert!(l2_dst_is_group_or_broadcast(&[
        0x33, 0x33, 0x00, 0x00, 0x00, 0x01
    ]));
    // Broadcast (all-FF): a group address.
    assert!(l2_dst_is_group_or_broadcast(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    ]));
}

// === #2367: bad-source suppression (spoofable backscatter) ===
//
// The PTB is addressed to the trigger packet's SOURCE address. A trigger
// whose source is not a single unicast host (unspecified, loopback,
// multicast, or — for IPv4 — broadcast) would make the firewall emit a
// PTB to a forbidden address: spoofable ICMP backscatter. RFC 1812
// §4.3.2.7 / RFC 4443 §2.4(e). The reject / Time-Exceeded gate already
// enforces this; these tests prove the PTB gate now does too and that the
// two share the SAME bad-source set. Each suppression test FAILS (the PTB
// is generated) if the `source_is_invalid_for_icmp_error` call in
// `ptb_reply_suppressed` is removed.

/// Rewrite the IPv4 SOURCE of a built inbound frame (and fix the IP header
/// checksum). The PTB builder reflects this as the reply destination.
fn set_v4_src(frame: &mut [u8], l3: usize, src: Ipv4Addr) {
    frame[l3 + 12..l3 + 16].copy_from_slice(&src.octets());
    frame[l3 + 10..l3 + 12].copy_from_slice(&[0, 0]);
    let csum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&csum.to_be_bytes());
}

/// Rewrite the IPv6 SOURCE of a built inbound frame.
fn set_v6_src(frame: &mut [u8], l3: usize, src: Ipv6Addr) {
    frame[l3 + 8..l3 + 24].copy_from_slice(&src.octets());
}

/// #2367 fail-on-revert (backscatter): an oversized DF IPv4 datagram whose
/// SOURCE is one of the forbidden addresses (0.0.0.0, 127.0.0.1,
/// 224.0.0.1 multicast, 255.255.255.255 broadcast) must NOT generate a PTB
/// — otherwise the firewall emits spoofable ICMP backscatter to that
/// source. Mirrors the reject/TE gate's IPv4 bad-source set exactly.
#[test]
fn ptb_suppressed_for_v4_bad_source_backscatter() {
    for bad in [
        Ipv4Addr::new(0, 0, 0, 0),         // unspecified
        Ipv4Addr::new(127, 0, 0, 1),       // loopback
        Ipv4Addr::new(224, 0, 0, 1),       // multicast
        Ipv4Addr::new(255, 255, 255, 255), // limited broadcast
    ] {
        let (mut frame, meta) = inbound_v4_udp(1500, true);
        let l3 = meta.l3_offset as usize;
        set_v4_src(&mut frame, l3, bad);
        assert!(
            ptb_reply_suppressed(&frame, meta, l3, &ForwardingState::default()),
            "IPv4 forbidden source {bad} must suppress the PTB (backscatter)"
        );
    }
}

/// #2367 fail-on-revert (backscatter): an oversized IPv6 datagram whose
/// SOURCE is forbidden (::, ::1, ff02::1 multicast) must NOT generate a
/// Packet-Too-Big. Mirrors the reject/TE gate's IPv6 bad-source set.
#[test]
fn ptb_suppressed_for_v6_bad_source_backscatter() {
    for bad in ["::", "::1", "ff02::1"] {
        let (mut frame, meta) = inbound_v6_udp(1300);
        let l3 = meta.l3_offset as usize;
        set_v6_src(&mut frame, l3, bad.parse().expect("v6 src"));
        assert!(
            ptb_reply_suppressed(&frame, meta, l3, &ForwardingState::default()),
            "IPv6 forbidden source {bad} must suppress the PTB (backscatter)"
        );
    }
}

/// #2367 anti-over-suppress (PMTUD must still work): an oversized DF IPv4
/// datagram from a NORMAL unicast source must STILL generate the PTB.
/// Pairs with the suppression test above: reverting the source gate turns
/// that one red while this stays green (the suppression is the source
/// gate, not the frame bytes).
#[test]
fn ptb_still_generated_for_v4_unicast_source() {
    let (mut frame, meta) = inbound_v4_udp(1500, true);
    let l3 = meta.l3_offset as usize;
    // Plain unicast source, distinct from the default to be explicit.
    set_v4_src(&mut frame, l3, Ipv4Addr::new(203, 0, 113, 7));
    assert!(
        !ptb_reply_suppressed(&frame, meta, l3, &ForwardingState::default()),
        "a unicast source must NOT suppress the PTB (PMTUD)"
    );
    let fwd = forwarding_with_egress(1400);
    let out = build_frag_needed_v4(&frame, meta, PTB_IFINDEX, &fwd, 1400)
        .expect("unicast-source PTB must build");
    // The PTB is addressed back to the (unicast) source.
    assert_eq!(
        &out[30..34],
        &Ipv4Addr::new(203, 0, 113, 7).octets(),
        "PTB dst = unicast trigger source"
    );
}

/// #2367 anti-over-suppress: an oversized IPv6 datagram from a normal
/// unicast source must STILL generate the Packet-Too-Big.
#[test]
fn ptb_still_generated_for_v6_unicast_source() {
    let (frame, meta) = inbound_v6_udp(1300);
    let l3 = meta.l3_offset as usize;
    // The default source 2001:559:8585:bf01::20 is unicast.
    assert!(
        !ptb_reply_suppressed(&frame, meta, l3, &ForwardingState::default()),
        "a unicast IPv6 source must NOT suppress the PTB (PMTUD)"
    );
    let fwd = forwarding_with_egress(1280);
    assert!(
        build_packet_too_big_v6(&frame, meta, PTB_IFINDEX, &fwd, 1280).is_some(),
        "unicast-source IPv6 PTB must build"
    );
}

/// #2367 direct unit test of the shared `source_is_invalid_for_icmp_error`
/// predicate, plus its fail-closed contract on an unknown family. This is
/// the SAME predicate the reject / Time-Exceeded gate
/// (`can_generate_icmp_error_reply`) calls, so the PTB and reject paths
/// suppress an identical source set.
#[test]
fn source_predicate_matches_reject_set_and_fails_closed() {
    // IPv4 forbidden sources -> invalid.
    for bad in [
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(224, 0, 0, 1),
        Ipv4Addr::new(255, 255, 255, 255),
    ] {
        let (mut frame, meta) = inbound_v4_udp(64, true);
        let l3 = meta.l3_offset as usize;
        set_v4_src(&mut frame, l3, bad);
        assert!(
            source_is_invalid_for_icmp_error(libc::AF_INET as u8, &frame[l3..]),
            "IPv4 {bad} must be an invalid ICMP-error source"
        );
    }
    // IPv4 unicast -> valid.
    let (frame, meta) = inbound_v4_udp(64, true);
    let l3 = meta.l3_offset as usize;
    assert!(
        !source_is_invalid_for_icmp_error(libc::AF_INET as u8, &frame[l3..]),
        "IPv4 unicast source must be valid"
    );
    // IPv6 forbidden sources -> invalid.
    for bad in ["::", "::1", "ff02::1"] {
        let (mut frame, meta) = inbound_v6_udp(64);
        let l3 = meta.l3_offset as usize;
        set_v6_src(&mut frame, l3, bad.parse().expect("v6 src"));
        assert!(
            source_is_invalid_for_icmp_error(libc::AF_INET6 as u8, &frame[l3..]),
            "IPv6 {bad} must be an invalid ICMP-error source"
        );
    }
    // IPv6 unicast -> valid.
    let (frame6, meta6) = inbound_v6_udp(64);
    let l36 = meta6.l3_offset as usize;
    assert!(
        !source_is_invalid_for_icmp_error(libc::AF_INET6 as u8, &frame6[l36..]),
        "IPv6 unicast source must be valid"
    );
    // Fail-closed: an unknown / non-IP family is treated as invalid
    // (suppress). Fails if the default arm is reverted to `false`.
    assert!(
        source_is_invalid_for_icmp_error(0, &frame[l3..]),
        "unknown addr_family must fail closed -> invalid source"
    );
    assert!(
        source_is_invalid_for_icmp_error(libc::AF_UNIX as u8, &frame[l3..]),
        "non-IP addr_family must fail closed -> invalid source"
    );
}

#[test]
fn no_primary_address_fails_closed() {
    // Egress has no primary v4 -> the builder returns None (caller silently
    // drops). The decision still fires, so the oversized original is dropped
    // either way; this proves the builder does not panic / forge a source.
    let (frame, meta) = inbound_v4_udp(1500, true);
    let mut fwd = forwarding_with_egress(1400);
    fwd.egress.get_mut(&PTB_IFINDEX).unwrap().primary_v4 = None;
    assert!(
        build_frag_needed_v4(&frame, meta, PTB_IFINDEX, &fwd, 1400).is_none(),
        "no ingress primary v4 -> fail-closed None"
    );
}

// ---------------------------------------------------------------------------
// #2330: post-transform (NAT64 / GRE / WireGuard) inner-source PMTUD.
//
// The on-wire size of a transformed forward differs from the SOURCE frame
// (encap grows, NAT64 header shrinks/grows), so #2301's source-vs-egress
// comparison is wrong and was deliberately skipped for these paths. #2330
// derives the INNER-source MTU from the #2300/#2331 SSOT helpers and compares
// the inner `source_frame` against THAT — feeding the existing decision +
// builders so the inner sender gets a PTB carrying the INNER MTU instead of a
// silent encap/translate drop.
// ---------------------------------------------------------------------------

const TUN_ID: u16 = 7;
const TRANSPORT_IFINDEX: i32 = PTB_IFINDEX; // egress carries the transport MTU

/// A ForwardingResolution wired for a native tunnel on `TRANSPORT_IFINDEX`.
fn tunnel_resolution() -> ForwardingResolution {
    ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: TRANSPORT_IFINDEX,
        tx_ifindex: TRANSPORT_IFINDEX,
        tunnel_endpoint_id: TUN_ID,
        next_hop: None,
        neighbor_mac: Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x09]),
        src_mac: Some(EGRESS_SRC_MAC),
        tx_vlan_id: 0,
    }
}

fn tunnel_decision() -> SessionDecision {
    SessionDecision {
        resolution: tunnel_resolution(),
        nat: NatDecision::default(),
    }
}

fn nat64_decision(nat64: bool) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: TRANSPORT_IFINDEX,
            tx_ifindex: TRANSPORT_IFINDEX,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x09]),
            src_mac: Some(EGRESS_SRC_MAC),
            tx_vlan_id: 0,
        },
        nat: NatDecision {
            nat64,
            ..NatDecision::default()
        },
    }
}

/// Insert a minimal tunnel endpoint of the given `mode` / outer family /
/// `key` so the SSOT inner-MTU helpers resolve.
fn insert_tunnel_endpoint(fwd: &mut ForwardingState, mode: &str, outer_family: i32, key: u32) {
    fwd.tunnel_endpoints.insert(
        TUN_ID,
        TunnelEndpoint {
            id: TUN_ID,
            logical_ifindex: TRANSPORT_IFINDEX,
            interface_label: "tun0".into(),
            interface: "tun0.0".into(),
            redundancy_group: 0,
            mode: mode.into(),
            outer_family,
            source: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            key,
            ttl: 64,
            transport_table: String::new(),
            wg_listen_port: 51820,
            wg_local_privkey: zeroize::Zeroizing::new([0u8; 32]),
            wg_peers: Vec::new(),
        },
    );
}

#[test]
fn post_transform_inner_mtu_gre_subtracts_outer_and_gre_header() {
    // transport MTU 1400, IPv4 outer (20) + GRE base (4), no key:
    // inner MTU = 1400 - 24 = 1376. SAME value the #2331 encap drop guard
    // enforces (native_gre_inner_mtu).
    let mut fwd = forwarding_with_egress(1400);
    insert_tunnel_endpoint(&mut fwd, "gre", libc::AF_INET, 0);
    let decision = tunnel_decision();
    let inner = post_transform_inner_mtu(&decision, &fwd, false, libc::AF_INET as u8, 1400, None);
    assert_eq!(
        inner, 1376,
        "GRE inner MTU = transport - outer_ip(20) - gre(4)"
    );
    assert_eq!(
        inner,
        native_gre_inner_mtu(&fwd, &decision),
        "post-transform GRE inner MTU MUST equal the #2331 encap-guard SSOT"
    );
}

#[test]
fn post_transform_inner_mtu_gre_counts_key_word() {
    // A key-present endpoint adds 4 bytes of GRE header: 1400 - 28 = 1372.
    let mut fwd = forwarding_with_egress(1400);
    insert_tunnel_endpoint(&mut fwd, "gre", libc::AF_INET, 0xdead_beef);
    let inner = post_transform_inner_mtu(
        &tunnel_decision(),
        &fwd,
        false,
        libc::AF_INET as u8,
        1400,
        None,
    );
    assert_eq!(
        inner, 1372,
        "key-present GRE counts the extra 4-byte key word"
    );
}

#[test]
fn post_transform_inner_mtu_wireguard_is_pad_aware() {
    // WG over an IPv4 outer: inner MTU = outer_mtu - WG_OVERHEAD_V4 - 15
    // (worst-case §5.4.6 padding). WG_OVERHEAD_V4 = 20 + 8 + 16 + 16 = 60.
    // 1400 - 60 - 15 = 1325. The inverse of frame::wg::wg_encapped_size.
    let mut fwd = forwarding_with_egress(1400);
    insert_tunnel_endpoint(&mut fwd, "wireguard", libc::AF_INET, 0);
    let inner = post_transform_inner_mtu(
        &tunnel_decision(),
        &fwd,
        false,
        libc::AF_INET as u8,
        1400,
        None,
    );
    assert_eq!(
        inner, 1325,
        "WG inner MTU = outer_mtu - WG_OVERHEAD_V4 - max_pad"
    );
    assert_eq!(
        inner,
        crate::afxdp::wg::mss::wg_inner_mtu(libc::AF_INET, 1400),
        "post-transform WG inner MTU MUST equal the wg_inner_mtu SSOT"
    );
}

#[test]
fn post_transform_inner_mtu_unknown_tunnel_kind_fails_open() {
    // An unknown/missing mode yields 0 (fail-open: the decision then returns
    // Forward and the frame falls through to its normal fail-closed build).
    let mut fwd = forwarding_with_egress(1400);
    insert_tunnel_endpoint(&mut fwd, "l2tp", libc::AF_INET, 0);
    assert_eq!(
        post_transform_inner_mtu(
            &tunnel_decision(),
            &fwd,
            false,
            libc::AF_INET as u8,
            1400,
            None
        ),
        0,
        "unknown tunnel mode -> 0 (fail-open)"
    );
}

#[test]
fn post_transform_inner_mtu_nat64_v6_to_v4_adds_header_delta() {
    // Inner v6 translated to a v4 egress: the v4 frame is 20 bytes SMALLER,
    // so a v6 inner up to egress_mtu + 20 still fits. egress 1400 -> 1420.
    let fwd = forwarding_with_egress(1400);
    let inner = post_transform_inner_mtu(
        &nat64_decision(true),
        &fwd,
        true,
        libc::AF_INET6 as u8,
        1400,
        None,
    );
    assert_eq!(inner, 1420, "NAT64 v6->v4 inner MTU = egress + 20");
}

#[test]
fn post_transform_inner_mtu_nat64_v4_to_v6_subtracts_header_delta() {
    // Inner v4 translated to a v6 egress: the v6 frame is 20 bytes LARGER,
    // so the v4 inner must be 20 bytes SMALLER. egress 1400 -> 1380.
    let fwd = forwarding_with_egress(1400);
    let inner = post_transform_inner_mtu(
        &nat64_decision(true),
        &fwd,
        true,
        libc::AF_INET as u8,
        1400,
        None,
    );
    assert_eq!(inner, 1380, "NAT64 v4->v6 inner MTU = egress - 20");
}

#[test]
fn post_transform_gre_oversized_v4_df_emits_inner_ptb() {
    // End-to-end: a 1500-byte inner v4 DF datagram over a GRE tunnel whose
    // inner MTU is 1376 must emit a Frag-Needed advertising 1376 (NOT the
    // 1400 transport MTU, NOT a silent #2331 drop). This is the #2331-loop
    // closure: the oversize that #2331 drops now yields a PTB.
    let (frame, meta) = inbound_v4_udp(1500, true);
    let l3 = meta.l3_offset as usize;
    let mut fwd = forwarding_with_egress(1400);
    insert_tunnel_endpoint(&mut fwd, "gre", libc::AF_INET, 0);
    let decision = tunnel_decision();
    let inner_mtu = post_transform_inner_mtu(&decision, &fwd, false, meta.addr_family, 1400, None);
    assert_eq!(inner_mtu, 1376);

    // Source-vs-egress (the WRONG pre-#2330 comparison) would advertise 1400;
    // the inner-MTU decision advertises 1376.
    let next_hop_mtu = match forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, inner_mtu)
    {
        EgressMtuDecision::EmitPacketTooBig { next_hop_mtu } => next_hop_mtu,
        other => panic!("expected EmitPacketTooBig, got {other:?}"),
    };
    assert_eq!(
        next_hop_mtu, 1376,
        "advertised MTU = GRE inner MTU, not transport MTU"
    );
    assert!(!ptb_reply_suppressed(
        &frame,
        meta,
        l3,
        &ForwardingState::default()
    ));
    let out = build_frag_needed_v4(&frame, meta, PTB_IFINDEX, &fwd, next_hop_mtu)
        .expect("inner-source frag-needed must build");
    let icmp = 14 + 20;
    assert_eq!(out[icmp], 3);
    assert_eq!(out[icmp + 1], 4);
    assert_eq!(
        u16::from_be_bytes([out[icmp + 6], out[icmp + 7]]),
        1376,
        "PTB carries the inner MTU"
    );
    assert_eq!(
        &out[30..34],
        &Ipv4Addr::new(198, 51, 100, 20).octets(),
        "dst = inner source"
    );
}

#[test]
fn post_transform_wireguard_oversized_v6_emits_inner_ptb() {
    // A 1300-payload inner v6 over a WG tunnel whose inner MTU is 1325
    // (1400 - 60 - 15) — the inner L3 is 40 + 8 + 1300 = 1348 > 1325 — must
    // emit a Packet-Too-Big advertising the WG inner MTU.
    let (frame, meta) = inbound_v6_udp(1300);
    let l3 = meta.l3_offset as usize;
    let mut fwd = forwarding_with_egress(1400);
    insert_tunnel_endpoint(&mut fwd, "wireguard", libc::AF_INET, 0);
    let inner_mtu = post_transform_inner_mtu(
        &tunnel_decision(),
        &fwd,
        false,
        meta.addr_family,
        1400,
        None,
    );
    assert_eq!(inner_mtu, 1325);
    let next_hop_mtu = match forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, inner_mtu)
    {
        EgressMtuDecision::EmitPacketTooBig { next_hop_mtu } => next_hop_mtu,
        other => panic!("expected EmitPacketTooBig, got {other:?}"),
    };
    assert_eq!(
        next_hop_mtu, 1325,
        "advertised MTU = WG pad-aware inner MTU"
    );
    let out = build_packet_too_big_v6(&frame, meta, PTB_IFINDEX, &fwd, next_hop_mtu as u32)
        .expect("inner-source PTB must build");
    let icmp = 14 + 40;
    assert_eq!(out[icmp], 2, "ICMPv6 Packet Too Big");
    assert_eq!(
        u32::from_be_bytes([out[icmp + 4], out[icmp + 5], out[icmp + 6], out[icmp + 7]]),
        1325,
    );
}

#[test]
fn post_transform_nat64_v6_oversized_emits_inner_ptb() {
    // NAT64 v6->v4: a 1400-payload inner v6 (L3 = 40 + 8 + 1400 = 1448)
    // translated to a v4 egress of MTU 1400. Inner MTU = 1400 + 20 = 1420;
    // 1448 > 1420 -> Packet-Too-Big advertising 1420 to the v6 inner source.
    let (frame, meta) = inbound_v6_udp(1400);
    let l3 = meta.l3_offset as usize;
    let fwd = forwarding_with_egress(1400);
    let inner_mtu = post_transform_inner_mtu(
        &nat64_decision(true),
        &fwd,
        true,
        meta.addr_family,
        1400,
        None,
    );
    assert_eq!(inner_mtu, 1420, "NAT64 v6->v4 inner MTU = egress + 20");
    let next_hop_mtu = match forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, inner_mtu)
    {
        EgressMtuDecision::EmitPacketTooBig { next_hop_mtu } => next_hop_mtu,
        other => panic!("expected EmitPacketTooBig, got {other:?}"),
    };
    assert_eq!(next_hop_mtu, 1420);
    let out = build_packet_too_big_v6(&frame, meta, PTB_IFINDEX, &fwd, next_hop_mtu as u32)
        .expect("NAT64 inner v6 PTB must build");
    let icmp = 14 + 40;
    assert_eq!(out[icmp], 2);
    assert_eq!(
        u32::from_be_bytes([out[icmp + 4], out[icmp + 5], out[icmp + 6], out[icmp + 7]]),
        1420,
    );
}

#[test]
fn post_transform_in_mtu_forwards_no_ptb() {
    // An inner packet that fits the GRE inner MTU must NOT emit a PTB
    // (no false signal on a correctly-sized transformed flow).
    let (frame, meta) = inbound_v4_udp(1000, true); // L3 = 1028 <= 1376
    let l3 = meta.l3_offset as usize;
    let mut fwd = forwarding_with_egress(1400);
    insert_tunnel_endpoint(&mut fwd, "gre", libc::AF_INET, 0);
    let inner_mtu = post_transform_inner_mtu(
        &tunnel_decision(),
        &fwd,
        false,
        meta.addr_family,
        1400,
        None,
    );
    assert_eq!(
        forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, inner_mtu),
        EgressMtuDecision::Forward,
        "in-inner-MTU transformed frame must forward, no PTB"
    );
}

// #2783: the egress-MTU decision must size off the IP-DECLARED L3 length
// (the same authority the PTB builders quote), NOT the AF_XDP buffer
// length. A buffer carrying ethernet padding / trailing bytes beyond the
// IP datagram must not mis-fire a PTB for a datagram that actually fits the
// egress MTU.
//
// FAIL-ON-REVERT: reverting `forwarded_egress_mtu_decision` to
// `frame.len() - l3_offset` (the buffer length) makes both halves of each
// assertion below FAIL — the padded buffer (> MTU) would emit a spurious
// PTB even though the declared datagram (<= MTU) fits.

#[test]
fn v4_trailing_padding_does_not_misfire_ptb() {
    // Declared L3 = 20 + 8 + 1000 = 1028 <= 1400 MTU (fits, DF set). Append
    // 500 bytes of ethernet padding / trailing junk so the BUFFER L3 length
    // is 1528 > 1400. The decision must read total_len (1028), not the
    // buffer (1528), and forward.
    let (mut frame, meta) = inbound_v4_udp(1000, true);
    let l3 = meta.l3_offset as usize;
    let declared_l3 = frame.len() - l3; // 1028
    frame.extend(std::iter::repeat(0x00u8).take(500));
    let buffer_l3 = frame.len() - l3; // 1528
    assert!(declared_l3 <= 1400 && buffer_l3 > 1400, "test setup");

    assert_eq!(
        forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, 1400),
        EgressMtuDecision::Forward,
        "padded-but-fitting v4 datagram must forward (IP-declared len, not buffer len)"
    );

    // The inverse: when the DECLARED datagram genuinely exceeds the MTU, the
    // PTB still fires regardless of any padding — so the fix doesn't suppress
    // legitimate PTBs. (Declared 1528 > 1400; +500 padding is irrelevant.)
    let (mut big, big_meta) = inbound_v4_udp(1500, true); // declared 1528
    big.extend(std::iter::repeat(0x00u8).take(500));
    assert_eq!(
        forwarded_egress_mtu_decision(&big, l3, big_meta.addr_family, 1400),
        EgressMtuDecision::EmitPacketTooBig { next_hop_mtu: 1400 },
        "genuinely-oversized declared v4 datagram must still emit PTB"
    );
}

#[test]
fn v6_trailing_padding_does_not_misfire_ptb() {
    // Declared L3 = 40 + 8 + 600 = 648 <= 1280 MTU (fits). Append 800 bytes
    // of trailing junk so the BUFFER L3 length is 1448 > 1280. The decision
    // must read 40 + payload_len (648), not the buffer (1448), and forward.
    let (mut frame, meta) = inbound_v6_udp(600);
    let l3 = meta.l3_offset as usize;
    let declared_l3 = frame.len() - l3; // 648
    frame.extend(std::iter::repeat(0x00u8).take(800));
    let buffer_l3 = frame.len() - l3; // 1448
    assert!(declared_l3 <= 1280 && buffer_l3 > 1280, "test setup");

    assert_eq!(
        forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, 1280),
        EgressMtuDecision::Forward,
        "padded-but-fitting v6 datagram must forward (IP-declared len, not buffer len)"
    );

    // Inverse: a genuinely-oversized declared v6 datagram still emits PTB.
    let (mut big, big_meta) = inbound_v6_udp(1300); // declared 1348
    big.extend(std::iter::repeat(0x00u8).take(800));
    assert_eq!(
        forwarded_egress_mtu_decision(&big, l3, big_meta.addr_family, 1280),
        EgressMtuDecision::EmitPacketTooBig { next_hop_mtu: 1280 },
        "genuinely-oversized declared v6 datagram must still emit PTB"
    );
}

#[test]
fn truncated_ip_header_forwards_fail_open() {
    // A buffer shorter than the minimum IP header (declared length
    // unreadable) must fail-open to Forward, never over-read.
    let (frame, meta) = inbound_v4_udp(1500, true);
    let l3 = meta.l3_offset as usize;
    // Truncate to 10 bytes of L3 (< 20-byte IPv4 header).
    let truncated = frame[..l3 + 10].to_vec();
    assert_eq!(
        forwarded_egress_mtu_decision(&truncated, l3, meta.addr_family, 1400),
        EgressMtuDecision::Forward,
        "truncated IPv4 header must fail-open to Forward"
    );
    let (v6_frame, v6_meta) = inbound_v6_udp(1300);
    let v6_truncated = v6_frame[..l3 + 20].to_vec(); // < 40-byte IPv6 header
    assert_eq!(
        forwarded_egress_mtu_decision(&v6_truncated, l3, v6_meta.addr_family, 1280),
        EgressMtuDecision::Forward,
        "truncated IPv6 header must fail-open to Forward"
    );
}

// ---------------------------------------------------------------------------
// #2684: the WireGuard PTB inner-MTU derives from the PHYSICAL underlay egress
// (1500), NOT the tunnel LOGICAL ifindex MTU (1420). Before #2684 the WG arm of
// `post_transform_inner_mtu` read `tunnel_outer_mtu`, which for a WG transit
// flow (endpoint.destination zeroed) falls back to the LOGICAL egress_ifindex
// MTU (~1420 = underlay − encap). Feeding that to `wg_inner_mtu` subtracts the
// WG encap overhead a SECOND time → the PTB advertises ~1345 (v4) / ~1325 (v6),
// ~80-100B SMALLER than the encap drop guard actually admits
// (`wg_inner_mtu(physical=1500)` = 1425 v4 / 1405 v6). These tests use the
// realistic `wg_outer_mtu_snapshot` (logical wg0.0 ifindex 400 MTU 1420 ≠
// physical reth0.80 ifindex 12 MTU 1500, peer routed via reth0.80) so the
// logical/physical split is real. They go RED if the WG arm reverts to
// `tunnel_outer_mtu` (logical 1420).
// ---------------------------------------------------------------------------

use crate::afxdp::forwarding_build::build_forwarding_state;

/// A tunnel-resolved WG `SessionDecision` matching what the resolver stores
/// for a WG transit flow: `egress_ifindex` = the tunnel LOGICAL ifindex (the
/// resolver copies `endpoint.logical_ifindex`), `tx_ifindex` = 0 (the WG
/// `endpoint.destination` is zeroed so `resolve_tunnel_outer` NoRoutes and the
/// stored tx_ifindex is unset). This is the production shape that makes
/// `tunnel_outer_mtu` fall back to the LOGICAL MTU.
fn wg_logical_tunnel_decision(logical_ifindex: i32, tunnel_endpoint_id: u16) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::MissingNeighbor,
            local_ifindex: 0,
            egress_ifindex: logical_ifindex,
            tx_ifindex: 0,
            tunnel_endpoint_id,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    }
}

#[test]
fn post_transform_wg_inner_mtu_uses_physical_underlay_not_logical_v4() {
    // Fail-on-revert: with the fix the WG inner MTU is derived from the
    // PHYSICAL underlay (reth0.80 = 1500): wg_inner_mtu(AF_INET, 1500) =
    // 1500 - 60 - 15 = 1425. Reverting to tunnel_outer_mtu reads the LOGICAL
    // wg0.0 MTU (1420) → wg_inner_mtu = 1345 → this assertion fails red.
    let state = build_forwarding_state(&crate::afxdp::test_fixtures::wg_outer_mtu_snapshot());
    // Sanity: the fixture really carries the distinct logical/physical MTUs.
    assert_eq!(
        state.egress.get(&400).map(|e| e.mtu),
        Some(1420),
        "wg0.0 logical"
    );
    assert_eq!(
        state.egress.get(&12).map(|e| e.mtu),
        Some(1500),
        "reth0.80 physical"
    );

    let decision = wg_logical_tunnel_decision(400, 1);
    let inner_mtu =
        post_transform_inner_mtu(&decision, &state, false, libc::AF_INET as u8, 0, None);
    assert_eq!(
        inner_mtu, 1425,
        "WG PTB inner MTU MUST be wg_inner_mtu(physical 1500) = 1425, NOT \
         wg_inner_mtu(logical 1420) = 1345 (the #2684 double-subtract)"
    );
    // It MUST equal the encap-guard SSOT: the inverse of wg_encapped_size at
    // the physical MTU, so the PTB advertises exactly what the guard admits.
    assert_eq!(
        inner_mtu,
        crate::afxdp::wg::mss::wg_inner_mtu(libc::AF_INET, 1500),
        "WG PTB inner MTU MUST equal wg_inner_mtu(physical underlay)"
    );

    // End-to-end: a 1400-byte inner v4 DF datagram (L3 = 1400 > 1425? no — it
    // is 1400 <= 1425 so it FORWARDS; pick > 1425 to fire the PTB). A 1440-byte
    // L3 (> 1425) must emit a Frag-Needed advertising 1425.
    let (frame, meta) = inbound_v4_udp(1440 - 28, true); // L3 = 20 + 8 + payload = 1440
    let l3 = meta.l3_offset as usize;
    let next_hop_mtu = match forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, inner_mtu)
    {
        EgressMtuDecision::EmitPacketTooBig { next_hop_mtu } => next_hop_mtu,
        other => panic!("expected EmitPacketTooBig, got {other:?}"),
    };
    assert_eq!(
        next_hop_mtu, 1425,
        "advertised v4 inner MTU = physical-derived 1425"
    );
    // The ICMP source is the ingress interface primary; use reth0.80 (ifindex
    // 12, primary 172.16.80.8) which exists in the snapshot-built state.
    let out = build_frag_needed_v4(&frame, meta, 12, &state, next_hop_mtu)
        .expect("WG inner-source frag-needed must build");
    // reth0.80 carries VLAN 80, so the reply L2 is tagged (18 bytes). Derive
    // the L3 offset from the ethertype rather than hardcoding 14.
    let eth = if u16::from_be_bytes([out[12], out[13]]) == 0x8100 {
        18
    } else {
        14
    };
    let icmp = eth + 20;
    assert_eq!(out[icmp], 3, "ICMP Frag-Needed type");
    assert_eq!(out[icmp + 1], 4, "ICMP Frag-Needed code");
    assert_eq!(
        u16::from_be_bytes([out[icmp + 6], out[icmp + 7]]),
        1425,
        "Frag-Needed carries the physical-derived inner MTU"
    );
}

#[test]
fn post_transform_wg_inner_mtu_uses_physical_underlay_not_logical_v6() {
    // Same fixture, flipped to a v6 outer (peer + transport route in inet6).
    // With the fix: wg_inner_mtu(AF_INET6, 1500) = 1500 - 80 - 15 = 1405.
    // Reverting to tunnel_outer_mtu (logical 1420) → 1325 → fails red.
    let mut snap = crate::afxdp::test_fixtures::wg_outer_mtu_snapshot();
    // Flip the WG endpoint + its peer + the underlay route to IPv6.
    {
        let ep = &mut snap.tunnel_endpoints[0];
        ep.outer_family = "inet6".to_string();
        ep.source = "2001:559:8585:80::8".to_string();
        ep.wg_peers[0].wg_endpoint = "[2001:db8:c0::7]:51820".to_string();
        ep.wg_peers[0].wg_allowed_ips = vec!["10.123.0.0/24".to_string()];
        ep.transport_table = "inet6.0".to_string();
    }
    // Physical reth0.80 already carries a v6 primary in the v4 fixture? No —
    // the v4 fixture's reth0.80 has only a v4 address. Give it a v6 primary so
    // the underlay route resolves on reth0.80, and add the v6 underlay route.
    snap.interfaces[0]
        .addresses
        .push(crate::InterfaceAddressSnapshot {
            family: "inet6".to_string(),
            address: "2001:559:8585:80::8/64".to_string(),
            scope: 0,
        });
    snap.routes = vec![crate::RouteSnapshot {
        table: "inet6.0".to_string(),
        family: "inet6".to_string(),
        destination: "2001:db8:c0::/64".to_string(),
        next_hops: vec!["2001:559:8585:80::1@reth0.80".to_string()],
        discard: false,
        next_table: String::new(),
        preference: 0,
    }];

    let state = build_forwarding_state(&snap);
    assert_eq!(
        state.egress.get(&12).map(|e| e.mtu),
        Some(1500),
        "reth0.80 physical"
    );

    let decision = wg_logical_tunnel_decision(400, 1);
    let inner_mtu =
        post_transform_inner_mtu(&decision, &state, false, libc::AF_INET6 as u8, 0, None);
    assert_eq!(
        inner_mtu, 1405,
        "WG PTB inner MTU (v6 outer) MUST be wg_inner_mtu(physical 1500) = 1405, \
         NOT wg_inner_mtu(logical 1420) = 1325 (the #2684 double-subtract)"
    );
    assert_eq!(
        inner_mtu,
        crate::afxdp::wg::mss::wg_inner_mtu(libc::AF_INET6, 1500),
        "WG PTB inner MTU (v6 outer) MUST equal wg_inner_mtu(physical underlay)"
    );

    // End-to-end: a 1420-byte inner v6 datagram (L3 = 40 + 8 + payload) that
    // exceeds 1405 must emit a Packet-Too-Big advertising 1405.
    let (frame, meta) = inbound_v6_udp(1420 - 48); // L3 = 40 + 8 + payload = 1420
    let l3 = meta.l3_offset as usize;
    let next_hop_mtu = match forwarded_egress_mtu_decision(&frame, l3, meta.addr_family, inner_mtu)
    {
        EgressMtuDecision::EmitPacketTooBig { next_hop_mtu } => next_hop_mtu,
        other => panic!("expected EmitPacketTooBig, got {other:?}"),
    };
    assert_eq!(
        next_hop_mtu, 1405,
        "advertised v6 inner MTU = physical-derived 1405"
    );
    // ICMPv6 source = ingress interface primary v6; reth0.80 (ifindex 12) now
    // carries 2001:559:8585:80::8 (added to the snapshot above).
    let out = build_packet_too_big_v6(&frame, meta, 12, &state, next_hop_mtu as u32)
        .expect("WG inner-source PTB must build");
    // VLAN 80 → tagged L2 (18 bytes); derive the L3 offset from the ethertype.
    let eth = if u16::from_be_bytes([out[12], out[13]]) == 0x8100 {
        18
    } else {
        14
    };
    let icmp = eth + 40;
    assert_eq!(out[icmp], 2, "ICMPv6 Packet Too Big");
    assert_eq!(
        u32::from_be_bytes([out[icmp + 4], out[icmp + 5], out[icmp + 6], out[icmp + 7]]),
        1405,
        "Packet-Too-Big carries the physical-derived inner MTU"
    );
}

#[test]
fn post_transform_wg_inner_mtu_falls_back_to_logical_when_no_peer_endpoint() {
    // Degenerate case: a WG endpoint with no peer endpoint address (no outer
    // hop to route to) falls back to the resolution's logical egress_ifindex
    // MTU — exactly what tunnel_outer_mtu would have yielded, so no regression.
    let mut snap = crate::afxdp::test_fixtures::wg_outer_mtu_snapshot();
    snap.tunnel_endpoints[0].wg_peers[0].wg_endpoint = String::new(); // responder-only
    let state = build_forwarding_state(&snap);
    let decision = wg_logical_tunnel_decision(400, 1);
    let inner_mtu =
        post_transform_inner_mtu(&decision, &state, false, libc::AF_INET as u8, 0, None);
    // Logical egress (400) MTU 1420 → wg_inner_mtu(1420) = 1345.
    assert_eq!(
        inner_mtu, 1345,
        "no peer endpoint → fall back to logical egress MTU (1420) → 1345, \
         no worse than the pre-#2684 tunnel_outer_mtu behaviour"
    );
}

// ---------------------------------------------------------------------------
// #2845: per-peer underlay MTU. One wg interface, TWO peers whose endpoints
// route over DIFFERENT physical underlays with DIFFERENT MTUs. The PTB inner
// MTU advertised for an inner destination must reflect the underlay of the
// SAME peer the encap path selects (by AllowedIPs LPM), NOT an arbitrary first
// peer's. Before #2845 the helper resolved via the FIRST peer with an endpoint
// regardless of inner destination, so traffic to peer B got peer A's underlay
// MTU (over- or under-advertised PMTU).
// ---------------------------------------------------------------------------

/// Extend the shared single-peer WG fixture with a SECOND physical underlay
/// (reth0.50, ifindex 13, MTU 1400) and a SECOND peer (peer B) whose endpoint
/// routes out reth0.50. Peer A keeps the original reth0.80 (ifindex 12, MTU
/// 1500) underlay. The two peers cover disjoint inner prefixes:
///   - peer A: 10.123.0.0/24 → endpoint 203.0.113.7 → reth0.80 (MTU 1500)
///   - peer B: 10.124.0.0/24 → endpoint 198.51.100.7 → reth0.50 (MTU 1400)
/// Peer A is listed first AND given the lexicographically-smaller pubkey, so
/// the pre-#2845 first-peer fallback always resolves to peer A's underlay
/// (1500) — the source of the fail-on-revert RED for peer B.
fn wg_two_peer_asymmetric_snapshot() -> crate::ConfigSnapshot {
    let mut snap = crate::afxdp::test_fixtures::wg_outer_mtu_snapshot();
    // Second physical underlay: reth0.50, ifindex 13, MTU 1400.
    snap.interfaces.push(crate::InterfaceSnapshot {
        name: "reth0.50".to_string(),
        zone: "wan".to_string(),
        linux_name: "ge-0-0-2.50".to_string(),
        ifindex: 13,
        parent_ifindex: 6,
        vlan_id: 50,
        mtu: 1400,
        redundancy_group: 1,
        hardware_addr: "02:bf:72:00:50:08".to_string(),
        addresses: vec![crate::InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "172.16.50.8/24".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    // Route to peer B's endpoint egresses reth0.50.
    snap.routes.push(crate::RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "198.51.100.0/24".to_string(),
        next_hops: vec!["172.16.50.1@reth0.50".to_string()],
        discard: false,
        next_table: String::new(),
        preference: 0,
    });
    {
        let ep = &mut snap.tunnel_endpoints[0];
        // Peer A: give it the smaller pubkey so it is first in any sorted order
        // (the first-peer revert path resolves here).
        ep.wg_peers[0].wg_peer_pubkey_hex = "0a0a0a0a".repeat(8);
        ep.wg_peers[0].wg_allowed_ips = vec!["10.123.0.0/24".to_string()];
        ep.wg_peers[0].wg_endpoint = "203.0.113.7:51820".to_string();
        // Peer B: distinct prefix + endpoint routing over the smaller underlay.
        ep.wg_peers.push(crate::TunnelWgPeerSnapshot {
            wg_peer_pubkey_hex: "0b0b0b0b".repeat(8),
            wg_allowed_ips: vec!["10.124.0.0/24".to_string()],
            wg_endpoint: "198.51.100.7:51820".to_string(),
            ..Default::default()
        });
    }
    snap
}

#[test]
fn post_transform_wg_inner_mtu_is_per_peer_underlay() {
    let state = build_forwarding_state(&wg_two_peer_asymmetric_snapshot());
    // Sanity: the two underlays really carry distinct MTUs, so the per-peer
    // assertion below is meaningful.
    assert_eq!(
        state.egress.get(&12).map(|e| e.mtu),
        Some(1500),
        "reth0.80 underlay"
    );
    assert_eq!(
        state.egress.get(&13).map(|e| e.mtu),
        Some(1400),
        "reth0.50 underlay"
    );

    let decision = wg_logical_tunnel_decision(400, 1);

    // Inner destination covered by peer A → its underlay is reth0.80 (1500).
    let peer_a_dst = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 123, 0, 9));
    let mtu_a = post_transform_inner_mtu(
        &decision,
        &state,
        false,
        libc::AF_INET as u8,
        0,
        Some(peer_a_dst),
    );
    // Inner destination covered by peer B → its underlay is reth0.50 (1400).
    let peer_b_dst = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 124, 0, 9));
    let mtu_b = post_transform_inner_mtu(
        &decision,
        &state,
        false,
        libc::AF_INET as u8,
        0,
        Some(peer_b_dst),
    );

    assert_eq!(
        mtu_a,
        crate::afxdp::wg::mss::wg_inner_mtu(libc::AF_INET, 1500),
        "peer A PTB inner MTU MUST derive from ITS underlay (reth0.80=1500)"
    );
    assert_eq!(
        mtu_b,
        crate::afxdp::wg::mss::wg_inner_mtu(libc::AF_INET, 1400),
        "peer B PTB inner MTU MUST derive from ITS underlay (reth0.50=1400), \
         NOT peer A's 1500 — reverting to the per-interface first-peer \
         assumption returns 1500 here and fails red"
    );
    // The whole point: asymmetric underlays yield DIFFERENT inner MTUs.
    assert_ne!(
        mtu_a, mtu_b,
        "per-peer underlay MTUs must differ for asymmetric peers"
    );
}

/// #8896: a NAT64 packet routed through a tunnel must have BOTH budgets
/// applied — the tunnel's encapsulation overhead AND the RFC 7915 header
/// delta. Before #8896 this function selected rather than composed: the
/// `is_nat64` arm returned first, so the encap overhead was never subtracted.
///
/// **The control is the tunnel-only value at the same MTU.** Asserting the
/// composed number alone would be satisfied by any arithmetic that happens to
/// land there; asserting that it differs from the tunnel-only value by exactly
/// the RFC 7915 delta, in the right direction, pins the composition.
#[test]
fn post_transform_inner_mtu_8896_nat64_through_gre_applies_both_budgets() {
    let mut fwd = forwarding_with_egress(1400);
    insert_tunnel_endpoint(&mut fwd, "gre", libc::AF_INET, 0);
    let decision = tunnel_decision();

    // CONTROL: tunnel only, no NAT64. 1400 - 20 (IPv4 outer) - 4 (GRE) = 1376.
    let tunnel_only =
        post_transform_inner_mtu(&decision, &fwd, false, libc::AF_INET6 as u8, 1400, None);
    assert_eq!(
        tunnel_only, 1376,
        "CONTROL: the tunnel-only inner MTU must be the underlay less the GRE \
         encapsulation. If this is not 1376 the fixture changed and every \
         comparison below is against the wrong baseline"
    );

    // SUBJECT v6->v4: the inner is IPv6, the translated IPv4 is 20 bytes
    // SMALLER, so an IPv6 inner up to tunnel_inner + 20 still fits.
    let composed_v6 =
        post_transform_inner_mtu(&decision, &fwd, true, libc::AF_INET6 as u8, 1400, None);
    assert_eq!(
        composed_v6,
        tunnel_only + 20,
        "#8896: NAT64(v6->v4) through GRE must apply the RFC 7915 delta ON TOP \
         of the tunnel budget. Got {composed_v6}, want {} (tunnel {tunnel_only} + 20). \
         Before #8896 this returned 1420 — the raw egress MTU + 20, with the GRE \
         overhead never subtracted, advertising an inner MTU 24 bytes too large.",
        tunnel_only + 20
    );

    // SUBJECT v4->v6: the translated IPv6 is 20 bytes LARGER, so the IPv4
    // inner must be 20 bytes smaller than the tunnel budget.
    let composed_v4 =
        post_transform_inner_mtu(&decision, &fwd, true, libc::AF_INET as u8, 1400, None);
    assert_eq!(
        composed_v4,
        tunnel_only - 20,
        "#8896: NAT64(v4->v6) through GRE must SUBTRACT the header delta from \
         the tunnel budget. Got {composed_v4}, want {}",
        tunnel_only - 20
    );

    // The two directions must not be equal — if they were, the direction arm
    // is not being read and both would pass a single-sided assertion.
    assert_ne!(
        composed_v6, composed_v4,
        "#8896: the two translation directions produced the same inner MTU, so \
         the family arm is not being consulted"
    );

    // FAIL CLOSED: an unknown mode yields 0 here exactly as the frame builders
    // drop it, rather than silently falling back to the un-composed budget.
    let mut unknown = forwarding_with_egress(1400);
    insert_tunnel_endpoint(&mut unknown, "ipsec-vti-future", libc::AF_INET, 0);
    assert_eq!(
        post_transform_inner_mtu(&decision, &unknown, true, libc::AF_INET6 as u8, 1400, None),
        0,
        "#2327: an unknown tunnel mode must yield no budget, not the NAT64-only one"
    );
}
