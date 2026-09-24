use super::*;

const ICMP_IFINDEX: i32 = 24;
const EGRESS_SRC_MAC: [u8; 6] = [0x02, 0xbf, 0x72, 0x00, 0x00, 0x01];

/// A ForwardingState with one egress interface (the ingress index
/// the reflected-error builders look up). `egress.vlan_id` is the
/// fallback used when the inbound frame is untagged.
fn forwarding_with_egress(vlan_id: u16) -> ForwardingState {
    let mut state = ForwardingState::default();
    state.egress.insert(
        ICMP_IFINDEX,
        EgressInterface {
            bind_ifindex: 0,
            vlan_id,
            mtu: 1500,
            src_mac: EGRESS_SRC_MAC,
            zone_id: 0,
            redundancy_group: 0,
            primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
            primary_v6: Some("2001:559:8585:80::8".parse().expect("v6")),
        },
    );
    state
}

#[derive(Clone, Copy)]
enum InL2 {
    Untagged,
    /// 802.1p priority-tagged VLAN-0: TPID 0x8100, PCP 5, VID 0.
    PriorityTaggedVlan0,
    /// Normal 802.1Q tag, PCP 0, VID 100.
    Vlan100,
}

/// Build an inbound IPv4 UDP packet (so the reflected reply is a
/// real error, not suppressed) with the chosen L2 header. The TTL
/// is 1 so `build_local_time_exceeded_v4` fires; the builders read
/// the inbound tag straight from the frame bytes.
fn inbound_v4(l2: InL2) -> (Vec<u8>, UserspaceDpMeta) {
    let mut frame = Vec::new();
    let dst_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]; // firewall NIC
    let src_mac = [0x00, 0x25, 0x90, 0x12, 0x34, 0x56]; // sender
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    let l3_off: u16 = match l2 {
        InL2::Untagged => {
            frame.extend_from_slice(&0x0800u16.to_be_bytes());
            14
        }
        InL2::PriorityTaggedVlan0 => {
            frame.extend_from_slice(&0x8100u16.to_be_bytes());
            // TCI = PCP 5 << 13 | DEI 0 | VID 0 = 0xA000.
            frame.extend_from_slice(&0xA000u16.to_be_bytes());
            frame.extend_from_slice(&0x0800u16.to_be_bytes());
            18
        }
        InL2::Vlan100 => {
            frame.extend_from_slice(&0x8100u16.to_be_bytes());
            frame.extend_from_slice(&100u16.to_be_bytes());
            frame.extend_from_slice(&0x0800u16.to_be_bytes());
            18
        }
    };
    let l3 = frame.len();
    // IPv4 header, IHL 5, TTL 1, proto UDP, total_len = 20 + 8.
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&28u16.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 1, 17, 0x00, 0x00]);
    frame.extend_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets()); // src
    frame.extend_from_slice(&Ipv4Addr::new(172, 16, 80, 200).octets()); // dst
    let ip_csum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&ip_csum.to_be_bytes());
    // 8-byte UDP header.
    frame.extend_from_slice(&49152u16.to_be_bytes());
    frame.extend_from_slice(&5201u16.to_be_bytes());
    frame.extend_from_slice(&8u16.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());

    let meta = UserspaceDpMeta {
        ingress_ifindex: ICMP_IFINDEX as u32,
        l3_offset: l3_off,
        addr_family: libc::AF_INET as u8,
        protocol: 17,
        ..UserspaceDpMeta::default()
    };
    (frame, meta)
}

/// #2149 regression: a priority-tagged VLAN-0 inbound frame
/// (TPID 0x8100, PCP 5, VID 0) must have its tag — including PCP —
/// reflected on the local-origin ICMP error. Pre-fix the builder
/// gated tag emission on `vlan_id > 0`, so VID 0 collapsed to
/// untagged (14-byte L2) and PCP was lost.
#[test]
fn reflected_v4_error_preserves_priority_tagged_vlan0() {
    let (frame, meta) = inbound_v4(InL2::PriorityTaggedVlan0);
    // Egress config VID is 0 (no membership) — the ONLY tag source
    // is the inbound priority tag, proving preservation rather than
    // an egress-config fallback.
    let fwd = forwarding_with_egress(0);
    let out = build_local_icmp_error_v4(&frame, meta, ICMP_IFINDEX, &fwd, 11, 0).expect("v4 error");

    assert_eq!(
        &out[12..14],
        &[0x81, 0x00],
        "reflected frame must carry an 802.1Q TPID"
    );
    assert_eq!(
        &out[14..16],
        &[0xA0, 0x00],
        "reflected TCI must preserve PCP=5, VID=0 (the priority tag)"
    );
    // EtherType IPv4 follows the tag → L3 starts at byte 18.
    assert_eq!(&out[16..18], &[0x08, 0x00]);
    assert_eq!(out[18], 0x45, "IPv4 outer header starts at offset 18");
    // MACs swapped: reflected dst = inbound src.
    assert_eq!(&out[0..6], &[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]);
    assert_eq!(&out[6..12], &EGRESS_SRC_MAC);
}

/// A normal VID > 0 inbound tag is reflected unchanged (regression
/// guard for the common path).
#[test]
fn reflected_v4_error_preserves_normal_vlan() {
    let (frame, meta) = inbound_v4(InL2::Vlan100);
    let fwd = forwarding_with_egress(0);
    let out = build_local_icmp_error_v4(&frame, meta, ICMP_IFINDEX, &fwd, 11, 0).expect("v4 error");
    assert_eq!(&out[12..14], &[0x81, 0x00]);
    assert_eq!(
        &out[14..16],
        &100u16.to_be_bytes(),
        "VID 100 preserved, PCP 0"
    );
    assert_eq!(out[18], 0x45);
}

/// An untagged inbound frame stays untagged on the reflected error
/// when the egress interface has no configured VID.
#[test]
fn reflected_v4_error_untagged_stays_untagged() {
    let (frame, meta) = inbound_v4(InL2::Untagged);
    let fwd = forwarding_with_egress(0);
    let out = build_local_icmp_error_v4(&frame, meta, ICMP_IFINDEX, &fwd, 11, 0).expect("v4 error");
    assert_eq!(
        &out[12..14],
        &[0x08, 0x00],
        "EtherType IPv4 at byte 12 (untagged)"
    );
    assert_eq!(out[14], 0x45, "IPv4 outer header starts at offset 14");
}

/// An untagged inbound frame on an egress interface WITH a
/// configured VID falls back to that VID (legacy egress behavior).
#[test]
fn reflected_v4_error_untagged_falls_back_to_egress_vid() {
    let (frame, meta) = inbound_v4(InL2::Untagged);
    let fwd = forwarding_with_egress(50);
    let out = build_local_icmp_error_v4(&frame, meta, ICMP_IFINDEX, &fwd, 11, 0).expect("v4 error");
    assert_eq!(&out[12..14], &[0x81, 0x00]);
    assert_eq!(&out[14..16], &50u16.to_be_bytes(), "egress VID 50 fallback");
}

/// #2314: rewrite the IPv4 destination of an `inbound_v4` frame
/// (offset depends on the L2 tag) and fix the IP-header checksum.
fn set_inbound_v4_dst(frame: &mut [u8], meta: UserspaceDpMeta, dst: Ipv4Addr) {
    let l3 = meta.l3_offset as usize;
    frame[l3 + 16..l3 + 20].copy_from_slice(&dst.octets());
    frame[l3 + 10..l3 + 12].copy_from_slice(&[0, 0]);
    let csum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&csum.to_be_bytes());
}

/// Build an inbound IPv6 UDP frame (untagged) destined to `dst`, with
/// `l4_offset` set so `can_generate_icmp_error_reply` can locate the
/// transport header.
fn inbound_v6_to(dst: Ipv6Addr) -> (Vec<u8>, UserspaceDpMeta) {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // firewall NIC
    frame.extend_from_slice(&[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]); // sender
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    let l3 = frame.len();
    frame.push(0x60); // version 6
    frame.extend_from_slice(&[0x00, 0x00, 0x00]); // TC/flow
    frame.extend_from_slice(&8u16.to_be_bytes()); // payload = 8 (UDP hdr)
    frame.push(17); // next header UDP
    frame.push(64); // hop limit
    frame.extend_from_slice(
        &"2001:559:8585:bf01::20"
            .parse::<Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    frame.extend_from_slice(&dst.octets());
    let l4 = frame.len();
    frame.extend_from_slice(&49152u16.to_be_bytes());
    frame.extend_from_slice(&5201u16.to_be_bytes());
    frame.extend_from_slice(&8u16.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    let meta = UserspaceDpMeta {
        ingress_ifindex: ICMP_IFINDEX as u32,
        l3_offset: l3 as u16,
        l4_offset: l4 as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: 17,
        ..UserspaceDpMeta::default()
    };
    (frame, meta)
}

/// #2314 reject/time-exceeded path: a trigger packet whose IPv4
/// destination is multicast (224.0.0.0/4) must suppress the locally
/// generated ICMP error (`can_generate_icmp_error_reply` returns false,
/// so `build_reject_icmp_unreachable` returns None). RFC 1812 §4.3.2.7.
#[test]
fn reject_suppressed_for_v4_multicast_dst() {
    let (mut frame, meta) = inbound_v4(InL2::Untagged);
    set_inbound_v4_dst(&mut frame, meta, Ipv4Addr::new(239, 1, 2, 3));
    assert!(
        !can_generate_icmp_error_reply(&frame, meta, &forwarding_with_egress(0)),
        "IPv4 multicast destination must suppress the reply"
    );
    let fwd = forwarding_with_egress(0);
    assert!(
        build_reject_icmp_unreachable(
            &frame,
            meta,
            ICMP_IFINDEX,
            &fwd,
            crate::filter::RejectMessage::ADMIN_PROHIBITED,
        )
        .is_none(),
        "reject unreachable must not build for a multicast destination"
    );
}

/// #2314: an IPv4 trigger destined to the limited broadcast
/// 255.255.255.255 must suppress the reply.
#[test]
fn reject_suppressed_for_v4_limited_broadcast_dst() {
    let (mut frame, meta) = inbound_v4(InL2::Untagged);
    set_inbound_v4_dst(&mut frame, meta, Ipv4Addr::new(255, 255, 255, 255));
    assert!(
        !can_generate_icmp_error_reply(&frame, meta, &forwarding_with_egress(0)),
        "IPv4 limited broadcast destination must suppress the reply"
    );
}

/// #2411: a `ForwardingState` whose connected v4 table holds a single
/// connected prefix, so the directed-broadcast gate has a subnet mask
/// to test the trigger destination against.
fn forwarding_with_connected_v4(cidr: &str) -> ForwardingState {
    let mut state = forwarding_with_egress(0);
    let net: ipnet::Ipv4Net = cidr.parse().expect("cidr");
    state.connected_v4.push(ConnectedRouteV4 {
        prefix: crate::prefix::PrefixV4::from_net(net),
        host: net.addr(),
        ifindex: ICMP_IFINDEX,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    state
}

/// #2411: an IPv4 trigger destined to a SUBNET-DIRECTED broadcast
/// (the all-ones host of a configured connected prefix, e.g.
/// 10.0.1.255 for 10.0.1.0/24) must suppress the locally generated
/// ICMP error (RFC 1812 §4.3.2.7) even though it is a plain unicast
/// address to the limited-broadcast / multicast tests. Fails (error
/// generated) if the `dest_is_directed_broadcast` check is removed.
#[test]
fn reject_suppressed_for_v4_directed_broadcast_dst() {
    let (mut frame, meta) = inbound_v4(InL2::Untagged);
    set_inbound_v4_dst(&mut frame, meta, Ipv4Addr::new(10, 0, 1, 255));
    let fwd = forwarding_with_connected_v4("10.0.1.0/24");
    assert!(
        !can_generate_icmp_error_reply(&frame, meta, &fwd),
        "IPv4 subnet-directed broadcast must suppress the reply"
    );
    assert!(
        build_reject_icmp_unreachable(
            &frame,
            meta,
            ICMP_IFINDEX,
            &fwd,
            crate::filter::RejectMessage::ADMIN_PROHIBITED,
        )
        .is_none(),
        "reject unreachable must not build for a directed broadcast"
    );
}

/// #2411 anti-over-suppress: a normal unicast HOST inside the same
/// connected subnet (10.0.1.42 in 10.0.1.0/24) must STILL generate
/// the error — only the all-ones host is the directed broadcast.
#[test]
fn reject_still_allowed_for_unicast_in_connected_subnet() {
    let (mut frame, meta) = inbound_v4(InL2::Untagged);
    set_inbound_v4_dst(&mut frame, meta, Ipv4Addr::new(10, 0, 1, 42));
    let fwd = forwarding_with_connected_v4("10.0.1.0/24");
    assert!(
        can_generate_icmp_error_reply(&frame, meta, &fwd),
        "a unicast host inside a connected subnet must allow the reply"
    );
}

/// #2411 fail-on-revert guard for the prefix-length skip: the .255
/// host of a /32 connected prefix is the host itself, NOT a directed
/// broadcast, so a normal unicast to a /32 host must NOT be
/// suppressed (the `prefix_len() < 31` guard keeps it allowed).
#[test]
fn reject_still_allowed_for_v4_host_route_all_ones_octet() {
    let (mut frame, meta) = inbound_v4(InL2::Untagged);
    set_inbound_v4_dst(&mut frame, meta, Ipv4Addr::new(10, 0, 1, 255));
    let fwd = forwarding_with_connected_v4("10.0.1.255/32");
    assert!(
        can_generate_icmp_error_reply(&frame, meta, &fwd),
        "a /32 connected host must not be treated as a directed broadcast"
    );
}

/// #2487: rewrite the IPv4 SOURCE of an `inbound_v4` frame (offset
/// depends on the L2 tag) and fix the IP-header checksum. Mirror of
/// `set_inbound_v4_dst` for the source-side directed-broadcast test.
fn set_inbound_v4_src(frame: &mut [u8], meta: UserspaceDpMeta, src: Ipv4Addr) {
    let l3 = meta.l3_offset as usize;
    frame[l3 + 12..l3 + 16].copy_from_slice(&src.octets());
    frame[l3 + 10..l3 + 12].copy_from_slice(&[0, 0]);
    let csum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&csum.to_be_bytes());
}

/// #2487: an IPv4 trigger whose SOURCE is a SUBNET-DIRECTED broadcast
/// (the all-ones host of a configured connected prefix, e.g.
/// 10.0.1.255 for 10.0.1.0/24) must suppress the locally generated
/// ICMP error (RFC 1812 §4.3.2.7). The error is addressed to the
/// trigger's source, so a directed-broadcast source would emit the
/// error to that directed broadcast (Smurf backscatter). This is the
/// source-side sibling of #2411 — the limited-broadcast test in
/// `source_is_invalid_for_icmp_error` (`is_broadcast()`) only catches
/// 255.255.255.255. FAILS (error generated) if the
/// `src_is_directed_broadcast` check is removed.
#[test]
fn reject_suppressed_for_v4_directed_broadcast_src() {
    let (mut frame, meta) = inbound_v4(InL2::Untagged);
    set_inbound_v4_src(&mut frame, meta, Ipv4Addr::new(10, 0, 1, 255));
    let fwd = forwarding_with_connected_v4("10.0.1.0/24");
    assert!(
        !can_generate_icmp_error_reply(&frame, meta, &fwd),
        "IPv4 subnet-directed broadcast SOURCE must suppress the reply"
    );
    assert!(
        build_reject_icmp_unreachable(
            &frame,
            meta,
            ICMP_IFINDEX,
            &fwd,
            crate::filter::RejectMessage::ADMIN_PROHIBITED,
        )
        .is_none(),
        "reject unreachable must not build for a directed-broadcast source"
    );
}

/// #2487 anti-over-suppress: a normal unicast HOST source inside the
/// same connected subnet (10.0.1.42 in 10.0.1.0/24) must STILL
/// generate the error — only the all-ones host is the directed
/// broadcast.
#[test]
fn reject_still_allowed_for_unicast_src_in_connected_subnet() {
    let (mut frame, meta) = inbound_v4(InL2::Untagged);
    set_inbound_v4_src(&mut frame, meta, Ipv4Addr::new(10, 0, 1, 42));
    let fwd = forwarding_with_connected_v4("10.0.1.0/24");
    assert!(
        can_generate_icmp_error_reply(&frame, meta, &fwd),
        "a unicast host source inside a connected subnet must allow the reply"
    );
}

/// #2487 fail-on-revert guard for the prefix-length skip: a /32
/// connected host's `.255` octet is the host itself, NOT a directed
/// broadcast, so a normal unicast source to a /32 host must NOT be
/// suppressed (the `prefix_len() < 31` guard keeps it allowed).
#[test]
fn reject_still_allowed_for_v4_host_route_all_ones_octet_src() {
    let (mut frame, meta) = inbound_v4(InL2::Untagged);
    set_inbound_v4_src(&mut frame, meta, Ipv4Addr::new(10, 0, 1, 255));
    let fwd = forwarding_with_connected_v4("10.0.1.255/32");
    assert!(
        can_generate_icmp_error_reply(&frame, meta, &fwd),
        "a /32 connected host source must not be treated as a directed broadcast"
    );
}

/// #2314: an IPv6 trigger destined to ff00::/8 multicast must suppress
/// the reply (RFC 4443 §2.4(e)).
#[test]
fn reject_suppressed_for_v6_multicast_dst() {
    let (frame, meta) = inbound_v6_to("ff02::1".parse().expect("v6 mcast"));
    assert!(
        !can_generate_icmp_error_reply(&frame, meta, &forwarding_with_egress(0)),
        "IPv6 multicast destination must suppress the reply"
    );
    let fwd = forwarding_with_egress(0);
    assert!(
        build_reject_icmp_unreachable(
            &frame,
            meta,
            ICMP_IFINDEX,
            &fwd,
            crate::filter::RejectMessage::ADMIN_PROHIBITED,
        )
        .is_none(),
        "reject unreachable must not build for an IPv6 multicast destination"
    );
}

/// #2314 fail-on-revert: a NORMAL unicast destination must STILL allow
/// the reply. Pairs with the suppression tests so reverting the gate
/// turns those red while this one stays green.
#[test]
fn reject_still_allowed_for_unicast_dst() {
    // IPv4 default destination 172.16.80.200 is plain unicast.
    let (frame4, meta4) = inbound_v4(InL2::Untagged);
    assert!(
        can_generate_icmp_error_reply(&frame4, meta4, &forwarding_with_egress(0)),
        "a unicast IPv4 destination must allow the reply"
    );
    let fwd = forwarding_with_egress(0);
    assert!(
        build_reject_icmp_unreachable(
            &frame4,
            meta4,
            ICMP_IFINDEX,
            &fwd,
            crate::filter::RejectMessage::ADMIN_PROHIBITED,
        )
        .is_some(),
        "reject unreachable must build for a unicast destination"
    );
    // IPv6 global unicast destination.
    let (frame6, meta6) = inbound_v6_to("2001:559:8585:80::200".parse().expect("v6 ucast"));
    assert!(
        can_generate_icmp_error_reply(&frame6, meta6, &forwarding_with_egress(0)),
        "a unicast IPv6 destination must allow the reply"
    );
}

/// #6854: the ICMP code on a reject reply comes from the term's
/// `then reject <message-type>`, not a hardcoded constant.
///
/// Before #6854 `build_reject_icmp_unreachable` passed literal 13 (v4) / 1 (v6)
/// for every reject, so `then reject host-unreachable` committed cleanly,
/// displayed back, and put administratively-prohibited on the wire. A peer that
/// distinguishes them — a traceroute renderer, or an application that retries on
/// host-unreachable but gives up on admin-prohibited — saw the wrong signal.
///
/// This asserts the code BYTE in the built frame rather than the resolver's
/// return value. A unit test on `resolve_reject_message` alone passes just as
/// well when the builder ignores its argument, which is exactly the state this
/// issue describes.
#[test]
fn reject_reply_carries_the_configured_icmp_code_6854() {
    let fwd = forwarding_with_egress(0);

    // v4: host-unreachable is RFC 792 code 1, not 13.
    let (frame, meta) = inbound_v4(InL2::Untagged);
    let msg = crate::filter::resolve_reject_message("host-unreachable");
    let built = build_reject_icmp_unreachable(&frame, meta, ICMP_IFINDEX, &fwd, msg)
        .expect("#6854: the v4 reject reply must build");
    let (ty, code) = icmp_type_code_v4_6854(&built);
    assert_eq!(
        (ty, code),
        (3, 1),
        "#6854: `then reject host-unreachable` must put ICMPv4 type 3 code 1 on the wire, \
         not the hardcoded code 13 (administratively-prohibited)"
    );

    // The default is unchanged: a term with no message-type still sends 13, so
    // this change is invisible to every config that does not use the feature.
    let dflt = crate::filter::resolve_reject_message("");
    let built = build_reject_icmp_unreachable(&frame, meta, ICMP_IFINDEX, &fwd, dflt)
        .expect("#6854: the default v4 reject reply must build");
    assert_eq!(
        icmp_type_code_v4_6854(&built),
        (3, 13),
        "#6854: a term with NO message-type must keep sending code 13 — this change must be \
         bit-identical for a config that does not use the feature"
    );
}

/// Read (type, code) out of the ICMPv4 payload of a built reply frame.
///
/// Walks the L2/L3 headers rather than indexing a fixed offset, so a VLAN tag
/// or an IP options change does not silently make this read the wrong bytes and
/// assert against garbage.
fn icmp_type_code_v4_6854(frame: &[u8]) -> (u8, u8) {
    let mut off = 14usize; // ethernet
    if frame.len() > 13 && u16::from_be_bytes([frame[12], frame[13]]) == 0x8100 {
        off += 4; // one VLAN tag
    }
    assert!(frame.len() > off, "frame too short for an IPv4 header");
    let ihl = usize::from(frame[off] & 0x0f) * 4;
    let icmp = off + ihl;
    assert!(
        frame.len() > icmp + 1,
        "frame too short for an ICMP type/code at offset {icmp}"
    );
    (frame[icmp], frame[icmp + 1])
}
