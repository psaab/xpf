// Tests for afxdp/frame/inspect.rs (#2361) — the live ingress frame parser
// must bound the L4 port read by the IP-DECLARED packet length
// (IPv4 total_len / IPv6 40+payload_len), not merely the backing slice.
//
// These pin the fail-closed invariant that out-of-datagram trailing slack
// (NIC zero-pad on a sub-60-byte frame, or attacker-supplied bytes) can NOT
// be read as L4 ports — mirroring the sibling generated-reply parser's
// `generated_l4_ports` bound (`generated.rs`, #2321/#2238). Loaded as a
// sibling submodule via `#[path = "inspect_tests.rs"]`.

use super::*;

const ETH_DST: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const ETH_SRC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

/// Build an untagged IPv4 frame: eth(14) + IPv4 header(20) + `l4` bytes.
/// `declared_total_len` is written into the IPv4 total_len field (bytes
/// [2..4]) INDEPENDENTLY of how many L4 bytes are actually appended, so a
/// caller can declare a short datagram but still carry trailing slack.
fn v4_frame(protocol: u8, declared_total_len: u16, l4: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&ETH_DST);
    frame.extend_from_slice(&ETH_SRC);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    // IPv4 header (IHL=5 => 20 bytes).
    frame.push(0x45);
    frame.push(0x00); // ToS
    frame.extend_from_slice(&declared_total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]); // id
    frame.extend_from_slice(&[0x40, 0x00]); // flags/frag-off (DF, offset 0)
    frame.extend_from_slice(&[64, protocol]); // ttl, proto
    frame.extend_from_slice(&[0x00, 0x00]); // checksum (unused by parser)
    frame.extend_from_slice(&Ipv4Addr::new(192, 0, 2, 1).octets());
    frame.extend_from_slice(&Ipv4Addr::new(192, 0, 2, 2).octets());
    frame.extend_from_slice(l4);
    frame
}

/// Build an untagged IPv6 frame: eth(14) + IPv6 header(40) + `l4` bytes.
/// `declared_payload_len` is written into the payload_len field (bytes
/// [4..6]) INDEPENDENTLY of the appended L4, so a short datagram can carry
/// trailing slack.
fn v6_frame(next_header: u8, declared_payload_len: u16, l4: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&ETH_DST);
    frame.extend_from_slice(&ETH_SRC);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.push(0x60); // version 6
    frame.extend_from_slice(&[0x00, 0x00, 0x00]); // tc + flow label
    frame.extend_from_slice(&declared_payload_len.to_be_bytes());
    frame.push(next_header);
    frame.push(64); // hop limit
    frame.extend_from_slice(&[0x20; 16]); // src
    frame.extend_from_slice(&[0x30; 16]); // dst
    frame.extend_from_slice(l4);
    frame
}

/// 4 TCP/UDP port bytes (src=0x1122, dst=0x3344) the parser must NOT read
/// when they fall outside the IP-declared packet end.
const FAKE_PORTS: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

fn v4_meta(protocol: u8) -> UserspaceDpMeta {
    UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol,
        ..UserspaceDpMeta::default()
    }
}

fn v6_meta(protocol: u8) -> UserspaceDpMeta {
    UserspaceDpMeta {
        addr_family: libc::AF_INET6 as u8,
        protocol,
        ..UserspaceDpMeta::default()
    }
}

// ---- IPv4 frame-led parser: out-of-declared-length ports -> None ----

#[test]
fn v4_total_len_ihl_only_with_fake_tcp_ports_returns_none() {
    // total_len = 20 (IHL only, no L4 in the IP-declared datagram) but the
    // buffer carries 4 trailing slack bytes that spell tcp/ports. The port
    // read at l4=l3+20 would land entirely OUTSIDE the IP-declared end
    // (l3+20) -> must fail closed (None / flowless).
    let frame = v4_frame(PROTO_TCP, 20, &FAKE_PORTS);
    assert_eq!(
        parse_ipv4_session_flow_from_frame(&frame, v4_meta(PROTO_TCP)),
        None,
        "ports past the IPv4 total_len must NOT be read as L4"
    );
    // The bytes ARE present in the slice — proving the old slice-only bound
    // would have returned them.
    assert_eq!(&frame[14 + 20..14 + 24], &FAKE_PORTS);
}

#[test]
fn v4_total_len_ihl_plus_two_with_fake_udp_ports_returns_none() {
    // total_len = 22 => declared end at l3+22, but the 4 UDP port bytes end
    // at l3+24 > l3+22 -> straddles the IP-declared boundary -> None.
    let frame = v4_frame(PROTO_UDP, 22, &FAKE_PORTS);
    assert_eq!(
        parse_ipv4_session_flow_from_frame(&frame, v4_meta(PROTO_UDP)),
        None,
        "ports straddling the IPv4 total_len boundary must fail closed"
    );
}

#[test]
fn v4_well_formed_tcp_parses_ports_normally() {
    // total_len == actual (20 + 4) so the ports lie INSIDE the declared
    // datagram. Anti-over-gate: a legitimate packet still classifies.
    let frame = v4_frame(PROTO_TCP, 24, &[0xab, 0xcd, 0x12, 0x34]);
    let flow = parse_ipv4_session_flow_from_frame(&frame, v4_meta(PROTO_TCP))
        .expect("well-formed v4 TCP must parse");
    assert_eq!(flow.forward_key.src_port, 0xabcd);
    assert_eq!(flow.forward_key.dst_port, 0x1234);
}

// ---- IPv6 frame-led parser ----

#[test]
fn v6_payload_len_zero_with_fake_tcp_ports_returns_none() {
    // payload_len = 0 => declared end at l3+40, but the slice carries 4
    // trailing fake port bytes at l3+40. Must fail closed.
    let frame = v6_frame(PROTO_TCP, 0, &FAKE_PORTS);
    assert_eq!(
        parse_session_flow_from_frame(&frame, v6_meta(PROTO_TCP)),
        None,
        "ports past the IPv6 payload_len must NOT be read as L4"
    );
    assert_eq!(&frame[14 + 40..14 + 44], &FAKE_PORTS);
}

#[test]
fn v6_well_formed_udp_parses_ports_normally() {
    // payload_len == 4 (the 4 UDP port bytes are inside the datagram).
    let frame = v6_frame(PROTO_UDP, 4, &[0x55, 0x66, 0x77, 0x88]);
    let flow = parse_session_flow_from_frame(&frame, v6_meta(PROTO_UDP))
        .expect("well-formed v6 UDP must parse");
    assert_eq!(flow.forward_key.src_port, 0x5566);
    assert_eq!(flow.forward_key.dst_port, 0x7788);
}

// ---- meta-offset fallback (parse_session_flow_from_bytes) ----

#[test]
fn meta_fallback_v4_short_total_len_returns_none() {
    // Drive the meta-offset fallback arm: stamp matching IPs (so the meta
    // fast path's metadata_tuple_complete is satisfied by addresses) but a
    // protocol that needs ports, with l4 pointing past the declared end.
    // total_len = 20 (no L4 declared) + trailing fake ports.
    let frame = v4_frame(PROTO_TCP, 20, &FAKE_PORTS);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        l4_offset: 14 + 20,
        ..UserspaceDpMeta::default()
    };
    assert_eq!(
        parse_session_flow_from_bytes(&frame, meta),
        None,
        "meta-offset fallback must also honor the IPv4 total_len bound"
    );
}

#[test]
fn meta_fallback_v6_short_payload_len_returns_none() {
    let frame = v6_frame(PROTO_TCP, 0, &FAKE_PORTS);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        l4_offset: 14 + 40,
        ..UserspaceDpMeta::default()
    };
    assert_eq!(
        parse_session_flow_from_bytes(&frame, meta),
        None,
        "meta-offset fallback must also honor the IPv6 payload_len bound"
    );
}

// ---- meta fast path (live_frame_ports_from_meta_bytes / _bytes) ----

#[test]
fn meta_fast_path_v4_out_of_declared_ports_returns_none() {
    // #2357-style chokepoint: a meta-stamped l4_offset that points past the
    // IP-declared end must not yield ports. total_len = 20, fake trailing
    // ports, l4_offset = l3+20.
    let frame = v4_frame(PROTO_TCP, 20, &FAKE_PORTS);
    let meta = ForwardPacketMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        l4_offset: 14 + 20,
        ..ForwardPacketMeta::default()
    };
    assert_eq!(
        live_frame_ports_from_meta_bytes(&frame, meta),
        None,
        "meta fast path must bound the port read by the IPv4 total_len"
    );
}

#[test]
fn meta_fast_path_v4_well_formed_returns_ports() {
    // Anti-over-gate for the meta fast path.
    let frame = v4_frame(PROTO_TCP, 24, &[0xab, 0xcd, 0x12, 0x34]);
    let meta = ForwardPacketMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        l4_offset: 14 + 20,
        ..ForwardPacketMeta::default()
    };
    assert_eq!(
        live_frame_ports_from_meta_bytes(&frame, meta),
        Some((0xabcd, 0x1234)),
        "well-formed meta fast path still returns ports"
    );
}

#[test]
fn live_frame_ports_bytes_v6_out_of_declared_returns_none() {
    // Byte-led variant (no usable meta l4): re-derives l3 + declared end
    // from the frame and must still fail closed.
    let frame = v6_frame(PROTO_TCP, 0, &FAKE_PORTS);
    assert_eq!(
        live_frame_ports_bytes(&frame, libc::AF_INET6 as u8, PROTO_TCP),
        None,
        "byte-led meta path must bound by the IPv6 payload_len"
    );
}

// ---- declared-end helper unit truth ----

#[test]
fn declared_end_helpers_clamp_to_slice_and_floor() {
    // v4: total_len declares MORE than the slice -> clamp to slice len.
    let frame = v4_frame(PROTO_TCP, 1500, &FAKE_PORTS); // slice = 14+20+4=38
    assert_eq!(ipv4_declared_l3_end(&frame, 14), Some(frame.len()));
    // v4: total_len below ihl floors at l3+ihl (l3+20).
    let frame2 = v4_frame(PROTO_TCP, 10, &FAKE_PORTS);
    assert_eq!(ipv4_declared_l3_end(&frame2, 14), Some(14 + 20));
    // v6: payload_len declares more than the slice -> clamp to slice.
    let frame3 = v6_frame(PROTO_TCP, 1000, &FAKE_PORTS);
    assert_eq!(ipv6_declared_l3_end(&frame3, 14), Some(frame3.len()));
}

// ---- clamp-panic safety (Copilot fold): ihl declares more than the slice ----

#[test]
fn ipv4_declared_end_oversized_ihl_truncated_buffer_returns_none_no_panic() {
    // IHL nibble = 15 => declared IPv4 header = 60 bytes, but the buffer
    // holds only l3 + 20 (eth + minimal IPv4 header, no options present).
    // Without the `frame.len() < l3 + ihl` guard, `clamp(min = l3+60,
    // max = l3+20)` has min > max and PANICS. Must fail closed (None).
    let mut frame = v4_frame(PROTO_TCP, 20, &[]); // eth(14) + IPv4(20), no L4
    assert_eq!(frame.len(), 14 + 20);
    frame[14] = 0x4f; // version 4, IHL = 15 (60-byte header claimed)
    // A panic here (clamp min > max) is a test FAILURE.
    assert_eq!(
        ipv4_declared_l3_end(&frame, 14),
        None,
        "oversized IHL on a truncated buffer must fail closed, not panic"
    );
}

#[test]
fn meta_fast_path_oversized_ihl_truncated_buffer_no_panic() {
    // Reachable from the meta-driven caller, which does NOT validate ihl
    // against the slice. Same crafted frame; must not panic and must yield
    // no ports (None).
    let mut frame = v4_frame(PROTO_TCP, 20, &[]);
    frame[14] = 0x4f; // IHL = 15
    let meta = ForwardPacketMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        l4_offset: 14 + 20,
        ..ForwardPacketMeta::default()
    };
    assert_eq!(
        live_frame_ports_from_meta_bytes(&frame, meta),
        None,
        "meta fast path must not panic on an oversized IHL truncated frame"
    );
}

// ---- #3067: ICMP identifier is a pseudo-port ONLY for query types ----
//
// `parse_flow_ports` reads bytes [l4+4, l4+6) of the ICMP/ICMPv6 header as a
// pseudo source port. Those two bytes are the Identifier ONLY for the query
// types (Echo, and for ICMPv4 the Timestamp/Information pairs). For error and
// control types (Dest-Unreachable, Packet-Too-Big, Time-Exceeded,
// Parameter-Problem, Redirect, ND/MLD) they are part of a gateway address /
// next-hop MTU / pointer / unused field — NOT a port — so treating them as one
// installed bogus identifier-keyed sessions for transit ICMP control traffic.
// These tests pin the type discrimination. Reverting it (back to an
// unconditional `Some((ident, 0))`) turns the non-query assertions RED.

/// Build an 8-byte ICMP/ICMPv6 header L4 payload: type, code, 2-byte checksum,
/// then a 2-byte "identifier" word (bytes [4..6]) and a 2-byte sequence word.
fn icmp_l4(icmp_type: u8, ident: u16) -> [u8; 8] {
    let id = ident.to_be_bytes();
    [icmp_type, 0x00, 0x00, 0x00, id[0], id[1], 0x00, 0x01]
}

const ICMP_IDENT: u16 = 0xABCD;
// Reachable l4/declared_end for the helper-built frames: eth(14) + IP header.
const V4_ICMP_L4: usize = 14 + 20;
const V6_ICMP_L4: usize = 14 + 40;

#[test]
fn icmpv4_echo_request_reply_still_yields_identifier_pseudo_port() {
    for icmp_type in [8u8, 0u8] {
        let frame = v4_frame(PROTO_ICMP, 28, &icmp_l4(icmp_type, ICMP_IDENT));
        let declared_end = ipv4_declared_l3_end(&frame, 14).expect("v4 declared end");
        assert_eq!(
            parse_flow_ports(&frame, V4_ICMP_L4, PROTO_ICMP, declared_end),
            Some((ICMP_IDENT, 0)),
            "ICMPv4 echo type {icmp_type} must still carry the identifier as the pseudo-port"
        );
    }
}

#[test]
fn icmpv4_timestamp_information_query_types_yield_identifier() {
    // RFC 792 query types whose Identifier sits at the same [4..6] offset.
    for icmp_type in [13u8, 14u8, 15u8, 16u8] {
        let frame = v4_frame(PROTO_ICMP, 28, &icmp_l4(icmp_type, ICMP_IDENT));
        let declared_end = ipv4_declared_l3_end(&frame, 14).unwrap();
        assert_eq!(
            parse_flow_ports(&frame, V4_ICMP_L4, PROTO_ICMP, declared_end),
            Some((ICMP_IDENT, 0)),
            "ICMPv4 query type {icmp_type} carries an identifier at [4..6]"
        );
    }
}

#[test]
fn icmpv4_error_control_types_yield_no_pseudo_port() {
    // Dest-Unreachable (3), Time-Exceeded (11), Parameter-Problem (12),
    // Redirect (5). Bytes [4..6] here are NOT an identifier — they are part of
    // the unused word / gateway address / pointer. Must be flowless (None) so
    // no bogus identifier-keyed session is installed.
    for icmp_type in [3u8, 5u8, 11u8, 12u8] {
        // The "identifier" bytes are present in the slice (proving the old
        // unconditional read would have returned them as a fake port).
        let frame = v4_frame(PROTO_ICMP, 28, &icmp_l4(icmp_type, ICMP_IDENT));
        let declared_end = ipv4_declared_l3_end(&frame, 14).unwrap();
        assert_eq!(
            parse_flow_ports(&frame, V4_ICMP_L4, PROTO_ICMP, declared_end),
            None,
            "ICMPv4 error/control type {icmp_type} must NOT install a pseudo-port"
        );
    }
}

#[test]
fn icmpv6_echo_request_reply_still_yields_identifier_pseudo_port() {
    for icmp_type in [128u8, 129u8] {
        let frame = v6_frame(PROTO_ICMPV6, 8, &icmp_l4(icmp_type, ICMP_IDENT));
        let declared_end = ipv6_declared_l3_end(&frame, 14).expect("v6 declared end");
        assert_eq!(
            parse_flow_ports(&frame, V6_ICMP_L4, PROTO_ICMPV6, declared_end),
            Some((ICMP_IDENT, 0)),
            "ICMPv6 echo type {icmp_type} must still carry the identifier as the pseudo-port"
        );
    }
}

#[test]
fn icmpv6_packet_too_big_redirect_nd_yield_no_pseudo_port() {
    // Packet-Too-Big (2) — bytes [4..6] are the high half of the next-hop MTU.
    // Dest-Unreachable (1), Time-Exceeded (3), Parameter-Problem (4),
    // Redirect (137), Router/Neighbor Solicit/Advert (133..136). None is an
    // identifier-bearing query type -> flowless.
    for icmp_type in [1u8, 2u8, 3u8, 4u8, 133u8, 134u8, 135u8, 136u8, 137u8] {
        let frame = v6_frame(PROTO_ICMPV6, 8, &icmp_l4(icmp_type, ICMP_IDENT));
        let declared_end = ipv6_declared_l3_end(&frame, 14).unwrap();
        assert_eq!(
            parse_flow_ports(&frame, V6_ICMP_L4, PROTO_ICMPV6, declared_end),
            None,
            "ICMPv6 error/control/ND type {icmp_type} must NOT install a pseudo-port"
        );
    }
}

// ---- #3290: the metadata fallback must honor the SAME ICMP query-type gate ----
//
// The XDP shim stamps `flow_src_port = bytes[l4+4..l4+6]` for EVERY ICMP type
// (no query gate), so a non-query ICMP error/control packet arrives with a
// hostile pseudo-port in metadata. `parse_session_flow_from_bytes` must NOT
// reconstruct a stateful SessionFlow from that metadata word — otherwise the
// #3067 frame-parser invariant is bypassed via the metadata path and the
// session table is polluted with a fake ICMP-control "flow". Reverting the
// gate (so the meta fallback is reached for these types) turns the None
// assertions RED.

/// Hostile pseudo-port the shim would stamp into `flow_src_port` from the
/// control bytes of a non-query ICMP packet.
const ICMP_HOSTILE_PORT: u16 = 0xBEEF;

#[test]
fn meta_fallback_icmpv4_error_control_installs_no_session() {
    // Dest-Unreachable (3), Redirect (5), Time-Exceeded (11),
    // Parameter-Problem (12). Frame is well-formed (the frame parser already
    // returns None for it), and metadata carries matching IPs plus the hostile
    // pseudo-port — exactly the #3290 attack shape.
    for icmp_type in [3u8, 5u8, 11u8, 12u8] {
        let frame = v4_frame(PROTO_ICMP, 28, &icmp_l4(icmp_type, ICMP_HOSTILE_PORT));
        let meta = UserspaceDpMeta {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            l3_offset: 14,
            l4_offset: V4_ICMP_L4 as u16,
            flow_src_port: ICMP_HOSTILE_PORT,
            flow_dst_port: 0,
            flow_src_addr: [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            flow_dst_addr: [192, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ..UserspaceDpMeta::default()
        };
        assert_eq!(
            parse_session_flow_from_bytes(&frame, meta),
            None,
            "ICMPv4 error/control type {icmp_type} must not install a metadata-keyed session"
        );
    }
}

#[test]
fn meta_fallback_icmpv6_error_control_nd_installs_no_session() {
    // Dest-Unreachable (1), Packet-Too-Big (2), Time-Exceeded (3),
    // Parameter-Problem (4), the MLD types (130 Query / 131 Report / 132 Done
    // / 143 MLDv2 Report), and the ND types (133..137 Router/Neighbor
    // Solicit/Advert + Redirect).
    for icmp_type in [
        1u8, 2u8, 3u8, 4u8, 130u8, 131u8, 132u8, 133u8, 134u8, 135u8, 136u8, 137u8, 143u8,
    ] {
        let frame = v6_frame(PROTO_ICMPV6, 8, &icmp_l4(icmp_type, ICMP_HOSTILE_PORT));
        let meta = UserspaceDpMeta {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_ICMPV6,
            l3_offset: 14,
            l4_offset: V6_ICMP_L4 as u16,
            flow_src_port: ICMP_HOSTILE_PORT,
            flow_dst_port: 0,
            flow_src_addr: [0x20; 16],
            flow_dst_addr: [0x30; 16],
            ..UserspaceDpMeta::default()
        };
        assert_eq!(
            parse_session_flow_from_bytes(&frame, meta),
            None,
            "ICMPv6 error/control/ND type {icmp_type} must not install a metadata-keyed session"
        );
    }
}

#[test]
fn meta_fallback_icmpv4_echo_still_keys_on_identifier() {
    // Identifier-bearing query types (Echo Request 8 / Reply 0) are
    // unaffected: the metadata identifier matches the frame-derived one, so a
    // stateful flow keyed on the identifier pseudo-port is still produced.
    for icmp_type in [8u8, 0u8] {
        let frame = v4_frame(PROTO_ICMP, 28, &icmp_l4(icmp_type, ICMP_IDENT));
        let meta = UserspaceDpMeta {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            l3_offset: 14,
            l4_offset: V4_ICMP_L4 as u16,
            flow_src_port: ICMP_IDENT,
            flow_dst_port: 0,
            flow_src_addr: [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            flow_dst_addr: [192, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ..UserspaceDpMeta::default()
        };
        let flow = parse_session_flow_from_bytes(&frame, meta)
            .expect("ICMPv4 echo query must still build an identifier-keyed flow");
        assert_eq!(flow.forward_key.src_port, ICMP_IDENT);
        assert_eq!(flow.forward_key.dst_port, 0);
    }
}

#[test]
fn meta_fallback_icmpv4_truncated_echo_installs_no_session() {
    // #3290 (frame-equivalence): an Echo (query) packet truncated between the
    // type byte and its 2-byte Identifier. `parse_flow_ports` returns None
    // here because the identifier END lies past the IP-declared datagram, so
    // the metadata gate must ALSO reject it — otherwise the shim's pseudo-port
    // (read from bytes outside the declared identifier) would still install a
    // metadata-keyed session. declared total_len = 24 -> declared end at frame
    // offset 38: the type byte (offset 34) is inside, the identifier
    // [38..40) is NOT. Checking only the type byte (the pre-fold behavior)
    // would wrongly admit the meta fallback -> RED on revert.
    let frame = v4_frame(PROTO_ICMP, 24, &icmp_l4(8, ICMP_IDENT));
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        l3_offset: 14,
        l4_offset: V4_ICMP_L4 as u16,
        flow_src_port: ICMP_HOSTILE_PORT,
        flow_dst_port: 0,
        flow_src_addr: [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [192, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ..UserspaceDpMeta::default()
    };
    assert_eq!(
        parse_session_flow_from_bytes(&frame, meta),
        None,
        "a query packet truncated before its identifier must not install a metadata-keyed session"
    );
}

// ---- #4555/#6923: the traversable-type predicate, bound to the walker ----

/// `ipv6_ext_header_is_traversable` must agree with what `walk_ipv6_ext_chain`
/// MEASURABLY does, for all 256 next-header values — not with a second copy of
/// the walker's match arms.
///
/// The probe is one minimal 8-byte header declaring TCP, laid out
/// `[TCP, 0, 0, 0, 0, 0, 0, 0]`. That form is the minimum of all three
/// traversable arms at once: GENERIC reads `HdrExtLen = 0` and advances
/// `(0 + 1) * 8`, AUTH reads `len = 0` and advances `(0 + 2) * 4`, Fragment
/// advances its fixed 8 — all three land on the TCP at offset 48. A value the
/// walker does NOT traverse resolves in place at 40 (terminal) or returns
/// `NoNextHeader` (59). So "landed at 48 carrying TCP" is a measurement of
/// traversal, and the predicate must reproduce it exactly.
///
/// This is what keeps the predicate honest when someone teaches the walker a new
/// extension-header type: adding an arm without adding the value here reds, and
/// so does the reverse. `tests_shim_ext_parity.rs` runs the same equivalence
/// against the SHIM's `eh_class`, so the three descriptions cannot drift apart.
#[test]
fn traversable_predicate_matches_walker_behaviour_over_all_256_values() {
    for proto in 0u8..=255 {
        let mut buf = vec![0u8; 40];
        buf[0] = 0x60;
        buf[4..6].copy_from_slice(&28u16.to_be_bytes());
        buf[6] = proto;
        buf.extend_from_slice(&[PROTO_TCP, 0, 0, 0, 0, 0, 0, 0]);
        buf.extend_from_slice(&[0u8; 20]);
        let walked_past = matches!(
            walk_ipv6_ext_chain(&buf, 0).outcome,
            ExtChainOutcome::L4(48, PROTO_TCP)
        );
        assert_eq!(
            ipv6_ext_header_is_traversable(proto),
            walked_past,
            "#6923: proto={proto}: ipv6_ext_header_is_traversable disagrees with what \
             walk_ipv6_ext_chain does with a one-header chain of that type (outcome {:?}). The \
             predicate is what stops an over-limit chain of this type from minting an installable \
             session key, so a walker arm it does not know about is a hole.",
            walk_ipv6_ext_chain(&buf, 0).outcome
        );
    }
    // Anti-vacuity: the sweep must actually observe both outcomes, and the
    // no-extension-header baseline must resolve at 40 so "landed at 48" is a
    // statement about traversal rather than about every chain.
    assert!(ipv6_ext_header_is_traversable(60));
    assert!(!ipv6_ext_header_is_traversable(PROTO_TCP));
    assert!(
        !ipv6_ext_header_is_traversable(59),
        "#6923: No-Next-Header is a terminal verdict on both sides, not a traversed header"
    );
    assert!(
        !ipv6_ext_header_is_traversable(50),
        "#6923: ESP is a resolved terminal — its payload is encrypted, so neither walker steps \
         past it and an ESP flow must keep its metadata tuple"
    );
}

/// #6837: `metadata_tuple_complete` is complete exactly for the protocols the
/// SHIM resolves an L4 identity for — and for no others.
///
/// The predicate's name asks "did the shim resolve an L4 identity?". Before
/// #6837 it answered "are both addresses set?", so every protocol the shim did
/// not parse arrived carrying the placeholder `0/0` its `parse_l4` catch-all
/// stamps and was declared complete anyway.
///
/// This is an ALLOWLIST sweep, deliberately. A denylist ("refuse GRE, ESP,
/// AH, OSPF") defaults every protocol number nobody thought about back to the
/// degenerate key, which is the defect itself wearing a longer match arm.
#[test]
fn metadata_tuple_complete_matches_the_shim_resolved_set_6837() {
    let src = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let judge = |protocol: u8, src_port: u16, dst_port: u16| {
        let flow = SessionFlow {
            src_ip: src,
            dst_ip: dst,
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol,
                src_ip: src,
                dst_ip: dst,
                src_port,
                dst_port,
                            discriminator: Default::default(),
                            routing_domain: 0,
            },
        };
        let meta = UserspaceDpMeta {
            addr_family: libc::AF_INET as u8,
            protocol,
            ..UserspaceDpMeta::default()
        };
        metadata_tuple_complete(meta, &flow)
    };

    let mut complete_portless = Vec::new();
    for proto in 0u8..=255 {
        // With a real port pair, only TCP/UDP/ICMP/ICMPv6 may be complete.
        assert_eq!(
            judge(proto, 1234, 5678),
            matches!(proto, PROTO_TCP | PROTO_UDP | PROTO_ICMP | PROTO_ICMPV6),
            "#6837: protocol {proto} — completeness must follow whether the SHIM resolves an L4 \
             identity, not whether the addresses happen to be set"
        );
        if judge(proto, 0, 0) {
            complete_portless.push(proto);
        }
    }

    // Portless: TCP/UDP need BOTH ports, so they drop out; ICMP stays, because
    // its pseudo-port is the IDENTIFIER and 0 is a legal identifier.
    assert_eq!(
        complete_portless,
        vec![PROTO_ICMP, PROTO_ICMPV6],
        "#6837: with 0/0 ports only ICMP/ICMPv6 may stay complete (identifier 0 is legal); \
         anything else here is a protocol getting a degenerate zero-port session key"
    );
}

/// #6837: the resolved set and the IPv6 traversable set must stay DISJOINT.
///
/// While they are, the `ipv6_ext_header_is_traversable` early return inside
/// `metadata_tuple_complete` is subsumed — every traversable value is portless,
/// so `_ => false` refuses it anyway, and deleting that branch reds nothing
/// (measured). It is kept as defence in depth for the day the sets overlap,
/// and this is the guard that makes that day visible instead of silent: adding
/// a traversable protocol to the resolved set lands here, where the reviewer
/// has to decide which rule wins, rather than in a branch nobody re-reads.
///
/// #6923's own protection does NOT depend on that branch. It lives in
/// `refused_protocol_set_equals_the_shim_traversable_set` and in
/// `server/helpers/session_sync.rs`; regressing the traversable set reds four
/// tests, none of which is this one.
#[test]
fn resolved_set_and_ipv6_traversable_set_are_disjoint_6837() {
    let src = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    for proto in 0u8..=255 {
        // Derived from the production predicate rather than a second copy of
        // the arm list — a duplicated allowlist could drift from the real one
        // and this guard would keep passing against its own stale copy.
        let flow = SessionFlow {
            src_ip: src,
            dst_ip: dst,
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: proto,
                src_ip: src,
                dst_ip: dst,
                src_port: 1234,
                dst_port: 5678,
                            discriminator: Default::default(),
                            routing_domain: 0,
            },
        };
        let meta = UserspaceDpMeta {
            addr_family: libc::AF_INET as u8,
            protocol: proto,
            ..UserspaceDpMeta::default()
        };
        let resolved = metadata_tuple_complete(meta, &flow);
        assert!(
            !(resolved && ipv6_ext_header_is_traversable(proto)),
            "#6837/#6923: protocol {proto} is in BOTH the shim-resolved set and the IPv6 \
             traversable set. Two rules now disagree about it on IPv6 — decide which wins \
             explicitly rather than letting branch order decide"
        );
    }
}

/// #6837 cross-boundary bind: the resolved set above is the shim's set.
///
/// `metadata_tuple_complete` cannot import `parse_l4` — it lives in the
/// `no_std` shim crate root, which cannot be `#[path]`-included the way
/// `ipv6_ext_walk.rs` is by `tests_shim_ext_parity`. So this reads the shim
/// source and pins the arms, with COMMENTS STRIPPED FIRST: this test's own
/// prose names the same `PROTO_*` identifiers, and an unstripped scan would be
/// satisfied by the documentation instead of by the code.
///
/// Teaching the shim to resolve a new protocol without widening
/// `metadata_tuple_complete` reds here — that identity would otherwise be
/// parsed and then discarded. The reverse reds too.
#[test]
fn shim_parse_l4_resolves_exactly_the_set_metadata_tuple_complete_accepts_6837() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../userspace-xdp/src/lib.rs");
    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let code_only: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    let start = code_only
        .find("fn parse_l4(")
        .expect("#6837: shim `parse_l4` not found — this bind has rotted, fix it, do not delete it");
    let body = &code_only[start..];
    let end = body
        .find("\n}")
        .expect("#6837: could not bound `parse_l4`'s body");
    let body = &body[..end];

    // Extract EVERY `PROTO_*` the body mentions, not just the four expected
    // ones. A membership check ("are TCP/UDP/ICMP/ICMPv6 present?") is
    // one-directional and cannot see a FIFTH arm — measured: adding
    // `PROTO_SCTP => ...` to the shim left such a check green, so the claim
    // above about teaching the shim a new protocol would have been false.
    let mut resolved: Vec<String> = Vec::new();
    let bytes = body.as_bytes();
    let mut i = 0usize;
    while let Some(hit) = body[i..].find("PROTO_") {
        let start = i + hit;
        let mut end = start + "PROTO_".len();
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        let name = body[start..end].to_string();
        if !resolved.contains(&name) {
            resolved.push(name);
        }
        i = end;
    }
    resolved.sort_unstable();
    assert_eq!(
        resolved,
        vec![
            "PROTO_ICMP".to_string(),
            "PROTO_ICMPV6".to_string(),
            "PROTO_TCP".to_string(),
            "PROTO_UDP".to_string(),
        ],
        "#6837: the shim's `parse_l4` must mention exactly the protocols \
         `metadata_tuple_complete` accepts. A protocol here that the predicate does not accept \
         has its identity parsed and then DISCARDED; one the predicate accepts but that is \
         missing here is a 0/0 placeholder being treated as resolved"
    );
    // #8274 RE-DECIDED, not relaxed. `parse_l4` grew a SIXTH tuple element — the
    // shim's WireGuard transport-data classification — so the pinned catch-all
    // literal changed shape and this assertion fired, exactly as its message
    // demands. The re-decision: the new element is orthogonal to
    // `metadata_tuple_complete`, which is about whether the 5-TUPLE identity was
    // resolved (ports and protocol) and says nothing about a payload byte. The
    // catch-all is still the 0/0 placeholder for every field the predicate reads;
    // it now also says `false` — "not a WireGuard transport-data record" — which
    // is correct for every non-UDP protocol that lands here. So the pin is
    // updated to the new shape rather than loosened to a prefix match: a prefix
    // match would stop seeing a future arm that made one of the 0s non-zero,
    // which is the thing this assertion is for.
    assert!(
        body.contains("_ => Some((l4_offset, 0, 0, 0, 0, false))"),
        "#6837: the shim's catch-all must still be the 0/0 PLACEHOLDER this predicate exists to \
         refuse. If it changed shape, `metadata_tuple_complete` needs re-deciding, not this \
         assertion relaxing"
    );
}

/// #6923's property, kept load-bearing after #6837 narrowed the predicate
/// around it.
///
/// The original form of this test paired "ext-header value is refused" against
/// "ESP's portless tuple stays complete", and said so: *"Refuses the ext-header
/// tuple alone is satisfied by a predicate that refuses every portless tuple,
/// **which would strand ESP, GRE and ICMPv6**; the ESP row is what excludes
/// that."*
///
/// #6837 is that predicate, and the rationale for excluding it was wrong.
/// "Strand" is a testable word and it was never measured: a flowless packet
/// still FORWARDS. Measured directly on this tree — a GRE transit descriptor
/// yields `tx=1` whether it is flow-backed or flowless; only the session count
/// changes (2 -> 0). See `portless_transit_is_flowless_and_still_forwards_6837`
/// in `tests_txn_flow_cache.rs`, which asserts both halves. What flowless
/// actually costs is stateful return admission, not reachability.
///
/// So the ESP row is gone and #6923's property needs a different anchor. The
/// one that survives is STRICTLY STRONGER than the row it replaces: a
/// traversable next-header value is refused on IPv6 **even when the tuple
/// carries real ports**, while TCP/UDP with those same ports are complete.
/// That distinguishes "refused because it is an unresolved chain" from
/// "refused because it is portless" — which is exactly the discrimination the
/// ESP row was there to provide, and it cannot be satisfied by #6837's rule.
#[test]
fn metadata_tuple_complete_refuses_unresolved_ipv6_ext_protocols_even_with_ports() {
    let src = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x11));
    let dst = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x22));
    let judge_ports = |family: u8, protocol: u8, src_port: u16, dst_port: u16| {
        let flow = SessionFlow {
            src_ip: src,
            dst_ip: dst,
            forward_key: SessionKey {
                addr_family: family,
                protocol,
                src_ip: src,
                dst_ip: dst,
                src_port,
                dst_port,
                            discriminator: Default::default(),
                            routing_domain: 0,
            },
        };
        let meta = UserspaceDpMeta {
            addr_family: family,
            protocol,
            ..UserspaceDpMeta::default()
        };
        metadata_tuple_complete(meta, &flow)
    };
    let judge = |family: u8, protocol: u8| judge_ports(family, protocol, 0, 0);
    let v6 = libc::AF_INET6 as u8;
    let v4 = libc::AF_INET as u8;

    // The ext-header numbers overlap nothing in the resolved set, so this
    // sweep would be vacuous if it only checked the portless case after #6837.
    // It checks the WITH-PORTS case, which #6837's rule cannot explain.
    let mut ext_rows = 0usize;
    for proto in 0u8..=255 {
        if ipv6_ext_header_is_traversable(proto) {
            ext_rows += 1;
            assert!(
                !judge(v6, proto),
                "#6923: IPv6 protocol {proto} is a next-header the walk traverses — the shim only \
                 emits it by EXHAUSTING its loop, so the tuple names where it gave up, not a \
                 resolved L4 flow"
            );
            // THE LOAD-BEARING ROW. Ports present, and still refused on IPv6.
            // #6837 refuses portless tuples; it has nothing to say about a
            // tuple carrying 1234/5678. Only the ext-header rule explains this,
            // so deleting `ipv6_ext_header_is_traversable` from
            // `metadata_tuple_complete` reds HERE and nowhere else.
            assert!(
                !judge_ports(v6, proto, 1234, 5678),
                "#6923: IPv6 protocol {proto} must stay refused even WITH ports — the refusal is \
                 about the unresolved chain, not about the tuple being portless"
            );
            // The same value on IPv4 has no extension-header meaning, so the
            // IPv6-only scoping of the ext-header rule is still observable
            // there: WITH ports it is judged by the #6837 rule alone.
            assert_eq!(
                judge_ports(v4, proto, 1234, 5678),
                matches!(proto, PROTO_TCP | PROTO_UDP),
                "#6923/#6837: IPv4 protocol {proto} carries no ext-header meaning, so it must be \
                 judged purely by whether the shim resolves an L4 identity for it"
            );
            continue;
        }
        if matches!(proto, PROTO_TCP | PROTO_UDP) {
            // Pre-#6923 rule, untouched: TCP/UDP need BOTH ports.
            assert!(!judge(v6, proto));
            assert!(judge_ports(v6, proto, 1234, 5678));
            continue;
        }
        if matches!(proto, PROTO_ICMP | PROTO_ICMPV6) {
            // #6837 keeps ICMP complete — the shim resolves a real identifier
            // for it, and 0 is a legal identifier.
            assert!(judge(v6, proto));
            continue;
        }
        // #6837: every other protocol is portless as far as the shim is
        // concerned, and its metadata tuple is a placeholder.
        assert!(
            !judge(v6, proto),
            "#6837: IPv6 protocol {proto} has no shim-resolved L4 identity, so its 0/0 tuple is a \
             placeholder and must not be declared complete"
        );
    }
    // Guard against the sweep silently covering nothing if the traversable set
    // is ever emptied — the assertions above would then all be skipped.
    assert_eq!(
        ext_rows, 10,
        "#6923: the traversable set changed size; this sweep is calibrated to it and would \
         otherwise pass vacuously"
    );
}

// ---- #7055: which l3_session_flow_from_meta None legs are REACHABLE ----
//
// The fragment-association HIT arm and the session-miss arm both wrap their
// entire per-packet enforcement block (interface input filter, PBR
// `then { routing-instance X; discard; }`) in
// `if let Some(l3_flow) = l3_ctx.as_ref()`. So every `None` is a packet
// forwarded with NO filter evaluation, and which `None`s are reachable decides
// whether that is a latent seam or a live fail-open.
//
// #7055 asserted `None` is "a test-fixture shape, not a production shape". These
// cells pin the measurement that says that is only half true: the addr_family
// leg is a fixture shape, the unspecified-source leg is not. Both the comment
// #7055 corrects and #7055's own correction reason from "the shim stamps the
// field" to "the value is usable", and that step does not hold.

// Counter deltas, read the way INTERFACE_SNAT_PAT_COLLISIONS' tests do: these
// are process-global and cumulative, so an absolute value would be order- and
// parallelism-dependent. `make test-rust` runs --test-threads=1, so a delta
// taken around a single call is exact.
fn l3_none_counts_7055() -> (u64, u64) {
    (
        L3_CTX_NONE_UNKNOWN_FAMILY.load(std::sync::atomic::Ordering::Relaxed),
        L3_CTX_NONE_UNSPECIFIED_ADDR.load(std::sync::atomic::Ordering::Relaxed),
    )
}

#[test]
fn l3_ctx_none_on_unknown_family_is_the_unreachable_leg_7055() {
    // The shim writes `addr_family: parsed.addr_family`, and `parsed` only ever
    // comes from parse_ipv4/parse_ipv6, which hard-code AF_INET/AF_INET6. A
    // packet whose parse fails never receives metadata at all. So this leg is a
    // FIXTURE shape: constructible here, not constructible by the shim.
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_UNIX as u8,
        flow_src_addr: [1u8; 16],
        flow_dst_addr: [2u8; 16],
        ..UserspaceDpMeta::default()
    };
    let (fam0, uns0) = l3_none_counts_7055();
    assert!(
        l3_session_flow_from_meta(meta).is_none(),
        "a non-v4/v6 addr_family must yield None"
    );
    let (fam1, uns1) = l3_none_counts_7055();
    assert_eq!(
        fam1 - fam0,
        1,
        "the UNKNOWN-FAMILY counter must advance for this leg"
    );
    assert_eq!(
        uns1 - uns0,
        0,
        "the UNSPECIFIED-ADDR counter must NOT advance for a family miss. The two \
         legs mean opposite things — unknown-family should be ZERO in production \
         and is a bug report, unspecified-addr is reachable traffic — so a \
         counter that cannot tell them apart tells a future reader nothing \
         actionable (#7055)"
    );
}

#[test]
fn l3_ctx_none_on_unspecified_source_is_the_reachable_leg_7055() {
    // THE CELL THAT MATTERS. A fully-parsed IPv4 packet whose header carries
    // 0.0.0.0 as the source: the shim stamps that faithfully, so this is a
    // PRODUCTION shape, not a fixture artefact. Nothing upstream rejects it —
    // routing keys on destination, `is_martian_dst` only sub-classifies an
    // already-decided NoRoute, and the addr_class source predicates gate
    // ICMP-error generation and neighbour learning rather than transit.
    let mut src_zero = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        ..UserspaceDpMeta::default()
    };
    src_zero.flow_src_addr[..4].copy_from_slice(&[0, 0, 0, 0]);
    src_zero.flow_dst_addr[..4].copy_from_slice(&[10, 0, 0, 1]);
    let (fam0, uns0) = l3_none_counts_7055();
    assert!(
        l3_session_flow_from_meta(src_zero).is_none(),
        "an unspecified IPv4 SOURCE with a valid destination must yield None — \
         this is the leg #7055 called a fixture shape and it is reachable: the \
         enforcement block is skipped for such a packet on both the hit and \
         miss arms"
    );
    let (fam1, uns1) = l3_none_counts_7055();
    assert_eq!(uns1 - uns0, 1, "the UNSPECIFIED-ADDR counter must advance");
    assert_eq!(
        fam1 - fam0,
        0,
        "the family counter must NOT advance — the family was valid AF_INET"
    );

    // Same for IPv6 (`::` source), the DAD shape.
    let mut v6_src_zero = UserspaceDpMeta {
        addr_family: libc::AF_INET6 as u8,
        ..UserspaceDpMeta::default()
    };
    v6_src_zero.flow_dst_addr = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];
    assert!(
        l3_session_flow_from_meta(v6_src_zero).is_none(),
        "an unspecified IPv6 source must yield None"
    );

    // POSITIVE CONTROL, on the same family and the same builder: a specified
    // source DOES yield Some. Without this the two assertions above would pass
    // on a function that returned None for everything, and the reachability
    // claim would be vacuous.
    let mut ok = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        ..UserspaceDpMeta::default()
    };
    ok.flow_src_addr[..4].copy_from_slice(&[192, 0, 2, 1]);
    ok.flow_dst_addr[..4].copy_from_slice(&[10, 0, 0, 1]);
    let (fam2, uns2) = l3_none_counts_7055();
    let flow = l3_session_flow_from_meta(ok)
        .expect("a fully specified v4 pair must yield Some — else these cells are vacuous");
    assert_eq!(flow.forward_key.src_port, 0, "flowless: no L4 ports (#3291)");
    let (fam3, uns3) = l3_none_counts_7055();
    assert_eq!(
        (fam3 - fam2, uns3 - uns2),
        (0, 0),
        "a SUCCESSFUL derivation must advance neither counter, or the counters \
         measure call volume rather than the skipped-enforcement events they \
         exist to report"
    );
}

// ---- #7890: the split — identity refuses, enforcement does not ----

/// The two questions, answered differently for the SAME packet.
///
/// This is the whole defect in one assertion: a header carrying `0.0.0.0` has no
/// usable session identity (a session keyed on it aliases every other
/// unspecified-source flow) but perfectly usable ADDRESSES. Six call sites read
/// the first refusal as "nothing to enforce" for the second question.
///
/// **This cell cannot be satisfied by "drop on `None`".** That repair leaves the
/// resolver refusing and changes the call sites to drop — so the enforcement
/// accessor would still return `None` here and this reds. The two repairs are
/// distinguishable at exactly this point, which is why the assertion is on the
/// returned addresses rather than on a packet's fate.
#[test]
fn an_unspecified_source_refuses_identity_but_yields_enforcement_addresses_7890() {
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    dst[..4].copy_from_slice(&[203, 0, 113, 9]); // valid destination
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        flow_src_addr: src,
        flow_dst_addr: dst,
        ..UserspaceDpMeta::default()
    };

    assert!(
        l3_session_flow_from_meta(meta).is_none(),
        "identity must still refuse — a session keyed on 0.0.0.0 aliases every \
         other unspecified-source flow, and #7890 does not change that"
    );

    let flow = l3_enforcement_flow_from_meta(meta)
        .expect("enforcement must get the addresses: a filter needs the packet's \
                 addresses, not a session, and 0.0.0.0 is a well-defined value \
                 to evaluate a `from`-clause against");
    assert_eq!(
        flow.src_ip,
        "0.0.0.0".parse::<std::net::IpAddr>().unwrap(),
        "the source must be carried through AS the header had it, not \
         substituted — the operator's term decides, not this resolver"
    );
    assert_eq!(
        flow.dst_ip,
        "203.0.113.9".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(flow.forward_key.src_port, 0, "flowless: no L4 ports");
    assert_eq!(flow.forward_key.dst_port, 0);

    // Anti-vacuity: the same source, unchanged, must be the reason. A valid
    // source yields a flow from BOTH, so the assertions above are about the
    // unspecified value and not about a resolver that always succeeds.
    src[..4].copy_from_slice(&[198, 51, 100, 7]);
    let ok = UserspaceDpMeta {
        flow_src_addr: src,
        ..meta
    };
    assert!(l3_session_flow_from_meta(ok).is_some());
    assert!(l3_enforcement_flow_from_meta(ok).is_some());
}

/// The witness still moves, and it now means "SEEN", not "refused".
///
/// Tests for the enforcement sites assert this counter advanced to prove the arm
/// was ENTERED before asserting what enforcement did — without it, a fixture
/// that misses a conjunct passes proving nothing, which is the failure the whole
/// #7890 enumeration existed to prevent.
#[test]
fn the_unspecified_witness_advances_on_the_enforcement_path_too_7890() {
    let mut dst = [0u8; 16];
    dst[..4].copy_from_slice(&[203, 0, 113, 9]);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        flow_src_addr: [0u8; 16],
        flow_dst_addr: dst,
        ..UserspaceDpMeta::default()
    };
    let (_, uns0) = l3_none_counts_7055();
    assert!(l3_enforcement_flow_from_meta(meta).is_some());
    let (_, uns1) = l3_none_counts_7055();
    assert_eq!(
        uns1 - uns0,
        1,
        "the witness must advance even though the lookup now SUCCEEDS — it \
         records that an unspecified address was seen here, which is what a \
         per-arm fixture asserts to prove it entered the arm"
    );
}

/// The unparseable-family leg still refuses on BOTH paths.
///
/// An unknown family has no addresses to enforce against, so unlike the
/// unspecified case there is nothing to hand a filter. Widening that too would
/// have been the over-correction.
#[test]
fn an_unparseable_family_still_refuses_on_the_enforcement_path_7890() {
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_UNIX as u8,
        flow_src_addr: [1u8; 16],
        flow_dst_addr: [2u8; 16],
        ..UserspaceDpMeta::default()
    };
    assert!(l3_session_flow_from_meta(meta).is_none());
    assert!(
        l3_enforcement_flow_from_meta(meta).is_none(),
        "an unparseable family has no addresses to evaluate a filter against; \
         #7890 widens the UNSPECIFIED leg only"
    );
}

// ---- #9894: the TCP/UDP metadata fast path must honor the IP-declared end ----
//
// The shim bounds its L4 read by the frame end INCLUDING slack (`parse_l4` in
// `userspace-xdp/src/lib.rs` reads against `data_end` and never consults IPv4
// `total_len`), so a short `total_len`/`payload_len` with trailing slack bytes
// arrives with a metadata tuple spelled from out-of-datagram bytes. The
// SessionFlow fast path (`parse_session_flow_from_bytes`) returned that tuple
// verbatim on `metadata_tuple_complete` — a predicate with NO length
// dimension — seeding sessions, NAT bindings, policy decisions and flow logs
// on a 5-tuple that never existed on the wire. The fix gates both
// metadata-return sites on `[l4, l4+4)` lying within `declared_l3_end`, the
// same #2361 bound `parse_flow_ports` already enforces.

/// Slack bytes spelling the probe tuple (1111, 443): 1111 = 0x0457,
/// 443 = 0x01BB.
const SLACK_PORTS_1111_443: [u8; 4] = [0x04, 0x57, 0x01, 0xBB];

#[test]
fn meta_fast_path_v4_slack_ports_outside_total_len_yield_no_flow_9894() {
    // total_len = 20 (IHL only): the 4 bytes at l3+20 are slack spelling
    // (1111, 443), exactly what the shim stamps into metadata. The declared-
    // end parse yields None, so the production path must too.
    let frame = v4_frame(PROTO_TCP, 20, &SLACK_PORTS_1111_443);
    // The bytes ARE present in the slice — proving a slice-only bound would
    // have returned them.
    assert_eq!(&frame[14 + 20..14 + 24], &SLACK_PORTS_1111_443);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        l4_offset: 14 + 20,
        flow_src_port: 1111,
        flow_dst_port: 443,
        flow_src_addr: [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [192, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ..UserspaceDpMeta::default()
    };
    assert_eq!(
        parse_session_flow_from_bytes(&frame, meta),
        None,
        "the (1111, 443) tuple lives in slack past total_len=20 — the fast path must not admit it"
    );
}

#[test]
fn meta_fast_path_v6_slack_ports_outside_payload_len_yield_no_flow_9894() {
    // IPv6 sibling: payload_len = 0, so the 4 bytes at l3+40 are slack.
    let frame = v6_frame(PROTO_UDP, 0, &SLACK_PORTS_1111_443);
    assert_eq!(&frame[14 + 40..14 + 44], &SLACK_PORTS_1111_443);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_UDP,
        l3_offset: 14,
        l4_offset: 14 + 40,
        flow_src_port: 1111,
        flow_dst_port: 443,
        flow_src_addr: [0x20; 16],
        flow_dst_addr: [0x30; 16],
        ..UserspaceDpMeta::default()
    };
    assert_eq!(
        parse_session_flow_from_bytes(&frame, meta),
        None,
        "the (1111, 443) tuple lives in slack past payload_len=0 — the fast path must not admit it"
    );
}

#[test]
fn meta_fast_path_v4_declared_ports_still_returned_9894() {
    // Anti-over-gate: total_len = 24 covers the 4 port bytes, so the same
    // complete-metadata shape still takes the fast path.
    let frame = v4_frame(PROTO_TCP, 24, &SLACK_PORTS_1111_443);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        l4_offset: 14 + 20,
        flow_src_port: 1111,
        flow_dst_port: 443,
        flow_src_addr: [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [192, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ..UserspaceDpMeta::default()
    };
    let flow = parse_session_flow_from_bytes(&frame, meta)
        .expect("in-declared ports must still resolve via the fast path");
    assert_eq!(flow.forward_key.src_port, 1111);
    assert_eq!(flow.forward_key.dst_port, 443);
}

// ---- #9894 review fold: helper truth-table, fast-vs-fallback, fall-through ----

#[test]
fn meta_l4_ports_gate_accepts_in_declared_rejects_slack_9894() {
    // Direct fault detection for the helper (SPARK-4): behavioral pins
    // alone cannot distinguish "gate correct" from "gate over/under-
    // rejects but a later arm masks it".
    let mk_meta = |family: u8, l4: u16| UserspaceDpMeta {
        addr_family: family,
        protocol: PROTO_TCP,
        l3_offset: 14,
        l4_offset: l4,
        ..UserspaceDpMeta::default()
    };
    // In-declared, exactly at the boundary (l4+4 == declared_end).
    let frame = v4_frame(PROTO_TCP, 24, &SLACK_PORTS_1111_443);
    assert!(meta_l4_ports_in_declared_end(
        &frame,
        mk_meta(libc::AF_INET as u8, 34)
    ));
    // Slack: total_len=20 ends at l4 itself.
    let frame = v4_frame(PROTO_TCP, 20, &SLACK_PORTS_1111_443);
    assert!(!meta_l4_ports_in_declared_end(
        &frame,
        mk_meta(libc::AF_INET as u8, 34)
    ));
    // Straddle: total_len=22 covers 2 of the 4 port bytes.
    let frame = v4_frame(PROTO_TCP, 22, &SLACK_PORTS_1111_443);
    assert!(!meta_l4_ports_in_declared_end(
        &frame,
        mk_meta(libc::AF_INET as u8, 34)
    ));
    // IPv6 pair: payload_len=4 covers the ports, 0 does not.
    let frame = v6_frame(PROTO_TCP, 4, &SLACK_PORTS_1111_443);
    assert!(meta_l4_ports_in_declared_end(
        &frame,
        mk_meta(libc::AF_INET6 as u8, 54)
    ));
    let frame = v6_frame(PROTO_TCP, 0, &SLACK_PORTS_1111_443);
    assert!(!meta_l4_ports_in_declared_end(
        &frame,
        mk_meta(libc::AF_INET6 as u8, 54)
    ));
}

#[test]
fn meta_l4_ports_gate_fails_closed_on_malformed_9894() {
    let frame = v4_frame(PROTO_TCP, 24, &SLACK_PORTS_1111_443);
    // Unknown family: no declared end derivable.
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_UNIX as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        l4_offset: 34,
        ..UserspaceDpMeta::default()
    };
    assert!(!meta_l4_ports_in_declared_end(&frame, meta));
    // Truncated L3 header (slice shorter than l3+20).
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        l4_offset: 34,
        ..UserspaceDpMeta::default()
    };
    assert!(!meta_l4_ports_in_declared_end(&frame[..20], meta));
    // l4_offset past the frame entirely.
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        l4_offset: 100,
        ..UserspaceDpMeta::default()
    };
    assert!(!meta_l4_ports_in_declared_end(&frame, meta));
}

#[test]
fn meta_fast_path_returns_stamped_tuple_not_frame_ports_9894() {
    // SPARK-5: the control cell below cannot distinguish fast-return from
    // frame fallback (both yield the same ports). Here the frame carries
    // real in-declared ports (0xAAAA, 0xBBBB) while metadata stamps a
    // DIFFERENT complete tuple (1111, 443), also in-declared. The fast path
    // trusts bounded meta, so the STAMPED tuple wins — proving the return
    // came from the fast path. Doubles as a TCP over-reject pin: a gate
    // that wrongly fails falls through to the frame and returns 0xAAAA.
    let frame = v4_frame(PROTO_TCP, 24, &[0xAA, 0xAA, 0xBB, 0xBB]);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        l4_offset: 14 + 20,
        flow_src_port: 1111,
        flow_dst_port: 443,
        flow_src_addr: [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [192, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ..UserspaceDpMeta::default()
    };
    let flow = parse_session_flow_from_bytes(&frame, meta)
        .expect("in-declared stamped tuple must resolve via the fast path");
    assert_eq!(
        (flow.forward_key.src_port, flow.forward_key.dst_port),
        (1111, 443),
        "the STAMPED tuple wins on the fast path, not the frame ports"
    );
}

#[test]
fn meta_fast_path_gate_failure_falls_through_to_frame_9894() {
    // SPARK-5: a complete meta tuple (nonzero ports, set addrs) with a BOGUS
    // l4_offset past the declared end fails the fast-path gate — yet the
    // frame itself is well-formed with real ports (0xCAFE, 0xF00D) at the
    // frame-derived L4. The failure must fall through to the authoritative
    // frame parse, not to None, so legitimate traffic on weird meta
    // survives. (Pre-#9894 the fast path returned the stamped tuple here.)
    let frame = v4_frame(PROTO_TCP, 24, &[0xCA, 0xFE, 0xF0, 0x0D]);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        l4_offset: 100,
        flow_src_port: 1111,
        flow_dst_port: 443,
        flow_src_addr: [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [192, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ..UserspaceDpMeta::default()
    };
    let flow = parse_session_flow_from_bytes(&frame, meta)
        .expect("gate failure must fall through to the frame parse, not None");
    assert_eq!(
        (flow.forward_key.src_port, flow.forward_key.dst_port),
        (0xCAFE, 0xF00D),
        "fall-through yields the authoritative frame ports"
    );
}

#[test]
fn term_extra_builder_leaves_ports_unknown_to_flowless_sites_9894() {
    // GPT-2 contract: the cold builder ALWAYS leaves `ports_unknown` false,
    // even for L4-absent shapes. The builder never sees the flow, so it
    // cannot know whether the evaluated ports are real — deriving the bit
    // here over-gates session-miss/flow-cache flows evaluated against an
    // unreadable frame (a DMA-mutated slice must not veto the cached tuple)
    // and under-gates L3 contexts evaluated against present-but-unevaluated
    // L4 bytes. The flowless input-filter/PBR sites set the bit themselves,
    // where the evaluated (synthetic) tuple is known. Reverting to a derived
    // bit reds here AND on the TX forward-request cells (flow + empty frame).
    let mk_meta = |protocol: u8| UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol,
        l3_offset: 14,
        l4_offset: 34,
        ..UserspaceDpMeta::default()
    };
    // Slack TCP: L4 absent from the declared datagram, bit still false.
    let frame = v4_frame(PROTO_TCP, 20, &SLACK_PORTS_1111_443);
    let extra = term_match_extra_from_frame(&frame, mk_meta(PROTO_TCP));
    assert!(!extra.ports_unknown);
    assert!(!extra.l4_present);
    // Truncated slice: L3 itself unreadable, bit still false.
    let extra = term_match_extra_from_frame(&frame[..10], mk_meta(PROTO_TCP));
    assert!(!extra.ports_unknown);
    // Well-formed control: unchanged.
    let frame = v4_frame(PROTO_TCP, 24, &[0xAB, 0xCD, 0x12, 0x34]);
    let extra = term_match_extra_from_frame(&frame, mk_meta(PROTO_TCP));
    assert!(!extra.ports_unknown);
}

/// Tag an untagged frame with 802.1Q (VID 10), moving L3 from 14 to 18.
fn tag_vlan_9900(frame: &[u8]) -> Vec<u8> {
    let mut tagged = frame.to_vec();
    tagged.splice(12..12, [0x81, 0x00, 0x00, 0x0a]);
    tagged
}

/// #9900 F-095 control: correct stamps resolve to themselves, tagged and
/// untagged, v4 and v6. The normal path is byte-identical before and after.
#[test]
fn nibble_checked_l3_trusts_correct_stamp_9900() {
    let v4 = v4_frame(PROTO_TCP, 40, &[0u8; 20]);
    let v6 = v6_frame(PROTO_TCP, 20, &[0u8; 20]);
    let v4_tagged = tag_vlan_9900(&v4);
    let inet = libc::AF_INET as u8;
    let inet6 = libc::AF_INET6 as u8;
    assert_eq!(nibble_checked_l3(&v4, 14, inet), Some(14));
    assert_eq!(nibble_checked_l3(&v4_tagged, 18, inet), Some(18));
    assert_eq!(nibble_checked_l3(&v6, 14, inet6), Some(14));
    // A non-14/18 stamp was never trusted and still derives from the wire.
    assert_eq!(nibble_checked_l3(&v4, 20, inet), Some(14));
    assert_eq!(nibble_checked_l3(&v4_tagged, 20, inet), Some(18));
}

/// #9900 F-095 repro: a wrong-but-plausible stamp falls back to the wire
/// parse instead of shifting every L3 read. Pre-fix the `14 | 18` arm
/// trusted the stamp, so each of these resolved to the STAMPED value.
#[test]
fn nibble_checked_l3_falls_back_on_wrong_stamp_9900() {
    let v4 = v4_frame(PROTO_TCP, 40, &[0u8; 20]);
    let v6 = v6_frame(PROTO_TCP, 20, &[0u8; 20]);
    let v4_tagged = tag_vlan_9900(&v4);
    let inet = libc::AF_INET as u8;
    let inet6 = libc::AF_INET6 as u8;
    // Untagged frame stamped 18: byte 18 is IP-ID high (nibble 0), not v4.
    assert_eq!(nibble_checked_l3(&v4, 18, inet), Some(14));
    // Tagged frame stamped 14: byte 14 is the tag TCI (0x00), not v4.
    assert_eq!(nibble_checked_l3(&v4_tagged, 14, inet), Some(18));
    // Family-swapped stamp: v4 bytes under a v6 family claim.
    assert_eq!(nibble_checked_l3(&v4, 18, inet6), Some(14));
    // v6 frame stamped 18: byte 18 is payload-len high (0x00), not v6.
    assert_eq!(nibble_checked_l3(&v6, 18, inet6), Some(14));
}

/// #9900 F-095: an unknown family cannot verify the stamp, so the offset is
/// derived from the wire. Same values as the old blind trust on well-formed
/// frames, but through the derive arm rather than the stamp arm.
#[test]
fn nibble_checked_l3_derives_on_unknown_family_9900() {
    let v4 = v4_frame(PROTO_TCP, 40, &[0u8; 20]);
    let v4_tagged = tag_vlan_9900(&v4);
    let unix = libc::AF_UNIX as u8;
    assert_eq!(nibble_checked_l3(&v4, 14, unix), Some(14));
    assert_eq!(nibble_checked_l3(&v4_tagged, 18, unix), Some(18));
    // ...and a wrong stamp under an unknown family still derives, not trusts.
    assert_eq!(nibble_checked_l3(&v4, 18, unix), Some(14));
}

/// #9900 F-095: nothing resolvable anywhere fails closed. A truncated frame
/// has no byte at the stamp AND no parseable ethertype.
#[test]
fn nibble_checked_l3_fails_closed_on_double_garbage_9900() {
    let inet = libc::AF_INET as u8;
    assert_eq!(nibble_checked_l3(&[0u8; 10], 14, inet), None);
    assert_eq!(nibble_checked_l3(&[0u8; 10], 18, inet), None);
    assert_eq!(nibble_checked_l3(&[], 14, inet), None);
}
