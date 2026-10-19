//! #15787: inner non-first fragments through tunnel decapsulation.
//!
//! `parse_inner_protocol_and_offsets` (GRE/WireGuard decap) and
//! `packet_rel_l4_offset_and_protocol` (the shared L3-relative walker,
//! also feeding the IPsec-inner descriptor path) must apply the XDP
//! shim's `PROTO_FRAGMENT_NO_L4` (255) substitution:
//!
//! * inner IPv6 non-first fragments are admitted as fragment-no-L4
//!   (255, payload offset = first byte past the Fragment header)
//!   instead of being dropped 100% (`None`);
//! * inner IPv4 non-first fragment payloads are not parsed as L4
//!   headers (previously the IPv4 Protocol byte was trusted and the
//!   payload bytes at the post-IP offset were read as a TCP/UDP
//!   header — ports/checksum/flags fabricated from payload).
//!
//! Reverting either substitution turns the matching test RED.

#![allow(unused_imports)]

use super::super::gre::parse_inner_protocol_and_offsets;
use super::*;
use crate::session::SHIM_PROTO_FRAGMENT_NO_L4;

/// IPv4 inner packet: 20-byte header + `payload`. `frag_off` is the raw
/// frag_off field (bytes 6..8: flags + 13-bit offset).
fn inner_v4(protocol: u8, frag_off: u16, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[6..8].copy_from_slice(&frag_off.to_be_bytes());
    p[8] = 64;
    p[9] = protocol;
    p[12..16].copy_from_slice(&[10, 0, 0, 1]);
    p[16..20].copy_from_slice(&[10, 0, 0, 2]);
    p[20..].copy_from_slice(payload);
    p
}

/// IPv6 inner packet: 40-byte base header (Next Header = Fragment 44)
/// + one 8-byte Fragment header + `payload`.
fn inner_v6_frag(frag_next: u8, frag_off_word: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p[6] = 44;
    p[7] = 64;
    p[8..24].copy_from_slice(&[0x20; 16]);
    p[24..40].copy_from_slice(&[0x30; 16]);
    let mut frag = [0u8; 8];
    frag[0] = frag_next;
    frag[2..4].copy_from_slice(&frag_off_word.to_be_bytes());
    frag[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    p.extend_from_slice(&frag);
    p.extend_from_slice(payload);
    p
}

#[test]
fn inner_v4_nonfirst_fragment_is_no_l4_not_parsed_as_tcp_15787() {
    // Payload crafted to look like a TCP header: ports 12345/443 and a
    // data-offset nibble of 5 (20-byte header). Pre-fix this returned
    // (6, 20, 40) — the payload read as a TCP header.
    let mut payload = vec![0u8; 20];
    payload[0..2].copy_from_slice(&12345u16.to_be_bytes());
    payload[2..4].copy_from_slice(&443u16.to_be_bytes());
    payload[12] = 0x50;
    let pkt = inner_v4(PROTO_TCP, 185, &payload);
    assert_eq!(
        parse_inner_protocol_and_offsets(&pkt, libc::AF_INET as u8),
        Some((SHIM_PROTO_FRAGMENT_NO_L4, 20, 20)),
        "#15787: IPv4 non-first fragment must be fragment-no-L4, not TCP"
    );
    // Same via the shared packet-relative walker.
    assert_eq!(
        packet_rel_l4_offset_and_protocol(&pkt, libc::AF_INET as u8),
        Some((20, SHIM_PROTO_FRAGMENT_NO_L4)),
        "#15787: shared walker must substitute the no-L4 sentinel for IPv4 non-first fragments"
    );
    assert_eq!(
        packet_rel_l4_offset(&pkt, libc::AF_INET as u8),
        None,
        "#15787: no L4 offset may be surrendered for an IPv4 non-first fragment"
    );
}

#[test]
fn inner_v4_nonfirst_fragment_is_no_l4_not_parsed_as_udp_15787() {
    let mut payload = vec![0u8; 8];
    payload[0..2].copy_from_slice(&53u16.to_be_bytes());
    payload[2..4].copy_from_slice(&5353u16.to_be_bytes());
    let pkt = inner_v4(PROTO_UDP, 1, &payload);
    assert_eq!(
        parse_inner_protocol_and_offsets(&pkt, libc::AF_INET as u8),
        Some((SHIM_PROTO_FRAGMENT_NO_L4, 20, 20)),
        "#15787: IPv4 non-first UDP fragment payload must not be parsed as UDP"
    );
}

#[test]
fn inner_v4_first_and_unfragmented_still_parse_l4_15787() {
    // Unfragmented TCP still resolves its real header.
    let mut payload = vec![0u8; 20];
    payload[12] = 0x50;
    let pkt = inner_v4(PROTO_TCP, 0, &payload);
    assert_eq!(
        parse_inner_protocol_and_offsets(&pkt, libc::AF_INET as u8),
        Some((PROTO_TCP, 20, 40))
    );
    // First fragment (MF=1, offset 0) carries the real L4 header.
    let pkt = inner_v4(PROTO_TCP, 0x2000, &payload);
    assert_eq!(
        parse_inner_protocol_and_offsets(&pkt, libc::AF_INET as u8),
        Some((PROTO_TCP, 20, 40)),
        "#15787: first fragment must keep its real L4 parse"
    );
    assert_eq!(
        packet_rel_l4_offset_and_protocol(&pkt, libc::AF_INET as u8),
        Some((20, PROTO_TCP))
    );
}

#[test]
fn inner_v6_nonfirst_fragment_admitted_as_no_l4_15787() {
    // Fragment header: Next Header = TCP, offset 185 (word 0x05c8),
    // M=0. Payload mimics a TCP header — must not be read as one.
    // Pre-fix both entry points returned None (100% drop in decap).
    let mut payload = vec![0u8; 20];
    payload[0..2].copy_from_slice(&12345u16.to_be_bytes());
    payload[12] = 0x50;
    let pkt = inner_v6_frag(PROTO_TCP, 0x05c8, &payload);
    assert_eq!(
        parse_inner_protocol_and_offsets(&pkt, libc::AF_INET6 as u8),
        Some((SHIM_PROTO_FRAGMENT_NO_L4, 48, 48)),
        "#15787: IPv6 non-first fragment must be admitted as fragment-no-L4"
    );
    assert_eq!(
        packet_rel_l4_offset_and_protocol(&pkt, libc::AF_INET6 as u8),
        Some((48, SHIM_PROTO_FRAGMENT_NO_L4)),
        "#15787: shared walker must substitute the no-L4 sentinel for IPv6 non-first fragments"
    );
    assert_eq!(
        packet_rel_l4_offset(&pkt, libc::AF_INET6 as u8),
        None,
        "#15787: no L4 offset may be surrendered for an IPv6 non-first fragment"
    );
}

#[test]
fn inner_v6_first_fragment_still_resolves_l4_15787() {
    // First fragment (offset 0, M=1) → TCP header follows the Fragment
    // header and must resolve normally.
    let mut payload = vec![0u8; 20];
    payload[12] = 0x50;
    let pkt = inner_v6_frag(PROTO_TCP, 0x0001, &payload);
    assert_eq!(
        parse_inner_protocol_and_offsets(&pkt, libc::AF_INET6 as u8),
        Some((PROTO_TCP, 48, 68)),
        "#15787: IPv6 first fragment must keep its real L4 parse"
    );
    assert_eq!(
        packet_rel_l4_offset_and_protocol(&pkt, libc::AF_INET6 as u8),
        Some((48, PROTO_TCP))
    );
}
