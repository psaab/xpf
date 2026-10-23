//! #16007: tiny first fragment flags-UNKNOWN regressions.
//!
//! An 8-byte first fragment (the minimum legal payload=multiple-of-8
//! shape) declares L4 < 14 bytes, so the TCP flags byte at L4+13 is
//! outside the DECLARED datagram. Before the fix the shim and the
//! worker both stamped flags=0 as if proven: `syn-frag` could not
//! fire, `no-flag` false-fired on the flow path, and session admission
//! read the zero as a proven non-SYN (admitted under no-syn-check and
//! on LocalDelivery). The extractor now fails closed with
//! `TinyFirstFragmentFlagsUnknown` -> "syn-frag", and hand-built
//! `tcp_flags_unknown` packets drop the same way.

use super::extract::extract_screen_info;
use super::packet::ScreenParseError;
use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const L3: usize = 14;
const SRC4: [u8; 4] = [192, 0, 2, 10];
const DST4: [u8; 4] = [198, 51, 100, 20];
const SRC6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const DST6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

fn make_state() -> ScreenState {
    let mut state = ScreenState::new();
    let mut profile = ScreenProfile::default();
    profile.syn_frag = true;
    profile.no_flag = true;
    profile.syn_fin = true;
    profile.fin_no_ack = true;
    let mut map = FxHashMap::default();
    map.insert("trust".to_string(), profile);
    state.update_profiles(map);
    state
}

/// IPv4 first fragment (MF=1, offset=0) whose declared total length
/// covers only `l4_bytes` of TCP. Ports are present, flags byte at
/// +13 may or may not be inside the declared datagram. Capture pads
/// the frame to a full TCP-looking tail so a capture-bound (vs
/// declared-bound) implementation would read a SYN from slack.
fn v4_tiny_first_fragment(l4_declared: usize) -> Vec<u8> {
    let mut frame = vec![0u8; L3];
    frame[12] = 0x08;
    frame[13] = 0x00;
    let total_len = (20 + l4_declared) as u16;
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&total_len.to_be_bytes());
    ip[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    ip[6..8].copy_from_slice(&0x2000u16.to_be_bytes()); // MF, offset 0
    ip[8] = 64;
    ip[9] = PROTO_TCP;
    ip[12..16].copy_from_slice(&SRC4);
    ip[16..20].copy_from_slice(&DST4);
    frame.extend_from_slice(&ip);
    // Captured TCP: ports + SYN at +13 hiding in Ethernet slack past
    // the declared end when l4_declared < 14.
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x02; // SYN in capture slack
    frame.extend_from_slice(&tcp);
    frame
}

fn v6_tiny_first_fragment(l4_declared: usize) -> Vec<u8> {
    let mut frame = vec![0u8; L3];
    frame[12] = 0x86;
    frame[13] = 0xdd;
    let payload_len = (8 + l4_declared) as u16;
    let mut ip = vec![0u8; 40];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
    ip[6] = 44; // Fragment
    ip[7] = 64;
    ip[8..24].copy_from_slice(&SRC6);
    ip[24..40].copy_from_slice(&DST6);
    frame.extend_from_slice(&ip);
    let mut frag = [0u8; 8];
    frag[0] = PROTO_TCP;
    frag[2..4].copy_from_slice(&0x0001u16.to_be_bytes()); // offset 0, M=1
    frag[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
    frame.extend_from_slice(&frag);
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x02;
    frame.extend_from_slice(&tcp);
    frame
}

fn extract_v4(frame: &[u8]) -> Result<ScreenPacketInfo, ScreenParseError> {
    extract_screen_info(
        frame,
        libc::AF_INET as u8,
        PROTO_TCP,
        0,
        frame.len() as u16,
        IpAddr::V4(Ipv4Addr::from(SRC4)),
        IpAddr::V4(Ipv4Addr::from(DST4)),
        12345,
        443,
        L3,
    )
}
fn extract_v6(frame: &[u8]) -> Result<ScreenPacketInfo, ScreenParseError> {
    extract_screen_info(
        frame,
        libc::AF_INET6 as u8,
        PROTO_TCP,
        0,
        frame.len() as u16,
        IpAddr::V6(Ipv6Addr::from(SRC6)),
        IpAddr::V6(Ipv6Addr::from(DST6)),
        12345,
        443,
        L3,
    )
}

#[test]
fn tiny_first_fragment_v4_8byte_declared_fails_closed_syn_frag_16007() {
    let frame = v4_tiny_first_fragment(8);
    let err = extract_v4(&frame).expect_err("8B first fragment must fail closed");
    assert_eq!(err, ScreenParseError::TinyFirstFragmentFlagsUnknown);
    assert_eq!(err.screen_reason(), "syn-frag");
}

#[test]
fn tiny_first_fragment_v6_8byte_declared_fails_closed_syn_frag_16007() {
    let frame = v6_tiny_first_fragment(8);
    let err = extract_v6(&frame).expect_err("v6 8B first fragment must fail closed");
    assert_eq!(err, ScreenParseError::TinyFirstFragmentFlagsUnknown);
    assert_eq!(err.screen_reason(), "syn-frag");
}

#[test]
fn first_fragment_with_flags_in_declared_end_still_screens_16007() {
    // Control: declared L4 = 20 covers flags byte; extractor must parse
    // and the profile must judge the real SYN (not fail closed).
    let frame = v4_tiny_first_fragment(20);
    let info = extract_v4(&frame).expect("full first fragment parses");
    assert!(info.is_first_fragment);
    // Caller passes meta flags 0 here; the extractor's own TCP read is
    // seq/mss only, so verdict uses the supplied flags. With SYN
    // supplied (as the shim would stamp when flags ARE declared):
    let frame2 = v4_tiny_first_fragment(20);
    let info2 = extract_screen_info(
        &frame2,
        libc::AF_INET as u8,
        PROTO_TCP,
        0x02,
        frame2.len() as u16,
        IpAddr::V4(Ipv4Addr::from(SRC4)),
        IpAddr::V4(Ipv4Addr::from(DST4)),
        12345,
        443,
        L3,
    )
    .expect("parses");
    let mut state = make_state();
    assert_eq!(
        state.check_packet("trust", &info2, 1),
        ScreenVerdict::Drop("syn-frag")
    );
    let _ = info;
}

#[test]
fn hand_built_unknown_flags_first_fragment_drops_syn_frag_not_no_flag_16007() {
    // Defense-in-depth: even if a ScreenPacketInfo with unknown flags
    // reaches check_packet, it drops as syn-frag (never Pass, never
    // the false tcp-no-flag on tf==0).
    let mut state = make_state();
    let mut pkt = ScreenPacketInfo {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        tcp_flags_unknown: true,
        src_ip: IpAddr::V4(Ipv4Addr::from(SRC4)),
        dst_ip: IpAddr::V4(Ipv4Addr::from(DST4)),
        src_port: 12345,
        dst_port: 443,
        tcp_seq: 0,
        tcp_ack: 0,
        tcp_mss: 0,
        pkt_len: 48,
        is_fragment: true,
        is_first_fragment: true,
        ip_ihl: 5,
        ip_frag_off: 0x2000,
        ip_total_len: 28,
        ip_payload_len: 0,
        frag_data_off: 0,
        saw_ipv4_source_route: false,
        saw_ipv6_routing_header: false,
    };
    assert_eq!(
        state.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("syn-frag")
    );
    // Known-flags control: same shape with proven flags=0 is no-flag.
    pkt.tcp_flags_unknown = false;
    let mut state2 = make_state();
    assert_eq!(
        state2.check_packet("trust", &pkt, 1),
        ScreenVerdict::Drop("tcp-no-flag")
    );
}
