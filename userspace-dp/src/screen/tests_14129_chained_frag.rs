// #14129: chained IPv6 Fragment headers must not overwrite the screen's
// fragment fields. [real-first][ATOMIC] used to report non-fragment
// (trailing ATOMIC overwrote the real first header), suppressing
// syn-frag / icmp-fragment. Production screen verdicts are asserted
// end-to-end (extract -> ScreenState::check_packet), with the plain
// single-header control for each case.

use super::*;
use std::net::{IpAddr, Ipv6Addr};

const L3: usize = 14;
const SRC6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const DST6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

const WORD_ATOMIC: u16 = 0x0000;
const WORD_FIRST: u16 = 0x0001;

fn default_profile() -> ScreenProfile {
    ScreenProfile {
        syn_frag: true,
        icmp_fragment: true,
        ..Default::default()
    }
}

fn make_state(zone: &str, profile: ScreenProfile) -> ScreenState {
    let mut state = ScreenState::new();
    let mut profiles = FxHashMap::default();
    profiles.insert(zone.to_string(), profile);
    state.update_profiles(profiles);
    state
}

/// Build an Ethernet/IPv6 frame: base -> Frag(word1) -> Frag(word2)? -> L4.
/// `terminal` is the upper-layer protocol (6 TCP, 58 ICMPv6).
fn chained_frame(frag_words: &[u16], terminal: u8, l4: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x60;
    pkt[6] = if frag_words.is_empty() { terminal } else { 44 };
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&SRC6);
    pkt[24..40].copy_from_slice(&DST6);
    let mut ext = Vec::new();
    for (i, word) in frag_words.iter().enumerate() {
        ext.push(if i + 1 < frag_words.len() {
            44
        } else {
            terminal
        });
        ext.push(0);
        ext.extend_from_slice(&word.to_be_bytes());
        ext.extend_from_slice(&0x0102_0304u32.to_be_bytes());
    }
    ext.extend_from_slice(l4);
    pkt[4..6].copy_from_slice(&(ext.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&ext);
    let mut frame = vec![0u8; 12];
    frame.extend_from_slice(&[0x86, 0xDD]);
    frame.extend_from_slice(&pkt);
    frame
}

fn tcp_syn() -> [u8; 20] {
    let mut t = [0u8; 20];
    t[0..2].copy_from_slice(&12345u16.to_be_bytes());
    t[2..4].copy_from_slice(&80u16.to_be_bytes());
    t[12] = 0x50;
    t[13] = 0x02; // SYN
    t
}

fn icmpv6_echo() -> [u8; 8] {
    [128, 0, 0, 0, 0, 1, 0, 0]
}

fn extract(frame: &[u8], protocol: u8, tcp_flags: u8) -> ScreenPacketInfo {
    extract_screen_info(
        frame,
        libc::AF_INET6 as u8,
        protocol,
        tcp_flags,
        frame.len() as u16,
        IpAddr::V6(Ipv6Addr::from(SRC6)),
        IpAddr::V6(Ipv6Addr::from(DST6)),
        12345,
        80,
        L3,
    )
    .expect("#14129: extractor must parse the chained-fragment frame")
}

#[test]
fn chained_real_first_then_atomic_syn_frag_drops_14129() {
    // Control: plain first fragment + SYN drops.
    let control = chained_frame(&[WORD_FIRST], PROTO_TCP, &tcp_syn());
    let info = extract(&control, PROTO_TCP, 0x02);
    assert!(info.is_fragment && info.is_first_fragment);
    let mut state = make_state("trust", default_profile());
    assert_eq!(
        state.check_packet("trust", &info, 1),
        ScreenVerdict::Drop("syn-frag"),
        "#14129 control: plain first fragment SYN must drop"
    );

    // Defect shape: real first fragment, trailing ATOMIC, terminal SYN.
    // First-fragment data must be 8-byte aligned (RFC 8200): two headers
    // (16) + TCP (20) = 36 is not a multiple of 8 for a non-last fragment;
    // pad TCP tail to 24 bytes total L4 region? Keep 20-byte TCP and add
    // 4 trailing bytes so fragment data (16+20+4=40 from first header's
    // payload perspective) — alignment is a sender property; the screen
    // does not validate it, but keep the fixture realistic.
    let chained = chained_frame(&[WORD_FIRST, WORD_ATOMIC], PROTO_TCP, &tcp_syn());
    let info = extract(&chained, PROTO_TCP, 0x02);
    assert!(
        info.is_fragment && info.is_first_fragment,
        "#14129: trailing ATOMIC must not clear the real first fragment, got is_fragment={} is_first={} ip_frag_off={:#x}",
        info.is_fragment,
        info.is_first_fragment,
        info.ip_frag_off
    );
    assert_eq!(info.ip_frag_off, WORD_FIRST);
    let mut state = make_state("trust", default_profile());
    assert_eq!(
        state.check_packet("trust", &info, 1),
        ScreenVerdict::Drop("syn-frag"),
        "#14129: chained [real-first][ATOMIC] SYN must drop like the control"
    );
}

#[test]
fn chained_real_first_then_atomic_icmp_fragment_drops_14129() {
    let control = chained_frame(&[WORD_FIRST], PROTO_ICMPV6, &icmpv6_echo());
    let info = extract(&control, PROTO_ICMPV6, 0);
    assert!(info.is_fragment && info.is_first_fragment);
    let mut state = make_state("trust", default_profile());
    assert_eq!(
        state.check_packet("trust", &info, 1),
        ScreenVerdict::Drop("icmp-fragment"),
        "#14129 control: plain first fragment ICMPv6 must drop"
    );

    let chained = chained_frame(&[WORD_FIRST, WORD_ATOMIC], PROTO_ICMPV6, &icmpv6_echo());
    let info = extract(&chained, PROTO_ICMPV6, 0);
    assert!(
        info.is_fragment,
        "#14129: trailing ATOMIC must not clear icmp fragment status"
    );
    let mut state = make_state("trust", default_profile());
    assert_eq!(
        state.check_packet("trust", &info, 1),
        ScreenVerdict::Drop("icmp-fragment"),
        "#14129: chained [real-first][ATOMIC] ICMPv6 must drop like the control"
    );
}

#[test]
fn chained_atomic_only_stays_nonfragment_14129() {
    // Guard against overcorrection: pure ATOMIC chain is not a fragment.
    let frame = chained_frame(&[WORD_ATOMIC], PROTO_TCP, &tcp_syn());
    let info = extract(&frame, PROTO_TCP, 0x02);
    assert!(!info.is_fragment && !info.is_first_fragment);
    let mut state = make_state("trust", default_profile());
    assert_eq!(state.check_packet("trust", &info, 1), ScreenVerdict::Pass);
}
