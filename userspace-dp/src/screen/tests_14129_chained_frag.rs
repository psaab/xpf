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

// ===== #14325: duplicated non-ATOMIC Fragment headers are malformed =====
//
// The #14129 downgrade (a later non-zero offset only cleared
// is_first_fragment) left is_first_fragment == false while ip_frag_off
// still reported the FIRST header's offset 0. check_tcp_flag_screens
// skips on !is_first_fragment; check_ping_of_death / check_teardrop
// require (ip_frag_off & 0xFFF8) > 0 / an oversize computation keyed on
// that offset -- so [Frag#1(off=0,M=1), Frag#2(offset=65528,M=1)] with
// 4 payload bytes evaded BOTH families. The extractor now rejects the
// duplicated non-ATOMIC header as MultipleIpv6FragmentHeaders
// (screen_reason "ip-malformed"), the fail-closed verdict every
// extract_screen_info caller already applies to parse errors. These
// cells assert the extractor verdict itself -- through
// ScreenState::check_packet the malformed verdict never materialises
// (no ScreenPacketInfo exists), so the honest observable is the Err
// plus its screen_reason; the screens' role is pinned by asserting
// that the pre-fix parsed fields (reconstructed by hand) would have
// passed BOTH sizing screens, i.e. that without the rejection the
// packet really did slip through.

const WORD_NONFIRST_MAX: u16 = 0xFFF9; // offset 8191 units = 65528 bytes, M=1

fn sizing_profile() -> ScreenProfile {
    ScreenProfile {
        ping_death: true,
        teardrop: true,
        ..Default::default()
    }
}

fn extract_err(frame: &[u8], protocol: u8, tcp_flags: u8) -> ScreenParseError {
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
    .expect_err("#14325: duplicated non-ATOMIC Fragment header must fail closed")
}

#[test]
fn chained_first_then_max_nonfirst_14325_wording() {
    // The issue's decisive shape, asserted at the level that decides it:
    // Frag#1(offset=0, M=1) -> Frag#2(offset=65528, M=1) with 4 bytes of
    // payload behind Frag#2. Pre-fix this parsed to
    // is_fragment=true, is_first_fragment=false, ip_frag_off=WORD_FIRST
    // (offset bits 0): check_tcp_flag_screens skipped on
    // !is_first_fragment, and neither sizing screen could fire
    // (ping-of-death: 0 + frag_data <= 65535; teardrop: offset 0 is not
    // a non-first fragment). Post-fix the extractor rejects it.
    let chained = chained_frame(&[WORD_FIRST, WORD_NONFIRST_MAX], PROTO_TCP, &[0u8; 4]);
    // Control first: the REAL non-first header alone (same offset/M,
    // 4-byte data) IS parsed and drops as teardrop (non-last, < 8).
    let control = chained_frame(&[WORD_NONFIRST_MAX], PROTO_TCP, &[0u8; 4]);
    let control_info = extract(&control, PROTO_TCP, 0x02);
    assert!(
        control_info.is_fragment && !control_info.is_first_fragment,
        "#14325 control: single max-offset fragment must parse as non-first"
    );
    assert_eq!(control_info.ip_frag_off, WORD_NONFIRST_MAX);
    let mut state = make_state("trust", sizing_profile());
    assert_eq!(
        state.check_packet("trust", &control_info, 1),
        ScreenVerdict::Drop("teardrop"),
        "#14325 control: single Frag(offset=65528,M=1, 4 bytes) must drop as teardrop"
    );
    // The second header alone at a SMALL offset with a big tail drops as
    // ping-of-death, pinning that both sizing screens engage on the
    // non-first fields Frag#2 carries (they are not teardrop-only):
    // offset 0xFFF8-byte-offset is already covered by the chained shape;
    // here offset 65528 with 60 data bytes overshoots the ceiling.
    let pod_control = chained_frame(&[WORD_NONFIRST_MAX], PROTO_TCP, &[0u8; 60]);
    let pod_info = extract(&pod_control, PROTO_TCP, 0x02);
    let mut state = make_state("trust", sizing_profile());
    assert_eq!(
        state.check_packet("trust", &pod_info, 1),
        ScreenVerdict::Drop("ping-of-death"),
        "#14325 control: single Frag(offset=65528, 60 bytes) must drop as ping-of-death"
    );
    // Defect shape: rejected at extract time, fail-closed.
    let err = extract_err(&chained, PROTO_TCP, 0x02);
    assert_eq!(err, ScreenParseError::MultipleIpv6FragmentHeaders);
    assert_eq!(err.screen_reason(), "ip-malformed");
    // Pin WHY the rejection is load-bearing: reconstruct the exact
    // ScreenPacketInfo the pre-fix extractor produced for this shape
    // (governing fields from Frag#1, is_first_fragment downgraded by
    // Frag#2) and confirm BOTH sizing screens pass it. If a future
    // change re-admits the parsed shape, this proves it would slip
    // through -- the malformed verdict is the only thing dropping it.
    let mut pre_fix_shape = control_info.clone();
    pre_fix_shape.ip_frag_off = WORD_FIRST;
    pre_fix_shape.is_first_fragment = false;
    pre_fix_shape.frag_data_off = 8;
    assert_eq!(
        stateless::check_ping_of_death(&sizing_profile(), &pre_fix_shape),
        None,
        "#14325: pre-fix fields (offset 0) cannot trigger ping-of-death"
    );
    assert_eq!(
        stateless::check_teardrop(&sizing_profile(), &pre_fix_shape),
        None,
        "#14325: pre-fix fields (offset 0) cannot trigger teardrop"
    );
}

#[test]
fn chained_duplicate_first_rejected_14325() {
    // [first][first]: the second sighting has offset 0, so the old
    // downgrade branch (keyed on non-zero offset) never even fired --
    // and the packet parsed as a clean first fragment. RFC 8200 allows
    // one Fragment header; a duplicated first fragment is as
    // nonconformant as [first][non-first] and is rejected identically.
    let chained = chained_frame(&[WORD_FIRST, WORD_FIRST], PROTO_TCP, &tcp_syn());
    let err = extract_err(&chained, PROTO_TCP, 0x02);
    assert_eq!(err, ScreenParseError::MultipleIpv6FragmentHeaders);
    assert_eq!(err.screen_reason(), "ip-malformed");
}

#[test]
fn chained_second_header_matrix_rejected_14325() {
    // Reachable duplicated-non-ATOMIC orderings reject: the gate is the
    // second non-ATOMIC sighting, not Frag#2's particular offset/M.
    // `[non-first][non-first]` is deliberately NOT here: the walk breaks
    // at the FIRST non-first header (its payload is never parsed as
    // extension headers, #3120/#14116), so a later "header" in that
    // payload is never sighted -- the packet is a plain non-first
    // fragment and its sizing screens decide normally.
    for (label, words) in [
        ("[first][non-first]", [WORD_FIRST, WORD_NONFIRST_MAX]),
        ("[first][first]", [WORD_FIRST, WORD_FIRST]),
    ] {
        let chained = chained_frame(&words, PROTO_TCP, &[0u8; 4]);
        let err = extract_err(&chained, PROTO_TCP, 0x02);
        assert_eq!(
            err,
            ScreenParseError::MultipleIpv6FragmentHeaders,
            "#14325: {label} must fail closed"
        );
        assert_eq!(err.screen_reason(), "ip-malformed", "#14325: {label}");
    }
}

#[test]
fn chained_atomic_then_nonfirst_still_decides_14325() {
    // [ATOMIC][real-non-first] is NOT a duplicated-non-ATOMIC chain: the
    // ATOMIC header is ignored entirely, so the real header is the first
    // (governing) sighting and the packet parses as a non-first fragment
    // whose sizing screens decide normally. Guards the #14325 gate
    // against rejecting every repeated-header chain -- only the second
    // non-ATOMIC sighting fails closed. Offset 65528 + 4 bytes, M=1:
    // teardrop (non-last, < 8) wins precedence over ping-of-death
    // (65528 + (payload - 16) stays under the ceiling).
    let chained = chained_frame(&[WORD_ATOMIC, WORD_NONFIRST_MAX], PROTO_TCP, &[0u8; 4]);
    let info = extract(&chained, PROTO_TCP, 0x02);
    assert!(
        info.is_fragment && !info.is_first_fragment,
        "#14325: [ATOMIC][real-non-first] must parse as the real non-first fragment"
    );
    assert_eq!(info.ip_frag_off, WORD_NONFIRST_MAX);
    assert_eq!(info.frag_data_off, 16);
    let mut state = make_state("trust", sizing_profile());
    assert_eq!(
        state.check_packet("trust", &info, 1),
        ScreenVerdict::Drop("teardrop"),
        "#14325: [ATOMIC][real-non-first] sizing screens must still decide the packet"
    );
}
