// #6435: preservation pins for the unified IPv6 extension-header walk
// (`walk_ipv6_ext_chain`) and the wrappers that fold its verdict.
//
// The pre-#6435 code hand-mirrored the walk six times in `inspect.rs`
// (plus the NAT64 and embedded-ICMP copies); the edges below are the
// places where those copies SUBTLY differed in shape while agreeing in
// verdict, so they are the places a careless unification would change
// behavior. Each test names the pre-#6435 arm it pins. These tests FAIL
// on a unification that (a) stops recording the first Fragment sighting,
// (b) starts rejecting a declared-but-truncated Fragment header in
// `ipv6_is_any_fragment`, (c) judges a double-Fragment chain by the
// second header, or (d) folds `Truncated`/`NoNextHeader` to anything
// other than the pre-#6435 fail-closed value.
//
// Sibling `#[path]` test module loaded from afxdp/frame/mod.rs, next to
// tests_fragment_term_extra.rs (which pins the TermMatchExtra fail-closed
// gates this refactor must not perturb).
#![allow(unused_imports)]

use super::super::test_fixtures::*;
use super::*;
use super::tests_support::*;

/// One 8-byte generic length-prefixed extension header (DestOpts shape):
/// byte 0 = next header, byte 1 = 0 (HdrExtLen → 8 bytes total).
fn ext8(next: u8) -> [u8; 8] {
    let mut h = [0u8; 8];
    h[0] = next;
    h
}

/// One 8-byte Fragment header: byte 0 = next header, bytes 2-3 = the
/// frag_off word (offset[15:3] | res[2:1] | M[0]), bytes 4-7 = ident.
fn frag8(next: u8, frag_off: u16) -> [u8; 8] {
    let mut h = [0u8; 8];
    h[0] = next;
    h[2..4].copy_from_slice(&frag_off.to_be_bytes());
    h[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    h
}

/// L3-relative IPv6 packet: 40-byte base header + `body` (ext chain + L4).
fn v6_pkt(base_next: u8, body: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&(body.len() as u16).to_be_bytes());
    p[6] = base_next;
    p[7] = 64;
    p[8..24].copy_from_slice(&[0x20; 16]);
    p[24..40].copy_from_slice(&[0x30; 16]);
    p.extend_from_slice(body);
    p
}

/// Full Ethernet frame wrapping the packet (IPv6 ethertype) for the
/// frame-relative wrappers (`ipv6_ext_chain_over_limit`, the
/// TermMatchExtra builder).
fn frame_of(pkt: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 12];
    f.extend_from_slice(&[0x86, 0xDD]);
    f.extend_from_slice(pkt);
    f
}

#[test]
fn ext_walk_core_verdict_truth_table() {
    // Plain TCP (no extension headers): the first iteration hits the
    // terminal arm — the hot no-ext path.
    let pkt = v6_pkt(PROTO_TCP, &[0u8; 20]);
    let w = walk_ipv6_ext_chain(&pkt, 0);
    assert_eq!(w.outcome, ExtChainOutcome::L4(40, PROTO_TCP));
    assert_eq!(w.fragment, None);

    // No-Next-Header (59): its own verdict, NOT an L4 and NOT over-limit.
    let pkt = v6_pkt(59, &[]);
    let w = walk_ipv6_ext_chain(&pkt, 0);
    assert_eq!(w.outcome, ExtChainOutcome::NoNextHeader);
    assert_eq!(w.fragment, None);

    // Base header shorter than 40 bytes: Truncated.
    assert_eq!(
        walk_ipv6_ext_chain(&pkt[..20], 0).outcome,
        ExtChainOutcome::Truncated
    );

    // ESP (50) is deliberately NOT walked: it falls to the terminal arm,
    // yielding an L4 verdict AT the ESP header (the payload is encrypted
    // and the inner next-header unreadable — stopping there is correct).
    let pkt = v6_pkt(50, &[0u8; 8]);
    assert_eq!(
        walk_ipv6_ext_chain(&pkt, 0).outcome,
        ExtChainOutcome::L4(40, 50)
    );

    // AH (51): the RFC 4302 `(len + 2) * 4` advance (byte 1 = 1 → 12).
    let mut ah = [0u8; 12];
    ah[0] = PROTO_TCP;
    ah[1] = 1;
    let mut body = ah.to_vec();
    body.extend_from_slice(&[0u8; 20]);
    let pkt = v6_pkt(51, &body);
    assert_eq!(
        walk_ipv6_ext_chain(&pkt, 0).outcome,
        ExtChainOutcome::L4(52, PROTO_TCP)
    );

    // Exactly MAX_IPV6_EXT_HEADERS extension headers: the loop exhausts
    // the bound still on an ext header → OverLimit (#2292/#4743).
    let mut body = Vec::new();
    for _ in 0..MAX_IPV6_EXT_HEADERS {
        body.extend_from_slice(&ext8(60));
    }
    let pkt = v6_pkt(60, &body);
    assert_eq!(
        walk_ipv6_ext_chain(&pkt, 0).outcome,
        ExtChainOutcome::OverLimit
    );

    // MAX_IPV6_EXT_HEADERS - 1 extension headers: resolves (the 8th loop
    // iteration consumes the terminal).
    let mut body = Vec::new();
    for i in 0..MAX_IPV6_EXT_HEADERS - 1 {
        let next = if i + 1 == MAX_IPV6_EXT_HEADERS - 1 {
            PROTO_TCP
        } else {
            60
        };
        body.extend_from_slice(&ext8(next));
    }
    body.extend_from_slice(&[0u8; 20]);
    let pkt = v6_pkt(60, &body);
    assert_eq!(
        walk_ipv6_ext_chain(&pkt, 0).outcome,
        ExtChainOutcome::L4(40 + 8 * (MAX_IPV6_EXT_HEADERS - 1), PROTO_TCP)
    );
}

#[test]
fn ext_walk_declared_but_truncated_fragment_preserves_predicate_verdicts() {
    // HOP → FRAG, but only 4 of the 8 Fragment-header bytes are present.
    let mut body = ext8(44).to_vec();
    body.extend_from_slice(&[PROTO_TCP, 0, 0, 0]); // partial Fragment header
    let pkt = v6_pkt(0, &body);

    // Pins the pre-#6435 `ipv6_is_any_fragment` arm `44 => return true`:
    // the DECLARED Fragment header matches even though its bytes are
    // truncated (that predicate never read the header bytes).
    assert!(ipv6_is_any_fragment(&pkt));
    // Pins the pre-#6435 `ipv6_is_non_first_fragment` else-return: the
    // offset bits are unreadable, so the predicate fails closed (false).
    assert!(!ipv6_is_non_first_fragment(&pkt));
    // The L4 resolvers' pre-#6435 `packet.get(offset..offset + 8)?` arm:
    // fail closed (None), never surrender the partial header as L4.
    assert_eq!(packet_rel_l4_offset(&pkt, libc::AF_INET6 as u8), None);
    assert_eq!(
        packet_rel_l4_offset_and_protocol(&pkt, libc::AF_INET6 as u8),
        None
    );
    assert_eq!(frame_l4_offset(&frame_of(&pkt), libc::AF_INET6 as u8), None);
    // #4743: truncation is NOT over-limit — the chain stays flowless.
    assert!(!ipv6_ext_chain_over_limit(
        &frame_of(&pkt),
        libc::AF_INET6 as u8
    ));
}

#[test]
fn ext_walk_first_fragment_then_ext_still_resolves_l4() {
    // FRAG(offset 0, MF=1 — a FIRST fragment) → DEST → TCP: the real L4
    // header follows the trailing chain (RFC 8200 permits ext headers
    // after the Fragment header; the screen path's #3120 walk agrees).
    let mut body = frag8(60, 0x0001).to_vec();
    body.extend_from_slice(&ext8(PROTO_TCP));
    body.extend_from_slice(&[0u8; 20]);
    let pkt = v6_pkt(44, &body);

    assert_eq!(packet_rel_l4_offset(&pkt, libc::AF_INET6 as u8), Some(56));
    assert_eq!(
        packet_rel_l4_offset_and_protocol(&pkt, libc::AF_INET6 as u8),
        Some((56, PROTO_TCP))
    );
    assert_eq!(
        frame_l4_offset(&frame_of(&pkt), libc::AF_INET6 as u8),
        Some(14 + 56)
    );
    assert!(ipv6_is_any_fragment(&pkt));
    assert!(!ipv6_is_non_first_fragment(&pkt));
    assert!(!ipv6_ext_chain_over_limit(
        &frame_of(&pkt),
        libc::AF_INET6 as u8
    ));
}

#[test]
fn ext_walk_double_fragment_chain_judges_by_first_sighting() {
    // Hostile double-Fragment chain. The pre-#6435 fragment predicates
    // STOPPED at the first Fragment header; the unified walk records only
    // the FIRST sighting, so the verdicts must match that stop.
    let mut body = frag8(44, 0x0000).to_vec(); // first: atomic (offset 0)
    body.extend_from_slice(&frag8(PROTO_TCP, 0x0008)); // second: non-first bits
    body.extend_from_slice(&[0u8; 20]);
    let pkt = v6_pkt(44, &body);
    assert!(ipv6_is_any_fragment(&pkt));
    assert!(
        !ipv6_is_non_first_fragment(&pkt),
        "first sighting is atomic (offset 0) — the second header's bits must not flip the verdict"
    );

    let mut body = frag8(44, 0x0008).to_vec(); // first: non-first bits
    body.extend_from_slice(&frag8(PROTO_TCP, 0x0000)); // second: atomic
    body.extend_from_slice(&[0u8; 20]);
    let pkt = v6_pkt(44, &body);
    assert!(
        ipv6_is_non_first_fragment(&pkt),
        "first sighting is non-first — the second (atomic) header must not clear the verdict"
    );

    // The L4 resolvers walked past BOTH Fragment headers before #6435
    // (their 44 arm advanced unconditionally) — same verdict today.
    assert_eq!(
        packet_rel_l4_offset_and_protocol(&pkt, libc::AF_INET6 as u8),
        Some((56, PROTO_TCP))
    );
}

#[test]
fn ext_walk_over_limit_records_fragment_and_fails_l4_closed() {
    // FRAG(non-first bits) + MAX_IPV6_EXT_HEADERS DestOpts headers: the
    // walk exhausts the bound still on an ext header (OverLimit), but the
    // recorded first-Fragment sighting must survive — the pre-#6435
    // predicates returned from the Fragment arm without ever reaching the
    // bound.
    let mut body = frag8(60, 0x0008).to_vec();
    for _ in 0..MAX_IPV6_EXT_HEADERS {
        body.extend_from_slice(&ext8(60));
    }
    body.extend_from_slice(&[0u8; 8]);
    let pkt = v6_pkt(44, &body);

    assert!(ipv6_ext_chain_over_limit(
        &frame_of(&pkt),
        libc::AF_INET6 as u8
    ));
    assert_eq!(packet_rel_l4_offset(&pkt, libc::AF_INET6 as u8), None);
    assert_eq!(
        packet_rel_l4_offset_and_protocol(&pkt, libc::AF_INET6 as u8),
        None
    );
    assert_eq!(frame_l4_offset(&frame_of(&pkt), libc::AF_INET6 as u8), None);
    assert!(ipv6_is_any_fragment(&pkt));
    assert!(ipv6_is_non_first_fragment(&pkt));
}

#[test]
fn ext_walk_no_next_header_is_not_over_limit() {
    // No-Next-Header (59): a valid terminal. Every wrapper's pre-#6435
    // arm agreed — L4 resolvers `59 => return None`, the over-limit gate
    // fell to `_ => return false`, the fragment predicates returned false.
    let pkt = v6_pkt(59, &[]);
    assert_eq!(packet_rel_l4_offset(&pkt, libc::AF_INET6 as u8), None);
    assert_eq!(
        packet_rel_l4_offset_and_protocol(&pkt, libc::AF_INET6 as u8),
        None
    );
    assert!(!ipv6_ext_chain_over_limit(
        &frame_of(&pkt),
        libc::AF_INET6 as u8
    ));
    assert!(!ipv6_is_any_fragment(&pkt));
    assert!(!ipv6_is_non_first_fragment(&pkt));
}

#[test]
fn term_match_extra_meta_flavors_produce_identical_extra() {
    // #6435: the retired `term_match_extra_from_frame_fwd` twin and the
    // input-filter builder were byte-identical by convention (a "MUST stay
    // identical" comment on a fail-closed security gate). The unified
    // builder must now yield the identical TermMatchExtra for BOTH
    // metadata flavors by construction — differential pin over a
    // first-fragment TCP frame with attacker-controlled Ethernet slack
    // past the IP-declared datagram (#5150/#5568 territory).
    let mut body = frag8(PROTO_TCP, 0x0001).to_vec(); // first fragment (MF=1)
    let mut tcp = [0u8; 20];
    tcp[13] = 0x12; // SYN+ACK
    body.extend_from_slice(&tcp);
    let pkt = v6_pkt(44, &body);
    let mut frame = frame_of(&pkt);
    frame.extend_from_slice(&FLEX_SLACK_MARKER);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 14 + 48, // past base header + Fragment header
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        tcp_flags: 0x12,
        ..UserspaceDpMeta::default()
    };

    let a = term_match_extra_from_frame(&frame, meta);
    let b = term_match_extra_from_frame(&frame, ForwardPacketMeta::from(meta));
    assert_eq!(a.tcp_flags, b.tcp_flags);
    assert_eq!(a.is_fragment, b.is_fragment);
    assert_eq!(a.icmp_type, b.icmp_type);
    assert_eq!(a.icmp_code, b.icmp_code);
    assert_eq!(a.l4_present, b.l4_present);
    assert_eq!(a.flex_l3, b.flex_l3);
    assert_eq!(a.flex_l4, b.flex_l4);

    // And the fail-closed gates themselves still hold on the unified
    // builder: the shim-stamped flags survive (declared datagram reaches
    // the flags byte), the fragment bit reads the declared chain, and the
    // flex slices stop at the IP-declared end (slack excluded).
    assert!(a.is_fragment);
    assert!(a.l4_present);
    assert_eq!(a.tcp_flags, 0x12);
    assert!(!a.flex_l3.expect("l3 slice").ends_with(&FLEX_SLACK_MARKER));
    assert!(!a.flex_l4.expect("l4 slice").ends_with(&FLEX_SLACK_MARKER));
}

#[test]
fn ext_walk_truncated_eighth_header_is_over_limit_10665() {
    // #10665: 7 complete extension headers + an 8th header whose bytes
    // overrun the frame. The chain is over-limit — resolving it would need
    // a 9th iteration even with the bytes present — so OverLimit takes
    // precedence over Truncated and the #4743 drop gate fires.

    // Short-read shape: the packet ends one byte into the 8th header.
    let mut body = Vec::new();
    for _ in 0..7 {
        body.extend_from_slice(&ext8(60));
    }
    body.push(60); // 8th header: next byte present, length byte missing
    let pkt = v6_pkt(60, &body);
    assert_eq!(
        walk_ipv6_ext_chain(&pkt, 0).outcome,
        ExtChainOutcome::OverLimit
    );
    assert!(ipv6_ext_chain_over_limit(
        &frame_of(&pkt),
        libc::AF_INET6 as u8
    ));
    assert_eq!(packet_rel_l4_offset(&pkt, libc::AF_INET6 as u8), None);
    assert_eq!(
        packet_rel_l4_offset_and_protocol(&pkt, libc::AF_INET6 as u8),
        None
    );

    // Declared-length-overrun shape: the 8th header's HdrExtLen runs past
    // the packet.
    let mut body = Vec::new();
    for _ in 0..7 {
        body.extend_from_slice(&ext8(60));
    }
    body.extend_from_slice(&[PROTO_TCP, 5]); // declares (5+1)*8 = 48 bytes
    let pkt = v6_pkt(60, &body);
    assert_eq!(
        walk_ipv6_ext_chain(&pkt, 0).outcome,
        ExtChainOutcome::OverLimit
    );
    assert!(ipv6_ext_chain_over_limit(
        &frame_of(&pkt),
        libc::AF_INET6 as u8
    ));

    // Fragment shape: the 8th header declares Fragment but truncates it.
    // The declaration is still recorded (pre-#6435 `ipv6_is_any_fragment`
    // semantics) while the verdict is OverLimit.
    let mut body = Vec::new();
    for _ in 0..6 {
        body.extend_from_slice(&ext8(60));
    }
    body.extend_from_slice(&ext8(44));
    body.extend_from_slice(&[PROTO_TCP, 0, 0, 0]); // partial Fragment header
    let pkt = v6_pkt(60, &body);
    let w = walk_ipv6_ext_chain(&pkt, 0);
    assert_eq!(w.outcome, ExtChainOutcome::OverLimit);
    assert_eq!(w.fragment.map(|f| f.bytes), Some(None));
    assert!(ipv6_is_any_fragment(&pkt));
    assert!(!ipv6_is_non_first_fragment(&pkt));
    assert!(ipv6_ext_chain_over_limit(
        &frame_of(&pkt),
        libc::AF_INET6 as u8
    ));

    // AH shape: the 8th header is an AH whose length byte is missing.
    let mut body = Vec::new();
    for _ in 0..6 {
        body.extend_from_slice(&ext8(60));
    }
    body.extend_from_slice(&ext8(51));
    body.push(PROTO_TCP);
    let pkt = v6_pkt(60, &body);
    assert_eq!(
        walk_ipv6_ext_chain(&pkt, 0).outcome,
        ExtChainOutcome::OverLimit
    );
    assert!(ipv6_ext_chain_over_limit(
        &frame_of(&pkt),
        libc::AF_INET6 as u8
    ));
}

#[test]
fn ext_walk_truncation_before_eighth_header_stays_truncated_10665() {
    // #10665 negative control: truncation BEFORE the 8th header is still
    // Truncated, not OverLimit — the precedence only engages at the bound.
    // 6 complete headers + a 7th truncated to one byte.
    let mut body = Vec::new();
    for _ in 0..6 {
        body.extend_from_slice(&ext8(60));
    }
    body.push(60);
    let pkt = v6_pkt(60, &body);
    assert_eq!(
        walk_ipv6_ext_chain(&pkt, 0).outcome,
        ExtChainOutcome::Truncated
    );
    assert!(!ipv6_ext_chain_over_limit(
        &frame_of(&pkt),
        libc::AF_INET6 as u8
    ));
}

#[test]
fn ext_walk_eight_complete_headers_fire_the_drop_gate_10665() {
    // #10665 control: 8 COMPLETE headers were already OverLimit (truth
    // table above); pin that the #4743 gate fires for them too, so the
    // truncated-8th case above is held to the same bar.
    let mut body = Vec::new();
    for _ in 0..MAX_IPV6_EXT_HEADERS {
        body.extend_from_slice(&ext8(60));
    }
    let pkt = v6_pkt(60, &body);
    assert_eq!(
        walk_ipv6_ext_chain(&pkt, 0).outcome,
        ExtChainOutcome::OverLimit
    );
    assert!(ipv6_ext_chain_over_limit(
        &frame_of(&pkt),
        libc::AF_INET6 as u8
    ));
}
