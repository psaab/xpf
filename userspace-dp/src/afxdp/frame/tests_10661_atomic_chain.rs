// #10661: an ATOMIC Fragment header followed by a REAL non-first Fragment
// header must classify the SAME across the overlap tracker, the forwarding
// predicates, the XDP shim, and the screens.
//
// The three consumers re-derived fragment status three ways: the tracker
// (`overlap_parse`) and the forwarding predicates
// (`ipv6_is_non_first_fragment` et al.) judged the FIRST sighted Fragment
// header, the shim (`walk_ipv6_ext_headers`) judged ANY sighting, and the
// screens (`extract_screen_info`) OVERWROTE per sighting. On an
// `[ATOMIC][real-non-first]` chain the tracker said `NonFragment` while the
// shim and screens said non-first — so no overlap range was ever recorded
// and the overlapping tail forwarded where the plain (single-header)
// control drops.
//
// Canonical rule (pinned here): a chain containing ANY non-ATOMIC Fragment
// header is a fragment; the tracker keys its range off the FIRST non-ATOMIC
// header (matching the plain control's ranges byte-for-byte), and L4
// presence is refused when ANY sighting carries a non-zero offset (the
// shim's long-standing verdict). ATOMIC-alone and double-ATOMIC chains stay
// `NonFragment` everywhere.
//
// Two orderings are EXPLICITLY reconciled rather than unified (see the
// residual cells): `[real-first][ATOMIC]`, where the screens' overwrite
// reports non-fragment while the tracker still tracks (both safe: the
// terminal L4 bytes are genuinely present), and
// `[real-first][real-non-first]`, where the tracker records the first-real
// (wider, conservative) range while every L4 gate agrees non-first.
#![allow(unused_imports)]

use super::*;
use std::net::{IpAddr, Ipv6Addr};

use crate::fragment_overlap::{
    FRAG_OVERLAP_DROPPED, OverlapParse, OverlapTracker, overlap_parse,
};
use crate::screen::{ScreenPacketInfo, ScreenParseError, extract_screen_info};

#[path = "../../../../userspace-xdp/src/ipv6_ext_walk.rs"]
mod shim_walk;

/// The shim's real walk, executed on a host buffer exactly as `parse_ipv6`
/// drives it (same shape as `tests_shim_ext_parity::raw_shim_walk`).
fn raw_shim_walk(buf: &[u8], l3: usize) -> Option<shim_walk::ExtWalk> {
    if buf.len() < l3 + 40 {
        return None;
    }
    let data = buf.as_ptr() as usize;
    let data_end = data + buf.len();
    shim_walk::walk_ipv6_ext_headers(data, data_end, l3 as u16, buf[l3 + 6], (l3 + 40) as u16)
}

const WORD_ATOMIC: u16 = 0x0000; // offset 0, M = 0
const WORD_FIRST: u16 = 0x0001; // offset 0, M = 1
const WORD_NONFIRST_O8: u16 = 0x0008; // offset 1 unit (8 bytes), M = 0
const IDENT_ATOMIC: u32 = 0xAAAA_0001;
const IDENT_REAL: u32 = 0x0102_0304;
const SRC6: [u8; 16] = [
    0x20, 1, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];
const DST6: [u8; 16] = [
    0x20, 1, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
];

/// L3-relative v6 packet whose extension chain is exactly the given
/// Fragment headers — each `(frag_off word, ident)` chained
/// `44 -> ... -> 44 -> TCP` — plus the `l4_tail` bytes at the terminal.
fn v6_frag_chain(frags: &[(u16, u32)], l4_tail: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x60;
    pkt[6] = if frags.is_empty() { PROTO_TCP } else { 44 };
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&SRC6);
    pkt[24..40].copy_from_slice(&DST6);
    let mut ext = Vec::with_capacity(frags.len() * 8 + l4_tail.len());
    for (i, (word, ident)) in frags.iter().enumerate() {
        ext.push(if i + 1 < frags.len() { 44 } else { PROTO_TCP });
        ext.push(0);
        ext.extend_from_slice(&word.to_be_bytes());
        ext.extend_from_slice(&ident.to_be_bytes());
    }
    ext.extend_from_slice(l4_tail);
    pkt[4..6].copy_from_slice(&(ext.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&ext);
    pkt
}

/// A parseable 20-byte TCP header (ports + data-offset 5 + SYN) so the
/// terminal bytes are a REAL L4 header a first-sighting-only consumer
/// would (wrongly, on a non-first chain) build a flow from.
fn tcp20() -> [u8; 20] {
    let mut t = [0u8; 20];
    t[0..2].copy_from_slice(&12345u16.to_be_bytes());
    t[2..4].copy_from_slice(&80u16.to_be_bytes());
    t[12] = 0x50;
    t[13] = 0x02;
    t
}

fn eth14(pkt: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 12];
    f.extend_from_slice(&[0x86, 0xDD]);
    f.extend_from_slice(pkt);
    f
}

fn v6_meta(protocol: u8) -> UserspaceDpMeta {
    UserspaceDpMeta {
        addr_family: libc::AF_INET6 as u8,
        protocol,
        l3_offset: 14,
        ..UserspaceDpMeta::default()
    }
}

fn screen_of(frame: &[u8], protocol: u8) -> ScreenPacketInfo {
    extract_screen_info(
        frame,
        libc::AF_INET6 as u8,
        protocol,
        0,
        frame.len() as u16,
        IpAddr::V6(Ipv6Addr::from(SRC6)),
        IpAddr::V6(Ipv6Addr::from(DST6)),
        0,
        0,
        14,
    )
    .expect("#10661: the screen extractor must parse the chain")
}

#[test]
fn atomic_then_real_nonfirst_tracker_records_fragment_10661() {
    // THE issue shape: `[ATOMIC][real-non-first]`. The tracker must key
    // its range off the FIRST non-ATOMIC header (at buffer offset 48):
    // start = 8, data = payload(36) - frag_data_off(16) = 20 wire bytes.
    // RED pre-fix: first-sighting read the ATOMIC header -> NonFragment.
    let pkt = v6_frag_chain(
        &[(WORD_ATOMIC, IDENT_ATOMIC), (WORD_NONFIRST_O8, IDENT_REAL)],
        &tcp20(),
    );
    match overlap_parse(&pkt, libc::AF_INET6) {
        OverlapParse::Fragment(k, s, e, is_last) => {
            assert_eq!((s, e), (8, 28));
            assert!(is_last, "M=0 with full wire bytes is the last fragment");
            assert_eq!(k.ident, IDENT_REAL);
            assert_eq!(k.protocol, 0, "v6 overlap key drops Next Header");
            assert_eq!(k.routing_domain, 0, "the caller stamps the domain");
        }
        other => panic!("#10661: tracker must track the real header, got {other:?}"),
    }
    let nat64_fragment = crate::nat64::ipv6_fragment_header(&pkt)
        .expect("#10661: NAT64 must select the real non-atomic header");
    assert_eq!(
        (nat64_fragment.offset_units, nat64_fragment.ident),
        (1, IDENT_REAL),
        "#10661: NAT64 must not retain the leading ATOMIC header"
    );
    assert!(crate::nat64::v6_to_v4_is_fragment_drop(&pkt));
}

#[test]
fn atomic_then_real_nonfirst_forwarding_sees_no_l4_10661() {
    // The forwarding family must agree with the shim: a non-zero offset
    // in ANY sighting means no L4 header at the terminal. RED pre-fix:
    // first-sighting read ATOMIC -> "has L4" -> payload parsed as ports.
    let pkt = v6_frag_chain(
        &[(WORD_ATOMIC, IDENT_ATOMIC), (WORD_NONFIRST_O8, IDENT_REAL)],
        &tcp20(),
    );
    assert!(
        ipv6_is_non_first_fragment(&pkt),
        "#10661: the wire predicate must judge every sighting, not the first"
    );
    assert!(ipv6_is_nonatomically_fragmented(&pkt));
    let frame = eth14(&pkt);
    assert!(
        frame_is_non_first_fragment(&frame, v6_meta(PROTO_TCP)),
        "#10661: the frame twin must agree with the wire predicate"
    );
    assert!(
        parse_session_flow_from_bytes(&frame, v6_meta(PROTO_TCP)).is_none(),
        "#10661: the #2344 chokepoint must keep the chain flowless (no ported \
         flow from payload bytes)"
    );
}

#[test]
fn atomic_then_real_nonfirst_screen_sees_nonfirst_10661() {
    // Control: the screens' overwrite already converges on the real
    // header (and sizes `frag_data_off` from it, exactly as the fixed
    // tracker does). GREEN pre- and post-fix; reds if the extractor walk
    // regresses to first-sighting or stops continuing past ATOMIC.
    let pkt = v6_frag_chain(
        &[(WORD_ATOMIC, IDENT_ATOMIC), (WORD_NONFIRST_O8, IDENT_REAL)],
        &tcp20(),
    );
    let frame = eth14(&pkt);
    // 255 = the shim's PROTO_FRAGMENT_NO_L4 stamp, as production meta carries.
    let info = screen_of(&frame, 255);
    assert!(
        info.is_fragment && !info.is_first_fragment,
        "#10661: screens must report the real non-first header"
    );
    assert_eq!(info.ip_frag_off, WORD_NONFIRST_O8);
    assert_eq!(
        info.frag_data_off, 16,
        "#10661: screen sizing (both headers) must match the tracker fix"
    );
    assert_eq!(
        info.protocol, PROTO_TCP,
        "#10661/#9114: the real upper-layer protocol is recovered, not the sentinel"
    );
}

#[test]
fn atomic_then_real_nonfirst_shim_sees_nonfirst_10661() {
    // Control: the shim's every-sighting verdict is the canonical one the
    // userspace side now matches. GREEN pre- and post-fix; reds on shim
    // or walk drift (the executable half of the #4555 parity argument).
    let pkt = v6_frag_chain(
        &[(WORD_ATOMIC, IDENT_ATOMIC), (WORD_NONFIRST_O8, IDENT_REAL)],
        &tcp20(),
    );
    let w = raw_shim_walk(&pkt, 0).expect("#10661: the shim must resolve the chain");
    assert!(
        w.non_first_fragment,
        "#10661: the shim must decline the L4 on the real offset"
    );
    assert_eq!((w.offset, w.protocol), (56, PROTO_TCP));
}

#[test]
fn atomic_chains_stay_nonfragment_everywhere_10661() {
    // ATOMIC-alone, double-ATOMIC, and no-fragment chains are NonFragment
    // to ALL four consumers. GREEN pre- and post-fix: the fix must not
    // promote pure-ATOMIC chains to fragments.
    for (name, frags) in [
        ("atomic-alone", vec![(WORD_ATOMIC, IDENT_ATOMIC)]),
        (
            "double-atomic",
            vec![(WORD_ATOMIC, IDENT_ATOMIC), (WORD_ATOMIC, IDENT_REAL)],
        ),
        ("no-fragment", vec![]),
    ] {
        let pkt = v6_frag_chain(&frags, &tcp20());
        assert_eq!(
            overlap_parse(&pkt, libc::AF_INET6),
            OverlapParse::NonFragment,
            "#10661: tracker must stay NonFragment on {name}"
        );
        assert!(
            !ipv6_is_non_first_fragment(&pkt),
            "#10661: forwarding must see L4 on {name}"
        );
        assert!(
            !ipv6_is_nonatomically_fragmented(&pkt),
            "#10661: atomic-only chains are not non-atomically fragmented"
        );
        let frame = eth14(&pkt);
        let info = screen_of(&frame, PROTO_TCP);
        assert!(
            !info.is_fragment && !info.is_first_fragment,
            "#10661: screens must stay non-fragment on {name}"
        );
        assert_eq!(
            raw_shim_walk(&pkt, 0).map(|w| w.non_first_fragment),
            Some(false),
            "#10661: shim must resolve L4 on {name}"
        );
    }
}

#[test]
fn atomic_then_real_first_agreement_10661() {
    // `[ATOMIC][real-first (M=1, off=0)]`: a genuine first fragment with
    // a real terminal L4. Tracker RED pre-fix (NonFragment via ATOMIC);
    // forwarding/shim/screens GREEN (L4 present) pre- and post-fix.
    let pkt = v6_frag_chain(
        &[(WORD_ATOMIC, IDENT_ATOMIC), (WORD_FIRST, IDENT_REAL)],
        &tcp20(),
    );
    match overlap_parse(&pkt, libc::AF_INET6) {
        OverlapParse::Fragment(k, s, e, is_last) => {
            assert_eq!((s, e), (0, 20));
            assert!(!is_last, "M=1 is never the last fragment");
            assert_eq!(k.ident, IDENT_REAL);
        }
        other => panic!("#10661: tracker must track the real first header, got {other:?}"),
    }
    let nat64_fragment = crate::nat64::ipv6_fragment_header(&pkt)
        .expect("#10661: NAT64 must select the real first header");
    assert_eq!(
        (nat64_fragment.offset_units, nat64_fragment.more, nat64_fragment.ident),
        (0, true, IDENT_REAL),
        "#10661: NAT64 must not retain the leading ATOMIC header"
    );
    assert!(
        !ipv6_is_non_first_fragment(&pkt),
        "#10661: offset 0 in every sighting keeps the L4"
    );
    assert!(ipv6_is_nonatomically_fragmented(&pkt));
    let frame = eth14(&pkt);
    let info = screen_of(&frame, PROTO_TCP);
    assert!(
        info.is_fragment && info.is_first_fragment,
        "#10661: screens must report the real first header (syn-frag eligible)"
    );
    assert_eq!(
        raw_shim_walk(&pkt, 0).map(|w| w.non_first_fragment),
        Some(false),
        "#10661: shim must resolve the L4"
    );
}

#[test]
fn real_first_then_atomic_residual_10661() {
    // EXPLICITLY RECONCILED, not unified: on `[real-first][ATOMIC]` the
    // tracker keys the first REAL header (Fragment-first) while the
    // screens' overwrite lands on the trailing ATOMIC (non-fragment).
    // Composition is safe either way — the tracker is engaged AND the
    // terminal L4 bytes are genuinely present (every L4 gate agrees) —
    // and making the screens sticky here would newly blind the TCP-flag
    // screens on a packet everyone else treats as first-fragment. Pins
    // both halves so neither drifts silently.
    let pkt = v6_frag_chain(
        &[(WORD_FIRST, IDENT_REAL), (WORD_ATOMIC, IDENT_ATOMIC)],
        &tcp20(),
    );
    assert!(
        matches!(
            overlap_parse(&pkt, libc::AF_INET6),
            OverlapParse::Fragment(_, 0, _, false)
        ),
        "#10661: tracker keys the first real (M=1) header"
    );
    assert!(!ipv6_is_non_first_fragment(&pkt));
    let frame = eth14(&pkt);
    let info = screen_of(&frame, PROTO_TCP);
    assert!(
        !info.is_fragment && !info.is_first_fragment,
        "#10661 residual: screens report the trailing ATOMIC header"
    );
    assert_eq!(
        raw_shim_walk(&pkt, 0).map(|w| w.non_first_fragment),
        Some(false)
    );
}

#[test]
fn real_first_then_real_nonfirst_tracker_first_record_10661() {
    // `[real-first][real-non-first]`: the tracker records the FIRST real
    // header's (wider, conservative) range while every L4 gate agrees
    // non-first. The forwarding assert is RED pre-fix (first-sighting
    // read offset 0 -> "has L4"); the tracker assert is stable (both
    // wordings key the first header here) and pins the conservative side.
    let pkt = v6_frag_chain(
        &[(WORD_FIRST, IDENT_REAL), (WORD_NONFIRST_O8, IDENT_REAL)],
        &tcp20(),
    );
    match overlap_parse(&pkt, libc::AF_INET6) {
        OverlapParse::Fragment(_, s, e, _) => assert_eq!((s, e), (0, 28)),
        other => panic!("#10661: tracker must record the first real header, got {other:?}"),
    }
    assert!(
        ipv6_is_non_first_fragment(&pkt),
        "#10661: the later non-zero offset must refuse the L4"
    );
    let frame = eth14(&pkt);
    let info = screen_of(&frame, 255);
    assert!(info.is_fragment && !info.is_first_fragment);
    assert_eq!(
        raw_shim_walk(&pkt, 0).map(|w| w.non_first_fragment),
        Some(true)
    );
}

#[test]
fn real_nonfirst_then_atomic_agreement_10661() {
    // `[real-non-first][ATOMIC]`: every consumer already agrees (the
    // screens break at the first non-first sighting; the tracker keys
    // it). Stable GREEN; pins the order the fix must not perturb.
    let pkt = v6_frag_chain(
        &[(WORD_NONFIRST_O8, IDENT_REAL), (WORD_ATOMIC, IDENT_ATOMIC)],
        &tcp20(),
    );
    assert!(
        matches!(
            overlap_parse(&pkt, libc::AF_INET6),
            OverlapParse::Fragment(_, 8, _, _)
        ),
        "#10661: tracker keys the non-first header"
    );
    assert!(ipv6_is_non_first_fragment(&pkt));
    let frame = eth14(&pkt);
    let info = screen_of(&frame, 255);
    assert!(info.is_fragment && !info.is_first_fragment);
    assert_eq!(
        raw_shim_walk(&pkt, 0).map(|w| w.non_first_fragment),
        Some(true)
    );
}

#[test]
fn atomic_then_truncated_second_header_10661() {
    // `[ATOMIC][declared-but-truncated]`: the real header's bits are
    // unreadable, so the tracker must NOT claim NonFragment. RED
    // pre-fix (first-sighting read ATOMIC -> NonFragment); post-fix
    // Unreadable, matching a truncated single header. Screens/shim
    // fail-closed (Err/None) pre- and post-fix — the chain never
    // forwards, so Unreadable's skip-cache arm is safe.
    let full = v6_frag_chain(
        &[(WORD_ATOMIC, IDENT_ATOMIC), (WORD_NONFIRST_O8, IDENT_REAL)],
        &tcp20(),
    );
    let pkt = full[..40 + 8 + 2].to_vec();
    assert_eq!(
        overlap_parse(&pkt, libc::AF_INET6),
        OverlapParse::Unreadable,
        "#10661: an unreadable real header is never NonFragment"
    );
    assert!(
        !ipv6_is_non_first_fragment(&pkt),
        "#10661: no READABLE non-zero offset was sighted"
    );
    assert!(ipv6_is_nonatomically_fragmented(&pkt));
    assert!(
        crate::nat64::ipv6_fragment_header(&pkt).is_none(),
        "#10661: NAT64 must fail closed on a truncated later header"
    );
    let frame = eth14(&pkt);
    assert!(
        matches!(
            extract_screen_info(
                &frame,
                libc::AF_INET6 as u8,
                255,
                0,
                frame.len() as u16,
                IpAddr::V6(Ipv6Addr::from(SRC6)),
                IpAddr::V6(Ipv6Addr::from(DST6)),
                0,
                0,
                14,
            ),
            Err(ScreenParseError::TruncatedIpv6ExtChain)
        ),
        "#10661: screens fail closed on the truncated header"
    );
    assert!(
        raw_shim_walk(&pkt, 0).is_none(),
        "#10661: the shim refuses the truncated chain"
    );
}

#[test]
fn overlap_tail_dropped_like_plain_control_10661() {
    // End-to-end at unit level: the `[ATOMIC][real]` chain parses to the
    // SAME key and range as the plain single-header control, so an
    // overlapping tail drops identically. RED pre-fix: the chain parsed
    // NonFragment, nothing was recorded, the tail forwarded.
    let control = v6_frag_chain(&[(WORD_NONFIRST_O8, IDENT_REAL)], &tcp20());
    let (ck, cs, ce) = match overlap_parse(&control, libc::AF_INET6) {
        OverlapParse::Fragment(k, s, e, _) => (k, s, e),
        other => panic!("#10661: control must parse, got {other:?}"),
    };
    let chain = v6_frag_chain(
        &[(WORD_ATOMIC, IDENT_ATOMIC), (WORD_NONFIRST_O8, IDENT_REAL)],
        &tcp20(),
    );
    let (k, s, e) = match overlap_parse(&chain, libc::AF_INET6) {
        OverlapParse::Fragment(k, s, e, _) => (k, s, e),
        other => panic!("#10661: chain must parse like the control, got {other:?}"),
    };
    assert_eq!((k, s, e), (ck, cs, ce), "#10661: chain == control");
    let t = OverlapTracker::new();
    assert!(
        !t.check_and_record(k, s, e, 1_000, &FRAG_OVERLAP_DROPPED),
        "#10661: first sighting of the range admits"
    );
    assert!(
        t.check_and_record(k, s + 8, e + 8, 2_000, &FRAG_OVERLAP_DROPPED),
        "#10661: the overlapping tail must drop, exactly like the control"
    );
}
