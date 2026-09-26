//! #9901 (F-072): the screen extractor and the forwarding walker must agree
//! on every IPv6 extension-header chain — pinned as a BEHAVIOURAL agreement,
//! not as a shared number and not (only) as shared source.
//!
//! The two walkers reach the same verdicts by different mechanisms (the
//! extractor's `0..8` loop with a terminal iteration vs `walk_ipv6_ext_chain`
//! with `MAX_IPV6_EXT_HEADERS`, documented at the extractor's walk) and since
//! #9901 share the TRAVERSED SET (`IPV6_GENERIC_EXT_HEADERS`, guarded here and
//! delegated-to there). What this file pins is the agreement relation over
//! all 256 next-header values x two chain shapes x every truncation length:
//!
//! - R1 (fail-closed, EXACT): the forwarding walker reports `Truncated` iff
//!   the screen extractor returns `Err`. This is the IDS-evasion direction —
//!   a chain the forwarder cannot parse must never screen clean — and it holds
//!   in both directions because both sides key truncation off the same chain
//!   bytes (base + each header's declared advance).
//! - R2 (TCP resolution): when the walker resolves `L4(off, TCP)` on a chain
//!   without a non-first fragment, the extractor must read the SAME bytes the
//!   walker pointed at (seq/ack), or zeros when fewer than 20 TCP bytes are
//!   captured. When the walker resolves anything else (non-TCP L4, `OverLimit`,
//!   `NoNextHeader`, or any chain with a non-first fragment sighted) the
//!   extractor must NOT resolve TCP (zeros).
//!
//! The L4-region leniency difference is INTENTIONAL and pinned, not papered
//! over: the walker LOCATES the L4 offset without reading L4 bytes, while the
//! extractor READS seq/ack only when 20 TCP bytes are captured and otherwise
//! returns `Ok` with zeros (it never `Err`s on a short TCP tail). So a
//! truncation inside the TCP header yields walker-`L4` + screen-zeros —
//! agreement on the verdict (no truncation on either side), zeros on the
//! unread read. The depth bound (>7 headers) is out of scope here —
//! `screen_ext_header_depth_agrees_with_the_forwarding_walker_6885` owns it —
//! and these shapes stay at <=2 headers so the bound never engages.

use std::net::{IpAddr, Ipv6Addr};

use crate::afxdp::{ExtChainOutcome, walk_ipv6_ext_chain};

use super::extract::extract_screen_info;

const L3: usize = 14;
const TCP_SEQ: u32 = 0x1122_3344;
const TCP_ACK: u32 = 0x5566_7788;
const SRC: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
const DST: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));

/// Eth + IPv6 base with `base_nh`, then `headers` (each an 8-byte
/// next/len/pad triple), then a valid 20-byte TCP header. Returns the frame
/// and the TCP header offset.
fn chain_frame(base_nh: u8, headers: &[[u8; 8]]) -> (Vec<u8>, usize) {
    let tcp_at = L3 + 40 + headers.len() * 8;
    let mut frame = vec![0u8; tcp_at + 20];
    frame[L3] = 0x60; // version = 6
    frame[L3 + 6] = base_nh;
    for (i, h) in headers.iter().enumerate() {
        frame[L3 + 40 + i * 8..L3 + 40 + (i + 1) * 8].copy_from_slice(h);
    }
    frame[tcp_at + 4..tcp_at + 8].copy_from_slice(&TCP_SEQ.to_be_bytes());
    frame[tcp_at + 8..tcp_at + 12].copy_from_slice(&TCP_ACK.to_be_bytes());
    frame[tcp_at + 12] = 0x50; // data offset = 5 words
    (frame, tcp_at)
}

/// An 8-byte generic ext-header slot: next header + HdrExtLen 0 + pad. Doubled
/// as a Fragment header it reads as atomic (offset 0, M 0) and as an AH as
/// `(0 + 2) * 4 = 8` bytes — every kind advances exactly 8 in the sweep.
fn ext_slot(next: u8) -> [u8; 8] {
    [next, 0, 0, 0, 0, 0, 0, 0]
}

fn assert_agreement(shape: &str, v: u8, prefix: &[u8]) {
    let t = prefix.len();
    let walk = walk_ipv6_ext_chain(prefix, L3);
    // Protocol is passed as TCP explicitly: the extractor's TCP read is gated
    // on the CALLER's protocol (the shim's), not on the walked terminal.
    let screen = extract_screen_info(
        prefix,
        libc::AF_INET6 as u8,
        6,
        0,
        prefix.len() as u16,
        SRC,
        DST,
        12345,
        80,
        L3,
    );
    let truncated = matches!(walk.outcome, ExtChainOutcome::Truncated);
    assert_eq!(
        screen.is_err(),
        truncated,
        "#9901 R1: {shape} v={v} t={t}: screen Err must equal walker Truncated \
         (walk={:?}, screen={screen:?})",
        walk.outcome,
    );
    // R2: TCP resolution agreement on the non-truncated side.
    if let Ok(info) = &screen {
        match walk.outcome {
            ExtChainOutcome::L4(off, 6) if !walk.non_first_fragment_offset_seen => {
                if walk.ah_present {
                    // #10729 X2-F6: deliberate divergence — the walker still
                    // resolves the inner offset (traversal preserved), but
                    // the screen suppresses inner-TCP exposure through AH.
                    assert_eq!(
                        (info.tcp_seq, info.tcp_ack),
                        (0, 0),
                        "#9901 R2 + #10729: {shape} v={v} t={t}: AH-sighted \
                         TCP must read zeros on the screen side",
                    );
                    return;
                }
                if off + 20 <= t {
                    let exp_seq =
                        u32::from_be_bytes(prefix[off + 4..off + 8].try_into().unwrap());
                    let exp_ack =
                        u32::from_be_bytes(prefix[off + 8..off + 12].try_into().unwrap());
                    assert_eq!(
                        (info.tcp_seq, info.tcp_ack),
                        (exp_seq, exp_ack),
                        "#9901 R2: {shape} v={v} t={t}: screen must read the \
                         TCP bytes the walker resolved at {off}",
                    );
                } else {
                    // The documented leniency difference: the walker locates
                    // the offset without reading L4 bytes, the extractor
                    // returns zeros for a short TCP tail (never Err).
                    assert_eq!(
                        (info.tcp_seq, info.tcp_ack),
                        (0, 0),
                        "#9901 R2: {shape} v={v} t={t}: short TCP tail must \
                         read zeros, not garbage",
                    );
                }
            }
            _ => {
                // Non-TCP terminal, over-limit/no-next, or any non-first
                // fragment sighted: the extractor must not resolve TCP.
                assert_eq!(
                    (info.tcp_seq, info.tcp_ack),
                    (0, 0),
                    "#9901 R2: {shape} v={v} t={t}: walker={:?} must not \
                     resolve TCP on the screen side",
                    walk.outcome,
                );
            }
        }
    }
}

#[test]
fn walker_and_screen_agree_on_all_next_headers_direct_9901() {
    // Shape DIRECT: base NextHdr = v straight onto one ext slot + TCP. Every
    // v in 0..=255, every truncation length 0..=full.
    for v in 0..=255u8 {
        let (frame, _tcp_at) = chain_frame(v, &[ext_slot(6)]);
        for t in 0..=frame.len() {
            assert_agreement("direct", v, &frame[..t]);
        }
    }
}

#[test]
fn walker_and_screen_agree_on_all_next_headers_one_ext_9901() {
    // Shape ONE-EXT: base -> Hop-by-Hop -> v-header -> TCP. Exercises v in a
    // non-base position (advance math on both sides, not just the base byte).
    for v in 0..=255u8 {
        let (frame, _tcp_at) = chain_frame(0, &[ext_slot(v), ext_slot(6)]);
        for t in 0..=frame.len() {
            assert_agreement("one-ext", v, &frame[..t]);
        }
    }
}

#[test]
fn walker_and_screen_agree_on_non_first_fragment_9901() {
    // A quoted/forwarded NON-FIRST fragment (offset 1) has no L4 header: the
    // walker still locates the terminal past it (recording the sighting) while
    // the screen side must stop without resolving TCP (#2344/#3064 flowless
    // contract), at every truncation length.
    let mut frag = ext_slot(6);
    frag[2] = 0x00;
    frag[3] = 0x08; // fragment offset 1 (0x0008 & 0xFFF8 != 0), M clear
    let (frame, _tcp_at) = chain_frame(44, &[frag]);
    for t in 0..=frame.len() {
        assert_agreement("nonfirst", 44, &frame[..t]);
    }
}

#[test]
fn extractor_references_the_shared_ext_header_set_9901() {
    // The behavioural sweep above pins AGREEMENT; this pins SHARING — that
    // `screen/extract.rs` guards on the `IPV6_GENERIC_EXT_HEADERS` single
    // source rather than a re-spelled arm list, and that the forwarding
    // predicate still delegates to the same const. Re-spelling the set in
    // either file reds here while the sweep stays green, which is exactly
    // the convention-drift F-072 is about.
    // Strip comment-only lines before pinning: a `contains` pin over raw
    // source would still pass with the arm commented out (the text survives
    // in the comment). Code lines only — the pins anchor on real code.
    fn code_only(src: &str) -> String {
        src.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let extract = code_only(
        &std::fs::read_to_string(root.join("screen/extract.rs")).expect("read extract.rs"),
    );
    let inspect = code_only(
        &std::fs::read_to_string(root.join("afxdp/frame/inspect.rs")).expect("read inspect.rs"),
    );
    assert!(
        extract.len() > 1000 && inspect.len() > 1000,
        "non-vacuity: both sources must be real files",
    );
    assert!(
        extract.contains("n if IPV6_GENERIC_EXT_HEADERS.contains(&n)"),
        "#9901: screen/extract.rs must guard its generic ext-header arm on the \
         shared IPV6_GENERIC_EXT_HEADERS const, not a local arm list",
    );
    assert!(
        extract.matches("IPV6_GENERIC_EXT_HEADERS").count() >= 2,
        "#9901: the shared const must be both imported and used in extract.rs",
    );
    assert!(
        inspect.contains("IPV6_GENERIC_EXT_HEADERS.contains(&protocol)"),
        "#9901: ipv6_ext_header_is_traversable must delegate to the shared \
         const — the set is stated once",
    );
}
