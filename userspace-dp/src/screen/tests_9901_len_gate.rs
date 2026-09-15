//! #9901 (F-075): one ingress IPv4 declared-length gate, shared by the shim
//! and userspace — pinned as AGREEMENT between the shim's own gate source
//! (this file compiles `userspace-xdp/src/ipv4_len_gate.rs` for the host and
//! runs it) and the userspace extractor's gate.
//!
//! The gate answers one question: can the declared total length cover the
//! header it counts? A total below `ihl*4` is impossible on the wire. The
//! shim refuses it before classification (otherwise a lying length reaches
//! flow stamping while L4 bytes are read from pad/slack past the declared
//! end); the extractor refuses it at the fail-closed boundary (otherwise a
//! frame that bypasses the shim reaches length-arithmetic screens with a
//! header no consumer can bound). The sweep below drives (ihl, total,
//! capture) over every boundary and requires both verdicts to agree; the
//! call-site pin requires the shim parser to actually consult the gate.

#[path = "../../../userspace-xdp/src/ipv4_len_gate.rs"]
mod shim_len_gate;

use std::net::{IpAddr, Ipv4Addr};

use shim_len_gate::{ipv4_declared_len_covers_header, ipv4_declared_read_end};

use super::extract::extract_screen_info;
use super::packet::ScreenParseError;

const L3: usize = 14;
const SRC: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const DST: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

/// A captured frame: eth + IPv4 header (`ihl_words`, `total_len`, NOP-padded
/// options, no fragmentation, proto TCP) + zero payload out to `caplen`.
fn v4_frame(ihl_words: u8, total_len: u16, caplen: usize) -> Vec<u8> {
    let ihl_bytes = ihl_words as usize * 4;
    let mut frame = vec![0u8; caplen.max(L3 + ihl_bytes)];
    frame[L3] = 0x40 | (ihl_words & 0x0F);
    frame[L3 + 2..L3 + 4].copy_from_slice(&total_len.to_be_bytes());
    frame[L3 + 8] = 64; // TTL
    frame[L3 + 9] = 6; // TCP
    frame[L3 + 12..L3 + 16].copy_from_slice(&[10, 0, 0, 1]);
    frame[L3 + 16..L3 + 20].copy_from_slice(&[10, 0, 0, 2]);
    for b in frame.iter_mut().take(L3 + ihl_bytes).skip(L3 + 20) {
        *b = 0x01; // NOP: always-valid options padding
    }
    // A valid TCP header at the L4 start when the capture covers one, so an
    // accepted frame has nothing else to trip on (the TCP tail read is
    // lenient anyway — zeros when short — but validity keeps the sweep about
    // the length gate rather than about TCP shape).
    let l4 = L3 + ihl_bytes;
    if caplen >= l4 + 20 {
        frame[l4 + 12] = 0x50;
    }
    frame.truncate(caplen);
    frame
}

fn extractor_verdict(frame: &[u8]) -> Result<(), ScreenParseError> {
    extract_screen_info(
        frame,
        libc::AF_INET as u8,
        6,
        0,
        frame.len() as u16,
        SRC,
        DST,
        12345,
        80,
        L3,
    )
    .map(|_| ())
}

#[test]
fn shim_gate_and_extractor_agree_on_declared_length_9901() {
    // Every (IHL, total, capture) boundary: totals below/at/above the header
    // length, captures below/at/above both. The extractor must refuse exactly
    // when the shim gate refuses (impossible length) or the capture is short
    // of the header the IHL itself declares (the pre-existing #4167 arm).
    let totals: Vec<u16> = vec![
        0, 1, 19, 20, 21, 22, 23, 24, 25, 27, 28, 33, 34, 39, 40, 59, 60, 61, 68, 576,
        1500, 65535,
    ];
    for ihl_words in [5u8, 6u8, 15u8] {
        let ihl_bytes = ihl_words as usize * 4;
        for &total in &totals {
            for caplen in [
                L3 + 19,
                L3 + ihl_bytes - 1,
                L3 + ihl_bytes,
                L3 + ihl_bytes + 1,
                L3 + (total as usize).min(1500),
                L3 + (total as usize).min(1500) + 14,
            ] {
                let frame = v4_frame(ihl_words, total, caplen);
                // The shim gate's verdict, from the shim's own source.
                let gate_ok = ipv4_declared_len_covers_header(total, ihl_bytes);
                assert_eq!(
                    gate_ok,
                    (total as usize) >= ihl_bytes,
                    "gate truth table",
                );
                // The clamp arithmetic, likewise from the shim's source.
                assert_eq!(
                    ipv4_declared_read_end(L3, total, caplen),
                    caplen.min(L3 + total as usize),
                    "ihl={ihl_words} total={total} caplen={caplen}: read end",
                );
                // The extractor must agree with the gate, modulo its own
                // capture-short arm (a header the capture cannot hold is
                // refused regardless of what the length declares).
                let capture_short = L3 + ihl_bytes > caplen;
                let expected_err = !gate_ok || capture_short;
                let verdict = extractor_verdict(&frame);
                assert_eq!(
                    verdict.is_err(),
                    expected_err,
                    "#9901: ihl={ihl_words} total={total} caplen={caplen}: \
                     extractor Err ({verdict:?}) must equal gate-refuses || \
                     capture-short (gate_ok={gate_ok} capture_short={capture_short})",
                );
                if expected_err && !capture_short {
                    // The refusal came from the length gate specifically.
                    assert!(
                        matches!(verdict, Err(ScreenParseError::TruncatedIpv4Header)),
                        "#9901: an impossible declared length must fail closed \
                         as TruncatedIpv4Header, got {verdict:?}",
                    );
                }
            }
        }
    }
}

#[test]
fn shim_parser_consults_the_declared_length_gate_9901() {
    // The sweep above pins gate-vs-extractor AGREEMENT; this pins that the
    // shipped parser actually consults the gate — the gate call, the declared
    // read end, the first-fragment tuple path, and the clamped whole-packet
    // L4 call, each exactly once in `parse_ipv4`'s statement flow. A parser
    // edit that stops consulting the gate reds here while the sweep stays
    // green.
    let lib = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("userspace-xdp/src/lib.rs");
    let src = std::fs::read_to_string(&lib).expect("read shim lib.rs");
    assert!(
        src.len() > 10_000 && src.contains("fn parse_ipv4"),
        "non-vacuity: the shim source must be the real parser",
    );
    for needle in [
        "ipv4_declared_len_covers_header(total_len, ihl)",
        "ipv4_declared_read_end(l3_offset as usize, total_len, data_end)",
        "first_fragment_l4(data, data_end, l4_end, l4_offset, protocol)",
        "parse_l4(data, data_end, l4_offset, protocol, l4_end)",
    ] {
        assert_eq!(
            src.matches(needle).count(),
            1,
            "#9901: the shim parser must consult the declared-length gate \
             exactly once via `{needle}`",
        );
    }
}
