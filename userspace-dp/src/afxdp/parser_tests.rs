// Tests for afxdp/parser.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep parser.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "parser_tests.rs"]` from parser.rs.

use super::*;

fn build_eth_arp_reply(vlan: bool) -> Vec<u8> {
    let mut f = Vec::new();
    // dst mac
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    // src mac
    f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    if vlan {
        // 802.1Q + VID 100
        f.extend_from_slice(&[0x81, 0x00, 0x00, 0x64]);
    }
    // ethertype = ARP
    f.extend_from_slice(&[0x08, 0x06]);
    // ARP body: htype=1, ptype=0x0800, hlen=6, plen=4, op=2 (reply)
    f.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]);
    // sender mac
    f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    // sender ip 10.0.0.42
    f.extend_from_slice(&[10, 0, 0, 42]);
    // target mac (filled to 28-byte body)
    f.extend_from_slice(&[0x00; 6]);
    // target ip
    f.extend_from_slice(&[10, 0, 0, 1]);
    f
}

#[test]
fn classify_arp_reply_untagged() {
    let f = build_eth_arp_reply(false);
    match classify_arp(&f) {
        ArpClassification::Reply(r) => {
            assert_eq!(r.sender_mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
            assert_eq!(r.sender_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)));
        }
        other => panic!("expected Reply, got {:?}", other),
    }
}

#[test]
fn classify_arp_reply_vlan_tagged() {
    let f = build_eth_arp_reply(true);
    match classify_arp(&f) {
        ArpClassification::Reply(r) => {
            assert_eq!(r.sender_mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        }
        other => panic!("expected Reply, got {:?}", other),
    }
}

#[test]
fn classify_arp_request_is_other_arp() {
    let mut f = build_eth_arp_reply(false);
    // flip op from 2 (reply) to 1 (request)
    f[14 + 6] = 0x00;
    f[14 + 7] = 0x01;
    assert_eq!(classify_arp(&f), ArpClassification::OtherArp);
}

#[test]
fn classify_arp_rejects_non_arp_ethertype() {
    let mut f = build_eth_arp_reply(false);
    // change ethertype to IPv4
    f[12] = 0x08;
    f[13] = 0x00;
    assert_eq!(classify_arp(&f), ArpClassification::NotArp);
}

#[test]
fn classify_arp_rejects_short_frame() {
    let f = vec![0u8; 30];
    assert_eq!(classify_arp(&f), ArpClassification::NotArp);
}

// #2369 fail-on-revert: a crafted opcode-2 ARP whose fixed header is not
// Ethernet/IPv4 (htype!=1, ptype!=0x0800, hlen!=6, or plen!=4) must NOT
// be learned — its sender bytes would otherwise be read at the
// Ethernet/IPv4 fixed offsets and poison the neighbor cache. Each of
// these MUST flip to `Reply` (poison) if the corresponding header check
// is removed from `classify_arp`.

#[test]
fn classify_arp_rejects_non_ethernet_htype() {
    let mut f = build_eth_arp_reply(false);
    // htype is at l3_start (offset 14) for an untagged frame. Flip 1 -> 0xfe.
    f[14] = 0x00;
    f[15] = 0xfe;
    assert_eq!(
        classify_arp(&f),
        ArpClassification::OtherArp,
        "opcode-2 ARP with htype!=1 must not be learned (neighbor-cache poison)"
    );
}

#[test]
fn classify_arp_rejects_non_ipv4_ptype() {
    let mut f = build_eth_arp_reply(false);
    // ptype is at l3_start+2 (offset 16). Flip 0x0800 -> 0x86dd (IPv6).
    f[16] = 0x86;
    f[17] = 0xdd;
    assert_eq!(
        classify_arp(&f),
        ArpClassification::OtherArp,
        "opcode-2 ARP with ptype!=0x0800 must not be learned"
    );
}

#[test]
fn classify_arp_rejects_bad_hlen() {
    let mut f = build_eth_arp_reply(false);
    // hlen is at l3_start+4 (offset 18). Flip 6 -> 8.
    f[18] = 8;
    assert_eq!(
        classify_arp(&f),
        ArpClassification::OtherArp,
        "opcode-2 ARP with hlen!=6 must not read sender at the Ethernet offset"
    );
}

#[test]
fn classify_arp_rejects_bad_plen() {
    let mut f = build_eth_arp_reply(false);
    // plen is at l3_start+5 (offset 19). Flip 4 -> 16.
    f[19] = 16;
    assert_eq!(
        classify_arp(&f),
        ArpClassification::OtherArp,
        "opcode-2 ARP with plen!=4 must not read sender at the IPv4 offset"
    );
}

#[test]
fn classify_arp_valid_reply_still_learns_after_validation() {
    // Anti-over-reject: a well-formed Ethernet/IPv4 opcode-2 ARP reply
    // must STILL learn after the #2369 field checks — IPv4 neighbor
    // resolution depends on this path. Pins that the validation does not
    // regress legitimate ARP learning.
    let f = build_eth_arp_reply(false);
    match classify_arp(&f) {
        ArpClassification::Reply(r) => {
            assert_eq!(r.sender_mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
            assert_eq!(r.sender_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)));
        }
        other => panic!("expected Reply (valid ARP must still learn), got {:?}", other),
    }
}

#[test]
fn classify_arp_truncated_body_does_not_panic() {
    // A frame with the ARP EtherType but a body shorter than 28 bytes
    // must classify without an out-of-bounds read/panic. Build a valid
    // reply and truncate into the ARP body at every length below the
    // full 28-byte body.
    let full = build_eth_arp_reply(false);
    for cut in 14..full.len() {
        let truncated = &full[..cut];
        // Must not panic; a too-short body is NotArp (the len guard fires
        // before any fixed-offset field read).
        let _ = classify_arp(truncated);
    }
}

// ICMPv6 checksum stamping is shared with the poll_stages #2370 tests via
// `afxdp::test_fixtures::stamp_icmpv6_checksum` (single source of truth so
// the pseudo-header / fold logic cannot drift between the two test sites).
use super::super::test_fixtures::stamp_icmpv6_checksum;

fn build_eth_ndp_na(vlan: bool, with_tlla: bool) -> Vec<u8> {
    build_eth_ndp_na_full(vlan, with_tlla, 255, 0, false)
}

/// Full NDP NA builder with explicit RFC 4861 §7.1.2 knobs (#2368).
///
///  - `hop_limit`        — IPv6 Hop Limit byte (255 required by §7.1.2).
///  - `code`             — ICMPv6 Code byte (0 required by §7.1.2).
///  - `target_multicast` — when true the Target Address is ff02::1
///    (multicast) instead of the default unicast fe80::abcd:ef01:0:42.
///
/// Always stamps a VALID ICMPv6 checksum over the declared packet so a
/// well-formed frame is accepted; rejection tests that need a bad
/// checksum corrupt the field after building.
fn build_eth_ndp_na_full(
    vlan: bool,
    with_tlla: bool,
    hop_limit: u8,
    code: u8,
    target_multicast: bool,
) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    if vlan {
        f.extend_from_slice(&[0x81, 0x00, 0x00, 0x64]);
    }
    // ethertype IPv6
    f.extend_from_slice(&[0x86, 0xdd]);
    let l3_start = if vlan { 18 } else { 14 };
    // IPv6 header (40 bytes): version=6, payload-len=24+8 if TLLA else 24,
    // next-header=58 ICMPv6
    let payload_len = if with_tlla { 32u16 } else { 24u16 };
    f.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // ver+tc+flow
    f.extend_from_slice(&payload_len.to_be_bytes());
    f.push(NEXT_HEADER_ICMPV6); // next header
    f.push(hop_limit); // hop limit
                       // src ip
    f.extend_from_slice(&[
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x01,
    ]);
    // dst ip
    f.extend_from_slice(&[0xff; 16]);
    let l4_start = l3_start + 40;
    // ICMPv6 NA: type=136, code, checksum(placeholder), flags=0, target
    f.push(ICMPV6_TYPE_NA);
    f.push(code); // code
    f.extend_from_slice(&[0x00, 0x00]); // checksum placeholder (stamped below)
    f.extend_from_slice(&[0; 4]); // flags
    if target_multicast {
        // ff02::1 — all-nodes multicast: an invalid Target Address.
        f.extend_from_slice(&[
            0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0x01,
        ]);
    } else {
        f.extend_from_slice(&[
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x42,
        ]);
    }
    if with_tlla {
        // option type=2 (TLLA), len=1 (×8 = 8 bytes), MAC
        f.push(NDP_OPT_TARGET_LL);
        f.push(1);
        f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }
    let packet_end = l3_start + 40 + payload_len as usize;
    stamp_icmpv6_checksum(&mut f, l3_start, l4_start, packet_end);
    f
}

#[test]
fn parse_ndp_na_with_tlla_untagged() {
    let f = build_eth_ndp_na(false, true);
    let r = parse_ndp_neighbor_advert(&f).expect("NA parses");
    assert_eq!(
        r.target_ip,
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0xabcd, 0xef01, 0, 0x42)),
    );
    assert_eq!(r.target_mac, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
}

#[test]
fn parse_ndp_na_with_tlla_vlan() {
    let f = build_eth_ndp_na(true, true);
    let r = parse_ndp_neighbor_advert(&f).expect("VLAN NA parses");
    assert_eq!(r.target_mac, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
}

#[test]
fn parse_ndp_na_without_tlla() {
    let f = build_eth_ndp_na(false, false);
    let r = parse_ndp_neighbor_advert(&f).expect("NA without TLLA still parses");
    assert!(r.target_mac.is_none());
}

/// #4475: the parser exposes the RFC 4861 §4.4 Override (O) flag (bit
/// 0x20 of the flags byte at `l4_start + 4` = 58 in the untagged layout)
/// so the learn site can honor §7.2.5. The default builder writes all-zero
/// flags (Override=0); flipping the bit + re-stamping the checksum yields
/// Override=1.
#[test]
fn parse_ndp_na_reports_override_flag() {
    let f0 = build_eth_ndp_na(false, true);
    assert!(
        !parse_ndp_neighbor_advert(&f0)
            .expect("NA parses")
            .override_flag,
        "default NA flags are zero → Override=0"
    );

    let mut f1 = build_eth_ndp_na(false, true);
    f1[14 + 40 + 4] |= 0x20; // set the O bit in the flags byte
    stamp_icmpv6_checksum(&mut f1, 14, 14 + 40, 14 + 40 + 32);
    assert!(
        parse_ndp_neighbor_advert(&f1)
            .expect("override NA parses")
            .override_flag,
        "the O bit must be reported as Override=1"
    );
    // Setting only the Solicited (0x40) / Router (0x80) bits must NOT read
    // as Override.
    let mut f2 = build_eth_ndp_na(false, true);
    f2[14 + 40 + 4] |= 0x40 | 0x80;
    stamp_icmpv6_checksum(&mut f2, 14, 14 + 40, 14 + 40 + 32);
    assert!(
        !parse_ndp_neighbor_advert(&f2)
            .expect("NA parses")
            .override_flag,
        "Solicited/Router bits must not be mistaken for Override"
    );
}

#[test]
fn parse_ndp_na_rejects_non_icmpv6_next_header() {
    let mut f = build_eth_ndp_na(false, true);
    // flip next-header from ICMPv6 (58) to UDP (17)
    f[14 + 6] = 17;
    assert!(parse_ndp_neighbor_advert(&f).is_none());
}

#[test]
fn parse_ndp_na_rejects_non_na_type() {
    let mut f = build_eth_ndp_na(false, true);
    // flip ICMPv6 type from 136 (NA) to 135 (NS)
    f[14 + 40] = 135;
    assert!(parse_ndp_neighbor_advert(&f).is_none());
}

#[test]
fn parse_eth_offsets_handles_short_frame() {
    let f = vec![0u8; 12];
    assert!(parse_eth_offsets(&f).is_none());
}

// ---------------------------------------------------------------------------
// #2150 sub-fix tests + drift-guard canaries.
//
// The L2 canary pins the four userspace L2 offset parsers (parse_eth_offsets
// [learning], frame/inspect::frame_l3_offset [forwarding], cos/ecn::ethernet_l3
// [CoS ECN], nat64::frame_l3_offset [NAT64]) to AGREE on the L3 offset for
// every L2 shape the shim can steer to userspace, so a future drift on a
// single 0x88a8 tag (or any new tag handling) is caught at `cargo test`.
//
// The IPv6 canary pins the learning NDP walker to AGREE with the shared #2148
// forwarding walker on the L4 offset for every IPv6 extension-header chain.
//
// Both canaries FAIL on pre-fix code: pre-fix parse_eth_offsets returns l3=14
// on a 0x88a8 tag (the others return 18), and pre-fix parse_ndp_neighbor_advert
// returns None for an NA behind a hop-by-hop header (the forwarding walker
// finds the ICMPv6). PR-2 (full parser unification) is gated on these staying
// green.
//
// #9888 extends the L2 canary to the double-tag shape
// (`l2_qinq_shape_contract_9888` below): those frames never reach userspace
// (the shim drops them with the qinq_drop counter), so the extension pins
// each parser's contract on the unreachable shape rather than a shared
// offset.
// ---------------------------------------------------------------------------

use crate::afxdp::cos::ecn::{EthernetL3, ethernet_l3};
use crate::afxdp::frame::frame_l3_offset;

/// Build an L2 frame: dst+src MAC, an optional VLAN tag with the given
/// outer TPID, the given inner ethertype, then `body_len` zero body bytes.
fn build_l2_frame(outer_tpid: Option<u16>, inner_ethertype: u16, body_len: usize) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst
    f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // src
    if let Some(tpid) = outer_tpid {
        f.extend_from_slice(&tpid.to_be_bytes());
        f.extend_from_slice(&0x0064u16.to_be_bytes()); // TCI: VID 100
    }
    f.extend_from_slice(&inner_ethertype.to_be_bytes());
    f.extend_from_slice(&vec![0u8; body_len]);
    f
}

/// The L2-offset parser that `nat64::frame_l3_offset` re-implements. We
/// can't reach the private `nat64::frame_l3_offset` from this module, so
/// `nat64_tests.rs::nat64_l2_offset_canary` proves NAT64 agrees; this
/// mirror documents the contract the four parsers share.
fn expected_l3_for_shape(outer_tpid: Option<u16>) -> usize {
    match outer_tpid {
        // single 0x8100 OR 0x88a8 tag → one tag → l3 at 18
        Some(0x8100) | Some(0x88a8) => 18,
        // untagged → l3 at 14
        None => 14,
        // any other outer ethertype is "untagged" from the L2 parser's
        // point of view (the ethertype IS the L3 discriminator)
        Some(_) => 14,
    }
}

#[test]
fn l2_offset_canary_all_parsers_agree() {
    // Every L2 shape the shim steers to userspace, × IPv4 / IPv6.
    let inner_families = [0x0800u16, 0x86DDu16];
    let outer_shapes = [None, Some(0x8100u16), Some(0x88a8u16)];

    for &outer in &outer_shapes {
        for &inner in &inner_families {
            let f = build_l2_frame(outer, inner, 64);
            let want = expected_l3_for_shape(outer);

            // L2-a learning parser.
            let (a_l3, a_ethertype) =
                parse_eth_offsets(&f).expect("parse_eth_offsets parses a valid L2 frame");
            assert_eq!(
                a_l3, want,
                "parse_eth_offsets l3 mismatch for outer={outer:?} inner={inner:#06x}"
            );
            assert_eq!(
                a_ethertype, inner,
                "parse_eth_offsets must return the inner ethertype for outer={outer:?}"
            );

            // L2-b forwarding parser.
            let b_l3 = frame_l3_offset(&f).expect("frame_l3_offset parses a valid L2 frame");
            assert_eq!(
                b_l3, want,
                "frame_l3_offset l3 mismatch for outer={outer:?} inner={inner:#06x}"
            );

            // L2-c CoS ECN parser (returns family + offset).
            let c = ethernet_l3(&f).expect("ethernet_l3 parses an IP L2 frame");
            let c_l3 = match c {
                EthernetL3::Ipv4(off) | EthernetL3::Ipv6(off) => off,
            };
            assert_eq!(
                c_l3, want,
                "ethernet_l3 l3 mismatch for outer={outer:?} inner={inner:#06x}"
            );
            // ethernet_l3 must also classify the family from the wire
            // bytes, not the sideband.
            match (inner, c) {
                (0x0800, EthernetL3::Ipv4(_)) | (0x86DD, EthernetL3::Ipv6(_)) => {}
                other => panic!("ethernet_l3 family mismatch: {other:?}"),
            }

            // All three reachable parsers must agree with each other and
            // with the documented contract.
            assert_eq!(a_l3, b_l3, "parse_eth_offsets vs frame_l3_offset disagree");
            assert_eq!(b_l3, c_l3, "frame_l3_offset vs ethernet_l3 disagree");
        }
    }
}

/// Build a QinQ frame: dst+src MAC, outer TPID+TCI, inner TPID+TCI, the
/// payload ethertype, then `body_len` zero body bytes.
fn build_qinq_frame(
    outer_tpid: u16,
    inner_tpid: u16,
    payload_ethertype: u16,
    body_len: usize,
) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst
    f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // src
    f.extend_from_slice(&outer_tpid.to_be_bytes());
    f.extend_from_slice(&0x0064u16.to_be_bytes()); // outer TCI: VID 100
    f.extend_from_slice(&inner_tpid.to_be_bytes());
    f.extend_from_slice(&0x00c8u16.to_be_bytes()); // inner TCI: VID 200
    f.extend_from_slice(&payload_ethertype.to_be_bytes());
    f.extend_from_slice(&vec![0u8; body_len]);
    f
}

#[test]
fn l2_qinq_shape_contract_9888() {
    // The L2 canary extended to the double-tag shape: parser-contract
    // coverage only, not steering enforcement. Complete-L2-header QinQ
    // frames never reach userspace in production — the shim drops them
    // with the qinq_drop counter, a disposition the Go BPF cells (which
    // run the real program) own — so what is pinned here is each
    // parser's CONTRACT on the unreachable shape, not a shared L3
    // offset: the offset parsers return the single-unwrap answer
    // (l3=18, inner TPID as ethertype) while the CoS classifier refuses
    // to guess (None). A future edit that changes any parser reds here
    // instead of silently reinterpreting the inner tag as an IP header.
    // A steering change that delivered this shape to userspace would NOT
    // red here (this test never executes the shim); that regression
    // belongs to the Go cells.
    let outers = [0x8100u16, 0x88a8u16];
    let inners = [0x8100u16, 0x88a8u16, 0x9100u16];
    for &outer in &outers {
        for &inner in &inners {
            let f = build_qinq_frame(outer, inner, 0x0800, 64);

            // Learning parser: single unwrap, inner TPID returned as-is.
            let (a_l3, a_ethertype) =
                parse_eth_offsets(&f).expect("parse_eth_offsets parses a double-tagged frame");
            assert_eq!(
                a_l3, 18,
                "parse_eth_offsets l3 for {outer:#06x}/{inner:#06x}"
            );
            assert_eq!(
                a_ethertype, inner,
                "parse_eth_offsets must return the inner TPID as-is for {outer:#06x}/{inner:#06x}"
            );

            // Forwarding parser: same single-unwrap offset.
            let b_l3 = frame_l3_offset(&f).expect("frame_l3_offset parses a double-tagged frame");
            assert_eq!(b_l3, 18, "frame_l3_offset l3 for {outer:#06x}/{inner:#06x}");

            // CoS ECN parser: refuses the nested stack rather than stamping
            // into the inner tag.
            assert_eq!(
                ethernet_l3(&f),
                None,
                "ethernet_l3 must reject the QinQ stack {outer:#06x}/{inner:#06x}"
            );
        }
    }

    // A legacy 0x9100 outer is not a recognised tag to any userspace
    // parser: the ethertype at 12..14 is returned as the L3 discriminator
    // (l3=14), which is non-IP, so no parser treats the tag bytes as IP.
    // (The shim drops this shape too — it never unwraps 0x9100.)
    let legacy = build_l2_frame(Some(0x9100), 0x0800, 64);
    let (l3, ethertype) = parse_eth_offsets(&legacy).expect("parses");
    assert_eq!((l3, ethertype), (14, 0x9100));
    assert_eq!(frame_l3_offset(&legacy), Some(14));
    assert_eq!(ethernet_l3(&legacy), None);

    // The trap this shape sets for neighbor learning: a double tag hiding
    // an ARP reply at offset 22 must NOT classify as a Reply. The learning
    // parser sees the inner TPID (not ARP) at the single-unwrap position
    // and declines before reading any ARP bytes.
    let mut f = build_qinq_frame(0x8100, 0x8100, 0x0806, 0);
    // Valid ARP-reply body at 22, where a two-unwrap parser would look.
    f.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]);
    f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // sender mac
    f.extend_from_slice(&[10, 0, 0, 42]); // sender ip
    f.extend_from_slice(&[0x00; 6]); // target mac
    f.extend_from_slice(&[10, 0, 0, 1]); // target ip
    assert_eq!(
        classify_arp(&f),
        ArpClassification::NotArp,
        "a double-tagged ARP reply must not be learned"
    );
}

#[test]
fn classify_arp_reply_8021ad_tagged() {
    // A single 0x88a8 (802.1ad) tagged ARP reply must be classified as a
    // Reply, not NotArp. Pre-#2150 parse_eth_offsets returned l3=14 with
    // ethertype 0x88a8, so classify_arp saw a non-ARP ethertype.
    let mut f = build_eth_arp_reply(true);
    // Rewrite the outer TPID from 0x8100 to 0x88a8.
    f[12] = 0x88;
    f[13] = 0xa8;
    match classify_arp(&f) {
        ArpClassification::Reply(r) => {
            assert_eq!(r.sender_mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
            assert_eq!(r.sender_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)));
        }
        other => panic!("expected Reply for 0x88a8-tagged ARP, got {:?}", other),
    }
}

/// Build an NDP NA frame with an arbitrary IPv6 extension-header chain
/// between the base IPv6 header and the ICMPv6 NA. Each `(next_header,
/// payload_len_units)` entry emits one ext header whose `next_header`
/// byte points at the following header (or 58 for the final, pointing at
/// ICMPv6).
fn build_ndp_na_with_ext_chain(ext_chain: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst mac
    f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // src mac
    f.extend_from_slice(&0x86ddu16.to_be_bytes()); // IPv6 ethertype

    // Build the ext-header block first so we know payload_len.
    let mut ext_block = Vec::new();
    for (i, &ext_type) in ext_chain.iter().enumerate() {
        // Each ext header is the minimal 8 bytes: next_header, hdr_ext_len=0,
        // then 6 bytes of padding/options.
        let next = if i + 1 < ext_chain.len() {
            ext_chain[i + 1]
        } else {
            NEXT_HEADER_ICMPV6
        };
        ext_block.push(next); // next header
        ext_block.push(0); // hdr ext len = 0 → header is 8 bytes
        ext_block.extend_from_slice(&[0u8; 6]); // pad to 8 bytes
        let _ = ext_type; // ext_type is informational; layout is uniform
    }

    // ICMPv6 NA: type, code, csum, flags(4), target(16), TLLA option(8) = 32.
    let mut na = Vec::new();
    na.push(ICMPV6_TYPE_NA);
    na.push(0); // code
    na.extend_from_slice(&[0x00, 0x00]); // checksum placeholder (stamped below)
    na.extend_from_slice(&[0u8; 4]); // flags
    na.extend_from_slice(&[
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x42,
    ]); // target
    na.push(NDP_OPT_TARGET_LL);
    na.push(1); // len ×8 = 8
    na.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // MAC

    let payload_len = (ext_block.len() + na.len()) as u16;

    // base IPv6 header
    f.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // ver+tc+flow
    f.extend_from_slice(&payload_len.to_be_bytes());
    // next-header = first ext header type, or ICMPv6 if no ext headers
    f.push(*ext_chain.first().unwrap_or(&NEXT_HEADER_ICMPV6));
    f.push(255); // hop limit
    f.extend_from_slice(&[
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x01,
    ]); // src
    f.extend_from_slice(&[0xff; 16]); // dst

    f.extend_from_slice(&ext_block);
    let l4_start = f.len();
    f.extend_from_slice(&na);
    // ext chain sits between the base IPv6 header (l3=14) and the NA;
    // the NA's L4 start is wherever the chain ends. The declared packet
    // end is l3 + 40 + payload_len = end of frame here.
    let packet_end = f.len();
    stamp_icmpv6_checksum(&mut f, 14, l4_start, packet_end);
    f
}

#[test]
fn parse_ndp_na_behind_hop_by_hop() {
    // NDP NA behind a single hop-by-hop (next_header 0) extension header.
    // Pre-#2150 this returned None (fixed l3+40 read the HBH bytes, not
    // ICMPv6). The fix walks the chain and finds the NA at l3+48.
    let f = build_ndp_na_with_ext_chain(&[0]); // 0 = hop-by-hop
    let r = parse_ndp_neighbor_advert(&f).expect("NA behind HBH must parse");
    assert_eq!(
        r.target_ip,
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0xabcd, 0xef01, 0, 0x42)),
    );
    assert_eq!(r.target_mac, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
}

#[test]
fn parse_ndp_na_behind_dest_options() {
    // Destination-options (60) ext header.
    let f = build_ndp_na_with_ext_chain(&[60]);
    let r = parse_ndp_neighbor_advert(&f).expect("NA behind dest-opts must parse");
    assert_eq!(r.target_mac, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
}

#[test]
fn ipv6_walk_canary_learning_agrees_with_forwarding() {
    // For every ext-header chain, the learning NDP walk must land on the
    // same L4 offset as the shared #2148 forwarding walker.
    let chains: &[&[u8]] = &[
        &[],       // no ext headers
        &[0],      // hop-by-hop
        &[60],     // dest-options
        &[0, 60],  // HBH + dest-opts
        &[43],     // routing
        &[0, 60, 43], // 3-deep, within the 6-iteration bound
    ];
    for chain in chains {
        let f = build_ndp_na_with_ext_chain(chain);
        let (l3, _) = parse_eth_offsets(&f).expect("L2 parses");
        // Forwarding walker authority (L3-relative).
        let l3_slice = &f[l3..];
        let (rel_l4, proto) = crate::afxdp::frame::packet_rel_l4_offset_and_protocol(
            l3_slice,
            libc::AF_INET6 as u8,
        )
        .expect("forwarding walker finds L4");
        assert_eq!(proto, NEXT_HEADER_ICMPV6, "terminal proto must be ICMPv6");
        // The learning parser must accept the same frame (proving it walks
        // to the same ICMPv6 the forwarding path found).
        let r = parse_ndp_neighbor_advert(&f)
            .unwrap_or_else(|| panic!("learning parser missed NA for chain {chain:?}"));
        assert_eq!(r.target_mac, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        // Sanity: the forwarding L4 offset points at the ICMPv6 type byte.
        assert_eq!(f[l3 + rel_l4], ICMPV6_TYPE_NA);
    }
}

#[test]
fn parse_ndp_na_truncated_ext_chain_no_panic() {
    // An NA whose ext chain is truncated before the ICMPv6 header must
    // return None, never panic / read OOB.
    let mut f = build_ndp_na_with_ext_chain(&[0]);
    // Truncate inside the ICMPv6 NA body (keep base + HBH + a few bytes).
    f.truncate(14 + 40 + 8 + 4);
    assert!(parse_ndp_neighbor_advert(&f).is_none());
}

// ---------------------------------------------------------------------------
// #2368 — RFC 4861 §7.1.2 NA validation + payload_len-bounded option walk.
//
// These are fail-on-revert security tests: each MUST fail (the neighbor
// cache is poisoned) if the corresponding validity check is removed, and
// the valid-NA test MUST fail if the validation is too strict.
// ---------------------------------------------------------------------------

#[test]
fn parse_ndp_na_2368_valid_na_still_learns() {
    // Anti-over-reject: a well-formed NA (hop-limit 255, code 0, valid
    // ICMPv6 checksum, TLLA within payload_len) MUST still learn the MAC.
    // Fails if the §7.1.2 validation is too strict (e.g. checksum logic
    // inverted) → legitimate IPv6 neighbor resolution would break.
    let f = build_eth_ndp_na_full(false, true, 255, 0, false);
    let r = parse_ndp_neighbor_advert(&f).expect("valid NA must still parse");
    assert_eq!(r.target_mac, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
}

#[test]
fn parse_ndp_na_2368_valid_na_vlan_still_learns() {
    // Same anti-over-reject check on a VLAN-tagged NA (l3 at 18).
    let f = build_eth_ndp_na_full(true, true, 255, 0, false);
    let r = parse_ndp_neighbor_advert(&f).expect("valid VLAN NA must still parse");
    assert_eq!(r.target_mac, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
}

#[test]
fn parse_ndp_na_2368_rejects_hop_limit_below_255() {
    // RFC 4861 §7.1.2: an NA with Hop Limit < 255 was forwarded by a
    // router and is therefore off-link — MUST NOT be learned. Fails (the
    // cache is poisoned by an off-link impersonator) if the hop-limit
    // gate is removed.
    let f = build_eth_ndp_na_full(false, true, 254, 0, false);
    assert!(
        parse_ndp_neighbor_advert(&f).is_none(),
        "NA with hop-limit 254 must not be learned"
    );
}

#[test]
fn parse_ndp_na_2368_rejects_nonzero_code() {
    // RFC 4861 §7.1.2: ICMPv6 Code MUST be 0. Fails if the code gate is
    // removed.
    let f = build_eth_ndp_na_full(false, true, 255, 1, false);
    assert!(
        parse_ndp_neighbor_advert(&f).is_none(),
        "NA with ICMPv6 code 1 must not be learned"
    );
}

#[test]
fn parse_ndp_na_2368_rejects_bad_checksum() {
    // RFC 4443: a valid ICMPv6 checksum is required. Corrupt the stamped
    // checksum and confirm the NA is rejected. Fails if the checksum
    // validation is removed.
    let mut f = build_eth_ndp_na_full(false, true, 255, 0, false);
    let l4_start = 14 + 40;
    // Flip the checksum field so it no longer matches the message.
    f[l4_start + 2] ^= 0xff;
    f[l4_start + 3] ^= 0xff;
    assert!(
        parse_ndp_neighbor_advert(&f).is_none(),
        "NA with a bad ICMPv6 checksum must not be learned"
    );
}

#[test]
fn parse_ndp_na_2368_rejects_multicast_target() {
    // RFC 4861 §7.1.2: the Target Address MUST NOT be multicast. Fails if
    // the multicast-target gate is removed.
    let f = build_eth_ndp_na_full(false, true, 255, 0, true);
    assert!(
        parse_ndp_neighbor_advert(&f).is_none(),
        "NA with a multicast Target Address must not be learned"
    );
}

#[test]
fn parse_ndp_na_2368_tlla_past_payload_len_not_read() {
    // #2368 (B): a frame declares payload_len covering ONLY the fixed NA
    // header (24 bytes, no TLLA), then appends a forged TLLA option in
    // the Ethernet trailer beyond `40 + payload_len`. The option walk
    // MUST be bounded by the IPv6-declared packet end, not raw_frame.len(),
    // so the trailer TLLA is NOT read as a link-layer address.
    //
    // Fails (the trailer MAC is learned) if the walk bound reverts to
    // frame.len().
    let mut f = build_eth_ndp_na_full(false, false, 255, 0, false); // no TLLA, payload_len=24
    // The stamped checksum already covers exactly l4..l3+40+24. Append a
    // forged TLLA option as pure Ethernet trailer (outside payload_len).
    f.push(NDP_OPT_TARGET_LL);
    f.push(1);
    f.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]); // attacker MAC
    let r = parse_ndp_neighbor_advert(&f).expect("base NA (no in-bounds TLLA) still parses");
    assert_eq!(
        r.target_mac, None,
        "a TLLA option in the trailer beyond payload_len must not be learned"
    );
}

#[test]
fn parse_ndp_na_2368_rejects_payload_len_overrunning_frame() {
    // A declared payload_len longer than the actual frame must be
    // rejected (packet_end > raw_frame.len()), never read OOB.
    let mut f = build_eth_ndp_na_full(false, true, 255, 0, false);
    // Inflate payload_len well past the real frame length.
    f[14 + 4..14 + 6].copy_from_slice(&0xffffu16.to_be_bytes());
    assert!(
        parse_ndp_neighbor_advert(&f).is_none(),
        "NA whose declared payload_len overruns the frame must be rejected"
    );
}

// ---------------------------------------------------------------------------
// #9893 — RFC 6980 fragment refusal + IPv6-source validation for NA learns.
//
// Fail-on-revert: each refusal cell MUST fail (the poisoned learn succeeds)
// if its gate is removed, and the still-learns cells MUST fail if the gates
// over-reject. Counter cells hold `ndp_na_refusal_counter_test_lock` across
// the before/after window so a parallel sibling cannot move the process-wide
// count inside it.
// ---------------------------------------------------------------------------

use std::sync::atomic::Ordering;

/// Build an untagged NA behind a single IPv6 Fragment header (44).
/// `frag_off_field` is the raw bytes-2..4 value (offset<<3 | res | M).
fn build_eth_ndp_na_behind_fragment(frag_off_field: u16) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    f.extend_from_slice(&[0x86, 0xdd]);
    let l3_start = 14usize;
    // payload = frag hdr (8) + NA (24) + TLLA (8) = 40.
    let payload_len = 40u16;
    f.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    f.extend_from_slice(&payload_len.to_be_bytes());
    f.push(44); // next = Fragment
    f.push(255); // hop limit
    f.extend_from_slice(&[
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x01,
    ]);
    f.extend_from_slice(&[0xff; 16]);
    // Fragment header: next=58, reserved=0, off/res/M, ident.
    f.push(NEXT_HEADER_ICMPV6);
    f.push(0);
    f.extend_from_slice(&frag_off_field.to_be_bytes());
    f.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    let l4_start = l3_start + 40 + 8;
    f.push(ICMPV6_TYPE_NA);
    f.push(0);
    f.extend_from_slice(&[0x00, 0x00]);
    f.extend_from_slice(&[0; 4]);
    f.extend_from_slice(&[
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x01, 0x00, 0x00, 0x00, 0x42,
    ]);
    f.push(NDP_OPT_TARGET_LL);
    f.push(1);
    f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    let packet_end = l3_start + 40 + payload_len as usize;
    stamp_icmpv6_checksum(&mut f, l3_start, l4_start, packet_end);
    f
}

#[test]
fn parse_ndp_na_9893_non_first_fragment_refused_and_counted() {
    // offset=1 (field 0x0008), M=0 — a non-first fragment per RFC 8200 §4.5,
    // the exact shape the shim diverts to AF_XDP as a flowless session miss.
    let _g = ndp_na_refusal_counter_test_lock();
    let f = build_eth_ndp_na_behind_fragment(0x0008);
    let frag_before = NDP_NA_FRAG_REFUSED.load(Ordering::Relaxed);
    let src_before = NDP_NA_BAD_SOURCE_REFUSED.load(Ordering::Relaxed);
    assert!(
        parse_ndp_neighbor_advert(&f).is_none(),
        "NA behind a non-first fragment must be refused (RFC 6980 §5 MUST)"
    );
    assert_eq!(
        NDP_NA_FRAG_REFUSED.load(Ordering::Relaxed),
        frag_before + 1,
        "the fragment refusal must be counted exactly once"
    );
    assert_eq!(
        NDP_NA_BAD_SOURCE_REFUSED.load(Ordering::Relaxed),
        src_before,
        "a fragment refusal must not pollute the bad-source series"
    );
    assert_eq!(
        crate::afxdp::coordinator::Coordinator::new().ndp_na_frag_refused_total(),
        frag_before + 1,
        "the fragment refusal must be readable through the coordinator status surface"
    );
}

#[test]
fn parse_ndp_na_9893_first_and_atomic_fragments_refused() {
    // RFC 6980 refuses ANY Fragment header — first (offset 0, M=1) and atomic
    // (offset 0, M=0) alike, not just non-first. Both carry a fully valid
    // NA otherwise (hop-limit 255, code 0, good checksum).
    let _g = ndp_na_refusal_counter_test_lock();
    for (name, field) in [("first", 0x0001u16), ("atomic", 0x0000u16)] {
        let f = build_eth_ndp_na_behind_fragment(field);
        assert!(
            parse_ndp_neighbor_advert(&f).is_none(),
            "NA behind a {name} fragment must be refused (RFC 6980 covers all)"
        );
    }
}

#[test]
fn parse_ndp_na_9893_bad_source_refused_and_counted() {
    let _g = ndp_na_refusal_counter_test_lock();
    let status_before =
        crate::afxdp::coordinator::Coordinator::new().ndp_na_bad_source_refused_total();
    for (name, src) in [
        ("unspecified", [0u8; 16]),
        ("loopback", [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        (
            "multicast",
            [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ),
    ] {
        let mut f = build_eth_ndp_na_full(false, true, 255, 0, false);
        f[14 + 8..14 + 24].copy_from_slice(&src);
        let packet_end = 14 + 40 + 32;
        stamp_icmpv6_checksum(&mut f, 14, 14 + 40, packet_end);
        let src_before = NDP_NA_BAD_SOURCE_REFUSED.load(Ordering::Relaxed);
        let frag_before = NDP_NA_FRAG_REFUSED.load(Ordering::Relaxed);
        assert!(
            parse_ndp_neighbor_advert(&f).is_none(),
            "NA with {name} IPv6 source must be refused (on-link unicast required)"
        );
        assert_eq!(
            NDP_NA_BAD_SOURCE_REFUSED.load(Ordering::Relaxed),
            src_before + 1,
            "the {name}-source refusal must be counted exactly once"
        );
        assert_eq!(
            NDP_NA_FRAG_REFUSED.load(Ordering::Relaxed),
            frag_before,
            "a source refusal must not pollute the fragment series"
        );
    }
    assert_eq!(
        crate::afxdp::coordinator::Coordinator::new().ndp_na_bad_source_refused_total(),
        status_before + 3,
        "the bad-source refusals must be readable through the coordinator status surface"
    );
}

#[test]
fn parse_ndp_na_9893_valid_unfragmented_na_still_learns() {
    // Anti-over-reject: a well-formed unfragmented NA from a valid source
    // must still parse — the two new gates must not break legit resolution.
    // (The #2368 goldens pin the same frame; this cell owns the #9893 pair.)
    let _g = ndp_na_refusal_counter_test_lock();
    let f = build_eth_ndp_na_full(false, true, 255, 0, false);
    let frag_before = NDP_NA_FRAG_REFUSED.load(Ordering::Relaxed);
    let src_before = NDP_NA_BAD_SOURCE_REFUSED.load(Ordering::Relaxed);
    let r = parse_ndp_neighbor_advert(&f).expect("valid NA must still parse");
    assert_eq!(r.target_mac, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
    assert_eq!(
        NDP_NA_FRAG_REFUSED.load(Ordering::Relaxed),
        frag_before,
        "a valid learn must not bump the fragment series"
    );
    assert_eq!(
        NDP_NA_BAD_SOURCE_REFUSED.load(Ordering::Relaxed),
        src_before,
        "a valid learn must not bump the bad-source series"
    );
}

#[test]
fn parse_ndp_na_9893_hbh_without_fragment_still_learns() {
    // The fragment gate must not over-reject NON-fragment extension headers:
    // an NA behind hop-by-hop (the #2150 shape) still learns and does not
    // count as a fragment refusal.
    let _g = ndp_na_refusal_counter_test_lock();
    let f = build_ndp_na_with_ext_chain(&[0]);
    let frag_before = NDP_NA_FRAG_REFUSED.load(Ordering::Relaxed);
    let r = parse_ndp_neighbor_advert(&f).expect("NA behind HBH must still parse after #9893");
    assert_eq!(r.target_mac, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
    assert_eq!(
        NDP_NA_FRAG_REFUSED.load(Ordering::Relaxed),
        frag_before,
        "an HBH (non-fragment) chain must not bump the fragment series"
    );
}

#[test]
fn parse_ndp_na_9893_non_na_fragment_does_not_pollute_counter() {
    // The per-packet probe sees ALL fragmented transit. A fragmented UDP
    // frame (terminal proto 17, not NA) must return None WITHOUT bumping
    // the NDP fragment series — the gate fires only for NA-shaped frames.
    let _g = ndp_na_refusal_counter_test_lock();
    let mut f = Vec::new();
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    f.extend_from_slice(&[0x86, 0xdd]);
    f.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    f.extend_from_slice(&16u16.to_be_bytes()); // frag(8) + udp(8)
    f.push(44); // next = Fragment
    f.push(64); // hop limit (transit, not NDP)
    f.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    f.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    f.push(17); // frag next = UDP
    f.push(0);
    f.extend_from_slice(&0x0008u16.to_be_bytes()); // non-first
    f.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    f.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    let frag_before = NDP_NA_FRAG_REFUSED.load(Ordering::Relaxed);
    assert!(
        parse_ndp_neighbor_advert(&f).is_none(),
        "a fragmented UDP frame is not an NA"
    );
    assert_eq!(
        NDP_NA_FRAG_REFUSED.load(Ordering::Relaxed),
        frag_before,
        "non-NA fragmented transit must not pollute the NDP series"
    );
}
