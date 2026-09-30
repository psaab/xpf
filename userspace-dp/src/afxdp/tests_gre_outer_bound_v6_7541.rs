//! #7541: the #6748 outer-datagram bound, exercised with an IPv6 OUTER.
//!
//! #6748's decap-level cells are IPv4-only, because every GRE frame builder in
//! the crate wrote an IPv4 outer. The bound's ARITHMETIC is unit-tested for both
//! families (`outer_datagram_end_reads_both_families_and_refuses_overdeclaration_6748`),
//! but no v6 frame was ever decapped end-to-end — so a regression in how a v6
//! outer REACHES that function had no cell: a wrong `l3_offset` for a v6
//! underlay, an extension-header assumption, a `parse_outer_addresses` mismatch.
//!
//! These cells mirror the three #6748 decap cells on a v6 outer, asserting the
//! SAME properties rather than a parallel set that happens to pass. Each keeps
//! #6748's negative control: trailers are ordinary (Ethernet min-frame padding
//! puts one on every small frame), so without it "bound by the outer datagram"
//! is indistinguishable from "reject trailing bytes", and the second blackholes
//! legitimate GRE.
//!
//! ONE AXIS CHANGES. The inner stays IPv4 in every cell here, exactly as in
//! #6748, so any difference in outcome isolates the OUTER family. A v6 inner is
//! a different question with its own extraction path.
//!
//! THE FIXTURE ARITHMETIC IS NOT THE IPv4 ONE. The v6 outer end is
//! `l3 + 40 + Payload Length`, and Payload Length EXCLUDES the 40-byte header,
//! where IPv4's Total Length INCLUDES its own 20. A premise check copied from
//! the v4 cells would compare against the wrong quantity — and, because the
//! frame is self-consistent either way, would pass while asserting nothing.

use super::tests_support::*;
use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::gre::try_native_gre_decap_from_frame;

const TRAILER_BYTE: u8 = 0xAA;
const TRAILER_LEN: usize = 16;

/// Rewrite an IPv4 packet's Total Length and fix its header checksum. Same as
/// the #6748 helper — the INNER is IPv4 in both families' cells.
fn set_inner_total_len(packet: &mut [u8], total: u16) {
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    packet[10] = 0;
    packet[11] = 0;
    let sum = checksum16(&packet[0..20]);
    packet[10] = (sum >> 8) as u8;
    packet[11] = sum as u8;
}

/// Assert the fixture is actually in the state under test, in v6 terms.
///
/// This is the guard against a cell that passes without reaching the code it
/// was written for: a decap refused for an unrelated reason (endpoint did not
/// resolve, meta was wrong, family mismatch) would otherwise read as the bound
/// working.
fn assert_v6_fixture_premises(frame: &[u8], outer_end: usize, l3: usize) {
    let payload_len = u16::from_be_bytes([frame[l3 + 4], frame[l3 + 5]]) as usize;
    assert_eq!(
        payload_len,
        outer_end - l3 - 40,
        "fixture: the v6 Payload Length must describe the datagram WITHOUT the trailer, \
         and it EXCLUDES the 40-byte header (this is where a copied IPv4 premise check \
         would silently compare the wrong quantity)",
    );
    assert_eq!(frame[l3] >> 4, 6, "fixture: the outer must be IPv6");
    assert_eq!(
        frame[l3 + 6], PROTO_GRE,
        "fixture: the v6 Next Header must be GRE, or decap never reaches the bound",
    );
    assert!(
        frame.len() > outer_end,
        "fixture: the trailer must actually sit past the outer datagram",
    );
}

/// A v6-outer frame must decap AT ALL before any bound cell means anything.
///
/// Without this, every cell below could pass because a v6 outer never resolves
/// its endpoint — refusal for the wrong reason reading as the bound holding.
/// This is the cell that makes the other three non-vacuous, and it is also the
/// cell that would have told us #7541 was a CODE gap rather than a fixture gap.
#[test]
fn gre_decap_accepts_a_plain_v6_outer_frame_7541() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot_v6());
    let honest = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_to_self_outer_frame_v6(0, &honest);
    let meta = gre_to_self_outer_meta_v6(0, frame.len());

    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding).expect(
        "a well-formed IPv6-outer GRE frame must decap. If this fails, #7541 is a CODE \
         gap and not a fixture gap, and every other cell in this file is vacuous.",
    );
    assert_eq!(
        &decap.frame[decap.meta.l3_offset as usize..],
        &honest[..],
        "the decapped inner must be byte-identical to the authored one",
    );
}

/// #7541 PRIMARY, mirroring
/// `gre_decap_refuses_an_inner_that_reaches_past_the_outer_datagram_6748`.
#[test]
fn gre_decap_v6_outer_refuses_an_inner_past_the_outer_datagram_7541() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot_v6());

    let honest = build_gre_inner_icmp_packet_v4();
    let mut lying = honest.clone();
    set_inner_total_len(&mut lying, (honest.len() + TRAILER_LEN) as u16);

    let mut frame = build_gre_to_self_outer_frame_v6(0, &lying);
    let outer_end = frame.len();
    frame.extend(std::iter::repeat_n(TRAILER_BYTE, TRAILER_LEN));
    assert_v6_fixture_premises(&frame, outer_end, 14);

    let meta = gre_to_self_outer_meta_v6(0, frame.len());
    if let Some(d) = try_native_gre_decap_from_frame(&frame, meta, &forwarding) {
        assert!(
            !d.frame.contains(&TRAILER_BYTE),
            "v6-outer decap PROMOTED bytes from outside the outer IP datagram. A peer that \
             appends a trailer and inflates the inner Total Length to cover it gets \
             attacker-chosen bytes into the packet the firewall then adjudicates and \
             forwards (#6748, v6 arm #7541).",
        );
        panic!(
            "v6-outer decap accepted a frame whose inner header declares {} bytes while the \
             outer datagram carries only {}. The inner extent must be bounded by the OUTER \
             datagram (l3 + 40 + Payload Length), and an inner header that lies about it is \
             refused, not clamped.",
            honest.len() + TRAILER_LEN,
            honest.len(),
        );
    }
}

/// #7541 NEGATIVE CONTROL. An HONEST inner under the same trailer must still
/// decap byte-identically on a v6 outer. Without this, the cell above is
/// satisfied by a build that rejects every v6 frame carrying trailing bytes —
/// which is an outage, not a fix.
#[test]
fn gre_decap_v6_outer_accepts_an_honest_inner_under_a_trailer_7541() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot_v6());
    let honest = build_gre_inner_icmp_packet_v4();

    let mut frame = build_gre_to_self_outer_frame_v6(0, &honest);
    let outer_end = frame.len();
    frame.extend(std::iter::repeat_n(TRAILER_BYTE, TRAILER_LEN));
    assert_v6_fixture_premises(&frame, outer_end, 14);

    let meta = gre_to_self_outer_meta_v6(0, frame.len());
    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding).expect(
        "an honest inner under trailing padding must still decap on a v6 outer — padding \
         is ordinary, and refusing it blackholes legitimate GRE",
    );
    assert_eq!(
        &decap.frame[decap.meta.l3_offset as usize..],
        &honest[..],
        "the decapped inner must be byte-identical to the authored one",
    );
    assert!(
        !decap.frame.contains(&TRAILER_BYTE),
        "the trailer must be trimmed, not carried",
    );
}

/// #7541 on the CHECKSUM-PRESENT path, mirroring
/// `gre_decap_checksum_present_honours_the_outer_bound_6748`. The option-field
/// skips move inside the outer bound too, so a checksummed v6 frame is subject
/// to the same rule — and must still accept an honest one, since
/// `gre_checksum_region` already excluded the trailer from the sum.
#[test]
fn gre_decap_v6_outer_checksum_present_honours_the_outer_bound_7541() {
    let mut snapshot = gre_to_self_snapshot_v6();
    snapshot.tunnel_endpoints[0].key = 42;
    let forwarding = build_forwarding_state(&snapshot);
    // C-bit + K-bit: option fields present. Use a nonzero matching key so
    // these controls remain valid under strict key-presence matching.
    const FLAGS: u16 = 0x8000 | 0x2000;

    // Refusal half.
    let honest = build_gre_inner_icmp_packet_v4();
    let mut lying = honest.clone();
    set_inner_total_len(&mut lying, (honest.len() + TRAILER_LEN) as u16);
    let mut frame = build_gre_checksum_present_outer_frame_v6(0, FLAGS, 42, 0, &lying);
    let outer_end = frame.len();
    frame.extend(std::iter::repeat_n(TRAILER_BYTE, TRAILER_LEN));
    assert_v6_fixture_premises(&frame, outer_end, 14);

    let meta = gre_to_self_outer_meta_v6(0, frame.len());
    if let Some(d) = try_native_gre_decap_from_frame(&frame, meta, &forwarding) {
        assert!(
            !d.frame.contains(&TRAILER_BYTE),
            "checksum-present v6-outer decap promoted out-of-datagram bytes",
        );
        panic!("checksum-present v6-outer decap accepted an over-declared inner");
    }

    // Acceptance half — the control that keeps the above from being a blanket
    // rejection of checksummed v6 frames with padding.
    let mut ok_frame = build_gre_checksum_present_outer_frame_v6(0, FLAGS, 42, 0, &honest);
    let ok_end = ok_frame.len();
    ok_frame.extend(std::iter::repeat_n(TRAILER_BYTE, TRAILER_LEN));
    assert_v6_fixture_premises(&ok_frame, ok_end, 14);

    let ok_meta = gre_to_self_outer_meta_v6(0, ok_frame.len());
    let decap = try_native_gre_decap_from_frame(&ok_frame, ok_meta, &forwarding).expect(
        "an honest inner under trailing padding must still decap on the checksum-present \
         v6 path — gre_checksum_region already excludes the trailer from the sum",
    );
    assert_eq!(
        &decap.frame[decap.meta.l3_offset as usize..],
        &honest[..],
        "the decapped inner must be byte-identical to the authored one",
    );
}
