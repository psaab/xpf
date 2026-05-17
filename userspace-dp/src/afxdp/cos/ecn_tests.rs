// Tests for afxdp/cos/ecn.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep ecn.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "ecn_tests.rs"]` from ecn.rs.

use super::*;
use crate::afxdp::PROTO_TCP;
use crate::afxdp::tx::test_support::*;

#[test]
fn mark_ecn_ce_ipv4_converts_ect0_to_ce_and_updates_checksum() {
    // ECT(0) = 0b10 in the low 2 bits of the TOS byte. Pick a
    // non-zero DSCP (0x28 = CS5 = expedited forwarding) to verify
    // the upper 6 bits survive the mark. TOS before = 0xa2.
    let tos = (0x28u8 << 2) | ECN_ECT_0;
    let mut pkt = build_ipv4_test_packet(tos);
    assert_eq!(ipv4_tos(&pkt), 0xa2);
    let csum_before = ipv4_checksum(&pkt);

    assert!(mark_ecn_ce_ipv4(&mut pkt, 14));

    // Low 2 bits now CE, upper 6 bits (DSCP) unchanged.
    assert_eq!(ipv4_tos(&pkt) & ECN_MASK, ECN_CE);
    assert_eq!(ipv4_tos(&pkt) >> 2, 0x28);
    // Checksum must differ from the before-state (ECN flipped one
    // bit in the low byte) AND be valid from scratch.
    assert_ne!(
        ipv4_checksum(&pkt),
        csum_before,
        "ECN bit flip must change the IP checksum",
    );
    assert_eq!(
        ipv4_checksum(&pkt),
        compute_ipv4_header_checksum(&pkt[14..34]),
        "incremental checksum must match a from-scratch recompute",
    );
}

#[test]
fn mark_ecn_ce_ipv4_converts_ect1_to_ce_and_updates_checksum() {
    // ECT(1) = 0b01. DSCP = 0, so TOS starts at 0x01 — stresses
    // the case where the high nibble is zero and only the low
    // bits mutate.
    let tos = ECN_ECT_1;
    let mut pkt = build_ipv4_test_packet(tos);

    assert!(mark_ecn_ce_ipv4(&mut pkt, 14));
    assert_eq!(ipv4_tos(&pkt), ECN_CE);
    assert_eq!(
        ipv4_checksum(&pkt),
        compute_ipv4_header_checksum(&pkt[14..34]),
    );
}

#[test]
fn mark_ecn_ce_ipv4_leaves_not_ect_untouched() {
    // NOT-ECT packet must be left entirely alone — RFC 3168 6.1.1.1
    // forbids forcing ECN on flows that did not negotiate it.
    let tos = 0xb8; // DSCP 46 (EF), ECN = 00
    let mut pkt = build_ipv4_test_packet(tos);
    let before = pkt.clone();

    assert!(!mark_ecn_ce_ipv4(&mut pkt, 14));
    assert_eq!(pkt, before, "NOT-ECT packet must be byte-identical");
}

#[test]
fn mark_ecn_ce_ipv4_leaves_ce_untouched() {
    // CE already — idempotent: function reports "not marked" but
    // also doesn't re-write the checksum, so bytes stay identical.
    let tos = 0xb8 | ECN_CE;
    let mut pkt = build_ipv4_test_packet(tos);
    let before = pkt.clone();

    assert!(!mark_ecn_ce_ipv4(&mut pkt, 14));
    assert_eq!(pkt, before, "CE packet must be byte-identical");
}

#[test]
fn mark_ecn_ce_ipv4_rejects_short_buffer() {
    // Buffer too short to hold a full 20-byte IPv4 header starting
    // at l3_offset=14 (only 33 bytes — one short). Must return
    // false and not panic.
    let mut pkt = vec![0u8; 33];
    assert!(!mark_ecn_ce_ipv4(&mut pkt, 14));

    // Also exercise the case where `l3_offset` itself pushes past
    // the buffer end.
    let mut pkt = vec![0u8; 16];
    assert!(!mark_ecn_ce_ipv4(&mut pkt, 14));
}

#[test]
fn mark_ecn_ce_ipv6_converts_ect0_to_ce() {
    // DSCP 46 (EF) + ECT(0) → full tclass 0xba.
    let tclass = (0x2eu8 << 2) | ECN_ECT_0;
    let mut pkt = build_ipv6_test_packet(tclass);
    assert_eq!(ipv6_tclass(&pkt), 0xba);
    // Preserve flow label / version bits for the round-trip check.
    let version_nibble_before = pkt[14] & 0xf0;
    let flow_label_low_before = pkt[15] & 0x0f;

    assert!(mark_ecn_ce_ipv6(&mut pkt, 14));
    assert_eq!(ipv6_tclass(&pkt) & ECN_MASK, ECN_CE);
    assert_eq!(ipv6_tclass(&pkt) >> 2, 0x2e);
    // Version + flow-label bits must not drift.
    assert_eq!(pkt[14] & 0xf0, version_nibble_before);
    assert_eq!(pkt[15] & 0x0f, flow_label_low_before);
}

#[test]
fn mark_ecn_ce_ipv6_converts_ect1_to_ce() {
    let tclass = ECN_ECT_1;
    let mut pkt = build_ipv6_test_packet(tclass);
    assert!(mark_ecn_ce_ipv6(&mut pkt, 14));
    assert_eq!(ipv6_tclass(&pkt), ECN_CE);
}

#[test]
fn mark_ecn_ce_ipv6_leaves_not_ect_untouched() {
    let tclass = 0xb8; // DSCP 46, ECN 00
    let mut pkt = build_ipv6_test_packet(tclass);
    let before = pkt.clone();
    assert!(!mark_ecn_ce_ipv6(&mut pkt, 14));
    assert_eq!(pkt, before);
}

#[test]
fn mark_ecn_ce_ipv6_leaves_ce_untouched() {
    let tclass = 0xb8 | ECN_CE;
    let mut pkt = build_ipv6_test_packet(tclass);
    let before = pkt.clone();
    assert!(!mark_ecn_ce_ipv6(&mut pkt, 14));
    assert_eq!(pkt, before);
}

#[test]
fn mark_ecn_ce_ipv6_rejects_short_buffer() {
    let mut pkt = vec![0u8; 15];
    assert!(!mark_ecn_ce_ipv6(&mut pkt, 14));
}

#[test]
fn maybe_mark_ecn_ce_dispatches_by_ethertype() {
    // IPv4 dispatch: ECT(0) → CE.
    let tos = ECN_ECT_0;
    let bytes = build_ipv4_test_packet(tos);
    let mut req = TxRequest {
        bytes,
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 1,
        cos_queue_id: Some(0),
        dscp_rewrite: None,
        mirror_clone: false,
    };
    assert!(maybe_mark_ecn_ce(&mut req));
    assert_eq!(req.bytes[15] & ECN_MASK, ECN_CE);

    // IPv6 dispatch: ECT(1) → CE.
    let tclass = ECN_ECT_1;
    let bytes = build_ipv6_test_packet(tclass);
    let mut req = TxRequest {
        bytes,
        expected_ports: None,
        expected_addr_family: libc::AF_INET6 as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 1,
        cos_queue_id: Some(0),
        dscp_rewrite: None,
        mirror_clone: false,
    };
    assert!(maybe_mark_ecn_ce(&mut req));
    assert_eq!(ipv6_tclass(&req.bytes), ECN_CE);

    // Unknown ethertype: no-op (and no panic). The all-zeros
    // packet has zero in the ethertype slot, so `ethernet_l3`
    // returns None and the marker bails. Note: dispatch is
    // driven by the parsed L2 ethertype, not by
    // `expected_addr_family` — that field is metadata only.
    let mut req = TxRequest {
        bytes: vec![0u8; 64],
        expected_ports: None,
        expected_addr_family: 0,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 1,
        cos_queue_id: Some(0),
        dscp_rewrite: None,
        mirror_clone: false,
    };
    assert!(!maybe_mark_ecn_ce(&mut req));
}

/// Regression pin for the VLAN-tagged admission path discovered in
/// the #727 live validation: a single 802.1Q tag (ethertype 0x8100)
/// pushes L3 four bytes deeper. `maybe_mark_ecn_ce` must detect
/// that via `ethernet_l3` and still mark the ECN bits at
/// the correct offset rather than stamping into the VLAN TCI.
#[test]
fn maybe_mark_ecn_ce_handles_single_vlan_tagged_frame() {
    // Build a standard IPv4 test packet, then splice a 4-byte VLAN
    // tag between the MAC addresses and the ethertype. The result
    // is: 6 dst + 6 src + TPID(0x8100) + TCI(VID=80, prio=5) +
    //     EthType(0x0800) + <20-byte IPv4 header>.
    let tos = ECN_ECT_0;
    let base = build_ipv4_test_packet(tos);
    let mut tagged = Vec::with_capacity(base.len() + 4);
    tagged.extend_from_slice(&base[..12]); // dst + src MAC
    tagged.extend_from_slice(&[0x81, 0x00]); // TPID
    // TCI: priority 5 << 13 | DEI 0 | VID 80.
    let tci: u16 = (5 << 13) | 80;
    tagged.extend_from_slice(&tci.to_be_bytes());
    tagged.extend_from_slice(&[0x08, 0x00]); // inner ethertype (IPv4)
    tagged.extend_from_slice(&base[14..]); // IPv4 header + payload

    // Confirm `ethernet_l3` parses IPv4 at offset 18 for this frame.
    assert_eq!(ethernet_l3(&tagged), Some(EthernetL3::Ipv4(18)));

    let mut req = TxRequest {
        bytes: tagged,
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 1,
        cos_queue_id: Some(4),
        dscp_rewrite: None,
        mirror_clone: false,
    };
    assert!(
        maybe_mark_ecn_ce(&mut req),
        "VLAN-tagged ECT(0) frame must be marked at the VLAN-shifted L3 offset"
    );
    // TOS byte sits at l3_offset + 1 = 19 in the tagged frame.
    assert_eq!(req.bytes[19] & ECN_MASK, ECN_CE);
    // And critically: the VLAN TCI bytes must NOT have been
    // mutated — if the old hardcoded offset 14 had hit, the "ECN
    // bits" we'd have touched are inside the VLAN priority nibble
    // at byte 15, which we assert stayed intact.
    let tci_after = u16::from_be_bytes([req.bytes[14], req.bytes[15]]);
    assert_eq!(tci_after, tci, "VLAN TCI must be untouched by ECN marking");
}

/// Counter-factual: ethertype 0 (or anything we don't understand)
/// returns `None` from `ethernet_l3`, so marking is a no-op.
/// Guards against a regression that defaults to offset 14 on
/// unknown frames.
#[test]
fn maybe_mark_ecn_ce_rejects_unknown_ethertype() {
    let mut req = TxRequest {
        bytes: {
            let mut b = build_ipv4_test_packet(ECN_ECT_0);
            b[12] = 0x12;
            b[13] = 0x34;
            b
        },
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 1,
        cos_queue_id: Some(0),
        dscp_rewrite: None,
        mirror_clone: false,
    };
    assert_eq!(ethernet_l3(&req.bytes), None);
    assert!(!maybe_mark_ecn_ce(&mut req));
    // ECT(0) bits at the would-have-been-wrong-offset untouched.
    assert_eq!(req.bytes[15] & ECN_MASK, ECN_ECT_0);
}

/// QinQ (0x88A8 outer + 0x8100 inner) must be rejected rather than
/// guessed at, because L3 actually lives at offset 22 on those
/// frames and a default to 18 would stamp into the inner VLAN TCI.
/// #728 review pin: once we've paid to parse the outer ethertype,
/// the parse must be the source of truth.
#[test]
fn ethernet_l3_rejects_qinq_until_explicitly_supported() {
    let base = build_ipv4_test_packet(ECN_ECT_0);
    let mut qinq = Vec::with_capacity(base.len() + 8);
    qinq.extend_from_slice(&base[..12]); // MACs
    // Outer 802.1ad: TPID 0x88A8, TCI with an outer VID 100.
    qinq.extend_from_slice(&[0x88, 0xA8]);
    let outer_tci: u16 = 100;
    qinq.extend_from_slice(&outer_tci.to_be_bytes());
    // Inner 802.1Q: TPID 0x8100 at the "inner ethertype" position.
    qinq.extend_from_slice(&[0x81, 0x00]);
    let inner_tci: u16 = 80;
    qinq.extend_from_slice(&inner_tci.to_be_bytes());
    qinq.extend_from_slice(&[0x08, 0x00]); // IPv4 (well beyond where we care)
    qinq.extend_from_slice(&base[14..]);

    assert_eq!(
        ethernet_l3(&qinq),
        None,
        "QinQ (0x88A8 → 0x8100) must be rejected — inner VLAN tag not yet supported"
    );

    // And the marker refuses such a frame — no ECN bits are flipped.
    let mut req = TxRequest {
        bytes: qinq,
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 1,
        cos_queue_id: Some(4),
        dscp_rewrite: None,
        mirror_clone: false,
    };
    assert!(!maybe_mark_ecn_ce(&mut req));
}

/// A VLAN-tagged frame whose inner ethertype is ARP / MPLS / etc.
/// must be rejected too, matching the `refuse to guess` contract.
/// Without this check we'd treat offset 18 as an IPv4 TOS byte and
/// stamp the low 2 bits of whatever is there (ARP's hardware type
/// in this case), corrupting the frame.
#[test]
fn ethernet_l3_rejects_vlan_tagged_non_ip_payload() {
    let base = build_ipv4_test_packet(ECN_ECT_0);
    let mut tagged = Vec::with_capacity(base.len() + 4);
    tagged.extend_from_slice(&base[..12]);
    tagged.extend_from_slice(&[0x81, 0x00]); // outer 802.1Q
    let tci: u16 = 80;
    tagged.extend_from_slice(&tci.to_be_bytes());
    tagged.extend_from_slice(&[0x08, 0x06]); // inner = ARP (0x0806)
    tagged.extend_from_slice(&base[14..]);
    assert_eq!(
        ethernet_l3(&tagged),
        None,
        "VLAN-tagged non-IP payload must not dispatch to an IP marker",
    );
}
