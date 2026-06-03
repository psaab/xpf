// #1748: ntuple UAPI layout tests + a NIC-gated live insert/list/delete
// round-trip. The compile-time `const _: () = assert!` checks in ntuple.rs
// already gate the build on the struct sizes/offsets; these `#[test]`s
// restate the critical sizes so a `cargo test` failure names the exact
// drifted field, and exercise the spec-builder byte encoding.

use super::*;
use std::mem::{offset_of, size_of};

#[test]
fn uapi_struct_sizes_match_kernel() {
    assert_eq!(size_of::<EthtoolTcpip4Spec>(), 16, "ethtool_tcpip4_spec");
    assert_eq!(size_of::<EthtoolTcpip6Spec>(), 40, "ethtool_tcpip6_spec");
    assert_eq!(size_of::<EthtoolFlowUnion>(), 52, "ethtool_flow_union");
    assert_eq!(size_of::<EthtoolFlowExt>(), 20, "ethtool_flow_ext");
    assert_eq!(size_of::<EthtoolRxFlowSpec>(), 168, "ethtool_rx_flow_spec");
    assert_eq!(size_of::<EthtoolRxnfc>(), 192, "ethtool_rxnfc");
}

#[test]
fn uapi_rx_flow_spec_offsets_match_kernel() {
    assert_eq!(offset_of!(EthtoolRxFlowSpec, flow_type), 0);
    assert_eq!(offset_of!(EthtoolRxFlowSpec, h_u), 4);
    assert_eq!(offset_of!(EthtoolRxFlowSpec, h_ext), 56);
    assert_eq!(offset_of!(EthtoolRxFlowSpec, m_u), 76);
    assert_eq!(offset_of!(EthtoolRxFlowSpec, m_ext), 128);
    assert_eq!(offset_of!(EthtoolRxFlowSpec, ring_cookie), 152);
    assert_eq!(offset_of!(EthtoolRxFlowSpec, location), 160);
}

#[test]
fn uapi_rxnfc_offsets_match_kernel() {
    assert_eq!(offset_of!(EthtoolRxnfc, cmd), 0);
    assert_eq!(offset_of!(EthtoolRxnfc, flow_type), 4);
    assert_eq!(offset_of!(EthtoolRxnfc, data), 8);
    assert_eq!(offset_of!(EthtoolRxnfc, fs), 16);
    assert_eq!(offset_of!(EthtoolRxnfc, rule_cnt), 184);
    assert_eq!(offset_of!(EthtoolRxnfc, rule_locs), 188);
}

/// #1748 review #7: list_locs reads the flexible rule_locs[] array from the
/// FIELD offset (188), NOT size_of::<EthtoolRxnfc>() (192). Reading from 192
/// would skip the first returned location. This pins the offset list_locs
/// uses against the size, which differ by the 4-byte trailing alignment pad.
#[test]
fn rule_locs_field_offset_is_not_struct_size() {
    assert_eq!(offset_of!(EthtoolRxnfc, rule_locs), 188);
    assert_eq!(size_of::<EthtoolRxnfc>(), 192);
    assert_ne!(
        offset_of!(EthtoolRxnfc, rule_locs),
        size_of::<EthtoolRxnfc>(),
        "list_locs must read from the field offset (188), not the struct size (192)"
    );
}

#[test]
fn build_flow_spec_tcp4_exact_match_encoding() {
    let flow = FlowSpec5Tuple {
        proto: FlowProto::Tcp4,
        // 10.0.61.102 -> 172.16.80.200 in network order.
        src_ip: [u32::from_be_bytes([10, 0, 61, 102]), 0, 0, 0],
        dst_ip: [u32::from_be_bytes([172, 16, 80, 200]), 0, 0, 0],
        src_port: 12345u16.to_be(),
        dst_port: 5210u16.to_be(),
    };
    let fs = build_flow_spec(&flow, 3);
    assert_eq!(fs.flow_type, TCP_V4_FLOW);
    assert_eq!(fs.ring_cookie, 3, "ring_cookie carries the queue index");
    // #1751: build_flow_spec leaves location 0; insert_rule sets a concrete
    // free slot (mlx5 rejects RX_CLS_LOC_ANY).
    assert_eq!(fs.location, 0, "location is set by insert_rule, not build_flow_spec");

    // Decode the tcp_ip4_spec back out of the h_u union bytes.
    let ip4src = u32::from_ne_bytes(fs.h_u.hdata[0..4].try_into().unwrap());
    let ip4dst = u32::from_ne_bytes(fs.h_u.hdata[4..8].try_into().unwrap());
    let psrc = u16::from_ne_bytes(fs.h_u.hdata[8..10].try_into().unwrap());
    let pdst = u16::from_ne_bytes(fs.h_u.hdata[10..12].try_into().unwrap());
    assert_eq!(ip4src, flow.src_ip[0]);
    assert_eq!(ip4dst, flow.dst_ip[0]);
    assert_eq!(psrc, flow.src_port);
    assert_eq!(pdst, flow.dst_port);

    // #1748 live BLOCKER A: the INPUT mask is DIRECT (1 = match), so an exact
    // 5-tuple match sets ip4src/ip4dst masks to 0xffff_ffff and psrc/pdst masks
    // to 0xffff, with the tos mask 0 (a non-zero tos mask makes mlx5 EINVAL).
    let m_ip4src = u32::from_ne_bytes(fs.m_u.hdata[0..4].try_into().unwrap());
    let m_ip4dst = u32::from_ne_bytes(fs.m_u.hdata[4..8].try_into().unwrap());
    let m_psrc = u16::from_ne_bytes(fs.m_u.hdata[8..10].try_into().unwrap());
    let m_pdst = u16::from_ne_bytes(fs.m_u.hdata[10..12].try_into().unwrap());
    let m_tos = fs.m_u.hdata[12];
    assert_eq!(m_ip4src, 0xffff_ffff, "src-ip mask must be all-ones (match)");
    assert_eq!(m_ip4dst, 0xffff_ffff, "dst-ip mask must be all-ones (match)");
    assert_eq!(m_psrc, 0xffff, "src-port mask must be all-ones (match)");
    assert_eq!(m_pdst, 0xffff, "dst-port mask must be all-ones (match)");
    assert_eq!(m_tos, 0, "tos mask MUST be 0 (mlx5 rejects a non-zero tos mask)");
}

#[test]
fn build_flow_spec_tcp6_uses_v6_flow_type() {
    let flow = FlowSpec5Tuple {
        proto: FlowProto::Tcp6,
        src_ip: [1, 2, 3, 4],
        dst_ip: [5, 6, 7, 8],
        src_port: 1000u16.to_be(),
        dst_port: 2000u16.to_be(),
    };
    let fs = build_flow_spec(&flow, 5);
    assert_eq!(fs.flow_type, TCP_V6_FLOW);
    assert_eq!(fs.ring_cookie, 5);
    let ip6src0 = u32::from_ne_bytes(fs.h_u.hdata[0..4].try_into().unwrap());
    assert_eq!(ip6src0, 1);
    // src+dst (32 B) addr mask is all-ones (1 = match), and the tclass mask
    // (byte 36) is 0 — the v6 analogue of the tos-mask-must-be-0 rule.
    assert_eq!(&fs.m_u.hdata[0..32], &[0xffu8; 32], "v6 addr mask is all-ones");
    assert_eq!(fs.m_u.hdata[36], 0, "tclass mask must be 0");
}

/// Live insert -> GRXCLSRLALL readback -> delete round-trip. Gated to run
/// only where a NIC that supports flow steering is named via
/// `XPF_NTUPLE_TEST_IFACE`. Without it the test no-ops (CI / dev boxes with
/// no mlx5 VF). On a supporting NIC: enable `ethtool -K <if> ntuple on`
/// first. This validates the wire semantics the compile-time asserts cannot.
#[test]
fn live_insert_list_delete_round_trip() {
    let Ok(ifname) = std::env::var("XPF_NTUPLE_TEST_IFACE") else {
        eprintln!("live_insert_list_delete_round_trip: skipped (set XPF_NTUPLE_TEST_IFACE)");
        return;
    };
    let sock = NtupleSocket::open(&ifname).expect("open ethtool socket");
    let flow = FlowSpec5Tuple {
        proto: FlowProto::Tcp4,
        src_ip: [u32::from_be_bytes([10, 0, 61, 200]), 0, 0, 0],
        dst_ip: [u32::from_be_bytes([172, 16, 80, 250]), 0, 0, 0],
        src_port: 54321u16.to_be(),
        dst_port: 5210u16.to_be(),
    };
    let before = sock.list_locs().expect("list before");
    let loc = match sock.insert_rule(&flow, 0) {
        Ok(loc) => loc,
        Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => {
            eprintln!("live round-trip: NIC does not support ntuple (EOPNOTSUPP) — skipped");
            return;
        }
        Err(e) => panic!("insert_rule failed: {e}"),
    };
    let after = sock.list_locs().expect("list after");
    assert!(
        after.contains(&loc),
        "inserted rule loc {loc} must appear in GRXCLSRLALL readback: {after:?}"
    );
    assert_eq!(
        after.len(),
        before.len() + 1,
        "exactly one rule added"
    );
    // #1748 live BLOCKER A: read the rule back via GRXCLSRULE and assert the
    // DIRECT mask the driver stored — all-ones on the matched 5-tuple fields,
    // tos mask 0. (GRXCLSRULE returns the raw stored flow_spec, i.e. what we
    // passed in; ethtool(8)'s `-n` display COMPLEMENTS the mask for humans,
    // which is what an earlier round misread as "0.0.0.0 = match".)
    let fs = sock.get_rule(loc).expect("get_rule readback");
    let m_ip4src = u32::from_ne_bytes(fs.m_u.hdata[0..4].try_into().unwrap());
    let m_ip4dst = u32::from_ne_bytes(fs.m_u.hdata[4..8].try_into().unwrap());
    let m_psrc = u16::from_ne_bytes(fs.m_u.hdata[8..10].try_into().unwrap());
    let m_pdst = u16::from_ne_bytes(fs.m_u.hdata[10..12].try_into().unwrap());
    let m_tos = fs.m_u.hdata[12];
    assert_eq!(m_ip4src, 0xffff_ffff, "src-ip mask must be all-ones (match)");
    assert_eq!(m_ip4dst, 0xffff_ffff, "dst-ip mask must be all-ones (match)");
    assert_eq!(m_psrc, 0xffff, "src-port mask must be all-ones (match)");
    assert_eq!(m_pdst, 0xffff, "dst-port mask must be all-ones (match)");
    assert_eq!(m_tos, 0, "tos mask must be 0 (mlx5 rejects a non-zero tos mask)");
    sock.delete_rule(loc).expect("delete rule");
    let cleaned = sock.list_locs().expect("list after delete");
    assert!(
        !cleaned.contains(&loc),
        "deleted rule loc {loc} must be gone: {cleaned:?}"
    );
}

// ── #1751: ethtool-compatible free-location picker ─────────────────────

/// find_empty_slot_top_down picks the highest free location (ethtool order,
/// which is why a manual insert on an empty table lands at size-1), skips used
/// locations, and a "delete" (removing a loc from the used set) frees it.
#[test]
fn find_empty_slot_top_down_picks_highest_free_and_frees_on_delete() {
    let size = 1024u32;

    // Empty table -> the very top slot (matches the live `ethtool -N` = 1023).
    assert_eq!(find_empty_slot_top_down(size, &[]), Some(1023));

    // With 1023 used, the next pick is 1022 (top-down).
    assert_eq!(find_empty_slot_top_down(size, &[1023]), Some(1022));

    // Used set need not be sorted/contiguous; pick the highest free.
    let mut used = vec![1023u32, 1022, 1020];
    assert_eq!(
        find_empty_slot_top_down(size, &used),
        Some(1021),
        "1021 is the highest free location"
    );

    // "Install" 1021, then "delete" 1022 (free it): the next pick is the
    // freed 1022 (now the highest free).
    used.push(1021);
    assert_eq!(find_empty_slot_top_down(size, &used), Some(1019));
    used.retain(|&l| l != 1022); // delete frees 1022
    assert_eq!(
        find_empty_slot_top_down(size, &used),
        Some(1022),
        "deleting a loc frees it for the next pick"
    );
}

/// A full location space yields None (caller maps to ENOSPC); a zero size
/// falls back to the mlx5 default depth (1024).
#[test]
fn find_empty_slot_top_down_full_and_zero_size() {
    // Tiny full table: size 2, both used -> None.
    assert_eq!(find_empty_slot_top_down(2, &[0, 1]), None);
    // size 2, only 1 used -> the other.
    assert_eq!(find_empty_slot_top_down(2, &[1]), Some(0));
    // size 0 falls back to 1024 depth -> top slot 1023 when empty.
    assert_eq!(find_empty_slot_top_down(0, &[]), Some(1023));
}

/// RX_CLS_LOC_SPECIAL flag bits on a returned location do not make a candidate
/// miss-compare (defensive mask in the picker).
#[test]
fn find_empty_slot_top_down_masks_special_flag() {
    // A used entry with the SPECIAL flag set still occupies its concrete slot.
    let used = vec![0x8000_0000u32 | 1023];
    assert_eq!(find_empty_slot_top_down(1024, &used), Some(1022));
}
