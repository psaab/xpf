//! #14645: outer-fragmented native GRE must reassemble before decap, and a
//! native-GRE local tail must not be passed to the kernel.

use super::tests_support::*;
use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::gre::try_native_gre_decap_from_frame;
use crate::afxdp::gre_reassembly::{GreReassembler, OfferAdmission, gre_outer_frag_counter_test_lock};

#[path = "../../../userspace-xdp/src/gre_classify.rs"]
mod shim_gre_classify;
#[path = "../../../userspace-xdp/src/tunnel_frag.rs"]
mod shim_tunnel_frag;
#[path = "../../../userspace-xdp/src/ipv6_ext_walk.rs"]
mod shim_walk;

fn split_v4_outer(frame: &[u8], split_payload: usize) -> (Vec<u8>, Vec<u8>) {
    let l3 = 14usize;
    let ihl = 20usize;
    let payload = &frame[l3 + ihl..];
    assert!(split_payload > 0 && split_payload < payload.len() && split_payload % 8 == 0);
    let ident = [frame[l3 + 4], frame[l3 + 5]];
    let mk = |off_units: u16, more: bool, part: &[u8]| -> Vec<u8> {
        let mut f = frame[..l3].to_vec();
        let total = (ihl + part.len()) as u16;
        f.extend_from_slice(&frame[l3..l3 + 2]);
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&ident);
        let field = ((off_units & 0x1fff) | if more { 0x2000 } else { 0 }) as u16;
        f.extend_from_slice(&field.to_be_bytes());
        f.extend_from_slice(&frame[l3 + 8..l3 + ihl]);
        f[l3 + 10] = 0;
        f[l3 + 11] = 0;
        let sum = checksum16(&f[l3..l3 + ihl]);
        f[l3 + 10..l3 + 12].copy_from_slice(&sum.to_be_bytes());
        f.extend_from_slice(part);
        f
    };
    (
        mk(0, true, &payload[..split_payload]),
        mk((split_payload / 8) as u16, false, &payload[split_payload..]),
    )
}

fn frag_meta(frame: &[u8], first: bool) -> UserspaceDpMeta {
    let mut meta = gre_to_self_outer_meta(0, frame.len());
    if !first {
        meta.protocol = crate::session::SHIM_PROTO_FRAGMENT_NO_L4;
        meta.flow_src_port = 0;
        meta.flow_dst_port = 0;
    }
    meta.flow_src_addr[..4].copy_from_slice(&[203, 0, 113, 9]);
    meta.flow_dst_addr[..4].copy_from_slice(&[172, 16, 80, 8]);
    meta
}

#[test]
fn native_gre_outer_fragment_v4_reassembles_and_decaps_14645() {
    let _lock = gre_outer_frag_counter_test_lock();
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();
    let whole = build_gre_to_self_outer_frame_v4(0, &inner);
    // Control: whole decaps byte-identically.
    let control = try_native_gre_decap_from_frame(&whole, gre_to_self_outer_meta(0, whole.len()), &forwarding)
        .expect("whole GRE control must decap");
    assert_eq!(&control.frame[control.meta.l3_offset as usize..], &inner[..]);

    let (head, tail) = split_v4_outer(&whole, 16);
    // Witness premise: head alone cannot decap (truncated inner).
    assert!(
        try_native_gre_decap_from_frame(&head, frag_meta(&head, true), &forwarding).is_none(),
        "fragment head alone must not decap"
    );
    let mut pool = GreReassembler::new();
    let now = 1_000_000_000u64;
    // #16028: a Tail offer consults only — pre-head tail is dropped,
    // not buffered. Completion now requires head-then-tail order.
    assert!(pool.offer(&tail, frag_meta(&tail, false), now, OfferAdmission::Tail).is_none(), "tail first consults only, creates nothing (#16028)");
    assert!(pool.offer(&head, frag_meta(&head, true), now + 1, OfferAdmission::Head).is_none(), "head buffers (#16028)");
    let (frame, meta) = pool
        .offer(&tail, frag_meta(&tail, false), now + 2, OfferAdmission::Tail)
        .expect("head+tail must complete reassembly (#16028)");
    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
        .expect("reassembled datagram must decap");
    assert_eq!(&decap.frame[decap.meta.l3_offset as usize..], &inner[..], "decapped inner must be byte-identical");
    // Exactly once: replaying tail does not complete again.
    assert!(pool.offer(&tail, frag_meta(&tail, false), now + 3, OfferAdmission::Tail).is_none());
}

fn build_v6_outer_fragmented(inner: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let whole = build_gre_to_self_outer_frame_v6(0, inner);
    let l3 = 14usize;
    // whole payload = GRE(4)+inner. Insert Fragment header after fixed hdr.
    let payload = whole[l3 + 40..].to_vec();
    let split = 16usize;
    let mk = |offset_units: u16, more: bool, part: &[u8], first: bool| -> Vec<u8> {
        let mut f = whole[..l3].to_vec();
        f.extend_from_slice(&whole[l3..l3 + 4]);
        let plen = (8 + part.len()) as u16;
        f.extend_from_slice(&plen.to_be_bytes());
        f.push(44);
        f.push(64);
        f.extend_from_slice(&whole[l3 + 8..l3 + 40]);
        let word = ((offset_units & 0x1fff) << 3) | if more { 1 } else { 0 };
        f.push(47);
        f.push(0);
        f.extend_from_slice(&word.to_be_bytes());
        f.extend_from_slice(&0x14645u32.to_be_bytes());
        let _ = first;
        f.extend_from_slice(part);
        f
    };
    (
        mk(0, true, &payload[..split], true),
        mk((split / 8) as u16, false, &payload[split..], false),
    )
}

fn frag_meta_v6(frame: &[u8], first: bool) -> UserspaceDpMeta {
    let mut meta = gre_to_self_outer_meta_v6(0, frame.len());
    meta.l4_offset = 14 + 48;
    meta.payload_offset = meta.l4_offset;
    if !first {
        meta.protocol = crate::session::SHIM_PROTO_FRAGMENT_NO_L4;
    }
    meta.flow_src_addr = GRE_V6_PEER;
    meta.flow_dst_addr = GRE_V6_LOCAL;
    meta
}

#[test]
fn native_gre_outer_fragment_v6_reassembles_and_decaps_14645() {
    let _lock = gre_outer_frag_counter_test_lock();
    let forwarding = build_forwarding_state(&gre_to_self_snapshot_v6());
    let inner = build_gre_inner_icmp_packet_v4();
    let whole = build_gre_to_self_outer_frame_v6(0, &inner);
    let control = try_native_gre_decap_from_frame(&whole, gre_to_self_outer_meta_v6(0, whole.len()), &forwarding)
        .expect("whole v6 GRE control must decap");
    assert_eq!(&control.frame[control.meta.l3_offset as usize..], &inner[..]);
    let (head, tail) = build_v6_outer_fragmented(&inner);
    assert!(try_native_gre_decap_from_frame(&head, frag_meta_v6(&head, true), &forwarding).is_none());
    let mut pool = GreReassembler::new();
    let now = 2_000_000_000u64;
    assert!(pool.offer(&head, frag_meta_v6(&head, true), now, OfferAdmission::Head).is_none());
    let (frame, meta) = pool
        .offer(&tail, frag_meta_v6(&tail, false), now + 1, OfferAdmission::Tail)
        .expect("v6 head+tail must complete");
    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
        .expect("reassembled v6 datagram must decap");
    assert_eq!(&decap.frame[decap.meta.l3_offset as usize..], &inner[..]);
}

/// #16032: a fragmented GRE datagram behind an experimental (253) IPv6
/// extension header must reassemble+decap. The reassembly walkers in
/// gre_reassembly.rs hand-copied `0|43|60|135|139|140` and omitted 253/254
/// from the SSOT `IPV6_GENERIC_EXT_HEADERS`, so parse_fragment returned
/// None and patch_v6_next_header_to_protocol stopped before Fragment.
/// RED on revert: restoring either hand-copied list drops this datagram.
fn build_v6_outer_fragmented_behind_ext(inner: &[u8], ext_type: u8) -> (Vec<u8>, Vec<u8>) {
    let whole = build_gre_to_self_outer_frame_v6(0, inner);
    let l3 = 14usize;
    // whole: fixed hdr (next=47 GRE) + GRE+inner. Rewrite as
    // fixed(next=ext) + ext(next=44, len0=8B) + frag(next=47) + GRE+inner.
    let payload = whole[l3 + 40..].to_vec();
    let split = 16usize;
    let mk = |offset_units: u16, more: bool, part: &[u8]| -> Vec<u8> {
        let mut f = whole[..l3].to_vec();
        f.extend_from_slice(&whole[l3..l3 + 4]);
        let plen = (8 + 8 + part.len()) as u16;
        f.extend_from_slice(&plen.to_be_bytes());
        f.push(ext_type);
        f.push(64);
        f.extend_from_slice(&whole[l3 + 8..l3 + 40]);
        f.push(44); // ext -> Fragment
        f.push(0); // HdrExtLen 0 => 8 bytes
        f.extend_from_slice(&[0u8; 6]);
        let word = ((offset_units & 0x1fff) << 3) | if more { 1 } else { 0 };
        f.push(47); // frag -> GRE
        f.push(0);
        f.extend_from_slice(&word.to_be_bytes());
        f.extend_from_slice(&0x16032u32.to_be_bytes());
        f.extend_from_slice(part);
        f
    };
    (
        mk(0, true, &payload[..split]),
        mk((split / 8) as u16, false, &payload[split..]),
    )
}

#[test]
fn native_gre_outer_fragment_v6_behind_ext253_reassembles_16032() {
    let _lock = gre_outer_frag_counter_test_lock();
    let forwarding = build_forwarding_state(&gre_to_self_snapshot_v6());
    let inner = build_gre_inner_icmp_packet_v4();
    for ext in [253u8, 254] {
        let (head, tail) = build_v6_outer_fragmented_behind_ext(&inner, ext);
        let mut hm = frag_meta_v6(&head, true);
        hm.l4_offset = 14 + 40 + 8 + 8;
        hm.payload_offset = hm.l4_offset;
        let mut tm = frag_meta_v6(&tail, false);
        tm.l4_offset = 14 + 40 + 8 + 8;
        tm.payload_offset = tm.l4_offset;
        let mut pool = GreReassembler::new();
        let now = 3_000_000_000u64 + ext as u64;
        assert!(pool.offer(&head, hm, now, OfferAdmission::Head).is_none(), "ext {ext}: head buffers");
        let (frame, meta) = pool
            .offer(&tail, tm, now + 1, OfferAdmission::Tail)
            .unwrap_or_else(|| panic!("ext {ext}: head+tail behind ext must complete reassembly (#16032)"));
        let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
            .unwrap_or_else(|| panic!("ext {ext}: reassembled datagram must decap (#16032)"));
        assert_eq!(
            &decap.frame[decap.meta.l3_offset as usize..],
            &inner[..],
            "ext {ext}: decapped inner must be byte-identical"
        );
    }
    // Parity: both walker sites must consume the SSOT const, not a re-spelled list.
    let src = include_str!("gre_reassembly.rs");
    assert!(
        src.matches("IPV6_GENERIC_EXT_HEADERS.contains(&n)").count() >= 2,
        "#16032: gre_reassembly.rs must guard both generic arms on IPV6_GENERIC_EXT_HEADERS"
    );
    assert!(
        !src.contains("0 | 43 | 60 | 135 | 139 | 140 =>"),
        "#16032: hand-copied walker list must not return"
    );
}

#[test]
fn native_gre_fragment_shim_truth_table_14645() {
    use shim_gre_classify::native_gre_fragment_stays_on_helper;
    // (protocol, wire, is_fragment, armed, stays_on_helper)
    let cases = [
        (47u8, 47u8, true, true, true, "first fragment head stays on helper"),
        (255, 47, true, true, true, "local/interface-NAT tail stays on helper, not cpumap_or_pass"),
        (47, 47, false, true, false, "whole GRE keeps ordinary disposition"),
        (255, 47, true, false, false, "non-native GRE tail follows kernel head"),
        (255, 6, true, true, false, "TCP tail is not GRE reassembly"),
        (50, 50, true, true, false, "ESP tail is not GRE reassembly"),
    ];
    for (p, w, frag, armed, want, why) in cases {
        assert_eq!(native_gre_fragment_stays_on_helper(p, w, frag, armed), want, "{why}");
    }
    // Interface-NAT helper predicate still refuses native GRE tails.
    assert!(!shim_tunnel_frag::interface_nat_tunnel_passes_to_kernel(255, 47, true));
}

#[test]
fn native_gre_outer_fragment_overlap_is_counted_drop_14645() {
    let _lock = gre_outer_frag_counter_test_lock();
    let inner = build_gre_inner_icmp_packet_v4();
    let whole = build_gre_to_self_outer_frame_v4(0, &inner);
    let (head, _tail) = split_v4_outer(&whole, 16);
    let mut pool = GreReassembler::new();
    let before = crate::afxdp::gre_reassembly::GRE_OUTER_FRAG_DROPS.load(std::sync::atomic::Ordering::Relaxed);
    assert!(pool.offer(&head, frag_meta(&head, true), 100, OfferAdmission::Head).is_none());
    assert!(pool.offer(&head, frag_meta(&head, true), 101, OfferAdmission::Head).is_none(), "overlap/retransmit refused");
    assert_eq!(
        crate::afxdp::gre_reassembly::GRE_OUTER_FRAG_DROPS.load(std::sync::atomic::Ordering::Relaxed),
        before + 1
    );
}
