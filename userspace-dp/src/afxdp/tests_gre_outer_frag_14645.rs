//! #14645: outer-fragmented native GRE must reassemble before decap, and a
//! native-GRE local tail must not be passed to the kernel.

use super::tests_support::*;
use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::gre::try_native_gre_decap_from_frame;
use crate::afxdp::gre_reassembly::{GreReassembler, gre_outer_frag_counter_test_lock};

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
    meta.pkt_len = frame.len() as u16 - 14;
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
    assert!(pool.offer(&tail, frag_meta(&tail, false), now).is_none(), "tail first buffers");
    let (frame, meta) = pool
        .offer(&head, frag_meta(&head, true), now + 1)
        .expect("head+tail must complete reassembly");
    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
        .expect("reassembled datagram must decap");
    assert_eq!(&decap.frame[decap.meta.l3_offset as usize..], &inner[..], "decapped inner must be byte-identical");
    // Exactly once: replaying tail does not complete again.
    assert!(pool.offer(&tail, frag_meta(&tail, false), now + 2).is_none());
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
    meta.pkt_len = frame.len() as u16 - 14;
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
    assert!(pool.offer(&head, frag_meta_v6(&head, true), now).is_none());
    let (frame, meta) = pool
        .offer(&tail, frag_meta_v6(&tail, false), now + 1)
        .expect("v6 head+tail must complete");
    let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
        .expect("reassembled v6 datagram must decap");
    assert_eq!(&decap.frame[decap.meta.l3_offset as usize..], &inner[..]);
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
    assert!(pool.offer(&head, frag_meta(&head, true), 100).is_none());
    assert!(pool.offer(&head, frag_meta(&head, true), 101).is_none(), "overlap/retransmit refused");
    assert_eq!(
        crate::afxdp::gre_reassembly::GRE_OUTER_FRAG_DROPS.load(std::sync::atomic::Ordering::Relaxed),
        before + 1
    );
}
