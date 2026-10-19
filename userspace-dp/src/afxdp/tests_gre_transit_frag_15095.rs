//! #15095: the #14645 GRE outer-fragment reassembler must buffer only
//! fragments whose outer destination is a configured native-GRE
//! endpoint.
//!
//! Before this fix `stage_native_gre_decap` offered EVERY fragmented
//! proto-47 datagram to the pool. A transit GRE/PPTP datagram fragmented
//! upstream was therefore consumed fragment-by-fragment; on completion
//! decap missed (no endpoint), the stage returned `Buffered`, and the
//! caller recycled the descriptor with no counter — fragmented transit
//! GRE was never forwarded and the loss was invisible.
//!
//! The probe under test is `stage_native_gre_decap` itself: `NotGre`
//! means the fragment falls through to the ordinary flowless /
//! fragment-association path; `Buffered` means the pool consumed it.

use super::tests_support::*;
use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::gre_reassembly::{GreReassembler, gre_outer_frag_counter_test_lock};
use crate::afxdp::poll_stages::{GreDecapStage, stage_native_gre_decap};

/// Split a whole v4 GRE outer frame into head+tail fragments. Mirror of
/// the #14645 helper (kept local so this file pins its own fixture).
fn split_v4_outer_15095(frame: &[u8], split_payload: usize) -> (Vec<u8>, Vec<u8>) {
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

fn frag_meta_15095(frame: &[u8], first: bool) -> UserspaceDpMeta {
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

/// Rewrite the outer IPv4 src/dst of a built GRE frame (and its IP
/// checksum) so the frame names a different outer pair than the
/// configured endpoint. Transit and wrong-pair fixtures are derived
/// from the to-self frame this way so every other byte stays identical.
fn rewrite_outer_v4(frame: &[u8], src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let l3 = 14usize;
    let mut f = frame.to_vec();
    f[l3 + 12..l3 + 16].copy_from_slice(&src);
    f[l3 + 16..l3 + 20].copy_from_slice(&dst);
    f[l3 + 10] = 0;
    f[l3 + 11] = 0;
    let sum = checksum16(&f[l3..l3 + 20]);
    f[l3 + 10..l3 + 12].copy_from_slice(&sum.to_be_bytes());
    f
}

fn meta_for_outer_15095(frame: &[u8], src: [u8; 4], dst: [u8; 4], first: bool) -> UserspaceDpMeta {
    let mut meta = frag_meta_15095(frame, first);
    meta.flow_src_addr[..4].copy_from_slice(&src);
    meta.flow_dst_addr[..4].copy_from_slice(&dst);
    meta
}

fn stage_15095(
    frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
    pool: &mut GreReassembler,
    now_ns: u64,
) -> GreDecapStage {
    let mut allows = |_: &[u8], _: UserspaceDpMeta| true;
    stage_native_gre_decap(frame, meta, forwarding, pool, now_ns, &mut allows)
}

#[test]
fn transit_gre_fragment_head_and_tail_return_not_gre_15095() {
    let _lock = gre_outer_frag_counter_test_lock();
    // No tunnel endpoints at all: every GRE datagram is transit.
    let mut snapshot = gre_to_self_snapshot();
    snapshot.tunnel_endpoints.clear();
    let forwarding = build_forwarding_state(&snapshot);
    assert!(
        forwarding.gre_decap_index.is_empty(),
        "fixture: no endpoints means an empty decap index"
    );
    let inner = build_gre_inner_icmp_packet_v4();
    let whole = build_gre_to_self_outer_frame_v4(0, &inner);
    let (head, tail) = split_v4_outer_15095(&whole, 16);
    let mut pool = GreReassembler::new();
    let now = 3_000_000_000u64;
    match stage_15095(&head, frag_meta_15095(&head, true), &forwarding, &mut pool, now) {
        GreDecapStage::NotGre(_) => {}
        GreDecapStage::Buffered => {
            panic!("#15095: transit GRE head must return NotGre, not Buffered (pool capture)")
        }
        GreDecapStage::Decapped(..) => panic!("#15095: transit GRE head must not decap"),
        GreDecapStage::FilterDropped => panic!("#15095: transit GRE head must not filter-drop"),
    }
    match stage_15095(&tail, frag_meta_15095(&tail, false), &forwarding, &mut pool, now + 1) {
        GreDecapStage::NotGre(_) => {}
        GreDecapStage::Buffered => {
            panic!("#15095: transit GRE tail must return NotGre, not Buffered (pool capture)")
        }
        GreDecapStage::Decapped(..) => panic!("#15095: transit GRE tail must not decap"),
        GreDecapStage::FilterDropped => panic!("#15095: transit GRE tail must not filter-drop"),
    }
    // Nothing was buffered: a later peer fragment still completes (the
    // flood-isolation cell below proves the pool stayed empty).
}

#[test]
fn gre_fragment_to_different_pair_returns_not_gre_15095() {
    let _lock = gre_outer_frag_counter_test_lock();
    // A tunnel IS configured (203.0.113.9 -> 172.16.80.8), but this
    // datagram names a different outer pair, so it is transit.
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    assert!(
        !forwarding.gre_decap_index.is_empty(),
        "fixture: the to-self endpoint must be indexed"
    );
    let inner = build_gre_inner_icmp_packet_v4();
    let whole = build_gre_to_self_outer_frame_v4(0, &inner);
    let transit = rewrite_outer_v4(&whole, [198, 51, 100, 7], [192, 0, 2, 55]);
    let (head, tail) = split_v4_outer_15095(&transit, 16);
    let src = [198, 51, 100, 7];
    let dst = [192, 0, 2, 55];
    let mut pool = GreReassembler::new();
    let now = 4_000_000_000u64;
    match stage_15095(&head, meta_for_outer_15095(&head, src, dst, true), &forwarding, &mut pool, now) {
        GreDecapStage::NotGre(_) => {}
        GreDecapStage::Buffered => {
            panic!("#15095: wrong-pair GRE head must return NotGre, not Buffered")
        }
        GreDecapStage::Decapped(..) => panic!("#15095: wrong-pair GRE head must not decap"),
        GreDecapStage::FilterDropped => panic!("#15095: wrong-pair GRE head must not filter-drop"),
    }
    match stage_15095(
        &tail,
        meta_for_outer_15095(&tail, src, dst, false),
        &forwarding,
        &mut pool,
        now + 1,
    ) {
        GreDecapStage::NotGre(_) => {}
        GreDecapStage::Buffered => {
            panic!("#15095: wrong-pair GRE tail must return NotGre, not Buffered")
        }
        GreDecapStage::Decapped(..) => panic!("#15095: wrong-pair GRE tail must not decap"),
        GreDecapStage::FilterDropped => panic!("#15095: wrong-pair GRE tail must not filter-drop"),
    }
}

#[test]
fn gre_to_self_fragments_still_reassemble_and_decap_15095() {
    let _lock = gre_outer_frag_counter_test_lock();
    // Named control: the #14645 GRE-to-self cells stay green through the
    // stage (not just through the pool directly).
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();
    let whole = build_gre_to_self_outer_frame_v4(0, &inner);
    let (head, tail) = split_v4_outer_15095(&whole, 16);
    let mut pool = GreReassembler::new();
    let now = 5_000_000_000u64;
    match stage_15095(&tail, frag_meta_15095(&tail, false), &forwarding, &mut pool, now) {
        GreDecapStage::Buffered => {}
        GreDecapStage::NotGre(_) => {
            panic!("#15095 control: to-self tail must buffer, not fall through")
        }
        GreDecapStage::Decapped(..) => panic!("control: tail alone must not decap"),
        GreDecapStage::FilterDropped => panic!("control: tail must not filter-drop"),
    }
    match stage_15095(&head, frag_meta_15095(&head, true), &forwarding, &mut pool, now + 1) {
        GreDecapStage::Decapped(m, frame) => {
            assert_eq!(
                &frame[m.l3_offset as usize..],
                &inner[..],
                "control: decapped inner must be byte-identical after reassembly"
            );
        }
        GreDecapStage::Buffered => panic!("control: completed to-self datagram must decap"),
        GreDecapStage::NotGre(_) => panic!("control: to-self head must not fall through"),
        GreDecapStage::FilterDropped => panic!("control: to-self head must not filter-drop"),
    }
    assert_eq!(
        forwarding.gre_decap_counters.reassembled_decap_refusals(),
        0,
        "control: a successful decap must not count a refusal"
    );
}

#[test]
fn non_peer_head_flood_cannot_block_peer_reassembly_15095() {
    let _lock = gre_outer_frag_counter_test_lock();
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();
    let whole = build_gre_to_self_outer_frame_v4(0, &inner);
    let (peer_head, peer_tail) = split_v4_outer_15095(&whole, 16);
    // 65 distinct transit heads (distinct outer src / IP ID), each of
    // which would have occupied a pool slot before the fix (pool cap 64).
    let mut pool = GreReassembler::new();
    let now = 6_000_000_000u64;
    for i in 0..65u8 {
        let src = [198, 51, 100, i];
        let dst = [192, 0, 2, 55];
        let transit = rewrite_outer_v4(&whole, src, dst);
        let (head, _tail) = split_v4_outer_15095(&transit, 16);
        match stage_15095(
            &head,
            meta_for_outer_15095(&head, src, dst, true),
            &forwarding,
            &mut pool,
            now + i as u64,
        ) {
            GreDecapStage::NotGre(_) => {}
            GreDecapStage::Buffered => {
                panic!("#15095: transit head {i} must return NotGre, not Buffered")
            }
            GreDecapStage::Decapped(..) => panic!("#15095: transit head must not decap"),
            GreDecapStage::FilterDropped => panic!("#15095: transit head must not filter-drop"),
        }
    }
    // The peer's fragmented datagram still reassembles and decaps: the
    // flood never touched the pool.
    match stage_15095(
        &peer_tail,
        frag_meta_15095(&peer_tail, false),
        &forwarding,
        &mut pool,
        now + 100,
    ) {
        GreDecapStage::Buffered => {}
        _ => panic!("#15095: peer tail must buffer after the transit flood"),
    }
    match stage_15095(
        &peer_head,
        frag_meta_15095(&peer_head, true),
        &forwarding,
        &mut pool,
        now + 101,
    ) {
        GreDecapStage::Decapped(..) => {}
        GreDecapStage::Buffered => {
            panic!("#15095: peer datagram must complete despite the transit flood")
        }
        GreDecapStage::NotGre(_) => panic!("#15095: peer head must not fall through"),
        GreDecapStage::FilterDropped => panic!("#15095: peer head must not filter-drop"),
    }
}

#[test]
fn reassembled_but_decap_refused_is_counted_15095() {
    let _lock = gre_outer_frag_counter_test_lock();
    // The outer pair IS indexed, so fragments buffer; the GRE header
    // carries a Key the unkeyed endpoint (key 0) refuses, so the
    // completed datagram's decap misses at the key check while the
    // outer tuple still matches. That is the counted refusal.
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();
    let whole = build_gre_to_self_outer_frame_v4(0, &inner);
    let mut keyed = whole.clone();
    // GRE flags: set K bit (0x2000) and insert a 4-byte key after the
    // 4-byte base header, shifting the inner by 4 bytes.
    keyed[14 + 20] = 0x20;
    keyed[14 + 21] = 0x00;
    let mut with_key = keyed[..14 + 20 + 4].to_vec();
    with_key.extend_from_slice(&0xdead_beefu32.to_be_bytes());
    with_key.extend_from_slice(&keyed[14 + 20 + 4..]);
    // Fix outer total length (+4).
    let total = (20 + 4 + 4 + inner.len()) as u16;
    with_key[14 + 2..14 + 4].copy_from_slice(&total.to_be_bytes());
    with_key[14 + 10] = 0;
    with_key[14 + 11] = 0;
    let sum = checksum16(&with_key[14..14 + 20]);
    with_key[14 + 10..14 + 12].copy_from_slice(&sum.to_be_bytes());
    let (khead, ktail) = split_v4_outer_15095(&with_key, 16);
    let mut pool = GreReassembler::new();
    let now = 7_000_000_000u64;
    let before = forwarding.gre_decap_counters.reassembled_decap_refusals();
    match stage_15095(&ktail, frag_meta_15095(&ktail, false), &forwarding, &mut pool, now) {
        GreDecapStage::Buffered => {}
        _ => panic!("#15095: keyed to-self tail must buffer (outer tuple is indexed)"),
    }
    match stage_15095(&khead, frag_meta_15095(&khead, true), &forwarding, &mut pool, now + 1) {
        GreDecapStage::Buffered => {}
        GreDecapStage::Decapped(..) => {
            panic!("#15095: keyed frame against an unkeyed endpoint must not decap")
        }
        GreDecapStage::NotGre(_) => panic!("#15095: completed datagram must not fall through"),
        GreDecapStage::FilterDropped => panic!("#15095: key mismatch must not filter-drop"),
    }
    assert_eq!(
        forwarding.gre_decap_counters.reassembled_decap_refusals(),
        before + 1,
        "#15095: a reassembled-but-decap-refused datagram must be counted exactly once"
    );
}
