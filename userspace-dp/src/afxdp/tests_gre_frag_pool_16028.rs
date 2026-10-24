//! #16028: the shared GRE/WG outer-fragment pool must not let tail
//! fragments create state, must not let one outer source starve the
//! other protocol / other peers, and must admit GRE heads only through
//! the full endpoint matcher (zone/host-inbound included).
//!
//! Pre-fix shape: `GreReassembler::offer` created a `FragEntry` for
//! ANY fragment (`or_insert` on first sight) behind only the
//! tuple-index probe in `outer_frame_targets_gre_endpoint`, in one
//! 64-entry pool shared with WireGuard. A tail flood from the
//! configured peer source (or spoofed as it) filled all 64 slots for
//! 10s and starved legitimate WG (and other GRE) reassembly.

use super::tests_support::*;
use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::gre_reassembly::{
    GreReassembler, MAX_GRE_FRAG_DATAGRAMS, MAX_GRE_FRAG_DATAGRAMS_PER_SRC, OfferAdmission,
    gre_outer_frag_counter_test_lock,
};
use crate::afxdp::poll_stages::{
    GreDecapStage, WgDecapStage, stage_native_gre_decap, stage_wg_decap,
};
use crate::afxdp::test_fixtures::wg_outer_mtu_snapshot;
use crate::afxdp::wg::WgWorkerScratch;
use crate::afxdp::wg::tests::established_pair;

// ---------------------------------------------------------------------
// Local fragment fixtures (mirrors of the #14645/#15102 helpers, kept
// local so this file pins its own shapes).
// ---------------------------------------------------------------------

fn split_v4_outer_16028(frame: &[u8], split_payload: usize) -> (Vec<u8>, Vec<u8>) {
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

fn frag_meta_16028(frame: &[u8], first: bool) -> UserspaceDpMeta {
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

/// Re-ident a GRE fragment: new outer IP ID (new datagram identity)
/// without touching addresses/protocol.
fn reident_16028(frame: &[u8], id: u16) -> Vec<u8> {
    let l3 = 14usize;
    let mut f = frame.to_vec();
    f[l3 + 4..l3 + 6].copy_from_slice(&id.to_be_bytes());
    f[l3 + 10] = 0;
    f[l3 + 11] = 0;
    let sum = checksum16(&f[l3..l3 + 20]);
    f[l3 + 10..l3 + 12].copy_from_slice(&sum.to_be_bytes());
    f
}

fn stage_gre_16028(
    frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
    pool: &mut GreReassembler,
    now_ns: u64,
) -> GreDecapStage {
    let mut allows = |_: &[u8], _: UserspaceDpMeta| true;
    stage_native_gre_decap(frame, meta, forwarding, pool, now_ns, &mut allows)
}

// ---------------------------------------------------------------------
// WG fixtures (mirrors of the #15102 helpers).
// ---------------------------------------------------------------------

const WG_PORT_16028: u16 = 51820;
const WG_LOCAL_16028: [u8; 4] = [172, 16, 80, 8];
const WG_PEER_16028: [u8; 4] = [203, 0, 113, 7];

fn wg_inner_16028() -> Vec<u8> {
    let mut p = vec![0u8; 20 + 8];
    p[0] = 0x45;
    let total = p.len() as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p[8] = 64;
    p[9] = PROTO_UDP;
    p[12..16].copy_from_slice(&[10, 123, 0, 5]);
    p[16..20].copy_from_slice(&[10, 0, 61, 102]);
    p[20..22].copy_from_slice(&1111u16.to_be_bytes());
    p[22..24].copy_from_slice(&2222u16.to_be_bytes());
    p[24..26].copy_from_slice(&8u16.to_be_bytes());
    p
}

fn wg_outer_frame_16028(record: &[u8], ident: u16, src: [u8; 4]) -> Vec<u8> {
    let mut f = vec![0u8; 14 + 20 + 8 + record.len()];
    f[..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
    f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    f[14] = 0x45;
    let ip_total = (20 + 8 + record.len()) as u16;
    f[16..18].copy_from_slice(&ip_total.to_be_bytes());
    f[18..20].copy_from_slice(&ident.to_be_bytes());
    f[22] = 64;
    f[23] = PROTO_UDP;
    f[26..30].copy_from_slice(&src);
    f[30..34].copy_from_slice(&WG_LOCAL_16028);
    f[34..36].copy_from_slice(&51820u16.to_be_bytes());
    f[36..38].copy_from_slice(&WG_PORT_16028.to_be_bytes());
    let udp_len = (8 + record.len()) as u16;
    f[38..40].copy_from_slice(&udp_len.to_be_bytes());
    f[42..].copy_from_slice(record);
    f
}

fn wg_outer_meta_16028(frame_len: usize, src: [u8; 4]) -> UserspaceDpMeta {
    let mut m = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame_len as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        config_generation: 0x5150_4646,
        fib_generation: 0x0BAD_F00D,
        rx_queue_index: 3,
        ingress_ifindex: 12,
        ..UserspaceDpMeta::default()
    };
    m.flow_src_addr[..4].copy_from_slice(&src);
    m.flow_dst_addr[..4].copy_from_slice(&WG_LOCAL_16028);
    m.flow_src_port = 51820;
    m.flow_dst_port = WG_PORT_16028;
    m
}

fn wg_frag_meta_16028(frame: &[u8], first: bool, src: [u8; 4]) -> UserspaceDpMeta {
    let mut meta = wg_outer_meta_16028(frame.len(), src);
    if !first {
        meta.protocol = crate::session::SHIM_PROTO_FRAGMENT_NO_L4;
        meta.flow_src_port = 0;
        meta.flow_dst_port = 0;
    }
    meta
}

fn wg_forwarding_16028() -> (ForwardingState, Vec<u8>, Vec<u8>) {
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, resp_pub) = established_pair(allowed.clone(), allowed);
    let mut forwarding = build_forwarding_state(&wg_outer_mtu_snapshot());
    let id = *forwarding
        .wg_engines
        .keys()
        .next()
        .expect("fixture configures a WireGuard tunnel");
    forwarding.wg_engines.insert(id, std::sync::Arc::new(resp));
    let inner = wg_inner_16028();
    let mut wire = vec![0u8; 2048];
    let enc = init
        .try_encap(&resp_pub, &inner, &mut wire)
        .expect("encap fragmented WG record");
    let frame = wg_outer_frame_16028(&wire[..enc.len], 0x6028, WG_PEER_16028);
    (forwarding, frame, inner)
}

fn stage_wg_16028(
    frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
    scratch: &WgWorkerScratch,
    pool: &mut GreReassembler,
    now_ns: u64,
) -> WgDecapStage {
    let mut allows = |_: &[u8], _: UserspaceDpMeta| true;
    stage_wg_decap(frame, meta, forwarding, scratch, pool, now_ns, &mut allows)
}

// ---------------------------------------------------------------------
// (1) Tail-only flood from the configured GRE peer creates NO state.
// RED pre-fix: every tail `or_insert`s an entry; 64 tails fill the
// pool and the legitimate head+tail below cannot complete.
// ---------------------------------------------------------------------
#[test]
fn gre_tail_only_flood_creates_no_pool_state_16028() {
    let _lock = gre_outer_frag_counter_test_lock();
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();
    let whole = build_gre_to_self_outer_frame_v4(0, &inner);
    let (head, tail) = split_v4_outer_16028(&whole, 16);
    let mut pool = GreReassembler::new();
    let now = 10_000_000_000u64;
    // 64 distinct tail datagrams (distinct IP IDs), all from the
    // configured peer source 203.0.113.9, none preceded by a head.
    for i in 0..MAX_GRE_FRAG_DATAGRAMS {
        let t = reident_16028(&tail, 0x4000 + i as u16);
        match stage_gre_16028(
            &t,
            frag_meta_16028(&t, false),
            &forwarding,
            &mut pool,
            now + i as u64,
        ) {
            GreDecapStage::Buffered => {}
            GreDecapStage::NotGre(_) => {
                panic!("#16028: to-self GRE tail {i} must be consumed (Buffered), not forwarded")
            }
            GreDecapStage::Decapped(..) => panic!("#16028: lone tail must not decap"),
            GreDecapStage::FilterDropped => panic!("#16028: lone tail must not filter-drop"),
        }
    }
    assert_eq!(
        pool.buffered_len(),
        0,
        "#16028: tail-only flood must create zero pool entries"
    );
    // The legitimate fragmented datagram still reassembles + decaps.
    match stage_gre_16028(
        &head,
        frag_meta_16028(&head, true),
        &forwarding,
        &mut pool,
        now + 100,
    ) {
        GreDecapStage::Buffered => {}
        _ => panic!("#16028: legit head must buffer after tail flood"),
    }
    assert_eq!(pool.buffered_len(), 1);
    match stage_gre_16028(
        &tail,
        frag_meta_16028(&tail, false),
        &forwarding,
        &mut pool,
        now + 101,
    ) {
        GreDecapStage::Decapped(m, frame) => {
            assert_eq!(&frame[m.l3_offset as usize..], &inner[..]);
        }
        _ => panic!("#16028: legit head+tail must decap after tail flood"),
    }
    assert_eq!(pool.buffered_len(), 0);
}

// ---------------------------------------------------------------------
// (2) GRE head flood from ONE peer source is sub-quota'd and cannot
// starve WG reassembly in the SAME shared pool.
// RED pre-fix: 64 GRE heads (one source) fill the pool; the WG head
// below is refused at the global cap and never decaps.
// Fixture note: GRE peer (203.0.113.9) and WG peer (203.0.113.7) are
// distinct sources, so this also pins cross-source fairness — the GRE
// source is capped at 32 and the WG source keeps its half.
// ---------------------------------------------------------------------
#[test]
fn gre_head_flood_cannot_starve_wg_in_shared_pool_16028() {
    let _lock = gre_outer_frag_counter_test_lock();
    let gre_forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let (wg_forwarding, wg_whole, wg_inner) = wg_forwarding_16028();
    let scratch = WgWorkerScratch::new(4096);
    let inner = build_gre_inner_icmp_packet_v4();
    let whole = build_gre_to_self_outer_frame_v4(0, &inner);
    let (head, _tail) = split_v4_outer_16028(&whole, 16);
    let (wg_head, wg_tail) = split_v4_outer_16028(&wg_whole, 16);

    let mut pool = GreReassembler::new();
    let now = 20_000_000_000u64;
    // Fill with GRE heads from the single configured peer source:
    // 64 distinct datagrams (distinct IP IDs), heads only.
    for i in 0..MAX_GRE_FRAG_DATAGRAMS {
        let h = reident_16028(&head, 0x5000 + i as u16);
        match stage_gre_16028(
            &h,
            frag_meta_16028(&h, true),
            &gre_forwarding,
            &mut pool,
            now + i as u64,
        ) {
            GreDecapStage::Buffered => {}
            _ => panic!("#16028: GRE head {i} must be consumed (Buffered)"),
        }
    }
    assert_eq!(
        pool.buffered_len(),
        MAX_GRE_FRAG_DATAGRAMS_PER_SRC,
        "#16028: one source must be capped at the per-source sub-quota ({MAX_GRE_FRAG_DATAGRAMS_PER_SRC} of {MAX_GRE_FRAG_DATAGRAMS})"
    );
    // WG head+tail from a DIFFERENT source still completes in the
    // same pool — the decisive cross-protocol fairness check.
    match stage_wg_16028(
        &wg_head,
        wg_frag_meta_16028(&wg_head, true, WG_PEER_16028),
        &wg_forwarding,
        &scratch,
        &mut pool,
        now + 100,
    ) {
        WgDecapStage::Buffered => {}
        _ => panic!("#16028: WG head must buffer despite the GRE head flood"),
    }
    match stage_wg_16028(
        &wg_tail,
        wg_frag_meta_16028(&wg_tail, false, WG_PEER_16028),
        &wg_forwarding,
        &scratch,
        &mut pool,
        now + 101,
    ) {
        WgDecapStage::Decapped(_m, frame) => {
            assert_eq!(
                &frame[14..],
                &wg_inner[..],
                "#16028: WG inner must survive GRE flood"
            );
        }
        _ => panic!("#16028: WG head+tail must decap despite the GRE head flood"),
    }
}

// ---------------------------------------------------------------------
// (3) GRE head with a WRONG KEY names the endpoint tuple but fails
// the full matcher: no pool state is created, and the refusal is
// counted. RED pre-fix: the index-only probe buffered it (state
// created; refusal only counted after the tail arrived/completed).
// ---------------------------------------------------------------------
#[test]
fn gre_wrong_key_head_creates_no_state_and_is_counted_16028() {
    let _lock = gre_outer_frag_counter_test_lock();
    // Keyed endpoint: configured key 0x1111_2222.
    let mut snapshot = gre_to_self_snapshot();
    snapshot.tunnel_endpoints[0].key = 0x1111_2222;
    let forwarding = build_forwarding_state(&snapshot);
    let inner = build_gre_inner_icmp_packet_v4();
    let whole = build_gre_to_self_outer_frame_v4(0, &inner);
    // Stamp a WRONG key (0xdeadbeef) into the GRE header.
    let mut keyed = whole.clone();
    keyed[14 + 20] = 0x20;
    keyed[14 + 21] = 0x00;
    let mut with_key = keyed[..14 + 20 + 4].to_vec();
    with_key.extend_from_slice(&0xdead_beefu32.to_be_bytes());
    with_key.extend_from_slice(&keyed[14 + 20 + 4..]);
    let total = (20 + 4 + 4 + inner.len()) as u16;
    with_key[14 + 2..14 + 4].copy_from_slice(&total.to_be_bytes());
    with_key[14 + 10] = 0;
    with_key[14 + 11] = 0;
    let sum = checksum16(&with_key[14..14 + 20]);
    with_key[14 + 10..14 + 12].copy_from_slice(&sum.to_be_bytes());

    let (khead, _ktail) = split_v4_outer_16028(&with_key, 16);
    let mut pool = GreReassembler::new();
    let now = 30_000_000_000u64;
    let before = forwarding.gre_decap_counters.reassembled_decap_refusals();
    match stage_gre_16028(
        &khead,
        frag_meta_16028(&khead, true),
        &forwarding,
        &mut pool,
        now,
    ) {
        GreDecapStage::Buffered => {}
        GreDecapStage::NotGre(_) => {
            panic!("#16028: wrong-key head to our endpoint must be consumed, not forwarded")
        }
        GreDecapStage::Decapped(..) => panic!("#16028: wrong-key head must not decap"),
        GreDecapStage::FilterDropped => panic!("#16028: wrong-key head must not filter-drop"),
    }
    assert_eq!(
        pool.buffered_len(),
        0,
        "#16028: wrong-key head must create no pool state"
    );
    assert_eq!(
        forwarding.gre_decap_counters.reassembled_decap_refusals(),
        before + 1,
        "#16028: wrong-key head refusal must be counted exactly once"
    );

    // Control: the CORRECT key head does create state and decaps.
    let mut good = whole.clone();
    good[14 + 20] = 0x20;
    good[14 + 21] = 0x00;
    let mut good_key = good[..14 + 20 + 4].to_vec();
    good_key.extend_from_slice(&0x1111_2222u32.to_be_bytes());
    good_key.extend_from_slice(&good[14 + 20 + 4..]);
    good_key[14 + 2..14 + 4].copy_from_slice(&total.to_be_bytes());
    good_key[14 + 10] = 0;
    good_key[14 + 11] = 0;
    let sum = checksum16(&good_key[14..14 + 20]);
    good_key[14 + 10..14 + 12].copy_from_slice(&sum.to_be_bytes());
    let (ghead, gtail) = split_v4_outer_16028(&good_key, 16);
    match stage_gre_16028(
        &ghead,
        frag_meta_16028(&ghead, true),
        &forwarding,
        &mut pool,
        now + 1,
    ) {
        GreDecapStage::Buffered => {}
        _ => panic!("#16028 control: correct-key head must buffer"),
    }
    assert_eq!(
        pool.buffered_len(),
        1,
        "#16028 control: correct-key head creates one entry"
    );
    match stage_gre_16028(
        &gtail,
        frag_meta_16028(&gtail, false),
        &forwarding,
        &mut pool,
        now + 2,
    ) {
        GreDecapStage::Decapped(m, frame) => {
            assert_eq!(&frame[m.l3_offset as usize..], &inner[..]);
        }
        _ => panic!("#16028 control: correct-key head+tail must decap"),
    }
}

// ---------------------------------------------------------------------
// (4) Zone leg of the fix direction: the same correctly-keyed GRE
// head arriving on an ingress whose zone DENIES GRE host-inbound
// creates no pool state. RED pre-fix for the same reason as (3):
// the index probe ignored host-inbound entirely at buffer time.
// ---------------------------------------------------------------------
#[test]
fn gre_head_on_host_inbound_denied_ingress_creates_no_state_16028() {
    let _lock = gre_outer_frag_counter_test_lock();
    let mut forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();
    let whole = build_gre_to_self_outer_frame_v4(0, &inner);
    let (head, _tail) = split_v4_outer_16028(&whole, 16);
    let meta = frag_meta_16028(&head, true);
    // Deny GRE on the actual ingress (mirrors #11054's fixture move).
    let ingress_ifindex = meta.ingress_ifindex as i32;
    let blocked_zone = 99;
    forwarding
        .ifindex_to_zone_id
        .insert(ingress_ifindex, blocked_zone);
    forwarding.zone_host_inbound.insert(
        blocked_zone,
        crate::afxdp::types::ZoneHostInbound::default(),
    );
    let mut pool = GreReassembler::new();
    let before = forwarding.gre_decap_counters.reassembled_decap_refusals();
    match stage_gre_16028(&head, meta, &forwarding, &mut pool, 40_000_000_000) {
        GreDecapStage::Buffered => {}
        GreDecapStage::NotGre(_) => {
            panic!("#16028: host-inbound-denied head must be consumed, not forwarded")
        }
        GreDecapStage::Decapped(..) => panic!("#16028: denied head must not decap"),
        GreDecapStage::FilterDropped => panic!("#16028: denied head must not filter-drop"),
    }
    assert_eq!(
        pool.buffered_len(),
        0,
        "#16028: host-inbound-denied head must create no pool state"
    );
    assert_eq!(
        forwarding.gre_decap_counters.reassembled_decap_refusals(),
        before + 1,
        "#16028: host-inbound-denied head refusal must be counted"
    );
}

// ---------------------------------------------------------------------
// (5) Pool-level per-source quota + tail-consult invariants, without
// the stage: two sources contend directly. Source A fills its quota
// with heads; source B's head still creates; a tail with no head
// creates nothing even when offered as Tail for B.
// ---------------------------------------------------------------------
#[test]
fn pool_per_source_quota_and_tail_consult_16028() {
    let _lock = gre_outer_frag_counter_test_lock();
    let inner = build_gre_inner_icmp_packet_v4();
    let whole = build_gre_to_self_outer_frame_v4(0, &inner);
    let (head, tail) = split_v4_outer_16028(&whole, 16);
    let mut pool = GreReassembler::new();
    let now = 50_000_000_000u64;
    // Tail-consult: no entry, no creation.
    assert!(
        pool.offer(
            &tail,
            frag_meta_16028(&tail, false),
            now,
            OfferAdmission::Tail
        )
        .is_none()
    );
    assert_eq!(
        pool.buffered_len(),
        0,
        "#16028: Tail offer must never create"
    );
    // Admission/offset mismatch is refused, never creates.
    assert!(
        pool.offer(
            &tail,
            frag_meta_16028(&tail, false),
            now,
            OfferAdmission::Head
        )
        .is_none()
    );
    assert_eq!(pool.buffered_len(), 0);
    // Source A (203.0.113.9 per frag_meta_16028) fills its sub-quota.
    for i in 0..MAX_GRE_FRAG_DATAGRAMS_PER_SRC {
        let h = reident_16028(&head, 0x6000 + i as u16);
        assert!(
            pool.offer(
                &h,
                frag_meta_16028(&h, true),
                now + i as u64,
                OfferAdmission::Head
            )
            .is_none(),
            "head {i} buffers (incomplete)"
        );
    }
    assert_eq!(pool.buffered_len(), MAX_GRE_FRAG_DATAGRAMS_PER_SRC);
    // One more A head: over quota — refused, still no eviction.
    let extra = reident_16028(&head, 0x6fff);
    assert!(
        pool.offer(
            &extra,
            frag_meta_16028(&extra, true),
            now + 100,
            OfferAdmission::Head
        )
        .is_none()
    );
    assert_eq!(
        pool.buffered_len(),
        MAX_GRE_FRAG_DATAGRAMS_PER_SRC,
        "#16028: over-quota head must not evict or create"
    );
    // Source B head (different outer source) still creates.
    let mut meta_b = frag_meta_16028(&head, true);
    meta_b.flow_src_addr[..4].copy_from_slice(&[198, 51, 100, 23]);
    let mut head_b = head.clone();
    head_b[14 + 12..14 + 16].copy_from_slice(&[198, 51, 100, 23]);
    head_b[14 + 10] = 0;
    head_b[14 + 11] = 0;
    let sum = checksum16(&head_b[14..14 + 20]);
    head_b[14 + 10..14 + 12].copy_from_slice(&sum.to_be_bytes());
    let head_b = reident_16028(&head_b, 0x7000);
    assert!(
        pool.offer(&head_b, meta_b, now + 101, OfferAdmission::Head)
            .is_none(),
        "source B head buffers (incomplete)"
    );
    assert_eq!(
        pool.buffered_len(),
        MAX_GRE_FRAG_DATAGRAMS_PER_SRC + 1,
        "#16028: second source must not be starved by first source's quota fill"
    );
}
