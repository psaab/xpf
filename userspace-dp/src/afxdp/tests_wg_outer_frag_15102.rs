//! #15102: outer-fragmented WireGuard must reassemble before decap, and a
//! WG tail must stay on the helper (not the kernel).

use super::tests_support::*;
use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::gre_reassembly::{GreReassembler, gre_outer_frag_counter_test_lock};
use crate::afxdp::poll_stages::{WgDecapStage, stage_wg_decap};
use crate::afxdp::test_fixtures::wg_outer_mtu_snapshot;
use crate::afxdp::wg::tests::established_pair;
use crate::afxdp::wg::{WgEngine, WgWorkerScratch};

#[path = "../../../userspace-xdp/src/gre_classify.rs"]
mod shim_gre_classify;

const WG_PORT_15102: u16 = 51820;
const XPF_OUTER_15102: [u8; 4] = [172, 16, 80, 8];
const PEER_OUTER_15102: [u8; 4] = [203, 0, 113, 7];

fn inner_v4_15102(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0u8; 20 + 8];
    p[0] = 0x45;
    let total = p.len() as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p[8] = 64;
    p[9] = PROTO_UDP;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[20..22].copy_from_slice(&1111u16.to_be_bytes());
    p[22..24].copy_from_slice(&2222u16.to_be_bytes());
    p[24..26].copy_from_slice(&8u16.to_be_bytes());
    p
}

fn outer_frame_15102(record: &[u8], dst_port: u16) -> Vec<u8> {
    let mut f = vec![0u8; 14 + 20 + 8 + record.len()];
    f[..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
    f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    f[14] = 0x45;
    let ip_total = (20 + 8 + record.len()) as u16;
    f[16..18].copy_from_slice(&ip_total.to_be_bytes());
    f[18..20].copy_from_slice(&0x1510u16.to_be_bytes());
    f[22] = 64;
    f[23] = PROTO_UDP;
    f[26..30].copy_from_slice(&PEER_OUTER_15102);
    f[30..34].copy_from_slice(&XPF_OUTER_15102);
    f[34..36].copy_from_slice(&51820u16.to_be_bytes());
    f[36..38].copy_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + record.len()) as u16;
    f[38..40].copy_from_slice(&udp_len.to_be_bytes());
    f[42..].copy_from_slice(record);
    f
}

fn outer_meta_15102(frame_len: usize) -> UserspaceDpMeta {
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
    m.flow_src_addr[..4].copy_from_slice(&PEER_OUTER_15102);
    m.flow_dst_addr[..4].copy_from_slice(&XPF_OUTER_15102);
    m.flow_src_port = 51820;
    m.flow_dst_port = WG_PORT_15102;
    m
}

fn split_v4_outer_wg(frame: &[u8], split_payload: usize) -> (Vec<u8>, Vec<u8>) {
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

fn frag_meta_wg(frame: &[u8], first: bool) -> UserspaceDpMeta {
    let mut meta = outer_meta_15102(frame.len());
    if !first {
        meta.protocol = crate::session::SHIM_PROTO_FRAGMENT_NO_L4;
        meta.flow_src_port = 0;
        meta.flow_dst_port = 0;
    }
    meta
}

fn forwarding_with_engine_15102(resp: WgEngine) -> ForwardingState {
    let mut forwarding = build_forwarding_state(&wg_outer_mtu_snapshot());
    let id = *forwarding
        .wg_engines
        .keys()
        .next()
        .expect("fixture configures a WireGuard tunnel");
    forwarding.wg_engines.insert(id, std::sync::Arc::new(resp));
    forwarding
}

fn encrypted_frames_15102() -> (ForwardingState, Vec<u8>, Vec<u8>, Vec<u8>) {
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (init, resp, _init_pub, resp_pub) = established_pair(allowed.clone(), allowed);
    let forwarding = forwarding_with_engine_15102(resp);
    let inner = inner_v4_15102([10, 123, 0, 5], [10, 0, 61, 102]);
    // Two DISTINCT records (encap advances the counter): the whole-record
    // control must not consume the fragmented record, or the engine's
    // replay window correctly refuses its second open.
    let mut wire = vec![0u8; 2048];
    let enc = init
        .try_encap(&resp_pub, &inner, &mut wire)
        .expect("encap control");
    let control_frame = outer_frame_15102(&wire[..enc.len], WG_PORT_15102);
    let mut wire2 = vec![0u8; 2048];
    let enc2 = init
        .try_encap(&resp_pub, &inner, &mut wire2)
        .expect("encap fragmented");
    let frame = outer_frame_15102(&wire2[..enc2.len], WG_PORT_15102);
    (forwarding, control_frame, frame, inner)
}

#[test]
fn wg_outer_fragment_v4_reassembles_and_decaps_exactly_once_15102() {
    let _lock = gre_outer_frag_counter_test_lock();
    let (forwarding, whole, frag_whole, inner) = encrypted_frames_15102();
    let scratch = WgWorkerScratch::new(4096);
    // Control: whole decaps.
    let control = crate::afxdp::wg::decap::try_wg_decap_from_frame(
        &whole,
        outer_meta_15102(whole.len()),
        &forwarding,
        &scratch,
    )
    .expect("whole WG control must decap");
    assert_eq!(&control.frame[14..], &inner[..]);

    let (head, tail) = split_v4_outer_wg(&frag_whole, 16);
    // Premise: head alone must NOT decap (truncated AEAD record). On
    // pre-fix master this is the failure the issue names; the stage had
    // no fragment branch at all.
    assert!(
        crate::afxdp::wg::decap::try_wg_decap_from_frame(
            &head,
            frag_meta_wg(&head, true),
            &forwarding,
            &scratch
        )
        .is_none(),
        "fragment head alone must not decap"
    );

    let mut pool = GreReassembler::new();
    let now = 3_000_000_000u64;
    let mut allows = |_: &[u8], _: UserspaceDpMeta| true;
    // Tail first: no buffered head -> not buffered, no state created.
    match stage_wg_decap(
        &tail,
        frag_meta_wg(&tail, false),
        &forwarding,
        &scratch,
        &mut pool,
        now,
        &mut allows,
    ) {
        WgDecapStage::NotWg(_) => {}
        WgDecapStage::Buffered => panic!("stray WG tail must not be buffered without a head"),
        WgDecapStage::Decapped(..) => panic!("stray tail must not decap"),
        WgDecapStage::FilterDropped => panic!("stray tail must not filter-drop"),
    }
    assert_eq!(
        pool.buffered_len(),
        0,
        "stray tail creates no reassembly state"
    );

    // Head: buffered.
    match stage_wg_decap(
        &head,
        frag_meta_wg(&head, true),
        &forwarding,
        &scratch,
        &mut pool,
        now + 1,
        &mut allows,
    ) {
        WgDecapStage::Buffered => {}
        other => panic!(
            "WG head must buffer, got {}",
            match other {
                WgDecapStage::Decapped(..) => "Decapped",
                WgDecapStage::NotWg(_) => "NotWg",
                WgDecapStage::FilterDropped => "FilterDropped",
                WgDecapStage::Buffered => unreachable!(),
            }
        ),
    }
    // Tail completes: decaps exactly once, inner byte-identical.
    match stage_wg_decap(
        &tail,
        frag_meta_wg(&tail, false),
        &forwarding,
        &scratch,
        &mut pool,
        now + 2,
        &mut allows,
    ) {
        WgDecapStage::Decapped(_meta, frame) => {
            assert_eq!(
                &frame[14..],
                &inner[..],
                "reassembled WG inner must be byte-identical"
            );
        }
        WgDecapStage::Buffered => panic!("head+tail must complete and decap"),
        WgDecapStage::NotWg(_) => panic!("head+tail must decap, got NotWg"),
        WgDecapStage::FilterDropped => panic!("head+tail must decap, got FilterDropped"),
    }
    // Replay tail: no second decap, no state.
    match stage_wg_decap(
        &tail,
        frag_meta_wg(&tail, false),
        &forwarding,
        &scratch,
        &mut pool,
        now + 3,
        &mut allows,
    ) {
        WgDecapStage::NotWg(_) | WgDecapStage::Buffered => {}
        WgDecapStage::Decapped(..) => panic!("replayed tail must not decap a second time"),
        WgDecapStage::FilterDropped => panic!("replayed tail must not filter-drop"),
    }
    assert_eq!(pool.buffered_len(), 0);
}

#[test]
fn wg_fragment_shim_truth_table_15102() {
    use shim_gre_classify::wg_fragment_stays_on_helper;
    // (protocol, wire, is_fragment, wg_rx_armed, stays)
    let cases = [
        (
            17u8,
            17u8,
            true,
            true,
            true,
            "first fragment (UDP head) stays on helper",
        ),
        (
            255,
            17,
            true,
            true,
            true,
            "WG tail (255/UDP) stays on helper, not cpumap_or_pass",
        ),
        (
            17,
            17,
            false,
            true,
            false,
            "whole UDP keeps ordinary disposition",
        ),
        (
            255,
            17,
            true,
            false,
            false,
            "no WG configured: tail keeps today's disposition",
        ),
        (255, 47, true, true, false, "GRE tail is not WG reassembly"),
        (255, 6, true, true, false, "TCP tail is not WG reassembly"),
        (
            4,
            17,
            true,
            true,
            false,
            "transport-data head is claimed via wg_worker_claim, predicate row needs UDP/255",
        ),
    ];
    for (p, w, frag, armed, want, why) in cases {
        // Row 7 uses protocol 4 as a stand-in non-UDP/255 value; the
        // predicate must still be false.
        assert_eq!(
            wg_fragment_stays_on_helper(p, w, frag, armed),
            want,
            "{why}"
        );
    }
}

fn outer_frame_v6_15102(record: &[u8], dst_port: u16) -> Vec<u8> {
    let src: std::net::Ipv6Addr = "2001:db8::7".parse().unwrap();
    let dst: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
    let mut f = vec![0u8; 14 + 40 + 8 + record.len()];
    f[..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
    f[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    f[14] = 0x60;
    f[18..20].copy_from_slice(&((8 + record.len()) as u16).to_be_bytes());
    f[20] = PROTO_UDP;
    f[21] = 64;
    f[22..38].copy_from_slice(&src.octets());
    f[38..54].copy_from_slice(&dst.octets());
    f[54..56].copy_from_slice(&51820u16.to_be_bytes());
    f[56..58].copy_from_slice(&dst_port.to_be_bytes());
    f[58..60].copy_from_slice(&((8 + record.len()) as u16).to_be_bytes());
    f[62..].copy_from_slice(record);
    let _ = (src, dst);
    f
}

fn build_v6_outer_fragmented_wg(frame: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let l3 = 14usize;
    let payload = frame[l3 + 40..].to_vec();
    let split = 16usize;
    let mk = |offset_units: u16, more: bool, part: &[u8]| -> Vec<u8> {
        let mut f = frame[..l3].to_vec();
        f.extend_from_slice(&frame[l3..l3 + 4]);
        let plen = (8 + part.len()) as u16;
        f.extend_from_slice(&plen.to_be_bytes());
        f.push(44);
        f.push(64);
        f.extend_from_slice(&frame[l3 + 8..l3 + 40]);
        let word = ((offset_units & 0x1fff) << 3) | if more { 1 } else { 0 };
        f.push(PROTO_UDP);
        f.push(0);
        f.extend_from_slice(&word.to_be_bytes());
        f.extend_from_slice(&0x15102u32.to_be_bytes());
        f.extend_from_slice(part);
        f
    };
    (
        mk(0, true, &payload[..split]),
        mk((split / 8) as u16, false, &payload[split..]),
    )
}

fn frag_meta_v6_wg(frame: &[u8], first: bool) -> UserspaceDpMeta {
    let src: std::net::Ipv6Addr = "2001:db8::7".parse().unwrap();
    let dst: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
    let mut m = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 14 + 48,
        payload_offset: 14 + 48,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_UDP,
        config_generation: 0x5150_4646,
        fib_generation: 0x0BAD_F00D,
        rx_queue_index: 3,
        ingress_ifindex: 12,
        ..UserspaceDpMeta::default()
    };
    m.flow_src_addr = src.octets();
    m.flow_dst_addr = dst.octets();
    if !first {
        m.protocol = crate::session::SHIM_PROTO_FRAGMENT_NO_L4;
    } else {
        m.flow_src_port = 51820;
        m.flow_dst_port = WG_PORT_15102;
        m.l4_offset = 14 + 48;
        m.payload_offset = m.l4_offset + 8;
    }
    m
}

#[test]
fn wg_outer_fragment_v6_reassembles_at_pool_level_15102() {
    // Pool-level v6: the reassembler must rebuild an unfragmented UDP
    // datagram (Fragment header removed, ports restored). Full WG decap
    // on a v6 listener is covered by the existing v6 decap cells; a v6
    // WG listener fixture with a live engine is the decap_tests harness.
    let _lock = gre_outer_frag_counter_test_lock();
    let record = vec![4u8; 64];
    let whole = outer_frame_v6_15102(&record, WG_PORT_15102);
    let (head, tail) = build_v6_outer_fragmented_wg(&whole);
    let mut pool = GreReassembler::new();
    let now = 4_000_000_000u64;
    assert!(
        pool.offer_for_protocol(&head, frag_meta_v6_wg(&head, true), now, PROTO_UDP)
            .is_none()
    );
    let (frame, meta) = pool
        .offer_for_protocol(&tail, frag_meta_v6_wg(&tail, false), now + 1, PROTO_UDP)
        .expect("v6 WG head+tail must complete reassembly");
    assert_eq!(meta.protocol, PROTO_UDP);
    assert_eq!(meta.flow_dst_port, WG_PORT_15102);
    // Rebuilt frame carries the whole UDP datagram after the fixed header.
    let l3 = 14usize;
    assert_eq!(&frame[l3 + 40 + 8..], &record[..]);
    assert_eq!(
        frame[l3 + 6],
        PROTO_UDP,
        "Fragment next-header patched to UDP"
    );
}
