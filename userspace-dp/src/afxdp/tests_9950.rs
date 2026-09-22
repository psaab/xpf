// STEP-0 repro cells for cohort #9950 (F-035, F-036, F-053).
// Each cell asserts the FIXED behavior, so on base it is RED.
// Bounded: named members + named tests only.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::test_zone_ids::*;
use crate::{
    DestinationNATRuleSnapshot, FirewallFilterSnapshot, FirewallTermSnapshot, NeighborSnapshot,
    PolicyRuleSnapshot, RouteSnapshot, SourceNATRuleSnapshot,
};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

fn ipv4_frag_frame_9950(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    id: u16,
    frag_off: u16,
    payload: &[u8],
) -> Vec<u8> {
    ipv4_frag_frame_9950_with_mac(src, dst, proto, id, frag_off, payload, TEST_LAN_MAC)
}

/// Build eth(14) + IPv4(20) + payload with explicit id/frag_off/proto/addrs.
fn ipv4_frag_frame_9950_with_mac(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    id: u16,
    frag_off: u16,
    payload: &[u8],
    dst_mac: [u8; 6],
) -> Vec<u8> {
    let mut f = vec![
        0x02, 0xbf, 0x72, 0x00, 0x80, 0x08, 0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5, 0x08, 0x00,
    ];
    f[..6].copy_from_slice(&dst_mac);
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    let total = (20 + payload.len()) as u16;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip[4..6].copy_from_slice(&id.to_be_bytes());
    ip[6..8].copy_from_slice(&frag_off.to_be_bytes());
    ip[8] = 64;
    ip[9] = proto;
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    // IPv4 header checksum.
    let sum = checksum16(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    f.extend_from_slice(&ip);
    f.extend_from_slice(payload);
    f
}

fn frag_meta_9950(
    ingress_ifindex: u32,
    proto: u8,
    tcp_flags: u8,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    pkt_len: u16,
) -> UserspaceDpMeta {
    let s = src.octets();
    let d = dst.octets();
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex,
        addr_family: libc::AF_INET as u8,
        protocol: proto,
        pkt_len,
        l3_offset: 14,
        l4_offset: 34,
        flow_src_port: 33333,
        flow_dst_port: 443,
        flow_src_addr: [s[0], s[1], s[2], s[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [d[0], d[1], d[2], d[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        tcp_flags,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}

fn checksum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
/// Parse the on-wire IPv4 src/dst from a rewritten frame, handling the
/// egress VLAN push (wan reth0.80 adds 4 bytes, l3 at 18; lan untagged at 14).
fn wire_ipv4_addrs_9950(out: &[u8]) -> (Ipv4Addr, Ipv4Addr) {
    let l3 = if out.len() >= 14 && out[12] == 0x81 && out[13] == 0x00 {
        18
    } else {
        14
    };
    let src = Ipv4Addr::new(out[l3 + 12], out[l3 + 13], out[l3 + 14], out[l3 + 15]);
    let dst = Ipv4Addr::new(out[l3 + 16], out[l3 + 17], out[l3 + 18], out[l3 + 19]);
    (src, dst)
}

/// F-035: overlapping fragments must be denied in BOTH arrival orders, while a
/// benign adjacent (non-overlapping) pair still forwards.
#[test]
fn f035_overlap_fragments_denied_both_orders_9950() {
    // Plain forwarding, no NAT: default-permit so the only drop can be the
    // overlap detector. First fragment earns the verdict; the overlapping
    // tail rewrites bytes the receiver reassembles after enforcement.
    let src = Ipv4Addr::new(10, 0, 61, 100);
    let dst = Ipv4Addr::new(172, 16, 80, 200);

    for (label, first_off, second_off, expect_second_forward) in [
        // Overlapping: first covers 0..16, second covers 8..24 -> overlap 8..16.
        ("overlap-first-then-tail", 0x2000u16, 0x0001u16, 0),
        // Same overlap, reverse arrival order: tail first, then head.
        ("overlap-tail-then-first", 0x0001u16, 0x2000u16, 0),
        // Positive control: adjacent, no overlap (0..16 then 16..24).
        ("benign-adjacent", 0x2000u16, 0x0002u16, 1),
        // Benign out-of-order disjoint: tail (16..24) arrives before the head.
        ("benign-adjacent-reversed", 0x0002u16, 0x2000u16, 1),
    ] {
        let mut snapshot = policy_deny_snapshot();
        snapshot.default_policy = "permit".to_string();
        snapshot.policies.clear();
        snapshot.neighbors = vec![frag_transit_wan_neighbor()];
        let forwarding = build_forwarding_state(&snapshot);
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
        binding.interface = Arc::<str>::from("reth1.0");
        let mut sessions = SessionTable::new();
        let ha_state = BTreeMap::new();

        // First fragment payload: 16 bytes (8B-aligned for MF=1 — wire-valid).
        let payload_first = [0xAAu8; 16];
        // Second fragment payload: 16 bytes for overlap cases, 8 for benign.
        let payload_second: Vec<u8> = if expect_second_forward == 1 {
            vec![0xBBu8; 8]
        } else {
            vec![0xBBu8; 16]
        };
        let id = 0xBEEF;
        // When the first arrival is a tail (offset != 0), it takes the tail payload.
        let (frame_first_arrival, frame_second_arrival) = if first_off != 0x2000 {
            let tail = ipv4_frag_frame_9950(src, dst, PROTO_TCP, id, first_off, &payload_second);
            let head = ipv4_frag_frame_9950(src, dst, PROTO_TCP, id, second_off, &payload_first);
            (tail, head)
        } else {
            let head = ipv4_frag_frame_9950(src, dst, PROTO_TCP, id, first_off, &payload_first);
            let tail = ipv4_frag_frame_9950(src, dst, PROTO_TCP, id, second_off, &payload_second);
            (head, tail)
        };
        let meta_a = frag_meta_9950(
            24,
            PROTO_TCP,
            0x10,
            src,
            dst,
            frame_first_arrival.len() as u16,
        );
        let meta_b = frag_meta_9950(
            24,
            PROTO_TCP,
            0x10,
            src,
            dst,
            frame_second_arrival.len() as u16,
        );

        let (_b1, dbg1) = txn_run_descriptor_checked(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &frame_first_arrival,
            meta_a,
            true,
        );
        assert_eq!(
            dbg1.forward, 1,
            "{label}: first arrival must forward (otherwise the overlap signal is vacuous)"
        );
        let d0 = crate::fragment_overlap::FRAG_OVERLAP_DROPPED
            .load(std::sync::atomic::Ordering::Relaxed);
        let (_b2, dbg2) = txn_run_descriptor_checked(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &frame_second_arrival,
            meta_b,
            true,
        );
        assert_eq!(
            dbg2.forward, expect_second_forward,
            "{label}: second arrival forward must be {expect_second_forward} (overlap denied, benign forwarded)"
        );
        // The drop (if any) is the overlap detector's — the fixture permits everything
        // else (default-permit, no screens, neighbor present), so attribution is exact.
        let want_drops = if expect_second_forward == 0 { 1u64 } else { 0 };
        assert_eq!(
            crate::fragment_overlap::FRAG_OVERLAP_DROPPED
                .load(std::sync::atomic::Ordering::Relaxed)
                .wrapping_sub(d0),
            want_drops,
            "{label}: overlap-drop counter delta"
        );
    }
}

/// A queued fragment that fails the production TTL rewrite must fail its
/// overlap admission. Otherwise the late overlap check can reclaim the
/// recorded datagram and admit a subsequent overlapping fragment.
#[test]
fn f035_ttl_rewrite_failure_keeps_overlap_anchored_10285() {
    let src = Ipv4Addr::new(10, 0, 61, 100);
    let dst = Ipv4Addr::new(172, 16, 80, 200);
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let head = ipv4_frag_frame_9950(src, dst, PROTO_UDP, 0xA285, 0x2000, &[0xAA; 16]);
    let tail = ipv4_frag_frame_9950(src, dst, PROTO_UDP, 0xA285, 0x0002, &[0xBB; 8]);
    let overlap = ipv4_frag_frame_9950(src, dst, PROTO_UDP, 0xA285, 0x0001, &[0xCC; 16]);
    let head_meta = frag_meta_9950(24, PROTO_UDP, 0, src, dst, head.len() as u16);
    let tail_meta = frag_meta_9950(24, PROTO_UDP, 0, src, dst, tail.len() as u16);
    let overlap_meta = frag_meta_9950(24, PROTO_UDP, 0, src, dst, overlap.len() as u16);

    let (_batch, first_dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &head,
        head_meta,
        true,
    );
    assert_eq!(first_dbg.forward, 1, "head must establish the overlap anchor");
    let mut head_request = binding
        .scratch
        .scratch_forwards
        .pop()
        .expect("head pending TX request");
    head_request
        .overlap_admissions
        .take()
        .expect("head overlap admissions")
        .commit();
    drop(head_request);

    let (_batch, tail_dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &tail,
        tail_meta,
        true,
    );
    assert_eq!(tail_dbg.forward, 1, "adjacent terminal tail must queue");
    let pending = binding
        .scratch
        .scratch_forwards
        .pop()
        .expect("terminal tail pending TX request");
    let desc = pending.desc;
    let area = binding.umem.area();
    {
        let frame = unsafe { area.slice_mut_unchecked(desc.addr as usize, tail.len()) }
            .expect("mutable tail UMEM frame");
        frame[14 + 8] = 1;
        frame[14 + 10..14 + 12].fill(0);
        let ip_sum = checksum16(&frame[14..34]);
        frame[14 + 10..14 + 12].copy_from_slice(&ip_sum.to_be_bytes());
    }
    assert!(
        crate::afxdp::frame::rewrite_forwarded_frame_in_place(
            area,
            desc,
            tail_meta,
            &pending.decision,
            pending.apply_nat_on_fabric,
            pending.expected_ports,
            0,
        )
        .is_none(),
        "TTL=1 must be refused by the production TX rewrite"
    );
    drop(pending);

    let drops_before =
        crate::fragment_overlap::FRAG_OVERLAP_DROPPED.load(std::sync::atomic::Ordering::Relaxed);
    let (_batch, overlap_dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &overlap,
        overlap_meta,
        true,
    );
    assert_eq!(
        overlap_dbg.forward, 0,
        "a later overlapping fragment must stay blocked after TTL refusal"
    );
    assert_eq!(
        crate::fragment_overlap::FRAG_OVERLAP_DROPPED
            .load(std::sync::atomic::Ordering::Relaxed)
            .wrapping_sub(drops_before),
        1,
        "the overlap detector must attribute the blocked tail"
    );
}

/// A refused non-terminal middle fragment must invalidate the datagram's
/// eventual terminal completion. The terminal fragment is allowed and queued,
/// but a later overlap remains blocked by the failed middle admission.
#[test]
fn f035_middle_ttl_rewrite_failure_then_terminal_keeps_overlap_anchored_10285() {
    let src = Ipv4Addr::new(10, 0, 61, 100);
    let dst = Ipv4Addr::new(172, 16, 80, 200);
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let head = ipv4_frag_frame_9950(src, dst, PROTO_UDP, 0xD286, 0x2000, &[0xAA; 16]);
    let middle =
        ipv4_frag_frame_9950(src, dst, PROTO_UDP, 0xD286, 0x2002, &[0xBB; 8]);
    let terminal =
        ipv4_frag_frame_9950(src, dst, PROTO_UDP, 0xD286, 0x0003, &[0xCC; 8]);
    let overlap =
        ipv4_frag_frame_9950(src, dst, PROTO_UDP, 0xD286, 0x0001, &[0xDD; 16]);
    let head_meta = frag_meta_9950(24, PROTO_UDP, 0, src, dst, head.len() as u16);
    let middle_meta = frag_meta_9950(24, PROTO_UDP, 0, src, dst, middle.len() as u16);
    let terminal_meta = frag_meta_9950(24, PROTO_UDP, 0, src, dst, terminal.len() as u16);
    let overlap_meta = frag_meta_9950(24, PROTO_UDP, 0, src, dst, overlap.len() as u16);

    let (_batch, head_dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &head,
        head_meta,
        true,
    );
    assert_eq!(head_dbg.forward, 1, "head must establish the overlap anchor");
    let mut head_request = binding
        .scratch
        .scratch_forwards
        .pop()
        .expect("head pending TX request");
    head_request
        .overlap_admissions
        .take()
        .expect("head overlap admissions")
        .commit();
    drop(head_request);

    let (_batch, middle_dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &middle,
        middle_meta,
        true,
    );
    assert_eq!(
        middle_dbg.forward, 1,
        "the non-terminal middle must queue before the rewrite refusal"
    );
    let mut middle_request = binding
        .scratch
        .scratch_forwards
        .pop()
        .expect("middle pending TX request");
    assert!(
        middle_request.overlap_admissions.is_some(),
        "middle request must carry its overlap admission into dispatch"
    );
    let middle_desc = middle_request.desc;
    let area = binding.umem.area();
    {
        let frame =
            unsafe { area.slice_mut_unchecked(middle_desc.addr as usize, middle.len()) }
                .expect("mutable middle UMEM frame");
        frame[14 + 8] = 1;
        frame[14 + 10..14 + 12].fill(0);
        let ip_sum = checksum16(&frame[14..34]);
        frame[14 + 10..14 + 12].copy_from_slice(&ip_sum.to_be_bytes());
    }
    assert!(
        crate::afxdp::frame::rewrite_forwarded_frame_in_place(
            area,
            middle_desc,
            middle_meta,
            &middle_request.decision,
            middle_request.apply_nat_on_fabric,
            middle_request.expected_ports,
            0,
        )
        .is_none(),
        "TTL=1 must refuse the middle request in the production rewrite"
    );
    drop(middle_request);
    assert_eq!(
        forwarding.nat64.frag_overlap.len(),
        1,
        "failed middle admission must retain the datagram entry"
    );

    let (_batch, terminal_dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &terminal,
        terminal_meta,
        true,
    );
    assert_eq!(
        terminal_dbg.forward, 1,
        "the adjacent terminal fragment must still forward"
    );
    assert_eq!(
        terminal_dbg.tx, 1,
        "the allowed terminal fragment must queue for TX"
    );
    let mut terminal_request = binding
        .scratch
        .scratch_forwards
        .pop()
        .expect("terminal pending TX request");
    terminal_request
        .overlap_admissions
        .take()
        .expect("terminal overlap admissions")
        .commit();
    drop(terminal_request);
    assert_eq!(
        forwarding.nat64.frag_overlap.len(),
        1,
        "failed middle keeps the complete datagram protected after terminal TX acceptance"
    );

    let (_batch, overlap_dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &overlap,
        overlap_meta,
        true,
    );
    assert_eq!(
        overlap_dbg.forward, 0,
        "a later overlap must remain blocked after middle rewrite failure"
    );
}

/// A terminal fragment refused by a DSCP output filter must not release the
/// recorded datagram. The next overlapping fragment remains denied.
#[test]
fn f035_terminal_tail_dscp_output_refusal_keeps_overlap_anchored_10285() {
    let src = Ipv4Addr::new(10, 0, 61, 100);
    let dst = Ipv4Addr::new(172, 16, 80, 200);
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "wan-drop-ef".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "drop-ef-udp".into(),
            protocols: vec!["udp".into()],
            dscp_values: vec![46],
            action: "discard".into(),
            ..Default::default()
        }],
    }];
    snapshot.interfaces[1].filter_output_v4 = "wan-drop-ef".into();
    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let head = ipv4_frag_frame_9950(src, dst, PROTO_UDP, 0xD285, 0x2000, &[0xAA; 16]);
    let mut tail = ipv4_frag_frame_9950(src, dst, PROTO_UDP, 0xD285, 0x0002, &[0xBB; 8]);
    tail[14 + 1] = 46 << 2;
    tail[14 + 10..14 + 12].fill(0);
    let tail_sum = checksum16(&tail[14..34]);
    tail[14 + 10..14 + 12].copy_from_slice(&tail_sum.to_be_bytes());
    let head_meta = frag_meta_9950(24, PROTO_UDP, 0, src, dst, head.len() as u16);
    let mut tail_meta = frag_meta_9950(24, PROTO_UDP, 0, src, dst, tail.len() as u16);
    tail_meta.dscp = 46;

    let (_batch, head_dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &head,
        head_meta,
        true,
    );
    assert_eq!(head_dbg.forward, 1, "head must establish the overlap anchor");
    let mut head_request = binding
        .scratch
        .scratch_forwards
        .pop()
        .expect("head pending TX request");
    head_request
        .overlap_admissions
        .take()
        .expect("head overlap admissions")
        .commit();
    drop(head_request);

    let drops_before_tail =
        crate::fragment_overlap::FRAG_OVERLAP_DROPPED.load(std::sync::atomic::Ordering::Relaxed);
    let (_batch, tail_dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &tail,
        tail_meta,
        true,
    );
    assert_eq!(
        tail_dbg.tx, 0,
        "the terminal DSCP-refused tail must not queue for TX"
    );
    assert_eq!(
        crate::fragment_overlap::FRAG_OVERLAP_DROPPED
            .load(std::sync::atomic::Ordering::Relaxed),
        drops_before_tail,
        "the terminal tail must reach the output filter, not the overlap gate"
    );
    assert!(
        binding.scratch.scratch_forwards.is_empty(),
        "output-filter refusal must not leave a forward request"
    );

    let overlap = ipv4_frag_frame_9950(src, dst, PROTO_UDP, 0xD285, 0x0001, &[0xCC; 16]);
    let overlap_meta = frag_meta_9950(24, PROTO_UDP, 0, src, dst, overlap.len() as u16);
    let (_batch, overlap_dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &overlap,
        overlap_meta,
        true,
    );
    assert_eq!(
        overlap_dbg.forward, 0,
        "a later overlapping fragment must remain blocked"
    );
}

#[test]
fn f035_shard_full_drop_is_not_forward_accounted_10285() {
    let src = Ipv4Addr::new(10, 0, 61, 100);
    let dst = Ipv4Addr::new(172, 16, 80, 200);
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    let forwarding = build_forwarding_state(&snapshot);
    let tracker = &forwarding.nat64.frag_overlap;
    let base = crate::fragment_overlap::OverlapKey {
        addr_family: libc::AF_INET as u8,
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        ident: 0,
        protocol: PROTO_UDP,
        routing_domain: 0,
    };
    let shard = crate::fragment_overlap::overlap_shard_index(&base);
    let mut keys = Vec::new();
    for ident in 0u32.. {
        let mut key = base;
        key.ident = ident;
        if crate::fragment_overlap::overlap_shard_index(&key) == shard {
            keys.push(key);
            if keys.len() == crate::fragment_overlap::OVERLAP_CAP_PER_SHARD + 1 {
                break;
            }
        }
    }
    for key in keys.iter().take(crate::fragment_overlap::OVERLAP_CAP_PER_SHARD) {
        assert!(!tracker.check_and_record_fragment(
            *key,
            0,
            8,
            false,
            123_000_000_000,
            &crate::fragment_overlap::FRAG_OVERLAP_DROPPED,
        ));
    }
    let full0 = crate::fragment_overlap::FRAG_OVERLAP_SHARD_FULL_DROPPED
        .load(std::sync::atomic::Ordering::Relaxed);
    let frame = ipv4_frag_frame_9950(
        src,
        dst,
        PROTO_UDP,
        keys[crate::fragment_overlap::OVERLAP_CAP_PER_SHARD].ident as u16,
        0x2000,
        &[0xAA; 16],
    );
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let (batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        frag_meta_9950(24, PROTO_UDP, 0, src, dst, frame.len() as u16),
        true,
    );
    assert_eq!(
        crate::fragment_overlap::FRAG_OVERLAP_SHARD_FULL_DROPPED
            .load(std::sync::atomic::Ordering::Relaxed)
            .wrapping_sub(full0),
        1,
        "single-tenant shard flood must be observable as SHARD_FULL"
    );
    assert_eq!(
        dbg.forward, 0,
        "a shard-full fragment drop is not a forwarded packet"
    );
    assert_eq!(
        batch.forward_candidate_packets, 0,
        "a shard-full fragment drop is not forward-accounted"
    );
    assert_eq!(tracker.len(), crate::fragment_overlap::OVERLAP_CAP_PER_SHARD);
}

/// F-036: DNAT reply non-first fragments must carry the translated source on
/// the wire, not the internal server address.
#[test]
fn f036_dnat_reply_nonfirst_translated_on_wire_9950() {
    // Topology: client 198.51.100.10 (wan) -> public 172.16.80.8:443 DNAT to
    // internal 10.0.61.102:8443 (lan). No SNAT of any kind: with an SNAT rule
    // the #6122 probe would match the reply src and fail closed, hiding the
    // DNAT-reverse gap this cell proves.
    let client = Ipv4Addr::new(198, 51, 100, 10);
    let public = Ipv4Addr::new(172, 16, 80, 8);
    let internal = Ipv4Addr::new(10, 0, 61, 102);
    let client_port = 54321u16;
    let public_port = 443u16;
    let internal_port = 8443u16;

    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    // LAN connected route for 10.0.61.0/24 (otherwise the DNAT-translated dst
    // resolves via the default wan gateway, egressing wan instead of lan, which
    // makes the reply foreign (#9519) and skips the #9950 hit-tail install).
    snapshot.interfaces[0].addresses = vec![crate::InterfaceAddressSnapshot {
        family: "inet".to_string(),
        address: "10.0.61.1/24".to_string(),
        scope: 0,
    }];
    snapshot.destination_nat_rules = vec![DestinationNATRuleSnapshot {
        counter_id: 0,
        name: "web-dnat".to_string(),
        from_zone: "wan".to_string(),
        from_interface: String::new(),
        from_routing_instance: String::new(),
        source_addresses: vec![],
        destination_address: "172.16.80.8".to_string(),
        destination_prefix: String::new(),
        destination_port: 443,
        protocol: "tcp".to_string(),
        pool_address: "10.0.61.102".to_string(),
        pool_port: 8443,
        match_source_ports: vec![],
        match_destination_ports: vec![],
        match_icmp_type: None,
        match_icmp_code: None,
        off: false,
        ..Default::default()
    }];
    // Default route via wan gateway + neighbors for gateway and internal host.
    snapshot.routes = vec![RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "0.0.0.0/0".to_string(),
        next_hops: vec!["172.16.80.1@reth0.80".to_string()],
        discard: false,
        next_table: String::new(),
        preference: 0,
        rule_priority: 0,
    }];
    snapshot.neighbors = vec![
        NeighborSnapshot {
            interface: "ge-0-0-0.80".to_string(),
            ifindex: 12,
            family: "inet".to_string(),
            ip: "172.16.80.1".to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            state: "reachable".to_string(),
            router: true,
            link_local: false,
            ..Default::default()
        },
        NeighborSnapshot {
            interface: "reth1.0".to_string(),
            ifindex: 24,
            family: "inet".to_string(),
            ip: "10.0.61.102".to_string(),
            mac: "02:aa:bb:cc:dd:01".to_string(),
            state: "reachable".to_string(),
            router: false,
            link_local: false,
            ..Default::default()
        },
    ];
    // No source_nat_rules / static / NPTv6: pure DNAT.
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = BTreeMap::new();
    let mut sessions = SessionTable::new();

    // (1) Forward SYN (unfragmented) wan->lan: establishes the DNAT session.
    let mut binding_wan = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding_wan.interface = Arc::<str>::from("reth0.80");
    let syn = build_txn_tcp_syn_frame_v4(client, public, client_port, public_port, 0x02, crate::afxdp::tests_support::TEST_WAN_MAC);
    let meta_syn = {
        let mut m = txn_meta_v4(12, 0x02, syn.len() as u16);
        m.protocol = PROTO_TCP;
        m.flow_src_port = client_port;
        m.flow_dst_port = public_port;
        m.flow_src_addr = [198, 51, 100, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        m.flow_dst_addr = [172, 16, 80, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        m
    };
    let (_b0, dbg0) = txn_run_descriptor_checked(
        &mut binding_wan,
        &mut sessions,
        &forwarding,
        &ha_state,
        &syn,
        meta_syn,
        true,
    );
    assert_eq!(dbg0.forward, 1, "F-036 premise: forward SYN must forward");
    assert_eq!(dbg0.nat_applied_dnat, 1, "F-036 premise: forward must DNAT");

    // (2) Reply first fragment lan->wan: internal:8443 -> client:54321,
    // offset 0 MF=1, with a real TCP header (ACK). Hits the reverse session,
    // reverse-translates src to public:443, and (after fix) installs the
    // reply fragment association.
    let mut binding_lan = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding_lan.interface = Arc::<str>::from("reth1.0");
    // TCP header (20B) + 4 pad = 24B: 8B-aligned for MF=1 (wire-valid).
    let mut tcp = vec![0u8; 24];
    tcp[0..2].copy_from_slice(&internal_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&client_port.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x10; // ACK
    let reply_id = 0xC001u16;
    let reply_first = ipv4_frag_frame_9950(internal, client, PROTO_TCP, reply_id, 0x2000, &tcp);
    let meta_first = {
        let mut m = frag_meta_9950(
            24,
            PROTO_TCP,
            0x10,
            internal,
            client,
            reply_first.len() as u16,
        );
        m.flow_src_port = internal_port;
        m.flow_dst_port = client_port;
        m.l4_offset = 34;
        m
    };
    // #10130: exercise the miss path with the reply tail arriving before the
    // first fragment. The live forward DNAT session must gate this tail
    // instead of forwarding it with the untranslated internal source.
    let reordered_tail_payload = [0xAAu8; 16];
    let reordered_tail = ipv4_frag_frame_9950(
        internal,
        client,
        PROTO_TCP,
        reply_id,
        0x0003,
        &reordered_tail_payload,
    );
    let mut meta_reordered = frag_meta_9950(
        24,
        PROTO_TCP,
        0,
        internal,
        client,
        reordered_tail.len() as u16,
    );
    meta_reordered.flow_src_port = internal_port;
    meta_reordered.flow_dst_port = client_port;
    let (batch_reordered, dbg_reordered) = txn_run_descriptor_checked(
        &mut binding_lan,
        &mut sessions,
        &forwarding,
        &ha_state,
        &reordered_tail,
        meta_reordered,
        true,
    );
    assert_eq!(
        dbg_reordered.forward, 0,
        "#10130: reordered DNAT reply tail must not forward untranslated"
    );
    assert_eq!(
        batch_reordered.nat_frag_untranslated_dropped, 1,
        "#10130: session-gated reply-tail drop is observable"
    );

    let (_b1, dbg1) = txn_run_descriptor_checked(
        &mut binding_lan,
        &mut sessions,
        &forwarding,
        &ha_state,
        &reply_first,
        meta_first,
        true,
    );
    assert_eq!(
        dbg1.forward, 1,
        "F-036 premise: reply first fragment must forward"
    );
    // Reverse DNAT shows as dnat or snat depending on counter attribution;
    // require that SOME translation applied (not none).
    assert_eq!(
        dbg1.nat_applied_none, 0,
        "F-036 premise: reply first fragment must be reverse-translated"
    );

    // (3) Reply non-first fragment: same datagram, offset 3 (24 bytes), 16 bytes
    // payload (24..40, adjacent past the 24-byte first — NOT overlapping, so
    // the #9950 overlap tracker lets it through). Must inherit the reverse
    // translation: wire src == public.
    let tail_payload = [0xCCu8; 16];
    let reply_tail =
        ipv4_frag_frame_9950(internal, client, PROTO_TCP, reply_id, 0x0003, &tail_payload);
    let meta_tail = {
        let mut m = frag_meta_9950(24, PROTO_TCP, 0, internal, client, reply_tail.len() as u16);
        m.flow_src_port = internal_port;
        m.flow_dst_port = client_port;
        m
    };
    // Clear prior forwards so index 0 is this packet's request.
    binding_lan.scratch.scratch_forwards.clear();
    let (_b2, dbg2) = txn_run_descriptor_checked(
        &mut binding_lan,
        &mut sessions,
        &forwarding,
        &ha_state,
        &reply_tail,
        meta_tail,
        true,
    );
    assert_eq!(
        dbg2.forward, 1,
        "F-036: reply non-first fragment must forward (with translation, not dropped)"
    );
    assert_eq!(
        binding_lan.scratch.scratch_forwards.len(),
        1,
        "F-036: exactly one forward request for the reply tail"
    );
    let fwd = &binding_lan.scratch.scratch_forwards[0];
    // Run the production TX rewrite and read the wire source.
    let area = binding_lan.umem.area();
    let desc = crate::afxdp::XdpDesc {
        addr: 128,
        len: reply_tail.len() as u32,
        options: 0,
    };
    let result = crate::afxdp::frame::rewrite_forwarded_frame_in_place(
        area,
        desc,
        meta_tail,
        &fwd.decision,
        false,
        None,
        0,
    )
    .expect("F-036: TX rewrite must succeed");
    let out = area
        .slice(result.offset as usize, result.len as usize)
        .expect("rewritten bytes");
    let (wire_src, _wire_dst) = wire_ipv4_addrs_9950(out);
    assert_eq!(
        wire_src, public,
        "F-036 RED: reply non-first wire src must be the translated public address, not the internal server"
    );

    // #10130: a plain outbound fragment from the same internal address must
    // remain eligible for forwarding; the session gate is not a source-address
    // blanket drop.
    let plain_tail = ipv4_frag_frame_9950(
        internal,
        Ipv4Addr::new(203, 0, 113, 9),
        PROTO_TCP,
        0xC002,
        0x0003,
        &[0xDDu8; 16],
    );
    let mut meta_plain = frag_meta_9950(
        24,
        PROTO_TCP,
        0,
        internal,
        Ipv4Addr::new(203, 0, 113, 9),
        plain_tail.len() as u16,
    );
    meta_plain.flow_src_port = internal_port;
    meta_plain.flow_dst_port = 443;
    binding_lan.scratch.scratch_forwards.clear();
    let (batch_plain, dbg_plain) = txn_run_descriptor_checked(
        &mut binding_lan,
        &mut sessions,
        &forwarding,
        &ha_state,
        &plain_tail,
        meta_plain,
        true,
    );
    assert_eq!(
        dbg_plain.forward, 1,
        "#10130: unrelated plain outbound fragment must still forward"
    );
    assert_eq!(
        batch_plain.nat_frag_untranslated_dropped, 0,
        "#10130: plain outbound forwarding is not a NAT-fragment drop"
    );
    assert_eq!(
        binding_lan.scratch.scratch_forwards.len(),
        1,
        "#10130: plain fragment has one forwarding request"
    );
}

/// F-053: pool-SNAT reply non-first fragments must carry the translated
/// destination on the wire (the #6122 probe's missing arm).
#[test]
fn f053_pool_snat_reply_nonfirst_translated_on_wire_9950() {
    let internal = Ipv4Addr::new(10, 0, 61, 100);
    let external = Ipv4Addr::new(8, 8, 8, 8);
    let pool = Ipv4Addr::new(172, 16, 80, 100);
    let internal_port = 33333u16;
    let external_port = 443u16;

    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "snat-pool".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "pool-a".to_string(),
        pool_addresses: vec!["172.16.80.100".to_string()],
        port_low: 20000,
        port_high: 20999,
        ..Default::default()
    }];
    snapshot.routes = vec![RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "0.0.0.0/0".to_string(),
        next_hops: vec!["172.16.80.1@reth0.80".to_string()],
        discard: false,
        next_table: String::new(),
        preference: 0,
        rule_priority: 0,
    }];
    snapshot.neighbors = vec![
        NeighborSnapshot {
            interface: "ge-0-0-0.80".to_string(),
            ifindex: 12,
            family: "inet".to_string(),
            ip: "172.16.80.1".to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            state: "reachable".to_string(),
            router: true,
            link_local: false,
            ..Default::default()
        },
        NeighborSnapshot {
            interface: "reth1.0".to_string(),
            ifindex: 24,
            family: "inet".to_string(),
            ip: "10.0.61.100".to_string(),
            mac: "02:aa:bb:cc:dd:02".to_string(),
            state: "reachable".to_string(),
            router: false,
            link_local: false,
            ..Default::default()
        },
        // The pool address itself needs a neighbor so the UNTRANSLATED base
        // behavior (dst == pool, next-hop == dst) forwards rather than dying
        // on MissingNeighbor — otherwise the RED signal is a drop, not the
        // wire-dst the issue requires asserting.
        NeighborSnapshot {
            interface: "ge-0-0-0.80".to_string(),
            ifindex: 12,
            family: "inet".to_string(),
            ip: "172.16.80.100".to_string(),
            mac: "00:11:22:33:44:77".to_string(),
            state: "reachable".to_string(),
            router: false,
            link_local: false,
            ..Default::default()
        },
    ];
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = BTreeMap::new();
    let mut sessions = SessionTable::new();

    // (1) Forward SYN lan->wan: allocates the pool port.
    let mut binding_lan = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding_lan.interface = Arc::<str>::from("reth1.0");
    let syn = build_txn_tcp_syn_frame_v4(internal, external, internal_port, external_port, 0x02, crate::afxdp::tests_support::TEST_LAN_MAC);
    let meta_syn = {
        let mut m = txn_meta_v4(24, 0x02, syn.len() as u16);
        m.flow_src_port = internal_port;
        m.flow_dst_port = external_port;
        m.flow_src_addr = [10, 0, 61, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        m.flow_dst_addr = [8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        m
    };
    let (_b0, dbg0) = txn_run_descriptor_checked(
        &mut binding_lan,
        &mut sessions,
        &forwarding,
        &ha_state,
        &syn,
        meta_syn,
        true,
    );
    assert_eq!(dbg0.forward, 1, "F-053 premise: forward SYN must forward");
    assert_eq!(
        binding_lan.scratch.scratch_forwards.len(),
        1,
        "F-053 premise: forward must queue exactly one request"
    );
    let pool_port = binding_lan.scratch.scratch_forwards[0]
        .decision
        .nat
        .rewrite_src_port
        .expect("F-053 premise: pool PAT must allocate a source port");
    assert_eq!(
        binding_lan.scratch.scratch_forwards[0]
            .decision
            .nat
            .rewrite_src,
        Some(IpAddr::V4(pool)),
        "F-053 premise: forward must SNAT to the pool address"
    );

    // (2) Reply first fragment wan->lan: external:443 -> pool:pool_port,
    // offset 0 MF=1 with TCP header. Hits reverse, dst -> internal.
    let mut binding_wan = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding_wan.interface = Arc::<str>::from("reth0.80");
    let mut tcp = vec![0u8; 24];
    tcp[0..2].copy_from_slice(&external_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&pool_port.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x10; // ACK
    let reply_id = 0xD001u16;
    let reply_first = ipv4_frag_frame_9950_with_mac(
        external,
        pool,
        PROTO_TCP,
        reply_id,
        0x2000,
        &tcp,
        TEST_WAN_MAC,
    );
    let meta_first = {
        let mut m = frag_meta_9950(
            12,
            PROTO_TCP,
            0x10,
            external,
            pool,
            reply_first.len() as u16,
        );
        m.flow_src_port = external_port;
        m.flow_dst_port = pool_port;
        m.l4_offset = 34;
        m
    };
    let (_b1, dbg1) = txn_run_descriptor_checked(
        &mut binding_wan,
        &mut sessions,
        &forwarding,
        &ha_state,
        &reply_first,
        meta_first,
        true,
    );
    assert_eq!(
        dbg1.forward, 1,
        "F-053 premise: reply first fragment must forward"
    );
    assert_eq!(
        dbg1.nat_applied_none, 0,
        "F-053 premise: reply first fragment must be reverse-translated"
    );

    // (3) Reply non-first: same datagram, offset 3 (24..40, adjacent past the
    // 24-byte first — NOT overlapping). Wire dst must be the internal host,
    // not the pool address.
    let tail_payload = [0xDDu8; 16];
    let reply_tail = ipv4_frag_frame_9950_with_mac(
        external,
        pool,
        PROTO_TCP,
        reply_id,
        0x0003,
        &tail_payload,
        TEST_WAN_MAC,
    );
    let meta_tail = {
        let mut m = frag_meta_9950(12, PROTO_TCP, 0, external, pool, reply_tail.len() as u16);
        m.flow_src_port = external_port;
        m.flow_dst_port = pool_port;
        m
    };
    binding_wan.scratch.scratch_forwards.clear();
    let (_b2, dbg2) = txn_run_descriptor_checked(
        &mut binding_wan,
        &mut sessions,
        &forwarding,
        &ha_state,
        &reply_tail,
        meta_tail,
        true,
    );
    assert_eq!(
        dbg2.forward, 1,
        "F-053: reply non-first fragment must forward (with translation)"
    );
    assert_eq!(
        binding_wan.scratch.scratch_forwards.len(),
        1,
        "F-053: exactly one forward request for the reply tail"
    );
    let fwd = &binding_wan.scratch.scratch_forwards[0];
    let area = binding_wan.umem.area();
    let desc = crate::afxdp::XdpDesc {
        addr: 128,
        len: reply_tail.len() as u32,
        options: 0,
    };
    let result = crate::afxdp::frame::rewrite_forwarded_frame_in_place(
        area,
        desc,
        meta_tail,
        &fwd.decision,
        false,
        None,
        0,
    )
    .expect("F-053: TX rewrite must succeed");
    let out = area
        .slice(result.offset as usize, result.len as usize)
        .expect("rewritten bytes");
    let (_wire_src, wire_dst) = wire_ipv4_addrs_9950(out);
    assert_eq!(
        wire_dst, internal,
        "F-053 RED: reply non-first wire dst must be the internal host, not the pool address"
    );
}

/// #9950 P0 regression: a SECOND reply datagram (new ident, same 5-tuple) must
/// still translate after the first datagram's ACK first fragment became cacheable.
/// Without fragment exclusion from the flow-cache (5-tuple key, no ident), the second
/// datagram's first would Consume from cache and never install its reply association,
/// so its tail would miss and forward untranslated. RED-on-revert of the cache gates.
#[test]
fn f053_second_reply_datagram_post_cache_translates_9950() {
    let internal = Ipv4Addr::new(10, 0, 61, 100);
    let external = Ipv4Addr::new(8, 8, 8, 8);
    let pool = Ipv4Addr::new(172, 16, 80, 100);
    let internal_port = 33333u16;
    let external_port = 443u16;
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "snat-pool".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "pool-a".to_string(),
        pool_addresses: vec!["172.16.80.100".to_string()],
        port_low: 20000,
        port_high: 20999,
        ..Default::default()
    }];
    snapshot.routes = vec![RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "0.0.0.0/0".to_string(),
        next_hops: vec!["172.16.80.1@reth0.80".to_string()],
        discard: false,
        next_table: String::new(),
        preference: 0,
        rule_priority: 0,
    }];
    snapshot.neighbors = vec![
        NeighborSnapshot {
            interface: "ge-0-0-0.80".to_string(),
            ifindex: 12,
            family: "inet".to_string(),
            ip: "172.16.80.1".to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            state: "reachable".to_string(),
            router: true,
            link_local: false,
            ..Default::default()
        },
        NeighborSnapshot {
            interface: "reth1.0".to_string(),
            ifindex: 24,
            family: "inet".to_string(),
            ip: "10.0.61.100".to_string(),
            mac: "02:aa:bb:cc:dd:02".to_string(),
            state: "reachable".to_string(),
            router: false,
            link_local: false,
            ..Default::default()
        },
        NeighborSnapshot {
            interface: "ge-0-0-0.80".to_string(),
            ifindex: 12,
            family: "inet".to_string(),
            ip: "172.16.80.100".to_string(),
            mac: "00:11:22:33:44:77".to_string(),
            state: "reachable".to_string(),
            router: false,
            link_local: false,
            ..Default::default()
        },
    ];
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = BTreeMap::new();
    let mut sessions = SessionTable::new();
    let mut binding_lan = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding_lan.interface = Arc::<str>::from("reth1.0");
    let syn = build_txn_tcp_syn_frame_v4(internal, external, internal_port, external_port, 0x02, crate::afxdp::tests_support::TEST_LAN_MAC);
    let meta_syn = {
        let mut m = txn_meta_v4(24, 0x02, syn.len() as u16);
        m.flow_src_port = internal_port;
        m.flow_dst_port = external_port;
        m.flow_src_addr = [10, 0, 61, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        m.flow_dst_addr = [8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        m
    };
    let (_b0, dbg0) = txn_run_descriptor_checked(
        &mut binding_lan,
        &mut sessions,
        &forwarding,
        &ha_state,
        &syn,
        meta_syn,
        true,
    );
    assert_eq!(dbg0.forward, 1, "premise: forward SYN must forward");
    let pool_port = binding_lan.scratch.scratch_forwards[0]
        .decision
        .nat
        .rewrite_src_port
        .expect("pool port");
    let mut binding_wan = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding_wan.interface = Arc::<str>::from("reth0.80");
    for (label, reply_id) in [("datagram-1", 0xD001u16), ("datagram-2", 0xD002u16)] {
        let mut tcp = vec![0u8; 24];
        tcp[0..2].copy_from_slice(&external_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&pool_port.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x10;
        let reply_first = ipv4_frag_frame_9950_with_mac(
            external,
            pool,
            PROTO_TCP,
            reply_id,
            0x2000,
            &tcp,
            TEST_WAN_MAC,
        );
        let meta_first = {
            let mut m = frag_meta_9950(
                12,
                PROTO_TCP,
                0x10,
                external,
                pool,
                reply_first.len() as u16,
            );
            m.flow_src_port = external_port;
            m.flow_dst_port = pool_port;
            m.l4_offset = 34;
            m
        };
        let (_b1, dbg1) = txn_run_descriptor_checked(
            &mut binding_wan,
            &mut sessions,
            &forwarding,
            &ha_state,
            &reply_first,
            meta_first,
            true,
        );
        assert_eq!(dbg1.forward, 1, "{label}: reply first must forward");
        let tail_payload = [0xDDu8; 16];
        let reply_tail = ipv4_frag_frame_9950_with_mac(
            external,
            pool,
            PROTO_TCP,
            reply_id,
            0x0003,
            &tail_payload,
            TEST_WAN_MAC,
        );
        let meta_tail = {
            let mut m = frag_meta_9950(12, PROTO_TCP, 0, external, pool, reply_tail.len() as u16);
            m.flow_src_port = external_port;
            m.flow_dst_port = pool_port;
            m
        };
        binding_wan.scratch.scratch_forwards.clear();
        let (_b2, dbg2) = txn_run_descriptor_checked(
            &mut binding_wan,
            &mut sessions,
            &forwarding,
            &ha_state,
            &reply_tail,
            meta_tail,
            true,
        );
        assert_eq!(dbg2.forward, 1, "{label}: reply tail must forward");
        let fwd = &binding_wan.scratch.scratch_forwards[0];
        let area = binding_wan.umem.area();
        let desc = crate::afxdp::XdpDesc {
            addr: 128,
            len: reply_tail.len() as u32,
            options: 0,
        };
        let result = crate::afxdp::frame::rewrite_forwarded_frame_in_place(
            area,
            desc,
            meta_tail,
            &fwd.decision,
            false,
            None,
            0,
        )
        .expect("rewrite");
        let out = area
            .slice(result.offset as usize, result.len as usize)
            .expect("bytes");
        let (_s, wire_dst) = wire_ipv4_addrs_9950(out);
        assert_eq!(
            wire_dst, internal,
            "{label}: wire dst must be internal (cache-bypass regression)"
        );
    }
}

/// #9950: forward first fragments of EXISTING NAT flows (session hits, not new-flow
/// commits) must install their datagram's association. Before the hit-tail install,
/// long-lived fragmented SNAT flows blackholed after their first datagram (later
/// datagrams' firsts hit the session, never installed, tails died fail-closed on #6122).
/// This cell locks the blackhole-to-forward behavior change (forward-hit installs are
/// ungated — same hook as replies, helpers self-gate, direction gate would be artificial).
#[test]
fn forward_hit_existing_flow_forwards_translated_9950() {
    let internal = Ipv4Addr::new(10, 0, 61, 100);
    let external = Ipv4Addr::new(172, 16, 80, 200);
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "snat-lan-wan".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..Default::default()
    }];
    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    // (1) Unfragmented SYN establishes the session (no frag assoc — not a fragment).
    let syn = build_txn_tcp_syn_frame_v4(internal, external, 33333, 443, 0x02, crate::afxdp::tests_support::TEST_LAN_MAC);
    let meta_syn = {
        let mut m = txn_meta_v4(24, 0x02, syn.len() as u16);
        m.flow_src_port = 33333;
        m.flow_dst_port = 443;
        m.flow_src_addr = [10, 0, 61, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        m.flow_dst_addr = [172, 16, 80, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        m
    };
    let (_b0, dbg0) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &syn,
        meta_syn,
        true,
    );
    assert_eq!(dbg0.forward, 1, "premise: SYN must forward");
    // (2) Later fragmented datagram on the SAME 5-tuple: first hits the session (not a
    // new-flow commit) and must install; tail inherits interface-SNAT (172.16.80.8).
    let mut tcp = vec![0u8; 24];
    tcp[0..2].copy_from_slice(&33333u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x10;
    let dat_id = 0xF001u16;
    let first = ipv4_frag_frame_9950(internal, external, PROTO_TCP, dat_id, 0x2000, &tcp);
    let meta_first = {
        let mut m = frag_meta_9950(24, PROTO_TCP, 0x10, internal, external, first.len() as u16);
        m.flow_src_port = 33333;
        m.flow_dst_port = 443;
        m.l4_offset = 34;
        m
    };
    let (_b1, dbg1) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &first,
        meta_first,
        true,
    );
    assert_eq!(dbg1.forward, 1, "forward first (session hit) must forward");
    assert_eq!(dbg1.nat_applied_none, 0, "forward first must be SNAT'd");
    let tail = ipv4_frag_frame_9950(internal, external, PROTO_TCP, dat_id, 0x0003, &[0xEEu8; 16]);
    let meta_tail = {
        let mut m = frag_meta_9950(24, PROTO_TCP, 0, internal, external, tail.len() as u16);
        m.flow_src_port = 33333;
        m.flow_dst_port = 443;
        m
    };
    binding.scratch.scratch_forwards.clear();
    let (_b2, dbg2) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &tail,
        meta_tail,
        true,
    );
    assert_eq!(
        dbg2.forward, 1,
        "forward tail must forward (was #6122 blackhole before hit-tail install)"
    );
    assert_eq!(dbg2.nat_applied_snat, 1, "forward tail must inherit SNAT");
    let fwd = &binding.scratch.scratch_forwards[0];
    let area = binding.umem.area();
    let desc = crate::afxdp::XdpDesc {
        addr: 128,
        len: tail.len() as u32,
        options: 0,
    };
    let result = crate::afxdp::frame::rewrite_forwarded_frame_in_place(
        area,
        desc,
        meta_tail,
        &fwd.decision,
        false,
        None,
        0,
    )
    .expect("rewrite");
    let out = area
        .slice(result.offset as usize, result.len as usize)
        .expect("bytes");
    let (wire_src, _d) = wire_ipv4_addrs_9950(out);
    assert_eq!(
        wire_src,
        Ipv4Addr::new(172, 16, 80, 8),
        "wire src must be the SNAT interface address"
    );
}

/// F-035 enforcement order with an ARMED `syn-fin` screen: the first fragment's benign
/// flags (ACK) pass the screen — the verdict the datagram "earns" — while the overlapping
/// tail, whose reassembled bytes would carry SYN+FIN, never reaches L4 verdicts (a
/// non-first fragment skips TCP-flag screens by construction, #1137) and is dropped by
/// the overlap tracker instead. RED-on-revert: without the tracker the tail forwards and
/// the receiver reassembles attacker flags the screens never saw.
#[test]
fn f035_enforcement_order_armed_screen_9950() {
    use crate::screen::{ScreenPacketInfo, ScreenProfile, ScreenState, ScreenVerdict};
    let mut zones = rustc_hash::FxHashMap::default();
    zones.insert(
        "lan".to_string(),
        ScreenProfile {
            syn_fin: true,
            ..ScreenProfile::default()
        },
    );
    let mut state = ScreenState::new();
    state.update_profiles(zones);
    let base = ScreenPacketInfo {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: 0x10, // ACK: benign.
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 33333,
        dst_port: 443,
        tcp_seq: 1,
        tcp_ack: 0,
        tcp_mss: 0,
        pkt_len: 60,
        is_fragment: true,
        is_first_fragment: true,
        ip_ihl: 5,
        ip_frag_off: 0x2000,
        ip_total_len: 40,
        ip_payload_len: 0,
        frag_data_off: 0,
        saw_ipv4_source_route: false,
        saw_ipv6_routing_header: false,
    };
    assert_eq!(
        state.check_packet("lan", &base, 1),
        ScreenVerdict::Pass,
        "benign first fragment earns the screen verdict"
    );
    // The overlapping tail: payload bytes spell SYN+FIN, but as a non-first fragment
    // the TCP-flag screens never see them.
    let tail = ScreenPacketInfo {
        tcp_flags: 0x03, // SYN|FIN smuggled in the overlapping bytes.
        is_first_fragment: false,
        ip_frag_off: 0x0001,
        ..base.clone()
    };
    assert_eq!(
        state.check_packet("lan", &tail, 1),
        ScreenVerdict::Pass,
        "non-first skips TCP screens — screens alone cannot stop the smuggle"
    );
    // The overlap tracker closes it: first planted 0..20, tail 8..28 overlaps.
    let t = crate::fragment_overlap::OverlapTracker::new();
    let key = crate::fragment_overlap::OverlapKey {
        addr_family: libc::AF_INET as u8,
        src: base.src_ip,
        dst: base.dst_ip,
        ident: 0xBEEF,
        protocol: PROTO_TCP,
        routing_domain: 0,
    };
    assert!(!t.check_and_record(key, 0, 20, 1_000, &crate::fragment_overlap::FRAG_OVERLAP_DROPPED));
    assert!(
        t.check_and_record(key, 8, 28, 2_000, &crate::fragment_overlap::FRAG_OVERLAP_DROPPED),
        "overlapping tail dropped despite passing screens"
    );
}

/// Build eth(14) + IPv6(40) + Fragment header(8) + payload.
fn ipv6_frag_frame_9950(
    src: std::net::Ipv6Addr,
    dst: std::net::Ipv6Addr,
    frag_off: u16,
    ident: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut f = vec![
        0x02, 0xbf, 0x72, 0x00, 0x80, 0x08, 0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5, 0x86, 0xDD,
    ];
    f[..6].copy_from_slice(&TEST_LAN_MAC);
    let mut ip = vec![0u8; 40];
    ip[0] = 0x60;
    let plen = (8 + payload.len()) as u16;
    ip[4..6].copy_from_slice(&plen.to_be_bytes());
    ip[6] = 44; // Fragment header.
    ip[7] = 64;
    ip[8..24].copy_from_slice(&src.octets());
    ip[24..40].copy_from_slice(&dst.octets());
    let mut frag = [0u8; 8];
    frag[0] = PROTO_TCP;
    frag[2..4].copy_from_slice(&frag_off.to_be_bytes());
    frag[4..8].copy_from_slice(&ident.to_be_bytes());
    f.extend_from_slice(&ip);
    f.extend_from_slice(&frag);
    f.extend_from_slice(payload);
    f
}

/// F-035 over IPv6 on the real poll path (parent review: unit tests alone do not prove
/// the v6 poll wiring): overlapping v6 fragments denied, benign adjacent forwarded.
/// RED-on-revert: without the v6 hook wiring both overlap orders forward.
#[test]
fn f035_overlap_v6_denied_both_orders_9950() {
    use std::net::Ipv6Addr;
    let lan_src: Ipv6Addr = "2001:559:8585:ef00::100".parse().unwrap();
    let wan_dst: Ipv6Addr = "2001:559:8585:80::200".parse().unwrap();
    for (label, first_off, second_off, first_len, second_len, expect_second) in [
        ("v6-overlap-first-then-tail", 0x0001u16, 0x0009u16, 24usize, 16usize, 0),
        ("v6-overlap-tail-then-first", 0x0009u16, 0x0001u16, 24usize, 16usize, 0),
        ("v6-benign-adjacent", 0x0001u16, 0x0018u16, 24usize, 8usize, 1),
    ] {
        let mut snapshot = nat_snapshot();
        // Default-permit (mirrors the v4 F-035 cell): nat_snapshot's allow-all does not
        // reliably cover v6 here, and default-deny drops without a dbg counter.
        snapshot.default_policy = "permit".to_string();
        snapshot.policies.clear();
        snapshot.source_nat_rules.clear();
        snapshot.neighbors.push(NeighborSnapshot {
            interface: "ge-0-0-0.80".to_string(),
            ifindex: 12,
            family: "inet6".to_string(),
            ip: "2001:559:8585:80::200".to_string(),
            mac: "00:aa:bb:cc:dd:ee".to_string(),
            state: "reachable".to_string(),
            router: false,
            link_local: false,
            ..Default::default()
        });
        let forwarding = build_forwarding_state(&snapshot);
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
        binding.interface = Arc::<str>::from("reth1.0");
        let mut sessions = SessionTable::new();
        // nat_snapshot interfaces carry redundancy groups — an empty HA map would park
        // every resolution HAInactive. Use the active txn HA state like all nat_snapshot cells.
        let ha_state = txn_ha_state();
        let ident = 0x0BEEF00D;
        // Head payload: real 20B TCP SYN header + pad (8B-aligned for M=1); the miss
        // path validates L4 shape, so dummy bytes would die before forwarding.
        let mk_head = |len: usize| {
            let mut h = vec![0u8; len];
            h[0..2].copy_from_slice(&33333u16.to_be_bytes());
            h[2..4].copy_from_slice(&443u16.to_be_bytes());
            h[12] = 0x50;
            h[13] = 0x02; // SYN.
            h
        };
        // First arrival takes the first length, second arrival the second.
        let is_tail_first = first_off != 0x0001;
        let (pay_a, pay_b, flags_a) = if is_tail_first {
            (vec![0xBBu8; second_len], mk_head(first_len), 0x10u8)
        } else {
            (mk_head(first_len), vec![0xBBu8; second_len], 0x02u8)
        };
        let frame_a = ipv6_frag_frame_9950(lan_src, wan_dst, first_off, ident, &pay_a);
        let frame_b = ipv6_frag_frame_9950(lan_src, wan_dst, second_off, ident, &pay_b);
        let meta_for = |frame: &Vec<u8>, flags: u8| UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 24,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            pkt_len: frame.len() as u16, // #6883: shim stamps the FULL frame length.
            l3_offset: 14,
            l4_offset: 62,
            flow_src_port: 33333,
            flow_dst_port: 443,
            flow_src_addr: lan_src.octets(),
            flow_dst_addr: wan_dst.octets(),
            tcp_flags: flags,
            config_generation: 7,
            fib_generation: 9,
            ..UserspaceDpMeta::default()
        };
        let flags_b = if is_tail_first { 0x02u8 } else { 0x10u8 };
        let (_b1, dbg1) = txn_run_descriptor_checked(&mut binding, &mut sessions, &forwarding, &ha_state, &frame_a, meta_for(&frame_a, flags_a), true);
        assert_eq!(dbg1.forward, 1, "{label}: first arrival must forward");
        let (_b2, dbg2) = txn_run_descriptor_checked(&mut binding, &mut sessions, &forwarding, &ha_state, &frame_b, meta_for(&frame_b, flags_b), true);
        assert_eq!(dbg2.forward, expect_second, "{label}: second arrival");
    }
}
