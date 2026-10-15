// #13527: the neighbor-retry sweep must (a) populate the flowless NAT
// decision BEFORE the #10683 IPsec selector fence reads it, and (b) apply
// the same TCP segmentation the immediate TX path applies. Both tests drive
// retry_pending_neigh itself; reverting the fence/NAT reorder or the
// segmentation block turns them RED.

use super::*;
use crate::protocol::IpsecBindlessSelectorSnapshot;
use crate::test_zone_ids::*;
use std::sync::atomic::Ordering;

const EGRESS: i32 = 80;
const NEXT_HOP: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1));

fn decision() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::MissingNeighbor,
            local_ifindex: 0,
            egress_ifindex: EGRESS,
            tx_ifindex: 22,
            tunnel_endpoint_id: 0,
            next_hop: Some(NEXT_HOP),
            neighbor_mac: None,
            src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x00, 0x01]),
            tx_vlan_id: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn egress_entry(mtu: usize) -> EgressInterface {
    EgressInterface {
        bind_ifindex: 22,
        vlan_id: 0,
        mtu,
        src_mac: [0x02, 0xbf, 0x72, 0x16, 0x00, 0x01],
        zone_id: TEST_WAN_ZONE_ID,
        redundancy_group: 0,
        primary_v4: Some(Ipv4Addr::new(192, 0, 2, 1)),
        primary_v6: None,
    }
}

/// Park `frame` on bindings[0], run one retry sweep, return the bindings.
fn flush(forwarding: &ForwardingState, frame: &[u8], meta: UserspaceDpMeta) -> Vec<BindingWorker> {
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
    ];
    unsafe {
        bindings[0]
            .umem
            .area()
            .slice_mut_unchecked(0, frame.len())
            .expect("ingress frame")
            .copy_from_slice(frame);
    }
    let queued_ns = 1_000_000_000u64;
    let key = (EGRESS, NEXT_HOP);
    bindings[0].pending_neigh.insert(
        key,
        PendingNeighPacket {
            addr: 0,
            desc: XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            fabric_ingress_zone: None,
            decision: decision(),
            flow_key: None,
            queued_ns,
            probe_attempts: 0,
        },
    );
    bindings[0].pending_neigh_schedule.arm(
        key,
        next_due_for_pending(
            queued_ns,
            queued_ns,
            0,
            PENDING_NEIGH_TIMEOUT_NS,
            PROBE_SCHEDULE_NS,
        ),
    );
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    dynamic_neighbors.insert(
        key,
        NeighborEntry {
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        },
    );
    let binding_lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let mut shared_recycles = Vec::new();
    let area = bindings[0].umem.area() as *const MmapArea;
    let (left, rest) = bindings.split_at_mut(0);
    let (binding, right) = rest.split_first_mut().expect("ingress binding");
    let mut counters = BatchCounters::default();
    let recent_exceptions = std::sync::Arc::new(std::sync::Mutex::new(
        crate::afxdp::ExceptionEventRing::new(),
    ));
    let mut dbg = crate::afxdp::DebugPollCounters::default();
    retry_pending_neigh(
        binding,
        left,
        0,
        right,
        &binding_lookup,
        &mirror_targets,
        forwarding,
        &dynamic_neighbors,
        None,
        queued_ns + 100,
        unsafe { &*area },
        &mut shared_recycles,
        None,
        &mut counters,
        &recent_exceptions,
        &mut dbg,
    );
    bindings
}

fn meta_for(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, pkt_len: usize) -> UserspaceDpMeta {
    let mut src_addr = [0u8; 16];
    src_addr[..4].copy_from_slice(&src.octets());
    let mut dst_addr = [0u8; 16];
    dst_addr[..4].copy_from_slice(&dst.octets());
    UserspaceDpMeta {
        ingress_ifindex: 11,
        l3_offset: 14,
        l4_offset: 34,
        pkt_len: pkt_len as u16,
        addr_family: libc::AF_INET as u8,
        protocol,
        flow_src_port: 0,
        flow_dst_port: 0,
        flow_src_addr: src_addr,
        flow_dst_addr: dst_addr,
        ..UserspaceDpMeta::default()
    }
}

/// Non-first IPv4 fragment (offset 1) of a UDP datagram, no TCP/UDP header.
fn non_first_udp_fragment(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut frame = vec![
        0x02, 0xbf, 0x72, 0x00, 0x80, 0x08, // dst MAC
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src MAC
        0x08, 0x00, // IPv4
        0x45, 0x00, 0x00, 0x1c, // version/IHL, TOS, total length 28
        0xbe, 0xef, 0x00, 0x01, // id, flags+offset (offset 1 = non-first)
        64, PROTO_UDP, 0x00, 0x00, // TTL, protocol, checksum
    ];
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    frame.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    frame
}

/// ATOMIC (unfragmented) oversized IPv4/TCP datagram, DF clear, ACK data.
fn oversized_tcp(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    const L3_LEN: usize = 1500;
    let mut frame = vec![
        0x02, 0xbf, 0x72, 0x00, 0x80, 0x08, // dst MAC
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src MAC
        0x08, 0x00, // IPv4
        0x45, 0x00, 0x05, 0xdc, // version/IHL, TOS, total length 1500
        0x12, 0x34, 0x00, 0x00, // id, flags+offset (DF clear, atomic)
        64, PROTO_TCP, 0x00, 0x00, // TTL, protocol, checksum
    ];
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    frame.extend_from_slice(&12345u16.to_be_bytes());
    frame.extend_from_slice(&443u16.to_be_bytes());
    frame.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x50, 0x10, 0xfa, 0xf0, // data offset, ACK, window
        0x00, 0x00, 0x00, 0x00, // checksum, urgent pointer
    ]);
    frame.resize(14 + L3_LEN, 0xab);
    frame
}

/// Fence/NAT fixture: interface SNAT rewrites 10.0.0.8 -> 192.0.2.1 (the
/// egress primary); the selector covers (192.0.2.1, 198.51.100.7), i.e. it
/// matches ONLY the post-NAT tuple. Pre-fix the fence runs against the
/// saved default NAT decision and the fragment leaks cleartext.
#[test]
fn retry_flowless_nat_populates_decision_before_ipsec_fence_13527() {
    let src = Ipv4Addr::new(10, 0, 0, 8);
    let dst = Ipv4Addr::new(198, 51, 100, 7);
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(EGRESS, egress_entry(1500));
    forwarding
        .zone_id_to_name
        .insert(TEST_LAN_ZONE_ID, "lan".into());
    forwarding
        .zone_id_to_name
        .insert(TEST_WAN_ZONE_ID, "wan".into());
    forwarding.ifindex_to_zone_id.insert(11, TEST_LAN_ZONE_ID);
    forwarding
        .ifindex_unambiguous_zone_id
        .insert(EGRESS, TEST_WAN_ZONE_ID);
    forwarding.source_nat_rules =
        crate::nat::parse_source_nat_rules(&[crate::SourceNATRuleSnapshot {
            name: "interface-snat".into(),
            from_zone: "lan".into(),
            to_zone: "wan".into(),
            source_addresses: vec!["0.0.0.0/0".into()],
            interface_mode: true,
            ..crate::SourceNATRuleSnapshot::default()
        }]);
    let selector_snapshot = ConfigSnapshot {
        bindless_selector_fence_enabled: true,
        bindless_selector_rows: vec![IpsecBindlessSelectorSnapshot {
            local_ts: "192.0.2.1/32".to_string(),
            remote_ts: "198.51.100.7/32".to_string(),
        }],
        ..ConfigSnapshot::default()
    };
    forwarding.bindless_ipsec_selector_fence =
        crate::afxdp::ipsec_selector_fence::BindlessIpsecSelectorFence::from_snapshot(
            &selector_snapshot,
        )
        .expect("valid selector snapshot");

    let frame = non_first_udp_fragment(src, dst);
    let meta = meta_for(src, dst, PROTO_UDP, frame.len());
    let bindings = flush(&forwarding, &frame, meta);

    assert!(
        bindings[0].pending_neigh.is_empty(),
        "resolved entry is consumed"
    );
    assert_eq!(
        bindings[0]
            .live
            .pending_neigh_visits
            .load(Ordering::Relaxed),
        1,
        "the retry sweep must visit the resolved packet"
    );
    assert!(
        bindings[1].tx_pipeline.pending_tx_prepared.is_empty()
            && bindings[1].tx_pipeline.pending_tx_local.is_empty()
            && bindings[0].tx_pipeline.pending_tx_prepared.is_empty()
            && bindings[0].tx_pipeline.pending_tx_local.is_empty(),
        "post-NAT tuple is selector-covered: the fragment must not be transmitted"
    );
    assert_eq!(
        bindings[0].tx_pipeline.pending_fill_frames.front(),
        Some(&0),
        "the fenced fragment frame must be recycled exactly once"
    );
}

#[test]
fn retry_pending_neighbor_segments_oversized_tcp_13527() {
    let src = Ipv4Addr::new(10, 0, 0, 1);
    let dst = Ipv4Addr::new(10, 0, 0, 2);
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(EGRESS, egress_entry(1400));

    let frame = oversized_tcp(src, dst);
    let meta = meta_for(src, dst, PROTO_TCP, frame.len());
    let bindings = flush(&forwarding, &frame, meta);

    assert!(
        bindings[0].pending_neigh.is_empty(),
        "resolved entry is consumed"
    );
    let locals = &bindings[1].tx_pipeline.pending_tx_local;
    assert_eq!(
        locals.len(),
        2,
        "oversized replay must emit two MSS-sized segments, not the whole frame"
    );
    for req in locals {
        assert!(
            req.bytes.len() <= 14 + 1400,
            "every segment must fit the egress MTU, got {}",
            req.bytes.len()
        );
    }
    let total_tcp_payload: usize = locals.iter().map(|req| req.bytes.len() - 54).sum();
    assert_eq!(
        total_tcp_payload, 1460,
        "segments must carry the complete original TCP payload"
    );
    assert!(
        bindings[1].tx_pipeline.pending_tx_prepared.is_empty(),
        "segments ride the copy queue, never a whole-frame prepared request"
    );
    assert_eq!(
        bindings[0].tx_pipeline.pending_fill_frames.front(),
        Some(&0),
        "the segmented original must be recycled exactly once"
    );
}
