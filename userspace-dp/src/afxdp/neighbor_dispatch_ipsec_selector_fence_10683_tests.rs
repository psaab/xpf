use super::*;
use crate::afxdp::tx::test_support::build_ipv4_test_packet;
use crate::protocol::IpsecBindlessSelectorSnapshot;
use crate::test_zone_ids::*;
use std::sync::atomic::Ordering;

#[test]
fn retry_pending_neighbor_rechecks_selector_after_nat_10683() {
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
    ];
    let frame = build_ipv4_test_packet(0);
    unsafe {
        bindings[0]
            .umem
            .area()
            .slice_mut_unchecked(0, frame.len())
            .expect("ingress frame")
            .copy_from_slice(&frame);
    }
    let next_hop = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1));
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        80,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x16, 0x00, 0x01],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );
    let selector_snapshot = ConfigSnapshot {
        bindless_selector_fence_enabled: true,
        bindless_selector_rows: vec![IpsecBindlessSelectorSnapshot {
            local_ts: "10.20.0.0/16".to_string(),
            remote_ts: "198.51.100.0/24".to_string(),
        }],
        ..ConfigSnapshot::default()
    };
    forwarding.bindless_ipsec_selector_fence =
        crate::afxdp::ipsec_selector_fence::BindlessIpsecSelectorFence::from_snapshot(
            &selector_snapshot,
        )
        .expect("valid selector snapshot");

    let meta = UserspaceDpMeta {
        ingress_ifindex: 11,
        l3_offset: 14,
        l4_offset: 34,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        flow_src_port: 40000,
        flow_dst_port: 443,
        flow_src_addr: [192, 0, 2, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [198, 51, 100, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::MissingNeighbor,
            local_ifindex: 0,
            egress_ifindex: 80,
            tx_ifindex: 22,
            tunnel_endpoint_id: 0,
            next_hop: Some(next_hop),
            neighbor_mac: None,
            src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x00, 0x01]),
            tx_vlan_id: 0,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(10, 20, 0, 8))),
            ..NatDecision::default()
        },
        install_table_domain: 0,
        install_table_check: 0,
    };
    let queued_ns = 1_000_000_000;
    let key = (80, next_hop);
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
            decision,
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

    retry_pending_neigh(
        binding,
        left,
        0,
        right,
        &binding_lookup,
        &mirror_targets,
        &forwarding,
        &dynamic_neighbors,
        None,
        queued_ns + 100,
        unsafe { &*area },
        &mut shared_recycles,
        None,
        &mut counters,
    );

    assert!(bindings[0].pending_neigh.is_empty(), "resolved entry is consumed");
    assert_eq!(bindings[0].tx_pipeline.pending_fill_frames.front(), Some(&0));
    assert!(bindings[1].tx_pipeline.pending_tx_prepared.is_empty());
    assert!(counters.touched, "selector-fence drop is visible to batch accounting");
    assert_eq!(
        bindings[0]
            .live
            .pending_neigh_visits
            .load(Ordering::Relaxed),
        1,
        "the retry path must actually visit the resolved pending packet"
    );
}
