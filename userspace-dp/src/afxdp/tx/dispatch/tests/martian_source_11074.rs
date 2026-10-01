use super::*;
use std::net::{IpAddr, Ipv4Addr};

/// Final TX dispatch is a second stale-decision boundary: even if an earlier
/// poll-stage check was bypassed or the forwarding snapshot changed while the
/// request was queued, a live transit frame with a newly martian source must
/// not be enqueued.
#[test]
fn final_live_tx_dispatch_rechecks_transit_source_martian_11074() {
    let source = Ipv4Addr::new(10, 0, 61, 255);
    let destination = Ipv4Addr::new(198, 51, 100, 2);
    let frame = crate::afxdp::tests_support::build_txn_tcp_syn_frame_v4(
        source,
        destination,
        12345,
        443,
        crate::tcp_flags::TCP_SYN,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    );
    let mut forwarding = test_forwarding_with_egress_mtu(1500);
    let source_snapshot = crate::ConfigSnapshot {
        interfaces: vec![crate::InterfaceSnapshot {
            name: "lan0".into(),
            ifindex: 11,
            hardware_addr: "02:bf:72:01:00:01".into(),
            addresses: vec![crate::InterfaceAddressSnapshot {
                family: "inet".into(),
                address: "10.0.61.1/24".into(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let source_scope = build_forwarding_state(&source_snapshot);
    forwarding
        .connected_v4_directed_broadcasts
        .extend(source_scope.connected_v4_directed_broadcasts);

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
            .copy_from_slice(&frame);
    }
    let mut request = test_live_forward_request_for_frame(
        frame.len(),
        test_forwarding_decision_to_bound_ifindex(22),
    );
    request.meta.flow_src_addr[..4].copy_from_slice(&source.octets());
    request.meta.flow_dst_addr[..4].copy_from_slice(&destination.octets());
    request.flow_key = Some(crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(source),
        dst_ip: IpAddr::V4(destination),
        src_port: 12345,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    });
    let mut pending = vec![request];
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let mut post_recycles = Vec::new();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> =
        BTreeMap::new();
    let mut dbg = DebugPollCounters::default();
    let mut counters = BatchCounters::default();
    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");

    enqueue_pending_forwards(
        left,
        0,
        ingress,
        right,
        &lookup,
        &mirror_targets,
        &mut pending,
        &mut post_recycles,
        1,
        &forwarding,
        &ingress_ident,
        unsafe { &*ingress_live },
        None,
        &local_tunnel_deliveries,
        &recent_exceptions,
        &mut dbg,
        &mut counters,
        0,
        &worker_commands_by_id,
    );

    assert!(
        bindings[1].tx_pipeline.pending_tx_prepared.is_empty()
            && bindings[1].tx_pipeline.pending_tx_local.is_empty(),
        "a live transit request whose source is now martian must not reach TX"
    );
    assert_eq!(
        ingress_recycled_count(&bindings[0]),
        1,
        "the rejected live ingress descriptor must be recycled exactly once"
    );
}
