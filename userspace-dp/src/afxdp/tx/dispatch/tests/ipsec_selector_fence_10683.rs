use super::*;
use crate::protocol::{ConfigSnapshot, IpsecBindlessSelectorSnapshot};

#[test]
fn pending_live_tx_drops_bindless_selector_match_before_enqueue_10683() {
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
    let mut forwarding = test_forwarding_with_egress_mtu(1500);
    let snapshot = ConfigSnapshot {
        bindless_selector_fence_enabled: true,
        bindless_selector_rows: vec![IpsecBindlessSelectorSnapshot {
            local_ts: "10.20.0.0/16".to_string(),
            remote_ts: "198.51.100.0/24".to_string(),
        }],
        ..ConfigSnapshot::default()
    };
    forwarding.bindless_ipsec_selector_fence =
        crate::afxdp::ipsec_selector_fence::BindlessIpsecSelectorFence::from_snapshot(&snapshot)
            .expect("valid selector snapshot");

    let mut request = test_live_forward_request_for_frame(
        frame.len(),
        test_forwarding_decision_to_bound_ifindex(22),
    );
    request.meta.flow_src_addr = [10, 20, 1, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    request.meta.flow_dst_addr = [198, 51, 100, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut pending = vec![request];
    let mut post_recycles = Vec::new();
    let binding_lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let ingress_ident = bindings[0].identity();
    let ingress_live = &*bindings[0].live as *const BindingLiveState;
    let local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>> =
        Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let worker_commands_by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();
    let mut dbg = DebugPollCounters::default();
    let mut counters = BatchCounters::default();
    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");

    enqueue_pending_forwards(
        left,
        0,
        ingress,
        right,
        &binding_lookup,
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

    assert_eq!(dbg.policy_deny, 1, "matching selector increments the drop counter");
    assert!(counters.touched, "selector drop reaches batch accounting");
    assert!(bindings[1].tx_pipeline.pending_tx_prepared.is_empty());
    assert_eq!(ingress_recycled_count(&bindings[0]), 1);
}
