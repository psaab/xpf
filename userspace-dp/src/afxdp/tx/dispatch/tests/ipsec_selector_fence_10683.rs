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
        None,
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

    assert_eq!(
        dbg.policy_deny, 1,
        "matching selector increments the drop counter"
    );
    // #15941: named counter + exception-ring attribution.
    assert_eq!(counters.transit_ipsec_fence_drops, 1);
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|entry| entry.reason().to_string())
        .collect();
    assert_eq!(reasons, vec!["transit_ipsec_selector_fence"]);
    assert!(counters.touched, "selector drop reaches batch accounting");
    assert!(bindings[1].tx_pipeline.pending_tx_prepared.is_empty());
    assert_eq!(ingress_recycled_count(&bindings[0]), 1);
}

/// #15941: a Live request whose target has no XSK binding increments the
/// exported no-egress-binding counter (not just dbg).
#[test]
fn pending_live_tx_no_egress_binding_counts_15941() {
    let mut bindings = vec![BindingWorker::new_for_mirror_test(0, 0, 11, 0)];
    let frame = build_ipv4_test_packet(0);
    unsafe {
        bindings[0]
            .umem
            .area()
            .slice_mut_unchecked(0, frame.len())
            .expect("ingress frame")
            .copy_from_slice(&frame);
    }
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let mut request = test_live_forward_request_for_frame(
        frame.len(),
        test_forwarding_decision_to_bound_ifindex(4242),
    );
    // Non-martian tuple so the #11074/#11413 rechecks pass and the request
    // reaches the no-binding arm.
    request.meta.flow_src_addr = [10, 0, 61, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    request.meta.flow_dst_addr = [198, 51, 100, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
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
        None,
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
    assert_eq!(dbg.no_egress_binding, 1);
    assert_eq!(
        counters.no_egress_binding_drops, 1,
        "#15941 exported mirror"
    );
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|e| e.reason().to_string())
        .collect();
    assert_eq!(reasons, vec!["missing_egress_binding"]);
}

/// #15941 revert-guard (GLM B4): a Live request whose UMEM slice fails at
/// dispatch must count as a forward build failure and ring
/// `forward_live_slice_failed`, not recycle silently.
#[test]
fn pending_live_tx_slice_failure_counts_15941() {
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
    ];
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let mut request =
        test_live_forward_request_for_frame(64, test_forwarding_decision_to_bound_ifindex(22));
    request.meta.flow_src_addr = [10, 0, 61, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    request.meta.flow_dst_addr = [198, 51, 100, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    // Descriptor far beyond the ingress UMEM mapping: slice() must fail.
    // (Length 0: recycling the bogus offset is then a no-op fill entry the
    // device drops as FILL_INVALID instead of dereferencing it.)
    request.desc.addr = 1 << 40;
    request.desc.len = 0;
    request.meta.pkt_len = 0;
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
        None,
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
    assert_eq!(
        counters.forward_build_failures, 1,
        "#15941 B4 slice failure must count"
    );
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|e| e.reason().to_string())
        .collect();
    assert_eq!(reasons, vec!["forward_live_slice_failed"]);
    // Recycle accounting for a bogus descriptor is device-defined
    // (FILL_INVALID drop), so the counter+ring above are the oracle.
}

/// #15941 revert-guard: a non-fabric Prebuilt request with no target
/// binding must count as missing-egress-binding (fabric keeps its own
/// `fabric_redirect_unsendable_drops` reason and is not double-counted).
#[test]
fn pending_prebuilt_tx_no_binding_counts_15941() {
    let mut bindings = vec![BindingWorker::new_for_mirror_test(0, 0, 11, 0)];
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let mut request =
        test_live_forward_request_for_frame(64, test_forwarding_decision_to_bound_ifindex(4242));
    request.frame = PendingForwardFrame::Prebuilt(vec![0u8; 64].into());
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
        None,
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
    assert_eq!(
        counters.no_egress_binding_drops, 1,
        "#15941 prebuilt no-binding must count"
    );
    assert_eq!(
        bindings[0]
            .live
            .fabric_redirect_unsendable_drops
            .load(Ordering::Relaxed),
        0,
        "non-fabric prebuilt must not pollute the fabric counter"
    );
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|e| e.reason().to_string())
        .collect();
    assert_eq!(reasons, vec!["missing_egress_binding"]);
}

/// #15954 site 5 (non-fabric Prebuilt enqueue-error): a Prebuilt frame
/// whose local enqueue fails (driven by the #2208 `FORCE_ENQUEUE_ERR`
/// fault injection — the only way this arm is reachable today) must
/// count a forward build failure and ring `forward_build_failed`, not
/// recycle silently. Removing that site's increment turns this RED;
/// the fabric twin keeps its own counter and is asserted 0 here.
#[test]
fn pending_prebuilt_enqueue_error_counts_15954() {
    struct ForceEnqueueErrGuard;
    impl Drop for ForceEnqueueErrGuard {
        fn drop(&mut self) {
            super::cos::FORCE_ENQUEUE_ERR.with(|c| c.set(false));
        }
    }
    let _guard = ForceEnqueueErrGuard;
    super::cos::FORCE_ENQUEUE_ERR.with(|c| c.set(true));
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
    ];
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let mut request =
        test_live_forward_request_for_frame(64, test_forwarding_decision_to_bound_ifindex(22));
    request.frame = PendingForwardFrame::Prebuilt(vec![0u8; 64].into());
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
        None,
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
    assert_eq!(
        counters.forward_build_failures, 1,
        "#15954 prebuilt enqueue-error site must increment forward_build_failures"
    );
    assert_eq!(
        bindings[0]
            .live
            .fabric_redirect_unsendable_drops
            .load(Ordering::Relaxed),
        0,
        "non-fabric prebuilt enqueue error must not pollute the fabric counter"
    );
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|e| e.reason().to_string())
        .collect();
    assert_eq!(reasons, vec!["forward_build_failed"]);
}
