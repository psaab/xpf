//! queue_service drain tests: drain_shaped_tx priming/service, TX-progress
//! gating, and exact local/prepared FIFO scratch commit/settle/release.

use super::*;

// #1782 Step-1: end-to-end pin for BOTH cold-start instruments through
// drain_shaped_tx — (ii) the selector-site per-cause v8 under-grant
// attribution (post-top-up `queue.hot.tokens < head_len`, plan r2 F1)
// and (i) the timer-wheel tick-advance sum/max accumulated on
// `WorkerCos` by `prime_cos_root_for_service`.
#[test]
fn drain_counts_v8_undergrant_cause_and_wheel_ticks() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 100_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    root.tokens = 100_000;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.runnable = true;
    root.queues[0].v_min.worker_id = 0;
    cos_queue_push_back(&mut root.queues[0], test_flow_cos_item(10_000, 1500));

    // v8 lease with ZERO active flows anywhere: the lazy lease install
    // rehydrates from this queue's (absent) flow-fair state, so
    // acquire_v8 grants nothing and reports ShareExhausted (pinned by
    // v8_acquire_with_cause_no_active_flows_reports_share_exhausted).
    let lease = Arc::new(SharedCoSQueueLease::new_v8(
        100_000_000 / 8,
        256 * 1024,
        1,
        0,
    ));

    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        4,
        vec![(4, test_queue_fast_path(true, 0, None, Some(lease.clone())))],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);
    let mut shared_recycles = Vec::new();

    let now_ns = 3 * TEST_EPOCH_DURATION_NS;
    let drained = drain_shaped_tx(&mut binding, now_ns, &mut shared_recycles);
    assert!(
        drained.is_none(),
        "token-starved exact queue must not drain"
    );

    // (ii): exactly one under-grant, attributed to ShareExhausted.
    let ug = binding.cos.cos_queue_lease_undergrants;
    assert!(
        ug.share_exhausted >= 1,
        "selector site must attribute the starvation to ShareExhausted, got {ug:?}"
    );
    assert_eq!(ug.seqlock_give_up, 0, "no seqlock give-up here: {ug:?}");
    assert_eq!(ug.cap_zero, 0, "no cap-zero here: {ug:?}");
    assert_eq!(ug.epoch_rotated, 0, "no rotation race here: {ug:?}");

    // (i): the single prime call advanced the wheel from tick 0 to
    // cos_tick(now_ns); sum and single-call high-water mark agree.
    let expected_ticks = now_ns / 50_000; // COS_TIMER_WHEEL_TICK_NS
    assert_eq!(
        binding.cos.cos_wheel_ticks_advanced_total, expected_ticks,
        "wheel tick sum"
    );
    assert_eq!(
        binding.cos.cos_wheel_ticks_advanced_max, expected_ticks,
        "wheel tick single-call max"
    );
}

#[test]
fn equal_flow_cap_reaches_drain_shaped_tx_entry_path() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 100_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: true,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.tokens = 100_000;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.runnable = true;
    root.queues[0].v_min.worker_id = 0;
    enable_test_flow_fair(&mut root.queues[0]);
    while test_flow_fair_state(&root.queues[0]).active_flow_buckets < 4 {
        let port = 10_000 + root.queues[0].hot.local_item_count as u16;
        cos_queue_push_back(&mut root.queues[0], test_flow_cos_item(port, 1500));
    }

    let lease = Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode(
        50_000_000,
        256 * 1024,
        8,
        1,
        V8RateMode::EqualFlowSuppress,
    ));
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(1, 1);
    root.queues[0].queue_lease_v8 = Some(lease.clone());
    let _ = lease.acquire_v8(0, TEST_EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(1, TEST_EPOCH_DURATION_NS, 1_800);
    let _ = lease.acquire_v8(0, 2 * TEST_EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(1, 2 * TEST_EPOCH_DURATION_NS, 1_800);
    let _ = lease.acquire_v8(1, 3 * TEST_EPOCH_DURATION_NS, 1);
    assert!(lease.v8_equal_flow_enforced());

    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        4,
        vec![(4, test_queue_fast_path(true, 0, None, Some(lease.clone())))],
        None,
        None,
    );
    let queued_before = root.queues[0].hot.queued_bytes;
    let root_tokens_before = root.tokens;
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);
    let mut shared_recycles = Vec::new();

    let drained = drain_shaped_tx(
        &mut binding,
        3 * TEST_EPOCH_DURATION_NS,
        &mut shared_recycles,
    )
    .expect("drain_shaped_tx must service the exact equal-flow queue");

    assert_eq!(drained.root_ifindex, 42);
    assert_eq!(drained.queue_idx, 0);
    assert_eq!(drained.queue_id, 4);
    let sent_bytes = binding
        .live
        .tx_bytes
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(sent_bytes > 0);
    assert!(sent_bytes <= 7_200);
    assert!(
        lease.v8_equal_flow_cap_hit_events() > 0,
        "drain_shaped_tx must route through equal-flow lease top-up"
    );
    assert_eq!(binding.cos.cos_queue_lease_acquire_v8_calls, 1);
    assert_eq!(binding.cos.cos_queue_lease_acquire_v8_granted_bytes, 7_200);
    let root = binding.cos.cos_interfaces.get(&42).expect("cos root");
    assert_eq!(
        root.queues[0].hot.queued_bytes,
        queued_before.saturating_sub(sent_bytes)
    );
    // #1630 (P2): the per-visit budget is now a FRAME-count cap rather
    // than the rate-scaled quantum (which clamped a 100 Mbps class to a
    // single frame per visit). The four equal-flow frames drain in one
    // pass, leaving the queue empty. `refresh_cos_interface_activity`
    // then sees `nonempty_queues == 0` and calls `release_cos_root_lease`,
    // which returns the worker's unused root credit to the shared pool
    // (`core::mem::take(&mut root.tokens)`). So after a drain that empties
    // the interface, root.tokens is 0 — the unspent root tokens were not
    // leaked, they were released. (Pre-#1630 the queue stayed backlogged
    // after one frame, so the release path did not fire and root.tokens
    // was `root_tokens_before - sent_bytes`.)
    assert!(
        root.queues[0].hot.items.is_empty(),
        "all four equal-flow frames must drain in one visit under the P2 frame-cap"
    );
    assert_eq!(
        root.tokens, 0,
        "emptying the interface releases the unused root lease to the shared pool"
    );
    assert_eq!(
        root.queues[0]
            .telemetry
            .owner_profile
            .drain_sent_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        sent_bytes
    );
}

#[test]
fn drain_shaped_tx_skips_root_prime_for_parked_not_due_queue() {
    let mut root = test_cos_interface_runtime(0);
    root.tokens = 0;
    root.queues[0].hot.tokens = 1500;
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;
    park_cos_queue(&mut root, 0, 10);

    let root_lease = Arc::new(SharedCoSRootLease::new(
        root.shaping_rate_bytes,
        root.burst_bytes,
        1,
    ));
    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        Some(root_lease),
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);
    let mut shared_recycles = Vec::new();

    let drained = drain_shaped_tx(
        &mut binding,
        9 * COS_TIMER_WHEEL_TICK_NS,
        &mut shared_recycles,
    );

    assert!(drained.is_none());
    let root = binding.cos.cos_interfaces.get(&42).expect("cos root");
    assert_eq!(
        root.timer_wheel.current_tick, 0,
        "not-yet-due parked queues must not advance the timer wheel"
    );
    assert_eq!(
        root.tokens, 0,
        "not-yet-due parked queues must not top up the root lease"
    );
    assert!(root.queues[0].hot.parked);
    assert!(!root.queues[0].hot.runnable);
}

#[test]
fn drain_shaped_tx_primes_and_services_due_parked_queue() {
    let mut root = test_cos_interface_runtime(0);
    root.tokens = 0;
    root.queues[0].hot.tokens = 1500;
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;
    park_cos_queue(&mut root, 0, 10);

    let root_lease = Arc::new(SharedCoSRootLease::new(
        root.shaping_rate_bytes,
        root.burst_bytes,
        1,
    ));
    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        Some(root_lease),
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);
    let mut shared_recycles = Vec::new();

    let drained = drain_shaped_tx(
        &mut binding,
        10 * COS_TIMER_WHEEL_TICK_NS,
        &mut shared_recycles,
    )
    .expect("due parked queue must wake and service");

    assert_eq!(drained.root_ifindex, 42);
    assert_eq!(drained.queue_idx, 0);
    assert_eq!(drained.queue_id, 0);
    assert!(
        binding
            .live
            .tx_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
    );
}

#[test]
fn cos_batch_tx_made_progress_requires_real_send_progress() {
    assert!(!cos_batch_tx_made_progress(Ok((0, 0))));
    assert!(cos_batch_tx_made_progress(Ok((1, 0))));
    assert!(cos_batch_tx_made_progress(Ok((0, 1500))));
}

#[test]
fn cos_batch_tx_made_progress_yields_on_retry_and_drop() {
    // #4971: TxError payloads are copyable reason codes, not Strings.
    assert!(!cos_batch_tx_made_progress(Err(TxError::Retry(
        TxRetryReason::NoFreeTxFrame
    ))));
    assert!(!cos_batch_tx_made_progress(Err(TxError::Drop(
        crate::afxdp::tx::TxDropReason::PreparedSliceOutOfRange { offset: 0, len: 0 }
    ))));
}

// #4971: an expected TX backpressure retry records its reason via the
// lock-free `last_tx_retry_status` atomic and must NOT take the
// `last_error` mutex. Driven end-to-end through `submit_local` with an
// empty free-frame pool (the NoFreeTxFrame retry inside transmit_batch).
//
// FAIL-ON-REVERT (assertion, NOT a build break — `last_error` exists in
// both worlds): reverting the retry arm to `set_error(...)` writes the
// mutex, so `last_error` is non-empty → assertion RED.
#[test]
fn tx_retry_status_lock_free_4971() {
    let now_ns = 1_000_000_000u64;
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    root.tokens = 100_000;
    root.queues[0].hot.tokens = 100_000;

    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    // Force the NoFreeTxFrame retry inside transmit_batch.
    binding.tx_pipeline.free_tx_frames.clear();
    // Premise: last_error starts empty.
    assert!(
        binding.live.last_error.lock().unwrap().is_empty(),
        "test premise: last_error starts empty"
    );

    let items = VecDeque::from([TxRequest {
        bytes: vec![0u8; 128],
        expected_ports: None,
        expected_addr_family: 0,
        expected_protocol: 0,
        flow_key: None,
        egress_ifindex: 42,
        cos_queue_id: Some(0),
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: now_ns,
    }]);
    let mut shared_recycles = Vec::new();

    let progress = submit_local(
        &mut binding,
        42,
        0,
        CoSServicePhase::Surplus,
        128,
        items,
        now_ns,
        &mut shared_recycles,
    );

    assert!(!progress, "an expected retry makes no send progress");
    // THE GATE: the expected-retry path must NOT have written the
    // last_error mutex. Reverting to `set_error(...)` makes it non-empty.
    assert!(
        binding.live.last_error.lock().unwrap().is_empty(),
        "#4971: an expected TX retry must be lock-free — the last_error \
         mutex must stay empty (revert to set_error(...) makes it non-empty)"
    );
}

#[test]
fn drain_exact_local_fifo_items_to_scratch_keeps_queue_until_commit() {
    let area = MmapArea::new(4096).expect("mmap");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![1, 2, 3, 4],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![5, 6, 7, 8],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 256,
            len: 4,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
        }));

    let mut free_tx_frames = VecDeque::from([64, 128, 192]);
    let mut scratch_local_tx = Vec::new();

    let build = drain_exact_local_fifo_items_to_scratch(
        &mut root.queues[0],
        &mut free_tx_frames,
        &mut scratch_local_tx,
        &area,
        u64::MAX,
        u64::MAX,
        None,
    );

    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    assert_eq!(scratch_local_tx.len(), 2);
    assert_eq!(free_tx_frames, VecDeque::from([192]));
    assert_eq!(area.slice(64, 4).expect("first frame"), &[1, 2, 3, 4]);
    assert_eq!(area.slice(128, 4).expect("second frame"), &[5, 6, 7, 8]);
    assert!(matches!(
        root.queues[0].hot.items.front(),
        Some(CoSPendingTxItem::Local(_))
    ));
    assert!(matches!(
        root.queues[0].hot.items.get(2),
        Some(CoSPendingTxItem::Prepared(_))
    ));
}

#[test]
fn drain_exact_local_fifo_drops_mirror_clone_before_tx_reserve() {
    let area = MmapArea::new(4096).expect("mmap");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "mirror".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    cos_queue_push_back(
        &mut root.queues[0],
        CoSPendingTxItem::Local(TxRequest {
            bytes: vec![1, 2, 3, 4],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: true,
            overlap_admissions: None,
            enqueue_ns: 0,
        }),
    );
    let mut free_tx_frames = (0..MIRROR_TX_FRAME_RESERVE as u64)
        .map(|idx| idx << UMEM_FRAME_SHIFT)
        .collect::<VecDeque<_>>();
    let original_free = free_tx_frames.clone();
    let mut scratch_local_tx = Vec::new();

    let build = drain_exact_local_fifo_items_to_scratch(
        &mut root.queues[0],
        &mut free_tx_frames,
        &mut scratch_local_tx,
        &area,
        u64::MAX,
        u64::MAX,
        None,
    );

    assert!(matches!(
        build,
        ExactCoSScratchBuild::MirrorTxFrameReserve { dropped_bytes: 4 }
    ));
    assert!(scratch_local_tx.is_empty());
    assert_eq!(free_tx_frames, original_free);
    assert!(root.queues[0].hot.items.is_empty());
}

#[test]
fn release_exact_local_scratch_frames_preserves_queue_after_failed_submit() {
    let area = MmapArea::new(4096).expect("mmap");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![1],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![2],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
        }));
    let mut free_tx_frames = VecDeque::from([64, 128]);
    let mut scratch_local_tx = Vec::new();

    let build = drain_exact_local_fifo_items_to_scratch(
        &mut root.queues[0],
        &mut free_tx_frames,
        &mut scratch_local_tx,
        &area,
        u64::MAX,
        u64::MAX,
        None,
    );

    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    release_exact_local_scratch_frames(&mut free_tx_frames, &mut scratch_local_tx);
    assert!(scratch_local_tx.is_empty());
    assert_eq!(free_tx_frames, VecDeque::from([64, 128]));
    assert_eq!(root.queues[0].hot.items.len(), 2);
    match root.queues[0].hot.items.pop_front().expect("first queued") {
        CoSPendingTxItem::Local(req) => assert_eq!(req.bytes, vec![1]),
        CoSPendingTxItem::Prepared(_) => panic!("unexpected prepared item"),
    }
    match root.queues[0].hot.items.pop_front().expect("second queued") {
        CoSPendingTxItem::Local(req) => assert_eq!(req.bytes, vec![2]),
        CoSPendingTxItem::Prepared(_) => panic!("unexpected prepared item"),
    }
}

#[test]
fn settle_exact_local_fifo_submission_pops_only_committed_prefix() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let tracker = crate::fragment_overlap::OverlapTracker::new();
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![1],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: Some(test_overlap_admissions_10285(&tracker, 1)),
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![2],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: Some(test_overlap_admissions_10285(&tracker, 2)),
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![3],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: Some(test_overlap_admissions_10285(&tracker, 3)),
            enqueue_ns: 0,
        }));
    let mut free_tx_frames = VecDeque::new();
    let mut scratch_local_tx = vec![
        ExactLocalScratchTxRequest { offset: 64, len: 1 },
        ExactLocalScratchTxRequest {
            offset: 128,
            len: 1,
        },
        ExactLocalScratchTxRequest {
            offset: 192,
            len: 1,
        },
    ];

    let mut in_flight_untracked_tx = crate::afxdp::FastSet::default();
    let (sent_packets, sent_bytes) = settle_exact_local_fifo_submission(
        Some(&mut root.queues[0]),
        &mut free_tx_frames,
        &mut scratch_local_tx,
        &mut in_flight_untracked_tx,
        1,
    );

    assert_eq!(sent_packets, 1);
    assert_eq!(sent_bytes, 1);
    assert!(scratch_local_tx.is_empty());
    assert_eq!(
        tracker.len(),
        2,
        "accepted FIFO prefix commits its admission; retry suffix stays held"
    );
    assert_eq!(free_tx_frames, VecDeque::from([128, 192]));
    assert_eq!(root.queues[0].hot.items.len(), 2);
    match root.queues[0]
        .hot
        .items
        .pop_front()
        .expect("first restored")
    {
        CoSPendingTxItem::Local(req) => assert_eq!(req.bytes, vec![2]),
        CoSPendingTxItem::Prepared(_) => panic!("unexpected prepared restored item"),
    }
    match root.queues[0]
        .hot
        .items
        .pop_front()
        .expect("second restored")
    {
        CoSPendingTxItem::Local(req) => assert_eq!(req.bytes, vec![3]),
        CoSPendingTxItem::Prepared(_) => panic!("unexpected prepared restored item"),
    }
}

#[test]
fn release_exact_prepared_scratch_preserves_queue_after_failed_submit() {
    let area = MmapArea::new(4096).expect("mmap");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 64,
            len: 4,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
        }));
    let frame = unsafe { area.slice_mut_unchecked(64, 4) }.expect("frame");
    frame.copy_from_slice(&[1, 2, 3, 4]);
    let mut scratch_prepared_tx = Vec::new();
    let mut free_tx_frames = VecDeque::new();
    let mut pending_fill_frames = VecDeque::new();

    let build = drain_exact_prepared_fifo_items_to_scratch(
        &mut root.queues[0],
        &mut scratch_prepared_tx,
        &area,
        &mut free_tx_frames,
        &mut pending_fill_frames,
        7,
        &mut Vec::new(),
        u64::MAX,
        u64::MAX,
        None,
    );

    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    release_exact_prepared_scratch(&mut scratch_prepared_tx);
    assert!(scratch_prepared_tx.is_empty());
    assert_eq!(root.queues[0].hot.items.len(), 1);
    match root.queues[0].hot.items.front().expect("queued prepared") {
        CoSPendingTxItem::Prepared(req) => assert_eq!(req.offset, 64),
        CoSPendingTxItem::Local(_) => panic!("unexpected local item"),
    }
}

#[test]
fn settle_exact_prepared_fifo_submission_pops_only_committed_prefix() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let tracker = crate::fragment_overlap::OverlapTracker::new();
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 64,
            len: 1,
            recycle: PreparedTxRecycle::FillOnSlot(7),
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: Some(test_overlap_admissions_10285(&tracker, 11)),
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 128,
            len: 1,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: Some(test_overlap_admissions_10285(&tracker, 12)),
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 192,
            len: 1,
            recycle: PreparedTxRecycle::FillOnSlot(9),
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: Some(test_overlap_admissions_10285(&tracker, 13)),
            enqueue_ns: 0,
        }));
    let mut scratch_prepared_tx = vec![
        ExactPreparedScratchTxRequest { offset: 64, len: 1 },
        ExactPreparedScratchTxRequest {
            offset: 128,
            len: 1,
        },
        ExactPreparedScratchTxRequest {
            offset: 192,
            len: 1,
        },
    ];
    let mut in_flight_prepared_recycles = FastMap::default();
    let mut in_flight_untracked_tx = FastSet::default();

    let (sent_packets, sent_bytes) = settle_exact_prepared_fifo_submission(
        Some(&mut root.queues[0]),
        &mut scratch_prepared_tx,
        &mut in_flight_prepared_recycles,
        &mut in_flight_untracked_tx,
        1,
    );

    assert_eq!(
        tracker.len(),
        2,
        "accepted prepared FIFO prefix commits; retry suffix stays held"
    );
    assert_eq!(sent_packets, 1);
    assert_eq!(sent_bytes, 1);
    assert!(scratch_prepared_tx.is_empty());
    assert_eq!(
        in_flight_prepared_recycles.get(&64),
        Some(&PreparedTxRecycle::FillOnSlot(7))
    );
    assert!(!in_flight_prepared_recycles.contains_key(&128));
    assert!(!in_flight_prepared_recycles.contains_key(&192));
    assert_eq!(root.queues[0].hot.items.len(), 2);
    match root.queues[0]
        .hot
        .items
        .pop_front()
        .expect("first restored")
    {
        CoSPendingTxItem::Prepared(req) => assert_eq!(req.offset, 128),
        CoSPendingTxItem::Local(_) => panic!("unexpected local restored item"),
    }
    match root.queues[0]
        .hot
        .items
        .pop_front()
        .expect("second restored")
    {
        CoSPendingTxItem::Prepared(req) => assert_eq!(req.offset, 192),
        CoSPendingTxItem::Local(_) => panic!("unexpected local restored item"),
    }
}

