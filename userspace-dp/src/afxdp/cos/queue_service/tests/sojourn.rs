//! queue_service sojourn tests (#1829): sojourn sampled only at the
//! committed-prefix settle points, never at pop/scratch/batch-build time.

use super::*;

// ---------------------------------------------------------------------------
// #1829 Phase 1 (re-anchored per Codex review on PR #1846): sojourn is
// sampled at the COMMITTED-PREFIX settle points, never at pop /
// scratch-build / batch-build time. The partial- and zero-insert paths
// push the retry suffix back WITH the original enqueue_ns, so sampling
// at pop would count a rolled-back item once per attempt (double-
// counting, biased-high windowed-min/EWMA). These tests pin:
//   (a) drains and batch builds record NOTHING;
//   (b) a partial-insert settle records ONLY the accepted prefix;
//   (c) a rolled-back item is sampled exactly ONCE, on the attempt
//       that finally ships it (differential replay equality — a
//       double sample would diverge the EWMA);
//   (d) the enqueue_ns == 0 legacy guard records nothing end to end;
//   (e) the non-exact submit path (enq sidecar in submit_local)
//       records committed sends end to end via drain_shaped_tx.
// ---------------------------------------------------------------------------

/// Stamp the item's `enqueue_ns` (test items default to 0).
fn stamp_cos_item(mut item: CoSPendingTxItem, enqueue_ns: u64) -> CoSPendingTxItem {
    match &mut item {
        CoSPendingTxItem::Local(req) => req.enqueue_ns = enqueue_ns,
        CoSPendingTxItem::Prepared(req) => req.enqueue_ns = enqueue_ns,
    }
    item
}

fn sojourn_test_exact_root() -> CoSInterfaceRuntime {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
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
    let fast_path = vec![test_queue_fast_path_for_promotion(false)];
    apply_cos_queue_flow_fair_promotion(&mut root, &fast_path, 0);
    assert!(root.queues[0].flow_fair());
    root
}

#[test]
fn sojourn_not_recorded_at_batch_build() {
    use crate::afxdp::types::CoSQueueSojourn;
    let now_ns = 1_000_000_000;
    let mut root = test_cos_runtime_with_exact(false);
    root.tokens = 1500;
    root.queues[0].hot.last_refill_ns = now_ns;
    root.queues[0].hot.tokens = 0;
    root.queues[0]
        .hot
        .items
        .push_back(stamp_cos_item(test_cos_item(1500), now_ns - 5_000_000));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let batch = select_cos_surplus_batch(&mut root, now_ns);
    assert!(batch.is_some(), "surplus batch must build");
    assert_eq!(
        root.queues[0].telemetry.sojourn,
        CoSQueueSojourn::default(),
        "batch build pops items but must NOT sample sojourn — the \
         batch can still be rolled back by a partial/zero TX insert",
    );
}

#[test]
fn sojourn_local_settle_samples_committed_prefix_exactly_once() {
    use crate::afxdp::types::{COS_SOJOURN_WINDOW_NS, CoSQueueSojourn};
    let now_ns = 10 * COS_SOJOURN_WINDOW_NS;
    let area = MmapArea::new(65536).expect("mmap");
    let mut root = sojourn_test_exact_root();
    // Two packets of the SAME flow (one bucket → deterministic FIFO
    // order within the bucket): A is older (larger sojourn), B newer.
    // If the rolled-back B were sampled on the first attempt too, the
    // replay-equality assert below would diverge on the EWMA.
    let enq_a = now_ns - 7_000_000;
    let enq_b = now_ns - 3_000_000;
    cos_queue_push_back(
        &mut root.queues[0],
        stamp_cos_item(test_flow_cos_item(5201, 512), enq_a),
    );
    cos_queue_push_back(
        &mut root.queues[0],
        stamp_cos_item(test_flow_cos_item(5201, 512), enq_b),
    );
    root.queues[0].hot.queued_bytes = 1024;

    // Attempt 1: drain both to scratch, TX ring accepts ONE (partial
    // insert). Settle must sample only the accepted prefix (A) and
    // push B back with its original stamp.
    let mut free_tx_frames = VecDeque::from([0u64, 4096]);
    let mut scratch_local_tx = Vec::new();
    let build = drain_exact_local_items_to_scratch_flow_fair(
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
    assert_eq!(
        root.queues[0].telemetry.sojourn,
        CoSQueueSojourn::default(),
        "scratch build must NOT sample sojourn",
    );
    let mut in_flight_untracked_tx = crate::afxdp::FastSet::default();
    let (sent_packets, _) = settle_exact_local_scratch_submission_flow_fair(
        Some(&mut root.queues[0]),
        &mut free_tx_frames,
        &mut scratch_local_tx,
        &mut in_flight_untracked_tx,
        1,
        now_ns,
    );
    assert_eq!(sent_packets, 1);
    let mut expected = CoSQueueSojourn::default();
    expected.record(enq_a, now_ns);
    assert_eq!(
        root.queues[0].telemetry.sojourn, expected,
        "partial-insert settle must sample ONLY the accepted prefix",
    );

    // Attempt 2: B (restored to the queue head with its ORIGINAL
    // enqueue_ns) drains and commits. It must be sampled now — its
    // first and only sample.
    let mut scratch_local_tx = Vec::new();
    let build = drain_exact_local_items_to_scratch_flow_fair(
        &mut root.queues[0],
        &mut free_tx_frames,
        &mut scratch_local_tx,
        &area,
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    assert_eq!(scratch_local_tx.len(), 1);
    let mut in_flight_untracked_tx = crate::afxdp::FastSet::default();
    let (sent_packets, _) = settle_exact_local_scratch_submission_flow_fair(
        Some(&mut root.queues[0]),
        &mut free_tx_frames,
        &mut scratch_local_tx,
        &mut in_flight_untracked_tx,
        1,
        now_ns,
    );
    assert_eq!(sent_packets, 1);
    expected.record(enq_b, now_ns);
    assert_eq!(
        root.queues[0].telemetry.sojourn, expected,
        "a rolled-back item must be sampled exactly ONCE, on the \
         attempt that ships it (replay equality incl. EWMA)",
    );
}

#[test]
fn sojourn_prepared_settle_samples_committed_prefix_exactly_once() {
    use crate::afxdp::types::{COS_SOJOURN_WINDOW_NS, CoSQueueSojourn};
    let now_ns = 10 * COS_SOJOURN_WINDOW_NS;
    let area = MmapArea::new(65536).expect("mmap");
    let mut root = sojourn_test_exact_root();
    let enq_a = now_ns - 6_000_000;
    let enq_b = now_ns - 2_000_000;
    cos_queue_push_back(
        &mut root.queues[0],
        stamp_cos_item(test_flow_prepared_cos_item(5201, 512, 4096), enq_a),
    );
    cos_queue_push_back(
        &mut root.queues[0],
        stamp_cos_item(test_flow_prepared_cos_item(5201, 512, 8192), enq_b),
    );
    root.queues[0].hot.queued_bytes = 1024;

    let mut free_tx_frames = VecDeque::new();
    let mut pending_fill_frames = VecDeque::new();
    let mut shared_recycles = Vec::new();
    let mut in_flight_prepared_recycles = FastMap::default();
    let mut scratch_prepared_tx = Vec::new();
    let build = drain_exact_prepared_items_to_scratch_flow_fair(
        &mut root.queues[0],
        &mut scratch_prepared_tx,
        &area,
        &mut free_tx_frames,
        &mut pending_fill_frames,
        0,
        &mut shared_recycles,
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    assert_eq!(scratch_prepared_tx.len(), 2);
    assert_eq!(
        root.queues[0].telemetry.sojourn,
        CoSQueueSojourn::default(),
        "prepared scratch build must NOT sample sojourn",
    );
    let mut in_flight_untracked_tx = crate::afxdp::FastSet::default();
    let (sent_packets, _) = settle_exact_prepared_scratch_submission_flow_fair(
        Some(&mut root.queues[0]),
        &mut scratch_prepared_tx,
        &mut in_flight_prepared_recycles,
        &mut in_flight_untracked_tx,
        1,
        now_ns,
    );
    assert_eq!(sent_packets, 1);
    let mut expected = CoSQueueSojourn::default();
    expected.record(enq_a, now_ns);
    assert_eq!(root.queues[0].telemetry.sojourn, expected);

    let mut scratch_prepared_tx = Vec::new();
    let build = drain_exact_prepared_items_to_scratch_flow_fair(
        &mut root.queues[0],
        &mut scratch_prepared_tx,
        &area,
        &mut free_tx_frames,
        &mut pending_fill_frames,
        0,
        &mut shared_recycles,
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    assert_eq!(scratch_prepared_tx.len(), 1);
    let mut in_flight_untracked_tx = crate::afxdp::FastSet::default();
    let (sent_packets, _) = settle_exact_prepared_scratch_submission_flow_fair(
        Some(&mut root.queues[0]),
        &mut scratch_prepared_tx,
        &mut in_flight_prepared_recycles,
        &mut in_flight_untracked_tx,
        1,
        now_ns,
    );
    assert_eq!(sent_packets, 1);
    expected.record(enq_b, now_ns);
    assert_eq!(
        root.queues[0].telemetry.sojourn, expected,
        "rolled-back prepared item sampled exactly ONCE on commit",
    );
}

#[test]
fn sojourn_recorded_end_to_end_via_submit_local() {
    use crate::afxdp::types::{COS_SOJOURN_WINDOW_NS, CoSQueueSojourn};
    // Full path: drain_shaped_tx → build_cos_batch_from_queue →
    // submit_local → transmit_batch → enq-sidecar committed-prefix
    // sampling. The single item is fully sent, so it is sampled
    // exactly once with the pass now_ns.
    let now_ns = 10 * COS_SOJOURN_WINDOW_NS;
    let enq = now_ns - 4_000_000;
    let mut root = test_cos_interface_runtime(0);
    root.tokens = 1500;
    root.queues[0].hot.tokens = 1500;
    root.queues[0].hot.last_refill_ns = now_ns;
    root.queues[0]
        .hot
        .items
        .push_back(stamp_cos_item(test_cos_item(1500), enq));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

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

    let drained = drain_shaped_tx(&mut binding, now_ns, &mut shared_recycles)
        .expect("queue must be serviced");
    assert_eq!(drained.root_ifindex, 42);
    assert!(
        binding
            .live
            .tx_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
    );

    let mut expected = CoSQueueSojourn::default();
    expected.record(enq, now_ns);
    let queue = &binding.cos.cos_interfaces.get(&42).expect("cos root").queues[0];
    assert_eq!(
        queue.telemetry.sojourn, expected,
        "committed send through submit_local must sample exactly once",
    );
}

// #hb166 T-6(e): the CoSBatch submit path (submit_local / submit_prepared)
// is the 5th V_min settle boundary. Like the four direct-service settle
// sites in service.rs, it must publish the committed queue_vtime so peers'
// V_min reduction sees this worker's real progress. Without it a
// surplus-phase shared_exact queue advances vtime unpublished and peers
// self-throttle against a stale-low slot.
//
// FAIL-ON-REVERT: removing the `publish_committed_queue_vtime(...)` call
// added to submit_local's Ok arm leaves the floor slot at None.
#[test]
fn submit_local_publishes_committed_vtime_on_settle() {
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
            surplus_sharing: true,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    root.tokens = 1500;
    root.queues[0].hot.tokens = 1500;
    // shared_exact flow-fair queue with a V_min floor for worker 0 of 2.
    let floor = attach_test_vtime_floor(&mut root.queues[0], 2, 0);
    // Pretend a drain has already advanced this queue's committed vtime.
    test_flow_fair_state_mut(&mut root.queues[0]).queue_vtime = 54_321;

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

    assert_eq!(floor.slots[0].read(), None, "test premise: slot starts unpublished");

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
        enqueue_ns: now_ns,
    }]);
    let mut shared_recycles = Vec::new();

    submit_local(
        &mut binding,
        42,
        0,
        CoSServicePhase::Surplus,
        128,
        items,
        now_ns,
        &mut shared_recycles,
    );

    assert_eq!(
        floor.slots[0].read(),
        Some(54_321),
        "submit_local settle must publish the committed queue_vtime to the V_min floor slot",
    );
}

#[test]
fn sojourn_zero_stamp_items_record_nothing_end_to_end() {
    use crate::afxdp::types::CoSQueueSojourn;
    let now_ns = 1_000_000_000;
    let area = MmapArea::new(65536).expect("mmap");
    let mut root = sojourn_test_exact_root();
    // test_flow_cos_item leaves enqueue_ns at 0 (the pre-#1829 /
    // non-CoS construction default) — drain + full-commit settle must
    // record NOTHING.
    cos_queue_push_back(&mut root.queues[0], test_flow_cos_item(5201, 512));
    root.queues[0].hot.queued_bytes = 512;

    let mut free_tx_frames = VecDeque::from([0u64]);
    let mut scratch_local_tx = Vec::new();
    let build = drain_exact_local_items_to_scratch_flow_fair(
        &mut root.queues[0],
        &mut free_tx_frames,
        &mut scratch_local_tx,
        &area,
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    let mut in_flight_untracked_tx = crate::afxdp::FastSet::default();
    let (sent_packets, _) = settle_exact_local_scratch_submission_flow_fair(
        Some(&mut root.queues[0]),
        &mut free_tx_frames,
        &mut scratch_local_tx,
        &mut in_flight_untracked_tx,
        1,
        now_ns,
    );
    assert_eq!(sent_packets, 1);
    assert_eq!(
        root.queues[0].telemetry.sojourn,
        CoSQueueSojourn::default(),
        "enqueue_ns == 0 must be treated as no-data, never a sample",
    );
}

