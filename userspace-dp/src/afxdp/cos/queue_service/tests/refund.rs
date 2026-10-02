//! queue_service refund/lease tests: Phase-1 honor refund on zero-TX and
//! shared-lease-gated non-exact guaranteed refill.

use super::*;

/// #3968: the NON-exact flow-fair service path
/// (`build_cos_batch_from_queue`) must clear the pop-snapshot stack
/// at batch start — the analog of the clear the exact drain path
/// (`drain_exact_*_flow_fair`) already performs (drain.rs).
///
/// A fully-committed non-exact batch leaves ALL of its snapshots on
/// the stack: `restore_cos_local_items_inner` only pops a snapshot
/// per RETRIED item, so a batch the TX ring accepted whole consumes
/// none. `drain_shaped_tx` builds one batch per call and the outer
/// TX loop calls it repeatedly, so a saturated promoted non-exact
/// queue with more than `TX_BATCH_SIZE` resident items is drained
/// across consecutive `build_cos_batch_from_queue` calls with NO
/// intervening `push_back` (the only other clear site). Without the
/// batch-start clear the second build pushes on top of the first
/// batch's stale snapshots, growing the stack past its documented
/// `TX_BATCH_SIZE` bound — a hot-path realloc / stale re-read (and
/// the per-pop `debug_assert` in `cos_queue_pop_known_bucket_inner`
/// trips in dev builds).
///
/// RED-on-revert: without the clear, the second batch's stack holds
/// `TX_BATCH_SIZE + 64` snapshots (release) or the per-pop
/// `debug_assert` panics (dev). A single build is unaffected.
#[test]
fn build_cos_batch_clears_pop_snapshot_stack_across_batches() {
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000_000 / 8,
            guarantee_enabled: true,
            // NON-exact: exercises the build_cos_batch_from_queue
            // service path (the exact path drains via
            // drain_exact_*_flow_fair, which already clears).
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 8 * 1024 * 1024,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    enable_test_flow_fair(queue);

    let pre_cap = test_flow_fair_state(queue).pop_snapshot_stack.capacity();
    assert_eq!(
        pre_cap, TX_BATCH_SIZE,
        "stack must be preallocated to TX_BATCH_SIZE",
    );

    // Saturate: TX_BATCH_SIZE + 64 items across two flows so the
    // MQFQ min-finish scan does real selection and the first build
    // pops a full TX_BATCH_SIZE batch with 64 items left resident.
    let total = TX_BATCH_SIZE + 64;
    for i in 0..total {
        let src_port = if i % 2 == 0 { 9001u16 } else { 9002u16 };
        cos_queue_push_back(queue, test_flow_cos_item(src_port, 100));
    }

    // #4973: this test drives build_cos_batch_from_queue directly (no submit),
    // so it passes throwaway batch scratch deques instead of the per-worker
    // WorkerCos scratch the production drain threads.
    let mut local_scratch = VecDeque::new();
    let mut prepared_scratch = VecDeque::new();

    // Batch 1: build_cos_batch_from_queue pops TX_BATCH_SIZE items,
    // pushing one rollback snapshot per pop. Budgets = u64::MAX so
    // nothing caps the batch below the frame-count bound.
    let batch1 = build_cos_batch_from_queue(
        &mut root.queues[0],
        0,
        u64::MAX,
        u64::MAX,
        CoSServicePhase::Guarantee,
        &mut local_scratch,
        &mut prepared_scratch,
    )
    .expect("first batch built");
    let batch1_len = match &batch1 {
        CoSBatch::Local { items, .. } => items.len(),
        CoSBatch::Prepared { items, .. } => items.len(),
    };
    assert_eq!(
        batch1_len, TX_BATCH_SIZE,
        "first batch fills a full TX_BATCH_SIZE batch",
    );
    assert_eq!(
        test_flow_fair_state(&root.queues[0])
            .pop_snapshot_stack
            .len(),
        TX_BATCH_SIZE,
        "one snapshot per popped item",
    );

    // Full commit: the TX ring accepted every item, so nothing is
    // push_fronted back and no snapshot is consumed. Drop the batch
    // WITHOUT a push_back (which would clear the stack) — mirrors
    // the drain_shaped_tx full-commit hot path exactly.
    drop(batch1);

    // Batch 2: drain the remaining 64 items with NO intervening
    // push_back. With the batch-start clear the stack holds ONLY the
    // second batch's own snapshots.
    let batch2 = build_cos_batch_from_queue(
        &mut root.queues[0],
        0,
        u64::MAX,
        u64::MAX,
        CoSServicePhase::Guarantee,
        &mut local_scratch,
        &mut prepared_scratch,
    )
    .expect("second batch built");
    let batch2_len = match &batch2 {
        CoSBatch::Local { items, .. } => items.len(),
        CoSBatch::Prepared { items, .. } => items.len(),
    };
    assert_eq!(
        batch2_len, 64,
        "second batch drains the remaining resident items",
    );
    assert_eq!(
        test_flow_fair_state(&root.queues[0])
            .pop_snapshot_stack
            .len(),
        batch2_len,
        "#3968: the second batch's stack holds ONLY its own \
         snapshots — no stale first-batch residue",
    );
    assert_eq!(
        test_flow_fair_state(&root.queues[0])
            .pop_snapshot_stack
            .capacity(),
        pre_cap,
        "#3968: stack must not realloc past TX_BATCH_SIZE",
    );
}

/// #4973: `build_cos_batch_from_queue` reuses a per-worker scratch deque
/// (`mem::take`n from `WorkerCos` at build, drained and stored back by the
/// submit handler). It MUST `clear()` that scratch at batch entry: a stale
/// element left resident — e.g. from a queue-torn-down submit early return that
/// stores the deque back undrained — would otherwise be emitted as the FIRST
/// item of the NEXT batch, corrupting its contents while `batch_bytes` counts
/// only the freshly popped items.
///
/// RED-on-revert: drop the `local_scratch.clear()` in the Local arm and the
/// built batch carries the pre-seeded 9999-byte stale request ahead of the ten
/// real items (len 11, first item = the marker); both assertions fail.
#[test]
fn build_cos_batch_local_clears_reused_scratch_between_batches() {
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000_000 / 8,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 8 * 1024 * 1024,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    enable_test_flow_fair(&mut root.queues[0]);

    // Ten real 100-byte Local items across two flows (well under TX_BATCH_SIZE
    // so the queue drains fully into one batch).
    let real_items = 10usize;
    for i in 0..real_items {
        let src_port = if i % 2 == 0 { 9001u16 } else { 9002u16 };
        cos_queue_push_back(&mut root.queues[0], test_flow_cos_item(src_port, 100));
    }

    // Pre-seed the reusable Local scratch with a STALE 9999-byte request,
    // modelling a store-back that left residue behind.
    let mut local_scratch = VecDeque::new();
    let mut prepared_scratch = VecDeque::new();
    match test_flow_cos_item(7777, 9999) {
        CoSPendingTxItem::Local(stale) => local_scratch.push_back(stale),
        CoSPendingTxItem::Prepared(_) => unreachable!("test_flow_cos_item yields Local"),
    }

    let batch = build_cos_batch_from_queue(
        &mut root.queues[0],
        0,
        u64::MAX,
        u64::MAX,
        CoSServicePhase::Guarantee,
        &mut local_scratch,
        &mut prepared_scratch,
    )
    .expect("local batch built");

    let items = match &batch {
        CoSBatch::Local { items, .. } => items,
        CoSBatch::Prepared { .. } => panic!("expected a Local batch"),
    };
    assert_eq!(
        items.len(),
        real_items,
        "the reused scratch must be cleared: only freshly popped queue items \
         appear, never the pre-seeded stale request",
    );
    assert!(
        items.iter().all(|req| req.bytes.len() == 100),
        "no batch item may carry the 9999-byte stale marker",
    );
    // The taken scratch is left empty in the field (mem::take), and the built
    // deque owns the ten real items.
    assert!(
        local_scratch.is_empty(),
        "the scratch is mem::taken into the batch, leaving the field empty",
    );
}

/// #4973: the Prepared arm of `build_cos_batch_from_queue` shares the same
/// clear-at-entry contract as the Local arm above; pin it independently so a
/// revert of only `prepared_scratch.clear()` is still caught RED.
#[test]
fn build_cos_batch_prepared_clears_reused_scratch_between_batches() {
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000_000 / 8,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 8 * 1024 * 1024,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    enable_test_flow_fair(&mut root.queues[0]);

    // Ten real 100-byte Prepared items across two flows.
    let real_items = 10usize;
    for i in 0..real_items {
        let src_port = if i % 2 == 0 { 9001u16 } else { 9002u16 };
        cos_queue_push_back(
            &mut root.queues[0],
            test_flow_prepared_cos_item(src_port, 100, 4096 + i as u64 * 4096),
        );
    }

    let mut local_scratch = VecDeque::new();
    let mut prepared_scratch = VecDeque::new();
    match test_flow_prepared_cos_item(7777, 9999, 512) {
        CoSPendingTxItem::Prepared(stale) => prepared_scratch.push_back(stale),
        CoSPendingTxItem::Local(_) => unreachable!("test_flow_prepared_cos_item yields Prepared"),
    }

    let batch = build_cos_batch_from_queue(
        &mut root.queues[0],
        0,
        u64::MAX,
        u64::MAX,
        CoSServicePhase::Guarantee,
        &mut local_scratch,
        &mut prepared_scratch,
    )
    .expect("prepared batch built");

    let items = match &batch {
        CoSBatch::Prepared { items, .. } => items,
        CoSBatch::Local { .. } => panic!("expected a Prepared batch"),
    };
    assert_eq!(
        items.len(),
        real_items,
        "the reused prepared scratch must be cleared: only freshly popped \
         queue items appear, never the pre-seeded stale request",
    );
    assert!(
        items.iter().all(|req| req.len == 100),
        "no batch item may carry the 9999-byte stale marker",
    );
    assert!(
        prepared_scratch.is_empty(),
        "the scratch is mem::taken into the batch, leaving the field empty",
    );
}

// hb166 T-2: a Phase-1 honored waterfill selection whose service makes
// ZERO TX progress must have its epoch honor REFUNDED, not burned.

/// Unit-level: the refund helper restores the debited Phase-1 budget,
/// clears the honored-epoch bit, and corrects the telemetry
/// (phase1_admissions back to 0, phase1_selected_no_progress = 1).
#[test]
fn waterfill_phase1_honor_refund_restores_budget_clears_bit_and_counts() {
    let mut root = waterfill_guarantee_rate_root(1.0);
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let s = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("phase-1 selection");

    // The smallest exact queue is ascending ordinal 0.
    let refund = s
        .phase1_honor
        .expect("a Phase-1 honored selection must carry refund info");
    assert!(refund.cost_bytes > 0, "a Phase-1 honor debits real bytes");
    assert_eq!(refund.bit_ordinal, 0, "smallest exact queue is ordinal 0");

    let budget_debited = root.waterfill_pass1_remaining_bytes;
    assert_ne!(
        root.waterfill_honored_epoch_bits[0] & 0b1,
        0,
        "selection set the ordinal-0 honored bit"
    );
    assert_eq!(
        root.queues[s.queue_idx]
            .telemetry
            .waterfill_counters
            .phase1_admissions,
        1,
        "selection bumped phase1_admissions"
    );

    // Zero-byte TX: refund the honor.
    apply_phase1_waterfill_honor_refund(&mut root, s.queue_idx, refund);

    assert_eq!(
        root.waterfill_pass1_remaining_bytes,
        budget_debited + refund.cost_bytes,
        "refund adds the debited cost back to the Phase-1 budget"
    );
    assert_eq!(
        root.waterfill_honored_epoch_bits[0] & 0b1,
        0,
        "refund clears the honored bit so the class is re-selectable this epoch"
    );
    let counters = root.queues[s.queue_idx].telemetry.waterfill_counters;
    assert_eq!(
        counters.phase1_admissions, 0,
        "refund undoes the over-counted admission (counts services, not selections)"
    );
    assert_eq!(
        counters.phase1_selected_no_progress, 1,
        "refund records the no-progress visit"
    );
}

/// End-to-end wiring: with the TX free-frame pool exhausted, the
/// service wrapper's Phase-1 honored selection makes zero progress and
/// the honor is refunded via the production
/// `service_exact_guarantee_queue_direct_with_info` path. RED-on-revert:
/// without the refund the honored bit stays set (`0b1`) and the class is
/// skipped for the rest of the epoch.
#[test]
fn service_exact_guarantee_zero_tx_refunds_phase1_honor() {
    let root = waterfill_guarantee_rate_root(1.0);
    let root_lease = Arc::new(SharedCoSRootLease::new(
        root.shaping_rate_bytes,
        root.burst_bytes,
        1,
    ));
    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![
            (0, test_queue_fast_path(false, 0, None, None)),
            (1, test_queue_fast_path(false, 0, None, None)),
            (2, test_queue_fast_path(false, 0, None, None)),
            (3, test_queue_fast_path(false, 0, None, None)),
        ],
        None,
        Some(root_lease),
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    // Force every service call to make zero TX progress: no free UMEM
    // frames and nothing to reap. This is the interface-wide TX-pressure
    // condition that the pre-fix code let burn the small class's epoch.
    binding.tx_pipeline.free_tx_frames.clear();

    let mut shared_recycles = Vec::new();
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let out =
        service_exact_guarantee_queue_direct_with_info(&mut binding, 42, 1, &mut shared_recycles, &mut tel);
    assert!(
        matches!(out, Some(None)),
        "exact selection fired but service made no TX progress"
    );

    let root = binding.cos.cos_interfaces.get(&42).expect("cos root");
    assert_eq!(
        root.waterfill_honored_epoch_bits[0] & 0b1,
        0,
        "zero-TX Phase-1 selection must REFUND the honored bit (T-2), not burn the epoch"
    );
    let counters = root.queues[0].telemetry.waterfill_counters;
    assert_eq!(
        counters.phase1_admissions, 0,
        "a no-progress selection must not count as an admission"
    );
    assert_eq!(
        counters.phase1_selected_no_progress, 1,
        "the refunded no-progress visit is recorded"
    );
}

// ---------------------------------------------------------------------------
// #4265 (R-2): non-exact guaranteed classes must be metered class-wide, not
// admitted at N_workers x their configured rate on a shared (sharded) egress.
// ---------------------------------------------------------------------------

/// A single non-exact GUARANTEED queue config with an explicit high
/// transmit-rate — the shape that runs the sharded `shared_exact`
/// execution policy (rate >= COS_SHARED_EXACT_MIN_RATE_BYTES) yet is
/// serviced through `select_nonexact_cos_guarantee_batch` because it is
/// not `exact`.
fn nonexact_guarantee_queue(rate_bytes: u64) -> CoSQueueConfig {
    CoSQueueConfig {
        queue_id: 4,
        forwarding_class: "iperf-be".into(),
        priority: 5,
        transmit_rate_bytes: rate_bytes,
        guarantee_enabled: true,
        exact: false,
        surplus_sharing: false,
        equal_flow_enforcement: false,
        equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
        surplus_weight: 1,
        buffer_bytes: 512 * 1024,
        dscp_rewrite: None,
        codel_target_ns: 0,
    }
}

#[test]
fn nonexact_guarantee_refill_is_gated_by_shared_lease_pool() {
    // #4265 (R-2): the non-exact guarantee selector must meter its refill
    // through the attached shared lease, NOT refill a private per-worker
    // bucket at the full configured rate. Attach a lease whose shared pool
    // is fully drained and cannot replenish within the call (no elapsed
    // time), and confirm the selector grants ZERO tokens -> the queue stays
    // token-starved and returns no batch, with `hot.tokens` left at 0.
    //
    // RED on revert: the pre-fix selector called `refill_cos_tokens`, which
    // ignores the lease and refills `hot.tokens` to the buffer cap on the
    // first refill -> a batch is returned and `hot.tokens > 0`.
    let rate = 3_000_000_000u64 / 8; // 3 Gbps, >= COS_SHARED_EXACT_MIN_RATE_BYTES
    let lease = Arc::new(SharedCoSQueueLease::new(rate, 256 * 1024, 6));

    let t0 = 8 * TEST_EPOCH_DURATION_NS;
    // Drain the shared pool to empty at t0 (a fresh lease starts with a
    // burst of credit).
    let drained = lease.acquire(t0, u64::MAX);
    assert!(
        drained > 0,
        "a fresh legacy lease starts with a burst to drain"
    );

    let mut root = test_cos_runtime_with_queues(rate, vec![nonexact_guarantee_queue(rate)]);
    root.tokens = u64::MAX / 2; // root shaper never caps
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.runnable = true;
    root.queues[0].v_min.worker_id = 0;
    for _ in 0..8 {
        cos_queue_push_back(&mut root.queues[0], test_flow_cos_item(10_000, 1500));
    }
    let fp = vec![test_queue_fast_path(true, 0, None, Some(lease.clone()))];

    // Same timestamp as the drain: no elapsed time, so the pool refills
    // nothing and the queue must be starved of guarantee credit.
    let batch = select_nonexact_cos_guarantee_batch(&mut root, &fp, t0);
    assert!(
        batch.is_none(),
        "an empty shared lease must starve the non-exact guarantee; a batch here \
         means the per-worker full-rate refill leaked through (the R-2 bug)"
    );
    assert_eq!(
        root.queues[0].hot.tokens, 0,
        "the selector must not refill a private per-worker bucket past the shared lease"
    );
}

#[test]
fn nonexact_guarantee_shared_lease_bounds_aggregate_admission_across_workers() {
    // #4265 (R-2): a non-exact guaranteed class sharded across N workers
    // must admit at AGGREGATE == its configured rate, not N x it. Before
    // the fix each worker's `select_nonexact_cos_guarantee_batch` refilled a
    // PRIVATE token bucket at the FULL rate, so N backlogged workers each
    // admitted a full rate -> ~N x over-admit at guarantee priority. With
    // the shared legacy lease attached, all N workers draw from ONE metered
    // pool, so the class-wide admission is bounded near the configured rate.
    //
    // Model: N per-worker replicas of the same queue, each backlogged, all
    // sharing one lease. Each tick every worker tops up through the selector
    // then "sends" all the credit it acquired (draining `hot.tokens` and
    // debiting the shared lease). The summed sends are the class-wide
    // admission over the window.
    //
    // RED on revert: without the lease routing the per-worker refill makes
    // the aggregate ~N x the configured rate.
    const N: usize = 6;
    let rate = 3_000_000_000u64 / 8; // 3 Gbps, >= COS_SHARED_EXACT_MIN_RATE_BYTES
    let burst = 256 * 1024u64;
    let lease = Arc::new(SharedCoSQueueLease::new(rate, burst, N));

    let mut roots: Vec<CoSInterfaceRuntime> = Vec::with_capacity(N);
    let mut fps: Vec<Vec<WorkerCoSQueueFastPath>> = Vec::with_capacity(N);
    for w in 0..N {
        let mut root = test_cos_runtime_with_queues(rate, vec![nonexact_guarantee_queue(rate)]);
        root.queues[0].hot.runnable = true;
        root.queues[0].v_min.worker_id = w as u32;
        roots.push(root);
        fps.push(vec![test_queue_fast_path(
            true,
            w as u32,
            None,
            Some(lease.clone()),
        )]);
    }

    let start = 8 * TEST_EPOCH_DURATION_NS;
    let step = TEST_EPOCH_DURATION_NS; // 200 us == one lease window
    let ticks = 100u64; // 20 ms observation window
    let mut aggregate_admitted = 0u64;

    let mut now = start;
    for _ in 0..ticks {
        now += step;
        for w in 0..N {
            let root = &mut roots[w];
            // Keep the queue backlogged and the root shaper uncapped so the
            // per-queue shared lease is the only admission gate under test.
            root.tokens = u64::MAX / 2;
            while root.queues[0].hot.items.len() < 96 {
                cos_queue_push_back(
                    &mut root.queues[0],
                    test_flow_cos_item(10_000 + w as u16, 500),
                );
            }
            root.queues[0].hot.runnable = true;

            let _ = select_nonexact_cos_guarantee_batch(root, &fps[w], now);

            // A fully-backlogged worker sends everything it was granted this
            // tick; debit the shared lease for those bytes.
            let admitted = root.queues[0].hot.tokens;
            aggregate_admitted = aggregate_admitted.saturating_add(admitted);
            lease.consume(admitted);
            root.queues[0].hot.tokens = 0;
        }
    }

    let window_ns = ticks * step;
    let expected = ((rate as u128) * (window_ns as u128) / 1_000_000_000u128) as u64;
    assert!(
        aggregate_admitted < 3 * expected,
        "aggregate non-exact guarantee admission {aggregate_admitted} B over {window_ns} ns must \
         stay bounded near the configured rate (expected ~{expected} B, N={N}); an aggregate \
         approaching N x expected means each worker refilled a private full-rate bucket (the R-2 bug)"
    );
    assert!(
        aggregate_admitted > expected / 2,
        "aggregate admission {aggregate_admitted} B collapsed well below the configured rate \
         (expected ~{expected} B) — the shared lease is over-throttling the class"
    );
}

