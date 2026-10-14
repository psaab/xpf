//! queue_service fairness-gate tests: #1229 v7 per-bucket cap and #917
//! V_min cross-worker lag brake on the `build_cos_batch_from_queue`
//! batch-build path (#13062 / deep-review D1-04).
//!
//! Pre-fix, that builder hardcoded `target_bps = u64::MAX` into
//! `cos_queue_peek_min_bucket` / `cos_queue_pop_known_bucket` and never
//! ran the V_min gate, so cap-aware bucket selection was dead code on
//! lazily-promoted non-exact guaranteed queues (#1735) and BOTH the cap
//! and the V_min lag brake were bypassed on `shared_exact`
//! `surplus_sharing` queues drained in Phase 3 (#915) — while
//! `apply_cos_*_result` still published the unthrottled `queue_vtime`
//! to `vtime_floor`.

use super::*;

/// #13062 (D1-04) probe 1: a lazily-promoted NON-exact guaranteed
/// queue (the exact shape `select_nonexact_cos_guarantee_batch_into`
/// services) must apply the #1229 v7 per-bucket fair-share cap when
/// building a batch: with `transmit_rate_bytes = 125_000_000` (1 Gbps)
/// and two active flow buckets, the target is `queue_bw / 2 =
/// 500 Mbps`, so an elephant bucket observed at 1 Gbps is deferred in
/// favor of the under-cap mouse bucket — even though the elephant has
/// the LOWER virtual finish time. `submit_local_cos_batch` /
/// `submit_prepared_cos_batch` already pay the per-packet
/// `account_flow_bucket_tx` cost that maintains `observed_bps` on this
/// path; the builder must honor it.
///
/// RED-on-revert: with the `u64::MAX` hardcode restored, the no-cap
/// min-finish scan pops the elephant's 500 B item first (batch_bytes
/// 500, src_port == src_a); both assertions below fail.
#[test]
fn nonexact_flow_fair_build_applies_v7_bucket_cap() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 125_000_000,
            guarantee_enabled: true,
            // NON-exact + shaped: the lazily-promoted flow-fair shape
            // (#1735) serviced by build_cos_batch_from_queue.
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

    // Two flows in DISTINCT buckets (seed 0 after enable_test_flow_fair).
    let src_a: u16 = 9999;
    let bucket_a = cos_flow_bucket_index(0, Some(&test_session_key(src_a, 5201)));
    let mut src_b: u16 = 9000;
    let bucket_b = loop {
        let b = cos_flow_bucket_index(0, Some(&test_session_key(src_b, 5201)));
        if b != bucket_a {
            break b;
        }
        src_b += 1;
    };

    // Elephant A small (500 B) then mouse B large (1500 B): with
    // queue_vtime at 0 the head-finish anchors at bytes, so
    // head_a = 500 < head_b = 1500 — the over-cap bucket is the
    // LOWER-finish one a naive min-finish selector would pop.
    cos_queue_push_back(queue, test_flow_cos_item(src_a, 500));
    cos_queue_push_back(queue, test_flow_cos_item(src_b, 1500));
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        500,
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_b],
        1500,
    );

    // A over cap (1 Gbps observed > 500 Mbps target), B under (0).
    {
        let ff = test_flow_fair_state_mut(queue);
        ff.flow_bucket_observed_bps[bucket_a] = 1_000_000_000;
        ff.flow_bucket_observed_bps[bucket_b] = 0;
    }

    // Secondary budget admits exactly one frame: the elephant's 500 B
    // or the mouse's 1500 B, never both.
    let mut local_scratch = VecDeque::new();
    let mut prepared_scratch = VecDeque::new();
    let batch = build_cos_batch_from_queue(
        &mut root.queues[0],
        0,
        u64::MAX,
        1500,
        CoSServicePhase::Guarantee,
        &mut local_scratch,
        &mut prepared_scratch,
    )
    .expect("cap-aware build must still be work-conserving (under-cap bucket)");
    let CoSBatch::Local {
        items, batch_bytes, ..
    } = batch
    else {
        panic!("Local items were pushed; batch must be the Local variant");
    };
    assert_eq!(items.len(), 1, "budget admits exactly one frame");
    assert_eq!(batch_bytes, 1500, "the MOUSE frame is the one admitted");
    assert_eq!(
        items[0].flow_key.as_ref().expect("flow key").src_port,
        src_b,
        "#1229 v7: the over-cap elephant bucket must be deferred in \
         favor of the under-cap mouse bucket",
    );
}

/// #13062 (D1-04) probe 2: a `shared_exact` queue with
/// `surplus_sharing == true` (#915) drained in Phase 3 must honor the
/// #917 V_min cross-worker lag brake inside the batch build. The local
/// worker publishes `queue_vtime` 100 MB ahead of the peer floor; the
/// first candidate pop must throttle the build (empty batch, no vtime
/// advance, #2646 counter not burned) so the fast worker moves on to
/// the next runnable queue in the surplus sweep.
///
/// RED-on-revert: with the V_min gate unwired, the build pops both
/// items and returns Some — every assertion below fails.
#[test]
fn shared_exact_surplus_build_is_v_min_throttled() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            // #915: the exact queue opts into Phase-3 surplus service,
            // which routes through build_cos_batch_from_queue.
            surplus_sharing: true,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 4 * 1024 * 1024,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    enable_test_flow_fair(queue);
    let floor = attach_test_vtime_floor(queue, 2, 0);

    // Peer worker 1 pegged at vtime 0. Local worker 0 has queue_vtime
    // 100 MB ahead — far past the ~625 KB lag budget at 10 Gbps / 2
    // participating workers.
    floor.slots[1].publish(0);
    test_flow_fair_state_mut(queue).queue_vtime = 100 * 1024 * 1024;

    cos_queue_push_back(queue, test_flow_cos_item(9001, 1500));
    cos_queue_push_back(queue, test_flow_cos_item(9002, 1500));

    let mut local_scratch = VecDeque::new();
    let mut prepared_scratch = VecDeque::new();
    let batch = build_cos_batch_from_queue(
        &mut root.queues[0],
        0,
        u64::MAX,
        u64::MAX,
        CoSServicePhase::Surplus,
        &mut local_scratch,
        &mut prepared_scratch,
    );
    assert!(
        batch.is_none(),
        "#917: a shared_exact surplus build 100 MB past the peer floor \
         must be throttled to an empty batch",
    );
    assert_eq!(
        root.queues[0].v_min.v_min_throttles_scratch, 1,
        "the throttle decision must be counted",
    );
    assert_eq!(
        root.queues[0].v_min.v_min_pop_count, 0,
        "#2646: a throttled break must not burn a cadence position",
    );
    assert_eq!(
        test_flow_fair_state(&root.queues[0]).queue_vtime,
        100 * 1024 * 1024,
        "no pop → no queue_vtime advance past the peer floor",
    );
    assert!(
        !cos_queue_is_empty(&root.queues[0]),
        "both items must stay resident for the peer / a later pass",
    );

    // Control: with the local vtime back inside the lag budget the
    // same build proceeds — the brake throttles, it never stalls.
    test_flow_fair_state_mut(&mut root.queues[0]).queue_vtime = 0;
    root.queues[0].v_min.v_min_throttles_scratch = 0;
    let batch = build_cos_batch_from_queue(
        &mut root.queues[0],
        0,
        u64::MAX,
        u64::MAX,
        CoSServicePhase::Surplus,
        &mut local_scratch,
        &mut prepared_scratch,
    )
    .expect("within the lag budget the surplus build must proceed");
    let CoSBatch::Local {
        items, batch_bytes, ..
    } = batch
    else {
        panic!("Local items were pushed; batch must be the Local variant");
    };
    assert_eq!(items.len(), 2, "both resident items drain");
    assert_eq!(batch_bytes, 2 * 1500);
    assert_eq!(
        root.queues[0].v_min.v_min_pop_count, 2,
        "#2646: two confirmed pops advance the cadence counter",
    );
    assert_eq!(
        root.queues[0].v_min.consecutive_v_min_skips, 0,
        "a passing V_min check resets the hard-cap accumulator",
    );
}
