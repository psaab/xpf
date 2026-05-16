// Tests for afxdp/cos/tx_completion.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep tx_completion.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "tx_completion_tests.rs"]` from tx_completion.rs.

use super::*;
use crate::afxdp::TX_BATCH_SIZE;
use crate::afxdp::cos::queue_service::{
    select_cos_guarantee_batch, select_exact_cos_guarantee_queue_with_fast_path,
};
use crate::afxdp::cos::token_bucket::COS_MIN_BURST_BYTES;
use crate::afxdp::tx::test_support::*;
use crate::afxdp::types::{
    COS_FLOW_FAIR_BUCKETS, CoSQueueDropCounters, CoSQueueOwnerProfile, FlowRrRing,
    SharedCoSExactBacklog, SharedCoSQueueLease,
};
use std::sync::Arc;
use std::sync::atomic::Ordering;

// #915 Codex code-review MEDIUM: direct unit tests for the
// phase-gated `shared_queue_lease` consumption helper. Both
// `apply_cos_send_result` and `apply_cos_prepared_result` route
// through `maybe_consume_exact_queue_lease` (extracted helper),
// so testing the helper covers both production paths without a
// full BindingWorker fixture.
//
// The lease's `outstanding_leased_tokens` field tracks how many
// bytes have been ACQUIRED but not yet CONSUMED. After a full
// acquire that maxes out `max_total_leased`, no further acquire
// can grant bytes (returns 0). Calling `consume` decrements
// `outstanding_leased_tokens`, freeing headroom for a subsequent
// acquire to succeed. This indirect observation lets us prove
// whether the helper called `lease.consume()` without exposing
// internal counters.

#[test]
fn maybe_consume_exact_queue_lease_skips_on_surplus_phase() {
    let lease = Arc::new(SharedCoSQueueLease::new(
        10_000_000, // 10 Mb/s lease rate (irrelevant; we mostly care about max_total)
        128 * 1024, // burst
        2,          // num workers
    ));
    // Acquire enough to fill outstanding to max_total_leased so no
    // further acquire can succeed without consume freeing headroom.
    let acquired = lease.acquire(0, 8 * 1024 * 1024);
    assert!(acquired > 0, "initial acquire must grant some bytes");
    // Drain remaining headroom — repeated acquires until 0 granted.
    loop {
        if lease.acquire(0, 8 * 1024 * 1024) == 0 {
            break;
        }
    }
    // Sanity: at saturation, another acquire grants 0.
    assert_eq!(
        lease.acquire(0, 1500),
        0,
        "saturated lease must grant 0 bytes"
    );

    // Surplus phase: helper must NOT consume, so headroom stays at 0.
    maybe_consume_exact_queue_lease(Some(&lease), CoSServicePhase::Surplus, 1500);
    assert_eq!(
        lease.acquire(0, 1500),
        0,
        "Surplus phase must not free queue-lease headroom"
    );
}

#[test]
fn maybe_consume_exact_queue_lease_debits_on_guarantee_phase() {
    let lease = Arc::new(SharedCoSQueueLease::new(10_000_000, 128 * 1024, 2));
    let _ = lease.acquire(0, 8 * 1024 * 1024);
    loop {
        if lease.acquire(0, 8 * 1024 * 1024) == 0 {
            break;
        }
    }
    assert_eq!(lease.acquire(0, 1500), 0);

    // Guarantee phase: helper consumes; headroom is freed.
    maybe_consume_exact_queue_lease(Some(&lease), CoSServicePhase::Guarantee, 1500);
    assert_eq!(
        lease.acquire(0, 1500),
        1500,
        "Guarantee phase must free 1500 bytes of queue-lease headroom"
    );
}

#[test]
fn maybe_consume_exact_queue_lease_no_lease_no_op() {
    // When the queue has no shared lease (None), both phases must
    // be no-ops. Defensive — covers the `if let Some` arm.
    maybe_consume_exact_queue_lease(None, CoSServicePhase::Surplus, 1500);
    maybe_consume_exact_queue_lease(None, CoSServicePhase::Guarantee, 1500);
    // No assertion needed — the function must not panic on None.
}

#[test]
fn account_queue_drain_sent_bytes_splits_phase_and_exact_backlog_steal() {
    let mut root = test_mixed_class_root_with_primed_queues();
    assert!(
        root_has_backlogged_exact_queue(&root),
        "mixed fixture must start with backlogged exact queues"
    );

    let nonexact = &mut root.queues[1];
    assert!(!nonexact.config.exact);
    account_queue_drain_sent_bytes(nonexact, CoSServicePhase::Surplus, 2048, true);
    assert_eq!(
        nonexact
            .telemetry
            .owner_profile
            .drain_sent_bytes
            .load(Ordering::Relaxed),
        2048
    );
    assert_eq!(
        nonexact
            .telemetry
            .owner_profile
            .drain_surplus_sent_bytes
            .load(Ordering::Relaxed),
        2048
    );
    assert_eq!(
        nonexact
            .telemetry
            .owner_profile
            .drain_nonexact_sent_bytes_while_exact_backlogged
            .load(Ordering::Relaxed),
        2048
    );

    let exact = &mut root.queues[0];
    assert!(exact.config.exact);
    account_queue_drain_sent_bytes(exact, CoSServicePhase::Guarantee, 1024, true);
    assert_eq!(
        exact
            .telemetry
            .owner_profile
            .drain_guarantee_sent_bytes
            .load(Ordering::Relaxed),
        1024
    );
    assert_eq!(
        exact
            .telemetry
            .owner_profile
            .drain_nonexact_sent_bytes_while_exact_backlogged
            .load(Ordering::Relaxed),
        0,
        "exact queue service must not be counted as non-exact steal"
    );
}

#[test]
fn apply_cos_send_result_counts_nonexact_bytes_when_exact_queue_backlogged() {
    let root = test_mixed_class_root_with_primed_queues();
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
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    apply_cos_send_result(
        &mut binding,
        42,
        1,
        CoSServicePhase::Surplus,
        1500,
        1500,
        std::collections::VecDeque::new(),
    );

    let root = binding.cos.cos_interfaces.get(&42).expect("cos root");
    let nonexact = &root.queues[1];
    assert!(!nonexact.config.exact);
    assert_eq!(
        nonexact
            .telemetry
            .owner_profile
            .drain_surplus_sent_bytes
            .load(Ordering::Relaxed),
        1500
    );
    assert_eq!(
        nonexact
            .telemetry
            .owner_profile
            .drain_nonexact_sent_bytes_while_exact_backlogged
            .load(Ordering::Relaxed),
        1500,
        "apply_cos_send_result must derive exact_backlogged from the root, not from caller input"
    );
}

#[test]
fn apply_cos_send_result_counts_nonexact_bytes_when_peer_exact_queue_backlogged() {
    let mut root = test_mixed_class_root_with_primed_queues();
    for queue in &mut root.queues {
        if queue.config.exact {
            queue.hot.items.clear();
            queue.hot.queued_bytes = 0;
            queue.hot.runnable = false;
        }
    }
    let mut fast_interfaces = test_cos_fast_interfaces(
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
        None,
    );
    let shared_exact_backlog = Arc::new(SharedCoSExactBacklog::new(1));
    shared_exact_backlog.publish(1, 12_000);
    fast_interfaces
        .get_mut(&42)
        .expect("test fast path")
        .shared_exact_backlog = Some(shared_exact_backlog);
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    apply_cos_send_result(
        &mut binding,
        42,
        1,
        CoSServicePhase::Surplus,
        1500,
        1500,
        std::collections::VecDeque::new(),
    );

    let root = binding.cos.cos_interfaces.get(&42).expect("cos root");
    assert!(
        !root_has_backlogged_exact_queue(root),
        "fixture must prove the local-root-only predicate would miss this case"
    );
    assert_eq!(
        root.queues[1]
            .telemetry
            .owner_profile
            .drain_nonexact_sent_bytes_while_exact_backlogged
            .load(Ordering::Relaxed),
        1500,
        "non-exact drain must consult interface-global peer exact backlog"
    );
}

#[test]
fn normalize_cos_queue_state_repairs_nonempty_unparked_queue_to_runnable() {
    let mut queue = CoSQueueRuntime {
        config: crate::afxdp::types::CoSQueueConfigState {
            queue_id: 5,
            priority: 5,
            transmit_rate_bytes: 11_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            flow_fair: false,
            shared_exact: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        },
        hot: crate::afxdp::types::CoSQueueHotState {
            surplus_deficit: 0,
            tokens: 0,
            last_refill_ns: 0,
            queued_bytes: 1500,
            runnable: false,
            parked: false,
            next_wakeup_tick: 0,
            wheel_level: 0,
            wheel_slot: 0,
            items: VecDeque::from([test_cos_item(1500)]),
            local_item_count: 0,
        },
        flow_fair_state: None,
        v_min: crate::afxdp::types::VMinQueueState {
            vtime_floor: None,
            worker_id: 0,
            consecutive_v_min_skips: 0,
            v_min_suspended_remaining: 0,
            v_min_hard_cap_overrides_scratch: 0,
            v_min_throttles_scratch: 0,
        },
        telemetry: crate::afxdp::types::CoSQueueTelemetry {
            drop_counters: CoSQueueDropCounters::default(),
            owner_profile: CoSQueueOwnerProfile::new(),
        },
        queue_lease_v8: None,
    };

    normalize_cos_queue_state(&mut queue);

    assert!(queue.hot.runnable);
    assert!(!queue.hot.parked);
    assert_eq!(queue.hot.next_wakeup_tick, 0);
}

#[test]
fn count_park_reason_helper_advances_exact_counter() {
    // Low-level test of the helper itself — paranoia pin against a
    // refactor that accidentally writes to the wrong field.
    let mut root = test_cos_runtime_with_exact(true);
    let before = snapshot_counters(&root.queues[0]);

    count_park_reason(&mut root, 0, ParkReason::RootTokenStarvation);
    let mid = snapshot_counters(&root.queues[0]);
    assert_eq!(
        mid.root_token_starvation_parks,
        before.root_token_starvation_parks + 1
    );
    assert_eq!(
        mid.queue_token_starvation_parks,
        before.queue_token_starvation_parks
    );

    count_park_reason(&mut root, 0, ParkReason::QueueTokenStarvation);
    let after = snapshot_counters(&root.queues[0]);
    assert_eq!(
        after.queue_token_starvation_parks,
        before.queue_token_starvation_parks + 1
    );
    assert_eq!(
        after.root_token_starvation_parks,
        mid.root_token_starvation_parks
    );

    // Out-of-range queue_idx is a no-op, not a panic.
    count_park_reason(&mut root, 999, ParkReason::RootTokenStarvation);
    assert_eq!(
        snapshot_counters(&root.queues[0]).root_token_starvation_parks,
        after.root_token_starvation_parks
    );
}

#[test]
fn timer_wheel_wakes_short_parked_queue() {
    let mut root = test_cos_interface_runtime(0);
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    park_cos_queue(&mut root, 0, 5);

    assert!(root.queues[0].hot.parked);
    assert!(!root.queues[0].hot.runnable);
    assert_eq!(root.runnable_queues, 0);

    advance_cos_timer_wheel(&mut root, 4 * COS_TIMER_WHEEL_TICK_NS);
    assert!(root.queues[0].hot.parked);
    assert!(!root.queues[0].hot.runnable);

    advance_cos_timer_wheel(&mut root, 5 * COS_TIMER_WHEEL_TICK_NS);
    assert!(!root.queues[0].hot.parked);
    assert!(root.queues[0].hot.runnable);
    assert_eq!(root.runnable_queues, 1);
}

#[test]
fn timer_wheel_cascades_long_parked_queue() {
    let mut root = test_cos_interface_runtime(0);
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let wake_tick = COS_TIMER_WHEEL_L0_SLOTS as u64 + 10;
    park_cos_queue(&mut root, 0, wake_tick);

    assert_eq!(root.queues[0].hot.wheel_level, 1);
    assert!(root.queues[0].hot.parked);

    advance_cos_timer_wheel(&mut root, (wake_tick - 1) * COS_TIMER_WHEEL_TICK_NS);
    assert!(root.queues[0].hot.parked);
    assert!(!root.queues[0].hot.runnable);

    advance_cos_timer_wheel(&mut root, wake_tick * COS_TIMER_WHEEL_TICK_NS);
    assert!(!root.queues[0].hot.parked);
    assert!(root.queues[0].hot.runnable);
    assert_eq!(root.runnable_queues, 1);
}

#[test]
fn root_serviceability_tracks_parked_queue_wakeup_tick() {
    let mut root = test_cos_interface_runtime(0);
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    assert!(cos_root_can_service_after_prime(&root, 1));

    park_cos_queue(&mut root, 0, 10);
    assert_eq!(root.runnable_queues, 0);
    assert!(!cos_root_can_service_after_prime(
        &root,
        9 * COS_TIMER_WHEEL_TICK_NS
    ));
    assert!(cos_root_can_service_after_prime(
        &root,
        10 * COS_TIMER_WHEEL_TICK_NS
    ));
}

#[test]
fn park_counter_root_token_starvation_ticks_only_its_reason() {
    let mut root = test_cos_runtime_with_exact(true);
    root.tokens = 0;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.runnable = true;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let before = snapshot_counters(&root.queues[0]);
    // Drive a selector that will park on root-token starvation.
    assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
    let after = snapshot_counters(&root.queues[0]);

    assert_eq!(
        after.root_token_starvation_parks,
        before.root_token_starvation_parks + 1,
        "root-token park counter must advance by 1"
    );
    assert_eq!(
        after.queue_token_starvation_parks,
        before.queue_token_starvation_parks
    );
    assert_eq!(
        after.admission_flow_share_drops,
        before.admission_flow_share_drops
    );
    assert_eq!(after.admission_buffer_drops, before.admission_buffer_drops);
    assert_eq!(
        after.tx_ring_full_submit_stalls,
        before.tx_ring_full_submit_stalls
    );
}

#[test]
fn park_counter_queue_token_starvation_ticks_only_its_reason_on_exact() {
    let mut root = test_cos_runtime_with_exact(true);
    // Root has headroom; per-queue tokens do not. Forces the
    // queue-token park branch on the exact selector.
    root.tokens = 1_000_000;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.last_refill_ns = 1; // skip the first-refill init path
    root.queues[0].hot.runnable = true;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let before = snapshot_counters(&root.queues[0]);
    let selection = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
    assert!(
        selection.is_none(),
        "exact selector must park, not return a queue"
    );
    let after = snapshot_counters(&root.queues[0]);

    assert_eq!(
        after.queue_token_starvation_parks,
        before.queue_token_starvation_parks + 1,
        "queue-token park counter must advance by 1"
    );
    assert_eq!(
        after.root_token_starvation_parks,
        before.root_token_starvation_parks
    );
    assert_eq!(
        after.admission_flow_share_drops,
        before.admission_flow_share_drops
    );
    assert_eq!(after.admission_buffer_drops, before.admission_buffer_drops);
    assert_eq!(
        after.tx_ring_full_submit_stalls,
        before.tx_ring_full_submit_stalls
    );
}
