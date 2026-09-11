//! queue_service selector tests: guarantee/surplus phase selection,
//! exact/non-exact RR cursors, priority + weighted sharing, promotion pairing.

use super::*;

#[test]
fn surplus_phase_selects_non_exact_queue_without_guarantee_tokens() {
    let mut root = test_cos_runtime_with_exact(false);
    root.tokens = 1500;
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
    let batch = select_cos_surplus_batch(&mut root, 1);

    assert!(matches!(
        batch,
        Some(CoSBatch::Local {
            phase: CoSServicePhase::Surplus,
            ..
        })
    ));
}

#[test]
fn nonexact_guarantee_skips_residual_only_scheduler_map_queue() {
    let mut root = test_cos_runtime_with_queues(
        1_000_000,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000,
            guarantee_enabled: false,
            exact: false,
            surplus_sharing: false,
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
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    assert!(
        select_nonexact_cos_guarantee_batch(&mut root, &[], 1).is_none(),
        "residual-only queue must not consume non-exact guarantee service"
    );
    assert!(matches!(
        select_cos_surplus_batch(&mut root, 1),
        Some(CoSBatch::Local {
            phase: CoSServicePhase::Surplus,
            ..
        })
    ));
}

// #hb166 T-6(b): the exact-demand mask that reserves best-effort surplus
// must count only SERVICEABLE exact guarantee queues (can ship their head
// right now), not merely non-empty ones. A v8-starved / token-parked exact
// class that ships zero bytes must release its reserved rate to best-effort.
//
// FAIL-ON-REVERT: restoring the `!cos_queue_is_empty` predicate re-includes
// the starved queue, flipping the `!mask.counts(1)` assertion.
#[test]
fn exact_demand_mask_excludes_starved_exact_queue() {
    let queue = |queue_id: u8, fc: &str| CoSQueueConfig {
        queue_id,
        forwarding_class: fc.into(),
        priority: 5,
        transmit_rate_bytes: 1_000_000_000,
        guarantee_enabled: true,
        exact: true,
        surplus_sharing: false,
        equal_flow_enforcement: false,
        equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
        surplus_weight: 1,
        buffer_bytes: COS_MIN_BURST_BYTES,
        dscp_rewrite: None,
        codel_target_ns: 0,
    };
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![queue(0, "iperf-a"), queue(1, "iperf-b")],
    );
    root.tokens = 100_000;
    // Queue 0: serviceable — runnable, tokens cover the head, non-empty.
    root.queues[0].hot.runnable = true;
    root.queues[0].hot.tokens = 10_000;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    // Queue 1: v8-starved — runnable + non-empty, but NO per-queue tokens,
    // so it cannot ship a byte this round.
    root.queues[1].hot.runnable = true;
    root.queues[1].hot.tokens = 0;
    root.queues[1].hot.items.push_back(test_cos_item(1500));
    root.queues[1].hot.queued_bytes = 1500;

    let mask = serviceable_exact_demand_mask(&root);
    assert!(mask.counts(0), "serviceable exact queue counts as demand");
    assert!(
        !mask.counts(1),
        "a token-starved (ships-zero) exact queue must NOT reserve BE surplus",
    );
}

fn residual_and_exact_test_root(exact_surplus_sharing: bool) -> CoSInterfaceRuntime {
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![
            CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 25_000_000_000 / 8,
                guarantee_enabled: false,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
            CoSQueueConfig {
                queue_id: 10,
                forwarding_class: "iperf-24g".into(),
                priority: 5,
                transmit_rate_bytes: 24_000_000_000 / 8,
                guarantee_enabled: true,
                exact: true,
                surplus_sharing: exact_surplus_sharing,
                equal_flow_enforcement: false,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 16,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
        ],
    );
    root.tokens = 64 * 1024;
    for queue in &mut root.queues {
        queue.hot.runnable = true;
        queue.hot.items.push_back(test_cos_item(1500));
        queue.hot.queued_bytes = 1500;
    }
    root.queues[0].hot.tokens = 0;
    root.queues[1].hot.tokens = 0;
    root.nonempty_queues = 2;
    root.runnable_queues = 2;
    root
}

fn residual_and_exact_fast_interfaces(
    shared_exact_backlog: Option<Arc<SharedCoSExactBacklog>>,
) -> FastMap<i32, WorkerCoSInterfaceFastPath> {
    let mut fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![
            (0, test_queue_fast_path(false, 0, None, None)),
            (10, test_queue_fast_path(false, 0, None, None)),
        ],
        None,
        None,
    );
    if let Some(shared_exact_backlog) = shared_exact_backlog {
        fast_interfaces
            .get_mut(&42)
            .expect("test fast path")
            .shared_exact_backlog = Some(shared_exact_backlog);
    }
    fast_interfaces
}

#[test]
fn build_nonexact_suppresses_residual_surplus_when_local_exact_backlogged() {
    let mut root = residual_and_exact_test_root(false);
    root.queues[1].config.transmit_rate_bytes = root.shaping_rate_bytes;
    root.queues[1].hot.tokens = 1500;
    let fast_interfaces = residual_and_exact_fast_interfaces(None);
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    assert!(
        build_nonexact_cos_batch(&mut binding, 42, 1).is_none(),
        "best-effort residual surplus must not drain when exact demand consumes the root shape"
    );
}

#[test]
fn build_nonexact_keeps_nonexact_guarantee_when_exact_backlogged() {
    let mut root = residual_and_exact_test_root(false);
    root.queues[0].config.guarantee_enabled = true;
    root.queues[0].hot.tokens = 1500;
    root.queues[1].hot.tokens = 1500;
    let fast_interfaces = residual_and_exact_fast_interfaces(None);
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    let batch = build_nonexact_cos_batch(&mut binding, 42, 1)
        .expect("non-exact explicit transmit-rate guarantee must still drain");
    assert!(matches!(
        batch,
        CoSBatch::Local {
            queue_idx: 0,
            phase: CoSServicePhase::Guarantee,
            ..
        }
    ));
}

#[test]
fn build_nonexact_allows_residual_surplus_when_local_exact_is_token_starved() {
    let root = residual_and_exact_test_root(false);
    let fast_interfaces = residual_and_exact_fast_interfaces(None);
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    let batch = build_nonexact_cos_batch(&mut binding, 42, 1)
        .expect("token-starved exact queue must not idle root while residual work is runnable");
    assert!(matches!(
        batch,
        CoSBatch::Local {
            queue_idx: 0,
            phase: CoSServicePhase::Surplus,
            ..
        }
    ));
}

#[test]
fn build_nonexact_suppresses_residual_surplus_when_peer_exact_backlogged() {
    let mut root = residual_and_exact_test_root(false);
    root.queues[1].hot.items.clear();
    root.queues[1].hot.queued_bytes = 0;
    root.queues[1].hot.runnable = false;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let shared_exact_backlog = Arc::new(SharedCoSExactBacklog::new(1));
    shared_exact_backlog.publish(1, 1500);
    let fast_interfaces = residual_and_exact_fast_interfaces(Some(shared_exact_backlog));
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    assert!(
        build_nonexact_cos_batch(&mut binding, 42, 1).is_none(),
        "best-effort residual surplus must not drain while a peer binding reports exact backlog"
    );
}

#[test]
fn build_nonexact_allows_residual_surplus_when_peer_exact_budget_refills() {
    let mut root = residual_and_exact_test_root(false);
    root.queues[1].hot.items.clear();
    root.queues[1].hot.queued_bytes = 0;
    root.queues[1].hot.runnable = false;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let shared_exact_backlog = Arc::new(SharedCoSExactBacklog::new(1));
    shared_exact_backlog.publish_with_serviceable(
        1,
        1500,
        0,
        ExactDemandQueueMask::EMPTY.with_queue(1),
    );
    let fast_interfaces = residual_and_exact_fast_interfaces(Some(shared_exact_backlog));
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    assert!(
        build_nonexact_cos_batch(&mut binding, 42, 1).is_none(),
        "shared residual budget starts closed when peer exact demand appears"
    );
    let batch = build_nonexact_cos_batch(&mut binding, 42, 2_000_000)
        .expect("peer exact demand should allow only refilled residual surplus");
    assert!(matches!(
        batch,
        CoSBatch::Local {
            queue_idx: 0,
            phase: CoSServicePhase::Surplus,
            ..
        }
    ));
}

#[test]
fn build_nonexact_counts_shared_exact_queue_once_across_bindings() {
    let root = residual_and_exact_test_root(false);
    let shared_exact_backlog = Arc::new(SharedCoSExactBacklog::new(1));
    shared_exact_backlog.publish_with_serviceable(
        1,
        1500,
        0,
        ExactDemandQueueMask::EMPTY.with_queue(1),
    );
    let fast_interfaces = residual_and_exact_fast_interfaces(Some(shared_exact_backlog));
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    assert!(
        build_nonexact_cos_batch(&mut binding, 42, 1).is_none(),
        "shared residual budget starts closed when aggregate exact demand appears"
    );
    let batch = build_nonexact_cos_batch(&mut binding, 42, 2_000_000)
        .expect("local and peer backlog on the same exact queue reserve that queue's rate once");
    assert!(matches!(
        batch,
        CoSBatch::Local {
            queue_idx: 0,
            phase: CoSServicePhase::Surplus,
            ..
        }
    ));
}

#[test]
fn build_nonexact_still_allows_exact_surplus_sharing_when_exact_backlogged() {
    let mut root = residual_and_exact_test_root(true);
    root.queues[1].config.transmit_rate_bytes = root.shaping_rate_bytes;
    root.queues[1].hot.tokens = 1500;
    let fast_interfaces = residual_and_exact_fast_interfaces(None);
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    let batch = build_nonexact_cos_batch(&mut binding, 42, 1)
        .expect("surplus-sharing exact queue should remain surplus eligible");
    assert!(matches!(
        batch,
        CoSBatch::Local {
            queue_idx: 1,
            phase: CoSServicePhase::Surplus,
            ..
        }
    ));
}

#[test]
fn nonexact_guarantee_selects_explicit_transmit_rate_queue() {
    let mut root = test_cos_runtime_with_queues(
        1_000_000,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
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
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    assert!(matches!(
        select_nonexact_cos_guarantee_batch(&mut root, &[], 1),
        Some(CoSBatch::Local {
            phase: CoSServicePhase::Guarantee,
            ..
        })
    ));
}

#[test]
fn fallback_root_shaped_default_queue_has_guarantee_service() {
    let mut root = test_cos_runtime_with_queues(
        1_000_000,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
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
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    assert!(matches!(
        select_nonexact_cos_guarantee_batch(&mut root, &[], 1),
        Some(CoSBatch::Local {
            phase: CoSServicePhase::Guarantee,
            ..
        })
    ));
}

#[test]
fn surplus_phase_skips_exact_queue_without_guarantee_tokens() {
    let mut root = test_cos_runtime_with_exact(true);
    root.tokens = 1500;
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
    assert!(select_cos_surplus_batch(&mut root, 1).is_none());
}

// #915: surplus_sharing=true on an exact queue with empty
// queue.hot.tokens — surplus selector picks it up because the
// `queue.config.exact && !surplus_sharing` skip evaluates to false.
#[test]
fn surplus_phase_includes_exact_with_surplus_sharing() {
    let mut root = test_cos_runtime_with_exact(true);
    root.queues[0].config.surplus_sharing = true;
    root.tokens = 1500;
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let batch = select_cos_surplus_batch(&mut root, 1);
    assert!(matches!(
        batch,
        Some(CoSBatch::Local {
            phase: CoSServicePhase::Surplus,
            ..
        })
    ));
}

// #915 §4.5 isolation test: an exact queue with surplus_sharing
// must NOT be parked when queue.hot.tokens runs out in the
// exact-guarantee selector. The drain_park_queue_tokens counter
// still increments (diagnostic parity), but `runnable` stays
// true and `parked` stays false so surplus phase can pick the
// queue up on the same drain pass. Failure here catches the
// Codex round-1 MAJOR 1 regression.
#[test]
fn exact_with_surplus_sharing_not_parked_on_queue_token_starvation() {
    let mut root = test_cos_runtime_with_exact(true);
    root.queues[0].config.surplus_sharing = true;
    root.tokens = 1_000_000; // root has plenty of tokens
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.tokens = 0; // queue bucket empty
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.queues[0].hot.parked = false;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let pre_park_count = root.queues[0]
        .telemetry
        .owner_profile
        .drain_park_queue_tokens
        .load(std::sync::atomic::Ordering::Relaxed);

    let selection = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
    // Selector returns None because queue.hot.tokens<head_len AND
    // surplus_sharing skips parking.
    assert!(
        selection.is_none(),
        "exact-guarantee selector must not select a token-starved queue"
    );
    assert!(
        !root.queues[0].hot.parked,
        "surplus_sharing exact queue must NOT be parked"
    );
    assert!(
        root.queues[0].hot.runnable,
        "surplus_sharing exact queue must stay runnable"
    );
    let post_park_count = root.queues[0]
        .telemetry
        .owner_profile
        .drain_park_queue_tokens
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        post_park_count,
        pre_park_count + 1,
        "drain_park_queue_tokens must still increment for diagnostic parity"
    );
}

// #915 Codex round-2 MINOR fix: the root-starvation branch in
// select_exact_cos_guarantee_queue_with_fast_path is also
// no-park'd for surplus_sharing exact queues (the §4.5 fix
// addressed only the queue-token branch in plan v3; round-1
// code review caught that the EARLIER root-token branch had
// the same problem). Pin that branch directly: when both
// root.tokens AND queue.hot.tokens are short, a surplus_sharing
// exact queue still must NOT be parked by the exact-guarantee
// selector. The drain_park_root_tokens diagnostic counter
// still increments. The same-pass surplus selector then
// handles the root-only park with require_queue_tokens=false.
#[test]
fn exact_with_surplus_sharing_not_parked_on_root_token_starvation() {
    let mut root = test_cos_runtime_with_exact(true);
    root.queues[0].config.surplus_sharing = true;
    root.tokens = 0; // root bucket empty (root-token starvation)
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.tokens = 0; // queue bucket also empty
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.queues[0].hot.parked = false;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let pre_root_park = root.queues[0]
        .telemetry
        .owner_profile
        .drain_park_root_tokens
        .load(std::sync::atomic::Ordering::Relaxed);
    let pre_queue_park = root.queues[0]
        .telemetry
        .owner_profile
        .drain_park_queue_tokens
        .load(std::sync::atomic::Ordering::Relaxed);

    let selection = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
    // Selector returns None because root.tokens<head_len; the
    // root-starvation no-park branch fires first, so the queue
    // is not parked.
    assert!(
        selection.is_none(),
        "exact-guarantee selector must not select a root-starved queue"
    );
    assert!(
        !root.queues[0].hot.parked,
        "surplus_sharing exact queue must NOT be parked on root-token starvation"
    );
    assert!(
        root.queues[0].hot.runnable,
        "surplus_sharing exact queue must stay runnable"
    );
    let post_root_park = root.queues[0]
        .telemetry
        .owner_profile
        .drain_park_root_tokens
        .load(std::sync::atomic::Ordering::Relaxed);
    let post_queue_park = root.queues[0]
        .telemetry
        .owner_profile
        .drain_park_queue_tokens
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        post_root_park,
        pre_root_park + 1,
        "drain_park_root_tokens must still increment for diagnostic parity"
    );
    assert_eq!(
        post_queue_park, pre_queue_park,
        "queue-token branch must NOT fire (we exited via root-token branch)"
    );

    // The same-pass surplus selector is the eventual park site
    // for root-token starvation: it uses require_queue_tokens=false
    // so the wake_tick is bound only by root refill. Verify it
    // parks the queue rather than leaving it spinning.
    let surplus = select_cos_surplus_batch(&mut root, 1);
    assert!(
        surplus.is_none(),
        "surplus selector returns None when root.tokens<head_len"
    );
    assert!(
        root.queues[0].hot.parked,
        "surplus selector must park the queue on root-token starvation"
    );
}

// #915 §4.5 contrast: a non-surplus-sharing exact queue still
// parks on queue-token starvation (preserves today's behavior).
#[test]
fn exact_without_surplus_sharing_parks_on_queue_token_starvation() {
    let mut root = test_cos_runtime_with_exact(true);
    // surplus_sharing left as false (default)
    root.tokens = 1_000_000;
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let _ = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
    assert!(
        root.queues[0].hot.parked,
        "non-surplus-sharing exact queue must be parked on queue-token starvation"
    );
}

// #915 production-order end-to-end smoke (Codex round-2 MINOR 4).
// The cleanest in-process production-order check is to call the
// exact-guarantee selector first and then the surplus selector
// — exactly what `drain_shaped_tx → service_exact_guarantee_*
// → build_nonexact_cos_batch → select_cos_surplus_batch` does in
// the real path. A surplus-sharing exact queue with empty
// queue.hot.tokens must NOT be picked by the exact-guarantee
// selector AND MUST be picked by the surplus selector on the
// same drain attempt.
#[test]
fn surplus_sharing_exact_reaches_surplus_through_full_drain_pass() {
    let mut root = test_cos_runtime_with_exact(true);
    root.queues[0].config.surplus_sharing = true;
    root.tokens = 1500;
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    // First: production-order exact-guarantee selector. Returns
    // None because queue.hot.tokens<head_len AND no parking (§4.5).
    let exact_pick = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
    assert!(
        exact_pick.is_none(),
        "exact-guarantee selector must decline token-starved surplus_sharing queue"
    );

    // Then: surplus selector picks the queue up on the same pass.
    let surplus_pick = select_cos_surplus_batch(&mut root, 1);
    assert!(
        matches!(
            surplus_pick,
            Some(CoSBatch::Local {
                phase: CoSServicePhase::Surplus,
                ..
            })
        ),
        "surplus selector must pick up surplus_sharing exact queue \
         after exact-guarantee declines"
    );
}

#[test]
fn guarantee_phase_parks_non_exact_queue_on_root_only_wakeup() {
    let mut root = test_cos_runtime_with_exact(false);
    root.tokens = 0;
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
    assert!(root.queues[0].hot.parked);
    assert_eq!(root.queues[0].hot.next_wakeup_tick, 30);
}

/// #1630 (P2): a low-rate queue with banked tokens drains its queued
/// frames whole in one visit, bounded by the per-visit FRAME-count cap
/// (`cos_guarantee_visit_cap_bytes` = TX_BATCH_SIZE × frame), NOT the
/// rate-scaled quantum. Before #1630 the 1 Mbps quantum (clamped to
/// 1500 B) limited the visit to a single frame and discarded the
/// sub-frame remainder, pinning the class near 60 % of its rate. Now
/// the rate is metered by `queue.hot.tokens` (refilled at the configured
/// rate) and the actual-byte debit, so a queue that has accumulated
/// tokens for several frames sends them in one pass.
#[test]
fn guarantee_phase_visit_cap_drains_banked_frames() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.tokens = 64 * 1024;
    // Bank enough tokens for all four queued frames.
    root.queues[0].hot.tokens = 64 * 1024;
    root.queues[0].hot.runnable = true;
    for _ in 0..4 {
        root.queues[0].hot.items.push_back(test_cos_item(1500));
    }
    root.queues[0].hot.queued_bytes = 4 * 1500;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let batch = select_cos_guarantee_batch(&mut root, 1).expect("guarantee batch");
    match batch {
        CoSBatch::Local { items, .. } => assert_eq!(items.len(), 4),
        CoSBatch::Prepared { .. } => panic!("expected local batch"),
    }
    assert_eq!(root.queues[0].hot.items.len(), 0);
}

#[test]
fn guarantee_phase_allows_larger_high_rate_visit_quantum() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000u64 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000u64 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 256 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.tokens = 256 * 1024;
    root.queues[0].hot.tokens = 256 * 1024;
    root.queues[0].hot.runnable = true;
    for _ in 0..200 {
        root.queues[0].hot.items.push_back(test_cos_item(1500));
    }
    root.queues[0].hot.queued_bytes = 200 * 1500;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    // #920: TX_BATCH_SIZE lowered 256 → 64 caps a single visit at
    // 64 items even when token budget would permit more (~166).
    // The remaining tokens stay with the queue for the next visit;
    // throughput is preserved across multiple shorter visits, with
    // the trade-off that mouse packets get an interleave point
    // every 64 packets instead of every 256.
    let batch = select_cos_guarantee_batch(&mut root, 1).expect("guarantee batch");
    match batch {
        CoSBatch::Local { items, .. } => assert_eq!(items.len(), TX_BATCH_SIZE),
        CoSBatch::Prepared { .. } => panic!("expected local batch"),
    }
    assert_eq!(root.queues[0].hot.items.len(), 200 - TX_BATCH_SIZE);
}

/// #920: separate from the batch-cap test above. Asserts the
/// rate-quantum invariant guarded by the original test name —
/// a 10 Gbps queue gets a strictly larger byte-budget visit
/// quantum than a 100 Mbps queue, regardless of TX_BATCH_SIZE.
/// Guards against silent regression if `cos_guarantee_quantum_bytes`
/// stops scaling with `transmit_rate_bytes`.
#[test]
fn guarantee_phase_quantum_scales_with_rate() {
    // cos_guarantee_quantum_bytes reached via super in cos/queue_service.
    let high_rate = test_cos_runtime_with_queues(
        10_000_000_000u64 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000u64 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 256 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let low_rate = test_cos_runtime_with_queues(
        100_000_000u64 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-low".into(),
            priority: 5,
            transmit_rate_bytes: 100_000_000u64 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 256 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let high_q = cos_guarantee_quantum_bytes(&high_rate.queues[0]);
    let low_q = cos_guarantee_quantum_bytes(&low_rate.queues[0]);
    assert!(
        high_q > low_q,
        "high-rate quantum ({high_q}) must exceed low-rate quantum ({low_q})"
    );
}

#[test]
fn guarantee_phase_rotates_between_backlogged_queues() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000,
        vec![
            CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
            CoSQueueConfig {
                queue_id: 1,
                forwarding_class: "af11".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
        ],
    );
    root.tokens = 64 * 1024;
    for queue in &mut root.queues {
        queue.hot.tokens = 64 * 1024;
        queue.hot.runnable = true;
        queue.hot.items.push_back(test_cos_item(1500));
        queue.hot.items.push_back(test_cos_item(1500));
        queue.hot.queued_bytes = 2 * 1500;
    }
    root.nonempty_queues = 2;
    root.runnable_queues = 2;

    let first = select_cos_guarantee_batch(&mut root, 1).expect("first guarantee batch");
    let second = select_cos_guarantee_batch(&mut root, 1).expect("second guarantee batch");

    match first {
        CoSBatch::Local { queue_idx, .. } => assert_eq!(queue_idx, 0),
        CoSBatch::Prepared { .. } => panic!("expected local batch"),
    }
    match second {
        CoSBatch::Local { queue_idx, .. } => assert_eq!(queue_idx, 1),
        CoSBatch::Prepared { .. } => panic!("expected local batch"),
    }
}

#[test]
fn exact_and_nonexact_guarantee_rr_cursors_advance_independently() {
    // #689 regression. Prior to the cursor split, serving an exact
    // queue advanced the shared `guarantee_rr` and could cause the
    // non-exact pass to skip a waiting queue on its next run. Pin
    // that the exact pass does not touch `nonexact_guarantee_rr`
    // and vice versa.
    let mut root = test_mixed_class_root_with_primed_queues();
    assert_eq!(root.exact_guarantee_rr, 0);
    assert_eq!(root.nonexact_guarantee_rr, 0);

    // Serving an exact queue must not disturb the non-exact cursor.
    let selection = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1)
        .expect("exact queue selection");
    assert_eq!(selection.queue_idx, 0);
    assert_eq!(
        root.exact_guarantee_rr, 1,
        "exact cursor must advance past the served queue"
    );
    assert_eq!(
        root.nonexact_guarantee_rr, 0,
        "serving an exact queue must not advance the non-exact cursor"
    );

    // Serving a non-exact queue must not disturb the exact cursor.
    let batch = select_nonexact_cos_guarantee_batch(&mut root, &[], 1).expect("nonexact queue batch");
    match batch {
        CoSBatch::Local { queue_idx, .. } => assert_eq!(queue_idx, 1),
        CoSBatch::Prepared { .. } => panic!("expected local batch"),
    }
    assert_eq!(
        root.exact_guarantee_rr, 1,
        "non-exact service must not advance the exact cursor"
    );
    assert_eq!(
        root.nonexact_guarantee_rr, 2,
        "non-exact cursor must advance past the served queue"
    );
}

#[test]
fn exact_guarantee_rr_walks_exact_queues_in_order_independent_of_nonexact() {
    // Exact queues must rotate exact-0 -> exact-2 -> exact-0 -> exact-2
    // regardless of non-exact activity between calls. #689 before-fix
    // behavior under the shared cursor was: exact-0 served (rr=1),
    // then a non-exact service would bump rr past exact-2's position,
    // so the next exact call would skip exact-2 and loop back to
    // exact-0. This test pins that the split cursor rotates exact
    // queues deterministically without regard for non-exact service.
    // Helper primes eight 1500-byte items and sets `queued_bytes`
    // to match; no additional priming needed here. Only bump
    // queue.hot.tokens on the exact queues to make sure they never hit
    // token-starvation during the four interleaved rounds below —
    // the exact selector does not refill exact-queue tokens itself
    // (that is done by the shared-lease path), so this test bypasses
    // that machinery by handing the queues a large local budget.
    let mut root = test_mixed_class_root_with_primed_queues();
    for queue in &mut root.queues {
        if queue.config.exact {
            queue.hot.tokens = 128 * 1024;
        }
    }

    let mut exact_order = Vec::new();
    for _ in 0..4 {
        // Interleave a non-exact service between exact calls; the exact
        // rotation must not notice.
        let selection = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1)
            .expect("exact queue");
        exact_order.push(selection.queue_idx);
        // Service a non-exact queue to simulate concurrent class activity;
        // ignore the result.
        let _ = select_nonexact_cos_guarantee_batch(&mut root, &[], 1);
    }
    assert_eq!(exact_order, vec![0, 2, 0, 2]);
}

#[test]
fn nonexact_guarantee_rr_walks_nonexact_queues_in_order_independent_of_exact() {
    // Symmetric to the exact test: non-exact rotation is 1 -> 3 -> 1 -> 3
    // regardless of exact-queue activity between calls. Helper primes
    // eight 1500-byte items per queue with `queued_bytes` already
    // consistent; no additional priming needed.
    let mut root = test_mixed_class_root_with_primed_queues();

    let mut nonexact_order = Vec::new();
    for _ in 0..4 {
        let batch = select_nonexact_cos_guarantee_batch(&mut root, &[], 1).expect("nonexact batch");
        let queue_idx = match batch {
            CoSBatch::Local { queue_idx, .. } => queue_idx,
            CoSBatch::Prepared { queue_idx, .. } => queue_idx,
        };
        nonexact_order.push(queue_idx);
        // Interleave an exact service; must not disturb non-exact rotation.
        let _ = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
    }
    assert_eq!(nonexact_order, vec![1, 3, 1, 3]);
}

#[test]
fn legacy_guarantee_rr_does_not_advance_class_cursors() {
    // The entire reason `legacy_guarantee_rr` exists as a third cursor
    // (instead of the legacy unified selector reusing one of the
    // production cursors) is to keep the legacy walk isolated from the
    // production exact/nonexact rotation state. Pin that contract:
    // a call through the legacy selector must advance only its own
    // cursor, never the two production cursors.
    let mut root = test_mixed_class_root_with_primed_queues();
    let batch = select_cos_guarantee_batch(&mut root, 1).expect("legacy guarantee batch");
    // Served something, so `legacy_guarantee_rr` advanced.
    match batch {
        CoSBatch::Local { queue_idx, .. } => {
            assert_eq!(queue_idx, 0, "legacy walk starts at index 0");
        }
        CoSBatch::Prepared { .. } => panic!("expected local batch"),
    }
    assert_eq!(root.legacy_guarantee_rr, 1);
    // Production cursors untouched — this is the isolation guarantee
    // that justifies the extra field over reusing either production
    // cursor for the legacy walk.
    assert_eq!(
        root.exact_guarantee_rr, 0,
        "legacy selector must not advance exact production cursor"
    );
    assert_eq!(
        root.nonexact_guarantee_rr, 0,
        "legacy selector must not advance nonexact production cursor"
    );
}

#[test]
fn guarantee_rr_cursors_start_at_zero_after_runtime_build() {
    // Pin the invariant that a fresh runtime starts with both cursors
    // at 0. `build_cos_interface_runtime` is the one production init
    // site; any refactor that accidentally leaves a cursor uninitialized
    // or drops one of the fields fails here.
    let root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "q0".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000_000 / 8,
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
    assert_eq!(root.exact_guarantee_rr, 0);
    assert_eq!(root.nonexact_guarantee_rr, 0);
    assert_eq!(root.legacy_guarantee_rr, 0);
}

#[test]
fn surplus_phase_prefers_higher_priority_queue() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000,
        vec![
            CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "bulk".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
            CoSQueueConfig {
                queue_id: 1,
                forwarding_class: "voice".into(),
                priority: 0,
                transmit_rate_bytes: 1_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
        ],
    );
    root.tokens = 64 * 1024;
    for queue in &mut root.queues {
        queue.hot.last_refill_ns = 1;
        queue.hot.tokens = 0;
        queue.hot.runnable = true;
        queue.hot.items.push_back(test_cos_item(1500));
        queue.hot.queued_bytes = 1500;
    }
    root.nonempty_queues = 2;
    root.runnable_queues = 2;

    assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
    let batch = select_cos_surplus_batch(&mut root, 1).expect("surplus batch");
    match batch {
        CoSBatch::Local { queue_idx, .. } => assert_eq!(queue_idx, 1),
        CoSBatch::Prepared { .. } => panic!("expected local batch"),
    }
}

#[test]
fn surplus_phase_applies_weighted_same_priority_sharing() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000,
        vec![
            CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "small".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
            CoSQueueConfig {
                queue_id: 1,
                forwarding_class: "large".into(),
                priority: 5,
                transmit_rate_bytes: 4_000_000,
                guarantee_enabled: true,
                exact: false,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 4,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
        ],
    );
    root.tokens = 64 * 1024;
    for queue in &mut root.queues {
        queue.hot.last_refill_ns = 1;
        queue.hot.tokens = 0;
        queue.hot.runnable = true;
        for _ in 0..8 {
            queue.hot.items.push_back(test_cos_item(1500));
        }
        queue.hot.queued_bytes = 8 * 1500;
    }
    root.nonempty_queues = 2;
    root.runnable_queues = 2;

    let first = select_cos_surplus_batch(&mut root, 1).expect("first surplus batch");
    let second = select_cos_surplus_batch(&mut root, 1).expect("second surplus batch");

    match first {
        CoSBatch::Local {
            queue_idx, items, ..
        } => {
            assert_eq!(queue_idx, 0);
            assert_eq!(items.len(), 1);
        }
        CoSBatch::Prepared { .. } => panic!("expected local batch"),
    }
    match second {
        CoSBatch::Local {
            queue_idx, items, ..
        } => {
            assert_eq!(queue_idx, 1);
            assert_eq!(items.len(), 4);
        }
        CoSBatch::Prepared { .. } => panic!("expected local batch"),
    }
}

/// Pin that `apply_cos_queue_flow_fair_promotion` propagates the
/// per-queue `shared_exact` bits correctly when the interface
/// has a mix of shared_exact and owner-local-exact queues — the
/// common production shape (a low-rate iperf-a queue next to a
/// high-rate iperf-c queue on the same interface). Breaking the
/// zip alignment between `runtime.queues` and
/// `iface_fast.queue_fast_path` at the
/// `ensure_cos_interface_runtime` call site would swap the two
/// queues' `shared_exact` shadows and their `flow_fair` bits,
/// silently routing both to the wrong admission branch and
/// turning off SFQ on the iperf-a queue (re-breaking #784).
#[test]
fn apply_promotion_pairs_queues_with_their_fast_path_entries() {
    let mut runtime = test_cos_runtime_with_queues(
        100_000_000_000 / 8,
        vec![
            CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000_000 / 8,
                guarantee_enabled: true,
                exact: true,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
            CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 25_000_000_000 / 8,
                guarantee_enabled: true,
                exact: true,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            codel_target_ns: 0,
            },
        ],
    );

    // Position 0 -> owner-local-exact; position 1 -> shared_exact.
    let fast_path = vec![
        test_queue_fast_path_for_promotion(false),
        test_queue_fast_path_for_promotion(true),
    ];
    apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path, 0);

    assert!(
        runtime.queues[0].flow_fair(),
        "queue at position 0 (iperf-a, shared_exact=false) must \
         be on the flow-fair path — #784 fairness fix depends on it",
    );
    assert!(
        !runtime.queues[0].shared_exact(),
        "queue at position 0 must get position-0's shared_exact=false",
    );
    assert!(
        runtime.queues[1].flow_fair(),
        "#785 Phase 3: queue at position 1 (iperf-c, \
         shared_exact=true) must also be on the flow-fair path \
         so MQFQ VFT ordering enforces per-flow fairness. The \
         admission gates (cos_queue_flow_share_limit, \
         apply_cos_admission_ecn_policy) separately downgrade to \
         aggregate-only on shared_exact queues.",
    );
    assert!(
        runtime.queues[1].shared_exact(),
        "queue at position 1 must get position-1's shared_exact=true \
         — zip misalignment would silently mis-route admission policy",
    );
}

