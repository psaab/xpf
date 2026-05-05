// Tests for afxdp/cos/queue_service/mod.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep mod.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "tests.rs"]` from mod.rs.

use super::*;
use crate::afxdp::cos::admission::apply_cos_queue_flow_fair_promotion;
use crate::afxdp::tx::test_support::*;
use crate::afxdp::PROTO_TCP;

#[test]
fn surplus_phase_selects_non_exact_queue_without_guarantee_tokens() {
    let mut root = test_cos_runtime_with_exact(false);
    root.tokens = 1500;
    root.queues[0].last_refill_ns = 1;
    root.queues[0].tokens = 0;
    root.queues[0].items.push_back(test_cos_item(1500));
    root.queues[0].queued_bytes = 1500;
    root.queues[0].runnable = true;
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
fn surplus_phase_skips_exact_queue_without_guarantee_tokens() {
    let mut root = test_cos_runtime_with_exact(true);
    root.tokens = 1500;
    root.queues[0].last_refill_ns = 1;
    root.queues[0].tokens = 0;
    root.queues[0].items.push_back(test_cos_item(1500));
    root.queues[0].queued_bytes = 1500;
    root.queues[0].runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
    assert!(select_cos_surplus_batch(&mut root, 1).is_none());
}

// #915: surplus_sharing=true on an exact queue with empty
// queue.tokens — surplus selector picks it up because the
// `queue.exact && !surplus_sharing` skip evaluates to false.
#[test]
fn surplus_phase_includes_exact_with_surplus_sharing() {
    let mut root = test_cos_runtime_with_exact(true);
    root.queues[0].surplus_sharing = true;
    root.tokens = 1500;
    root.queues[0].last_refill_ns = 1;
    root.queues[0].tokens = 0;
    root.queues[0].items.push_back(test_cos_item(1500));
    root.queues[0].queued_bytes = 1500;
    root.queues[0].runnable = true;
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
// must NOT be parked when queue.tokens runs out in the
// exact-guarantee selector. The drain_park_queue_tokens counter
// still increments (diagnostic parity), but `runnable` stays
// true and `parked` stays false so surplus phase can pick the
// queue up on the same drain pass. Failure here catches the
// Codex round-1 MAJOR 1 regression.
#[test]
fn exact_with_surplus_sharing_not_parked_on_queue_token_starvation() {
    let mut root = test_cos_runtime_with_exact(true);
    root.queues[0].surplus_sharing = true;
    root.tokens = 1_000_000; // root has plenty of tokens
    root.queues[0].last_refill_ns = 1;
    root.queues[0].tokens = 0; // queue bucket empty
    root.queues[0].items.push_back(test_cos_item(1500));
    root.queues[0].queued_bytes = 1500;
    root.queues[0].runnable = true;
    root.queues[0].parked = false;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let pre_park_count = root.queues[0]
        .owner_profile
        .drain_park_queue_tokens
        .load(std::sync::atomic::Ordering::Relaxed);

    let selection =
        select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
    // Selector returns None because queue.tokens<head_len AND
    // surplus_sharing skips parking.
    assert!(selection.is_none(),
        "exact-guarantee selector must not select a token-starved queue");
    assert!(!root.queues[0].parked,
        "surplus_sharing exact queue must NOT be parked");
    assert!(root.queues[0].runnable,
        "surplus_sharing exact queue must stay runnable");
    let post_park_count = root.queues[0]
        .owner_profile
        .drain_park_queue_tokens
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(post_park_count, pre_park_count + 1,
        "drain_park_queue_tokens must still increment for diagnostic parity");
}

// #915 Codex round-2 MINOR fix: the root-starvation branch in
// select_exact_cos_guarantee_queue_with_fast_path is also
// no-park'd for surplus_sharing exact queues (the §4.5 fix
// addressed only the queue-token branch in plan v3; round-1
// code review caught that the EARLIER root-token branch had
// the same problem). Pin that branch directly: when both
// root.tokens AND queue.tokens are short, a surplus_sharing
// exact queue still must NOT be parked by the exact-guarantee
// selector. The drain_park_root_tokens diagnostic counter
// still increments. The same-pass surplus selector then
// handles the root-only park with require_queue_tokens=false.
#[test]
fn exact_with_surplus_sharing_not_parked_on_root_token_starvation() {
    let mut root = test_cos_runtime_with_exact(true);
    root.queues[0].surplus_sharing = true;
    root.tokens = 0; // root bucket empty (root-token starvation)
    root.queues[0].last_refill_ns = 1;
    root.queues[0].tokens = 0; // queue bucket also empty
    root.queues[0].items.push_back(test_cos_item(1500));
    root.queues[0].queued_bytes = 1500;
    root.queues[0].runnable = true;
    root.queues[0].parked = false;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let pre_root_park = root.queues[0]
        .owner_profile
        .drain_park_root_tokens
        .load(std::sync::atomic::Ordering::Relaxed);
    let pre_queue_park = root.queues[0]
        .owner_profile
        .drain_park_queue_tokens
        .load(std::sync::atomic::Ordering::Relaxed);

    let selection =
        select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
    // Selector returns None because root.tokens<head_len; the
    // root-starvation no-park branch fires first, so the queue
    // is not parked.
    assert!(selection.is_none(),
        "exact-guarantee selector must not select a root-starved queue");
    assert!(!root.queues[0].parked,
        "surplus_sharing exact queue must NOT be parked on root-token starvation");
    assert!(root.queues[0].runnable,
        "surplus_sharing exact queue must stay runnable");
    let post_root_park = root.queues[0]
        .owner_profile
        .drain_park_root_tokens
        .load(std::sync::atomic::Ordering::Relaxed);
    let post_queue_park = root.queues[0]
        .owner_profile
        .drain_park_queue_tokens
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(post_root_park, pre_root_park + 1,
        "drain_park_root_tokens must still increment for diagnostic parity");
    assert_eq!(post_queue_park, pre_queue_park,
        "queue-token branch must NOT fire (we exited via root-token branch)");

    // The same-pass surplus selector is the eventual park site
    // for root-token starvation: it uses require_queue_tokens=false
    // so the wake_tick is bound only by root refill. Verify it
    // parks the queue rather than leaving it spinning.
    let surplus = select_cos_surplus_batch(&mut root, 1);
    assert!(surplus.is_none(),
        "surplus selector returns None when root.tokens<head_len");
    assert!(root.queues[0].parked,
        "surplus selector must park the queue on root-token starvation");
}

// #915 §4.5 contrast: a non-surplus-sharing exact queue still
// parks on queue-token starvation (preserves today's behavior).
#[test]
fn exact_without_surplus_sharing_parks_on_queue_token_starvation() {
    let mut root = test_cos_runtime_with_exact(true);
    // surplus_sharing left as false (default)
    root.tokens = 1_000_000;
    root.queues[0].last_refill_ns = 1;
    root.queues[0].tokens = 0;
    root.queues[0].items.push_back(test_cos_item(1500));
    root.queues[0].queued_bytes = 1500;
    root.queues[0].runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let _ = select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
    assert!(root.queues[0].parked,
        "non-surplus-sharing exact queue must be parked on queue-token starvation");
}

// #915 production-order end-to-end smoke (Codex round-2 MINOR 4).
// The cleanest in-process production-order check is to call the
// exact-guarantee selector first and then the surplus selector
// — exactly what `drain_shaped_tx → service_exact_guarantee_*
// → build_nonexact_cos_batch → select_cos_surplus_batch` does in
// the real path. A surplus-sharing exact queue with empty
// queue.tokens must NOT be picked by the exact-guarantee
// selector AND MUST be picked by the surplus selector on the
// same drain attempt.
#[test]
fn surplus_sharing_exact_reaches_surplus_through_full_drain_pass() {
    let mut root = test_cos_runtime_with_exact(true);
    root.queues[0].surplus_sharing = true;
    root.tokens = 1500;
    root.queues[0].last_refill_ns = 1;
    root.queues[0].tokens = 0;
    root.queues[0].items.push_back(test_cos_item(1500));
    root.queues[0].queued_bytes = 1500;
    root.queues[0].runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    // First: production-order exact-guarantee selector. Returns
    // None because queue.tokens<head_len AND no parking (§4.5).
    let exact_pick =
        select_exact_cos_guarantee_queue_with_fast_path(&mut root, &[], 1);
    assert!(exact_pick.is_none(),
        "exact-guarantee selector must decline token-starved surplus_sharing queue");

    // Then: surplus selector picks the queue up on the same pass.
    let surplus_pick = select_cos_surplus_batch(&mut root, 1);
    assert!(matches!(
        surplus_pick,
        Some(CoSBatch::Local {
            phase: CoSServicePhase::Surplus,
            ..
        })
    ),
        "surplus selector must pick up surplus_sharing exact queue \
         after exact-guarantee declines");
}

#[test]
fn guarantee_phase_parks_non_exact_queue_on_root_only_wakeup() {
    let mut root = test_cos_runtime_with_exact(false);
    root.tokens = 0;
    root.queues[0].last_refill_ns = 1;
    root.queues[0].tokens = 0;
    root.queues[0].items.push_back(test_cos_item(1500));
    root.queues[0].queued_bytes = 1500;
    root.queues[0].runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    assert!(select_cos_guarantee_batch(&mut root, 1).is_none());
    assert!(root.queues[0].parked);
    assert_eq!(root.queues[0].next_wakeup_tick, 30);
}

#[test]
fn guarantee_phase_limits_service_to_visit_quantum() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000,
            exact: false,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    root.tokens = 64 * 1024;
    root.queues[0].tokens = 64 * 1024;
    root.queues[0].runnable = true;
    for _ in 0..4 {
        root.queues[0].items.push_back(test_cos_item(1500));
    }
    root.queues[0].queued_bytes = 4 * 1500;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    let batch = select_cos_guarantee_batch(&mut root, 1).expect("guarantee batch");
    match batch {
        CoSBatch::Local { items, .. } => assert_eq!(items.len(), 1),
        CoSBatch::Prepared { .. } => panic!("expected local batch"),
    }
    assert_eq!(root.queues[0].items.len(), 3);
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
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: 256 * 1024,
            dscp_rewrite: None,
        }],
    );
    root.tokens = 256 * 1024;
    root.queues[0].tokens = 256 * 1024;
    root.queues[0].runnable = true;
    for _ in 0..200 {
        root.queues[0].items.push_back(test_cos_item(1500));
    }
    root.queues[0].queued_bytes = 200 * 1500;
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
    assert_eq!(root.queues[0].items.len(), 200 - TX_BATCH_SIZE);
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
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: 256 * 1024,
            dscp_rewrite: None,
        }],
    );
    let low_rate = test_cos_runtime_with_queues(
        100_000_000u64 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-low".into(),
            priority: 5,
            transmit_rate_bytes: 100_000_000u64 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: 256 * 1024,
            dscp_rewrite: None,
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
                exact: false,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            },
            CoSQueueConfig {
                queue_id: 1,
                forwarding_class: "af11".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000,
                exact: false,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            },
        ],
    );
    root.tokens = 64 * 1024;
    for queue in &mut root.queues {
        queue.tokens = 64 * 1024;
        queue.runnable = true;
        queue.items.push_back(test_cos_item(1500));
        queue.items.push_back(test_cos_item(1500));
        queue.queued_bytes = 2 * 1500;
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
    let batch = select_nonexact_cos_guarantee_batch(&mut root, 1).expect("nonexact queue batch");
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
    // queue.tokens on the exact queues to make sure they never hit
    // token-starvation during the four interleaved rounds below —
    // the exact selector does not refill exact-queue tokens itself
    // (that is done by the shared-lease path), so this test bypasses
    // that machinery by handing the queues a large local budget.
    let mut root = test_mixed_class_root_with_primed_queues();
    for queue in &mut root.queues {
        if queue.exact {
            queue.tokens = 128 * 1024;
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
        let _ = select_nonexact_cos_guarantee_batch(&mut root, 1);
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
        let batch = select_nonexact_cos_guarantee_batch(&mut root, 1).expect("nonexact batch");
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
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
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
                exact: false,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            },
            CoSQueueConfig {
                queue_id: 1,
                forwarding_class: "voice".into(),
                priority: 0,
                transmit_rate_bytes: 1_000_000,
                exact: false,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            },
        ],
    );
    root.tokens = 64 * 1024;
    for queue in &mut root.queues {
        queue.last_refill_ns = 1;
        queue.tokens = 0;
        queue.runnable = true;
        queue.items.push_back(test_cos_item(1500));
        queue.queued_bytes = 1500;
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
                exact: false,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            },
            CoSQueueConfig {
                queue_id: 1,
                forwarding_class: "large".into(),
                priority: 5,
                transmit_rate_bytes: 4_000_000,
                exact: false,
                surplus_sharing: false,
                surplus_weight: 4,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            },
        ],
    );
    root.tokens = 64 * 1024;
    for queue in &mut root.queues {
        queue.last_refill_ns = 1;
        queue.tokens = 0;
        queue.runnable = true;
        for _ in 0..8 {
            queue.items.push_back(test_cos_item(1500));
        }
        queue.queued_bytes = 8 * 1500;
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
                exact: true,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
            },
            CoSQueueConfig {
                queue_id: 5,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 25_000_000_000 / 8,
                exact: true,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: 128 * 1024,
                dscp_rewrite: None,
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
        runtime.queues[0].flow_fair,
        "queue at position 0 (iperf-a, shared_exact=false) must \
         be on the flow-fair path — #784 fairness fix depends on it",
    );
    assert!(
        !runtime.queues[0].shared_exact,
        "queue at position 0 must get position-0's shared_exact=false",
    );
    assert!(
        runtime.queues[1].flow_fair,
        "#785 Phase 3: queue at position 1 (iperf-c, \
         shared_exact=true) must also be on the flow-fair path \
         so MQFQ VFT ordering enforces per-flow fairness. The \
         admission gates (cos_queue_flow_share_limit, \
         apply_cos_admission_ecn_policy) separately downgrade to \
         aggregate-only on shared_exact queues.",
    );
    assert!(
        runtime.queues[1].shared_exact,
        "queue at position 1 must get position-1's shared_exact=true \
         — zip misalignment would silently mis-route admission policy",
    );
}

use crate::afxdp::types::{
    CoSQueueConfig, CoSQueueDropCounters, CoSQueueOwnerProfile, FlowRrRing, COS_FLOW_FAIR_BUCKETS,
};

#[test]
fn cos_batch_tx_made_progress_requires_real_send_progress() {
    assert!(!cos_batch_tx_made_progress(Ok((0, 0))));
    assert!(cos_batch_tx_made_progress(Ok((1, 0))));
    assert!(cos_batch_tx_made_progress(Ok((0, 1500))));
}

#[test]
fn cos_batch_tx_made_progress_yields_on_retry_and_drop() {
    assert!(!cos_batch_tx_made_progress(Err(TxError::Retry(
        "no free TX frame available".to_string()
    ))));
    assert!(!cos_batch_tx_made_progress(Err(TxError::Drop(
        "tx ring insert failed".to_string()
    ))));
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
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    root.queues[0]
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
        }));
    root.queues[0]
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
        }));
    root.queues[0]
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
        root.queues[0].items.front(),
        Some(CoSPendingTxItem::Local(_))
    ));
    assert!(matches!(
        root.queues[0].items.get(2),
        Some(CoSPendingTxItem::Prepared(_))
    ));
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
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    root.queues[0]
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
        }));
    root.queues[0]
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
    assert_eq!(root.queues[0].items.len(), 2);
    match root.queues[0].items.pop_front().expect("first queued") {
        CoSPendingTxItem::Local(req) => assert_eq!(req.bytes, vec![1]),
        CoSPendingTxItem::Prepared(_) => panic!("unexpected prepared item"),
    }
    match root.queues[0].items.pop_front().expect("second queued") {
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
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    root.queues[0]
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
        }));
    root.queues[0]
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
        }));
    root.queues[0]
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

    let (sent_packets, sent_bytes) = settle_exact_local_fifo_submission(
        Some(&mut root.queues[0]),
        &mut free_tx_frames,
        &mut scratch_local_tx,
        1,
    );

    assert_eq!(sent_packets, 1);
    assert_eq!(sent_bytes, 1);
    assert!(scratch_local_tx.is_empty());
    assert_eq!(free_tx_frames, VecDeque::from([128, 192]));
    assert_eq!(root.queues[0].items.len(), 2);
    match root.queues[0].items.pop_front().expect("first restored") {
        CoSPendingTxItem::Local(req) => assert_eq!(req.bytes, vec![2]),
        CoSPendingTxItem::Prepared(_) => panic!("unexpected prepared restored item"),
    }
    match root.queues[0].items.pop_front().expect("second restored") {
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
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    root.queues[0]
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
        u64::MAX,
        u64::MAX,
        None,
    );

    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    release_exact_prepared_scratch(&mut scratch_prepared_tx);
    assert!(scratch_prepared_tx.is_empty());
    assert_eq!(root.queues[0].items.len(), 1);
    match root.queues[0].items.front().expect("queued prepared") {
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
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    root.queues[0]
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
        }));
    root.queues[0]
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
        }));
    root.queues[0]
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

    let (sent_packets, sent_bytes) = settle_exact_prepared_fifo_submission(
        Some(&mut root.queues[0]),
        &mut scratch_prepared_tx,
        &mut in_flight_prepared_recycles,
        1,
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
    assert_eq!(root.queues[0].items.len(), 2);
    match root.queues[0].items.pop_front().expect("first restored") {
        CoSPendingTxItem::Prepared(req) => assert_eq!(req.offset, 128),
        CoSPendingTxItem::Local(_) => panic!("unexpected local restored item"),
    }
    match root.queues[0].items.pop_front().expect("second restored") {
        CoSPendingTxItem::Prepared(req) => assert_eq!(req.offset, 192),
        CoSPendingTxItem::Local(_) => panic!("unexpected local restored item"),
    }
}

#[test]
fn assign_local_dscp_rewrite_preserves_existing_filter_rewrite() {
    let mut items = VecDeque::from([
        TxRequest {
            bytes: vec![0; 64],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 42,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
        },
        TxRequest {
            bytes: vec![0; 64],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 42,
            cos_queue_id: Some(0),
            dscp_rewrite: Some(0),
        },
    ]);

    assign_local_dscp_rewrite(&mut items, Some(46));

    assert_eq!(items[0].dscp_rewrite, Some(46));
    assert_eq!(items[1].dscp_rewrite, Some(0));
}

#[test]
fn estimate_cos_queue_wakeup_tick_uses_token_deficits() {
    let mut root = test_cos_interface_runtime(0);
    root.tokens = 0;
    root.queues[0].tokens = 0;

    let wake_tick = estimate_cos_queue_wakeup_tick(
        root.tokens,
        root.shaping_rate_bytes,
        root.queues[0].tokens,
        root.queues[0].transmit_rate_bytes,
        1500,
        0,
        true,
    )
    .expect("wake tick");

    assert_eq!(wake_tick, 30);
}

#[test]
fn estimate_cos_queue_wakeup_tick_ignores_queue_deficit_for_surplus() {
    let mut root = test_cos_interface_runtime(0);
    root.tokens = 0;
    root.queues[0].tokens = 0;

    let wake_tick = estimate_cos_queue_wakeup_tick(
        root.tokens,
        root.shaping_rate_bytes,
        root.queues[0].tokens,
        root.queues[0].transmit_rate_bytes,
        1500,
        0,
        false,
    )
    .expect("wake tick");

    assert_eq!(wake_tick, 30);
}

#[test]
fn restore_cos_local_items_marks_queue_runnable_after_retry() {
    let mut queue = CoSQueueRuntime {
        queue_id: 5,
        priority: 5,
        transmit_rate_bytes: 11_000_000_000 / 8,
        exact: true,
        surplus_sharing: false,
        flow_fair: false,
        shared_exact: false,
        flow_hash_seed: 0,
        surplus_weight: 1,
        surplus_deficit: 0,
        buffer_bytes: COS_MIN_BURST_BYTES,
        dscp_rewrite: None,
        tokens: 0,
        last_refill_ns: 0,
        queued_bytes: 0,
        active_flow_buckets: 0,
        active_flow_buckets_peak: 0,
        flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
        flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
        flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
        queue_vtime: 0,
        pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
        flow_rr_buckets: FlowRrRing::default(),
        flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
        runnable: false,
        parked: false,
        next_wakeup_tick: 0,
        wheel_level: 0,
        wheel_slot: 0,
        items: VecDeque::new(),
        local_item_count: 0,

        vtime_floor: None,

        worker_id: 0,
        drop_counters: CoSQueueDropCounters::default(),
        owner_profile: CoSQueueOwnerProfile::new(),
        consecutive_v_min_skips: 0,
        v_min_suspended_remaining: 0,
        v_min_hard_cap_overrides_scratch: 0,
                v_min_throttles_scratch: 0,
    };
    let retry = VecDeque::from([TxRequest {
        bytes: vec![0; 1500],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 80,
        cos_queue_id: Some(5),
        dscp_rewrite: None,
    }]);

    let retry_bytes = restore_cos_local_items_inner(&mut queue, retry);

    assert_eq!(queue.items.len(), 1);
    assert_eq!(retry_bytes, 1500);
    assert!(queue.runnable);
    assert!(!queue.parked);
}

#[test]
fn restore_cos_prepared_items_marks_queue_runnable_after_retry() {
    let mut queue = CoSQueueRuntime {
        queue_id: 5,
        priority: 5,
        transmit_rate_bytes: 11_000_000_000 / 8,
        exact: true,
        surplus_sharing: false,
        flow_fair: false,
        shared_exact: false,
        flow_hash_seed: 0,
        surplus_weight: 1,
        surplus_deficit: 0,
        buffer_bytes: COS_MIN_BURST_BYTES,
        dscp_rewrite: None,
        tokens: 0,
        last_refill_ns: 0,
        queued_bytes: 0,
        active_flow_buckets: 0,
        active_flow_buckets_peak: 0,
        flow_bucket_bytes: [0; COS_FLOW_FAIR_BUCKETS],
        flow_bucket_head_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
        flow_bucket_tail_finish_bytes: [0; COS_FLOW_FAIR_BUCKETS],
        queue_vtime: 0,
        pop_snapshot_stack: Vec::with_capacity(TX_BATCH_SIZE),
        flow_rr_buckets: FlowRrRing::default(),
        flow_bucket_items: std::array::from_fn(|_| VecDeque::new()),
        runnable: false,
        parked: false,
        next_wakeup_tick: 0,
        wheel_level: 0,
        wheel_slot: 0,
        items: VecDeque::new(),
        local_item_count: 0,

        vtime_floor: None,

        worker_id: 0,
        drop_counters: CoSQueueDropCounters::default(),
        owner_profile: CoSQueueOwnerProfile::new(),
        consecutive_v_min_skips: 0,
        v_min_suspended_remaining: 0,
        v_min_hard_cap_overrides_scratch: 0,
                v_min_throttles_scratch: 0,
    };
    let retry = VecDeque::from([PreparedTxRequest {
        offset: 64,
        len: 1500,
        recycle: PreparedTxRecycle::FreeTxFrame,
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 80,
        cos_queue_id: Some(5),
        dscp_rewrite: None,
    }]);

    let retry_bytes = restore_cos_prepared_items_inner(&mut queue, retry);

    assert_eq!(queue.items.len(), 1);
    assert_eq!(retry_bytes, 1500);
    assert!(queue.runnable);
    assert!(!queue.parked);
}

#[test]
fn estimate_cos_queue_wakeup_tick_root_rate_zero_returns_some() {
    // #916: transparent root. When `root_rate_bytes == 0` and
    // queue_rate is non-zero, the root-refill question is
    // meaningless (transparent semantics: bucket always full).
    // Pre-fix: cos_refill_ns_until(_, _, 0) → None propagated by
    // `?` → the caller skips parking AND the queue stays in
    // limbo. Post-fix: bypass the root-refill check.
    let wake_tick = estimate_cos_queue_wakeup_tick(
        0, 0, // root: zero tokens, zero rate (transparent)
        0, 1_000_000, // queue: zero tokens, 1 Mbps rate
        1500,
        0,
        true,
    );
    assert!(
        wake_tick.is_some(),
        "transparent root + queue with rate must produce a wake tick (Some)",
    );
}

#[test]
fn estimate_cos_queue_wakeup_tick_both_rates_zero_returns_some() {
    // #916: transparent root + transparent queue. Both refill
    // checks must be bypassed; estimator returns the next-tick
    // wake-tick (1ns past now ≈ next-tick).
    let wake_tick = estimate_cos_queue_wakeup_tick(
        0, 0, // root: transparent
        0, 0, // queue: transparent
        1500,
        0,
        true,
    );
    assert!(
        wake_tick.is_some(),
        "fully transparent (root + queue both rate=0) must produce a wake tick (Some)",
    );
}

#[test]
fn estimate_cos_queue_wakeup_tick_root_rate_zero_with_require_queue_false() {
    // #916: surplus path (require_queue_tokens = false). With
    // transparent root, the root-refill check is bypassed; the
    // queue-refill check is skipped because require=false. Result
    // should be Some(_).
    let wake_tick = estimate_cos_queue_wakeup_tick(
        0, 0, // root: transparent
        0, 0, // queue: irrelevant when require=false
        1500,
        0,
        false,
    );
    assert!(wake_tick.is_some());
}
