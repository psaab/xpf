// Tests for afxdp/cos/queue_ops/v_min.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep v_min.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "v_min_tests.rs"]` from v_min.rs.

// V_min coordination tests colocated with the production fns,
// moved here per #1034 P4 from queue_ops/mod.rs's `mod tests`
// (where they were originally placed before the V_min split
// landed in #1036).
use super::*;
use crate::afxdp::cos::queue_ops::{
    cos_queue_pop_front, cos_queue_push_back, cos_queue_push_front,
};
use crate::afxdp::cos::queue_service::{
    drain_exact_local_items_to_scratch_flow_fair, drain_exact_prepared_items_to_scratch_flow_fair,
};
use crate::afxdp::cos::token_bucket::COS_MIN_BURST_BYTES;
use crate::afxdp::tx::cos_classify::demote_prepared_cos_queue_to_local;
use crate::afxdp::tx::test_support::*;
use crate::afxdp::types::{CoSQueueConfig, PreparedTxRecycle, PreparedTxRequest, TxRequest};
use crate::afxdp::umem::MmapArea;
use crate::afxdp::PROTO_TCP;

/// #940: speculative pop (snapshot variant) must NOT publish to the
/// V_min slot. The slot stays at NOT_PARTICIPATING throughout the
/// snapshot pop. Rolling back via `cos_queue_push_front` republishes
/// the post-rollback vtime via the existing rollback hook.
#[test]
fn vmin_pop_snapshot_does_not_publish() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);

    // Sanity: slot starts at NOT_PARTICIPATING.
    assert_eq!(
        floor.slots[1].read(),
        None,
        "fresh slot should be NOT_PARTICIPATING"
    );

    // Push an item and pop with snapshot. With #940, this must
    // NOT publish — slot stays at NOT_PARTICIPATING.
    cos_queue_push_back(queue, test_cos_item(1500));
    let _popped = cos_queue_pop_front(queue);
    assert_eq!(
        floor.slots[1].read(),
        None,
        "snapshot pop must not publish to V_min slot (#940)",
    );

    // Now roll back — push_front republishes the rolled-back vtime
    // via the existing rollback hook in cos_queue_push_front.
    if let Some(item) = _popped {
        cos_queue_push_front(queue, item);
    }
    // After rollback, queue_vtime is back to 0; the rollback hook
    // publishes that. Slot should now reflect a value (0 — the
    // pre-pop state).
    assert_eq!(
        floor.slots[1].read(),
        Some(0),
        "rollback path republishes corrected vtime",
    );
}

/// #940: post-settle publish on the Local-flow-fair commit site.
/// After a successful drain + insert + settle, the slot reflects
/// the committed queue_vtime.
///
/// This test exercises the `publish_committed_queue_vtime` helper
/// directly (the helper is the publish primitive). The full
/// scratch-builder + commit + settle path is exercised by the
/// existing `cos_exact_drain_throughput_micro_bench` and the
/// integration tests; this pin asserts the helper's contract.
#[test]
fn vmin_post_settle_publish_writes_committed_vtime() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 2);

    // Set queue_vtime as if a drain has just committed.
    queue.queue_vtime = 12345;
    publish_committed_queue_vtime(Some(&*queue));
    assert_eq!(
        floor.slots[2].read(),
        Some(12345),
        "post-settle publish must write committed queue_vtime to the slot",
    );

    // Calling again with a higher vtime advances the slot
    // (idempotent / monotonic in normal flow).
    queue.queue_vtime = 23456;
    publish_committed_queue_vtime(Some(&*queue));
    assert_eq!(
        floor.slots[2].read(),
        Some(23456),
        "subsequent publish must overwrite",
    );
}

/// #940 F4: `publish_committed_queue_vtime` is a no-op when
/// `vtime_floor = None`. Existing tests rely on this — non-V_min
/// queues must not publish anywhere.
#[test]
fn vmin_publish_helper_noop_when_floor_none() {
    let mut root = test_cos_runtime_with_queues(
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
    let queue = &mut root.queues[0];
    // No floor attached; default state.
    assert!(queue.vtime_floor.is_none());
    queue.queue_vtime = 99999;
    // Must not panic and must not publish anywhere.
    publish_committed_queue_vtime(Some(&*queue));
    // Sanity: still no floor, no observable effect.
    assert!(queue.vtime_floor.is_none());
}

/// #942 (deferred): pin the cos_queue_v_min_continue throttle
/// behavior in isolation. The Prepared flow-fair scratch builder
/// does NOT actually call this in production yet — wiring it
/// caused a severe shared_exact regression that bisection traced
/// to this exact wiring (see plan.md "#942 deferred"). The
/// underlying cos_queue_v_min_continue function still works
/// correctly when called directly, as this test confirms.
#[test]
fn vmin_throttle_function_fires_on_lag_breach() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: 4 * 1024 * 1024,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);

    // Peer worker 0 pegged at vtime 0. Local worker 1 has
    // queue_vtime well past LAG_THRESHOLD (~1.25 MB at 10 Gb/s).
    floor.slots[0].publish(0);
    queue.queue_vtime = 100 * 1024 * 1024; // 100 MB ahead

    // V_min check at pop_count==1 must throttle (return false).
    assert!(
        !cos_queue_v_min_continue(queue, 1),
        "throttle MUST fire when local vtime >> peer V_min + LAG",
    );

    // Reset queue_vtime to within LAG and confirm the check passes.
    queue.queue_vtime = 0;
    assert!(
        cos_queue_v_min_continue(queue, 1),
        "throttle MUST NOT fire when local vtime <= V_min + LAG",
    );
}

/// #943: every regular V_min throttle decision (i.e. not a hard-cap
/// override) bumps `v_min_throttles_scratch`. The scratch flushes
/// to `BindingLiveState::v_min_throttles` in `update_binding_debug_state`
/// (covered separately under the umem flush tests). This test pins
/// just the increment site so a future refactor that drops the
/// counter increment from the throttle path surfaces here.
#[test]
fn vmin_throttle_increments_v_min_throttles_scratch() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: 4 * 1024 * 1024,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);
    floor.slots[0].publish(0);
    queue.queue_vtime = 100 * 1024 * 1024; // 100 MB ahead → throttle

    assert_eq!(
        queue.v_min_throttles_scratch, 0,
        "scratch starts at zero"
    );

    // Throttle decision (not a hard-cap override).
    let cont = cos_queue_v_min_continue(queue, 1);
    assert!(!cont, "expected throttle decision");
    assert_eq!(
        queue.v_min_throttles_scratch, 1,
        "regular throttle MUST bump v_min_throttles_scratch by 1"
    );
    assert_eq!(
        queue.v_min_hard_cap_overrides_scratch, 0,
        "regular throttle MUST NOT bump the hard-cap counter"
    );

    // Two more throttles — counter increments by exactly +1 each.
    // V_MIN_CONSECUTIVE_SKIP_HARD_CAP is fixed at 8 (mod.rs:112) so
    // we're well below the hard-cap boundary; assert the exact
    // count to catch off-by-one or dropped increments
    // (Copilot review).
    let _ = cos_queue_v_min_continue(queue, 1);
    let _ = cos_queue_v_min_continue(queue, 1);
    assert_eq!(
        queue.v_min_throttles_scratch, 3,
        "three throttles → scratch == 3 (not >= 2 — exact count catches off-by-one)"
    );
}

/// #943: when the hard-cap override fires (after
/// V_MIN_CONSECUTIVE_SKIP_HARD_CAP back-to-back throttles), only
/// `v_min_hard_cap_overrides_scratch` increments — the regular
/// `v_min_throttles_scratch` does NOT. The two counters are
/// disjoint diagnostics; double-counting would muddy the
/// LAG_THRESHOLD ratio metric.
#[test]
fn vmin_hard_cap_override_does_not_double_count_throttle() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: 4 * 1024 * 1024,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);
    floor.slots[0].publish(0);
    queue.queue_vtime = 100 * 1024 * 1024;

    // Drive the throttle counter to V_MIN_CONSECUTIVE_SKIP_HARD_CAP - 1
    // back-to-back throttle decisions. Each bumps v_min_throttles_scratch.
    for _ in 0..(V_MIN_CONSECUTIVE_SKIP_HARD_CAP - 1) {
        let cont = cos_queue_v_min_continue(queue, 1);
        assert!(!cont, "expected throttle (not yet at hard-cap)");
    }
    let throttles_before_cap = queue.v_min_throttles_scratch;
    let hard_cap_before = queue.v_min_hard_cap_overrides_scratch;
    assert_eq!(hard_cap_before, 0, "hard-cap not yet fired");

    // The next throttle decision triggers the hard-cap override:
    // function returns true, hard-cap counter bumps, throttle counter
    // does NOT bump (the override path is taken instead).
    let cont = cos_queue_v_min_continue(queue, 1);
    assert!(cont, "hard-cap override force-continues");
    assert_eq!(
        queue.v_min_hard_cap_overrides_scratch, 1,
        "hard-cap counter bumps exactly once"
    );
    assert_eq!(
        queue.v_min_throttles_scratch, throttles_before_cap,
        "throttle counter MUST NOT increment on the hard-cap path"
    );
}

/// #940: full pop → push_front (rollback) → re-pop → publish-via-
/// post-settle sequence. Pins that the rollback hook in
/// `cos_queue_push_front` and the new post-settle publish compose
/// correctly under partial-rollback workloads. Per Gemini
/// adversarial review.
#[test]
fn vmin_pop_rollback_repop_postsettle_compose() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);

    // Push 2 items.
    cos_queue_push_back(queue, test_cos_item(1500));
    cos_queue_push_back(queue, test_cos_item(1500));
    let v0 = queue.queue_vtime;
    assert_eq!(floor.slots[1].read(), None, "fresh slot");

    // Pop 1: snapshot variant (NO publish).
    let popped1 = cos_queue_pop_front(queue);
    let v1 = queue.queue_vtime;
    assert!(v1 > v0, "pop must advance vtime");
    assert_eq!(floor.slots[1].read(), None, "snapshot pop must not publish");

    // Roll back via push_front: republishes via existing rollback
    // hook. Slot now holds the rolled-back vtime (back to v0).
    if let Some(item) = popped1 {
        cos_queue_push_front(queue, item);
    }
    let v_after_rollback = queue.queue_vtime;
    assert_eq!(v_after_rollback, v0, "rollback must restore vtime");
    assert_eq!(
        floor.slots[1].read(),
        Some(v0),
        "rollback hook must publish corrected vtime",
    );

    // Re-pop (snapshot). queue_vtime advances again. Slot stays at
    // v0 because the snapshot pop doesn't publish.
    let _popped2 = cos_queue_pop_front(queue);
    assert!(
        queue.queue_vtime > v_after_rollback,
        "re-pop advances vtime"
    );
    assert_eq!(
        floor.slots[1].read(),
        Some(v0),
        "re-pop snapshot must not publish",
    );

    // Post-settle publish: slot reflects the new committed vtime.
    publish_committed_queue_vtime(Some(&*queue));
    assert_eq!(
        floor.slots[1].read(),
        Some(queue.queue_vtime),
        "post-settle publish broadcasts the new committed vtime",
    );
}

/// #940: demote_prepared_cos_queue_to_local must not publish to
/// V_min during drain_all. Reframed per Gemini review: assert slot
/// value before demote == slot value after demote completes the
/// internal save/restore but BEFORE the new explicit post-restore
/// publish call... well actually the publish happens at the end of
/// demote_prepared_cos_queue_to_local now, so we observe:
///
///   1. Pre-demote: slot at SOME_PRE_VTIME (set explicitly).
///   2. Build a queue with prepared items.
///   3. Run demote (which drains internally with no-snapshot
///      pops, advances queue_vtime by drained bytes,
///      converts items to Local, then RESTORES queue_vtime
///      from the saved value, then publishes).
///   4. Post-demote: slot at SOME_PRE_VTIME (== restored value
///      since demote saves+restores symmetrically).
///
/// The test cannot observe the transient drain-time queue_vtime
/// from a single thread; the assertion is "slot value at start ==
/// slot value at end" which proves no transient leaked.
#[test]
fn vmin_demote_no_drain_all_leak() {
    // demote_prepared_cos_queue_to_local takes &MmapArea and
    // operates on Prepared items. We need a real MmapArea and
    // a queue with Prepared items. Start with a small UMEM.
    let area = MmapArea::new(2 * 1024 * 1024).expect("mmap umem");

    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: 4 * 1024 * 1024,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 0);
    // Set a non-zero "prior committed" vtime so we can detect
    // accidental publishes-of-zero from drain_all.
    queue.queue_vtime = 7777;
    floor.slots[0].publish(7777);
    let pre_slot = floor.slots[0].read();
    assert_eq!(pre_slot, Some(7777), "fixture sanity");

    // Push a Prepared item.
    let prep = PreparedTxRequest {
        offset: 0,
        len: 1500,
        recycle: PreparedTxRecycle::FreeTxFrame,
        dscp_rewrite: None,
        cos_queue_id: Some(0),
        flow_key: None,
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        egress_ifindex: 80,
    };
    cos_queue_push_back(queue, CoSPendingTxItem::Prepared(prep));

    let mut free_tx = VecDeque::new();
    let mut pending_fill = VecDeque::new();
    let _ok = demote_prepared_cos_queue_to_local(
        &area,
        &mut free_tx,
        &mut pending_fill,
        0,
        &mut root,
        Some(0),
    );

    // Re-borrow queue and floor (root was reborrowed by demote).
    let queue = &root.queues[0];
    let post_slot = queue
        .vtime_floor
        .as_ref()
        .and_then(|f| f.slots.get(0))
        .and_then(|s| s.read());

    // Slot at end MUST equal slot at start: demote saves+restores
    // queue_vtime (#926) and the new post-restore publish writes
    // the SAME (saved) value back. drain_all's internal vtime
    // inflation never reaches the slot because the pop-time
    // publish has been removed (#940).
    assert_eq!(
        post_slot, pre_slot,
        "demote must not leak drain_all vtime to V_min slot — \
         the saved+restored vtime must round-trip cleanly (#940)",
    );
}

/// #941 Work item A: when the worker's last active bucket on a
/// shared_exact queue empties, the V_min slot is vacated to
/// NOT_PARTICIPATING. Without vacate, the slot would hold the
/// stale-low queue_vtime — phantom-participating — and peers would
/// throttle against it indefinitely.
#[test]
fn vmin_vacate_on_bucket_empty() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);

    // Establish participation: enqueue + drain + publish so slot
    // has a non-NOT_PARTICIPATING value.
    let item = test_flow_cos_item(1234, 1500);
    cos_queue_push_back(queue, item);
    let _ = cos_queue_pop_front(queue);
    publish_committed_queue_vtime(Some(&*queue));
    assert!(
        floor.slots[1].read().is_some(),
        "slot should be participating after publish",
    );

    // active_flow_buckets is now 0 because pop drained the only bucket.
    // Enqueue + dequeue another item with the SAME flow_key to retrigger
    // the bucket-empty vacate path. Must use account_cos_queue_flow_*
    // helpers explicitly — push_back/pop_front delegate to them but
    // we want to exercise the dequeue accounting that holds the
    // vacate hook.
    let key = test_session_key(1234, 5201);
    account_cos_queue_flow_enqueue(queue, Some(&key), 1500);
    // Now dequeue: should fire the bucket-empty path AND vacate.
    account_cos_queue_flow_dequeue(queue, Some(&key), 1500);
    assert_eq!(queue.active_flow_buckets, 0, "bucket count drained to 0");
    assert!(
        floor.slots[1].read().is_none(),
        "Work item A: slot must be vacated to NOT_PARTICIPATING when the last bucket empties",
    );
}

/// #941 Work item A: the vacate fires ONLY when active_flow_buckets
/// transitions to 0. If two flows hash to two buckets, dequeueing
/// the first bucket should NOT vacate (the second is still active).
#[test]
fn vmin_vacate_only_when_last_bucket_empties() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);
    // Pick keys that map to different buckets — try several until
    // we find two with distinct hashes.
    let mut keys: Vec<SessionKey> = Vec::new();
    let mut buckets = std::collections::HashSet::new();
    for src in 1000u16..2000 {
        let k = test_session_key(src, 5201);
        let bkt = cos_flow_bucket_index(queue.flow_hash_seed, Some(&k));
        if buckets.insert(bkt) {
            keys.push(k);
            if keys.len() == 2 {
                break;
            }
        }
    }
    assert_eq!(keys.len(), 2, "need two distinct buckets");
    // Enqueue both flows; active_flow_buckets becomes 2.
    account_cos_queue_flow_enqueue(queue, Some(&keys[0]), 1500);
    account_cos_queue_flow_enqueue(queue, Some(&keys[1]), 1500);
    assert_eq!(queue.active_flow_buckets, 2);
    // Establish participation by publishing.
    publish_committed_queue_vtime(Some(&*queue));
    assert!(floor.slots[1].read().is_some());
    // Dequeue first flow's bucket. active_flow_buckets goes 2→1; no vacate.
    account_cos_queue_flow_dequeue(queue, Some(&keys[0]), 1500);
    assert_eq!(queue.active_flow_buckets, 1);
    assert!(
        floor.slots[1].read().is_some(),
        "vacate must NOT fire when other buckets are still active",
    );
    // Dequeue second flow's bucket. active_flow_buckets goes 1→0 → vacate.
    account_cos_queue_flow_dequeue(queue, Some(&keys[1]), 1500);
    assert_eq!(queue.active_flow_buckets, 0);
    assert!(
        floor.slots[1].read().is_none(),
        "vacate must fire when the last bucket empties",
    );
}

/// #941 Work item D: hard-cap activation. After
/// V_MIN_CONSECUTIVE_SKIP_HARD_CAP back-to-back throttle decisions,
/// the function force-continues AND arms suspension.
#[test]
fn vmin_hard_cap_force_continue_activates_suspension() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);
    // Peer 0 publishes a tiny vtime — guarantees the throttle path.
    floor.slots[0].publish(0);
    queue.queue_vtime = 100 * 1024 * 1024; // 100 MB ahead, way past lag.
                                           // Each call returns false (throttle) until consecutive_v_min_skips
                                           // reaches HARD_CAP. The Nth call returns true (force-continue) and
                                           // arms suspension.
    for n in 1..V_MIN_CONSECUTIVE_SKIP_HARD_CAP {
        let cont = cos_queue_v_min_continue(queue, 1);
        assert!(
            !cont,
            "throttle must fire on call {} of {}",
            n, V_MIN_CONSECUTIVE_SKIP_HARD_CAP
        );
    }
    // The Nth call hits the hard-cap.
    let final_cont = cos_queue_v_min_continue(queue, 1);
    assert!(final_cont, "hard-cap activation must force-continue");
    assert_eq!(
        queue.v_min_suspended_remaining, V_MIN_SUSPENSION_BATCHES,
        "hard-cap must arm suspension to V_MIN_SUSPENSION_BATCHES",
    );
    assert_eq!(
        queue.consecutive_v_min_skips, 0,
        "hard-cap must reset consecutive skips to 0",
    );
    assert_eq!(
        queue.v_min_hard_cap_overrides_scratch, 1,
        "hard-cap activation must increment the override counter",
    );
}

/// #941 Work item D: `cos_queue_v_min_consume_suspension` decrements
/// the counter once per call and returns the suspension state.
#[test]
fn vmin_consume_suspension_decrements_once() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    let _floor = attach_test_vtime_floor(queue, 4, 1);
    // No suspension active initially — returns false, no change.
    assert!(!cos_queue_v_min_consume_suspension(queue));
    assert_eq!(queue.v_min_suspended_remaining, 0);
    // Arm suspension manually (simulating hard-cap).
    queue.v_min_suspended_remaining = 5;
    // Each call decrements by 1 and returns true.
    for expected_remaining in (0..5).rev() {
        assert!(cos_queue_v_min_consume_suspension(queue));
        assert_eq!(queue.v_min_suspended_remaining, expected_remaining);
    }
    // Drained — next call returns false.
    assert!(!cos_queue_v_min_consume_suspension(queue));
    assert_eq!(queue.v_min_suspended_remaining, 0);
}

/// #941 Work item D + Gemini Q6: the drain-call preflight must NOT
/// burn a suspension slot when free_tx_frames is empty (no work
/// can be done). Validates `cos_queue_v_min_consume_suspension`
/// is called AFTER the preflight, not before.
#[test]
fn vmin_suspension_not_decremented_on_empty_tx_frames() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    let _floor = attach_test_vtime_floor(queue, 4, 1);
    // Arm suspension at a known value.
    queue.v_min_suspended_remaining = 100;
    let initial = queue.v_min_suspended_remaining;
    let area = MmapArea::new(2 * 1024 * 1024).expect("mmap");
    let mut empty_free: VecDeque<u64> = VecDeque::new();
    let mut scratch: Vec<(u64, TxRequest)> = Vec::new();
    // Call drain with empty free_tx_frames. The function should
    // return early WITHOUT consuming a suspension slot.
    let _ = drain_exact_local_items_to_scratch_flow_fair(
        queue,
        &mut empty_free,
        &mut scratch,
        &area,
        u64::MAX,
        u64::MAX,
        None,
    );
    assert_eq!(
        queue.v_min_suspended_remaining, initial,
        "drain with empty free_tx_frames must NOT consume a suspension slot",
    );
}

/// #941 Work item D: hard-cap counter increments and is reset on a
/// successful pop (V_min returns true with no peers participating).
#[test]
fn vmin_hard_cap_counter_resets_on_success() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);
    floor.slots[0].publish(0);
    queue.queue_vtime = 100 * 1024 * 1024;
    // 3 throttles increment the counter to 3.
    for _ in 0..3 {
        assert!(!cos_queue_v_min_continue(queue, 1));
    }
    assert_eq!(queue.consecutive_v_min_skips, 3);
    // Now make the check succeed: vacate the peer, so participating==0.
    floor.slots[0].vacate();
    assert!(cos_queue_v_min_continue(queue, 1));
    assert_eq!(
        queue.consecutive_v_min_skips, 0,
        "successful V_min check must reset consecutive_v_min_skips",
    );
}

/// #941: confirms Work item B was correctly dropped. After Work
/// item A vacates, the slot stays NOT_PARTICIPATING until the next
/// post-settle publish (#940's hook). No first-enqueue publish.
#[test]
fn vmin_no_first_enqueue_publish() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);
    // Establish slot at NOT_PARTICIPATING (initial state from
    // SharedCoSQueueVtimeFloor::new()).
    assert!(floor.slots[1].read().is_none());
    // Enqueue an item — Work item A's hook does NOT fire on enqueue,
    // and Work item B was dropped so no first-enqueue publish either.
    let key = test_session_key(1234, 5201);
    account_cos_queue_flow_enqueue(queue, Some(&key), 1500);
    assert!(
        floor.slots[1].read().is_none(),
        "no first-enqueue publish: slot must remain NOT_PARTICIPATING after enqueue (Work item B was DROPPED)",
    );
}

/// #942: Prepared flow-fair drain MUST honor the V_min throttle.
/// Mirrors Local-flow's `vmin_throttle_function_fires_on_lag_breach`
/// pattern: synthetic peer slot pegged at 0; local qvtime well past
/// LAG_THRESHOLD; cos_queue_v_min_continue must return false. Then
/// the suspended path: when v_min_suspended_remaining is non-zero,
/// the drain consumes one slot and skips V_min entirely.
#[test]
fn vmin_prepared_flow_fair_throttle_and_suspension() {
    let mut umem = MmapArea::new(2 * 1024 * 1024).expect("umem");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);
    floor.slots[0].publish(0);
    queue.queue_vtime = 100 * 1024 * 1024;

    // Push a Prepared item so the preflight passes.
    let packet = vec![0u8; 1500];
    let prepared = test_prepared_item_in_umem(&mut umem, 0, &packet, libc::AF_INET as u8);
    cos_queue_push_back(queue, prepared);

    let mut scratch: Vec<PreparedTxRequest> = Vec::new();
    let mut free_tx: VecDeque<u64> = VecDeque::new();
    let mut pending_fill: VecDeque<u64> = VecDeque::new();
    let _ = drain_exact_prepared_items_to_scratch_flow_fair(
        queue,
        &mut scratch,
        &umem,
        &mut free_tx,
        &mut pending_fill,
        0,
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(
        scratch.is_empty(),
        "V_min throttle must break Prepared drain before any item is committed",
    );
    assert_eq!(queue.consecutive_v_min_skips, 1);

    // Arm suspension; next drain consumes one slot and skips V_min,
    // draining the pending Prepared item.
    queue.v_min_suspended_remaining = 5;
    let mut scratch2: Vec<PreparedTxRequest> = Vec::new();
    let _ = drain_exact_prepared_items_to_scratch_flow_fair(
        queue,
        &mut scratch2,
        &umem,
        &mut free_tx,
        &mut pending_fill,
        0,
        u64::MAX,
        u64::MAX,
        None,
    );
    assert_eq!(
        queue.v_min_suspended_remaining, 4,
        "drain MUST consume one suspension slot",
    );
    assert!(
        !scratch2.is_empty(),
        "with suspension active, drain must NOT throttle; Prepared item must reach scratch",
    );
}

/// #942: preflight returns early without consuming suspension when
/// queue head is Local (not Prepared). Mirrors Local-flow's
/// `vmin_suspension_not_decremented_on_empty_tx_frames`.
#[test]
fn vmin_prepared_no_suspension_burn_when_head_is_local() {
    let umem = MmapArea::new(2 * 1024 * 1024).expect("umem");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    let _floor = attach_test_vtime_floor(queue, 4, 1);
    queue.v_min_suspended_remaining = 100;
    let initial = queue.v_min_suspended_remaining;

    // Queue head is Local — preflight returns Ready early.
    cos_queue_push_back(queue, test_cos_item(1500));

    let mut scratch: Vec<PreparedTxRequest> = Vec::new();
    let mut free_tx: VecDeque<u64> = VecDeque::new();
    let mut pending_fill: VecDeque<u64> = VecDeque::new();
    let _ = drain_exact_prepared_items_to_scratch_flow_fair(
        queue,
        &mut scratch,
        &umem,
        &mut free_tx,
        &mut pending_fill,
        0,
        u64::MAX,
        u64::MAX,
        None,
    );
    assert_eq!(
        queue.v_min_suspended_remaining, initial,
        "Prepared drain with non-Prepared head MUST NOT consume a suspension slot",
    );
}

/// #942 (Codex/Gemini Q4): hard-cap arms via the Prepared drain
/// itself, not just via direct `cos_queue_v_min_continue` calls.
/// After V_MIN_CONSECUTIVE_SKIP_HARD_CAP repeated drain attempts
/// under throttle conditions, the next drain force-continues, arms
/// suspension, and successfully commits the head Prepared item.
#[test]
fn vmin_prepared_drain_arms_hard_cap_after_repeated_throttle() {
    let mut umem = MmapArea::new(2 * 1024 * 1024).expect("umem");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);
    floor.slots[0].publish(0);
    queue.queue_vtime = 100 * 1024 * 1024;

    let packet = vec![0u8; 1500];
    let prepared = test_prepared_item_in_umem(&mut umem, 0, &packet, libc::AF_INET as u8);
    cos_queue_push_back(queue, prepared);

    let mut free_tx: VecDeque<u64> = VecDeque::new();
    let mut pending_fill: VecDeque<u64> = VecDeque::new();

    // First (HARD_CAP - 1) drain calls each throttle and bump
    // consecutive_v_min_skips. The head Prepared item must NOT be
    // committed during these calls.
    for n in 1..V_MIN_CONSECUTIVE_SKIP_HARD_CAP {
        let mut scratch: Vec<PreparedTxRequest> = Vec::new();
        let _ = drain_exact_prepared_items_to_scratch_flow_fair(
            queue,
            &mut scratch,
            &umem,
            &mut free_tx,
            &mut pending_fill,
            0,
            u64::MAX,
            u64::MAX,
            None,
        );
        assert!(
            scratch.is_empty(),
            "drain {} of {}: throttle must keep scratch empty",
            n,
            V_MIN_CONSECUTIVE_SKIP_HARD_CAP,
        );
        assert_eq!(
            queue.consecutive_v_min_skips, n,
            "drain {}: consecutive_v_min_skips must increment",
            n,
        );
        assert_eq!(
            queue.v_min_suspended_remaining, 0,
            "drain {}: suspension must NOT yet be armed",
            n,
        );
    }

    // The HARD_CAP-th drain hits the cap: force-continues at
    // pop_count=1, arms suspension, drains the item.
    let mut scratch: Vec<PreparedTxRequest> = Vec::new();
    let _ = drain_exact_prepared_items_to_scratch_flow_fair(
        queue,
        &mut scratch,
        &umem,
        &mut free_tx,
        &mut pending_fill,
        0,
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(
        !scratch.is_empty(),
        "hard-cap drain must commit the head Prepared item",
    );
    assert_eq!(
        queue.v_min_suspended_remaining, V_MIN_SUSPENSION_BATCHES,
        "hard-cap drain must arm suspension to V_MIN_SUSPENSION_BATCHES",
    );
    assert_eq!(
        queue.consecutive_v_min_skips, 0,
        "hard-cap drain must reset consecutive_v_min_skips",
    );
    assert_eq!(
        queue.v_min_hard_cap_overrides_scratch, 1,
        "hard-cap drain must increment the override counter",
    );
}

/// #942 (Gemini Q6 missing test): when a peer slot vacates to
/// NOT_PARTICIPATING mid-drain, the next V_min check observes the
/// vacated state through the `Arc<AtomicU64>` and stops throttling.
/// This is the dynamic-correctness counterpart to
/// `vmin_throttle_function_fires_on_lag_breach`.
#[test]
fn vmin_prepared_drain_unblocks_when_peer_slot_vacates() {
    let mut umem = MmapArea::new(2 * 1024 * 1024).expect("umem");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);
    // Peer 0 publishes a tiny vtime — guarantees throttle.
    floor.slots[0].publish(0);
    queue.queue_vtime = 100 * 1024 * 1024;

    let packet = vec![0u8; 1500];
    let prepared = test_prepared_item_in_umem(&mut umem, 0, &packet, libc::AF_INET as u8);
    cos_queue_push_back(queue, prepared);

    // First drain: throttle fires, nothing committed.
    let mut scratch: Vec<PreparedTxRequest> = Vec::new();
    let mut free_tx: VecDeque<u64> = VecDeque::new();
    let mut pending_fill: VecDeque<u64> = VecDeque::new();
    let _ = drain_exact_prepared_items_to_scratch_flow_fair(
        queue,
        &mut scratch,
        &umem,
        &mut free_tx,
        &mut pending_fill,
        0,
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(
        scratch.is_empty(),
        "throttle must hold the Prepared item before vacate",
    );

    // Peer 0 vacates (Work item A path: bucket-empty transition).
    // The Arc<AtomicU64> publishes immediately to all readers.
    floor.slots[0].vacate();

    // Second drain: peer is NOT_PARTICIPATING, V_min returns true,
    // the head item drains.
    let mut scratch2: Vec<PreparedTxRequest> = Vec::new();
    let _ = drain_exact_prepared_items_to_scratch_flow_fair(
        queue,
        &mut scratch2,
        &umem,
        &mut free_tx,
        &mut pending_fill,
        0,
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(
        !scratch2.is_empty(),
        "peer vacate must clear the throttle and let drain proceed",
    );
    assert_eq!(
        queue.v_min_suspended_remaining, 0,
        "vacate-then-drain must NOT arm suspension (no hard-cap path)",
    );
}

/// #942 (Codex Q4): suspension state is queue-level, not per-drain-
/// function. If the Local drain arms suspension via hard-cap, the
/// subsequent Prepared drain on the same queue MUST see and consume
/// that suspension (rather than re-throttling). Validates the
/// shared `queue.v_min_suspended_remaining` lifecycle across both
/// drain entry points.
#[test]
fn vmin_local_hard_cap_suspension_carries_into_prepared_drain() {
    let mut umem = MmapArea::new(2 * 1024 * 1024).expect("umem");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 1);
    floor.slots[0].publish(0);
    queue.queue_vtime = 100 * 1024 * 1024;

    // Simulate Local hard-cap firing: arm consecutive_v_min_skips
    // to one short of cap, then call cos_queue_v_min_continue
    // directly (matching what Local drain would do at pop_count=1).
    queue.consecutive_v_min_skips = V_MIN_CONSECUTIVE_SKIP_HARD_CAP - 1;
    let _ = cos_queue_v_min_continue(queue, 1);
    assert_eq!(
        queue.v_min_suspended_remaining, V_MIN_SUSPENSION_BATCHES,
        "Local hard-cap path must arm queue-level suspension",
    );

    // Now call Prepared drain. With suspension active, V_min check
    // is skipped (no throttle), and the item drains. Suspension is
    // consumed once at drain entry.
    let packet = vec![0u8; 1500];
    let prepared = test_prepared_item_in_umem(&mut umem, 0, &packet, libc::AF_INET as u8);
    cos_queue_push_back(queue, prepared);
    let suspension_before = queue.v_min_suspended_remaining;

    let mut scratch: Vec<PreparedTxRequest> = Vec::new();
    let mut free_tx: VecDeque<u64> = VecDeque::new();
    let mut pending_fill: VecDeque<u64> = VecDeque::new();
    let _ = drain_exact_prepared_items_to_scratch_flow_fair(
        queue,
        &mut scratch,
        &umem,
        &mut free_tx,
        &mut pending_fill,
        0,
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(
        !scratch.is_empty(),
        "Prepared drain under inherited Local-armed suspension must drain",
    );
    assert_eq!(
        queue.v_min_suspended_remaining,
        suspension_before - 1,
        "Prepared drain must consume exactly one queue-level suspension slot",
    );
}
