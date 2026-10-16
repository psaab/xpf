use super::*;

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
    let queue = &mut root.queues[0];
    let floor = attach_test_vtime_floor(queue, 4, 2);

    // Set queue_vtime as if a drain has just committed.
    // #13657: publish only broadcasts with an active bucket; enqueue one.
    account_cos_queue_flow_enqueue(queue, Some(&test_session_key(1234, 5201)), 1500);
    test_flow_fair_state_mut(queue).queue_vtime = 12345;
    publish_committed_queue_vtime(Some(&*queue));
    assert_eq!(
        floor.slots[2].read(),
        Some(12345),
        "post-settle publish must write committed queue_vtime to the slot",
    );

    // Calling again with a higher vtime advances the slot
    // (idempotent / monotonic in normal flow).
    test_flow_fair_state_mut(queue).queue_vtime = 23456;
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
    let queue = &mut root.queues[0];
    enable_test_flow_fair(queue);
    // No floor attached; default state.
    assert!(queue.v_min.vtime_floor.is_none());
    test_flow_fair_state_mut(queue).queue_vtime = 99999;
    // Must not panic and must not publish anywhere.
    publish_committed_queue_vtime(Some(&*queue));
    // Sanity: still no floor, no observable effect.
    assert!(queue.v_min.vtime_floor.is_none());
}
