//! queue_service wakeup tests: wakeup-tick estimation, runnable restore
//! after retry, and local DSCP-rewrite preservation.

use super::*;

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
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
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
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
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
    root.queues[0].hot.tokens = 0;

    let wake_tick = estimate_cos_queue_wakeup_tick(
        root.tokens,
        root.shaping_rate_bytes,
        root.queues[0].hot.tokens,
        root.queues[0].transmit_rate_bytes(),
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
    root.queues[0].hot.tokens = 0;

    let wake_tick = estimate_cos_queue_wakeup_tick(
        root.tokens,
        root.shaping_rate_bytes,
        root.queues[0].hot.tokens,
        root.queues[0].transmit_rate_bytes(),
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
        config: crate::afxdp::types::CoSQueueConfigState {
            queue_id: 5,
            priority: 5,
            transmit_rate_bytes: 11_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            flow_fair_eligible: false,
            shared_exact: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        },
        hot: crate::afxdp::types::CoSQueueHotState {
            surplus_deficit: 0,
            tokens: 0,
            last_refill_ns: 0,
            queued_bytes: 0,
            runnable: false,
            parked: false,
            next_wakeup_tick: 0,
            wheel_level: 0,
            wheel_slot: 0,
            items: VecDeque::new(),
            local_item_count: 0,
            cos_demote_empty_settles: 0,
        },
        flow_fair_state: None,
        v_min: crate::afxdp::types::VMinQueueState {
            vtime_floor: None,
            worker_id: 0,
            consecutive_v_min_skips: 0,
            v_min_suspended_remaining: 0,
            v_min_hard_cap_overrides_scratch: 0,
            v_min_throttles_scratch: 0,
            v_min_suspended_batches_scratch: 0,
            v_min_suspension_window: 0,
            v_min_pop_count: 0,
        },
        telemetry: crate::afxdp::types::CoSQueueTelemetry {
            drop_counters: CoSQueueDropCounters::default(),
            waterfill_counters: CoSQueueWaterfillCounters::default(),
            owner_profile: CoSQueueOwnerProfile::new(),
            sojourn: crate::afxdp::types::CoSQueueSojourn::default(),
        },
        queue_lease_v8: None,
    };
    let mut retry = VecDeque::from([TxRequest {
        bytes: vec![0; 1500],
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
    }]);

    let retry_bytes = restore_cos_local_items_inner(&mut queue, &mut retry);

    assert_eq!(queue.hot.items.len(), 1);
    assert_eq!(retry_bytes, 1500);
    assert!(queue.hot.runnable);
    assert!(!queue.hot.parked);
}

#[test]
fn restore_cos_prepared_items_marks_queue_runnable_after_retry() {
    let mut queue = CoSQueueRuntime {
        config: crate::afxdp::types::CoSQueueConfigState {
            queue_id: 5,
            priority: 5,
            transmit_rate_bytes: 11_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            flow_fair_eligible: false,
            shared_exact: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        },
        hot: crate::afxdp::types::CoSQueueHotState {
            surplus_deficit: 0,
            tokens: 0,
            last_refill_ns: 0,
            queued_bytes: 0,
            runnable: false,
            parked: false,
            next_wakeup_tick: 0,
            wheel_level: 0,
            wheel_slot: 0,
            items: VecDeque::new(),
            local_item_count: 0,
            cos_demote_empty_settles: 0,
        },
        flow_fair_state: None,
        v_min: crate::afxdp::types::VMinQueueState {
            vtime_floor: None,
            worker_id: 0,
            consecutive_v_min_skips: 0,
            v_min_suspended_remaining: 0,
            v_min_hard_cap_overrides_scratch: 0,
            v_min_throttles_scratch: 0,
            v_min_suspended_batches_scratch: 0,
            v_min_suspension_window: 0,
            v_min_pop_count: 0,
        },
        telemetry: crate::afxdp::types::CoSQueueTelemetry {
            drop_counters: CoSQueueDropCounters::default(),
            waterfill_counters: CoSQueueWaterfillCounters::default(),
            owner_profile: CoSQueueOwnerProfile::new(),
            sojourn: crate::afxdp::types::CoSQueueSojourn::default(),
        },
        queue_lease_v8: None,
    };
    let mut retry = VecDeque::from([PreparedTxRequest {
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
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    }]);

    let retry_bytes = restore_cos_prepared_items_inner(&mut queue, &mut retry);

    assert_eq!(queue.hot.items.len(), 1);
    assert_eq!(retry_bytes, 1500);
    assert!(queue.hot.runnable);
    assert!(!queue.hot.parked);
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
        1500, 0, true,
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
        1500, 0, true,
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
        1500, 0, false,
    );
    assert!(wake_tick.is_some());
}

