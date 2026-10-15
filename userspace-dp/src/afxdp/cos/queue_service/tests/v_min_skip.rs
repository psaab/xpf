//! queue_service V_min-skip tests (#13063): a #917 cross-worker V_min lag
//! skip on a selected shared_exact queue is QUEUE-LOCAL. It must neither
//! abort the whole `drain_shaped_tx` pass (the `Some(None)` interface-TX-
//! stall encoding) nor refund the Phase-1 waterfill epoch honor — the
//! refund re-selected the same lagged queue on every subsequent pass,
//! starving every other exact/non-exact queue on the worker and burning
//! the #941 `V_MIN_CONSECUTIVE_SKIP_HARD_CAP` in a single epoch.
//!
//! Source finding: deep-review D1-05 (run `review-work.2e4cldwkh1`).

use super::*;

/// 1 Gbps shared_exact guarantee class — the LOWEST rate, so the Phase-1
/// ascending walk honors it first every epoch.
fn vmin_skip_exact_queue(queue_id: u8, transmit_rate_bytes: u64) -> CoSQueueConfig {
    CoSQueueConfig {
        queue_id,
        forwarding_class: "exact".into(),
        priority: 5,
        transmit_rate_bytes,
        guarantee_enabled: true,
        exact: true,
        surplus_sharing: false,
        equal_flow_enforcement: false,
        equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
        surplus_weight: 1,
        buffer_bytes: 4 * 1024 * 1024,
        dscp_rewrite: None,
        codel_target_ns: 0,
    }
}

/// Non-exact guaranteed class for the fall-through probe: with every exact
/// queue V_min-skipped, `drain_shaped_tx` must service THIS queue via
/// `build_nonexact_cos_batch` instead of aborting the pass.
fn vmin_skip_nonexact_queue(queue_id: u8) -> CoSQueueConfig {
    CoSQueueConfig {
        queue_id,
        forwarding_class: "best-effort".into(),
        priority: 5,
        transmit_rate_bytes: 1_000_000 / 8,
        guarantee_enabled: true,
        exact: false,
        surplus_sharing: false,
        equal_flow_enforcement: false,
        equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
        surplus_weight: 1,
        buffer_bytes: 4 * 1024 * 1024,
        dscp_rewrite: None,
        codel_target_ns: 0,
    }
}

/// GuaranteeRate root with two shared_exact flow-fair queues (`idx 0` at
/// 1 Gbps, `idx 1` at 2 Gbps; ascending vec [0, 1]). Queue 0's owning
/// worker is 100 MB of virtual time AHEAD of its peer, so the #917 brake
/// must fire on its first pop; queue 1 sits at vtime 0, inside the lag
/// budget. Returns the root ready for `BindingWorker::new_for_cos_drain_test`.
fn vmin_skip_two_exact_queues_root() -> CoSInterfaceRuntime {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![
            vmin_skip_exact_queue(0, 125_000_000),
            vmin_skip_exact_queue(2, 250_000_000),
        ],
    );
    root.oversubscription_policy = CoSOversubscriptionPolicy::GuaranteeRate;
    root.oversubscription_guarantee_fraction = 1.0;
    root.exact_queues_by_rate_ascending = vec![0, 1];
    root.tokens = 1024 * 1024;
    root.nonempty_queues = 2;
    root.runnable_queues = 2;

    let lagged_floor = attach_test_vtime_floor(&mut root.queues[0], 2, 0);
    lagged_floor.slots[1].publish(0);
    test_flow_fair_state_mut(&mut root.queues[0]).queue_vtime = 100 * 1024 * 1024;

    let in_lag_floor = attach_test_vtime_floor(&mut root.queues[1], 2, 0);
    in_lag_floor.slots[1].publish(0);

    for queue_idx in [0usize, 1] {
        let queue = &mut root.queues[queue_idx];
        queue.hot.tokens = 128 * 1024;
        queue.hot.last_refill_ns = 1;
        queue.hot.runnable = true;
        for _ in 0..8 {
            cos_queue_push_back(
                queue,
                test_flow_cos_item((10_000 + 100 * queue_idx) as u16, 1500),
            );
        }
    }
    root
}

fn vmin_skip_binding(root: CoSInterfaceRuntime) -> BindingWorker {
    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![
            (0, test_queue_fast_path(false, 0, None, None)),
            (2, test_queue_fast_path(false, 0, None, None)),
        ],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path)
}

/// D1-05 probe 1: when the Phase-1-honored lowest-rate queue is V_min
/// throttled at its first pop, the SAME service call must move on and
/// service the next runnable exact queue — and the skipped queue must
/// KEEP its epoch honor (a skip is not a zero-TX refund).
#[test]
fn v_min_skipped_exact_queue_keeps_honor_and_services_next_exact_queue() {
    let mut binding = vmin_skip_binding(vmin_skip_two_exact_queues_root());

    let mut shared_recycles = Vec::new();
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let serviced = service_exact_guarantee_queue_direct_with_info(
        &mut binding,
        42,
        1,
        &mut shared_recycles,
        &mut tel,
    )
    .expect("the Phase-1 exact selection fired")
    .expect(
        "#13063: a V_min skip is queue-local — the pass must service the \
                 NEXT runnable exact queue instead of aborting as an interface \
                 TX stall",
    );
    assert_eq!(
        serviced.queue_idx, 1,
        "the in-lag exact queue q1 must be serviced on the same pass",
    );

    let root = binding.cos.cos_interfaces.get(&42).expect("cos root");
    assert_ne!(
        root.waterfill_honored_epoch_bits[0] & 0b1,
        0,
        "#13063: the V_min-skipped q0 must KEEP its Phase-1 epoch honor — the \
         queue is ahead in virtual time and must not re-enter Phase 1 this \
         epoch; refunding the honor re-selected q0 on every pass (the \
         starvation loop the finding describes)",
    );
    let counters = root.queues[0].telemetry.waterfill_counters;
    assert_eq!(
        counters.phase1_selected_no_progress, 0,
        "a V_min skip is not a zero-progress TX refund",
    );
    assert_eq!(
        root.queues[0].v_min.consecutive_v_min_skips, 1,
        "the brake counted exactly one skip for the epoch-honored selection",
    );
}

/// D1-05 probe 2: with the ONLY exact queue V_min-throttled and a runnable
/// non-exact guaranteed queue backed up behind it, `drain_shaped_tx` must
/// fall through to `build_nonexact_cos_batch` and service the non-exact
/// queue — not abort the whole pass.
#[test]
fn v_min_skipped_exact_queue_falls_through_to_nonexact_batch() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![
            vmin_skip_exact_queue(0, 125_000_000),
            vmin_skip_nonexact_queue(1),
        ],
    );
    root.oversubscription_policy = CoSOversubscriptionPolicy::GuaranteeRate;
    root.oversubscription_guarantee_fraction = 1.0;
    root.exact_queues_by_rate_ascending = vec![0];
    root.tokens = 1024 * 1024;
    root.nonempty_queues = 2;
    root.runnable_queues = 2;

    let lagged_floor = attach_test_vtime_floor(&mut root.queues[0], 2, 0);
    lagged_floor.slots[1].publish(0);
    test_flow_fair_state_mut(&mut root.queues[0]).queue_vtime = 100 * 1024 * 1024;
    root.queues[0].hot.tokens = 128 * 1024;
    root.queues[0].hot.last_refill_ns = 1;
    root.queues[0].hot.runnable = true;
    for _ in 0..8 {
        cos_queue_push_back(&mut root.queues[0], test_flow_cos_item(10_000, 1500));
    }

    root.queues[1].hot.tokens = 8 * 1500;
    root.queues[1].hot.last_refill_ns = 1;
    root.queues[1].hot.runnable = true;
    for _ in 0..8 {
        root.queues[1].hot.items.push_back(test_cos_item(1500));
    }

    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![
            (0, test_queue_fast_path(false, 0, None, None)),
            (1, test_queue_fast_path(false, 0, None, None)),
        ],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    let mut shared_recycles = Vec::new();
    let drained = drain_shaped_tx(&mut binding, 1, &mut shared_recycles).expect(
        "#13063: with every exact queue V_min-skipped the pass must fall \
         through and service the runnable non-exact queue, not abort",
    );
    assert_eq!(
        drained.queue_idx, 1,
        "the non-exact guaranteed queue is serviced on the fall-through",
    );
    assert_eq!(drained.queue_id, 1);
}

/// D1-05 hard-cap clause: repeated service passes over a persistently
/// V_min-lagged queue must skip it AT MOST ONCE PER EPOCH. Pre-fix, the
/// honor refund re-selected q0 on every pass, so 8 back-to-back throttle
/// decisions accumulated inside ~one epoch, armed the #941 hard-cap
/// suspension (`v_min_suspended_remaining = 1000`), and force-drained the
/// lagged queue — the fairness brake defeating itself.
#[test]
fn v_min_skip_does_not_burn_hard_cap_within_repeated_passes() {
    let mut binding = vmin_skip_binding(vmin_skip_two_exact_queues_root());

    let mut shared_recycles = Vec::new();
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let mut in_lag_serviced_passes = 0usize;
    for _pass in 0..8 {
        let out = service_exact_guarantee_queue_direct_with_info(
            &mut binding,
            42,
            1,
            &mut shared_recycles,
            &mut tel,
        );
        if let Some(serviced) = out {
            let serviced = serviced.expect(
                "#13063: a V_min skip must never surface as the interface-wide \
                 Some(None) TX-stall abort",
            );
            assert_ne!(
                serviced.queue_idx, 0,
                "the V_min-lagged q0 must not be force-serviced while it is \
                 ahead of the peer floor — that is the #941 hard-cap defeating \
                 the brake",
            );
            in_lag_serviced_passes += 1;
        }
    }
    assert!(
        in_lag_serviced_passes >= 1,
        "the in-lag exact queue q1 must keep receiving exact service across \
         the lagged epochs",
    );

    let root = binding.cos.cos_interfaces.get(&42).expect("cos root");
    assert_eq!(
        root.queues[0].v_min.v_min_suspended_remaining, 0,
        "#13063: per-epoch V_min skips (one honor per epoch) must not arm the \
         #941 hard-cap suspension — pre-fix the refund loop burned all 8 \
         consecutive-skip budget inside a single epoch",
    );
    assert!(
        root.queues[0].v_min.consecutive_v_min_skips < 8,
        "the lagged queue is skipped at most once per epoch, so the \
         consecutive-skip budget must not be exhausted",
    );
}

/// Even after an empty Phase-2 walk, the deferred queue may only be
/// reconsidered at the TIME boundary, not on every poll of the same
/// waterfill epoch. The next real epoch must restore eligibility.
#[test]
fn v_min_deferred_epoch_does_not_wrap_early_or_stick_forever() {
    let mut binding = vmin_skip_binding(vmin_skip_two_exact_queues_root());
    let mut shared_recycles = Vec::new();
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    for _ in 0..8 {
        let _ = service_exact_guarantee_queue_direct_with_info(
            &mut binding,
            42,
            1,
            &mut shared_recycles,
            &mut tel,
        );
    }
    let root = binding.cos.cos_interfaces.get(&42).expect("cos root");
    assert_eq!(root.queues[0].v_min.consecutive_v_min_skips, 1);
    assert!(root.waterfill_v_min_skipped_epoch);
    assert!(!root.waterfill_epoch_wrap_pending);

    let _ = service_exact_guarantee_queue_direct_with_info(
        &mut binding,
        42,
        1 + COS_GUARANTEE_VISIT_NS,
        &mut shared_recycles,
        &mut tel,
    );
    let root = binding.cos.cos_interfaces.get(&42).expect("cos root");
    assert_eq!(
        root.queues[0].v_min.consecutive_v_min_skips, 2,
        "real epoch boundary must reconsider the lagged queue"
    );
}

/// Phase-2 selections have no Phase-1 honor bit to retain. Deferral
/// must mark their sorted ordinal too or the descending walk retries
/// them on every poll and burns the V_min hard cap.
#[test]
fn v_min_skipped_phase2_queue_is_deferred_until_time_boundary() {
    let mut root = vmin_skip_two_exact_queues_root();
    root.oversubscription_guarantee_fraction = 0.001;
    root.queues[1].hot.runnable = false;
    root.runnable_queues = 1;
    let mut binding = vmin_skip_binding(root);
    let mut shared_recycles = Vec::new();
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    for _ in 0..8 {
        assert!(
            service_exact_guarantee_queue_direct_with_info(
                &mut binding,
                42,
                1,
                &mut shared_recycles,
                &mut tel,
            )
            .is_none(),
            "a queue-local Phase-2 skip must fall through, not stall TX"
        );
    }
    let root = binding.cos.cos_interfaces.get(&42).expect("cos root");
    assert_eq!(root.queues[0].v_min.consecutive_v_min_skips, 1);
    assert_eq!(root.queues[0].v_min.v_min_suspended_remaining, 0);
    assert_eq!(root.waterfill_honored_epoch_bits[0] & 1, 1);
    assert_eq!(
        root.queues[0]
            .telemetry
            .waterfill_counters
            .phase2_admissions,
        0,
        "a Phase-2 V_min skip did not transmit"
    );
    let _ = service_exact_guarantee_queue_direct_with_info(
        &mut binding,
        42,
        1 + COS_GUARANTEE_VISIT_NS,
        &mut shared_recycles,
        &mut tel,
    );
    assert_eq!(
        binding.cos.cos_interfaces[&42].queues[0]
            .v_min
            .consecutive_v_min_skips,
        2,
        "the next real epoch must reconsider the deferred Phase-2 queue"
    );
}

/// The Prepared flow-fair drain reports the same queue-local outcome as
/// Local. A prepared head from a lagged worker must not block a Local
/// exact queue on that interface.
#[test]
fn v_min_skipped_prepared_queue_services_next_exact_queue() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![
            vmin_skip_exact_queue(0, 125_000_000),
            vmin_skip_exact_queue(2, 250_000_000),
        ],
    );
    root.oversubscription_policy = CoSOversubscriptionPolicy::GuaranteeRate;
    root.oversubscription_guarantee_fraction = 1.0;
    root.exact_queues_by_rate_ascending = vec![0, 1];
    root.tokens = 1024 * 1024;
    root.nonempty_queues = 2;
    root.runnable_queues = 2;

    let floor = attach_test_vtime_floor(&mut root.queues[0], 2, 0);
    floor.slots[1].publish(0);
    test_flow_fair_state_mut(&mut root.queues[0]).queue_vtime = 100 * 1024 * 1024;
    let mut area = MmapArea::new(4096).expect("prepared test UMEM");
    let prepared = test_prepared_item_in_umem(&mut area, 0, &[0; 1500], libc::AF_INET as u8);
    cos_queue_push_back(&mut root.queues[0], prepared);
    for queue in &mut root.queues {
        queue.hot.tokens = 128 * 1024;
        queue.hot.last_refill_ns = 1;
        queue.hot.runnable = true;
    }
    cos_queue_push_back(&mut root.queues[1], test_flow_cos_item(10_100, 1500));
    let mut binding = vmin_skip_binding(root);
    let mut shared_recycles = Vec::new();
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let serviced = service_exact_guarantee_queue_direct_with_info(
        &mut binding,
        42,
        1,
        &mut shared_recycles,
        &mut tel,
    )
    .expect("exact class selected")
    .expect("Prepared V_min skip must not stall the Local exact queue");
    assert_eq!(serviced.queue_idx, 1);
    assert_eq!(
        binding.cos.cos_interfaces[&42].queues[0]
            .v_min
            .consecutive_v_min_skips,
        1,
    );
}
