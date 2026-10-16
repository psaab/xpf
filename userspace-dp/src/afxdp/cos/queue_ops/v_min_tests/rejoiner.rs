use super::*;

/// A 10 Gb/s shared_exact queue config used by the R-7 reseed tests.
/// Above `COS_SHARED_EXACT_MIN_RATE_BYTES`; a nonzero rate so
/// `cos_queue_v_min_continue` does not early-return on the #2981
/// unshaped path.
fn r7_exact_queue(queue_id: u8) -> CoSQueueConfig {
    CoSQueueConfig {
        queue_id,
        forwarding_class: "iperf-c".into(),
        priority: 5,
        transmit_rate_bytes: 10_000_000_000 / 8,
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

/// #4254 (R-7): `peer_frontier_vtime` returns the MAX participating peer
/// slot, excludes the caller's own slot, and returns `None` when no peer
/// participates.
#[test]
fn vmin_peer_frontier_vtime_max_excludes_self_and_none_when_empty() {
    let floor = SharedCoSQueueVtimeFloor::new(4);
    // No peers participating yet -> None (cold-start / full reset).
    assert_eq!(
        floor.peer_frontier_vtime(1),
        None,
        "no participating peer -> None (seed stays 0)",
    );
    // Populate three peers; worker 1 is the caller (self-excluded).
    floor.slots[0].publish(500);
    floor.slots[1].publish(999_999); // caller's own slot — must be ignored
    floor.slots[2].publish(4_000);
    floor.slots[3].publish(1_500);
    assert_eq!(
        floor.peer_frontier_vtime(1),
        Some(4_000),
        "frontier must be the MAX participating peer slot, excluding self",
    );
    // Vacate the max peer; frontier falls back to the next-highest peer.
    floor.slots[2].vacate();
    assert_eq!(
        floor.peer_frontier_vtime(1),
        Some(1_500),
        "vacated max peer drops out of the frontier reduction",
    );
}

/// #4254 (R-7): a shared_exact worker rebuilt via the production
/// `promote_cos_queue_flow_fair` path seeds its fresh `queue_vtime` to
/// the current peer frontier instead of 0. Cold start (no peer) keeps 0.
///
/// RED-on-revert: dropping the reseed leaves `queue_vtime == 0`, so the
/// first assertion (`== FRONTIER`) fails.
#[test]
fn vmin_r7_rejoiner_seeds_to_peer_frontier_not_zero() {
    const FRONTIER: u64 = 100 * 1024 * 1024 * 1024; // ~100 GB cumulative

    // Shared floor: 2 workers. Worker 0 (survivor) is terabytes ahead.
    let floor = Arc::new(SharedCoSQueueVtimeFloor::new(2));
    floor.slots[0].publish(FRONTIER);

    // Worker 1 rebuilds its runtime through the production promotion
    // path with the reused floor attached.
    let mut rejoiner = test_cos_runtime_with_queues(10_000_000_000 / 8, vec![r7_exact_queue(0)]);
    let fast = vec![test_queue_fast_path_for_promotion_with_floor(
        true,
        Some(Arc::clone(&floor)),
    )];
    apply_cos_queue_flow_fair_promotion(&mut rejoiner, &fast, 1);

    assert!(
        rejoiner.queues[0].shared_exact(),
        "fixture must be shared_exact"
    );
    assert_eq!(
        test_flow_fair_state(&rejoiner.queues[0]).queue_vtime,
        FRONTIER,
        "R-7: a rejoining shared_exact worker MUST seed queue_vtime to the \
         peer frontier, not 0 (RED on revert)",
    );

    // Cold start: no participating peer -> seed stays 0.
    let cold_floor = Arc::new(SharedCoSQueueVtimeFloor::new(2));
    let mut cold = test_cos_runtime_with_queues(10_000_000_000 / 8, vec![r7_exact_queue(0)]);
    let cold_fast = vec![test_queue_fast_path_for_promotion_with_floor(
        true,
        Some(Arc::clone(&cold_floor)),
    )];
    apply_cos_queue_flow_fair_promotion(&mut cold, &cold_fast, 1);
    assert_eq!(
        test_flow_fair_state(&cold.queues[0]).queue_vtime,
        0,
        "cold start (no participating peer) must keep queue_vtime == 0",
    );
}

/// #4254 (R-7) — the T-7 trap scenario end-to-end. A surviving peer
/// terabytes ahead must NOT be trapped in the throttle duty cycle after
/// a peer worker resets and rejoins. With the reseed, the rejoiner's
/// first publish lands on the frontier, so the survivor's V_min gate
/// continues.
///
/// RED-on-revert: without the reseed the rejoiner publishes ~0, the
/// survivor's V_min collapses to 0, and its gate throttles — the final
/// `assert!(cont)` fails.
#[test]
fn vmin_r7_rejoiner_does_not_trap_surviving_peer() {
    const FRONTIER: u64 = 100 * 1024 * 1024 * 1024;

    let floor = Arc::new(SharedCoSQueueVtimeFloor::new(2));
    // Survivor (worker 0) publishes its real, terabytes-ahead vtime.
    floor.slots[0].publish(FRONTIER);

    // Rejoiner (worker 1) rebuilds + seeds, then has a live bucket before
    // publishing its committed frontier. The guard intentionally skips
    // empty workers so rejoin tests model a participating worker explicitly.
    let mut rejoiner = test_cos_runtime_with_queues(10_000_000_000 / 8, vec![r7_exact_queue(0)]);
    let fast = vec![test_queue_fast_path_for_promotion_with_floor(
        true,
        Some(Arc::clone(&floor)),
    )];
    apply_cos_queue_flow_fair_promotion(&mut rejoiner, &fast, 1);
    account_cos_queue_flow_enqueue(
        &mut rejoiner.queues[0],
        Some(&test_session_key(1234, 5201)),
        1500,
    );
    publish_committed_queue_vtime(Some(&rejoiner.queues[0]));
    // Post-fix the rejoiner's slot reflects the frontier, not ~0.
    assert_eq!(
        floor.slots[1].read(),
        Some(FRONTIER),
        "rejoiner's first publish must broadcast the seeded frontier",
    );

    // Build the survivor's queue on worker 0 sharing the same floor.
    let mut survivor = test_cos_runtime_with_queues(10_000_000_000 / 8, vec![r7_exact_queue(0)]);
    {
        let q = &mut survivor.queues[0];
        enable_test_flow_fair(q);
        q.v_min.vtime_floor = Some(Arc::clone(&floor));
        q.v_min.worker_id = 0;
        q.config.shared_exact = true;
        test_flow_fair_state_mut(q).queue_vtime = FRONTIER;
    }

    // The survivor reads the rejoiner's slot (== FRONTIER) -> V_min at
    // the frontier -> its own vtime is within LAG -> continue (no trap).
    assert!(
        cos_queue_v_min_continue(&mut survivor.queues[0], 1),
        "R-7: a surviving peer MUST NOT be trapped by a reset/rejoining \
         worker — the reseed keeps the rejoiner's published vtime on the \
         frontier (RED on revert: rejoiner publishes ~0 -> throttle)",
    );
    assert_eq!(
        survivor.queues[0].v_min.v_min_throttles_scratch, 0,
        "no throttle should have been recorded for the survivor",
    );
}

/// #4254 (R-7): the reseed distinguishes a rejoining-0 worker from a
/// GENUINE laggard. A genuine laggard (a live peer with a real, lower
/// published vtime — never reconstructed) must remain the cross-worker
/// V_min that everyone defers to. Seeding the rejoiner to the MAX peer
/// (frontier) — not the min — guarantees it never becomes a new
/// artificial low, and the seeded rejoiner still defers to the genuine
/// laggard.
#[test]
fn vmin_r7_seeded_rejoiner_still_defers_to_genuine_laggard() {
    const FRONTIER: u64 = 100 * 1024 * 1024 * 1024;
    // A genuine laggard: real, lower cumulative vtime, well below the
    // frontier and below FRONTIER minus any plausible lag.
    const LAGGARD: u64 = 40 * 1024 * 1024 * 1024;

    // 3 workers: 0 = survivor-high, 2 = genuine laggard, 1 = rejoiner.
    let floor = Arc::new(SharedCoSQueueVtimeFloor::new(3));
    floor.slots[0].publish(FRONTIER);
    floor.slots[2].publish(LAGGARD);

    let mut rejoiner = test_cos_runtime_with_queues(10_000_000_000 / 8, vec![r7_exact_queue(0)]);
    let fast = vec![test_queue_fast_path_for_promotion_with_floor(
        true,
        Some(Arc::clone(&floor)),
    )];
    apply_cos_queue_flow_fair_promotion(&mut rejoiner, &fast, 1);

    // Seed is the MAX peer (frontier), NOT the laggard's low value and
    // NOT 0.
    assert_eq!(
        test_flow_fair_state(&rejoiner.queues[0]).queue_vtime,
        FRONTIER,
        "rejoiner must seed to the frontier (max peer), not the genuine \
         laggard's lower vtime and not 0",
    );

    // Evaluate the rejoiner's OWN gate: with peers {slot0=FRONTIER,
    // slot2=LAGGARD}, V_min == LAGGARD. The rejoiner sits at FRONTIER,
    // far past LAGGARD + lag, so it MUST throttle — i.e. it defers to the
    // genuine laggard. The fix does not let a rejoiner ignore a
    // legitimately-behind peer.
    assert!(
        !cos_queue_v_min_continue(&mut rejoiner.queues[0], 1),
        "the seeded rejoiner MUST still throttle (defer) to a genuine \
         laggard peer whose real vtime is the cross-worker V_min",
    );
}
