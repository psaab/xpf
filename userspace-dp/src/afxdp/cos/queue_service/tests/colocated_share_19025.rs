//! #19025 / #19023: a non-exact instance on a worker that also carries an
//! exact class got a small fraction of its peers' share of the non-exact
//! residual, and nothing at all when the exact class was bounded by that
//! worker's TX capacity.
//!
//! Live (tcp, #18748 fix, failover-free X arm): in 1 of 3 runs the two
//! `iperf-uncapped` flows that shared a worker with an exact `iperf-24g`
//! flow ran at about 0.07 Gbit/s, with 10-11 s at or below 0.05 Gbit/s,
//! while each exact worker ran about 10 Gb/s and every other non-exact flow
//! about 1 Gb/s.
//!
//! Two layers (design note on #19025): the drain served a worker's exact
//! guarantee before anything else (L1), and every binding's non-exact
//! surplus drew from one first-come residual bucket that the busy exact
//! worker lost (L2). The property is the non-exact class's fairness contract
//! applied to the instance an exact class shares a worker with: while exact
//! demand holds the non-exact class to the residual (`shaping - configured
//! exact rate`), every backlogged non-exact instance is owed an equal part of
//! it. The fix (`queue_service::build_colocated_nonexact_turn_batch`) gives
//! the colocated instance one turn after each exact service on its worker,
//! drawing on the same interface-wide residual every other non-exact batch
//! draws on. The cells run the multi-worker simulation in
//! `cos_drain_sim.rs`. RED at the #18748 fold: R1 0.21-1.46 Gb/s against a
//! 2.125 floor, R2 and LX 0.000 for the whole window.
//!
//! The first version (f15d2f08bd) metered each binding with a private
//! `residual / n` part instead; review (Codex, #19025) found it credited the
//! same interval twice when n changed (1.5 x the residual), stranded parts a
//! slow binding could not spend, let a share larger than the worker take the
//! exact class's whole worker (0.00 Gb/s), and let an unsendable turn block
//! exact service. The `_19025` review cells below are RED on it.

use super::cos_drain_sim::*;
use super::*;

/// The colocated non-exact instance on every worker that carries exact
/// traffic gets at least half of an equal part of the residual, and is
/// never unserved for longer than `MAX_UNSERVED_NS`.
fn colocated_residual_share(arm: &Arm) -> impl Fn(&Outcome) -> Result<(), String> + '_ {
    move |o: &Outcome| {
        let instances = arm.nonexact_backlogged.iter().filter(|b| **b).count();
        let equal_part = residual_gbit(arm) / instances as f64;
        for w in 0..arm.workers {
            if arm.exact_offered_on(w) == 0 || !arm.nonexact_backlogged[w] {
                continue;
            }
            let got = o.nonexact_gbps(w);
            if got < 0.5 * equal_part {
                return Err(format!(
                    "worker {w}: colocated non-exact {got:.3} Gb/s < half of an equal part \
                     ({equal_part:.3} Gb/s) of the {:.1} Gb/s residual",
                    residual_gbit(arm)
                ));
            }
            if o.longest_unserved_ns[w] > MAX_UNSERVED_NS {
                return Err(format!(
                    "worker {w}: colocated non-exact unserved for {} ms > {} ms",
                    o.longest_unserved_ns[w] / 1_000_000,
                    MAX_UNSERVED_NS / 1_000_000
                ));
            }
        }
        Ok(())
    }
}

/// `shaping - configured exact rate` of the arm's single exact class.
fn residual_gbit(arm: &Arm) -> f64 {
    let reserved: u64 = arm.exact.iter().map(|class| class.rate_bytes).sum();
    SHAPING_BYTES.saturating_sub(reserved) as f64 * 8.0 / 1e9
}

/// #19025: the exact class is limited by its own rate (configured 8 Gb/s,
/// offered 12). It keeps its rate; the rest of the root is the non-exact
/// residual, and the instance on the exact worker must get its part of it
/// (17 / 4 = 4.25 Gb/s; floor 2.125). At f327be14d0: 0.25-0.31 Gb/s against
/// 5.7 for each peer.
#[test]
fn colocated_nonexact_shares_the_residual_beside_a_self_limited_exact_class_19025() {
    let arm = Arm::new(4, 15, 8, &[12]);
    assert_every_seed("R1 cfg8 off12 cap15", &arm, colocated_residual_share(&arm));
}

/// #19023: the exact class is bounded by its workers' TX capacity (offered
/// above what the worker can send, below its configured rate). Strict
/// guarantee-before-surplus on that worker left the colocated non-exact
/// instance nothing. At f327be14d0: 0 Gb/s, unserved for the whole window,
/// in both shapes.
#[test]
fn colocated_nonexact_is_served_beside_a_tx_capped_exact_class_19023() {
    let r2 = Arm::new(4, 10, 24, &[14]);
    assert_every_seed("R2 cfg24 off14 cap10", &r2, colocated_residual_share(&r2));
    let lx = Arm::new(8, 11, 24, &[12, 12]);
    assert_every_seed(
        "LX cfg24 off12+12 cap11",
        &lx,
        colocated_residual_share(&lx),
    );
}

/// What the colocated turn costs the exact class on a TX-capped worker. R2:
/// the 24 Gb/s class is held by its 10 Gb/s worker, the residual is 1 Gb/s.
/// Every non-exact byte, turn or not, comes out of the interface-wide
/// residual, so the exact class keeps at least its worker less the residual
/// (within 5%) and the colocated instance never gets more than the residual
/// (within 10%). Run at surplus weight 1 and 8: at weight 8 one turn is 8
/// frames, so a turn not bounded by the residual budget would show up here.
#[test]
fn tx_capped_exact_class_loses_at_most_the_residual_19025() {
    for weight in [1u32, 8] {
        let mut arm = Arm::new(4, 10, 24, &[14]);
        arm.nonexact_surplus_weight = weight;
        let residual = residual_gbit(&arm);
        let cap = 10.0;
        assert_every_seed(&format!("R2 bound weight {weight}"), &arm, |o| {
            let exact = o.exact_gbps();
            if exact < 0.95 * (cap - residual) {
                return Err(format!(
                    "exact class {exact:.2} Gb/s < 95% of the {cap:.0} Gb/s worker less the \
                     {residual:.2} Gb/s residual"
                ));
            }
            let colocated = o.nonexact_gbps(0);
            if colocated > 1.1 * residual {
                return Err(format!(
                    "colocated non-exact {colocated:.3} Gb/s > 110% of the {residual:.2} Gb/s \
                     residual: the turn is not bounded by the residual budget"
                ));
            }
            Ok(())
        });
    }
}

/// The residual is divided only among the bindings that want it. The exact
/// class is held by its worker's TX capacity (so its demand persists all
/// window) and only workers 1 and 2 carry non-exact backlog: each must get
/// about half of the 1 Gb/s residual, together the whole of it and no more.
/// A divisor that counted every binding (option B) would idle half of it; one
/// that let every binding draw the whole residual would double it.
#[test]
fn residual_is_divided_among_backlogged_bindings_only_19025() {
    let mut arm = Arm::new(4, 10, 24, &[14]);
    arm.nonexact_backlogged = vec![false, true, true, false];
    let residual = residual_gbit(&arm);
    assert_every_seed("R2 two-instance share cfg24 off14 cap10", &arm, |o| {
        let total = o.nonexact_total_gbps();
        if total < 0.9 * residual || total > 1.15 * residual {
            return Err(format!(
                "non-exact {total:.3} Gb/s outside 90-115% of the {residual:.2} Gb/s residual"
            ));
        }
        for w in [1, 2] {
            if o.nonexact_gbps(w) < 0.8 * residual / 2.0 {
                return Err(format!(
                    "worker {w}: {:.3} Gb/s < 80% of half the residual",
                    o.nonexact_gbps(w)
                ));
            }
        }
        Ok(())
    });
}

/// A zero residual (exact reservation equal to the root) leaves the
/// non-exact class no budget. That must not strand root credit (#18748
/// review R6 P1): the non-exact-only workers give their root back, the exact
/// worker's colocated turn finds no budget and does not go ahead of it, and
/// the exact class still gets its offered 10 Gb/s.
#[test]
fn zero_residual_owes_nothing_and_strands_no_root_19025() {
    let mut arm = Arm::new(3, 15, 25, &[10]);
    arm.root_burst_bytes = 96_000;
    assert_every_seed("P1 colocated cfg25 off10 burst96k", &arm, |o| {
        if o.exact_gbps() < 0.95 * 10.0 {
            return Err(format!(
                "exact class {:.2} Gb/s < 95% of its 10 Gb/s offered load",
                o.exact_gbps()
            ));
        }
        Ok(())
    });
}

/// The colocated turn goes ahead of THIS worker's exact class only, and only
/// once per exact service. Without a pending turn, or without local exact
/// demand, it stays out of the way, so the normal order (a non-exact
/// guarantee queue ahead of surplus, #18748's root release) applies; with
/// both it serves non-exact queues only, so a surplus-sharing exact queue
/// (here visited first) waits for the normal surplus pass.
#[test]
fn colocated_turn_needs_its_turn_and_local_exact_demand_and_serves_nonexact_only_19025() {
    let now = 2_000_000_000u64;
    let build = |turn: bool, local_exact_demand: bool| {
        // Queues: 0 exact guarantee (24 Gb/s), 1 exact surplus-sharing
        // (1 Gb/s), 2 non-exact. A peer publishes demand for queue 0, so the
        // residual is 1 Gb/s, and the shared residual has had a second to
        // fill.
        let mut root = lab_runtime(&[24 * GBIT, GBIT], SHAPING_BYTES / 100);
        root.tokens = 1_000_000;
        root.nonexact_turn = turn;
        root.queues[1].config.surplus_sharing = true;
        for idx in 0..3 {
            if idx == 0 && !local_exact_demand {
                continue;
            }
            let queue = &mut root.queues[idx];
            queue.hot.runnable = true;
            // The surplus-sharing exact queue holds no tokens of its own, so
            // it reserves nothing (the residual stays 1 Gb/s) yet is still a
            // surplus candidate: surplus draws on root tokens and its deficit.
            queue.hot.tokens = if idx == 1 { 0 } else { 100_000 };
            queue.hot.items.push_back(test_cos_item(FRAME));
            queue.hot.queued_bytes = FRAME as u64;
        }
        root.nonempty_queues = if local_exact_demand { 3 } else { 2 };
        root.runnable_queues = root.nonempty_queues;
        let backlog = Arc::new(SharedCoSExactBacklog::new(1));
        backlog.publish_demand(1, 1500, ExactDemandQueueMask::EMPTY.with_queue(0));
        // Open the shared residual's refill epoch a second ago.
        let _ = backlog.residual_surplus_budget(now - 1_000_000_000, GBIT, 1_000_000);
        let mut fast = test_cos_fast_interfaces(
            IFX,
            IFX,
            NONEXACT_QUEUE,
            vec![
                (
                    EXACT_QUEUE_IDS[0],
                    test_queue_fast_path(true, 0, None, None),
                ),
                (
                    EXACT_QUEUE_IDS[1],
                    test_queue_fast_path(true, 0, None, None),
                ),
                (NONEXACT_QUEUE, test_queue_fast_path(true, 0, None, None)),
            ],
            None,
            None,
        );
        fast.get_mut(&IFX).expect("fast path").shared_exact_backlog = Some(backlog);
        let fast_path = fast.get(&IFX).expect("fast path").clone();
        let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, IFX, root, fast_path);
        build_colocated_nonexact_turn_batch(&mut binding, IFX, now)
    };
    assert!(
        build(false, true).is_none(),
        "no turn pending (exact was not just served): the colocated batch must wait"
    );
    assert!(
        build(true, false).is_none(),
        "no local exact demand: the colocated turn must not go ahead of the normal order"
    );
    let batch = build(true, true).expect("a pending turn, local exact demand, residual: a batch");
    assert!(
        matches!(batch, CoSBatch::Local { queue_idx: 2, .. }),
        "the colocated turn must serve the non-exact queue, not the surplus-sharing exact one"
    );
}

/// #19025 on #18748 v3: only a binding with non-exact backlog claims a part
/// of the residual. #18748's Codex P1 cell found the gap: an exact-only
/// worker whose exact pass kept falling through to the non-exact build asked
/// for the residual budget with nothing to send and held a claim, so the
/// best-effort worker beside it got about half the residual (56,250,000
/// against 74,995,000 bytes for 2,500-byte packets). Here slot 0 holds exact
/// demand (24 of 25 Gb/s) and no non-exact backlog, and asks halfway through
/// an epoch. Slot 1, the only binding with non-exact work, must still be able
/// to spend the whole residual pool. Mutant: claim without non-exact backlog.
#[test]
fn a_binding_without_nonexact_backlog_claims_no_residual_19025() {
    let mut exact_only = lab_runtime(&[24 * GBIT], SHAPING_BYTES / 100);
    let (rate, burst) =
        residual_rate_and_burst(&exact_only, 24 * GBIT).expect("premise: exact demand");
    let backlog = SharedCoSExactBacklog::new(1);
    let epoch_start = 2_000_000_000u64;
    // A second of refill: the pool is the residual's whole burst.
    let _ = backlog.residual_surplus_budget(epoch_start - 1_000_000_000, rate, burst);
    let now = epoch_start + 500_000;
    assert!(
        exact_only
            .queues
            .iter()
            .all(|queue| queue.config.exact || cos_queue_is_empty(queue)),
        "premise: slot 0 has no non-exact backlog"
    );
    let _ = nonexact_surplus_budget_under_exact_demand(
        &mut exact_only,
        0,
        now,
        24 * GBIT,
        Some(&backlog),
    );
    let pool = backlog.residual_surplus_budget(now, rate, burst);
    assert!(pool > 0, "premise: the residual pool holds credit");
    assert_eq!(
        backlog.nonexact_surplus_budget(1, now, rate, burst),
        pool,
        "slot 0 asked with nothing non-exact queued and reserved part of the residual"
    );
}

/// #19025 on #18748 (the demand-gated pool floor): the colocated turn is
/// non-exact surplus, so on a root that takes root credit per batch it leaves
/// the pool floor `F` like every other non-exact batch. The turn runs only
/// with local exact demand, so the floor is always on for it. A 96 KB root
/// (`C = 24,000`, `F = 4,096`) whose available pool peers have drained to six
/// frames (9,000 bytes), a full residual, and a non-exact queue whose
/// 16-frame quantum could take them all: the turn's batch is at least one
/// frame and at most the pool less `F`. A turn that acquired against the
/// whole pool would take all six frames. Mutant: the turn takes the whole
/// pool.
#[test]
fn the_colocated_turn_leaves_the_pool_floor_19025() {
    use crate::afxdp::tx_frame_capacity;
    const POOL: u64 = 6 * FRAME as u64;
    let now = 2_000_000_000u64;
    let root_burst = 96_000;
    let root_lease = Arc::new(SharedCoSRootLease::new(SHAPING_BYTES, root_burst, 2));
    while root_lease.available_for_test(now) > POOL {
        let taken = root_lease.acquire(now, root_lease.available_for_test(now) - POOL);
        assert!(taken > 0, "premise: peers drain the pool");
        root_lease.consume(taken);
    }
    let mut root = lab_runtime(&[24 * GBIT], root_burst);
    root.shared_root_lease = Some(root_lease.clone());
    root.nonexact_turn = true;
    {
        let exact = &mut root.queues[0];
        exact.hot.runnable = true;
        exact.hot.tokens = 100_000;
        exact.hot.items.push_back(test_cos_item(FRAME));
        exact.hot.queued_bytes = FRAME as u64;
    }
    {
        let nonexact = &mut root.queues[1];
        nonexact.config.surplus_weight = 16;
        nonexact.hot.runnable = true;
        for _ in 0..16 {
            nonexact.hot.items.push_back(test_cos_item(FRAME));
        }
        nonexact.hot.queued_bytes = 16 * FRAME as u64;
    }
    root.nonempty_queues = 2;
    root.runnable_queues = 2;
    let backlog = Arc::new(SharedCoSExactBacklog::new(1));
    backlog.publish_demand(1, 1500, ExactDemandQueueMask::EMPTY.with_queue(0));
    // A second of refill: the residual budget is the residual's whole burst.
    let _ = backlog.residual_surplus_budget(now - 1_000_000_000, GBIT, 1_000_000);
    let mut fast = test_cos_fast_interfaces(
        IFX,
        IFX,
        NONEXACT_QUEUE,
        vec![
            (
                EXACT_QUEUE_IDS[0],
                test_queue_fast_path(true, 0, None, None),
            ),
            (NONEXACT_QUEUE, test_queue_fast_path(true, 0, None, None)),
        ],
        None,
        Some(root_lease.clone()),
    );
    fast.get_mut(&IFX).expect("fast path").shared_exact_backlog = Some(backlog);
    let fast_path = fast.get(&IFX).expect("fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, IFX, root, fast_path);
    let batch = build_colocated_nonexact_turn_batch(&mut binding, IFX, now)
        .expect("premise: a pending turn, local exact demand and a residual give a batch");
    let CoSBatch::Local {
        queue_idx, items, ..
    } = batch
    else {
        panic!("premise: a Local batch");
    };
    assert_eq!(queue_idx, 1, "premise: the turn serves the non-exact queue");
    let floor = (tx_frame_capacity() as u64).min(root_lease.max_total_leased() / 2);
    let bytes = items.len() as u64 * FRAME as u64;
    assert!(
        (FRAME as u64..=POOL - floor).contains(&bytes),
        "the colocated turn took {} frames ({bytes} bytes) of a {POOL}-byte pool; it may \
         take at most the pool less the floor {floor}",
        items.len()
    );
}

/// #19025 review (mutant T6 survived): the colocated turn is bounded by the
/// residual budget the binding holds, not just gated on it covering one
/// frame. The non-exact queue's surplus quantum is 16 frames (24,000 bytes)
/// and 16 frames are queued; the shared residual (1 Gb/s, a peer's 24 Gb/s
/// demand on a 25 Gb/s root) has refilled for 30 us, so the binding's
/// budget is 3,750 bytes. The turn's batch must be at least one frame and
/// at most that budget: two frames, where a turn that ignores its budget
/// takes the whole quantum (16 frames). Every throughput cell runs a weight
/// of 1, where one surplus batch is one frame, so none of them could see
/// this.
#[test]
fn the_colocated_turn_never_sends_past_the_residual_budget_19025() {
    let now = 2_000_000_000u64;
    let mut root = lab_runtime(&[24 * GBIT], SHAPING_BYTES / 100);
    root.tokens = 1_000_000;
    root.nonexact_turn = true;
    {
        let exact = &mut root.queues[0];
        exact.hot.runnable = true;
        exact.hot.tokens = 100_000;
        exact.hot.items.push_back(test_cos_item(FRAME));
        exact.hot.queued_bytes = FRAME as u64;
    }
    {
        let nonexact = &mut root.queues[1];
        nonexact.config.surplus_weight = 16;
        nonexact.hot.runnable = true;
        for _ in 0..16 {
            nonexact.hot.items.push_back(test_cos_item(FRAME));
        }
        nonexact.hot.queued_bytes = 16 * FRAME as u64;
    }
    root.nonempty_queues = 2;
    root.runnable_queues = 2;
    let backlog = Arc::new(SharedCoSExactBacklog::new(1));
    backlog.publish_demand(1, 1500, ExactDemandQueueMask::EMPTY.with_queue(0));
    // Open the shared residual's refill epoch 30 us ago: 3,750 bytes at
    // 1 Gb/s.
    let _ = backlog.residual_surplus_budget(now - 30_000, GBIT, 1_000_000);
    let mut fast = test_cos_fast_interfaces(
        IFX,
        IFX,
        NONEXACT_QUEUE,
        vec![
            (
                EXACT_QUEUE_IDS[0],
                test_queue_fast_path(true, 0, None, None),
            ),
            (NONEXACT_QUEUE, test_queue_fast_path(true, 0, None, None)),
        ],
        None,
        None,
    );
    fast.get_mut(&IFX).expect("fast path").shared_exact_backlog = Some(backlog);
    let fast_path = fast.get(&IFX).expect("fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, IFX, root, fast_path);
    let batch = build_colocated_nonexact_turn_batch(&mut binding, IFX, now)
        .expect("premise: a pending turn, local exact demand and a residual give a batch");
    let CoSBatch::Local {
        queue_idx, items, ..
    } = batch
    else {
        panic!("premise: a Local batch");
    };
    assert_eq!(queue_idx, 1, "premise: the turn serves the non-exact queue");
    let bytes = items.len() as u64 * FRAME as u64;
    assert!(
        (FRAME as u64..=3_750).contains(&bytes),
        "the colocated turn took {} frames ({bytes} bytes) against a 3,750-byte residual \
         budget",
        items.len()
    );
}

/// #19025 review (Codex F1): the non-exact surplus stays within the residual
/// while the SET of backlogged non-exact bindings changes. The 24 Gb/s exact
/// class is held by its 10 Gb/s worker, so its demand persists all window
/// and the non-exact class is held to the 1 Gb/s residual throughout.
/// Worker 1's non-exact load arrives open-loop below what it would get, so
/// its queue keeps emptying and refilling; worker 2 is always backlogged.
/// Varied over worker 1's offered load and the surplus weight. Private
/// per-binding parts refilled at `residual / n` with the CURRENT n credited
/// the same interval twice when n fell (worker 2 at n = 1 for time worker 1
/// had already been paid for at n = 2): up to 1.5 x the residual.
#[test]
fn nonexact_surplus_stays_within_the_residual_as_membership_changes_19025() {
    for weight in [1u32, 8] {
        for offered_fraction in [0.25f64, 0.5, 0.75] {
            let mut arm = Arm::new(4, 10, 24, &[14]);
            arm.nonexact_backlogged = vec![false, true, true, false];
            arm.nonexact_surplus_weight = weight;
            let residual = residual_gbit(&arm);
            arm.nonexact_offered_bytes[1] = Some((offered_fraction * residual * 1e9 / 8.0) as u64);
            let name = format!("membership w1 at {offered_fraction} x residual, weight {weight}");
            assert_every_seed(&name, &arm, |o| {
                let nonexact = o.nonexact_total_gbps();
                if nonexact > 1.1 * residual {
                    return Err(format!(
                        "non-exact {nonexact:.3} Gb/s > 110% of the {residual:.1} Gb/s residual"
                    ));
                }
                if o.exact_gbps() < 0.95 * 10.0 {
                    return Err(format!(
                        "exact class {:.2} Gb/s < 95% of its 10 Gb/s worker",
                        o.exact_gbps()
                    ));
                }
                Ok(())
            });
        }
    }
}

/// #19025 review (Codex F4): the residual is work-conserving across bindings
/// of unequal capacity. The 24 Gb/s exact class is held by its 20 Gb/s worker
/// (its demand persists), leaving a 1 Gb/s residual; worker 1 can send only
/// 0.1 Gb/s, worker 2 far more. What worker 1 cannot use must reach worker
/// 2: together they must use the residual. Fixed private parts left worker 2
/// at its half and idled 0.4 Gb/s.
#[test]
fn unused_residual_reaches_a_binding_that_can_spend_it_19025() {
    let mut arm = Arm::new(3, 20, 24, &[22]);
    arm.nonexact_backlogged = vec![false, true, true];
    arm.worker_tx_cap_override[1] = Some(GBIT / 10);
    let residual = residual_gbit(&arm);
    assert_every_seed("unequal capacity 0.1 / 20", &arm, |o| {
        let nonexact = o.nonexact_total_gbps();
        if nonexact < 0.9 * residual {
            return Err(format!(
                "non-exact {nonexact:.3} Gb/s < 90% of the {residual:.1} Gb/s residual: \
                 worker 1's unused part never reached worker 2"
            ));
        }
        Ok(())
    });
}

/// #19025 review (Codex task 4): the colocated turn must not take the exact
/// class's own worker. Non-exact backlog only on the exact worker, so the
/// whole 17 Gb/s residual is available to it, more than the 10 Gb/s worker;
/// the 8 Gb/s exact class must still get its rate there. The private-part
/// version gave it 0.00 Gb/s.
#[test]
fn exact_keeps_its_rate_when_the_residual_exceeds_its_worker_19025() {
    let mut arm = Arm::new(2, 10, 8, &[12]);
    arm.nonexact_backlogged = vec![true, false];
    assert_every_seed("colocated only, cfg8 off12 cap10", &arm, |o| {
        if o.exact_gbps() < 0.95 * 8.0 {
            return Err(format!(
                "exact class {:.2} Gb/s < 95% of its 8 Gb/s rate beside a residual larger \
                 than its worker",
                o.exact_gbps()
            ));
        }
        Ok(())
    });
}

/// #19025 review (Codex F2): a colocated non-exact turn that cannot be sent
/// must not block the exact queue. The binding has no free TX frames (no
/// completions return any), so the Local non-exact batch cannot transmit; its
/// exact queue holds Prepared packets that own their frames and can. With a
/// turn pending, the SAME drain must fall through to exact service: one
/// drain, both exact packets sent (they go in one batch). The private-part
/// version returned from the drain instead, every drain.
#[test]
fn an_unsendable_colocated_batch_does_not_block_exact_service_19025() {
    let now = 2_000_000_000u64;
    let backlog = Arc::new(SharedCoSExactBacklog::new(1));
    let mut fast = test_cos_fast_interfaces(
        IFX,
        IFX,
        NONEXACT_QUEUE,
        vec![
            (
                EXACT_QUEUE_IDS[0],
                test_queue_fast_path(true, 0, None, None),
            ),
            (NONEXACT_QUEUE, test_queue_fast_path(true, 0, None, None)),
        ],
        None,
        None,
    );
    fast.get_mut(&IFX).expect("fast path").shared_exact_backlog = Some(backlog.clone());
    let fast_path = fast.get(&IFX).expect("fast path").clone();
    // A full residual: the non-exact class is eligible ahead of exact if
    // anything lets it be.
    let _ = backlog.residual_surplus_budget(now - 1_000_000_000, GBIT, 1_000_000);
    let mut root = lab_runtime(&[24 * GBIT], SHAPING_BYTES / 100);
    root.tokens = 1_000_000;
    {
        let exact = &mut root.queues[0];
        exact.hot.runnable = true;
        exact.hot.tokens = 1_000_000;
        for frame in 0..2u64 {
            exact
                .hot
                .items
                .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
                    offset: frame << 12,
                    len: FRAME as u32,
                    recycle: PreparedTxRecycle::FreeTxFrame,
                    expected_ports: None,
                    expected_addr_family: libc::AF_INET as u8,
                    expected_protocol: PROTO_TCP,
                    flow_key: None,
                    egress_ifindex: IFX,
                    cos_queue_id: Some(EXACT_QUEUE_IDS[0]),
                    dscp_rewrite: None,
                    mirror_clone: false,
                    overlap_admissions: None,
                    enqueue_ns: now,
                }));
        }
        exact.hot.queued_bytes = 2 * FRAME as u64;
    }
    {
        let nonexact = &mut root.queues[1];
        nonexact.hot.runnable = true;
        nonexact
            .hot
            .items
            .push_back(sim_item(NONEXACT_QUEUE, 40_000, now));
        nonexact.hot.queued_bytes = FRAME as u64;
    }
    root.nonempty_queues = 2;
    root.runnable_queues = 2;
    // The exact class was just served: the colocated turn is pending.
    root.nonexact_turn = true;
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, IFX, root, fast_path);
    binding.tx_pipeline.free_tx_frames.clear();
    let mut recycles = Vec::new();
    let _ = drain_shaped_tx(&mut binding, now, &mut recycles);
    assert_eq!(
        queued_bytes(&binding, 0),
        0,
        "both Prepared exact packets must be sent by this drain: an unsendable Local \
         non-exact turn ahead of them must fall through to exact service"
    );
    assert_eq!(
        queued_bytes(&binding, 1),
        FRAME as u64,
        "premise: the non-exact packet is still queued (with no free TX frame it could not \
         be sent)"
    );
}
