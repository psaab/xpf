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
/// backlog, it stays out of the way, so the normal order (a non-exact
/// guarantee queue ahead of surplus, #18748's root release) applies; with
/// both it serves non-exact queues only, so a surplus-sharing exact queue
/// (here visited first) waits for the normal surplus pass.
///
/// #19100 v6.1 (C3): "local exact demand" was cached own tokens covering the
/// head. Codex v6 P1-1 showed that predicate starves the minimum turn: the
/// exact selector tops a token-empty leased exact queue up and serves it
/// first (`selectors.rs`, `maybe_top_up_cos_queue_lease`), and every exact
/// queue with a rate gets a v8 lease (`coordinator/cos_leases.rs`). That
/// holds for a surplus-sharing exact queue too, so its token-empty backlog
/// now earns the one-packet minimum turn (and only that: the funded turn
/// still needs serviceable demand); with no exact backlog at all, no turn.
#[test]
fn colocated_turn_needs_its_turn_and_local_exact_demand_and_serves_nonexact_only_19025() {
    let now = 2_000_000_000u64;
    let build = |turn: bool, local_exact_demand: bool, sharing_backlog: bool| {
        // Queues: 0 exact guarantee (24 Gb/s), 1 exact surplus-sharing
        // (1 Gb/s), 2 non-exact. A peer publishes demand for queue 0, so the
        // residual is 1 Gb/s, and the shared residual has had a second to
        // fill.
        let mut root = lab_runtime(&[24 * GBIT, GBIT], SHAPING_BYTES / 100);
        root.tokens = 1_000_000;
        root.nonexact_turn = turn;
        root.queues[1].config.surplus_sharing = true;
        for idx in 0..3 {
            if (idx == 0 && !local_exact_demand) || (idx == 1 && !sharing_backlog) {
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
        root.nonempty_queues = 1 + usize::from(local_exact_demand) + usize::from(sharing_backlog);
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
        build(false, true, true).is_none(),
        "no turn pending (exact was not just served): the colocated batch must wait"
    );
    assert!(
        build(true, false, false).is_none(),
        "no local exact backlog: the colocated turn must not go ahead of the normal order"
    );
    let minimum = build(true, false, true)
        .expect("a token-empty surplus-sharing exact backlog: the minimum turn (Codex v6 P1-1)");
    let CoSBatch::Local { queue_idx, items, .. } = minimum else {
        panic!("premise: a Local batch");
    };
    assert_eq!(queue_idx, 2, "the minimum turn serves the non-exact queue");
    assert_eq!(
        items.len(),
        1,
        "without serviceable exact demand only the one-packet minimum goes ahead"
    );
    let batch = build(true, true, true).expect("a pending turn, local exact demand, residual: a batch");
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
    // Codex v6 P2 (8) / v6.1 P2-8: a witness that FOLLOWS the attempt: the
    // turn batch was built and handed to submit in this drain, so a turn that
    // returns before building cannot pass.
    assert_eq!(
        binding.cos.cos_interfaces.get(&IFX).expect("root").v61_test.turn_submits,
        1,
        "witness: the colocated turn was built and submitted in this drain"
    );
}

/// #19100 v6.1 fixture: a colocated turn root whose exact queue is backlogged
/// with `exact_tokens` of its own and whose non-exact queue holds `n`
/// packets of `len` bytes; a peer publishes demand for the exact queue.
fn v61_turn_binding(exact_tokens: u64, n: usize, len: usize) -> BindingWorker {
    let mut root = lab_runtime(&[24 * GBIT], SHAPING_BYTES / 100);
    root.tokens = 1_000_000;
    root.nonexact_turn = true;
    {
        let exact = &mut root.queues[0];
        exact.hot.runnable = true;
        exact.hot.tokens = exact_tokens;
        for _ in 0..16 {
            exact.hot.items.push_back(test_cos_item(FRAME));
        }
        exact.hot.queued_bytes = 16 * FRAME as u64;
    }
    {
        let nonexact = &mut root.queues[1];
        nonexact.config.surplus_weight = 16;
        nonexact.hot.runnable = true;
        for _ in 0..n {
            nonexact.hot.items.push_back(test_cos_item(len));
        }
        nonexact.hot.queued_bytes = (n * len) as u64;
    }
    root.nonempty_queues = 2;
    root.runnable_queues = 2;
    let backlog = Arc::new(SharedCoSExactBacklog::new(1));
    backlog.publish_demand(1, 1500, ExactDemandQueueMask::EMPTY.with_queue(0));
    let mut fast = test_cos_fast_interfaces(
        IFX,
        IFX,
        NONEXACT_QUEUE,
        vec![
            (EXACT_QUEUE_IDS[0], test_queue_fast_path(true, 0, None, None)),
            (NONEXACT_QUEUE, test_queue_fast_path(true, 0, None, None)),
        ],
        None,
        None,
    );
    fast.get_mut(&IFX).expect("fast path").shared_exact_backlog = Some(backlog);
    let fast_path = fast.get(&IFX).expect("fast path").clone();
    BindingWorker::new_for_cos_drain_test(0, 0, IFX, root, fast_path)
}

/// #19100 v6.1 (Codex v6 P1-1): the minimum turn does not need cached exact
/// tokens. The exact queue is backlogged but holds none of its own (the
/// selector replenishes them only afterwards), so it is not serviceable and
/// the demand mask is empty. The epoch's minimum turn must still go: exactly
/// one packet. Mutant: return on an empty demand mask before the minimum.
#[test]
fn a_minimum_turn_needs_no_cached_exact_tokens_19100() {
    let now = 2_000_000_000u64 + 50_000;
    let mut binding = v61_turn_binding(0, 16, 64);
    let batch = build_colocated_nonexact_turn_batch(&mut binding, IFX, now)
        .expect("the epoch's minimum turn, with the exact queue token-empty");
    let CoSBatch::Local { queue_idx, items, .. } = batch else {
        panic!("premise: a Local batch");
    };
    assert_eq!(queue_idx, 1, "premise: the turn serves the non-exact queue");
    assert_eq!(items.len(), 1, "the minimum turn is one packet");
}

/// #19100 v6.1 (Codex v6 P1-3): a minimum turn the credits did not cover is
/// carried as DEBT, so later exact service repays it before any credit-funded
/// turn. With no credit earned, a minimum turn that commits leaves the byte
/// credit negative by its bytes and the opportunity credit negative by its
/// packet. Mutants (both settle arms each): the turn is not charged; the byte
/// debt is forgiven (floored at zero); the opportunity debt is forgiven.
#[test]
fn a_minimum_turn_is_carried_as_debt_19100() {
    let now = 2_000_000_000u64 + 50_000;
    let mut binding = v61_turn_binding(100_000, 16, FRAME);
    let batch = build_colocated_nonexact_turn_batch(&mut binding, IFX, now)
        .expect("premise: the minimum turn");
    let mut recycles = Vec::new();
    assert!(
        submit_cos_batch(&mut binding, IFX, batch, now, &mut recycles),
        "premise: the minimum turn commits"
    );
    let root = binding.cos.cos_interfaces.get(&IFX).expect("root");
    assert!(
        root.v61_byte_credit == -((FRAME as i64) << V61_CREDIT_SHIFT),
        "byte credit {} after an uncovered minimum turn of {FRAME} bytes: must carry the debt",
        root.v61_byte_credit
    );
    assert!(
        root.v61_opp_credit == -(1i64 << V61_CREDIT_SHIFT),
        "opportunity credit {} after an uncovered one-packet minimum turn: must carry exactly \
         its one committed packet as debt (Codex v6.1 P2-5)",
        root.v61_opp_credit
    );
    assert!(!root.v6_inflight_turn, "the turn tag is consumed at settlement");
}

/// #19100 v6.1 (C3, Codex v6 P1-3): the minimum turn waits out its debt on
/// BOTH credits, so its sustained cost stays inside the credit bound. A fresh
/// epoch, a pending turn, a token-empty exact backlog (no serviceable demand,
/// so no funded turn) and non-exact backlog: with either credit below zero
/// no turn is built; with both at zero the minimum is. Mutants: the minimum
/// ignores the byte debt; it ignores the opportunity debt.
#[test]
fn a_minimum_turn_waits_out_its_debt_19100() {
    let now = 2_000_000_000u64 + 50_000;
    for (byte, opp, expect) in [(-1i64, 0i64, false), (0, -1, false), (0, 0, true)] {
        let mut binding = v61_turn_binding(0, 16, 64);
        {
            let root = binding.cos.cos_interfaces.get_mut(&IFX).expect("root");
            root.v61_byte_credit = byte;
            root.v61_opp_credit = opp;
        }
        let built = build_colocated_nonexact_turn_batch(&mut binding, IFX, now).is_some();
        assert_eq!(
            built, expect,
            "byte credit {byte}, opportunity credit {opp}: minimum turn built = {built}"
        );
    }
}

/// #19100 v6.1 (C3): a turn that cannot be built leaves the non-exact queue
/// as it found it. With no root credit no batch is built, and the non-exact
/// queue must stay runnable: parked, it would lose the ordinary pass it is
/// owed until its wake tick. (This is state hygiene. The #18748 floor-cell
/// regression was the floor-hold stamp, pinned by
/// `a_turn_leaves_the_pool_floor_hold_alone_19100`; removing the park alone
/// did not move it.) Mutant: the turn selects with the ordinary park.
#[test]
fn a_failed_turn_attempt_leaves_the_nonexact_queue_runnable_19100() {
    let now = 2_000_000_000u64 + 50_000;
    let mut binding = v61_turn_binding(0, 16, FRAME);
    binding.cos.cos_interfaces.get_mut(&IFX).expect("root").tokens = 0;
    assert!(
        build_colocated_nonexact_turn_batch(&mut binding, IFX, now).is_none(),
        "premise: no root credit, no turn"
    );
    let root = binding.cos.cos_interfaces.get(&IFX).expect("root");
    assert!(
        root.queues[1].hot.runnable && !root.queues[1].hot.parked,
        "a failed turn attempt parked the non-exact queue"
    );
    assert!(!root.v6_inflight_turn, "a failed turn attempt left a turn tag");
}

/// #19100 v6.1 (C3): a turn reads the #18748 pool floor and leaves its hold
/// alone. The hold runs for `COS_EXACT_FLOOR_HOLD_NS` after an ordinary
/// non-exact build last saw exact work; a turn is attempted after every exact
/// service, so a turn that stamped `exact_work_seen_ns` kept the floor on
/// without a gap and best-effort parked against it (#18748's floor cell at a
/// 12 KB root: 1.64 against 3.66 Gb/s). On a per-batch root (a root lease
/// attached), a turn is built and the stamp must be unchanged. Mutant: the
/// turn stamps the hold (`cos_exact_floor_on(root, true, now)`).
#[test]
fn a_turn_leaves_the_pool_floor_hold_alone_19100() {
    let now = 2_000_000_000u64 + 50_000;
    let mut binding = v61_turn_binding(0, 16, FRAME);
    let stamp = now - 5_000_000;
    {
        let root = binding.cos.cos_interfaces.get_mut(&IFX).expect("root");
        root.shared_root_lease = Some(Arc::new(SharedCoSRootLease::new(SHAPING_BYTES, 1_000_000, 1)));
        root.exact_work_seen_ns = stamp;
    }
    assert!(
        cos_root_credit_per_batch(binding.cos.cos_interfaces.get(&IFX).expect("root")),
        "premise: a per-batch root"
    );
    let _ = build_colocated_nonexact_turn_batch(&mut binding, IFX, now)
        .expect("premise: the minimum turn is built");
    assert_eq!(
        binding.cos.cos_interfaces.get(&IFX).expect("root").exact_work_seen_ns,
        stamp,
        "the turn refreshed the pool floor's hold"
    );
}

/// #19100 v6.1 (Codex v6 P1-5): the turn tag rides with its batch. A turn
/// that never reaches settlement (Retry/Drop) must not leave the tag for the
/// next ordinary batch, which would then skip the shared-pool debit. Build a
/// turn, do not settle it, then build an ordinary non-exact batch: the tag
/// must now say "not a turn". Mutant: the ordinary build leaves the tag.
#[test]
fn an_unsettled_turn_does_not_tag_the_next_ordinary_batch_19100() {
    let now = 2_000_000_000u64 + 50_000;
    let mut binding = v61_turn_binding(100_000, 16, FRAME);
    let _turn = build_colocated_nonexact_turn_batch(&mut binding, IFX, now)
        .expect("premise: a turn is built");
    assert!(
        binding.cos.cos_interfaces.get(&IFX).expect("root").v6_inflight_turn,
        "premise: the turn is tagged"
    );
    // The turn is dropped unsettled (Retry/Drop). The exact queue is drained
    // so the ordinary build reaches the non-exact queue.
    {
        let root = binding.cos.cos_interfaces.get_mut(&IFX).expect("root");
        root.queues[0].hot.items.clear();
        root.queues[0].hot.queued_bytes = 0;
        root.nonempty_queues = 1;
    }
    // The peer's exact demand ends too, so the ordinary build is unmetered
    // surplus (an empty residual pool would otherwise give it nothing).
    binding
        .cos
        .cos_fast_interfaces
        .get(&IFX)
        .and_then(|fast| fast.shared_exact_backlog.as_ref())
        .expect("backlog")
        .publish_demand(1, 0, ExactDemandQueueMask::EMPTY);
    let _ordinary = build_nonexact_cos_batch(&mut binding, IFX, now + 1_000)
        .expect("premise: an ordinary non-exact batch");
    assert!(
        !binding.cos.cos_interfaces.get(&IFX).expect("root").v6_inflight_turn,
        "an ordinary batch built after an unsettled turn carried the turn tag"
    );
}

/// #19100 v6.2 (Codex v6.1 P1-1): the minimum turn's debt is repaid under
/// alternating exact denominators. Codex's schedule: a 125,000,000 B/s root;
/// two exact classes configured at 124,999,000 and 124,998,000 B/s, only one
/// backlogged at a time; one 64-byte exact commit each, alternating. Every
/// commit changes the accrual denominator. With whole-byte accrual and the
/// remainder reset at each change, each commit earned floor(64 x 1,000 /
/// 124,999,000) = 0 bytes, and after the first minimum the class never got
/// another. In Q32 each commit earns 64 x R / (S - R) bytes (less 2^-32), so
/// the debt of one 1,500-byte, one-packet minimum is repaid within the
/// analytic number of commit pairs, plus 1%. Mutant: accrual floored to whole
/// bytes per commit.
#[test]
fn a_minimum_survives_alternating_exact_denominators_19100() {
    const ROOT: u64 = 125_000_000;
    let mut root = lab_runtime(&[124_999_000, 124_998_000], 96_000);
    root.shaping_rate_bytes = ROOT;
    assert!(
        root.queues[0].hot.items.is_empty() && root.queues[1].hot.items.is_empty(),
        "premise: only the committing exact class is counted"
    );
    // The epoch's minimum committed: 1,500 bytes and one packet of debt.
    v61_settle_turn(&mut root, FRAME as u64, 1);
    assert!(!v61_minimum_credits(&root), "premise: the minimum left debt");
    let per_pair = 64.0 * 1_000.0 / 124_999_000.0 + 64.0 * 2_000.0 / 124_998_000.0;
    let bound_pairs = (FRAME as f64 / per_pair * 1.01).ceil() as u64;
    let mut pairs = 0u64;
    while !v61_minimum_credits(&root) {
        assert!(
            pairs <= bound_pairs,
            "after {pairs} alternating commit pairs (bound {bound_pairs}) the minimum's debt \
             is unpaid: byte credit {} B, opportunity credit {} packets",
            root.v61_byte_credit >> V61_CREDIT_SHIFT,
            root.v61_opp_credit >> V61_CREDIT_SHIFT
        );
        v61_accrue_turn_credit(&mut root, 0, 64, 1);
        v61_accrue_turn_credit(&mut root, 1, 64, 1);
        pairs += 1;
    }
}

/// #19100 v6.2 (Codex v6.1 P1-1): subsequent minima in REAL drains under
/// alternating exact denominators, Codex's arrival schedule. One 64-byte exact
/// arrival before each exact-serving drain (only when both exact queues are
/// empty, so one class is backlogged at a time), alternating between two
/// leased exact classes
/// (124,050,000 and 124,000,000 B/s on a 125,000,000 B/s root, so a commit
/// earns 0.49 or 0.52 bytes of credit: under one byte, a different
/// denominator each commit). Each exact queue empties and returns its tokens,
/// so the next turn check sees no serviceable demand: funded turns are
/// unavailable, and class 11 (continuously backlogged, 1,500-byte packets) is
/// served only by minima. Over 30 ms the minimum must recur: Q32 accrual
/// repays a minimum in about 3,000 commits (3 ms). Whole-byte accrual earned
/// nothing and gave one minimum. These are SCALED rates, chosen so repayment
/// fits in 30 ms; Codex's exact rates are in the accounting cells
/// (`a_minimum_survives_alternating_exact_denominators_19100`,
/// `the_minimum_keeps_earning_at_one_byte_per_second_residuals_19100`).
/// Progress is asserted on COMMITTED minimum packets and class-11 bytes, not
/// on builds (Codex v6.2: failed submissions would satisfy a build count).
/// Mutant: accrual floored to whole bytes per commit.
#[test]
fn repeated_minima_survive_alternating_exact_classes_in_real_drains_19100() {
    const ROOT: u64 = 125_000_000;
    let rates = [124_050_000u64, 124_000_000];
    let start = 2_000_000_000u64;
    let root_lease = Arc::new(SharedCoSRootLease::new(ROOT, 1_000_000, 1));
    let leases: Vec<Arc<SharedCoSQueueLease>> = rates
        .iter()
        .map(|&rate| {
            Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode_and_policy(
                rate,
                96_000,
                1,
                0,
                V8RateMode::CstructDefault,
                EqualFlowTargetPolicy::Slowest,
            ))
        })
        .collect();
    let mut fast = test_cos_fast_interfaces(
        IFX,
        IFX,
        NONEXACT_QUEUE,
        vec![
            (EXACT_QUEUE_IDS[0], test_queue_fast_path(true, 0, None, Some(leases[0].clone()))),
            (EXACT_QUEUE_IDS[1], test_queue_fast_path(true, 0, None, Some(leases[1].clone()))),
            (NONEXACT_QUEUE, test_queue_fast_path(true, 0, None, None)),
        ],
        None,
        Some(root_lease.clone()),
    );
    fast.get_mut(&IFX).expect("fast path").shared_exact_backlog =
        Some(Arc::new(SharedCoSExactBacklog::new(0)));
    let fast = fast.get(&IFX).expect("fast path").clone();
    let mut root = lab_runtime(&rates, 96_000);
    root.shaping_rate_bytes = ROOT;
    root.shared_root_lease = Some(root_lease);
    apply_cos_queue_flow_fair_promotion(&mut root, &fast.queue_fast_path, 0);
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, IFX, root, fast);
    let nonexact_idx = rates.len();
    let mut recycles = Vec::new();
    let mut descs: Vec<crate::xsk_ffi::XdpDesc> = Vec::new();
    let drains = 30_000u64;
    let mut arrivals = 0u64;
    for i in 0..drains {
        let now = start + i * 1_000;
        while queued_bytes(&binding, nonexact_idx) < 12_000 {
            if !sim_enqueue(&mut binding, NONEXACT_QUEUE, sim_item(NONEXACT_QUEUE, 31_000, now)) {
                break;
            }
        }
        if queued_bytes(&binding, 0) == 0 && queued_bytes(&binding, 1) == 0 {
            let class = (arrivals % 2) as usize;
            assert!(
                sim_enqueue(
                    &mut binding,
                    EXACT_QUEUE_IDS[class],
                    sim_item_len(EXACT_QUEUE_IDS[class], 41_000 + class as u16, now, 64),
                ),
                "premise: the exact arrival is admitted"
            );
            arrivals += 1;
        }
        let _ = drain_shaped_tx(&mut binding, now, &mut recycles);
        descs.clear();
        binding.xsk.tx.take_submitted_for_test(&mut descs);
        for desc in &descs {
            binding.xsk.device.push_comp_for_test(desc.addr);
        }
        let _ = crate::afxdp::tx::reap_tx_completions(&mut binding, &mut recycles);
        recycles.clear();
    }
    let root = &binding.cos.cos_interfaces[&IFX];
    let exact_sent: u64 = (0..rates.len())
        .map(|q| {
            root.queues[q]
                .telemetry
                .owner_profile
                .drain_sent_bytes
                .load(std::sync::atomic::Ordering::Relaxed)
        })
        .sum();
    assert!(
        exact_sent + 64 >= 64 * arrivals && arrivals >= drains * 9 / 10,
        "premise: every exact arrival was served and arrivals kept pace with drains \
         ({arrivals} arrivals in {drains} drains, {exact_sent} bytes)"
    );
    assert_eq!(
        root.v61_test.funded_builds, 0,
        "premise: no serviceable demand at the turn check, so no funded turn"
    );
    let class11_sent = root.queues[nonexact_idx]
        .telemetry
        .owner_profile
        .drain_sent_bytes
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        root.v61_test.turn_packets >= 5 && class11_sent >= 5 * FRAME as u64,
        "class 11 committed {} minimum-turn packets ({class11_sent} bytes) in 30 ms of \
         alternating-denominator exact commits (repayment takes about 3 ms; {} built)",
        root.v61_test.turn_packets,
        root.v61_test.minimum_builds
    );
}

/// #19100 v6.2 (Codex v6.1 P1-2): short exact batches buy no extra turn
/// packets. Opportunity is earned per committed exact PACKET and charged per
/// committed turn packet, so one-packet exact commits (as Local/Prepared
/// alternation produces) earn 1/31 of a turn packet each at phi = 1/32, not a
/// full batch's worth per commit. 1,984 one-packet 1,536-byte exact commits,
/// with every affordable 64-byte, one-packet turn spent at once, may buy at
/// most 1,984 / 31 + 1 turn packets. Granting opportunity per commit call let
/// the byte credit alone bind: about 0.77 turn packets per exact packet,
/// Codex's 43.6% displacement. Mutant: opportunity granted per commit call.
#[test]
fn short_exact_batches_buy_no_extra_turn_packets_19100() {
    let mut root = lab_runtime(&[24 * GBIT], SHAPING_BYTES / 100);
    let mut exact_packets = 0u64;
    let mut turn_packets = 0u64;
    for _ in 0..31 * 64 {
        v61_accrue_turn_credit(&mut root, 0, 1_536, 1);
        exact_packets += 1;
        while v61_funded_credits(&root) {
            v61_settle_turn(&mut root, 64, 1);
            turn_packets += 1;
        }
    }
    let bound = exact_packets / 31 + 1;
    assert!(
        turn_packets <= bound,
        "{turn_packets} one-packet turns for {exact_packets} one-packet exact commits: \
         phi/(1-phi) = 1/31 allows {bound}"
    );
    assert!(
        turn_packets + 1 >= exact_packets / 31,
        "premise: the credit funds turns at phi/(1-phi) ({turn_packets} turns)"
    );
}

/// #19100 v6.2 (Codex v6.1 P2-3): a pace share is a coherent observation or
/// nothing. With this worker's allotment published (a quarter of the class),
/// the pace is a quarter of the configured rate. With the rotation writer
/// stalled mid-write the reader gives up, and the pace is UNAVAILABLE: no
/// funded turn on that check, never the full class rate. Mutant: an
/// unavailable read falls back to the configured rate.
#[test]
fn an_unavailable_share_never_prices_the_full_class_19100() {
    const RATE: u64 = 50_000_000;
    let lease = Arc::new(SharedCoSQueueLease::new_v8(RATE, 256 * 1024, 4, 3));
    lease.publish_epoch_share_for_test(1, 1_000_000, 250_000);
    let mut root = lab_runtime(&[RATE], SHAPING_BYTES / 100);
    root.queues[0].queue_lease_v8 = Some(lease.clone());
    root.queues[0].v_min.worker_id = 1;
    let demand = ExactDemandQueueMask::EMPTY.with_queue(0);
    assert_eq!(
        v61_pace_share(&root, demand),
        Some(RATE / 4),
        "premise: a published allotment paces at the worker's quarter of the class"
    );
    lease.stall_epoch_writer_for_test();
    assert_eq!(
        v61_pace_share(&root, demand),
        None,
        "an unavailable share must not price the pace at the full class rate"
    );
}

/// #19100 v6.3 (Codex v6.2 P1): no loss of earnings across alternating
/// denominators at the bottom of the rate domain. Codex's schedule: a 100
/// Gb/s root (12,500,000,000 B/s), two exact classes at 12,499,999,999 and
/// 12,499,999,998 B/s (residuals 1 and 2 B/s), alternating one-packet,
/// 64-byte commits, so the denominator changes at EVERY commit and a packet
/// commit earns 0.34 or 0.69 of a Q32 unit. Resetting the remainders at each
/// change earned nothing, so the minimum's one-packet debt stood for ever.
/// Leg 1 checks the progress bound of `v61_accrue_turn_credit` on the exact
/// value V = credit + rem / d, for bytes and packets, over 2^20 alternating
/// commits: every commit raises V by more than (s x r x 2^32 - 1) / d'. Leg 2
/// starts the packet credit three units below zero (the end of a repayment)
/// and requires the minimum to become eligible again within the bound, then
/// charges it and requires the debt to be carried: the minimum recurs. (A
/// whole repayment at these residuals is about 1.25 x 10^10 one-packet
/// commits per packet: the residual contract, not simulated.) Mutant: the
/// remainders reset at a denominator change.
#[test]
fn the_minimum_keeps_earning_at_one_byte_per_second_residuals_19100() {
    const ROOT: u64 = 12_500_000_000;
    let rates = [12_499_999_999u64, 12_499_999_998];
    let mut root = lab_runtime(&rates, 96_000);
    root.shaping_rate_bytes = ROOT;
    let unit = 1u128 << V61_CREDIT_SHIFT;
    // V x d x d' compared exactly in i128 (|credit| < 2^51, d, d' < 2^34).
    let gained = |c0: i64, r0: u64, d0: u64, c1: i64, r1: u64, d1: u64| -> i128 {
        (c1 as i128 - c0 as i128) * d0 as i128 * d1 as i128 + r1 as i128 * d0 as i128
            - r0 as i128 * d1 as i128
    };
    v61_accrue_turn_credit(&mut root, 0, 64, 1);
    for k in 1..(1u64 << 20) {
        let q = (k % 2) as usize;
        let residual = (ROOT - rates[q]) as u128;
        let (cb, rb, d0, cp, rp) = (
            root.v61_byte_credit,
            root.v6_credit_rem,
            root.v6_credit_den,
            root.v61_opp_credit,
            root.v61_opp_rem,
        );
        v61_accrue_turn_credit(&mut root, q, 64, 1);
        let d1 = root.v6_credit_den;
        assert_ne!(d0, d1, "premise: the denominator changes at every commit");
        let byte_gain = gained(cb, rb, d0, root.v61_byte_credit, root.v6_credit_rem, d1);
        let opp_gain = gained(cp, rp, d0, root.v61_opp_credit, root.v61_opp_rem, d1);
        let byte_floor = (64 * residual * unit - 1) as i128 * d0 as i128;
        let opp_floor = (residual * unit - 1) as i128 * d0 as i128;
        assert!(
            byte_gain > byte_floor && opp_gain > opp_floor,
            "commit {k}: V gained {byte_gain} (bytes) / {opp_gain} (packets), x d x d'; the \
             progress bound needs more than {byte_floor} / {opp_floor}"
        );
    }
    // Leg 2: the minimum recurs.
    root.v61_byte_credit = 0;
    root.v61_opp_credit = -3;
    let mut commits = 0u64;
    while !v61_minimum_credits(&root) {
        assert!(commits < 64, "the minimum did not become eligible again ({commits} commits)");
        v61_accrue_turn_credit(&mut root, (commits % 2) as usize, 64, 1);
        commits += 1;
    }
    v61_settle_turn(&mut root, FRAME as u64, 1);
    assert!(
        !v61_minimum_credits(&root) && root.v61_opp_credit < 0,
        "the recurring minimum is charged and its debt carried"
    );
}

/// #19100 v6.3 (Codex v6.2 P2-2): a colocated turn's packet limit is a true
/// packet limit. A selected 1,500-byte head followed by 64-byte packets, a
/// 3,000-byte budget and a 2-packet limit: the batch holds 2 packets. As a
/// head-length byte estimate (1,500 x 2) it held 1 + floor(1,500 / 64) = 24.
/// Mutant: the builder ignores `max_packets`.
#[test]
fn a_colocated_turn_takes_at_most_its_packet_limit_of_mixed_sizes_19100() {
    let now = 2_000_000_000u64;
    let mut root = lab_runtime(&[24 * GBIT], SHAPING_BYTES / 100);
    root.tokens = 1_000_000;
    {
        let nonexact = &mut root.queues[1];
        nonexact.hot.runnable = true;
        nonexact.hot.items.push_back(test_cos_item(FRAME));
        for _ in 0..30 {
            nonexact.hot.items.push_back(test_cos_item(64));
        }
        nonexact.hot.queued_bytes = (FRAME + 30 * 64) as u64;
        nonexact.hot.surplus_deficit = 3_000;
    }
    root.nonempty_queues = 1;
    root.runnable_queues = 1;
    let mut local_scratch = std::collections::VecDeque::new();
    let mut prepared_scratch = std::collections::VecDeque::new();
    let batch = select_cos_surplus_batch_filtered(
        &mut root,
        now,
        SurplusPass::Colocated { max_packets: 2 },
        Some(3_000),
        RootGrantLimit::FULL,
        &mut local_scratch,
        &mut prepared_scratch,
    )
    .expect("premise: a turn batch is built");
    let CoSBatch::Local { items, .. } = batch else {
        panic!("premise: a Local batch");
    };
    assert_eq!(items.len(), 2, "a 2-packet turn took {} packets of mixed sizes", items.len());
}

/// #19100 v6.3 (Codex v6.2 P2-8): Prepared turn settlement charges the
/// committed packets. The minimum turn of a non-exact queue holding Prepared
/// items commits one packet through `apply_cos_prepared_result`, and must
/// leave exactly one packet and its bytes of debt. Mutant: the Prepared settle
/// arm charges 64 packets per turn (the Local arm and the helper unchanged).
#[test]
fn a_prepared_turn_is_charged_its_committed_packets_19100() {
    let now = 2_000_000_000u64 + 50_000;
    let mut binding = v61_turn_binding(100_000, 0, FRAME);
    {
        let root = binding.cos.cos_interfaces.get_mut(&IFX).expect("root");
        let nonexact = &mut root.queues[1];
        for frame in 8..11u64 {
            nonexact
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
                    cos_queue_id: Some(NONEXACT_QUEUE),
                    dscp_rewrite: None,
                    mirror_clone: false,
                    overlap_admissions: None,
                    enqueue_ns: now,
                }));
        }
        nonexact.hot.queued_bytes = 3 * FRAME as u64;
    }
    let batch = build_colocated_nonexact_turn_batch(&mut binding, IFX, now)
        .expect("premise: the minimum turn");
    assert!(matches!(batch, CoSBatch::Prepared { .. }), "premise: a Prepared turn batch");
    let mut recycles = Vec::new();
    assert!(
        submit_cos_batch(&mut binding, IFX, batch, now, &mut recycles),
        "premise: the Prepared minimum turn commits"
    );
    let root = binding.cos.cos_interfaces.get(&IFX).expect("root");
    assert_eq!(root.v61_test.turn_packets, 1, "premise: one packet committed");
    assert_eq!(
        (root.v61_byte_credit, root.v61_opp_credit),
        (-((FRAME as i64) << V61_CREDIT_SHIFT), -(1i64 << V61_CREDIT_SHIFT)),
        "a committed one-packet Prepared turn must be charged exactly its bytes and one packet"
    );
}

/// #19100 v6.3 (Codex v6.2 P2-8): a committed turn does not debit the shared
/// residual pool; an ordinary surplus batch beside the same peer demand does
/// (same-run control). The minimum turn commits with peer exact demand
/// published: the pool's budget is unchanged. Then an ordinary non-exact batch
/// commits: the pool is debited. Mutant: turns debit the pool too.
#[test]
fn a_turn_leaves_the_shared_residual_pool_alone_19100() {
    let now = 2_000_000_000u64 + 50_000;
    let mut binding = v61_turn_binding(100_000, 16, FRAME);
    let backlog = binding
        .cos
        .cos_fast_interfaces
        .get(&IFX)
        .and_then(|fast| fast.shared_exact_backlog.clone())
        .expect("backlog");
    let _ = backlog.residual_surplus_budget(now - 1_000_000_000, GBIT, 1_000_000);
    let before = backlog.residual_surplus_budget(now, GBIT, 1_000_000);
    let batch = build_colocated_nonexact_turn_batch(&mut binding, IFX, now)
        .expect("premise: the minimum turn");
    let mut recycles = Vec::new();
    assert!(submit_cos_batch(&mut binding, IFX, batch, now, &mut recycles), "premise: committed");
    let after_turn = backlog.residual_surplus_budget(now, GBIT, 1_000_000);
    assert_eq!(after_turn, before, "a committed turn debited the shared residual pool");
    let ordinary = build_nonexact_cos_batch(&mut binding, IFX, now)
        .expect("control premise: an ordinary non-exact batch");
    assert!(
        submit_cos_batch(&mut binding, IFX, ordinary, now, &mut recycles),
        "control premise: the ordinary batch commits"
    );
    let after_ordinary = backlog.residual_surplus_budget(now, GBIT, 1_000_000);
    assert!(
        after_ordinary < after_turn,
        "control: an ordinary surplus batch under peer exact demand debits the pool \
         ({after_turn} -> {after_ordinary})"
    );
}

/// #19100 v6.3 (Codex v6.2 cost audit), report-only: the per-exact-commit
/// accrual cost (a queue-rate walk, two u128 quotient/remainder pairs, and on
/// a denominator change two u128 rescales), measured, not asserted.
#[test]
#[ignore = "report-only: accrual cost per exact commit"]
fn meas_v63_accrual_cost_19100() {
    let rates = [12_499_999_999u64, 12_499_999_998];
    let mut root = lab_runtime(&rates, 96_000);
    root.shaping_rate_bytes = 12_500_000_000;
    let n = 10_000_000u64;
    let t = std::time::Instant::now();
    for k in 0..n {
        v61_accrue_turn_credit(&mut root, (k % 2) as usize, 4_096, 64);
    }
    let alternating = t.elapsed().as_nanos() as f64 / n as f64;
    let t = std::time::Instant::now();
    for _ in 0..n {
        v61_accrue_turn_credit(&mut root, 0, 4_096, 64);
    }
    let fixed = t.elapsed().as_nanos() as f64 / n as f64;
    std::hint::black_box(&root);
    println!(
        "V63COST accrual ns per exact commit: denominator change every commit {alternating:.1}, \
         fixed denominator {fixed:.1}"
    );
}

/// #19100 v6.3.1 (Codex v6.3 P1): a positive residual below 32 B/s still
/// earns. Shaping 31 B/s, an exact class at 30 B/s: R_local = 1 B/s, above the
/// 1/32 cap (31/32 B/s), so phi/(1-phi) is exactly 1/31. The floored cap
/// `min(R_local, shaping / 32)` made the share 0 here, and nothing ever
/// accrued. Three minima in a row must each be repaid by 64-byte, one-packet
/// exact commits within ceil(1,500 x 31 / 64) + 1 = 728 commits: the minimum
/// recurs. Mutant: the floored cap restored.
#[test]
fn a_sub_32_byte_per_second_residual_still_repays_the_minimum_19100() {
    let mut root = lab_runtime(&[30], 96);
    root.shaping_rate_bytes = 31;
    let bound = (FRAME as u64 * 31).div_ceil(64) + 1;
    for minimum in 0..3 {
        v61_settle_turn(&mut root, FRAME as u64, 1);
        let mut commits = 0u64;
        while !v61_minimum_credits(&root) {
            assert!(
                commits <= bound,
                "minimum {minimum}: its debt is unpaid after {commits} commits (bound {bound}): \
                 byte credit {} B, opportunity credit {} packets",
                root.v61_byte_credit >> V61_CREDIT_SHIFT,
                root.v61_opp_credit >> V61_CREDIT_SHIFT
            );
            v61_accrue_turn_credit(&mut root, 0, 64, 1);
            commits += 1;
        }
    }
}
