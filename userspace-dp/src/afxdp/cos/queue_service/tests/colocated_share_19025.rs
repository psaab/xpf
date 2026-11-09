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
//! it. The cells run the multi-worker simulation in `cos_drain_sim.rs`.
//! RED at the #18748 fold (f327be14d0): R1 0.25-0.31 Gb/s against a 2.125
//! floor, R2 and LX 0.000 for the whole window.

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

/// The bound on what the owed share costs the exact class (#19025 option A):
/// on a worker whose TX capacity is the bottleneck, serving the colocated
/// instance's part first takes at most that part, `residual / n`, from the
/// exact class. R2: residual 1 Gb/s over 4 instances, so the exact class on
/// its 10 Gb/s worker keeps at least 10 - 0.25 Gb/s (within 5%), and the
/// colocated instance gets no more than 125% of its part. Run at surplus
/// weight 1 and 8: at weight 8 one surplus batch is 8 frames, so an owed
/// pass not bounded by the part would show up as rate here.
#[test]
fn tx_capped_exact_class_loses_at_most_the_owed_share_19025() {
    for weight in [1u32, 8] {
        let mut arm = Arm::new(4, 10, 24, &[14]);
        arm.nonexact_surplus_weight = weight;
        let part = residual_gbit(&arm) / 4.0;
        let cap = 10.0;
        assert_every_seed(&format!("R2 bound weight {weight}"), &arm, |o| {
            let exact = o.exact_gbps();
            if exact < 0.95 * (cap - part) {
                return Err(format!(
                    "exact class {exact:.2} Gb/s < 95% of the {cap:.0} Gb/s worker less its \
                     {part:.3} Gb/s owed share"
                ));
            }
            let colocated = o.nonexact_gbps(0);
            if colocated > 1.25 * part {
                return Err(format!(
                    "colocated non-exact {colocated:.3} Gb/s > 125% of its {part:.3} Gb/s part: \
                     the owed pass is not bounded by the share"
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

/// A zero residual (exact reservation equal to the root) gives every part a
/// zero rate. That must not strand root credit (#18748 review R6 P1): the
/// non-exact-only workers give their root back, the exact worker's own
/// colocated instance is owed nothing and does not go ahead of it, and the
/// exact class still gets its offered 10 Gb/s.
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

/// The `n` of `residual / n` follows each binding's non-exact backlog: the
/// production enqueue publishes the flag when a non-exact queue becomes
/// backlogged, and the settle that empties the queue clears it. A stale set
/// flag shrinks every other binding's part; a missing one inflates them.
#[test]
fn nonexact_backlog_flag_follows_the_queue_19025() {
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
    let mut runtime = lab_runtime(&[24 * GBIT], SHAPING_BYTES / 100);
    runtime.tokens = 1_000_000;
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, IFX, runtime, fast_path);
    assert_eq!(
        backlog.nonexact_backlogged_bindings(),
        0,
        "premise: nothing backlogged"
    );
    assert!(
        sim_enqueue(
            &mut binding,
            NONEXACT_QUEUE,
            sim_item(NONEXACT_QUEUE, 40_000, now)
        ),
        "premise: the production enqueue admitted the item"
    );
    assert_eq!(
        backlog.nonexact_backlogged_bindings(),
        1,
        "the enqueue that backlogs a non-exact queue must publish this binding's part"
    );
    let mut recycles = Vec::new();
    for _ in 0..4 {
        let _ = drain_shaped_tx(&mut binding, now, &mut recycles);
    }
    assert_eq!(
        queued_bytes(&binding, 1),
        0,
        "premise: the drain sent the item"
    );
    assert_eq!(
        backlog.nonexact_backlogged_bindings(),
        0,
        "the settle that empties the non-exact queue must withdraw this binding's part"
    );
}

/// The owed pass goes ahead of THIS worker's exact guarantee only. With no
/// local exact demand it stays out of the way, so the normal order (a
/// non-exact guarantee queue ahead of surplus, the #18748 root release)
/// applies; with local demand it serves non-exact queues only, so a
/// surplus-sharing exact queue (here visited first) waits for the normal
/// surplus pass.
#[test]
fn owed_pass_needs_local_exact_demand_and_serves_nonexact_only_19025() {
    let now = 2_000_000_000u64;
    let build = |local_exact_demand: bool| {
        // Queues: 0 exact guarantee (24 Gb/s), 1 exact surplus-sharing
        // (1 Gb/s), 2 non-exact. A peer publishes demand for queue 0, so the
        // residual is 1 Gb/s and this binding's part has had a second to fill.
        let mut root = lab_runtime(&[24 * GBIT, GBIT], SHAPING_BYTES / 100);
        root.tokens = 1_000_000;
        root.queues[1].config.surplus_sharing = true;
        root.nonexact_surplus_under_exact_last_refill_ns = now - 1_000_000_000;
        for idx in 0..3 {
            if idx == 0 && !local_exact_demand {
                continue;
            }
            let queue = &mut root.queues[idx];
            queue.hot.runnable = true;
            // The surplus-sharing exact queue holds no tokens of its own, so it
            // reserves nothing (the residual stays 1 Gb/s) yet is still a
            // surplus candidate: surplus draws on root tokens and its deficit.
            queue.hot.tokens = if idx == 1 { 0 } else { 100_000 };
            queue.hot.items.push_back(test_cos_item(FRAME));
            queue.hot.queued_bytes = FRAME as u64;
        }
        root.nonempty_queues = if local_exact_demand { 3 } else { 2 };
        root.runnable_queues = root.nonempty_queues;
        let backlog = Arc::new(SharedCoSExactBacklog::new(1));
        backlog.publish_demand(1, 1500, ExactDemandQueueMask::EMPTY.with_queue(0));
        backlog.publish_nonexact_backlogged(0, true);
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
        build_owed_nonexact_surplus_batch(&mut binding, IFX, now)
    };
    assert!(
        build(false).is_none(),
        "no local exact demand: the owed pass must not go ahead of the normal order"
    );
    let batch = build(true).expect("local exact demand and a full part: the owed batch");
    assert!(
        matches!(batch, CoSBatch::Local { queue_idx: 2, .. }),
        "the owed pass must serve the non-exact queue, not the surplus-sharing exact one"
    );
}
