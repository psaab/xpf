//! #18748: a backlogged EXACT class starves the per-worker instances of a
//! NON-exact class under root saturation, and the exact class itself falls
//! far below its guarantee.
//!
//! Live (tcp lab, `reth0.80` shaped 25 Gb/s, `guarantee-rate 0.7`): an exact
//! `iperf-24g` class carrying 2 TCP flows plus the non-exact `iperf-uncapped`
//! class (8 TCP flows). Every worker drew about an equal share of the root.
//! On a worker that carried an exact flow, the exact queue's guarantee
//! priority spent that whole share, the colocated non-exact flow got about
//! nothing (0.026 Gbit/s, head age 4.1 s), and the exact class ran at about
//! one worker's share (2.2-3.5 Gb/s per flow) against its 24 Gb/s guarantee.
//!
//! The throughput cells run the multi-worker drain simulation in
//! `cos_drain_sim.rs` (production drain, enqueue, root and v8 leases and
//! shared backlog). Every committed seed must pass; the floors come from
//! wider seed sweeps recorded in docs/log/18748.md. On master (#hb166 T-6(b)
//! predicate: runnable AND root tokens AND own tokens cover the head, and
//! neither review fix) 12 of the 21 cells this filter names fail: a
//! root-parked exact queue dropped out of the demand masks, so peers never
//! reserved root for it. The no-exact control passes on both. The release
//! cell fails on master on the guarantee and catches the pre-T-6(b) rule on
//! the link it idles, so it keeps the T-6(b) protection honest.

use super::cos_drain_sim::*;
use super::*;

const EXACT_QUEUE: u8 = EXACT_QUEUE_IDS[0];
const EXACT_IDX: usize = 0;
const NONEXACT_IDX: usize = 1;

/// The colocated non-exact instance on a worker that carries an exact class
/// must keep its share of that worker: at least half of what the worker can
/// still send after the exact offered load, and never unserved for longer
/// than `MAX_UNSERVED_NS`. Master: X starves it to 0 Gb/s, unserved for the
/// whole window, in 1 of the 5 committed seeds. On the fix L8 measured
/// exactly the 2.0 Gb/s remainder on all 120 seeds of a sweep
/// (docs/log/18748.md), so half of it is not a seed-luck floor.
fn colocated_share(arm: &Arm) -> impl Fn(&Outcome) -> Result<(), String> + '_ {
    move |o: &Outcome| {
        for w in 0..arm.workers {
            if arm.exact_offered_on(w) == 0 || !arm.nonexact_backlogged[w] {
                continue;
            }
            let remainder = (arm.worker_tx_cap_bytes - arm.exact_offered_on(w)) as f64 * 8.0 / 1e9;
            let got = o.nonexact_gbps(w);
            if got < 0.5 * remainder {
                return Err(format!(
                    "worker {w}: colocated non-exact {got:.2} Gb/s < half the {remainder:.2} Gb/s left after the exact class"
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

/// Every exact class must reach min(configured, offered) within 5%.
fn exact_guarantee(arm: &Arm) -> impl Fn(&Outcome) -> Result<(), String> + '_ {
    move |o: &Outcome| {
        for (c, class) in arm.exact.iter().enumerate() {
            let offered: u64 = class.offered_bytes.iter().sum();
            let want = class.rate_bytes.min(offered) as f64 * 8.0 / 1e9;
            if o.exact_class_gbps(c) < 0.95 * want {
                return Err(format!(
                    "exact class {c}: {:.2} Gb/s < 95% of min(configured, offered) = {want:.2}",
                    o.exact_class_gbps(c)
                ));
            }
        }
        Ok(())
    }
}

/// The link stays full: the root's shaping rate is used, within 5%.
fn link_full(o: &Outcome) -> Result<(), String> {
    if o.total_gbps() < 0.95 * SHAPING_GBIT {
        return Err(format!(
            "{:.2} Gb/s of a {SHAPING_GBIT:.0} Gb/s root used: the reservation idled the link",
            o.total_gbps()
        ));
    }
    Ok(())
}

/// #18748 (b): a non-exact instance colocated with an exact class keeps its
/// share of its worker. X is the live shape (one exact flow on a worker that
/// also carries non-exact traffic); L8 spreads 8 workers with exact flows on
/// two of them.
#[test]
fn colocated_nonexact_instance_keeps_its_share_18748() {
    let x = Arm::new(4, 10, 24, &[8]);
    assert_every_seed("X cfg24 off8 cap10", &x, colocated_share(&x));
    let l8 = Arm::new(8, 6, 24, &[4, 4]);
    assert_every_seed("L8 cfg24 off4+4 cap6", &l8, colocated_share(&l8));
}

/// #18748 (a): the exact class reaches min(configured, offered) when its
/// flows sit on two workers and the root is saturated by non-exact traffic.
/// Master: 5.0-7.2 of 12 Gb/s in all 5 X2 seeds.
#[test]
fn exact_class_reaches_its_guarantee_across_workers_18748() {
    let x2 = Arm::new(4, 10, 24, &[6, 6]);
    assert_every_seed("X2 cfg24 off6+6 cap10", &x2, exact_guarantee(&x2));
    let l8 = Arm::new(8, 6, 24, &[4, 4]);
    assert_every_seed("L8 cfg24 off4+4 cap6", &l8, exact_guarantee(&l8));
}

/// An exact class offered more than its rate is limited by its own tokens and
/// must still reach its configured rate (master: 1.8-2.5 of 8 Gb/s, every
/// seed), with the link full. Whether it releases the rest of the root cannot
/// be observed here: a class held at exactly its configured rate leaves the
/// same root - 8 Gb/s whether or not it keeps its reservation. The release
/// is pinned by `exact_classes_held_by_their_own_rate_release_the_rest_18748`.
#[test]
fn self_limited_exact_class_meets_its_rate_18748() {
    let mut arm = Arm::new(4, 15, 8, &[12]);
    arm.nonexact_backlogged[0] = false;
    let guarantee = exact_guarantee(&arm);
    assert_every_seed("R1b cfg8 off12 cap15", &arm, |o| {
        guarantee(o)?;
        link_full(o)
    });
}

/// The #hb166 T-6(b) release rule, end to end, on production v8 leases: two
/// exact classes whose configured rates sum past the root (24 + 3 Gb/s on 25,
/// like the lab's oversubscribed CoS fixture). The 3g class is offered 6 Gb/s,
/// so its v8 lease holds it at 3: it is backlogged but parked on its own
/// tokens between grants and must not hold its reservation there. The 24g
/// class is offered 14. Best-effort must get what the exact classes do not
/// use and the link must stay full. A predicate that kept every backlogged
/// queue's reservation (the pre-T-6(b) rule) reserves 27 Gb/s whenever both
/// are backlogged, holds best-effort near zero and idles the link (measured:
/// 18.1 of 25 Gb/s, best-effort 1.1). Master fails it on the guarantee: the
/// 24 Gb/s class ran 2.2-2.6 of its 14 Gb/s offered load.
#[test]
fn exact_classes_held_by_their_own_rate_release_the_rest_18748() {
    let mut arm = Arm::new(4, 15, 24, &[14]);
    arm.exact.push(ExactClass {
        rate_bytes: 3 * GBIT,
        offered_bytes: vec![0, 6 * GBIT, 0, 0],
        flows: vec![1; 4],
        buffer_bytes: None,
    });
    arm.nonexact_backlogged = vec![false, false, true, true];
    let guarantee = exact_guarantee(&arm);
    assert_every_seed("MULTI 24g off14 + 3g off6", &arm, |o| {
        guarantee(o)?;
        link_full(o)?;
        let left = SHAPING_GBIT - o.exact_gbps();
        if o.nonexact_total_gbps() < 0.95 * left {
            return Err(format!(
                "best-effort {:.2} Gb/s < 95% of the {left:.2} Gb/s the exact classes left",
                o.nonexact_total_gbps()
            ));
        }
        Ok(())
    });
}

/// A production v8 exact lease that under-grants one worker (ShareExhausted):
/// the class is configured at 12 Gb/s with one 12 Gb/s flow on worker 0 and
/// fifteen 0.2 Gb/s flows on worker 1; best-effort on workers 2 and 3. The
/// lease splits the class by flows, so worker 0 keeps parking on its own
/// tokens between grants and, under the T-6(b) rule, releases its
/// reservation there. Worker 1's light flows must get all they offer, the
/// link must stay full, and the class must keep at least `V8_FLOOR_GBIT` of
/// the 12 Gb/s it is owed. That floor is NOT the target: over 100 seeds
/// (docs/log/18748.md) this branch ran 8.06-9.39 Gb/s, the master predicate
/// 4.81-5.84, and reserve-whenever-backlogged 12.0 (with best-effort at 13
/// and the link full). The gap to 12 is #19031; raise the floor with it.
#[test]
fn exact_class_whose_v8_lease_under_grants_a_worker_keeps_most_of_its_rate_18748() {
    const V8_FLOOR_GBIT: f64 = 7.0;
    let mut arm = Arm::new(4, 15, 12, &[12, 3]);
    arm.exact[0].flows = vec![1, 15, 1, 1];
    arm.nonexact_backlogged = vec![false, false, true, true];
    assert_every_seed("V8UNDER cfg12 w0 1x12 w1 15x0.2", &arm, |o| {
        link_full(o)?;
        let light = Outcome::gbps(o.exact_bytes[1]);
        if light < 0.95 * 3.0 {
            return Err(format!(
                "worker 1's light flows {light:.2} Gb/s < 95% of the 3 Gb/s they offer"
            ));
        }
        if o.exact_gbps() < V8_FLOOR_GBIT {
            return Err(format!(
                "exact class {:.2} Gb/s < the {V8_FLOOR_GBIT} Gb/s floor",
                o.exact_gbps()
            ));
        }
        Ok(())
    });
}

/// The lab's oversubscribed shape (`cos-iperf-config.set` sums 109 Gb/s of
/// exact classes on a 25 Gb/s root): exact classes of 24, 21, 18 and 3 Gb/s,
/// each offered 12 Gb/s on its own worker, best-effort on workers 4 and 5.
/// While the demanding exact rates sum past the root the residual is zero,
/// so best-effort surplus gets NOTHING: strict exact-over-surplus, and
/// `oversubscription-policy guarantee-rate` splits the root between the exact
/// classes, it reserves nothing for best-effort. This pins that semantic
/// (#18748 review R4 F5): the link stays full of exact traffic, the 3 Gb/s
/// class keeps its rate, and best-effort stays under 1% of the root
/// (measured 0.00 on this branch over 30 seeds; on the master predicate the
/// three large classes fell to about 1.2 Gb/s each while best-effort took
/// 20 Gb/s).
#[test]
fn exact_classes_summing_past_the_root_leave_best_effort_nothing_18748() {
    let mut arm = Arm::new(6, 10, 24, &[12]);
    for (rate, worker) in [(21u64, 1usize), (18, 2), (3, 3)] {
        let mut offered_bytes = vec![0; 6];
        offered_bytes[worker] = 12 * GBIT;
        arm.exact.push(ExactClass {
            rate_bytes: rate * GBIT,
            offered_bytes,
            flows: vec![1; 6],
            buffer_bytes: None,
        });
    }
    arm.nonexact_backlogged = vec![false, false, false, false, true, true];
    assert_every_seed("LAB4 24/21/18/3 off12 each", &arm, |o| {
        link_full(o)?;
        if o.exact_class_gbps(3) < 0.95 * 3.0 {
            return Err(format!(
                "the 3 Gb/s exact class ran {:.2} Gb/s",
                o.exact_class_gbps(3)
            ));
        }
        if o.nonexact_total_gbps() > 0.01 * SHAPING_GBIT {
            return Err(format!(
                "best-effort {:.2} Gb/s while the demanding exact rates sum past the root",
                o.nonexact_total_gbps()
            ));
        }
        Ok(())
    });
}

/// Harness control, matching live arm Z: with no exact traffic the root,
/// saturated by non-exact traffic alone, is fully used and no instance goes
/// unserved. A simulation that starved here would be measuring itself.
#[test]
fn nonexact_alone_saturating_the_root_starves_no_instance_18748() {
    let arm = Arm::new(4, 10, 24, &[]);
    assert_every_seed("Z no exact cap10", &arm, |o| {
        link_full(o)?;
        if let Some((w, ns)) = o
            .longest_unserved_ns
            .iter()
            .enumerate()
            .find(|(_, ns)| **ns > MAX_UNSERVED_NS)
        {
            return Err(format!("worker {w} unserved for {} ms", ns / 1_000_000));
        }
        Ok(())
    });
}

/// #18748 review (R6 P1): a reservation equal to the root rate leaves a zero
/// residual, so peers' non-exact surplus can spend nothing. A peer that still
/// primed root credit held it, and with a small explicit burst the lease's
/// aggregate outstanding cap (`burst / 4` = 24,000 bytes here, 12,000 per
/// top-up) was reached by two such peers, after which the demanding exact
/// worker could never acquire root: 0.00 Gb/s of exact traffic, every seed,
/// at bdb3614407 (#18748's first commit, which made the reservation hold
/// while root-parked). Master, where the reservation lapses, ran 2.6 Gb/s.
/// A worker whose only work is residual-bounded surplus that cannot cover a
/// frame gives its root credit back and stops priming until the budget
/// returns.
#[test]
fn zero_residual_reservation_does_not_strand_root_credit_18748() {
    let mut arm = Arm::new(3, 15, 25, &[10]);
    arm.nonexact_backlogged[0] = false;
    arm.root_burst_bytes = 96_000;
    assert_every_seed("P1 cfg25 off10 burst96k", &arm, |o| {
        if o.exact_gbps() < 0.95 * 10.0 {
            return Err(format!(
                "exact class {:.2} Gb/s < 95% of its 10 Gb/s offered load: root credit stranded",
                o.exact_gbps()
            ));
        }
        if o.nonexact_total_gbps() < 1.0 {
            return Err(format!(
                "non-exact {:.2} Gb/s: surplus stalled",
                o.nonexact_total_gbps()
            ));
        }
        Ok(())
    });
}

fn predicate_root(queue_tokens: u64, root_tokens: u64, items: usize) -> CoSInterfaceRuntime {
    let mut root = test_cos_runtime_with_queues(
        SHAPING_BYTES,
        vec![queue_config(EXACT_QUEUE, 24 * GBIT, true)],
    );
    root.tokens = root_tokens;
    let queue = &mut root.queues[0];
    queue.hot.runnable = true;
    queue.hot.tokens = queue_tokens;
    for _ in 0..items {
        queue.hot.items.push_back(test_cos_item(FRAME));
    }
    queue.hot.queued_bytes = (items * FRAME) as u64;
    root
}

/// Park the exact queue the way the selectors do: a root park records demand
/// iff the queue's own tokens cover its head, an own-token park records none
/// (`a_parked_exact_queues_demand_does_not_rescan_its_flow_buckets_18748`
/// drives the real park sites).
fn park(root: &mut CoSInterfaceRuntime) {
    let own_tokens_cover_head = root.queues[0].hot.tokens >= FRAME as u64;
    crate::afxdp::cos::tx_completion::record_exact_park_demand(root, 0, own_tokens_cover_head);
    let queue = &mut root.queues[0];
    queue.hot.runnable = false;
    queue.hot.parked = true;
    queue.hot.next_wakeup_tick = 7;
}

/// The demand predicate, state by state. Kept: backlogged with its own
/// tokens covering the head, whether the root is short (runnable or parked
/// on root). Released: empty, own tokens short, parked on its own tokens.
#[test]
fn exact_demand_keeps_root_starved_and_releases_self_limited_queues_18748() {
    let head = FRAME as u64;
    let kept = [
        ("serviceable", predicate_root(10_000, 100_000, 2), false),
        ("root short, runnable", predicate_root(10_000, 0, 2), false),
        ("parked on root", predicate_root(10_000, 0, 2), true),
        (
            "own tokens exactly cover the head, runnable",
            predicate_root(head, 0, 2),
            false,
        ),
        (
            "own tokens exactly cover the head, parked on root",
            predicate_root(head, 0, 2),
            true,
        ),
    ];
    for (state, mut root, parked) in kept {
        if parked {
            park(&mut root);
        }
        assert!(
            local_exact_demand_mask(&root).counts(0),
            "{state}: an exact queue limited only by the root must keep its reservation"
        );
    }
    let released = [
        ("empty", predicate_root(10_000, 100_000, 0), false),
        (
            "own tokens short, runnable",
            predicate_root(head - 1, 100_000, 2),
            false,
        ),
        (
            "parked on its own tokens",
            predicate_root(0, 100_000, 2),
            true,
        ),
        (
            "parked on root and own tokens short",
            predicate_root(head - 1, 0, 2),
            true,
        ),
    ];
    for (state, mut root, parked) in released {
        if parked {
            park(&mut root);
        }
        assert!(
            !local_exact_demand_mask(&root).counts(0),
            "{state}: an exact queue limited by itself must release its reservation"
        );
    }
}

/// A parked queue's recorded demand follows its LATEST park. A queue that
/// parked on root (demand recorded), woke, spent its own tokens and parked
/// again on them must release its reservation: a demand bit left set from the
/// earlier park would keep a self-limited class reserving its rate (the
/// T-6(b) over-reservation) for as long as it stays parked on itself.
#[test]
fn an_exact_queue_reparked_on_its_own_tokens_releases_its_demand_18748() {
    let mut root = predicate_root(10_000, 0, 2);
    park(&mut root);
    assert!(
        local_exact_demand_mask(&root).counts(0),
        "premise: parked on root with its own tokens covering the head"
    );
    {
        let queue = &mut root.queues[0];
        queue.hot.parked = false;
        queue.hot.runnable = true;
        queue.hot.next_wakeup_tick = 0;
        queue.hot.tokens = 0;
    }
    park(&mut root);
    assert!(
        !local_exact_demand_mask(&root).counts(0),
        "re-parked on its own tokens: the earlier root park's demand must not survive"
    );
}

/// Peers learn of a root-parked exact queue: `publish_cos_exact_backlog`
/// publishes it in the demand mask, and drops it again once it is released.
#[test]
fn published_backlog_carries_a_root_parked_exact_queue_18748() {
    let publish = |root: CoSInterfaceRuntime| {
        let backlog = Arc::new(SharedCoSExactBacklog::new(1));
        let mut fast = test_cos_fast_interfaces(
            IFX,
            IFX,
            EXACT_QUEUE,
            vec![(EXACT_QUEUE, test_queue_fast_path(true, 0, None, None))],
            None,
            None,
        );
        fast.get_mut(&IFX).expect("fast path").shared_exact_backlog = Some(backlog.clone());
        let fast_path = fast.get(&IFX).expect("fast path").clone();
        let binding = BindingWorker::new_for_cos_drain_test(0, 0, IFX, root, fast_path);
        crate::afxdp::cos::publish_cos_exact_backlog(&binding, IFX);
        backlog.peer_exact_demand_queue_mask(1).counts(0)
    };
    let mut kept = predicate_root(10_000, 0, 2);
    park(&mut kept);
    assert!(
        publish(kept),
        "a peer must see the root-parked exact queue as demand"
    );
    let mut released = predicate_root(0, 100_000, 2);
    park(&mut released);
    assert!(
        !publish(released),
        "a queue parked on its own tokens must not be published as demand"
    );
}

/// #18748 review (R6 P2): an exact queue that enters a drain with no tokens
/// of its own published no demand at enqueue (the production enqueue path).
/// When the selector's top-up then gives it tokens and the root is short, it
/// parks on root and selects nothing; that transition must still reach the
/// published slot, or peers keep running unconstrained while it waits for
/// exactly the root the reservation protects. A finite burst has no later
/// enqueue to repair it, so several no-progress drains follow.
#[test]
fn a_top_up_that_parks_on_root_publishes_its_demand_18748() {
    let now = 2_000_000_000u64;
    let root_lease = Arc::new(SharedCoSRootLease::new(
        SHAPING_BYTES,
        SHAPING_BYTES / 100,
        2,
    ));
    // A peer drains the shared root credit, so this worker's prime acquires
    // nothing at `now`.
    while root_lease.acquire(now, u64::MAX) > 0 {}
    let exact_lease = Arc::new(SharedCoSQueueLease::new(24 * GBIT, 24 * GBIT / 100, 2));
    let backlog = Arc::new(SharedCoSExactBacklog::new(1));
    let mut fast = test_cos_fast_interfaces(
        IFX,
        IFX,
        NONEXACT_QUEUE,
        vec![
            (
                EXACT_QUEUE,
                test_queue_fast_path(true, 0, None, Some(exact_lease)),
            ),
            (NONEXACT_QUEUE, test_queue_fast_path(true, 0, None, None)),
        ],
        None,
        Some(root_lease),
    );
    fast.get_mut(&IFX).expect("fast path").shared_exact_backlog = Some(backlog.clone());
    let fast_path = fast.get(&IFX).expect("fast path").clone();
    let mut runtime = lab_runtime(&[24 * GBIT], SHAPING_BYTES / 100);
    runtime.tokens = 0;
    runtime.queues[EXACT_IDX].hot.tokens = 0;
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, IFX, runtime, fast_path);
    for i in 0..3u16 {
        assert!(
            sim_enqueue(
                &mut binding,
                EXACT_QUEUE,
                sim_item(EXACT_QUEUE, 30_000 + i, now)
            ),
            "premise: the production enqueue admitted the burst"
        );
    }
    assert!(
        !backlog.peer_exact_demand_queue_mask(1).counts(EXACT_IDX),
        "premise: the enqueue published no demand (no own tokens yet)"
    );

    let mut recycles = Vec::new();
    for _ in 0..3 {
        let _ = drain_shaped_tx(&mut binding, now, &mut recycles);
    }

    let queue = &binding.cos.cos_interfaces.get(&IFX).expect("root").queues[EXACT_IDX];
    assert!(
        queue.hot.parked && queue.hot.tokens >= FRAME as u64,
        "premise: the selector topped the queue up and parked it on root (parked {}, tokens {})",
        queue.hot.parked,
        queue.hot.tokens
    );
    assert!(
        backlog.peer_exact_demand_queue_mask(1).counts(EXACT_IDX),
        "a root-parked exact queue with its own tokens must be published as demand"
    );
}

/// #18748 review (R4 F1, R6 P3): the demand of a PARKED exact queue is
/// decided when it parks. Checking it must not re-run the MQFQ head search,
/// which walks every active flow bucket, on each publish (every exact
/// enqueue) and each non-exact surplus build and settle. Both park kinds,
/// driven through the production selector with more than 1,024 active flow
/// buckets, and both the local mask and the publish path.
#[test]
fn a_parked_exact_queues_demand_does_not_rescan_its_flow_buckets_18748() {
    let now = 2_000_000_000u64;
    for park_on_root in [false, true] {
        let backlog = Arc::new(SharedCoSExactBacklog::new(1));
        let root_lease = Arc::new(SharedCoSRootLease::new(
            SHAPING_BYTES,
            SHAPING_BYTES / 100,
            2,
        ));
        while root_lease.acquire(now, u64::MAX) > 0 {}
        let exact_lease = Arc::new(SharedCoSQueueLease::new(24 * GBIT, 24 * GBIT / 100, 2));
        let mut fast = test_cos_fast_interfaces(
            IFX,
            IFX,
            NONEXACT_QUEUE,
            vec![
                (
                    EXACT_QUEUE,
                    test_queue_fast_path(true, 0, None, park_on_root.then(|| exact_lease.clone())),
                ),
                (NONEXACT_QUEUE, test_queue_fast_path(true, 0, None, None)),
            ],
            None,
            park_on_root.then(|| root_lease.clone()),
        );
        fast.get_mut(&IFX).expect("fast path").shared_exact_backlog = Some(backlog.clone());
        let fast_path = fast.get(&IFX).expect("fast path").clone();
        let mut runtime = lab_runtime(&[24 * GBIT], SHAPING_BYTES / 100);
        apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path.queue_fast_path, 0);
        // Root parks need an empty root; own-token parks need root that
        // covers the head so the selector reaches the queue-token check.
        runtime.tokens = if park_on_root { 0 } else { 1_000_000 };
        runtime.queues[EXACT_IDX].hot.tokens = 0;
        let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, IFX, runtime, fast_path);
        for flow in 0..2_000u16 {
            let _ = sim_enqueue(
                &mut binding,
                EXACT_QUEUE,
                sim_item(EXACT_QUEUE, 1_000 + flow, now),
            );
        }
        let mut recycles = Vec::new();
        let _ = drain_shaped_tx(&mut binding, now, &mut recycles);
        let root = binding.cos.cos_interfaces.get(&IFX).expect("root");
        let active = root.queues[EXACT_IDX]
            .flow_fair_state
            .as_ref()
            .map(|ff| ff.flow_rr_buckets.len())
            .unwrap_or(0);
        assert!(
            active >= 1_024,
            "premise: {active} active flow buckets, want >= 1024"
        );
        assert!(
            root.queues[EXACT_IDX].hot.parked,
            "premise: the selector parked the queue"
        );

        crate::afxdp::cos::queue_ops::front_scan_probe::reset();
        let demand = local_exact_demand_mask(root).counts(EXACT_IDX);
        crate::afxdp::cos::publish_cos_exact_backlog(&binding, IFX);
        assert_eq!(
            crate::afxdp::cos::queue_ops::front_scan_probe::count(),
            0,
            "park_on_root={park_on_root}: a parked queue's demand check re-ran the flow-bucket head search"
        );
        assert_eq!(
            demand, park_on_root,
            "root park keeps demand, own-token park releases it"
        );
    }
}

/// The local half of the reservation: while this worker's own exact queue
/// waits on root (parked, own tokens covering its head), its own non-exact
/// surplus is metered by the residual budget like every peer's, so it cannot
/// take the root that the parked exact queue is waiting for (the root here
/// holds 100,000 bytes, as after a lease top-up before the exact queue's wake
/// tick). The fresh shared residual holds nothing yet, so no surplus batch is
/// built. Under the #hb166 T-6(b) predicate the parked queue was not demand
/// and the worker's own non-exact queue drained unconstrained. The twins: an
/// exact queue parked on its own tokens, or empty, reserves nothing, and the
/// same build does select the non-exact batch.
#[test]
fn own_root_parked_exact_queue_meters_this_workers_surplus_18748() {
    let build = |exact_tokens: u64, exact_items: usize| {
        let mut root = lab_runtime(&[24 * GBIT], SHAPING_BYTES / 100);
        root.tokens = 100_000;
        {
            let exact = &mut root.queues[EXACT_IDX];
            exact.hot.tokens = exact_tokens;
            for _ in 0..exact_items {
                exact.hot.items.push_back(test_cos_item(FRAME));
            }
            exact.hot.queued_bytes = (exact_items * FRAME) as u64;
        }
        if exact_items > 0 {
            park(&mut root);
        }
        {
            let nonexact = &mut root.queues[NONEXACT_IDX];
            nonexact.hot.runnable = true;
            nonexact.hot.items.push_back(test_cos_item(FRAME));
            nonexact.hot.queued_bytes = FRAME as u64;
        }
        root.nonempty_queues = 1 + usize::from(exact_items > 0);
        root.runnable_queues = 1;
        let backlog = Arc::new(SharedCoSExactBacklog::new(1));
        let mut fast = test_cos_fast_interfaces(
            IFX,
            IFX,
            NONEXACT_QUEUE,
            vec![
                (EXACT_QUEUE, test_queue_fast_path(true, 0, None, None)),
                (NONEXACT_QUEUE, test_queue_fast_path(true, 0, None, None)),
            ],
            None,
            None,
        );
        fast.get_mut(&IFX).expect("fast path").shared_exact_backlog = Some(backlog);
        let fast_path = fast.get(&IFX).expect("fast path").clone();
        let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, IFX, root, fast_path);
        build_nonexact_cos_batch(&mut binding, IFX, 2_000_000_000).is_some()
    };
    assert!(
        !build(10_000, 1),
        "this worker's non-exact surplus took root while its own exact queue was parked on root"
    );
    assert!(
        build(FRAME as u64 - 1, 1),
        "twin: an exact queue parked on its own tokens reserves nothing, so surplus is selected"
    );
    assert!(
        build(0, 0),
        "twin: no exact backlog, so surplus is selected"
    );
}

/// #18748 review cycle 2 (Codex F1): crossed root and exact-lease credit.
/// Two workers, a 25 Gb/s root with a 16,000-byte burst (a 4,000-byte
/// aggregate outstanding cap), one 25 Gb/s exact class whose lease burst is
/// 4,096 bytes; each worker queues two 1,500-byte exact packets, worker 1
/// two best-effort packets too. Worker 1 primes all 4,000 root bytes before
/// worker 0's exact pass takes all 4,096 exact-lease bytes and parks on
/// root. Worker 1 cannot get exact-lease credit, its best-effort residual is
/// zero, and its exact backlog kept it from returning the root it held: at
/// 6d41c6e911 nothing was sent in 20,000 50-us steps. Root credit held
/// unspent for a lease interval is now reclaimed, so all 9,000 bytes drain,
/// under every pass order tried, including worker 1 draining twice per
/// worker 0 pass (it must not take the returned credit straight back).
#[test]
fn crossed_root_and_exact_lease_credit_cannot_deadlock_18748() {
    for order in [&[0usize, 1][..], &[1, 0], &[1, 1, 0]] {
        let sent = crossed_credit_run(order);
        assert_eq!(
            sent, 9_000,
            "pass order {order:?}: {sent} of the 9,000 queued bytes sent after a second of \
             drain passes with crossed root and exact-lease credit"
        );
    }
}

fn crossed_credit_run(order: &[usize]) -> u64 {
    use crate::afxdp::cos::tx_completion::prime_cos_root_for_service;
    let start = 2_000_000_000u64;
    let root_lease = Arc::new(SharedCoSRootLease::new(SHAPING_BYTES, 16_000, 2));
    let exact_lease = Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode_and_policy(
        SHAPING_BYTES,
        4_096,
        2,
        1,
        V8RateMode::CstructDefault,
        EqualFlowTargetPolicy::Slowest,
    ));
    let backlog = Arc::new(SharedCoSExactBacklog::new(1));
    let mut bindings: Vec<_> = (0..2u32)
        .map(|w| {
            let mut fast = test_cos_fast_interfaces(
                IFX,
                IFX,
                NONEXACT_QUEUE,
                vec![
                    (
                        EXACT_QUEUE,
                        test_queue_fast_path(true, 0, None, Some(exact_lease.clone())),
                    ),
                    (NONEXACT_QUEUE, test_queue_fast_path(true, 0, None, None)),
                ],
                None,
                Some(root_lease.clone()),
            );
            fast.get_mut(&IFX).expect("fast path").shared_exact_backlog = Some(backlog.clone());
            let fast = fast.get(&IFX).expect("fast path").clone();
            let mut root = lab_runtime(&[SHAPING_BYTES], 16_000);
            root.queues[EXACT_IDX].config.buffer_bytes = 4_096;
            root.shared_root_lease = Some(root_lease.clone());
            apply_cos_queue_flow_fair_promotion(&mut root, &fast.queue_fast_path, w);
            BindingWorker::new_for_cos_drain_test(w, w, IFX, root, fast)
        })
        .collect();
    for (w, binding) in bindings.iter_mut().enumerate() {
        for _ in 0..2 {
            assert!(sim_enqueue(
                binding,
                EXACT_QUEUE,
                sim_item(EXACT_QUEUE, 30_000 + w as u16, start)
            ));
        }
    }
    for _ in 0..2 {
        assert!(sim_enqueue(
            &mut bindings[1],
            NONEXACT_QUEUE,
            sim_item(NONEXACT_QUEUE, 40_000, start)
        ));
    }
    // Worker 1 primes root; worker 0 reaches its exact-lease acquire first.
    assert!(prime_cos_root_for_service(&mut bindings[1], IFX, start));
    assert_eq!(
        bindings[1].cos.cos_interfaces[&IFX].tokens, 4_000,
        "premise: worker 1 holds the root's whole outstanding allowance"
    );
    let mut recycles = Vec::new();
    let mut descs: Vec<crate::xsk_ffi::XdpDesc> = Vec::new();
    let mut now = start;
    for _ in 0..100 {
        let _ = drain_shaped_tx(&mut bindings[0], now, &mut recycles);
        if bindings[0].cos.cos_interfaces[&IFX].queues[EXACT_IDX]
            .hot
            .tokens
            == 4_096
        {
            break;
        }
        now += 50_000;
    }
    assert_eq!(
        bindings[0].cos.cos_interfaces[&IFX].queues[EXACT_IDX]
            .hot
            .tokens,
        4_096,
        "premise: worker 0 holds the exact lease's whole outstanding allowance"
    );
    for _ in 0..20_000 {
        now += 50_000;
        for &w in order {
            let binding = &mut bindings[w];
            let _ = drain_shaped_tx(binding, now, &mut recycles);
            descs.clear();
            binding.xsk.tx.take_submitted_for_test(&mut descs);
            for desc in &descs {
                binding.xsk.device.push_comp_for_test(desc.addr);
            }
            let _ = crate::afxdp::tx::reap_tx_completions(binding, &mut recycles);
            recycles.clear();
        }
    }
    bindings
        .iter()
        .map(|b| b.live.tx_bytes.load(std::sync::atomic::Ordering::Relaxed))
        .sum()
}

/// #18748 review cycle 2 (Codex F2): a live lease-set replacement returns a
/// parked exact queue's own tokens to its lease
/// (`release_all_cos_queue_leases`) and leaves the queue parked with its
/// wake tick (1.5 s away at this 8 kb/s root). The demand recorded at the
/// park was decided on credit the queue no longer holds, so neither the local
/// mask nor the republished slot may still count it.
#[test]
fn returning_a_parked_queues_own_tokens_withdraws_its_demand_18748() {
    let now = 2_000_000_000u64;
    let root_lease = Arc::new(SharedCoSRootLease::new(1_000, 96_000, 2));
    while root_lease.acquire(now, u64::MAX) > 0 {}
    let exact_lease = Arc::new(SharedCoSQueueLease::new(1_000, 96_000, 2));
    let backlog = Arc::new(SharedCoSExactBacklog::new(1));
    let mut fast = test_cos_fast_interfaces(
        IFX,
        IFX,
        NONEXACT_QUEUE,
        vec![
            (
                EXACT_QUEUE,
                test_queue_fast_path(true, 0, None, Some(exact_lease)),
            ),
            (NONEXACT_QUEUE, test_queue_fast_path(true, 0, None, None)),
        ],
        None,
        Some(root_lease),
    );
    fast.get_mut(&IFX).expect("fast path").shared_exact_backlog = Some(backlog.clone());
    let fast = fast.get(&IFX).expect("fast path").clone();
    let mut runtime = lab_runtime(&[1_000], 96_000);
    runtime.shaping_rate_bytes = 1_000;
    runtime.tokens = 0;
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, IFX, runtime, fast);
    assert!(sim_enqueue(
        &mut binding,
        EXACT_QUEUE,
        sim_item(EXACT_QUEUE, 30_000, now)
    ));
    let _ = drain_shaped_tx(&mut binding, now, &mut Vec::new());
    assert!(
        binding.cos.cos_interfaces[&IFX].queues[EXACT_IDX]
            .hot
            .parked
            && backlog.peer_exact_demand_queue_mask(1).counts(EXACT_IDX),
        "premise: parked on root with its own tokens, published as demand"
    );
    crate::afxdp::cos::token_bucket::release_all_cos_queue_leases(&mut binding);
    crate::afxdp::cos::publish_cos_exact_backlog(&binding, IFX);
    let root = &binding.cos.cos_interfaces[&IFX];
    assert!(
        root.queues[EXACT_IDX].hot.parked && root.queues[EXACT_IDX].hot.tokens == 0,
        "premise: still parked, own tokens returned"
    );
    assert!(
        !local_exact_demand_mask(root).counts(EXACT_IDX),
        "a parked queue whose own tokens were returned must not count as demand"
    );
    assert!(
        !backlog.peer_exact_demand_queue_mask(1).counts(EXACT_IDX),
        "the republished slot must not count it either"
    );
}

/// #18748 review cycle 2: the drain makes progress in every shape of root
/// burst, exact rate, exact-lease burst and class mix, and every worker
/// interleaving the committed seeds produce: no stretch of more than 2 ms in
/// which no worker sends while work is queued. Two workers, each with exact
/// and best-effort traffic. The retained exact reservation can leave root
/// credit with a worker that cannot spend it (Codex F1); a fix for one shape
/// at a time is not enough, so the shapes are varied.
#[test]
fn drain_makes_progress_across_burst_lease_and_class_shapes_18748() {
    let class = |rate_gbit: u64, buffer: Option<u64>| ExactClass {
        rate_bytes: rate_gbit * GBIT,
        offered_bytes: vec![rate_gbit * GBIT / 2; 2],
        flows: vec![1; 2],
        buffer_bytes: buffer,
    };
    let shapes: Vec<(&str, u64, Vec<ExactClass>)> = vec![
        (
            "root 16k, exact 25 lease 4k",
            16_000,
            vec![class(25, Some(4_096))],
        ),
        (
            "root 96k, exact 25 lease 4k",
            96_000,
            vec![class(25, Some(4_096))],
        ),
        (
            "root 16k, exact 12 lease default",
            16_000,
            vec![class(12, None)],
        ),
        (
            "root default, exact 25 lease 4k",
            SHAPING_BYTES / 100,
            vec![class(25, Some(4_096))],
        ),
        (
            "root 16k, exact 15 + 10 lease 4k",
            16_000,
            vec![class(15, Some(4_096)), class(10, Some(4_096))],
        ),
    ];
    for (label, root_burst, exact) in shapes {
        let mut arm = Arm::new(2, 15, 25, &[]);
        arm.exact = exact;
        arm.root_burst_bytes = root_burst;
        assert_every_seed(label, &arm, |o| {
            if o.longest_global_stall_ns > 2_000_000 {
                return Err(format!(
                    "no worker sent anything for {} us while work was queued",
                    o.longest_global_stall_ns / 1_000
                ));
            }
            if o.total_gbps() == 0.0 {
                return Err("nothing sent in the window".into());
            }
            Ok(())
        });
    }
}
