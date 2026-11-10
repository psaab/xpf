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
///
/// #18748 review cycle 3 (Codex): the re-park leaves a POSITIVE balance one
/// byte short of the head. With a zero balance the cycle-2 own-tokens guard
/// (`tokens == 0`) answered no demand by itself, so the cell passed even
/// with the earlier park's bit left set; with a sub-head balance only the
/// re-park clearing the bit can make it pass.
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
        queue.hot.tokens = FRAME as u64 - 1;
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
/// two best-effort packets too. The setup is the one that crossed the credit
/// at 6d41c6e911: worker 1 primes all 4,000 root bytes, then worker 0's exact
/// pass takes all 4,096 exact-lease bytes and parks on root. Worker 1 cannot
/// get exact-lease credit, its best-effort residual is zero, and it held the
/// root: nothing was sent in 20,000 50-us steps.
///
/// Cycle 3: on a root with an exact class no worker holds root credit
/// between drains (Rule 2), so the setup cannot cross the credit; every
/// pass order must drain all 9,000 bytes.
#[test]
fn crossed_root_and_exact_lease_credit_cannot_deadlock_18748() {
    for order in [&[0usize, 1][..], &[1, 0], &[1, 1, 0]] {
        let run = crossed_run(&CrossedShape::order(order));
        assert_eq!(
            run.total, 9_000,
            "pass order {order:?}: {} of the 9,000 queued bytes sent after a second of \
             drain passes with crossed root and exact-lease credit",
            run.total
        );
    }
}

/// #18748 review cycle 3 (Codex re-review of 5e1b3c55cc, P1 #2): the same
/// crossed setup with unequal polling, worker 1 every 50 us and worker 0
/// every `period` x 50 us at every phase. At 5e1b3c55cc (Codex's trace)
/// worker 1 returned its idle root at 200 us, cooled down until 400 us and
/// took all 4,000 bytes back; worker 0 polled at 450 us and got nothing, and
/// so on for the whole second: 0 of 9,000 bytes, at four of eight phases of
/// a 400 us period and at 800 us and 2 ms too. With no root credit held
/// between drains there is nothing to take back.
#[test]
fn crossed_credit_drains_at_every_poll_ratio_18748() {
    let mut failures = Vec::new();
    for period in [1usize, 2, 4, 5, 6, 8, 10, 12, 16, 20, 40] {
        for phase in 0..period {
            let mut shape = CrossedShape::order(&[1, 0]);
            shape.worker0_period = period;
            shape.worker0_phase = phase;
            let run = crossed_run(&shape);
            if run.total != 9_000 {
                failures.push(format!(
                    "worker 0 every {} us at phase {} us: {} of 9,000 bytes",
                    period * 50,
                    phase * 50,
                    run.total
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} poll ratios stalled:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// #18748 review cycle 3 (Codex re-review of 5e1b3c55cc, P1 #3): a holder
/// that keeps SPENDING is never reclaimed by an idle timer. The crossed
/// setup with a 24 Gb/s exact class (a 1 Gb/s residual) and worker 1's
/// best-effort queue refilled every step: worker 1's residual-bounded
/// best-effort sends reset its idle clock, so it kept the root credit and
/// the exact class sent 0 of its 6,000 bytes in a second at 5e1b3c55cc
/// while worker 1 sent about 1 Gb/s of best-effort. Master's predicate
/// starves it as well (Codex's control). Both workers drain until noop each
/// step. Every exact byte must go.
#[test]
fn a_spending_best_effort_holder_cannot_starve_the_exact_class_18748() {
    let mut shape = CrossedShape::order(&[1, 0]);
    shape.exact_rate = 24 * GBIT;
    shape.refill_best_effort = true;
    shape.drains_per_step = 64;
    let run = crossed_run(&shape);
    assert_eq!(
        run.exact, 6_000,
        "{} of the 6,000 exact bytes sent in a second beside a spending best-effort holder \
         ({} bytes in all)",
        run.exact, run.total
    );
}

struct CrossedShape {
    exact_rate: u64,
    order: Vec<usize>,
    worker0_period: usize,
    worker0_phase: usize,
    refill_best_effort: bool,
    drains_per_step: usize,
}

impl CrossedShape {
    fn order(order: &[usize]) -> Self {
        Self {
            exact_rate: SHAPING_BYTES,
            order: order.to_vec(),
            worker0_period: 1,
            worker0_phase: 0,
            refill_best_effort: false,
            drains_per_step: 1,
        }
    }
}

struct CrossedRun {
    exact: u64,
    total: u64,
}

fn crossed_run(shape: &CrossedShape) -> CrossedRun {
    use crate::afxdp::cos::tx_completion::prime_cos_root_for_service;
    let start = 2_000_000_000u64;
    let root_lease = Arc::new(SharedCoSRootLease::new(SHAPING_BYTES, 16_000, 2));
    let exact_lease = Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode_and_policy(
        shape.exact_rate,
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
            let mut root = lab_runtime(&[shape.exact_rate], 16_000);
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
    // The setup that crossed the credit before cycle 3: worker 1 primes root
    // (at 5e1b3c55cc it then held the whole 4,000-byte outstanding cap), and
    // worker 0 drains until its exact queue holds the exact lease's whole
    // 4,096-byte allowance. Since cycle 3 the prime takes no root credit on
    // this root and worker 0 just sends; neither is asserted, the outcome is.
    let _ = prime_cos_root_for_service(&mut bindings[1], IFX, start);
    let mut recycles = Vec::new();
    let mut descs: Vec<crate::xsk_ffi::XdpDesc> = Vec::new();
    let mut now = start;
    let mut pass = |binding: &mut BindingWorker, now: u64, recycles: &mut Vec<(u32, u64)>| {
        let before = binding
            .live
            .tx_bytes
            .load(std::sync::atomic::Ordering::Relaxed);
        let _ = drain_shaped_tx(binding, now, recycles);
        descs.clear();
        binding.xsk.tx.take_submitted_for_test(&mut descs);
        for desc in &descs {
            binding.xsk.device.push_comp_for_test(desc.addr);
        }
        let _ = crate::afxdp::tx::reap_tx_completions(binding, recycles);
        recycles.clear();
        binding
            .live
            .tx_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
            > before
    };
    for _ in 0..100 {
        let _ = pass(&mut bindings[0], now, &mut recycles);
        if bindings[0].cos.cos_interfaces[&IFX].queues[EXACT_IDX]
            .hot
            .tokens
            == 4_096
        {
            break;
        }
        now += 50_000;
    }
    for step in 0..20_000usize {
        now += 50_000;
        if shape.refill_best_effort {
            while queued_bytes(&bindings[1], NONEXACT_IDX) < 48 * FRAME as u64 {
                if !sim_enqueue(
                    &mut bindings[1],
                    NONEXACT_QUEUE,
                    sim_item(NONEXACT_QUEUE, 40_000, now),
                ) {
                    break;
                }
            }
        }
        for &w in &shape.order {
            if w == 0 && step % shape.worker0_period != shape.worker0_phase {
                continue;
            }
            for _ in 0..shape.drains_per_step {
                if !pass(&mut bindings[w], now, &mut recycles) {
                    break;
                }
            }
        }
    }
    let exact = bindings
        .iter()
        .map(|b| {
            b.cos.cos_interfaces[&IFX].queues[EXACT_IDX]
                .telemetry
                .owner_profile
                .drain_sent_bytes
                .load(std::sync::atomic::Ordering::Relaxed)
        })
        .sum();
    let total = bindings
        .iter()
        .map(|b| b.live.tx_bytes.load(std::sync::atomic::Ordering::Relaxed))
        .sum();
    CrossedRun { exact, total }
}

/// #18748 review cycle 3 (Codex re-review of 5e1b3c55cc, P1 #1): nothing
/// may take a low-rate exact class's root credit away on a clock. One
/// worker, a root of 1 Mb/s, 10 Mb/s or 100 Mb/s with a 16,000-byte burst,
/// an exact class at the root's rate, half of it or a tenth of it, polled
/// every 50, 200 or 500 us, alone or beside an always-backlogged best-effort
/// class. Over the second second the class must carry at least 90% of its
/// rate (less one frame of quantization). At 5e1b3c55cc (Codex's trace) a
/// 1 Mb/s class beside best-effort, polled every 50 us, sent nothing in the
/// measured second: the root credit it was waking to spend was reclaimed on
/// the pass that woke it, every 12 ms. A 50 Mb/s class on a 100 Mb/s root
/// polled every 500 us got 24 Mb/s against 48 Mb/s without reclamation.
#[test]
fn a_low_rate_exact_class_keeps_its_rate_at_any_poll_period_18748() {
    let mut failures = Vec::new();
    for root_rate in [125_000u64, 1_250_000, 12_500_000] {
        for divisor in [1u64, 2, 10] {
            for poll_ns in [50_000u64, 200_000, 500_000] {
                for best_effort in [false, true] {
                    let exact_rate = root_rate / divisor;
                    let sent = low_rate_run(root_rate, exact_rate, poll_ns, best_effort);
                    let floor = (exact_rate * 9 / 10).saturating_sub(FRAME as u64);
                    if sent < floor {
                        failures.push(format!(
                            "root {root_rate} B/s, exact {exact_rate} B/s, poll {} us, \
                             best-effort {best_effort}: {sent} B/s < {floor}",
                            poll_ns / 1_000
                        ));
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} shapes under-served:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// Exact bytes sent in the second second of a two-second run (see
/// `a_low_rate_exact_class_keeps_its_rate_at_any_poll_period_18748`).
fn low_rate_run(root_rate: u64, exact_rate: u64, poll_ns: u64, best_effort: bool) -> u64 {
    let start = 2_000_000_000u64;
    let root_burst = 16_000;
    let root_lease = Arc::new(SharedCoSRootLease::new(root_rate, root_burst, 1));
    loop {
        let granted = root_lease.acquire(start, u64::MAX);
        if granted == 0 {
            break;
        }
        root_lease.consume(granted);
    }
    let exact_lease = Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode_and_policy(
        exact_rate,
        96_000,
        1,
        0,
        V8RateMode::CstructDefault,
        EqualFlowTargetPolicy::Slowest,
    ));
    let backlog = Arc::new(SharedCoSExactBacklog::new(0));
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
        Some(root_lease.clone()),
    );
    fast.get_mut(&IFX).expect("fast path").shared_exact_backlog = Some(backlog);
    let fast = fast.get(&IFX).expect("fast path").clone();
    let mut root = lab_runtime(&[exact_rate], root_burst);
    root.shaping_rate_bytes = root_rate;
    root.queues[EXACT_IDX].config.buffer_bytes = 96_000;
    root.queues[NONEXACT_IDX].config.buffer_bytes = 96_000;
    root.queues[NONEXACT_IDX].config.transmit_rate_bytes = root_rate;
    root.shared_root_lease = Some(root_lease);
    apply_cos_queue_flow_fair_promotion(&mut root, &fast.queue_fast_path, 0);
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, IFX, root, fast);
    let mut recycles = Vec::new();
    let mut descs: Vec<crate::xsk_ffi::XdpDesc> = Vec::new();
    let exact_sent = |binding: &BindingWorker| {
        binding.cos.cos_interfaces[&IFX].queues[EXACT_IDX]
            .telemetry
            .owner_profile
            .drain_sent_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    };
    let mut base = 0;
    for step in 0..(2_000_000_000 / poll_ns) {
        let now = start + step * poll_ns;
        for (idx, queue_id) in [(EXACT_IDX, EXACT_QUEUE), (NONEXACT_IDX, NONEXACT_QUEUE)] {
            if idx == NONEXACT_IDX && !best_effort {
                continue;
            }
            while queued_bytes(&binding, idx) < 12_000 {
                if !sim_enqueue(
                    &mut binding,
                    queue_id,
                    sim_item(queue_id, 30_000 + idx as u16, now),
                ) {
                    break;
                }
            }
        }
        for _ in 0..64 {
            let before = binding
                .live
                .tx_bytes
                .load(std::sync::atomic::Ordering::Relaxed);
            let _ = drain_shaped_tx(&mut binding, now, &mut recycles);
            descs.clear();
            binding.xsk.tx.take_submitted_for_test(&mut descs);
            for desc in &descs {
                binding.xsk.device.push_comp_for_test(desc.addr);
            }
            let _ = crate::afxdp::tx::reap_tx_completions(&mut binding, &mut recycles);
            recycles.clear();
            if binding
                .live
                .tx_bytes
                .load(std::sync::atomic::Ordering::Relaxed)
                == before
            {
                break;
            }
        }
        if step * poll_ns < 1_000_000_000 {
            base = exact_sent(&binding);
        }
    }
    exact_sent(&binding) - base
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

/// #18748 review cycle 3: every backlogged exact class makes progress in
/// every shape of root burst, exact rate, exact-lease burst, class mix and
/// per-worker poll cadence. Two workers, each with exact and best-effort
/// traffic. Per exact class:
/// - no stretch of more than 2 ms may pass with the class queued and none of
///   it sent;
/// - with every worker polled every microsecond, the class carries at least
///   `share` of what it can (its rate or its offered load, whichever is
///   lower); with unequal polling it carries something.
///
/// `share` is 0.5, except "root 16k, exact 15 + 10 lease 4k" at 0.4, a
/// non-regression floor against master b57a950e21 there (4.86-5.12 of
/// 15 Gb/s, 0.32-0.34; this: 6.83-7.16, 0.46-0.48). What binds there is the
/// 16,000-byte root's 4,000-byte outstanding cap, not the 4,096-byte v8
/// leases (R5 C2 on 2c985b38fa): with the same leases, the 32 KB twin carries
/// 0.68 and the 96 KB twin ("root 96k, exact 15 + 10 lease 4k" below) 0.65,
/// and the own-token park count is 2,800 at every root burst. At 16 KB the
/// cap holds the whole link to about 15.3 of 25 Gb/s. That is the small
/// root cap family (#19051, #19075). Every shape was measured on master, at
/// 5e1b3c55cc and here with this harness, on the committed seeds; this is
/// at or above master for every class of every shape (docs/log/18748.md).
///
/// The cycle-2 form of this cell watched only the global stall (no worker
/// sending anything), which resets on any send: Codex showed it passes with
/// the exact class fully starved while best-effort moves. This form fails
/// on exactly that outcome (mutant: exact service never runs).
#[test]
fn every_exact_class_progresses_across_burst_lease_class_and_cadence_shapes_18748() {
    let class = |rate_gbit: u64, buffer: Option<u64>| ExactClass {
        rate_bytes: rate_gbit * GBIT,
        offered_bytes: vec![rate_gbit * GBIT / 2; 2],
        flows: vec![1; 2],
        buffer_bytes: buffer,
    };
    let default_burst = SHAPING_BYTES / 100;
    let lease_4k = Some(4_096);
    let shapes: Vec<(&str, u64, Vec<ExactClass>, [u64; 2], f64)> = vec![
        (
            "root 16k, exact 25 lease 4k",
            16_000,
            vec![class(25, lease_4k)],
            [1, 1],
            0.5,
        ),
        (
            "root 96k, exact 25 lease 4k",
            96_000,
            vec![class(25, lease_4k)],
            [1, 1],
            0.5,
        ),
        (
            "root 16k, exact 12 lease default",
            16_000,
            vec![class(12, None)],
            [1, 1],
            0.5,
        ),
        (
            "root default, exact 25 lease 4k",
            default_burst,
            vec![class(25, lease_4k)],
            [1, 1],
            0.5,
        ),
        (
            "root 16k, exact 15 + 10 lease 4k",
            16_000,
            vec![class(15, lease_4k), class(10, lease_4k)],
            [1, 1],
            0.4,
        ),
        (
            "root 96k, exact 15 + 10 lease 4k",
            96_000,
            vec![class(15, lease_4k), class(10, lease_4k)],
            [1, 1],
            0.5,
        ),
        (
            "root 16k, exact 15 + 10 lease default",
            16_000,
            vec![class(15, None), class(10, None)],
            [1, 1],
            0.5,
        ),
        (
            "root 16k, exact 25 lease 4k, polls 50/400 us",
            16_000,
            vec![class(25, lease_4k)],
            [50, 400],
            0.0,
        ),
        (
            "root 96k, exact 12 lease default, polls 1/400 us",
            96_000,
            vec![class(12, None)],
            [1, 400],
            0.0,
        ),
        (
            "root default, exact 24 lease default, polls 50/50 us",
            default_burst,
            vec![class(24, None)],
            [50, 50],
            0.0,
        ),
        (
            "root 16k, exact 1 lease default, polls 1/500 us",
            16_000,
            vec![class(1, None)],
            [1, 500],
            0.0,
        ),
    ];
    for (label, root_burst, exact, polls, share) in shapes {
        let mut arm = Arm::new(2, 15, 25, &[]);
        arm.exact = exact;
        arm.root_burst_bytes = root_burst;
        arm.poll_period_steps = polls.to_vec();
        assert_every_seed(label, &arm, |o| {
            for (c, class) in arm.exact.iter().enumerate() {
                if o.longest_exact_class_stall_ns[c] > 2_000_000 {
                    return Err(format!(
                        "exact class {c} sent nothing for {} us while it was queued",
                        o.longest_exact_class_stall_ns[c] / 1_000
                    ));
                }
                let can = class.rate_bytes.min(class.offered_bytes.iter().sum());
                let floor = share * can as f64 * 8.0 / 1e9;
                if o.exact_class_gbps(c) <= floor {
                    return Err(format!(
                        "exact class {c} carried {:.2} Gb/s, floor {floor:.2}",
                        o.exact_class_gbps(c)
                    ));
                }
            }
            Ok(())
        });
    }
}

/// R4 C3-1 on 2c985b38fa, reconstructed (G1a): a 2 Gb/s non-exact
/// transmit-rate guarantee on each of workers 1-3 beside an exact class
/// configured at the whole 25 Gb/s root but offered 8 Gb/s on worker 0, whose
/// TX capacity (6 Gb/s) holds it below both. The exact class publishes demand
/// for its configured 25 Gb/s, so the residual is zero and best-effort
/// surplus gets nothing; the guarantees must still get their rate. Cycle 3's
/// reserve (#19073) reserved the whole outstanding cap for that demand and
/// gave the guarantees 0.00 Gb/s, idling the link at 6 of 25 Gb/s; master
/// and this carry 2.0 each and 12.0 in all. Every guarantee instance must
/// carry at least 95% of its rate, and the exact class 95% of what its
/// worker can send. Mutant: a non-exact guarantee gets no root while the
/// demanding exact classes' configured rates cover the root.
#[test]
fn a_nonexact_guarantee_keeps_its_rate_beside_exact_demand_covering_the_root_18748() {
    let mut arm = Arm::new(4, 6, 25, &[8]);
    arm.nonexact_backlogged = vec![false, true, true, true];
    arm.nonexact_guarantee_bytes = Some(2 * GBIT);
    assert_every_seed(
        "G1a: exact cfg 25 offered 8 on a 6 Gb/s worker, 2g guarantees",
        &arm,
        |o| {
            for w in 1..arm.workers {
                if o.nonexact_gbps(w) < 0.95 * 2.0 {
                    return Err(format!(
                        "worker {w}: the 2 Gb/s non-exact guarantee carried {:.2} Gb/s",
                        o.nonexact_gbps(w)
                    ));
                }
            }
            if o.exact_gbps() < 0.95 * 6.0 {
                return Err(format!(
                    "the exact class carried {:.2} Gb/s of the 6 its worker can send",
                    o.exact_gbps()
                ));
            }
            Ok(())
        },
    );
}

/// R4 C3-1 on 2c985b38fa, reconstructed (G2): the lab's four exact classes
/// (24, 21, 18 and 3 Gb/s), each offered 12 Gb/s on its own 10 Gb/s worker,
/// beside a 2 Gb/s non-exact guarantee on each of workers 4 and 5, on a
/// 96 KB root. (At the default burst the root bank that builds during the
/// warm-up carries the link past 1.01 x the root in some seeds; R4's run
/// showed the same.) The guarantees must get their rate (the pair at least
/// 95% of its 4 Gb/s, each instance at least 90%: over the 60 ms window one
/// instance carries 1.93-2.23 Gb/s here) and the exact classes the rest of
/// the root (here 20.6-20.9 of 21 Gb/s). Cycle 3's reserve (#19073) gave the
/// guarantees 0.00 Gb/s (exact 25.0). Master gives the guarantee instances
/// 19.4-19.8 Gb/s in all and starves the exact classes to 5.2-5.6. Mutant:
/// a non-exact guarantee gets no root while the demanding exact classes'
/// configured rates cover the root.
#[test]
fn nonexact_guarantees_and_the_lab_exact_classes_share_the_root_18748() {
    let mut arm = Arm::new(6, 10, 24, &[12]);
    arm.exact = [24u64, 21, 18, 3]
        .iter()
        .enumerate()
        .map(|(c, rate)| {
            let mut offered = vec![0; 6];
            offered[c] = 12 * GBIT;
            ExactClass {
                rate_bytes: rate * GBIT,
                offered_bytes: offered,
                flows: vec![1; 6],
                buffer_bytes: None,
            }
        })
        .collect();
    arm.nonexact_backlogged = vec![false, false, false, false, true, true];
    arm.nonexact_guarantee_bytes = Some(2 * GBIT);
    arm.root_burst_bytes = 96_000;
    assert_every_seed(
        "G2: exact 24/21/18/3 offered 12 each, 2g guarantees",
        &arm,
        |o| {
            for w in 4..arm.workers {
                if o.nonexact_gbps(w) < 0.9 * 2.0 {
                    return Err(format!(
                        "worker {w}: the 2 Gb/s non-exact guarantee carried {:.2} Gb/s",
                        o.nonexact_gbps(w)
                    ));
                }
            }
            if o.nonexact_total_gbps() < 0.95 * 4.0 {
                return Err(format!(
                    "the two 2 Gb/s non-exact guarantees carried {:.2} Gb/s in all",
                    o.nonexact_total_gbps()
                ));
            }
            if o.exact_gbps() < 0.9 * (SHAPING_GBIT - 4.0) {
                return Err(format!(
                    "the exact classes carried {:.2} Gb/s of the {:.0} the guarantees leave",
                    o.exact_gbps(),
                    SHAPING_GBIT - 4.0
                ));
            }
            Ok(())
        },
    );
}
