//! #18748: a root with an exact class holds no root credit between drains
//! (Rule 2), and non-exact service leaves one frame of the root lease's
//! available pool (the pool floor). docs/log/18748.md has the design.
//!
//! - Rule 2 (`cos_root_credit_per_batch`, `acquire_root_for_batch`,
//!   `return_unspent_batch_root_credit`): on a root with an exact class a
//!   worker takes root credit only for the batch it is about to build, after
//!   that batch's own gate. It returns what it did not spend before the
//!   drain returns, and before the non-exact fallback that follows an exact
//!   pass that sent nothing (Codex P2 on 2c985b38fa).
//! - The pool floor (`RootGrantLimit::nonexact`,
//!   `SharedCoSRootLease::acquire_above_pool_floor`): non-exact service,
//!   guarantee and surplus alike, never takes the lease's available pool
//!   below `F = min(tx_frame_capacity, C / 2)`, where `C` is the lease's
//!   outstanding cap.
//!
//! Cycle 3's Rule 1, a reserve on outstanding credit for the demanding exact
//! classes, was split out of #18748 into #19073. One cell here pins what its
//! absence buys (Codex P1): 2,500- and 3,000-byte best-effort packets, larger
//! than the reserve would have left, still progress on a 16,000-byte root.
//! R4's G1a/G2 guarantee cells are in exact_starvation_18748.rs.

use super::cos_drain_sim::*;
use super::v_min_skip::{vmin_skip_exact_queue, vmin_skip_nonexact_queue};
use super::*;
use crate::afxdp::cos::tx_completion::{exact_root_frame_bytes, RootGrantLimit};
use crate::afxdp::tx_frame_capacity;
use crate::afxdp::types::lease_cas_probe;
use std::sync::atomic::Ordering as AtomicOrdering;

const EXACT_QUEUE: u8 = EXACT_QUEUE_IDS[0];
const EXACT_IDX: usize = 0;
const NONEXACT_IDX: usize = 1;

/// Root lease shapes (burst, active shards): the 16,000-byte root of the
/// crossed-lease cells (a 4,000-byte cap), a 96 KB root, a 1 MB root and the
/// lab's default 1%-of-rate burst.
const LEASE_SHAPES: [(u64, usize); 4] = [
    (16_000, 2),
    (96_000, 6),
    (1_000_000, 6),
    (SHAPING_BYTES / 100, 6),
];

fn xorshift(seed: u64) -> impl FnMut() -> u64 {
    let mut state = seed | 1;
    move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    }
}

/// The pool floor, at the lease. Random interleavings of exact acquires
/// (`acquire`, the whole pool), non-exact acquires
/// (`acquire_above_pool_floor` with `RootGrantLimit::nonexact`), consumes and
/// returns on one root lease, per lease shape. Time advances by up to 20 us
/// every 64 steps, so the pool drains between refills and the floor binds.
/// Every grant matches the model: an exact request gets
/// `min(want, available, C - outstanding)`, and a non-exact one gets the
/// same less the floor, so a non-exact grant never takes the pool below
/// `F = min(tx_frame_capacity, C / 2)` (computed here, not read from the
/// code under test). Mutants: the floor is zero (`RootGrantLimit::nonexact`),
/// and the lease ignores the floor.
#[test]
fn nonexact_root_grants_leave_one_frame_of_the_pool_18748() {
    let mut next = xorshift(0x1874_8c03_0001);
    for (burst, shards) in LEASE_SHAPES {
        let lease = SharedCoSRootLease::new(SHAPING_BYTES, burst, shards);
        let cap = lease.max_total_leased();
        let floor = (tx_frame_capacity() as u64).min(cap / 2);
        let limit = RootGrantLimit::nonexact(cap);
        let label = format!("burst {burst}, shards {shards}, cap {cap}, floor {floor}");
        let mut now = 1_000_000_000u64;
        let mut held = 0u64;
        let mut floor_bound = 0u64;
        for step in 0..20_000 {
            if step % 64 == 0 {
                now += next() % 20_000;
            }
            let available = lease.available_for_test(now);
            let headroom = cap - lease.outstanding_for_test();
            match next() % 4 {
                0 => {
                    let want = 1 + next() % (2 * cap);
                    let granted = lease.acquire_above_pool_floor(now, want, limit.pool_floor);
                    assert_eq!(
                        granted,
                        want.min(available.saturating_sub(floor)).min(headroom),
                        "{label} step {step}: non-exact asked {want} with {available} in the \
                         pool and {headroom} of headroom"
                    );
                    if granted < want.min(headroom) {
                        floor_bound += 1;
                    }
                    held += granted;
                }
                1 => {
                    let want = 1 + next() % (2 * cap);
                    let granted = lease.acquire(now, want);
                    assert_eq!(
                        granted,
                        want.min(available).min(headroom),
                        "{label} step {step}: exact asked {want} with {available} in the pool \
                         and {headroom} of headroom"
                    );
                    held += granted;
                }
                op => {
                    let bytes = next() % (held + 1);
                    if op == 2 {
                        lease.consume(bytes);
                    } else {
                        lease.release_unused(bytes);
                    }
                    held -= bytes;
                }
            }
            assert_eq!(
                lease.outstanding_for_test(),
                held,
                "{label} step {step}: model"
            );
        }
        assert!(
            floor_bound > 10,
            "{label}: premise: the floor bound a non-exact grant ({floor_bound} times)"
        );
    }
}

/// The pool floor, at a drain. On a root with an exact class, best-effort
/// drains the root lease's available pool as far as it may, at one instant;
/// then an exact frame arrives at the idle exact queue (own tokens covering
/// it) and is drained at the same instant. It must be sent at once, without
/// root-parking: best-effort may not take the pool's last frame
/// (`exact_root_frame_bytes`). Without the floor, with no root credit held
/// between drains, the exact frame found the pool empty, root-parked for a
/// wheel tick (50 us) and published demand that throttled every non-exact
/// instance while it caught up (the X shape: the colocated non-exact
/// instance fell to 0.63-0.69 Gb/s). Mutant: floor = 0.
#[test]
fn an_exact_frame_arriving_after_best_effort_drained_the_pool_is_sent_at_once_18748() {
    let now = 2_000_000_000u64;
    let root_burst = 96_000;
    let root_lease = Arc::new(SharedCoSRootLease::new(SHAPING_BYTES, root_burst, 1));
    let mut fast = test_cos_fast_interfaces(
        IFX,
        IFX,
        NONEXACT_QUEUE,
        vec![
            (EXACT_QUEUE, test_queue_fast_path(true, 0, None, None)),
            (NONEXACT_QUEUE, test_queue_fast_path(true, 0, None, None)),
        ],
        None,
        Some(root_lease.clone()),
    );
    fast.get_mut(&IFX).expect("fast path").shared_exact_backlog =
        Some(Arc::new(SharedCoSExactBacklog::new(0)));
    let fast = fast.get(&IFX).expect("fast path").clone();
    let mut root = lab_runtime(&[24 * GBIT], root_burst);
    root.shared_root_lease = Some(root_lease.clone());
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, IFX, root, fast);
    let mut descs = Vec::new();
    for _ in 0..200 {
        top_up_backlog(&mut binding, NONEXACT_IDX, NONEXACT_QUEUE, 40_000, now);
        let before = binding.live.tx_bytes.load(AtomicOrdering::Relaxed);
        let _ = drain_shaped_tx(&mut binding, now, &mut Vec::new());
        complete_tx(&mut binding, &mut descs);
        if binding.live.tx_bytes.load(AtomicOrdering::Relaxed) == before {
            break;
        }
    }
    let floor = exact_root_frame_bytes(root_lease.max_total_leased());
    let left = root_lease.available_for_test(now);
    assert!(
        left < floor + FRAME as u64,
        "premise: best-effort drained the pool to its floor (left {left}, floor {floor})"
    );
    {
        let queue = &mut binding
            .cos
            .cos_interfaces
            .get_mut(&IFX)
            .expect("root")
            .queues[EXACT_IDX];
        queue.hot.tokens = 96_000;
        queue.hot.last_refill_ns = now;
    }
    assert!(sim_enqueue(
        &mut binding,
        EXACT_QUEUE,
        sim_item(EXACT_QUEUE, 30_000, now)
    ));
    let _ = drain_shaped_tx(&mut binding, now, &mut Vec::new());
    let queue = &binding.cos.cos_interfaces[&IFX].queues[EXACT_IDX];
    assert_eq!(
        queue.telemetry.drop_counters.root_token_starvation_parks, 0,
        "the arriving exact frame root-parked (pool left {left})"
    );
    assert_eq!(
        queue
            .telemetry
            .owner_profile
            .drain_sent_bytes
            .load(AtomicOrdering::Relaxed),
        FRAME as u64,
        "the arriving exact frame was not sent at once (pool left {left})"
    );
}

/// Bindings on one root with an exact class at `exact_rate`, `workers` of
/// them, sharing one root lease, one v8 exact lease and one exact backlog.
fn exact_root_bindings(
    workers: u32,
    exact_rate: u64,
    root_burst: u64,
) -> (Vec<BindingWorker>, Arc<SharedCoSRootLease>) {
    let root_lease = Arc::new(SharedCoSRootLease::new(
        SHAPING_BYTES,
        root_burst,
        workers as usize,
    ));
    let exact_lease = Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode_and_policy(
        exact_rate,
        exact_rate / 100,
        workers as usize,
        workers as usize - 1,
        V8RateMode::CstructDefault,
        EqualFlowTargetPolicy::Slowest,
    ));
    let backlog = Arc::new(SharedCoSExactBacklog::new(workers as usize - 1));
    let bindings = (0..workers)
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
            let mut root = lab_runtime(&[exact_rate], root_burst);
            root.shared_root_lease = Some(root_lease.clone());
            apply_cos_queue_flow_fair_promotion(&mut root, &fast.queue_fast_path, w);
            BindingWorker::new_for_cos_drain_test(w, w, IFX, root, fast)
        })
        .collect();
    (bindings, root_lease)
}

fn complete_tx(binding: &mut BindingWorker, descs: &mut Vec<crate::xsk_ffi::XdpDesc>) {
    let mut recycles = Vec::new();
    descs.clear();
    binding.xsk.tx.take_submitted_for_test(descs);
    for desc in descs.iter() {
        binding.xsk.device.push_comp_for_test(desc.addr);
    }
    let _ = crate::afxdp::tx::reap_tx_completions(binding, &mut recycles);
}

fn top_up_backlog(binding: &mut BindingWorker, idx: usize, queue_id: u8, port: u16, now: u64) {
    while queued_bytes(binding, idx) < 24 * FRAME as u64 {
        if !sim_enqueue(binding, queue_id, sim_item(queue_id, port, now)) {
            break;
        }
    }
}

/// Rule 2. On a root with an exact class, after EVERY drain exit,
/// the worker holds no root credit and the root lease has none outstanding
/// (the cell is single-threaded, so outstanding credit could only be credit
/// a worker kept). Two workers with exact and best-effort backlog, at an
/// exact rate that leaves a residual (24 of 25 Gb/s) and one that leaves
/// none (25 of 25), on a 16,000-byte and a 96 KB root. The exits it drives:
/// exact sent, best-effort sent, best-effort cut by a zero residual, a queue
/// parked on root (the pool drained), and every fifth pass a TX ring with no
/// free frame (the batch is built and cannot be sent). Mutant: the drain
/// skips the end-of-drain return.
#[test]
fn no_root_credit_is_held_between_drains_on_an_exact_root_18748() {
    for exact_gbit in [24u64, 25] {
        for root_burst in [16_000u64, 96_000] {
            let label = format!("exact {exact_gbit} Gb/s, root burst {root_burst}");
            let (mut bindings, root_lease) = exact_root_bindings(2, exact_gbit * GBIT, root_burst);
            let mut descs = Vec::new();
            let mut now = 2_000_000_000u64;
            let mut sent_exact = false;
            let mut sent_best_effort = false;
            for step in 0..4_000u64 {
                now += 1_000;
                for (w, binding) in bindings.iter_mut().enumerate() {
                    top_up_backlog(binding, EXACT_IDX, EXACT_QUEUE, 30_000 + w as u16, now);
                    top_up_backlog(
                        binding,
                        NONEXACT_IDX,
                        NONEXACT_QUEUE,
                        40_000 + w as u16,
                        now,
                    );
                    for pass in 0..8u64 {
                        let starve_tx = (step + pass) % 5 == 0;
                        let frames = if starve_tx {
                            core::mem::take(&mut binding.tx_pipeline.free_tx_frames)
                        } else {
                            Default::default()
                        };
                        let _ = drain_shaped_tx(binding, now, &mut Vec::new());
                        if starve_tx {
                            binding.tx_pipeline.free_tx_frames = frames;
                        }
                        let root = &binding.cos.cos_interfaces[&IFX];
                        assert_eq!(
                            root.tokens, 0,
                            "{label}: worker {w} kept {} root bytes after a drain (step {step}, \
                             pass {pass}, TX starved {starve_tx})",
                            root.tokens
                        );
                        assert_eq!(
                            root_lease.outstanding_for_test(),
                            0,
                            "{label}: root credit outstanding between drains (step {step})"
                        );
                        complete_tx(binding, &mut descs);
                    }
                }
                sent_exact |= bindings.iter().any(|b| {
                    b.cos.cos_interfaces[&IFX].queues[EXACT_IDX]
                        .telemetry
                        .owner_profile
                        .drain_sent_bytes
                        .load(AtomicOrdering::Relaxed)
                        > 0
                });
                sent_best_effort |= bindings.iter().any(|b| {
                    b.cos.cos_interfaces[&IFX].queues[NONEXACT_IDX]
                        .telemetry
                        .owner_profile
                        .drain_sent_bytes
                        .load(AtomicOrdering::Relaxed)
                        > 0
                });
            }
            assert!(sent_exact, "{label}: premise: exact traffic was sent");
            if exact_gbit < 25 {
                assert!(sent_best_effort, "{label}: premise: best-effort was sent");
            }
        }
    }
}

/// Best-effort beside an idle exact class, against master on the SAME
/// configuration (four workers of best-effort beside an idle 24 Gb/s exact
/// class, drain simulation, committed seeds; master b57a950e21 measured with
/// this harness ported):
/// - 96 KB and default (1%-of-rate) root bursts: master carries 25.00 Gb/s
///   on every seed, and so must this (at least 95% of the root). The pool
///   floor costs nothing here.
/// - 16,000-byte root (`C = 4,000`): master carries 0.00 Gb/s on every
///   seed. Prime-and-hold splits the 4,000-byte cap into sub-frame holdings
///   no worker can add to. Rule 2 holds nothing between drains, so this
///   carries 19.6-20.1 Gb/s; at least 75% of the root. The gain applies only
///   to a root with an exact class: a root without one still primes and
///   holds, and still sends nothing at 16 KB (#19075, R5 C1).
///
/// The pool floor's cost at 12-32 KB bursts is not pinned here; #19074
/// tracks it (CoS README). Mutant: prime and hold on a root with an exact
/// class.
#[test]
fn best_effort_beside_an_idle_exact_class_fills_the_root_18748() {
    for (root_burst, share) in [(16_000, 0.75), (96_000, 0.95), (SHAPING_BYTES / 100, 0.95)] {
        let mut arm = Arm::new(4, 10, 24, &[]);
        arm.root_burst_bytes = root_burst;
        assert_every_seed(
            &format!("idle exact class, root burst {root_burst}"),
            &arm,
            |o| {
                if o.nonexact_total_gbps() < share * SHAPING_GBIT {
                    return Err(format!(
                        "best-effort {:.2} Gb/s beside an idle exact class, < {share} of the root",
                        o.nonexact_total_gbps()
                    ));
                }
                Ok(())
            },
        );
    }
}

/// Rule 2's gate for exact service: a drain whose only work is an exact
/// queue short of its own tokens does not touch the root lease at all, not
/// even for the length of the drain. That is the root leg of the crossed
/// lease: a worker in this state held the root's whole outstanding cap at
/// 5e1b3c55cc. Mutants: acquire before the own-token gate; prime and hold on
/// a root with an exact class.
#[test]
fn an_exact_queue_short_of_its_own_tokens_takes_no_root_18748() {
    let now = 2_000_000_000u64;
    let root_lease = Arc::new(SharedCoSRootLease::new(SHAPING_BYTES, 16_000, 2));
    let mut fast = test_cos_fast_interfaces(
        IFX,
        IFX,
        NONEXACT_QUEUE,
        vec![
            (EXACT_QUEUE, test_queue_fast_path(true, 0, None, None)),
            (NONEXACT_QUEUE, test_queue_fast_path(true, 0, None, None)),
        ],
        None,
        Some(root_lease.clone()),
    );
    fast.get_mut(&IFX).expect("fast path").shared_exact_backlog =
        Some(Arc::new(SharedCoSExactBacklog::new(1)));
    let fast = fast.get(&IFX).expect("fast path").clone();
    let mut root = lab_runtime(&[24 * GBIT], 16_000);
    root.shared_root_lease = Some(root_lease.clone());
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, IFX, root, fast);
    assert!(sim_enqueue(
        &mut binding,
        EXACT_QUEUE,
        sim_item(EXACT_QUEUE, 30_000, now)
    ));
    {
        let queue = &mut binding
            .cos
            .cos_interfaces
            .get_mut(&IFX)
            .expect("root")
            .queues[EXACT_IDX];
        queue.hot.tokens = FRAME as u64 - 1;
        queue.hot.last_refill_ns = now;
    }
    let _ = lease_cas_probe::take();
    let _ = drain_shaped_tx(&mut binding, now, &mut Vec::new());
    let root = &binding.cos.cos_interfaces[&IFX];
    assert!(
        !root.queues[EXACT_IDX].hot.items.is_empty() || root.queues[EXACT_IDX].hot.queued_bytes > 0,
        "premise: the exact frame is still queued"
    );
    assert_eq!(
        lease_cas_probe::take(),
        0,
        "a drain whose only work is an exact queue short of its own tokens touched the root lease"
    );
    assert_eq!(root_lease.outstanding_for_test(), 0);
}

/// What a per-batch root costs in shared-lease compare-exchange attempts.
/// One worker, an always-backlogged best-effort queue (and an exact queue
/// when `exact_backlog`), on a root with or without an exact class. Returns
/// (CAS attempts per batch, batches).
fn lease_cas_per_batch(with_exact_class: bool, exact_backlog: bool) -> (f64, u64) {
    let (mut bindings, _lease) = if with_exact_class {
        exact_root_bindings(1, 24 * GBIT, SHAPING_BYTES / 100)
    } else {
        let root_lease = Arc::new(SharedCoSRootLease::new(
            SHAPING_BYTES,
            SHAPING_BYTES / 100,
            1,
        ));
        let mut fast = test_cos_fast_interfaces(
            IFX,
            IFX,
            NONEXACT_QUEUE,
            vec![(NONEXACT_QUEUE, test_queue_fast_path(true, 0, None, None))],
            None,
            Some(root_lease.clone()),
        );
        let fast = fast.remove(&IFX).expect("fast path");
        let mut root = lab_runtime(&[], SHAPING_BYTES / 100);
        root.shared_root_lease = Some(root_lease.clone());
        (
            vec![BindingWorker::new_for_cos_drain_test(0, 0, IFX, root, fast)],
            root_lease,
        )
    };
    let binding = &mut bindings[0];
    let best_effort_idx = if with_exact_class { NONEXACT_IDX } else { 0 };
    let mut descs = Vec::new();
    let mut now = 2_000_000_000u64;
    let mut batches = 0u64;
    let mut attempts = 0u64;
    for step in 0..20_000u64 {
        now += 2_000;
        top_up_backlog(binding, best_effort_idx, NONEXACT_QUEUE, 40_000, now);
        if exact_backlog {
            top_up_backlog(binding, EXACT_IDX, EXACT_QUEUE, 30_000, now);
        }
        let _ = lease_cas_probe::take();
        let before = binding.live.tx_bytes.load(AtomicOrdering::Relaxed);
        let _ = drain_shaped_tx(binding, now, &mut Vec::new());
        complete_tx(binding, &mut descs);
        let cas = lease_cas_probe::take();
        if step >= 1_000 && binding.live.tx_bytes.load(AtomicOrdering::Relaxed) > before {
            batches += 1;
            attempts += cas;
        }
    }
    (attempts as f64 / batches.max(1) as f64, batches)
}

/// Condition 1 of the cycle-3 brief, the uncontended half: what Rule 2 adds
/// in shared-lease compare-exchange attempts per sent batch. Prime-and-hold
/// (a root with no exact class) acquires when its held credit falls below
/// the lease target, and every settle consumes. Per batch, Rule 2 acquires
/// once, consumes once, and returns once when credit is left over, so it
/// may cost at most two attempts more per batch. The numbers are printed
/// for docs/log/18748.md; the contended half is
/// `per_batch_root_contention_bench_18748` (ignored, wall-clock).
#[test]
fn per_batch_root_costs_at_most_two_lease_cas_per_batch_more_18748() {
    let (hold, hold_batches) = lease_cas_per_batch(false, false);
    let (idle_exact, idle_batches) = lease_cas_per_batch(true, false);
    let (busy_exact, busy_batches) = lease_cas_per_batch(true, true);
    eprintln!(
        "lease CAS attempts per batch: prime-and-hold {hold:.2} ({hold_batches} batches); \
         per-batch root, best-effort only {idle_exact:.2} ({idle_batches}); \
         per-batch root, exact + best-effort {busy_exact:.2} ({busy_batches})"
    );
    for (label, per_batch, batches) in [
        ("best-effort only", idle_exact, idle_batches),
        ("exact + best-effort", busy_exact, busy_batches),
    ] {
        assert!(
            batches > 1_000,
            "{label}: premise: batches were sent ({batches})"
        );
        assert!(
            per_batch <= hold + 2.0,
            "{label}: {per_batch:.2} lease CAS attempts per batch against {hold:.2} for \
             prime-and-hold"
        );
    }
}

/// Condition 1 of the cycle-3 brief, the contended half: per-batch drain
/// latency and lease CAS attempts per batch with six workers contending for
/// one root lease, against the same six workers on a root with no exact
/// class (prime-and-hold). Wall-clock, so it is ignored by default; run it in
/// a runner VM with `--ignored --nocapture` and record the numbers in
/// docs/log/18748.md. The root is shaped far above what six test workers can
/// send so the lease word, not the rate, is what they contend on.
#[test]
#[ignore = "wall-clock microbench; run explicitly in a runner VM"]
fn per_batch_root_contention_bench_18748() {
    const WORKERS: usize = 6;
    const RUN: std::time::Duration = std::time::Duration::from_millis(400);
    let shaping = 1_000 * GBIT;
    let report = |with_exact_class: bool, exact_backlog: bool| {
        let root_lease = Arc::new(SharedCoSRootLease::new(shaping, shaping / 100, WORKERS));
        let exact_lease = Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode_and_policy(
            shaping * 24 / 25,
            shaping * 24 / 25 / 100,
            WORKERS,
            WORKERS - 1,
            V8RateMode::CstructDefault,
            EqualFlowTargetPolicy::Slowest,
        ));
        let backlog = Arc::new(SharedCoSExactBacklog::new(WORKERS - 1));
        let start = std::time::Instant::now();
        let barrier = Arc::new(std::sync::Barrier::new(WORKERS));
        let handles: Vec<_> = (0..WORKERS)
            .map(|w| {
                let root_lease = root_lease.clone();
                let exact_lease = exact_lease.clone();
                let backlog = backlog.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut entries = Vec::new();
                    if with_exact_class {
                        entries.push((
                            EXACT_QUEUE,
                            test_queue_fast_path(true, 0, None, Some(exact_lease)),
                        ));
                    }
                    entries.push((NONEXACT_QUEUE, test_queue_fast_path(true, 0, None, None)));
                    let mut fast = test_cos_fast_interfaces(
                        IFX,
                        IFX,
                        NONEXACT_QUEUE,
                        entries,
                        None,
                        Some(root_lease.clone()),
                    );
                    fast.get_mut(&IFX).expect("fast path").shared_exact_backlog = Some(backlog);
                    let fast = fast.remove(&IFX).expect("fast path");
                    let exact_rates: &[u64] = if with_exact_class { &[24 * GBIT] } else { &[] };
                    let mut root = lab_runtime(exact_rates, shaping / 100);
                    root.shaping_rate_bytes = shaping;
                    if with_exact_class {
                        root.queues[EXACT_IDX].config.transmit_rate_bytes = shaping * 24 / 25;
                    }
                    root.shared_root_lease = Some(root_lease);
                    apply_cos_queue_flow_fair_promotion(&mut root, &fast.queue_fast_path, w as u32);
                    let mut binding =
                        BindingWorker::new_for_cos_drain_test(w as u32, w as u32, IFX, root, fast);
                    let best_effort_idx = exact_rates.len();
                    let mut descs = Vec::new();
                    let mut batches = 0u64;
                    let mut busy_ns = 0u128;
                    let mut cas = 0u64;
                    barrier.wait();
                    let _ = lease_cas_probe::take();
                    while start.elapsed() < RUN {
                        let now = 1_000_000_000 + start.elapsed().as_nanos() as u64;
                        top_up_backlog(&mut binding, best_effort_idx, NONEXACT_QUEUE, 40_000, now);
                        if exact_backlog {
                            top_up_backlog(&mut binding, EXACT_IDX, EXACT_QUEUE, 30_000, now);
                        }
                        let before = binding.live.tx_bytes.load(AtomicOrdering::Relaxed);
                        let t0 = std::time::Instant::now();
                        let _ = drain_shaped_tx(&mut binding, now, &mut Vec::new());
                        let dt = t0.elapsed().as_nanos();
                        let attempts = lease_cas_probe::take();
                        if binding.live.tx_bytes.load(AtomicOrdering::Relaxed) > before {
                            batches += 1;
                            busy_ns += dt;
                            cas += attempts;
                        }
                        complete_tx(&mut binding, &mut descs);
                    }
                    (batches, busy_ns, cas)
                })
            })
            .collect();
        let (batches, busy_ns, cas) = handles
            .into_iter()
            .map(|h| h.join().expect("bench worker"))
            .fold((0u64, 0u128, 0u64), |acc, r| {
                (acc.0 + r.0, acc.1 + r.1, acc.2 + r.2)
            });
        format!(
            "{WORKERS} workers: {batches} batches, {:.0} ns per batch, {:.2} lease CAS per batch",
            busy_ns as f64 / batches.max(1) as f64,
            cas as f64 / batches.max(1) as f64
        )
    };
    eprintln!(
        "BENCH prime-and-hold (no exact class): {}",
        report(false, false)
    );
    eprintln!(
        "BENCH per-batch root, best-effort only: {}",
        report(true, false)
    );
    eprintln!(
        "BENCH per-batch root, exact + best-effort: {}",
        report(true, true)
    );
}

/// Codex P2 on 2c985b38fa: an exact pass that sends nothing must not fund
/// the non-exact fallback. A 10 Gb/s root with a shared root lease (96 KB
/// burst, two shards, so `C = 24,000`) and an exact class, so it takes root
/// credit per batch. Its exact queue has own tokens and eight frames, but
/// the #917 V_min brake rejects it: its worker is 100 MB of virtual time
/// ahead of the peer. A non-exact guarantee queue has eight frames and the
/// tokens for them. Peers have drained the pool to 12,000 bytes.
///
/// The exact selection takes those 12,000 bytes for its visit, against the
/// whole pool (`RootGrantLimit::FULL`), and the V_min skip leaves them in
/// `root.tokens`. Before the fix, the fallback found them there, skipped its
/// own acquire and sent all eight frames, taking the pool to zero, past the
/// floor. Now the credit goes back first, the fallback acquires under the
/// pool floor, and the pool keeps at least `F` for the next exact frame.
/// Mutant: no return before the fallback.
#[test]
fn a_v_min_skipped_exact_visit_does_not_fund_the_nonexact_fallback_18748() {
    const NOW: u64 = 1;
    const POOL: u64 = 8 * FRAME as u64;
    let shaping = 10_000_000_000 / 8;
    let root_lease = Arc::new(SharedCoSRootLease::new(shaping, 96_000, 2));
    let cap = root_lease.max_total_leased();
    let floor = (tx_frame_capacity() as u64).min(cap / 2);
    while root_lease.available_for_test(NOW) > POOL {
        let taken = root_lease.acquire(NOW, root_lease.available_for_test(NOW) - POOL);
        assert!(taken > 0, "premise: peers drain the pool");
        root_lease.consume(taken);
    }
    let mut root = test_cos_runtime_with_queues(
        shaping,
        vec![
            vmin_skip_exact_queue(0, 125_000_000),
            vmin_skip_nonexact_queue(1),
        ],
    );
    root.oversubscription_policy = CoSOversubscriptionPolicy::GuaranteeRate;
    root.oversubscription_guarantee_fraction = 1.0;
    root.exact_queues_by_rate_ascending = vec![0];
    root.shared_root_lease = Some(root_lease.clone());
    root.tokens = 0;
    root.nonempty_queues = 2;
    root.runnable_queues = 2;
    let lagged_floor = attach_test_vtime_floor(&mut root.queues[0], 2, 0);
    lagged_floor.slots[1].publish(0);
    test_flow_fair_state_mut(&mut root.queues[0]).queue_vtime = 100 * 1024 * 1024;
    root.queues[0].hot.tokens = 128 * 1024;
    root.queues[0].hot.last_refill_ns = NOW;
    root.queues[0].hot.runnable = true;
    for _ in 0..8 {
        cos_queue_push_back(&mut root.queues[0], test_flow_cos_item(10_000, FRAME));
    }
    root.queues[1].hot.tokens = POOL;
    root.queues[1].hot.last_refill_ns = NOW;
    root.queues[1].hot.runnable = true;
    for _ in 0..8 {
        root.queues[1].hot.items.push_back(test_cos_item(FRAME));
    }
    let fast = test_cos_fast_interfaces(
        IFX,
        IFX,
        0,
        vec![
            (0, test_queue_fast_path(false, 0, None, None)),
            (1, test_queue_fast_path(false, 0, None, None)),
        ],
        None,
        Some(root_lease.clone()),
    );
    let fast = fast.get(&IFX).expect("fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, IFX, root, fast);
    let drained = drain_shaped_tx(&mut binding, NOW, &mut Vec::new())
        .expect("premise: the V_min skip falls through to the non-exact guarantee");
    assert_eq!(
        drained.queue_idx, 1,
        "premise: the non-exact guarantee was serviced"
    );
    let root = &binding.cos.cos_interfaces[&IFX];
    assert_eq!(
        root.queues[0].v_min.consecutive_v_min_skips, 1,
        "premise: the V_min brake skipped the exact queue once"
    );
    let sent = root.queues[1]
        .telemetry
        .owner_profile
        .drain_sent_bytes
        .load(AtomicOrdering::Relaxed);
    assert!(
        sent >= FRAME as u64,
        "premise: the fallback sent ({sent} bytes)"
    );
    let left = root_lease.available_for_test(NOW);
    assert!(
        left >= floor,
        "the non-exact fallback sent {sent} bytes and left {left} in the pool, below the \
         one-frame floor {floor}: it spent the root credit the exact visit acquired"
    );
    assert_eq!(
        root_lease.outstanding_for_test(),
        0,
        "root credit outstanding after the drain"
    );
}

/// Codex P1 on 2c985b38fa, reconstructed: two workers on a 25 Gb/s root with
/// a 16,000-byte burst (`C = 4,000`). A 24 Gb/s exact class is backlogged on
/// worker E (polled every 400 us) when `exact_backlogged`, and best-effort
/// packets of `be_len` bytes on worker B (polled every 50 us). Each visit
/// drains until a drain sends nothing, at most 64 drains. One simulated
/// second. Returns (exact bytes, best-effort bytes).
fn small_cap_run(be_len: usize, exact_backlogged: bool) -> (u64, u64) {
    const BURST: u64 = 16_000;
    let start = 2_000_000_000u64;
    let root_lease = Arc::new(SharedCoSRootLease::new(SHAPING_BYTES, BURST, 2));
    let exact_lease = Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode_and_policy(
        24 * GBIT,
        24 * GBIT / 100,
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
            let mut root = lab_runtime(&[24 * GBIT], BURST);
            root.shared_root_lease = Some(root_lease.clone());
            apply_cos_queue_flow_fair_promotion(&mut root, &fast.queue_fast_path, w);
            BindingWorker::new_for_cos_drain_test(w, w, IFX, root, fast)
        })
        .collect();
    let mut descs = Vec::new();
    let sent = |b: &BindingWorker, idx: usize| {
        b.cos.cos_interfaces[&IFX].queues[idx]
            .telemetry
            .owner_profile
            .drain_sent_bytes
            .load(AtomicOrdering::Relaxed)
    };
    for step in 0..20_000u64 {
        let now = start + step * 50_000;
        if exact_backlogged {
            top_up_backlog(&mut bindings[0], EXACT_IDX, EXACT_QUEUE, 30_000, now);
        }
        while queued_bytes(&bindings[1], NONEXACT_IDX) < 24 * be_len as u64 {
            if !sim_enqueue(
                &mut bindings[1],
                NONEXACT_QUEUE,
                sim_item_len(NONEXACT_QUEUE, 40_000, now, be_len),
            ) {
                break;
            }
        }
        for w in [1usize, 0] {
            if w == 0 && step % 8 != 0 {
                continue;
            }
            let binding = &mut bindings[w];
            for _ in 0..64 {
                let before = binding.live.tx_bytes.load(AtomicOrdering::Relaxed);
                let _ = drain_shaped_tx(binding, now, &mut Vec::new());
                complete_tx(binding, &mut descs);
                if binding.live.tx_bytes.load(AtomicOrdering::Relaxed) == before {
                    break;
                }
            }
        }
    }
    (
        bindings.iter().map(|b| sent(b, EXACT_IDX)).sum(),
        bindings.iter().map(|b| sent(b, NONEXACT_IDX)).sum(),
    )
}

/// Codex P1: on a 16,000-byte root (`C = 4,000`), best-effort packets
/// larger than half the cap progress beside a backlogged exact class, and
/// so does the exact class. Cycle 3's reserve (#19073) left non-exact 2,000
/// bytes of the cap there, so 2,500- and 3,000-byte packets were never sent
/// (0 bytes, against 74,995,000 and 59,997,000 here). Master sends the
/// best-effort but the exact class gets 0 bytes. Best-effort beside the
/// backlogged exact class must keep at least 90% of what it sends beside an
/// idle one, and that must be at least one packet per two 50 us polls.
/// Mutant: a pool floor 7x the frame (14,000 bytes of the 16,000-byte
/// pool).
#[test]
fn best_effort_over_half_a_small_cap_progresses_beside_exact_18748() {
    const POLLS: u64 = 20_000;
    for be_len in [3_000usize, 2_500] {
        let label = format!("{be_len}-byte best-effort on a 16,000-byte root");
        let (exact, best_effort) = small_cap_run(be_len, true);
        let (_, alone) = small_cap_run(be_len, false);
        assert!(
            alone >= POLLS / 2 * be_len as u64,
            "{label}: best-effort beside an idle exact class sent {alone} bytes, under one \
             packet per two polls"
        );
        assert!(
            best_effort * 10 >= alone * 9,
            "{label}: best-effort sent {best_effort} bytes beside a backlogged exact class, \
             under 90% of the {alone} it sends beside an idle one"
        );
        assert!(exact > 0, "{label}: the exact class sent nothing");
    }
}
