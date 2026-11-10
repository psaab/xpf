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
//!   outstanding cap, while an exact class has work and for 1 ms after
//!   (`cos_exact_class_has_work`, `cos_exact_floor_on`). With the exact
//!   classes idle past that hold it takes the whole pool.
//!
//! Cycle 3's Rule 1, a reserve on outstanding credit for the demanding exact
//! classes, was split out of #18748 into #19073. One cell here pins what its
//! absence buys (Codex P1): 2,500- and 3,000-byte best-effort packets, larger
//! than the reserve would have left, still progress on a 16,000-byte root.
//! R4's G1a/G2 guarantee cells are in exact_starvation_18748.rs.

use super::cos_drain_sim::*;
use super::v_min_skip::{vmin_skip_exact_queue, vmin_skip_nonexact_queue};
use super::*;
use crate::afxdp::cos::tx_completion::RootGrantLimit;
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

/// The demand-gated pool floor's wake-up bound (it replaces the always-on
/// floor's arrival cell, which asserted that an idle exact class's first frame
/// went at the very instant best-effort had drained the pool). Four 10 Gb/s
/// workers saturate the root with best-effort while a 24 Gb/s exact class is
/// idle; from the window's start 8 Gb/s of it arrives on worker 0. Its first
/// frame arrives 1 us in (1,500 bytes at 8 Gb/s); it must be sent in that
/// step, the class must carry at least 95% of its 8 Gb/s over the first
/// millisecond, and none of its frames may root-park in the window: the
/// enqueue publishes the backlog, and best-effort on the other workers leaves
/// the floor from then on. Measured at every burst: first frame at 1 us,
/// 7.99 Gb/s over 1 ms, 8.00 over 10, no root park. With the gate blind to the
/// peers' published backlog, the first frame waited up to 50 us (a wheel
/// tick) and the class root-parked 60-82 times in 100 ms. Mutant: the gate
/// ignores the peers' published backlog.
#[test]
fn an_idle_exact_class_waking_beside_saturating_best_effort_is_served_at_once_18748() {
    for (root_burst, label) in [
        (12_000u64, "12k"),
        (16_000, "16k"),
        (24_000, "24k"),
        (32_000, "32k"),
        (96_000, "96k"),
        (SHAPING_BYTES / 100, "default"),
    ] {
        let mut arm = Arm::new(4, 10, 24, &[8]);
        arm.root_burst_bytes = root_burst;
        arm.exact_arrivals = Arrivals::FromWindowStart;
        arm.window_ns = 10_000_000;
        assert_every_seed(&format!("wake-up, root burst {label}"), &arm, |o| {
            match o.first_exact_send_ns[0] {
                Some(ns) if ns <= 1_000 => {}
                first => {
                    return Err(format!(
                        "the first exact frame arrived at 1 us and was first sent at {first:?} \
                         ns, after {} drains",
                        o.drains_to_first_exact[0]
                    ))
                }
            }
            let first_ms = o.exact_class_bytes_by_mark[0][0] as f64 * 8.0 / 1e6;
            if first_ms < 0.95 * 8.0 {
                return Err(format!(
                    "the waking class carried {first_ms:.2} Gb/s over its first millisecond"
                ));
            }
            if o.exact_root_parks > 0 {
                return Err(format!(
                    "the waking class root-parked {} times",
                    o.exact_root_parks
                ));
            }
            Ok(())
        });
    }
}

/// The demand-gated pool floor and its hold while an exact class is active.
/// An exact class running below its rate (8 Gb/s of a 24 Gb/s class on a
/// 10 Gb/s worker) empties its queue between frames. Best-effort Gb/s,
/// shipped / floor without the hold / no floor (R5 on #18748 at
/// 85bf4e2155; exact 8.00 in every column):
/// - 12 KB: 3.63-3.66 / 8.30-8.63 / 4.83-5.11;
/// - 16 KB: 9.86-11.14 / 13.14-13.17 / 5.33-6.23;
/// - 24 KB: 10.89-12.09 / 9.78-9.96 / 5.75-6.20;
/// - 32 KB: 12.81-13.86 / 8.73-9.41 / 6.92-7.46;
/// - 96 KB: 16.97-16.98 / 16.96-16.97 / 13.24-13.41.
/// Without the hold the floor dropped at each gap, best-effort drained the
/// pool, and the next frame turned the floor back on with the pool to refill
/// past `F` first. Without the floor exact root-parked 185-291 times a run
/// and each park cut surplus to the residual. So best-effort must carry at
/// least 3.0 Gb/s at 12 KB, 9.0 at 16 KB, 10.5 at 24 KB, 12.0 at 32 KB and
/// 16.0 at 96 KB, and the exact class its 8 Gb/s at every burst with no root
/// park. Mutants: no hold (24 and 32 KB); no floor (16 KB, 5.33-6.23, roughly
/// halved); a floor 7x the frame (12 KB, 2.18-2.22, below 3.0).
#[test]
fn a_steady_exact_class_below_its_rate_keeps_the_floor_through_its_gaps_18748() {
    let mut failures = Vec::new();
    for (root_burst, label, best_effort) in [
        (12_000u64, "12k", 3.0),
        (16_000, "16k", 9.0),
        (24_000, "24k", 10.5),
        (32_000, "32k", 12.0),
        (96_000, "96k", 16.0),
    ] {
        let mut arm = Arm::new(4, 10, 24, &[8]);
        arm.root_burst_bytes = root_burst;
        // Every burst is checked, so a red run names every row it breaks.
        let checked = check_every_seed(
            &format!("steady exact 8 of 24, root burst {label}"),
            &arm,
            |o| {
                if o.nonexact_total_gbps() < best_effort {
                    return Err(format!(
                        "best-effort carried {:.2} Gb/s, under {best_effort}",
                        o.nonexact_total_gbps()
                    ));
                }
                if o.exact_class_gbps(0) < 0.95 * 8.0 {
                    return Err(format!(
                        "the exact class carried {:.2} of its 8 Gb/s",
                        o.exact_class_gbps(0)
                    ));
                }
                if o.exact_root_parks > 0 {
                    return Err(format!(
                        "the exact class root-parked {} times",
                        o.exact_root_parks
                    ));
                }
                Ok(())
            },
        );
        if let Err(failure) = checked {
            failures.push(failure);
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The demand-gated pool floor under an exact class whose demand flips
/// idle and busy (8 Gb/s for `on`, idle for `off`, from the start), at 5/5,
/// 100/100 and 1,000/1,000 us, on a 16 KB, a 96 KB and the default root. The
/// floor toggles with it (the 1,000 us off phases outlast the 1 ms hold), and
/// neither side may lose: every exact frame that arrives in the window is
/// admitted, the class sends at least 95% of the bytes that arrived, it never
/// root-parks, and no best-effort instance goes unserved for longer than
/// `MAX_UNSERVED_NS`. Measured: exact 4.00 Gb/s with no drop and
/// a 1 us longest stall in every shape; with the gate blind to the peers'
/// published backlog, 31-63 root parks and 50 us stalls. Mutant: the gate
/// ignores the peers' published backlog.
#[test]
fn an_exact_class_flipping_idle_and_busy_loses_nothing_either_side_18748() {
    for (root_burst, label) in [
        (16_000u64, "16k"),
        (96_000, "96k"),
        (SHAPING_BYTES / 100, "default"),
    ] {
        for (on_ns, off_ns) in [
            (5_000u64, 5_000u64),
            (100_000, 100_000),
            (1_000_000, 1_000_000),
        ] {
            let mut arm = Arm::new(4, 10, 24, &[8]);
            arm.root_burst_bytes = root_burst;
            arm.exact_arrivals = Arrivals::OnOff { on_ns, off_ns };
            assert_every_seed(
                &format!("exact on {on_ns} ns / off {off_ns} ns, root burst {label}"),
                &arm,
                |o| {
                    if o.exact_dropped_bytes[0] > 0 {
                        return Err(format!(
                            "{} of {} arriving exact bytes were not admitted",
                            o.exact_dropped_bytes[0], o.exact_arrived_bytes[0]
                        ));
                    }
                    if (o.exact_class_bytes[0] as f64) < 0.95 * o.exact_arrived_bytes[0] as f64 {
                        return Err(format!(
                            "the exact class sent {} of the {} bytes that arrived",
                            o.exact_class_bytes[0], o.exact_arrived_bytes[0]
                        ));
                    }
                    if o.exact_root_parks > 0 {
                        return Err(format!(
                            "the exact class root-parked {} times",
                            o.exact_root_parks
                        ));
                    }
                    if let Some(w) =
                        (0..arm.workers).find(|&w| o.longest_unserved_ns[w] > MAX_UNSERVED_NS)
                    {
                        return Err(format!(
                            "best-effort on worker {w} went unserved for {} ms",
                            o.longest_unserved_ns[w] / 1_000_000
                        ));
                    }
                    Ok(())
                },
            );
        }
    }
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
/// class, drain simulation, committed seeds; master f490c6db2b measured with
/// this harness ported):
/// - 96 KB and default (1%-of-rate) root bursts: master carries 25.00 Gb/s
///   on every seed, and so must this (at least 95% of the root).
/// - 16,000-byte root (`C = 4,000`): master carries 0.00 Gb/s on every
///   seed. Prime-and-hold splits the 4,000-byte cap into sub-frame holdings
///   no worker can add to. Rule 2 holds nothing between drains, so this
///   carries 19.85-20.51 Gb/s; at least 75% of the root. The gain applies
///   only to a root with an exact class: a root without one still primes and
///   holds, and still sends nothing at 16 KB (#19075, R5 C1).
/// - 12, 24 and 32 KB (R4 C3-2): master carries 11.63, 19.58-20.03 and
///   22.98-23.22 Gb/s. A pool floor left on with the exact class idle cost
///   these roots 1.68 (10x below master), 20.81-21.47 and 24.00 Gb/s; the
///   demand-gated floor takes the whole pool and carries 12.33-12.39, 23.52
///   and 24.78. So at least 48% (12.0 Gb/s, at or above master), 90% and
///   97% of the root.
///
/// Mutants: prime and hold on a root with an exact class (16 KB); the floor
/// left on with every exact class idle (12, 24 and 32 KB).
#[test]
fn best_effort_beside_an_idle_exact_class_fills_the_root_18748() {
    for (root_burst, share) in [
        (12_000, 0.48),
        (16_000, 0.75),
        (24_000, 0.90),
        (32_000, 0.97),
        (96_000, 0.95),
        (SHAPING_BYTES / 100, 0.95),
    ] {
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
    // What `enqueue_cos_item` counts for the items it queues (the direct
    // pushes above and below do not): the gate of the demand-gated floor
    // reads it.
    root.queues[0].hot.queued_bytes = 8 * FRAME as u64;
    root.queues[1].hot.queued_bytes = 8 * FRAME as u64;
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
