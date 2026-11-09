//! #18748 review cycle 3: the exact classes' share of the root is reserved
//! at the root lease, and a root with an exact class holds no root credit
//! between drains (docs/log/18748.md, "Cycle-3 design").
//!
//! - Rule 1 (`SharedCoSRootLease::acquire_unreserved`,
//!   `exact_root_reserve_bytes`): non-exact service is never granted root
//!   credit that would raise the lease's outstanding credit above
//!   `C - R`, where `C` is the outstanding cap and `R` the demanding exact
//!   classes' share of it (zero without exact demand, kept one frame from
//!   either end).
//! - Rule 2 (`cos_root_credit_per_batch`, `acquire_root_for_batch`,
//!   `return_unspent_batch_root_credit`): on a root with an exact class a
//!   worker takes root credit only for the batch it is about to build, after
//!   that batch's own gate, and returns what it did not spend before the
//!   drain returns.

use super::cos_drain_sim::*;
use super::*;
use crate::afxdp::cos::tx_completion::{exact_root_frame_bytes, exact_root_reserve_bytes};
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

/// Cell 1 (Rule 1). Random interleavings of exact acquires (full cap),
/// non-exact acquires (`acquire_unreserved` with the reserve), consumes and
/// returns on one root lease, per lease shape and exact demand share. Every
/// non-exact grant leaves the lease's outstanding credit at or below
/// `C - R`, and every exact request is granted at least what is left of the
/// reserve after the exact side's own holdings (`R - X`). Each step is a
/// second apart, so the credit pool is full and only the outstanding cap can
/// bind. Mutant: non-exact acquires against the full cap.
#[test]
fn nonexact_root_grants_leave_the_exact_reserve_18748() {
    let mut next = xorshift(0x1874_8c03_0001);
    for (burst, shards) in LEASE_SHAPES {
        for demand_permille in [0u64, 20, 40, 500, 960, 1_000] {
            let lease = SharedCoSRootLease::new(SHAPING_BYTES, burst, shards);
            let cap = lease.max_total_leased();
            let reserve = exact_root_reserve_bytes(
                cap,
                SHAPING_BYTES * demand_permille / 1_000,
                SHAPING_BYTES,
            );
            let label = format!("burst {burst}, shards {shards}, cap {cap}, demand {demand_permille}/1000, reserve {reserve}");
            let mut now = 1_000_000_000u64;
            let mut exact_held = 0u64;
            let mut nonexact_held = 0u64;
            for step in 0..4_000 {
                now += 1_000_000_000;
                match next() % 4 {
                    0 => {
                        let floor = exact_root_frame_bytes(cap);
                        let granted =
                            lease.acquire_unreserved(now, 1 + next() % (2 * cap), reserve, floor);
                        nonexact_held += granted;
                        if granted > 0 {
                            assert!(
                                lease.outstanding_for_test() <= cap - reserve,
                                "{label} step {step}: a non-exact grant raised outstanding \
                                 credit to {} past C - R = {}",
                                lease.outstanding_for_test(),
                                cap - reserve
                            );
                            assert!(
                                lease.available_for_test(now) >= floor,
                                "{label} step {step}: a non-exact grant took the pool below \
                                 its one-frame floor {floor}"
                            );
                        }
                    }
                    1 => {
                        let want = 1 + next() % (2 * cap);
                        let granted = lease.acquire(now, want);
                        let floor = want.min(reserve.saturating_sub(exact_held));
                        assert!(
                            granted >= floor,
                            "{label} step {step}: exact asked {want} holding {exact_held} \
                             beside non-exact {nonexact_held} and got {granted} < {floor}"
                        );
                        exact_held += granted;
                    }
                    op => {
                        let held = if next() % 2 == 0 {
                            &mut exact_held
                        } else {
                            &mut nonexact_held
                        };
                        let bytes = next() % (*held + 1);
                        if op == 2 {
                            lease.consume(bytes);
                        } else {
                            lease.release_unused(bytes);
                        }
                        *held -= bytes;
                    }
                }
                assert_eq!(
                    lease.outstanding_for_test(),
                    exact_held + nonexact_held,
                    "{label} step {step}: model"
                );
            }
        }
    }
}

/// Cell 8 (Rule 1, the frame floor). With non-exact holding everything it
/// may, exact still gets a full frame, and while the residual is positive
/// non-exact still gets one too: `F = min(tx_frame_capacity, C / 2)` on each
/// side, at exact demand shares from 0.1% to 99.9%, on every lease shape
/// (the 16,000-byte root has `C = 4,000`, so `F = 2,000` covers a 1,500-byte
/// frame on each side). Mutant: the reserve is the proportional share alone.
#[test]
fn a_frame_fits_on_each_side_of_the_exact_reserve_18748() {
    for (burst, shards) in LEASE_SHAPES {
        for demand_permille in [1u64, 20, 40, 500, 960, 999] {
            let now = 2_000_000_000u64;
            let lease = SharedCoSRootLease::new(SHAPING_BYTES, burst, shards);
            let cap = lease.max_total_leased();
            let reserve = exact_root_reserve_bytes(
                cap,
                SHAPING_BYTES * demand_permille / 1_000,
                SHAPING_BYTES,
            );
            let frame = (tx_frame_capacity() as u64).min(cap / 2);
            let label = format!(
                "burst {burst}, cap {cap}, demand {demand_permille}/1000, reserve {reserve}"
            );
            let nonexact =
                lease.acquire_unreserved(now, 4 * cap, reserve, exact_root_frame_bytes(cap));
            assert!(
                nonexact >= frame,
                "{label}: non-exact got {nonexact} < one frame ({frame}) with a positive residual"
            );
            let exact = lease.acquire(now, frame);
            assert_eq!(
                exact, frame,
                "{label}: exact got {exact} of one frame ({frame}) beside a full non-exact hold"
            );
        }
    }
    // The ends: no demand reserves nothing, demand covering the root
    // reserves the whole cap.
    assert_eq!(exact_root_reserve_bytes(4_000, 0, SHAPING_BYTES), 0);
    assert_eq!(
        exact_root_reserve_bytes(4_000, SHAPING_BYTES, SHAPING_BYTES),
        4_000
    );
    assert_eq!(
        exact_root_reserve_bytes(4_000, 2 * SHAPING_BYTES, SHAPING_BYTES),
        4_000
    );
}

/// The pool floor (Rule 1). On a root with an exact class, best-effort
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

/// Cell 2 (Rule 2). On a root with an exact class, after EVERY drain exit,
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

/// One drain of a backlogged non-exact queue on a 96 KB root
/// (`C = 24,000`) that also has two exact classes (24 and 1 Gb/s) with no
/// local backlog, while a peer publishes exact demand `demand`. The
/// non-exact queue has a 1 Gb/s transmit-rate guarantee (`Guarantee`), or
/// is best-effort surplus with a 16-frame surplus quantum (`Surplus`, served
/// on a second drain 1 ms after the first, once the residual budget has
/// refilled). Returns (bytes sent by the measured drain, `C`).
#[derive(Clone, Copy)]
enum NonExact {
    Guarantee,
    Surplus,
}

fn nonexact_drain(demand: ExactDemandQueueMask, kind: NonExact) -> (u64, u64) {
    let root_burst = 96_000;
    let mut now = 2_000_000_000u64;
    let root_lease = Arc::new(SharedCoSRootLease::new(SHAPING_BYTES, root_burst, 2));
    let backlog = Arc::new(SharedCoSExactBacklog::new(1));
    backlog.publish_demand(1, 100 * FRAME as u64, demand);
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
        Some(root_lease.clone()),
    );
    fast.get_mut(&IFX).expect("fast path").shared_exact_backlog = Some(backlog);
    let fast = fast.get(&IFX).expect("fast path").clone();
    let mut root = lab_runtime(&[24 * GBIT, GBIT], root_burst);
    root.shared_root_lease = Some(root_lease.clone());
    let config = &mut root.queues[2].config;
    config.buffer_bytes = 96_000;
    match kind {
        NonExact::Guarantee => {
            config.guarantee_enabled = true;
            config.transmit_rate_bytes = GBIT;
        }
        NonExact::Surplus => config.surplus_weight = 16,
    }
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, IFX, root, fast);
    for _ in 0..32 {
        assert!(sim_enqueue(
            &mut binding,
            NONEXACT_QUEUE,
            sim_item(NONEXACT_QUEUE, 40_000, now)
        ));
    }
    if matches!(kind, NonExact::Surplus) {
        // The first drain starts the residual budget's clock.
        let _ = drain_shaped_tx(&mut binding, now, &mut Vec::new());
        now += 1_000_000;
    }
    binding
        .cos
        .cos_interfaces
        .get_mut(&IFX)
        .expect("root")
        .queues[2]
        .hot
        .tokens = 96_000;
    let before = binding.live.tx_bytes.load(AtomicOrdering::Relaxed);
    let _ = drain_shaped_tx(&mut binding, now, &mut Vec::new());
    (
        binding.live.tx_bytes.load(AtomicOrdering::Relaxed) - before,
        root_lease.max_total_leased(),
    )
}

/// Cell 7 (Rule 1, an idle exact class). Exact classes that are configured
/// but have no demand reserve nothing.
/// - Per drain: the non-exact guarantee of `nonexact_drain` with
///   the 24 + 1 Gb/s exact classes idle is not held to the `C - R` that 24
///   Gb/s of demand would leave (it would get nothing at all if the
///   configured 25 Gb/s were reserved).
/// - In aggregate, against master on the SAME configuration (four workers of
///   best-effort beside an idle 24 Gb/s exact class, drain simulation,
///   committed seeds; master b57a950e21 measured with this harness ported):
///   - 96 KB and default (1%-of-rate) root bursts: master carries 25.00 Gb/s
///     on every seed, and so must this (at least 95% of the root);
///   - 16,000-byte root (`C = 4,000`): master carries 0.00 Gb/s on every
///     seed (prime-and-hold splits the 4,000-byte cap into sub-frame
///     holdings no worker can add to: #19051's class). Rule 2 holds nothing,
///     so this carries 19.6-20.1 Gb/s; at least 75% of the root.
///
/// Mutant: the reserve is sized from the configured exact rate instead of
/// the demand.
#[test]
fn an_idle_exact_class_reserves_nothing_18748() {
    let (sent, cap) = nonexact_drain(ExactDemandQueueMask::EMPTY, NonExact::Guarantee);
    let held_to = cap - exact_root_reserve_bytes(cap, 24 * GBIT, SHAPING_BYTES);
    assert!(
        sent > held_to,
        "idle exact classes: the non-exact guarantee sent {sent} in a drain, held to the \
         C - R = {held_to} that exact demand would leave"
    );
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

/// The non-exact transmit-rate guarantee semantics under Rule 1 (documented
/// in docs/fairness-regimes.md). A non-exact queue with a transmit-rate
/// guarantee (1 Gb/s here) is served from the UNRESERVED side of the root's
/// outstanding cap, like surplus: the exact reservation does not protect it.
/// - Peer exact demand of 24 of 25 Gb/s: a drain sends at least one frame
///   (the one-frame floor) and no more than `C - R`.
/// - Peer exact demand covering the root (24 + 1 Gb/s): it sends nothing.
///
/// (With no exact demand it is not held to `C - R`:
/// `an_idle_exact_class_reserves_nothing_18748`.)
#[test]
fn a_nonexact_guarantee_is_served_from_the_unreserved_share_18748() {
    let first_class = ExactDemandQueueMask::EMPTY.with_queue(0);
    let (sent, cap) = nonexact_drain(first_class, NonExact::Guarantee);
    let reserve = exact_root_reserve_bytes(cap, 24 * GBIT, SHAPING_BYTES);
    assert!(
        sent >= FRAME as u64 && sent <= cap - reserve,
        "exact demand 24 of 25 Gb/s: the guarantee sent {sent}, expected one frame up to \
         C - R = {}",
        cap - reserve
    );
    let (sent, _) = nonexact_drain(first_class.with_queue(1), NonExact::Guarantee);
    assert_eq!(
        sent, 0,
        "exact demand covering the root: the guarantee must wait"
    );
}

/// Rule 1 for surplus: best-effort surplus (a 16-frame quantum, so a visit
/// could take 24,000 bytes) beside a peer's 24 of 25 Gb/s exact demand sends
/// at least a frame and at most `C - R` in a drain, and is not held to it
/// without exact demand. Mutant: surplus acquires against the full cap.
#[test]
fn surplus_is_served_from_the_unreserved_share_18748() {
    let (sent, cap) = nonexact_drain(ExactDemandQueueMask::EMPTY.with_queue(0), NonExact::Surplus);
    let held_to = cap - exact_root_reserve_bytes(cap, 24 * GBIT, SHAPING_BYTES);
    assert!(
        sent >= FRAME as u64 && sent <= held_to,
        "exact demand 24 of 25 Gb/s: surplus sent {sent}, expected one frame up to C - R = {held_to}"
    );
    let (sent, _) = nonexact_drain(ExactDemandQueueMask::EMPTY, NonExact::Surplus);
    assert!(
        sent > held_to,
        "no exact demand: surplus sent {sent}, still held to C - R = {held_to}"
    );
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
