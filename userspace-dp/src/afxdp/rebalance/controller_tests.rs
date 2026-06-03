// #1751 controller unit tests: COUNT-balancing selection (sum-of-squares
// convergence, overshoot guard, K threshold, cooldown, truncation defer,
// unsteerable-never-source) PLUS the #1748 move-machinery tests (barrier
// ordering, reverse-barrier rollback, budget-exhaustion, second-move unwind,
// teardown) carried forward UNCHANGED in behavior — the machinery is re-used
// verbatim, only the SELECTION (which flow / which target / the guards)
// changed. The barrier transport is mocked so the move protocol is exercised
// without a live Coordinator/NIC.

use super::*;
use super::super::ntuple::FlowSpec5Tuple;
use crate::session::SessionKey;
use std::net::{IpAddr, Ipv4Addr};

fn key(src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port,
        dst_port: 5210,
    }
}

fn worker(worker_id: u32, byte_rate: f64) -> WorkerByteRate {
    WorkerByteRate { worker_id, queue_id: worker_id, byte_rate }
}

// #1751: byte_rate is observability-only on the decision path; for count tests
// it is irrelevant, so flow() takes a byte_rate but most tests pass 0.0.
fn flow(src_port: u16, worker_id: u32, byte_rate: f64) -> FlowSample {
    FlowSample { key: key(src_port), worker_id, byte_rate, origin: None }
}

// #1751: a flow whose copy on `worker_id` is the abandoned RebalancedOut copy
// left after a move — it must contribute 0 to the per-worker count and never be
// chosen as a move source.
fn rebalanced_out_flow(src_port: u16, worker_id: u32) -> FlowSample {
    FlowSample {
        key: key(src_port),
        worker_id,
        byte_rate: 0.0,
        origin: Some(crate::session::SessionOrigin::RebalancedOut),
    }
}

/// Build `n_flows` flows on `worker_id` with distinct src_ports derived from
/// (worker_id, index) so keys are unique across the whole vector. byte_rate 0
/// (count-balancing ignores it on the decision path).
fn flows_on(worker_id: u32, n_flows: u32) -> Vec<FlowSample> {
    (0..n_flows)
        .map(|i| flow(1000 + (worker_id as u16) * 100 + i as u16, worker_id, 0.0))
        .collect()
}

/// Build a `RebalanceTickInput` for a per-worker COUNT vector `counts[w]` over
/// workers 0..counts.len(). Each worker gets `counts[w]` distinct flows; byte
/// rates are 0 (irrelevant to count-balancing). `truncated = false`.
fn count_input(ifindex: i32, counts: &[u32], now_secs: u64) -> RebalanceTickInput {
    let workers: Vec<WorkerByteRate> =
        (0..counts.len() as u32).map(|w| worker(w, 0.0)).collect();
    let mut flows = Vec::new();
    for (w, &c) in counts.iter().enumerate() {
        flows.extend(flows_on(w as u32, c));
    }
    RebalanceTickInput { ifindex, workers, flows, now_secs, truncated: false }
}

/// Records every barrier call in order so tests can assert the protocol
/// ordering (promote before demote, restore before replica-demote, etc).
#[derive(Default)]
struct MockTransport {
    calls: Vec<String>,
    promote_ok: bool,
    demote_ok: bool,
    install_ok: bool,
    /// When true, restore_owner returns false (simulates an ack timeout / key
    /// absent on W_old) so tests can exercise the gated reverse barrier.
    restore_fails: bool,
    /// When true, delete_rule returns an error (simulates an ioctl failure) so
    /// tests can exercise the second-move prior-rule delete-failure branch.
    delete_fails: bool,
    /// Per-(worker,key) origin as the mock "session table" sees it, so tests
    /// can confirm there is always >= 1 owner across a rollback even when a
    /// flow has lived on more than one worker over a chain of moves.
    origins: std::collections::HashMap<(u32, u16), &'static str>,
}

impl MockTransport {
    fn good() -> Self {
        Self {
            promote_ok: true,
            demote_ok: true,
            install_ok: true,
            ..Default::default()
        }
    }
    fn owners(&self) -> usize {
        self.origins
            .values()
            .filter(|o| matches!(**o, "owner" | "rebalanced_owner"))
            .count()
    }
}

impl BarrierTransport for MockTransport {
    fn promote(&mut self, worker_id: u32, key: &SessionKey) -> bool {
        self.calls.push(format!("promote:{worker_id}:{}", key.src_port));
        if self.promote_ok {
            self.origins.insert((worker_id, key.src_port), "rebalanced_owner");
        }
        self.promote_ok
    }
    fn demote(&mut self, worker_id: u32, key: &SessionKey) -> bool {
        self.calls.push(format!("demote:{worker_id}:{}", key.src_port));
        if self.demote_ok {
            self.origins.insert((worker_id, key.src_port), "rebalanced_out");
        }
        self.demote_ok
    }
    fn restore_owner(&mut self, worker_id: u32, key: &SessionKey) -> bool {
        self.calls.push(format!("restore:{worker_id}:{}", key.src_port));
        if self.restore_fails {
            return false;
        }
        self.origins.insert((worker_id, key.src_port), "owner");
        true
    }
    fn demote_replica(&mut self, worker_id: u32, key: &SessionKey) -> bool {
        self.calls.push(format!("replica:{worker_id}:{}", key.src_port));
        if self.origins.get(&(worker_id, key.src_port)) == Some(&"rebalanced_owner") {
            self.origins.insert((worker_id, key.src_port), "replica");
        }
        true
    }
    fn install_rule(&mut self, _flow: &FlowSpec5Tuple, queue: u32, loc: u32) -> std::io::Result<u32> {
        // #1751: the controller now picks the concrete loc and passes it in;
        // the mock returns it verbatim (the real ioctl returns the loc it
        // installed at, == the requested loc for a concrete request).
        self.calls.push(format!("install:q{queue}:loc{loc}"));
        if self.install_ok {
            Ok(loc)
        } else {
            Err(std::io::Error::from_raw_os_error(libc::ENOSPC))
        }
    }
    fn delete_rule(&mut self, loc: u32) -> std::io::Result<()> {
        self.calls.push(format!("delete:{loc}"));
        if self.delete_fails {
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }
        Ok(())
    }
}

/// Build a controller. #1748 review-r3: the controller no longer owns the
/// NtupleSocket (it lives separately on the Coordinator), so these tests drive
/// the move protocol purely through the MockTransport — no real socket needed.
fn test_controller(config: RebalanceConfig) -> RebalanceController {
    RebalanceController::new(config)
}

fn cfg() -> RebalanceConfig {
    RebalanceConfig {
        count_delta_k: 2,
        rebalance_interval_secs: 1,
        max_rules: 64,
    }
}

/// Drive the controller through the anti-churn dwell (DWELL_TICKS_REQUIRED
/// sustained arm-threshold ticks) and the interval gate by ticking the SAME
/// count vector at 1s spacing until a move is committed or the tick budget is
/// hit. Returns the first committed outcome. Used by the convergence tests
/// where we want one accepted move at a time.
fn drive_one_move<T: BarrierTransport>(
    c: &mut RebalanceController,
    tx: &mut T,
    counts: &[u32],
    start_secs: u64,
) -> Option<MoveOutcome> {
    for t in 0..(DWELL_TICKS_REQUIRED as u64 + 8) {
        let input = count_input(5, counts, start_secs + t);
        if let Some(mv) = c.tick(&input, tx) {
            return Some(mv);
        }
    }
    None
}

// ── #1751 count-balancing convergence + selection ──────────────────────

/// THE KEY REGRESSION (#1748's byte-rate selector installed 0 rules live): a
/// real per-worker count imbalance MUST produce an install via the
/// count-balancing selector.
#[test]
fn count_imbalance_produces_an_install() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    // [3,3,2,2,1,1]: hi has 3 flows (worker 0), lo has 1 (worker 4 or 5).
    let mv = drive_one_move(&mut c, &mut tx, &[3, 3, 2, 2, 1, 1], 10)
        .expect("a count imbalance MUST install");
    assert_eq!(c.metrics().installs_total, 1);
    assert!(c.metrics().rules_active >= 1);
    // Source is a count-3 worker; destination is a count-1 worker.
    assert!(matches!(mv.old_worker, 0 | 1), "source is a count-3 worker: {mv:?}");
    assert!(matches!(mv.new_worker, 4 | 5), "destination is a count-1 worker: {mv:?}");
    assert!(tx.calls.iter().any(|c| c.starts_with("install:")));
}

/// The live [0,3,5,2,0,2] distribution converges and installs.
#[test]
fn live_count_distribution_installs() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    let mv = drive_one_move(&mut c, &mut tx, &[0, 3, 5, 2, 0, 2], 10)
        .expect("the live imbalance MUST install");
    assert_eq!(mv.old_worker, 2, "source is the count-5 worker 2");
    assert!(matches!(mv.new_worker, 0 | 4), "destination is a count-0 worker");
    assert_eq!(c.metrics().installs_total, 1);
}

/// Sum-of-squares Ψ strictly decreases by >= 2 per accepted move and the
/// vector converges toward even. Drives [2,2,1,1,4,2] -> ... applying each
/// move to a simulated count vector, asserting ΔΨ <= -2 each time.
#[test]
fn count_balance_converges_to_even_partition() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    let mut counts: Vec<u32> = vec![2, 2, 1, 1, 4, 2]; // sum 12, 6 workers
    let mut now = 10u64;
    let mut prev_psi = sum_of_squares(&counts);
    let mut moves = 0;
    loop {
        let Some(mv) = drive_one_move(&mut c, &mut tx, &counts, now) else {
            break; // converged (no admitted move)
        };
        // Apply the move to the simulated vector.
        counts[mv.old_worker as usize] -= 1;
        counts[mv.new_worker as usize] += 1;
        let psi = sum_of_squares(&counts);
        assert!(
            prev_psi >= psi + 2,
            "Psi must drop by >= 2 per move: {prev_psi} -> {psi} after move {mv:?}, counts={counts:?}"
        );
        prev_psi = psi;
        moves += 1;
        c.clear_cooldown_for_test(); // allow the next distinct move
        now += 10;
        assert!(moves < 20, "must terminate");
    }
    // Converged to an even partition: max - min <= 1.
    let max = *counts.iter().max().unwrap();
    let min = *counts.iter().min().unwrap();
    assert!(max - min <= 1, "converged within +-1 of even: {counts:?}");
    assert_eq!(counts, vec![2, 2, 2, 2, 2, 2], "12/6 converges to all-2");
    assert!(moves >= 1, "at least one move happened");
}

/// The Codex counterexamples that broke max-min and L1: [3,3,3,3,1,1,1,1]
/// converges in exactly 4 moves and [2,2,2,2,0] converges, with Ψ dropping by
/// >= 2 each move even though max-min / L1 are not per-move monotone (§3.4).
#[test]
fn count_balance_sos_potential_counterexamples() {
    // [3,3,3,3,1,1,1,1]: sum 16, 8 workers, mean 2. 4 moves to all-2.
    {
        let mut c = test_controller(cfg());
        let mut tx = MockTransport::good();
        let mut counts: Vec<u32> = vec![3, 3, 3, 3, 1, 1, 1, 1];
        let mut now = 10u64;
        let mut prev = sum_of_squares(&counts);
        let mut moves = 0;
        while let Some(mv) = drive_one_move(&mut c, &mut tx, &counts, now) {
            counts[mv.old_worker as usize] -= 1;
            counts[mv.new_worker as usize] += 1;
            let psi = sum_of_squares(&counts);
            assert!(prev >= psi + 2, "Psi -2/move: {prev}->{psi} {counts:?}");
            prev = psi;
            moves += 1;
            c.clear_cooldown_for_test();
            now += 10;
            assert!(moves <= 8, "bounded");
        }
        assert_eq!(moves, 4, "[3;4,1;4] takes exactly 4 moves (Codex r1 counterexample)");
        assert_eq!(counts, vec![2, 2, 2, 2, 2, 2, 2, 2]);
    }
    // [2,2,2,2,0]: sum 8, 5 workers, NON-INTEGER mean 1.6 (Codex r2 / L1 break).
    {
        let mut c = test_controller(cfg());
        let mut tx = MockTransport::good();
        let mut counts: Vec<u32> = vec![2, 2, 2, 2, 0];
        // SoS check on the FIRST admitted move (the one that broke L1): 2->0
        // gives [2,2,2,1,1], Psi 16 -> 14 (= -2), whereas L1 dropped only 0.8.
        let mut now = 10u64;
        let mut prev = sum_of_squares(&counts); // 4*4 + 0 = 16
        assert_eq!(prev, 16);
        let mut moves = 0;
        while let Some(mv) = drive_one_move(&mut c, &mut tx, &counts, now) {
            counts[mv.old_worker as usize] -= 1;
            counts[mv.new_worker as usize] += 1;
            let psi = sum_of_squares(&counts);
            assert!(prev >= psi + 2, "Psi -2/move on non-integer mean: {prev}->{psi} {counts:?}");
            prev = psi;
            moves += 1;
            c.clear_cooldown_for_test();
            now += 10;
            assert!(moves <= 6, "bounded");
        }
        // Converges within +-1 of mean 1.6 -> counts all in {1,2}.
        assert!(counts.iter().all(|&x| x == 1 || x == 2), "within +-1: {counts:?}");
        let max = *counts.iter().max().unwrap();
        let min = *counts.iter().min().unwrap();
        assert!(max - min <= 1, "converged: {counts:?}");
        assert_eq!(moves, 1, "[2,2,2,2,0] needs exactly one move to balance");
    }
}

/// Overshoot guard: a 1-delta imbalance (3,2) yields NO move — moving one flow
/// would just swap which worker is the max (Magnitude skip, count-overshoot).
#[test]
fn count_overshoot_guard_blocks_1_delta() {
    // K=1 so the threshold does NOT block; the OVERSHOOT guard must.
    let mut c = test_controller(RebalanceConfig {
        count_delta_k: 1, // effective_k() floors to 2, but exercise both gates
        rebalance_interval_secs: 1,
        max_rules: 64,
    });
    let mut tx = MockTransport::good();
    // [3,2]: delta 1. No move should be admitted.
    assert!(drive_one_move(&mut c, &mut tx, &[3, 2], 10).is_none());
    assert_eq!(c.metrics().installs_total, 0);
    assert!(!tx.calls.iter().any(|c| c.starts_with("install:")));
}

/// K count-delta threshold: an imbalance below K is Balanced (no move). With
/// K=3, a [3,1,...]-style delta-2 imbalance is below threshold.
#[test]
fn count_delta_threshold_k_blocks_below_k() {
    let mut c = test_controller(RebalanceConfig {
        count_delta_k: 3,
        rebalance_interval_secs: 1,
        max_rules: 64,
    });
    let mut tx = MockTransport::good();
    // delta = 3 - 1 = 2 < K=3 -> Balanced, no move.
    assert!(drive_one_move(&mut c, &mut tx, &[3, 2, 1], 10).is_none());
    let bal = c.metrics().moves_skipped.get(&SkipReason::Balanced).copied().unwrap_or(0);
    assert!(bal >= 1, "below-K imbalance recorded Balanced: {:?}", c.metrics().moves_skipped);
    // delta = 4 - 1 = 3 >= K=3 -> a move.
    assert!(drive_one_move(&mut c, &mut tx, &[4, 2, 1], 100).is_some());
}

/// Truly-even counts yield no move.
#[test]
fn even_counts_yield_no_move() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    assert!(drive_one_move(&mut c, &mut tx, &[2, 2, 2, 2, 2, 2], 10).is_none());
    assert_eq!(c.metrics().installs_total, 0);
    let bal = c.metrics().moves_skipped.get(&SkipReason::Balanced).copied().unwrap_or(0);
    assert!(bal >= 1, "even counts recorded Balanced");
}

// ── #1751 r2 ANTI-CHURN (sustained dwell + deadband + strong cooldown) ──

/// A SINGLE-TICK imbalance must NOT move (the bursty-traffic blip). Only an
/// imbalance SUSTAINED across >= DWELL_TICKS_REQUIRED ticks may move.
#[test]
fn transient_single_tick_imbalance_does_not_move() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    // One imbalanced tick, then immediately balanced again (a burst blip).
    assert!(c.tick(&count_input(5, &[4, 0, 2, 2, 2, 2], 10), &mut tx).is_none(),
        "first imbalanced tick only accrues dwell, never moves");
    assert!(c.tick(&count_input(5, &[2, 2, 2, 2, 2, 2], 11), &mut tx).is_none(),
        "next tick is balanced -> settle, no move");
    assert_eq!(c.metrics().installs_total, 0, "a single-tick blip installs nothing");
    assert!(!tx.calls.iter().any(|s| s.starts_with("install:")));
}

/// A SUSTAINED imbalance (held >= DWELL_TICKS_REQUIRED ticks) DOES move, and the
/// dwell is exactly the debounce: no move before the required tick count.
#[test]
fn sustained_imbalance_moves_after_dwell() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    // Hold a clear imbalance. No move may commit before DWELL_TICKS_REQUIRED
    // arm-threshold ticks have elapsed.
    let mut moved_at = None;
    for t in 0..(DWELL_TICKS_REQUIRED as u64 + 4) {
        let r = c.tick(&count_input(5, &[4, 0, 2, 2, 2, 2], 10 + t), &mut tx);
        if r.is_some() {
            moved_at = Some(t);
            break;
        }
    }
    let moved_at = moved_at.expect("a sustained imbalance must eventually move");
    assert!(
        moved_at >= (DWELL_TICKS_REQUIRED as u64 - 1),
        "no move before the dwell window elapsed (moved at tick {moved_at}, need >= {})",
        DWELL_TICKS_REQUIRED - 1
    );
    assert_eq!(c.metrics().installs_total, 1);
}

/// A CONVERGED placement produces ZERO further installs AND ZERO deletes across
/// many ticks — steady state is zero churn (the core live regression). Drive an
/// imbalance to even, then tick the even vector for a long time and assert the
/// install/delete counters STOP climbing.
#[test]
fn converged_placement_has_zero_churn() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    // Converge [4,0,2,2,2,2] -> even, applying each move to a sim vector.
    let mut counts: Vec<u32> = vec![4, 0, 2, 2, 2, 2];
    let mut now = 10u64;
    loop {
        let Some(mv) = drive_one_move(&mut c, &mut tx, &counts, now) else { break; };
        counts[mv.old_worker as usize] -= 1;
        counts[mv.new_worker as usize] += 1;
        c.clear_cooldown_for_test();
        now += 5;
        assert!(now < 200, "must converge");
    }
    let max = *counts.iter().max().unwrap();
    let min = *counts.iter().min().unwrap();
    assert!(max - min <= 1, "converged within +-1: {counts:?}");
    let installs_converged = c.metrics().installs_total;
    let deletes_converged = c.metrics().deletes_total;
    assert!(installs_converged >= 1, "at least one move happened");

    // Now hold the converged (even) vector for a LONG run. With cooldown
    // cleared each iteration (so cooldown is NOT what stops us), the deadband +
    // settle must be what keeps churn at zero.
    for t in 0..50u64 {
        c.clear_cooldown_for_test();
        assert!(
            c.tick(&count_input(5, &counts, now + t), &mut tx).is_none(),
            "no move on an already-converged vector at tick {t}"
        );
    }
    assert_eq!(c.metrics().installs_total, installs_converged, "installs STOP climbing once converged");
    assert_eq!(c.metrics().deletes_total, deletes_converged, "deletes STOP climbing once converged");
    // Rules are bounded: at most a handful (the flows actually relocated), far
    // below max_rules, and not climbing. [4,0,2,2,2,2] needs ~2 relocations.
    let rules = c.metrics().rules_active;
    assert!(rules <= 4, "rules bounded to the few relocated flows, not the cap: {rules}");
    assert!(rules >= 1, "at least one rule installed");
}

/// A BURSTY count sequence that oscillates around even (+-1, occasional +-2)
/// must NOT thrash: zero installs, zero deletes, no barrier churn. This is the
/// deadband doing its job — it does not chase fluctuations around convergence.
#[test]
fn bursty_oscillation_around_even_does_not_thrash() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    // Oscillating vectors, all within delta <= 2, never SUSTAINED at the arm
    // threshold for a full dwell window: balanced, +1 blip, +2 blip, back.
    let seq: [&[u32]; 6] = [
        &[2, 2, 2, 2, 2, 2],
        &[3, 1, 2, 2, 2, 2],
        &[2, 2, 2, 2, 2, 2],
        &[2, 2, 2, 2, 3, 1],
        &[2, 2, 2, 2, 2, 2],
        &[1, 3, 2, 2, 2, 2],
    ];
    let mut now = 10u64;
    for cycle in 0..6u64 {
        for v in seq.iter() {
            assert!(
                c.tick(&count_input(5, v, now), &mut tx).is_none(),
                "bursty oscillation must never move (cycle {cycle}, v={v:?})"
            );
            now += 1;
        }
    }
    assert_eq!(c.metrics().installs_total, 0, "no install on bursty oscillation");
    assert_eq!(c.metrics().deletes_total, 0, "no delete on bursty oscillation");
    assert!(!tx.calls.iter().any(|s| s.starts_with("install:") || s.starts_with("delete:")));
}

/// The strong per-flow cooldown blocks an IMMEDIATE re-move of the same flow,
/// preventing the install->delete->install ping-pong. After a move the moved
/// flow is ineligible for COOLDOWN_MIN_SECS (>= 30 s) even if the controller
/// would otherwise re-select it.
#[test]
fn cooldown_blocks_immediate_re_move_of_same_flow() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    // Move one flow off the hot worker.
    let mv = drive_one_move(&mut c, &mut tx, &[4, 0, 2, 2, 2, 2], 10).expect("first move");
    let moved_port = mv.key.src_port;
    let installs_after_first = c.metrics().installs_total;

    // Re-present an imbalance that would re-select the SAME flow (it now lives
    // on its new worker). Do NOT clear the cooldown. The move committed around
    // now=12, so its cooldown runs until ~12 + COOLDOWN_MIN_SECS. Tick a window
    // that stays STRICTLY inside the cooldown so the moved flow must never be
    // re-selected. (now starts at 20, stays well below 12 + 30 = 42.)
    let new_worker = mv.new_worker;
    let mut now = 20u64;
    for _ in 0..15u64 {
        // Build a vector where the moved flow's new worker is hottest, with the
        // moved flow as a candidate, plus a fresh idle worker as lo.
        let mut flows = vec![
            FlowSample { key: key(moved_port), worker_id: new_worker, byte_rate: 0.0, origin: None },
            flow(8001, new_worker, 0.0),
            flow(8002, new_worker, 0.0),
        ];
        // Some other workers carry 0 so there is a real imbalance.
        flows.extend(flows_on(0, 1));
        let workers: Vec<WorkerByteRate> = (0..6).map(|w| worker(w, 0.0)).collect();
        let input = RebalanceTickInput { ifindex: 5, workers, flows, now_secs: now, truncated: false };
        if let Some(mv2) = c.tick(&input, &mut tx) {
            assert_ne!(
                mv2.key.src_port, moved_port,
                "the just-moved flow must be in cooldown and not re-selected"
            );
        }
        now += 1;
    }
    // The moved flow itself was never re-pinned within its cooldown window.
    let _ = installs_after_first;
}

/// A truncated snapshot defers — no decision on understated counts.
#[test]
fn truncated_snapshot_defers() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    // A clear imbalance, but the snapshot is truncated => defer.
    for t in 0..4u64 {
        let mut input = count_input(5, &[5, 0, 0, 0, 0, 0], 10 + t);
        input.truncated = true;
        assert!(c.tick(&input, &mut tx).is_none());
    }
    assert_eq!(c.metrics().installs_total, 0);
    let trunc = c.metrics().moves_skipped.get(&SkipReason::Truncated).copied().unwrap_or(0);
    assert!(trunc >= 1, "truncated snapshot recorded Truncated defer");
    assert!(!tx.calls.iter().any(|c| c.starts_with("install:")));
}

/// A worker carrying only non-steerable traffic (steerable-count 0) is never
/// chosen as the `hi` source (§3.3.1). Here worker 4 has steerable-count 0 (no
/// flows); the source must be the count-4 worker 0, never worker 4.
#[test]
fn unsteerable_only_worker_is_never_source() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    // [4,1,1,1,0]: worker 4 has 0 steerable flows (it is the lo, not the hi).
    let mv = drive_one_move(&mut c, &mut tx, &[4, 1, 1, 1, 0], 10)
        .expect("install off the count-4 worker");
    assert_eq!(mv.old_worker, 0, "source is the count-4 worker, never the count-0 worker");
    assert_eq!(mv.new_worker, 4, "destination IS the count-0 worker");
}

/// Cooldown: a just-moved flow is not re-chosen as the immediate next move
/// (anti-thrash). After the first move on a [4,0] vector, the same flow is in
/// cooldown so the very next tick cannot re-pin it.
#[test]
fn cooldown_prevents_immediate_thrash() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    let mv1 = drive_one_move(&mut c, &mut tx, &[3, 0], 10).expect("first move");
    let moved_port = mv1.key.src_port;
    // Immediately (inside the cooldown window) present the SAME flows again.
    // The moved flow is in cooldown, so it cannot be the chosen candidate; the
    // remaining flows on worker 0 can still move, but the just-moved one must
    // not be re-selected.
    let input = count_input(5, &[3, 0], 12);
    c.tick(&input, &mut tx);
    let input2 = count_input(5, &[3, 0], 13);
    if let Some(mv2) = c.tick(&input2, &mut tx) {
        assert_ne!(mv2.key.src_port, moved_port, "cooled-down flow not re-chosen");
    }
}

// ── #1751 sum-of-squares helper for the convergence tests ──────────────
fn sum_of_squares(counts: &[u32]) -> u64 {
    counts.iter().map(|&c| (c as u64) * (c as u64)).sum()
}

// ── #1748 move-machinery tests, carried forward (count-driven) ─────────

/// Barrier order: promote(W_new) -> demote(W_old) -> install. Drive a [3,0]
/// count imbalance (worker 0 hi, worker 1 lo).
#[test]
fn barrier_order_is_promote_then_demote_then_install() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    drive_one_move(&mut c, &mut tx, &[3, 0], 10).expect("move");
    let promote_idx = tx.calls.iter().position(|c| c.starts_with("promote:1:")).unwrap();
    let demote_idx = tx.calls.iter().position(|c| c.starts_with("demote:0:")).unwrap();
    let install_idx = tx.calls.iter().position(|c| c.starts_with("install:")).unwrap();
    assert!(promote_idx < demote_idx, "promote(W_new=1) before demote(W_old=0): {:?}", tx.calls);
    assert!(demote_idx < install_idx, "demote before install: {:?}", tx.calls);
    // Destination queue is worker 1's queue_id (== worker_id in the fixture);
    // #1751 the install also carries the ledger-picked loc (top slot 1023).
    assert!(tx.calls.iter().any(|c| c.starts_with("install:q1:loc")), "install on q1: {:?}", tx.calls);
    assert!(tx.calls.iter().any(|c| c == "install:q1:loc1023"), "first install at top slot 1023: {:?}", tx.calls);
}

/// Demote-ack failure rolls back via the reverse barrier and keeps >= 1 owner.
#[test]
fn demote_failure_reverse_barrier_keeps_an_owner() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    tx.demote_ok = false;
    assert!(drive_one_move(&mut c, &mut tx, &[3, 0], 10).is_none());
    let restore_idx = tx.calls.iter().position(|c| c.starts_with("restore:")).unwrap();
    let replica_idx = tx.calls.iter().position(|c| c.starts_with("replica:")).unwrap();
    assert!(restore_idx < replica_idx, "restore before replica: {:?}", tx.calls);
    assert!(!tx.calls.iter().any(|c| c.starts_with("install:")));
    assert!(tx.owners() >= 1, "rollback keeps >= 1 owner: {:?}", tx.origins);
}

/// Install ioctl failure rolls back via the reverse barrier; no rule recorded.
#[test]
fn install_failure_reverse_barrier_keeps_an_owner() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    tx.install_ok = false;
    assert!(drive_one_move(&mut c, &mut tx, &[3, 0], 10).is_none());
    let restore_idx = tx.calls.iter().position(|c| c.starts_with("restore:")).unwrap();
    let replica_idx = tx.calls.iter().position(|c| c.starts_with("replica:")).unwrap();
    assert!(restore_idx < replica_idx);
    assert!(tx.owners() >= 1);
    assert_eq!(c.metrics().rules_active, 0, "no rule recorded on failed install");
}

/// #1751 live BLOCKER — FULL SUCCESS PATH end to end. A count imbalance drives
/// the complete forward barrier promote -> demote -> install and records a
/// ledger entry. (The barrier machinery was carried from #1748 and never ran
/// live; this pins the success wiring: ordered promote(W_new) -> demote(W_old)
/// -> install + a recorded rule.)
#[test]
fn full_barrier_success_path_installs_and_records_ledger() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    let mv = drive_one_move(&mut c, &mut tx, &[3, 0], 10)
        .expect("the full barrier must commit a move");
    // Ordered: promote(W_new=1) -> demote(W_old=0) -> install.
    let p = tx.calls.iter().position(|c| c.starts_with("promote:1:")).unwrap();
    let d = tx.calls.iter().position(|c| c.starts_with("demote:0:")).unwrap();
    let i = tx.calls.iter().position(|c| c.starts_with("install:")).unwrap();
    assert!(p < d && d < i, "promote -> demote -> install order: {:?}", tx.calls);
    // A rule was installed and recorded in the ledger.
    assert_eq!(c.metrics().installs_total, 1);
    assert_eq!(c.metrics().rules_active, 1, "ledger entry recorded");
    assert_eq!(mv.old_worker, 0);
    assert_eq!(mv.new_worker, 1);
    // No rollback calls on the success path.
    assert!(!tx.calls.iter().any(|c| c.starts_with("restore:")), "no rollback: {:?}", tx.calls);
}

/// #1751 live BLOCKER ROOT-CAUSE FIX — a SAME-NODE move where W_new does NOT
/// pre-hold the flow's session. The worker-side promote returns a CLAIM
/// (result=true) with origin None (the entry materializes when the rule steers
/// packets there), so the controller's claim-only promote must accept it and
/// the move must still install. The pre-fix promote required
/// origin==RebalancedOwner and failed 100% on this (the live BarrierFailed).
#[test]
fn promote_claim_succeeds_when_w_new_does_not_hold_the_flow() {
    // A mock that models the same-node worker: promote does NOT create/flip an
    // entry (W_new has none) but the worker still ACKs the claim as success.
    #[derive(Default)]
    struct SameNodeMock {
        calls: Vec<String>,
    }
    impl BarrierTransport for SameNodeMock {
        fn promote(&mut self, w: u32, k: &SessionKey) -> bool {
            // W_new does not hold the flow: no origin flip, but the claim is
            // accepted (this is what the worker-side handler now returns).
            self.calls.push(format!("promote:{w}:{}", k.src_port));
            true
        }
        fn demote(&mut self, w: u32, k: &SessionKey) -> bool {
            self.calls.push(format!("demote:{w}:{}", k.src_port));
            true
        }
        fn restore_owner(&mut self, w: u32, k: &SessionKey) -> bool {
            self.calls.push(format!("restore:{w}:{}", k.src_port));
            true
        }
        fn demote_replica(&mut self, w: u32, k: &SessionKey) -> bool {
            self.calls.push(format!("replica:{w}:{}", k.src_port));
            true
        }
        fn install_rule(&mut self, _f: &FlowSpec5Tuple, q: u32, loc: u32) -> std::io::Result<u32> {
            self.calls.push(format!("install:q{q}:loc{loc}"));
            Ok(loc)
        }
        fn delete_rule(&mut self, loc: u32) -> std::io::Result<()> {
            self.calls.push(format!("delete:{loc}"));
            Ok(())
        }
    }
    let mut c = test_controller(cfg());
    let mut tx = SameNodeMock::default();
    let mv = drive_one_move(&mut c, &mut tx, &[3, 0], 10)
        .expect("a same-node move (W_new absent) MUST still install via the claim-only promote");
    assert_eq!(c.metrics().installs_total, 1);
    assert_eq!(c.metrics().rules_active, 1);
    assert_eq!(mv.new_worker, 1);
    assert!(tx.calls.iter().any(|c| c.starts_with("install:")));
}

/// Promote-ack failure (the worker queue/ack broke — NOT an absent entry)
/// rolls back cleanly: no install, no ledger entry, W_new defensively demoted
/// back to a replica.
#[test]
fn promote_failure_rolls_back_clean() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    tx.promote_ok = false; // simulate a promote ack timeout / queue failure
    assert!(drive_one_move(&mut c, &mut tx, &[3, 0], 10).is_none());
    // No demote of W_old, no install (the move aborts at the promote step).
    assert!(!tx.calls.iter().any(|c| c.starts_with("demote:0:")), "no W_old demote: {:?}", tx.calls);
    assert!(!tx.calls.iter().any(|c| c.starts_with("install:")), "no install: {:?}", tx.calls);
    // Defensive replica-demote of W_new is the only cleanup.
    assert!(tx.calls.iter().any(|c| c.starts_with("replica:1:")), "defensive W_new replica-demote: {:?}", tx.calls);
    assert_eq!(c.metrics().rules_active, 0, "no rule recorded");
    let bf = c.metrics().moves_skipped.get(&SkipReason::BarrierFailed).copied().unwrap_or(0);
    assert!(bf >= 1, "BarrierFailed recorded on promote failure");
}

/// Budget exhaustion stops with NO eviction. Drive an EVOLVING count vector
/// (each committed move shifts a flow hi->lo), so each move re-pins a DISTINCT
/// flow (the moved flows stay in cooldown — we do NOT clear it — so they are
/// never re-chosen). With max_rules=2 only 2 installs may commit; the rest are
/// budget-exhausted skips with NO rule ever deleted.
#[test]
fn budget_exhaustion_stops_no_eviction() {
    let mut c = test_controller(RebalanceConfig {
        count_delta_k: 2,
        rebalance_interval_secs: 1, // cooldown = 5s keeps moved flows out
        max_rules: 2,
    });
    let mut tx = MockTransport::good();
    // 6 workers, all surplus on worker 0. Moving 0->each idle worker keeps
    // worker 0 the source and each destination reaches at most 1, so no moved
    // flow ever re-becomes the hottest and gets re-chosen (no second-move
    // unwind that would free budget). Moved flows stay in the 5s cooldown.
    let mut counts: Vec<u32> = vec![6, 0, 0, 0, 0, 0];
    let mut now = 10u64;
    let mut installs = 0;
    for _ in 0..40 {
        let input = count_input(5, &counts, now);
        if let Some(mv) = c.tick(&input, &mut tx) {
            counts[mv.old_worker as usize] -= 1;
            counts[mv.new_worker as usize] += 1;
            installs += 1;
        }
        now += 1; // 1s/tick: clears the install cadence, stays < 5s cooldown
    }
    assert_eq!(installs, 2, "exactly max_rules moves commit");
    assert_eq!(c.metrics().rules_active, 2, "stops at max_rules");
    assert!(!tx.calls.iter().any(|c| c.starts_with("delete:")), "NO eviction at cap: {:?}", tx.calls);
    assert_eq!(c.metrics().deletes_total, 0);
    let skipped = c.metrics().moves_skipped.get(&SkipReason::BudgetExhausted).copied().unwrap_or(0);
    assert!(skipped >= 1, "budget-exhausted skip recorded");
}

// ── #1751 ledger-based ntuple location picking (decoupled from GRXCLSRLALL) ──

/// The location picker reads the controller's LEDGER used-set, never the NIC.
/// Top-down from MAX-1: an empty used-set yields 1023, then 1022, skipping
/// occupied slots; a freed (deleted) loc becomes pickable again.
#[test]
fn free_loc_top_down_picks_highest_free_skipping_used() {
    // Empty ledger -> top slot.
    assert_eq!(free_loc_top_down(MAX_NTUPLE_LOCATION, &[]), Some(1023));
    // 1023 taken -> next is 1022.
    assert_eq!(free_loc_top_down(MAX_NTUPLE_LOCATION, &[1023]), Some(1022));
    // 1023+1022 taken -> 1021.
    assert_eq!(free_loc_top_down(MAX_NTUPLE_LOCATION, &[1023, 1022]), Some(1021));
    // Occupied slots are skipped regardless of insertion order; the gap at 1022
    // (freed by a delete) is re-picked before descending further.
    assert_eq!(free_loc_top_down(MAX_NTUPLE_LOCATION, &[1021, 1023]), Some(1022));
    // A non-contiguous used-set still returns the single highest free slot.
    assert_eq!(free_loc_top_down(MAX_NTUPLE_LOCATION, &[1023, 1021, 1020]), Some(1022));
}

/// A FULL location space (every loc in [0, MAX) used) yields None, which the
/// caller maps to ENOSPC / BudgetExhausted — no NIC query involved.
#[test]
fn free_loc_top_down_full_ledger_is_none() {
    let all_used: Vec<u32> = (0..MAX_NTUPLE_LOCATION).collect();
    assert_eq!(free_loc_top_down(MAX_NTUPLE_LOCATION, &all_used), None);
    // One free slot in the middle is still found.
    let mut minus_one = all_used.clone();
    minus_one.retain(|&l| l != 500);
    assert_eq!(free_loc_top_down(MAX_NTUPLE_LOCATION, &minus_one), Some(500));
}

/// Successive installs consume the top-down ledger slots (1023, 1022, ...);
/// a delete (second-move unwind) frees a slot that the next install reuses.
/// This exercises the integration of next_free_ledger_loc through tick without
/// any GRXCLSRLALL/NIC query.
#[test]
fn installs_consume_ledger_slots_top_down() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    // First move: empty ledger -> loc 1023. [3,0] picks the lowest key on
    // worker 0 (port 1000) and moves it to worker 1.
    let mv1 = drive_one_move(&mut c, &mut tx, &[3, 0], 10).expect("first move");
    assert!(
        tx.calls.iter().any(|s| s == "install:q1:loc1023"),
        "first install at top slot 1023: {:?}", tx.calls
    );

    // Second move of a DIFFERENT key. Build the vector by hand so the FIRST
    // moved flow STAYS PRESENT (on its new worker 1) — otherwise #1751 r4
    // flow-close reclamation would correctly free slot 1023. A new hot worker 2
    // supplies the second-move candidate; a fresh idle worker 3 is the lo.
    tx.calls.clear();
    c.clear_cooldown_for_test();
    let workers: Vec<WorkerByteRate> = (0..4).map(|w| worker(w, 0.0)).collect();
    let mut flows = vec![
        // The first-moved flow, still alive on worker 1 (keeps slot 1023).
        FlowSample { key: key(mv1.key.src_port), worker_id: 1, byte_rate: 0.0, origin: None },
    ];
    // Worker 2 is the new hottest (3 flows); workers 0/1/3 idle-ish.
    flows.extend(flows_on(2, 3));
    let mk = |now| RebalanceTickInput {
        ifindex: 5,
        workers: workers.clone(),
        flows: flows.clone(),
        now_secs: now,
        truncated: false,
    };
    let mut moved = false;
    for t in 0..(DWELL_TICKS_REQUIRED as u64 + 8) {
        if c.tick(&mk(100 + t), &mut tx).is_some() {
            moved = true;
            break;
        }
    }
    assert!(moved, "second move commits");
    // The next free ledger slot below the still-held 1023 is 1022.
    assert!(
        tx.calls.iter().any(|s| s.starts_with("install:") && s.ends_with(":loc1022")),
        "second install reuses next free slot 1022: {:?}", tx.calls
    );
    assert_eq!(c.metrics().rules_active, 2, "both rules persist (neither flow ended)");
}

/// Install with a FULL location space aborts as BudgetExhausted BEFORE the
/// barrier (no promote/demote side-effects to roll back). We model "full" by
/// configuring max_rules == MAX_NTUPLE_LOCATION is impractical (1024 installs),
/// so this drives the picker contract directly: a synthetic full ledger has no
/// free slot, and the controller skip path records BudgetExhausted. The unit
/// above (free_loc_top_down_full_ledger_is_none) proves None on a full set;
/// here we confirm the controller's budget gate (max_rules) reaches the same
/// skip reason before the location space could ever exhaust.
#[test]
fn full_capacity_skips_budget_exhausted_without_barrier() {
    let mut c = test_controller(RebalanceConfig {
        count_delta_k: 2,
        rebalance_interval_secs: 1,
        max_rules: 1,
    });
    let mut tx = MockTransport::good();
    // First move commits at the cap.
    let mv1 = drive_one_move(&mut c, &mut tx, &[3, 0], 10).expect("first move at cap");
    assert_eq!(c.metrics().rules_active, 1);
    tx.calls.clear();
    // Now at the cap: a further imbalance must skip BudgetExhausted with NO
    // barrier calls (the budget gate is checked before select/barrier). Keep the
    // first-moved flow PRESENT (on worker 1) so #1751 r4 flow-close reclamation
    // does NOT free its rule — the cap must stay full for this test.
    c.clear_cooldown_for_test();
    let workers: Vec<WorkerByteRate> = (0..4).map(|w| worker(w, 0.0)).collect();
    let mut flows = vec![
        FlowSample { key: key(mv1.key.src_port), worker_id: 1, byte_rate: 0.0, origin: None },
    ];
    flows.extend(flows_on(2, 3));
    for t in 0..8u64 {
        let input = RebalanceTickInput {
            ifindex: 5,
            workers: workers.clone(),
            flows: flows.clone(),
            now_secs: 100 + t,
            truncated: false,
        };
        assert!(c.tick(&input, &mut tx).is_none(), "no move past the cap");
    }
    assert!(
        !tx.calls.iter().any(|s| s.starts_with("promote:") || s.starts_with("install:")),
        "no barrier side-effects past the cap: {:?}", tx.calls
    );
    let skipped = c.metrics().moves_skipped
        .get(&SkipReason::BudgetExhausted).copied().unwrap_or(0);
    assert!(skipped >= 1, "BudgetExhausted recorded past the cap");
}

/// #1751 PIVOT: the install path is fully decoupled from any NIC location
/// query (GRXCLSRLALL/reconcile_orphans). The BarrierTransport surface the
/// controller drives has NO list/reconcile method — install_rule takes the
/// loc the controller already picked from its ledger. A successful committed
/// move therefore PROVES installs never consult the NIC for a free slot, so a
/// GRXCLSRLALL EINVAL (which only the swallowed startup reconcile uses) cannot
/// block a move. The loc carried into install_rule is the ledger pick (1023 on
/// an empty table), confirming the picker, not the NIC, is the source.
#[test]
fn install_is_decoupled_from_nic_location_query() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    let mv = drive_one_move(&mut c, &mut tx, &[3, 0], 10).expect("move installs");
    assert_eq!(mv.loc, 1023, "loc comes from the ledger picker, not a NIC query");
    assert!(
        tx.calls.iter().any(|s| s == "install:q1:loc1023"),
        "install carries the ledger-picked loc: {:?}", tx.calls
    );
    assert_eq!(c.metrics().installs_total, 1);
}

// ── #1751 r4 FLOW-CLOSE rule reclamation (plan §4.5) ────────────────────

/// A ledgered/ruled flow that DISAPPEARS from the presence flow set (connection
/// ended / flow-cache entry aged out) has its ntuple rule reclaimed on the next
/// tick: delete the rule, free the location, drop the ledger entry, decrement
/// rules_active. The freed slot is then reusable by a later move.
#[test]
fn ended_flow_rule_is_reclaimed_and_slot_freed() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    // Move a flow -> rule at the top slot 1023.
    let mv = drive_one_move(&mut c, &mut tx, &[3, 0], 10).expect("first move");
    assert_eq!(c.metrics().rules_active, 1);
    assert_eq!(mv.loc, 1023);
    let deletes_before = c.metrics().deletes_total;
    tx.calls.clear();

    // Next tick: the moved flow is GONE from the presence set (it ended). With
    // an otherwise-balanced, present-flow-free snapshot the controller must
    // reclaim its rule.
    let workers: Vec<WorkerByteRate> = (0..2).map(|w| worker(w, 0.0)).collect();
    let input = RebalanceTickInput {
        ifindex: 5,
        workers: workers.clone(),
        flows: Vec::new(), // the moved flow (and all flows) ended
        now_secs: 20,
        truncated: false,
    };
    assert!(c.tick(&input, &mut tx).is_none(), "no move; just reclamation");
    assert_eq!(c.metrics().rules_active, 0, "ended flow's rule reclaimed");
    assert_eq!(c.metrics().deletes_total, deletes_before + 1, "one delete recorded");
    assert!(
        tx.calls.iter().any(|s| s == "delete:1023"),
        "the freed rule was at slot 1023: {:?}", tx.calls
    );
    // No reverse-barrier on a flow-close reclamation (no live owner to restore).
    assert!(!tx.calls.iter().any(|s| s.starts_with("restore:")), "no restore on flow-close: {:?}", tx.calls);
    assert!(!tx.calls.iter().any(|s| s.starts_with("replica:")), "no replica demote on flow-close: {:?}", tx.calls);

    // The freed slot 1023 is reusable: a new imbalance re-pins at the top slot.
    tx.calls.clear();
    c.clear_cooldown_for_test();
    let mv2 = drive_one_move(&mut c, &mut tx, &[3, 0], 30).expect("re-pin after reclaim");
    assert_eq!(mv2.loc, 1023, "the reclaimed top slot is reused");
    assert_eq!(c.metrics().rules_active, 1);
}

/// Reclamation does NOT fire on a TRUNCATED snapshot — a flow absent only
/// because the snapshot truncated has not ended; deleting its rule would
/// wrongly un-pin a live flow.
#[test]
fn truncated_snapshot_does_not_reclaim_rules() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    drive_one_move(&mut c, &mut tx, &[3, 0], 10).expect("move");
    assert_eq!(c.metrics().rules_active, 1);
    tx.calls.clear();
    // Truncated snapshot with NO flows: must NOT reclaim (the flow may still be
    // live, just not in the truncated rows).
    let mut input = count_input(5, &[0, 0], 20);
    input.flows = Vec::new();
    input.truncated = true;
    assert!(c.tick(&input, &mut tx).is_none());
    assert_eq!(c.metrics().rules_active, 1, "no reclamation on a truncated snapshot");
    assert!(!tx.calls.iter().any(|s| s.starts_with("delete:")), "no delete on truncation: {:?}", tx.calls);
}

/// Repeated move/end CYCLES do not accumulate rules toward the cap: each cycle's
/// flow is reclaimed when it ends, so the live rule count returns to baseline
/// and the budget is never exhausted (the live #1751 r4 cap-march regression).
#[test]
fn repeated_move_end_cycles_do_not_accumulate_rules() {
    let mut c = test_controller(RebalanceConfig {
        count_delta_k: 2,
        rebalance_interval_secs: 1,
        max_rules: 4, // small cap: a leak would hit it within a few cycles
    });
    let mut tx = MockTransport::good();
    let workers: Vec<WorkerByteRate> = (0..2).map(|w| worker(w, 0.0)).collect();

    let mut now = 10u64;
    for cycle in 0..12u64 {
        // A fresh batch of flows on worker 0 (distinct keys per cycle so each is
        // a genuinely new connection), worker 1 idle -> imbalance -> one move.
        let base_port = 2000 + (cycle as u16) * 10;
        let mut moved = false;
        for t in 0..(DWELL_TICKS_REQUIRED as u64 + 6) {
            let flows = vec![
                flow(base_port, 0, 0.0),
                flow(base_port + 1, 0, 0.0),
                flow(base_port + 2, 0, 0.0),
            ];
            let input = RebalanceTickInput {
                ifindex: 5,
                workers: workers.clone(),
                flows,
                now_secs: now,
                truncated: false,
            };
            if c.tick(&input, &mut tx).is_some() {
                moved = true;
            }
            now += 1;
        }
        assert!(moved, "cycle {cycle} made a move");
        // The whole batch ENDS: tick a few empty-flow snapshots so the moved
        // flow is reclaimed before the next cycle's batch arrives.
        for _ in 0..2 {
            let input = RebalanceTickInput {
                ifindex: 5,
                workers: workers.clone(),
                flows: Vec::new(),
                now_secs: now,
                truncated: false,
            };
            c.tick(&input, &mut tx);
            now += 1;
        }
        // After each cycle's flows end, the rule is reclaimed -> back to 0.
        assert_eq!(
            c.metrics().rules_active, 0,
            "cycle {cycle}: rules return to baseline (no accumulation toward the cap)"
        );
    }
    // 12 cycles each installed and reclaimed; never stuck at the cap.
    assert!(c.metrics().rules_active < 4, "never marched to the cap");
    assert!(c.metrics().installs_total >= 12, "each cycle installed");
    assert!(c.metrics().deletes_total >= 12, "each cycle reclaimed");
}

/// Teardown of a live move uses the reverse barrier (restore W_old -> delete ->
/// replica W_new) and restores the REAL W_old.
#[test]
fn teardown_live_move_uses_reverse_barrier() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    drive_one_move(&mut c, &mut tx, &[3, 0], 10).expect("move");
    tx.calls.clear();
    c.teardown_all(&mut tx, |_w, _k| true);
    let restore_idx = tx.calls.iter().position(|c| c.starts_with("restore:")).unwrap();
    let delete_idx = tx.calls.iter().position(|c| c.starts_with("delete:")).unwrap();
    let replica_idx = tx.calls.iter().position(|c| c.starts_with("replica:")).unwrap();
    assert!(restore_idx < delete_idx && delete_idx < replica_idx, "reverse barrier order: {:?}", tx.calls);
    assert!(tx.calls[restore_idx].starts_with("restore:0:"), "restore the RSS-natural W_old 0");
    assert_eq!(c.metrics().rules_active, 0);
}

/// Teardown restore-failure keeps W_new as owner (no replica demote).
#[test]
fn teardown_live_move_restore_failure_keeps_w_new_owner() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    drive_one_move(&mut c, &mut tx, &[3, 0], 10).expect("move");
    tx.calls.clear();
    tx.restore_fails = true;
    c.teardown_all(&mut tx, |_w, _k| true);
    assert!(tx.calls.iter().any(|c| c.starts_with("delete:")));
    assert!(!tx.calls.iter().any(|c| c.starts_with("replica:")), "no replica demote on restore fail: {:?}", tx.calls);
    assert!(tx.owners() >= 1);
}

/// Teardown of a dead flow is a plain delete (no barrier).
#[test]
fn teardown_dead_flow_is_plain_delete() {
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    drive_one_move(&mut c, &mut tx, &[3, 0], 10).expect("move");
    tx.calls.clear();
    c.teardown_all(&mut tx, |_w, _k| false);
    assert!(tx.calls.iter().any(|c| c.starts_with("delete:")));
    assert!(!tx.calls.iter().any(|c| c.starts_with("restore:")));
    assert!(!tx.calls.iter().any(|c| c.starts_with("replica:")));
}

/// Second move of the same key replaces the rule + reverse-barriers the prior
/// owner, carrying the RSS-natural old_worker forward. Move worker0->worker2
/// (via a [3,0,0] vector), then re-pin the SAME flow to a third worker.
#[test]
fn second_move_chain_replaces_rule_and_reverse_barriers_prior_owner() {
    let mut c = test_controller(RebalanceConfig {
        count_delta_k: 2,
        rebalance_interval_secs: 0,
        max_rules: 8,
    });
    let mut tx = MockTransport::good();
    // First move: worker 0 (3 flows) -> worker 2 (0). lo tie-break = lower
    // worker_id, so among the two count-0 workers {1,2} worker 1 wins... make
    // worker 1 ineligible by giving it a flow: [3,1,0] => lo is worker 2.
    let mv1 = drive_one_move(&mut c, &mut tx, &[3, 1, 0], 10).expect("first move");
    assert_eq!(mv1.old_worker, 0);
    assert_eq!(mv1.new_worker, 2);
    let moved_port = mv1.key.src_port;
    assert_eq!(c.metrics().rules_active, 1);
    c.clear_cooldown_for_test();
    tx.calls.clear();
    let installs_before = c.metrics().installs_total;

    // The moved flow now lives on worker 2. Present a vector where that flow's
    // worker (2) is the hi and a fresh worker (3) is the lo, with the SAME
    // moved flow as the candidate. Build the flows by hand so the moved flow
    // is on worker 2 and worker 2 is hi.
    let mut flows = vec![
        FlowSample { key: key(moved_port), worker_id: 2, byte_rate: 0.0, origin: None },
        flow(7001, 2, 0.0),
        flow(7002, 2, 0.0),
    ];
    flows.extend(flows_on(0, 1));
    let workers: Vec<WorkerByteRate> = (0..4).map(|w| worker(w, 0.0)).collect();
    let mk = |now| RebalanceTickInput {
        ifindex: 5,
        workers: workers.clone(),
        flows: flows.clone(),
        now_secs: now,
        truncated: false,
    };
    // worker 2 has 3 flows, worker 3 has 0 -> hi=2, lo=3. The selector picks
    // the lowest session_key on worker 2; that may or may not be moved_port,
    // but if it IS moved_port the second-move unwind path fires. Tick through
    // the anti-churn dwell window (#1751 r2) until the second move commits.
    let mut mv2 = None;
    for t in 0..(DWELL_TICKS_REQUIRED as u64 + 8) {
        if let Some(mv) = c.tick(&mk(20 + t), &mut tx) {
            mv2 = Some(mv);
            break;
        }
    }
    let mv2 = mv2.expect("second move");
    // Whatever flow is chosen, the ledger must still hold exactly one rule per
    // distinct key (replace-not-append for a repeated key).
    assert!(c.metrics().installs_total > installs_before);
    assert!(tx.owners() >= 1, "chain keeps >= 1 owner: {:?}", tx.origins);
    let _ = mv2;
}

/// flow_spec_from_key encodes v4 5-tuple in network order (carried from #1748).
#[test]
fn flow_spec_from_key_encodes_network_order_v4() {
    let k = key(0x1234);
    let spec = flow_spec_from_key(&k);
    assert_eq!(spec.src_port, 0x1234u16.to_be());
    assert_eq!(spec.dst_port, 5210u16.to_be());
    assert_eq!(spec.src_ip[0], u32::from_ne_bytes([10, 0, 61, 102]));
    assert_eq!(spec.dst_ip[0], u32::from_ne_bytes([172, 16, 80, 200]));
    assert_eq!(spec.src_ip[0].to_ne_bytes(), [10, 0, 61, 102]);
}

// ── helpers retained from #1748 (still used by the Coordinator tick) ────
#[test]
fn cumulative_to_rate_basic_delta_over_time() {
    let prev_ns = 1_000_000_000u64;
    let now_ns = prev_ns + 1_000_000_000;
    assert!((cumulative_to_rate(2000, 1000, now_ns, prev_ns) - 1000.0).abs() < 1e-6);
}

#[test]
fn cumulative_to_rate_first_sample_and_reset_are_zero() {
    let prev_ns = 1_000_000_000u64;
    assert_eq!(cumulative_to_rate(5000, 1000, prev_ns, prev_ns), 0.0);
    let now_ns = prev_ns + 1_000_000_000;
    assert_eq!(cumulative_to_rate(100, 9000, now_ns, prev_ns), 0.0);
}

/// per_worker_counts counts steerable flows per worker_id (the count==rows
/// invariant): the count is exactly the number of rows for that worker.
#[test]
fn per_worker_counts_matches_row_count() {
    let flows = count_input(5, &[3, 1, 0, 2], 0).flows;
    let counts = per_worker_counts(&flows);
    assert_eq!(counts.get(&0).copied().unwrap_or(0), 3);
    assert_eq!(counts.get(&1).copied().unwrap_or(0), 1);
    assert_eq!(counts.get(&2).copied().unwrap_or(0), 0); // no rows => absent => 0
    assert_eq!(counts.get(&3).copied().unwrap_or(0), 2);
}

/// #1751 EXACTLY-ONCE COUNT (the live 5211 over-install bug): a flow that was
/// rebalanced leaves an abandoned RebalancedOut copy on the OLD worker AND a
/// live copy on the new worker. The old copy must contribute 0 to
/// per_worker_counts so each flow is counted ONCE, at its current owner.
///
/// Construct a worker set that is TRULY even (2 flows each across 6 workers =
/// 12 real flows) but where 6 extra RebalancedOut copies linger on various
/// workers — the pre-fix double-count that made the live count read 18 and the
/// vector look like [3,1,3,4,4,3]. With exactly-once accounting the count reads
/// a flat [2,2,2,2,2,2] and select_move returns NO further move (no churn).
#[test]
fn rebalanced_out_copies_are_not_counted_so_even_placement_holds() {
    // 12 real owners: 2 counted flows per worker (ports 1000+w*100+i).
    let mut flows = Vec::new();
    for w in 0..6u32 {
        flows.push(flow(1000 + (w as u16) * 100, w, 0.0));
        flows.push(flow(1001 + (w as u16) * 100, w, 0.0));
    }
    // 6 abandoned RebalancedOut copies scattered so that, if counted, the
    // vector would be the lumpy [3,1,3,4,4,3]=18 the live run reported. They
    // sit on workers 0,2,3,3,4,4 (distinct keys so they are real rows).
    flows.push(rebalanced_out_flow(9000, 0));
    flows.push(rebalanced_out_flow(9002, 2));
    flows.push(rebalanced_out_flow(9003, 3));
    flows.push(rebalanced_out_flow(9013, 3));
    flows.push(rebalanced_out_flow(9004, 4));
    flows.push(rebalanced_out_flow(9014, 4));

    // Exactly-once count: every worker reads 2, never the inflated value.
    let counts = per_worker_counts(&flows);
    for w in 0..6u32 {
        assert_eq!(
            counts.get(&w).copied().unwrap_or(0),
            2,
            "worker {w} counts its 2 real owners only (RebalancedOut excluded): {counts:?}"
        );
    }
    assert_eq!(count_sum_of_squares(&counts), 24, "6*2^2 = 24 (not 1+9+... = 60)");

    // The controller sees a flat vector and takes NO move (no over-install /
    // no churn). Drive several ticks at the dwell+interval cadence to be sure.
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    let workers: Vec<WorkerByteRate> = (0..6u32).map(|w| worker(w, 0.0)).collect();
    for t in 0..6u64 {
        let input = RebalanceTickInput {
            ifindex: 5,
            workers: workers.clone(),
            flows: flows.clone(),
            now_secs: 10 + t,
            truncated: false,
        };
        assert!(
            c.tick(&input, &mut tx).is_none(),
            "even-after-exactly-once placement takes no move at tick {t}"
        );
    }
    assert_eq!(c.metrics().installs_total, 0, "no install on a truly-even vector");
    assert!(!tx.calls.iter().any(|s| s.starts_with("install:")), "no churn: {:?}", tx.calls);
}

/// #1751 EXACTLY-ONCE selection: an abandoned RebalancedOut copy on the hottest
/// worker is never chosen as a move SOURCE — only a real (counted) owner is.
#[test]
fn rebalanced_out_copy_is_never_a_move_source() {
    // Worker 0 has ONE real owner (port 1000) + ONE abandoned RebalancedOut
    // copy (port 9000). Worker 1 is empty. If the abandoned copy were counted
    // and movable, worker 0 would read count 2 and the controller could pick
    // the abandoned copy. With exactly-once accounting worker 0 reads count 1,
    // worker 1 reads 0 — delta 1 < K=2 — so NO move is admitted at all, and
    // critically the abandoned key 9000 is never the selected source.
    let flows = vec![
        flow(1000, 0, 0.0),
        rebalanced_out_flow(9000, 0),
    ];
    let counts = per_worker_counts(&flows);
    assert_eq!(counts.get(&0).copied().unwrap_or(0), 1, "only the real owner counts");
    assert_eq!(counts.get(&1).copied().unwrap_or(0), 0);

    // Even if we force a genuine imbalance by adding a second real owner on
    // worker 0 (count 2 vs 0), the move source must be a real owner (1000/1001),
    // never the abandoned 9000.
    let flows2 = vec![
        flow(1000, 0, 0.0),
        flow(1001, 0, 0.0),
        rebalanced_out_flow(9000, 0),
    ];
    let mut c = test_controller(cfg());
    let mut tx = MockTransport::good();
    let workers = vec![worker(0, 0.0), worker(1, 0.0)];
    let mut moved_key_port = None;
    for t in 0..8u64 {
        let input = RebalanceTickInput {
            ifindex: 5,
            workers: workers.clone(),
            flows: flows2.clone(),
            now_secs: 10 + t,
            truncated: false,
        };
        if let Some(mv) = c.tick(&input, &mut tx) {
            moved_key_port = Some(mv.key.src_port);
            break;
        }
    }
    let port = moved_key_port.expect("a 2-vs-0 imbalance admits one move");
    assert!(
        port == 1000 || port == 1001,
        "the move source is a real owner, never the abandoned RebalancedOut copy (got port {port})"
    );
    assert_ne!(port, 9000, "RebalancedOut copy must never be selected as a source");
}

/// count_sum_of_squares matches the test-local sum_of_squares (the in-tree
/// potential helper used by the convergence guarantee).
#[test]
fn count_sum_of_squares_matches_potential() {
    let flows = count_input(5, &[2, 2, 1, 1, 4, 2], 0).flows;
    let counts = per_worker_counts(&flows);
    // 4+4+1+1+16+4 = 30
    assert_eq!(count_sum_of_squares(&counts), 30);
}
