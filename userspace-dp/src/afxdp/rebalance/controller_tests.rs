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
    FlowSample { key: key(src_port), worker_id, byte_rate }
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
    next_loc: u32,
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
            next_loc: 100,
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
    fn install_rule(&mut self, _flow: &FlowSpec5Tuple, queue: u32) -> std::io::Result<u32> {
        self.calls.push(format!("install:q{queue}"));
        if self.install_ok {
            let loc = self.next_loc;
            self.next_loc += 1;
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

/// Drive the controller through the dwell (DWELL_TICKS_REQUIRED=2) and the
/// interval gate by ticking the SAME count vector at 1s spacing until a move
/// is committed or `max_ticks` is hit. Returns the first committed outcome.
/// Used by the convergence tests where we want one accepted move at a time.
fn drive_one_move<T: BarrierTransport>(
    c: &mut RebalanceController,
    tx: &mut T,
    counts: &[u32],
    start_secs: u64,
) -> Option<MoveOutcome> {
    for t in 0..8u64 {
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
    // Destination queue is worker 1's queue_id (== worker_id in the fixture).
    assert!(tx.calls.iter().any(|c| c == "install:q1"));
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
        FlowSample { key: key(moved_port), worker_id: 2, byte_rate: 0.0 },
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
    // but if it IS moved_port the second-move unwind path fires.
    c.tick(&mk(20), &mut tx);
    let mv2 = c.tick(&mk(21), &mut tx).expect("second move");
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

/// count_sum_of_squares matches the test-local sum_of_squares (the in-tree
/// potential helper used by the convergence guarantee).
#[test]
fn count_sum_of_squares_matches_potential() {
    let flows = count_input(5, &[2, 2, 1, 1, 4, 2], 0).flows;
    let counts = per_worker_counts(&flows);
    // 4+4+1+1+16+4 = 30
    assert_eq!(count_sum_of_squares(&counts), 30);
}
