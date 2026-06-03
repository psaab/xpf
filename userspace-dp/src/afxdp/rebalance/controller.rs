// #1748: reactive cross-worker ntuple rebalance controller.
//
// Ticked at the coordinator status cadence (~1 Hz, NOT per-packet, NOT
// per-poll). On each tick it derives per-worker byte-rate over the window,
// and — only when the imbalance has persisted past the dwell — moves the
// single flow whose relocation most flattens the per-worker byte-rate
// vector, subject to a magnitude guard (<= gap/2), a per-flow cooldown, an
// epsilon improvement band, and a hard rule budget with STOP-on-exhaustion
// (NO eviction). The move itself is a barriered ownership transfer
// (`promote W_new -> ack -> demote W_old -> ack -> install rule`); rollback
// and teardown-of-a-live-move use the reverse barrier.
//
// Default-OFF: when the knob is unset the Coordinator never constructs a
// controller, so there is zero extra per-tick work and zero ioctl sockets.

use std::collections::HashMap;
use std::net::IpAddr;

use super::ntuple::{FlowProto, FlowSpec5Tuple};
use crate::session::SessionKey;

/// #1748 live BUG #1 instrumentation. Emits a per-eval diagnostic line to
/// stderr (journald) ONLY in `debug-log` feature builds, so production release
/// builds compile it out entirely (zero cost, removable). Mirrors the
/// `debug_log!` pattern in `session/mod.rs`. Build the helper with
/// `--features debug-log` to read these lines via `journalctl -u xpfd`.
#[allow(unused_macros)]
macro_rules! debug_log_rebalance {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-log")]
        eprintln!($($arg)*);
    };
}
#[allow(unused_imports)]
pub(in crate::afxdp) use debug_log_rebalance;

/// Operator-tunable knobs compiled from the `class-of-service flow-rebalance`
/// config leaf. Absent leaf => `None` controller => default path untouched.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(in crate::afxdp) struct RebalanceConfig {
    /// #1751 count-balancing: the count-delta threshold `K`. A move is only
    /// considered when the highest-flow-count worker carries at least `K` more
    /// steerable flows than the lowest. `K=2` is the default; it converges a
    /// count partition to even in the minimum number of moves and stops
    /// cleanly (the overshoot guard requires `delta >= 2` to admit a move, so
    /// `K < 2` would never produce an admitted move anyway).
    pub count_delta_k: u32,
    /// Minimum seconds between rule installs (dwell / one-move-per-interval).
    pub rebalance_interval_secs: u64,
    /// Hard cap on concurrently-installed xpf rules per interface.
    pub max_rules: u32,
}

impl Default for RebalanceConfig {
    fn default() -> Self {
        Self {
            count_delta_k: 2,
            rebalance_interval_secs: 1,
            max_rules: 64,
        }
    }
}

impl RebalanceConfig {
    /// A config is meaningful only with a positive budget. (`count_delta_k` is
    /// clamped to `>= 2` at use, since the overshoot guard cannot admit a move
    /// below a delta of 2.)
    pub(in crate::afxdp) fn is_enabled(&self) -> bool {
        self.max_rules > 0
    }

    /// The effective count-delta threshold, clamped to the floor of 2 (a `K`
    /// below 2 can never produce an admitted move under the overshoot guard).
    #[inline]
    pub(in crate::afxdp) fn effective_k(&self) -> u32 {
        self.count_delta_k.max(2)
    }
}

/// Reason a candidate move was skipped — exported as the
/// `moves_skipped_total{reason}` metric label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(in crate::afxdp) enum SkipReason {
    /// #1751: the per-worker flow-count imbalance is below the `K` threshold
    /// (`max_count - min_count < K`), or the counts are already even — no move
    /// worthwhile. (Was the byte-rate "below imbalance ratio" reject in #1748.)
    Balanced,
    /// Within the per-flow cooldown window.
    Cooldown,
    /// #1751: count overshoot guard — moving one flow would make the
    /// destination worker the new max count (requires `c_hi - c_lo >= 2`).
    /// Re-purposed from #1748's byte-rate magnitude guard; same metric label
    /// `magnitude` for ABI stability.
    Magnitude,
    /// #1748 byte-rate epsilon reject. UNUSED on the #1751 count-balancing
    /// decision path; retained only for `moves_skipped_total` metric ABI
    /// stability (never recorded by the count selector).
    Epsilon,
    /// The highest-count source worker had no movable (non-cooldown) flow.
    /// Under the same-snapshot count (#1751 §2.2 opt 1) this is structurally
    /// near-impossible — the count IS the row count — so a non-zero rate here
    /// means every flow on the source is in cooldown.
    NoEligibleFlow,
    /// Rule budget exhausted (STOP — no eviction).
    BudgetExhausted,
    /// Barrier failed (ack timeout / key absent / ioctl error) — rolled back.
    BarrierFailed,
    /// One move already happened this interval.
    Dwell,
    /// Reverse-barrier restore of W_old failed (timeout / key absent) during
    /// rollback or teardown — W_new is intentionally LEFT as owner so >= 1
    /// cleanup owner remains (#1748 review #4). Operator-visible: a non-zero
    /// rate here means worker command acks are stalling under load.
    RestoreFailed,
    /// #1751: the `flow_worker_map` snapshot was truncated (row count caps at
    /// FLOW_WORKER_MAP_MAX_ROWS / per-binding 256), so the per-worker row count
    /// would understate the true active count. Defer the balancer this tick
    /// rather than act on an understated count (plan §2.3/§6.2).
    Truncated,
}

impl SkipReason {
    pub(in crate::afxdp) fn as_str(self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::Cooldown => "cooldown",
            Self::Magnitude => "magnitude",
            Self::Epsilon => "epsilon",
            Self::NoEligibleFlow => "no_eligible_flow",
            Self::BudgetExhausted => "budget_exhausted",
            Self::BarrierFailed => "barrier_failed",
            Self::Dwell => "dwell",
            Self::RestoreFailed => "restore_failed",
            Self::Truncated => "truncated",
        }
    }
}

/// Per-interface controller metrics (exported as
/// `xpf_userspace_flow_rebalance_*{ifindex}`).
#[derive(Clone, Debug, Default, PartialEq)]
pub(in crate::afxdp) struct RebalanceMetrics {
    pub rules_active: u32,
    pub installs_total: u64,
    pub deletes_total: u64,
    pub moves_skipped: HashMap<SkipReason, u64>,
    /// Coefficient of variation of the per-worker byte-rate at the last tick.
    pub worker_byterate_cov: f64,
}

impl RebalanceMetrics {
    fn record_skip(&mut self, reason: SkipReason) {
        *self.moves_skipped.entry(reason).or_insert(0) += 1;
    }
}

/// One worker's byte-rate sample for the current tick.
#[derive(Clone, Copy, Debug)]
pub(in crate::afxdp) struct WorkerByteRate {
    pub worker_id: u32,
    pub queue_id: u32,
    /// Bytes/sec over the observation window.
    pub byte_rate: f64,
}

/// One live flow eligible to move: its 5-tuple key, current worker, and
/// observed byte-rate over the window.
#[derive(Clone, Debug)]
pub(in crate::afxdp) struct FlowSample {
    pub key: SessionKey,
    pub worker_id: u32,
    pub byte_rate: f64,
    /// #1751 exactly-once count: the session origin of this flow on
    /// `worker_id`. `Some(RebalancedOut)` marks the ABANDONED forward copy
    /// left on the OLD worker after a rebalance move — it must NOT be counted
    /// (the flow's current owner is the NEW worker's `RebalancedOwner` copy)
    /// and must NEVER be re-selected as a move source. The live worker path
    /// already evicts the abandoned flow-cache copy at demote (see
    /// `worker/loop_body`), so a RebalancedOut row normally never reaches the
    /// controller; this field is the defensive belt-and-suspenders that makes
    /// the count exactly-once even if a stray in-flight packet briefly
    /// re-touched the W_old cache entry before it aged out. `None` (the common
    /// case for plain forward flows whose origin the snapshot did not carry)
    /// is COUNTED — only an explicit RebalancedOut is excluded.
    pub origin: Option<crate::session::SessionOrigin>,
}

impl FlowSample {
    /// #1751: a flow is counted at exactly one worker — its CURRENT owner.
    /// The abandoned `RebalancedOut` copy on the old worker is not counted
    /// (and is never a move source). Every other origin (ForwardFlow,
    /// RebalancedOwner, WorkerLocalImport, …) is the flow's live placement and
    /// IS counted.
    pub(in crate::afxdp) fn is_counted(&self) -> bool {
        !matches!(
            self.origin,
            Some(crate::session::SessionOrigin::RebalancedOut)
        )
    }
}

/// Per-tick input snapshot the Coordinator assembles from existing
/// telemetry (umem `tx_bytes` deltas keyed by worker + the flow-worker map).
pub(in crate::afxdp) struct RebalanceTickInput {
    pub ifindex: i32,
    pub workers: Vec<WorkerByteRate>,
    pub flows: Vec<FlowSample>,
    /// Monotonic seconds (for cooldown / dwell timing).
    pub now_secs: u64,
    /// #1751: true when the `flow_worker_map` snapshot was truncated (the
    /// per-worker row count would understate the true active count). The
    /// controller defers the balancer this tick rather than act on an
    /// understated count (plan §2.3).
    pub truncated: bool,
}

/// The transport the controller uses to drive the barriered move and program
/// the NIC. The Coordinator implements this against its worker command queues
/// + ack slots + the per-interface `NtupleSocket`. Abstracted so the
/// selection/barrier logic is unit-testable with a mock.
pub(in crate::afxdp) trait BarrierTransport {
    /// Promote W_new's replica to RebalancedOwner; block until acked. Returns
    /// true iff the worker confirmed the key reached `RebalancedOwner`.
    fn promote(&mut self, worker_id: u32, key: &SessionKey) -> bool;
    /// Demote W_old's entry to RebalancedOut; block until acked. Returns true
    /// iff the worker confirmed the key reached `RebalancedOut`.
    fn demote(&mut self, worker_id: u32, key: &SessionKey) -> bool;
    /// Reverse-barrier: restore W_old to a local owner; block until acked.
    fn restore_owner(&mut self, worker_id: u32, key: &SessionKey) -> bool;
    /// Reverse-barrier: demote W_new back to a worker-local replica; block
    /// until acked.
    fn demote_replica(&mut self, worker_id: u32, key: &SessionKey) -> bool;
    /// Install the exact-5-tuple rule steering the flow to `queue` at the
    /// CONCRETE location `loc` (#1751: the controller picks `loc` from its
    /// ledger used-set; the transport does NOT query the NIC for a location).
    /// Returns the location the rule was installed at on success.
    fn install_rule(&mut self, flow: &FlowSpec5Tuple, queue: u32, loc: u32)
        -> std::io::Result<u32>;
    /// Delete the rule at `loc`.
    fn delete_rule(&mut self, loc: u32) -> std::io::Result<()>;
}

/// A live move record in the controller's in-memory ledger.
#[derive(Clone, Debug)]
struct LedgerEntry {
    key: SessionKey,
    /// The worker the flow was steered AWAY from (W_old). #1748 review #2:
    /// the reverse barrier on teardown/rollback must restore THIS worker to
    /// owner, not `new_worker`. The RSS-natural worker for the flow once the
    /// rule is gone IS the original source worker (RSS hashing is
    /// deterministic on the 5-tuple), so restoring `old_worker` hands
    /// ownership to exactly the worker that will receive the packets.
    old_worker: u32,
    /// The worker the flow now lives on (W_new).
    new_worker: u32,
    /// The driver-assigned ntuple rule location.
    loc: u32,
}

/// Persistent controller state for one interface (ledger + cooldown +
/// hysteresis + metrics). The NtupleSocket is owned separately by the
/// Coordinator (see the struct comment below) so it can be borrowed as the
/// BarrierTransport while the controller is borrowed `&mut`.
pub(in crate::afxdp) struct RebalanceController {
    // #1748 review-r3 (soundness): the NtupleSocket is deliberately NOT owned
    // by the controller. The barrier transport needs a shared `&NtupleSocket`
    // while the controller's tick/teardown take `&mut self`; owning the socket
    // here and aliasing it through a raw pointer into the transport during a
    // `&mut self` call is undefined behavior under stacked borrows. The socket
    // lives in the Coordinator's separate `rebalance_sockets` map so the socket
    // and the controller are independent borrows; the socket is passed to
    // tick/teardown_all via the BarrierTransport `tx` parameter.
    config: RebalanceConfig,
    ledger: Vec<LedgerEntry>,
    /// Per-flow cooldown: key -> monotonic secs until which it is ineligible.
    cooldown: HashMap<SessionKey, u64>,
    /// Monotonic secs of the last install (dwell gate).
    last_move_secs: u64,
    /// Consecutive evaluation ticks the count imbalance has stayed at/above the
    /// ARM threshold (`K_high`). Reset to 0 on any tick whose imbalance is below
    /// `K_high`, AND after every accepted move — so EACH move (not just the
    /// first) requires the imbalance to persist `DWELL_TICKS_REQUIRED` ticks.
    /// This is the anti-churn debounce on the imbalance itself (#1751 r2 fix 1):
    /// a single-tick bursty blip never triggers a move.
    dwell_ticks: u32,
    /// #1751 r2 fix 2 (deadband hysteresis): false while the controller is
    /// actively rebalancing an imbalance down to even; true once the placement
    /// has SETTLED (imbalance fell to the stop band `<= K_low`). While settled
    /// the controller refuses to engage until a SUSTAINED imbalance `>= K_high`
    /// reappears — it does NOT chase the ±1 count fluctuations that bursty
    /// traffic produces around the even partition. Starts settled (an
    /// already-balanced fleet must not move on the first imbalanced tick).
    settled: bool,
    metrics: RebalanceMetrics,
}

/// Consecutive ARM-threshold-imbalanced ticks required before EACH move
/// (hysteresis / anti-churn debounce — absorbs transient RSS-count blips on
/// bursty traffic; #1751 §3.3 + r2 fix 1). Ticks fire at the rebalance-interval
/// cadence (>= 1 s), so this is a multi-second sustained-imbalance requirement.
const DWELL_TICKS_REQUIRED: u32 = 3;

/// #1751 r2 fix 2 (deadband): margin that keeps the ARM threshold strictly
/// ABOVE the stop band. The arm threshold is
/// `K_high = max(effective_k, K_LOW_STOP_BAND + REARM_DELTA_MARGIN)` and the
/// stop band is `delta <= K_LOW_STOP_BAND`. With the defaults
/// (effective_k = 2, K_LOW_STOP_BAND = 1) this yields `K_high = 2`, so the
/// controller re-engages on a real `delta >= 2` imbalance but only when it is
/// SUSTAINED (DWELL_TICKS_REQUIRED) — convergence still drives all the way to
/// `delta <= 1`. The deadband proper is the SETTLED-state requirement that the
/// `delta >= K_high` imbalance persist a full dwell window before re-arming, so
/// the controller does not chase the single-tick +-1/+-2 count fluctuations
/// bursty traffic throws off around the even partition. A larger configured
/// `count-delta` K raises K_high directly.
const REARM_DELTA_MARGIN: u32 = 1;

/// #1751 r2 fix 2 (deadband): the stop band. Convergence drives the imbalance
/// down to `delta <= K_LOW_STOP_BAND`; reaching it marks the placement SETTLED.
/// 1 == the even-partition target (`max - min <= 1`), so the controller stops
/// exactly at convergence and does not waste a move trying to flatten an
/// already-even +-1 vector.
const K_LOW_STOP_BAND: u32 = 1;

/// #1751: ntuple location-space depth (mlx5 `MAX_NUM_OF_ETHTOOL_RULES =
/// BIT(10)`). Locations are in `[0, MAX_NTUPLE_LOCATION)`. The controller picks
/// a concrete location below this from its LEDGER used-set — it does NOT query
/// the NIC (GRXCLSRLALL is unreliable on this mlx5 path and is NOT on the
/// install critical path). The controller's `max_rules` cap (<= 1024) keeps the
/// in-use count well under this depth.
const MAX_NTUPLE_LOCATION: u32 = 1024;

impl RebalanceController {
    pub(in crate::afxdp) fn new(config: RebalanceConfig) -> Self {
        Self {
            config,
            ledger: Vec::new(),
            cooldown: HashMap::new(),
            last_move_secs: 0,
            dwell_ticks: 0,
            // Start SETTLED: an already-balanced fleet at startup must not move
            // on the first imbalanced tick — it must first observe a SUSTAINED
            // arm-threshold imbalance.
            settled: true,
            metrics: RebalanceMetrics::default(),
        }
    }

    /// #1751 r2 fix 2: the ARM threshold `K_high` — the count delta a SETTLED
    /// controller must see (sustained) before it re-engages. Held strictly
    /// above the stop band so re-arming requires a real imbalance, not a delta
    /// at the convergence edge.
    #[inline]
    fn arm_threshold(&self) -> u32 {
        self.config
            .effective_k()
            .max(K_LOW_STOP_BAND + REARM_DELTA_MARGIN)
    }

    pub(in crate::afxdp) fn metrics(&self) -> &RebalanceMetrics {
        &self.metrics
    }

    /// Test-only: clear the per-flow cooldown so a unit test can drive a
    /// second move of the same key without waiting out the cooldown window.
    #[cfg(test)]
    pub(in crate::afxdp) fn clear_cooldown_for_test(&mut self) {
        self.cooldown.clear();
    }

    /// #1751: pick the highest free ntuple location from the controller's own
    /// LEDGER used-set (top-down from MAX-1, skipping ledger locs). The ledger
    /// is the authoritative used-set: the controller is the only ntuple-rule
    /// user, the table starts empty, and every install/delete is tracked. This
    /// does NOT query the NIC (the GRXCLSRLALL path is unreliable on mlx5 and
    /// is decoupled from installs). `None` only when all MAX locations are in
    /// the ledger (caller -> ENOSPC); the `max_rules` cap makes that impossible
    /// in practice. The second-move unwind has ALREADY removed the prior entry
    /// from the ledger before this is called, so a re-pin of the same key does
    /// not collide with its own freed loc.
    fn next_free_ledger_loc(&self) -> Option<u32> {
        let used: Vec<u32> = self.ledger.iter().map(|e| e.loc).collect();
        free_loc_top_down(MAX_NTUPLE_LOCATION, &used)
    }

    /// One controller tick. Pure decision + barriered move. `tx` drives the
    /// worker barrier and NIC programming. Returns the move outcome for the
    /// caller's logging (None = no move attempted/taken this tick).
    pub(in crate::afxdp) fn tick<T: BarrierTransport>(
        &mut self,
        input: &RebalanceTickInput,
        tx: &mut T,
    ) -> Option<MoveOutcome> {
        // Always refresh the CoV gauge so operators see the live byte-rate
        // imbalance even when no move is taken. (#1751: the gauge is now
        // observability only — the DECISION is driven by the flow COUNT, not
        // byte-rate.)
        let cov = byte_rate_cov(&input.workers);
        self.metrics.worker_byterate_cov = cov;
        self.expire_cooldowns(input.now_secs);

        // #1751 truncation defer (plan §2.3/§6.2): a truncated flow-worker-map
        // snapshot would understate the per-worker row count, so defer rather
        // than act on a wrong count. Cannot fire at the P12 gate (24 << 256).
        if input.truncated {
            self.metrics.record_skip(SkipReason::Truncated);
            return None;
        }

        // #1751 r2 anti-churn gate: deadband hysteresis + sustained-imbalance
        // dwell. The live regression was perpetual install->delete->install
        // churn (installs_total AND deletes_total both climbing forever, rules
        // pinned near the cap, CoV never settling) because the controller
        // reacted to every transient single-tick count blip on bursty traffic.
        //
        // Two guards work together:
        //   1. DEADBAND: once the placement SETTLES (imbalance fell to the stop
        //      band `delta <= K_LOW_STOP_BAND`), the controller will not engage
        //      again until a SUSTAINED imbalance at/above the ARM threshold
        //      `K_high` reappears. It does NOT chase the +-1 (or delta-2) count
        //      fluctuations bursty traffic throws off around the even partition.
        //   2. SUSTAINED DWELL: arming requires the imbalance to stay >= K_high
        //      for DWELL_TICKS_REQUIRED consecutive ticks (a single-tick burst
        //      blip resets the counter), AND each subsequent move re-requires a
        //      full dwell window (dwell_ticks is reset to 0 after every move).
        let delta = self.count_delta(&input.workers, &input.flows);
        // Settle as soon as the imbalance reaches the stop band, regardless of
        // whether we are mid-rebalance — this is what makes installs+deletes
        // STOP climbing the instant the fleet is balanced.
        if delta <= K_LOW_STOP_BAND {
            self.settled = true;
            self.dwell_ticks = 0;
            self.metrics.record_skip(SkipReason::Balanced);
            return None;
        }
        // SETTLED: only a SUSTAINED arm-threshold imbalance may re-engage. A
        // delta in the deadband (K_LOW_STOP_BAND < delta < K_high) is ignored
        // entirely while settled — no dwell accrual, no move.
        if self.settled {
            if delta >= self.arm_threshold() {
                self.dwell_ticks = self.dwell_ticks.saturating_add(1);
                if self.dwell_ticks >= DWELL_TICKS_REQUIRED {
                    // Sustained arm-threshold imbalance confirmed: leave the
                    // deadband and start rebalancing this episode.
                    self.settled = false;
                }
            } else {
                // Deadband: below the arm threshold while settled — do nothing,
                // and do not let a flicker at K_high accumulate dwell.
                self.dwell_ticks = 0;
            }
            if self.settled {
                self.metrics.record_skip(SkipReason::Balanced);
                return None;
            }
        } else {
            // ACTIVELY REBALANCING (not settled): keep converging while the
            // imbalance stays >= effective_k, but still require each move to be
            // dwell-debounced so a one-tick count blip cannot trigger it.
            if delta >= self.config.effective_k() {
                self.dwell_ticks = self.dwell_ticks.saturating_add(1);
            } else {
                // Above the stop band but below K: not worth a move and not
                // sustained — hold (do not move, do not re-settle yet; the stop
                // band above is the only settle trigger).
                self.dwell_ticks = 0;
                self.metrics.record_skip(SkipReason::Balanced);
                return None;
            }
            if self.dwell_ticks < DWELL_TICKS_REQUIRED {
                self.metrics.record_skip(SkipReason::Balanced);
                return None;
            }
        }

        // One move per rebalance_interval (dwell gate on install cadence).
        if input.now_secs.saturating_sub(self.last_move_secs)
            < self.config.rebalance_interval_secs
        {
            self.metrics.record_skip(SkipReason::Dwell);
            return None;
        }

        // Budget gate: STOP at the cap, never evict.
        if self.ledger.len() as u32 >= self.config.max_rules {
            self.metrics.record_skip(SkipReason::BudgetExhausted);
            return None;
        }

        let Some(mut candidate) = self.select_move(input) else {
            // select_move records the precise skip reason.
            return None;
        };

        // #1748 review #6: SECOND MOVE of a key already in the ledger. The
        // flow currently lives on its prior W_new (the ledger's `new_worker`)
        // under a still-installed rule. Moving it to a third worker must first
        // unwind that prior move at the CONTROLLER level — delete the old rule
        // and reverse-barrier the prior owner back — so the flow is RSS-placed
        // again before the new forward barrier re-pins it. Without this the
        // controller just appends a second ledger entry and a second rule for
        // the same 5-tuple (the second rule may never even take effect, and
        // the prior owner is left RebalancedOwner forever). We replace, not
        // append.
        let prior_idx = self
            .ledger
            .iter()
            .position(|e| e.key == candidate.key);
        if let Some(idx) = prior_idx {
            let prior = self.ledger[idx].clone();
            // #1748 review-r2 MAJOR: `old_worker` is the RSS-natural worker for
            // the 5-tuple — the worker the flow lands on when NO rebalance rule
            // exists. RSS is deterministic on the tuple, so this is INVARIANT
            // across moves. On a second move `candidate.old_worker` is the prior
            // W_new (the flow's *current* worker mid-move), NOT the RSS-natural
            // worker. Carry the prior entry's `old_worker` forward so (a) the
            // forward-barrier demote below targets the correct worker and (b)
            // the replacement ledger entry records the RSS-natural worker, so a
            // later teardown restores it (not the prior W_new).
            candidate.old_worker = prior.old_worker;
            // Reverse barrier on the prior move: restore the prior W_old to
            // owner, delete the prior rule, demote the prior W_new to replica.
            // Gate the W_new demote on a successful restore ack (#1748 #4): if
            // the restore times out we must NOT demote the only owner.
            if !tx.restore_owner(prior.old_worker, &prior.key) {
                // Could not hand ownership back to the prior W_old. Abort the
                // second move and leave the prior move intact (>= 1 owner is
                // still the prior W_new). Do not append a second rule.
                // #1748 review-r2 MINOR: this is a restore-ack failure — record
                // RestoreFailed, matching the other three restore-fail sites.
                self.metrics.record_skip(SkipReason::RestoreFailed);
                return None;
            }
            // #1748 review-r2 MINOR: handle the prior-rule delete failure. If
            // the delete fails we must NOT proceed to install a new rule for
            // the same 5-tuple — that re-creates the duplicate-HW-rule hazard
            // #6 fixed. Abort the move this tick and KEEP the prior ledger
            // entry (the prior rule is still installed and still steering to
            // the prior W_new). We restored W_old above, but restore_owner is
            // an idempotent tag flip and the prior W_new is still
            // RebalancedOwner, so >= 1 owner holds; the next tick retries the
            // delete. Do NOT demote the prior W_new here (its rule still
            // routes traffic to it).
            if tx.delete_rule(prior.loc).is_err() {
                self.metrics.record_skip(SkipReason::BarrierFailed);
                debug_log_rebalance!(
                    "REBALANCE_BARRIER step=second_move_delete ifindex={} loc={} src_port={} result=failed",
                    input.ifindex, prior.loc, prior.key.src_port
                );
                return None;
            }
            tx.demote_replica(prior.new_worker, &prior.key);
            self.metrics.deletes_total += 1;
            self.ledger.remove(idx);
            self.metrics.rules_active = self.ledger.len() as u32;
        }

        // #1751: pick the concrete ntuple location from the LEDGER used-set
        // BEFORE the barrier, so a full location space aborts cleanly with no
        // barrier side-effects (no promote/demote to roll back). The
        // second-move unwind above has already removed any prior entry for this
        // key, so a re-pin reuses the freed loc. None => location space full
        // (cannot happen under the max_rules cap) => BudgetExhausted.
        let Some(chosen_loc) = self.next_free_ledger_loc() else {
            self.metrics.record_skip(SkipReason::BudgetExhausted);
            return None;
        };

        // Forward barrier: promote (claim) W_new BEFORE the rule, then demote
        // W_old, then install. The promote is CLAIM-ONLY (#1751) — for a
        // same-node move W_new does not pre-hold the flow, so promote no longer
        // fails on an absent entry; it only fails if the worker queue/ack
        // itself broke.
        if !tx.promote(candidate.new_worker, &candidate.key) {
            self.metrics.record_skip(SkipReason::BarrierFailed);
            debug_log_rebalance!(
                "REBALANCE_BARRIER step=promote ifindex={} new_worker={} src_port={} result=failed",
                input.ifindex, candidate.new_worker, candidate.key.src_port
            );
            // Nothing to roll back: the only mutation attempted was the
            // promote, which failed to commit. Reverse it defensively.
            tx.demote_replica(candidate.new_worker, &candidate.key);
            return None;
        }
        if !tx.demote(candidate.old_worker, &candidate.key) {
            self.metrics.record_skip(SkipReason::BarrierFailed);
            debug_log_rebalance!(
                "REBALANCE_BARRIER step=demote ifindex={} old_worker={} src_port={} result=failed",
                input.ifindex, candidate.old_worker, candidate.key.src_port
            );
            // Reverse barrier: restore W_old to owner FIRST, and only demote
            // W_new back to a replica if that restore is acked (#1748 #4). If
            // the restore fails (timeout / key absent on W_old), keep W_new as
            // the owner — demoting it would lose the only cleanup owner.
            if tx.restore_owner(candidate.old_worker, &candidate.key) {
                tx.demote_replica(candidate.new_worker, &candidate.key);
            } else {
                self.metrics.record_skip(SkipReason::RestoreFailed);
            }
            return None;
        }
        // Only after BOTH acks: install the rule at the ledger-chosen loc.
        let spec = flow_spec_from_key(&candidate.key);
        match tx.install_rule(&spec, candidate.new_queue, chosen_loc) {
            Ok(loc) => {
                self.ledger.push(LedgerEntry {
                    key: candidate.key.clone(),
                    old_worker: candidate.old_worker,
                    new_worker: candidate.new_worker,
                    loc,
                });
                let cooldown_secs = (self.config.rebalance_interval_secs
                    * COOLDOWN_INTERVAL_MULTIPLIER)
                    .max(COOLDOWN_MIN_SECS);
                self.cooldown
                    .insert(candidate.key.clone(), input.now_secs + cooldown_secs);
                self.last_move_secs = input.now_secs;
                // Require the imbalance to persist ANOTHER full dwell window
                // before the NEXT move (anti-churn: each move is independently
                // debounced, not just the first).
                self.dwell_ticks = 0;
                self.metrics.installs_total += 1;
                self.metrics.rules_active = self.ledger.len() as u32;
                Some(MoveOutcome {
                    key: candidate.key,
                    old_worker: candidate.old_worker,
                    new_worker: candidate.new_worker,
                    loc,
                })
            }
            Err(_e) => {
                self.metrics.record_skip(SkipReason::BarrierFailed);
                debug_log_rebalance!(
                    "REBALANCE_BARRIER step=install ifindex={} new_worker={} queue={} src_port={} result=failed err={:?}",
                    input.ifindex, candidate.new_worker, candidate.new_queue,
                    candidate.key.src_port, _e.raw_os_error()
                );
                // Rule install failed: reverse the ownership transfer with the
                // reverse barrier so >= 1 cleanup owner remains. Gate the W_new
                // demote on the W_old restore ack (#1748 #4).
                if tx.restore_owner(candidate.old_worker, &candidate.key) {
                    tx.demote_replica(candidate.new_worker, &candidate.key);
                } else {
                    self.metrics.record_skip(SkipReason::RestoreFailed);
                }
                None
            }
        }
    }

    /// Tear down ALL installed rules (controller disable / daemon shutdown).
    /// A still-live move must reverse the ownership transfer BEFORE the rule
    /// is removed (reverse barrier): restore W_old -> owner + ack, delete the
    /// rule, then demote W_new -> replica + ack. Only a flow already expired
    /// off W_new is a plain rule delete — but the controller cannot prove
    /// that here, so it conservatively reverse-barriers every live ledger
    /// entry. The caller passes the set of keys still present on W_new (live)
    /// vs gone (dead); empty `live_keys` => all plain deletes.
    pub(in crate::afxdp) fn teardown_all<T: BarrierTransport, F>(
        &mut self,
        tx: &mut T,
        mut is_live_on_new: F,
    ) where
        F: FnMut(u32, &SessionKey) -> bool,
    {
        let entries = std::mem::take(&mut self.ledger);
        for entry in entries {
            if is_live_on_new(entry.new_worker, &entry.key) {
                // Reverse barrier: hand ownership back to the REAL W_old
                // (entry.old_worker — #1748 review #2), which is the
                // RSS-natural worker that will receive the flow once the rule
                // is gone, BEFORE removing the rule. Gate the W_new demote on
                // the restore ack (#1748 #4): if W_old cannot be restored, keep
                // W_new as the owner rather than demoting the only owner away.
                if tx.restore_owner(entry.old_worker, &entry.key) {
                    let _ = tx.delete_rule(entry.loc);
                    tx.demote_replica(entry.new_worker, &entry.key);
                } else {
                    self.metrics.record_skip(SkipReason::RestoreFailed);
                    // Delete the rule anyway (RSS will re-hash to W_old which
                    // keeps the packets via origin-agnostic last_seen refresh),
                    // but leave W_new as RebalancedOwner so >= 1 cleanup owner
                    // remains until its own GC.
                    let _ = tx.delete_rule(entry.loc);
                }
            } else {
                // Flow already expired off W_new — no live ownership to hand
                // back; plain rule delete.
                let _ = tx.delete_rule(entry.loc);
            }
            self.metrics.deletes_total += 1;
        }
        self.metrics.rules_active = 0;
    }

    /// #1751: the per-worker steerable-flow COUNT imbalance exceeds the `K`
    /// threshold (`max_count - min_count >= K`). The count is over POST-FILTER
    /// steerable `flows` (the same rows the candidate is drawn from), keyed by
    /// the real worker_id — so count and rows are the same object (plan §2.2
    /// opt 1) and the #1748 count-vs-rows skew is structurally impossible.
    ///
    /// The min/max range MUST be taken over ALL `workers` (a worker with no
    /// steerable rows has count 0 and is a valid `lo` destination), NOT just
    /// the workers that appear in `per_worker_counts` — otherwise a `[3,0]`
    /// vector (worker 1 absent from the count map) would look balanced.
    fn is_count_imbalanced(&self, workers: &[WorkerByteRate], flows: &[FlowSample]) -> bool {
        self.count_delta(workers, flows) >= self.config.effective_k()
    }

    /// The per-worker steerable-flow count SPREAD (`max_count - min_count`) over
    /// ALL `workers` (a worker with no steerable rows counts 0 and is a valid
    /// `lo`). This is the single imbalance magnitude the anti-churn deadband and
    /// dwell gate decide on. Returns 0 for a degenerate (< 2 workers) fleet.
    fn count_delta(&self, workers: &[WorkerByteRate], flows: &[FlowSample]) -> u32 {
        if workers.len() < 2 {
            return 0;
        }
        let counts = per_worker_counts(flows);
        let mut max = 0u32;
        let mut min = u32::MAX;
        for w in workers {
            let c = counts.get(&w.worker_id).copied().unwrap_or(0);
            max = max.max(c);
            min = min.min(c);
        }
        max.saturating_sub(min)
    }

    fn expire_cooldowns(&mut self, now_secs: u64) {
        self.cooldown.retain(|_, &mut until| until > now_secs);
    }

    /// #1751 count-balancing selection (replaces #1748's byte-rate selection).
    /// Move a flow from the highest-steerable-flow-COUNT worker (`hi`) to the
    /// lowest-count worker (`lo`), converging toward an even count partition.
    /// NO per-flow byte-rates and NO byte-rate magnitude guard on the decision
    /// path — the count comes from the same `flows` snapshot the candidate is
    /// drawn from (plan §2.2 opt 1, §3.2). Records the precise skip reason on
    /// the no-move paths.
    fn select_move(&mut self, input: &RebalanceTickInput) -> Option<MoveCandidate> {
        if input.workers.len() < 2 {
            self.metrics.record_skip(SkipReason::Balanced);
            return None;
        }
        // Per-worker steerable-flow count, over ALL workers in the rate vector
        // (a worker with no steerable rows has count 0 and IS a valid `lo`
        // destination). Counted from the post-filter `flows` (same object as
        // the candidate rows) so count==rows by construction.
        let counts = per_worker_counts(&input.flows);
        // hi = argmax count (tie-break: higher byte_rate, then lower worker_id);
        // lo = argmin count (tie-break: lower byte_rate, then lower worker_id).
        // Deterministic tie-breaks make the selection reproducible.
        let hi = input
            .workers
            .iter()
            .max_by(|a, b| {
                let ca = counts.get(&a.worker_id).copied().unwrap_or(0);
                let cb = counts.get(&b.worker_id).copied().unwrap_or(0);
                ca.cmp(&cb)
                    .then(a.byte_rate.total_cmp(&b.byte_rate))
                    .then(b.worker_id.cmp(&a.worker_id))
            })?;
        let lo = input
            .workers
            .iter()
            .min_by(|a, b| {
                let ca = counts.get(&a.worker_id).copied().unwrap_or(0);
                let cb = counts.get(&b.worker_id).copied().unwrap_or(0);
                ca.cmp(&cb)
                    .then(a.byte_rate.total_cmp(&b.byte_rate))
                    .then(a.worker_id.cmp(&b.worker_id))
            })?;
        let c_hi = counts.get(&hi.worker_id).copied().unwrap_or(0);
        let c_lo = counts.get(&lo.worker_id).copied().unwrap_or(0);

        // Same worker as both hi and lo => fully even => nothing to do.
        if hi.worker_id == lo.worker_id {
            self.metrics.record_skip(SkipReason::Balanced);
            self.log_skip(input, SkipReason::Balanced, hi, lo, c_hi, c_lo);
            return None;
        }
        // K count-delta threshold: only act if the imbalance is worth a move.
        if c_hi.saturating_sub(c_lo) < self.config.effective_k() {
            self.metrics.record_skip(SkipReason::Balanced);
            self.log_skip(input, SkipReason::Balanced, hi, lo, c_hi, c_lo);
            return None;
        }
        // Count overshoot guard (plan §3.2, §3.4): admit a move only when
        // `c_hi - c_lo >= 2`, so moving ONE flow does not make `lo` the new max
        // — and so the sum-of-squares potential strictly drops by >= 2 per move
        // (ΔΨ = 2 - 2(c_hi - c_lo) <= -2). With K defaulting to 2 this is
        // implied by the threshold, but the guard is explicit and independent
        // so a configured K < 2 still cannot admit an overshooting move.
        if c_hi.saturating_sub(c_lo) < 2 {
            self.metrics.record_skip(SkipReason::Magnitude);
            self.log_skip(input, SkipReason::Magnitude, hi, lo, c_hi, c_lo);
            return None;
        }

        // Choose a flow on `hi` not in cooldown. Homogeneous traffic: any flow
        // is equally good; pick the lowest session_key deterministically for
        // reproducibility (plan §3.2).
        // #1751: never re-select the abandoned RebalancedOut copy as a move
        // source (it is not the flow's current owner). Matches the count filter
        // in per_worker_counts so the source set and the count agree.
        let mut candidates: Vec<&FlowSample> = input
            .flows
            .iter()
            .filter(|f| {
                f.worker_id == hi.worker_id
                    && f.is_counted()
                    && !self.cooldown.contains_key(&f.key)
            })
            .collect();
        candidates.sort_by(|a, b| session_key_order(&a.key, &b.key));

        let Some(flow) = candidates.first() else {
            // Every steerable flow on `hi` is in cooldown (or — structurally
            // unlikely under same-snapshot counting — `hi` had no rows).
            let had_any_on_hi = input
                .flows
                .iter()
                .any(|f| f.worker_id == hi.worker_id && f.is_counted());
            let reason = if had_any_on_hi {
                SkipReason::Cooldown
            } else {
                SkipReason::NoEligibleFlow
            };
            self.metrics.record_skip(reason);
            self.log_skip(input, reason, hi, lo, c_hi, c_lo);
            return None;
        };

        Some(MoveCandidate {
            key: flow.key.clone(),
            old_worker: hi.worker_id,
            new_worker: lo.worker_id,
            new_queue: lo.queue_id,
        })
    }

    /// #1751 instrumentation: emit ONE debug line per eval when no move is
    /// taken, with the count vectors so a single `--features debug-log` deploy
    /// gives ground truth (per-worker counts + the chosen hi/lo + skip reason).
    /// Gated to the `debug-log` feature — compiled out of release builds.
    #[inline]
    fn log_skip(
        &self,
        input: &RebalanceTickInput,
        reason: SkipReason,
        hi: &WorkerByteRate,
        lo: &WorkerByteRate,
        c_hi: u32,
        c_lo: u32,
    ) {
        let _ = (input, reason, hi, lo, c_hi, c_lo);
        #[cfg(feature = "debug-log")]
        {
            let counts = per_worker_counts(&input.flows);
            let mut per_worker: std::collections::BTreeMap<u32, u32> =
                std::collections::BTreeMap::new();
            for w in &input.workers {
                per_worker.insert(w.worker_id, counts.get(&w.worker_id).copied().unwrap_or(0));
            }
            debug_log_rebalance!(
                "REBALANCE_SKIP ifindex={} reason={} K={} counts={:?} hi_w={} hi_count={} lo_w={} lo_count={} flows_total={}",
                input.ifindex,
                reason.as_str(),
                self.config.effective_k(),
                per_worker,
                hi.worker_id,
                c_hi,
                lo.worker_id,
                c_lo,
                input.flows.len(),
            );
        }
    }
}

/// #1751 r2 fix 3 (strong per-flow cooldown): a moved flow is ineligible to
/// move again for `max(interval * COOLDOWN_INTERVAL_MULTIPLIER,
/// COOLDOWN_MIN_SECS)` seconds. This is the oscillation guard that prevents the
/// install -> delete -> install ping-pong (the climbing deletes_total seen
/// live): once a flow is pinned it stays pinned for a long window, so bursty
/// count fluctuations cannot drive it back and forth. The absolute floor makes
/// the cooldown many seconds even when `rebalance_interval_secs == 1`.
const COOLDOWN_INTERVAL_MULTIPLIER: u64 = 20;

/// #1751 r2 fix 3: absolute minimum per-flow cooldown in seconds, so a small
/// configured rebalance-interval still yields a long anti-thrash window.
const COOLDOWN_MIN_SECS: u64 = 30;

#[derive(Clone, Debug)]
struct MoveCandidate {
    key: SessionKey,
    old_worker: u32,
    new_worker: u32,
    new_queue: u32,
}

/// The outcome of a committed move, for caller-side logging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct MoveOutcome {
    pub key: SessionKey,
    pub old_worker: u32,
    pub new_worker: u32,
    pub loc: u32,
}

/// #1751: per-worker steerable-flow COUNT, counted from the POST-FILTER
/// `flows` (the same row set the candidate is drawn from — plan §2.2 opt 1, so
/// count==rows by construction). Keyed by the real `worker_id`. A worker with
/// no steerable rows simply does not appear (callers treat absent as count 0).
pub(in crate::afxdp) fn per_worker_counts(flows: &[FlowSample]) -> HashMap<u32, u32> {
    let mut counts: HashMap<u32, u32> = HashMap::new();
    for f in flows {
        // #1751: exactly-once accounting — skip the abandoned RebalancedOut
        // copy on the old worker so a recently-moved flow is counted only at
        // its current owner. Counting it at W_old too inflated W_old's count,
        // made the controller keep moving flows off an already-drained worker,
        // and prevented convergence (over-installed ntuple rules).
        if !f.is_counted() {
            continue;
        }
        *counts.entry(f.worker_id).or_insert(0) += 1;
    }
    counts
}

/// Deterministic total order on `SessionKey` for reproducible candidate-flow
/// selection (homogeneous traffic: any flow on `hi` is equally good, so pick
/// the lowest key). Orders on the wire-relevant fields.
fn session_key_order(a: &SessionKey, b: &SessionKey) -> std::cmp::Ordering {
    a.addr_family
        .cmp(&b.addr_family)
        .then(a.protocol.cmp(&b.protocol))
        .then(a.src_ip.cmp(&b.src_ip))
        .then(a.dst_ip.cmp(&b.dst_ip))
        .then(a.src_port.cmp(&b.src_port))
        .then(a.dst_port.cmp(&b.dst_port))
}

/// Coefficient of variation (stddev / mean) of the per-worker byte-rates.
/// Returns 0 for a degenerate (empty / zero-mean) vector.
pub(in crate::afxdp) fn byte_rate_cov(workers: &[WorkerByteRate]) -> f64 {
    if workers.is_empty() {
        return 0.0;
    }
    let n = workers.len() as f64;
    let mean = workers.iter().map(|w| w.byte_rate).sum::<f64>() / n;
    if mean <= 0.0 {
        return 0.0;
    }
    let var = workers
        .iter()
        .map(|w| {
            let d = w.byte_rate - mean;
            d * d
        })
        .sum::<f64>()
        / n;
    var.sqrt() / mean
}

/// #1748 review #8: derive a byte-RATE from two CUMULATIVE byte-count samples
/// taken at `prev_ns` and `now_ns`. Single source of truth for both the
/// per-worker (tx_bytes) and per-flow (observed_bytes) rate derivation in the
/// Coordinator tick. Returns 0 when there is no prior sample, no elapsed time,
/// or the cumulative counter went backwards (a flow re-homing to a different
/// worker's cache entry resets its cumulative to ~0 — saturating_sub yields 0).
pub(in crate::afxdp) fn cumulative_to_rate(
    cumulative: u64,
    prev_cumulative: u64,
    now_ns: u64,
    prev_ns: u64,
) -> f64 {
    if now_ns <= prev_ns {
        return 0.0;
    }
    let dt = (now_ns - prev_ns) as f64 / 1_000_000_000.0;
    if dt <= 0.0 {
        return 0.0;
    }
    cumulative.saturating_sub(prev_cumulative) as f64 / dt
}

/// #1751 convergence potential: the sum-of-squares of the per-worker counts,
/// `Ψ = Σ_w count_w²` (mean-independent — `Σ(count-μ)²` differs from `Σcount²`
/// only by the constant `−N²/Nᵥ`, so the PER-MOVE change `ΔΨ` is identical;
/// the plain `Σcount²` form avoids a float mean). Each admitted move
/// (`c_hi − c_lo ≥ 2`) strictly decreases this by `≥ 2`
/// (`ΔΨ = 2 − 2(c_hi − c_lo) ≤ −2`), guaranteeing termination at the even
/// partition (plan §3.4). Test helper + an optional anti-thrash invariant
/// check; not on the hot path.
pub(in crate::afxdp) fn count_sum_of_squares(counts: &HashMap<u32, u32>) -> u64 {
    counts.values().map(|&c| (c as u64) * (c as u64)).sum()
}

/// #1751: pick the highest free ntuple location in `[0, size)` not present in
/// the `used` set, top-down (from `size-1`). Top-down matches ethtool's
/// `rmgr_find_empty_slot` order (lowest priority first → 1023 on an empty
/// table). The `used` set is the controller's LEDGER (the authoritative
/// used-set for our rules — the controller is the only ntuple-rule user and
/// the table starts empty), NOT a NIC query. `None` when all `size` locations
/// are used (caller → ENOSPC). The used set is tiny (bounded by `max_rules`),
/// so a linear scan is trivially cheap.
pub(in crate::afxdp) fn free_loc_top_down(size: u32, used: &[u32]) -> Option<u32> {
    (0..size).rev().find(|loc| !used.contains(loc))
}

/// Translate a SessionKey to the ethtool 5-tuple, converting host-order ports
/// and `IpAddr` into the network-order words the kernel UAPI expects.
pub(in crate::afxdp) fn flow_spec_from_key(key: &SessionKey) -> FlowSpec5Tuple {
    let (proto, src_ip, dst_ip) = match (key.src_ip, key.dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let proto = if key.protocol == super::super::PROTO_TCP {
                FlowProto::Tcp4
            } else {
                FlowProto::Udp4
            };
            (
                proto,
                [u32::from_ne_bytes(s.octets()), 0, 0, 0],
                [u32::from_ne_bytes(d.octets()), 0, 0, 0],
            )
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let proto = if key.protocol == super::super::PROTO_TCP {
                FlowProto::Tcp6
            } else {
                FlowProto::Udp6
            };
            (proto, v6_words(s), v6_words(d))
        }
        // Mixed families never form a real session key; default to v4 TCP so
        // the spec is well-formed (the move would simply never match).
        _ => (FlowProto::Tcp4, [0; 4], [0; 4]),
    };
    FlowSpec5Tuple {
        proto,
        src_ip,
        dst_ip,
        // SessionKey ports are host order; the kernel field is __be16.
        src_port: key.src_port.to_be(),
        dst_port: key.dst_port.to_be(),
    }
}

/// IPv6 address -> four network-order u32 words (matching `__be32[4]`).
fn v6_words(addr: std::net::Ipv6Addr) -> [u32; 4] {
    let o = addr.octets();
    [
        u32::from_ne_bytes([o[0], o[1], o[2], o[3]]),
        u32::from_ne_bytes([o[4], o[5], o[6], o[7]]),
        u32::from_ne_bytes([o[8], o[9], o[10], o[11]]),
        u32::from_ne_bytes([o[12], o[13], o[14], o[15]]),
    ]
}

#[cfg(test)]
#[path = "controller_tests.rs"]
mod tests;
