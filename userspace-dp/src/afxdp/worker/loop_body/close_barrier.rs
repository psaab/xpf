// #19026 — the bounded close-permit barrier, split out of housekeeping.rs.
//
// A Close delta that cannot take its tuple install permits is a teardown
// barrier: `run_session_housekeeping` retries it before command/control work
// and before `poll_binding` (the #10419 teardown-before-poll order). Before
// #19026 that barrier was unbounded: housekeeping returned "skip the tick" on
// every pass, the loop `continue`d before `poll_binding`, and because the
// heartbeat is stored before housekeeping the worker stayed "healthy" while it
// polled no RX at all. This module owns the bound:
//
// - ONE RX bound per run (R13 N1): a run is the consecutive ticks that skipped
//   RX for a blocked Close, whichever Closes they were. Inside
//   `CLOSE_PERMIT_BARRIER_NS` of the run's start the tick skips RX; only a
//   tick that polls RX ends the run.
// - Park at the bound (R13 F1, R1(b)): past it the blocked Close leaves the
//   FIFO for a side slot (`parked`), and the drain continues in the same
//   tick. The deltas behind it (the other Closes, every session's HA
//   open/close, RT_FLOW, the RPC mirror) retire before RX polls, up to the
//   pass budget `CLOSE_PARK_PASS_BUDGET`. Past the budget, the Closes left in
//   the ring and the deferred overflow suffix also wait for a later pass. A
//   parked Close is retried before and after the drains, at most
//   `PARKED_RETRY_PASS_BUDGET` tries a pass (a cursor over the slot), and
//   retires once its permit frees. A same-tuple reincarnation that overtakes
//   it is safe: the flush's stale-incarnation fence
//   (`session_delta.rs::close_delta_is_stale_incarnation`) makes the old
//   Close's local teardown id-conditional, and an old Close whose EXACT key
//   now holds the reincarnation skips its HA legs (the binary HA Close
//   carries no id; Codex R16 F1, `close_delta_is_superseded_on_exact_key`).
// - Head-blocked bit (R13 F2/F3): `SessionTable::close_head_blocked` makes
//   the next drain re-test the head's permits with one try instead of a
//   256-delta drain/requeue, and makes the post-RX export/recovery slices
//   leave the ring alone instead of re-draining it and `continue`ing past the
//   rest of the tick.
// - Park log (R13 F5/F6): one rate-limited line per park naming the blocked
//   tuple and a `TupleGate::probe()` of its holder class.
//
// Residual (stated, not handled here): while a Close waits across an RX poll
// (a parked Close, a Close a budget exit left in the ring, or a deferred
// overflow suffix), a packet of its tuple can re-materialize a same-id row
// from the still-published shared copy: the #10419 hazard, for those tuples.
// The cycle-1 "zombie retirement" queued a bare `DeleteSynced` for it, which
// could delete a queued replacement (Codex R15 P1#4); it was removed.
// Tracked in #19047.

use super::*;

/// #19026: the longest one worker may withhold its RX poll for blocked
/// Closes, per run of held ticks (R13 N1). 1 ms matches the idle path's own `INTERRUPT_POLL_TIMEOUT_MS` block:
/// short enough that a permit that never returns costs one tuple's teardown
/// ordering, never the worker's RX; long enough to keep the #10419
/// teardown-before-poll order for ordinary contention (permits are held for
/// microseconds).
pub(super) const CLOSE_PERMIT_BARRIER_NS: u64 = 1_000_000;

/// #19026 (Codex review of af0ea8415c): parking work allowed in ONE
/// housekeeping pass, in deltas moved: ring deltas re-drained behind a
/// newly blocked head, plus overflow suffix deltas copied around a parked
/// overflow head. The 1 ms bound limits skipped TICKS, not the work of one
/// pass. Without this budget, 4,096 distinct blocked Closes cost about one
/// million delta drains in the pass that parked them; master stopped at the
/// first blocked head. One ring's worth (`MAX_SESSION_DELTAS`) keeps a pass
/// within the cost of draining one full ring. Past it the pass returns to RX
/// and the run carries over, so the next pass parks at once.
pub(super) const CLOSE_PARK_PASS_BUDGET: usize = crate::session::MAX_SESSION_DELTAS;

/// #19026 (R13 N8 on 661d9cb6ba): parked-Close permit tries (and so
/// retirements) allowed in ONE housekeeping pass, across its two retry calls.
/// The slot is walked with a cursor, so a backlog larger than this cycles
/// over the following passes. R13 measured about 29 ms a tick for 16,000
/// parked Closes with the unbounded walk.
pub(super) const PARKED_RETRY_PASS_BUDGET: usize = 256;

/// #19026: process-wide rate limit for the barrier journal lines (one line
/// per interval across ALL workers, the #1760 CAS-throttle pattern), so a
/// recurring permit stall cannot flood journald. Suppressed lines are counted
/// and reported on the next emitted line.
pub(super) const CLOSE_PERMIT_BARRIER_WARN_INTERVAL_NS: u64 = 10_000_000_000;
static CLOSE_PERMIT_BARRIER_WARN_LAST_NS: AtomicU64 = AtomicU64::new(0);
static CLOSE_PERMIT_BARRIER_WARN_SUPPRESSED: AtomicU64 = AtomicU64::new(0);

/// Pure throttle predicate (pinned by a cell): `last == 0` means never
/// emitted.
pub(super) fn close_barrier_warn_due(last_ns: u64, now_ns: u64) -> bool {
    last_ns == 0 || now_ns.saturating_sub(last_ns) >= CLOSE_PERMIT_BARRIER_WARN_INTERVAL_NS
}

fn try_claim_close_permit_barrier_warn(now_ns: u64) -> bool {
    let last = CLOSE_PERMIT_BARRIER_WARN_LAST_NS.load(Ordering::Acquire);
    if !close_barrier_warn_due(last, now_ns) {
        return false;
    }
    CLOSE_PERMIT_BARRIER_WARN_LAST_NS
        .compare_exchange(last, now_ns.max(1), Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// #19026 (R13 F3): whether a Close's tuple install permits are free right
/// now (taken and released at once). Non-Close deltas need none.
pub(super) fn close_permits_available(delta: &SessionDelta) -> bool {
    if delta.kind != SessionDeltaKind::Close {
        return true;
    }
    crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs(crate::afxdp::session_delta::close_install_keys(delta))
        .is_ok()
}

/// #19026 (R13 F2/F3): the ring's head is a Close that a previous attempt
/// found blocked AND whose permits are still busy. One permit try; no drain.
pub(super) fn front_close_still_blocked(sessions: &crate::session::SessionTable) -> bool {
    sessions.close_head_blocked()
        && sessions
            .front_pending_delta()
            .is_some_and(|front| !close_permits_available(front))
}

/// Where the blocked Close sits when an attempt fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BlockedAt {
    /// The session delta ring's head.
    Ring,
    /// The head of the deferred expiry-overflow suffix (#10309).
    Overflow,
}

/// What the tick does about a blocked Close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BlockedVerdict {
    /// Inside the run's RX bound: skip the rest of the tick (teardown first).
    HoldRx,
    /// Past the bound: the Close was moved to the side slot; drain on.
    Parked,
    /// Nothing identifiable is blocked (the delta retired between the
    /// attempt and the check): let the tick run.
    PollRx,
}

/// #19026: per-worker state of the close-permit barrier (worker-loop local).
#[derive(Debug, Default)]
pub(super) struct ClosePermitBarrier {
    /// Loop time the current run of RX-skipping ticks began; 0 = the last
    /// tick polled RX.
    run_since_ns: u64,
    /// Closes parked at the RX bound, oldest first.
    pub(super) parked: Vec<SessionDelta>,
    /// Closes ever parked (diagnostic).
    pub(super) parked_total: u64,
    /// Parking work spent in this housekeeping pass (`CLOSE_PARK_PASS_BUDGET`).
    pass_work: usize,
    /// The budget ran out this pass: the run carries over the RX tick.
    budget_exhausted: bool,
    /// Where the next parked retry resumes in `parked`.
    pub(super) retry_cursor: usize,
    /// Parked permit tries left in this pass (`PARKED_RETRY_PASS_BUDGET`).
    retry_left: usize,
    /// Parked permit tries ever made (diagnostic; cells count it).
    pub(super) retry_tries: u64,
}

impl ClosePermitBarrier {
    /// An attempt to retire a Close failed on its tuple permit. Locates the
    /// blocked delta (`at`); inside the run's RX bound holds the tick, past it
    /// parks the delta.
    pub(super) fn on_blocked(
        &mut self,
        sessions: &mut crate::session::SessionTable,
        overflow: &mut Vec<SessionDelta>,
        at: BlockedAt,
        worker_id: u32,
        now_ns: u64,
    ) -> BlockedVerdict {
        let blocked = match at {
            BlockedAt::Ring => sessions.front_pending_delta(),
            BlockedAt::Overflow => overflow.first(),
        };
        if blocked.is_none() {
            return BlockedVerdict::PollRx;
        }
        // Every Ring caller reports a block that `drain_and_flush_all_impl`
        // found, and it set the head bit when it did.
        debug_assert!(
            at != BlockedAt::Ring || sessions.close_head_blocked(),
            "a blocked ring head carries the head-blocked bit"
        );
        if self.run_since_ns == 0 {
            self.run_since_ns = now_ns.max(1);
        }
        let held_ns = now_ns.saturating_sub(self.run_since_ns);
        if held_ns < CLOSE_PERMIT_BARRIER_NS {
            return BlockedVerdict::HoldRx;
        }
        emit_barrier_line(sessions, at, overflow, worker_id, held_ns, now_ns, "parked after");
        let parked = match at {
            BlockedAt::Ring => sessions.pop_front_delta(),
            BlockedAt::Overflow => Some(overflow.remove(0)),
        };
        if let Some(parked) = parked {
            self.parked.push(parked);
            self.parked_total = self.parked_total.saturating_add(1);
        }
        if at == BlockedAt::Ring {
            sessions.set_close_head_blocked(false);
        }
        BlockedVerdict::Parked
    }

    /// The tick polls RX: the run of held ticks ends, unless this pass
    /// stopped parking at its work budget. Then the run carries over, so the
    /// next pass parks the remaining blocked heads at once instead of
    /// holding RX for a fresh bound.
    pub(super) fn clear(&mut self, sessions: &mut crate::session::SessionTable) {
        sessions.set_close_head_blocked(false);
        if !std::mem::take(&mut self.budget_exhausted) {
            self.run_since_ns = 0;
        }
    }

    /// A housekeeping pass starts: its parking and retry budgets are fresh.
    pub(super) fn begin_pass(&mut self) {
        self.pass_work = 0;
        self.retry_left = PARKED_RETRY_PASS_BUDGET;
    }

    /// This call's parked-retry limit: the tries left in the pass, but never
    /// more than one walk of the slot. Each try spends one (`spend_retry`),
    /// so tries a call does not make stay for the pass's later call.
    pub(super) fn retry_limit(&self) -> usize {
        self.retry_left.min(self.parked.len())
    }

    /// One parked permit try.
    pub(super) fn spend_retry(&mut self) {
        self.retry_left = self.retry_left.saturating_sub(1);
        self.retry_tries = self.retry_tries.saturating_add(1);
    }

    /// Account `work` deltas of parking work. Returns `true` (and marks the
    /// run to carry over) once this pass is over `CLOSE_PARK_PASS_BUDGET`.
    pub(super) fn spend(&mut self, work: usize) -> bool {
        self.pass_work = self.pass_work.saturating_add(work);
        if self.pass_work >= CLOSE_PARK_PASS_BUDGET {
            self.budget_exhausted = true;
        }
        self.budget_exhausted
    }
}

/// #19026 (R13 F6): the barrier journal line, pure so a cell can pin it.
pub(super) fn format_close_barrier_line(
    worker_id: u32,
    what: &str,
    held_ns: u64,
    delta: &SessionDelta,
    probe_forward: crate::afxdp::bpf_map::TupleGateProbe,
    probe_reverse: crate::afxdp::bpf_map::TupleGateProbe,
    queued: usize,
    suppressed: u64,
) -> String {
    format!(
        "xpf-dp: w{worker_id}: #19026 session close {what} {} us for its tuple permit; \
         RX polling continues. close proto={} {}:{} -> {}:{} id={:#x} origin={} \
         gate fwd={:?} rev={:?} queued={} (other parks since last line: {})",
        held_ns / 1_000,
        delta.key.protocol,
        delta.key.src_ip,
        delta.key.src_port,
        delta.key.dst_ip,
        delta.key.dst_port,
        delta.session_id,
        delta.origin.as_str(),
        probe_forward,
        probe_reverse,
        queued,
        suppressed,
    )
}

/// Once per park, rate-limited process-wide (cold). Returns whether a line
/// was printed.
#[cold]
#[inline(never)]
fn emit_barrier_line(
    sessions: &crate::session::SessionTable,
    at: BlockedAt,
    overflow: &[SessionDelta],
    worker_id: u32,
    held_ns: u64,
    now_ns: u64,
    what: &str,
) -> bool {
    let delta = match at {
        BlockedAt::Ring => sessions.front_pending_delta(),
        BlockedAt::Overflow => overflow.first(),
    };
    let Some(delta) = delta else {
        return false;
    };
    if !try_claim_close_permit_barrier_warn(now_ns) {
        CLOSE_PERMIT_BARRIER_WARN_SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let gate = crate::afxdp::bpf_map::global_tuple_gate();
    let [forward, reverse] = crate::afxdp::session_delta::close_install_keys(delta);
    eprintln!(
        "{}",
        format_close_barrier_line(
            worker_id,
            what,
            held_ns,
            delta,
            gate.probe(&forward),
            gate.probe(&reverse),
            sessions.pending_delta_count() + overflow.len(),
            CLOSE_PERMIT_BARRIER_WARN_SUPPRESSED.swap(0, Ordering::Relaxed),
        )
    );
    true
}
