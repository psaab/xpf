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
//   FIFO for a side slot (`parked`) and the drain continues in the same tick,
//   so every delta behind it (the other Closes, every session's HA
//   open/close, RT_FLOW, the RPC mirror) retires before RX polls; only the
//   parked Close waits. A parked Close is retried first on every tick and
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
// Residual (stated, not handled here): while a parked Close waits, RX polls,
// so a packet of that one tuple can re-materialize a same-id row from the
// still-published shared copy (the #10419 hazard, for the parked tuple only).
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

    /// The tick polls RX: the run of held ticks ends.
    pub(super) fn clear(&mut self, sessions: &mut crate::session::SessionTable) {
        sessions.set_close_head_blocked(false);
        self.run_since_ns = 0;
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
