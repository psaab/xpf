// #19026 — the bounded close-permit barrier, split out of housekeeping.rs.
//
// A Close delta that cannot take its tuple install permits is a teardown
// barrier: `run_session_housekeeping` retries it before command/control work
// and before `poll_binding` (the #10419 teardown-before-poll order). Before
// #19026 that barrier was unbounded: housekeeping returned "skip the tick" on
// every pass, the loop `continue`d before `poll_binding`, and because the
// heartbeat is stored before housekeeping the worker stayed "healthy" while it
// polled no RX at all. This module owns the bound and everything that keeps a
// stuck permit from costing more than its own tuple:
//
// - RX bound: inside `CLOSE_PERMIT_BARRIER_NS` of one blocked EPISODE (one
//   Close, keyed by tuple + session id) the tick skips RX; past it the Close
//   keeps first claim on every tick and the tick then polls RX.
// - Park bound (R13 F1): past `CLOSE_PARK_AFTER_NS` the blocked Close leaves
//   the FIFO for a side slot (`parked`) so the deltas behind it — every other
//   session's HA open/close, RT_FLOW, the RPC mirror — keep flowing instead of
//   filling the 4096 ring and latching delta-loss. A parked Close is retried
//   first on every tick and retires once its permit frees. A same-tuple
//   reincarnation that overtakes it is safe: the flush's stale-incarnation
//   fence (`session_delta.rs::close_delta_is_stale_incarnation`) makes the old
//   Close's teardown and HA close id-conditional.
// - Head-blocked bit (R13 F2/F3): `SessionTable::close_head_blocked` makes
//   the next drain re-test the head's permits with one try instead of a
//   256-delta drain/requeue, and makes the post-RX export/recovery slices
//   leave the ring alone instead of re-draining it and `continue`ing past the
//   rest of the tick.
// - Zombie retirement (R13 F4): while RX polled with the Close blocked, a
//   packet of that tuple could re-materialize a same-id local row from the
//   still-published shared copy. When such a Close finally retires, a
//   same-id local row is queued for `DeleteSynced` on this worker too (the
//   flush fans the delete out to siblings only).
// - Episode log (R13 F5): one rate-limited line per expired episode naming
//   the blocked tuple and a `TupleGate::probe()` of its holder class; an
//   episode whose line was printed also logs its end.

use super::*;

/// #19026: the longest one worker may withhold its RX poll for one blocked
/// Close. 1 ms matches the idle path's own `INTERRUPT_POLL_TIMEOUT_MS` block:
/// short enough that a permit that never returns costs one tuple's teardown
/// ordering, never the worker's RX; long enough to keep the #10419
/// teardown-before-poll order for ordinary contention (permits are held for
/// microseconds).
pub(super) const CLOSE_PERMIT_BARRIER_NS: u64 = 1_000_000;

/// #19026 (R13 F1): past this age a blocked Close is parked out of the FIFO.
/// 10 ms keeps the delta stream's head-of-line stall far below the 4096-slot
/// ring's capacity at any realistic per-worker delta rate (400 k deltas/s
/// would be needed to fill it), while ordinary contention never parks.
pub(super) const CLOSE_PARK_AFTER_NS: u64 = 10_000_000;

const _: () = assert!(CLOSE_PARK_AFTER_NS > CLOSE_PERMIT_BARRIER_NS);

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
    /// Inside the RX bound: skip the rest of the tick (teardown first).
    HoldRx,
    /// Past the RX bound: poll RX; the Close keeps first claim next tick.
    PollRx,
    /// Past the park bound: the Close was moved to the side slot; poll RX.
    Parked,
}

/// #19026: per-worker state of the close-permit barrier (worker-loop local).
#[derive(Debug, Default)]
pub(super) struct ClosePermitBarrier {
    /// Loop time the current blocked episode began; 0 = no episode.
    since_ns: u64,
    /// The episode's Close: (tuple, session id). A different blocked Close
    /// starts a new episode with its own RX window (R13 F5).
    episode: Option<(SessionKey, u64)>,
    /// The episode outlived `CLOSE_PERMIT_BARRIER_NS`; RX polls resumed.
    expired: bool,
    /// This episode's expiry line was actually printed.
    logged: bool,
    /// Closes parked past `CLOSE_PARK_AFTER_NS`, oldest first.
    pub(super) parked: Vec<SessionDelta>,
    /// Episodes that outlived the RX bound (diagnostic).
    pub(super) expired_episodes: u64,
    /// Closes ever parked (diagnostic).
    pub(super) parked_total: u64,
}

impl ClosePermitBarrier {
    /// An attempt to retire a Close failed on its tuple permit. Locates the
    /// blocked delta (`at`), runs its episode, and parks it past the park
    /// bound. `own_queue` receives the zombie-retirement `DeleteSynced` of a
    /// PREVIOUS expired episode whose Close has since retired (R13 F4).
    pub(super) fn on_blocked(
        &mut self,
        sessions: &mut crate::session::SessionTable,
        overflow: &mut Vec<SessionDelta>,
        at: BlockedAt,
        worker_id: u32,
        own_queue: Option<&Arc<Mutex<VecDeque<WorkerCommand>>>>,
        now_ns: u64,
    ) -> BlockedVerdict {
        let blocked = match at {
            BlockedAt::Ring => sessions.front_pending_delta(),
            BlockedAt::Overflow => overflow.first(),
        };
        let Some(blocked) = blocked else {
            // Nothing identifiable is blocked (the delta retired between the
            // attempt and here): let the tick run.
            return BlockedVerdict::PollRx;
        };
        let identity = (blocked.key.clone(), blocked.session_id);
        if self.episode.as_ref() != Some(&identity) {
            self.end_episode(sessions, worker_id, own_queue, now_ns);
            self.episode = Some(identity);
            self.since_ns = now_ns.max(1);
        }
        // Every Ring caller reports a block that `drain_and_flush_all_impl`
        // found, and it set the head bit when it did (a mutant that set it
        // here as well survived every cell: it was redundant).
        debug_assert!(
            at != BlockedAt::Ring || sessions.close_head_blocked(),
            "a blocked ring head carries the head-blocked bit"
        );
        let held_ns = now_ns.saturating_sub(self.since_ns);
        if held_ns < CLOSE_PERMIT_BARRIER_NS {
            return BlockedVerdict::HoldRx;
        }
        if !self.expired {
            self.expired = true;
            self.expired_episodes = self.expired_episodes.saturating_add(1);
            self.logged = emit_barrier_line(sessions, at, overflow, worker_id, held_ns, now_ns, "waiting");
        }
        if held_ns < CLOSE_PARK_AFTER_NS {
            return BlockedVerdict::PollRx;
        }
        let parked = match at {
            BlockedAt::Ring => sessions.pop_front_delta(),
            BlockedAt::Overflow => (!overflow.is_empty()).then(|| overflow.remove(0)),
        };
        if let Some(parked) = parked {
            if self.logged {
                eprintln!(
                    "xpf-dp: w{worker_id}: #19026 blocked session close parked after {} ms; \
                     later deltas flow, the close retries first every tick",
                    held_ns / 1_000_000
                );
            }
            self.parked.push(parked);
            self.parked_total = self.parked_total.saturating_add(1);
        }
        if at == BlockedAt::Ring {
            sessions.set_close_head_blocked(false);
        }
        // The parked Close is retried (and zombie-checked) from the side
        // slot; this episode is over.
        self.episode = None;
        self.since_ns = 0;
        self.expired = false;
        self.logged = false;
        BlockedVerdict::Parked
    }

    /// No Close is blocked this tick: end the episode, if any.
    pub(super) fn clear(
        &mut self,
        sessions: &mut crate::session::SessionTable,
        worker_id: u32,
        own_queue: Option<&Arc<Mutex<VecDeque<WorkerCommand>>>>,
        now_ns: u64,
    ) {
        sessions.set_close_head_blocked(false);
        if self.since_ns == 0 {
            return;
        }
        self.end_episode(sessions, worker_id, own_queue, now_ns);
    }

    fn end_episode(
        &mut self,
        sessions: &crate::session::SessionTable,
        worker_id: u32,
        own_queue: Option<&Arc<Mutex<VecDeque<WorkerCommand>>>>,
        now_ns: u64,
    ) {
        if let Some((key, session_id)) = self.episode.take()
            && self.expired
        {
            // RX polled while this Close was blocked, and it has now retired.
            retire_rx_exposed_zombie(sessions, &key, session_id, own_queue);
            if self.logged {
                eprintln!(
                    "xpf-dp: w{worker_id}: #19026 blocked session close drained after {} ms",
                    now_ns.saturating_sub(self.since_ns) / 1_000_000
                );
            }
        }
        self.since_ns = 0;
        self.expired = false;
        self.logged = false;
    }
}

/// #19026 (R13 F4): a Close that waited while RX polled has retired (its
/// shared rows, BPF state, sibling copies and HA close are gone). A same-id
/// local row on THIS worker can only be a re-materialized copy of the closed
/// session — the flush fans `DeleteSynced` out to siblings, never to itself —
/// so queue the same delete here through the ordinary command path (NAT
/// holder release, steering release, flow-cache eviction included).
pub(super) fn retire_rx_exposed_zombie(
    sessions: &crate::session::SessionTable,
    key: &SessionKey,
    session_id: u64,
    own_queue: Option<&Arc<Mutex<VecDeque<WorkerCommand>>>>,
) -> bool {
    if session_id == 0 || sessions.session_id_for_bare_tuple(key) != Some(session_id) {
        return false;
    }
    let Some(queue) = own_queue else {
        return false;
    };
    let mut pending = crate::afxdp::worker_queue::lock_recover(queue);
    crate::afxdp::worker_queue::push_bounded(&mut pending, WorkerCommand::DeleteSynced(key.clone()))
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
         gate fwd={:?} rev={:?} queued={} (other episodes since last line: {})",
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

/// Once per expired episode, rate-limited process-wide (cold). Returns
/// whether a line was printed (R13 F5: `logged` follows the print).
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
