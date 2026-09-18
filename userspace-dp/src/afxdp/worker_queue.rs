// #1807: shared poison-recovery helpers for the per-worker
// `Mutex<VecDeque<WorkerCommand>>` command queues.
//
// One uniform policy for every producer and consumer of a worker
// command queue (extends the #1790 coordinator-side recovery):
//
// - Poison means a thread panicked while holding the lock. The panic
//   already happened and was contained (#925 worker supervisor); the
//   deque holds the **committed prefix** of every completed push — a
//   panic between the pushes of a multi-push section (e.g. the
//   DemoteOwnerRGS + VacateAllSharedExactSlots pair in ha.rs, or the
//   forward + reverse UpsertLocal pair in tunnel.rs) leaves exactly
//   the commands pushed before the panic. Commands are individually
//   self-contained, so consumers tolerate partial batches; discarding
//   the queue instead would lose acknowledged HA/session commands.
// - `clear_poison` restores the fast unpoisoned path for subsequent
//   accesses, so the Poisoned arm stays cold after the first recovery
//   instead of taxing every later lock.
// - Every recovery bumps `WORKER_COMMAND_QUEUE_POISON_RECOVERIES`,
//   surfaced via ProcessStatus as the Prometheus counter
//   `xpf_userspace_worker_command_queue_poison_recoveries_total`.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, TryLockError};

use super::types::{TxRequest, WorkerCommand};

/// #1807: total worker-command-queue poison recoveries across every
/// producer/consumer site (worker poll peek + apply, HA enqueues,
/// session replication, activation prewarm, tunnel install/drain-wait,
/// cross-binding CoS redirect). Read by
/// `Coordinator::worker_command_queue_poison_recoveries_total()`.
pub(in crate::afxdp) static WORKER_COMMAND_QUEUE_POISON_RECOVERIES: AtomicU64 = AtomicU64::new(0);

/// #6929: the per-worker command-queue capacity.
///
/// WHY A CAP IS NEEDED AT ALL. #6929 justified this cap by observing that the
/// consumer could not be outrun: the drain took the WHOLE deque in one
/// `core::mem::take`, so every poll emptied the queue however fast the producer
/// ran. **That is no longer how the drain works** — #7201 replaced the
/// take-everything drain with a bounded prefix drain
/// ([`drain_bounded_into`]), so a poll now removes at most
/// [`WORKER_COMMAND_DRAIN_BUDGET`] commands and a backlog can persist across
/// polls.
///
/// The cap's justification survives that change, because it never rested on the
/// drain granularity. What governs whether the cap is reached is the consumer's
/// PROCESSING rate (~1 µs/command, measured in #7201), not how many commands one
/// `mem::take` moved: a producer faster than ~1 command/µs reaches the cap under
/// either drain, and a slower one reaches it under neither. The bounded drain
/// revisits the queue ~16x more often for the same absorbed throughput.
///
/// The unbounded case was never a rate mismatch anyway — it is a consumer that
/// has STOPPED:
///
///   - `spawn_supervised_worker` catches a `worker_loop` panic, sets
///     `runtime_atomics.dead = true` and lets the thread exit;
///   - the worker RECORD is never removed — no PRODUCTION path removes a single
///     record (registration is post-spawn-success and teardown publishes an
///     empty map; #7209's `remove_record_for_test` is `cfg(test)` only);
///   - every producer fans out with `for rec in workers.records().values()` —
///     since #7209 that reads the published `ArcSwap` rather than an owned
///     `BTreeMap`, which changes WHERE the set comes from and nothing about
///     this argument — and no `dead` check, so it keeps pushing into that queue
///     forever.
///
/// The `dead` flag is read by `coordinator/status.rs` for diagnostics AND by
/// record-keyed fan-out producers, which shed (skip + count) dead workers
/// instead of feeding them (#9900 F-093). Slice-based producers (session
/// replication, CoS redirect, PPTP broadcast) carry bare queue handles with
/// no record access and still push; `push_bounded` caps those queues at 4096
/// so a dead worker's backlog is bounded, never unbounded.
///
/// 4096 mirrors `MAX_PENDING_SESSION_DELTAS`, the sibling bound this codebase
/// already applies to the same class of producer-side deque. Matching it is
/// deliberate: two different ceilings for two per-worker backlogs would be a
/// number an operator has to look up rather than know.
pub(in crate::afxdp) const MAX_PENDING_WORKER_COMMANDS: usize = 4096;

/// #6929: worker commands refused because the target queue was already at
/// `MAX_PENDING_WORKER_COMMANDS`.
///
/// SEPARATE from `WORKER_COMMAND_QUEUE_POISON_RECOVERIES` on purpose, and the
/// distinction is not cosmetic: a poison recovery means a producer/consumer
/// panicked and the queue was RECOVERED with its committed prefix intact — no
/// command was lost. A capacity drop means a command was DISCARDED. Folding
/// them into one number would tell an operator "something happened to the
/// queue" while hiding whether anything was actually lost, and the two have
/// opposite remediations.
pub(in crate::afxdp) static WORKER_COMMAND_QUEUE_DROPS: AtomicU64 = AtomicU64::new(0);

/// #9900 F-093: worker commands SHED because the target worker is dead
/// (the #925 supervisor recorded its panic and the thread exited).
///
/// THIRD signal alongside the two above, and again the distinction is
/// load-bearing: a poison recovery loses nothing, a capacity drop discards a
/// command a LIVE worker would have consumed, and a shed discards a command
/// addressed to a worker that can never consume anything again. Folding shed
/// into DROPS would report dead-worker fan-out as live-queue overload — the
/// two have opposite remediations (restart/reconcile the dead worker vs shed
/// load from a live one).
pub(in crate::afxdp) static WORKER_COMMAND_QUEUE_SHED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Test-only serializer for exact-delta assertions on
/// `WORKER_COMMAND_QUEUE_SHED_TOTAL`. The counter is process-global and
/// several tests bump it (fan-out sheds, export shed, prewarm filter), so
/// unsynchronized exact deltas flake under parallel execution. Every test
/// that bumps OR asserts this counter holds this lock for its duration.
#[cfg(test)]
pub(crate) static SHED_TEST_LOCK: Mutex<()> = Mutex::new(());

/// #9720: RG-transition commands a full worker queue REFUSED, held out-of-band
/// per worker until the worker's drain cursor reaches the refused command's
/// logical position.
///
/// WHY OUT-OF-BAND. `update_ha_state` stores the new RG runtime BEFORE fanning
/// out, so a later call diffs against the demoted state and never re-drives a
/// refused `DemoteOwnerRGS` / `VacateAllSharedExactSlots` / `RefreshOwnerRGS`.
/// The signal that must reach the worker cannot travel through the queue that
/// refused it — the same shape as #8586's delete-drop epoch, but the payload
/// here is a versioned op log rather than a tripwire.
///
/// POSITION (parent GPT-1/SPARK-F1; v2 got this backwards). `push_bounded`
/// refuses the NEWEST command, so at refusal time the refused transition is
/// NEWER than the full backlog but OLDER than every post-refusal arrival: its
/// true FIFO position is after the backlog, before the arrivals. Dispatching
/// ahead of the backlog installs transitions before older commands (v2: a
/// queued stale reverse installs verbatim AFTER a debt-refresh missed); only
/// dispatching AT the boundary is correct for both classes.
///
/// The boundary is positional, not temporal: each op records the backlog
/// length observed under the queue guard at refusal (`remaining`), and every
/// apply decrements it by the commands it drained. The op dispatches once its
/// countdown reaches zero — i.e. once every pre-transition command has been
/// dispatched — or when the queue drains fully, whichever comes first. The
/// queue-empty clause is load-bearing, not a shortcut: the producer reads the
/// length under the queue guard but records after releasing it (ABBA
/// discipline below), so a worker drain or a producer deschedule in between
/// overstates `remaining`; an empty queue means every pre-transition command
/// was dispatched regardless, so the position is reached. Misplacement is
/// bounded by ~1 slice either way, never by backlog depth or arrival rate.
///
/// ORDER + SUPERSESSION (parent SPARK-F2). The log is chronological (one op
/// per refused push, appended in refusal order). Recording a transition for
/// an RG strips that RG from ALL older ops first: an older entry for a
/// re-transitioned RG is superseded by definition, so the log holds at most
/// one pending op per RG per kind plus vacates, and same-RG flaps collapse
/// to the latest transition. Cross-RG order is preserved in the log.
///
/// NET-EFFECT CHARACTERIZATION (parent O5 — read before touching dispatch).
/// What the log replays is ordered; what it MEANS is net-effect under current
/// state, and that rests on four facts: (1) the Refresh handler IGNORES its
/// RG list beyond the any-positive gate and wide-scans every HA-managed
/// session, so a Refresh subset is advisory (call/don't-call) with cross-RG
/// blast radius, while a Demote subset is precise (narrow indexed walk) — a
/// future narrow-refresh "optimization" must preserve debt semantics;
/// (2) demote ops commute across RGs (disjoint per-RG flips) and refresh is
/// idempotent within one tick, so same-tick replay order among survivors is
/// behaviorally moot — the log order that MATTERS is debt-vs-backlog
/// (position), not debt-vs-debt; (3) a fully-filtered op is a net no-change
/// (skip implies back to pre-transition state, where pre-transition
/// dispositions are correct); (4) every activation emits its own wide refresh
/// in-band-or-debt, covering split-RG companions.
///
/// SCHEDULING (parent GPT-2). The epoch is bumped AFTER the slot write on
/// every record; the worker loop samples it EVERY pass and calls
/// `apply_worker_commands` when it changed — even with an empty queue — so
/// a producer descheduled between refusal and record cannot strand debt:
/// the next pass observes the bump and dispatches. Consumption is
/// last-observed-after-apply (a record landing mid-apply refires the next
/// pass; at most one spurious apply), plus a `transition_debt_pending` carry
/// for the contended-with-empty pass, which the tunnel drain-wait makes real
/// (`wait_for_local_tunnel_session_install` polls queues read-only).
///
/// LOCK DISCIPLINE (reviews A1/B2): the debt lock is a LEAF. `record` drops
/// the queue guard BEFORE taking it; decrement/extract releases it before
/// dispatching (handlers run with NO debt guard held). No path ever holds
/// the debt lock and the queue lock together, in either order — there is no
/// new lock-graph edge for a green suite to miss.
///
/// Indexed by worker id, bounded by `MAX_NAT_HOLDER_WORKERS` — the same
/// ceiling the planner refuses to mint past. The per-command DROPPED counters
/// count EVERY refusal (bumped by the caller before recording); the slot +
/// epoch exist only for in-range ids, so an out-of-range refusal (a test-only
/// shape in production) is counter-only, with no worker to wake.
/// `register` clears the slot (no epoch reset needed: the worker seeds its
/// last-observed from current, so a cleared slot plus a running epoch never
/// spuriously fires), so a reused worker id never replays the previous
/// generation's debt onto a fresh worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum TransitionDebtKind {
    Demote,
    Refresh,
    Vacate,
}

/// One refused transition push, in chronological log order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct TransitionDebtOp {
    kind: TransitionDebtKind,
    /// RG set for Demote/Refresh (deduped, first-occurrence order); always
    /// empty for Vacate.
    rgs: Vec<i32>,
    /// Pre-transition backlog still to drain before dispatch. Observed as the
    /// queue length under the guard at refusal; decremented per drained
    /// command; the queue-empty clause covers record-race overstatement.
    remaining: usize,
}

impl TransitionDebtOp {
    pub(in crate::afxdp) fn kind(&self) -> TransitionDebtKind {
        self.kind
    }

    pub(in crate::afxdp) fn rgs(&self) -> &[i32] {
        &self.rgs
    }

    pub(in crate::afxdp) fn remaining(&self) -> usize {
        self.remaining
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct HaTransitionDebt {
    ops: Vec<TransitionDebtOp>,
}

impl HaTransitionDebt {
    const fn new() -> Self {
        Self { ops: Vec::new() }
    }

    pub(in crate::afxdp) fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub(in crate::afxdp) fn ops(&self) -> &[TransitionDebtOp] {
        &self.ops
    }

    /// Strip one RG from all older Demote/Refresh ops (record-time
    /// supersession): a newer transition for the RG makes older pending ones
    /// moot. Vacate ops are never stripped (vacate is unconditional).
    fn supersede(&mut self, rg: i32) {
        for op in self.ops.iter_mut() {
            if op.kind != TransitionDebtKind::Vacate {
                op.rgs.retain(|r| *r != rg);
            }
        }
        self.ops
            .retain(|op| op.kind == TransitionDebtKind::Vacate || !op.rgs.is_empty());
    }

    /// Append refused pushes in emission order (Demote, Vacate, Refresh is
    /// `update_ha_state`'s own fan-out order), each positioned after the
    /// `backlog` commands that were ahead of it at refusal. RG sets are tiny
    /// (cluster RG count), so linear dedup/supersede scans are cheaper than
    /// a set import — and `Vec::new` is `const`, which the static array
    /// below needs.
    fn record(&mut self, demote: &[i32], refresh: &[i32], vacate: bool, backlog: usize) {
        for rg in demote.iter().chain(refresh.iter()) {
            self.supersede(*rg);
        }
        let mut deduped = |rgs: &[i32]| {
            let mut out = Vec::with_capacity(rgs.len());
            for rg in rgs {
                if !out.contains(rg) {
                    out.push(*rg);
                }
            }
            out
        };
        if !demote.is_empty() {
            self.ops.push(TransitionDebtOp {
                kind: TransitionDebtKind::Demote,
                rgs: deduped(demote),
                remaining: backlog,
            });
        }
        if vacate {
            self.ops.push(TransitionDebtOp {
                kind: TransitionDebtKind::Vacate,
                rgs: Vec::new(),
                remaining: backlog,
            });
        }
        if !refresh.is_empty() {
            self.ops.push(TransitionDebtOp {
                kind: TransitionDebtKind::Refresh,
                rgs: deduped(refresh),
                remaining: backlog,
            });
        }
    }

    /// Decrement every op by the commands just drained and extract the ops
    /// whose position is reached: countdown at zero, or the queue fully
    /// drained (the record-race backstop — see the header). Returns the ready
    /// ops in log order; the rest stay queued with their updated countdowns.
    fn step(&mut self, drained: usize, queue_empty: bool) -> Vec<TransitionDebtOp> {
        for op in self.ops.iter_mut() {
            op.remaining = op.remaining.saturating_sub(drained);
        }
        let mut ready = Vec::new();
        self.ops.retain(|op| {
            if op.remaining == 0 || queue_empty {
                ready.push(op.clone());
                false
            } else {
                true
            }
        });
        ready
    }
}

pub(in crate::afxdp) static HA_TRANSITION_DEBT: [Mutex<HaTransitionDebt>;
    crate::nat::MAX_NAT_HOLDER_WORKERS as usize] =
    [const { Mutex::new(HaTransitionDebt::new()) }; crate::nat::MAX_NAT_HOLDER_WORKERS as usize];

/// #9720: per-worker transition-debt epoch, bumped on every record.
///
/// The out-of-band wakeup the #8586 delete-drop epoch is for deletes: the
/// worker loop samples this EVERY pass and applies on change even with an
/// empty queue, so debt recorded while the worker idles (or was descheduled
/// past the drain) is dispatched on the next pass rather than stranded until
/// the next enqueue. Same width/indexing/relaxed-ordering precedent as
/// `SESSION_DELETE_DROP_EPOCH`; the mutex carries the payload, this atomic
/// carries the hint. Bumped AFTER the slot write leaves the critical section
/// (shorter hold; same-atomic coherence orders the hint).
pub(in crate::afxdp) static HA_TRANSITION_DEBT_EPOCH: [AtomicU64;
    crate::nat::MAX_NAT_HOLDER_WORKERS as usize] =
    [const { AtomicU64::new(0) }; crate::nat::MAX_NAT_HOLDER_WORKERS as usize];

/// Read one worker's transition-debt epoch. Out of range reads 0 (an id past
/// the planner's ceiling can neither be recorded nor dispatched, so the pair
/// is consistent) — mirrors `session_delete_drop_epoch`.
#[inline]
pub(in crate::afxdp) fn transition_debt_epoch(worker_id: u32) -> u64 {
    HA_TRANSITION_DEBT_EPOCH
        .get(worker_id as usize)
        .map(|e| e.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// Whether the worker loop must call `apply_worker_commands` this pass.
///
/// The debt arms are what make stranded debt impossible: an epoch change
/// fires the apply that dispatches debt on an otherwise idle worker, and the
/// carried pending flag covers the contended-with-empty pass (real: the
/// tunnel drain-wait polls queues read-only). The call site, the fresh epoch
/// load, the post-apply consume, and the results-field carry are pinned by
/// the source-scan wiring guard in `worker_queue_tests.rs` (#7201 pattern) —
/// a truth table alone cannot pin production wiring.
#[inline]
pub(in crate::afxdp) fn should_apply_worker_commands(
    has_commands: bool,
    debt_epoch_changed: bool,
    debt_pending: bool,
) -> bool {
    has_commands || debt_epoch_changed || debt_pending
}

/// Lock a transition-debt slot, recovering and CLEARING poison.
///
/// The uniform #1807 policy, verbatim: committed debt intact, fast path
/// restored, one shared `WORKER_COMMAND_QUEUE_POISON_RECOVERIES` bump. The
/// debt lock sits on the worker command delivery path (HA-enqueue record
/// side, worker-apply step side), so it shares that counter rather than
/// minting a fourth queue signal.
#[inline]
fn lock_debt_recover(m: &Mutex<HaTransitionDebt>) -> MutexGuard<'_, HaTransitionDebt> {
    match m.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            m.clear_poison();
            WORKER_COMMAND_QUEUE_POISON_RECOVERIES.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "xpf-ha: transition-debt mutex poisoned; recovering committed debt and clearing poison"
            );
            poisoned.into_inner()
        }
    }
}

/// Record refused RG-transition commands for one worker (the #9720 debt).
///
/// The caller MUST have dropped the queue guard first: this takes the debt
/// lock, and any path holding both locks in queue→debt order would ABBA
/// against a debt→queue holder. The step side holds the debt lock alone and
/// releases it before dispatching, so no reverse edge exists — the discipline
/// keeps it that way.
///
/// `backlog` is the queue length observed under the guard at refusal: every
/// one of those commands predates the transition, so the op dispatches once
/// the worker has drained that many. The epoch bumps after the slot write
/// (S6: shorter critical section; the mutex already ordered the payload).
#[inline]
pub(in crate::afxdp) fn record_transition_debt(
    worker_id: u32,
    demote: &[i32],
    refresh: &[i32],
    vacate: bool,
    backlog: usize,
) {
    if demote.is_empty() && refresh.is_empty() && !vacate {
        return;
    }
    let Some(slot) = HA_TRANSITION_DEBT.get(worker_id as usize) else {
        return;
    };
    lock_debt_recover(slot).record(demote, refresh, vacate, backlog);
    if let Some(epoch) = HA_TRANSITION_DEBT_EPOCH.get(worker_id as usize) {
        epoch.fetch_add(1, Ordering::Relaxed);
    }
}

/// Step one worker's debt countdown by the commands just drained and extract
/// the ops whose position is reached, returning them with whether debt
/// remains for a future pass.
///
/// Takes and releases the debt lock around the step ONLY — handlers run with
/// no debt guard held (reviews A1/B2), so a full-table demote scan never
/// stretches a lock across BPF publishes and neighbor reads. `queue_empty`
/// MUST be the drain's own emptiness observation from the slice critical
/// section (S3): re-locking after dispatch would skip debt whenever arrivals
/// landed mid-slice and starve it under sustained load.
#[inline]
pub(in crate::afxdp) fn take_ready_transition_debt(
    worker_id: u32,
    drained: usize,
    queue_empty: bool,
) -> (Vec<TransitionDebtOp>, bool) {
    let Some(slot) = HA_TRANSITION_DEBT.get(worker_id as usize) else {
        return (Vec::new(), false);
    };
    let mut debt = lock_debt_recover(slot);
    let ready = debt.step(drained, queue_empty);
    let pending = !debt.is_empty();
    (ready, pending)
}

/// Whether one worker's debt slot is non-empty (the contended-path peek).
///
/// Used ONLY when the queue lock could not be acquired: the countdown cannot
/// advance without a drain count, but the carry flag still needs a value.
/// Blocking policy like every other debt access (held across `is_empty`
/// only); out of range reads false.
#[inline]
pub(in crate::afxdp) fn has_transition_debt(worker_id: u32) -> bool {
    HA_TRANSITION_DEBT
        .get(worker_id as usize)
        .map(|slot| !lock_debt_recover(slot).is_empty())
        .unwrap_or(false)
}

/// Clear one worker's transition-debt slot.
///
/// Called from `WorkerManager::register`: worker ids are reused across
/// generations, and a worker that died with undrained debt must not replay it
/// onto its fresh successor. The epoch is deliberately NOT reset: the new
/// worker seeds its last-observed from current, so clear-then-seed never
/// spuriously fires, and any record after the clear bumps past the seed. The
/// clear races spawn (the thread starts before its record publishes — review
/// B6) but the race is benign: a fresh worker holds an empty session table
/// and fresh CoS slots, so a replayed op is a no-op walk, and the clear still
/// bounds staleness to one generation.
#[inline]
pub(in crate::afxdp) fn clear_transition_debt(worker_id: u32) {
    if let Some(slot) = HA_TRANSITION_DEBT.get(worker_id as usize) {
        *lock_debt_recover(slot) = HaTransitionDebt::new();
    }
}

/// #9720: refused `DemoteOwnerRGS` / `RefreshOwnerRGS` /
/// `VacateAllSharedExactSlots` pushes, per command type.
///
/// `WORKER_COMMAND_QUEUE_DROPS` (bumped by `push_bounded` on the same refusal)
/// stays the aggregate; these three are the PER-COMMAND split the issue
/// requires, so an operator can tell a lost transition from lost session
/// churn. Units are PUSHES (one per refused fan-out leg).
///
/// A refusal counted here is recorded as transition debt (in-range ids) and
/// dispatched positionally — or filtered as stale below. So
/// `DEMOTE_DROPPED ≈ demote-RGs-applied-late + DEMOTE_STALE_SKIPPED` (and
/// likewise Refresh), relating a push-level count to RG-level dispositions;
/// a climbing DROPPED with flat applies means transitions are outrunning a
/// live worker's drain, not that commands are being silently lost.
pub(in crate::afxdp) static HA_TRANSITION_DEMOTE_DROPPED: AtomicU64 = AtomicU64::new(0);
pub(in crate::afxdp) static HA_TRANSITION_REFRESH_DROPPED: AtomicU64 = AtomicU64::new(0);
pub(in crate::afxdp) static HA_TRANSITION_VACATE_DROPPED: AtomicU64 = AtomicU64::new(0);

/// #9720: debt RGs filtered as stale at dispatch, per command type (parent
/// O8). A demote RG whose group is currently active (failback landed first)
/// or a refresh RG whose group is not active is superseded: dispatching it
/// would corrupt post-transition state, so it is skipped — and the skip is
/// counted here so `DROPPED climbs + slot empty + no effect` reads as
/// documented behavior rather than a loss. Units are RG APPLICATIONS (one
/// per filtered RG), not pushes. Vacate never skips (unconditional).
pub(in crate::afxdp) static HA_TRANSITION_DEMOTE_STALE_SKIPPED: AtomicU64 = AtomicU64::new(0);
pub(in crate::afxdp) static HA_TRANSITION_REFRESH_STALE_SKIPPED: AtomicU64 = AtomicU64::new(0);

/// #9720 test seam: snapshot one worker's pending debt log.
#[cfg(test)]
pub(in crate::afxdp) fn transition_debt_for_test(worker_id: u32) -> HaTransitionDebt {
    HA_TRANSITION_DEBT
        .get(worker_id as usize)
        .map(|slot| lock_debt_recover(slot).clone())
        .unwrap_or_default()
}

/// Push a command onto a worker queue, refusing at the capacity bound (#6929).
///
/// Returns whether the command was accepted. Callers that need to know a
/// command was LOST — the HA upsert/delete paths — can act on `false`; callers
/// for whom a drop is merely a missed optimisation can ignore it.
///
/// REFUSES AT THE BOUND RATHER THAN EVICTING THE OLDEST. The queue carries
/// ordered state transitions (`UpsertSynced` then `DeleteSynced` for one key),
/// and dropping from the FRONT would apply a delete whose matching upsert was
/// discarded, leaving the worker's view of that key inverted rather than merely
/// stale. Refusing the newest keeps the retained prefix internally consistent,
/// which is the same choice `push_session_delta` makes.
#[inline]
pub(in crate::afxdp) fn push_bounded(
    pending: &mut VecDeque<WorkerCommand>,
    cmd: WorkerCommand,
) -> bool {
    if pending.len() >= MAX_PENDING_WORKER_COMMANDS {
        WORKER_COMMAND_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    pending.push_back(cmd);
    true
}

/// Enqueue a shaped-local request without losing ownership on capacity refusal.
///
/// `push_bounded` accepts a complete `WorkerCommand`, so its boolean refusal
/// cannot recover the `TxRequest` nested inside the command. CoS redirect
/// callers need the request for their Step 2/3 fallback; check the same bound
/// while holding the queue lock, account the refusal, and only then move the
/// request into the command.
#[inline]
pub(in crate::afxdp) fn push_shaped_local_bounded(
    pending: &mut VecDeque<WorkerCommand>,
    req: TxRequest,
) -> Result<(), TxRequest> {
    if pending.len() >= MAX_PENDING_WORKER_COMMANDS {
        WORKER_COMMAND_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
        return Err(req);
    }
    pending.push_back(WorkerCommand::EnqueueShapedLocal(req));
    Ok(())
}

/// #7201: the most commands one `apply_worker_commands` call may process before
/// returning to the worker loop.
///
/// THIS IS A RING-SERVICE BUDGET, NOT A FAIRNESS KNOB. The worker does not touch
/// its AF_XDP RX/TX rings while it is applying commands, so the batch size is
/// wall-clock time the rings go unserviced. `ring_entries` defaults to 4096
/// (`server/lifecycle.rs`), and at 25 Gbps with 1500 B frames (~2.08 Mpps) a
/// 4096-slot RX ring fills in ~1.97 ms. A drain of the full
/// [`MAX_PENDING_WORKER_COMMANDS`] measured 3.85 ms — already past that, and a
/// LOWER bound, since the measurement ran with a steering-map fd of `-1` so the
/// `bpf_map_update_elem` calls failed at the fd check without paying the
/// kernel-side hash insert (a forward `publish_live_session_entry` issues up to
/// four real map updates). That burst arrives at RG activation, the moment the
/// node has just become forwarding-authoritative.
///
/// 256 is the same slice `sessions.drain_deltas(256)` already takes in this
/// loop, so the worker keeps one batch granularity rather than two. At the
/// measured ~1 µs/command it bounds the unserviced window to ~256 µs — an order
/// of magnitude under the ring's fill time, with margin for the real map
/// syscalls the measurement could not pay.
pub(in crate::afxdp) const WORKER_COMMAND_DRAIN_BUDGET: usize = 256;

/// The budget must be a strict fraction of the queue capacity.
///
/// Compile-time, and deliberately HERE rather than in the test module: the
/// failure it prevents is silent. At
/// `WORKER_COMMAND_DRAIN_BUDGET >= MAX_PENDING_WORKER_COMMANDS` the drain can
/// never leave a remainder, so every behavioural cell for #7201 still passes
/// while the budget has quietly become the take-everything drain it replaced.
/// An invariant over two production constants has to hold in a production
/// build, not only under `cfg(test)`.
const _: () = assert!(WORKER_COMMAND_DRAIN_BUDGET < MAX_PENDING_WORKER_COMMANDS);

/// Move at most [`WORKER_COMMAND_DRAIN_BUDGET`] commands from the front of
/// `pending` into `scratch`, returning whether `pending` still holds a backlog.
///
/// PREFIX, NOT FILTER. The slice is contiguous and taken from the FRONT, so FIFO
/// and every ordering group inside the batch survive by construction — there is
/// no ordering rule for a split to violate that a whole-batch drain would have
/// honoured. A budget that skipped or reordered commands to fill a quota is what
/// would break `apply_worker_commands_dispatch_order_pin_with_demote_dedup`.
///
/// `scratch` is worker-owned and recycled across calls; it is drained by the
/// caller, so it keeps its allocation. This is what replaces the
/// `core::mem::take(&mut *pending)` the drain used to do — that left the SHARED
/// deque at zero capacity on every pass, forcing the producers (which hold the
/// lock) to reallocate it from scratch each time.
///
/// The caller MUST treat a `true` return as work for the worker loop's idle
/// regulation. `did_work` in `worker/loop_body` is set only by `poll_binding`,
/// so a backlog left behind by this budget is invisible to it; on a node with no
/// traffic yet — the standby that has just been told to take over — `idle_iters`
/// passes `IDLE_SPIN_ITERS` and each remaining slice lands behind a 1 ms
/// `poll(2)` in Interrupt mode. That would convert a bounded 3.85 ms stall into
/// ~16 ms of drain, which is worse than the defect this budget exists to fix.
#[inline]
pub(in crate::afxdp) fn drain_bounded_into(
    pending: &mut VecDeque<WorkerCommand>,
    scratch: &mut VecDeque<WorkerCommand>,
) -> bool {
    let take = pending.len().min(WORKER_COMMAND_DRAIN_BUDGET);
    scratch.extend(pending.drain(..take));
    !pending.is_empty()
}

/// Lock a worker-command queue, recovering and CLEARING poison.
///
/// Policy (#1807, extends #1790): a panic that poisoned the queue
/// already happened and was contained ([#925] supervisor); the deque
/// holds the committed prefix of every completed push — discarding it
/// would lose acknowledged HA/session commands. `clear_poison` restores
/// the fast unpoisoned path for subsequent accesses.
#[inline]
pub(in crate::afxdp) fn lock_recover(
    m: &Mutex<VecDeque<WorkerCommand>>,
) -> MutexGuard<'_, VecDeque<WorkerCommand>> {
    match m.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            m.clear_poison();
            WORKER_COMMAND_QUEUE_POISON_RECOVERIES.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "xpf-ha: worker command queue mutex poisoned; recovering committed queue and clearing poison"
            );
            poisoned.into_inner()
        }
    }
}

/// #4800: [`lock_recover`] that reports whether it had to block, for the
/// N-way session-replication fan-out.
///
/// `try_lock` first (one CAS on an uncontended mutex — what `lock()` cost
/// anyway); on WouldBlock bump `contended` and fall through to the blocking
/// [`lock_recover`], which carries the poison policy. Kept as an explicit
/// opt-in rather than folded into `lock_recover` because that helper is
/// shared by the tunnel, TX-drain, HA and cross-binding CoS enqueues —
/// counting all of them would blur the very attribution this exists for.
#[inline]
pub(in crate::afxdp) fn lock_recover_counting<'a>(
    m: &'a Mutex<VecDeque<WorkerCommand>>,
    contended: &AtomicU64,
) -> MutexGuard<'a, VecDeque<WorkerCommand>> {
    if let Some(guard) = try_lock_recover(m) {
        return guard;
    }
    contended.fetch_add(1, Ordering::Relaxed);
    lock_recover(m)
}

/// `try_lock` variant of [`lock_recover`]: WouldBlock → `None`
/// (unchanged skip semantics — another thread holds the lock and will
/// release it shortly); Poisoned → recover + clear + `Some(guard)`,
/// same committed-prefix policy as [`lock_recover`].
#[inline]
pub(in crate::afxdp) fn try_lock_recover(
    m: &Mutex<VecDeque<WorkerCommand>>,
) -> Option<MutexGuard<'_, VecDeque<WorkerCommand>>> {
    match m.try_lock() {
        Ok(guard) => Some(guard),
        Err(TryLockError::WouldBlock) => None,
        Err(TryLockError::Poisoned(poisoned)) => {
            m.clear_poison();
            WORKER_COMMAND_QUEUE_POISON_RECOVERIES.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "xpf-ha: worker command queue mutex poisoned; recovering committed queue and clearing poison"
            );
            Some(poisoned.into_inner())
        }
    }
}

#[cfg(test)]
#[path = "worker_queue_tests.rs"]
// #7015: `pub(in crate::afxdp)` so the source-scan helpers this module owns
// (`blank_comments_and_strings`, `afxdp_rs_files`, `is_fixture`) can be shared
// with the prune-obligation guard in forwarding_build/tests.rs rather than
// copied. A second implementation of comment-blanking is the shape where a
// source-scanning gate quietly stops seeing what it is meant to see.
// #7053: widened again from `pub(in crate::afxdp)` — the routing-instance
// pairing guard lives in `filter/tests.rs`, outside this module tree, and a
// second copy of comment-blanking is exactly where a source-scanning gate
// quietly stops seeing what it is meant to.
pub(crate) mod tests;

/// #7699: broadcast a PPTP association install to EVERY worker.
///
/// The control channel (TCP/1723) and the GRE data channel are not reliably
/// co-located — RSS hashes the flow tuple, so they share a worker only by
/// chance — which is why this is a broadcast rather than a send to one worker.
///
/// Returns the number of queues that ACCEPTED the command. A short count is not
/// an error but it is not nothing either: a worker that missed the install
/// resolves that call's packets as UNASSOCIATED until it is re-published, which
/// is the forward-and-count path rather than a drop. Callers that can retry
/// should; callers that cannot should surface the shortfall rather than treat a
/// partial broadcast as a complete one.
pub(in crate::afxdp) fn broadcast_pptp_install(
    queues: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    call: crate::session::pptp::PptpCall,
    control: crate::session::pptp::ControlChannelId,
    learned_ns: u64,
) -> usize {
    let mut accepted = 0;
    for q in queues {
        let mut pending = lock_recover(q);
        if push_bounded(
            &mut pending,
            WorkerCommand::InstallPptpCall { call, control, learned_ns },
        ) {
            accepted += 1;
        }
    }
    accepted
}

/// #7699: drain the PPTP control inbox — parse, install locally, publish.
///
/// Returns how many associations were learned on this pass.
///
/// **This is the production join.** Every other piece of #7699 works in
/// isolation: the parser parses, the table resolves, the broadcast fans out,
/// the drain applies. Until this function existed nothing chained them, and
/// each end's cells stayed green against a build where the middle was missing.
///
/// # It is safe to call every poll iteration, and that is a property of the
/// callee
///
/// The interval gate lives inside [`PptpControlInbox::take_pending`], not here
/// and not at the call site. The caller is the worker poll loop, which runs at
/// packet rate; a gate written at the call site would be one edit away from
/// running per-poll — the defect that shipped in #8399, where the association
/// expiry landed ABOVE `expire_stale_entries_ha`'s gc-interval gate and scanned
/// the whole map on every call.
///
/// # Why it installs locally AND broadcasts
///
/// `peer_worker_commands` EXCLUDES this worker (built with a
/// `filter(|(id, _)| **id != worker_id)` at the coordinator's bring-up). A
/// broadcast alone would therefore teach every worker but the one that saw the
/// segment — and since RSS does not co-locate the control and data channels,
/// that worker is as likely as any to be the one the call's GRE data lands on.
/// The local install is not a duplicate of the broadcast; it is the half the
/// broadcast structurally cannot reach.
pub(in crate::afxdp) fn drain_pptp_control_inbox(
    inbox: &crate::session::pptp_control::PptpControlInbox,
    sessions: &mut crate::session::SessionTable,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    now_ns: u64,
) -> usize {
    let mut learned = 0;
    for seg in inbox.take_pending(now_ns) {
        let Some(call) = crate::session::pptp_control::learn_from_control_segment(
            seg.src,
            seg.dst,
            &seg.payload,
        ) else {
            // Not a control message, truncated, or a call that did not connect.
            // All three mean no association — the call's data takes the
            // unassociated path, forwarded and counted.
            continue;
        };
        let control = crate::session::pptp::ControlChannelId::new(
            seg.src,
            seg.src_port,
            seg.dst,
            seg.dst_port,
        );
        if let Err(e) = sessions.pptp_mut().install(call, control, now_ns) {
            debug_log!("PPTP association refused on the local worker: {:?}", e);
            continue;
        }
        broadcast_pptp_install(peer_worker_commands, call, control, now_ns);
        learned += 1;
    }
    learned
}

/// #7699: broadcast a PPTP association teardown to every worker.
///
/// Same broadcast reasoning as the install, and a stronger reason to notice a
/// shortfall: a worker that misses a teardown keeps a stale association, and
/// PPTP call IDs are 16-bit and REUSED — so a later call can pair onto the dead
/// handle. That is a mis-attribution, not a leak, which is why the association
/// must also expire on its own rather than relying on this reaching everyone.
pub(in crate::afxdp) fn broadcast_pptp_forget(
    queues: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    handle: u32,
) -> usize {
    let mut accepted = 0;
    for q in queues {
        let mut pending = lock_recover(q);
        if push_bounded(&mut pending, WorkerCommand::ForgetPptpCall(handle)) {
            accepted += 1;
        }
    }
    accepted
}

#[cfg(test)]
mod pptp_broadcast_tests_7699 {
    use super::*;
    use crate::session::pptp::PptpCall;

    fn queues(n: usize) -> Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> {
        (0..n).map(|_| Arc::new(Mutex::new(VecDeque::new()))).collect()
    }

    fn a_ctl() -> crate::session::pptp::ControlChannelId {
        crate::session::pptp::ControlChannelId::new(
            "198.51.100.7".parse().unwrap(),
            49152,
            "203.0.113.9".parse().unwrap(),
            1723,
        )
    }

    fn a_call() -> PptpCall {
        PptpCall::new(
            "198.51.100.7".parse().unwrap(),
            0x1111,
            "203.0.113.9".parse().unwrap(),
            0x2222,
        )
    }

    /// EVERY worker must get the install, not just one.
    ///
    /// This is the property the whole broadcast exists for: RSS lands a call's
    /// data packets on a worker chosen by the flow hash, which is generally not
    /// the one that saw its control channel. A send-to-one would leave the call
    /// unresolvable on N-1 workers, and a fixture with a single queue would not
    /// notice — so this asserts over several.
    #[test]
    fn an_install_reaches_every_worker_7699() {
        let qs = queues(4);
        assert_eq!(broadcast_pptp_install(&qs, a_call(), a_ctl(), 0), 4);
        for (i, q) in qs.iter().enumerate() {
            let pending = q.lock().expect("queue");
            assert_eq!(pending.len(), 1, "worker {i} did not receive the install");
            assert!(matches!(pending[0], WorkerCommand::InstallPptpCall { .. }));
        }
    }

    /// A teardown must reach every worker too.
    ///
    /// Asserted separately rather than assumed symmetric with the install: a
    /// worker that keeps a stale association re-pairs a REUSED 16-bit call id
    /// onto a dead handle, which is a mis-attribution rather than a leak.
    #[test]
    fn a_teardown_reaches_every_worker_7699() {
        let qs = queues(3);
        assert_eq!(broadcast_pptp_forget(&qs, 0xdead_beef), 3);
        for q in &qs {
            let pending = q.lock().expect("queue");
            assert!(matches!(pending[0], WorkerCommand::ForgetPptpCall(0xdead_beef)));
        }
    }

    /// A FULL queue is reported, not swallowed.
    ///
    /// `push_bounded` drops when the queue is at capacity, so a broadcast can
    /// be partial. That is survivable — the missed worker resolves those
    /// packets as unassociated and forwards them — but it must be VISIBLE, or a
    /// caller cannot tell a complete broadcast from one that reached half the
    /// dataplane. The count is the signal.
    #[test]
    fn a_full_queue_makes_the_broadcast_report_short_7699() {
        let qs = queues(2);
        {
            let mut full = qs[1].lock().expect("queue");
            for _ in 0..MAX_PENDING_WORKER_COMMANDS {
                full.push_back(WorkerCommand::VacateAllSharedExactSlots);
            }
        }
        assert_eq!(
            broadcast_pptp_install(&qs, a_call(), a_ctl(), 0),
            1,
            "a broadcast that reached only one of two workers must report 1; \
             reporting 2 would let a caller treat a half-delivered association \
             as installed"
        );
    }
}
