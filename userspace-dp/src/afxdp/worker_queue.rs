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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, TryLockError};

use super::types::WorkerCommand;

/// #1807: total worker-command-queue poison recoveries across every
/// producer/consumer site (worker poll peek + apply, HA enqueues,
/// session replication, activation prewarm, tunnel install/drain-wait,
/// cross-binding CoS redirect). Read by
/// `Coordinator::worker_command_queue_poison_recoveries_total()`.
pub(in crate::afxdp) static WORKER_COMMAND_QUEUE_POISON_RECOVERIES: AtomicU64 = AtomicU64::new(0);

/// #6929: the per-worker command-queue capacity.
///
/// WHY A CAP IS NEEDED AT ALL, since the consumer cannot be outrun. The worker
/// drain takes the WHOLE deque in one `core::mem::take` (`session_glue::mod.rs`),
/// so no sustained producer can outpace it — every poll empties the queue. The
/// unbounded case is not a rate mismatch, it is a consumer that has STOPPED:
///
///   - `spawn_supervised_worker` catches a `worker_loop` panic, sets
///     `runtime_atomics.dead = true` and lets the thread exit;
///   - the worker RECORD is never removed — nothing calls `records.remove`;
///   - every producer fans out with `for rec in self.workers.records.values()`
///     and no `dead` check, so it keeps pushing into that queue forever.
///
/// The `dead` flag is read only by `coordinator/status.rs`, for diagnostics. So
/// after any worker panic the queues grow without bound until memory is
/// exhausted, which is a correction rather than a hardening.
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
