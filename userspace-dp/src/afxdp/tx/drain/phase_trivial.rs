// Four thin drain phases collapsed into one file: reap, rekick,
// ingest, and finish. Each is small enough that the
// filesystem-level separation Codex wanted for the larger phases
// would be over-modularization here.

use super::super::*;
use super::DrainCtx;

/// Phase 1 — drain completions from the kernel TX completion ring.
/// Invariant: returns the initial value of `did_work` for the
/// orchestrator to fold subsequent phase contributions into.
#[inline]
pub(super) fn drain_phase_reap_completions(
    binding: &mut BindingWorker,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> bool {
    reap_tx_completions(binding, shared_recycles) > 0
}

/// Phase 2 — re-kick the TX ring in copy mode when the kernel has
/// outstanding entries but no pending prepared/local work to drive
/// the next sendto(). Invariant: only kicks when there is no
/// pending work that would drive the next sendto() itself.
#[inline]
pub(super) fn drain_phase_maybe_rekick(binding: &mut BindingWorker, ctx: &DrainCtx<'_>) {
    if binding.tx_pipeline.outstanding_tx > 0
        && binding.tx_pipeline.pending_tx_prepared.is_empty()
        && binding.tx_pipeline.pending_tx_local.is_empty()
    {
        maybe_wake_tx(binding, false, ctx.now_ns);
    }
}

/// Phase 3 — first ingest pass: move `pending_tx_local` + MPSC
/// inbox items into CoS queues where possible. Invariant: items
/// lacking a matching CoS configuration (or `cos_queue_id=None`)
/// stay in `pending_tx_local` and flow through the backup phase.
#[inline]
pub(super) fn drain_phase_ingest_cos(
    binding: &mut BindingWorker,
    ctx: &DrainCtx<'_>,
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    super::ingest_cos_pending_tx(
        binding,
        ctx.forwarding,
        ctx.now_ns,
        ctx.worker_id,
        ctx.worker_commands_by_id,
        shared_recycles,
    );
}

/// Phase 6 — final debug-state snapshot + the
/// `did_work || binding_has_pending_tx_work(binding)` fold that
/// `drain_pending_tx` returns. Neither submits nor wakes: TX
/// submission happens in the shaped/backup phases and ring kicks
/// in `drain_phase_maybe_rekick`. Invariant: this is the single
/// `update_binding_debug_state` call on the fall-through path.
#[inline]
pub(super) fn drain_phase_finish(binding: &mut BindingWorker, did_work: bool) -> bool {
    update_binding_debug_state(binding);
    did_work || super::binding_has_pending_tx_work(binding)
}
