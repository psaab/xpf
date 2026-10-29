// Phase 4 — service shaped CoS queues until noop, then a bounded
// re-ingest budget that catches late peer arrivals on the MPSC
// inbox.
//
// Codex round-2 finding 3.1 split: factored into two private
// helpers in the same file so the orchestrator still has one
// `drain_phase_drain_cos` entry point. `did_work: &mut bool` lets
// inner loops accumulate cumulative state into the orchestrator's
// local without leaking the backup outcome machinery here.

use super::super::*;
use super::DrainCtx;
use super::should_enter_shaped_drain;

// #17151: test-only seam between the initial shaped pass and the
// re-ingest budget in `drain_phase_drain_cos`. A regression cell arms it
// to enqueue a peer arrival into the redirect inbox AFTER the initial
// pass has run, so a re-ingest terminating noop cannot be satisfied by
// the initial pass. Thread-local storage isolates concurrent tests and
// adds no release-build state or call.
#[cfg(test)]
thread_local! {
    pub(crate) static AFTER_INITIAL_DRAIN_HOOK:
        std::cell::RefCell<Option<Box<dyn FnOnce(&mut BindingWorker)>>>
        = std::cell::RefCell::new(None);
}

/// Phase 4 entry point — orchestrator-facing.
#[inline]
pub(super) fn drain_phase_drain_cos(
    binding: &mut BindingWorker,
    ctx: &DrainCtx<'_>,
    shared_recycles: &mut Vec<(u32, u64)>,
    did_work: &mut bool,
) {
    shaped_initial_drain(binding, ctx, shared_recycles, did_work);
    // #17151: the hook block is `#[cfg(test)]` only; release builds keep
    // the bare two-call sequence with zero added cost.
    #[cfg(test)]
    {
        let hook = AFTER_INITIAL_DRAIN_HOOK.with(|h| h.borrow_mut().take());
        if let Some(hook) = hook {
            hook(binding);
        }
    }
    shaped_reingest_budget(binding, ctx, shared_recycles, did_work);
}

/// Single source of truth for the timed shaped-drain step (#17151):
/// service shaped queues until `drain_shaped_tx` reports noop
/// (`None`), attributing latency + invocations to each serviced
/// queue via its returned queue ref.
///
/// Noop policy (ONE, for every caller): the terminating `None` drain
/// bumps `binding.live.owner_profile_owner.drain_noop_invocations`
/// exactly once per call. This matches the counter's written
/// contracts — `worker/cos/mod.rs`: "counts drain calls that made no
/// progress on *any* queue" and `binding_state/mod.rs`: "terminating
/// `drain_shaped_tx` calls that returned `None`" — because that terminating
/// drain made no progress on any queue, whether or not earlier
/// iterations of this same call serviced work. The initial pass and
/// every re-ingest pass therefore count identically; callers MUST
/// NOT add their own noop arm.
///
/// Sets `*did_work` when any queue was serviced and returns whether
/// any queue was serviced (`serviced_any`).
/// Invariant: loops until `should_enter_shaped_drain` is false
/// or `drain_shaped_tx` returns no serviced queue (noop).
#[inline]
pub(super) fn service_shaped_until_noop(
    binding: &mut BindingWorker,
    ctx: &DrainCtx<'_>,
    shared_recycles: &mut Vec<(u32, u64)>,
    did_work: &mut bool,
) -> bool {
    let mut serviced_any = false;
    while should_enter_shaped_drain(binding) {
        let start_ns = monotonic_nanos();
        let serviced = drain_shaped_tx(binding, ctx.now_ns, shared_recycles);
        if let Some(serviced) = serviced.as_ref() {
            let delta = monotonic_nanos().saturating_sub(start_ns);
            let bucket = bucket_index_for_ns(delta);
            if let Some(root) = binding.cos.cos_interfaces.get(&serviced.root_ifindex) {
                if let Some(queue) = root.queues.get(serviced.queue_idx) {
                    if queue.queue_id() == serviced.queue_id {
                        queue.telemetry.owner_profile.drain_latency_hist[bucket]
                            .fetch_add(1, Ordering::Relaxed);
                        queue
                            .telemetry
                            .owner_profile
                            .drain_invocations
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            *did_work = true;
            serviced_any = true;
        } else {
            binding
                .live
                .owner_profile_owner
                .drain_noop_invocations
                .fetch_add(1, Ordering::Relaxed);
            break;
        }
    }
    serviced_any
}

/// Original #751 drain loop: service shaped queues until noop via
/// `service_shaped_until_noop` (the shared step; see its noop policy).
///
/// #1318: skip the whole shaped-drain call path when this binding
/// has no queued CoS work. `drain_shaped_tx` has its own defensive
/// bail, but the caller would still pay `monotonic_nanos()`, one
/// no-op call, and noop telemetry on every idle worker tick. The
/// helper preserves this: it only reaches the terminating `None`
/// (and its noop count) after `should_enter_shaped_drain` admitted
/// the loop, so an idle binding counts nothing.
#[inline]
fn shaped_initial_drain(
    binding: &mut BindingWorker,
    ctx: &DrainCtx<'_>,
    shared_recycles: &mut Vec<(u32, u64)>,
    did_work: &mut bool,
) {
    let _ = service_shaped_until_noop(binding, ctx, shared_recycles, did_work);
}

/// #760: bounded re-ingest → drain_shaped_tx loop, but ONLY
/// while the MPSC inbox has late peer arrivals AND CoS is
/// configured on some egress. For non-CoS traffic
/// (`forwarding.cos.interfaces` empty, or `pending_tx_local`
/// items all have `cos_queue_id=None`), the first ingest is
/// sufficient and re-ingesting does nothing useful — items
/// in `pending_tx_local` that `Err`'d out of the first pass
/// will `Err` the same way on every subsequent pass. The
/// quiesce guard below is inbox-only because that is the only
/// place peer workers can push new work after the first ingest.
///
/// Perf note: without the inbox-only guard, a 25 Gbps non-CoS
/// flow burns all 4 budget iterations per `drain_pending_tx`
/// call because `pending_tx_local` never empties — observed as
/// a severe throughput regression (25 Gbps → 3 Gbps). The
/// inbox-only guard keeps the non-CoS fast path at exactly the
/// pre-#760 cost.
///
/// Invariant: the `forwarding.cos.interfaces.is_empty()` guard
/// MUST stay here and MUST NOT be hoisted into the orchestrator —
/// it is independent of the same guard in the backup phase.
#[inline]
fn shaped_reingest_budget(
    binding: &mut BindingWorker,
    ctx: &DrainCtx<'_>,
    shared_recycles: &mut Vec<(u32, u64)>,
    did_work: &mut bool,
) {
    if ctx.forwarding.cos.interfaces.is_empty() {
        return;
    }
    const REINGEST_BUDGET: usize = 4;
    for _ in 0..REINGEST_BUDGET {
        if binding.live.pending_tx_empty() {
            break;
        }
        super::ingest_cos_pending_tx_with_provenance(
            binding,
            ctx.forwarding,
            ctx.now_ns,
            ctx.worker_id,
            ctx.worker_commands_by_id,
            false,
            shared_recycles,
        );
        // #17151: the shared step applies the ONE noop policy; the
        // wrapper keeps only its budget, inbox guard, and the
        // `!serviced_any -> break` quiesce rule.
        let serviced_any = service_shaped_until_noop(binding, ctx, shared_recycles, did_work);
        if !serviced_any {
            break;
        }
    }
}
