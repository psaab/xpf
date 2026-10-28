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

/// Phase 4 entry point — orchestrator-facing.
#[inline]
pub(super) fn drain_phase_drain_cos(
    binding: &mut BindingWorker,
    ctx: &DrainCtx<'_>,
    shared_recycles: &mut Vec<(u32, u64)>,
    did_work: &mut bool,
) {
    shaped_initial_drain(binding, ctx, shared_recycles, did_work);
    shaped_reingest_budget(binding, ctx, shared_recycles, did_work);
}

/// Original #751 drain loop: service shaped queues until noop.
/// Each shaped drain attributes latency + invocations to the
/// specific queue via `drain_shaped_tx`'s returned queue ref.
///
/// #1318: skip the whole shaped-drain call path when this binding
/// has no queued CoS work. `drain_shaped_tx` has its own defensive
/// bail, but the caller would still pay `monotonic_nanos()`, one
/// no-op call, and noop telemetry on every idle worker tick.
///
/// Invariant: loops until `should_enter_shaped_drain` is false
/// or `drain_shaped_tx` returns no serviced queue (noop).
#[inline]
fn shaped_initial_drain(
    binding: &mut BindingWorker,
    ctx: &DrainCtx<'_>,
    shared_recycles: &mut Vec<(u32, u64)>,
    did_work: &mut bool,
) {
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
        } else {
            binding
                .live
                .owner_profile_owner
                .drain_noop_invocations
                .fetch_add(1, Ordering::Relaxed);
            break;
        }
    }
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
        let mut serviced_in_inner = false;
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
                serviced_in_inner = true;
            } else {
                break;
            }
        }
        if !serviced_in_inner {
            break;
        }
    }
}
