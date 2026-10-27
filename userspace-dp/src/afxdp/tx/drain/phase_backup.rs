// Phase 5 — post-CoS backup transmit. Drops CoS-bound items
// that reached this path instead of being shaped, then drains
// `pending_tx_prepared` via `transmit_prepared_batch`, then
// the `pending_tx_local`/inbox tail via `transmit_batch` with
// `TX_BATCH_SIZE` retry batching.
//
// Factored into two private helpers in the same file.
// `backup_drain_prepared` returns `Option<BackupOutcome>` so the
// prepared-side `TxError::Retry` (which returns `true`
// unconditionally) can short-circuit the local-side drain.
// `backup_drain_local` returns `BackupOutcome` directly; both of
// its empty-pending early returns collapse to `Return(..)` carrying
// the already-folded result, and the single
// `update_binding_debug_state` call is owned by the orchestrator,
// which invokes `drain_phase_finish` on the fall-through path.

use super::super::*;
use super::DrainCtx;
use super::{
    binding_has_pending_tx_work, drop_cos_bound_local_leftovers, drop_cos_bound_prepared_leftovers,
    restore_pending_tx_requests, take_pending_tx_requests,
};

/// Outcome of the backup phase. Two variants only: either fall
/// through to phase 6 (`drain_phase_finish`), or return the
/// enclosed result immediately. The orchestrator owns the single
/// `update_binding_debug_state` call site (in this branch or in
/// `drain_phase_finish`); every path reaching this phase passes
/// through it exactly once. The enclosed result is `true`
/// unconditionally for the prepared-side `TxError::Retry`
/// (ignoring accumulated `did_work`), and the
/// `did_work || binding_has_pending_tx_work(binding)` OR-fold
/// itself for the empty-pending early returns. Invariant: no
/// variant encodes a debug-update distinction — that distinction
/// only shifted a ~1-in-65536 debug-publish cadence tick.
pub(super) enum BackupOutcome {
    /// Fall through to phase 6 (`drain_phase_finish`).
    Continue,
    /// Return the enclosed `bool` from `drain_pending_tx`
    /// immediately, skipping phase 6.
    Return(bool),
}

#[inline]
pub(super) fn drain_phase_drain_local_backup(
    binding: &mut BindingWorker,
    ctx: &DrainCtx<'_>,
    shared_recycles: &mut Vec<(u32, u64)>,
    did_work: &mut bool,
) -> BackupOutcome {
    if let Some(early) = backup_drain_prepared(binding, ctx, shared_recycles, did_work) {
        return early;
    }
    backup_drain_local(binding, ctx, shared_recycles, did_work)
}

/// Invariants:
/// - #760 fast-exit when no CoS is configured.
/// - `drop_cos_bound_prepared_leftovers` drops items that
///   reached this backup path instead of being shaped.
/// - `transmit_prepared_batch` loop with `TxError::Retry` →
///   return `true` unconditionally (encoded as
///   `Some(BackupOutcome::Return(true))`).
#[inline]
fn backup_drain_prepared(
    binding: &mut BindingWorker,
    ctx: &DrainCtx<'_>,
    shared_recycles: &mut Vec<(u32, u64)>,
    did_work: &mut bool,
) -> Option<BackupOutcome> {
    if !ctx.forwarding.cos.interfaces.is_empty() {
        drop_cos_bound_prepared_leftovers(binding, ctx.forwarding, shared_recycles);
    }
    while !binding.tx_pipeline.pending_tx_prepared.is_empty() {
        match transmit_prepared_batch(binding, ctx.now_ns, shared_recycles) {
            Ok((packets, bytes)) => {
                if packets == 0 {
                    break;
                }
                *did_work = true;
                binding
                    .live
                    .tx_packets
                    .fetch_add(packets, Ordering::Relaxed);
                binding.live.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
                // #760 instrumentation: these bytes went out via
                // the post-CoS backup path in drain_pending_tx —
                // they did NOT pass through any queue's token gate.
                // Non-zero here is the direct fingerprint of the
                // cap bypass we're hunting.
                binding
                    .live
                    .owner_profile_owner
                    .post_drain_backup_bytes
                    .fetch_add(bytes, Ordering::Relaxed);
            }
            Err(TxError::Retry(reason)) => {
                // #4971: expected TX backpressure — record the reason
                // lock-free instead of taking the `last_error` mutex.
                binding.live.set_tx_retry_status(reason);
                return Some(BackupOutcome::Return(true));
            }
            Err(TxError::Drop(reason)) => {
                // #15786: an all-invalid prepared batch reaches here
                // with every frame already recycled + counted per
                // frame in `record_prepared_drop`; counting again
                // would double-count. Only the operator message is
                // still latched.
                // #4971: exceptional drop path (rare) may still render
                // the diagnostic message via the mutex-backed set_error.
                binding.live.set_error(reason.message());
            }
        }
    }
    None
}

/// Invariants:
/// - empty-after-prepared short-circuit returns the OR-fold.
/// - `take_pending_tx_requests` + empty-after-take short-circuit
///   likewise returns the OR-fold (the deque allocation is handed
///   back first, #7204).
/// - #760 `drop_cos_bound_local_leftovers` when CoS configured.
/// - `transmit_batch` retry loop with `TxError::Retry` →
///   break + `restore_pending_tx_requests` + fall through to
///   phase 6 (Continue). This is distinct from the prepared-side
///   Retry (which returns `true` unconditionally) — local-side
///   Retry restores and continues to the finish phase.
#[inline]
fn backup_drain_local(
    binding: &mut BindingWorker,
    ctx: &DrainCtx<'_>,
    shared_recycles: &mut Vec<(u32, u64)>,
    did_work: &mut bool,
) -> BackupOutcome {
    if binding.tx_pipeline.pending_tx_local.is_empty() && binding.live.pending_tx_empty() {
        return BackupOutcome::Return(*did_work || binding_has_pending_tx_work(binding));
    }
    let mut pending = take_pending_tx_requests(binding);
    if pending.is_empty() {
        // #7204 (A1-b6-F4): give the allocation back before returning.
        // `take_pending_tx_requests` mem::takes `pending_tx_local`, so bailing
        // out here used to leave the shared deque at capacity 0 and make the
        // producer regrow it — the idle-binding path, which is the one this
        // early return exists to make cheap.
        binding.tx_pipeline.pending_tx_local = pending;
        return BackupOutcome::Return(*did_work || binding_has_pending_tx_work(binding));
    }
    // #760: drop any CoS-bound items. Fast-exit if no CoS is
    // configured at all — saves the O(n) scan + reallocation on
    // the non-CoS hot path. This guard is INDEPENDENT of the
    // prepared-side guard above; both MUST stay in place.
    if !ctx.forwarding.cos.interfaces.is_empty() {
        drop_cos_bound_local_leftovers(
            binding,
            ctx.forwarding,
            ctx.now_ns,
            &mut pending,
            shared_recycles,
        );
    }
    // #7204 (A1-b6-F4): recycle the worker-owned retry deque instead of
    // allocating one per batch. Parked empty in `backup_retry_scratch` between
    // batches, so its capacity survives.
    let mut retry = core::mem::take(&mut binding.tx_pipeline.backup_retry_scratch);
    while let Some(req) = pending.pop_front() {
        retry.push_back(req);
        if retry.len() >= TX_BATCH_SIZE
            || binding.tx_pipeline.free_tx_frames.is_empty()
            || pending.is_empty()
        {
            match transmit_batch(binding, &mut retry, ctx.now_ns, shared_recycles) {
                Ok((packets, bytes)) => {
                    if packets > 0 {
                        *did_work = true;
                        binding
                            .live
                            .tx_packets
                            .fetch_add(packets, Ordering::Relaxed);
                        binding.live.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
                        // #760 instrumentation: bytes that left via
                        // the fallback transmit_batch WITHOUT going
                        // through any CoS queue's token gate. See
                        // the post_drain_backup_bytes field comment
                        // for why this is the #760 smoking gun.
                        binding
                            .live
                            .owner_profile_owner
                            .post_drain_backup_bytes
                            .fetch_add(bytes, Ordering::Relaxed);
                    }
                }
                Err(TxError::Retry(reason)) => {
                    // #4971: expected TX backpressure — lock-free status,
                    // no `last_error` mutex on the send hot path.
                    binding.live.set_tx_retry_status(reason);
                    retry.append(&mut pending);
                    break;
                }
                Err(TxError::Drop(reason)) => {
                    binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
                    binding
                        .live
                        .tx_submit_error_drops
                        .fetch_add(1, Ordering::Relaxed);
                    // #4971: exceptional drop path may still set_error.
                    binding.live.set_error(reason.message());
                }
            }
        }
    }
    // #7204 (A1-b6-F4): BOTH deques go back, on BOTH paths. The old tail
    // restored only when `retry` was non-empty, so the full-success path — the
    // common one — dropped the fresh retry deque AND the `pending_tx_local`
    // allocation this drain had taken, and the next batch re-allocated two
    // deques on the warmed TX path.
    //
    // `restore_pending_tx_requests` prepends its argument to `pending_tx_local`,
    // so it must be given the deque that still HOLDS items; whichever is empty
    // becomes next batch's scratch. Handing the wrong one over would reorder
    // untransmitted requests behind newly-arrived ones.
    let to_restore = binding.tx_pipeline.park_drained_deques(pending, retry);
    restore_pending_tx_requests(binding, to_restore);
    BackupOutcome::Continue
}
