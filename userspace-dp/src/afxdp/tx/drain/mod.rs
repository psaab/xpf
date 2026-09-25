// Per-tick drain dispatch + queue-bound / pending-queue helpers.
// Single-writer (owner worker); atomic ops use `Ordering::Relaxed`.

use super::*;

mod phase_backup;
mod phase_shaped;
mod phase_trivial;

use phase_backup::{BackupOutcome, drain_phase_drain_local_backup};
use phase_shaped::drain_phase_drain_cos;
use phase_trivial::{
    drain_phase_ingest_cos, drain_phase_maybe_rekick, drain_phase_reap_completions,
    drain_phase_submit_and_wake,
};

/// Per-tick drain context — references-only, stack-built once
/// per drain call; passed to phase helpers by `&DrainCtx<'_>`.
/// Hot-path allocation contract: zero new allocations.
pub(in crate::afxdp) struct DrainCtx<'a> {
    pub forwarding: &'a ForwardingState,
    pub worker_id: u32,
    pub worker_commands_by_id: &'a BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    pub now_ns: u64,
}

pub(in crate::afxdp) fn pending_tx_capacity(ring_entries: u32) -> usize {
    (ring_entries as usize)
        .saturating_mul(PENDING_TX_LIMIT_MULTIPLIER)
        .max(TX_BATCH_SIZE.saturating_mul(2))
}

pub(in crate::afxdp) fn bound_pending_tx_local(binding: &mut BindingWorker) {
    while binding.tx_pipeline.pending_tx_local.len() > binding.tx_pipeline.max_pending_tx {
        if binding.tx_pipeline.pending_tx_local.pop_front().is_some() {
            // #804: bound-pending FIFO overflow — distinct from the CoS
            // queue admission overflow counter. Keep this attribution
            // precise so operators can tell which path is dropping.
            binding.telemetry.dbg_bound_pending_overflow += 1;
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            // #710: dedicated drop-reason counter. Subset of tx_errors.
            binding
                .live
                .pending_tx_local_overflow_drops
                .fetch_add(1, Ordering::Relaxed);
            // #hb166 T-6(g): no per-drop `set_error(format!())` here — this
            // is a `while overflow` loop, so the String alloc fired once per
            // evicted packet under backpressure (hot-path-allocation-rule
            // violation, CLAUDE.md). The dedicated
            // `pending_tx_local_overflow_drops` counter above (a subset of
            // `tx_errors`) already attributes the drop without allocating.
        }
    }
}

pub(in crate::afxdp) fn bound_pending_tx_prepared(
    binding: &mut BindingWorker,
    mut shared_recycles: Option<&mut Vec<(u32, u64)>>,
) {
    let limit = binding.tx_pipeline.max_pending_tx;
    while binding.tx_pipeline.pending_tx_prepared.len() > limit {
        if let Some(req) = binding.tx_pipeline.pending_tx_prepared.pop_front() {
            // #804: bound-pending FIFO overflow (prepared side). Same
            // semantic bucket as `bound_pending_tx_local` — internal
            // prepared/local distinction is irrelevant to operators.
            binding.telemetry.dbg_bound_pending_overflow += 1;
            recycle_prepared_immediately_with_shared(
                binding,
                &req,
                shared_recycles.as_deref_mut(),
            );
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            // #710: same drop category — prepared vs local FIFO is an
            // internal distinction irrelevant to the operator.
            binding
                .live
                .pending_tx_local_overflow_drops
                .fetch_add(1, Ordering::Relaxed);
            // #hb166 T-6(g): no per-drop `set_error(format!())` — same
            // hot-path String alloc removal as the local overflow loop above.
        }
    }
}

pub(in crate::afxdp) fn drain_pending_tx(
    binding: &mut BindingWorker,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
    forwarding: &ForwardingState,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
) -> bool {
    if !binding_has_pending_tx_work(binding) {
        return false;
    }
    let ctx = DrainCtx {
        forwarding,
        worker_id,
        worker_commands_by_id,
        now_ns,
    };

    let mut did_work = drain_phase_reap_completions(binding, shared_recycles);
    drain_phase_maybe_rekick(binding, &ctx);
    drain_phase_ingest_cos(binding, &ctx, shared_recycles);
    drain_phase_drain_cos(binding, &ctx, shared_recycles, &mut did_work);
    match drain_phase_drain_local_backup(binding, &ctx, shared_recycles, &mut did_work) {
        BackupOutcome::Continue => {}
        BackupOutcome::EarlyReturnRetry => return true,
        BackupOutcome::EarlyReturnAfterDebugUpdate => {
            update_binding_debug_state(binding);
            return did_work || binding_has_pending_tx_work(binding);
        }
        BackupOutcome::EarlyReturnNoDebugUpdate => {
            return did_work || binding_has_pending_tx_work(binding);
        }
    }
    drain_phase_submit_and_wake(binding, did_work)
}

/// #760: drop any prepared TX requests whose `cos_queue_id` is
/// `Some(_)` — these items should have been admitted to a CoS
/// queue via `ingest_cos_pending_tx`, and transmitting them
/// through the post-CoS backup path bypasses the shaper. The
/// UMEM frame slot each request holds is recycled immediately so
/// the free-frame allocator stays in balance. A non-zero drop
/// count here means the prepared-request re-ingest cascade left
/// CoS-bound residue: `ingest_cos_pending_tx_with_provenance`
/// first attempts `redirect_prepared_cos_request_to_owner`, then
/// `redirect_prepared_cos_request_to_owner_binding`, then
/// `enqueue_prepared_into_cos`. Any item dropped here therefore
/// indicates that all applicable redirect/enqueue attempts
/// failed (or otherwise left the request unconsumed), so this
/// counter should be interpreted as a leftover-after-reingest
/// defense rather than only a narrow redirect-to-owner +
/// local-enqueue failure.
pub(super) fn drop_cos_bound_prepared_leftovers(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    if binding.tx_pipeline.pending_tx_prepared.is_empty() {
        return;
    }
    // #784 Codex review: the earlier head-peek fast-exit was a
    // correctness bug. `take_pending_tx_into` / inbox drain can
    // interleave non-CoS items (head) with CoS-bound items
    // (tail). If the head is non-CoS and we return early, later
    // CoS-bound items escape to the unshaped transmit_batch
    // path, bypassing the CoS cap. Scan the full deque always.
    //
    // Scan in-place. pop_front until empty; CoS-bound items are
    // dropped (+ recycled), non-CoS items are rotated back to
    // the tail. O(n) but only runs when a leftover exists AFTER
    // the bounded ingest-drain loop exited with residue, not
    // per-frame.
    let mut dropped = 0u64;
    let mut dropped_bytes = 0u64;
    let original_len = binding.tx_pipeline.pending_tx_prepared.len();
    for _ in 0..original_len {
        let Some(req) = binding.tx_pipeline.pending_tx_prepared.pop_front() else {
            break;
        };
        if tx_request_targets_cos_interface(forwarding, req.egress_ifindex, req.cos_queue_id) {
            dropped = dropped.saturating_add(1);
            dropped_bytes = dropped_bytes.saturating_add(req.len as u64);
            recycle_prepared_immediately_with_shared(binding, &req, Some(shared_recycles));
        } else {
            binding.tx_pipeline.pending_tx_prepared.push_back(req);
        }
    }
    if dropped > 0 {
        binding.live.tx_errors.fetch_add(dropped, Ordering::Relaxed);
        binding
            .live
            .owner_profile_owner
            .post_drain_backup_cos_drops
            .fetch_add(dropped, Ordering::Relaxed);
        binding
            .live
            .owner_profile_owner
            .post_drain_backup_cos_drop_bytes
            .fetch_add(dropped_bytes, Ordering::Relaxed);
    }
}

/// #760: symmetric to `drop_cos_bound_prepared_leftovers` but for
/// local (non-prepared) TxRequests. `TxRequest::bytes` is a
/// Vec<u8> owned by the request — dropping the request frees the
/// buffer, so no explicit recycle is needed here.
/// #784 rewrite: give CoS-bound items one final chance to route
/// into their queue before dropping. The previous revision
/// dropped unconditionally, which was correct for items that had
/// failed ingest's full three-step cascade — BUT items pulled
/// from the MPSC redirect inbox at `take_pending_tx_requests`
/// (after the bounded ingest-drain loop exited) had never been
/// attempted for ingest at all. On iperf3 -P 12 against a 1 Gbps
/// cap with owner-local-exact queue 4, peer workers continuously
/// push packets to the owner binding's inbox. The budget-loop
/// exits while packets are still arriving; `take_pending_tx_requests`
/// then pulls them; the drop filter killed them wholesale. That
/// produced the reported bimodal fairness: flows whose packets
/// happened to land on the owner worker's own RX got through;
/// flows that crossed workers got dropped here.
///
/// The fix: attempt `enqueue_local_into_cos` here. If it succeeds,
/// the item joins its queue and traverses the normal shaped path
/// on the next drain. If it fails (the genuine cross-worker
/// routing failure case this function was originally designed for),
/// drop as before so the #760 CoS cap bypass stays closed.
/// #784 pure-function scan: for each item in `pending`, classify
/// by `cos_queue_id`. Non-CoS items are preserved (rotated back
/// to tail). CoS-bound items get one last rescue attempt via
/// `try_rescue`; if that returns Err, the item is dropped (not
/// re-enqueued) and counted. Returns `(dropped_count, dropped_bytes)`.
///
/// **CRITICAL INVARIANT** (pinned by
/// `partition_cos_bound_local_scans_mixed_head_deque` below): the
/// scan walks the ENTIRE deque, not just the head. An earlier
/// head-peek fast-exit was a correctness bug: items pulled from
/// the redirect inbox via `take_pending_tx_requests` can
/// interleave non-CoS and CoS-bound; exiting early on a non-CoS
/// head lets later CoS-bound items escape to the unshaped
/// `transmit_batch` backup path, bypassing the CoS cap.
/// Adversarial reviewers MUST reject any PR that re-introduces
/// an early-exit on head inspection.
fn tx_request_targets_cos_interface(
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    cos_queue_id: Option<u8>,
) -> bool {
    cos_queue_id.is_some() || forwarding.cos.interfaces.contains_key(&egress_ifindex)
}

fn partition_cos_bound_local_with_rescue<P, F>(
    pending: &mut VecDeque<TxRequest>,
    mut is_cos_bound: P,
    mut try_rescue: F,
) -> (u64, u64)
where
    P: FnMut(&TxRequest) -> bool,
    F: FnMut(TxRequest) -> Result<(), TxRequest>,
{
    let mut dropped = 0u64;
    let mut dropped_bytes = 0u64;
    let original_len = pending.len();
    for _ in 0..original_len {
        let Some(req) = pending.pop_front() else {
            break;
        };
        if is_cos_bound(&req) {
            let bytes_len = req.bytes.len() as u64;
            match try_rescue(req) {
                Ok(()) => { /* rescued — do not drop */ }
                Err(_req) => {
                    dropped = dropped.saturating_add(1);
                    dropped_bytes = dropped_bytes.saturating_add(bytes_len);
                }
            }
        } else {
            pending.push_back(req);
        }
    }
    (dropped, dropped_bytes)
}

pub(super) fn drop_cos_bound_local_leftovers(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    now_ns: u64,
    pending: &mut VecDeque<TxRequest>,
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    // Delegate the scan to the pure helper so the mixed-head
    // invariant (Codex review on #784) is unit-testable without
    // constructing a full BindingWorker.
    let (dropped, dropped_bytes) = partition_cos_bound_local_with_rescue(
        pending,
        |req| tx_request_targets_cos_interface(forwarding, req.egress_ifindex, req.cos_queue_id),
        |req| match enqueue_local_into_cos(
            binding,
            forwarding,
            req,
            now_ns,
            Some(&mut *shared_recycles),
        ) {
            Ok(()) => Ok(()),
            Err(req) => Err(req),
        },
    );
    if dropped > 0 {
        binding.live.tx_errors.fetch_add(dropped, Ordering::Relaxed);
        binding
            .live
            .owner_profile_owner
            .post_drain_backup_cos_drops
            .fetch_add(dropped, Ordering::Relaxed);
        binding
            .live
            .owner_profile_owner
            .post_drain_backup_cos_drop_bytes
            .fetch_add(dropped_bytes, Ordering::Relaxed);
    }
}

pub(super) fn binding_has_pending_tx_work(binding: &BindingWorker) -> bool {
    binding.tx_pipeline.outstanding_tx > 0
        || !binding.tx_pipeline.pending_tx_prepared.is_empty()
        || !binding.tx_pipeline.pending_tx_local.is_empty()
        || !binding.live.pending_tx_empty()
        || binding.cos.cos_nonempty_interfaces > 0
}

#[inline]
pub(super) fn should_enter_shaped_drain(binding: &BindingWorker) -> bool {
    has_queued_cos_work(
        binding.cos.cos_nonempty_interfaces,
        binding.cos.cos_interface_order.len(),
    )
}

#[inline]
fn has_queued_cos_work(cos_nonempty_interfaces: usize, cos_interface_order_len: usize) -> bool {
    cos_nonempty_interfaces > 0 && cos_interface_order_len > 0
}

pub(in crate::afxdp) fn drain_pending_tx_local_owner(
    binding: &mut BindingWorker,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
    forwarding: &ForwardingState,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
) -> bool {
    drain_pending_tx(
        binding,
        now_ns,
        shared_recycles,
        forwarding,
        worker_id,
        worker_commands_by_id,
    )
}

pub(super) fn ingest_cos_pending_tx(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    now_ns: u64,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    ingest_cos_pending_tx_with_provenance(
        binding,
        forwarding,
        now_ns,
        worker_id,
        worker_commands_by_id,
        true,
        shared_recycles,
    );
}

/// #760: same as `ingest_cos_pending_tx` but skips the
/// `owner_pps` / `peer_pps` attribution. `drain_pending_tx` calls
/// ingest once at the top (attribution ON) and then again after
/// the shaped-drain loop exits (attribution OFF). The second pass
/// drains items that peers pushed to the MPSC inbox DURING the
/// shaped drain; counting those as `owner_pps` would corrupt the
/// provenance telemetry because items left over in
/// `pending_tx_local` from the first pass get indistinguishably
/// mixed with fresh inbox arrivals on the second pass. Per Codex
/// adversarial review (PR #773): "The second pass reclassifies
/// peer requests as owner-local; inflates owner_pps, deflates
/// peer_pps — exactly the wrong signal for diagnosing owner
/// hotspots."
pub(super) fn ingest_cos_pending_tx_with_provenance(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    now_ns: u64,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    count_pps: bool,
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    if forwarding.cos.interfaces.is_empty() {
        return;
    }

    if !binding.tx_pipeline.pending_tx_prepared.is_empty() {
        let mut pending = core::mem::take(&mut binding.tx_pipeline.pending_tx_prepared);
        process_pending_queue_in_place(&mut pending, |req| {
            let req = match redirect_prepared_cos_request_to_owner(
                binding,
                req,
                worker_id,
                worker_commands_by_id,
                Some(&mut *shared_recycles),
            ) {
                Ok(()) => return Ok(()),
                Err(req) => req,
            };
            let req = match redirect_prepared_cos_request_to_owner_binding(
                binding,
                req,
                Some(&mut *shared_recycles),
            ) {
                Ok(()) => return Ok(()),
                Err(req) => req,
            };
            match enqueue_prepared_into_cos(
                binding,
                forwarding,
                req,
                now_ns,
                Some(&mut *shared_recycles),
            ) {
                Ok(()) => Ok(()),
                Err(req) => Err(req),
            }
        });
        binding.tx_pipeline.pending_tx_prepared = pending;
    }

    let mut pending = core::mem::take(&mut binding.tx_pipeline.pending_tx_local);
    // #709: the split between owner-local and peer-redirected packets.
    // `pending` starts with this worker's own locally-produced requests
    // (this worker drove RX on this binding). `take_pending_tx_into`
    // then APPENDS the MPSC inbox — every item appended was pushed by
    // a peer worker that redirected a TxRequest at this binding as
    // owner. Count the split here, before
    // `process_pending_queue_in_place` mixes them with outbound
    // re-redirects.
    //
    // For non-owner bindings the MPSC inbox is empty (peers never push
    // to a binding they do not own), so `peer` naturally stays at 0.
    //
    // #760: `count_pps` is false on re-ingest passes — items already
    // in `pending_tx_local` at that point were left over from the
    // first pass (Err returns), and re-classifying them as owner-
    // local would double-count or mis-attribute them.
    let owner_local_count = pending.len() as u64;
    // SAFETY: this drain runs on the binding's owner worker, the sole inbox
    // consumer; redirects only enqueue from peers, and this call cannot overlap
    // the other owner drain in the same worker loop.
    unsafe { binding.live.take_pending_tx_into(&mut pending) };
    let peer_count = (pending.len() as u64).saturating_sub(owner_local_count);
    if count_pps && owner_local_count > 0 {
        binding
            .live
            .owner_profile_owner
            .owner_pps
            .fetch_add(owner_local_count, Ordering::Relaxed);
    }
    if count_pps && peer_count > 0 {
        binding
            .live
            .owner_profile_peer
            .peer_pps
            .fetch_add(peer_count, Ordering::Relaxed);
    }
    // #780 fast path: memoize the routing decision per
    // (egress_ifindex, cos_queue_id) across the batch. iperf-style
    // workloads push ~all items in a batch to the same queue, so
    // this hits >99%. Saves 2-3 FastMap lookups per item on the
    // hot path (profile: 1.96% CPU in this function at line rate).
    //
    // Semantic correctness: this mirrors the pre-#780 cascade of
    //   Step 1: redirect_local_cos_request_to_owner
    //   Step 2: redirect_local_cos_request_to_owner_binding
    //   Step 3: enqueue_local_into_cos (Err→item stays in pending)
    // exactly. Step 1 bails (Err) on:
    //   - queue not in iface, OR
    //   - shared_exact AND tx_owner_live is Some, OR
    //   - owner_worker_id == current_worker_id
    // Step 2 (only reached when Step 1 bailed) ignores the queue
    // and checks iface-level tx_owner_live; routes if set AND not
    // ptr_eq(tx_owner_live, &binding.live).
    //
    // Codex adversarial review (PR #782 round 1) flagged that
    // collapsing both steps lost the "queue_fast=None but Step 2
    // would still route via iface" path, and the "same owner
    // worker but not owner binding" path. This rewrite evaluates
    // Step 1 and Step 2 independently on the cached lookup and
    // picks whichever routes, falling through to EnqueueLocal
    // only when both bail — matching the prior cascade.
    // Codex adversarial review (PR #782 round 2) flagged that the
    // earlier rewrite lost the cascade's failure fallthrough: when
    // Step 1's enqueue returned Err, the OLD code walked to Step 2,
    // then Step 3. The previous PR revision returned Err after the
    // first step's failure. Restore exact fallthrough semantics by
    // caching BOTH Step 1 and Step 2 options on the decision, then
    // dispatching Step 1 → Step 2 → Step 3 with failure fallthrough
    // at each boundary.
    let mut cached_key: Option<(i32, Option<u8>)> = None;
    let mut cached_decision: Option<LocalRoutingDecision> = None;
    process_pending_queue_in_place(&mut pending, |req| {
        let key = (req.egress_ifindex, req.cos_queue_id);
        if cached_key != Some(key) {
            cached_key = Some(key);
            let iface_fast_opt = binding.cos.cos_fast_interfaces.get(&req.egress_ifindex);
            cached_decision = Some(resolve_local_routing_decision(
                iface_fast_opt,
                req.cos_queue_id,
                worker_id,
                &binding.live,
            ));
        }
        let decision = cached_decision.as_ref().expect("decision cached above");
        // Try Step 1 first (if present). `enqueue_tx_owned` does
        // not currently return Err in any observed path (see
        // umem.rs #710/#706 tests — drop-newest returns Ok), but
        // the Result signature MUST be honored for
        // cascade-equivalence.
        let req = match &decision.step1 {
            Some(Step1Action::Arc(arc)) => match arc.enqueue_tx_owned(req) {
                Ok(()) => return Ok(()),
                Err(req) => req,
            },
            Some(Step1Action::Command(owner_worker_id)) => {
                if let Some(commands) = worker_commands_by_id.get(owner_worker_id) {
                    // #1807: a poisoned mutex is RECOVERED (committed-
                    // prefix + clear_poison policy, worker_queue.rs).
                    let mut pending = crate::afxdp::worker_queue::lock_recover(commands);
                    match worker_queue::push_shaped_local_bounded(
                        &mut pending,
                        req,
                    ) {
                        Ok(()) => return Ok(()),
                        Err(req) => req,
                    }
                } else {
                    req
                }
            }
            None => req,
        };
        // Fallthrough to Step 2 (if present).
        let req = match &decision.step2 {
            Some(arc) => match arc.enqueue_tx_owned(req) {
                Ok(()) => return Ok(()),
                Err(req) => req,
            },
            None => req,
        };
        // Fallthrough to Step 3 (EnqueueLocal).
        match enqueue_local_into_cos(
            binding,
            forwarding,
            req,
            now_ns,
            Some(&mut *shared_recycles),
        ) {
            Ok(()) => Ok(()),
            Err(req) => Err(req),
        }
    });
    binding.tx_pipeline.pending_tx_local = pending;
    bound_pending_tx_local(binding);
}

pub(in crate::afxdp) const COS_GUARANTEE_VISIT_NS: u64 = 200_000;
pub(in crate::afxdp) const COS_GUARANTEE_QUANTUM_MIN_BYTES: u64 = 1500;
pub(in crate::afxdp) const COS_GUARANTEE_QUANTUM_MAX_BYTES: u64 = 512 * 1024;
pub(in crate::afxdp) const COS_SURPLUS_ROUND_QUANTUM_BYTES: u64 = 1500;

fn process_pending_queue_in_place<T, F>(pending: &mut VecDeque<T>, mut f: F)
where
    F: FnMut(T) -> Result<(), T>,
{
    let initial_len = pending.len();
    for _ in 0..initial_len {
        let Some(item) = pending.pop_front() else {
            break;
        };
        if let Err(item) = f(item) {
            pending.push_back(item);
        }
    }
}

pub(super) fn take_pending_tx_requests(binding: &mut BindingWorker) -> VecDeque<TxRequest> {
    // Reuse the worker-owned `pending_tx_local` buffer as the drain
    // target so the owner-worker hot path stays allocation-free. `pop`
    // from the lock-free inbox appends into the same buffer without a
    // queue-to-queue copy.
    let mut out = core::mem::take(&mut binding.tx_pipeline.pending_tx_local);
    // SAFETY: this binding worker is mutably borrowed by the owner drain, which
    // is the sole consumer of its redirect inbox.
    unsafe { binding.live.take_pending_tx_into(&mut out) };
    out
}

pub(super) fn restore_pending_tx_requests(binding: &mut BindingWorker, mut retry: VecDeque<TxRequest>) {
    retry.append(&mut binding.tx_pipeline.pending_tx_local);
    binding.tx_pipeline.pending_tx_local = retry;
    bound_pending_tx_local(binding);
}

#[cfg(test)]
mod tests;
