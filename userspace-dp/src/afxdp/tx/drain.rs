// Per-tick drain dispatch + queue-bound / pending-queue helpers.
// Single-writer (owner worker); atomic ops use `Ordering::Relaxed`.

use super::*;

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
            binding.live.set_error(format!(
                "pending TX local overflow on slot {}",
                binding.slot
            ));
        }
    }
}

pub(in crate::afxdp) fn bound_pending_tx_prepared(binding: &mut BindingWorker) {
    let limit = binding.tx_pipeline.max_pending_tx;
    while binding.tx_pipeline.pending_tx_prepared.len() > limit {
        if let Some(req) = binding.tx_pipeline.pending_tx_prepared.pop_front() {
            // #804: bound-pending FIFO overflow (prepared side). Same
            // semantic bucket as `bound_pending_tx_local` — internal
            // prepared/local distinction is irrelevant to operators.
            binding.telemetry.dbg_bound_pending_overflow += 1;
            recycle_prepared_immediately(binding, &req);
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            // #710: same drop category — prepared vs local FIFO is an
            // internal distinction irrelevant to the operator.
            binding
                .live
                .pending_tx_local_overflow_drops
                .fetch_add(1, Ordering::Relaxed);
            binding.live.set_error(format!(
                "pending TX prepared overflow on slot {}",
                binding.slot
            ));
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
    _cos_owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
    _cos_owner_live_by_queue: &BTreeMap<(i32, u8), Arc<BindingLiveState>>,
) -> bool {
    if !binding_has_pending_tx_work(binding) {
        return false;
    }
    let mut did_work = reap_tx_completions(binding, shared_recycles) > 0;
    // In copy mode, the kernel needs sendto() to process TX ring entries.
    // If outstanding entries remain after reaping (kernel didn't finish in
    // the previous kick), re-kick now so they don't stall forever.
    if binding.tx_pipeline.outstanding_tx > 0
        && binding.tx_pipeline.pending_tx_prepared.is_empty()
        && binding.tx_pipeline.pending_tx_local.is_empty()
    {
        maybe_wake_tx(binding, false, now_ns);
    }
    // First ingest pass — same structure as pre-#760. Moves
    // pending_tx_local + inbox items into CoS queues where
    // possible. Items that can't be CoS-enqueued (no CoS config
    // for the egress, or cos_queue_id=None) stay in
    // pending_tx_local and flow through the backup paths below —
    // that's the expected non-CoS fast path and MUST stay fast.
    ingest_cos_pending_tx(
        binding,
        forwarding,
        now_ns,
        worker_id,
        worker_commands_by_id,
    );
    // Original #751 drain loop: service shaped queues until noop.
    // Each shaped drain attributes latency + invocations to the
    // specific queue via drain_shaped_tx's returned queue ref.
    loop {
        let start_ns = monotonic_nanos();
        let serviced = drain_shaped_tx(binding, now_ns, shared_recycles);
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
            did_work = true;
        } else {
            binding
                .live
                .owner_profile_owner
                .drain_noop_invocations
                .fetch_add(1, Ordering::Relaxed);
            break;
        }
    }
    // #760: bounded re-ingest → drain_shaped_tx loop, but ONLY
    // while the MPSC inbox has late peer arrivals AND CoS is
    // configured on some egress. For non-CoS traffic
    // (forwarding.cos.interfaces empty, or pending_tx_local
    // items all have cos_queue_id=None), the first ingest is
    // sufficient and re-ingesting does nothing useful — items
    // in pending_tx_local that Err'd out of the first pass will
    // Err the same way on every subsequent pass. The quiesce
    // guard below is inbox-only because that is the only place
    // peer workers can push new work after the first ingest.
    //
    // Perf note: without the inbox-only guard, a 25 Gbps non-CoS
    // flow burns all 4 budget iterations per drain_pending_tx
    // call because pending_tx_local never empties — observed as
    // a severe throughput regression (25 Gbps → 3 Gbps). The
    // inbox-only guard keeps the non-CoS fast path at exactly
    // the pre-#760 cost.
    if !forwarding.cos.interfaces.is_empty() {
        const REINGEST_BUDGET: usize = 4;
        for _ in 0..REINGEST_BUDGET {
            if binding.live.pending_tx_empty() {
                break;
            }
            ingest_cos_pending_tx_with_provenance(
                binding,
                forwarding,
                now_ns,
                worker_id,
                worker_commands_by_id,
                false,
            );
            let mut serviced_in_inner = false;
            loop {
                let start_ns = monotonic_nanos();
                let serviced = drain_shaped_tx(binding, now_ns, shared_recycles);
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
                    did_work = true;
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
    // #760: drop CoS-bound items that reached this backup path
    // instead of transmitting them unshaped. Fast-exit when no
    // CoS is configured (no possible cos_queue_id.is_some() on
    // any item) — keeps the non-CoS hot path allocation-free.
    if !forwarding.cos.interfaces.is_empty() {
        drop_cos_bound_prepared_leftovers(binding);
    }
    while !binding.tx_pipeline.pending_tx_prepared.is_empty() {
        match transmit_prepared_batch(binding, now_ns) {
            Ok((packets, bytes)) => {
                if packets == 0 {
                    break;
                }
                did_work = true;
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
            Err(TxError::Retry(err)) => {
                binding.live.set_error(err);
                return true;
            }
            Err(TxError::Drop(err)) => {
                binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
                // #710: frame-level submit error (capacity / slice /
                // other `TxError::Drop`). Subset of tx_errors.
                binding
                    .live
                    .tx_submit_error_drops
                    .fetch_add(1, Ordering::Relaxed);
                binding.live.set_error(err);
            }
        }
    }
    if binding.tx_pipeline.pending_tx_local.is_empty() && binding.live.pending_tx_empty() {
        update_binding_debug_state(binding);
        return did_work || binding_has_pending_tx_work(binding);
    }
    let mut pending = take_pending_tx_requests(binding);
    if pending.is_empty() {
        return did_work || binding_has_pending_tx_work(binding);
    }
    // #760: drop any CoS-bound items. Fast-exit if no CoS is
    // configured at all — saves the O(n) scan + reallocation on
    // the non-CoS hot path.
    if !forwarding.cos.interfaces.is_empty() {
        drop_cos_bound_local_leftovers(binding, forwarding, now_ns, &mut pending);
    }
    let mut retry = VecDeque::new();
    while let Some(req) = pending.pop_front() {
        retry.push_back(req);
        if retry.len() >= TX_BATCH_SIZE
            || binding.tx_pipeline.free_tx_frames.is_empty()
            || pending.is_empty()
        {
            match transmit_batch(binding, &mut retry, now_ns, shared_recycles) {
                Ok((packets, bytes)) => {
                    if packets > 0 {
                        did_work = true;
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
                Err(TxError::Retry(err)) => {
                    binding.live.set_error(err);
                    retry.append(&mut pending);
                    break;
                }
                Err(TxError::Drop(err)) => {
                    binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
                    binding.live.set_error(err);
                }
            }
        }
    }
    if !retry.is_empty() {
        restore_pending_tx_requests(binding, retry);
    }
    update_binding_debug_state(binding);
    did_work || binding_has_pending_tx_work(binding)
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
fn drop_cos_bound_prepared_leftovers(binding: &mut BindingWorker) {
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
        if req.cos_queue_id.is_some() {
            dropped = dropped.saturating_add(1);
            dropped_bytes = dropped_bytes.saturating_add(req.len as u64);
            recycle_prepared_immediately(binding, &req);
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
fn partition_cos_bound_local_with_rescue<F>(
    pending: &mut VecDeque<TxRequest>,
    mut try_rescue: F,
) -> (u64, u64)
where
    F: FnMut(TxRequest) -> Result<(), TxRequest>,
{
    let mut dropped = 0u64;
    let mut dropped_bytes = 0u64;
    let original_len = pending.len();
    for _ in 0..original_len {
        let Some(req) = pending.pop_front() else {
            break;
        };
        if req.cos_queue_id.is_some() {
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

fn drop_cos_bound_local_leftovers(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    now_ns: u64,
    pending: &mut VecDeque<TxRequest>,
) {
    // Delegate the scan to the pure helper so the mixed-head
    // invariant (Codex review on #784) is unit-testable without
    // constructing a full BindingWorker.
    let (dropped, dropped_bytes) = partition_cos_bound_local_with_rescue(pending, |req| {
        match enqueue_local_into_cos(binding, forwarding, req, now_ns) {
            Ok(()) => Ok(()),
            Err(req) => Err(req),
        }
    });
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

fn binding_has_pending_tx_work(binding: &BindingWorker) -> bool {
    binding.tx_pipeline.outstanding_tx > 0
        || !binding.tx_pipeline.pending_tx_prepared.is_empty()
        || !binding.tx_pipeline.pending_tx_local.is_empty()
        || !binding.live.pending_tx_empty()
        || binding.cos.cos_nonempty_interfaces > 0
}

pub(in crate::afxdp) fn drain_pending_tx_local_owner(
    binding: &mut BindingWorker,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
    forwarding: &ForwardingState,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    cos_owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
    cos_owner_live_by_queue: &BTreeMap<(i32, u8), Arc<BindingLiveState>>,
) -> bool {
    drain_pending_tx(
        binding,
        now_ns,
        shared_recycles,
        forwarding,
        worker_id,
        worker_commands_by_id,
        cos_owner_worker_by_queue,
        cos_owner_live_by_queue,
    )
}

fn ingest_cos_pending_tx(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    now_ns: u64,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
) {
    ingest_cos_pending_tx_with_provenance(
        binding,
        forwarding,
        now_ns,
        worker_id,
        worker_commands_by_id,
        true,
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
fn ingest_cos_pending_tx_with_provenance(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    now_ns: u64,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    count_pps: bool,
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
            ) {
                Ok(()) => return Ok(()),
                Err(req) => req,
            };
            let req = match redirect_prepared_cos_request_to_owner_binding(binding, req) {
                Ok(()) => return Ok(()),
                Err(req) => req,
            };
            match enqueue_prepared_into_cos(binding, forwarding, req, now_ns) {
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
    binding.live.take_pending_tx_into(&mut pending);
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
                    if let Ok(mut pending) = commands.lock() {
                        pending.push_back(WorkerCommand::EnqueueShapedLocal(req));
                        return Ok(());
                    } else {
                        // Pointer-equal poisoned mutex is
                        // unrecoverable; fall through to Step 2/3
                        // for best-effort rather than dropping.
                        // process_pending_queue_in_place will
                        // either route via Step 2 or retain in
                        // pending_tx_local for the next cycle.
                        req
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
        match enqueue_local_into_cos(binding, forwarding, req, now_ns) {
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

fn take_pending_tx_requests(binding: &mut BindingWorker) -> VecDeque<TxRequest> {
    // Reuse the worker-owned `pending_tx_local` buffer as the drain
    // target so the owner-worker hot path stays allocation-free. `pop`
    // from the lock-free inbox appends into the same buffer without a
    // queue-to-queue copy.
    let mut out = core::mem::take(&mut binding.tx_pipeline.pending_tx_local);
    binding.live.take_pending_tx_into(&mut out);
    out
}

fn restore_pending_tx_requests(binding: &mut BindingWorker, mut retry: VecDeque<TxRequest>) {
    retry.append(&mut binding.tx_pipeline.pending_tx_local);
    binding.tx_pipeline.pending_tx_local = retry;
    bound_pending_tx_local(binding);
}

#[cfg(test)]
#[path = "drain_tests.rs"]
mod tests;
