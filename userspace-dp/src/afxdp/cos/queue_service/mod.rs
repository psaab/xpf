// CoS dispatch / drain / submit subsystem. Hot-path call chain:
//
//   drain_shaped_tx
//    -> select_cos_*_batch (guarantee / nonexact / surplus)
//      -> service_exact_*_queue_direct(_flow_fair)
//        -> drain_exact_*_to_scratch
//          -> submit_cos_batch + cos_batch_tx_made_progress
//            -> settle_exact_*_submission*
//
// All per-byte / per-batch hot-path fns carry `#[inline]` to
// preserve cross-module inlining at the `pub(in crate::afxdp)`
// boundary. Larger drain/settle bodies skip `#[inline]` — LLVM's
// heuristic threshold covers them.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use crate::afxdp::frame::{apply_dscp_rewrite_to_frame, frame_has_tcp_rst};
use crate::afxdp::mirror::MIRROR_TX_FRAME_RESERVE;
use crate::afxdp::neighbor::monotonic_nanos;
use crate::afxdp::types::{
    COS_PRIORITY_LEVELS, CoSInterfaceRuntime, CoSOversubscriptionPolicy, CoSPendingTxItem,
    CoSQueueRuntime, ExactDemandQueueMask, ExactLocalScratchTxRequest,
    ExactPreparedScratchTxRequest, PreparedTxRecycle, PreparedTxRequest, SharedCoSExactBacklog,
    TxRequest, WorkerCoSQueueFastPath,
};
use crate::afxdp::umem::MmapArea;
use crate::afxdp::worker::BindingWorker;
use crate::afxdp::{FastMap, TX_BATCH_SIZE, tx_frame_capacity};
use crate::xsk_ffi::xdp::XdpDesc;

use super::{
    COS_MIN_BURST_BYTES, CoSQueueLeaseAcquireTelemetry, cos_item_len,
    cos_queue_clear_orphan_snapshot_after_drop, cos_queue_front, cos_queue_front_with_cap,
    cos_queue_is_empty, cos_queue_peek_min_bucket, cos_queue_pop_known_bucket,
    cos_queue_push_front, cos_queue_v_min_consume_suspension, cos_queue_v_min_continue,
    cos_refill_ns_until, maybe_top_up_cos_queue_lease, publish_committed_queue_vtime,
    refill_cos_tokens,
};
// #1229 v7 per-bucket TX accounting + threshold-gated EWMA.
use super::exact_demand::{exact_demand_rate_bytes_for_mask, serviceable_exact_demand_mask};
use super::fairness::account_flow_bucket_tx;
use super::flow_hash::cos_flow_bucket_index;

// #1035 P2: drain stage of the queue service pipeline split into
// a sibling submodule.
mod drain;
pub(in crate::afxdp) use drain::{
    drain_exact_local_fifo_items_to_scratch, drain_exact_local_items_to_scratch_flow_fair,
    drain_exact_prepared_fifo_items_to_scratch, drain_exact_prepared_items_to_scratch_flow_fair,
};

// #1035 P3: service stage of the queue service pipeline (the four
// service_exact_*_queue_direct fns) split into a sibling submodule.
mod service;
use service::{service_exact_local_queue_direct, service_exact_prepared_queue_direct};

// #1331: per-variant submit handlers split into flat sibling files,
// mirroring drain.rs / service.rs. submit_cos_batch below stays a
// thin match shim that dispatches to these handlers.
mod submit_local;
mod submit_prepared;
use submit_local::submit_local;
use submit_prepared::submit_prepared;

use super::tx_completion::{
    CoSServicePhase, ParkReason, apply_cos_prepared_result, apply_cos_send_result,
    apply_direct_exact_send_result, cos_root_can_service_after_prime, cos_tick_for_ns,
    count_park_reason, count_tx_ring_full_submit_stall, park_cos_queue, prime_cos_root_for_service,
    refresh_cos_interface_activity, restore_cos_local_items_inner,
    restore_cos_prepared_items_inner,
};
// Back-edges to crate::afxdp::tx are XSK-ring / worker-binding /
// prepared-frame primitives — primitives that own the kernel ring
// state and are hosted there for that reason.
use crate::afxdp::tx::{
    COS_GUARANTEE_QUANTUM_MAX_BYTES, COS_GUARANTEE_QUANTUM_MIN_BYTES, COS_GUARANTEE_VISIT_NS,
    COS_SURPLUS_ROUND_QUANTUM_BYTES, TxError, TxRetryReason, cos_queue_dscp_rewrite, maybe_wake_tx,
    reap_tx_completions, recycle_cancelled_prepared_offset_with_shared, remember_prepared_recycle,
    stamp_submits, transmit_batch, transmit_prepared_queue,
};

pub(in crate::afxdp) enum CoSBatch {
    Local {
        queue_idx: usize,
        phase: CoSServicePhase,
        batch_bytes: u64,
        items: VecDeque<TxRequest>,
    },
    Prepared {
        queue_idx: usize,
        phase: CoSServicePhase,
        batch_bytes: u64,
        items: VecDeque<PreparedTxRequest>,
    },
}

#[derive(Clone, Copy)]
enum ExactCoSQueueKind {
    Local,
    Prepared,
}

#[derive(Clone, Copy)]
pub(in crate::afxdp) struct ExactCoSQueueSelection {
    pub(in crate::afxdp) queue_idx: usize,
    pub(in crate::afxdp) secondary_budget: u64,
    kind: ExactCoSQueueKind,
    /// hb166 T-2: `Some` only for a Phase-1 HONORED waterfill selection,
    /// carrying the epoch honor that must be UNDONE if the service call
    /// makes zero TX progress. The waterfill selector debits the Phase-1
    /// budget and sets the honored-epoch bit at selection time; a
    /// zero-byte TX (ring full / no free frame / build Drop) must not
    /// burn the small class's 200 us epoch guarantee, so the service
    /// wrapper refunds the debit + clears the bit on `progress == false`.
    /// `None` for fast-path, Phase-2, and legacy-RR selections (which set
    /// no honor bit and debit no budget), so they refund nothing.
    phase1_honor: Option<Phase1HonorRefund>,
}

/// hb166 T-2: the Phase-1 waterfill honor to refund on a zero-byte-TX
/// service failure. Captured at selection so the service wrapper can undo
/// exactly what the selector committed, without re-deriving it.
#[derive(Clone, Copy)]
struct Phase1HonorRefund {
    /// Bytes debited from `waterfill_pass1_remaining_bytes` at selection
    /// (the queue's stable `phase1_cost`), to add back on no-progress.
    cost_bytes: u64,
    /// Ascending-vec ordinal `i` whose bit was set in
    /// `waterfill_honored_epoch_bits`. `>= 64` means the ordinal was out
    /// of the u64 bitset range and no bit was set (nothing to clear).
    bit_ordinal: u32,
}

pub(in crate::afxdp) enum ExactCoSScratchBuild {
    Ready,
    Drop { error: String, dropped_bytes: u64 },
    MirrorTxFrameReserve { dropped_bytes: u64 },
}

/// #751: one drain pass through the binding's CoS interfaces. Returns
/// the (root_ifindex, queue_idx, queue_id) that was actually serviced
/// so the caller can attribute the drain latency to the specific
/// queue's per-queue atomics without walking the queues vec a second
/// time.
///
/// `queue_idx` is the stable position within `root.queues` captured
/// at selection time. The drain path mutates queue state (tokens,
/// queued_bytes) but does not reorder or reshape `root.queues`
/// within a single drain pass, so using the idx for direct indexed
/// access is safe and avoids the O(#queues) linear scan by
/// `queue_id` that the first revision of this PR used (Copilot
/// review).
///
/// `queue_id` is retained as a stable 8-bit identifier for the
/// snapshot and telemetry paths which key on id, not idx.
pub(in crate::afxdp) struct DrainedQueueRef {
    pub(in crate::afxdp) root_ifindex: i32,
    pub(in crate::afxdp) queue_idx: usize,
    pub(in crate::afxdp) queue_id: u8,
}

#[inline]
fn record_cos_queue_lease_acquire(
    binding: &mut BindingWorker,
    telemetry: CoSQueueLeaseAcquireTelemetry,
) {
    binding.cos.cos_queue_lease_acquire_v8_calls = binding
        .cos
        .cos_queue_lease_acquire_v8_calls
        .wrapping_add(telemetry.v8_calls);
    binding.cos.cos_queue_lease_acquire_v8_granted_bytes = binding
        .cos
        .cos_queue_lease_acquire_v8_granted_bytes
        .wrapping_add(telemetry.v8_granted_bytes);
    // #1782 Step-1 (ii): flush the selector-attributed per-cause
    // under-grant counts into the worker-local accumulator published
    // at the ~1s runtime tick.
    binding
        .cos
        .cos_queue_lease_undergrants
        .add_assign(&telemetry.v8_undergrants);
}

#[inline]
pub(in crate::afxdp) fn drain_shaped_tx(
    binding: &mut BindingWorker,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Option<DrainedQueueRef> {
    if binding.cos.cos_nonempty_interfaces == 0 || binding.cos.cos_interface_order.is_empty() {
        return None;
    }
    let start = binding.cos.cos_interface_rr % binding.cos.cos_interface_order.len();
    for offset in 0..binding.cos.cos_interface_order.len() {
        let root_ifindex = binding.cos.cos_interface_order
            [(start + offset) % binding.cos.cos_interface_order.len()];
        let Some(root) = binding.cos.cos_interfaces.get(&root_ifindex) else {
            continue;
        };
        if root.nonempty_queues == 0 {
            continue;
        }
        if !cos_root_can_service_after_prime(root, now_ns) {
            continue;
        }
        if !prime_cos_root_for_service(binding, root_ifindex, now_ns) {
            continue;
        }
        let mut lease_telemetry = CoSQueueLeaseAcquireTelemetry::default();
        if let Some(serviced) = service_exact_guarantee_queue_direct_with_info(
            binding,
            root_ifindex,
            now_ns,
            shared_recycles,
            &mut lease_telemetry,
        ) {
            record_cos_queue_lease_acquire(binding, lease_telemetry);
            binding.cos.cos_interface_rr =
                (start + offset + 1) % binding.cos.cos_interface_order.len();
            return serviced;
        }
        record_cos_queue_lease_acquire(binding, lease_telemetry);
        let Some(batch) = build_nonexact_cos_batch(binding, root_ifindex, now_ns) else {
            continue;
        };
        // #751: capture both queue_idx (stable Vec position) and
        // queue_id (stable u8 identifier) BEFORE submit_cos_batch
        // takes ownership of the batch. Pre-Copilot-review this
        // resolved only queue_id and the outer loop did a linear
        // scan by id; now we carry the idx through for direct
        // indexed access.
        let located = cos_batch_queue_ref(binding, root_ifindex, &batch);
        binding.cos.cos_interface_rr = (start + offset + 1) % binding.cos.cos_interface_order.len();
        if submit_cos_batch(binding, root_ifindex, batch, now_ns, shared_recycles) {
            return located.map(|(queue_idx, queue_id)| DrainedQueueRef {
                root_ifindex,
                queue_idx,
                queue_id,
            });
        }
        return None;
    }
    None
}

#[inline]
fn cos_batch_queue_ref(
    binding: &BindingWorker,
    root_ifindex: i32,
    batch: &CoSBatch,
) -> Option<(usize, u8)> {
    let queue_idx = match batch {
        CoSBatch::Local { queue_idx, .. } | CoSBatch::Prepared { queue_idx, .. } => *queue_idx,
    };
    binding
        .cos
        .cos_interfaces
        .get(&root_ifindex)
        .and_then(|root| root.queues.get(queue_idx))
        .map(|queue| (queue_idx, queue.queue_id()))
}

#[inline]
fn build_nonexact_cos_batch(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    now_ns: u64,
) -> Option<CoSBatch> {
    // #4972: borrow the shared exact-backlog `Arc` from the disjoint
    // `cos_fast_interfaces` field rather than cloning it per non-exact
    // batch build. It coexists with the `cos_interfaces` mutable borrow
    // below — the same borrow-split `queue_fast_path` (a few lines down)
    // already relies on.
    let shared_exact_backlog = binding
        .cos
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_exact_backlog.as_ref());
    let peer_exact_demand_mask = shared_exact_backlog
        .map(|backlog| backlog.peer_exact_demand_queue_mask(binding.slot))
        .unwrap_or(ExactDemandQueueMask::EMPTY);
    // #4265 (R-2): the non-exact guarantee refill now routes through the
    // shared queue lease (when the coordinator built one for a sharded
    // non-exact guaranteed queue) so admission is metered class-wide
    // instead of per-worker. The fast-path slice reads the disjoint
    // `cos_fast_interfaces` field, so it coexists with the `cos_interfaces`
    // mutable borrow below (same borrow-split the exact direct path uses).
    let queue_fast_path = binding
        .cos
        .cos_fast_interfaces
        .get(&root_ifindex)
        .map(|iface_fast| iface_fast.queue_fast_path.as_slice())
        .unwrap_or(&[]);
    // #4973: split-borrow the per-worker reusable Local/Prepared batch deques
    // from their disjoint `WorkerCos` fields alongside the `cos_interfaces`
    // mutable borrow (the same disjoint-field borrow-split `queue_fast_path` /
    // `shared_exact_backlog` above already rely on). The selected batch build
    // `mem::take`s the matching deque into the `CoSBatch`; the submit handler
    // drains it empty and stores it back, so the shaped-TX drain reuses the
    // ring-buffer allocation instead of `VecDeque::new()`ing per batch.
    // Borrow the fields directly (not through an intermediate `&mut
    // binding.cos`, which would conflict with the still-live shared borrow of
    // `binding.cos.cos_fast_interfaces` held by `queue_fast_path`). An explicit
    // `match` (not `.or_else`) keeps the surplus fallback out of a closure that
    // would try to re-capture the scratch references.
    let selected = {
        let local_scratch = &mut binding.cos.cos_local_batch_scratch;
        let prepared_scratch = &mut binding.cos.cos_prepared_batch_scratch;
        let root = binding.cos.cos_interfaces.get_mut(&root_ifindex)?;
        match select_nonexact_cos_guarantee_batch_into(
            root,
            queue_fast_path,
            now_ns,
            local_scratch,
            prepared_scratch,
        ) {
            Some(batch) => Some(batch),
            None => {
                // Strict priority applies to surplus service only. Non-exact
                // queues with explicit transmit-rate guarantees keep their
                // guarantee pass. Residual/best-effort surplus remains
                // work-conserving, but while exact queues are backlogged it may
                // consume only the residual root rate after backlogged exact
                // guarantee rates are reserved.
                let exact_demand_mask =
                    serviceable_exact_demand_mask(root) | peer_exact_demand_mask;
                let exact_demand_rate = exact_demand_rate_bytes_for_mask(root, exact_demand_mask);
                let nonexact_budget = nonexact_surplus_budget_under_exact_demand(
                    root,
                    now_ns,
                    exact_demand_rate,
                    shared_exact_backlog.map(|backlog| &**backlog),
                );
                select_cos_surplus_batch_filtered(
                    root,
                    now_ns,
                    true,
                    nonexact_budget,
                    local_scratch,
                    prepared_scratch,
                )
            }
        }
    };
    if selected.is_some() {
        refresh_cos_interface_activity(binding, root_ifindex);
    }
    selected
}

#[inline]
fn reset_nonexact_surplus_under_exact_budget(
    root: &mut CoSInterfaceRuntime,
    now_ns: u64,
    shared_exact_backlog: Option<&SharedCoSExactBacklog>,
) {
    root.nonexact_surplus_under_exact_tokens = 0;
    root.nonexact_surplus_under_exact_last_refill_ns = now_ns;
    if let Some(backlog) = shared_exact_backlog {
        backlog.reset_residual_surplus_budget(now_ns);
    }
}

#[inline]
fn residual_rate_and_burst(
    root: &CoSInterfaceRuntime,
    exact_demand_rate: u64,
) -> Option<(u64, u64)> {
    if exact_demand_rate == 0 || root.shaping_rate_bytes == 0 {
        return None;
    }
    let residual_rate = root.shaping_rate_bytes.saturating_sub(exact_demand_rate);
    if residual_rate == 0 {
        return Some((0, 0));
    }
    let residual_burst = (residual_rate / 100)
        .max(COS_MIN_BURST_BYTES)
        .min(root.burst_bytes.max(COS_MIN_BURST_BYTES));
    Some((residual_rate, residual_burst))
}

#[inline]
fn nonexact_surplus_budget_under_exact_demand(
    root: &mut CoSInterfaceRuntime,
    now_ns: u64,
    exact_demand_rate: u64,
    shared_exact_backlog: Option<&SharedCoSExactBacklog>,
) -> Option<u64> {
    let Some((residual_rate, residual_burst)) = residual_rate_and_burst(root, exact_demand_rate)
    else {
        reset_nonexact_surplus_under_exact_budget(root, now_ns, shared_exact_backlog);
        return None;
    };
    if residual_rate == 0 {
        reset_nonexact_surplus_under_exact_budget(root, now_ns, shared_exact_backlog);
        return Some(0);
    }
    if let Some(backlog) = shared_exact_backlog {
        root.nonexact_surplus_under_exact_tokens = 0;
        root.nonexact_surplus_under_exact_last_refill_ns = now_ns;
        return Some(backlog.residual_surplus_budget(now_ns, residual_rate, residual_burst));
    }
    refill_cos_tokens(
        &mut root.nonexact_surplus_under_exact_tokens,
        residual_rate,
        residual_burst,
        &mut root.nonexact_surplus_under_exact_last_refill_ns,
        now_ns,
    );
    Some(root.nonexact_surplus_under_exact_tokens)
}

#[inline]
fn service_exact_guarantee_queue_direct(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Option<bool> {
    let mut lease_telemetry = CoSQueueLeaseAcquireTelemetry::default();
    let ret = service_exact_guarantee_queue_direct_with_info(
        binding,
        root_ifindex,
        now_ns,
        shared_recycles,
        &mut lease_telemetry,
    )
    .map(|slot| slot.is_some());
    record_cos_queue_lease_acquire(binding, lease_telemetry);
    ret
}

/// #751: variant that additionally reports which queue was actually
/// serviced so the caller can attribute per-queue drain latency.
/// Returns:
///   * `Some(Some(ref))` — exact-guarantee selection fired, batch
///     service progressed on `ref`.
///   * `Some(None)` — exact-guarantee selection fired but the service
///     call made no progress (batch build declined / TX ring refused).
///   * `None` — no exact-guarantee selection; caller falls through
///     to the non-exact path.
#[inline]
fn service_exact_guarantee_queue_direct_with_info(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
    lease_telemetry: &mut CoSQueueLeaseAcquireTelemetry,
) -> Option<Option<DrainedQueueRef>> {
    let queue_fast_path = binding
        .cos
        .cos_fast_interfaces
        .get(&root_ifindex)?
        .queue_fast_path
        .as_slice();
    let selection = {
        let root = binding.cos.cos_interfaces.get_mut(&root_ifindex)?;
        select_exact_cos_guarantee_queue_with_lease_telemetry(
            root,
            queue_fast_path,
            now_ns,
            lease_telemetry,
        )?
    };

    let queue_id = binding
        .cos
        .cos_interfaces
        .get(&root_ifindex)
        .and_then(|root| root.queues.get(selection.queue_idx))
        .map(|queue| queue.queue_id());

    let progress = match selection.kind {
        ExactCoSQueueKind::Local => service_exact_local_queue_direct(
            binding,
            root_ifindex,
            selection.queue_idx,
            selection.secondary_budget,
            now_ns,
            shared_recycles,
        ),
        ExactCoSQueueKind::Prepared => service_exact_prepared_queue_direct(
            binding,
            root_ifindex,
            selection.queue_idx,
            selection.secondary_budget,
            now_ns,
            shared_recycles,
        ),
    };

    if !progress {
        if let Some(refund) = selection.phase1_honor {
            refund_phase1_waterfill_honor(binding, root_ifindex, selection.queue_idx, refund);
        }
    }

    Some(if progress {
        queue_id.map(|queue_id| DrainedQueueRef {
            root_ifindex,
            queue_idx: selection.queue_idx,
            queue_id,
        })
    } else {
        None
    })
}

/// hb166 T-2: undo the Phase-1 waterfill honor for a queue that was
/// SELECTED via the Phase-1 honored walk but transmitted zero bytes (TX
/// ring full / no free UMEM frame / frame-build Drop → service returned
/// `progress == false`).
///
/// The waterfill selector commits the honor at SELECTION: it debits
/// `waterfill_pass1_remaining_bytes` by the queue's stable `phase1_cost`
/// and sets the queue's ascending-ordinal bit in
/// `waterfill_honored_epoch_bits`, marking it "already took its guarantee
/// this epoch" so BOTH phases skip it until the epoch refills (~200 us).
/// A zero-byte TX must NOT burn that guarantee — the small class should
/// keep its honor and retry once the interface-wide TX-ring / free-frame
/// pressure clears. This refund restores the debit and clears the bit so
/// the queue is re-selectable this same epoch.
///
/// Correctness: the debit is undone by the exact `cost_bytes` captured at
/// selection, and nothing else mutates `waterfill_pass1_remaining_bytes`
/// between selection and this refund on the single-threaded owner (so the
/// `saturating_add` cannot exceed the pre-selection budget → no honor
/// leak). A queue that DID transmit keeps its honor consumed (this runs
/// only on `progress == false` → no double-consume). Telemetry:
/// `phase1_admissions` was bumped at selection, so decrement it (it must
/// count only progressing services) and record the no-progress in
/// `phase1_selected_no_progress`.
#[inline]
fn refund_phase1_waterfill_honor(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    refund: Phase1HonorRefund,
) {
    if let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) {
        apply_phase1_waterfill_honor_refund(root, queue_idx, refund);
    }
}

/// Root-scoped body of the Phase-1 honor refund (see
/// `refund_phase1_waterfill_honor`), split out so it is exercisable
/// without a full `BindingWorker`. Restores the debited budget, clears
/// the honored-epoch bit, and corrects the telemetry.
#[inline]
fn apply_phase1_waterfill_honor_refund(
    root: &mut CoSInterfaceRuntime,
    queue_idx: usize,
    refund: Phase1HonorRefund,
) {
    root.waterfill_pass1_remaining_bytes = root
        .waterfill_pass1_remaining_bytes
        .saturating_add(refund.cost_bytes);
    if refund.bit_ordinal < 64 {
        root.waterfill_honored_epoch_bits &= !(1u64 << refund.bit_ordinal);
    }
    if let Some(queue) = root.queues.get_mut(queue_idx) {
        let counters = &mut queue.telemetry.waterfill_counters;
        counters.phase1_admissions = counters.phase1_admissions.saturating_sub(1);
        counters.phase1_selected_no_progress =
            counters.phase1_selected_no_progress.wrapping_add(1);
    }
}

#[cfg(test)]
#[inline]
pub(in crate::afxdp) fn select_cos_guarantee_batch(
    root: &mut CoSInterfaceRuntime,
    now_ns: u64,
) -> Option<CoSBatch> {
    select_cos_guarantee_batch_with_fast_path(root, &[], now_ns)
}

// Legacy single-pass guarantee selector that walks both classes in one
// iteration. The production path in `drain_shaped_tx` no longer calls this
// (it uses the two specialized selectors for strict-priority exact-over-
// nonexact service); `select_cos_guarantee_batch_with_fast_path` is retained
// solely for unit-test coverage of the batch-build mechanics and is
// compiled out of non-test builds along with its `legacy_guarantee_rr`
// cursor. Uses its own cursor so test harnesses that call this do not
// corrupt the production `exact_guarantee_rr` / `nonexact_guarantee_rr`
// cursors and vice versa.
#[cfg(test)]
#[inline]
pub(in crate::afxdp) fn select_cos_guarantee_batch_with_fast_path(
    root: &mut CoSInterfaceRuntime,
    queue_fast_path: &[WorkerCoSQueueFastPath],
    now_ns: u64,
) -> Option<CoSBatch> {
    let queue_count = root.queues.len();
    if queue_count == 0 {
        return None;
    }
    let start = root.legacy_guarantee_rr % queue_count;
    // #4973: this legacy test-only selector does not thread worker scratch, so
    // it uses throwaway batch deques. Production reuse lives on the
    // `_into` / `_filtered` selectors driven by `build_nonexact_cos_batch`.
    let mut local_scratch = VecDeque::new();
    let mut prepared_scratch = VecDeque::new();
    for offset in 0..queue_count {
        let queue_idx = (start + offset) % queue_count;
        let queue = &mut root.queues[queue_idx];
        if cos_queue_is_empty(queue) || !queue.hot.runnable || !queue.config.guarantee_enabled {
            continue;
        }
        if queue.config.exact {
            let _ = maybe_top_up_cos_queue_lease(
                queue,
                queue_fast_path
                    .get(queue_idx)
                    .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref()),
                now_ns,
            );
        } else {
            let transmit_rate_bytes = queue.transmit_rate_bytes();
            let buffer_bytes = queue.config.buffer_bytes.max(COS_MIN_BURST_BYTES);
            refill_cos_tokens(
                &mut queue.hot.tokens,
                transmit_rate_bytes,
                buffer_bytes,
                &mut queue.hot.last_refill_ns,
                now_ns,
            );
        }
        let Some(head) = cos_queue_front(queue) else {
            continue;
        };
        let head_len = cos_item_len(head);
        if root.tokens < head_len {
            if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                root.tokens,
                root.shaping_rate_bytes,
                queue.hot.tokens,
                queue.transmit_rate_bytes(),
                head_len,
                now_ns,
                queue.config.exact,
            ) {
                count_park_reason(root, queue_idx, ParkReason::RootTokenStarvation);
                park_cos_queue(root, queue_idx, wake_tick);
            }
            continue;
        }
        if queue.hot.tokens < head_len {
            if queue.config.exact {
                if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                    root.tokens,
                    root.shaping_rate_bytes,
                    queue.hot.tokens,
                    queue.transmit_rate_bytes(),
                    head_len,
                    now_ns,
                    true,
                ) {
                    count_park_reason(root, queue_idx, ParkReason::QueueTokenStarvation);
                    park_cos_queue(root, queue_idx, wake_tick);
                }
            }
            continue;
        }
        root.legacy_guarantee_rr = (start + offset + 1) % queue_count;
        // #1630 (P2): per-visit FRAME-count cap, not the rate-scaled
        // quantum (which discarded the sub-frame remainder each visit).
        let guarantee_budget = queue
            .hot
            .tokens
            .min(cos_guarantee_visit_cap_bytes())
            .max(head_len);
        if let Some(batch) = build_cos_batch_from_queue(
            queue,
            queue_idx,
            root.tokens,
            guarantee_budget,
            CoSServicePhase::Guarantee,
            &mut local_scratch,
            &mut prepared_scratch,
        ) {
            return Some(batch);
        }
    }
    None
}

// Selects the next exact-class guarantee queue for service. Rotates
// independently of the non-exact pass via `exact_guarantee_rr` — the two
// classes are scheduled with strict-priority exact-over-nonexact and
// class-independent RR within each class.
#[cfg(test)]
#[inline]
pub(in crate::afxdp) fn select_exact_cos_guarantee_queue_with_fast_path(
    root: &mut CoSInterfaceRuntime,
    queue_fast_path: &[WorkerCoSQueueFastPath],
    now_ns: u64,
) -> Option<ExactCoSQueueSelection> {
    let mut lease_telemetry = CoSQueueLeaseAcquireTelemetry::default();
    select_exact_cos_guarantee_queue_with_lease_telemetry(
        root,
        queue_fast_path,
        now_ns,
        &mut lease_telemetry,
    )
}

#[inline]
fn select_exact_cos_guarantee_queue_with_lease_telemetry(
    root: &mut CoSInterfaceRuntime,
    queue_fast_path: &[WorkerCoSQueueFastPath],
    now_ns: u64,
    lease_telemetry: &mut CoSQueueLeaseAcquireTelemetry,
) -> Option<ExactCoSQueueSelection> {
    // #1614 A1: in GuaranteeRate mode (operator opt-in), dispatch to
    // the small-first waterfill selector. The default Proportional
    // mode falls through to the legacy round-robin selector below.
    //
    // NOTE (#4220): priority_low_min_share_bytes is WIRE-SURFACE ONLY
    // and is NOT enforced by this or any other selector — no cap_eff
    // subtraction exists anywhere in the tree (matching the honest
    // field note at afxdp/types/cos.rs, "Currently UNUSED"). The
    // intended per-pass reservation of the priority-low min-share
    // before the A1 selector is deferred research. Because no code
    // consults the field, the Proportional fall-through is bit-for-bit
    // unchanged for ANY value of priority_low_min_share_bytes, not just
    // 0.
    if matches!(
        root.oversubscription_policy,
        CoSOversubscriptionPolicy::GuaranteeRate
    ) && root.oversubscription_guarantee_fraction > 0.0
    {
        return select_exact_cos_guarantee_queue_waterfill(
            root,
            queue_fast_path,
            now_ns,
            lease_telemetry,
        );
    }
    let queue_count = root.queues.len();
    if queue_count == 0 {
        return None;
    }
    let start = root.exact_guarantee_rr % queue_count;
    for offset in 0..queue_count {
        let queue_idx = (start + offset) % queue_count;
        let queue = &mut root.queues[queue_idx];
        if cos_queue_is_empty(queue)
            || !queue.hot.runnable
            || !queue.config.guarantee_enabled
            || !queue.config.exact
        {
            continue;
        }
        let top_up = maybe_top_up_cos_queue_lease(
            queue,
            queue_fast_path
                .get(queue_idx)
                .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref()),
            now_ns,
        );
        lease_telemetry.add_assign(top_up);
        let Some(head) = cos_queue_front(queue) else {
            continue;
        };
        let head_len = cos_item_len(head);
        if root.tokens < head_len {
            // #760 instrumentation: record the per-queue observation
            // that the interface shaper held it back. Written
            // regardless of whether the wakeup-tick estimator
            // succeeds in parking it, because "gate fired" is the
            // signal we care about, not "queue successfully
            // scheduled". Same Relaxed reasoning as drain_invocations.
            queue
                .telemetry
                .owner_profile
                .drain_park_root_tokens
                .fetch_add(1, Ordering::Relaxed);
            // #915 (Codex code-review MAJOR): surplus-sharing exact
            // queues stay runnable on root-token starvation too —
            // surplus eligibility waits ONLY on root tokens, never
            // on queue tokens. If we park here with
            // `require_queue_tokens=true`, a low-rate
            // surplus-sharing queue with empty queue.hot.tokens would
            // be put to sleep until BOTH buckets refill, even
            // though `select_cos_surplus_batch` would have been
            // happy to send as soon as root tokens recover (it
            // calls `estimate_cos_queue_wakeup_tick(..., false)`).
            // Falling through to the surplus selector lets that
            // selector handle the root-only park with
            // `require_queue_tokens=false`.
            if queue.config.surplus_sharing {
                continue;
            }
            if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                root.tokens,
                root.shaping_rate_bytes,
                queue.hot.tokens,
                queue.transmit_rate_bytes(),
                head_len,
                now_ns,
                true,
            ) {
                count_park_reason(root, queue_idx, ParkReason::RootTokenStarvation);
                park_cos_queue(root, queue_idx, wake_tick);
            }
            continue;
        }
        if queue.hot.tokens < head_len {
            // #760 instrumentation: the per-queue token gate held
            // this queue back. A queue that sustains throughput
            // above its configured rate with this counter near zero
            // is direct evidence the gate never fired.
            queue
                .telemetry
                .owner_profile
                .drain_park_queue_tokens
                .fetch_add(1, Ordering::Relaxed);
            // #1782 Step-1 (ii): the plan r2-F1 selector-site
            // comparison — post-top-up tokens still below head_len —
            // attributed to the v8 shortfall cause this pass's
            // `maybe_top_up_cos_queue_lease` reported (`None` causes,
            // e.g. legacy lease or full grant, are not counted).
            lease_telemetry.count_v8_undergrant(top_up.v8_shortfall_cause);
            // #915: surplus-sharing exact queues stay runnable when
            // queue.hot.tokens runs out — do NOT park. This lets the
            // queue fall through to `select_cos_surplus_batch` on
            // the same drain pass (root tokens permitting). The
            // `drain_park_queue_tokens` counter still increments
            // because the per-queue bucket DID starve; that's
            // diagnostic parity, not a bug. Without this branch
            // the queue would be parked here, marked
            // `runnable = false`, and skipped by the surplus
            // selector — defeating the whole point of #915.
            if queue.config.surplus_sharing {
                continue;
            }
            if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                root.tokens,
                root.shaping_rate_bytes,
                queue.hot.tokens,
                queue.transmit_rate_bytes(),
                head_len,
                now_ns,
                true,
            ) {
                count_park_reason(root, queue_idx, ParkReason::QueueTokenStarvation);
                park_cos_queue(root, queue_idx, wake_tick);
            }
            continue;
        }
        root.exact_guarantee_rr = (start + offset + 1) % queue_count;
        // #1630 (P2): per-visit FRAME-count cap, not the rate-scaled
        // quantum. Combined with #1630 (P1)'s N-frame token bank, a
        // low-rate exact class can now drain its banked frames whole
        // instead of losing the sub-frame remainder each visit.
        let secondary_budget = queue
            .hot
            .tokens
            .min(cos_guarantee_visit_cap_bytes())
            .max(head_len);
        let kind = match head {
            CoSPendingTxItem::Local(_) => ExactCoSQueueKind::Local,
            CoSPendingTxItem::Prepared(_) => ExactCoSQueueKind::Prepared,
        };
        return Some(ExactCoSQueueSelection {
            queue_idx,
            secondary_budget,
            kind,
            // Legacy Proportional RR selector: no Phase-1 waterfill honor
            // to refund (it debits no budget and sets no honored bit).
            phase1_honor: None,
        });
    }
    None
}

// #1614 A1: two-phase waterfill selector for `guarantee-rate`
// oversubscription policy. Activated when the interface's
// `oversubscription_policy == GuaranteeRate` AND `guarantee_fraction
// > 0`. Implements an operator-tunable budget split between Phase 1
// (small-first honored set) and Phase 2 (residual distributed
// across larger queues).
//
// Per-call state (carried on `CoSInterfaceRuntime`):
//   - `waterfill_pass1_remaining_bytes`: Phase 1 budget remaining
//     in the current epoch. #1743: refilled to
//     `(shaping_rate_bytes × COS_GUARANTEE_VISIT_NS / 1e9 ×
//     guarantee_fraction)` for a SHAPED root (the documented
//     "fraction × cap" contract), or the legacy
//     `(quantum_sum × guarantee_fraction)` for a transparent
//     (unshaped) root, clamped to ≥ one min-quantum. Refilled on
//     EITHER the exhausted (`pass1 == 0`) path OR the time-based
//     path (`elapsed ≥ COS_GUARANTEE_VISIT_NS`).
//   - `waterfill_phase2_cursor`: where Phase 2's descending walk
//     last stopped; lets the selector resume on subsequent calls.
//     Reset to 0 ONLY on a genuine Phase-2 WRAP (the end-of-function
//     `None` path); NEITHER refill path touches it, so the descending
//     walk advances continuously across epochs (#1743 Hunk C / r2).
//   - `waterfill_epoch_start_ns`: timestamp of the last refill,
//     drives the time-based refresh (#1743).
//   - `waterfill_epoch_wrap_pending`: set by the Phase-2 wrap (`None`)
//     path; gates the honored-bitset clear so a bare mid-walk
//     `pass1 == 0` refill does NOT re-honor an exact-fit queue
//     (#1743 r3 livelock fix).
//
// Each call returns ONE queue selection. The selector first tries
// Phase 1 (ascending walk; each Phase-1 honor decrements
// `pass1_remaining` by the chosen queue's STABLE configured
// quantum `phase1_cost`, #1743 Hunk B — NOT the token-clamped
// send budget). When Phase 1 has insufficient budget for the next
// ascending queue, the selector enters Phase 2 (descending walk
// through queues NOT honored in Phase 1; Phase 2 does NOT debit
// `pass1`). When Phase 2 exhausts, the epoch resets and Phase 1
// budget is refilled.
//
// AGY r2 #1's equal-rate starvation concern is bounded by
// stable sort (queues with identical rates retain queue_id
// order). Codex code-r1 #1's fraction-honoring contract is
// preserved: `fraction = 0.4` and `fraction = 0.7` produce
// measurably different Phase 1 budgets and therefore different
// distributions.
#[inline]
fn select_exact_cos_guarantee_queue_waterfill(
    root: &mut CoSInterfaceRuntime,
    queue_fast_path: &[WorkerCoSQueueFastPath],
    now_ns: u64,
    lease_telemetry: &mut CoSQueueLeaseAcquireTelemetry,
) -> Option<ExactCoSQueueSelection> {
    let queue_count = root.queues.len();
    if queue_count == 0 || root.exact_queues_by_rate_ascending.is_empty() {
        return None;
    }
    // Phase 1 epoch refill (#4408 Increment 3a). See
    // `refill_waterfill_epoch` for the two refill triggers, the
    // epoch-boundary gate on the honored bitset, and the #1743 r2/r3
    // ordering hazard that keeps that block atomic.
    refill_waterfill_epoch(root, now_ns);
    let ascending_len = root.exact_queues_by_rate_ascending.len();
    debug_assert!(
        ascending_len <= 64,
        "waterfill honored bitset is u64; >64 exact guarantee queues on one \
         interface is unsupported (ordinal bit range overflow)"
    );
    // Phase 1: ascending-rate walk (#4408 Increment 3b). `None` means
    // "budget exhausted or nothing eligible" — both of the original body's
    // non-selecting Phase-1 exits — and falls through to Phase 2.
    if let Some(selection) = waterfill_phase1_select(
        root,
        queue_fast_path,
        now_ns,
        lease_telemetry,
        queue_count,
        ascending_len,
    ) {
        return Some(selection);
    }
    // Phase 2: descending-rate residual walk (#4408 Increment 3b). `None`
    // means the descending cycle serviced nothing, which is the genuine
    // Phase-2 WRAP handled by the tail below.
    if let Some(selection) = waterfill_phase2_select(
        root,
        queue_fast_path,
        now_ns,
        lease_telemetry,
        queue_count,
        ascending_len,
    ) {
        return Some(selection);
    }
    // Genuine Phase-2 WRAP: a full descending cycle serviced nothing, so the
    // epoch is fully consumed. Reset the Phase-1 budget and the cursor for
    // the next call, and arm `epoch_wrap_pending` so the refill above clears
    // the honored bitset (a true epoch boundary). #1743 (Codex r3): this is
    // the ONLY place that arms the honored-bits clear besides the time tick —
    // a bare mid-walk `pass1 == 0` does not, which avoids the all-min-quantum
    // re-honor livelock.
    root.waterfill_pass1_remaining_bytes = 0;
    root.waterfill_phase2_cursor = 0;
    root.waterfill_epoch_wrap_pending = true;
    None
}

// Phase 1: ascending-rate walk. Pick the first runnable queue
// whose secondary_budget ≤ pass1_remaining that has NOT already been
// honored this epoch.
//
// #1732: the honored set is the persistent `waterfill_honored_epoch_bits`
// on `root`, keyed by the ASCENDING-VEC ORDINAL `i` (NOT `queue_idx`).
// It is read by BOTH phases and cleared at the epoch refill above, so
// each queue is honored at most once per epoch: without the Phase-1 skip
// the smallest-rate queue would be re-honored on every selector call and
// monopolise the Phase-1 budget (the lowest-rate skew this fix targets).
// Iterating by index over the persistent vec avoids the per-call heap
// clone the old code used solely to dodge the `&mut root.queues` borrow
// conflict; `queue_idx` is copied out (a `Copy` `usize`) before the
// `&mut` borrow, so borrow-split holds with no allocation.
//
// #4408 Increment 3b: lifted verbatim out of
// `select_exact_cos_guarantee_queue_waterfill`. Every non-selecting exit of
// this walk — the `break` and loop exhaustion alike — already converged on
// the SAME successor in the original body, so `None` encodes them faithfully
// rather than inventing an outcome protocol. `#[inline(always)]` +
// same-module keeps the post-inline IR the shape it was (plan §2d); no
// coldness claim is made or needed.
//
// The interior of this walk is NOT further decomposable: `queue`'s `&mut`
// borrow of `root.queues` coexists with reads of the disjoint `root.tokens`
// and then ends so `count_park_reason`/`park_cos_queue` can take `&mut root`
// whole. That is NLL-precise; splitting inside would have to re-derive it.
#[inline(always)]
fn waterfill_phase1_select(
    root: &mut CoSInterfaceRuntime,
    queue_fast_path: &[WorkerCoSQueueFastPath],
    now_ns: u64,
    lease_telemetry: &mut CoSQueueLeaseAcquireTelemetry,
    queue_count: usize,
    ascending_len: usize,
) -> Option<ExactCoSQueueSelection> {
    for i in 0..ascending_len {
        let queue_idx = root.exact_queues_by_rate_ascending[i];
        // #1732: at-most-once Phase-1 honor per epoch. Skip a queue already
        // honored this epoch (by ORDINAL `i`) so the ascending walk advances
        // to the next-smallest queue instead of re-honoring the smallest one
        // every call. `i < 64` guards the shift (release strips the
        // debug_assert; ordinals ≥64 are conservatively untracked).
        if i < 64 && (root.waterfill_honored_epoch_bits & (1u64 << i)) != 0 {
            continue;
        }
        let queue = &mut root.queues[queue_idx];
        if cos_queue_is_empty(queue)
            || !queue.hot.runnable
            || !queue.config.guarantee_enabled
            || !queue.config.exact
        {
            continue;
        }
        let top_up = maybe_top_up_cos_queue_lease(
            queue,
            queue_fast_path
                .get(queue_idx)
                .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref()),
            now_ns,
        );
        lease_telemetry.add_assign(top_up);
        let Some(head) = cos_queue_front(queue) else {
            continue;
        };
        let head_len = cos_item_len(head);
        // #1628 (r4 AGY): hoist `kind` next to `head_len` so `head`'s
        // immutable borrow of `queue` ends HERE — both are `Copy`. This
        // lets the per-queue telemetry mutations below (`&mut queue`)
        // compile, and the `return` reuses `kind` instead of re-matching
        // `head`.
        let kind = match head {
            CoSPendingTxItem::Local(_) => ExactCoSQueueKind::Local,
            CoSPendingTxItem::Prepared(_) => ExactCoSQueueKind::Prepared,
        };
        // #1628 site 2: Phase-1 eligible visit — counted after the
        // eligibility gate + head-present, BEFORE the token gate, so a
        // token-starved-but-owned queue is still a visit.
        queue.telemetry.waterfill_counters.eligible_visits = queue
            .telemetry
            .waterfill_counters
            .eligible_visits
            .wrapping_add(1);
        if root.tokens < head_len {
            queue
                .telemetry
                .owner_profile
                .drain_park_root_tokens
                .fetch_add(1, Ordering::Relaxed);
            if queue.config.surplus_sharing {
                continue;
            }
            if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                root.tokens,
                root.shaping_rate_bytes,
                queue.hot.tokens,
                queue.transmit_rate_bytes(),
                head_len,
                now_ns,
                true,
            ) {
                count_park_reason(root, queue_idx, ParkReason::RootTokenStarvation);
                park_cos_queue(root, queue_idx, wake_tick);
            }
            continue;
        }
        if queue.hot.tokens < head_len {
            queue
                .telemetry
                .owner_profile
                .drain_park_queue_tokens
                .fetch_add(1, Ordering::Relaxed);
            // #1782 Step-1 (ii): waterfill selector-site under-grant
            // attribution — same contract as the legacy RR site above.
            lease_telemetry.count_v8_undergrant(top_up.v8_shortfall_cause);
            if queue.config.surplus_sharing {
                continue;
            }
            if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                root.tokens,
                root.shaping_rate_bytes,
                queue.hot.tokens,
                queue.transmit_rate_bytes(),
                head_len,
                now_ns,
                true,
            ) {
                count_park_reason(root, queue_idx, ParkReason::QueueTokenStarvation);
                park_cos_queue(root, queue_idx, wake_tick);
            }
            continue;
        }
        // Picked. #1630 (P2): decouple the two roles the quantum used
        // to play. The Phase-1 budget gate / consumption stays on the
        // RATE-SCALED quantum (`phase1_cost`) so the small-first
        // ordering and the shaper-anchored Phase-1 budget remain
        // consistent with `oversubscription_guarantee_fraction`.
        // The actual per-visit send budget (`send_budget`) is the
        // FRAME-count cap so a queue whose token bucket has banked
        // several frames (#1630 P1) drains them whole instead of
        // discarding the sub-frame remainder of the small quantum.
        //
        // #1743 Hunk B: charge the STABLE configured quantum, NOT
        // `queue.hot.tokens.min(quantum)`. Under v8-lease pressure
        // `queue.hot.tokens` collapses toward one frame, which collapsed
        // `phase1_cost` to `head_len`: the queue then trivially passed
        // the budget gate, consumed almost none of `pass1`, yet was
        // marked fully honored (below) — so Phase-2 skipped it
        // (phase2_admit stayed 0) while pass1 never neared exhaustion.
        // The honor decision must reflect the queue's full guaranteed
        // share for the epoch, independent of its current token bank.
        // (`send_budget` keeps the token clamp — it bounds the bytes
        // actually drained this visit, which legitimately tracks tokens.)
        let phase1_cost = cos_guarantee_quantum_bytes(queue).max(head_len);
        let send_budget = queue
            .hot
            .tokens
            .min(cos_guarantee_visit_cap_bytes())
            .max(head_len);
        // Phase 1 gate: if the rate-scaled cost for this queue exceeds
        // the remaining Phase 1 byte budget, this queue is past the
        // Phase 1 boundary. Mark all queues up to this point as
        // honored (they're the small classes that fit), break to
        // Phase 2 descending walk.
        if phase1_cost > root.waterfill_pass1_remaining_bytes {
            // Budget exhausted before this ascending queue could
            // be honored. Fall through to Phase 2 (descending walk over
            // queues NOT in the persistent honored set).
            // #1628 site 3: Phase-1 budget-exhausted break. Per-INTERFACE
            // (the break only sees the first crossing queue). Disjoint
            // `root` field, same pattern as the `:913` write below.
            root.waterfill_phase1_budget_breaks =
                root.waterfill_phase1_budget_breaks.wrapping_add(1);
            break;
        }
        // Phase 1 honor: consume the budget, mark honored, return.
        root.waterfill_pass1_remaining_bytes = root
            .waterfill_pass1_remaining_bytes
            .saturating_sub(phase1_cost);
        // #1732: mark this queue honored for the rest of the epoch by its
        // ASCENDING-VEC ORDINAL `i` (persists into later selector calls; both
        // phases skip it). `i < 64` guards the shift; ordinals ≥64 are left
        // untracked rather than wrapping `1u64 << (≥64)`.
        if i < 64 {
            root.waterfill_honored_epoch_bits |= 1u64 << i;
        }
        root.exact_guarantee_rr = (queue_idx + 1) % queue_count;
        // #1628 site 4: Phase-1 honor admission. `head` already dropped
        // (kind hoisted above), so this `&mut queue` write compiles.
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            queue.telemetry.waterfill_counters.phase1_admissions = queue
                .telemetry
                .waterfill_counters
                .phase1_admissions
                .wrapping_add(1);
        }
        return Some(ExactCoSQueueSelection {
            queue_idx,
            secondary_budget: send_budget,
            kind,
            // hb166 T-2: carry the epoch honor just committed above
            // (budget debit at `:1104`, honored bit at `:1112`) so the
            // service wrapper can REFUND it if this queue transmits zero
            // bytes. `cost_bytes` is always debited; the bit was set only
            // when `i < 64`, so the refund clears it under the same guard.
            phase1_honor: Some(Phase1HonorRefund {
                cost_bytes: phase1_cost,
                bit_ordinal: i as u32,
            }),
        });
    }
    None
}

// Phase 2: descending-rate walk over queues NOT honored in Phase 1
// this epoch.
//
// #1732: this reads the SAME persistent `waterfill_honored_epoch_bits`
// that Phase 1 sets, keyed by the ascending-vec ORDINAL `pos_from_end`,
// so it correctly skips queues that already took their Phase-1 guarantee
// this epoch and serves the residual to the larger un-honored queues —
// the documented descending-residual intent. (Previously this checked an
// empty function-local `honored_mask`, which is why the old comment here
// admitted it only "approximated".) Iterating `exact_queues_by_rate_
// ascending` by index avoids the heap clone the old code used.
//
// #4408 Increment 3b: lifted verbatim out of
// `select_exact_cos_guarantee_queue_waterfill`. Every non-selecting exit of
// this walk — the `break` and loop exhaustion alike — already converged on
// the SAME successor in the original body, so `None` encodes them faithfully
// rather than inventing an outcome protocol. `#[inline(always)]` +
// same-module keeps the post-inline IR the shape it was (plan §2d); no
// coldness claim is made or needed.
#[inline(always)]
fn waterfill_phase2_select(
    root: &mut CoSInterfaceRuntime,
    queue_fast_path: &[WorkerCoSQueueFastPath],
    now_ns: u64,
    lease_telemetry: &mut CoSQueueLeaseAcquireTelemetry,
    queue_count: usize,
    ascending_len: usize,
) -> Option<ExactCoSQueueSelection> {
    let mut phase2_idx = root.waterfill_phase2_cursor;
    if phase2_idx >= ascending_len {
        phase2_idx = 0;
    }
    let start_phase2 = phase2_idx;
    // Walk descending starting from the cursor position
    // (interpreted as "position in the descending walk"). Use a
    // bounded loop to avoid scanning forever.
    for _step in 0..ascending_len {
        // Map cursor → descending iteration: the ascending vec is
        // ascending, so index from the END. `pos_from_end` is the
        // ascending-vec ORDINAL of the queue visited here — the same key
        // Phase 1 set.
        let pos_from_end = ascending_len - 1 - phase2_idx;
        let queue_idx = root.exact_queues_by_rate_ascending[pos_from_end];
        // Skip queues honored in Phase 1 this epoch (persistent bitset,
        // keyed by ordinal). `pos_from_end < 64` guards the shift; ordinals
        // ≥64 are conservatively untracked (same reason as Phase 1).
        if pos_from_end < 64
            && (root.waterfill_honored_epoch_bits & (1u64 << pos_from_end)) != 0
        {
            phase2_idx = (phase2_idx + 1) % ascending_len;
            if phase2_idx == start_phase2 {
                break;
            }
            continue;
        }
        let queue = &mut root.queues[queue_idx];
        if cos_queue_is_empty(queue)
            || !queue.hot.runnable
            || !queue.config.guarantee_enabled
            || !queue.config.exact
        {
            phase2_idx = (phase2_idx + 1) % ascending_len;
            if phase2_idx == start_phase2 {
                break;
            }
            continue;
        }
        let top_up = maybe_top_up_cos_queue_lease(
            queue,
            queue_fast_path
                .get(queue_idx)
                .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref()),
            now_ns,
        );
        lease_telemetry.add_assign(top_up);
        let Some(head) = cos_queue_front(queue) else {
            phase2_idx = (phase2_idx + 1) % ascending_len;
            if phase2_idx == start_phase2 {
                break;
            }
            continue;
        };
        let head_len = cos_item_len(head);
        // #1628 (r4 AGY): hoist `kind` so `head`'s borrow of `queue` ends
        // here (both `Copy`), allowing the per-queue telemetry writes
        // below to compile.
        let kind = match head {
            CoSPendingTxItem::Local(_) => ExactCoSQueueKind::Local,
            CoSPendingTxItem::Prepared(_) => ExactCoSQueueKind::Prepared,
        };
        // #1628 site 5: Phase-2 eligible visit — counted after the
        // eligibility gate + head-present, BEFORE the token gate.
        queue.telemetry.waterfill_counters.eligible_visits = queue
            .telemetry
            .waterfill_counters
            .eligible_visits
            .wrapping_add(1);
        if root.tokens < head_len || queue.hot.tokens < head_len {
            // Don't park in Phase 2 — the queue may legitimately
            // wait for next epoch. The legacy selector parks; we
            // skip silently here because Phase 2 service is
            // best-effort residual, not a guarantee.
            phase2_idx = (phase2_idx + 1) % ascending_len;
            if phase2_idx == start_phase2 {
                break;
            }
            continue;
        }
        // Phase 2 selection: return and advance cursor. #1630 (P2):
        // per-visit FRAME-count cap (Phase 2 has no Phase-1 budget
        // accounting, so there is no rate-scaled cost to preserve here).
        let candidate_budget = queue
            .hot
            .tokens
            .min(cos_guarantee_visit_cap_bytes())
            .max(head_len);
        root.waterfill_phase2_cursor = (phase2_idx + 1) % ascending_len;
        root.exact_guarantee_rr = (queue_idx + 1) % queue_count;
        // #1628 site 6: Phase-2 admission. `head` already dropped (kind
        // hoisted above), so this `&mut queue` write compiles.
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            queue.telemetry.waterfill_counters.phase2_admissions = queue
                .telemetry
                .waterfill_counters
                .phase2_admissions
                .wrapping_add(1);
        }
        return Some(ExactCoSQueueSelection {
            queue_idx,
            secondary_budget: candidate_budget,
            kind,
            // Phase 2 debits no Phase-1 budget and sets no honored bit, so
            // a zero-byte TX here loses nothing — nothing to refund.
            phase1_honor: None,
        });
    }
    None
}

// Phase 1 epoch refill. The BUDGET is refilled on two triggers:
//   (a) `pass1 == 0` — budget spent. Covers both the genuine Phase-2
//       wrap (the `None` path zeroes pass1 and arms wrap-pending) and a
//       mid-walk Phase-1 exact-fit honor that subtracted the last bytes.
//       Also the first-call path (pass1 seeds to 0 in the builder).
//   (b) #1743 time-based: `elapsed >= COS_GUARANTEE_VISIT_NS` since the
//       last refill. Phase-2 selections do NOT decrement `pass1`, so
//       under saturation `pass1` freezes at a small non-zero value below
//       every remaining quantum and small classes stop being honored;
//       the time tick refreshes the budget once per 200µs window.
//
// The honored BITSET, however, is cleared (allowing re-honoring) ONLY on
// a genuine epoch boundary: the time tick OR a Phase-2 WRAP
// (`waterfill_epoch_wrap_pending`). #1743 r3: a bare mid-walk `pass1 == 0`
// refills the budget but must NOT clear the bits, else an all-min-quantum
// exact-fit config livelocks Phase 1 on q0 and never reaches Phase 2.
//
// CRITICAL: NEITHER refill path resets `waterfill_phase2_cursor`
// (#1743 r2 — only the genuine Phase-2 wrap at the end-of-function `None`
// path does) so the descending RR walk advances through ALL large classes
// across epochs rather than restarting at the largest (the
// residual-starvation regression #1630 r4 caught).
//
// #4408 Increment 3a: lifted verbatim out of
// `select_exact_cos_guarantee_queue_waterfill` so the selector reads as
// three named phases rather than one 432-line body. This block MUST stay
// atomic: the order of the `waterfill_epochs` bump, the
// `epoch_boundary`-gated honored-bitset clear, and the
// `waterfill_epoch_wrap_pending = false` reset IS the #1743 r3 livelock
// fix. Do not split it further into "compute budget" + "clear bits".
//
// `#[inline(always)]` + same-module is deliberate: the post-inline IR is
// by construction the shape it was before the split, so no coldness claim
// is made or needed (plan §2d).
#[inline(always)]
fn refill_waterfill_epoch(root: &mut CoSInterfaceRuntime, now_ns: u64) {
    let elapsed_since_refresh = now_ns.saturating_sub(root.waterfill_epoch_start_ns);
    let time_refresh = elapsed_since_refresh >= COS_GUARANTEE_VISIT_NS;
    let exhausted = root.waterfill_pass1_remaining_bytes == 0;
    if time_refresh || exhausted {
        // fraction is clamped 0.0..1.0 at config-apply time; the
        // dispatch gate also requires fraction > 0. We use f64 → u64
        // with a floor + saturating cast guarded by the multiplication.
        let frac = root.oversubscription_guarantee_fraction;
        let raw_pass1 = if root.shaping_rate_bytes == 0 {
            // Transparent (unshaped) root: there is no shaper-delivered
            // cap to anchor against, so fall back to the legacy
            // `quantum_sum × fraction` over the current eligible set.
            // The result fits in u64 because quantum_sum ≤ 512 KB ×
            // N_queues and fraction ≤ 1.0.
            let mut quantum_sum: u64 = 0;
            for &qi in &root.exact_queues_by_rate_ascending {
                quantum_sum =
                    quantum_sum.saturating_add(cos_guarantee_quantum_bytes(&root.queues[qi]));
            }
            ((quantum_sum as f64) * frac).floor() as u64
        } else {
            // #1743 Hunk A: anchor pass1 to the shaper-delivered bytes
            // per epoch × fraction — the documented contract "fraction ×
            // cap" where cap = shaper × VISIT_NS (docs/fairness-regimes.md).
            // The legacy `quantum_sum × fraction` over-provisioned pass1
            // by ~4× for any oversubscribed config (Σ R_i > shaper), so
            // Phase 2 never fired and the selector degenerated to
            // ascending RR over all classes. shaping_rate_bytes is
            // bytes/sec; the u128 product is overflow-safe.
            let cap_per_epoch = ((root.shaping_rate_bytes as u128)
                * (COS_GUARANTEE_VISIT_NS as u128)
                / 1_000_000_000u128) as u64;
            ((cap_per_epoch as f64) * frac).floor() as u64
        };
        // AGY RISK-1 (Codex code-r1 #2): a tiny-positive fraction floors
        // `raw_pass1` to 0 on EITHER branch — the dispatch gate admits any
        // `fraction > 0`, including transparent + tiny-fraction. A zero
        // budget makes `exhausted` true on every selector call → refill +
        // cursor-reset thrash → Phase-2 starves from index 0. Clamp BOTH
        // branches to at least one min-quantum so the smallest class is
        // honorable and the exhausted path can't fire every call. (The
        // clamp is a no-op for normal fractions where raw_pass1 already
        // exceeds the smallest quantum.)
        let pass1 = raw_pass1.max(COS_GUARANTEE_QUANTUM_MIN_BYTES);
        root.waterfill_pass1_remaining_bytes = pass1;
        root.waterfill_epoch_start_ns = now_ns;
        // #1743 (Codex code-r3): clear the persistent honored bitset ONLY on
        // a genuine epoch boundary — the time tick OR a Phase-2 WRAP
        // (`waterfill_epoch_wrap_pending`, set by the end-of-function `None`
        // path). A bare `exhausted` (pass1 == 0) that did NOT come from a
        // wrap — e.g. a Phase-1 exact-fit honor that subtracted the last
        // bytes mid-walk — must NOT clear the bits: clearing there re-enabled
        // a degenerate all-min-quantum livelock where q0 is honored, pass1
        // hits 0, the next call clears its bit, q0 is re-honored, and Phase 2
        // is never reached. With the bits intact, the already-honored small
        // queue is skipped (the `i < 64` check below), so the walk advances
        // to the next queue or breaks to Phase 2 — guaranteeing forward
        // progress. The budget is still refilled on a bare `exhausted` so
        // Phase 1 can resume against the un-honored queues.
        let epoch_boundary = time_refresh || root.waterfill_epoch_wrap_pending;
        if epoch_boundary {
            root.waterfill_honored_epoch_bits = 0;
        }
        root.waterfill_epoch_wrap_pending = false;
        // #1743 (Codex code-r2): the refill never resets the Phase-2 cursor.
        // The cursor's ONLY reset is the genuine Phase-2 WRAP at the
        // end-of-function `None` path (which also re-arms epoch_wrap_pending),
        // so the descending walk advances continuously across epochs — the
        // #1630 r4 continuity invariant.
        //
        // #1628 site 1: completed-epoch / Phase-1-refill counter. Bumped
        // here (no `queue` borrowed yet) on every refill, either trigger.
        root.waterfill_epochs = root.waterfill_epochs.wrapping_add(1);
    }
}

// Selects the next non-exact guarantee queue for service. Rotates
// independently of the exact pass via `nonexact_guarantee_rr` — a service
// event on an exact queue does not advance this cursor, so non-exact RR
// order is stable across bursts of exact-queue activity.
//
// #4973: the production drain (`build_nonexact_cos_batch`) calls
// `select_nonexact_cos_guarantee_batch_into` with the per-worker reusable batch
// deques so `build_cos_batch_from_queue` does not `VecDeque::new()` per batch.
// This thin wrapper preserves the original allocating signature for unit tests
// that do not thread worker scratch.
#[cfg(test)]
#[inline]
pub(in crate::afxdp) fn select_nonexact_cos_guarantee_batch(
    root: &mut CoSInterfaceRuntime,
    queue_fast_path: &[WorkerCoSQueueFastPath],
    now_ns: u64,
) -> Option<CoSBatch> {
    let mut local_scratch = VecDeque::new();
    let mut prepared_scratch = VecDeque::new();
    select_nonexact_cos_guarantee_batch_into(
        root,
        queue_fast_path,
        now_ns,
        &mut local_scratch,
        &mut prepared_scratch,
    )
}

#[inline]
pub(in crate::afxdp) fn select_nonexact_cos_guarantee_batch_into(
    root: &mut CoSInterfaceRuntime,
    queue_fast_path: &[WorkerCoSQueueFastPath],
    now_ns: u64,
    local_scratch: &mut VecDeque<TxRequest>,
    prepared_scratch: &mut VecDeque<PreparedTxRequest>,
) -> Option<CoSBatch> {
    let queue_count = root.queues.len();
    if queue_count == 0 {
        return None;
    }
    let start = root.nonexact_guarantee_rr % queue_count;
    for offset in 0..queue_count {
        let queue_idx = (start + offset) % queue_count;
        let queue = &mut root.queues[queue_idx];
        if cos_queue_is_empty(queue)
            || !queue.hot.runnable
            || !queue.config.guarantee_enabled
            || queue.config.exact
        {
            continue;
        }
        // #4265 (R-2): meter the guarantee refill through the shared queue
        // lease when the coordinator attached one (a sharded non-exact
        // guaranteed queue, rate >= COS_SHARED_EXACT_MIN_RATE_BYTES). All
        // workers draw from the one legacy lease -> aggregate admission ==
        // configured rate. When no lease is attached (single-owner low-rate
        // non-exact queue), `maybe_top_up_cos_queue_lease` falls through to
        // the same per-worker `refill_cos_tokens` used before this change,
        // so single-owner behaviour is unchanged. The legacy lease returns
        // default (no-v8) telemetry, so nothing is dropped by ignoring it.
        let _ = maybe_top_up_cos_queue_lease(
            queue,
            queue_fast_path
                .get(queue_idx)
                .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref()),
            now_ns,
        );
        let Some(head) = cos_queue_front(queue) else {
            continue;
        };
        let head_len = cos_item_len(head);
        if root.tokens < head_len {
            if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                root.tokens,
                root.shaping_rate_bytes,
                queue.hot.tokens,
                queue.transmit_rate_bytes(),
                head_len,
                now_ns,
                false,
            ) {
                count_park_reason(root, queue_idx, ParkReason::RootTokenStarvation);
                park_cos_queue(root, queue_idx, wake_tick);
            }
            continue;
        }
        if queue.hot.tokens < head_len {
            continue;
        }
        root.nonexact_guarantee_rr = (start + offset + 1) % queue_count;
        // #1630 (P2): per-visit FRAME-count cap. The non-exact guarantee
        // bucket already accumulates to `buffer_bytes` (refill_cos_tokens),
        // so it needs only this P2 half — the quantum clamp was its sole
        // sub-frame-discard cause.
        let guarantee_budget = queue
            .hot
            .tokens
            .min(cos_guarantee_visit_cap_bytes())
            .max(head_len);
        if let Some(batch) = build_cos_batch_from_queue(
            queue,
            queue_idx,
            root.tokens,
            guarantee_budget,
            CoSServicePhase::Guarantee,
            local_scratch,
            prepared_scratch,
        ) {
            return Some(batch);
        }
    }
    None
}

// #4973: unit-test-facing surplus selector. The production drain calls
// `select_cos_surplus_batch_filtered` directly with the per-worker reusable
// batch deques; this wrapper allocates throwaway deques so tests keep the
// original allocating signature.
#[cfg(test)]
#[inline]
pub(in crate::afxdp) fn select_cos_surplus_batch(
    root: &mut CoSInterfaceRuntime,
    now_ns: u64,
) -> Option<CoSBatch> {
    let mut local_scratch = VecDeque::new();
    let mut prepared_scratch = VecDeque::new();
    select_cos_surplus_batch_filtered(
        root,
        now_ns,
        true,
        None,
        &mut local_scratch,
        &mut prepared_scratch,
    )
}

#[inline]
fn select_cos_surplus_batch_filtered(
    root: &mut CoSInterfaceRuntime,
    now_ns: u64,
    allow_nonexact: bool,
    nonexact_surplus_budget: Option<u64>,
    local_scratch: &mut VecDeque<TxRequest>,
    prepared_scratch: &mut VecDeque<PreparedTxRequest>,
) -> Option<CoSBatch> {
    for priority in 0..COS_PRIORITY_LEVELS {
        let indices_len = root.queue_indices_by_priority[priority].len();
        if indices_len == 0 {
            continue;
        }
        let start = root.rr_index_by_priority[priority] % indices_len;
        for offset in 0..indices_len {
            let queue_idx =
                root.queue_indices_by_priority[priority][(start + offset) % indices_len];
            let queue = &mut root.queues[queue_idx];
            if cos_queue_is_empty(queue) || !queue.hot.runnable {
                continue;
            }
            if !allow_nonexact && !queue.config.exact {
                continue;
            }
            if !queue.config.exact {
                if nonexact_surplus_budget.is_some_and(|budget| budget == 0) {
                    continue;
                }
            }
            // #915: exact queues are excluded from surplus by default
            // (preserves Junos `transmit-rate exact` hard-cap
            // semantics). When `surplus_sharing` is set, the queue
            // is allowed to participate in surplus and consumes
            // root.tokens + surplus_deficit + shared_root_lease only;
            // its per-queue rate cap stays a Guarantee-phase concept
            // (see tx_completion::apply_cos_*_result phase gate).
            if queue.config.exact && !queue.config.surplus_sharing {
                continue;
            }
            let Some(head) = cos_queue_front(queue) else {
                continue;
            };
            let head_len = cos_item_len(head);
            if root.tokens < head_len {
                if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                    root.tokens,
                    root.shaping_rate_bytes,
                    queue.hot.tokens,
                    queue.transmit_rate_bytes(),
                    head_len,
                    now_ns,
                    false,
                ) {
                    count_park_reason(root, queue_idx, ParkReason::RootTokenStarvation);
                    park_cos_queue(root, queue_idx, wake_tick);
                }
                continue;
            }
            if queue.hot.surplus_deficit < head_len {
                queue.hot.surplus_deficit = queue
                    .hot
                    .surplus_deficit
                    .saturating_add(cos_surplus_quantum_bytes(queue));
                if queue.hot.surplus_deficit < head_len {
                    continue;
                }
            }
            root.rr_index_by_priority[priority] = (start + offset + 1) % indices_len;
            let secondary_budget = if !queue.config.exact {
                queue
                    .hot
                    .surplus_deficit
                    .min(nonexact_surplus_budget.unwrap_or(u64::MAX))
            } else {
                queue.hot.surplus_deficit
            };
            if let Some(batch) = build_cos_batch_from_queue(
                queue,
                queue_idx,
                root.tokens,
                secondary_budget,
                CoSServicePhase::Surplus,
                local_scratch,
                prepared_scratch,
            ) {
                return Some(batch);
            }
        }
    }
    None
}

pub(in crate::afxdp) fn release_exact_local_scratch_frames(
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<ExactLocalScratchTxRequest>,
) {
    while let Some(req) = scratch_local_tx.pop() {
        free_tx_frames.push_front(req.offset);
    }
}

fn restore_exact_local_scratch_to_queue_head_flow_fair(
    queue: Option<&mut CoSQueueRuntime>,
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<(u64, TxRequest)>,
) {
    let Some(queue) = queue else {
        // #hb166 T-7: the queue was torn down mid-drain, but each scratch
        // entry still owns a `free_tx_frames` UMEM offset popped at
        // scratch-build time. Recycle them before dropping — the pre-fix
        // bare `.clear()` leaked every offset (an uncounted UMEM-frame
        // leak), unlike the FIFO sibling `settle_exact_local_fifo_submission`
        // (via `release_exact_local_scratch_frames`).
        while let Some((offset, _req)) = scratch_local_tx.pop() {
            free_tx_frames.push_front(offset);
        }
        return;
    };
    while let Some((offset, req)) = scratch_local_tx.pop() {
        free_tx_frames.push_front(offset);
        cos_queue_push_front(queue, CoSPendingTxItem::Local(req));
    }
}

pub(in crate::afxdp) fn release_exact_prepared_scratch(
    scratch_prepared_tx: &mut Vec<ExactPreparedScratchTxRequest>,
) {
    scratch_prepared_tx.clear();
}

fn restore_exact_prepared_scratch_to_queue_head_flow_fair(
    queue: Option<&mut CoSQueueRuntime>,
    scratch_prepared_tx: &mut Vec<PreparedTxRequest>,
) {
    let Some(queue) = queue else {
        scratch_prepared_tx.clear();
        return;
    };
    while let Some(req) = scratch_prepared_tx.pop() {
        cos_queue_push_front(queue, CoSPendingTxItem::Prepared(req));
    }
}

pub(in crate::afxdp) fn settle_exact_local_fifo_submission(
    queue: Option<&mut CoSQueueRuntime>,
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<ExactLocalScratchTxRequest>,
    inserted: usize,
) -> (u64, u64) {
    let Some(queue) = queue else {
        release_exact_local_scratch_frames(free_tx_frames, scratch_local_tx);
        return (0, 0);
    };
    let sent = inserted.min(scratch_local_tx.len());
    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    for _ in 0..sent {
        match queue.hot.items.pop_front() {
            Some(CoSPendingTxItem::Local(req)) => {
                sent_packets += 1;
                sent_bytes += req.bytes.len() as u64;
                // #6310: the committed buffer's bytes were copied into a
                // UMEM TX frame during the drain build, so the buffer is
                // dead here. Return it to the per-worker pool that feeds
                // the cross-worker redirect copy (`cos::redirect_pool`).
                super::redirect_pool::recycle(req.bytes);
            }
            Some(item) => {
                queue.hot.items.push_front(item);
                break;
            }
            None => break,
        }
    }
    for req in scratch_local_tx.drain(sent..).rev() {
        free_tx_frames.push_front(req.offset);
    }
    scratch_local_tx.clear();
    (sent_packets, sent_bytes)
}

pub(in crate::afxdp) fn settle_exact_local_scratch_submission_flow_fair(
    queue: Option<&mut CoSQueueRuntime>,
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<(u64, TxRequest)>,
    inserted: usize,
    now_ns: u64,
) -> (u64, u64) {
    let Some(queue) = queue else {
        // #hb166 T-7: recycle the UMEM offsets before dropping the scratch
        // (queue torn down mid-drain) — the pre-fix `.clear()` leaked them,
        // uncounted. Mirrors the FIFO `settle_exact_local_fifo_submission`
        // None arm and `restore_exact_local_scratch_to_queue_head_flow_fair`.
        while let Some((offset, _req)) = scratch_local_tx.pop() {
            free_tx_frames.push_front(offset);
        }
        return (0, 0);
    };
    // #1229 v7: per-bucket TX rate accounting. Capture the
    // FlowFair seed once; we'll need it to map each committed
    // packet's flow_key to its bucket.
    let flow_hash_seed = queue
        .flow_fair_state
        .as_ref()
        .map(|ff| ff.flow_hash_seed)
        .unwrap_or(0);
    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    while let Some((offset, req)) = scratch_local_tx.pop() {
        if scratch_local_tx.len() >= inserted {
            free_tx_frames.push_front(offset);
            cos_queue_push_front(queue, CoSPendingTxItem::Local(req));
        } else {
            // Committed: account the TX bytes against the bucket
            // BEFORE moving the request out (req still owned).
            // now_ns is sampled once per batch by the caller; this
            // scope reuses that single value for every packet.
            let bytes = req.bytes.len() as u64;
            if let Some(ff) = queue.flow_fair_state.as_mut() {
                let bucket = cos_flow_bucket_index(flow_hash_seed, req.flow_key.as_ref()) as u16;
                account_flow_bucket_tx(ff, bucket, bytes, now_ns);
            }
            // #1829 Phase 1 (Codex review on PR #1846): sojourn is
            // sampled HERE, at the committed-prefix settle — never at
            // pop/scratch-build time. The rollback branch above
            // push_fronts the suffix WITH its original enqueue_ns, so
            // sampling at pop would count a rolled-back item once per
            // attempt; sampling only the committed prefix counts each
            // packet exactly once, on the attempt that ships it. Same
            // pass-level now_ns the bucket accounting uses (no clock
            // reads, #1734).
            queue.telemetry.sojourn.record(req.enqueue_ns, now_ns);
            sent_packets += 1;
            sent_bytes += bytes;
            // #6310: committed buffer already copied into UMEM during the
            // flow-fair drain build — return it to the per-worker pool
            // for reuse by the cross-worker redirect copy. The rollback
            // branch above keeps `req` (push_front) and never reaches
            // here, so a re-tried packet's buffer is not recycled early.
            super::redirect_pool::recycle(req.bytes);
        }
    }
    (sent_packets, sent_bytes)
}

pub(in crate::afxdp) fn settle_exact_prepared_fifo_submission(
    queue: Option<&mut CoSQueueRuntime>,
    scratch_prepared_tx: &mut Vec<ExactPreparedScratchTxRequest>,
    in_flight_prepared_recycles: &mut FastMap<u64, PreparedTxRecycle>,
    inserted: usize,
) -> (u64, u64) {
    let Some(queue) = queue else {
        scratch_prepared_tx.clear();
        return (0, 0);
    };
    let sent = inserted.min(scratch_prepared_tx.len());
    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    for _ in 0..sent {
        match queue.hot.items.pop_front() {
            Some(CoSPendingTxItem::Prepared(req)) => {
                remember_prepared_recycle(in_flight_prepared_recycles, &req);
                sent_packets += 1;
                sent_bytes += req.len as u64;
            }
            Some(item) => {
                queue.hot.items.push_front(item);
                break;
            }
            None => break,
        }
    }
    scratch_prepared_tx.clear();
    (sent_packets, sent_bytes)
}

fn settle_exact_prepared_scratch_submission_flow_fair(
    queue: Option<&mut CoSQueueRuntime>,
    scratch_prepared_tx: &mut Vec<PreparedTxRequest>,
    in_flight_prepared_recycles: &mut FastMap<u64, PreparedTxRecycle>,
    inserted: usize,
    now_ns: u64,
) -> (u64, u64) {
    let Some(queue) = queue else {
        scratch_prepared_tx.clear();
        return (0, 0);
    };
    // #1229 v7: per-bucket TX rate accounting on the prepared-peer
    // commit path (same shape as the local exact path above).
    let flow_hash_seed = queue
        .flow_fair_state
        .as_ref()
        .map(|ff| ff.flow_hash_seed)
        .unwrap_or(0);
    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    while let Some(req) = scratch_prepared_tx.pop() {
        if scratch_prepared_tx.len() >= inserted {
            cos_queue_push_front(queue, CoSPendingTxItem::Prepared(req));
        } else {
            let bytes = req.len as u64;
            if let Some(ff) = queue.flow_fair_state.as_mut() {
                let bucket = cos_flow_bucket_index(flow_hash_seed, req.flow_key.as_ref()) as u16;
                account_flow_bucket_tx(ff, bucket, bytes, now_ns);
            }
            // #1829 Phase 1 (Codex review on PR #1846): committed-
            // prefix-only sojourn sample — see the Local settle above.
            queue.telemetry.sojourn.record(req.enqueue_ns, now_ns);
            remember_prepared_recycle(in_flight_prepared_recycles, &req);
            sent_packets += 1;
            sent_bytes += bytes;
        }
    }
    (sent_packets, sent_bytes)
}

#[inline]
fn subtract_direct_cos_queue_bytes(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    dropped_bytes: u64,
) {
    if dropped_bytes == 0 {
        refresh_cos_interface_activity(binding, root_ifindex);
        return;
    }
    if let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) {
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            queue.hot.queued_bytes = queue.hot.queued_bytes.saturating_sub(dropped_bytes);
        }
    }
    refresh_cos_interface_activity(binding, root_ifindex);
}

#[inline]
// #4973: `local_scratch` / `prepared_scratch` are the per-worker reusable
// batch deques (WorkerCos state). The selected arm `clear()`s its scratch at
// entry (defensive — a submit-side store-back leaves it empty, but a stale
// element from a torn-down-queue early-return would otherwise corrupt this
// batch), fills it, and `mem::take`s it into the `CoSBatch`. The submit
// handler drains it empty and stores it back, so the ring-buffer allocation is
// retained across drains instead of a `VecDeque::new()` per selected batch. The
// non-selected arm's scratch is left untouched (keeps its capacity).
fn build_cos_batch_from_queue(
    queue: &mut CoSQueueRuntime,
    queue_idx: usize,
    root_budget: u64,
    secondary_budget: u64,
    phase: CoSServicePhase,
    local_scratch: &mut VecDeque<TxRequest>,
    prepared_scratch: &mut VecDeque<PreparedTxRequest>,
) -> Option<CoSBatch> {
    // #3968: clear the pop-snapshot stack at batch start — the
    // non-exact analog of the clear `drain_exact_local_items_to_scratch_flow_fair`
    // / `drain_exact_prepared_items_to_scratch_flow_fair` already do
    // (queue_service/drain.rs). A fully-committed non-exact batch
    // leaves ALL of its snapshots on the stack:
    // `restore_cos_local_items_inner` pops one only per RETRIED item,
    // so a whole-batch commit consumes none. `drain_shaped_tx` builds
    // one batch per call and the outer TX loop calls it repeatedly, so
    // a saturated promoted non-exact queue with more than
    // `TX_BATCH_SIZE` resident items is drained across consecutive
    // `build_cos_batch_from_queue` calls with NO intervening
    // `cos_queue_push_back` (the only other clear site). Without this,
    // the next build pushes on top of the prior batch's stale
    // snapshots, growing the stack past its documented `TX_BATCH_SIZE`
    // bound (hot-path realloc / stale re-read; the per-pop
    // `debug_assert` in `cos_queue_pop_known_bucket_inner` trips in dev
    // builds). Cleared unconditionally at entry: any snapshots resident
    // here belong to an already-submitted batch and are stale — the
    // submit (and its synchronous rollback) completed before this call.
    if let Some(ff) = queue.flow_fair_state.as_mut() {
        ff.pop_snapshot_stack.clear();
    }
    let head = cos_queue_front(queue)?;
    match head {
        CoSPendingTxItem::Local(_) => {
            local_scratch.clear();
            let mut remaining_root = root_budget;
            let mut remaining_secondary = secondary_budget;
            let mut batch_bytes = 0u64;
            while local_scratch.len() < TX_BATCH_SIZE {
                // #1763 Lever A — fused select+pop. Peek returns the
                // min-finish bucket id; if we commit to popping, reuse
                // that exact bucket (no re-scan). No queue mutation
                // occurs between peek and the matching pop, so the
                // selected bucket is byte-identical to a re-scan.
                let Some((bucket, front)) = cos_queue_peek_min_bucket(queue, u64::MAX) else {
                    break;
                };
                let len = cos_item_len(front);
                if !matches!(front, CoSPendingTxItem::Local(_))
                    || remaining_root < len
                    || remaining_secondary < len
                {
                    break;
                }
                remaining_root = remaining_root.saturating_sub(len);
                remaining_secondary = remaining_secondary.saturating_sub(len);
                match cos_queue_pop_known_bucket(queue, bucket, u64::MAX) {
                    Some(CoSPendingTxItem::Local(req)) => {
                        batch_bytes = batch_bytes.saturating_add(len);
                        local_scratch.push_back(req);
                    }
                    Some(other) => {
                        cos_queue_push_front(queue, other);
                        break;
                    }
                    None => break,
                }
            }
            if local_scratch.is_empty() {
                None
            } else {
                Some(CoSBatch::Local {
                    queue_idx,
                    phase,
                    batch_bytes,
                    items: core::mem::take(local_scratch),
                })
            }
        }
        CoSPendingTxItem::Prepared(_) => {
            prepared_scratch.clear();
            let mut remaining_root = root_budget;
            let mut remaining_secondary = secondary_budget;
            let mut batch_bytes = 0u64;
            while prepared_scratch.len() < TX_BATCH_SIZE {
                // #1763 Lever A — fused select+pop (Prepared arm). See
                // the Local arm above for the no-mutation invariant.
                let Some((bucket, front)) = cos_queue_peek_min_bucket(queue, u64::MAX) else {
                    break;
                };
                let len = cos_item_len(front);
                if !matches!(front, CoSPendingTxItem::Prepared(_))
                    || remaining_root < len
                    || remaining_secondary < len
                {
                    break;
                }
                remaining_root = remaining_root.saturating_sub(len);
                remaining_secondary = remaining_secondary.saturating_sub(len);
                match cos_queue_pop_known_bucket(queue, bucket, u64::MAX) {
                    Some(CoSPendingTxItem::Prepared(req)) => {
                        batch_bytes = batch_bytes.saturating_add(len);
                        prepared_scratch.push_back(req);
                    }
                    Some(other) => {
                        cos_queue_push_front(queue, other);
                        break;
                    }
                    None => break,
                }
            }
            if prepared_scratch.is_empty() {
                None
            } else {
                Some(CoSBatch::Prepared {
                    queue_idx,
                    phase,
                    batch_bytes,
                    items: core::mem::take(prepared_scratch),
                })
            }
        }
    }
}

// #1331: per-variant body extracted into submit_local /
// submit_prepared sibling modules. This fn stays the dispatch shim.
#[inline]
fn submit_cos_batch(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    batch: CoSBatch,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> bool {
    match batch {
        CoSBatch::Local {
            queue_idx,
            phase,
            batch_bytes,
            items,
        } => submit_local(
            binding,
            root_ifindex,
            queue_idx,
            phase,
            batch_bytes,
            items,
            now_ns,
            shared_recycles,
        ),
        CoSBatch::Prepared {
            queue_idx,
            phase,
            batch_bytes,
            items,
        } => submit_prepared(
            binding,
            root_ifindex,
            queue_idx,
            phase,
            batch_bytes,
            items,
            now_ns,
            shared_recycles,
        ),
    }
}

#[inline]
pub(in crate::afxdp) fn cos_batch_tx_made_progress(result: Result<(u64, u64), TxError>) -> bool {
    matches!(result, Ok((packets, bytes)) if packets > 0 || bytes > 0)
}

#[inline]
pub(in crate::afxdp) fn cos_surplus_quantum_bytes(queue: &CoSQueueRuntime) -> u64 {
    COS_SURPLUS_ROUND_QUANTUM_BYTES.saturating_mul(u64::from(queue.config.surplus_weight.max(1)))
}

#[inline]
pub(in crate::afxdp) fn cos_guarantee_quantum_bytes(queue: &CoSQueueRuntime) -> u64 {
    let bytes_for_visit = ((queue.transmit_rate_bytes() as u128) * (COS_GUARANTEE_VISIT_NS as u128)
        / 1_000_000_000u128) as u64;
    bytes_for_visit.clamp(
        COS_GUARANTEE_QUANTUM_MIN_BYTES,
        COS_GUARANTEE_QUANTUM_MAX_BYTES,
    )
}

/// #1630 (P2): per-VISIT send budget cap for guarantee-phase service.
///
/// The selectors previously clamped each visit's `secondary_budget` to
/// `cos_guarantee_quantum_bytes` (= `rate × 200 µs`). For a low-rate
/// class that quantum (e.g. 2500 B for 100 Mbps) is below two MTUs, so
/// the drain sent one frame and DISCARDED the sub-frame remainder every
/// visit — a per-visit efficiency ceiling that rose with the configured
/// rate (100m and 1g far under shape, ≥3g ~100 %) and, under saturation,
/// read as proportional equalization.
///
/// The fix turns the per-visit bound into a FRAME-COUNT cap: a visit may
/// drain up to `TX_BATCH_SIZE` frames, bounded in bytes here so a banked
/// queue (#1630 P1 raised the token watermark to an N-frame bank) cannot
/// monopolize a drain pass. `TX_BATCH_SIZE × tx_frame_capacity()` is a
/// clean multiple of the frame size and at least 64 max-MTU frames, so
/// the `items.len() < TX_BATCH_SIZE` loop bound in the drain is the
/// binding per-visit constraint and no sub-frame remainder is lost. The
/// RR cursor still advances after each visit, preserving round-robin
/// fairness across queues. The long-run rate is unchanged — it is metered
/// by `queue.hot.tokens` (refilled at the configured rate via the v8
/// lease, #1630 cause-1 carry) and the actual-byte debit in tx_completion.
#[inline]
pub(in crate::afxdp) fn cos_guarantee_visit_cap_bytes() -> u64 {
    (TX_BATCH_SIZE as u64) * (tx_frame_capacity() as u64)
}

pub(in crate::afxdp) fn estimate_cos_queue_wakeup_tick(
    root_tokens: u64,
    root_rate_bytes: u64,
    queue_tokens: u64,
    queue_rate_bytes: u64,
    need_bytes: u64,
    now_ns: u64,
    require_queue_tokens: bool,
) -> Option<u64> {
    // #916: transparent root or transparent queue. When the
    // corresponding rate is 0 the bucket is always-full (see the
    // top-up fast path in `maybe_top_up_cos_root_lease` /
    // `maybe_top_up_cos_queue_lease`), so the wakeup-on-refill
    // question is meaningless. Treat the refill as 0 ns —
    // immediately runnable. Without these bypasses,
    // `cos_refill_ns_until(_, _, 0)` would return None and the
    // caller would skip parking, leaving the queue in a limbo
    // where it never wakes AND never drains.
    let root_refill_ns = if root_rate_bytes == 0 {
        0
    } else {
        cos_refill_ns_until(root_tokens, need_bytes, root_rate_bytes)?
    };
    let queue_refill_ns = if require_queue_tokens {
        if queue_rate_bytes == 0 {
            0
        } else {
            cos_refill_ns_until(queue_tokens, need_bytes, queue_rate_bytes)?
        }
    } else {
        0
    };
    let wake_ns = now_ns.saturating_add(root_refill_ns.max(queue_refill_ns));
    Some(cos_tick_for_ns(wake_ns).max(cos_tick_for_ns(now_ns).saturating_add(1)))
}

#[inline]
pub(in crate::afxdp) fn assign_local_dscp_rewrite(
    items: &mut VecDeque<TxRequest>,
    queue_dscp_rewrite: Option<u8>,
) {
    if queue_dscp_rewrite.is_none() {
        return;
    }
    for req in items.iter_mut() {
        req.dscp_rewrite = req.dscp_rewrite.or(queue_dscp_rewrite);
    }
}

#[inline]
fn assign_prepared_dscp_rewrite(
    items: &mut VecDeque<PreparedTxRequest>,
    queue_dscp_rewrite: Option<u8>,
) {
    if queue_dscp_rewrite.is_none() {
        return;
    }
    for req in items.iter_mut() {
        req.dscp_rewrite = req.dscp_rewrite.or(queue_dscp_rewrite);
    }
}

// #1331: restore_cos_local_items / restore_cos_prepared_items moved
// into queue_service/submit_local.rs and submit_prepared.rs
// respectively (each has exactly one caller, inside its owning
// variant arm). The *_inner companions remain in tx_completion (used
// by other call chains).

#[cfg(test)]
mod tests;
