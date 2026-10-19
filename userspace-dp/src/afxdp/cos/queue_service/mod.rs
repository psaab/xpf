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
use crate::afxdp::{FastMap, FastSet, TX_BATCH_SIZE, tx_frame_capacity};
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
// #13062 (D1-04): shared with build_cos_batch_from_queue so the
// non-exact / surplus batch-build path honors the same #1229 v7
// per-bucket fair-share cap as the exact drains.
use drain::compute_drain_target_bps;

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

// #13065 (D1-14): selection, waterfill, and settlement stages split
// into flat sibling files, mirroring drain.rs / service.rs /
// submit_*.rs. mod.rs keeps the shared batch/selection types and the
// drain_shaped_tx orchestration. Pure code motion: no logic changed.
mod selectors;
mod settle;
mod waterfill;

use selectors::{
    select_cos_surplus_batch_filtered, select_exact_cos_guarantee_queue_with_lease_telemetry,
    select_nonexact_cos_guarantee_batch_into,
};
#[cfg(test)]
pub(in crate::afxdp) use settle::estimate_cos_queue_wakeup_tick as estimate_cos_queue_wakeup_tick_for_test;
use settle::{
    assign_local_dscp_rewrite, assign_prepared_dscp_rewrite, build_cos_batch_from_queue,
    cos_batch_tx_made_progress, cos_guarantee_quantum_bytes, cos_guarantee_visit_cap_bytes,
    cos_surplus_quantum_bytes, estimate_cos_queue_wakeup_tick, release_exact_local_scratch_frames,
    release_exact_prepared_scratch, restore_exact_local_scratch_to_queue_head_flow_fair,
    restore_exact_prepared_scratch_to_queue_head_flow_fair,
    settle_exact_prepared_scratch_submission_flow_fair, submit_cos_batch,
    subtract_direct_cos_queue_bytes,
};
pub(in crate::afxdp) use settle::{
    settle_exact_local_fifo_submission, settle_exact_local_scratch_submission_flow_fair,
    settle_exact_prepared_fifo_submission,
};
use waterfill::{
    defer_v_min_skipped_waterfill_queue, refund_phase1_waterfill_honor,
    select_exact_cos_guarantee_queue_waterfill,
};

#[cfg(test)]
pub(in crate::afxdp) use selectors::{
    select_cos_guarantee_batch, select_cos_guarantee_batch_with_fast_path,
    select_exact_cos_guarantee_queue_with_fast_path,
};
#[cfg(test)]
use selectors::{select_cos_surplus_batch, select_nonexact_cos_guarantee_batch};
#[cfg(test)]
use waterfill::apply_phase1_waterfill_honor_refund;

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
    /// `waterfill_honored_epoch_bits`; used to clear that honor on refund.
    bit_ordinal: usize,
}

pub(in crate::afxdp) enum ExactCoSScratchBuild {
    Ready,
    Drop {
        error: String,
        dropped_bytes: u64,
    },
    /// The first pop was withheld by the queue-local cross-worker brake;
    /// unlike `Ready` with empty scratch, another queue may still send.
    VMinSkipped,
    MirrorTxFrameReserve {
        dropped_bytes: u64,
    },
}

/// A queue-local V_min brake is not an interface-wide TX failure.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ExactServiceOutcome {
    Sent,
    VMinSkipped,
    NoProgress,
}

impl From<bool> for ExactServiceOutcome {
    #[inline]
    fn from(progress: bool) -> Self {
        if progress {
            Self::Sent
        } else {
            Self::NoProgress
        }
    }
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

/// #751: variant that additionally reports which queue was actually
/// serviced so the caller can attribute per-queue drain latency.
///   * `Some(Some(ref))` — exact-guarantee selection made TX progress.
///   * `Some(None)` — an exact service attempt made no TX progress for a
///     reason other than V_min (preserving the Phase-1 honor refund).
///   * `None` — no exact selection, or all selected queues were V_min
///     throttled; caller falls through to non-exact service.
#[inline]
fn service_exact_guarantee_queue_direct_with_info(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
    lease_telemetry: &mut CoSQueueLeaseAcquireTelemetry,
) -> Option<Option<DrainedQueueRef>> {
    // A V_min skip affects only the selected queue. Try at most one visit
    // per queue, then allow non-exact queues (and other interfaces) to run.
    for _ in 0..binding.cos.cos_interfaces.get(&root_ifindex)?.queues.len() {
        let selection = {
            let queue_fast_path = binding
                .cos
                .cos_fast_interfaces
                .get(&root_ifindex)?
                .queue_fast_path
                .as_slice();
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

        let outcome = match selection.kind {
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
        match outcome {
            ExactServiceOutcome::Sent => {
                return Some(queue_id.map(|queue_id| DrainedQueueRef {
                    root_ifindex,
                    queue_idx: selection.queue_idx,
                    queue_id,
                }));
            }
            ExactServiceOutcome::NoProgress => {
                if let Some(refund) = selection.phase1_honor {
                    refund_phase1_waterfill_honor(
                        binding,
                        root_ifindex,
                        selection.queue_idx,
                        refund,
                    );
                }
                return Some(None);
            }
            ExactServiceOutcome::VMinSkipped => {
                if let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) {
                    defer_v_min_skipped_waterfill_queue(root, &selection);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests;
