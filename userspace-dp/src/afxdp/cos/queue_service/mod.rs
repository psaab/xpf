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
    CoSQueueRuntime, ExactLocalScratchTxRequest, ExactPreparedScratchTxRequest, PreparedTxRecycle,
    PreparedTxRequest, SharedCoSExactBacklog, TxRequest, WorkerCoSQueueFastPath,
};
use crate::afxdp::umem::MmapArea;
use crate::afxdp::worker::BindingWorker;
use crate::afxdp::{FastMap, TX_BATCH_SIZE, tx_frame_capacity};
use crate::xsk_ffi::xdp::XdpDesc;

use super::{
    COS_MIN_BURST_BYTES, CoSQueueLeaseAcquireTelemetry, cos_item_len,
    cos_queue_clear_orphan_snapshot_after_drop, cos_queue_front, cos_queue_front_with_cap,
    cos_queue_is_empty, cos_queue_pop_front, cos_queue_pop_front_with_cap, cos_queue_push_front,
    cos_queue_v_min_consume_suspension, cos_queue_v_min_continue, cos_refill_ns_until,
    maybe_top_up_cos_queue_lease, publish_committed_queue_vtime, refill_cos_tokens,
};
// #1229 v7 per-bucket TX accounting + threshold-gated EWMA.
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
    COS_SURPLUS_ROUND_QUANTUM_BYTES, TxError, cos_queue_dscp_rewrite, maybe_wake_tx,
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
    let shared_exact_backlog = binding
        .cos
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_exact_backlog.clone());
    let peer_exact_demand_mask = shared_exact_backlog
        .as_ref()
        .map(|backlog| backlog.peer_exact_demand_queue_mask(binding.slot))
        .unwrap_or(0);
    let selected = {
        let root = binding.cos.cos_interfaces.get_mut(&root_ifindex)?;
        select_nonexact_cos_guarantee_batch(root, now_ns).or_else(|| {
            // Strict priority applies to surplus service only. Non-exact
            // queues with explicit transmit-rate guarantees keep their
            // guarantee pass. Residual/best-effort surplus remains
            // work-conserving, but while exact queues are backlogged it may
            // consume only the residual root rate after backlogged exact
            // guarantee rates are reserved.
            let exact_demand_mask = root_exact_demand_queue_mask(root) | peer_exact_demand_mask;
            let exact_demand_rate = exact_demand_rate_bytes_for_mask(root, exact_demand_mask);
            let nonexact_budget = nonexact_surplus_budget_under_exact_demand(
                root,
                now_ns,
                exact_demand_rate,
                shared_exact_backlog.as_deref(),
            );
            select_cos_surplus_batch_filtered(root, now_ns, true, nonexact_budget)
        })
    };
    if selected.is_some() {
        refresh_cos_interface_activity(binding, root_ifindex);
    }
    selected
}

#[inline]
fn root_exact_demand_queue_mask(root: &CoSInterfaceRuntime) -> u64 {
    root.queues
        .iter()
        .enumerate()
        .filter(|(_, queue)| {
            queue.config.exact && queue.config.guarantee_enabled && !cos_queue_is_empty(queue)
        })
        .fold(0u64, |acc, (queue_idx, _)| {
            if queue_idx < u64::BITS as usize {
                acc | (1u64 << queue_idx)
            } else {
                u64::MAX
            }
        })
}

#[inline]
fn exact_demand_rate_bytes_for_mask(root: &CoSInterfaceRuntime, exact_demand_mask: u64) -> u64 {
    if exact_demand_mask == 0 {
        return 0;
    }
    root.queues
        .iter()
        .enumerate()
        .filter(|(queue_idx, queue)| {
            queue.config.exact
                && queue.config.guarantee_enabled
                && (*queue_idx >= u64::BITS as usize
                    || (exact_demand_mask & (1u64 << *queue_idx)) != 0)
        })
        .fold(0u64, |acc, (_, queue)| {
            acc.saturating_add(queue.transmit_rate_bytes())
        })
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
    // mode falls through to the legacy round-robin selector below,
    // bit-for-bit unchanged when priority_low_min_share_bytes == 0
    // (see service_exact_guarantee_queue_direct_with_info for the
    // cap_eff subtraction that handles priority-low orthogonality
    // per AGY r3 finding B).
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
//     in the current epoch. Initialized lazily to
//     `(quantum_sum × guarantee_fraction).floor()` whenever it's
//     zero on entry (one full epoch == one full ascending walk +
//     one descending Phase 2 walk).
//   - `waterfill_phase2_cursor`: where Phase 2's descending walk
//     last stopped; lets the selector resume on subsequent calls.
//
// Each call returns ONE queue selection. The selector first tries
// Phase 1 (ascending walk; each selection decrements
// `pass1_remaining` by the chosen queue's secondary_budget). When
// Phase 1 has insufficient budget for the next ascending queue,
// the selector enters Phase 2 (descending walk through queues
// NOT honored in Phase 1). When Phase 2 exhausts, the epoch
// resets and Phase 1 budget is refilled.
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
    // Phase 1 epoch refill: when `pass1_remaining` is zero we're
    // either at first call OR just completed an epoch. Compute the
    // new budget from `quantum_sum × fraction`. quantum_sum is
    // taken over the current eligible set (runnable + nonempty)
    // so a transiently empty queue doesn't inflate the budget
    // it would consume.
    if root.waterfill_pass1_remaining_bytes == 0 {
        let mut quantum_sum: u64 = 0;
        for &qi in &root.exact_queues_by_rate_ascending {
            quantum_sum =
                quantum_sum.saturating_add(cos_guarantee_quantum_bytes(&root.queues[qi]));
        }
        // fraction is clamped 0.0..1.0 at config-apply time; here
        // we use f64 → u64 with saturating cast guarded by the
        // multiplication via f64. The result fits in u64 because
        // quantum_sum ≤ 512 KB × N_queues and fraction ≤ 1.0.
        let frac = root.oversubscription_guarantee_fraction;
        let pass1 = ((quantum_sum as f64) * frac).floor() as u64;
        root.waterfill_pass1_remaining_bytes = pass1;
        root.waterfill_phase2_cursor = 0;
    }
    // Phase 1: ascending-rate walk. Pick the first runnable queue
    // whose secondary_budget ≤ pass1_remaining. Tracks honored
    // queues via a bitmask so Phase 2 can skip them. (Bitmask is
    // safe up to 64 exact queues; deployments well below that.)
    let mut honored_mask: u64 = 0;
    let sorted_indices: Vec<usize> = root.exact_queues_by_rate_ascending.clone();
    for queue_idx in &sorted_indices {
        let queue_idx = *queue_idx;
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
        // ordering and the `quantum_sum × fraction` Phase-1 budget
        // remain consistent with `oversubscription_guarantee_fraction`.
        // The actual per-visit send budget (`send_budget`) is the
        // FRAME-count cap so a queue whose token bucket has banked
        // several frames (#1630 P1) drains them whole instead of
        // discarding the sub-frame remainder of the small quantum.
        let phase1_cost = queue
            .hot
            .tokens
            .min(cos_guarantee_quantum_bytes(queue))
            .max(head_len);
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
            // be honored. Fall through to Phase 2 (descending
            // walk over queues NOT in honored_mask).
            break;
        }
        // Phase 1 honor: consume the budget, mark honored, return.
        root.waterfill_pass1_remaining_bytes = root
            .waterfill_pass1_remaining_bytes
            .saturating_sub(phase1_cost);
        if queue_idx < 64 {
            honored_mask |= 1u64 << queue_idx;
        }
        root.exact_guarantee_rr = (queue_idx + 1) % queue_count;
        let kind = match head {
            CoSPendingTxItem::Local(_) => ExactCoSQueueKind::Local,
            CoSPendingTxItem::Prepared(_) => ExactCoSQueueKind::Prepared,
        };
        return Some(ExactCoSQueueSelection {
            queue_idx,
            secondary_budget: send_budget,
            kind,
        });
    }
    // Phase 2: descending-rate walk over queues NOT honored above.
    // honored_mask is empty on this call (we returned on Phase 1
    // success), so we must rely on the persistent honored set: a
    // queue is "honored already this epoch" iff
    // pass1_remaining_bytes < its quantum_bytes (its visit was
    // skipped this iteration). We approximate by walking
    // descending and picking the largest queue whose tokens can
    // sustain a send; this matches the plan's "residual
    // distributed proportionally to larger queues" intent.
    let mut phase2_idx = root.waterfill_phase2_cursor;
    if phase2_idx >= sorted_indices.len() {
        phase2_idx = 0;
    }
    let start_phase2 = phase2_idx;
    // Walk descending starting from the cursor position
    // (interpreted as "position in the descending walk"). Use a
    // bounded loop to avoid scanning forever.
    for _step in 0..sorted_indices.len() {
        // Map cursor → descending iteration: sorted_indices is
        // ascending, so index from the END.
        let pos_from_end = sorted_indices.len() - 1 - phase2_idx;
        let queue_idx = sorted_indices[pos_from_end];
        // Skip queues honored above (bitmask check; safe to skip
        // even when bitmask is stale, this just defers their
        // service one round).
        if queue_idx < 64 && (honored_mask & (1u64 << queue_idx)) != 0 {
            phase2_idx = (phase2_idx + 1) % sorted_indices.len();
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
            phase2_idx = (phase2_idx + 1) % sorted_indices.len();
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
            phase2_idx = (phase2_idx + 1) % sorted_indices.len();
            if phase2_idx == start_phase2 {
                break;
            }
            continue;
        };
        let head_len = cos_item_len(head);
        if root.tokens < head_len || queue.hot.tokens < head_len {
            // Don't park in Phase 2 — the queue may legitimately
            // wait for next epoch. The legacy selector parks; we
            // skip silently here because Phase 2 service is
            // best-effort residual, not a guarantee.
            phase2_idx = (phase2_idx + 1) % sorted_indices.len();
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
        root.waterfill_phase2_cursor = (phase2_idx + 1) % sorted_indices.len();
        root.exact_guarantee_rr = (queue_idx + 1) % queue_count;
        let kind = match head {
            CoSPendingTxItem::Local(_) => ExactCoSQueueKind::Local,
            CoSPendingTxItem::Prepared(_) => ExactCoSQueueKind::Prepared,
        };
        return Some(ExactCoSQueueSelection {
            queue_idx,
            secondary_budget: candidate_budget,
            kind,
        });
    }
    // Epoch exhausted: nothing serviced. Reset Phase 1 budget
    // for next call (lazy refill above will recompute).
    root.waterfill_pass1_remaining_bytes = 0;
    root.waterfill_phase2_cursor = 0;
    None
}

// Selects the next non-exact guarantee queue for service. Rotates
// independently of the exact pass via `nonexact_guarantee_rr` — a service
// event on an exact queue does not advance this cursor, so non-exact RR
// order is stable across bursts of exact-queue activity.
#[inline]
pub(in crate::afxdp) fn select_nonexact_cos_guarantee_batch(
    root: &mut CoSInterfaceRuntime,
    now_ns: u64,
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
        let transmit_rate_bytes = queue.transmit_rate_bytes();
        refill_cos_tokens(
            &mut queue.hot.tokens,
            transmit_rate_bytes,
            queue.config.buffer_bytes.max(COS_MIN_BURST_BYTES),
            &mut queue.hot.last_refill_ns,
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
        ) {
            return Some(batch);
        }
    }
    None
}

#[inline]
pub(in crate::afxdp) fn select_cos_surplus_batch(
    root: &mut CoSInterfaceRuntime,
    now_ns: u64,
) -> Option<CoSBatch> {
    select_cos_surplus_batch_filtered(root, now_ns, true, None)
}

#[inline]
fn select_cos_surplus_batch_filtered(
    root: &mut CoSInterfaceRuntime,
    now_ns: u64,
    allow_nonexact: bool,
    nonexact_surplus_budget: Option<u64>,
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
        scratch_local_tx.clear();
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
        scratch_local_tx.clear();
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
            sent_packets += 1;
            sent_bytes += bytes;
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
fn build_cos_batch_from_queue(
    queue: &mut CoSQueueRuntime,
    queue_idx: usize,
    root_budget: u64,
    secondary_budget: u64,
    phase: CoSServicePhase,
) -> Option<CoSBatch> {
    let head = cos_queue_front(queue)?;
    match head {
        CoSPendingTxItem::Local(_) => {
            let mut items = VecDeque::new();
            let mut remaining_root = root_budget;
            let mut remaining_secondary = secondary_budget;
            let mut batch_bytes = 0u64;
            while items.len() < TX_BATCH_SIZE {
                let Some(front) = cos_queue_front(queue) else {
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
                match cos_queue_pop_front(queue) {
                    Some(CoSPendingTxItem::Local(req)) => {
                        batch_bytes = batch_bytes.saturating_add(len);
                        items.push_back(req);
                    }
                    Some(other) => {
                        cos_queue_push_front(queue, other);
                        break;
                    }
                    None => break,
                }
            }
            if items.is_empty() {
                None
            } else {
                Some(CoSBatch::Local {
                    queue_idx,
                    phase,
                    batch_bytes,
                    items,
                })
            }
        }
        CoSPendingTxItem::Prepared(_) => {
            let mut items = VecDeque::new();
            let mut remaining_root = root_budget;
            let mut remaining_secondary = secondary_budget;
            let mut batch_bytes = 0u64;
            while items.len() < TX_BATCH_SIZE {
                let Some(front) = cos_queue_front(queue) else {
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
                match cos_queue_pop_front(queue) {
                    Some(CoSPendingTxItem::Prepared(req)) => {
                        batch_bytes = batch_bytes.saturating_add(len);
                        items.push_back(req);
                    }
                    Some(other) => {
                        cos_queue_push_front(queue, other);
                        break;
                    }
                    None => break,
                }
            }
            if items.is_empty() {
                None
            } else {
                Some(CoSBatch::Prepared {
                    queue_idx,
                    phase,
                    batch_bytes,
                    items,
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

/// #1630 (P2): per-VISIT budget cap for guarantee-phase service.
///
/// The selectors previously clamped each visit's `secondary_budget` to
/// `cos_guarantee_quantum_bytes` (= `rate × 200 µs`). For a low-rate
/// class that quantum (e.g. 2500 B for 100 Mbps) is below two MTUs, so
/// the drain sent one frame and DISCARDED the sub-frame remainder every
/// visit — a per-visit efficiency ceiling that rose with the configured
/// rate (100m → ~60 %, 1g → ~96 %, ≥3g → ~100 %) and, under saturation,
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
/// fairness across queues. The long-run rate is unchanged — it is
/// metered by `queue.hot.tokens` (refilled at the configured rate via
/// the v8 lease) and the actual-byte debit in tx_completion.
#[inline]
pub(in crate::afxdp) fn cos_guarantee_visit_cap_bytes() -> u64 {
    // #1630 §3.6 MEASUREMENT PROBE (throwaway): P2 is compile-time
    // selected via the XPF_COS_P2 env at build time (matching XPF_COS_K)
    // so the baked binary needs no runtime env on the daemon. P2 ON =
    // frame-count cap; OFF returns u64::MAX so the call-site
    // `.min(tokens)` ignores it and the per-visit send budget reverts to
    // the token bucket alone (the phase1_cost / quantum gate is untouched
    // by this helper).
    if P2_FRAME_CAP_ON {
        (TX_BATCH_SIZE as u64) * (tx_frame_capacity() as u64)
    } else {
        u64::MAX
    }
}

/// #1630 §3.6 MEASUREMENT PROBE (throwaway): P2 frame-count cap enabled
/// when XPF_COS_P2 is set to a non-empty, non-"0" string at build time.
const P2_FRAME_CAP_ON: bool = match option_env!("XPF_COS_P2") {
    None => false,
    Some(s) => !s.is_empty() && !matches!(s.as_bytes(), [b'0']),
};

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
#[path = "tests.rs"]
mod tests;
