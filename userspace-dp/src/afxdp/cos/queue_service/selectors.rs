// Selection stage of the worker CoS service pipeline: the guarantee,
// exact, non-exact, and surplus selectors that pick the next queue (or
// batch) for service. Extracted from queue_service/mod.rs (#13065,
// source finding D1-14), mirroring the drain.rs / service.rs /
// submit_*.rs layout (#1035 / #1331). The GuaranteeRate waterfill walk
// lives in waterfill.rs; batch building and settlement live in
// settle.rs. Pure code motion: no logic changed.

use super::*;

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
pub(super) fn select_exact_cos_guarantee_queue_with_lease_telemetry(
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
pub(super) fn select_cos_surplus_batch_filtered(
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
