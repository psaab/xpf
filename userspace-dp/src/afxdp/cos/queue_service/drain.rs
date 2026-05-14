use super::*;

// Drain stage of the worker CoS service pipeline. These four fns
// move items from the per-queue runtime structures into the worker's
// per-batch scratch buffers, ready for the kernel TX submission.
// FIFO variants serve queues that don't need flow-fairness; the
// _flow_fair variants implement MQFQ ordering across the per-flow
// buckets within a queue.

/// #1229 v7: per-bucket fair-share target for the cap-aware MQFQ
/// selector. `bucket_target = queue_bw / max(1, active_flow_buckets)`.
///
/// For non-flow-fair queues or queues without a configured
/// transmit_rate, returns u64::MAX (no cap, work-conserving fallback).
///
/// Sampled ONCE at drain-batch start; same value used for every
/// pop in the batch so the eligible-set is stable.
#[inline]
fn compute_drain_target_bps(queue: &CoSQueueRuntime) -> u64 {
    let Some(ff) = queue.flow_fair_state.as_ref() else {
        return u64::MAX;
    };
    // transmit_rate_bytes = 0 means "no shape configured"; preserve
    // the existing work-conserving behavior by disabling the cap.
    let rate_bytes = queue.config.transmit_rate_bytes;
    if rate_bytes == 0 {
        return u64::MAX;
    }
    // Convert bytes/sec → bits/sec. u128 intermediate avoids overflow
    // at 100+ Gbps configured rates; clamp to u64::MAX before narrowing
    // so extreme configured rates saturate rather than silently wrap.
    let queue_bw_bps = (rate_bytes as u128)
        .saturating_mul(8)
        .min(u64::MAX as u128) as u64;
    let denom = ff.active_flow_buckets.max(1) as u64;
    queue_bw_bps / denom
}

pub(in crate::afxdp) fn drain_exact_local_fifo_items_to_scratch(
    queue: &mut CoSQueueRuntime,
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<ExactLocalScratchTxRequest>,
    area: &MmapArea,
    root_budget: u64,
    secondary_budget: u64,
    queue_dscp_rewrite: Option<u8>,
) -> ExactCoSScratchBuild {
    debug_assert!(!queue.flow_fair());
    // #942: no V_min wiring needed here. This FIFO Local variant
    // runs only on `!flow_fair` queues per the debug_assert above.
    // shared_exact queues always have `flow_fair = queue.exact`
    // (per `promote_cos_queue_flow_fair`), so this path is
    // unreachable on shared_exact. V_min coordination is a
    // shared_exact-only concept.
    let mut remaining_root = root_budget;
    let mut remaining_secondary = secondary_budget;
    let mut index = 0usize;
    while scratch_local_tx.len() < TX_BATCH_SIZE {
        if free_tx_frames.is_empty() {
            break;
        }
        let mut drop_error: Option<(String, u64)> = None;
        let mut built = false;
        {
            let Some(front) = queue.hot.items.get(index) else {
                break;
            };
            let CoSPendingTxItem::Local(req) = front else {
                break;
            };
            let len = req.bytes.len() as u64;
            if remaining_root < len || remaining_secondary < len {
                break;
            }
            if req.bytes.len() > tx_frame_capacity() {
                drop_error = Some((
                    format!(
                        "local tx frame exceeds UMEM frame capacity: len={} cap={}",
                        req.bytes.len(),
                        tx_frame_capacity()
                    ),
                    len,
                ));
            } else {
                let Some(offset) = free_tx_frames.pop_front() else {
                    break;
                };
                if let Some(frame) =
                    unsafe { area.slice_mut_unchecked(offset as usize, req.bytes.len()) }
                {
                    frame.copy_from_slice(&req.bytes);
                    if let Some(dscp_rewrite) = req.dscp_rewrite.or(queue_dscp_rewrite) {
                        let _ = apply_dscp_rewrite_to_frame(frame, dscp_rewrite);
                    }
                    scratch_local_tx.push(ExactLocalScratchTxRequest {
                        offset,
                        len: req.bytes.len() as u32,
                    });
                    remaining_root = remaining_root.saturating_sub(len);
                    remaining_secondary = remaining_secondary.saturating_sub(len);
                    built = true;
                } else {
                    free_tx_frames.push_front(offset);
                    drop_error = Some((
                        format!(
                            "tx frame slice out of range: offset={offset} len={}",
                            req.bytes.len()
                        ),
                        len,
                    ));
                }
            }
        }
        if let Some((error, fallback_dropped_bytes)) = drop_error {
            // Error path only: remove the specific malformed item we just
            // examined. VecDeque::remove(index) is O(N), but this only runs for
            // oversized/out-of-range frames, never on the steady-state hot path.
            let dropped_bytes = match queue.hot.items.remove(index) {
                Some(CoSPendingTxItem::Local(req)) => req.bytes.len() as u64,
                Some(CoSPendingTxItem::Prepared(_)) | None => fallback_dropped_bytes,
            };
            return ExactCoSScratchBuild::Drop {
                error,
                dropped_bytes,
            };
        }
        if !built {
            break;
        }
        index += 1;
    }

    ExactCoSScratchBuild::Ready
}

pub(in crate::afxdp) fn drain_exact_local_items_to_scratch_flow_fair(
    queue: &mut CoSQueueRuntime,
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<(u64, TxRequest)>,
    area: &MmapArea,
    root_budget: u64,
    secondary_budget: u64,
    queue_dscp_rewrite: Option<u8>,
) -> ExactCoSScratchBuild {
    // #785 Phase 3 — Codex round-3 NEW-2 / Rust reviewer LOW:
    // clear the pop-snapshot stack at batch start. The bound
    // "at most TX_BATCH_SIZE snapshots live at once" (see
    // `FlowFairState::pop_snapshot_stack` doc) relies on each
    // batch drain starting from an empty stack; committed
    // submissions leave stale snapshots until some later event
    // (push_back or another rollback) happens to clear them.
    // Without this clear, drain-all teardown paths and
    // successful-commit chains can grow the stack unbounded.
    if let Some(ff) = queue.flow_fair_state.as_mut() {
        ff.pop_snapshot_stack.clear();
    }
    // #1229 v7: per-bucket fair-share cap = queue_bw / max(1,
    // active_flow_buckets). At iperf3 -P 12 scale (collisions rare,
    // ~12 active buckets), each bucket gets queue_bw/12 = per-flow
    // share. At 100K-flow scale, ~4096 active buckets each get
    // queue_bw/4096; per-flow share via TCP cwnd within bucket.
    // Pass to the cap-aware front/pop helpers so over-cap buckets
    // are deferred in favor of cooler ones.
    let target_bps = compute_drain_target_bps(queue);
    // #941 Work item D: drain-call preflight. If no free TX frames at
    // entry, return early WITHOUT consuming a suspension slot — that
    // way TX-ring-full no-progress drains don't burn the suspension
    // window.
    if free_tx_frames.is_empty() {
        return ExactCoSScratchBuild::Ready;
    }
    // #941 Work item D: consume one suspension slot for this drain
    // call. `suspended` persists for the entire loop body — every pop
    // sees the same suspension state, so a hard-cap-armed suspension
    // is honored across all cadence pops (1, 8, 16, ...) within this
    // drain.
    let suspended = cos_queue_v_min_consume_suspension(queue);
    let mut remaining_root = root_budget;
    let mut remaining_secondary = secondary_budget;
    let mut v_min_pop_count = 0u32;
    while scratch_local_tx.len() < TX_BATCH_SIZE {
        if free_tx_frames.is_empty() {
            break;
        }
        // #917 Phase 4: V_min check on drain-batch start (pop_count
        // transitions 0→1) and every K=8 pops thereafter. Throttle
        // = early break out of this queue's drain. The fast worker
        // moves on to next runnable queue (or exits the drain
        // entirely if all queues throttle); revisits this queue
        // next round when V_min has likely advanced.
        //
        // #941 Work item D: skip the V_min check entirely when this
        // drain is suspended (hard-cap previously armed).
        v_min_pop_count = v_min_pop_count.saturating_add(1);
        if !suspended && !cos_queue_v_min_continue(queue, v_min_pop_count) {
            break;
        }
        // #1229 v7: cap-aware front/pop. target_bps was sampled
        // once at drain-batch start; same value used for every
        // pop in the batch so the eligible-set is stable.
        let Some(front) = cos_queue_front_with_cap(queue, target_bps) else {
            break;
        };
        let len = match front {
            CoSPendingTxItem::Local(req) => req.bytes.len() as u64,
            CoSPendingTxItem::Prepared(_) => break,
        };
        if remaining_root < len || remaining_secondary < len {
            break;
        }
        let Some(CoSPendingTxItem::Local(mut req)) =
            cos_queue_pop_front_with_cap(queue, target_bps)
        else {
            break;
        };
        remaining_root = remaining_root.saturating_sub(len);
        remaining_secondary = remaining_secondary.saturating_sub(len);

        if let Some(dscp_rewrite) = queue_dscp_rewrite {
            req.dscp_rewrite = req.dscp_rewrite.or(Some(dscp_rewrite));
        }
        if let Some(dscp_rewrite) = req.dscp_rewrite {
            let _ = apply_dscp_rewrite_to_frame(&mut req.bytes, dscp_rewrite);
        }
        if req.bytes.len() > tx_frame_capacity() {
            // #913: clean up the orphan snapshot for this dropped
            // item. The matching pop pushed a snapshot; on Drop
            // we abandon the item, so the snapshot would
            // otherwise sit at the top of the stack and trip a
            // bucket-mismatch panic when the subsequent
            // restore_front push_fronts a different surviving
            // item. Codex code review (HIGH): also clamp
            // remaining snapshots' pre_pop_queue_vtime so
            // survivor restores preserve this dropped item's
            // committed vtime advance — see helper docstring.
            cos_queue_clear_orphan_snapshot_after_drop(queue);
            return ExactCoSScratchBuild::Drop {
                error: format!(
                    "local tx frame exceeds UMEM frame capacity: len={} cap={}",
                    req.bytes.len(),
                    tx_frame_capacity()
                ),
                dropped_bytes: len,
            };
        }
        let Some(offset) = free_tx_frames.pop_front() else {
            cos_queue_push_front(queue, CoSPendingTxItem::Local(req));
            break;
        };
        let Some(frame) = (unsafe { area.slice_mut_unchecked(offset as usize, req.bytes.len()) })
        else {
            free_tx_frames.push_front(offset);
            // #913: same orphan-snapshot cleanup as above (slice
            // failure path).
            cos_queue_clear_orphan_snapshot_after_drop(queue);
            return ExactCoSScratchBuild::Drop {
                error: format!(
                    "tx frame slice out of range: offset={offset} len={}",
                    req.bytes.len()
                ),
                dropped_bytes: len,
            };
        };
        frame.copy_from_slice(&req.bytes);
        scratch_local_tx.push((offset, req));
    }

    ExactCoSScratchBuild::Ready
}

pub(in crate::afxdp) fn drain_exact_prepared_fifo_items_to_scratch(
    queue: &mut CoSQueueRuntime,
    scratch_prepared_tx: &mut Vec<ExactPreparedScratchTxRequest>,
    area: &MmapArea,
    free_tx_frames: &mut VecDeque<u64>,
    pending_fill_frames: &mut VecDeque<u64>,
    slot: u32,
    shared_recycles: &mut Vec<(u32, u64)>,
    root_budget: u64,
    secondary_budget: u64,
    queue_dscp_rewrite: Option<u8>,
) -> ExactCoSScratchBuild {
    debug_assert!(!queue.flow_fair());
    // #942: no V_min wiring needed here. This FIFO Prepared variant
    // runs only on `!flow_fair` queues per the debug_assert above,
    // and shared_exact queues always have `flow_fair = queue.exact`
    // (per `promote_cos_queue_flow_fair`), so this path is
    // unreachable on shared_exact. V_min coordination is a
    // shared_exact-only concept; no participation needed.
    let mut remaining_root = root_budget;
    let mut remaining_secondary = secondary_budget;
    let mut index = 0usize;

    while scratch_prepared_tx.len() < TX_BATCH_SIZE {
        let mut drop_error: Option<(String, u64)> = None;
        let mut built = false;
        {
            let Some(front) = queue.hot.items.get(index) else {
                break;
            };
            let CoSPendingTxItem::Prepared(req) = front else {
                break;
            };
            let len = req.len as u64;
            if remaining_root < len || remaining_secondary < len {
                break;
            }
            if req.len as usize > tx_frame_capacity() {
                drop_error = Some((
                    format!(
                        "prepared tx frame exceeds UMEM frame capacity: len={} cap={}",
                        req.len,
                        tx_frame_capacity()
                    ),
                    len,
                ));
            } else {
                let valid = if let Some(dscp_rewrite) = req.dscp_rewrite.or(queue_dscp_rewrite) {
                    match unsafe { area.slice_mut_unchecked(req.offset as usize, req.len as usize) }
                    {
                        Some(frame) => {
                            let _ = apply_dscp_rewrite_to_frame(frame, dscp_rewrite);
                            true
                        }
                        None => false,
                    }
                } else {
                    area.slice(req.offset as usize, req.len as usize).is_some()
                };
                if !valid {
                    drop_error = Some((
                        format!(
                            "prepared tx frame slice out of range: offset={} len={}",
                            req.offset, req.len
                        ),
                        len,
                    ));
                } else {
                    scratch_prepared_tx.push(ExactPreparedScratchTxRequest {
                        offset: req.offset,
                        len: req.len,
                    });
                    remaining_root = remaining_root.saturating_sub(len);
                    remaining_secondary = remaining_secondary.saturating_sub(len);
                    built = true;
                }
            }
        }
        if let Some((error, fallback_dropped_bytes)) = drop_error {
            let dropped_bytes = match queue.hot.items.remove(index) {
                Some(CoSPendingTxItem::Prepared(req)) => {
                    recycle_cancelled_prepared_offset_with_shared(
                        free_tx_frames,
                        pending_fill_frames,
                        Some(shared_recycles),
                        slot,
                        req.recycle,
                        req.offset,
                    );
                    req.len as u64
                }
                Some(CoSPendingTxItem::Local(_)) | None => fallback_dropped_bytes,
            };
            return ExactCoSScratchBuild::Drop {
                error,
                dropped_bytes,
            };
        }
        if !built {
            break;
        }
        index += 1;
    }

    ExactCoSScratchBuild::Ready
}

pub(in crate::afxdp) fn drain_exact_prepared_items_to_scratch_flow_fair(
    queue: &mut CoSQueueRuntime,
    scratch_prepared_tx: &mut Vec<PreparedTxRequest>,
    area: &MmapArea,
    free_tx_frames: &mut VecDeque<u64>,
    pending_fill_frames: &mut VecDeque<u64>,
    slot: u32,
    shared_recycles: &mut Vec<(u32, u64)>,
    root_budget: u64,
    secondary_budget: u64,
    queue_dscp_rewrite: Option<u8>,
) -> ExactCoSScratchBuild {
    // #785 Phase 3 — Codex round-3 NEW-2 / Rust reviewer LOW:
    // clear the pop-snapshot stack at batch start. See the
    // matching comment in `drain_exact_local_items_to_scratch_flow_fair`
    // for the rationale — committed-submit chains or drain-all
    // teardowns can otherwise leave stale snapshots that violate
    // the documented TX_BATCH_SIZE bound.
    if let Some(ff) = queue.flow_fair_state.as_mut() {
        ff.pop_snapshot_stack.clear();
    }
    // #1229 v7: per-bucket fair-share cap (same compute as the Local
    // flow-fair drain above; mirror).
    let target_bps = compute_drain_target_bps(queue);
    let mut remaining_root = root_budget;
    let mut remaining_secondary = secondary_budget;
    // #942: V_min wiring on the Prepared flow-fair drain. Mirrors
    // the Local-flow pattern at `drain_exact_local_items_to_scratch_flow_fair`.
    //
    // The original attempt (commit eeade5e2 in #950) caused a severe
    // regression because peer slots held stale-low values that
    // throttled the heavy worker indefinitely. #941 (PR #952) added
    // bucket-empty vacate + hard-cap-with-suspension to make this
    // safe: a temporary smoke with the wiring confirmed iperf-c P=12 =
    // 23.1 Gb/s (clears the 22 Gb/s gate).
    //
    // Preflight (mirrors Local's `free_tx_frames.is_empty()` early-
    // return): if there is no Prepared item at the front of the queue,
    // return early WITHOUT consuming a suspension slot. This prevents
    // a no-progress Prepared drain (e.g. queue head is Local) from
    // eroding the hard-cap suspension window.
    match cos_queue_front_with_cap(queue, target_bps) {
        Some(CoSPendingTxItem::Prepared(_)) => {}
        _ => return ExactCoSScratchBuild::Ready,
    }
    // #942: consume one suspension slot for this drain call. The
    // `suspended` flag persists for the entire loop body so cadence
    // pops at pop_count=1, 8, 16, ... all see the same suspension
    // state. See `cos_queue_v_min_consume_suspension` doc.
    let suspended = cos_queue_v_min_consume_suspension(queue);
    let mut v_min_pop_count = 0u32;

    while scratch_prepared_tx.len() < TX_BATCH_SIZE {
        // #942: V_min check on the Prepared flow-fair drain path,
        // mirroring the Local-flow wiring. Same K=8 cadence with
        // mandatory check at pop_count==1 (drain-batch start).
        // Skipped entirely when the drain is suspended (#941 hard-cap).
        v_min_pop_count = v_min_pop_count.saturating_add(1);
        if !suspended && !cos_queue_v_min_continue(queue, v_min_pop_count) {
            break;
        }
        let Some(front) = cos_queue_front_with_cap(queue, target_bps) else {
            break;
        };
        let len = match front {
            CoSPendingTxItem::Prepared(req) => req.len as u64,
            CoSPendingTxItem::Local(_) => break,
        };
        if remaining_root < len || remaining_secondary < len {
            break;
        }
        let Some(CoSPendingTxItem::Prepared(mut req)) =
            cos_queue_pop_front_with_cap(queue, target_bps)
        else {
            break;
        };
        remaining_root = remaining_root.saturating_sub(len);
        remaining_secondary = remaining_secondary.saturating_sub(len);

        if let Some(dscp_rewrite) = queue_dscp_rewrite {
            req.dscp_rewrite = req.dscp_rewrite.or(Some(dscp_rewrite));
        }
        if req.len as usize > tx_frame_capacity() {
            recycle_cancelled_prepared_offset_with_shared(
                free_tx_frames,
                pending_fill_frames,
                Some(shared_recycles),
                slot,
                req.recycle,
                req.offset,
            );
            // #913: orphan snapshot cleanup with vtime preservation.
            // See helper docstring; same as local-builder
            // capacity-fail site.
            cos_queue_clear_orphan_snapshot_after_drop(queue);
            return ExactCoSScratchBuild::Drop {
                error: format!(
                    "prepared tx frame exceeds UMEM frame capacity: len={} cap={}",
                    req.len,
                    tx_frame_capacity()
                ),
                dropped_bytes: len,
            };
        }
        let valid = if let Some(dscp_rewrite) = req.dscp_rewrite {
            match unsafe { area.slice_mut_unchecked(req.offset as usize, req.len as usize) } {
                Some(frame) => {
                    let _ = apply_dscp_rewrite_to_frame(frame, dscp_rewrite);
                    true
                }
                None => false,
            }
        } else {
            area.slice(req.offset as usize, req.len as usize).is_some()
        };
        if !valid {
            recycle_cancelled_prepared_offset_with_shared(
                free_tx_frames,
                pending_fill_frames,
                Some(shared_recycles),
                slot,
                req.recycle,
                req.offset,
            );
            // #913: orphan snapshot cleanup with vtime preservation
            // (slice failure path). See helper docstring.
            cos_queue_clear_orphan_snapshot_after_drop(queue);
            return ExactCoSScratchBuild::Drop {
                error: format!(
                    "prepared tx frame slice out of range: offset={} len={}",
                    req.offset, req.len
                ),
                dropped_bytes: len,
            };
        }
        scratch_prepared_tx.push(req);
    }

    ExactCoSScratchBuild::Ready
}
