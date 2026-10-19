// Settlement stage of the worker CoS service pipeline: batch building
// from a selected queue, scratch-frame release/restore, submission
// settlement, and the quantum / wakeup helpers the selectors share.
// Extracted from queue_service/mod.rs (#13065, source finding D1-14),
// mirroring the drain.rs / service.rs / submit_*.rs layout (#1035 /
// #1331). Pure code motion: no logic changed.

use super::*;

pub(in crate::afxdp) fn release_exact_local_scratch_frames(
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<ExactLocalScratchTxRequest>,
) {
    while let Some(req) = scratch_local_tx.pop() {
        free_tx_frames.push_front(req.offset);
    }
}

pub(super) fn restore_exact_local_scratch_to_queue_head_flow_fair(
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

pub(super) fn restore_exact_prepared_scratch_to_queue_head_flow_fair(
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
    in_flight_untracked_tx: &mut FastSet<u64>,
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
            Some(CoSPendingTxItem::Local(mut req)) => {
                sent_packets += 1;
                sent_bytes += req.bytes.len() as u64;
                // #10285: the kernel accepted this desc — commit its overlap
                // admissions (drop without commit would fail them and pin the
                // entry until TTL, starving exact-queued fragments of reclaim).
                if let Some(mut admissions) = req.overlap_admissions.take() {
                    admissions.commit();
                }
                // #6310: the committed buffer's bytes were copied into a
                // UMEM TX frame during the drain build, so the buffer is
                // dead here. Return it to the per-worker pool that feeds
                // the cross-worker redirect copy (`cos::redirect_pool`).
                crate::afxdp::cos::redirect_pool::recycle(req.bytes);
            }
            Some(item) => {
                queue.hot.items.push_front(item);
                break;
            }
            None => break,
        }
    }
    // #9900 F-092 (GPT-2): the kernel accepted the `..sent` prefix — record
    // ownership for exactly those descs (the drain built them in ring order,
    // so the prefix is what `inserted` accepted).
    for req in scratch_local_tx.iter().take(sent) {
        in_flight_untracked_tx.insert(req.offset);
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
    in_flight_untracked_tx: &mut FastSet<u64>,
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
    while let Some((offset, mut req)) = scratch_local_tx.pop() {
        if scratch_local_tx.len() >= inserted {
            free_tx_frames.push_front(offset);
            cos_queue_push_front(queue, CoSPendingTxItem::Local(req));
        } else {
            // #10285: the kernel accepted this desc — commit its overlap
            // admissions before accounting/recycling the request.
            if let Some(mut admissions) = req.overlap_admissions.take() {
                admissions.commit();
            }
            // #9900 F-092 (GPT-2): kernel-accepted — record ownership.
            in_flight_untracked_tx.insert(offset);
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
            crate::afxdp::cos::redirect_pool::recycle(req.bytes);
        }
    }
    (sent_packets, sent_bytes)
}

pub(in crate::afxdp) fn settle_exact_prepared_fifo_submission(
    queue: Option<&mut CoSQueueRuntime>,
    scratch_prepared_tx: &mut Vec<ExactPreparedScratchTxRequest>,
    in_flight_prepared_recycles: &mut FastMap<u64, PreparedTxRecycle>,
    in_flight_untracked_tx: &mut FastSet<u64>,
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
            Some(CoSPendingTxItem::Prepared(mut req)) => {
                // #10285: exact prepared TX acceptance commits overlap
                // admissions; otherwise successful exact traffic remains
                // pinned until TTL.
                if let Some(mut admissions) = req.overlap_admissions.take() {
                    admissions.commit();
                }
                remember_prepared_recycle(
                    in_flight_prepared_recycles,
                    in_flight_untracked_tx,
                    &req,
                );
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

pub(super) fn settle_exact_prepared_scratch_submission_flow_fair(
    queue: Option<&mut CoSQueueRuntime>,
    scratch_prepared_tx: &mut Vec<PreparedTxRequest>,
    in_flight_prepared_recycles: &mut FastMap<u64, PreparedTxRecycle>,
    in_flight_untracked_tx: &mut FastSet<u64>,
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
    while let Some(mut req) = scratch_prepared_tx.pop() {
        if scratch_prepared_tx.len() >= inserted {
            cos_queue_push_front(queue, CoSPendingTxItem::Prepared(req));
        } else {
            // #10285: the kernel accepted this prepared exact request.
            if let Some(mut admissions) = req.overlap_admissions.take() {
                admissions.commit();
            }
            let bytes = req.len as u64;
            if let Some(ff) = queue.flow_fair_state.as_mut() {
                let bucket = cos_flow_bucket_index(flow_hash_seed, req.flow_key.as_ref()) as u16;
                account_flow_bucket_tx(ff, bucket, bytes, now_ns);
            }
            // #1829 Phase 1 (Codex review on PR #1846): committed-
            // prefix-only sojourn sample — see the Local settle above.
            queue.telemetry.sojourn.record(req.enqueue_ns, now_ns);
            remember_prepared_recycle(in_flight_prepared_recycles, in_flight_untracked_tx, &req);
            sent_packets += 1;
            sent_bytes += bytes;
        }
    }
    (sent_packets, sent_bytes)
}

#[inline]
pub(super) fn subtract_direct_cos_queue_bytes(
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
pub(super) fn build_cos_batch_from_queue(
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
    // #13062 (D1-04): this builder is not a non-exact-only path. It
    // also serves (a) lazily-promoted non-exact guaranteed queues
    // (#1735: `!exact && transmit_rate_bytes > 0`), whose per-packet
    // `account_flow_bucket_tx` in submit_local / submit_prepared
    // maintains `flow_bucket_observed_bps` at real CPU cost, and (b)
    // `shared_exact` queues with `surplus_sharing == true` (#915) in
    // Phase 3 (`CoSServicePhase::Surplus` via
    // `select_cos_surplus_batch_filtered`). The pre-fix `u64::MAX`
    // hardcode made #1229 v7 cap-aware bucket selection dead code on
    // (a) — elephant buckets were never deferred on this path — and
    // bypassed BOTH the #1229 v7 cap and the #917 V_min cross-worker
    // lag brake on (b), while `apply_cos_*_result` still published the
    // unthrottled `queue_vtime` to `vtime_floor`: a surplus-draining
    // worker could run arbitrarily far ahead of its peers without ever
    // tripping the lag brake.
    //
    // Fix: sample the per-flow fair-share target ONCE per build (same
    // stable-eligible-set contract as drain.rs) and thread it into the
    // cap-aware peek/pop. `compute_drain_target_bps` returns
    // `u64::MAX` for non-flow-fair or unshaped queues, so best-effort
    // and unshaped builds keep byte-identical selection.
    let target_bps = compute_drain_target_bps(queue);
    match head {
        CoSPendingTxItem::Local(_) => {
            local_scratch.clear();
            // #941 Work item D analog: consume one suspension slot for
            // this build call, AFTER the empty-queue preflight above
            // (drain.rs consumes after its free-frame preflight for the
            // same no-progress reason). `suspended` persists for the
            // whole loop so every cadence pop sees the same state.
            let suspended = cos_queue_v_min_consume_suspension(queue);
            let mut remaining_root = root_budget;
            let mut remaining_secondary = secondary_budget;
            let mut batch_bytes = 0u64;
            while local_scratch.len() < TX_BATCH_SIZE {
                // #917 Phase 4 (#13062 / D1-04): V_min gate before the
                // peek, mirroring drain_exact_local_items_to_scratch_
                // flow_fair. `cos_queue_v_min_continue` self-gates to a
                // no-op unless the queue is shared_exact AND shaped AND
                // floored, so non-exact / best-effort builds are
                // unaffected. The candidate counter persists across
                // builds; the commit is deferred to the confirmed pop
                // (#2646 — a throttled or budget-missed break must not
                // burn a cadence position).
                let candidate_pop_count = queue.v_min.v_min_pop_count.wrapping_add(1);
                if !suspended && !cos_queue_v_min_continue(queue, candidate_pop_count) {
                    break;
                }
                // #1763 Lever A — fused select+pop. Peek returns the
                // cap-aware min-finish bucket id (#1229 v7 via the
                // once-per-build `target_bps`); if we commit to popping,
                // reuse that exact bucket (no re-scan). No queue
                // mutation occurs between peek and the matching pop, so
                // the selected bucket is byte-identical to a re-scan.
                let Some((bucket, front)) = cos_queue_peek_min_bucket(queue, target_bps) else {
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
                match cos_queue_pop_known_bucket(queue, bucket, target_bps) {
                    Some(CoSPendingTxItem::Local(req)) => {
                        // #2646: pop confirmed — advance the cadence
                        // counter now; the breaks above did not.
                        queue.v_min.v_min_pop_count = candidate_pop_count;
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
            // #941 Work item D analog (Prepared arm): same post-
            // preflight suspension consume as the Local arm above.
            let suspended = cos_queue_v_min_consume_suspension(queue);
            let mut remaining_root = root_budget;
            let mut remaining_secondary = secondary_budget;
            let mut batch_bytes = 0u64;
            while prepared_scratch.len() < TX_BATCH_SIZE {
                // #917 Phase 4 (#13062 / D1-04): V_min gate before the
                // peek, mirroring drain_exact_prepared_items_to_scratch_
                // flow_fair (and the Local arm above). Same self-gating
                // and #2646 deferred-counter contract.
                let candidate_pop_count = queue.v_min.v_min_pop_count.wrapping_add(1);
                if !suspended && !cos_queue_v_min_continue(queue, candidate_pop_count) {
                    break;
                }
                // #1763 Lever A — fused select+pop (Prepared arm, now
                // cap-aware via `target_bps`). See the Local arm above
                // for the no-mutation invariant.
                let Some((bucket, front)) = cos_queue_peek_min_bucket(queue, target_bps) else {
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
                match cos_queue_pop_known_bucket(queue, bucket, target_bps) {
                    Some(CoSPendingTxItem::Prepared(req)) => {
                        // #2646: pop confirmed — advance the cadence
                        // counter now; the breaks above did not.
                        queue.v_min.v_min_pop_count = candidate_pop_count;
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
pub(super) fn submit_cos_batch(
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
    // #15100 (A70-02): park-aware demand scheduling. Only a queue that
    // is actually short of `need_bytes` is parked, and only for its
    // own deficit refill time (`cos_refill_ns_until` already returns
    // Some(0) when tokens cover the need — the `queue_tokens >=
    // need_bytes` case below makes that contract explicit so a
    // future helper change cannot reintroduce a full-frame park for
    // a queue that is already serviceable). Transparent (rate 0)
    // queues keep the #916 bypass.
    let queue_refill_ns = if require_queue_tokens {
        if queue_rate_bytes == 0 || queue_tokens >= need_bytes {
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
pub(super) fn assign_prepared_dscp_rewrite(
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
