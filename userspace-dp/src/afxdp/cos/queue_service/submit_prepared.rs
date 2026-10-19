// #1331: Prepared-variant submit handler extracted verbatim from
// the CoSBatch::Prepared arm of submit_cos_batch (mod.rs
// pre-refactor L1298-L1402). Pure code motion.
use super::*;

#[inline]
pub(super) fn submit_prepared(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    phase: CoSServicePhase,
    batch_bytes: u64,
    mut items: VecDeque<PreparedTxRequest>,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> bool {
    assign_prepared_dscp_rewrite(
        &mut items,
        cos_queue_dscp_rewrite(binding, root_ifindex, queue_idx),
    );
    // #1229 v7: pre-transmit sidecar (same shape as Local
    // path — transmit_prepared_queue consumes the successful
    // prefix in-place). Stack array avoids per-batch
    // allocation; only populated for flow-fair queues.
    let prepared_seed_opt = binding
        .cos
        .cos_interfaces
        .get(&root_ifindex)
        .and_then(|root| root.queues.get(queue_idx))
        .and_then(|q| q.flow_fair_state.as_ref())
        .map(|ff| ff.flow_hash_seed);
    let mut sidecar = [(0u16, 0u64); TX_BATCH_SIZE];
    let sidecar_len = if let Some(seed) = prepared_seed_opt {
        let mut n = 0usize;
        for req in items.iter().take(TX_BATCH_SIZE) {
            sidecar[n] = (
                cos_flow_bucket_index(seed, req.flow_key.as_ref()) as u16,
                req.len as u64,
            );
            n += 1;
        }
        n
    } else {
        0
    };
    // #1829 Phase 1 (Codex review on PR #1846): unconditional
    // enqueue_ns sidecar for committed-prefix-only sojourn sampling —
    // see the matching comment in submit_local.rs.
    let mut enq_sidecar = [0u64; TX_BATCH_SIZE];
    let enq_len = {
        let mut n = 0usize;
        for req in items.iter().take(TX_BATCH_SIZE) {
            enq_sidecar[n] = req.enqueue_ns;
            n += 1;
        }
        n
    };
    // #4973: capture the batch outcome so the drained `items` deque can be
    // stored back into the per-worker Prepared batch scratch after the match,
    // retaining the ring-buffer allocation `build_cos_batch_from_queue` reused.
    let made_progress = match transmit_prepared_queue(binding, &mut items, now_ns, shared_recycles)
    {
        Ok((packets, bytes)) => {
            // #15786: snapshot the committed identities (ORIGINAL-input
            // positions actually shipped) into a local fixed array
            // BEFORE the mutable borrows below. A per-frame validation
            // drop is an interior removal, so the committed set is no
            // longer a prefix — charge through THESE indices, not
            // `sidecar[..packets]`.
            let mut committed = [0u16; TX_BATCH_SIZE];
            let committed_len = {
                let src = &binding.scratch.scratch_prepared_committed_orig_idx;
                let n = src.len().min(TX_BATCH_SIZE);
                committed[..n].copy_from_slice(&src[..n]);
                n
            };
            debug_assert_eq!(
                committed_len, packets as usize,
                "prepared committed identity count must equal the transmitted packet count",
            );
            // #15786: remove validation-drop orphan snapshots BEFORE
            // apply restores the retry tail — its LIFO push_fronts must
            // consume survivor snapshots, not a dropped frame's.
            let (dropped, dropped_len) = dropped_prepared_positions(binding);
            if dropped_len > 0 {
                if let Some(queue) = binding
                    .cos
                    .cos_interfaces
                    .get_mut(&root_ifindex)
                    .and_then(|root| root.queues.get_mut(queue_idx))
                {
                    remove_dropped_prepared_snapshots(queue, &dropped[..dropped_len], items.len());
                }
            }
            items = apply_cos_prepared_result(
                binding,
                root_ifindex,
                queue_idx,
                phase,
                batch_bytes,
                bytes,
                items,
            );
            if committed_len > 0 && sidecar_len > 0 {
                if let Some(ff) = binding
                    .cos
                    .cos_interfaces
                    .get_mut(&root_ifindex)
                    .and_then(|root| root.queues.get_mut(queue_idx))
                    .and_then(|q| q.flow_fair_state.as_mut())
                {
                    for &oi in &committed[..committed_len] {
                        let oi = oi as usize;
                        if oi < sidecar_len {
                            let (bucket, bytes) = sidecar[oi];
                            account_flow_bucket_tx(ff, bucket, bytes, now_ns);
                        }
                    }
                }
            }
            // #1829 + #15786: committed-only sojourn samples by
            // ORIGINAL identity (see the sidecar comment above).
            if committed_len > 0 {
                if let Some(queue) = binding
                    .cos
                    .cos_interfaces
                    .get_mut(&root_ifindex)
                    .and_then(|root| root.queues.get_mut(queue_idx))
                {
                    for &oi in &committed[..committed_len] {
                        let oi = oi as usize;
                        if oi < enq_len {
                            queue.telemetry.sojourn.record(enq_sidecar[oi], now_ns);
                        }
                    }
                }
            }
            if packets > 0 {
                binding
                    .live
                    .tx_packets
                    .fetch_add(packets, Ordering::Relaxed);
                binding.live.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
                // #760 instrumentation, Prepared path (the
                // in-place-rewrite hot path). See umem.rs
                // field comment.
                binding
                    .live
                    .owner_profile_owner
                    .drain_sent_bytes_shaped_unconditional
                    .fetch_add(bytes, Ordering::Relaxed);
            }
            // #hb166 T-6(e): publish the committed queue_vtime on the
            // Prepared CoSBatch settle boundary too — see the matching
            // block + rationale in submit_local.rs. No-op for
            // non-flow-fair / non-shared queues.
            publish_committed_queue_vtime(
                binding
                    .cos
                    .cos_interfaces
                    .get(&root_ifindex)
                    .and_then(|root| root.queues.get(queue_idx)),
            );
            cos_batch_tx_made_progress(Ok((packets, bytes)))
        }
        Err(TxError::Retry(reason)) => {
            // #4971: expected TX backpressure — lock-free status, no
            // `last_error` mutex on the send hot path.
            binding.live.set_tx_retry_status(reason);
            // #15786: `items` holds the staged survivors; remove any
            // validation-drop orphans before the LIFO restore.
            let (dropped, dropped_len) = dropped_prepared_positions(binding);
            items = restore_cos_prepared_items(
                binding,
                root_ifindex,
                queue_idx,
                batch_bytes,
                items,
                &dropped[..dropped_len],
            );
            cos_batch_tx_made_progress(Err(TxError::Retry(reason)))
        }
        Err(TxError::Drop(reason)) => {
            // #15786: all-invalid batch — every frame was already
            // recycled + counted per frame in `record_prepared_drop`,
            // and `items` is empty, so there is nothing to restore.
            // (Counting again here would double-count.) The Drop
            // reason is still surfaced for the operator message; the
            // snapshot unwind happens in restore_cos_prepared_items.
            binding.live.set_error(reason.message());
            let (dropped, dropped_len) = dropped_prepared_positions(binding);
            items = restore_cos_prepared_items(
                binding,
                root_ifindex,
                queue_idx,
                batch_bytes,
                items,
                &dropped[..dropped_len],
            );
            cos_batch_tx_made_progress(Err(TxError::Drop(reason)))
        }
    };
    // #4973: return the drained batch deque to the per-worker Prepared batch
    // scratch so the next shaped-TX drain reuses its capacity instead of
    // allocating a fresh `VecDeque`.
    binding.cos.cos_prepared_batch_scratch = items;
    made_progress
}

/// #15786: copy the validation-dropped original positions out of the
/// per-binding scratch (pop order). No allocation — fixed stack array.
fn dropped_prepared_positions(binding: &BindingWorker) -> ([u16; TX_BATCH_SIZE], usize) {
    let mut dropped = [0u16; TX_BATCH_SIZE];
    let src = &binding.scratch.scratch_prepared_dropped_orig_idx;
    let n = src.len().min(TX_BATCH_SIZE);
    dropped[..n].copy_from_slice(&src[..n]);
    (dropped, n)
}

/// #15786: remove the orphaned pop snapshots of validation-dropped
/// items from `queue` (DESCENDING original position, so each
/// positional removal only touches already-removed-above entries —
/// the #15172 contract). No-op when nothing was dropped.
fn remove_dropped_prepared_snapshots(
    queue: &mut crate::afxdp::types::CoSQueueRuntime,
    dropped: &[u16],
    retry_len: usize,
) {
    if dropped.is_empty() {
        return;
    }
    for &pos in dropped.iter().rev() {
        let _ = cos_queue_remove_orphan_snapshot_at(queue, usize::from(pos));
    }
    if let Some(ff) = queue.flow_fair_state.as_ref() {
        debug_assert!(
            ff.pop_snapshot_stack.len() >= retry_len,
            "#15786: pop_snapshot_stack ({}) shorter than the {} restored items at restore entry after validation-drop orphan removal",
            ff.pop_snapshot_stack.len(),
            retry_len,
        );
    }
}

// Moved from queue_service/mod.rs (pre-refactor L1511-L1532). Sole
// caller is submit_prepared's Err arms above.
//
// #4973: returns the drained (now-empty) `retry` deque so the submit handler
// can reclaim it as the per-worker Prepared batch scratch. On the
// queue-torn-down early return the deque is returned undrained (its items are
// dropped by the next `build_cos_batch_from_queue` `clear()`, exactly as the
// previous by-value drop dropped them — the queue is gone).
fn restore_cos_prepared_items(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    batch_bytes: u64,
    mut retry: VecDeque<PreparedTxRequest>,
    dropped_prepared: &[u16],
) -> VecDeque<PreparedTxRequest> {
    {
        let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) else {
            return retry;
        };
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            // #15786: orphan removal BEFORE the LIFO restore inside
            // restore_cos_prepared_items_inner.
            remove_dropped_prepared_snapshots(queue, dropped_prepared, retry.len());
            let retry_bytes = restore_cos_prepared_items_inner(queue, &mut retry);
            queue.hot.queued_bytes = queue
                .hot
                .queued_bytes
                .saturating_sub(batch_bytes)
                .saturating_add(retry_bytes);
        }
    }
    refresh_cos_interface_activity(binding, root_ifindex);
    retry
}
