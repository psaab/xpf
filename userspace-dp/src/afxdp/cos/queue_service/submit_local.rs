// #1331: Local-variant submit handler extracted verbatim from the
// CoSBatch::Local arm of submit_cos_batch (mod.rs pre-refactor
// L1192-L1297). Pure code motion.
//
// #5157: the mirror_clone sidecar prefix-attribution defect is now
// FIXED. `transmit_batch` can drop a `mirror_clone` request mid-batch
// via `continue` (mirror-reserve back-pressure) — a NON-prefix /
// interior removal — so the committed set is no longer a prefix of the
// input `items`. It reports the ORIGINAL-input positions it actually
// committed in `binding.scratch.scratch_committed_orig_idx`, and the Ok
// arm below charges flow-bucket / sojourn accounting through THOSE
// indices instead of the old `sidecar[..packets]` prefix.
use super::*;

#[inline]
pub(super) fn submit_local(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    phase: CoSServicePhase,
    batch_bytes: u64,
    mut items: VecDeque<TxRequest>,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> bool {
    assign_local_dscp_rewrite(
        &mut items,
        cos_queue_dscp_rewrite(binding, root_ifindex, queue_idx),
    );
    // #1229 v7: pre-transmit sidecar — record (bucket, bytes) for each
    // item in submit (== original input) order. #5157: transmit_batch
    // reports which ORIGINAL positions it actually committed (in
    // `scratch.scratch_committed_orig_idx`); the Ok arm indexes THIS
    // sidecar by those positions to account only the bytes actually
    // shipped. A mid-batch mirror drop makes the committed set a
    // non-prefix, so the old `sidecar[..packets]` slice would charge the
    // dropped mirror's flow and miss the shifted real packet.
    //
    // Stack-allocated array (TX_BATCH_SIZE × 10 bytes = 640 B)
    // avoids per-batch heap allocation on the hot path. The
    // Option<u64> seed acts as a presence flag: None means no
    // flow_fair state → sidecar_len stays 0 and accounting is
    // skipped entirely (no iteration, no branch inside the
    // success block).
    let local_seed_opt = binding
        .cos
        .cos_interfaces
        .get(&root_ifindex)
        .and_then(|root| root.queues.get(queue_idx))
        .and_then(|q| q.flow_fair_state.as_ref())
        .map(|ff| ff.flow_hash_seed);
    let mut sidecar = [(0u16, 0u64); TX_BATCH_SIZE];
    let sidecar_len = if let Some(seed) = local_seed_opt {
        let mut n = 0usize;
        for req in items.iter().take(TX_BATCH_SIZE) {
            sidecar[n] = (
                cos_flow_bucket_index(seed, req.flow_key.as_ref()) as u16,
                req.bytes.len() as u64,
            );
            n += 1;
        }
        n
    } else {
        0
    };
    // #1829 Phase 1 (Codex review on PR #1846): enqueue_ns sidecar,
    // filled UNCONDITIONALLY (FIFO unpromoted queues measure sojourn
    // too) in submit order. transmit_batch consumes the successful
    // prefix in-place and the retry suffix is push_fronted back WITH
    // its original enqueue_ns, so sampling at pop/batch-build time
    // would count a rolled-back item once per attempt. Recording only
    // the COMMITTED entries after the TX insert settles counts each
    // packet exactly once, on the attempt that ships it. 512 B stack,
    // one u64 store per item, no allocation. #5157: sampled by
    // committed original-position identity (see the #1229 sidecar
    // above), not a `[..packets]` prefix, so a mid-batch mirror drop
    // no longer shifts a packet's sojourn onto the wrong item.
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
    // stored back into the per-worker Local batch scratch after the match. The
    // transmit/apply/restore path empties `items` and returns it, retaining the
    // ring-buffer allocation `build_cos_batch_from_queue` reused.
    let made_progress = match transmit_batch(binding, &mut items, now_ns, shared_recycles) {
        Ok((packets, bytes)) => {
            // #5157: snapshot the committed identities (ORIGINAL-input
            // positions transmit_batch actually shipped) into a local
            // fixed array BEFORE the mutable `binding` borrows below.
            // These indices — not a `[..packets]` prefix — drive both
            // accounting passes, so a mid-batch mirror drop charges the
            // real transmitted flows, never the dropped mirror's flow.
            let mut committed = [0u16; TX_BATCH_SIZE];
            let committed_len = {
                let src = &binding.scratch.scratch_committed_orig_idx;
                let n = src.len().min(TX_BATCH_SIZE);
                committed[..n].copy_from_slice(&src[..n]);
                n
            };
            debug_assert_eq!(
                committed_len, packets as usize,
                "committed identity count must equal the transmitted packet count",
            );
            // #15172: remove mirror-drop orphan snapshots BEFORE
            // apply_cos_send_result restores the retry tail — its
            // LIFO push_fronts must consume survivor snapshots, not
            // the dropped mirror's. `items` here is exactly the
            // retry tail, so its length is the restore-entry count.
            let (dropped, dropped_len) = dropped_mirror_positions(binding);
            if dropped_len > 0 {
                if let Some(queue) = binding
                    .cos
                    .cos_interfaces
                    .get_mut(&root_ifindex)
                    .and_then(|root| root.queues.get_mut(queue_idx))
                {
                    remove_dropped_mirror_snapshots(queue, &dropped[..dropped_len], items.len());
                }
            }
            items = apply_cos_send_result(
                binding,
                root_ifindex,
                queue_idx,
                phase,
                batch_bytes,
                bytes,
                items,
            );
            // #1229 v7 + #5157: account per-bucket bytes for the
            // committed items by identity. sidecar_len > 0 ↔ flow_fair
            // is active. Every committed index < items.len() <=
            // sidecar_len (build_cos_batch_from_queue caps items at
            // TX_BATCH_SIZE), so `oi < sidecar_len` always holds; the
            // guard is defensive.
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
            // #1829 + #5157: committed-only sojourn samples by identity
            // (see the enq_sidecar comment above). Same pass now_ns as
            // the bucket accounting; record() skips enqueue_ns == 0.
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
                // #760 instrumentation, non-exact / shared-exact
                // Local path. See umem.rs field comment.
                binding
                    .live
                    .owner_profile_owner
                    .drain_sent_bytes_shaped_unconditional
                    .fetch_add(bytes, Ordering::Relaxed);
            }
            // #hb166 T-6(e): publish the committed queue_vtime on THIS
            // CoSBatch settle boundary. The four direct-service settle
            // sites in service.rs already publish; the CoSBatch submit path
            // (surplus-phase shared_exact service) advanced queue_vtime
            // during batch build but never broadcast it, so peers read a
            // stale-low V_min slot and self-throttle exactly when surplus
            // works hardest. No-op for non-flow-fair / non-shared queues
            // (vtime_floor is None).
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
            // #4971: expected TX backpressure — record the reason
            // lock-free instead of taking the `last_error` mutex.
            binding.live.set_tx_retry_status(reason);
            // #15172: `items` is back to the full survivor set here
            // (transmit_batch returned every staged entry); remove
            // mirror-drop orphans before the LIFO restore.
            let (dropped, dropped_len) = dropped_mirror_positions(binding);
            items = restore_cos_local_items(
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
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            // #710: frame-level submit drop during CoS batch
            // transmit; items are restored to the queue head,
            // so this counts the submit-attempt failure, not a
            // lost packet. Subset of tx_errors.
            binding
                .live
                .tx_submit_error_drops
                .fetch_add(1, Ordering::Relaxed);
            // #4971: exceptional drop path (rare) still renders the
            // diagnostic message via the mutex-backed set_error.
            binding.live.set_error(reason.message());
            // #15172: same orphan removal as the Retry arm — the
            // staged prefix is back in `items`, so remove the
            // dropped mirror's snapshot before the LIFO restore.
            let (dropped, dropped_len) = dropped_mirror_positions(binding);
            items = restore_cos_local_items(
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
    // #4973: return the drained batch deque to the per-worker Local batch
    // scratch so the next shaped-TX drain reuses its capacity instead of
    // allocating a fresh `VecDeque`.
    binding.cos.cos_local_batch_scratch = items;
    made_progress
}

/// #15172: copy the mirror-reserve dropped original positions out of
/// the per-binding scratch (pop order). No allocation — fixed stack
/// array, same shape as the committed-identity copy in the Ok arm.
fn dropped_mirror_positions(binding: &BindingWorker) -> ([u16; TX_BATCH_SIZE], usize) {
    let mut dropped = [0u16; TX_BATCH_SIZE];
    let src = &binding.scratch.scratch_dropped_mirror_orig_idx;
    let n = src.len().min(TX_BATCH_SIZE);
    dropped[..n].copy_from_slice(&src[..n]);
    (dropped, n)
}

/// #15172: remove the orphaned pop snapshots of mirror-reserve
/// dropped items from `queue` (DESCENDING original position, so each
/// positional removal only touches already-removed-above entries),
/// The removal itself is the fix: with the orphan gone, the LIFO
/// restore's top entries are the survivors' own snapshots, so
/// `pop_matching_snapshot` matches each survivor's bucket (its
/// `assert!(false)` remains the fail-closed tripwire if a future
/// caller desyncs the stack). `retry_len` is retained for the
/// restore-entry debug guard below.
/// No-op when nothing was dropped — the common path adds one length
/// check and no queue access.
fn remove_dropped_mirror_snapshots(
    queue: &mut crate::afxdp::types::CoSQueueRuntime,
    dropped: &[u16],
    retry_len: usize,
) {
    if dropped.is_empty() {
        return;
    }
    for &pos in dropped.iter().rev() {
        // Fail-closed: a `false` here means the stack desynced from
        // the batch (short stack / no flow-fair state). The assert
        // below trips on the length mismatch rather than restoring
        // against a wrong snapshot.
        let _ = cos_queue_remove_orphan_snapshot_at(queue, usize::from(pos));
    }
    // Restore-entry invariant (debug only): after orphan removal the
    // stack must still hold AT LEAST one snapshot per restored item
    // (the survivors' own, at the top, in batch order; any entries
    // below them are committed-prefix snapshots a partial commit
    // leaves resident for the next build-start clear — #3968). A
    // short stack here means the positional removal desynced, and
    // the LIFO restore would run off the bottom / consume a wrong
    // entry; trip in debug instead. Bucket alignment per item is
    // enforced by pop_matching_snapshot's assert on restore.
    if let Some(ff) = queue.flow_fair_state.as_ref() {
        debug_assert!(
            ff.pop_snapshot_stack.len() >= retry_len,
            "#15172: pop_snapshot_stack ({}) shorter than the {}              restored items at restore entry after mirror-drop              orphan removal",
            ff.pop_snapshot_stack.len(),
            retry_len,
        );
    }
}

// Moved from queue_service/mod.rs (pre-refactor L1488-L1509). Sole
// caller is submit_local's Err arms above; the *_inner variant lives
// in tx_completion and is still reached via super::.
//
// #4973: returns the drained (now-empty) `retry` deque so the submit handler
// can reclaim it as the per-worker Local batch scratch. On the queue-torn-down
// early return the deque is returned undrained (its items are dropped by the
// next `build_cos_batch_from_queue` `clear()`, exactly as the previous by-value
// drop dropped them — the queue is gone).
fn restore_cos_local_items(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    batch_bytes: u64,
    mut retry: VecDeque<TxRequest>,
    dropped_mirror: &[u16],
) -> VecDeque<TxRequest> {
    {
        let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) else {
            return retry;
        };
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            // #15172: orphan removal BEFORE the LIFO restore inside
            // restore_cos_local_items_inner (retry.len() is the
            // restore-entry survivor count at this point).
            remove_dropped_mirror_snapshots(queue, dropped_mirror, retry.len());
            let retry_bytes = restore_cos_local_items_inner(queue, &mut retry);
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
