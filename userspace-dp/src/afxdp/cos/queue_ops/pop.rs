use super::*;

// Pop operations: dequeue path including the snapshot stack used to
// preserve in-flight item state across batched drain operations.
// `pop_front` records a snapshot for batched rollback; `pop_front_no_snapshot`
// is the non-batched variant used when the caller has already committed
// to dropping the item. `pop_front_inner` is the shared implementation.

#[inline]
pub(in crate::afxdp) fn cos_queue_pop_front(
    queue: &mut CoSQueueRuntime,
) -> Option<CoSPendingTxItem> {
    cos_queue_pop_front_inner(queue, true)
}

/// #785 Phase 3 — Codex round-3 NEW-2 / Rust reviewer LOW:
/// teardown-only variant of `cos_queue_pop_front` that does NOT
/// push a rollback snapshot. Used by drain-all-items-until-empty
/// paths (`cos_queue_drain_all` and the worker teardown loop)
/// where the drained items are either discarded or restored via
/// a single reverse push_front loop that doesn't need per-pop
/// pre-state capture (nothing has mutated the bucket between
/// drain and restore in those paths).
///
/// Without this variant, a teardown of >TX_BATCH_SIZE items would
/// grow `pop_snapshot_stack` past its documented bound and trip
/// the per-pop debug_assert.
#[inline]
pub(in crate::afxdp) fn cos_queue_pop_front_no_snapshot(
    queue: &mut CoSQueueRuntime,
) -> Option<CoSPendingTxItem> {
    cos_queue_pop_front_inner(queue, false)
}

#[inline]
fn cos_queue_pop_front_inner(
    queue: &mut CoSQueueRuntime,
    push_snapshot: bool,
) -> Option<CoSPendingTxItem> {
    let item = if !queue.flow_fair() {
        queue.hot.items.pop_front()?
    } else {
        let Some(ff) = queue.flow_fair_state.as_mut() else {
            return None;
        };
        // #785 Phase 3 — MQFQ: pop from the bucket whose head
        // packet has the smallest virtual-finish-time, not DRR
        // rotation order. The active set (`flow_rr_buckets`) is
        // still maintained on 0↔>0 transitions so the min-scan
        // only iterates the currently-active buckets (typically
        // 2-16), not all 4096.
        let bucket_u16 = cos_queue_min_finish_bucket(ff)?;
        let bucket = usize::from(bucket_u16);
        if push_snapshot {
            // #785 Phase 3 — Codex round-3 HIGH + NEW-1: snapshot
            // pre-pop bucket + vtime state BEFORE we mutate anything,
            // and push onto the per-queue LIFO stack. Every popped
            // item gets its own snapshot so a batched rollback (N
            // pops into scratch, submit a prefix, push_front the tail
            // in LIFO order) can restore exact pre-pop head/tail for
            // EVERY item — not just the most recent pop.
            //
            // Earlier revision kept a single `Option<...>`; Codex
            // NEW-1 flagged that earlier drained buckets in a
            // multi-pop rollback fell back to the
            // `max(tail, queue_vtime) + bytes` re-anchor formula,
            // which can overshoot the pre-pop head when queue_vtime
            // has advanced since the bucket's original enqueue.
            //
            // Stack capacity is preallocated to TX_BATCH_SIZE
            // (see types/mod.rs), so this push is amortized O(1) and
            // allocation-free.
            //
            // #785 Phase 3 — Codex round-3 NEW-2 / Rust reviewer LOW:
            // debug_assert the stack stays within its documented bound.
            // Drain helpers clear at batch start and teardown paths
            // use `cos_queue_pop_front_no_snapshot`. If this trips
            // under dev/test, a new caller is leaking snapshots
            // and could realloc on the hot path in release builds.
            debug_assert!(
                ff.pop_snapshot_stack.len() < TX_BATCH_SIZE,
                "pop_snapshot_stack exceeded TX_BATCH_SIZE bound ({}); \
                 a caller is leaking snapshots — drain helpers must \
                 clear at batch start and teardown paths must use \
                 cos_queue_pop_front_no_snapshot",
                TX_BATCH_SIZE,
            );
            ff.pop_snapshot_stack.push(CoSQueuePopSnapshot {
                bucket: bucket_u16,
                pre_pop_head_finish: ff.flow_bucket_head_finish_bytes[bucket],
                pre_pop_tail_finish: ff.flow_bucket_tail_finish_bytes[bucket],
                pre_pop_queue_vtime: ff.queue_vtime,
            });
        }
        // #913: capture served_finish (the popped packet's finish
        // time) BEFORE pop_front + head-advance below mutate it.
        let served_finish = ff.flow_bucket_head_finish_bytes[bucket];
        let item = ff.flow_bucket_items[bucket].pop_front()?;
        // #913: branched vtime advance.
        // - push_snapshot=true (hot path / `cos_queue_pop_front`):
        //   MQFQ served-finish semantics — `vtime = max(vtime,
        //   served_finish)`. Closes #911 same-class HOL by
        //   tracking the system frontier (smallest head_finish
        //   across active buckets at pop time) instead of
        //   aggregate bytes.
        // - push_snapshot=false (`cos_queue_pop_front_no_snapshot`,
        //   used by drain_all + worker.rs:1859 teardown):
        //   legacy `vtime += bytes` retained. The
        //   `demote_prepared_cos_queue_to_local` failure-restore
        //   path (drain_all → restore_front) relies on this
        //   symmetry with push_front's `vtime -= item_len`
        //   rewind for round-trip neutrality. drain_all clears
        //   the snapshot stack at start so push_front of the
        //   restored items takes the empty-stack aggregate
        //   path. See plan §3.5 / §3.7.
        if push_snapshot {
            ff.queue_vtime = ff.queue_vtime.max(served_finish);
        } else {
            let bytes = cos_item_len(&item);
            ff.queue_vtime = ff.queue_vtime.saturating_add(bytes);
        }
        // #940: V_min publish moved to post-settle commit boundary.
        // See `publish_committed_queue_vtime` for details.
        if let Some(next_head) = ff.flow_bucket_items[bucket].front() {
            // Bucket still has packets. Advance head-finish to
            // the NEW head packet's finish: head += bytes(new head).
            // This is the "fresh HOL key" for the next min-scan;
            // without it, the bucket's selection key would stay
            // frozen at the just-popped packet's finish and
            // equal-depth backlogged flows would drain in
            // `A,A,B,B` bursts (Codex HIGH on the first Phase 3
            // revision).
            let next_bytes = cos_item_len(next_head);
            ff.flow_bucket_head_finish_bytes[bucket] =
                ff.flow_bucket_head_finish_bytes[bucket].saturating_add(next_bytes);
        } else {
            // Bucket drained — deregister from the active set.
            // `FlowRrRing::remove` is O(active_count), typically
            // 2-16 compares; bounded by 4096 worst case.
            ff.flow_rr_buckets.remove(bucket_u16);
        }
        item
    };
    // #774: decrement the Local counter BEFORE account_flow_dequeue
    // so that if account_flow_dequeue panics the counter isn't
    // stuck high. saturating_sub is a no-op on 0 (never should be
    // 0 when a Local item is popping, but defense-in-depth).
    if matches!(item, CoSPendingTxItem::Local(_)) {
        queue.hot.local_item_count = queue.hot.local_item_count.saturating_sub(1);
    }
    let item_len = cos_item_len(&item);
    let flow_key = cos_item_flow_key(&item);
    account_cos_queue_flow_dequeue(queue, flow_key, item_len);
    Some(item)
}

#[cfg(test)]
#[path = "pop_tests.rs"]
mod tests;
