use super::*;

// Drain orchestration — bulk-empty + rollback helpers. `cos_queue_drain_all`
// is called when a queue is being torn down (worker exit, RG demote).
// `cos_queue_restore_front` is the partial-commit rollback path used by
// the worker drain loop when only a prefix of a popped batch successfully
// got onto the wire. `cos_queue_clear_orphan_snapshot_after_drop` cleans
// up the pop-snapshot stack when a previously-popped item is being
// dropped (not retried).

/// #913 — used by scratch-builder Drop paths to clean up the
/// orphan snapshot for an item that was popped and then dropped
/// (frame-too-big, slice-fail). The naive `pop_snapshot_stack.pop()`
/// loses the dropped item's vtime contribution: subsequent
/// survivor restores via `cos_queue_push_front` would rewind vtime
/// below the dropped item's commit, breaking MQFQ ordering.
///
/// Fix (Codex code review HIGH): after popping the orphan, clamp
/// every remaining snapshot's `pre_pop_queue_vtime` to ≥ the
/// post-drop `queue_vtime`. This preserves the "drops consume
/// virtual service" semantic: when surviving items are restored,
/// their vtime restores can't go below the dropped item's
/// committed advance.
///
/// Walkthrough: pre-batch vtime=0; pop A (head=1500) → vtime=1500;
/// pop B (head=2000) → vtime=2000; pop Z (head=3000) → vtime=3000.
/// Drop Z: z_committed_vtime=3000; pop snap_Z; clamp snap_B and
/// snap_A pre_pop_queue_vtime to max(orig, 3000)=3000. Restore B:
/// vtime=3000. Restore A: vtime=3000. Z's vtime contribution
/// preserved across the rollback.
#[inline]
pub(in crate::afxdp) fn cos_queue_clear_orphan_snapshot_after_drop(queue: &mut CoSQueueRuntime) {
    let Some(ff) = queue.flow_fair_state.as_mut() else {
        return;
    };
    let Some(orphan) = ff.pop_snapshot_stack.pop() else {
        return;
    };
    // ff.queue_vtime here reflects the dropped item's pop
    // advance (already applied in cos_queue_pop_front_inner).
    // Clamp remaining snapshots to preserve it across rollback.
    let z_committed_vtime = ff.queue_vtime;
    // #927: also preserve the dropped item's bucket-frontier
    // contribution. The dropped item's served_finish equals
    // `orphan.pre_pop_head_finish` (served_finish is read from
    // `flow_bucket_head_finish_bytes[bucket]` BEFORE the
    // post-pop overwrite at the orphan's pop site, so it
    // matches the snapshot's pre_pop_head_finish capture).
    // Older same-bucket snapshots were captured before the
    // dropped item's pop, so their pre_pop_head/tail_finish
    // do not include the dropped item's frontier. When such a
    // snapshot is later restored via the `was_empty` snapshot
    // path in `cos_queue_push_front`, the bucket would be
    // re-anchored at a stale (lower) finish-time — competing
    // active buckets could be incorrectly scheduled before
    // it. Bumping to `orphan_served_finish` via .max() is
    // monotone (only raises) and never crosses a committed
    // boundary, so it is safe across all rollback orderings.
    let orphan_served_finish = orphan.pre_pop_head_finish;
    for snap in ff.pop_snapshot_stack.iter_mut() {
        if snap.pre_pop_queue_vtime < z_committed_vtime {
            snap.pre_pop_queue_vtime = z_committed_vtime;
        }
        if snap.bucket == orphan.bucket {
            snap.pre_pop_head_finish = snap.pre_pop_head_finish.max(orphan_served_finish);
            snap.pre_pop_tail_finish = snap.pre_pop_tail_finish.max(orphan_served_finish);
        }
    }
}
/// #15172 — remove the pop snapshot for the dropped ORIGINAL-input
/// position `orig_pos` in a batch whose pops pushed snapshots in
/// original-input order (stack index == original position for a batch
/// built by `build_cos_batch_from_queue`, which clears the stack at
/// build start and appends one snapshot per pop in order).
///
/// `transmit_batch` drops a `mirror_clone` interior to a
/// `CoSBatch::Local` batch WITHOUT returning it to `pending`, so the
/// dropped item is neither committed nor restored; its snapshot is
/// orphaned. Left in place, the later LIFO `push_front` restore of an
/// earlier survivor (any `inserted == 0` / partial-insert retry, or a
/// `Drop` settle) consumes the WRONG top snapshot: a bucket mismatch
/// hits `assert!(false)` in `pop_matching_snapshot` (worker-thread
/// death), and same-bucket cases silently restore the orphan's
/// pre-pop head/tail finishes.
///
/// Unlike `cos_queue_clear_orphan_snapshot_after_drop` — which pops
/// the TOP entry for a just-popped scratch-builder drop — this removes
/// an INTERIOR entry: the dropped item may be followed by later pops
/// whose snapshots sit above it. Removal is followed by the same
/// clamp the orphan helper applies (remaining pre-pop vtimes raised
/// to at least the current `queue_vtime`; same-bucket snapshots
/// raised to at least the orphan's served finish), so the dropped
/// item's committed vtime/frontier advance survives every later
/// rollback restore. Callers MUST pass drops in DESCENDING
/// `orig_pos` order (the scratch list is built in pop order, so a
/// reverse walk) — with the stack==batch-length premise each removal
/// then only touches already-removed-above positions.
///
/// Fail-closed on premise violation: a missing flow-fair state, a
/// short stack, or an out-of-range position returns `false` with the
/// stack untouched, and the caller asserts at restore entry so a
/// desynchronised stack panics in the submit path (fail-closed)
/// instead of restoring against a wrong snapshot. Returns `true`
/// once the entry is removed.
#[inline]
pub(in crate::afxdp) fn cos_queue_remove_orphan_snapshot_at(
    queue: &mut CoSQueueRuntime,
    orig_pos: usize,
) -> bool {
    let Some(ff) = queue.flow_fair_state.as_mut() else {
        return false;
    };
    if orig_pos >= ff.pop_snapshot_stack.len() {
        return false;
    }
    let orphan = ff.pop_snapshot_stack.remove(orig_pos);
    let z_committed_vtime = ff.queue_vtime;
    let orphan_served_finish = orphan.pre_pop_head_finish;
    for snap in ff.pop_snapshot_stack.iter_mut() {
        if snap.pre_pop_queue_vtime < z_committed_vtime {
            snap.pre_pop_queue_vtime = z_committed_vtime;
        }
        if snap.bucket == orphan.bucket {
            snap.pre_pop_head_finish = snap.pre_pop_head_finish.max(orphan_served_finish);
            snap.pre_pop_tail_finish = snap.pre_pop_tail_finish.max(orphan_served_finish);
        }
    }
    true
}

pub(in crate::afxdp) fn cos_queue_drain_all(
    queue: &mut CoSQueueRuntime,
) -> VecDeque<CoSPendingTxItem> {
    // #913 / Codex R3: clear stale snapshots from any prior
    // committed hot-path drain. Without this, a subsequent
    // `cos_queue_restore_front` would consume orphan snapshots
    // and apply them to the wrong items (the failure-restore
    // path in `demote_prepared_cos_queue_to_local`). The §3.7
    // round-trip-neutrality walkthrough relies on the stack
    // being EMPTY when restore_front begins.
    if let Some(ff) = queue.flow_fair_state.as_mut() {
        ff.pop_snapshot_stack.clear();
    }
    let mut items = VecDeque::new();
    // #785 Phase 3 — Codex round-3 NEW-2 / Rust reviewer LOW:
    // drain-all is a teardown/reconfigure helper. Unlike the
    // hot-path batch drains (which cap at TX_BATCH_SIZE and
    // may be followed by a matching push_front rollback), this
    // path pops the entire queue without a paired rollback and
    // can visit >TX_BATCH_SIZE items. Use the no-snapshot
    // variant so we don't grow the snapshot stack past its
    // documented bound or trip the per-pop debug_assert.
    while let Some(item) = cos_queue_pop_front_no_snapshot(queue) {
        items.push_back(item);
    }
    items
}

#[inline]
pub(in crate::afxdp) fn cos_queue_restore_front(
    queue: &mut CoSQueueRuntime,
    mut items: VecDeque<CoSPendingTxItem>,
) {
    while let Some(item) = items.pop_back() {
        cos_queue_push_front(queue, item);
    }
}
