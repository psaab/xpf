use super::*;
use std::sync::atomic::Ordering;

// Flow accounting helpers — increment / decrement the per-flow byte
// counters that the MQFQ queue uses to compute virtual finish times.
// Both fns are called from push/pop hot paths in queue_ops/mod.rs.

#[inline]
pub(super) fn account_cos_queue_flow_enqueue(
    queue: &mut CoSQueueRuntime,
    flow_key: Option<&SessionKey>,
    item_len: u64,
) {
    if !queue.flow_fair() || item_len == 0 {
        return;
    }
    // #1229 Phase 6 v8: capture worker_id BEFORE the flow_fair_state
    // mutable borrow; NLL ends the `ff` borrow at its last use site,
    // after which `queue.queue_lease_v8` is a separate field that can
    // be borrowed without cloning the Arc.
    let worker_id = queue.v_min.worker_id as usize;
    // #15154 (B14-01): reseed on vacate re-entry. The #4254 frontier
    // reseed (admission.rs `promote_cos_queue_flow_fair`) runs only at
    // FlowFairState construction. A worker whose last bucket drained
    // vacated its slot (#941 A, in `account_cos_queue_flow_dequeue`)
    // but kept its frozen `queue_vtime`; without a reseed here its
    // first post-settle publish re-enters at that stale value and
    // becomes the cross-worker V_min, trapping busy peers. Detect
    // re-entry exactly: empty queue (`active_flow_buckets == 0` before
    // this enqueue) on a shared_exact queue whose own slot is
    // NOT_PARTICIPATING. Capture the frontier before the `ff` borrow;
    // `peer_frontier_vtime` excludes our own slot, so a genuine
    // laggard peer is never reseeded and still defers everyone.
    // `vtime_floor` is Some only on shared_exact queues; the explicit
    // `shared_exact()` + slot check keeps non-shared queues untouched.
    // No publish here — the slot stays NOT_PARTICIPATING until the
    // first post-settle publish (#940), which now broadcasts the
    // reseeded value.
    let reentry_frontier = if queue.shared_exact()
        && queue
            .flow_fair_state
            .as_ref()
            .is_some_and(|s| s.active_flow_buckets == 0)
    {
        queue.v_min.vtime_floor.as_ref().and_then(|floor| {
            let slot = floor.slots.get(worker_id)?;
            if slot.read().is_none() {
                floor.peer_frontier_vtime(queue.v_min.worker_id)
            } else {
                None
            }
        })
    } else {
        None
    };
    // Invariant: `flow_fair() == true` ↔ `flow_fair_state.is_some()`.
    // Silent return here would desync per-bucket bytes / active counts
    // from actual queue contents, breaking selection. Panic instead.
    let ff = queue
        .flow_fair_state
        .as_mut()
        .expect("account_cos_queue_flow_enqueue: flow_fair queue without flow_fair_state");
    let bucket = cos_flow_bucket_index(ff.flow_hash_seed, flow_key);
    // #15154 (B14-01): apply the re-entry reseed BEFORE the bucket
    // anchor below (`max(tail, queue_vtime) + item_len`), so the new
    // bucket anchors at the frontier, not the frozen vtime. Max
    // semantics: an ahead re-entrant is never pulled down, and no
    // participating peer (None frontier) leaves the value unchanged.
    if let Some(frontier) = reentry_frontier {
        ff.queue_vtime = ff.queue_vtime.max(frontier);
    }
    let bucket_was_empty = ff.flow_bucket_bytes[bucket] == 0;
    if bucket_was_empty {
        ff.active_flow_buckets = ff.active_flow_buckets.saturating_add(1);
        // #784 diagnostic: track the peak distinct-flow count.
        // Operators can compare this to the test's -P N count to
        // detect SFQ hash collisions under real workloads.
        if ff.active_flow_buckets > ff.active_flow_buckets_peak {
            ff.active_flow_buckets_peak = ff.active_flow_buckets;
        }
    }
    ff.flow_bucket_bytes[bucket] = ff.flow_bucket_bytes[bucket].saturating_add(item_len);
    // #785 Phase 3 — MQFQ head/tail finish-time update.
    //
    // When the bucket was idle before this enqueue, the HEAD
    // packet is THIS one, so both head and tail advance to
    // `max(tail, queue.vtime) + bytes` — the `max` re-anchors
    // the bucket at the current frontier (otherwise an idle bucket
    // with tail=0 would sweep past all established flows in one
    // bounded round, starving them).
    //
    // When the bucket was already active, this packet arrives at
    // the TAIL of the bucket queue — advance only the tail. The
    // head packet (and therefore head-finish) is unchanged because
    // the drain-order key for this bucket is still the previously-
    // queued packets. The new packet's finish is implicit: tail.
    //
    // Codex adversarial review flagged the original single-counter
    // design as HIGH severity: keying selection off tail-finish
    // rather than head-finish collapsed MQFQ to packet-count
    // fairness for equal-byte flows (A,A,B,B bursts instead of
    // A,B,A,B interleave).
    let new_tail = ff.flow_bucket_tail_finish_bytes[bucket]
        .max(ff.queue_vtime)
        .saturating_add(item_len);
    ff.flow_bucket_tail_finish_bytes[bucket] = new_tail;
    if bucket_was_empty {
        ff.flow_bucket_head_finish_bytes[bucket] = new_tail;
    }
    // `ff` borrow ends here (NLL: last use above). `queue.queue_lease_v8`
    // is a disjoint field; no Arc clone needed.
    if bucket_was_empty {
        // v8 lease delta: bump per-worker active counter on bucket
        // 0→nonzero transition. Single-writer-per-slot invariant
        // (this worker_id never seen on any peer's queue runtime).
        if let Some(lease) = queue.queue_lease_v8.as_ref() {
            if let Some(slot) = lease.worker_active_flow_buckets_for(worker_id) {
                slot.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[inline]
pub(super) fn account_cos_queue_flow_dequeue(
    queue: &mut CoSQueueRuntime,
    flow_key: Option<&SessionKey>,
    item_len: u64,
) {
    if !queue.flow_fair() || item_len == 0 {
        return;
    }
    let shared_exact = queue.shared_exact();
    // #1229 Phase 6 v8: capture worker_id BEFORE the flow_fair_state
    // mutable borrow; NLL ends the `ff` borrow at its last use site,
    // after which `queue.queue_lease_v8` is a separate field that can
    // be borrowed without cloning the Arc.
    let worker_id = queue.v_min.worker_id as usize;
    // Invariant: see account_cos_queue_flow_enqueue. Silent return here
    // would leave active_flow_buckets / finish-times stale and break
    // V_min slot vacate logic.
    let ff = queue
        .flow_fair_state
        .as_mut()
        .expect("account_cos_queue_flow_dequeue: flow_fair queue without flow_fair_state");
    let bucket = cos_flow_bucket_index(ff.flow_hash_seed, flow_key);
    let remaining = ff.flow_bucket_bytes[bucket].saturating_sub(item_len);
    let bucket_drained = ff.flow_bucket_bytes[bucket] > 0 && remaining == 0;
    if bucket_drained {
        // Codex 2026-05-08 code-review note #2: parity with the
        // dead-code helper `unbump_active_flow_buckets` (which has
        // a `debug_assert!(active_flow_buckets > 0)`). saturating_sub
        // hides the bug in release; assert in debug to catch any
        // future caller that decrements past zero.
        debug_assert!(
            ff.active_flow_buckets > 0,
            "active_flow_buckets dequeue past 0 (bucket {})",
            bucket
        );
        ff.active_flow_buckets = ff.active_flow_buckets.saturating_sub(1);
        // #785 Phase 3 — MQFQ bucket-idle reset. When a bucket
        // drains to 0 its head/tail finish-times are stale
        // (they point at the virtual time when the LAST packet
        // finished, not the current frontier). Without reset, a
        // bucket that comes back active later would skip ahead
        // of the enqueue-side `max(tail, vtime)` anchor and starve
        // established buckets until its stale tail converges with
        // vtime. Reset both head and tail to 0 so the next
        // enqueue re-anchors at the live `queue.vtime`.
        ff.flow_bucket_head_finish_bytes[bucket] = 0;
        ff.flow_bucket_tail_finish_bytes[bucket] = 0;
        // #4259 (hb166 R-1) — bucket identity ends here. Also reset the
        // per-bucket TX-rate EWMA state written by
        // `account_flow_bucket_tx` (cos/fairness.rs). Without this, the
        // observed-rate EWMA survives flow death: it decays only on TX
        // commits (which require service), and its skip-ramp arms only at
        // 0 — so a bucket driven high by a departed elephant keeps that
        // rate indefinitely. A new flow that hashes into the recycled
        // bucket is then deferred by the cap-aware MQFQ selector
        // (queue_ops/mod.rs `observed_bps > target_bps`) as if it were the
        // old elephant, inverting the mechanism's purpose (it throttles the
        // coolest flow — a newcomer). Zeroing `observed_bps` re-arms the
        // skip-ramp; zeroing `last_tx_ns` routes the next commit through
        // the first-commit stamp path; zeroing `pending_bytes` drops the
        // departed flow's un-rolled accumulation. This mirrors the
        // head/tail reset above — a drain to 0 is treated as idle/recycled,
        // consistent with the enqueue-side re-anchor. The monotonic
        // lifetime counter `flow_bucket_tx_bytes` is left intact (its
        // "never decremented" diagnostic contract).
        ff.flow_bucket_observed_bps[bucket] = 0;
        ff.flow_bucket_last_tx_ns[bucket] = 0;
        ff.flow_bucket_pending_bytes[bucket] = 0;
        // #941 Work item A: bucket-empty vacate. When this worker's
        // last active bucket on a shared_exact queue empties, vacate
        // the V_min slot so peers don't see a phantom-participating
        // worker holding a stale-low value. Single-writer invariant
        // holds — only this worker writes its own slot.
        if shared_exact && ff.active_flow_buckets == 0 {
            if let Some(floor) = queue.v_min.vtime_floor.as_ref() {
                if let Some(slot) = floor.slots.get(queue.v_min.worker_id as usize) {
                    slot.vacate();
                }
            }
        }
    }
    ff.flow_bucket_bytes[bucket] = remaining;
    // `ff` borrow ends here (NLL: last use above).
    if bucket_drained {
        // v8 lease delta: unbump per-worker counter on bucket nonzero→0
        // transition. Defensive underflow protection: only fetch_sub
        // if slot is currently > 0 (single-writer guarantee makes
        // load-then-fetch_sub safe; defends against any local/lease
        // count divergence).
        if let Some(lease) = queue.queue_lease_v8.as_ref() {
            if let Some(slot) = lease.worker_active_flow_buckets_for(worker_id) {
                let prev = slot.load(Ordering::Relaxed);
                if prev > 0 {
                    slot.fetch_sub(1, Ordering::Relaxed);
                } else {
                    // Codex code-review note #2: parity with helper.
                    debug_assert!(
                        false,
                        "v8 lease counter dequeue past 0 (worker {})",
                        worker_id
                    );
                }
            }
        }
    }
}
