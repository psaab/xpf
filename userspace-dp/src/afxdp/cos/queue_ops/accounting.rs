use super::*;

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
    let Some(ff) = queue.flow_fair_state.as_mut() else {
        return;
    };
    let bucket = cos_flow_bucket_index(ff.flow_hash_seed, flow_key);
    if ff.flow_bucket_bytes[bucket] == 0 {
        ff.active_flow_buckets = ff.active_flow_buckets.saturating_add(1);
        // #784 diagnostic: track the peak distinct-flow count.
        // Operators can compare this to the test's -P N count to
        // detect SFQ hash collisions under real workloads.
        if ff.active_flow_buckets > ff.active_flow_buckets_peak {
            ff.active_flow_buckets_peak = ff.active_flow_buckets;
        }
    }
    let was_idle = ff.flow_bucket_bytes[bucket] == 0;
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
    if was_idle {
        ff.flow_bucket_head_finish_bytes[bucket] = new_tail;
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
    let Some(ff) = queue.flow_fair_state.as_mut() else {
        return;
    };
    let bucket = cos_flow_bucket_index(ff.flow_hash_seed, flow_key);
    let remaining = ff.flow_bucket_bytes[bucket].saturating_sub(item_len);
    if ff.flow_bucket_bytes[bucket] > 0 && remaining == 0 {
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
}
