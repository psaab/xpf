// CoS queue primitives: accessors, enqueue/dequeue, MQFQ ordering
// bookkeeping, V-min slot lifecycle. Per-byte hot-path fns carry
// `#[inline]` to preserve cross-module inlining at the
// `pub(in crate::afxdp)` boundary.

use std::collections::VecDeque;

use crate::afxdp::types::{
    CoSPendingTxItem, CoSQueuePopSnapshot, CoSQueueRuntime,
};
use crate::afxdp::TX_BATCH_SIZE;
use crate::session::SessionKey;

use super::flow_hash::{cos_flow_bucket_index, cos_item_flow_key};

// #1034 P1: MQFQ V_min coordination split into a sibling submodule.
mod v_min;
pub(in crate::afxdp) use v_min::{
    cos_queue_v_min_consume_suspension, cos_queue_v_min_continue,
    publish_committed_queue_vtime,
};

// #1034 P2: flow accounting + drain orchestration split into siblings.
mod accounting;
mod drain;
use accounting::{account_cos_queue_flow_dequeue, account_cos_queue_flow_enqueue};
pub(in crate::afxdp) use drain::{
    cos_queue_clear_orphan_snapshot_after_drop, cos_queue_drain_all, cos_queue_restore_front,
};

// #1034 P3: push + pop ops split into siblings.
mod pop;
mod push;
pub(in crate::afxdp) use pop::{cos_queue_pop_front, cos_queue_pop_front_no_snapshot};
pub(in crate::afxdp) use push::{cos_queue_push_back, cos_queue_push_front};

#[inline]
pub(in crate::afxdp) fn cos_queue_is_empty(queue: &CoSQueueRuntime) -> bool {
    if !queue.flow_fair {
        return queue.items.is_empty();
    }
    queue.flow_rr_buckets.is_empty()
}

#[inline]
pub(in crate::afxdp) fn cos_queue_len(queue: &CoSQueueRuntime) -> usize {
    if !queue.flow_fair {
        return queue.items.len();
    }
    queue
        .flow_rr_buckets
        .iter()
        .map(|bucket| queue.flow_bucket_items[usize::from(bucket)].len())
        .sum()
}

/// #785 Phase 3 — find the flow bucket whose HEAD packet has the
/// smallest MQFQ virtual-finish-time among the currently active
/// set. The head-packet's finish (not the tail) is the correct
/// selection key: drains pop from the head, so that's the packet
/// whose ordering actually matters.
///
/// Linear scan over the active ring. Size bound: `active_flow_buckets
/// <= COS_FLOW_FAIR_BUCKETS = 4096`, typical workloads 2-16. At 12
/// active buckets this is 12 × (u64 load + compare) ≈ 20 ns — well
/// below NAPI batch pacing.
///
/// If we ever profile this as hot (e.g. with thousands of active
/// flows on a single queue), the replacement is a min-heap keyed by
/// `flow_bucket_head_finish_bytes`. For iperf3-sized workloads the
/// linear scan is cache-friendlier and simpler.
#[inline]
fn cos_queue_min_finish_bucket(queue: &CoSQueueRuntime) -> Option<u16> {
    let mut best: Option<u16> = None;
    let mut best_finish = u64::MAX;
    for bucket in queue.flow_rr_buckets.iter() {
        let finish = queue.flow_bucket_head_finish_bytes[usize::from(bucket)];
        if finish < best_finish {
            best_finish = finish;
            best = Some(bucket);
        }
    }
    best
}

#[inline]
pub(in crate::afxdp) fn cos_queue_front(queue: &CoSQueueRuntime) -> Option<&CoSPendingTxItem> {
    if !queue.flow_fair {
        return queue.items.front();
    }
    // #785 Phase 3 — MQFQ: return the head of the bucket with the
    // smallest virtual-finish-time, not the DRR-rotation head. This
    // is the byte-rate-fair dequeue order (classical SFQ / WFQ).
    let bucket = usize::from(cos_queue_min_finish_bucket(queue)?);
    queue.flow_bucket_items[bucket].front()
}

/// #917 — V_min sync throttle decision. Plan §3.3 v2 cadence:
/// K=8 + mandatory check at drain-batch start (`pop_count == 1`).
const V_MIN_READ_CADENCE: u32 = 8;

/// #917 — per-flow drift budget that V_min sync tolerates before
/// throttling the fast worker. Plan §3.5: `per_worker_rate × 1 ms`.
const V_MIN_LAG_THRESHOLD_NS: u64 = 1_000_000;

/// Floor for the lag budget so the throttle never fires below the
/// minimum forward-progress unit (~16 MTU at 1500 B = 24 KB).
const V_MIN_MIN_LAG_BYTES: u64 = 24_000;


/// #941 Work item D — hard-cap escape hatch constants.
pub(in crate::afxdp) const V_MIN_CONSECUTIVE_SKIP_HARD_CAP: u32 = 8;

/// #941 Work item D — N drain calls of V_min suspension after a
/// hard-cap activation. At ~5 K successful drain invocations/sec
/// under load, N=1000 ≈ 200 ms suspension window — long enough for
/// peers to either catch up or visibly persist as out-of-band, and
/// short enough that mouse-latency budgets (#905) are unaffected.
pub(in crate::afxdp) const V_MIN_SUSPENSION_BATCHES: u32 = 1000;

#[inline]
pub(in crate::afxdp) fn cos_item_len(item: &CoSPendingTxItem) -> u64 {
    match item {
        CoSPendingTxItem::Local(req) => req.bytes.len() as u64,
        CoSPendingTxItem::Prepared(req) => req.len as u64,
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
