// CoS queue primitives: accessors, enqueue/dequeue, MQFQ ordering
// bookkeeping, V-min slot lifecycle. Per-byte hot-path fns carry
// `#[inline]` to preserve cross-module inlining at the
// `pub(in crate::afxdp)` boundary.

use std::collections::VecDeque;

use crate::afxdp::types::{CoSPendingTxItem, CoSQueuePopSnapshot, CoSQueueRuntime, FlowFairState};
use crate::afxdp::TX_BATCH_SIZE;
use crate::session::SessionKey;

use super::flow_hash::{cos_flow_bucket_index, cos_flow_hash_seed_from_os, cos_item_flow_key};

// #1034 P1: MQFQ V_min coordination split into a sibling submodule.
mod v_min;
pub(in crate::afxdp) use v_min::{
    cos_queue_v_min_consume_suspension, cos_queue_v_min_continue, publish_committed_queue_vtime,
};

// #1034 P2: flow accounting + drain orchestration split into siblings.
mod accounting;
mod drain;
// #1229 Phase 6 v8: centralized active-bucket transition helpers.
// Plan §v8.1. The canonical pattern for mutating `active_flow_buckets`
// is in `active_buckets.rs` — it handles both the local count and the
// v8 lease's per-worker counter atomically. Existing call sites
// (accounting.rs, push.rs) inline the equivalent logic directly because
// they already hold an `&mut FlowFairState` borrow for adjacent
// finish-time math; the helpers are available for future call sites
// that don't have an active `ff` borrow.
pub(in crate::afxdp) mod active_buckets;
use accounting::{account_cos_queue_flow_dequeue, account_cos_queue_flow_enqueue};
pub(in crate::afxdp) use drain::{
    cos_queue_clear_orphan_snapshot_after_drop, cos_queue_drain_all,
    cos_queue_remove_orphan_snapshot_at, cos_queue_restore_front,
};

// #1034 P3: push + pop ops split into siblings.
mod pop;
mod push;
// #1763: `cos_queue_pop_front` / `cos_queue_pop_front_with_cap` are now
// fused out of production (peek_min_bucket + pop_known_bucket). They are
// retained as the reference single-pop API used by tests (incl. the
// fused-vs-reference differential oracle). #17195: they are `#[cfg(test)]`
// in pop.rs, so the re-export is test-only too.
#[cfg(test)]
pub(in crate::afxdp) use pop::{cos_queue_pop_front, cos_queue_pop_front_with_cap};
pub(in crate::afxdp) use pop::{cos_queue_pop_front_no_snapshot, cos_queue_pop_known_bucket};
pub(in crate::afxdp) use push::{cos_queue_push_back, cos_queue_push_front};

#[inline]
pub(in crate::afxdp) fn cos_queue_is_empty(queue: &CoSQueueRuntime) -> bool {
    if !queue.flow_fair() {
        return queue.hot.items.is_empty();
    }
    // Invariant: `flow_fair() == true` ↔ `flow_fair_state.is_some()`.
    // Returning "empty" on a structural invariant violation would mask
    // the bug and stall selection.
    let ff = queue
        .flow_fair_state
        .as_ref()
        .expect("cos_queue_is_empty: flow_fair queue without flow_fair_state");
    ff.flow_rr_buckets.is_empty()
}

#[inline]
pub(in crate::afxdp) fn cos_queue_len(queue: &CoSQueueRuntime) -> usize {
    if !queue.flow_fair() {
        return queue.hot.items.len();
    }
    // Invariant: see cos_queue_is_empty. Returning 0 on violation would
    // mask the bug.
    let ff = queue
        .flow_fair_state
        .as_ref()
        .expect("cos_queue_len: flow_fair queue without flow_fair_state");
    ff.flow_rr_buckets
        .iter()
        .map(|bucket| ff.flow_bucket_items[usize::from(bucket)].len())
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
/// #1229 v7: when `target_bps < u64::MAX`, skip buckets whose
/// EWMA-observed rate exceeds the per-bucket fair-share target. If
/// all buckets are over-cap we fall back to the lowest-finish bucket
/// unconditionally (work-conserving — same behavior as standard
/// MQFQ). With `target_bps = u64::MAX` (the default for callers that
/// don't compute a cap), the eligibility check is a no-op:
/// `observed_bps <= u64::MAX` always holds.
///
/// If we ever profile this as hot (e.g. with thousands of active
/// flows on a single queue), the replacement is a min-heap keyed by
/// `flow_bucket_head_finish_bytes`. For iperf3-sized workloads the
/// linear scan is cache-friendlier and simpler.
///
/// #1763 Lever B — no-cap fast path. When `target_bps == u64::MAX`
/// (every `cos_queue_front` / `cos_queue_pop_front` caller, i.e. the
/// whole best-effort builder) `observed <= u64::MAX` is always true,
/// so `eligible == fallback` always holds and the two-pass plus the
/// second strided `flow_bucket_observed_bps` load are dead work. The
/// no-cap branch scans only `flow_bucket_head_finish_bytes`, removing
/// one big-array load per bucket (the two arrays live on different
/// cache lines, so this halves the per-bucket cache-miss exposure).
/// The selected bucket is **byte-identical** to the cap-aware pass at
/// `target_bps == u64::MAX`: both return the lowest-finish active
/// bucket (first-wins on ties, since `<` is strict).
#[inline]
fn cos_queue_min_finish_bucket(ff: &FlowFairState, target_bps: u64) -> Option<u16> {
    if target_bps == u64::MAX {
        return cos_queue_min_finish_bucket_no_cap(ff);
    }
    let mut eligible: Option<u16> = None;
    let mut eligible_finish = u64::MAX;
    let mut fallback: Option<u16> = None;
    let mut fallback_finish = u64::MAX;
    for bucket in ff.flow_rr_buckets.iter() {
        let b = usize::from(bucket);
        let finish = ff.flow_bucket_head_finish_bytes[b];
        // #hb166 T-7: distinguish "no bucket chosen yet" from a real
        // head-finish that has SATURATED to u64::MAX. `head_finish` is a
        // saturating cumulative byte counter; if it ever reaches u64::MAX
        // (the same value seeded into `*_finish` as the not-found
        // sentinel), the bare `finish < *_finish` compare would skip that
        // bucket forever — a permanently unselectable active bucket whose
        // packets never drain. Gating on `is_none()` selects the FIRST
        // active bucket regardless of its finish value, keeping the
        // domains disjoint. Byte-identical to the pre-fix selection for
        // every non-saturated input (strict `<` still gives first-wins on
        // ties). Mirrors the R-8(b)/#4271 vtime-sentinel clamp for the
        // head-finish domain (which #4271 did NOT cover).
        if fallback.is_none() || finish < fallback_finish {
            fallback_finish = finish;
            fallback = Some(bucket);
        }
        let observed = ff.flow_bucket_observed_bps[b];
        if observed <= target_bps && (eligible.is_none() || finish < eligible_finish) {
            eligible_finish = finish;
            eligible = Some(bucket);
        }
    }
    eligible.or(fallback)
}

/// #1763 Lever B — the `target_bps == u64::MAX` specialization of
/// `cos_queue_min_finish_bucket`. Single pass, single big-array load
/// per bucket. Returns the lowest-`flow_bucket_head_finish_bytes`
/// active bucket, first-wins on ties — identical selection to the
/// cap-aware loop evaluated at `target_bps == u64::MAX`, where every
/// bucket is eligible so `eligible` collapses onto `fallback`.
#[inline]
fn cos_queue_min_finish_bucket_no_cap(ff: &FlowFairState) -> Option<u16> {
    let mut best: Option<u16> = None;
    let mut best_finish = u64::MAX;
    for bucket in ff.flow_rr_buckets.iter() {
        let finish = ff.flow_bucket_head_finish_bytes[usize::from(bucket)];
        // #hb166 T-7: gate on `is_none()` so a head-finish that has
        // SATURATED to u64::MAX (the same value seeded as the not-found
        // sentinel) is still selectable — otherwise it becomes a
        // permanently unselectable active bucket. Byte-identical to the
        // pre-fix selection for every non-saturated input (strict `<`
        // keeps first-wins on ties); stays in lockstep with the cap-aware
        // `cos_queue_min_finish_bucket` scan above.
        if best.is_none() || finish < best_finish {
            best_finish = finish;
            best = Some(bucket);
        }
    }
    best
}

#[inline]
pub(in crate::afxdp) fn cos_queue_front(queue: &CoSQueueRuntime) -> Option<&CoSPendingTxItem> {
    if !queue.flow_fair() {
        return queue.hot.items.front();
    }
    // Invariant: see cos_queue_is_empty. Silent None here would cause
    // drain callers to treat a flow_fair queue as empty and skip it.
    let ff = queue
        .flow_fair_state
        .as_ref()
        .expect("cos_queue_front: flow_fair queue without flow_fair_state");
    // #785 Phase 3 — MQFQ: return the head of the bucket with the
    // smallest virtual-finish-time, not the DRR-rotation head. This
    // is the byte-rate-fair dequeue order (classical SFQ / WFQ).
    let bucket = usize::from(cos_queue_min_finish_bucket(ff, u64::MAX)?);
    ff.flow_bucket_items[bucket].front()
}

/// #1229 v7: cap-aware variant of `cos_queue_front` for the drain
/// path. Skips over-cap buckets when `target_bps` is finite; falls
/// back to the lowest-finish bucket if all are over-cap. Used by
/// `drain_exact_local_items_to_scratch_flow_fair` to throttle hot
/// flows so cooler flows on the same queue (or other workers via
/// the shared CoS lease) get bandwidth.
#[inline]
pub(in crate::afxdp) fn cos_queue_front_with_cap(
    queue: &CoSQueueRuntime,
    target_bps: u64,
) -> Option<&CoSPendingTxItem> {
    if !queue.flow_fair() {
        return queue.hot.items.front();
    }
    let ff = queue
        .flow_fair_state
        .as_ref()
        .expect("cos_queue_front_with_cap: flow_fair queue without flow_fair_state");
    let bucket = usize::from(cos_queue_min_finish_bucket(ff, target_bps)?);
    ff.flow_bucket_items[bucket].front()
}

/// #1763 Lever A — fused select+peek that ALSO returns the selected
/// MQFQ bucket id so the caller can pop that exact bucket via
/// `cos_queue_pop_known_bucket` without a second min-finish scan.
///
/// The drain hot paths peek-then-pop with NO queue mutation between
/// the two calls, so the second `cos_queue_min_finish_bucket` scan
/// inside `cos_queue_pop_front*` re-derives the identical bucket. This
/// helper hands the peek's chosen bucket to the pop so the redundant
/// scan is removed on every committed pop.
///
/// Selection is byte-identical to `cos_queue_front_with_cap`: it calls
/// the same `cos_queue_min_finish_bucket`. The returned `bucket` is the
/// active-set winner; the returned item is that bucket's head.
///
/// FIFO (non-flow-fair) queues return a `MIN_FINISH_BUCKET_FIFO`
/// sentinel for the bucket; `cos_queue_pop_known_bucket` ignores the
/// bucket on the FIFO path (it pops the hot deque directly), so the
/// sentinel never indexes a bucket array.
#[inline]
pub(in crate::afxdp) fn cos_queue_peek_min_bucket(
    queue: &CoSQueueRuntime,
    target_bps: u64,
) -> Option<(u16, &CoSPendingTxItem)> {
    if !queue.flow_fair() {
        return queue
            .hot
            .items
            .front()
            .map(|item| (MIN_FINISH_BUCKET_FIFO, item));
    }
    let ff = queue
        .flow_fair_state
        .as_ref()
        .expect("cos_queue_peek_min_bucket: flow_fair queue without flow_fair_state");
    let bucket_u16 = cos_queue_min_finish_bucket(ff, target_bps)?;
    let item = ff.flow_bucket_items[usize::from(bucket_u16)].front()?;
    Some((bucket_u16, item))
}

/// #1763 — sentinel bucket id returned by `cos_queue_peek_min_bucket`
/// for FIFO (non-flow-fair) queues. `cos_queue_pop_known_bucket`
/// branches on `queue.flow_fair()` and never indexes a bucket array
/// with this value on the FIFO path, so the exact value is immaterial;
/// it is documented as "not a real bucket" for the debug_assert and
/// reader clarity.
pub(in crate::afxdp) const MIN_FINISH_BUCKET_FIFO: u16 = u16::MAX;

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

/// #hb166 T-6(a) — floor for the decaying re-arm of the V_min
/// suspension window. Each consecutive hard-cap activation (no
/// intervening passing V_min check) halves the suspension window from
/// `V_MIN_SUSPENSION_BATCHES` toward this floor, so a PERSISTENTLY
/// skewed shared_exact queue re-engages the fairness brake far sooner
/// than the fixed 1000-batch (~200 ms) window would — instead of the
/// brake staying off ~99% of the time. A clean V_min check resets the
/// window back to `V_MIN_SUSPENSION_BATCHES`.
pub(in crate::afxdp) const V_MIN_SUSPENSION_MIN_BATCHES: u32 = 64;

/// #1735: consecutive quiescent batch settles required before a
/// lazily-promoted non-exact flow-fair queue is demoted back to FIFO
/// (dropping its ~232 KB `FlowFairState`). Hysteresis so a queue
/// oscillating 1<->2 flows does not thrash the alloc/free. 4 settles is
/// long enough to ride out a brief gap between bursts of the same flow
/// pair, short enough that a genuinely idle best-effort queue releases
/// the footprint within a handful of drain ticks.
pub(in crate::afxdp) const COS_DEMOTE_EMPTY_SETTLE_HYSTERESIS: u8 = 4;

/// #1735: lazy demotion at a quiescent batch-settle boundary.
///
/// Called at the END of `apply_cos_send_result` / `apply_cos_prepared_result`,
/// strictly AFTER `restore_cos_local_items_inner` has push_fronted any
/// retry items back and `queued_bytes` is settled. Only NON-exact
/// lazily-promoted queues demote; exact queues promote eagerly at build
/// and stay promoted for the interface's lifetime (their V_min / v8
/// lease coordination assumes a stable `flow_fair_state`).
///
/// Quiescence predicate (Codex round-1 Q4): the queue must be fully
/// drained — `active_flow_buckets == 0 && flow_rr_buckets empty &&
/// queued_bytes == 0`. Because this runs AFTER the retry restore (which
/// re-bumps `active_flow_buckets` / `queued_bytes` via push_front of
/// each retried item), a partial-commit retry leaves the queue
/// non-quiescent and blocks demotion — demote fires only on a
/// fully-committed empty queue.
///
/// Note we do NOT gate on an empty `pop_snapshot_stack`. The non-exact
/// service path (`build_cos_batch_from_queue` → `cos_queue_pop_front`
/// with snapshots) leaves committed-batch snapshots on the stack, and
/// nothing clears them while the queue stays idle (only a subsequent
/// `cos_queue_push_back` does, at push.rs:38). Those snapshots are
/// STALE the moment the queue is fully drained — they describe
/// pre-pop bucket state for items that have all committed, with no
/// resident items left to roll back to. Gating on the stack would make
/// demotion structurally impossible. Dropping the whole `FlowFairState`
/// box discards the stale snapshots safely; the next promotion starts
/// from a fresh empty stack.
#[inline]
pub(in crate::afxdp) fn maybe_demote_drained_best_effort(queue: &mut CoSQueueRuntime) {
    // Exact queues never demote (eager promotion is permanent).
    if queue.config.exact || !queue.config.flow_fair_eligible {
        return;
    }
    let Some(ff) = queue.flow_fair_state.as_ref() else {
        return;
    };
    if ff.active_flow_buckets != 0
        || !ff.flow_rr_buckets.is_empty()
        || queue.hot.queued_bytes != 0
    {
        queue.hot.cos_demote_empty_settles = 0;
        return;
    }
    queue.hot.cos_demote_empty_settles = queue.hot.cos_demote_empty_settles.saturating_add(1);
    if queue.hot.cos_demote_empty_settles >= COS_DEMOTE_EMPTY_SETTLE_HYSTERESIS {
        // Drop the ~232 KB FlowFairState box (incl. any stale committed-
        // batch snapshots); the queue reverts to the cheap FIFO path
        // until the front-key probe re-promotes it.
        queue.flow_fair_state = None;
        queue.hot.cos_demote_empty_settles = 0;
    }
}

#[inline]
pub(in crate::afxdp) fn cos_item_len(item: &CoSPendingTxItem) -> u64 {
    match item {
        CoSPendingTxItem::Local(req) => req.bytes.len() as u64,
        CoSPendingTxItem::Prepared(req) => req.len as u64,
    }
}

/// Whether a guaranteed exact queue DEMANDS its reserved rate: it is
/// backlogged and its OWN token bucket covers the head packet, so the only
/// thing that can hold it back is the shared root. Callers still apply the
/// `exact && guarantee_enabled` config gate separately.
///
/// #hb166 T-6(b) introduced the release rule this keeps: an exact class
/// that is backlogged but ships zero bytes because it is limited by ITSELF
/// (its own rate is spent and it parked on queue tokens, or its v8 lease is
/// not granting) must not reserve its rate, or best-effort is held to the
/// residual while the link idles. Every such state has `tokens < head`.
///
/// #18748 narrowed what counts as "limited by itself". T-6(b) required the
/// queue to be serviceable right now: runnable and holding ROOT tokens for
/// its head as well. Every exact selector checks the root before the queue
/// tokens and parks a root-short queue on `RootTokenStarvation`, so a queue
/// that lost the root race dropped out of the local and the published demand
/// masks. Peers' non-exact surplus then ran unconstrained, the greedy root
/// lease gave its worker about 1/N of the root, and the exact queue spent
/// that share ahead of the colocated non-exact queue: the exact class was
/// capped near one worker's share and the colocated non-exact instance got
/// about nothing, a loop that sustained itself. The root is the resource
/// the reservation protects, so a queue short only of root keeps its demand;
/// reserving makes peers yield the root and the reserved rate is spent, not
/// idled. `runnable` is not consulted: a root-parked queue is not runnable,
/// and a queue-token-parked queue is parked only from a `tokens < head`
/// branch and is not topped up until it wakes, so this test releases it.
#[inline]
pub(in crate::afxdp) fn cos_exact_queue_demands_reservation(queue: &CoSQueueRuntime) -> bool {
    cos_queue_front(queue).is_some_and(|head| queue.hot.tokens >= cos_item_len(head))
}

#[cfg(test)]
mod tests;

// #1763 — fused select+pop fairness-neutrality differential test (the
// hard gate: proves byte-identical selection vs the original double-scan).
#[cfg(test)]
#[path = "fused_diff_tests.rs"]
mod fused_diff_tests;
