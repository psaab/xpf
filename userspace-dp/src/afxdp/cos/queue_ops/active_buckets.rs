// #1229 Phase 6 v8: centralized helpers for `active_flow_buckets`
// transitions. Plan §v8.1 / docs/pr/1229-cross-worker-vtime/phase6-fair-lease.md.
//
// Every production site that mutates `flow_fair_state.active_flow_buckets`
// MUST go through `bump_active_flow_buckets` / `unbump_active_flow_buckets`.
// The helpers atomically update both the queue-local count AND the v8
// lease's per-worker counter (when `queue_lease_v8` is `Some`).
//
// Why centralized: pre-v8, transitions happened in
// `accounting.rs::account_cos_queue_flow_enqueue/dequeue` AND in
// `push.rs:153` (rollback-with-snapshot path) AND `push.rs:167`
// (idle-bucket rebuild on a fresh-flow push). If the v8 lease delta
// were only wired into `accounting.rs`, the rollback paths would
// undercount; eventually `fetch_sub` on the lease counter would wrap
// `AtomicU32` to `u32::MAX`, poisoning the per-worker fair-share
// denominator. Codex flagged this in v7 review; v8 fixes by funneling
// every site through here.
//
// Single-writer-per-slot invariant: `worker_active_flow_buckets[id]`
// on the v8 lease is written ONLY by worker `id` (the lease's
// per-worker counter is sized to `max_worker_id + 1` and indexed by
// the worker's stable id). Both helpers below take `&mut CoSQueueRuntime`,
// which is owned by the worker thread; no peer can mutate the same slot
// concurrently. The lease counter uses `Relaxed` because we don't need
// inter-worker ordering — only the per-worker delta matters; the
// cross-worker sum is read at epoch rotation under separate seqlock
// snapshot semantics.

use crate::afxdp::types::CoSQueueRuntime;
use std::sync::atomic::Ordering;

/// #1229 Phase 6 v8: increment `active_flow_buckets` by 1 and mirror
/// to the v8 lease's per-worker counter (if attached). Updates the
/// peak counter for telemetry. No-op if the queue has no flow_fair_state.
///
/// **Currently inlined at all four migration sites** (accounting.rs:25,
/// accounting.rs:84, push.rs ~153, push.rs ~167) — those callers
/// already have an `&mut FlowFairState` borrow active for adjacent
/// finish-time math, and re-acquiring `&mut CoSQueueRuntime` through
/// this helper would conflict. The standalone helper exists for
/// FUTURE call sites that emerge without an in-flight `as_mut` borrow,
/// and as a single-source-of-truth comment block describing the
/// canonical bump pattern.
#[allow(dead_code)]
#[inline]
pub(in crate::afxdp) fn bump_active_flow_buckets(queue: &mut CoSQueueRuntime) {
    // Capture worker_id BEFORE the flow_fair_state mutable borrow,
    // since `v_min` and `flow_fair_state` are disjoint fields but the
    // borrow checker is stricter when a method call sits between them.
    let worker_id = queue.v_min.worker_id as usize;

    if let Some(ff) = queue.flow_fair_state.as_mut() {
        ff.active_flow_buckets = ff.active_flow_buckets.saturating_add(1);
        if ff.active_flow_buckets > ff.active_flow_buckets_peak {
            ff.active_flow_buckets_peak = ff.active_flow_buckets;
        }
    } else {
        return;
    }
    // `flow_fair_state` borrow scope ends at the `}` above; reborrow
    // queue for the disjoint `queue_lease_v8` field.
    if let Some(lease) = queue.queue_lease_v8.as_ref() {
        if let Some(slot) = lease.worker_active_flow_buckets_for(worker_id) {
            slot.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// #1229 Phase 6 v8: decrement `active_flow_buckets` by 1 and mirror
/// to the v8 lease's per-worker counter (if attached). Defensive
/// underflow protection on the lease counter — only `fetch_sub` if
/// the slot is currently > 0. The local count uses `saturating_sub`.
/// No-op if the queue has no flow_fair_state.
///
/// See `bump_active_flow_buckets` for the dead-code rationale.
#[allow(dead_code)]
#[inline]
pub(in crate::afxdp) fn unbump_active_flow_buckets(queue: &mut CoSQueueRuntime) {
    let worker_id = queue.v_min.worker_id as usize;

    if let Some(ff) = queue.flow_fair_state.as_mut() {
        debug_assert!(
            ff.active_flow_buckets > 0,
            "unbump_active_flow_buckets: local count already 0"
        );
        ff.active_flow_buckets = ff.active_flow_buckets.saturating_sub(1);
    } else {
        return;
    }
    if let Some(lease) = queue.queue_lease_v8.as_ref() {
        if let Some(slot) = lease.worker_active_flow_buckets_for(worker_id) {
            // Single-writer-per-slot guarantees no concurrent decrement;
            // load-then-fetch_sub is safe and prevents u32 wrap if
            // local/lease counts ever diverge.
            let prev = slot.load(Ordering::Relaxed);
            if prev > 0 {
                slot.fetch_sub(1, Ordering::Relaxed);
            } else {
                debug_assert!(
                    false,
                    "unbump_active_flow_buckets: lease counter already 0"
                );
            }
        }
    }
}
