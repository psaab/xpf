// Token-bucket lease/refill plumbing for TX pacing.
//
// `COS_MIN_BURST_BYTES` (64 × MTU) is the universal floor for both
// root and per-queue burst caps and lives here as canonical owner.
//
// The 3 per-byte helpers (`refill_cos_tokens`,
// `maybe_top_up_cos_root_lease`, `maybe_top_up_cos_queue_lease`)
// carry `#[inline]` to preserve cross-module inlining at the
// `pub(in crate::afxdp)` boundary. The other 4 helpers fire at
// most once per drain loop or once per RG-transition / shutdown,
// so they stay un-attributed.

use std::sync::Arc;

use crate::afxdp::tx_frame_capacity;
use crate::afxdp::types::{
    CoSInterfaceRuntime, CoSQueueRuntime, SharedCoSQueueLease, SharedCoSRootLease,
};
use crate::afxdp::worker::BindingWorker;

/// Universal floor for both root and per-queue burst-byte caps
/// (64 × default MTU = 96 KB). Sized so a single max-len frame can
/// always fit a freshly-allocated queue without immediately tripping
/// the buffer-limit gate.
pub(in crate::afxdp) const COS_MIN_BURST_BYTES: u64 = 64 * 1500;

/// Worker-local observation of v8 queue-lease acquisitions. The hot path
/// accumulates this in `WorkerCos`, not in the shared lease, so the
/// diagnostic path does not add cross-worker atomics to `acquire_v8`.
#[must_use = "queue-lease acquire telemetry must be accumulated by the caller"]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::afxdp) struct CoSQueueLeaseAcquireTelemetry {
    pub(in crate::afxdp) v8_calls: u64,
    pub(in crate::afxdp) v8_granted_bytes: u64,
}

impl CoSQueueLeaseAcquireTelemetry {
    #[inline]
    pub(in crate::afxdp) fn add_assign(&mut self, other: Self) {
        self.v8_calls = self.v8_calls.wrapping_add(other.v8_calls);
        self.v8_granted_bytes = self
            .v8_granted_bytes
            .wrapping_add(other.v8_granted_bytes);
    }

    #[inline]
    fn record_v8_grant(&mut self, granted: u64) {
        self.v8_calls = self.v8_calls.wrapping_add(1);
        self.v8_granted_bytes = self.v8_granted_bytes.wrapping_add(granted);
    }
}

#[inline]
pub(in crate::afxdp) fn maybe_top_up_cos_root_lease(
    root: &mut CoSInterfaceRuntime,
    shared_root_lease: &SharedCoSRootLease,
    now_ns: u64,
) {
    // #916: transparent root. When the interface has no
    // `shaping-rate` configured (Junos default = "no shaping at the
    // interface level"), `shaping_rate_bytes == 0`. Refilling from
    // a zero-rate shared lease is a no-op (the shared lease never
    // accrues tokens), which combined with the rate=0 short-circuit
    // in `cos_refill_ns_until` would leave the queue unable to park
    // OR drain. Fast-path-fill the bucket to its burst cap and
    // skip the lease acquire — the per-queue token buckets continue
    // to gate per-queue rates as configured.
    if root.shaping_rate_bytes == 0 {
        root.tokens = root.burst_bytes.max(COS_MIN_BURST_BYTES);
        return;
    }
    // Ensure the target is at least tx_frame_capacity() so that a maximum-sized frame
    // can always become eligible.  shared_root_lease already sizes max_total_leased using
    // lease_bytes.max(tx_frame_capacity()), so the shared pool can always satisfy this.
    let lease_bytes = shared_root_lease
        .lease_bytes()
        .max(tx_frame_capacity() as u64)
        .min(root.burst_bytes.max(COS_MIN_BURST_BYTES));
    if root.tokens >= lease_bytes {
        return;
    }
    let grant = shared_root_lease.acquire(now_ns, lease_bytes.saturating_sub(root.tokens));
    root.tokens = root
        .tokens
        .saturating_add(grant)
        .min(root.burst_bytes.max(COS_MIN_BURST_BYTES));
}

/// #1229 Phase 6 v8: dispatch lease acquisition between v8 (per-worker
/// fair-share) and legacy (greedy aggregate) paths. Caller's queue
/// must already be lazy-installed via `ensure_v8_lease_attached`.
#[inline]
fn acquire_via_lease(
    lease: &SharedCoSQueueLease,
    queue: &CoSQueueRuntime,
    now_ns: u64,
    requested: u64,
) -> (u64, CoSQueueLeaseAcquireTelemetry) {
    if lease.is_v8() {
        let worker_id = queue.v_min.worker_id as usize;
        let granted = lease.acquire_v8(worker_id, now_ns, requested);
        let mut telemetry = CoSQueueLeaseAcquireTelemetry::default();
        telemetry.record_v8_grant(granted);
        (granted, telemetry)
    } else {
        (
            lease.acquire(now_ns, requested),
            CoSQueueLeaseAcquireTelemetry::default(),
        )
    }
}

/// #1229 Phase 6 v8: lazy worker-side install of v8 lease back-reference
/// onto the queue runtime + initial rehydration of the lease's
/// per-worker active-flow-bucket counter.
///
/// Plan §v5.3 "worker-side rehydration at lease install" + Codex
/// review note F (steps 9 and 10 must land together): this is the
/// single point that makes a v8 lease usable for a worker. After this
/// runs, future bucket transitions in `accounting.rs` and `push.rs`
/// will deltas the lease's per-worker counter (plan §v8.1, commit
/// 22f195aa).
///
/// The rehydration uses THIS runtime's local `active_flow_buckets`
/// — Codex probe answer F (v7 review): "one lease per queue, summed
/// across workers, correct." Per-worker per-queue runtime; no
/// cross-queue summation needed.
#[inline]
fn ensure_v8_lease_attached(queue: &mut CoSQueueRuntime, lease: &Arc<SharedCoSQueueLease>) {
    if !lease.is_v8() {
        return;
    }
    let needs_install = match queue.queue_lease_v8.as_ref() {
        Some(curr) => !Arc::ptr_eq(curr, lease),
        None => true,
    };
    if !needs_install {
        return;
    }
    let count: u32 = queue
        .flow_fair_state
        .as_ref()
        .map(|ff| u32::from(ff.active_flow_buckets))
        .unwrap_or(0);
    let worker_id = queue.v_min.worker_id as usize;
    queue.queue_lease_v8 = Some(Arc::clone(lease));
    // Rehydrate AFTER attaching so the slot reflects current state
    // before any transitions land via the helpers (which are gated on
    // `queue.queue_lease_v8.is_some()`).
    lease.rehydrate_worker_active_count(worker_id, count);
}

#[inline]
pub(in crate::afxdp) fn maybe_top_up_cos_queue_lease(
    queue: &mut CoSQueueRuntime,
    shared_queue_lease: Option<&Arc<SharedCoSQueueLease>>,
    now_ns: u64,
) -> CoSQueueLeaseAcquireTelemetry {
    // #916: transparent queue. When `transmit_rate_bytes == 0`
    // (scheduler had no `transmit-rate` configured AND the parent
    // root has no `shaping-rate`, see the fallback in
    // `forwarding_build.rs`), the per-queue token bucket cannot
    // refill from any rate. Mirror the transparent-root fast path:
    // fill the bucket to its buffer cap and return. Per-queue
    // exact caps with a non-zero scheduler rate are unaffected
    // (queue.transmit_rate_bytes() > 0 in that case).
    if queue.transmit_rate_bytes() == 0 {
        queue.hot.tokens = queue.config.buffer_bytes.max(COS_MIN_BURST_BYTES);
        queue.hot.last_refill_ns = now_ns;
        return CoSQueueLeaseAcquireTelemetry::default();
    }
    // #1229 Phase 6 v8: lazy-install lease back-reference + rehydrate
    // per-worker counter on first sight of a v8 lease. Idempotent:
    // skip if already attached to the same lease Arc. Replacement
    // (HA failover, config change) triggers re-attach + re-rehydrate
    // because the new Arc fails ptr_eq.
    if let Some(lease) = shared_queue_lease {
        ensure_v8_lease_attached(queue, lease);
    }
    if queue.config.exact {
        let Some(shared_queue_lease) = shared_queue_lease else {
            return CoSQueueLeaseAcquireTelemetry::default();
        };
        let lease_bytes = shared_queue_lease
            .lease_bytes()
            .max(tx_frame_capacity() as u64)
            .min(queue.config.buffer_bytes.max(COS_MIN_BURST_BYTES));
        if queue.hot.tokens >= lease_bytes {
            return CoSQueueLeaseAcquireTelemetry::default();
        }
        let (grant, telemetry) = acquire_via_lease(
            shared_queue_lease,
            queue,
            now_ns,
            lease_bytes.saturating_sub(queue.hot.tokens),
        );
        queue.hot.tokens = queue
            .hot
            .tokens
            .saturating_add(grant)
            .min(queue.config.buffer_bytes.max(COS_MIN_BURST_BYTES));
        queue.hot.last_refill_ns = now_ns;
        return telemetry;
    }
    let Some(shared_queue_lease) = shared_queue_lease else {
        let transmit_rate_bytes = queue.transmit_rate_bytes();
        refill_cos_tokens(
            &mut queue.hot.tokens,
            transmit_rate_bytes,
            queue.config.buffer_bytes.max(COS_MIN_BURST_BYTES),
            &mut queue.hot.last_refill_ns,
            now_ns,
        );
        return CoSQueueLeaseAcquireTelemetry::default();
    };
    let lease_bytes = shared_queue_lease
        .lease_bytes()
        .max(tx_frame_capacity() as u64)
        .min(queue.config.buffer_bytes.max(COS_MIN_BURST_BYTES));
    if queue.hot.tokens >= lease_bytes {
        return CoSQueueLeaseAcquireTelemetry::default();
    }
    let (grant, telemetry) = acquire_via_lease(
        shared_queue_lease,
        queue,
        now_ns,
        lease_bytes.saturating_sub(queue.hot.tokens),
    );
    queue.hot.tokens = queue
        .hot
        .tokens
        .saturating_add(grant)
        .min(queue.config.buffer_bytes.max(COS_MIN_BURST_BYTES));
    queue.hot.last_refill_ns = now_ns;
    telemetry
}

#[inline]
pub(in crate::afxdp) fn refill_cos_tokens(
    tokens: &mut u64,
    rate_bytes_per_sec: u64,
    burst_bytes: u64,
    last_refill_ns: &mut u64,
    now_ns: u64,
) {
    if burst_bytes == 0 {
        return;
    }
    if *last_refill_ns == 0 {
        *tokens = burst_bytes;
        *last_refill_ns = now_ns;
        return;
    }
    if now_ns <= *last_refill_ns || rate_bytes_per_sec == 0 {
        return;
    }
    let elapsed_ns = now_ns - *last_refill_ns;
    let added = ((elapsed_ns as u128) * (rate_bytes_per_sec as u128) / 1_000_000_000u128) as u64;
    if added == 0 {
        return;
    }
    *tokens = tokens.saturating_add(added).min(burst_bytes);
    *last_refill_ns = now_ns;
}

/// Time-until-refill helper. Returns `Some(ns)` for the wait-time
/// estimate, or `None` when `tokens < need` AND `rate == 0`
/// (i.e., "the question is unanswerable — there's no rate to
/// refill at").
///
/// **Caller contract for transparent root/queue (#916)**: when
/// `rate_bytes_per_sec == 0`, the bucket is meant to be
/// permanently full (transparent semantic; see
/// `maybe_top_up_cos_root_lease` and `maybe_top_up_cos_queue_lease`
/// fast paths). Callers MUST NOT propagate the `None` return
/// through the `?` operator without first short-circuiting the
/// rate=0 case at the call site (otherwise the queue is never
/// parked AND never served — see `estimate_cos_queue_wakeup_tick`
/// for the canonical handling pattern). The helper preserves the
/// `None` return as a defensive sentinel rather than silently
/// returning `Some(0)` because a zero return would mask
/// "tokens=0, rate=0" as runnable, leading to a busy-loop on the
/// caller side.
pub(in crate::afxdp) fn cos_refill_ns_until(
    tokens: u64,
    need: u64,
    rate_bytes_per_sec: u64,
) -> Option<u64> {
    if tokens >= need {
        return Some(0);
    }
    if rate_bytes_per_sec == 0 {
        return None;
    }
    let deficit = need.saturating_sub(tokens) as u128;
    let rate = rate_bytes_per_sec as u128;
    Some(deficit.saturating_mul(1_000_000_000u128).div_ceil(rate) as u64)
}

pub(in crate::afxdp) fn release_cos_root_lease(binding: &mut BindingWorker, root_ifindex: i32) {
    let released = binding
        .cos
        .cos_interfaces
        .get_mut(&root_ifindex)
        .map(|root| core::mem::take(&mut root.tokens))
        .unwrap_or(0);
    if released == 0 {
        return;
    }
    if let Some(shared_root_lease) = binding
        .cos
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_root_lease.as_ref())
    {
        shared_root_lease.release_unused(released);
    }
}

pub(in crate::afxdp) fn release_all_cos_root_leases(binding: &mut BindingWorker) {
    let root_ifindexes = binding
        .cos
        .cos_interfaces
        .keys()
        .copied()
        .collect::<Vec<_>>();
    for root_ifindex in root_ifindexes {
        release_cos_root_lease(binding, root_ifindex);
    }
}

pub(in crate::afxdp) fn release_all_cos_queue_leases(binding: &mut BindingWorker) {
    let queue_keys = binding
        .cos
        .cos_interfaces
        .iter()
        .flat_map(|(&root_ifindex, root)| {
            root.queues
                .iter()
                .enumerate()
                .filter(|(_, queue)| queue.config.exact && queue.hot.tokens > 0)
                .map(move |(queue_idx, _)| (root_ifindex, queue_idx))
        })
        .collect::<Vec<_>>();
    for (root_ifindex, queue_idx) in queue_keys {
        let released = binding
            .cos
            .cos_interfaces
            .get_mut(&root_ifindex)
            .and_then(|root| root.queues.get_mut(queue_idx))
            .map(|queue| core::mem::take(&mut queue.hot.tokens))
            .unwrap_or(0);
        if released == 0 {
            continue;
        }
        if let Some(shared_queue_lease) = binding
            .cos
            .cos_fast_interfaces
            .get(&root_ifindex)
            .and_then(|iface_fast| iface_fast.queue_fast_path.get(queue_idx))
            .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref())
        {
            shared_queue_lease.release_unused(released);
        }
    }
}

#[cfg(test)]
#[path = "token_bucket_tests.rs"]
mod tests;
