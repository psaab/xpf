// Token-bucket lease/refill plumbing for TX pacing.
//
// `COS_MIN_BURST_BYTES` (64 × MTU) is the DEFAULT (unset) floor for
// both root and per-queue burst caps and lives here as canonical
// owner. Explicit values use the one-frame floor via
// `cos_effective_burst_bytes` (#16545).
//
// The 3 per-byte helpers (`refill_cos_tokens`,
// `maybe_top_up_cos_root_lease`, `maybe_top_up_cos_queue_lease`)
// carry `#[inline]` to preserve cross-module inlining at the
// `pub(in crate::afxdp)` boundary. The other 4 helpers fire at
// most once per drain loop or once per RG-transition / shutdown,
// so they stay un-attributed.

use std::sync::Arc;

use crate::afxdp::types::{
    AcquireV8ShortfallCause, CoSInterfaceRuntime, CoSQueueRuntime, SharedCoSQueueLease,
    SharedCoSRootLease,
};
use crate::afxdp::worker::BindingWorker;
use crate::afxdp::worker_runtime::CoSQueueLeaseUndergrantCounters;
use crate::afxdp::{tx_frame_capacity, COS_EXACT_QUEUE_LEASE_BANK_BYTES};

/// Default (unset) floor for both root and per-queue burst-byte caps
/// (64 × default MTU = 96 KB). Applied only when no explicit value was
/// configured (`forwarding_build` substitutes this floor for a zero
/// rate-derived default, and zero buffer/burst reaching the runtime is
/// treated as unset). Explicit operator values are NOT raised to this
/// floor — see `cos_effective_burst_bytes`.
pub(in crate::afxdp) const COS_MIN_BURST_BYTES: u64 = 64 * 1500;

/// Effective burst/buffer cap for a configured value (#16545).
///
/// An explicit (non-zero) value is honoured as configured, floored only
/// at one max frame (`tx_frame_capacity`) so a single max-len frame can
/// always fit. A zero value means unset and keeps the
/// `COS_MIN_BURST_BYTES` default floor. Raising explicit values to
/// 96 KB silently defeated documented low-rate latency/burst bounds
/// (e.g. `buffer-size temporal 10ms` at 125 kB/s = 1250 B became
/// 96 KB = 768 ms of queueing).
#[inline]
pub(in crate::afxdp) fn cos_effective_burst_bytes(configured: u64) -> u64 {
    if configured == 0 {
        COS_MIN_BURST_BYTES
    } else {
        configured.max(tx_frame_capacity() as u64)
    }
}

/// Worker-local observation of v8 queue-lease acquisitions. The hot path
/// accumulates this in `WorkerCos`, not in the shared lease, so the
/// diagnostic path does not add cross-worker atomics to `acquire_v8`.
#[must_use = "queue-lease acquire telemetry must be accumulated by the caller"]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::afxdp) struct CoSQueueLeaseAcquireTelemetry {
    pub(in crate::afxdp) v8_calls: u64,
    pub(in crate::afxdp) v8_granted_bytes: u64,
    /// #1782 Step-1 (ii): shortfall cause reported by the most recent
    /// v8 acquire observed through this telemetry value. On a per-call
    /// `maybe_top_up_cos_queue_lease` return this is exactly that
    /// call's cause (`None` when no v8 acquire ran or it granted in
    /// full); on an accumulated value `add_assign` keeps the latest
    /// non-`None` cause as a diagnostic. The selector sites read the
    /// PER-CALL value before merging, so accumulation semantics never
    /// drive counting.
    pub(in crate::afxdp) v8_shortfall_cause: AcquireV8ShortfallCause,
    /// #1782 Step-1 (ii): per-cause under-grant counts recorded by the
    /// selector sites via `count_v8_undergrant` (only when the
    /// post-top-up `queue.hot.tokens < head_len` comparison fails).
    pub(in crate::afxdp) v8_undergrants: CoSQueueLeaseUndergrantCounters,
}

impl CoSQueueLeaseAcquireTelemetry {
    #[inline]
    pub(in crate::afxdp) fn add_assign(&mut self, other: Self) {
        self.v8_calls = self.v8_calls.wrapping_add(other.v8_calls);
        self.v8_granted_bytes = self.v8_granted_bytes.wrapping_add(other.v8_granted_bytes);
        if other.v8_shortfall_cause != AcquireV8ShortfallCause::None {
            self.v8_shortfall_cause = other.v8_shortfall_cause;
        }
        self.v8_undergrants.add_assign(&other.v8_undergrants);
    }

    #[inline]
    fn record_v8_grant(&mut self, granted: u64, cause: AcquireV8ShortfallCause) {
        self.v8_calls = self.v8_calls.wrapping_add(1);
        self.v8_granted_bytes = self.v8_granted_bytes.wrapping_add(granted);
        self.v8_shortfall_cause = cause;
    }

    /// #1782 Step-1 (ii): attribute one under-grant observation
    /// (`queue.hot.tokens < head_len` after a top-up) to the given v8
    /// shortfall cause. `None` is deliberately NOT counted — those
    /// under-grants are ordinary token pacing (legacy lease, no lease,
    /// or a fully-granted acquire still below `head_len` watermarks)
    /// already visible via `drain_park_queue_tokens`.
    #[inline]
    pub(in crate::afxdp) fn count_v8_undergrant(&mut self, cause: AcquireV8ShortfallCause) {
        let c = &mut self.v8_undergrants;
        match cause {
            AcquireV8ShortfallCause::None => {}
            AcquireV8ShortfallCause::SeqlockGiveUp => {
                c.seqlock_give_up = c.seqlock_give_up.wrapping_add(1);
            }
            AcquireV8ShortfallCause::CapZero => {
                c.cap_zero = c.cap_zero.wrapping_add(1);
            }
            AcquireV8ShortfallCause::EpochRotated => {
                c.epoch_rotated = c.epoch_rotated.wrapping_add(1);
            }
            AcquireV8ShortfallCause::ShareExhausted => {
                c.share_exhausted = c.share_exhausted.wrapping_add(1);
            }
            AcquireV8ShortfallCause::ClassCap => {
                c.class_cap = c.class_cap.wrapping_add(1);
            }
            AcquireV8ShortfallCause::OutstandingCap => {
                c.outstanding_cap = c.outstanding_cap.wrapping_add(1);
            }
        }
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
        root.tokens = cos_effective_burst_bytes(root.burst_bytes);
        return;
    }
    // Ensure the target is at least tx_frame_capacity() so that a maximum-sized frame
    // can always become eligible.  shared_root_lease already sizes max_total_leased using
    // lease_bytes.max(tx_frame_capacity()), so the shared pool can always satisfy this.
    let lease_bytes = shared_root_lease
        .lease_bytes()
        .max(tx_frame_capacity() as u64)
        .min(cos_effective_burst_bytes(root.burst_bytes));
    if root.tokens >= lease_bytes {
        return;
    }
    let grant = shared_root_lease.acquire(now_ns, lease_bytes.saturating_sub(root.tokens));
    root.tokens = root
        .tokens
        .saturating_add(grant)
        .min(cos_effective_burst_bytes(root.burst_bytes));
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
        let (granted, cause) = lease.acquire_v8_with_cause(worker_id, now_ns, requested);
        let mut telemetry = CoSQueueLeaseAcquireTelemetry::default();
        telemetry.record_v8_grant(granted, cause);
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
        queue.hot.tokens = cos_effective_burst_bytes(queue.config.buffer_bytes);
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
        // #1630 (P1): raise the exact-queue top-up watermark from
        // `lease_bytes` (= rate × 200 µs, floored at one frame) to an
        // N-frame burst bank. A low-rate class could otherwise bank only
        // ~1-2 frames and lost the unspent per-epoch lease cap at each
        // rotation, pinning it well below its configured rate. The bucket
        // accumulates the surplus across epochs via the `saturating_add`
        // in the credit path; the long-run rate stays metered by the v8
        // per-epoch grant (`rate × elapsed`, #1630 cause-1 carry) and the
        // actual-byte debit in tx_completion, so the hard-cap (Gate 4) is
        // preserved. The companion `max_total_leased` raise in
        // `compute_shared_cos_lease_config` keeps the outstanding-credit
        // cap from defeating this watermark at low `active_shards`.
        let lease_bytes = shared_queue_lease
            .lease_bytes()
            .max(COS_EXACT_QUEUE_LEASE_BANK_BYTES)
            .max(tx_frame_capacity() as u64)
            .min(cos_effective_burst_bytes(queue.config.buffer_bytes));
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
            .min(cos_effective_burst_bytes(queue.config.buffer_bytes));
        queue.hot.last_refill_ns = now_ns;
        return telemetry;
    }
    let Some(shared_queue_lease) = shared_queue_lease else {
        let transmit_rate_bytes = queue.transmit_rate_bytes();
        refill_cos_tokens(
            &mut queue.hot.tokens,
            transmit_rate_bytes,
            cos_effective_burst_bytes(queue.config.buffer_bytes),
            &mut queue.hot.last_refill_ns,
            now_ns,
        );
        return CoSQueueLeaseAcquireTelemetry::default();
    };
    let lease_bytes = shared_queue_lease
        .lease_bytes()
        .max(tx_frame_capacity() as u64)
        .min(cos_effective_burst_bytes(queue.config.buffer_bytes));
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
        .min(cos_effective_burst_bytes(queue.config.buffer_bytes));
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
    let scaled = (elapsed_ns as u128) * (rate_bytes_per_sec as u128);
    let added = (scaled / 1_000_000_000u128) as u64;
    if added == 0 {
        // No whole byte accrued this call. Leave `last_refill_ns`
        // untouched so the sub-byte credit keeps accumulating against
        // the original timestamp (advancing it here would discard it —
        // the #4261 dust bug for low-rate classes).
        return;
    }
    *tokens = tokens.saturating_add(added).min(burst_bytes);
    // #4261 (hb166 R-4) — carry the fractional remainder across refills.
    // `added` floors the byte grant; advancing `last_refill_ns` fully to
    // `now_ns` would discard `scaled % 1e9` byte-nanoseconds of accrued-
    // but-ungranted credit EVERY refill. At 64 kbps (8000 B/s) on the
    // ~200 µs drain cadence that is added = 1.6 → 1 with 0.6 B dropped per
    // interval — a 37.5% shortfall the low-rate class never recovers.
    // Instead of advancing to `now_ns`, rewind by the time-equivalent of
    // the ungranted fraction so it stays on the clock for the next refill.
    // `remainder` is the leftover byte-nanoseconds (`< 1e9`); dividing by
    // the rate converts it back to the elapsed time not yet turned into a
    // whole byte. Conservation: cumulative granted == floor(total_elapsed ×
    // rate / 1e9), matching the #1630 byte-carry precedent one decade up.
    // Bounds: `leftover_ns = remainder / rate ≤ elapsed_ns` (remainder ≤
    // elapsed×rate), so `now_ns - leftover_ns` stays in
    // `[*last_refill_ns, now_ns]` — the timestamp never moves backward and
    // never overshoots. `rate_bytes_per_sec != 0` is guaranteed by the
    // early return above, so the division is safe.
    let remainder = scaled - (added as u128) * 1_000_000_000u128;
    let leftover_ns = (remainder / (rate_bytes_per_sec as u128)) as u64;
    *last_refill_ns = now_ns - leftover_ns;
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
    release_cos_root_lease_on_cos(&mut binding.cos, root_ifindex);
}

/// #17186: field-split form for callers holding only `&mut WorkerCos`.
pub(in crate::afxdp) fn release_cos_root_lease_on_cos(
    cos: &mut crate::afxdp::worker::WorkerCos,
    root_ifindex: i32,
) {
    let released = cos
        .cos_interfaces
        .get_mut(&root_ifindex)
        .map(|root| core::mem::take(&mut root.tokens))
        .unwrap_or(0);
    if released == 0 {
        return;
    }
    if let Some(shared_root_lease) = cos
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
                // #5156 (teardown half): give back EVERY queue that holds
                // banked tokens, not just exact ones. A non-exact
                // lease-metered queue (#4265) acquires its buffer_bytes
                // through the shared lease at runtime, so its outstanding
                // credit must be returned here on worker exit / binding
                // reset / lease-set swap — otherwise the (often reused)
                // lease Arc stays permanently over-charged and under-
                // provisions the class. The per-queue loop below gates BOTH
                // the `mem::take` AND the credit on `shared_queue_lease
                // .is_some()` (#6272), so a truly un-leased queue (single-
                // owner exact OR single-owner non-exact) KEEPS its private
                // per-worker burst — there is nowhere to give it back —
                // exactly mirroring the runtime empty give-back in
                // `refresh_cos_interface_activity` (R-5(a)), which already
                // keys the take on lease presence rather than `exact`.
                .filter(|(_, queue)| queue.hot.tokens > 0)
                .map(move |(queue_idx, _)| (root_ifindex, queue_idx))
        })
        .collect::<Vec<_>>();
    for (root_ifindex, queue_idx) in queue_keys {
        // #6272: gate the `mem::take` ITSELF on lease presence, mirroring the
        // runtime give-back `refresh_cos_interface_activity` (R-5(a)). An
        // un-leased queue (single-owner exact OR single-owner non-exact) has
        // nowhere to return its banked burst, so leave `hot.tokens` intact —
        // zeroing it would destroy the private per-worker burst on a mere
        // lease-set swap (loop_body persists `cos_interfaces` while it rebuilds
        // `cos_fast_interfaces`), contradicting the #6270 contract. The probe
        // reads the disjoint `cos_fast_interfaces` field, so it coexists with
        // the `cos_interfaces` mutable borrow below.
        let has_lease = binding
            .cos
            .cos_fast_interfaces
            .get(&root_ifindex)
            .and_then(|iface_fast| iface_fast.queue_fast_path.get(queue_idx))
            .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref())
            .is_some();
        if !has_lease {
            continue;
        }
        // Capture the worker id alongside the take — the v8 give-back needs
        // it to re-credit the right per-worker grant slot (#4246 T-1).
        let taken = binding
            .cos
            .cos_interfaces
            .get_mut(&root_ifindex)
            .and_then(|root| root.queues.get_mut(queue_idx))
            .map(|queue| {
                (
                    queue.v_min.worker_id as usize,
                    core::mem::take(&mut queue.hot.tokens),
                )
            });
        let Some((worker_id, released)) = taken else {
            continue;
        };
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
            // #4246 (T-1): re-credit the v8 epoch ledger on teardown too, so
            // a rebind/config-swap does not leave the class parked at
            // ClassCap. No-op v8 leg for legacy leases.
            shared_queue_lease.release_unused_v8(worker_id, released);
        }
    }
}

#[cfg(test)]
#[path = "token_bucket_tests.rs"]
mod tests;
