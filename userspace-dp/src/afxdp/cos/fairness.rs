//! #1229 v7 per-bucket TX rate accounting + threshold-gated EWMA.
//!
//! Tracks observed bits/sec per FlowFair bucket so the cap-aware MQFQ
//! selector can compare against a per-class target rate
//! (`Queue_BW_bps / max(1, active_flow_buckets)`). The bucket whose
//! observed rate is over the cap is deferred in favor of a less-served
//! bucket; if all buckets are over-cap, the selector falls back to
//! standard min-finish MQFQ to avoid stall.
//!
//! All updates are owner-only (single-writer per FlowFairState). The
//! cap-aware selector reads observed_bps without atomic synchronization
//! — the worker that owns this queue is the same worker that calls
//! `account_flow_bucket_tx`, so there is no cross-worker contention.

use crate::afxdp::types::{FlowFairState, COS_FLOW_FAIR_BUCKETS};

/// Minimum dt window for an EWMA roll. Sub-threshold dt accumulates
/// into `flow_bucket_pending_bytes` so back-to-back packets (dt = 100
/// ns at full line rate) cannot inject "100+ Gbps over 100 ns"
/// microspikes into the rate estimate.
///
/// 100 µs picked because it is short enough that TCP cwnd dynamics
/// are visible (cwnd doubles on each RTT, typically 100s of µs to
/// ms), and long enough that a single packet's per-instant rate
/// doesn't dominate. Tunable post-smoke.
pub(in crate::afxdp) const EWMA_MIN_DT_NS: u64 = 100_000;

/// EWMA mixing factor (1/8 weight on the new sample). Heuristic
/// starting point; tunable.
const EWMA_NEW_WEIGHT: u64 = 1;
const EWMA_OLD_WEIGHT: u64 = 7;
const EWMA_TOTAL_WEIGHT: u64 = EWMA_NEW_WEIGHT + EWMA_OLD_WEIGHT;

/// Account `bytes` of committed TX on `bucket` at `now_ns`. Updates
/// the monotonic counter and rolls/defers the EWMA.
///
/// `now_ns` is sampled ONCE per batch commit at the
/// `apply_cos_*_result` call site; this function does NOT sample its
/// own time. Per-packet `monotonic_nanos()` would be a syscall/VDSO
/// read in the hot path — the v6 → v7 fix.
///
/// Single-writer: this function is called only by the worker that
/// owns the FlowFairState (same worker that drains the queue).
#[inline]
pub(in crate::afxdp) fn account_flow_bucket_tx(
    state: &mut FlowFairState,
    bucket: u16,
    bytes: u64,
    now_ns: u64,
) {
    let b = bucket as usize;
    debug_assert!(b < COS_FLOW_FAIR_BUCKETS);

    // Monotonic counter — never decremented.
    state.flow_bucket_tx_bytes[b] = state.flow_bucket_tx_bytes[b].wrapping_add(bytes);

    let last_ns = state.flow_bucket_last_tx_ns[b];
    let pending = state.flow_bucket_pending_bytes[b] as u64;
    let total = pending.saturating_add(bytes);

    if last_ns == 0 {
        // First commit on this bucket since FlowFairState init or
        // reset. Stamp the time and accumulate; defer EWMA roll.
        state.flow_bucket_last_tx_ns[b] = now_ns;
        // Saturate — pending is u32 (max 4 GB). At 25 Gbps × 100 µs =
        // 312 KB and we roll at the next sample, so saturation is
        // unreachable in practice; the `as u32` cast still needs to
        // be defensive.
        state.flow_bucket_pending_bytes[b] = total.min(u32::MAX as u64) as u32;
        return;
    }

    let dt_ns = now_ns.saturating_sub(last_ns);
    if dt_ns < EWMA_MIN_DT_NS {
        // Below threshold: accumulate, do not roll EWMA. This
        // neutralizes back-to-back packet microspikes.
        state.flow_bucket_pending_bytes[b] = total.min(u32::MAX as u64) as u32;
        return;
    }

    // Threshold crossed: compute the average rate over the elapsed
    // window using all bytes that accrued (pending + this packet),
    // and roll EWMA.
    //
    // u128 intermediate: `total * 8 * 1e9` overflows u64 above
    // ~2.3 × 10^9 bytes (2.3 GB), well within reach if a single
    // packet's `bytes` is large or pending has accumulated for a
    // long dt. u128 division by dt_ns then narrows back to u64
    // safely.
    let inst_bps = ((total as u128) * 8 * 1_000_000_000 / (dt_ns as u128)) as u64;

    let smoothed = state.flow_bucket_observed_bps[b];
    state.flow_bucket_observed_bps[b] = if smoothed == 0 {
        // Skip-ramp: first non-zero sample after a long idle (or
        // bucket creation). Initialize observed_bps directly from
        // inst_bps so the cap is responsive immediately, instead of
        // ramping from 0 over many EWMA periods.
        inst_bps
    } else {
        (smoothed * EWMA_OLD_WEIGHT + inst_bps * EWMA_NEW_WEIGHT) / EWMA_TOTAL_WEIGHT
    };

    state.flow_bucket_last_tx_ns[b] = now_ns;
    state.flow_bucket_pending_bytes[b] = 0;
}

/// Compute the per-bucket target rate for the cap-aware selector.
///
/// `queue_bw_bps` is the queue's effective bytes/sec budget under the
/// SharedCoSQueueLease — caller resolves it from
/// `transmit_rate_bps()` for exact-phase or
/// `root_shaping_rate × surplus_share` for surplus-phase.
///
/// `active_flow_buckets` is the existing per-FlowFairState field at
/// `types/cos.rs:551` (single-writer, owner-only — no cross-worker
/// state needed for the per-bucket cap).
///
/// At all flow scales the math gives the right answer:
/// * 12 flows / 4096 buckets → ~12 active buckets each get
///   queue_bw / 12 (per-flow, since collisions are rare).
/// * 100K flows / 4096 buckets → ~4096 active buckets each get
///   queue_bw / 4096; per-flow ≈ queue_bw / 100K via TCP cwnd
///   statistical multiplexing within the bucket.
/// * 1 flow → 1 active bucket gets full queue_bw. Work-conserving.
#[inline]
pub(in crate::afxdp) fn bucket_target_bps(
    queue_bw_bps: u64,
    active_flow_buckets: u16,
) -> u64 {
    let denom = active_flow_buckets.max(1) as u64;
    queue_bw_bps / denom
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_state() -> FlowFairState {
        FlowFairState::new(0)
    }

    #[test]
    fn first_commit_stamps_last_tx_ns_and_skips_ewma() {
        let mut s = fresh_state();
        account_flow_bucket_tx(&mut s, 5, 1500, 1_000_000);
        assert_eq!(s.flow_bucket_tx_bytes[5], 1500);
        assert_eq!(s.flow_bucket_last_tx_ns[5], 1_000_000);
        assert_eq!(s.flow_bucket_pending_bytes[5], 1500);
        // EWMA not rolled on first commit.
        assert_eq!(s.flow_bucket_observed_bps[5], 0);
    }

    #[test]
    fn sub_threshold_dt_accumulates_pending() {
        let mut s = fresh_state();
        account_flow_bucket_tx(&mut s, 5, 1500, 1_000_000);
        // dt = 50 µs < 100 µs threshold.
        account_flow_bucket_tx(&mut s, 5, 1500, 1_050_000);
        assert_eq!(s.flow_bucket_tx_bytes[5], 3000);
        assert_eq!(s.flow_bucket_pending_bytes[5], 3000);
        // EWMA still 0 — never crossed threshold.
        assert_eq!(s.flow_bucket_observed_bps[5], 0);
        // last_tx_ns unchanged from first commit.
        assert_eq!(s.flow_bucket_last_tx_ns[5], 1_000_000);
    }

    #[test]
    fn threshold_crossing_rolls_ewma_with_skip_ramp() {
        let mut s = fresh_state();
        account_flow_bucket_tx(&mut s, 5, 1500, 1_000_000);
        // dt = 200 µs > 100 µs threshold. Total bytes = 1500.
        // inst_bps = 1500 * 8 * 1e9 / 200_000 ns
        //          = 12000 bits / 0.0002 sec = 60_000_000 bps = 60 Mbps.
        // Note: the field name is _bps (bits per second), not bytes/sec.
        account_flow_bucket_tx(&mut s, 5, 0, 1_200_000);
        // Skip-ramp: first non-zero sample after 0 → set directly.
        assert_eq!(s.flow_bucket_observed_bps[5], 60_000_000);
        assert_eq!(s.flow_bucket_pending_bytes[5], 0);
        assert_eq!(s.flow_bucket_last_tx_ns[5], 1_200_000);
    }

    #[test]
    fn ewma_smooths_subsequent_samples() {
        let mut s = fresh_state();
        // Set observed_bps directly to skip the skip-ramp path.
        // 8 Gbps = 8_000_000_000 bps.
        s.flow_bucket_observed_bps[5] = 8_000_000_000;
        s.flow_bucket_last_tx_ns[5] = 1_000_000;

        // dt = 200 µs, bytes = 200_000 → 200_000 * 8 / 0.0002s
        //   = 1_600_000 bits / 0.0002s = 8_000_000_000 bps = 8 Gbps.
        account_flow_bucket_tx(&mut s, 5, 200_000, 1_200_000);
        // (8G * 7 + 8G * 1) / 8 = 8 Gbps unchanged.
        assert_eq!(s.flow_bucket_observed_bps[5], 8_000_000_000);

        // dt = 200 µs, bytes = 400_000 → 16 Gbps inst.
        account_flow_bucket_tx(&mut s, 5, 400_000, 1_400_000);
        // (8G * 7 + 16G * 1) / 8 = 9 Gbps.
        assert_eq!(s.flow_bucket_observed_bps[5], 9_000_000_000);
    }

    #[test]
    fn microspike_neutralized_by_threshold() {
        let mut s = fresh_state();
        account_flow_bucket_tx(&mut s, 5, 1500, 1_000_000);
        // 12 back-to-back packets at 100 ns dt each. Naive EWMA
        // would compute 1500*8e9/100 = 120 Gbps per packet.
        for i in 1..=12 {
            account_flow_bucket_tx(&mut s, 5, 1500, 1_000_000 + i * 100);
        }
        // All 12 packets accumulated into pending; EWMA never rolled
        // because total dt = 1.2 µs < 100 µs.
        assert_eq!(s.flow_bucket_observed_bps[5], 0);
        assert_eq!(s.flow_bucket_pending_bytes[5], 1500 * 13);
        // tx_bytes monotonic accounts everything.
        assert_eq!(s.flow_bucket_tx_bytes[5], 1500 * 13);
    }

    #[test]
    fn bucket_target_bps_basic_math() {
        // 25 Gbps queue, 12 active buckets → 25G/12 ≈ 2.08 Gbps/bucket.
        let target = bucket_target_bps(25_000_000_000, 12);
        assert_eq!(target, 2_083_333_333);
        // 1 active bucket → full queue_bw.
        assert_eq!(bucket_target_bps(25_000_000_000, 1), 25_000_000_000);
        // 0 active buckets → max(1, 0) = 1 → full queue_bw.
        assert_eq!(bucket_target_bps(25_000_000_000, 0), 25_000_000_000);
        // Saturated 4096 buckets → 25G / 4096 ≈ 6.1 Mbps.
        assert_eq!(bucket_target_bps(25_000_000_000, 4096), 6_103_515);
    }
}
