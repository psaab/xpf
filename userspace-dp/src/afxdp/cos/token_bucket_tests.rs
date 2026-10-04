// Tests for afxdp/cos/token_bucket.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep token_bucket.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "token_bucket_tests.rs"]` from token_bucket.rs.

use super::*;
use crate::afxdp::types::EqualFlowTargetPolicy;
use crate::afxdp::tx::test_support::*;
use crate::afxdp::types::{CoSQueueConfig, V8RateMode};

const TEST_EPOCH_DURATION_NS: u64 = 200_000;

#[test]
fn shared_cos_root_lease_bounds_total_outstanding_credit() {
    let lease = SharedCoSRootLease::new(400_000_000, 256 * 1024, 2);
    let lease_bytes = lease.lease_bytes();

    let first = lease.acquire(1, lease_bytes);
    let second = lease.acquire(1, lease_bytes);
    let third = lease.acquire(1, lease_bytes);

    assert_eq!(first, lease_bytes);
    assert_eq!(second, lease_bytes);
    assert_eq!(third, 0);

    lease.release_unused(lease_bytes);
    let fourth = lease.acquire(1, lease_bytes);
    assert_eq!(fourth, lease_bytes);
}

#[test]
fn shared_cos_queue_lease_bounds_total_outstanding_credit() {
    // #1630 (P1): the outstanding-credit cap is now floored at one
    // N-frame burst bank (COS_EXACT_QUEUE_LEASE_BANK_BYTES) so a
    // low-`active_shards` queue can bank the full watermark. At 10 Mbps /
    // 128 KB burst / 2 shards the bank floor (32 KB at N=8) dominates the
    // old `max_frame_lease_bytes × active_shards` term (4096×2 = 8 KB) but
    // stays under `burst/4` (32 KB) and the credit pool (128 KB).
    let lease = SharedCoSQueueLease::new(10_000_000, 128 * 1024, 2);
    let request = 2500;
    let cap = COS_EXACT_QUEUE_LEASE_BANK_BYTES;

    let mut total = 0u64;
    // Drain the lease in `request`-sized chunks; the lease must hand out
    // exactly `cap` bytes of outstanding credit before refusing more.
    loop {
        let granted = lease.acquire(1, request);
        if granted == 0 {
            break;
        }
        total += granted;
        assert!(total <= cap, "outstanding credit exceeded the cap");
    }
    assert_eq!(total, cap, "lease must hand out exactly the bank cap");
    // Further acquires are refused while the credit is outstanding.
    assert_eq!(lease.acquire(1, 1), 0);

    // Releasing frees headroom for a subsequent acquire.
    lease.release_unused(request);
    let after_release = lease.acquire(1, request);
    assert_eq!(after_release, request);
}

#[test]
fn exact_queue_without_shared_lease_does_not_locally_refill() {
    let mut root = test_cos_runtime_with_queues(
        400_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 100_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 125_000,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.tokens = 1500;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;
    let queue_fast_path = vec![test_queue_fast_path(true, 0, None, None)];

    let batch =
        select_cos_guarantee_batch_with_fast_path(&mut root, &queue_fast_path, 1_000_000_000);

    assert!(
        batch.is_none(),
        "exact queues must not locally refill when the shared queue lease is unavailable"
    );
    assert_eq!(root.queues[0].hot.tokens, 0);
    assert_eq!(root.queues[0].hot.last_refill_ns, 0);
}

use crate::afxdp::cos::queue_service::{
    select_cos_guarantee_batch, select_cos_guarantee_batch_with_fast_path,
};

#[test]
fn maybe_top_up_cos_root_lease_unblocks_large_frame_exceeding_lease_bytes() {
    // Pick a shaping rate low enough that lease_bytes() floors to COS_ROOT_LEASE_MIN_BYTES
    // (1500) and stays below tx_frame_capacity() (4096).  At 50 Mbps / 256 KB burst / 1 shard
    // the raw target lease is rate*TARGET_US/1e6 = 1250 bytes, which floors up to 1500.
    // Without the .max(tx_frame_capacity()) fix in maybe_top_up_cos_root_lease, root.tokens
    // could never exceed 1500 and any frame with len > 1500 would deadlock the CoS queue.
    let rate_bytes = 50_000_000u64 / 8;
    let lease = Arc::new(SharedCoSRootLease::new(rate_bytes, 256 * 1024, 1));
    assert!(
        lease.lease_bytes() < tx_frame_capacity() as u64,
        "precondition: lease_bytes must be below tx_frame_capacity for this regression"
    );

    let mut root = test_cos_runtime_with_queues(
        rate_bytes,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: rate_bytes,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let frame_len = tx_frame_capacity();
    root.queues[0].hot.tokens = 64 * 1024;
    root.queues[0].hot.runnable = true;
    root.queues[0].hot.items.push_back(test_cos_item(frame_len));
    root.queues[0].hot.queued_bytes = frame_len as u64;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;

    maybe_top_up_cos_root_lease(&mut root, &lease, 1_000_000_000);

    assert!(
        root.tokens >= frame_len as u64,
        "root tokens ({}) must cover frame len ({}) after lease top-up",
        root.tokens,
        frame_len
    );
    let batch = select_cos_guarantee_batch(&mut root, 1_000_000_000);
    assert!(
        batch.is_some(),
        "large frame must be dequeued after lease top-up"
    );
}

#[test]
fn maybe_top_up_cos_queue_lease_unblocks_local_exact_queue_without_tokens() {
    let mut root = test_cos_runtime_with_queues(
        400_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 400_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.tokens = 1500;
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.items.push_back(test_cos_item(1500));
    root.queues[0].hot.queued_bytes = 1500;
    root.queues[0].hot.runnable = true;
    root.nonempty_queues = 1;
    root.runnable_queues = 1;
    let shared_queue_lease = Arc::new(SharedCoSQueueLease::new(
        400_000_000 / 8,
        COS_MIN_BURST_BYTES,
        2,
    ));
    let queue_fast_path = vec![test_queue_fast_path(
        true,
        0,
        None,
        Some(shared_queue_lease.clone()),
    )];

    let _ = maybe_top_up_cos_queue_lease(
        &mut root.queues[0],
        Some(&shared_queue_lease),
        1_000_000_000,
    );

    assert!(
        root.queues[0].hot.tokens >= 1500,
        "shared exact queue lease must replenish local queue tokens"
    );
    assert!(
        select_cos_guarantee_batch_with_fast_path(&mut root, &queue_fast_path, 1_000_000_000,)
            .is_some()
    );
}

#[test]
fn maybe_top_up_cos_queue_lease_reports_v8_acquire_calls_and_grants() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 100_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.queues[0].hot.tokens = 0;
    root.queues[0].v_min.worker_id = 0;
    let lease = Arc::new(SharedCoSQueueLease::new_v8(
        100_000_000 / 8,
        COS_MIN_BURST_BYTES,
        1,
        0,
    ));
    lease.rehydrate_worker_active_count(0, 1);

    let telemetry = maybe_top_up_cos_queue_lease(&mut root.queues[0], Some(&lease), 200_000);

    assert_eq!(telemetry.v8_calls, 1);
    assert!(
        telemetry.v8_granted_bytes > 0,
        "active v8 worker should receive a nonzero grant"
    );
    assert_eq!(telemetry.v8_granted_bytes, root.queues[0].hot.tokens);
}

#[test]
fn maybe_top_up_cos_queue_lease_enforces_equal_flow_cap() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 100_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: true,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.queues[0].hot.tokens = 0;
    root.queues[0].v_min.worker_id = 0;
    enable_test_flow_fair(&mut root.queues[0]);
    test_flow_fair_state_mut(&mut root.queues[0]).active_flow_buckets = 4;
    let lease = Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode(
        50_000_000,
        256 * 1024,
        8,
        1,
        V8RateMode::EqualFlowSuppress,
    ));
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(1, 1);
    root.queues[0].queue_lease_v8 = Some(lease.clone());

    // Seed two valid skewed epochs through the real v8 lease. Worker 1's
    // slower 1-flow grant establishes a 1,800 B/flow target; worker 0 has
    // four active flow buckets, so the next epoch must cap it at 7,200 B.
    let _ = lease.acquire_v8(0, TEST_EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(1, TEST_EPOCH_DURATION_NS, 1_800);
    let _ = lease.acquire_v8(0, 2 * TEST_EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(1, 2 * TEST_EPOCH_DURATION_NS, 1_800);
    let _ = lease.acquire_v8(1, 3 * TEST_EPOCH_DURATION_NS, 1);
    assert!(lease.v8_equal_flow_enforced());

    let telemetry = maybe_top_up_cos_queue_lease(
        &mut root.queues[0],
        Some(&lease),
        3 * TEST_EPOCH_DURATION_NS,
    );

    assert_eq!(telemetry.v8_calls, 1);
    assert_eq!(telemetry.v8_granted_bytes, 7_200);
    assert_eq!(root.queues[0].hot.tokens, 7_200);
    assert!(
        lease.v8_equal_flow_cap_hit_events() > 0,
        "production top-up path must fire the equal-flow cap"
    );
    assert!(
        lease.v8_equal_flow_suppressed_grant_bytes() > 0,
        "production top-up path must report withheld grant bytes"
    );
}

#[test]
fn maybe_top_up_cos_root_lease_transparent_when_shaping_rate_zero() {
    // #916: transparent root. When the interface has shaping_rate=0,
    // `maybe_top_up_cos_root_lease` MUST fast-path-fill the bucket
    // to its burst cap and skip the (zero-rate) shared lease
    // acquire. Without this, the shared lease's zero-rate refill
    // never grants tokens and the queue never drains.
    let lease = Arc::new(SharedCoSRootLease::new(0, 256 * 1024, 1));
    let mut root = test_cos_runtime_with_queues(
        0, // <- shaping_rate_bytes = 0 (transparent root)
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    // Force tokens to 0 so the top-up has work to do.
    root.tokens = 0;

    maybe_top_up_cos_root_lease(&mut root, &lease, 1_000_000_000);

    assert!(
        root.tokens >= COS_MIN_BURST_BYTES,
        "transparent-root top-up must fast-path-fill to >= COS_MIN_BURST_BYTES, got {}",
        root.tokens,
    );
    assert_eq!(root.shaping_rate_bytes, 0);
}

#[test]
fn maybe_top_up_cos_queue_lease_transparent_when_queue_rate_zero_exact_no_lease() {
    // #916: transparent queue with `exact: true` and NO shared
    // lease. This is the precise case the old code couldn't
    // handle — pre-fix, `if queue.exact { let Some(lease) = ...
    // else { return; } }` returned early without filling tokens.
    // Asserting `tokens >= COS_MIN_BURST_BYTES` after the call
    // fails on the old code (which would leave them at 0).
    //
    // Codex round-1: strengthened to fail against the old path.
    let mut root = test_cos_runtime_with_queues(
        0,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 0,
            guarantee_enabled: true,
            exact: true, // <- precise old-code-failing branch
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.queues[0].hot.tokens = 0;
    root.queues[0].hot.last_refill_ns = 0;

    // No shared queue lease — old code would early-return with
    // tokens still at 0; new code's transparent fast-path runs
    // before the exact branch and fills to the buffer cap.
    let _ = maybe_top_up_cos_queue_lease(&mut root.queues[0], None, 1_000_000_000);

    assert!(
        root.queues[0].hot.tokens >= COS_MIN_BURST_BYTES,
        "transparent-queue + exact + no lease MUST fast-path-fill (old code would leave tokens=0); got {}",
        root.queues[0].hot.tokens,
    );
    assert_eq!(
        root.queues[0].hot.last_refill_ns, 1_000_000_000,
        "last_refill_ns must be advanced to now_ns by the transparent fast path",
    );
}

#[test]
fn maybe_top_up_cos_queue_lease_transparent_non_exact_with_nonzero_last_refill() {
    // #916: companion test covering the non-exact branch. With
    // transmit_rate_bytes=0 + exact=false + no shared lease, the
    // old code fell through to `refill_cos_tokens` which has its
    // own `if rate_bytes_per_sec == 0 { return; }` early-return.
    // Pre-pop last_refill_ns to non-zero so refill_cos_tokens'
    // first-call init branch doesn't accidentally fill tokens —
    // old code would leave tokens at 0 in this configuration; the
    // fast path fills them.
    let mut root = test_cos_runtime_with_queues(
        0,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 0,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.queues[0].hot.tokens = 0;
    // Non-zero last_refill_ns — old code's refill_cos_tokens
    // would skip refill at rate=0; new fast-path fills regardless.
    root.queues[0].hot.last_refill_ns = 500_000_000;

    let _ = maybe_top_up_cos_queue_lease(&mut root.queues[0], None, 1_000_000_000);

    assert!(
        root.queues[0].hot.tokens >= COS_MIN_BURST_BYTES,
        "transparent-queue + non-exact + nonzero last_refill_ns MUST fast-path-fill; got {}",
        root.queues[0].hot.tokens,
    );
    assert_eq!(
        root.queues[0].hot.last_refill_ns, 1_000_000_000,
        "last_refill_ns must advance even on the non-exact transparent path",
    );
}

#[test]
fn transparent_root_preserves_per_queue_exact_cap() {
    // #916 plan §Tests: with transparent root (shaping_rate=0)
    // AND a per-queue exact cap (e.g., 1 Gbps), the per-queue
    // token bucket must still gate the queue. Confirms that
    // transparent root does NOT bypass per-queue caps.
    use std::sync::Arc;
    let one_gbps_bytes: u64 = 1_000_000_000 / 8;
    let lease = Arc::new(SharedCoSQueueLease::new(
        one_gbps_bytes,
        COS_MIN_BURST_BYTES,
        1,
    ));
    let mut root = test_cos_runtime_with_queues(
        0, // <- transparent root
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: one_gbps_bytes, // <- per-queue exact cap
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.queues[0].hot.tokens = 0;

    let _ = maybe_top_up_cos_queue_lease(&mut root.queues[0], Some(&lease), 1_000_000_000);

    // Per-queue tokens populated by lease.acquire — bounded by the
    // lease size and buffer cap. The transparent-queue fast-path
    // is gated on `transmit_rate_bytes == 0` so it does NOT fire
    // here (queue rate is 1G). Per-queue cap preserved.
    assert!(
        root.queues[0].hot.tokens > 0,
        "per-queue lease must still grant tokens at non-zero rate"
    );
    assert!(
        root.queues[0].hot.tokens <= COS_MIN_BURST_BYTES,
        "per-queue tokens must be bounded by buffer cap (not u64::MAX); got {}",
        root.queues[0].hot.tokens,
    );
}

/// #4261 (hb166 R-4) — refill dust conservation.
///
/// A 64 kbps class (8000 B/s) refilled at the ~200 µs drain cadence
/// accrues 1.6 B/interval. The pre-fix `refill_cos_tokens` floored to 1
/// B AND advanced `last_refill_ns` to `now_ns`, discarding the 0.6 B
/// remainder every interval → 5000 B/s delivered (37.5% under the 8000
/// B/s shape). The fix carries the fractional remainder in the
/// timestamp so cumulative granted tracks `rate × elapsed`.
///
/// RED-on-revert: with the timestamp advanced fully to `now_ns`, the
/// class delivers ~5000 B/s and this test's `>= 7900` floor fails.
#[test]
fn refill_cos_tokens_carries_fractional_dust_for_low_rate_class() {
    // 64 kbps = 8000 bytes/sec.
    const RATE_BYTES_PER_SEC: u64 = 8_000;
    // ~200 µs drain cadence — deliberately NON-integral bytes/interval
    // (8000 * 200_000 / 1e9 = 1.6 B).
    const INTERVAL_NS: u64 = 200_000;
    // 1 second of refills.
    const INTERVALS: u64 = 5_000;
    // Burst large enough that the bucket never saturates — we are
    // measuring pure refill accounting, not the cap.
    const BURST_BYTES: u64 = 1_000_000;

    // Consume tokens each interval so the bucket never fills and we can
    // sum the actual grants. Start "primed" (last_refill_ns != 0) so we
    // exercise the rate path, not the first-refill fill-to-burst path.
    let mut tokens: u64 = 0;
    let mut last_refill_ns: u64 = 1_000_000_000;
    let mut now = last_refill_ns;
    let mut granted_total: u64 = 0;

    for _ in 0..INTERVALS {
        now += INTERVAL_NS;
        let before = tokens;
        refill_cos_tokens(
            &mut tokens,
            RATE_BYTES_PER_SEC,
            BURST_BYTES,
            &mut last_refill_ns,
            now,
        );
        let added = tokens - before;
        granted_total += added;
        // Drain everything granted so the bucket cannot approach BURST.
        tokens = 0;
    }

    let elapsed_ns = now - 1_000_000_000;
    let ideal = (elapsed_ns as u128 * RATE_BYTES_PER_SEC as u128 / 1_000_000_000u128) as u64;
    // ideal == 8000 B over 1 s.
    assert_eq!(ideal, 8_000, "fixture sanity: 1 s at 8000 B/s = 8000 B");

    // Conservation: cumulative granted must equal ideal within a
    // small bounded error (sub-nanosecond flooring in the leftover
    // rewind). The pre-fix behavior delivered ~5000 B (37.5% under)
    // and fails this floor.
    assert!(
        granted_total >= 7_900,
        "low-rate class under-ran: granted {} B over 1 s vs 8000 B ideal \
         (dust discarded each refill — #4261 regression)",
        granted_total,
    );
    assert!(
        granted_total <= 8_000,
        "low-rate class over-ran: granted {} B > 8000 B ideal (dust \
         carry must not manufacture credit)",
        granted_total,
    );

    // The carried remainder lives in the timestamp: after the last
    // granting refill, `last_refill_ns` trails `now` by the ungranted
    // fraction (< one byte's worth of time), never advancing past it.
    assert!(
        last_refill_ns <= now,
        "last_refill_ns {} overshot now {}",
        last_refill_ns,
        now,
    );
    assert!(
        now - last_refill_ns < (1_000_000_000 / RATE_BYTES_PER_SEC),
        "carried leftover {} ns must be under one byte's time ({} ns)",
        now - last_refill_ns,
        1_000_000_000 / RATE_BYTES_PER_SEC,
    );
}

/// hb166 R-10 / R-4: `cos_refill_ns_until` had no direct unit test — it
/// was exercised only transitively through the wakeup-tick estimator.
/// Pin all three branches plus the div_ceil rounding: the wait math
/// must round UP so the caller never wakes one tick early with the
/// bucket still short of `need`.
#[test]
fn cos_refill_ns_until_covers_all_branches() {
    // Branch 1 — already have `need` tokens: zero wait, regardless of rate.
    assert_eq!(cos_refill_ns_until(1_500, 1_500, 1_000_000), Some(0));
    assert_eq!(cos_refill_ns_until(3_000, 1_500, 1_000_000), Some(0));
    // The token-sufficiency check precedes the rate check, so a rate of 0
    // with enough tokens is still Some(0), NOT None.
    assert_eq!(cos_refill_ns_until(10, 10, 0), Some(0));

    // Branch 2 — unshaped (rate 0) and short: never refills.
    assert_eq!(cos_refill_ns_until(0, 1_500, 0), None);
    assert_eq!(cos_refill_ns_until(500, 1_500, 0), None);

    // Branch 3 — wait = ceil(deficit * 1e9 / rate).
    // Exact division: deficit 1000 B at 1_000_000 B/s = 1_000_000 ns.
    assert_eq!(cos_refill_ns_until(500, 1_500, 1_000_000), Some(1_000_000));
    // Non-divisible: deficit 1 B at 3 B/s = 1e9 / 3 = 333_333_333.33 ns.
    // RED-on-revert if div_ceil is swapped for truncating division
    // (which yields 333_333_333, waking a tick early with the bucket
    // still one byte short).
    assert_eq!(cos_refill_ns_until(0, 1, 3), Some(333_333_334));
    assert_eq!(cos_refill_ns_until(0, 2, 3), Some(666_666_667));
}

// #5156: the shared non-exact queue lease must be conserved across a
// worker init -> top-up -> teardown cycle. A non-exact GUARANTEED queue
// whose rate trips COS_SHARED_EXACT_MIN_RATE_BYTES is lease-metered
// (`is_shared_lease_metered`): the coordinator attaches a shared legacy
// `SharedCoSQueueLease` so its class-wide admission is metered, exactly
// like exact queues. Two halves of the asymmetry are exercised here:
//
//   Init half   — `build_cos_interface_runtime` must start such a queue's
//                 token bucket at 0 (metered via the lease at runtime),
//                 NOT pre-fill `buffer_bytes` un-metered. On revert to the
//                 old `else` arm the queue starts at `buffer_bytes` and the
//                 first assertion fails.
//
//   Teardown half — `release_all_cos_queue_leases` must give the queue's
//                 outstanding leased tokens back to the shared lease. On
//                 revert to the `queue.config.exact && ...` filter the
//                 non-exact queue is skipped, the lease stays permanently
//                 over-charged, and its post-teardown drainable capacity is
//                 short by the outstanding grant — the conservation
//                 assertion fails.
#[test]
fn nonexact_queue_lease_conserved_across_teardown_5156() {
    use crate::afxdp::cos::builders::build_cos_interface_runtime;
    use crate::afxdp::types::{CoSInterfaceConfig, CoSOversubscriptionPolicy, FastMap};
    use crate::afxdp::worker::{BindingWorker, COS_SHARED_EXACT_MIN_RATE_BYTES};

    const IFINDEX: i32 = 42;
    const QUEUE_ID: u8 = 5;
    const BUFFER_BYTES: u64 = 128 * 1024;
    // 3 Gbps > COS_SHARED_EXACT_MIN_RATE_BYTES (2.5 Gbps) — a lease-metered
    // non-exact guaranteed queue.
    const RATE_BYTES: u64 = 3_000_000_000 / 8;
    const SHARDS: usize = 6;
    const NOW_NS: u64 = 1_000_000_000;

    assert!(
        RATE_BYTES >= COS_SHARED_EXACT_MIN_RATE_BYTES,
        "test queue must be lease-metered"
    );

    let make_cfg = || CoSInterfaceConfig {
        queue_id_bitmap: [0; 4],
        shaping_rate_bytes: 25_000_000_000 / 8,
        burst_bytes: 256 * 1024,
        default_queue: QUEUE_ID,
        dscp_classifier: String::new(),
        ieee8021_classifier: String::new(),
        dscp_queue_by_dscp: [u8::MAX; 64],
        ieee8021_queue_by_pcp: [u8::MAX; 8],
        queue_by_forwarding_class: FastMap::default(),
        queues: vec![CoSQueueConfig {
            queue_id: QUEUE_ID,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: RATE_BYTES,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: BUFFER_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        inet_precedence_classifier: String::new(),
        inet_precedence_queue_by_prec: [u8::MAX; 8],
    };

    // Drain a lease's full outstanding-credit capacity at a fixed clock.
    fn drain_capacity(lease: &SharedCoSQueueLease, now_ns: u64) -> u64 {
        let mut total = 0u64;
        loop {
            let granted = lease.acquire(now_ns, u64::MAX);
            if granted == 0 {
                break;
            }
            total = total.saturating_add(granted);
        }
        total
    }

    // --- Init half: the lease-metered non-exact queue starts at 0. ---
    let mut root = build_cos_interface_runtime(&make_cfg(), NOW_NS);
    assert_eq!(
        root.queues[0].hot.tokens, 0,
        "#5156 init: a lease-metered non-exact queue must start with 0 local \
         tokens (metered via the shared lease), not a pre-filled buffer_bytes bank"
    );

    // Baseline capacity of a pristine, never-charged lease.
    let baseline_lease = Arc::new(SharedCoSQueueLease::new(RATE_BYTES, BUFFER_BYTES, SHARDS));
    let baseline_capacity = drain_capacity(&baseline_lease, NOW_NS);
    assert!(baseline_capacity > 0, "baseline lease must hand out credit");

    // Control: a lease charged but NOT torn down loses exactly the grant —
    // proves the conservation assertion below is non-vacuous. The charge is
    // whatever the runtime top-up moved into the queue's local bucket.
    let leaked_lease = Arc::new(SharedCoSQueueLease::new(RATE_BYTES, BUFFER_BYTES, SHARDS));
    let _ = maybe_top_up_cos_queue_lease(&mut root.queues[0], Some(&leaked_lease), NOW_NS);
    let charged = root.queues[0].hot.tokens;
    assert!(
        charged > 0,
        "runtime top-up must acquire leased tokens for the non-exact queue"
    );
    let leaked_capacity = drain_capacity(&leaked_lease, NOW_NS);
    assert_eq!(
        leaked_capacity,
        baseline_capacity - charged,
        "a charged-but-not-released lease must be short by the outstanding grant"
    );

    // --- Teardown half: release_all_cos_queue_leases returns the grant. ---
    let test_lease = Arc::new(SharedCoSQueueLease::new(RATE_BYTES, BUFFER_BYTES, SHARDS));
    // Re-run the top-up against the lease that IS attached to the fast path,
    // so the queue's outstanding charge lives on `test_lease`.
    root.queues[0].hot.tokens = 0;
    let charged2 = {
        let _ = maybe_top_up_cos_queue_lease(&mut root.queues[0], Some(&test_lease), NOW_NS);
        root.queues[0].hot.tokens
    };
    assert!(charged2 > 0, "second top-up must also charge the lease");

    let fast_interfaces = test_cos_fast_interfaces(
        IFINDEX,
        IFINDEX,
        QUEUE_ID,
        vec![(
            QUEUE_ID,
            test_queue_fast_path(false, 0, None, Some(test_lease.clone())),
        )],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&IFINDEX).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, IFINDEX, root, fast_path);

    release_all_cos_queue_leases(&mut binding);

    assert_eq!(
        binding.cos.cos_interfaces.get(&IFINDEX).unwrap().queues[0]
            .hot
            .tokens,
        0,
        "teardown must drain the queue's local token bucket"
    );

    let conserved_capacity = drain_capacity(&test_lease, NOW_NS);
    assert_eq!(
        conserved_capacity, baseline_capacity,
        "#5156 teardown: after release_all_cos_queue_leases the shared lease's \
         drainable capacity must fully recover to the pristine baseline — the \
         non-exact queue's outstanding grant was returned. The exact-only \
         filter leaves it short by the grant."
    );
}

// #6272: `release_all_cos_queue_leases` must gate the `mem::take` on lease
// presence, mirroring the runtime give-back `refresh_cos_interface_activity`
// (R-5(a)). A single-owner NON-EXACT queue with NO shared lease attached has
// nowhere to return its banked burst, so its private per-worker `hot.tokens`
// MUST survive a lease-set swap. Before #6272 the take was unconditional (only
// the CREDIT was lease-gated), so an un-leased queue's burst was zeroed with
// nothing credited — contradicting the #6270 README/comment.
//
// Two queues on one interface exercise the gate discrimination in a single
// teardown call:
//   queue[0] — single-owner non-exact, UN-leased: `hot.tokens` must be left
//              intact (fail-on-revert: the unconditional take zeroes it).
//   queue[1] — non-exact, LEASED: still drains + credits (the #6270/#5156
//              conservation case must keep holding — the lease's drainable
//              capacity recovers to the pristine baseline).
#[test]
fn unleased_nonexact_burst_survives_lease_swap_6272() {
    use crate::afxdp::cos::builders::build_cos_interface_runtime;
    use crate::afxdp::types::{CoSInterfaceConfig, CoSOversubscriptionPolicy, FastMap};
    use crate::afxdp::worker::{BindingWorker, COS_SHARED_EXACT_MIN_RATE_BYTES};

    const IFINDEX: i32 = 77;
    const UNLEASED_QID: u8 = 3;
    const LEASED_QID: u8 = 4;
    const BUFFER_BYTES: u64 = 128 * 1024;
    // Banked private burst held by the single-owner un-leased queue.
    const UNLEASED_BURST: u64 = 96 * 1024;
    // 3 Gbps > COS_SHARED_EXACT_MIN_RATE_BYTES (2.5 Gbps) — both queues are
    // lease-metering-eligible; the difference is purely whether a shared lease
    // is attached on the fast path.
    const RATE_BYTES: u64 = 3_000_000_000 / 8;
    const SHARDS: usize = 6;
    const NOW_NS: u64 = 1_000_000_000;

    assert!(
        RATE_BYTES >= COS_SHARED_EXACT_MIN_RATE_BYTES,
        "test queues must be lease-metering-eligible"
    );

    let make_queue = |queue_id: u8| CoSQueueConfig {
        queue_id,
        forwarding_class: format!("fc-{queue_id}"),
        priority: 5,
        transmit_rate_bytes: RATE_BYTES,
        guarantee_enabled: true,
        exact: false,
        surplus_sharing: false,
        equal_flow_enforcement: false,
        equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
        surplus_weight: 1,
        buffer_bytes: BUFFER_BYTES,
        dscp_rewrite: None,
        codel_target_ns: 0,
    };
    let cfg = CoSInterfaceConfig {
        queue_id_bitmap: [0; 4],
        shaping_rate_bytes: 25_000_000_000 / 8,
        burst_bytes: 256 * 1024,
        default_queue: UNLEASED_QID,
        dscp_classifier: String::new(),
        ieee8021_classifier: String::new(),
        dscp_queue_by_dscp: [u8::MAX; 64],
        ieee8021_queue_by_pcp: [u8::MAX; 8],
        queue_by_forwarding_class: FastMap::default(),
        // Order MUST match the fast-path queue_entries order below: the
        // teardown indexes `queue_fast_path` by the `root.queues` position.
        queues: vec![make_queue(UNLEASED_QID), make_queue(LEASED_QID)],
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        inet_precedence_classifier: String::new(),
        inet_precedence_queue_by_prec: [u8::MAX; 8],
    };

    fn drain_capacity(lease: &SharedCoSQueueLease, now_ns: u64) -> u64 {
        let mut total = 0u64;
        loop {
            let granted = lease.acquire(now_ns, u64::MAX);
            if granted == 0 {
                break;
            }
            total = total.saturating_add(granted);
        }
        total
    }

    let mut root = build_cos_interface_runtime(&cfg, NOW_NS);

    // queue[0] (un-leased): give it a private per-worker banked burst.
    root.queues[0].hot.tokens = UNLEASED_BURST;
    assert!(!root.queues[0].config.exact, "queue[0] must be non-exact");

    // queue[1] (leased): charge the shared lease via the runtime top-up so its
    // outstanding grant is meaningful. baseline is the pristine, never-charged
    // capacity of an identical lease.
    let baseline_lease = Arc::new(SharedCoSQueueLease::new(RATE_BYTES, BUFFER_BYTES, SHARDS));
    let baseline_capacity = drain_capacity(&baseline_lease, NOW_NS);
    assert!(baseline_capacity > 0, "baseline lease must hand out credit");

    let test_lease = Arc::new(SharedCoSQueueLease::new(RATE_BYTES, BUFFER_BYTES, SHARDS));
    root.queues[1].hot.tokens = 0;
    let _ = maybe_top_up_cos_queue_lease(&mut root.queues[1], Some(&test_lease), NOW_NS);
    let charged = root.queues[1].hot.tokens;
    assert!(charged > 0, "leased queue top-up must acquire tokens");

    // Fast path: queue[0] has NO lease (single-owner), queue[1] carries the
    // shared lease. Entry order matches `cfg.queues` so the teardown's
    // per-position `queue_fast_path` lookup lines up with `root.queues`.
    let fast_interfaces = test_cos_fast_interfaces(
        IFINDEX,
        IFINDEX,
        UNLEASED_QID,
        vec![
            (UNLEASED_QID, test_queue_fast_path(false, 0, None, None)),
            (
                LEASED_QID,
                test_queue_fast_path(false, 0, None, Some(test_lease.clone())),
            ),
        ],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&IFINDEX).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, IFINDEX, root, fast_path);

    release_all_cos_queue_leases(&mut binding);

    let queues = &binding.cos.cos_interfaces.get(&IFINDEX).unwrap().queues;
    assert_eq!(
        queues[0].hot.tokens, UNLEASED_BURST,
        "#6272: a single-owner un-leased non-exact queue's private banked burst \
         must survive a lease-set swap — the teardown `mem::take` is gated on \
         lease presence. The unconditional take zeroes it."
    );
    assert_eq!(
        queues[1].hot.tokens, 0,
        "#6270/#5156: a LEASED non-exact queue still drains its local bucket on \
         teardown"
    );

    let conserved_capacity = drain_capacity(&test_lease, NOW_NS);
    assert_eq!(
        conserved_capacity, baseline_capacity,
        "#6270/#5156: the LEASED queue's outstanding grant is credited back on \
         teardown, so the shared lease recovers to the pristine baseline — the \
         #6272 gate does not regress leased-queue conservation."
    );
}
