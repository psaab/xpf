// Tests for afxdp/types/shared_cos_lease/ — relocated from inline
// `#[cfg(test)] mod tests` to keep mod.rs under the modularity-discipline
// LOC threshold. Loaded as a dir-local submodule via
// `#[path = "shared_cos_lease_tests.rs"]` from shared_cos_lease/mod.rs.
// File moved in #1329 alongside mod.rs into the dir module layout.

use super::*;
use std::mem::align_of;

// #694 / #711: `FlowRrRing` invariant pins.
//
// The ring is the SFQ round-robin cursor storage. Every bug class
// that can break it is pinned here so a future refactor that
// changes the indexing math, the wrap condition, or the head/len
// update order fails loudly in CI instead of during live
// validation.

fn shared_cos_lease_snapshot(lease: &SharedCoSRootLease) -> (u64, u64, u64) {
    let (available_tokens, outstanding_leased_tokens) =
        unpack_shared_cos_lease_credits(lease.state.credits.load(Ordering::Relaxed));
    let last_refill_ns = lease.state.last_refill_ns.load(Ordering::Relaxed);
    (available_tokens, outstanding_leased_tokens, last_refill_ns)
}

#[test]
fn shared_cos_root_lease_refill_respects_outstanding_burst_credit() {
    let lease = SharedCoSRootLease::new(10_000_000, 16_000, 1);
    lease
        .state
        .credits
        .store(pack_shared_cos_lease_credits(0, 4_000), Ordering::Relaxed);
    lease.state.last_refill_ns.store(1, Ordering::Relaxed);

    refill_shared_cos_lease_state(lease.config, &lease.state, 1_000_000_001);

    let (available_tokens, outstanding_leased_tokens, _) = shared_cos_lease_snapshot(&lease);
    assert_eq!(
        available_tokens,
        lease.config.burst_bytes - outstanding_leased_tokens
    );
}

#[test]
fn shared_cos_root_lease_release_unused_preserves_total_burst_bound() {
    let lease = SharedCoSRootLease::new(10_000_000, 16_000, 1);
    lease.state.credits.store(
        pack_shared_cos_lease_credits(lease.config.burst_bytes, 4_000),
        Ordering::Relaxed,
    );

    lease.release_unused(1_500);

    let (available_tokens, outstanding_leased_tokens, _) = shared_cos_lease_snapshot(&lease);
    assert_eq!(
        available_tokens + outstanding_leased_tokens,
        lease.config.burst_bytes
    );
}

#[test]
fn shared_cos_lease_state_is_cacheline_aligned() {
    assert_eq!(align_of::<SharedCoSLeaseState>(), 64);
}

#[test]
fn vtime_publish_clamps_below_not_participating_sentinel() {
    // #4269 (R-8b): a saturated live vtime must NEVER be published as the
    // NOT_PARTICIPATING sentinel (u64::MAX), or peers would skip a
    // participating worker in the V_min reduction. publish() clamps to
    // MAX-1, so the slot reads back as participating.
    let slot = PaddedVtimeSlot::not_participating();
    slot.publish(u64::MAX);
    assert_eq!(
        slot.read(),
        Some(NOT_PARTICIPATING - 1),
        "u64::MAX vtime must clamp to the participating value MAX-1, not the sentinel"
    );
    // A below-boundary value passes through unchanged.
    let slot2 = PaddedVtimeSlot::not_participating();
    slot2.publish(4242);
    assert_eq!(slot2.read(), Some(4242));
}

#[test]
fn shared_cos_lease_config_clamps_burst_to_packed_range() {
    let lease = SharedCoSRootLease::new(10_000_000, u64::MAX, 1);
    assert_eq!(lease.config.burst_bytes, u32::MAX as u64);
}

// === #1229 Phase 6 v8 tests ===
// Plan: docs/pr/1229-cross-worker-vtime/phase6-fair-lease.md (PLAN-READY).
// Spine: PackedEpochGrant, seqlock rotation, two-CAS-rollback, tag-checked
// CAS for cross-epoch safety, bounded rollback retries.

#[test]
fn v8_pack_unpack_roundtrip() {
    for (tag, granted) in [(0u32, 0u32), (1, 100), (1234, 56789), (u32::MAX, u32::MAX)] {
        let packed = PackedEpochGrant::pack(tag, granted);
        let (t, g) = PackedEpochGrant::unpack(packed);
        assert_eq!(t, tag, "tag roundtrip");
        assert_eq!(g, granted, "granted roundtrip");
    }
}

#[test]
fn v8_legacy_lease_does_not_advertise_v8_mode() {
    let lease = SharedCoSQueueLease::new(10_000_000, 64 * 1024, 2);
    assert!(!lease.is_v8(), "legacy::new should NOT produce v8 lease");
    assert_eq!(lease.v8_rollback_retry_exceeded(), 0);
}

#[test]
fn v8_new_v8_advertises_v8_mode() {
    let lease = SharedCoSQueueLease::new_v8(10_000_000, 64 * 1024, 2, 5);
    assert!(lease.is_v8(), "new_v8 should produce v8 lease");
    // worker_active_flow_buckets array sized max_worker_id + 1.
    assert!(
        lease.worker_active_flow_buckets_for(0).is_some(),
        "worker 0 in range"
    );
    assert!(
        lease.worker_active_flow_buckets_for(5).is_some(),
        "worker 5 (max_worker_id) in range"
    );
    assert!(
        lease.worker_active_flow_buckets_for(6).is_none(),
        "worker 6 (out of range) returns None"
    );
}

#[test]
fn v8_matches_config_v8_distinguishes_max_worker_id() {
    let lease = SharedCoSQueueLease::new_v8(10_000_000, 64 * 1024, 2, 5);
    assert!(
        lease.matches_config_v8(10_000_000, 64 * 1024, 2, 5, V8RateMode::CstructDefault, EqualFlowTargetPolicy::Slowest),
        "same config matches"
    );
    assert!(
        !lease.matches_config_v8(10_000_000, 64 * 1024, 2, 6, V8RateMode::CstructDefault, EqualFlowTargetPolicy::Slowest),
        "max_worker_id change does NOT match (forces rebuild)"
    );
    assert!(
        !lease.matches_config_v8(10_000_000, 64 * 1024, 2, 5, V8RateMode::EqualFlowSuppress, EqualFlowTargetPolicy::Slowest),
        "rate-mode change does NOT match (forces rebuild)"
    );
    assert!(
        !lease.matches_config(10_000_000, 64 * 1024, 2),
        "v8 lease must NOT match legacy matches_config (mode mismatch)"
    );
}

#[test]
fn v8_legacy_lease_matches_legacy_only() {
    let lease = SharedCoSQueueLease::new(10_000_000, 64 * 1024, 2);
    assert!(lease.matches_config(10_000_000, 64 * 1024, 2));
    assert!(
        !lease.matches_config_v8(10_000_000, 64 * 1024, 2, 0, V8RateMode::CstructDefault, EqualFlowTargetPolicy::Slowest),
        "legacy lease must NOT match matches_config_v8"
    );
}

#[test]
fn v8_acquire_zero_when_no_active_flows() {
    // No rehydration → all worker_active_flow_buckets == 0 → after
    // first rotation, total_flows is forced to 1 (avoid div-by-zero)
    // BUT no worker has active count > 0, so per-worker my_fair_share
    // will be 0 for every worker, AND surplus path is gated on
    // active_flow_buckets[id] > 0 (so even surplus returns 0).
    let lease = SharedCoSQueueLease::new_v8(10_000_000, 64 * 1024, 2, 1);
    let granted = lease.acquire_v8(0, 1_000_000, 4_096);
    assert_eq!(granted, 0, "no active flows → no grants");
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "worker_id 2 out of range")]
fn v8_acquire_debug_panics_for_out_of_range_worker_id() {
    let lease = SharedCoSQueueLease::new_v8(10_000_000, 64 * 1024, 2, 1);
    // max_worker_id = 1, so worker_id 0 and 1 are valid; 2+ are out of range.
    // Debug builds should fail loudly for this caller bug.
    let _ = lease.acquire_v8(2, 1_000_000, 4_096);
}

#[cfg(not(debug_assertions))]
#[test]
fn v8_acquire_release_returns_zero_for_out_of_range_worker_id() {
    let lease = SharedCoSQueueLease::new_v8(10_000_000, 64 * 1024, 2, 1);
    // max_worker_id = 1, so worker_id 0 and 1 are valid; 2+ are out of range.
    // Release-mode skips debug_assert, so this returns 0 cleanly.
    let granted = lease.acquire_v8(2, 1_000_000, 4_096);
    assert_eq!(granted, 0, "out-of-range worker_id → 0 grant");
}

#[test]
fn v8_acquire_returns_zero_on_zero_request() {
    let lease = SharedCoSQueueLease::new_v8(10_000_000, 64 * 1024, 2, 1);
    lease.rehydrate_worker_active_count(0, 1);
    let granted = lease.acquire_v8(0, 1_000_000, 0);
    assert_eq!(granted, 0, "zero request → zero grant");
}

// #1782 Step-1 (ii): `acquire_v8_with_cause` shortfall attribution
// pins. The cause enum feeds the per-worker
// `cos_queue_lease_undergrant_*` wire counters, so the mapping from
// exhaustion path to reported cause is a contract.

#[test]
fn v8_acquire_with_cause_full_grant_reports_none() {
    let lease = SharedCoSQueueLease::new_v8(12_500_000, 64 * 1024, 1, 0);
    lease.rehydrate_worker_active_count(0, 1);
    // Request well below the per-epoch cap (~2500 bytes at 12.5 MB/s
    // x 200 us) so the primary path grants in full.
    let (granted, cause) = lease.acquire_v8_with_cause(0, EPOCH_DURATION_NS, 100);
    assert_eq!(granted, 100, "small request must be granted in full");
    assert_eq!(
        cause,
        AcquireV8ShortfallCause::None,
        "fully-granted acquire must report no shortfall cause"
    );
}

#[test]
fn v8_acquire_with_cause_no_active_flows_reports_share_exhausted() {
    // No rehydration -> my_fair_share == 0 for every worker (see
    // v8_acquire_zero_when_no_active_flows). The zero-grant exits via
    // the `my_consumed >= my_effective_share` primary break, so the
    // attributed cause is ShareExhausted.
    let lease = SharedCoSQueueLease::new_v8(10_000_000, 64 * 1024, 2, 1);
    let (granted, cause) = lease.acquire_v8_with_cause(0, 1_000_000, 4_096);
    assert_eq!(granted, 0, "no active flows -> no grants");
    assert_eq!(
        cause,
        AcquireV8ShortfallCause::ShareExhausted,
        "zero fair share must be attributed to ShareExhausted"
    );
}

#[test]
fn v8_acquire_with_cause_over_request_reports_capacity_bound() {
    let lease = SharedCoSQueueLease::new_v8(12_500_000, 64 * 1024, 1, 0);
    lease.rehydrate_worker_active_count(0, 1);
    // Request far above the per-epoch cap. The grant ends short on a
    // capacity bound; which one (share, class cap, or outstanding
    // credit) depends on the lease config interplay, but it must be a
    // real capacity cause, never None and never a transient.
    let (granted, cause) = lease.acquire_v8_with_cause(0, EPOCH_DURATION_NS, 1_000_000);
    assert!(granted > 0, "active single-flow worker should get a grant");
    assert!(granted < 1_000_000, "grant must be short of the request");
    assert!(
        matches!(
            cause,
            AcquireV8ShortfallCause::ShareExhausted
                | AcquireV8ShortfallCause::ClassCap
                | AcquireV8ShortfallCause::OutstandingCap
        ),
        "under-grant must be attributed to a capacity bound, got {cause:?}"
    );
}

#[test]
fn v8_acquire_with_cause_zero_request_reports_none() {
    let lease = SharedCoSQueueLease::new_v8(10_000_000, 64 * 1024, 2, 1);
    lease.rehydrate_worker_active_count(0, 1);
    let (granted, cause) = lease.acquire_v8_with_cause(0, 1_000_000, 0);
    assert_eq!(granted, 0);
    assert_eq!(
        cause,
        AcquireV8ShortfallCause::None,
        "requested == 0 carries no shortfall attribution"
    );
}

#[test]
fn v8_acquire_wrapper_matches_with_cause_grant() {
    // The legacy-signature wrapper must stay byte-identical in grant
    // behavior to the cause-reporting variant (serial calls on two
    // identically-configured leases).
    let lease_a = SharedCoSQueueLease::new_v8(12_500_000, 64 * 1024, 1, 0);
    let lease_b = SharedCoSQueueLease::new_v8(12_500_000, 64 * 1024, 1, 0);
    lease_a.rehydrate_worker_active_count(0, 1);
    lease_b.rehydrate_worker_active_count(0, 1);
    for (now, req) in [
        (EPOCH_DURATION_NS, 1_000u64),
        (EPOCH_DURATION_NS, 10_000),
        (2 * EPOCH_DURATION_NS, 4_096),
    ] {
        let g_wrap = lease_a.acquire_v8(0, now, req);
        let (g_cause, _) = lease_b.acquire_v8_with_cause(0, now, req);
        assert_eq!(g_wrap, g_cause, "wrapper grant diverged at ({now}, {req})");
    }
}

#[test]
fn v8_rehydrate_then_acquire_grants_proportional_share() {
    // 100 Mbps = 12.5 MB/s. EPOCH_DURATION_NS = 200µs → cap = 2500
    // bytes per epoch. Single worker with 1 active flow → my_fair_share
    // = cap. Should be granted up to cap.
    let lease = SharedCoSQueueLease::new_v8(12_500_000, 64 * 1024, 1, 0);
    lease.rehydrate_worker_active_count(0, 1);
    let granted = lease.acquire_v8(0, EPOCH_DURATION_NS, 4_096);
    // Cap is 2500 (= 12.5MB/s × 200µs). May get less due to outstanding
    // cap, but should be > 0 since rate × elapsed > 0.
    assert!(granted > 0, "single-flow active worker should get a grant");
    assert!(
        granted <= 2500,
        "grant must not exceed epoch cap of 2500 bytes (got {})",
        granted
    );
}

#[test]
fn v8_acquire_respects_aggregate_cap_under_serial_calls() {
    // Force two workers each with 1 active flow → fair_share = cap/2 each.
    // Serial calls should not collectively exceed cap.
    let lease = SharedCoSQueueLease::new_v8(12_500_000, 64 * 1024, 2, 1);
    lease.rehydrate_worker_active_count(0, 1);
    lease.rehydrate_worker_active_count(1, 1);
    // Grant for both workers in succession.
    let g0 = lease.acquire_v8(0, EPOCH_DURATION_NS, 10_000);
    let g1 = lease.acquire_v8(1, EPOCH_DURATION_NS, 10_000);
    // Cap at this point ≈ 2500 (rate × 200µs).
    // Sum of grants must not exceed cap.
    assert!(
        g0 + g1 <= 2500,
        "aggregate grants {}+{} must not exceed cap 2500",
        g0,
        g1
    );
}

#[test]
fn v8_acquire_clamps_to_u32_max() {
    // Even if request and cap are very large, packed counter is u32.
    // Lease at 100 Gbps with very long burst should never overflow.
    let lease = SharedCoSQueueLease::new_v8(12_500_000_000, 4_000_000_000, 1, 0);
    lease.rehydrate_worker_active_count(0, 1);
    // Force a long elapsed by setting epoch_start_ns far in the past
    // — but we can't directly access internals; rely on the
    // rotation's elapsed_ns.min(EPOCH_DURATION_NS) cap to keep us safe.
    let granted = lease.acquire_v8(0, EPOCH_DURATION_NS, u64::MAX);
    // At 100 Gbps × 200µs = 2.5 MB. Far below u32::MAX.
    assert!(granted <= 2_500_000, "grant must respect epoch cap");
}

#[test]
fn v8_telemetry_rollback_metric_starts_zero() {
    let lease = SharedCoSQueueLease::new_v8(10_000_000, 64 * 1024, 2, 5);
    assert_eq!(
        lease.v8_rollback_retry_exceeded(),
        0,
        "rollback metric starts at 0"
    );
}

#[test]
fn v8_legacy_lease_telemetry_returns_zero() {
    let lease = SharedCoSQueueLease::new(10_000_000, 64 * 1024, 2);
    assert_eq!(
        lease.v8_rollback_retry_exceeded(),
        0,
        "legacy lease has no v8 telemetry"
    );
}

#[test]
fn v8_rehydrate_worker_active_count_is_additive() {
    // #1229 Phase 6 v8 Codex code-review finding #1 (2026-05-08):
    // rehydrate uses fetch_add so multi-runtime / multi-binding
    // installs on the same worker thread contribute additively to
    // the per-worker slot. A `store` would have clobbered prior
    // runtimes' contributions; verify the additive contract.
    let lease = SharedCoSQueueLease::new_v8(10_000_000, 64 * 1024, 2, 3);
    lease.rehydrate_worker_active_count(2, 7);
    let slot = lease.worker_active_flow_buckets_for(2).unwrap();
    assert_eq!(slot.load(Ordering::Relaxed), 7);
    // Second runtime on same worker rehydrates with its own count;
    // additive semantics → total is sum across runtimes.
    lease.rehydrate_worker_active_count(2, 3);
    assert_eq!(slot.load(Ordering::Relaxed), 10);
    // Zero count is a no-op (prevents fetch_add(0) from being a memory
    // barrier we don't need).
    lease.rehydrate_worker_active_count(2, 0);
    assert_eq!(slot.load(Ordering::Relaxed), 10);
}

#[test]
fn v8_rehydrate_multiple_workers_isolated() {
    // Different workers' slots are independent — additive within a
    // slot, isolated across slots. Defends against a regression where
    // rehydrate accidentally writes the wrong slot or sums across
    // workers.
    let lease = SharedCoSQueueLease::new_v8(10_000_000, 64 * 1024, 4, 3);
    lease.rehydrate_worker_active_count(0, 2);
    lease.rehydrate_worker_active_count(1, 5);
    lease.rehydrate_worker_active_count(2, 1);
    lease.rehydrate_worker_active_count(3, 4);
    assert_eq!(
        lease
            .worker_active_flow_buckets_for(0)
            .unwrap()
            .load(Ordering::Relaxed),
        2
    );
    assert_eq!(
        lease
            .worker_active_flow_buckets_for(1)
            .unwrap()
            .load(Ordering::Relaxed),
        5
    );
    assert_eq!(
        lease
            .worker_active_flow_buckets_for(2)
            .unwrap()
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        lease
            .worker_active_flow_buckets_for(3)
            .unwrap()
            .load(Ordering::Relaxed),
        4
    );
}

#[test]
fn v8_rehydrate_multi_binding_same_worker_summation() {
    // #1229 Phase 6 v8 Codex code-review finding #1: 'multi-binding
    // same-worker rehydration case'. Two runtimes on the same worker
    // for the same (ifindex, queue_id) lease, each rehydrating their
    // own active count. Total slot value = sum.
    let lease = SharedCoSQueueLease::new_v8(10_000_000, 64 * 1024, 2, 1);
    // Runtime A on worker 0 has 4 active flow buckets; runtime B
    // (different binding, same worker, same lease) has 3.
    lease.rehydrate_worker_active_count(0, 4); // A
    lease.rehydrate_worker_active_count(0, 3); // B
    let slot = lease.worker_active_flow_buckets_for(0).unwrap();
    assert_eq!(
        slot.load(Ordering::Relaxed),
        7,
        "multi-binding additive total = sum, not clobbered"
    );
    // Subsequent transitions on either runtime delta normally.
    slot.fetch_add(1, Ordering::Relaxed); // A's bucket goes 0→1
    assert_eq!(slot.load(Ordering::Relaxed), 8);
    slot.fetch_sub(1, Ordering::Relaxed); // B's bucket goes 1→0
    assert_eq!(slot.load(Ordering::Relaxed), 7);
}

#[test]
fn v8_rehydrate_out_of_range_worker_id_is_noop() {
    let lease = SharedCoSQueueLease::new_v8(10_000_000, 64 * 1024, 2, 1);
    // worker_id 5 is out of range (len = 2). Must not panic, must not
    // mutate any other slot.
    lease.rehydrate_worker_active_count(5, 99);
    let slot0 = lease.worker_active_flow_buckets_for(0).unwrap();
    let slot1 = lease.worker_active_flow_buckets_for(1).unwrap();
    assert_eq!(slot0.load(Ordering::Relaxed), 0);
    assert_eq!(slot1.load(Ordering::Relaxed), 0);
}

#[test]
fn v8_rehydrate_on_legacy_lease_is_noop() {
    let lease = SharedCoSQueueLease::new(10_000_000, 64 * 1024, 2);
    // Legacy lease has no v8 state. Must not panic.
    lease.rehydrate_worker_active_count(0, 99);
    assert!(lease.worker_active_flow_buckets_for(0).is_none());
}

#[test]
fn v8_acquire_proportional_share_with_asymmetric_flow_counts() {
    // Two workers, A has 4 flows, B has 1 flow. Fair share:
    // A primary = 4/5 × cap; B primary = 1/5 × cap.
    // Order: A acquires first under primary cap.
    let lease = SharedCoSQueueLease::new_v8(50_000_000, 256 * 1024, 2, 1);
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(1, 1);
    // First acquire by A under primary path (pre-grace).
    let g_a = lease.acquire_v8(0, EPOCH_DURATION_NS, u64::MAX);
    let g_b = lease.acquire_v8(1, EPOCH_DURATION_NS, u64::MAX);
    // Cap = 50e6 × 200e-6 = 10000 bytes. A's primary share ≈ 8000;
    // B's ≈ 2000. Pre-grace, neither can take surplus.
    let cap = 10_000_u64;
    assert!(
        g_a + g_b <= cap,
        "aggregate {}+{} must not exceed cap {}",
        g_a,
        g_b,
        cap
    );
    // A should have substantially more than B (4× ratio).
    assert!(
        g_a > g_b,
        "asymmetric share: A ({} flows) > B ({} flows): A={}, B={}",
        4,
        1,
        g_a,
        g_b
    );
}

#[test]
fn v8_post_grace_does_not_grant_unarmed_surplus_beyond_fair_share() {
    // Two workers, A has 4 flows and B has 1. B's primary share is
    // 1/5 of the epoch cap. Once B has consumed that share, merely
    // waiting past the grace point must not let it claim A's reserved
    // primary share. That would preserve RSS-placement unfairness by
    // allowing low-flow-count workers to overrun their proportional
    // budget during normal shaper-bound traffic.
    let lease = SharedCoSQueueLease::new_v8(50_000_000, 256 * 1024, 2, 1);
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(1, 1);

    let first = lease.acquire_v8(1, EPOCH_DURATION_NS, 2_000);
    assert_eq!(first, 2_000, "B gets its 1/5 primary share");

    let after_grace_same_epoch = EPOCH_DURATION_NS + (EPOCH_DURATION_NS / 2) + 1;
    let second = lease.acquire_v8(1, after_grace_same_epoch, u64::MAX);
    assert_eq!(
        second, 0,
        "unarmed post-grace surplus must not exceed B's fair share"
    );

    let v8 = lease.v8.as_ref().unwrap();
    let curr = v8.worker_starvation_events[1].0.load(Ordering::Acquire);
    let (_tag, events) = PackedEpochGrant::unpack(curr);
    assert_eq!(
        events, 1,
        "post-grace denial must still feed the bypass detector"
    );
}

#[test]
fn v8_explicit_bypass_still_allows_surplus_beyond_fair_share() {
    // The strict path only removes unconditional post-grace surplus.
    // The explicit CPU-bound bypass remains available for the
    // work-conservation case where rotation detected prior-epoch
    // starvation, aggregate underuse, and an under-utilized peer.
    let lease = SharedCoSQueueLease::new_v8(50_000_000, 256 * 1024, 2, 1);
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(1, 1);

    let first = lease.acquire_v8(1, EPOCH_DURATION_NS, 2_000);
    assert_eq!(first, 2_000, "B gets its 1/5 primary share");

    lease
        .v8
        .as_ref()
        .unwrap()
        .epoch
        .bypass_grace_rotations_remaining
        .store(1, Ordering::Release);

    let before_grace_same_epoch = EPOCH_DURATION_NS + 1;
    let second = lease.acquire_v8(1, before_grace_same_epoch, u64::MAX);
    assert!(
        second > 0,
        "explicit bypass should still open surplus when armed"
    );
}

#[test]
fn bypass_does_not_arm_from_underutil_peer_without_demand() {
    // A quiet peer with a nonzero active-flow count must not be
    // treated as CPU-bound merely because it consumed less than its
    // primary share. Otherwise strict exact CoS would immediately
    // defeat itself in asymmetric normal-traffic placements.
    let lease = SharedCoSQueueLease::new_v8(50_000_000, 256 * 1024, 2, 1);
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(1, 1);

    let _ = lease.acquire_v8(1, EPOCH_DURATION_NS, 1);
    {
        let v8 = lease.v8.as_ref().unwrap();
        let cap = v8.epoch.epoch_total_grant_cap.load(Ordering::Acquire);
        assert_eq!(cap, 10_000);
        let curr = v8.epoch.packed_granted.0.load(Ordering::Acquire);
        let (tag, _) = PackedEpochGrant::unpack(curr);
        v8.epoch
            .packed_granted
            .0
            .store(PackedEpochGrant::pack(tag, 3_000), Ordering::Release);
        v8.worker_grants[0]
            .0
            .store(PackedEpochGrant::pack(tag, 1_000), Ordering::Release);
        v8.worker_starvation_events[1]
            .0
            .store(PackedEpochGrant::pack(tag, 1), Ordering::Release);
        v8.worker_demand_events[0]
            .0
            .store(PackedEpochGrant::pack(tag, 0), Ordering::Release);
    }

    let arms_before = lease.v8_bypass_grace_arms();
    let _ = lease.acquire_v8(1, 2 * EPOCH_DURATION_NS, 1);
    assert_eq!(
        lease.v8_bypass_grace_arms(),
        arms_before,
        "underutilized peer without demand must not arm bypass"
    );
    assert!(!lease.v8_bypass_grace_active());
}

#[test]
fn bypass_arms_for_underutil_peer_with_demand() {
    // Positive control for the demand-qualified peer-underutil gate:
    // a signaled worker plus aggregate underuse plus an active peer
    // that both requested lease credit and consumed <60% of share
    // still arms the explicit CPU-bound bypass.
    let lease = SharedCoSQueueLease::new_v8(50_000_000, 256 * 1024, 2, 1);
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(1, 1);

    let _ = lease.acquire_v8(1, EPOCH_DURATION_NS, 1);
    {
        let v8 = lease.v8.as_ref().unwrap();
        let cap = v8.epoch.epoch_total_grant_cap.load(Ordering::Acquire);
        assert_eq!(cap, 10_000);
        let curr = v8.epoch.packed_granted.0.load(Ordering::Acquire);
        let (tag, _) = PackedEpochGrant::unpack(curr);
        v8.epoch
            .packed_granted
            .0
            .store(PackedEpochGrant::pack(tag, 3_000), Ordering::Release);
        v8.worker_grants[0]
            .0
            .store(PackedEpochGrant::pack(tag, 1_000), Ordering::Release);
        v8.worker_starvation_events[1]
            .0
            .store(PackedEpochGrant::pack(tag, 1), Ordering::Release);
        v8.worker_demand_events[0]
            .0
            .store(PackedEpochGrant::pack(tag, 1), Ordering::Release);
    }

    let arms_before = lease.v8_bypass_grace_arms();
    let _ = lease.acquire_v8(1, 2 * EPOCH_DURATION_NS, 1);
    assert_eq!(
        lease.v8_bypass_grace_arms(),
        arms_before + 1,
        "demand-qualified underutilized peer should arm bypass"
    );
    assert!(lease.v8_bypass_grace_active());
}

// === #1304 equal-flow suppression prototype tests ===

fn new_equal_flow_lease() -> SharedCoSQueueLease {
    SharedCoSQueueLease::new_v8_with_rate_mode(
        50_000_000,
        256 * 1024,
        8,
        1,
        V8RateMode::EqualFlowSuppress,
    )
}

fn seed_two_valid_skewed_equal_flow_epochs(lease: &SharedCoSQueueLease) {
    // Pre-#1746 expectations: clip-to-slowest target = min(8000/4,
    // 1800/1) = 1800; cap = 1800 x 4 = 7200.
    seed_two_valid_skewed_epochs_expecting(lease, 1_800, 7_200);
}

/// #1746: parameterized two-epoch skewed seeding shared by the per-
/// policy tests. Worker 0 carries 4 flows and is granted 8000 B/epoch
/// (2000 B/flow); worker 1 carries 1 flow granted 1800 B/epoch
/// (1800 B/flow). The lease rate is 50 MB/s => nominal 10_000 B/epoch.
/// Expected targets per policy over these samples:
///   Slowest:    min(2000, 1800)            = 1800, cap 1800 x 4 = 7200
///   Mean:       (8000 + 1800) / (4 + 1)    = 1960, cap 1960 x 4 = 7840
///   IdealShare: 10_000 / (4 + 1)           = 2000, cap 2000 x 4 = 8000
fn seed_two_valid_skewed_epochs_expecting(
    lease: &SharedCoSQueueLease,
    expected_target: u64,
    expected_cap: u64,
) {
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(1, 1);

    let _ = lease.acquire_v8(0, EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(1, EPOCH_DURATION_NS, 1_800);
    assert!(!lease.v8_equal_flow_enforced());

    let _ = lease.acquire_v8(0, 2 * EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(1, 2 * EPOCH_DURATION_NS, 1_800);
    assert!(!lease.v8_equal_flow_enforced());

    let _ = lease.acquire_v8(1, 3 * EPOCH_DURATION_NS, 1);
    assert!(lease.v8_equal_flow_enforced());
    assert_eq!(lease.v8_equal_flow_target_per_flow(), expected_target);
    assert_eq!(lease.v8_equal_flow_worker_cap(), expected_cap);
}

fn new_equal_flow_lease_with_policy(policy: EqualFlowTargetPolicy) -> SharedCoSQueueLease {
    SharedCoSQueueLease::new_v8_with_rate_mode_and_policy(
        50_000_000,
        256 * 1024,
        8,
        1,
        V8RateMode::EqualFlowSuppress,
        policy,
    )
}

#[test]
fn equal_flow_default_new_v8_behavior_unchanged() {
    let lease = SharedCoSQueueLease::new_v8(50_000_000, 256 * 1024, 2, 1);
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(1, 1);
    assert!(!lease.v8_equal_flow_active());

    let g0 = lease.acquire_v8(0, EPOCH_DURATION_NS, 8_000);
    let g1 = lease.acquire_v8(1, EPOCH_DURATION_NS, 2_000);
    assert_eq!(g0, 8_000);
    assert_eq!(g1, 2_000);
    assert_eq!(lease.v8_equal_flow_fail_open_count(), 0);
}

// === #1746 equal-flow target-policy tests ===

#[test]
fn equal_flow_named_slowest_policy_is_byte_identical_to_default() {
    // The named `slowest` value and the unset default must produce the
    // same published target/cap over identical inputs (Q1/Q4 of the
    // #1746 plan: no `"" vs named` divergence).
    let named = new_equal_flow_lease_with_policy(EqualFlowTargetPolicy::Slowest);
    seed_two_valid_skewed_epochs_expecting(&named, 1_800, 7_200);
    assert_eq!(named.v8_equal_flow_target_policy_label(), "slowest");

    let default = new_equal_flow_lease();
    seed_two_valid_skewed_epochs_expecting(&default, 1_800, 7_200);
    assert_eq!(default.v8_equal_flow_target_policy_label(), "slowest");
}

#[test]
fn equal_flow_mean_policy_targets_aggregate_mean_per_flow() {
    // Mean = sum(prev_grants) / sum(active_flows) over the sampled set:
    // (8000 + 1800) / (4 + 1) = 1960 B/epoch. Higher than the slowest
    // band (1800) but below the fastest per-flow rate (2000), so only
    // the lucky outliers clip.
    let lease = new_equal_flow_lease_with_policy(EqualFlowTargetPolicy::Mean);
    seed_two_valid_skewed_epochs_expecting(&lease, 1_960, 7_840);
    assert_eq!(lease.v8_equal_flow_target_policy_label(), "mean");
}

#[test]
fn equal_flow_ideal_share_policy_targets_nominal_share() {
    // IdealShare = nominal epoch budget / total active flows =
    // 10_000 / 5 = 2000 B/epoch. Equal to the fastest per-flow rate
    // here, i.e. the documented capacity-limited no-op: worker 0's cap
    // (2000 x 4 = 8000) equals its fair share, so nothing clips.
    let lease = new_equal_flow_lease_with_policy(EqualFlowTargetPolicy::IdealShare);
    seed_two_valid_skewed_epochs_expecting(&lease, 2_000, 8_000);
    assert_eq!(lease.v8_equal_flow_target_policy_label(), "ideal-share");
}

#[test]
fn equal_flow_ideal_share_numerator_scales_with_lagged_rotation_budget() {
    // Codex r1 F1 on PR #1867: the IdealShare nominal numerator must be
    // the TRUE per-rotation budget (rate x elapsed + carry), not a fixed
    // one-EPOCH nominal — otherwise a lagged rotation (new_cap = K x
    // rate x EPOCH) would keep a 1x target and clip away the v8
    // lag-recovery credit. With a 3-epoch rotation lag the budget is
    // 30_000 B, so the candidate is 30_000 / 5 = 6000 and the EWMA over
    // the prior 2000 gives (3 x 2000 + 6000) / 4 = 3000.
    let lease = new_equal_flow_lease_with_policy(EqualFlowTargetPolicy::IdealShare);
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(1, 1);

    let _ = lease.acquire_v8(0, EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(1, EPOCH_DURATION_NS, 1_800);
    assert!(!lease.v8_equal_flow_enforced());

    let _ = lease.acquire_v8(0, 2 * EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(1, 2 * EPOCH_DURATION_NS, 1_800);
    assert!(!lease.v8_equal_flow_enforced());

    // 3-epoch lag (raw_elapsed = 3 x EPOCH <= K = 8): regime-1 recovery
    // grants the raw lag, so new_cap = 30_000 and the published target
    // scales with it instead of staying at the fixed-EPOCH 2000.
    let _ = lease.acquire_v8(1, 5 * EPOCH_DURATION_NS, 1);
    assert!(lease.v8_equal_flow_enforced());
    assert_eq!(lease.v8_equal_flow_target_per_flow(), 3_000);
    assert_eq!(lease.v8_equal_flow_worker_cap(), 12_000);
}

#[test]
fn matches_config_v8_distinguishes_equal_flow_target_policy() {
    // #1746 F3: a live policy change must rebuild the lease; a stale
    // lease must not be reused across a policy edit.
    let lease = new_equal_flow_lease_with_policy(EqualFlowTargetPolicy::Mean);
    assert!(lease.matches_config_v8(
        50_000_000,
        256 * 1024,
        8,
        1,
        V8RateMode::EqualFlowSuppress,
        EqualFlowTargetPolicy::Mean,
    ));
    assert!(
        !lease.matches_config_v8(
            50_000_000,
            256 * 1024,
            8,
            1,
            V8RateMode::EqualFlowSuppress,
            EqualFlowTargetPolicy::Slowest,
        ),
        "policy change must force a lease rebuild"
    );
}

#[test]
fn equal_flow_caps_ahead_worker_after_prior_skew() {
    let lease = new_equal_flow_lease();
    seed_two_valid_skewed_equal_flow_epochs(&lease);

    let granted = lease.acquire_v8(0, 3 * EPOCH_DURATION_NS, 10_000);
    assert_eq!(
        granted, 7_200,
        "4-flow worker is capped at lagging prior per-flow target"
    );
    assert!(lease.v8_equal_flow_cap_hit_events() > 0);
    assert!(lease.v8_equal_flow_suppressed_grant_bytes() > 0);
}

#[test]
fn equal_flow_intentionally_leaves_class_capacity_unused() {
    let lease = new_equal_flow_lease();
    seed_two_valid_skewed_equal_flow_epochs(&lease);

    let g0 = lease.acquire_v8(0, 3 * EPOCH_DURATION_NS, 10_000);
    let g1 = lease.acquire_v8(1, 3 * EPOCH_DURATION_NS, 10_000);
    assert_eq!(g0, 7_200);
    assert_eq!(
        g1, 1_799,
        "worker 1 already consumed one byte in this epoch"
    );
    assert!(
        g0 + g1 < 10_000,
        "equal-flow enforcement suppresses ahead workers instead of filling cap"
    );
}

/// #1830 (e): regression pin for the removed 32-worker scratch cap.
/// Pre-#1830 the rotation captured per-worker swap results in fixed
/// `[_; 32]` stack arrays; any ACTIVE worker with id >= 32 fell into
/// `active_outside_scratch` and forced an `UnsampledActiveWorker`
/// fail-open EVERY rotation, so equal-flow could never enforce on
/// >32-worker hosts (release builds: the only guard was a stripped
/// debug_assert). With the heap scratch sized to the true worker-array
/// length, a worker id far above 32 participates normally and the
/// lease reaches enforcement.
#[test]
fn equal_flow_enforces_beyond_legacy_32_worker_scratch_cap() {
    let lease = SharedCoSQueueLease::new_v8_with_rate_mode(
        50_000_000,
        256 * 1024,
        8,
        39, // 40 worker slots — beyond the old MAX_WORKERS_SCRATCH = 32
        V8RateMode::EqualFlowSuppress,
    );
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(35, 1);

    let _ = lease.acquire_v8(0, EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(35, EPOCH_DURATION_NS, 1_800);
    assert!(!lease.v8_equal_flow_enforced());

    let _ = lease.acquire_v8(0, 2 * EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(35, 2 * EPOCH_DURATION_NS, 1_800);
    assert!(!lease.v8_equal_flow_enforced());
    assert_ne!(
        lease.v8_equal_flow_fail_open_reason(),
        V8EqualFlowFailOpenReason::UnsampledActiveWorker,
        "active worker id 35 must be captured by the rotation scratch, \
         not blamed as an unsampled outside-scratch worker"
    );

    let _ = lease.acquire_v8(35, 3 * EPOCH_DURATION_NS, 1);
    assert!(
        lease.v8_equal_flow_enforced(),
        "equal-flow must reach enforcement with an active worker id > 32"
    );
    assert_eq!(lease.v8_equal_flow_target_per_flow(), 1_800);
    assert_eq!(lease.v8_equal_flow_worker_cap(), 7_200);
}

/// #1830 (e): default-mode (CstructDefault) sibling of the >32-worker
/// pin — rotation and per-worker fair-share publication must cover the
/// full worker-id range, not just the first 32 slots.
#[test]
fn default_mode_rotation_covers_beyond_32_worker_ids() {
    let lease = SharedCoSQueueLease::new_v8(50_000_000, 256 * 1024, 8, 47);
    lease.rehydrate_worker_active_count(40, 3);
    lease.rehydrate_worker_active_count(2, 1);

    let g40 = lease.acquire_v8(40, EPOCH_DURATION_NS, 6_000);
    let g2 = lease.acquire_v8(2, EPOCH_DURATION_NS, 2_000);
    assert_eq!(g40, 6_000);
    assert_eq!(g2, 2_000);

    let v8 = lease.v8.as_ref().expect("v8 lease");
    let share40 = v8.worker_fair_share[40].load(Ordering::Acquire);
    let share2 = v8.worker_fair_share[2].load(Ordering::Acquire);
    assert!(
        share40 > 0 && share2 > 0,
        "fair shares must be published for worker ids above the old cap"
    );
    assert_eq!(
        share40,
        3 * share2,
        "flow-proportional shares must use the true per-worker counts"
    );
    assert_eq!(lease.v8_equal_flow_fail_open_count(), 0);
}

#[test]
fn equal_flow_bypass_cannot_exceed_cap() {
    let lease = new_equal_flow_lease();
    seed_two_valid_skewed_equal_flow_epochs(&lease);
    lease
        .v8
        .as_ref()
        .unwrap()
        .epoch
        .bypass_grace_rotations_remaining
        .store(1, Ordering::Release);

    let first = lease.acquire_v8(0, 3 * EPOCH_DURATION_NS, 10_000);
    let second = lease.acquire_v8(0, 3 * EPOCH_DURATION_NS, 10_000);
    assert_eq!(first, 7_200);
    assert_eq!(second, 0, "bypass must not grant beyond equal-flow cap");
    assert_eq!(lease.v8_bypass_grace_uses(), 0);
}

#[test]
fn equal_flow_acquire_side_cap_check_is_read_only_on_inconsistent_snapshot() {
    let lease = new_equal_flow_lease();
    seed_two_valid_skewed_equal_flow_epochs(&lease);
    let v8 = lease.v8.as_ref().expect("v8 lease");
    let tag = v8.equal_flow.epoch_tag.load(Ordering::Acquire);
    let target = v8
        .equal_flow
        .current_target_per_flow
        .load(Ordering::Acquire);
    let reason_before = lease.v8_equal_flow_fail_open_reason();
    let count_before = lease.v8_equal_flow_fail_open_count();
    let stale_before = lease.v8_equal_flow_stale_or_tag_mismatch_events();

    assert_eq!(
        lease.equal_flow_cap_v8(v8, 0, tag.wrapping_add(1)),
        None,
        "stale acquirer must fail open without publishing telemetry"
    );
    assert_eq!(
        lease.v8_equal_flow_stale_or_tag_mismatch_events(),
        stale_before + 1
    );

    v8.equal_flow
        .current_target_per_flow
        .store(0, Ordering::Release);
    assert_eq!(
        lease.equal_flow_cap_v8(v8, 0, tag),
        None,
        "transient zero target must be read-only on acquire"
    );

    v8.equal_flow
        .current_target_per_flow
        .store(u64::MAX, Ordering::Release);
    assert_eq!(
        lease.equal_flow_cap_v8(v8, 0, tag),
        None,
        "overflow while reading a transient payload must be read-only"
    );

    v8.equal_flow
        .current_target_per_flow
        .store(target, Ordering::Release);
    assert!(lease.v8_equal_flow_enforced());
    assert_eq!(lease.v8_equal_flow_fail_open_reason(), reason_before);
    assert_eq!(lease.v8_equal_flow_fail_open_count(), count_before);
    assert_eq!(
        lease.v8_equal_flow_stale_or_tag_mismatch_events(),
        stale_before + 1,
        "only stale/tag mismatch increments the transient side channel"
    );
}

/// #13071 (deep-review D2-06): `equal_flow_cap_v8` must size the worker
/// cap from the epoch-consistent flow count (#1745 sticky-max acquire-time
/// sample), not the live `worker_active_flow_buckets` count. A peer flow
/// that drains mid-epoch decrements the live count AFTER the epoch's fair
/// budget was computed for — and partially consumed by — the original
/// count; multiplying the live count retroactively shrank the worker cap
/// below bytes already spent, starving the remaining flows for the rest
/// of the epoch and feeding false cap-hit/suppressed-grant telemetry.
#[test]
fn v8_equal_flow_cap_preserves_remaining_flow_share_when_sibling_flow_drains_mid_epoch() {
    let lease = new_equal_flow_lease();
    seed_two_valid_skewed_equal_flow_epochs(&lease);
    let v8 = lease.v8.as_ref().expect("v8 lease");
    let tag = v8.equal_flow.epoch_tag.load(Ordering::Acquire);
    assert_eq!(lease.v8_equal_flow_target_per_flow(), 1_800);

    // In-flight epoch 3: worker 0 (4 flows) acquires once so the
    // epoch-tagged sticky-max sample (tag, 4) is recorded — the same
    // denominator the rotation publisher used for this epoch.
    let live0 = lease.worker_active_flow_buckets_for(0).unwrap();
    assert_eq!(live0.load(Ordering::Relaxed), 4);
    assert_eq!(lease.acquire_v8(0, 3 * EPOCH_DURATION_NS + 1_000, 1), 1);

    // Flows F1..F3 each consumed their 1_800 B per-flow target.
    v8.worker_grants[0]
        .0
        .store(PackedEpochGrant::pack(tag, 3 * 1_800), Ordering::Release);

    // F3 drains its last packet mid-epoch: live 4 -> 3, while the
    // epoch-sticky sample stays 4.
    live0.fetch_sub(1, Ordering::Relaxed);

    // Decisive check: the cap keeps the epoch-consistent 4-flow budget
    // instead of collapsing to the drained live count (3 * 1_800).
    assert_eq!(lease.equal_flow_cap_v8(v8, 0, tag), Some(7_200));

    let cap_hits_before = lease.v8_equal_flow_cap_hit_events();
    let suppressed_before = lease.v8_equal_flow_suppressed_grant_bytes();

    // F4 asks for its own 1_800 B share later in the same epoch: the
    // 5_400 B already consumed must only count against the full 7_200 B
    // epoch budget, and a legitimate grant must not be miscounted as
    // equal-flow suppression telemetry.
    let f4 = lease.acquire_v8(0, 3 * EPOCH_DURATION_NS + 100_000, 1_800);
    assert_eq!(f4, 1_800, "remaining flow must keep its per-flow share");
    assert_eq!(lease.v8_equal_flow_cap_hit_events(), cap_hits_before);
    assert_eq!(
        lease.v8_equal_flow_suppressed_grant_bytes(),
        suppressed_before
    );

    // All four flows have now drained (live -> 0): a straggler acquire
    // still evaluates against the epoch-consistent budget, not a
    // synthetic zero cap.
    live0.store(0, Ordering::Relaxed);
    assert_eq!(
        lease.equal_flow_cap_v8(v8, 0, tag),
        Some(7_200),
        "drained-live worker must keep the epoch-consistent cap"
    );
}

/// #13071 (deep-review D2-06) zero-denominator doctrine: a worker with
/// no live flows AND no epoch sample must not receive a synthetic
/// `Some(0)` cap — that denied every remaining byte of the epoch and
/// counted cap-hit/suppressed telemetry for a cap that was zero only
/// because the flow count was. Match the read-only `target == 0` /
/// stale-tag doctrine: `None`.
#[test]
fn v8_equal_flow_cap_is_none_for_worker_with_no_flows_and_no_epoch_sample() {
    let lease = new_equal_flow_lease();
    seed_two_valid_skewed_equal_flow_epochs(&lease);
    let v8 = lease.v8.as_ref().expect("v8 lease");
    let tag = v8.equal_flow.epoch_tag.load(Ordering::Acquire);

    // Worker 0: live count drained to zero mid-epoch, and its sample
    // slot carries no sample for the current epoch tag.
    lease
        .worker_active_flow_buckets_for(0)
        .unwrap()
        .store(0, Ordering::Relaxed);
    v8.worker_equal_flow_active_samples[0]
        .0
        .store(PackedEpochGrant::pack(tag, 0), Ordering::Release);

    assert_eq!(
        lease.equal_flow_cap_v8(v8, 0, tag),
        None,
        "idle-at-cap-eval worker must fail open read-only, not Some(0)"
    );
}

#[test]
fn equal_flow_epoch_payload_is_visible_after_tag_under_concurrent_readers() {
    let lease = new_equal_flow_lease();
    let v8 = lease.v8.as_ref().expect("v8 lease");
    let ack = std::sync::atomic::AtomicU32::new(0);
    let start = std::sync::Barrier::new(2);
    const ITERS: u32 = 1_000;

    std::thread::scope(|scope| {
        scope.spawn(|| {
            start.wait();
            for tag in 1..=ITERS {
                if tag % 2 == 0 {
                    v8.equal_flow
                        .enforce_epoch(tag, tag as u64 + 10, tag as u64 + 20);
                } else {
                    v8.equal_flow
                        .fail_open(tag, V8EqualFlowFailOpenReason::NoActiveFlows);
                }
                while ack.load(Ordering::Acquire) < tag {
                    std::hint::spin_loop();
                }
            }
        });

        start.wait();
        for tag in 1..=ITERS {
            loop {
                let seen_tag = v8.equal_flow.epoch_tag.load(Ordering::Acquire);
                if seen_tag >= tag {
                    assert_eq!(seen_tag, tag, "writer must wait for reader ack");
                    break;
                }
                std::hint::spin_loop();
            }

            let enforced = v8.equal_flow.enforced.load(Ordering::Acquire);
            let target = v8
                .equal_flow
                .current_target_per_flow
                .load(Ordering::Acquire);
            let worker_cap = v8.equal_flow.current_worker_cap.load(Ordering::Acquire);
            let reason = V8EqualFlowFailOpenReason::from_u32(
                v8.equal_flow.fail_open_reason.load(Ordering::Acquire),
            );

            if tag % 2 == 0 {
                assert_eq!(enforced, 1, "tag {tag} must publish enforced payload");
                assert_eq!(target, tag as u64 + 10);
                assert_eq!(worker_cap, tag as u64 + 20);
                assert_eq!(reason, V8EqualFlowFailOpenReason::None);
            } else {
                assert_eq!(enforced, 0, "tag {tag} must publish fail-open payload");
                assert_eq!(target, 0);
                assert_eq!(worker_cap, 0);
                assert_eq!(reason, V8EqualFlowFailOpenReason::NoActiveFlows);
            }

            ack.store(tag, Ordering::Release);
        }
    });
}

#[test]
fn equal_flow_fail_open_after_enforcement_does_not_reuse_stale_cap() {
    let lease = new_equal_flow_lease();
    seed_two_valid_skewed_equal_flow_epochs(&lease);

    // Epoch 3 was enforced with a 7,200-byte cap for worker 0. Worker 0
    // then has no epoch-3 sample, so rotating into epoch 4 must fail open
    // and grant the ordinary active-flow-proportional 8,000-byte share,
    // never the stale enforced cap from epoch 3.
    let granted = lease.acquire_v8(0, 4 * EPOCH_DURATION_NS, 10_000);
    assert_eq!(granted, 8_000);
    assert!(!lease.v8_equal_flow_enforced());
    // #1745: the sample set is now the acquire-time sticky-max. In epoch 3
    // only worker 1 acquired (the seed's `acquire_v8(1, 3*EPOCH, 1)`), so
    // at the epoch-4 rotation worker 0 is active-at-rotation but with no
    // epoch-3 demand/grant/sample — an idle-at-rotation worker that is
    // correctly EXCLUDED (not blamed as UnsampledActiveWorker). With only
    // worker 1 sampled, the publisher bails InsufficientSampledWorkers.
    // The load-bearing assertions (not enforced, grant = ordinary share,
    // no stale cap reuse) are unchanged.
    assert_eq!(
        lease.v8_equal_flow_fail_open_reason(),
        V8EqualFlowFailOpenReason::InsufficientSampledWorkers
    );
}

#[test]
fn equal_flow_fail_open_for_one_sampled_worker() {
    let lease = new_equal_flow_lease();
    lease.rehydrate_worker_active_count(0, 1);
    let _ = lease.acquire_v8(0, EPOCH_DURATION_NS, 1_000);
    let _ = lease.acquire_v8(0, 2 * EPOCH_DURATION_NS, 1_000);
    assert!(!lease.v8_equal_flow_enforced());
    assert_eq!(
        lease.v8_equal_flow_fail_open_reason(),
        V8EqualFlowFailOpenReason::InsufficientSampledWorkers
    );
}

#[test]
fn equal_flow_fail_open_for_unsampled_active_worker() {
    let lease = new_equal_flow_lease();
    lease.rehydrate_worker_active_count(0, 1);
    lease.rehydrate_worker_active_count(1, 1);
    let _ = lease.acquire_v8(0, EPOCH_DURATION_NS, 1_000);
    let _ = lease.acquire_v8(0, 2 * EPOCH_DURATION_NS, 1_000);
    assert!(!lease.v8_equal_flow_enforced());
    // #1745: worker 1 has a nonzero rehydrated flow bucket but never
    // acquired (sent zero traffic this window) -> no demand/grant/sample
    // -> idle-at-rotation, correctly EXCLUDED rather than blamed. Only
    // worker 0 is a real participant, so the publisher bails
    // InsufficientSampledWorkers (one sampled worker), which is the
    // accurate reason. This is precisely the banked/idle decoupling the
    // fix introduces: a flow-bucket-nonzero-but-silent worker no longer
    // forces a fail-open on behalf of the truly-active worker.
    assert_eq!(
        lease.v8_equal_flow_fail_open_reason(),
        V8EqualFlowFailOpenReason::InsufficientSampledWorkers
    );
}

#[test]
fn equal_flow_fail_open_for_zero_or_tiny_target() {
    let lease = new_equal_flow_lease();
    lease.rehydrate_worker_active_count(0, 2_000);
    lease.rehydrate_worker_active_count(1, 2_000);
    let _ = lease.acquire_v8(0, EPOCH_DURATION_NS, 1);
    let _ = lease.acquire_v8(1, EPOCH_DURATION_NS, 1);
    let _ = lease.acquire_v8(0, 2 * EPOCH_DURATION_NS, 1);
    assert!(!lease.v8_equal_flow_enforced());
    assert_eq!(
        lease.v8_equal_flow_fail_open_reason(),
        V8EqualFlowFailOpenReason::ZeroTarget
    );
}

#[test]
fn equal_flow_fail_open_for_quiet_active_worker_without_demand_or_grant() {
    let lease = new_equal_flow_lease();
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(1, 1);
    let _ = lease.acquire_v8(0, EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(0, 2 * EPOCH_DURATION_NS, 8_000);
    assert!(!lease.v8_equal_flow_enforced());
    // #1745: worker 1 is "quiet active" — a nonzero flow bucket but no
    // demand/grant/sample (it never acquired). It is the idle-at-rotation
    // exclude case, so it no longer forces an UnsampledActiveWorker bail.
    // Only worker 0 is sampled -> InsufficientSampledWorkers.
    assert_eq!(
        lease.v8_equal_flow_fail_open_reason(),
        V8EqualFlowFailOpenReason::InsufficientSampledWorkers
    );
}

#[test]
fn equal_flow_fail_open_for_nonzero_low_demand_worker() {
    let lease = new_equal_flow_lease();
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(1, 1);

    let _ = lease.acquire_v8(0, EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(1, EPOCH_DURATION_NS, 1);
    let _ = lease.acquire_v8(0, 2 * EPOCH_DURATION_NS, 8_000);
    assert!(!lease.v8_equal_flow_enforced());
    assert_eq!(
        lease.v8_equal_flow_fail_open_reason(),
        V8EqualFlowFailOpenReason::LowDemandWorker
    );
}

// === #1745: acquire-time active-flow sampling regression tests ===

/// #1745 regression: a forced `InsufficientSampledWorkers` epoch must
/// leave `suppressed_grant_bytes` and `cap_hit_events` untouched (it is a
/// fail-open, not a suppression). Validation gate 3.
#[test]
fn equal_flow_insufficient_sampled_workers_leaves_suppression_unchanged() {
    let lease = new_equal_flow_lease();
    // Single active worker (-P1-style): it acquires alone, so the
    // publisher can never reach the sampled>=2 threshold.
    lease.rehydrate_worker_active_count(0, 1);
    let _ = lease.acquire_v8(0, EPOCH_DURATION_NS, 1_000);
    let _ = lease.acquire_v8(0, 2 * EPOCH_DURATION_NS, 1_000);
    assert!(!lease.v8_equal_flow_enforced());
    assert_eq!(
        lease.v8_equal_flow_fail_open_reason(),
        V8EqualFlowFailOpenReason::InsufficientSampledWorkers
    );
    let suppressed_before = lease.v8_equal_flow_suppressed_grant_bytes();
    let cap_hits_before = lease.v8_equal_flow_cap_hit_events();
    // Drive another fail-open epoch with the same single worker.
    let _ = lease.acquire_v8(0, 3 * EPOCH_DURATION_NS, 1_000);
    assert!(!lease.v8_equal_flow_enforced());
    assert_eq!(
        lease.v8_equal_flow_suppressed_grant_bytes(),
        suppressed_before,
        "fail-open epoch must not increment suppressed_grant_bytes"
    );
    assert_eq!(
        lease.v8_equal_flow_cap_hit_events(),
        cap_hits_before,
        "fail-open epoch must not increment cap_hit_events"
    );
}

/// #1745 positive: two workers sampled via the acquire-time sticky-max
/// path reach enforcement. Crucially, the worker that is "ahead" stops
/// re-acquiring on the enforcing epoch (models the banked exact queue
/// that skips acquire_v8 while it has tokens); the OTHER worker's acquire
/// triggers the rotation. Enforcement must still publish because both
/// workers left a sticky-max sample in the just-ended epoch, even though
/// only one of them demands on the rotating epoch itself.
#[test]
fn equal_flow_enforces_from_acquire_time_samples_when_ahead_worker_banks() {
    let lease = new_equal_flow_lease();
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(1, 1);

    // Epoch 1 + 2: both workers acquire (both leave samples + demand).
    let _ = lease.acquire_v8(0, EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(1, EPOCH_DURATION_NS, 1_800);
    let _ = lease.acquire_v8(0, 2 * EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(1, 2 * EPOCH_DURATION_NS, 1_800);
    assert!(!lease.v8_equal_flow_enforced());

    // Epoch 3 rotation: only worker 1 acquires (worker 0 is "banked" and
    // skips acquire). The epoch-2 samples for BOTH workers were captured
    // at acquire time, so the publisher has a 2-worker sample set and
    // enforces. Under the pre-#1745 rotation-instant logic worker 0 would
    // have been active-but-undemanded and forced a fail-open.
    let _ = lease.acquire_v8(1, 3 * EPOCH_DURATION_NS, 1);
    assert!(
        lease.v8_equal_flow_enforced(),
        "enforcement must trigger from acquire-time samples even when the \
         ahead worker banks and skips acquire on the rotating epoch"
    );
    assert!(lease.v8_equal_flow_target_per_flow() > 0);
    assert!(lease.v8_equal_flow_worker_cap() > 0);
}

/// #1745: the sample is a STICKY-MAX across the epoch, not last-write. A
/// worker that records a high flow count then a lower one (flow teardown)
/// in the same epoch must contribute the MAX to the rotation sample.
#[test]
fn equal_flow_active_sample_is_sticky_max_within_epoch() {
    let lease = new_equal_flow_lease();
    let v8 = lease.v8.as_ref().expect("v8 lease");
    // Use the published epoch tag the slot was reset to at construction
    // (tag 0). Record high then low for worker 0.
    let tag = v8.equal_flow.epoch_tag.load(Ordering::Acquire);
    record_equal_flow_active_sample(&v8.worker_equal_flow_active_samples[0], tag, 10);
    record_equal_flow_active_sample(&v8.worker_equal_flow_active_samples[0], tag, 3);
    let (slot_tag, slot_count) =
        PackedEpochGrant::unpack(v8.worker_equal_flow_active_samples[0].0.load(Ordering::Acquire));
    assert_eq!(slot_tag, tag);
    assert_eq!(slot_count, 10, "sticky-max must keep the high count");
}

/// #1745 critical race: a stale acquirer (snapshotted a different epoch
/// tag) must NEVER write its tag over a slot the rotation already advanced
/// to a different epoch. The helper matches on tag EQUALITY, so any
/// mismatch (forward, backward, OR wrapped) no-ops.
#[test]
fn equal_flow_active_sample_never_writes_tag_backwards() {
    let lease = new_equal_flow_lease();
    let v8 = lease.v8.as_ref().expect("v8 lease");
    // Simulate a rotation having advanced the slot to epoch tag 5, count 0.
    v8.worker_equal_flow_active_samples[0]
        .0
        .store(PackedEpochGrant::pack(5, 0), Ordering::Release);
    // A stale acquirer holding my_tag = 3 tries to record.
    record_equal_flow_active_sample(&v8.worker_equal_flow_active_samples[0], 3, 99);
    let (slot_tag, slot_count) =
        PackedEpochGrant::unpack(v8.worker_equal_flow_active_samples[0].0.load(Ordering::Acquire));
    assert_eq!(slot_tag, 5, "stale acquirer must not write tag backwards");
    assert_eq!(slot_count, 0, "stale acquirer must not corrupt the count");
}

/// #1745 / Codex code-review HIGH: the u32 epoch tag wraps every ~9.94
/// days at the 200µs epoch. A stale acquirer holding `my_tag = u32::MAX`
/// racing a rotation that reset the slot to the freshly-wrapped epoch
/// `(0, 0)` must NOT write its wrapped-old tag backwards. Equality
/// matching makes `0 != u32::MAX` a clean no-op; a relational
/// `curr_tag > my_tag` check would have failed (`0 > u32::MAX == false`)
/// and corrupted the fresh epoch-0 slot.
#[test]
fn equal_flow_active_sample_safe_across_tag_wrap() {
    let lease = new_equal_flow_lease();
    let v8 = lease.v8.as_ref().expect("v8 lease");
    // Rotation has just wrapped: slot freshly reset to epoch tag 0.
    v8.worker_equal_flow_active_samples[0]
        .0
        .store(PackedEpochGrant::pack(0, 0), Ordering::Release);
    // A stale acquirer from the pre-wrap epoch (my_tag = u32::MAX) records.
    record_equal_flow_active_sample(&v8.worker_equal_flow_active_samples[0], u32::MAX, 99);
    let (slot_tag, slot_count) =
        PackedEpochGrant::unpack(v8.worker_equal_flow_active_samples[0].0.load(Ordering::Acquire));
    assert_eq!(slot_tag, 0, "wrapped stale acquirer must not write tag backwards");
    assert_eq!(slot_count, 0, "wrapped stale acquirer must not corrupt the count");
    // And the legitimate epoch-0 acquirer still records normally.
    record_equal_flow_active_sample(&v8.worker_equal_flow_active_samples[0], 0, 7);
    let (slot_tag2, slot_count2) =
        PackedEpochGrant::unpack(v8.worker_equal_flow_active_samples[0].0.load(Ordering::Acquire));
    assert_eq!(slot_tag2, 0);
    assert_eq!(slot_count2, 7, "fresh epoch-0 acquirer records its sample");
}

/// #1745: the default `CstructDefault` rate mode must never touch the
/// acquire-time sample array, on either the acquire or rotation side.
#[test]
fn equal_flow_default_mode_never_records_active_samples() {
    let lease = SharedCoSQueueLease::new_v8(50_000_000, 256 * 1024, 2, 1);
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(1, 1);
    let _ = lease.acquire_v8(0, EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(1, EPOCH_DURATION_NS, 2_000);
    let _ = lease.acquire_v8(0, 2 * EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(1, 2 * EPOCH_DURATION_NS, 2_000);
    let v8 = lease.v8.as_ref().expect("v8 lease");
    for slot in v8.worker_equal_flow_active_samples.iter() {
        assert_eq!(
            slot.0.load(Ordering::Acquire),
            0,
            "CstructDefault path must leave the equal-flow sample array untouched"
        );
    }
}

/// #1745 / Codex Finding 4 safety: a worker that demanded-or-was-granted
/// bytes but whose acquire-time sample is missing (a real participant we
/// failed to sample, e.g. via the tag-backwards race) must keep the
/// `UnsampledActiveWorker` fail-open rather than be silently excluded.
#[test]
fn equal_flow_unsampled_real_participant_still_fails_open() {
    let lease = new_equal_flow_lease();
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(1, 1);
    // Both workers acquire for two epochs to build demand + grants +
    // samples, reaching the verge of enforcement.
    let _ = lease.acquire_v8(0, EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(1, EPOCH_DURATION_NS, 1_800);
    let _ = lease.acquire_v8(0, 2 * EPOCH_DURATION_NS, 8_000);
    let _ = lease.acquire_v8(1, 2 * EPOCH_DURATION_NS, 1_800);
    // Before the next rotation, wipe worker 0's epoch-2 sample slot so it
    // becomes a "demanded+granted but unsampled" participant at rotation.
    let v8 = lease.v8.as_ref().expect("v8 lease");
    v8.worker_equal_flow_active_samples[0]
        .0
        .store(0, Ordering::Release);
    // Worker 1 triggers the rotation into epoch 3.
    let _ = lease.acquire_v8(1, 3 * EPOCH_DURATION_NS, 1);
    assert!(!lease.v8_equal_flow_enforced());
    assert_eq!(
        lease.v8_equal_flow_fail_open_reason(),
        V8EqualFlowFailOpenReason::UnsampledActiveWorker,
        "a demanded/granted-but-unsampled real participant must keep the \
         safety fail-open, not be silently excluded"
    );
}

#[test]
fn v8_lease_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SharedCoSQueueLease>();
}

// === #1231 v5 'all peers CPU-bound' bypass-grace tests ===

#[test]
fn bypass_telemetry_starts_zero() {
    let lease = SharedCoSQueueLease::new_v8(10_000_000, 64 * 1024, 2, 5);
    assert!(!lease.v8_bypass_grace_active());
    assert_eq!(lease.v8_bypass_grace_arms(), 0);
    assert_eq!(lease.v8_bypass_grace_uses(), 0);
}

#[test]
fn bypass_telemetry_legacy_lease_returns_zero() {
    let lease = SharedCoSQueueLease::new(10_000_000, 64 * 1024, 2);
    assert!(!lease.v8_bypass_grace_active());
    assert_eq!(lease.v8_bypass_grace_arms(), 0);
    assert_eq!(lease.v8_bypass_grace_uses(), 0);
}

#[test]
fn bypass_does_not_arm_under_subsaturation() {
    // iperf-e style: workers consume below their primary share. No
    // narrow signal fires; bypass stays off across multiple rotations.
    let lease = SharedCoSQueueLease::new_v8(2_000_000_000, 64 * 1024, 4, 3);
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(1, 3);
    lease.rehydrate_worker_active_count(2, 4);
    lease.rehydrate_worker_active_count(3, 1);

    let mut now_ns = EPOCH_DURATION_NS;
    for _epoch in 0..10 {
        for worker_id in 0..4 {
            let _ = lease.acquire_v8(worker_id, now_ns, 1_000);
        }
        now_ns += EPOCH_DURATION_NS;
    }
    assert_eq!(
        lease.v8_bypass_grace_arms(),
        0,
        "sub-saturation should not arm bypass"
    );
    assert!(!lease.v8_bypass_grace_active());
}

#[test]
fn bypass_decays_over_rotations_when_no_signal() {
    // Once forced-on, bypass decays one rotation at a time when no
    // worker fires the narrow exit.
    let lease = SharedCoSQueueLease::new_v8(2_000_000_000, 64 * 1024, 1, 0);
    lease.rehydrate_worker_active_count(0, 1);

    // Establish initial epoch with a rotation.
    let _ = lease.acquire_v8(0, EPOCH_DURATION_NS, 1);

    // Force-arm via direct field access (bypassing the arming logic
    // to exercise decay independently).
    lease
        .v8
        .as_ref()
        .unwrap()
        .epoch
        .bypass_grace_rotations_remaining
        .store(5, Ordering::Release);
    assert!(lease.v8_bypass_grace_active());

    // Trigger 6 successive rotations with NO narrow-exit signal
    // (workers consume below primary share).
    for i in 0..6 {
        let now = (i as u64 + 2) * EPOCH_DURATION_NS;
        let _ = lease.acquire_v8(0, now, 1);
    }
    assert!(
        !lease.v8_bypass_grace_active(),
        "bypass should decay to off after ≥5 no-signal rotations"
    );
}

#[test]
fn bypass_does_not_arm_at_class_cap_saturation() {
    // Edge case: when prior epoch's class_granted == cap exactly
    // (no underuse slack), bypass MUST NOT arm even if a worker
    // signaled — there's no stranded primary share to recover.
    // Verify the aggregate-underuse condition gates correctly.
    //
    // To force this state we'd need a worker to consume at the cap;
    // mocking it directly is simpler and more deterministic.
    let lease = SharedCoSQueueLease::new_v8(2_000_000_000, 64 * 1024, 1, 0);
    lease.rehydrate_worker_active_count(0, 1);
    let _ = lease.acquire_v8(0, EPOCH_DURATION_NS, 1); // initial rotation

    // Force packed_granted to == cap (no underuse). Tag from current
    // epoch.
    {
        let v8 = lease.v8.as_ref().unwrap();
        let cap = v8.epoch.epoch_total_grant_cap.load(Ordering::Acquire);
        let curr = v8.epoch.packed_granted.0.load(Ordering::Acquire);
        let (tag, _) = PackedEpochGrant::unpack(curr);
        // Set packed_granted to (tag, cap as u32) — saturated.
        v8.epoch
            .packed_granted
            .0
            .store(PackedEpochGrant::pack(tag, cap as u32), Ordering::Release);
        // Inject a starvation event for worker 0.
        v8.worker_starvation_events[0]
            .0
            .store(PackedEpochGrant::pack(tag, 1), Ordering::Release);
    }

    // Trigger next rotation. With prev_granted == cap, underuse is
    // false → bypass MUST NOT arm even though signal is present.
    let arms_before = lease.v8_bypass_grace_arms();
    let _ = lease.acquire_v8(0, 2 * EPOCH_DURATION_NS, 1);
    let arms_after = lease.v8_bypass_grace_arms();
    assert_eq!(
        arms_after, arms_before,
        "saturation at cap (no underuse) must NOT arm bypass"
    );
}

#[test]
fn bypass_atomic_swap_resets_packed_granted() {
    // Verify Codex v5 fix: rotation uses atomic swap on packed_granted
    // (not load+store). After rotation, the value is (new_tag, 0).
    let lease = SharedCoSQueueLease::new_v8(2_000_000_000, 64 * 1024, 1, 0);
    lease.rehydrate_worker_active_count(0, 1);

    let _ = lease.acquire_v8(0, EPOCH_DURATION_NS, 1_000);

    // Read packed_granted post-rotation; should reflect new_tag.
    let v8 = lease.v8.as_ref().unwrap();
    let curr = v8.epoch.packed_granted.0.load(Ordering::Acquire);
    let (tag, _) = PackedEpochGrant::unpack(curr);
    assert_eq!(tag, 1, "first rotation publishes tag=1");

    // Trigger another rotation.
    let _ = lease.acquire_v8(0, 2 * EPOCH_DURATION_NS, 1_000);
    let curr = v8.epoch.packed_granted.0.load(Ordering::Acquire);
    let (tag, _) = PackedEpochGrant::unpack(curr);
    assert_eq!(tag, 2, "second rotation publishes tag=2");
}

#[test]
fn bypass_starvation_events_swap_at_rotation() {
    // Verify worker_starvation_events also uses atomic-swap reset.
    // After rotation, prior epoch's events are reset to (new_tag, 0).
    let lease = SharedCoSQueueLease::new_v8(2_000_000_000, 64 * 1024, 1, 0);
    lease.rehydrate_worker_active_count(0, 1);
    let _ = lease.acquire_v8(0, EPOCH_DURATION_NS, 1); // initial epoch

    let v8 = lease.v8.as_ref().unwrap();
    // Inject an event for worker 0 in the current epoch.
    let curr = v8.worker_starvation_events[0].0.load(Ordering::Acquire);
    let (tag, _) = PackedEpochGrant::unpack(curr);
    v8.worker_starvation_events[0]
        .0
        .store(PackedEpochGrant::pack(tag, 5), Ordering::Release);

    // Trigger next rotation.
    let _ = lease.acquire_v8(0, 2 * EPOCH_DURATION_NS, 1);

    // After rotation, slot should be (new_tag, 0).
    let curr = v8.worker_starvation_events[0].0.load(Ordering::Acquire);
    let (new_tag, count) = PackedEpochGrant::unpack(curr);
    assert!(new_tag > tag, "rotation incremented tag");
    assert_eq!(count, 0, "rotation reset count to 0");
}

// === #1630 (cause-1): bounded rotation credit carry ===
//
// `maybe_rotate_epoch_v8` is purely lazy — a low-rate exact class is only
// rotated when the scheduler next visits its queue, so the gap between two
// rotations of the SAME queue routinely exceeds one epoch. The pre-#1630
// clamp computed `elapsed = min(lag, EPOCH)` and reset `epoch_start := now`,
// permanently discarding `rate × (lag − EPOCH)` of grant per lagged
// rotation and pinning the lowest-rate classes below shape. These tests
// pin the bounded-carry replacement and the burst bound (the invariant the
// clamp protected) so a future refactor that re-clamps, removes a regime,
// or unbounds the carry fails loudly in CI.
//
// All tests drive the rotation through the public `acquire_v8` entrypoint
// (it rotates then snapshots) and read the published `epoch_total_grant_cap`
// directly — the cap is the rate-meter the carry enlarges. 100 Mbps =
// 12.5 MB/s, so `rate × EPOCH = 12_500_000 × 200µs = 2500 B`.

const RATE_100M: u64 = 12_500_000;
const CAP_PER_EPOCH_100M: u64 = 2_500; // rate × EPOCH_DURATION_NS

fn carry_test_lease() -> SharedCoSQueueLease {
    // active_shards/burst chosen large enough that the per-class cap, not
    // the outstanding-credit cap, is the binding limiter for these reads.
    let lease = SharedCoSQueueLease::new_v8(RATE_100M, 4_000_000, 8, 0);
    lease.rehydrate_worker_active_count(0, 1);
    lease
}

fn published_cap(lease: &SharedCoSQueueLease) -> u64 {
    lease
        .v8
        .as_ref()
        .unwrap()
        .epoch
        .epoch_total_grant_cap
        .load(Ordering::Acquire)
}

fn published_carry(lease: &SharedCoSQueueLease) -> u64 {
    lease
        .v8
        .as_ref()
        .unwrap()
        .epoch
        .epoch_carry_bytes
        .load(Ordering::Acquire)
}

#[test]
fn v8_carry_first_rotation_is_cold_resume_single_epoch() {
    // start == 0 → regime 3 cold-resume → exactly one epoch of grant,
    // identical to the pre-#1630 first-rotation behavior. No carry banked.
    let lease = carry_test_lease();
    let _ = lease.acquire_v8(0, EPOCH_DURATION_NS, u64::MAX);
    assert_eq!(
        published_cap(&lease),
        CAP_PER_EPOCH_100M,
        "first (start==0) rotation grants exactly one epoch"
    );
    assert_eq!(published_carry(&lease), 0, "cold-resume banks no carry");
}

#[test]
fn v8_carry_first_rotation_drops_stale_carry_even_with_zero_start() {
    let lease = carry_test_lease();
    lease
        .v8
        .as_ref()
        .unwrap()
        .epoch
        .epoch_carry_bytes
        .store(CAP_PER_EPOCH_100M, Ordering::Release);

    let _ = lease.acquire_v8(0, EPOCH_DURATION_NS, u64::MAX);

    assert_eq!(published_cap(&lease), CAP_PER_EPOCH_100M);
    assert_eq!(published_carry(&lease), 0, "start==0 cold-resume drops stale carry");
}

#[test]
fn v8_carry_normal_recovery_recovers_lagged_credit() {
    // THE cause-1 fix. A lag within K epochs (regime 1) must grant the
    // FULL lagged credit (`rate × lag`), not the clamped single epoch the
    // old code gave. This is exactly the per-class shape loss being fixed.
    let lease = carry_test_lease();
    let t0 = EPOCH_DURATION_NS;
    let _ = lease.acquire_v8(0, t0, u64::MAX); // cold-resume, start := t0
    // Second visit 5 epochs later (lag = 5 ≤ K=8 → regime 1).
    let lag_epochs = 5u64;
    let _ = lease.acquire_v8(0, t0 + lag_epochs * EPOCH_DURATION_NS, u64::MAX);
    assert_eq!(
        published_cap(&lease),
        lag_epochs * CAP_PER_EPOCH_100M,
        "regime-1 recovery grants the full lagged credit (was clamped to 1 epoch pre-#1630)"
    );
}

#[test]
fn v8_carry_bank_residual_no_cliff_at_k_plus_one() {
    // Gate 5d: a lag just beyond K (regime 2) must NOT drop to a single
    // epoch (the v2 cliff). It grants the K-epoch ceiling NOW and banks
    // the residual `rate × (lag − K×EPOCH)` for the next visit.
    let lease = carry_test_lease();
    let t0 = EPOCH_DURATION_NS;
    let _ = lease.acquire_v8(0, t0, u64::MAX);
    let lag_epochs = MAX_ROTATION_LAG_EPOCHS + 4; // 12 epochs at K=8
    let _ = lease.acquire_v8(0, t0 + lag_epochs * EPOCH_DURATION_NS, u64::MAX);
    assert_eq!(
        published_cap(&lease),
        MAX_ROTATION_LAG_EPOCHS * CAP_PER_EPOCH_100M,
        "regime-2 grants exactly the K-epoch ceiling (no cliff to 1 epoch)"
    );
    // Residual = (lag − K) epochs of rate, banked.
    let residual = (lag_epochs - MAX_ROTATION_LAG_EPOCHS) * CAP_PER_EPOCH_100M;
    assert_eq!(
        published_carry(&lease),
        residual,
        "regime-2 banks the residual beyond the K-epoch window"
    );
}

#[test]
fn v8_carry_banked_residual_drains_on_next_visit() {
    // The banked residual (regime 2) must be released on the next
    // on-time visit (regime 1 draw), bounded by the per-epoch drain cap.
    let lease = carry_test_lease();
    let t0 = EPOCH_DURATION_NS;
    let _ = lease.acquire_v8(0, t0, u64::MAX);
    // Bank a residual: lag K+2 → banks 2 epochs of rate.
    let lag1 = MAX_ROTATION_LAG_EPOCHS + 2;
    let t1 = t0 + lag1 * EPOCH_DURATION_NS;
    let _ = lease.acquire_v8(0, t1, u64::MAX);
    let banked = published_carry(&lease);
    assert_eq!(banked, 2 * CAP_PER_EPOCH_100M, "2 epochs banked");
    // Next on-time visit (lag = 1 epoch → regime 1) drains the carry on
    // top of the base epoch grant.
    let t2 = t1 + EPOCH_DURATION_NS;
    let _ = lease.acquire_v8(0, t2, u64::MAX);
    assert!(
        published_cap(&lease) > CAP_PER_EPOCH_100M,
        "next visit drains banked carry on top of base epoch grant"
    );
    assert!(
        published_carry(&lease) < banked,
        "carry reservoir shrinks as it drains"
    );
}

#[test]
fn v8_carry_burst_bound_holds_after_two_second_stall() {
    // Gate 5 (burst bound) — the invariant the old clamp protected. A
    // worker stalled 2 s then resumed must NOT receive a `rate × 2s`
    // one-shot grant (= 25 MB). lag = 2s ≫ STALL → regime-3 cold-resume
    // → exactly one epoch. This is the burst the unclamped probe risked.
    let lease = carry_test_lease();
    let t0 = EPOCH_DURATION_NS;
    let _ = lease.acquire_v8(0, t0, u64::MAX);
    let two_seconds = 2_000_000_000u64;
    let _ = lease.acquire_v8(0, t0 + two_seconds, u64::MAX);
    assert_eq!(
        published_cap(&lease),
        CAP_PER_EPOCH_100M,
        "2 s stall cold-resumes to ONE epoch, not rate × 2 s"
    );
    // Sanity: rate × 2 s would have been 25 MB — assert we are far below.
    assert!(
        published_cap(&lease) < RATE_100M * 2,
        "cap must be nowhere near the unbounded rate × stall grant"
    );
}

#[test]
fn v8_carry_per_rotation_grant_never_exceeds_k_epoch_ceiling() {
    // Stronger burst bound: across ANY single rotation, including one
    // that drains a full reservoir in regime 1, the published cap is
    // bounded by `(2K − 1) × rate × EPOCH`. Drive the worst case: bank a
    // full reservoir (regime 2 with a huge-but-below-STALL lag), then a
    // single on-time visit that drains the reservoir.
    let lease = carry_test_lease();
    let t0 = EPOCH_DURATION_NS;
    let _ = lease.acquire_v8(0, t0, u64::MAX);
    // Lag below STALL but large enough to fill the reservoir to its cap.
    let lag = STALL_THRESHOLD_EPOCHS - 1;
    let t1 = t0 + lag * EPOCH_DURATION_NS;
    let _ = lease.acquire_v8(0, t1, u64::MAX);
    // Reservoir is clamped at CARRY_MAX_EPOCHS × rate × EPOCH.
    assert_eq!(
        published_carry(&lease),
        CARRY_MAX_EPOCHS * CAP_PER_EPOCH_100M,
        "reservoir clamps at CARRY_MAX_EPOCHS even for a near-STALL lag"
    );
    // WORST-CASE regime-1 drain: a lag of EXACTLY K×EPOCH is the largest
    // raw lag that still selects regime 1 (regime 2 is `raw > K×EPOCH`), so
    // base = K epochs AND the full reservoir drain adds (K−1) epochs — the
    // tight `(2K−1)×rate×EPOCH` per-rotation maximum.
    let t2 = t1 + MAX_ROTATION_LAG_EPOCHS * EPOCH_DURATION_NS;
    let _ = lease.acquire_v8(0, t2, u64::MAX);
    let ceiling = (MAX_ROTATION_LAG_EPOCHS + CARRY_DRAIN_MAX_EPOCHS) * CAP_PER_EPOCH_100M;
    assert_eq!(
        published_cap(&lease),
        ceiling,
        "worst-case regime-1 grant equals exactly the (2K−1)-epoch ceiling"
    );
    assert!(
        published_cap(&lease) <= ceiling,
        "single-rotation grant {} must not exceed (2K−1) ceiling {}",
        published_cap(&lease),
        ceiling
    );
}

#[test]
fn v8_carry_regime_boundaries_use_exact_nanoseconds_not_floored_epochs() {
    // Codex r1 Major/Medium: regime selection must compare EXACT wall-clock
    // nanoseconds, not a floored epoch count. A floored `lag = raw/EPOCH`
    // would (a) admit a regime-1 lag up to `(K+1)×EPOCH − 1ns` (breaching
    // the per-rotation burst bound by one epoch), and (b) skip regime-3
    // cold-resume for a raw lag of `STALL×EPOCH + 1ns` (floors to STALL),
    // banking instead of dropping stale carry across an HA gap.
    //
    // (a) K-window upper edge: raw lag = (K+1)×EPOCH − 1ns must be REGIME 2
    // (grants exactly the K-epoch ceiling), NOT regime 1 with a near-(K+1)
    // base grant.
    {
        let lease = carry_test_lease();
        let t0 = EPOCH_DURATION_NS;
        let _ = lease.acquire_v8(0, t0, u64::MAX);
        let raw = (MAX_ROTATION_LAG_EPOCHS + 1) * EPOCH_DURATION_NS - 1;
        let _ = lease.acquire_v8(0, t0 + raw, u64::MAX);
        assert_eq!(
            published_cap(&lease),
            MAX_ROTATION_LAG_EPOCHS * CAP_PER_EPOCH_100M,
            "raw lag just under (K+1) epochs is regime 2 (K-epoch ceiling), not a near-(K+1) regime-1 grant"
        );
    }
    // (b) STALL upper edge: raw lag = STALL×EPOCH + 1ns must be REGIME 3
    // (cold-resume, drop carry), NOT regime 2 (bank).
    {
        let lease = carry_test_lease();
        let t0 = EPOCH_DURATION_NS;
        let _ = lease.acquire_v8(0, t0, u64::MAX);
        // First bank a residual so there is carry to (not) preserve.
        let t1 = t0 + (MAX_ROTATION_LAG_EPOCHS + 3) * EPOCH_DURATION_NS;
        let _ = lease.acquire_v8(0, t1, u64::MAX);
        assert!(published_carry(&lease) > 0, "carry banked");
        let raw = STALL_THRESHOLD_EPOCHS * EPOCH_DURATION_NS + 1;
        let _ = lease.acquire_v8(0, t1 + raw, u64::MAX);
        assert_eq!(
            published_cap(&lease),
            CAP_PER_EPOCH_100M,
            "raw lag just over STALL is regime-3 cold-resume (one epoch)"
        );
        assert_eq!(
            published_carry(&lease),
            0,
            "regime-3 at the exact STALL+1ns boundary drops stale carry"
        );
    }
    // Lower edge of regime 3 / upper edge of regime 2: raw lag = exactly
    // STALL×EPOCH must still be REGIME 2 (banks), proving the `>` is strict.
    {
        let lease = carry_test_lease();
        let t0 = EPOCH_DURATION_NS;
        let _ = lease.acquire_v8(0, t0, u64::MAX);
        let raw = STALL_THRESHOLD_EPOCHS * EPOCH_DURATION_NS;
        let _ = lease.acquire_v8(0, t0 + raw, u64::MAX);
        assert_eq!(
            published_cap(&lease),
            MAX_ROTATION_LAG_EPOCHS * CAP_PER_EPOCH_100M,
            "raw lag of exactly STALL epochs is still regime 2 (banks), not regime 3"
        );
        assert!(
            published_carry(&lease) > 0,
            "exactly-STALL lag banks the residual (not a cold-resume drop)"
        );
    }
}

#[test]
fn v8_carry_cold_resume_drops_stale_carry_for_ha_failback() {
    // Gate 6 (HA): leases are REUSED across an HA demote→promote when the
    // config matches, so `epoch_start` survives. A long demotion gap on a
    // reused lease must NOT replay a banked deficit or a multi-epoch
    // burst. Bank a residual, then simulate a >STALL failback gap and
    // assert the next grant is a single epoch with the stale carry dropped.
    let lease = carry_test_lease();
    let t0 = EPOCH_DURATION_NS;
    let _ = lease.acquire_v8(0, t0, u64::MAX);
    // Bank a residual via a regime-2 lag.
    let t1 = t0 + (MAX_ROTATION_LAG_EPOCHS + 3) * EPOCH_DURATION_NS;
    let _ = lease.acquire_v8(0, t1, u64::MAX);
    assert!(published_carry(&lease) > 0, "carry banked before failback");
    // Demotion gap well beyond STALL (failback ≥ 500 epochs).
    let t2 = t1 + (STALL_THRESHOLD_EPOCHS + 1000) * EPOCH_DURATION_NS;
    let _ = lease.acquire_v8(0, t2, u64::MAX);
    assert_eq!(
        published_cap(&lease),
        CAP_PER_EPOCH_100M,
        "post-failback first grant on a REUSED lease is one epoch (no K-epoch burst)"
    );
    assert_eq!(
        published_carry(&lease),
        0,
        "cold-resume drops the stale carry so it cannot replay across the gap"
    );
}
// === #15100 (A70-02): self-scheduled park lag vs the bounded carry ===
//
// A backlogged exact queue parks for its own refill time: the wakeup
// estimator parks it until a full frame refills at its configured rate,
// so a low-rate class's next visit lag is frame-scale, not epoch-scale
// (1500 B at 8000 B/s = 187.5 ms; at 1 Mbps = 12 ms). The fixed
// K x EPOCH (1.6 ms) / STALL (51.2 ms) windows cannot see that as a
// legitimate visit gap: the lag is either credited only 1.6 ms with the
// residual banked (and the bank is then dropped at the following
// 187.5 ms revisit, which is beyond STALL), or cold-resumed to one
// epoch with the credit dropped. The class is blackholed or held far
// below its configured rate despite being continuously backlogged.

#[test]
fn v8_self_park_lag_grants_full_frame_15100() {
    // THE #15100 acceptance cell: lease at 8000 B/s (64 kbps),
    // acquiring at t0 and again at t0 + 187.5 ms (the self-park
    // interval for one 1500 B frame) grants at least 1499 B.
    let lease = SharedCoSQueueLease::new_v8(8_000, 64 * 1024, 1, 0);
    lease.rehydrate_worker_active_count(0, 1);
    let t0 = EPOCH_DURATION_NS;
    let _ = lease.acquire_v8(0, t0, u64::MAX);
    let park_ns = 187_500_000u64; // 1500 B at 8000 B/s
    let g = lease.acquire_v8(0, t0 + park_ns, 1500);
    assert!(
        g >= 1499,
        "self-park lag of 187.5 ms at 8000 B/s must grant >= 1499 B, got {g}"
    );
}

#[test]
fn v8_configured_frame_park_scales_stall_window_15100() {
    // At lease creation for an 8000 B/s class the stall window covers
    // at least the self-park for one 1500 B frame (187.5 ms), so the
    // queue's own park is not classified as a worker stall / HA gap.
    assert!(
        stall_window_ns_for_rate(8_000) >= 187_500_000,
        "8000 B/s stall window {} ns must cover the 187.5 ms frame park",
        stall_window_ns_for_rate(8_000)
    );
    // High-rate control: the fixed 51.2 ms floor still dominates.
    assert_eq!(
        stall_window_ns_for_rate(RATE_100M),
        EPOCH_DURATION_NS * STALL_THRESHOLD_EPOCHS,
        "100 Mbps stall window stays at the fixed floor"
    );
    // Zero-rate (transparent) leases keep the fixed floor.
    assert_eq!(
        stall_window_ns_for_rate(0),
        EPOCH_DURATION_NS * STALL_THRESHOLD_EPOCHS
    );
}

#[test]
fn v8_stall_burst_bound_still_holds_15100() {
    // Control: a genuine stall far beyond even the rate-relative
    // window still cold-resumes to exactly one epoch and drops carry.
    let lease = carry_test_lease();
    let t0 = EPOCH_DURATION_NS;
    let _ = lease.acquire_v8(0, t0, u64::MAX);
    let t1 = t0 + (MAX_ROTATION_LAG_EPOCHS + 3) * EPOCH_DURATION_NS;
    let _ = lease.acquire_v8(0, t1, u64::MAX);
    assert!(published_carry(&lease) > 0, "carry banked before stall");
    let t2 = t1 + 2_000_000_000u64; // 2 s stall
    let _ = lease.acquire_v8(0, t2, u64::MAX);
    assert_eq!(
        published_cap(&lease),
        CAP_PER_EPOCH_100M,
        "2 s stall still cold-resumes to one epoch"
    );
    assert_eq!(published_carry(&lease), 0, "stall still drops stale carry");
}

#[test]
fn v8_sustained_self_park_delivery_15100() {
    // Sustained backlogged delivery under the self-park cadence: at
    // 1 Mbps (125000 B/s) a full 4096 B frame refills every 32.768 ms.
    // Over 44 such parks (~1.44 s) the class must deliver >= 95% of
    // the rate-implied bytes (consuming each grant so the
    // outstanding-credit cap does not bind).
    let lease = SharedCoSQueueLease::new_v8(125_000, 256 * 1024, 1, 0);
    lease.rehydrate_worker_active_count(0, 1);
    let t0 = EPOCH_DURATION_NS;
    let _ = lease.acquire_v8(0, t0, u64::MAX);
    let park_ns = 32_768_000u64; // 4096 B at 125000 B/s
    let mut total = 0u64;
    for i in 1..=44u64 {
        let g = lease.acquire_v8(0, t0 + i * park_ns, 4096);
        lease.consume(g);
        total += g;
    }
    let expected = 125_000u64 * 144 / 100; // 180000 B over ~1.44 s
    assert!(
        total * 100 >= expected * 95,
        "self-parked 1 Mbps class delivered {total} B, expected >= 95% of {expected} B"
    );
}

#[test]
fn v8_carry_field_is_reader_private() {
    // Gate 5b (carry-reader-private guard). `epoch_carry_bytes` must be
    // written/read ONLY by the rotation winner inside the seqlock ODD
    // section. If it ever leaks into the acquire/snapshot reader path or
    // the coordinator status path it re-introduces the #1619 seqlock
    // tearing class for the carry. Grep the crate source: the only
    // references allowed are the field definition + its initializer in
    // epoch.rs, the rotation read/write in rotate_epoch_v8.rs, and this
    // test file. Any reference in acquire_v8 / snapshot_epoch_v8 /
    // coordinator/status.rs is a regression.
    //
    // #2158 (P2): the `SharedCoSEpochState` definition (and thus the
    // `epoch_carry_bytes` field decl + initializer + doc) moved from the
    // lease `mod.rs` into the `epoch.rs` submodule during the file-split;
    // the allowlist entry tracks that move. The rotation-private
    // invariant is unchanged — the only READER/WRITER is still the
    // rotation winner in `rotate_epoch_v8.rs`.
    use std::path::Path;
    let crate_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    let allowed = [
        // field def + initializer + doc live in the epoch submodule
        "afxdp/types/shared_cos_lease/epoch.rs",
        // the single legitimate writer/reader: the rotation winner
        "afxdp/types/shared_cos_lease/rotate_epoch_v8.rs",
        // this test file
        "afxdp/types/shared_cos_lease/shared_cos_lease_tests.rs",
    ];
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(&crate_src, &mut files);
    for f in files {
        let rel = f.strip_prefix(&crate_src).unwrap().to_string_lossy().replace('\\', "/");
        if allowed.iter().any(|a| rel == *a) {
            continue;
        }
        let body = std::fs::read_to_string(&f).unwrap();
        if body.contains("epoch_carry_bytes") {
            offenders.push(rel);
        }
    }
    assert!(
        offenders.is_empty(),
        "epoch_carry_bytes is rotation-private; unexpected references in: {:?}",
        offenders
    );
}

// #1863 Step-0: per-worker cumulative claim-flow counters
// (requested/granted). The attribution contract: requested counts
// EVERY ask with requested > 0 (granted or not); granted counts the
// call's total_granted; neither resets at rotation; legacy leases
// report None.

#[test]
fn v8_claim_flow_counts_requested_and_granted() {
    let lease = SharedCoSQueueLease::new_v8(12_500_000, 64 * 1024, 1, 1);
    lease.rehydrate_worker_active_count(0, 1);
    let (granted, _) = lease.acquire_v8_with_cause(0, EPOCH_DURATION_NS, 100);
    assert_eq!(granted, 100);
    let (requested, granted_flow) = lease
        .v8_worker_claim_flow()
        .expect("v8 lease must report claim flow");
    assert_eq!(requested.len(), 2, "len = max_worker_id + 1");
    assert_eq!(requested[0], 100, "worker 0 asked 100 bytes");
    assert_eq!(granted_flow[0], 100, "worker 0 was granted 100 bytes");
    assert_eq!(requested[1], 0, "worker 1 never asked");
    assert_eq!(granted_flow[1], 0);
}

#[test]
fn v8_claim_flow_counts_denied_asks() {
    // No rehydration → zero active flows → my_fair_share 0 → 0 grant,
    // but the ASK must still be counted (the sampling-loss
    // discriminator needs "did this worker ask at all").
    let lease = SharedCoSQueueLease::new_v8(10_000_000, 64 * 1024, 2, 1);
    let granted = lease.acquire_v8(0, 1_000_000, 4_096);
    assert_eq!(granted, 0);
    let (requested, granted_flow) = lease.v8_worker_claim_flow().expect("v8 lease");
    assert_eq!(requested[0], 4_096, "denied ask still counted");
    assert_eq!(granted_flow[0], 0, "nothing granted");
}

#[test]
fn v8_claim_flow_accumulates_across_rotations() {
    let lease = SharedCoSQueueLease::new_v8(12_500_000, 64 * 1024, 1, 0);
    lease.rehydrate_worker_active_count(0, 1);
    let (g1, _) = lease.acquire_v8_with_cause(0, EPOCH_DURATION_NS, 100);
    // Second acquire two epochs later forces a rotation in between;
    // the cumulative counters must NOT reset.
    let (g2, _) = lease.acquire_v8_with_cause(0, 3 * EPOCH_DURATION_NS, 100);
    assert_eq!((g1, g2), (100, 100));
    let (requested, granted_flow) = lease.v8_worker_claim_flow().expect("v8 lease");
    assert_eq!(requested[0], 200, "asks accumulate across rotations");
    assert_eq!(granted_flow[0], 200, "grants accumulate across rotations");
}

#[test]
fn legacy_lease_reports_no_claim_flow() {
    let lease = SharedCoSQueueLease::new(10_000_000, 64 * 1024, 2);
    assert!(lease.v8_worker_claim_flow().is_none());
}

// #1863 Path A-ii: class-level unclaimed-budget carry at rotation.
// Contract: an epoch's unclaimed class budget (prev_cap − prev_granted)
// is banked into `epoch_carry_bytes` and drawn into the next rotation's
// cap (flow-proportionally re-dealt by the share formula); a fully
// claimed epoch banks nothing (byte-identical steady state); regime-3
// cold-resume still drops carry; all existing bounds hold.

// 12.5 MB/s → exactly 2,500 B per 200 µs epoch.
const CARRY_TEST_RATE: u64 = 12_500_000;

#[test]
fn v8_unclaimed_budget_carries_into_next_epoch_cap() {
    let lease = SharedCoSQueueLease::new_v8(CARRY_TEST_RATE, 64 * 1024, 2, 0);
    lease.rehydrate_worker_active_count(0, 1);
    // First rotation (start==0, regime 3): cap = one epoch = 2,500.
    // Claim only 500 of it.
    let (g1, _) = lease.acquire_v8_with_cause(0, EPOCH_DURATION_NS, 500);
    assert_eq!(g1, 500);
    // One epoch later: rotation banks the 2,000 unclaimed and draws it
    // back — cap = base 2,500 + carry 2,000 = 4,500, all on worker 0's
    // share (sole flow).
    let (g2, _) = lease.acquire_v8_with_cause(0, 2 * EPOCH_DURATION_NS, 10_000);
    assert_eq!(
        g2, 4_500,
        "unclaimed prior-epoch budget must be re-dealt, not evaporate"
    );
}

#[test]
fn v8_fully_claimed_epoch_banks_no_carry() {
    let lease = SharedCoSQueueLease::new_v8(CARRY_TEST_RATE, 64 * 1024, 2, 0);
    lease.rehydrate_worker_active_count(0, 1);
    let (g1, _) = lease.acquire_v8_with_cause(0, EPOCH_DURATION_NS, 10_000);
    assert_eq!(g1, 2_500, "full claim of the one-epoch cap");
    // Healthy steady state: next epoch's cap is exactly the base —
    // byte-identical to the pre-#1863 rotation.
    let (g2, _) = lease.acquire_v8_with_cause(0, 2 * EPOCH_DURATION_NS, 10_000);
    assert_eq!(g2, 2_500, "fully-claimed epoch must bank nothing");
}

#[test]
fn v8_cold_resume_drops_unclaimed_carry() {
    let lease = SharedCoSQueueLease::new_v8(CARRY_TEST_RATE, 64 * 1024, 2, 0);
    lease.rehydrate_worker_active_count(0, 1);
    let (g1, _) = lease.acquire_v8_with_cause(0, EPOCH_DURATION_NS, 500);
    assert_eq!(g1, 500);
    // Resume past the stall window (256 epochs): regime 3 grants one
    // epoch and DROPS the banked remainder.
    let stall_ns = EPOCH_DURATION_NS * 300;
    let (g2, _) = lease.acquire_v8_with_cause(0, EPOCH_DURATION_NS + stall_ns, 10_000);
    assert_eq!(g2, 2_500, "cold-resume must not burst stale unclaimed budget");
}

#[test]
fn v8_unclaimed_carry_bounded_by_carry_max() {
    let lease = SharedCoSQueueLease::new_v8(CARRY_TEST_RATE, 64 * 1024, 2, 0);
    lease.rehydrate_worker_active_count(0, 1);
    // 20 consecutive epochs claiming 1 byte each: unclaimed ~2,499/epoch
    // accumulates but the bank is clamped at CARRY_MAX_EPOCHS (8) worth
    // and each draw at CARRY_DRAIN_MAX_EPOCHS (7) worth.
    for i in 1..=20u64 {
        let _ = lease.acquire_v8_with_cause(0, i * EPOCH_DURATION_NS, 1);
    }
    let (g, _) = lease.acquire_v8_with_cause(0, 21 * EPOCH_DURATION_NS, 1_000_000);
    let base = 2_500u64;
    let drain_max = 7 * 2_500u64;
    assert!(
        g <= base + drain_max,
        "carry draw must stay within the existing (base + drain_max) bound; got {g}"
    );
    assert!(g > base, "some banked budget must be drawn; got {g}");
}

#[test]
fn v8_equal_flow_mode_never_banks_unclaimed_budget() {
    // EqualFlowSuppress leases keep pre-#1863 evaporation semantics:
    // an under-claimed (fail-open) epoch must NOT inflate the next cap.
    let lease = new_equal_flow_lease_with_policy(EqualFlowTargetPolicy::Slowest);
    lease.rehydrate_worker_active_count(0, 1);
    let g1 = lease.acquire_v8(0, EPOCH_DURATION_NS, 500);
    assert_eq!(g1, 500, "fail-open epoch grants proportionally");
    // 50 MB/s -> 10,000 B/epoch. Without banking, the next epoch's cap
    // is exactly the one-epoch base; with banking it would be 19,500.
    let g2 = lease.acquire_v8(0, 2 * EPOCH_DURATION_NS, 50_000);
    assert_eq!(
        g2, 10_000,
        "equal-flow mode must not recycle unclaimed budget"
    );
}

#[test]
fn v8_unclaimed_carry_redeals_flow_proportionally_across_workers() {
    // Two workers, one flow each (5,000 B/epoch share at 50 MB/s →
    // 10,000 B/epoch cap). Worker 1 misses epoch 1 entirely (sampling
    // loss); its unclaimed share banks. Epoch 2's cap = 10,000 + 5,000
    // and the share formula re-deals it 50/50 — BOTH workers' epoch-2
    // shares are 7,500, preserving flow-proportional isolation (the
    // carried budget is not first-come-first-served).
    let lease = SharedCoSQueueLease::new_v8(50_000_000, 256 * 1024, 2, 1);
    lease.rehydrate_worker_active_count(0, 1);
    lease.rehydrate_worker_active_count(1, 1);
    let g0_e1 = lease.acquire_v8(0, EPOCH_DURATION_NS, 50_000);
    assert_eq!(g0_e1, 5_000, "epoch 1: worker 0 claims exactly its share");
    // Worker 1 never acquires in epoch 1. Epoch 2:
    let g0_e2 = lease.acquire_v8(0, 2 * EPOCH_DURATION_NS, 50_000);
    let g1_e2 = lease.acquire_v8(1, 2 * EPOCH_DURATION_NS, 50_000);
    assert_eq!(
        (g0_e2, g1_e2),
        (7_500, 7_500),
        "epoch 2 re-deals the banked 5,000 flow-proportionally"
    );
}

#[test]
fn v8_regime2_banks_lag_owed_plus_unclaimed_and_draws_nothing() {
    // Regime 2 (K < lag <= STALL): grant exactly the K-epoch ceiling,
    // draw 0, bank rate x (lag - K x EPOCH) PLUS the just-ended
    // epoch's unclaimed remainder.
    let lease = SharedCoSQueueLease::new_v8(CARRY_TEST_RATE, 64 * 1024, 2, 0);
    lease.rehydrate_worker_active_count(0, 1);
    // First rotation (regime 3): cap 2,500; claim 500 -> 2,000 unclaimed.
    let (g1, _) = lease.acquire_v8_with_cause(0, EPOCH_DURATION_NS, 500);
    assert_eq!(g1, 500);
    // Next acquire 10 epochs later: lag 10 > K=8 -> regime 2.
    // cap = 8 x 2,500 = 20,000 (draw 0); carry banks the 2-epoch
    // overshoot (5,000) + unclaimed 2,000 = 7,000.
    let (g2, _) = lease.acquire_v8_with_cause(0, 11 * EPOCH_DURATION_NS, 50_000);
    assert_eq!(g2, 20_000, "regime 2 grants the K-epoch ceiling, no draw");
    // One epoch later (regime 1, fully-claimed prior epoch): cap =
    // base 2,500 + draw min(7,000, drain_max 17,500) = 9,500.
    let (g3, _) = lease.acquire_v8_with_cause(0, 12 * EPOCH_DURATION_NS, 50_000);
    assert_eq!(
        g3, 9_500,
        "the banked lag-owed + unclaimed budget drains on the next visit"
    );
}

#[test]
fn v8_concurrent_acquires_and_rotations_respect_the_budget_bound() {
    // 4 worker threads hammer acquire_v8 with monotonically advancing
    // per-thread clocks spanning ~100 epochs, racing rotations against
    // grants. Invariant under ANY interleaving: total granted bytes
    // never exceed rate x span + the bounded carry/burst slack
    // (carry_max = 8 epochs, plus the K-epoch first-window grant).
    use std::sync::Arc as StdArc;
    let lease = StdArc::new(SharedCoSQueueLease::new_v8(CARRY_TEST_RATE, 64 * 1024, 4, 3));
    for w in 0..4 {
        lease.rehydrate_worker_active_count(w, 1);
    }
    const STEPS: u64 = 400;
    let total: StdArc<std::sync::atomic::AtomicU64> =
        StdArc::new(std::sync::atomic::AtomicU64::new(0));
    let mut handles = Vec::new();
    for w in 0..4usize {
        let lease = StdArc::clone(&lease);
        let total = StdArc::clone(&total);
        handles.push(std::thread::spawn(move || {
            for i in 1..=STEPS {
                // Interleaved per-thread clocks: ~4 acquires per epoch
                // across the threads, with skew.
                let now = i * (EPOCH_DURATION_NS / 4) + (w as u64) * 17_000;
                let g = lease.acquire_v8(w, now, 4_096);
                total.fetch_add(g, std::sync::atomic::Ordering::Relaxed);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // Span ~= STEPS/4 epochs = 100 epochs -> rate budget 250,000 B.
    // Slack: carry_max (8 epochs = 20,000) + the K-epoch ceiling on
    // any single rotation (covered by carry_max accounting) + one
    // epoch of pre-span grant.
    let span_epochs = STEPS / 4 + 1;
    let bound = (span_epochs + 8 + 1) * 2_500;
    let granted = total.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        granted <= bound,
        "concurrent grants {granted} exceed the hard budget bound {bound}"
    );
    assert!(granted > 0, "some grants must land");
}

// === #4246 (T-1, folds R-5(a)): v8 lease give-back re-credits the epoch
// ledger. Before the fix `release_unused` touched only `state.credits`,
// leaving `packed_granted`/`worker_grants` charged for returned bytes. ===

/// Read the v8 epoch ledger for a worker: (class_granted, worker_grant).
fn v8_ledger(lease: &SharedCoSQueueLease, worker_id: usize) -> (u32, u32) {
    let v8 = lease.v8.as_ref().expect("v8 lease");
    let (_c_tag, class_granted) =
        PackedEpochGrant::unpack(v8.epoch.packed_granted.0.load(Ordering::Acquire));
    let (_w_tag, worker_grant) =
        PackedEpochGrant::unpack(v8.worker_grants[worker_id].0.load(Ordering::Acquire));
    (class_granted, worker_grant)
}

#[test]
fn v8_release_unused_v8_recredits_epoch_ledger() {
    // 100 Mbps = 12.5 MB/s, EPOCH = 200µs -> cap = 2500 B. Large burst so
    // the outstanding cap does not bind before the class cap.
    let lease = SharedCoSQueueLease::new_v8(12_500_000, 256 * 1024, 1, 0);
    lease.rehydrate_worker_active_count(0, 1);
    let granted = lease.acquire_v8(0, EPOCH_DURATION_NS, 100_000);
    assert!(
        granted >= 2,
        "acquire must grant a divisible amount (got {granted})"
    );
    let (class_before, worker_before) = v8_ledger(&lease, 0);
    assert_eq!(class_before as u64, granted, "class ledger charged the grant");
    assert_eq!(
        worker_before as u64, granted,
        "worker ledger charged the grant"
    );

    // Queue drained early: return half the grant.
    let released = granted / 2;
    lease.release_unused_v8(0, released);

    let (class_after, worker_after) = v8_ledger(&lease, 0);
    // RED before the fix: release_unused touched only state.credits, so
    // both ledgers stayed == granted and the class stayed at ClassCap.
    assert_eq!(
        class_after as u64,
        granted - released,
        "class ledger must be re-credited on give-back"
    );
    assert_eq!(
        worker_after as u64,
        granted - released,
        "worker ledger must be re-credited on give-back"
    );
    assert_eq!(
        lease.v8_release_recredited_bytes(),
        released,
        "recredit counter tracks the returned bytes"
    );
}

#[test]
fn v8_release_unused_v8_reopens_classcap_same_epoch() {
    // The T-1 scenario: a mid-rate exact class drains the whole epoch cap,
    // empties, and returns part of the grant. Before the fix the class
    // ledger stayed at cap, so same-epoch re-arrivals broke ClassCap and
    // parked until the next rotation (~94% service). After the fix the
    // returned bytes re-open the class within the same epoch.
    let lease = SharedCoSQueueLease::new_v8(12_500_000, 256 * 1024, 1, 0);
    lease.rehydrate_worker_active_count(0, 1);
    let now = EPOCH_DURATION_NS;

    // Claim the whole class cap in one shot.
    let g1 = lease.acquire_v8(0, now, 100_000);
    assert!(g1 > 0);
    // A further same-epoch acquire must be refused (ClassCap / share).
    let g2 = lease.acquire_v8(0, now, 4_096);
    assert_eq!(g2, 0, "class is at cap; further same-epoch grant refused");

    // Queue drains early and returns part of the grant.
    let released = g1 / 2;
    assert!(released > 0);
    lease.release_unused_v8(0, released);

    // Same epoch, same clock: the returned budget must be re-grantable.
    let g3 = lease.acquire_v8(0, now, 100_000);
    assert!(
        g3 > 0,
        "returned budget must re-open the class within the epoch \
         (RED before fix: parked at ClassCap, g3 == 0)"
    );
    assert!(
        g3 <= released,
        "re-grant bounded by the returned budget (got {g3}, released {released})"
    );
}

#[test]
fn v8_release_unused_v8_cross_epoch_is_noop() {
    // A give-back that arrives after rotation reset this worker's grant
    // slot must not decrement the NEW epoch's ledger. Worker 1 triggers the
    // rotation; worker 0 (which does not re-acquire) then issues a stale
    // release of its epoch-N grant. Guards the cap/tag check — a naive
    // decrement of `packed_granted` by `bytes` would underflow worker 0's
    // now-zero slot and corrupt the new epoch's class total.
    let lease = SharedCoSQueueLease::new_v8(12_500_000, 256 * 1024, 2, 1);
    lease.rehydrate_worker_active_count(0, 1);
    lease.rehydrate_worker_active_count(1, 1);

    // Epoch N: worker 0 grabs its share.
    let g0 = lease.acquire_v8(0, EPOCH_DURATION_NS, 100_000);
    assert!(g0 > 0);

    // Rotate to epoch N+1 via worker 1 (worker 0 stays quiet).
    let g1 = lease.acquire_v8(1, 5 * EPOCH_DURATION_NS, 100_000);
    assert!(g1 > 0);
    let (class_before, worker0_before) = v8_ledger(&lease, 0);
    let (_, worker1_before) = v8_ledger(&lease, 1);
    assert_eq!(worker0_before, 0, "rotation reset worker 0's grant slot");

    // Stale release of worker 0's epoch-N grant.
    lease.release_unused_v8(0, g0);

    let (class_after, worker0_after) = v8_ledger(&lease, 0);
    let (_, worker1_after) = v8_ledger(&lease, 1);
    assert_eq!(
        class_after, class_before,
        "class ledger unchanged (cross-epoch give-back is a no-op)"
    );
    assert_eq!(worker0_after, 0, "worker 0 slot stays zero (no underflow)");
    assert_eq!(worker1_after, worker1_before, "worker 1 slot untouched");
    assert_eq!(
        lease.v8_release_recredited_bytes(),
        0,
        "cross-epoch give-back re-credits nothing"
    );
}

#[test]
fn v8_release_unused_v8_caps_at_worker_grant_preserving_class_total() {
    // Over-release (more bytes than this worker was granted this epoch —
    // e.g. banked burst from a prior epoch) must decrement the class total
    // by AT MOST this worker's grant, never below the sum of the OTHER
    // workers' grants (which would be over-admission). Guards the
    // `bytes.min(consumed)` cap that keeps sum(worker_grants) ==
    // packed_granted intact.
    let lease = SharedCoSQueueLease::new_v8(12_500_000, 256 * 1024, 2, 1);
    lease.rehydrate_worker_active_count(0, 1);
    lease.rehydrate_worker_active_count(1, 1);
    let now = EPOCH_DURATION_NS;

    let g0 = lease.acquire_v8(0, now, 100_000);
    let g1 = lease.acquire_v8(1, now, 100_000);
    assert!(g0 > 0 && g1 > 0);
    let (class_before, worker0_before) = v8_ledger(&lease, 0);
    assert_eq!(class_before as u64, g0 + g1, "class total = sum of grants");
    assert_eq!(worker0_before as u64, g0);

    // Release far more than worker 0 was granted this epoch.
    lease.release_unused_v8(0, g0 + 50_000);

    let (class_after, worker0_after) = v8_ledger(&lease, 0);
    let (_, worker1_after) = v8_ledger(&lease, 1);
    assert_eq!(
        worker0_after, 0,
        "worker 0 grant capped to zero, not underflowed"
    );
    assert_eq!(worker1_after as u64, g1, "worker 1 grant untouched");
    assert_eq!(
        class_after as u64, g1,
        "class total decremented by at most worker 0's grant (never below worker 1's)"
    );
    assert_eq!(
        lease.v8_release_recredited_bytes(),
        g0,
        "recredit capped at worker 0's current-epoch grant"
    );
}

#[test]
fn v8_release_unused_v8_counter_excludes_step3_noop() {
    // The #1630 diagnostic counter must count ONLY bytes actually
    // re-credited to packed_granted. If step 3 (the class-ledger decrement)
    // no-ops because a rotation swapped the class tag between the
    // worker-slot claim (step 2) and step 3, release_recredited_bytes must
    // NOT increment. RED before the conditional-increment fix: the counter
    // over-reported by `credit`.
    let lease = SharedCoSQueueLease::new_v8(12_500_000, 256 * 1024, 1, 0);
    lease.rehydrate_worker_active_count(0, 1);
    let g = lease.acquire_v8(0, EPOCH_DURATION_NS, 100_000);
    assert!(g > 0);

    // Simulate the rotation window: advance packed_granted's tag WITHOUT
    // touching worker_grants[0] (rotation swaps packed_granted first — at
    // rotate_epoch_v8 STEP 1 — before the per-worker slots at STEP 3).
    let worker_grant = {
        let v8 = lease.v8.as_ref().unwrap();
        let (t, wg) = PackedEpochGrant::unpack(v8.worker_grants[0].0.load(Ordering::Acquire));
        v8.epoch.packed_granted.0.store(
            PackedEpochGrant::pack(t.wrapping_add(1), 500),
            Ordering::Release,
        );
        wg
    };
    assert!(worker_grant > 0, "worker slot still carries the grant");

    // Give back: step 2 claims from worker_grants[0] (its own tag matches),
    // step 3 finds packed_granted at a different tag and no-ops.
    lease.release_unused_v8(0, worker_grant as u64);

    let v8 = lease.v8.as_ref().unwrap();
    let (_wt, wg_after) = PackedEpochGrant::unpack(v8.worker_grants[0].0.load(Ordering::Acquire));
    assert_eq!(wg_after, 0, "step 2 claimed the worker-slot credit");
    assert_eq!(
        lease.v8_release_recredited_bytes(),
        0,
        "counter must exclude bytes step 3 did not re-credit (rotation window)"
    );
}

#[test]
fn v8_release_unused_v8_concurrent_preserves_ledger_invariant() {
    // N worker threads hammer acquire+release on their own slots within a
    // single epoch (fixed clock -> no rotation). Under ANY interleaving the
    // class ledger must equal the sum of the per-worker grants at
    // quiescence, stay within [0, cap], and never underflow. An over- or
    // under-decrement in the release CAS would break the invariant.
    use std::sync::Arc as StdArc;
    let lease = StdArc::new(SharedCoSQueueLease::new_v8(12_500_000, 4 * 1024 * 1024, 4, 3));
    for w in 0..4 {
        lease.rehydrate_worker_active_count(w, 1);
    }
    // Publish the epoch once (single-threaded) so all threads share a tag.
    let now = EPOCH_DURATION_NS;
    let _ = lease.acquire_v8(0, now, 1);
    const ROUNDS: u64 = 3_000;
    let mut handles = Vec::new();
    for w in 0..4usize {
        let lease = StdArc::clone(&lease);
        handles.push(std::thread::spawn(move || {
            for _ in 0..ROUNDS {
                let g = lease.acquire_v8(w, now, 512);
                if g > 0 {
                    lease.release_unused_v8(w, g);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let v8 = lease.v8.as_ref().unwrap();
    let (_c_tag, class_granted) =
        PackedEpochGrant::unpack(v8.epoch.packed_granted.0.load(Ordering::Acquire));
    let mut sum: u64 = 0;
    for slot in v8.worker_grants.iter() {
        let (_t, g) = PackedEpochGrant::unpack(slot.0.load(Ordering::Acquire));
        sum += g as u64;
    }
    // sum <= class always (release under-decrement / mid-acquire is the only
    // slack, both keep class >= sum). cap = 12.5MB/s * 200µs = 2500 B.
    assert!(
        sum <= class_granted as u64,
        "class ledger {class_granted} must never drop below sum of grants {sum} (over-admission)"
    );
    assert!(
        class_granted as u64 <= 2_500,
        "class total {class_granted} must never exceed the epoch cap 2500"
    );
    // #7062: a SYSTEMIC-regression backstop, not a contention reading.
    //
    // This was `== 0`: no tag-checked-rollback may exhaust its retries under
    // the contention this test happens to generate. That is a statement about
    // the machine, not about the lease. It red once during a full
    // `--test-threads=1` run while several other build jobs saturated the box,
    // with `left: 1, right: 0` — one exhaustion across 4 threads x 3 000 rounds
    // = 12 000 operations, while the two ledger invariants asserted immediately
    // above (which ARE the properties, and are contention-independent) held.
    //
    // The bound distinguishes the two causes by ORDER OF MAGNITUDE rather than
    // by calibration. Load produces a handful of exhaustions out of 12 000. A
    // regression that made the retry budget structurally too small produces one
    // on a large fraction of them, because every operation would hit the same
    // ceiling. ROUNDS (3 000, a quarter of the operations) sits far above the
    // former and far below the latter, so no amount of CPU contention reaches
    // it and a real regression cannot avoid it.
    //
    // If this ever reds, do NOT raise it. It is not measuring contention, so a
    // higher number cannot make it correct — a value near this bound means
    // rollback is exhausting on a quarter of all operations, which is the
    // condition it exists to catch. The counter's zero-at-rest contract is
    // bound separately and deterministically by
    // v8_telemetry_rollback_metric_starts_zero.
    let exhausted = lease.v8_rollback_retry_exceeded();
    assert!(
        exhausted < ROUNDS,
        "tag-checked-rollback exhausted {exhausted} times across {} operations \
         (4 threads x {ROUNDS} rounds). A handful under host load is expected \
         and harmless — the ledger invariants above are the properties. This \
         many means the retry budget is structurally too small, not that the \
         box was busy: do not raise the bound (#7062)",
        4 * ROUNDS
    );
    assert_eq!(
        sum, class_granted as u64,
        "ledger invariant sum(worker_grants) == packed_granted after concurrent churn"
    );
}

/// #4260 (hb166 R-3) — v8 epoch seqlock writer/reader ordering.
///
/// The rotation winner (`maybe_rotate_epoch_v8`) now issues a
/// `fence(Ordering::Release)` immediately after the EVEN→ODD claim CAS so
/// the Relaxed payload stores are published AFTER the ODD claim becomes
/// visible. That is the writer half of the #1643 reader `fence(Acquire)`;
/// together they close the #1619 cross-epoch tearing window.
///
/// This test drives many concurrent snapshots against a single rotating
/// writer and asserts a CROSS-FIELD invariant that a torn snapshot would
/// violate. All rotations here happen at `now_ns = k*EPOCH`, which
/// publishes `grace = now_ns + EPOCH/2` and `tag = k` from the SAME
/// rotation, so any consistent snapshot MUST satisfy
/// `grace == tag*EPOCH + EPOCH/2`. A reader that paired a fresh `tag`
/// with a stale `grace` (or vice-versa — a torn cross-epoch read) breaks
/// the equality.
///
/// NOTE: x86-TSO does not reorder plain stores, so on the CI host this
/// test cannot deterministically REPRODUCE the tear — it passes with and
/// without the writer fence there. It is a structural ordering-correctness
/// guard plus executable documentation of the invariant: on a weakly-
/// ordered CPU (ARM/POWER), or under a loom model, the missing-fence
/// writer would let this equality fail. The crate carries no loom
/// dependency, so this contention test is the available regression
/// surface for the writer half.
#[test]
fn v8_epoch_seqlock_snapshot_never_tears_tag_grace() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
    use std::sync::Arc;

    const MAX_WORKER_ID: usize = 3;
    // rate_bytes / burst are irrelevant to the tag/grace invariant; any
    // v8 lease rotates on the same schedule.
    let lease = Arc::new(SharedCoSQueueLease::new_v8(
        100_000_000,
        64 * 1024,
        MAX_WORKER_ID + 1,
        MAX_WORKER_ID,
    ));

    const ROTATIONS: u64 = 4_000;
    // The writer's last-rotated now_ns, published for the readers. 0 =
    // "no rotation yet".
    let clock = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    // #6945: reader progress, PUBLISHED so the writer can establish it
    // instead of hoping for it. See the wait below `stop.store(true)`.
    let observed = Arc::new(AtomicU64::new(0));

    // Reader threads: pure snapshots (no rotation) racing the writer's
    // payload publish. Each verifies the tag/grace invariant.
    let mut readers = Vec::new();
    for worker_id in 0..=MAX_WORKER_ID {
        let lease = Arc::clone(&lease);
        let clock = Arc::clone(&clock);
        let stop = Arc::clone(&stop);
        let observed = Arc::clone(&observed);
        readers.push(std::thread::spawn(move || -> u64 {
            let mut checked: u64 = 0;
            while !stop.load(AtomicOrdering::Relaxed) {
                if clock.load(AtomicOrdering::Relaxed) == 0 {
                    std::hint::spin_loop();
                    continue;
                }
                // Pure seqlock read — snapshot_epoch_v8 does NOT rotate.
                if let Some((_cap, _share, grace, tag)) = lease.test_snapshot_epoch_v8(worker_id) {
                    if tag >= 1 {
                        let expected = tag as u64 * EPOCH_DURATION_NS + EPOCH_DURATION_NS / 2;
                        assert_eq!(
                            grace, expected,
                            "torn seqlock snapshot: tag {} paired with grace \
                             {} (expected {}) — writer publish ordering broken",
                            tag, grace, expected,
                        );
                        checked += 1;
                        observed.fetch_add(1, AtomicOrdering::Relaxed);
                    }
                }
            }
            checked
        }));
    }

    // Single writer: the ONLY rotation driver, stepping the clock one
    // epoch per iteration so rotation k lands at now_ns = k*EPOCH with
    // tag == k and grace == k*EPOCH + EPOCH/2.
    for k in 1..=ROTATIONS {
        let now = k * EPOCH_DURATION_NS;
        // acquire_v8 runs maybe_rotate_epoch_v8(now) then the snapshot.
        let _ = lease.acquire_v8(0, now, 1);
        clock.store(now, AtomicOrdering::Relaxed);
    }
    // #6945: WAIT for a reader to validate a snapshot before stopping them.
    //
    // The `total_checked > 0` guard below is a non-vacuity check, not the
    // property under test — the property is the tag/grace equality asserted
    // inside the reader loop. But the guard was HOPED for rather than
    // established: readers spin while `clock == 0`, the writer publishes
    // `clock` only after its first rotation, and all 4 000 rotations are
    // in-memory, so on a contended box the writer could finish and set `stop`
    // before any reader was scheduled past that spin. Every reader then
    // returned 0, `total_checked` was 0, and the guard tripped while the
    // tearing assertion had never been evaluated once.
    //
    // Measured, at master, on a 16-core box: 0/8 full-suite runs reproduced it
    // under ambient load, but confining the test's threads to 2 CPUs
    // (`taskset -c 0,1`) failed 16 of 25 runs — and EVERY failure was this
    // guard, never the tag/grace assertion. Contention starved the readers; it
    // did not tear a snapshot.
    //
    // So this is not a timing bound to relax. Waiting for the signal makes the
    // precondition true by construction, which is the same treatment #6633
    // gave the sibling guard in `install_session_serializes_with_reconcile_
    // removal` ("can no longer trip as a scheduler artifact on a loaded
    // machine"). `yield_now` rather than a spin so the wait cannot itself
    // starve the readers it is waiting on, which on 2 CPUs it otherwise would.
    // BOUNDED, and the bound is a deadlock guard rather than a timing
    // assertion. An unbounded wait would convert a genuine regression -- one
    // where `test_snapshot_epoch_v8` stopped returning snapshots at all -- from
    // a named RED into a HANG, and a suite that times out reports nothing about
    // which assertion failed. If the bound is ever reached the loop simply
    // falls through and the `total_checked > 0` assert below fires with its
    // original message, so the failure mode is preserved exactly. The cap is
    // deliberately enormous relative to the work: readers need one scheduling
    // slot, and the writer has already completed every rotation before this
    // point.
    for _ in 0..50_000_000u64 {
        if observed.load(AtomicOrdering::Relaxed) > 0 {
            break;
        }
        std::thread::yield_now();
    }
    stop.store(true, AtomicOrdering::Relaxed);

    let total_checked: u64 = readers.into_iter().map(|h| h.join().unwrap()).sum();
    assert!(
        total_checked > 0,
        "readers must have validated at least one snapshot (test not vacuous)"
    );

    // Writer completed all rotations: final tag == ROTATIONS.
    let (_c, _s, grace, tag) = lease
        .test_snapshot_epoch_v8(0)
        .expect("final snapshot must succeed with no concurrent writer");
    assert_eq!(tag as u64, ROTATIONS, "writer must reach the final epoch");
    assert_eq!(
        grace,
        ROTATIONS * EPOCH_DURATION_NS + EPOCH_DURATION_NS / 2,
        "final grace must match the final epoch's tag",
    );
}

// ===========================================================================
// #7206 A1-b5-F4 — residual-surplus budget reset vs refill linearizability.
//
// `reset_residual_surplus_budget` publishes `tokens = 0` and `last_refill_ns`
// as two independent stores, and `refill_residual_surplus_budget` claims the
// timestamp CAS and THEN adds tokens in a separate loop. A reset interleaved
// between those two steps left non-zero tokens after a completed reset — a
// resurrected burst, granting surplus the reset had just cancelled.
//
// The fix is a generation bumped by every reset and validated by the refill on
// both sides of its token CAS. The commit step is extracted so the guard is
// reachable without winning a race: a threaded probe that simply fails to hit
// the interleaving returns the same green as a correct implementation, so it
// cannot be the primary evidence.
// ===========================================================================

/// A reset must advance the generation. Everything below rests on this, so it
/// is asserted directly rather than inferred from the behaviour it drives.
#[test]
fn reset_advances_the_residual_generation_7206_f4() {
    let backlog = SharedCoSExactBacklog::new(3);
    let before = backlog.residual_generation_for_test();
    backlog.reset_residual_surplus_budget(1_000);
    let after = backlog.residual_generation_for_test();
    assert_ne!(
        before, after,
        "reset_residual_surplus_budget did not advance the generation, so a refill \
         holding a pre-reset epoch has no way to detect that its `added` is stale"
    );
}

/// The defect cell. A refill sampled its generation, derived `added` from the
/// epoch that was current then, and a reset landed before it could commit.
/// Committing that `added` resurrects the burst the reset cancelled.
#[test]
fn a_refill_whose_epoch_a_reset_ended_adds_nothing_7206_f4() {
    let backlog = SharedCoSExactBacklog::new(3);

    // The refill's view of the world, sampled before the reset.
    let stale_generation = backlog.residual_generation_for_test();

    // A reset lands: budget is empty as of now.
    backlog.reset_residual_surplus_budget(2_000);
    assert_eq!(backlog.residual_tokens_for_test(), 0, "reset must zero the budget");

    // The in-flight refill now tries to commit tokens it derived from the
    // epoch the reset just ended.
    backlog.commit_refill_tokens_for_test(stale_generation, 750_000, 1_000_000);

    assert_eq!(
        backlog.residual_tokens_for_test(),
        0,
        "a refill holding a PRE-reset epoch committed 750000 tokens on top of a completed \
         reset. The reset said the residual-surplus budget is empty as of its own now_ns; \
         this resurrects a burst and grants surplus that was deliberately cancelled."
    );
}

/// The positive control, WITHOUT WHICH the cell above proves nothing: a
/// `commit_refill_tokens` that never added anything — because the guard is
/// inverted, or because `added` is dropped on the floor — would satisfy the
/// "adds nothing" assertion perfectly.
#[test]
fn a_refill_holding_the_current_generation_still_adds_7206_f4() {
    let backlog = SharedCoSExactBacklog::new(3);
    backlog.reset_residual_surplus_budget(2_000);

    let current = backlog.residual_generation_for_test();
    backlog.commit_refill_tokens_for_test(current, 750_000, 1_000_000);

    assert_eq!(
        backlog.residual_tokens_for_test(),
        750_000,
        "a refill whose generation is current must still add its tokens — if it does not, \
         the residual-surplus budget never refills at all and the sibling stale-generation \
         test is measuring nothing"
    );
}

/// The burst bound still clamps a current-generation commit. Guards against a
/// fix that preserves linearizability by widening the ceiling.
#[test]
fn a_current_generation_commit_is_still_clamped_to_burst_7206_f4() {
    let backlog = SharedCoSExactBacklog::new(3);
    let current = backlog.residual_generation_for_test();
    backlog.commit_refill_tokens_for_test(current, u64::MAX, 1_000_000);
    assert_eq!(
        backlog.residual_tokens_for_test(),
        1_000_000,
        "a commit must saturate at residual_burst_bytes"
    );
}

/// Concurrent stress. This is deliberately NOT the primary evidence — it
/// cannot fail informatively, because not hitting the interleaving looks
/// exactly like being correct. It is here to catch a livelock or an unbounded
/// token value under real contention, which the deterministic cells cannot see.
///
/// The invariant it can assert: every reset uses the SAME `now_ns` the refills
/// use, so after a reset no refill can legitimately add (`now_ns <=
/// last_refill_ns` returns early). Tokens must therefore stay within the burst
/// bound throughout, and the final state after a trailing reset must be zero.
#[test]
fn concurrent_reset_and_refill_stay_bounded_7206_f4() {
    use std::sync::atomic::{AtomicBool, Ordering as O};
    use std::sync::Arc;

    const BURST: u64 = 1_000_000;
    const RATE: u64 = 1_000_000_000; // 1 byte/ns, so elapsed maps 1:1

    let backlog = Arc::new(SharedCoSExactBacklog::new(3));
    let stop = Arc::new(AtomicBool::new(false));

    let refiller = {
        let backlog = Arc::clone(&backlog);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut now = 10_000u64;
            while !stop.load(O::Relaxed) {
                now += 1_000;
                let tokens = backlog.residual_surplus_budget(now, RATE, BURST);
                assert!(
                    tokens <= BURST,
                    "residual budget {tokens} exceeded the burst bound {BURST} under contention"
                );
            }
        })
    };

    // Reset from this thread, then signal the refiller to stop. Looping the
    // resetter against a bounded refiller (rather than equal iteration counts)
    // keeps both live for the whole window — equal counts let the cheap loop
    // finish inside the expensive one's first pass and probe nothing.
    for i in 0..20_000u64 {
        backlog.reset_residual_surplus_budget(10_000 + i);
    }
    stop.store(true, O::Relaxed);
    refiller.join().expect("refill thread panicked");

    // A trailing reset is the newest intent; nothing may survive it.
    backlog.reset_residual_surplus_budget(u64::MAX);
    assert_eq!(
        backlog.residual_tokens_for_test(),
        0,
        "tokens survived a completed reset"
    );
}

// === #9117: a worker going idle -> active MID-EPOCH ===
//
// The FOURTH shape, absent from publish_equal_flow_epoch_v8's own three-case
// enumeration. Such a worker has a usable sample, demanded, and was granted —
// everything that makes a case-1 sample-set member — but its share was
// published as 0 at the last rotation because its buckets were empty then. It
// used to trip case 2's UnsampledActiveWorker fail-open, and fail_open resets
// valid_streak and smoothed_target_per_flow, so with
// EQUAL_FLOW_VALID_STREAK_REQUIRED = 2 one activation cost ~3 epochs of
// enforcement ACROSS THE WHOLE CLASS (one lease serves every worker on it).
//
// These two cells are a PAIR and the control is load-bearing: without it,
// "not enforced" is the state at every early epoch, so the subject would pass
// against code that never enforces at all.

/// Three workers, so the newcomer (1) is distinct from the two established
/// ones (0 and 2). new_equal_flow_lease caps max_worker_id at 1.
fn new_equal_flow_lease_3w_9117() -> SharedCoSQueueLease {
    SharedCoSQueueLease::new_v8_with_rate_mode(
        50_000_000,
        256 * 1024,
        8,
        2,
        V8RateMode::EqualFlowSuppress,
    )
}

#[test]
fn control_established_workers_reach_enforcement_9117() {
    let lease = new_equal_flow_lease_3w_9117();
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(2, 1);

    for epoch in 1..=2u64 {
        let _ = lease.acquire_v8(0, epoch * EPOCH_DURATION_NS, 8_000);
        let _ = lease.acquire_v8(2, epoch * EPOCH_DURATION_NS, 1_800);
    }
    let _ = lease.acquire_v8(2, 3 * EPOCH_DURATION_NS, 1);
    assert!(
        lease.v8_equal_flow_enforced(),
        "#9117 control: two established workers must reach enforcement by the \
         third rotation. If this fails, the SUBJECT cell below proves nothing — \
         'not enforced' would be the state at every early epoch regardless."
    );
}

#[test]
fn newly_active_worker_is_excluded_not_class_wide_fail_open_9117() {
    let lease = new_equal_flow_lease_3w_9117();
    lease.rehydrate_worker_active_count(0, 4);
    lease.rehydrate_worker_active_count(2, 1);

    for epoch in 1..=2u64 {
        let _ = lease.acquire_v8(0, epoch * EPOCH_DURATION_NS, 8_000);
        let _ = lease.acquire_v8(2, epoch * EPOCH_DURATION_NS, 1_800);
    }

    // Worker 1 wakes MID-EPOCH-2: it had no buckets at the last rotation, so
    // its share was published as 0, and it now demands and is granted.
    lease.rehydrate_worker_active_count(1, 1);
    let _ = lease.acquire_v8(1, 2 * EPOCH_DURATION_NS + 1_000, 1_800);

    // Assert the PRECONDITION directly, so a future change that stops
    // constructing this shape fails loudly instead of passing vacuously.
    assert_eq!(
        lease.v8_worker_fair_share_for_test(1),
        0,
        "#9117 fixture: worker 1 must have a published share of 0 — that is the \
         shape under test. A non-zero share means the setup no longer creates a \
         mid-epoch newcomer and every assertion below is measuring something else."
    );
    assert_ne!(
        lease.v8_worker_fair_share_for_test(0),
        0,
        "#9117 fixture: worker 0 must have a real share, else 'share == 0' is not \
         discriminating anything"
    );

    let excluded_before = lease.v8_newly_active_excluded_count();
    let _ = lease.acquire_v8(2, 3 * EPOCH_DURATION_NS, 1);

    assert!(
        lease.v8_equal_flow_enforced(),
        "#9117 [reason={:?} excluded={}] one worker waking mid-epoch disarmed equal-flow enforcement for the \
         WHOLE CLASS. fail_open resets valid_streak and smoothed_target_per_flow, so \
         with EQUAL_FLOW_VALID_STREAK_REQUIRED = 2 that costs ~3 epochs of \
         enforcement on every worker sharing the lease. The newcomer's sample is \
         PARTIAL, not unusable: exclude it for one epoch, exactly as the \
         idle-at-rotation case already does, rather than using it to disarm the \
         comparison.",
        lease.v8_equal_flow_fail_open_reason(),
        lease.v8_newly_active_excluded_count()
    );
    assert!(
        lease.v8_newly_active_excluded_count() > excluded_before,
        "#9117: enforcement survived but nothing recorded that a worker was \
         excluded. The exclusion must be observable — otherwise 'the class kept \
         enforcing' cannot be told apart from 'the newcomer was silently included \
         and dragged the target down'."
    );
}

// #9117 KNOWN COVERAGE BOUND, recorded rather than left for someone to
// rediscover as a survivor.
//
// The pair above is ALSO satisfied by "exclude EVERY unsampled participant" —
// a mutation that replaced the `published_share == Some(0)` discriminator with
// an unconditional exclusion passed both cells. That mutation would delete the
// genuine case-2 safety fail-open, so the gap is real.
//
// The cell that would close it needs an ESTABLISHED worker (non-zero published
// share) that is ACTIVE but UNSAMPLED, and that state is not constructible
// through this API: `rehydrate_worker_active_count(id, 0)` clears
// `active_by_worker` as well as the sampled flow count, so such a worker is
// skipped by the `!active_by_worker[id]` guard before it ever reaches the
// participation arm — the attempt produced `reason=None` with enforcement ON,
// i.e. the shape never occurred. Closing it needs a seam that sets the sampled
// flow count independently of the active flag, which is a change to the
// production type for a test's benefit and is not obviously worth it.
//
// What DOES bound the mutation today: the discriminator is one line, it is
// commented with its reason, and the fail-open it narrows is still reached by
// every worker whose share is non-zero or absent.
