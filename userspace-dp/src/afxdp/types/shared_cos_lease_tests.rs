// Tests for afxdp/types/shared_cos_lease.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep shared_cos_lease.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "shared_cos_lease_tests.rs"]` from shared_cos_lease.rs.

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
        lease.matches_config_v8(10_000_000, 64 * 1024, 2, 5),
        "same config matches"
    );
    assert!(
        !lease.matches_config_v8(10_000_000, 64 * 1024, 2, 6),
        "max_worker_id change does NOT match (forces rebuild)"
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
        !lease.matches_config_v8(10_000_000, 64 * 1024, 2, 0),
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

#[test]
fn v8_acquire_returns_zero_for_out_of_range_worker_id() {
    let lease = SharedCoSQueueLease::new_v8(10_000_000, 64 * 1024, 2, 1);
    // max_worker_id = 1, so worker_id 0 and 1 are valid; 2+ are out of range.
    // debug_assert in production fires; release-mode returns 0.
    // Since cargo test --release skips debug_assert, this returns 0 cleanly.
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
        lease.worker_active_flow_buckets_for(0).unwrap().load(Ordering::Relaxed),
        2
    );
    assert_eq!(
        lease.worker_active_flow_buckets_for(1).unwrap().load(Ordering::Relaxed),
        5
    );
    assert_eq!(
        lease.worker_active_flow_buckets_for(2).unwrap().load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        lease.worker_active_flow_buckets_for(3).unwrap().load(Ordering::Relaxed),
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
