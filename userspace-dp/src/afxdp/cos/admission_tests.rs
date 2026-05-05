// Tests for afxdp/cos/admission.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep admission.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "admission_tests.rs"]` from admission.rs.

use super::*;
use crate::afxdp::cos::ecn::{ECN_CE, ECN_ECT_0, ECN_MASK, ECN_NOT_ECT};
use crate::afxdp::tx::test_support::*;
use crate::afxdp::types::{PreparedTxRecycle, PreparedTxRequest};
use crate::afxdp::PROTO_TCP;

/// #914: shared_exact rate-aware cap — verify the formula
/// `max(fair_share*2, bdp_floor).clamp(MIN, buffer_limit)`
/// scales correctly with `transmit_rate_bytes` and active flows
/// rather than collapsing to the rate-unaware MIN floor.
#[test]
fn flow_share_limit_shared_exact_scales_with_rate() {
    // 10 Gbps shared_exact queue at N=128 → per_flow_rate = 9.77 MB/s,
    // bdp_floor = 9.77 MB/s × 10 ms = 97.6 KB. Buffer_limit ≫ that,
    // so the cap should follow bdp_floor.
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: 0,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    queue.flow_fair = true;
    queue.shared_exact = true;
    queue.active_flow_buckets = 128;
    for bucket in 0..128 {
        queue.flow_bucket_bytes[bucket] = 1_000;
    }
    let buffer_limit = cos_flow_aware_buffer_limit(queue, 0);
    let share = cos_queue_flow_share_limit(queue, buffer_limit, 0);
    // bdp_floor = (1.25 GB/s / 128) × 10 ms = 97_656 bytes (rounded).
    let expected_bdp = bdp_floor_bytes(queue.transmit_rate_bytes, 128);
    assert_eq!(
        share, expected_bdp,
        "shared_exact cap should follow bdp_floor at N=128 (cap={share}, bdp={expected_bdp})"
    );
    assert!(
        share > COS_FLOW_FAIR_MIN_SHARE_BYTES,
        "rate-aware cap ({share}) must exceed the rate-unaware MIN floor ({COS_FLOW_FAIR_MIN_SHARE_BYTES})"
    );
    assert!(
        share <= buffer_limit,
        "cap ({share}) must not exceed buffer_limit ({buffer_limit})"
    );
}

/// #914: at low N, `bdp_floor` exceeds `buffer_limit`; the formula
/// must clamp to buffer_limit and degenerate to today's behavior
/// rather than capping below per-flow BDP (which would collapse
/// TCP cwnd).
#[test]
fn flow_share_limit_shared_exact_caps_at_aggregate_for_single_flow() {
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: 0,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    queue.flow_fair = true;
    queue.shared_exact = true;
    queue.active_flow_buckets = 1;
    queue.flow_bucket_bytes[0] = 1_000;
    let buffer_limit = cos_flow_aware_buffer_limit(queue, 0);
    let share = cos_queue_flow_share_limit(queue, buffer_limit, 0);
    // At N=1 the bdp_floor (~12.5 MB) is way above buffer_limit,
    // so we clamp to buffer_limit.
    assert_eq!(
        share, buffer_limit,
        "single-flow shared_exact cap must clamp to buffer_limit (no regression vs current)"
    );
}

/// #914 (Codex review): at moderate N where `bdp_floor` exceeds
/// `buffer_limit` (the degeneration regime per plan §3.2), the
/// cap must clamp to `buffer_limit` rather than below it. Pins
/// the low-N behavior so a future regression where the formula
/// caps below buffer_limit fails this test rather than slipping
/// through.
#[test]
fn flow_share_limit_shared_exact_clamps_to_buffer_at_low_n() {
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: 0,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    queue.flow_fair = true;
    queue.shared_exact = true;
    // N = 8: per-flow rate = 156 MB/s, bdp_floor = 1.56 MB,
    // far above buffer_limit (which at default base = 96 KB and
    // 8 × MIN_SHARE = 192 KB clamps to ~192 KB).
    queue.active_flow_buckets = 8;
    for bucket in 0..8 {
        queue.flow_bucket_bytes[bucket] = 1_000;
    }
    let buffer_limit = cos_flow_aware_buffer_limit(queue, 0);
    let bdp = bdp_floor_bytes(queue.transmit_rate_bytes, 8);
    assert!(
        bdp > buffer_limit,
        "test premise: bdp_floor ({bdp}) must exceed buffer_limit ({buffer_limit}) at N=8"
    );
    let share = cos_queue_flow_share_limit(queue, buffer_limit, 0);
    assert_eq!(
        share, buffer_limit,
        "low-N shared_exact must clamp to buffer_limit, not below"
    );
}

/// #914: at high N where bdp_floor < buffer_limit, the cap is
/// active and protects mice from elephant starvation (the actual
/// design goal).
#[test]
fn flow_share_limit_shared_exact_protects_against_dominant_flow() {
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: 0,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    queue.flow_fair = true;
    queue.shared_exact = true;
    queue.active_flow_buckets = 128;
    for bucket in 0..128 {
        queue.flow_bucket_bytes[bucket] = 1_000;
    }
    let buffer_limit = cos_flow_aware_buffer_limit(queue, 0);
    let share = cos_queue_flow_share_limit(queue, buffer_limit, 0);
    // The cap must be strictly less than buffer_limit at N=128 —
    // i.e. one flow cannot fill the entire queue.
    assert!(
        share < buffer_limit,
        "rate-aware cap ({share}) must split the buffer at N=128 (buffer_limit={buffer_limit})"
    );
    // And strictly greater than buffer_limit / N (the rate-unaware
    // arithmetic share) because of the bdp_floor and 2× headroom.
    assert!(
        share >= buffer_limit / 128,
        "cap ({share}) must be at least buffer_limit/N ({})",
        buffer_limit / 128
    );
}

/// #914: owner-local-exact queues (NOT shared_exact) keep the
/// legacy `buffer_limit / prospective_active` arithmetic share.
/// Verify the new shared_exact branch does not affect them.
#[test]
fn flow_share_limit_owner_local_exact_unchanged() {
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: 125_000,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    queue.flow_fair = true;
    queue.shared_exact = false; // owner-local-exact
    queue.active_flow_buckets = 12;
    for bucket in 0..12 {
        queue.flow_bucket_bytes[bucket] = 1_000;
    }
    let buffer_limit = cos_flow_aware_buffer_limit(queue, 0);
    let share = cos_queue_flow_share_limit(queue, buffer_limit, 0);
    // Legacy formula: buffer_limit / prospective_active, clamped to
    // [MIN_SHARE, buffer_limit]. With 12 buckets and the prospective
    // +1 for empty target bucket, the divisor is 13 (or 12 if the
    // target bucket is non-empty).
    let prospective = cos_queue_prospective_active_flows(queue, 0);
    let expected = buffer_limit
        .div_ceil(prospective)
        .clamp(COS_FLOW_FAIR_MIN_SHARE_BYTES, buffer_limit);
    assert_eq!(
        share, expected,
        "owner-local-exact cap must use the legacy aggregate/N formula"
    );
}

#[test]
fn admission_ecn_marked_counter_increments_when_marking_above_threshold() {
    // Drive the queue to >50% of buffer_limit with an ECT(0) packet
    // incoming. The mark must fire; the counter must advance by
    // exactly one; no drop counters advance; the packet is "admitted"
    // (we run the decision in isolation, so we just assert `marked`).
    let mut root = test_cos_runtime_with_exact(false);
    let queue = &mut root.queues[0];
    let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
    // Half + 1 byte — strictly above the 50% threshold.
    queue.queued_bytes = (buffer_limit / 2) + 1;
    let before = snapshot_counters(queue);

    let mut item = test_local_ipv4_item(ECN_ECT_0);
    let umem = test_admission_umem();
    // Non-flow-fair queue: share_cap == buffer_limit, so both
    // thresholds collapse onto the aggregate one. `flow_bucket=0`
    // is unused beyond the (constant-returning) share-limit call.
    let marked =
        apply_cos_admission_ecn_policy(queue, buffer_limit, 0, false, false, &mut item, &umem);

    assert!(marked);
    let after = snapshot_counters(queue);
    assert_eq!(
        after.admission_ecn_marked,
        before.admission_ecn_marked + 1,
        "ECN counter must advance by 1",
    );
    assert_eq!(
        after.admission_flow_share_drops,
        before.admission_flow_share_drops
    );
    assert_eq!(after.admission_buffer_drops, before.admission_buffer_drops);
    // Packet bytes now carry CE.
    if let CoSPendingTxItem::Local(req) = &item {
        assert_eq!(req.bytes[15] & ECN_MASK, ECN_CE);
    } else {
        panic!("item must stay Local variant");
    }
}

#[test]
fn admission_does_not_mark_below_threshold() {
    let mut root = test_cos_runtime_with_exact(false);
    let queue = &mut root.queues[0];
    let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
    // Exactly at the mark threshold — `>` comparison must not fire.
    // Written against the constants so retuning NUM/DEN doesn't
    // silently break this pin; at any fraction < 1, an at-threshold
    // queue must stay unmarked by the `>` comparison in
    // `apply_cos_admission_ecn_policy`.
    queue.queued_bytes = buffer_limit * COS_ECN_MARK_THRESHOLD_NUM / COS_ECN_MARK_THRESHOLD_DEN;
    let before = snapshot_counters(queue);

    let mut item = test_local_ipv4_item(ECN_ECT_0);
    let umem = test_admission_umem();
    let marked =
        apply_cos_admission_ecn_policy(queue, buffer_limit, 0, false, false, &mut item, &umem);

    assert!(!marked, "at-threshold must not mark");
    let after = snapshot_counters(queue);
    assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked);
    // Packet bytes unchanged.
    if let CoSPendingTxItem::Local(req) = &item {
        assert_eq!(req.bytes[15] & ECN_MASK, ECN_ECT_0);
    } else {
        panic!("item must stay Local variant");
    }
}

#[test]
fn admission_does_not_mark_non_ect_packets() {
    // Queue above threshold, but packet is NOT-ECT. Mark must not
    // fire and counter must not advance — RFC 3168 compliance.
    let mut root = test_cos_runtime_with_exact(false);
    let queue = &mut root.queues[0];
    let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
    queue.queued_bytes = (buffer_limit / 2) + 1;
    let before = snapshot_counters(queue);

    let mut item = test_local_ipv4_item(ECN_NOT_ECT);
    let umem = test_admission_umem();
    let marked =
        apply_cos_admission_ecn_policy(queue, buffer_limit, 0, false, false, &mut item, &umem);

    assert!(!marked);
    let after = snapshot_counters(queue);
    assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked);
    if let CoSPendingTxItem::Local(req) = &item {
        assert_eq!(req.bytes[15] & ECN_MASK, ECN_NOT_ECT);
    } else {
        panic!("item must stay Local variant");
    }
}

#[test]
fn admission_does_not_mark_when_drop_is_imminent() {
    // Queue above threshold AND flow-share/buffer exceeded: don't
    // burn the mark on a packet that's about to be dropped.
    let mut root = test_cos_runtime_with_exact(false);
    let queue = &mut root.queues[0];
    let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
    queue.queued_bytes = (buffer_limit / 2) + 1;
    let before = snapshot_counters(queue);

    let mut item = test_local_ipv4_item(ECN_ECT_0);
    let umem = test_admission_umem();
    // Signal that the caller already decided this packet will drop.
    let marked =
        apply_cos_admission_ecn_policy(queue, buffer_limit, 0, true, false, &mut item, &umem);
    assert!(!marked, "flow_share_exceeded path must skip marking");
    let after_share = snapshot_counters(queue);
    assert_eq!(
        after_share.admission_ecn_marked,
        before.admission_ecn_marked
    );

    let marked =
        apply_cos_admission_ecn_policy(queue, buffer_limit, 0, false, true, &mut item, &umem);
    assert!(!marked, "buffer_exceeded path must skip marking");
    let after_buf = snapshot_counters(queue);
    assert_eq!(after_buf.admission_ecn_marked, before.admission_ecn_marked);

    // Packet bytes unchanged through both calls.
    if let CoSPendingTxItem::Local(req) = &item {
        assert_eq!(req.bytes[15] & ECN_MASK, ECN_ECT_0);
    } else {
        panic!("item must stay Local variant");
    }
}

#[test]
fn admission_ecn_marks_when_per_flow_above_threshold_aggregate_below() {
    // Live failure mode from #722: queue sits at ~31% utilisation
    // so the aggregate 50% threshold never trips, but a dominant
    // flow's bucket is past the per-flow 50% threshold and is
    // about to be dropped by the flow-share cap.
    let mut root = test_flow_fair_exact_queue_16_flows();
    let queue = &mut root.queues[0];
    let target = 0usize;

    // buffer_limit at 16 active flows: 16 × 24 KB = 384 KB (clamped
    // by delay_cap = 625 KB on a 1 Gbps queue @ 5 ms). share_cap =
    // 384000 / 16 = 24000. At the current NUM/DEN = 1/3 (33%) per
    // #754, the thresholds are aggregate = 384000 / 3 = 128_000 and
    // per-flow = 24000 / 3 = 8_000. If NUM/DEN is retuned, both
    // derived values move together — the asserts below are written
    // against concrete numbers (not the constants) so a future
    // retune fails the pin loudly, which is the whole point.
    let target_bucket_bytes = 15_000; // > 8 000 per-flow threshold with a generous margin
    let queued_bytes = seed_sixteen_flow_buckets(queue, target, target_bucket_bytes);
    queue.queued_bytes = queued_bytes;
    let buffer_limit = cos_flow_aware_buffer_limit(queue, target);
    assert_eq!(buffer_limit, 384_000);
    let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, target);
    assert_eq!(share_cap, 24_000);
    let aggregate_ecn_threshold =
        buffer_limit.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
    let flow_ecn_threshold =
        share_cap.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
    // Concrete expected values at NUM/DEN = 1/3: aggregate =
    // 384_000 / 3 = 128_000 and per-flow = 24_000 / 3 = 8_000.
    assert_eq!(
        aggregate_ecn_threshold, 128_000,
        "aggregate threshold must remain pinned for this fixture",
    );
    assert_eq!(
        flow_ecn_threshold, 8_000,
        "per-flow threshold must remain pinned for this fixture",
    );

    // Counter-factual: reconstruct the pre-#722 aggregate-only
    // formula and assert that on this exact state it would NOT
    // fire. This is what #718 did and why it missed the live
    // workload — keep this pin live so a future refactor that
    // drops the per-flow arm fails here loudly.
    assert!(
        queue.queued_bytes <= aggregate_ecn_threshold,
        "aggregate-only formula must fall below threshold on the #722 live state",
    );
    // And the per-flow arm must be above its threshold.
    assert!(queue.flow_bucket_bytes[target] > flow_ecn_threshold);

    let before = snapshot_counters(queue);
    let mut item = test_local_ipv4_item(ECN_ECT_0);
    let umem = test_admission_umem();
    let marked =
        apply_cos_admission_ecn_policy(queue, buffer_limit, target, false, false, &mut item, &umem);

    assert!(marked, "per-flow arm must fire when aggregate is below");
    let after = snapshot_counters(queue);
    assert_eq!(
        after.admission_ecn_marked,
        before.admission_ecn_marked + 1,
        "ECN counter must advance by exactly 1",
    );
    assert_eq!(
        after.admission_flow_share_drops, before.admission_flow_share_drops,
        "mark is not a drop",
    );
    assert_eq!(
        after.admission_buffer_drops, before.admission_buffer_drops,
        "mark is not a drop",
    );
    if let CoSPendingTxItem::Local(req) = &item {
        assert_eq!(req.bytes[15] & ECN_MASK, ECN_CE, "CE bit must be set");
    } else {
        panic!("item must stay Local variant");
    }
}

/// #784: SFQ fairness regression pin. The former behavior of
/// the aggregate-above ECN arm actively broke per-flow fairness
/// on iperf3 -P 12 against a 1 Gbps cap (3 winners at 145 Mbps
/// with 0 retrans, 9 losers at 50-75 Mbps with thousands of
/// retrans each). Removing the aggregate arm restored fairness
/// because flows that hadn't filled their bucket no longer got
/// penalised for OTHER flows' bursts.
///
/// If this test ever flips to assert `marked` is true, the
/// aggregate arm has been reintroduced and the iperf3 fairness
/// regression in #784 WILL come back. Do not weaken this test.
#[test]
fn admission_ecn_does_not_mark_when_only_aggregate_above_threshold() {
    let mut root = test_flow_fair_exact_queue_16_flows();
    let queue = &mut root.queues[0];
    let target = 0usize;

    let target_bucket_bytes = 500; // << per-flow threshold (8 000 B at 1/3)
    let _ = seed_sixteen_flow_buckets(queue, target, target_bucket_bytes);
    let buffer_limit = cos_flow_aware_buffer_limit(queue, target);
    let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, target);
    let aggregate_ecn_threshold =
        buffer_limit.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
    let flow_ecn_threshold =
        share_cap.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
    queue.queued_bytes = aggregate_ecn_threshold + 1; // strictly above

    assert!(queue.queued_bytes > aggregate_ecn_threshold);
    assert!(queue.flow_bucket_bytes[target] <= flow_ecn_threshold);

    let before = snapshot_counters(queue);
    let mut item = test_local_ipv4_item(ECN_ECT_0);
    let umem = test_admission_umem();
    let marked =
        apply_cos_admission_ecn_policy(queue, buffer_limit, target, false, false, &mut item, &umem);

    assert!(
        !marked,
        "#784: aggregate arm must NOT fire — only per-flow threshold triggers marks. \
         If this assertion ever flips, the SFQ iperf3 -P 12 fairness regression returns."
    );
    let after = snapshot_counters(queue);
    assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked);
}

#[test]
fn admission_ecn_does_not_mark_when_both_thresholds_below() {
    // Both below — no congestion signal. Mark must stay off and
    // the counter unchanged. Packet bytes untouched.
    let mut root = test_flow_fair_exact_queue_16_flows();
    let queue = &mut root.queues[0];
    let target = 0usize;

    let target_bucket_bytes = 500; // < 8 000 (per-flow threshold at NUM/DEN = 1/3)
    let queued_bytes = seed_sixteen_flow_buckets(queue, target, target_bucket_bytes);
    queue.queued_bytes = queued_bytes; // ≪ 128 000 (aggregate threshold at 1/3)
    let buffer_limit = cos_flow_aware_buffer_limit(queue, target);
    let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, target);
    let aggregate_ecn_threshold =
        buffer_limit.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
    let flow_ecn_threshold =
        share_cap.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
    assert!(queue.queued_bytes <= aggregate_ecn_threshold);
    assert!(queue.flow_bucket_bytes[target] <= flow_ecn_threshold);

    let before = snapshot_counters(queue);
    let mut item = test_local_ipv4_item(ECN_ECT_0);
    let umem = test_admission_umem();
    let marked =
        apply_cos_admission_ecn_policy(queue, buffer_limit, target, false, false, &mut item, &umem);

    assert!(!marked, "no threshold tripped — no mark");
    let after = snapshot_counters(queue);
    assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked);
    if let CoSPendingTxItem::Local(req) = &item {
        assert_eq!(
            req.bytes[15] & ECN_MASK,
            ECN_ECT_0,
            "packet bytes must be byte-identical below threshold",
        );
    } else {
        panic!("item must stay Local variant");
    }
}

#[test]
fn admission_ecn_does_not_mark_when_flow_share_already_exceeded() {
    // Per-flow above threshold BUT the caller has also decided the
    // packet will drop (flow_share_exceeded = true). Preserves the
    // #718 invariant that we don't burn marks on doomed packets —
    // a marked-then-dropped packet wastes both the mark and the
    // bandwidth the mark was trying to steer.
    let mut root = test_flow_fair_exact_queue_16_flows();
    let queue = &mut root.queues[0];
    let target = 0usize;

    let target_bucket_bytes = 15_000; // > 8 000 per-flow threshold (NUM/DEN = 1/3)
    let queued_bytes = seed_sixteen_flow_buckets(queue, target, target_bucket_bytes);
    queue.queued_bytes = queued_bytes;
    let buffer_limit = cos_flow_aware_buffer_limit(queue, target);

    let before = snapshot_counters(queue);
    let mut item = test_local_ipv4_item(ECN_ECT_0);
    let umem = test_admission_umem();
    let marked =
        apply_cos_admission_ecn_policy(queue, buffer_limit, target, true, false, &mut item, &umem);

    assert!(!marked, "flow_share_exceeded must suppress the mark");
    let after = snapshot_counters(queue);
    assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked);
    if let CoSPendingTxItem::Local(req) = &item {
        assert_eq!(
            req.bytes[15] & ECN_MASK,
            ECN_ECT_0,
            "doomed packet must not be rewritten",
        );
    } else {
        panic!("item must stay Local variant");
    }
}

#[test]
fn admission_ecn_per_flow_threshold_matches_share_cap_denominator() {
    // Pin that the per-flow threshold uses the SAME
    // NUM/DEN fraction as the aggregate threshold. If a future
    // refactor changes the constants (e.g. drops the aggregate
    // arm to 33%) without updating the per-flow arm, both arms
    // drift out of lockstep and this test fails. Computed from
    // the state as `share_cap × NUM / DEN` independently — no
    // internal call into the policy function.
    //
    // #784: seed with `target_bytes > 0` so prospective_active
    // stays at 16 both in the test's computed threshold and in
    // the policy's live recompute. Earlier revision seeded
    // target=0 and set the bucket above threshold later, which
    // shifted prospective_active from 17 → 16 between compute
    // and policy call and silently passed on the aggregate arm.
    let mut root = test_flow_fair_exact_queue_16_flows();
    let queue = &mut root.queues[0];
    let target = 0usize;

    seed_sixteen_flow_buckets(queue, target, 1);
    let buffer_limit = cos_flow_aware_buffer_limit(queue, target);
    let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, target);

    let expected_aggregate =
        buffer_limit.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;
    let expected_flow =
        share_cap.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM) / COS_ECN_MARK_THRESHOLD_DEN;

    // Ratio check: both thresholds must be exactly NUM/DEN of their
    // respective caps, i.e. `threshold × DEN == cap × NUM`. Stated
    // as multiplications so integer truncation does not mask drift.
    assert_eq!(
        expected_aggregate.saturating_mul(COS_ECN_MARK_THRESHOLD_DEN),
        buffer_limit.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM),
        "aggregate threshold must be NUM/DEN of buffer_limit",
    );
    assert_eq!(
        expected_flow.saturating_mul(COS_ECN_MARK_THRESHOLD_DEN),
        share_cap.saturating_mul(COS_ECN_MARK_THRESHOLD_NUM),
        "per-flow threshold must be NUM/DEN of share_cap",
    );

    // Drive the policy at a state that trips BOTH arms and
    // verify the mark fires — proves the live code path uses
    // the same fractions we computed by hand.
    queue.queued_bytes = expected_aggregate + 1;
    queue.flow_bucket_bytes[target] = expected_flow + 1;
    let before = snapshot_counters(queue);
    let mut item = test_local_ipv4_item(ECN_ECT_0);
    let umem = test_admission_umem();
    let marked =
        apply_cos_admission_ecn_policy(queue, buffer_limit, target, false, false, &mut item, &umem);
    assert!(marked);
    let after = snapshot_counters(queue);
    assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked + 1);
}

#[test]
fn admission_ecn_marks_prepared_ipv4_ect0_packet_above_threshold() {
    // Pre: queue above aggregate threshold, Prepared IPv4 ECT(0)
    // packet lives at UMEM offset 0. Counter-factual pins that
    // make this robust against partial regressions:
    //   1. Before the call: TOS byte has ECN = ECT(0).
    //   2. After the call: TOS byte has ECN = CE.
    //   3. Counter bumped by exactly 1.
    //   4. IP checksum recomputed-from-scratch matches what's in
    //      the UMEM bytes.
    let mut root = test_cos_runtime_with_exact(false);
    let queue = &mut root.queues[0];
    let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
    queue.queued_bytes = (buffer_limit / 2) + 1;
    let before = snapshot_counters(queue);

    let tos = (0x28u8 << 2) | ECN_ECT_0;
    let packet = build_ipv4_test_packet(tos);
    let mut umem = test_admission_umem();
    let mut item = test_prepared_item_in_umem(&mut umem, 0, &packet, libc::AF_INET as u8);

    // Pin (1): pre-state is ECT(0).
    let pre_bytes = umem
        .slice(0, packet.len())
        .expect("slice readback")
        .to_vec();
    assert_eq!(pre_bytes[15] & ECN_MASK, ECN_ECT_0);

    let marked =
        apply_cos_admission_ecn_policy(queue, buffer_limit, 0, false, false, &mut item, &umem);

    assert!(marked, "Prepared variant must be marked");
    // Pin (3): counter bumped by exactly 1.
    let after = snapshot_counters(queue);
    assert_eq!(
        after.admission_ecn_marked,
        before.admission_ecn_marked + 1,
        "ECN counter must advance by exactly 1",
    );
    assert_eq!(
        after.admission_flow_share_drops,
        before.admission_flow_share_drops
    );
    assert_eq!(after.admission_buffer_drops, before.admission_buffer_drops);

    // Pin (2): UMEM bytes now carry CE and preserve DSCP.
    let post_bytes = umem
        .slice(0, packet.len())
        .expect("slice readback")
        .to_vec();
    assert_eq!(post_bytes[15] & ECN_MASK, ECN_CE, "ECN bits must be CE");
    assert_eq!(post_bytes[15] >> 2, 0x28, "DSCP must survive marking");

    // Pin (4): IP checksum recomputed from scratch matches what's
    // actually sitting in UMEM. If the incremental update were
    // off-by-one or skipped a word, this would fail.
    let stored_csum = ((post_bytes[24] as u16) << 8) | post_bytes[25] as u16;
    let from_scratch = compute_ipv4_header_checksum(&post_bytes[14..34]);
    assert_eq!(
        stored_csum, from_scratch,
        "incremental IP checksum must match a from-scratch recompute",
    );
}

#[test]
fn admission_ecn_marks_prepared_ipv6_ect0_packet_above_threshold() {
    // IPv6 Prepared packet at a non-zero UMEM offset. IPv6 has no
    // header checksum, so the pins are:
    //   1. Pre-state tclass has ECN = ECT(0).
    //   2. Post-state tclass has ECN = CE.
    //   3. Version + flow-label untouched.
    //   4. Counter bumped by exactly 1.
    let mut root = test_cos_runtime_with_exact(false);
    let queue = &mut root.queues[0];
    let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
    queue.queued_bytes = (buffer_limit / 2) + 1;
    let before = snapshot_counters(queue);

    let tclass = (0x2eu8 << 2) | ECN_ECT_0;
    let packet = build_ipv6_test_packet(tclass);
    // Pick a non-zero offset to prove that `slice_mut` is
    // honouring `req.offset` rather than always slicing from 0.
    let offset: u64 = 128;
    let mut umem = test_admission_umem();
    let mut item = test_prepared_item_in_umem(&mut umem, offset, &packet, libc::AF_INET6 as u8);

    let pre_bytes = umem
        .slice(offset as usize, packet.len())
        .expect("slice readback")
        .to_vec();
    let pre_version_nibble = pre_bytes[14] & 0xf0;
    let pre_flow_label_low = pre_bytes[15] & 0x0f;
    assert_eq!(
        ((pre_bytes[14] & 0x0f) << 4) | ((pre_bytes[15] >> 4) & 0x0f),
        tclass,
    );

    let marked =
        apply_cos_admission_ecn_policy(queue, buffer_limit, 0, false, false, &mut item, &umem);

    assert!(marked, "Prepared IPv6 must be marked");
    let after = snapshot_counters(queue);
    assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked + 1,);

    let post_bytes = umem
        .slice(offset as usize, packet.len())
        .expect("slice readback")
        .to_vec();
    let post_tclass = ((post_bytes[14] & 0x0f) << 4) | ((post_bytes[15] >> 4) & 0x0f);
    assert_eq!(post_tclass & ECN_MASK, ECN_CE);
    assert_eq!(post_tclass >> 2, 0x2e, "DSCP must survive marking");
    assert_eq!(
        post_bytes[14] & 0xf0,
        pre_version_nibble,
        "version nibble must not drift",
    );
    assert_eq!(
        post_bytes[15] & 0x0f,
        pre_flow_label_low,
        "flow-label low nibble must not drift",
    );
}

#[test]
fn admission_ecn_leaves_prepared_not_ect_packet_untouched() {
    // Queue above threshold, but the Prepared packet is NOT-ECT.
    // RFC 3168 §6.1.1.1: never mark a flow that did not negotiate
    // ECN. Counter must stay put and UMEM bytes byte-identical.
    let mut root = test_cos_runtime_with_exact(false);
    let queue = &mut root.queues[0];
    let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
    queue.queued_bytes = (buffer_limit / 2) + 1;
    let before = snapshot_counters(queue);

    let tos = 0xb8; // DSCP 46 (EF), ECN = 00 (NOT-ECT)
    let packet = build_ipv4_test_packet(tos);
    let mut umem = test_admission_umem();
    let mut item = test_prepared_item_in_umem(&mut umem, 0, &packet, libc::AF_INET as u8);
    let pre_bytes = umem
        .slice(0, packet.len())
        .expect("slice readback")
        .to_vec();

    let marked =
        apply_cos_admission_ecn_policy(queue, buffer_limit, 0, false, false, &mut item, &umem);

    assert!(!marked, "NOT-ECT packet must not be marked");
    let after = snapshot_counters(queue);
    assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked);
    let post_bytes = umem
        .slice(0, packet.len())
        .expect("slice readback")
        .to_vec();
    assert_eq!(
        post_bytes, pre_bytes,
        "NOT-ECT packet bytes must be byte-identical",
    );
    assert_eq!(post_bytes[15] & ECN_MASK, ECN_NOT_ECT);
}

#[test]
fn admission_ecn_skips_prepared_when_umem_slice_out_of_range() {
    // Constructed `PreparedTxRequest` points past the end of the
    // UMEM (`offset` > umem.len()). `slice_mut_unchecked` returns
    // None, the marker returns false, and the admission policy
    // must neither panic nor bump the counter. Guards the
    // out-of-range None-handling path — a regression that removed
    // the `let Some(...) = ... else { return false }` shape would
    // fail here without needing to catch a UB-flavoured panic.
    let mut root = test_cos_runtime_with_exact(false);
    let queue = &mut root.queues[0];
    let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
    queue.queued_bytes = (buffer_limit / 2) + 1;
    let before = snapshot_counters(queue);

    let umem = test_admission_umem();
    // Offset deliberately past the UMEM len. `len: 1` so we do
    // not trip the internal `checked_add` overflow path — we want
    // the `end > self.len` check in `slice_mut_unchecked` to be
    // what returns None.
    let mut item = CoSPendingTxItem::Prepared(PreparedTxRequest {
        offset: u64::MAX / 2,
        len: 1,
        recycle: PreparedTxRecycle::FreeTxFrame,
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 42,
        cos_queue_id: Some(0),
        dscp_rewrite: None,
    });

    let marked =
        apply_cos_admission_ecn_policy(queue, buffer_limit, 0, false, false, &mut item, &umem);

    assert!(!marked, "out-of-range slice must not be marked");
    let after = snapshot_counters(queue);
    assert_eq!(
        after.admission_ecn_marked, before.admission_ecn_marked,
        "counter must stay put when the slice is out of range",
    );
}

#[test]
fn admission_ecn_counter_increments_for_both_local_and_prepared_in_same_queue() {
    // Drive the queue above threshold and pass ONE Local + ONE
    // Prepared, both ECT(0). The single `admission_ecn_marked`
    // counter must advance by exactly 2 — proves neither variant
    // is double-counting or under-counting, and that both paths
    // share the same counter. Counter-factual for a refactor
    // that accidentally split the counter: this test would drop
    // to +1.
    let mut root = test_cos_runtime_with_exact(false);
    let queue = &mut root.queues[0];
    let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
    queue.queued_bytes = (buffer_limit / 2) + 1;
    let before = snapshot_counters(queue);

    let mut umem = test_admission_umem();

    // Local variant first.
    let mut local_item = test_local_ipv4_item(ECN_ECT_0);
    let marked_local = apply_cos_admission_ecn_policy(
        queue,
        buffer_limit,
        0,
        false,
        false,
        &mut local_item,
        &umem,
    );
    assert!(marked_local, "Local variant must mark");

    // Prepared variant next.
    let packet = build_ipv4_test_packet(ECN_ECT_0);
    let mut prepared_item = test_prepared_item_in_umem(&mut umem, 0, &packet, libc::AF_INET as u8);
    let marked_prepared = apply_cos_admission_ecn_policy(
        queue,
        buffer_limit,
        0,
        false,
        false,
        &mut prepared_item,
        &umem,
    );
    assert!(marked_prepared, "Prepared variant must mark");

    let after = snapshot_counters(queue);
    assert_eq!(
        after.admission_ecn_marked,
        before.admission_ecn_marked + 2,
        "single counter must reflect both Local and Prepared marks",
    );
}

/// #728 review pin: the Prepared (zero-copy) path has its own
/// slice/offset plumbing on top of the L3-offset helper. The VLAN
/// regression on the Local path is necessary but not sufficient —
/// Local could stay correct while Prepared silently regressed to
/// stamping the wrong byte. This drives a single-802.1Q ECT(0)
/// frame through `apply_cos_admission_ecn_policy` at a *non-zero*
/// UMEM offset and pins that:
///   - CE lands at `l3_offset + 1` relative to the frame start
///     (i.e. at `frame_offset + 19` inside the UMEM),
///   - the VLAN TCI bytes at frame-offset 14..16 are unchanged,
///   - the IPv4 header checksum still validates from scratch.
/// A revert to a hardcoded 14 would stamp byte 15 (inside the TCI)
/// and this test would fail on the checksum validate as well as
/// on the TCI-untouched assertion.
#[test]
fn admission_ecn_marks_prepared_single_vlan_tagged_ipv4_packet() {
    let mut root = test_cos_runtime_with_exact(false);
    let queue = &mut root.queues[0];
    let buffer_limit = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
    queue.queued_bytes = (buffer_limit / 2) + 1;

    let packet = build_ipv4_test_packet(ECN_ECT_0);
    let vid: u16 = 80;
    let priority: u8 = 5;
    let tci: u16 = ((priority as u16) << 13) | vid;
    let tagged = insert_single_vlan_tag(packet, vid, priority);

    // Non-zero UMEM offset so we also prove offset arithmetic
    // (slice_mut + l3_offset) composes correctly on a
    // non-head frame.
    let frame_offset: u64 = 128;
    let mut umem = test_admission_umem();
    let mut item =
        test_prepared_item_in_umem(&mut umem, frame_offset, &tagged, libc::AF_INET as u8);

    let before = snapshot_counters(queue);
    let marked =
        apply_cos_admission_ecn_policy(queue, buffer_limit, 0, false, false, &mut item, &umem);
    assert!(
        marked,
        "VLAN-tagged ECT(0) Prepared frame must be marked at the VLAN-shifted offset",
    );
    let after = snapshot_counters(queue);
    assert_eq!(after.admission_ecn_marked, before.admission_ecn_marked + 1);

    // Read back the UMEM bytes for the frame and verify ECN = CE
    // at frame_offset + 19 (= l3_offset + 1 = 18 + 1).
    let post = umem
        .slice(frame_offset as usize, tagged.len())
        .expect("umem slice readback")
        .to_vec();
    assert_eq!(
        post[19] & ECN_MASK,
        ECN_CE,
        "CE must land at VLAN-shifted l3_offset + 1",
    );
    // VLAN TCI at bytes 14..16 must be byte-identical. A revert to
    // hardcoded offset 14 would corrupt these bytes.
    assert_eq!(
        u16::from_be_bytes([post[14], post[15]]),
        tci,
        "VLAN TCI must be untouched by ECN marking on the Prepared path",
    );
    // IP checksum recomputed from scratch over the post-mark
    // IPv4 header must equal the 16-bit value in the frame.
    let iphdr_start = 18;
    let iphdr = &post[iphdr_start..iphdr_start + 20];
    let expected_csum = compute_ipv4_header_checksum(iphdr);
    let actual_csum = u16::from_be_bytes([post[iphdr_start + 10], post[iphdr_start + 11]]);
    assert_eq!(
        actual_csum, expected_csum,
        "incremental checksum update must match a from-scratch recomputation",
    );
}

use crate::afxdp::types::{CoSQueueConfig, COS_FLOW_FAIR_BUCKETS};

#[test]
fn cos_flow_aware_buffer_limit_scales_with_prospective_active_flow_count() {
    // #707 + #716 review: at the 1 Gbps/16-flow workload a fixed
    // 125 KB buffer divided across 16 flows gives each flow a 7.8
    // KB share, below the TCP fast-retransmit floor of 16 MSS =
    // 24 KB. The flow-aware buffer limit grows the aggregate cap
    // so the per-flow floor can be honoured. "Prospective" count
    // means the same denominator the per-flow clamp uses: current
    // `active_flow_buckets + (target bucket empty ? 1 : 0)`, so
    // the two gates never disagree about whether a new flow's
    // first packet has room.
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            // Decimal KB to match the operator `buffer-size 125k`
            // config, not KiB — the admission-boundary math must
            // use the same units as the live system.
            buffer_bytes: 125_000,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    queue.flow_fair = true;

    // Base floor wins when prospective flow count × min share is
    // small. `flow_bucket = 0` is empty → prospective_active += 1.
    queue.active_flow_buckets = 0;
    assert_eq!(
        cos_flow_aware_buffer_limit(queue, 0),
        queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
        "zero active (+1 prospective) flows must stay at the operator-configured base"
    );
    queue.active_flow_buckets = 2;
    assert_eq!(
        cos_flow_aware_buffer_limit(queue, 0),
        queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
        "3 prospective × 24 KB = 72 KB stays below the 125 KB configured base, so base wins"
    );

    // Flow-aware floor wins past the break-even point. Now mark 16
    // buckets populated so prospective = 16 (target bucket already
    // non-empty).
    queue.active_flow_buckets = 16;
    for bucket in 0..16 {
        queue.flow_bucket_bytes[bucket] = 1_000;
    }
    assert_eq!(
        cos_flow_aware_buffer_limit(queue, 0),
        16 * COS_FLOW_FAIR_MIN_SHARE_BYTES,
        "16 × 24 KB = 384 KB exceeds the 125 KB base and becomes the cap"
    );
}

#[test]
fn cos_flow_aware_buffer_limit_matches_share_limit_at_new_flow_boundary() {
    // #716 review: the aggregate cap and the per-flow clamp must
    // use the SAME denominator. Before the review fix the
    // aggregate cap used the current `active_flow_buckets` while
    // the per-flow clamp used `active + (target bucket empty ? 1 :
    // 0)`, so the first packet of a newly arriving flow could
    // pass the per-flow gate and fail the aggregate one right at
    // the boundary. This test drives the queue to the *actual*
    // admission boundary so the assertion exercises the old
    // failure mode rather than trivial 0-bytes arithmetic.
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            // Decimal KB to match the operator `buffer-size 125k`
            // config, not KiB — the admission-boundary math must
            // use the same units as the live system.
            buffer_bytes: 125_000,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    queue.flow_fair = true;

    // 15 active flows filled to 24 KB each. Target bucket empty →
    // prospective_active = 16. Both caps must key off 16, not 15.
    queue.active_flow_buckets = 15;
    for bucket in 0..15 {
        queue.flow_bucket_bytes[bucket] = COS_FLOW_FAIR_MIN_SHARE_BYTES;
    }
    // Aggregate queued equals the pre-fix aggregate cap exactly —
    // this is the value that made the bug observable: under the
    // old formula the aggregate cap was `15 × min-share` and the
    // check `queued + 1500 > cap` tripped; under the fix the cap
    // is `16 × min-share` and the packet fits.
    queue.queued_bytes = 15 * COS_FLOW_FAIR_MIN_SHARE_BYTES;

    let new_flow_bucket = 100;
    assert_eq!(queue.flow_bucket_bytes[new_flow_bucket], 0);

    let buffer_limit = cos_flow_aware_buffer_limit(queue, new_flow_bucket);
    let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, new_flow_bucket);

    // Fixed caps: aggregate = 16 × min-share, per-flow = min-share.
    assert_eq!(buffer_limit, 16 * COS_FLOW_FAIR_MIN_SHARE_BYTES);
    assert_eq!(share_cap, COS_FLOW_FAIR_MIN_SHARE_BYTES);

    // Per-flow gate: new bucket is empty, so +1500 is well below cap.
    assert!(
        queue.flow_bucket_bytes[new_flow_bucket].saturating_add(1500) <= share_cap,
        "per-flow share must admit the new flow's first packet"
    );

    // Aggregate gate: queued is at the pre-fix cap. Fix makes
    // +1500 still fit; without the fix this was a drop.
    assert!(
        queue.queued_bytes.saturating_add(1500) <= buffer_limit,
        "aggregate cap must admit the new flow's first packet at the near-cap boundary \
         (queued_bytes = {}, +1500 must fit within buffer_limit = {})",
        queue.queued_bytes,
        buffer_limit,
    );

    // Counter-factual: prove the pre-fix formula (non-prospective)
    // would have rejected the same packet. Guards against a future
    // refactor silently reverting to `active_flow_buckets` without
    // the `+1` bump.
    let non_prospective_cap = u64::from(queue.active_flow_buckets)
        .max(1)
        .saturating_mul(COS_FLOW_FAIR_MIN_SHARE_BYTES)
        .max(queue.buffer_bytes.max(COS_MIN_BURST_BYTES));
    assert!(
        queue.queued_bytes.saturating_add(1500) > non_prospective_cap,
        "without prospective-active, the same queued state would reject the new flow \
         (queued_bytes + 1500 = {}, non-prospective cap = {})",
        queue.queued_bytes + 1500,
        non_prospective_cap,
    );
}

#[test]
fn cos_flow_aware_buffer_limit_respects_non_flow_fair_queues() {
    // Pure rate-limited (non-flow-fair) queues must keep the
    // operator's configured buffer. The flow-aware scaling only
    // applies when SFQ-style per-flow accounting is active.
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 100_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: 128 * 1024,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    queue.flow_fair = false;
    queue.active_flow_buckets = 64; // should be ignored

    // `flow_bucket` argument is irrelevant when flow_fair=false; use 0.
    assert_eq!(
        cos_flow_aware_buffer_limit(queue, 0),
        queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
        "flow_fair=false must bypass the flow-count multiplier"
    );
}

#[test]
fn cos_queue_flow_share_limit_never_drops_below_fast_retransmit_floor() {
    // At 16 flows with a 125 KB buffer, the naive arithmetic share
    // is 7.8 KB — a single packet drop yields < 3 dupacks, forcing
    // RTO. The clamp to `COS_FLOW_FAIR_MIN_SHARE_BYTES` must hold
    // the per-flow cap at 24 KB no matter the denominator.
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            // Decimal KB to match the operator `buffer-size 125k`
            // config, not KiB — the admission-boundary math must
            // use the same units as the live system.
            buffer_bytes: 125_000,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    queue.flow_fair = true;

    // Simulate 16 distinct populated flow buckets.
    queue.active_flow_buckets = 16;
    for bucket in 0..16 {
        queue.flow_bucket_bytes[bucket] = 1_000;
    }

    let buffer_limit = cos_flow_aware_buffer_limit(queue, 0);
    assert_eq!(
        buffer_limit,
        16 * COS_FLOW_FAIR_MIN_SHARE_BYTES,
        "flow-aware cap must expand to accommodate 16 × min-share"
    );

    let share = cos_queue_flow_share_limit(queue, buffer_limit, 0);
    assert!(
        share >= COS_FLOW_FAIR_MIN_SHARE_BYTES,
        "per-flow cap ({share}) must stay ≥ {COS_FLOW_FAIR_MIN_SHARE_BYTES} (16 MTU-sized packets)"
    );
    assert_eq!(
        share, COS_FLOW_FAIR_MIN_SHARE_BYTES,
        "with buffer_limit == active × min-share, per-flow cap equals the floor"
    );
}

#[test]
fn cos_flow_aware_buffer_limit_clamps_high_flow_count_to_max_delay() {
    // #717: at the architectural maximum of 1024 active buckets
    // the pre-clamp flow-aware expansion reaches
    // 1024 × COS_FLOW_FAIR_MIN_SHARE_BYTES ≈ 24 MB. On a 1 Gbps
    // queue that is ~190 ms of queue residence — far outside the
    // scheduler's predictable regime. The latency-envelope clamp
    // caps the aggregate at
    // `transmit_rate_bytes × COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS / 1e9`
    // so the tail stays bounded.
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            // 1 Gbps → 125_000_000 bytes/s (decimal, matches
            // operator `transmit-rate 1g` semantics).
            transmit_rate_bytes: 125_000_000,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            // Decimal KB to match the operator `buffer-size 125k`
            // config, not KiB.
            buffer_bytes: 125_000,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    queue.flow_fair = true;

    // Drive to the architectural maximum: 1024 populated buckets.
    queue.active_flow_buckets = COS_FLOW_FAIR_BUCKETS as u16;
    for bucket in 0..COS_FLOW_FAIR_BUCKETS {
        queue.flow_bucket_bytes[bucket] = 1_000;
    }

    let cap = cos_flow_aware_buffer_limit(queue, 0);

    // Expected delay cap: 125_000_000 B/s × 5 ms = 625_000 B.
    let expected_delay_cap = 625_000u64;
    assert_eq!(
        cap, expected_delay_cap,
        "flow-aware cap must be clamped to the 5 ms delay envelope, not the ~24 MB \
         unclamped expansion"
    );

    // Counter-factual: prove the pre-clamp formula would have
    // returned 24 MB. Guards against a future refactor silently
    // deleting the clamp.
    let unclamped = u64::from(queue.active_flow_buckets)
        .max(1)
        .saturating_mul(COS_FLOW_FAIR_MIN_SHARE_BYTES)
        .max(queue.buffer_bytes.max(COS_MIN_BURST_BYTES));
    assert_eq!(
        unclamped,
        COS_FLOW_FAIR_BUCKETS as u64 * COS_FLOW_FAIR_MIN_SHARE_BYTES,
        "unclamped formula baseline: COS_FLOW_FAIR_BUCKETS × COS_FLOW_FAIR_MIN_SHARE_BYTES \
         (4096 × 24 KB = ~96 MB after the GEMINI-NEXT.md fairness bump from 1024)"
    );
    assert!(
        cap < unclamped,
        "clamp must shrink the flow-aware expansion (cap = {cap}, unclamped = {unclamped})"
    );
}

#[test]
fn cos_flow_aware_buffer_limit_honours_operator_base_above_delay_cap() {
    // #717: the clamp is `.min(delay_cap.max(base))` — if the
    // operator explicitly configured a buffer larger than
    // `delay_cap`, we honour their intent. The clamp must never
    // shrink below the operator's `buffer-size`. On a 1 Gbps queue
    // the delay cap is 625_000 B; a 100 MiB operator base is well
    // above that.
    let operator_base: u64 = 100 * 1024 * 1024;
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 125_000_000,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: operator_base,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    queue.flow_fair = true;

    // Use a middling flow count so prospective × min-share sits
    // between delay_cap and operator_base. That exercises the
    // branch where delay_cap < base < flow-aware expansion.
    queue.active_flow_buckets = 16;
    for bucket in 0..16 {
        queue.flow_bucket_bytes[bucket] = 1_000;
    }

    let cap = cos_flow_aware_buffer_limit(queue, 0);
    assert_eq!(
        cap, operator_base,
        "operator base ({operator_base}) must survive the clamp even when it exceeds \
         delay_cap (625_000) — the clamp is .min(delay_cap.max(base))"
    );

    // Counter-factual: a naive `.min(delay_cap)` (without
    // `.max(base)`) would have clamped the operator's explicit
    // 100 MiB down to 625 KB. Pin that this is NOT what we do.
    let naive_delay_cap = 625_000u64;
    assert!(
        cap > naive_delay_cap,
        "naive delay-only clamp would shrink operator intent to {naive_delay_cap}; the \
         `.max(base)` guard must preserve {operator_base}"
    );
}

#[test]
fn cos_flow_aware_buffer_limit_preserves_non_flow_fair_path_after_clamp() {
    // #717: the latency clamp must not leak into the non-flow-fair
    // path. Pure rate-limited queues bypass both the floor and the
    // clamp and return the raw `buffer_bytes.max(COS_MIN_BURST_BYTES)`.
    // This is the companion to
    // `cos_flow_aware_buffer_limit_respects_non_flow_fair_queues`
    // but exercises the config shape where the delay cap *would*
    // have been tighter than the operator base, to catch a future
    // refactor that moves the clamp above the `flow_fair` early
    // return.
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            // 1 Gbps → delay_cap = 625 KB.
            transmit_rate_bytes: 125_000_000,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            // Operator configured 10 MB — well above delay_cap.
            // If the clamp leaks into this path, the returned cap
            // would be 625 KB, not 10 MB.
            buffer_bytes: 10 * 1_000_000,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    queue.flow_fair = false;
    queue.active_flow_buckets = 64; // should be ignored

    assert_eq!(
        cos_flow_aware_buffer_limit(queue, 0),
        queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
        "flow_fair=false must bypass both the flow-aware floor and the latency clamp"
    );
}

#[test]
fn cos_flow_aware_buffer_limit_delay_cap_scales_linearly_with_rate() {
    // #717: pin the delay-cap formula's linearity. Same active
    // flow count and same COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS, but
    // 10 Gbps vs 1 Gbps — the delay-cap-driven return must be 10×
    // larger. Catches future refactors that accidentally clamp
    // the rate (e.g. saturating at a hardcoded byte count) or
    // swap the product for a divide.
    fn run_at_rate(rate_bytes: u64) -> u64 {
        let mut root = test_cos_runtime_with_queues(
            25_000_000_000 / 8,
            vec![CoSQueueConfig {
                queue_id: 4,
                forwarding_class: "iperf-a".into(),
                priority: 5,
                transmit_rate_bytes: rate_bytes,
                exact: true,
                surplus_sharing: false,
                surplus_weight: 1,
                // Small operator base so the delay cap dominates.
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        );
        let queue = &mut root.queues[0];
        queue.flow_fair = true;
        // Populate all buckets so prospective_active × min-share
        // blows past the delay cap at both rates — the clamp is
        // what's being measured.
        queue.active_flow_buckets = COS_FLOW_FAIR_BUCKETS as u16;
        for bucket in 0..COS_FLOW_FAIR_BUCKETS {
            queue.flow_bucket_bytes[bucket] = 1_000;
        }
        cos_flow_aware_buffer_limit(queue, 0)
    }

    // 1 Gbps decimal: 125_000_000 B/s × 5 ms = 625_000 B.
    let cap_1g = run_at_rate(125_000_000);
    // 10 Gbps decimal: 1_250_000_000 B/s × 5 ms = 6_250_000 B.
    let cap_10g = run_at_rate(1_250_000_000);

    assert_eq!(cap_1g, 625_000);
    assert_eq!(cap_10g, 6_250_000);
    assert_eq!(
        cap_10g,
        cap_1g * 10,
        "delay cap must scale linearly with transmit_rate_bytes \
         (1 Gbps → {cap_1g}, 10 Gbps → {cap_10g})"
    );
}
