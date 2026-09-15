use super::*;

/// A burst up to `burst` passes; the (burst+1)th within the same instant is
/// rate-limited (dropped + counter bumped). FAIL-ON-REVERT: without the
/// limiter every call returns true and `rate_limited` stays 0, so the
/// `assert!(!allowed)` + counter assertion both fail.
#[test]
fn burst_beyond_capacity_is_rate_limited() {
    let _g = global_bucket_test_lock();
    let reason = GeneratedErrorReason::TimeExceeded;
    let t0 = 1_000_000_000u64;
    reset_bucket_for_test(reason, t0);
    let before = rate_limited_count(reason);
    // burst=5, rate=1000/s. At a frozen instant only 5 tokens are
    // available.
    for i in 0..5 {
        assert!(
            allow_generated_error_at(reason, t0, 1000, 5),
            "token {i} within burst must pass"
        );
    }
    // The 6th at the same instant: bucket empty → rate-limited.
    assert!(
        !allow_generated_error_at(reason, t0, 1000, 5),
        "beyond-burst generated error must be rate-limited"
    );
    assert_eq!(
        rate_limited_count(reason),
        before + 1,
        "the dropped generated error must bump the per-reason counter"
    );
}

/// Tokens refill over wall-clock time: after exhausting the burst, advancing
/// the clock by enough to accrue >= 1 token at the configured rate restores
/// capacity.
#[test]
fn refill_over_time_restores_capacity() {
    let _g = global_bucket_test_lock();
    let reason = GeneratedErrorReason::PacketTooBig;
    let t0 = 5_000_000_000u64;
    reset_bucket_for_test(reason, t0);
    // burst=2, rate=1000/s → one token accrues every 1ms.
    assert!(allow_generated_error_at(reason, t0, 1000, 2));
    assert!(allow_generated_error_at(reason, t0, 1000, 2));
    assert!(
        !allow_generated_error_at(reason, t0, 1000, 2),
        "burst exhausted at the frozen instant"
    );
    // Advance 2ms → 2 tokens refill (capped at burst=2).
    let t1 = t0 + 2_000_000;
    assert!(
        allow_generated_error_at(reason, t1, 1000, 2),
        "a token must be available after the refill interval elapses"
    );
    assert!(
        allow_generated_error_at(reason, t1, 1000, 2),
        "second refilled token available"
    );
    assert!(
        !allow_generated_error_at(reason, t1, 1000, 2),
        "refill is capped at the burst depth"
    );
}

/// Per-reason isolation: exhausting the TimeExceeded bucket must not affect
/// the Reject bucket. FAIL-ON-REVERT for a single-shared-bucket regression.
#[test]
fn reasons_are_isolated() {
    let _g = global_bucket_test_lock();
    let te = GeneratedErrorReason::TimeExceeded;
    let rj = GeneratedErrorReason::Reject;
    let t0 = 9_000_000_000u64;
    reset_bucket_for_test(te, t0);
    reset_bucket_for_test(rj, t0);
    // Drain TimeExceeded (burst=1).
    assert!(allow_generated_error_at(te, t0, 1000, 1));
    assert!(
        !allow_generated_error_at(te, t0, 1000, 1),
        "TimeExceeded exhausted"
    );
    // Reject is untouched — still has its own capacity.
    assert!(
        allow_generated_error_at(rj, t0, 1000, 1),
        "Reject bucket must be independent of TimeExceeded exhaustion"
    );
}

/// #2955 FAIL-ON-REVERT: under heavy multi-thread contention at a FROZEN
/// first-use instant, the limiter must admit AT MOST `burst` tokens — never
/// more — regardless of interleaving. The pre-#2955 split-atomic
/// implementation (CAS `millitokens`, then a SEPARATE relaxed `last_ns`
/// store) let every worker that read while `last_ns == 0` (the boot epoch)
/// take the first-use branch and force `refreshed = cap`, each granting
/// itself a full burst — admitting MORE than `burst` total (a torn
/// refill/double-credit). With the GCRA single-CAS word, refill and consume
/// commit together, so the admitted count is hard-capped at `burst`.
///
/// This mirrors the demonstrated race vector exactly: each trial starts from
/// `TokenBucket::new()` (TAT == 0, the boot/first-use state) and a start
/// barrier maximises the simultaneous-read window. Every call uses the SAME
/// frozen `now_ns`, so no real time elapses and the only legitimately
/// admissible tokens are the initial burst — any `total > burst` is the bug.
/// Verified RED against the split-atomic revert (admitted 51 > burst 50).
#[test]
fn concurrent_hammer_never_over_admits() {
    use std::sync::atomic::AtomicU64;
    use std::sync::{Arc, Barrier};
    use std::thread;

    let now = 100_000_000_000u64;
    let rate = 1000u64;
    let burst = 50u64;
    let threads = 16;
    let calls_per_thread = 200u64;

    for trial in 0..2000 {
        let bucket = Arc::new(TokenBucket::new()); // TAT == 0 (boot/first-use)
        let admitted = Arc::new(AtomicU64::new(0));
        let barrier = Arc::new(Barrier::new(threads));
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let bucket = Arc::clone(&bucket);
                let admitted = Arc::clone(&admitted);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..calls_per_thread {
                        if bucket.try_take(now, rate, burst) {
                            admitted.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let total = admitted.load(Ordering::Relaxed);
        assert!(
            total <= burst,
            "trial {trial}: at a frozen first-use instant the limiter must \
                 admit AT MOST the burst ({burst}); admitted {total} means a \
                 split-atomic double-credit over-admit (the #2955 race)"
        );
    }
}

/// #2955 deterministic atomicity guard: a single successful `try_take`
/// advances the WHOLE state word by exactly one interval. If the refill and
/// consume were ever split back into two atomics, a reader between them
/// could observe an inconsistent (consumed-but-not-timestamped) state. Here
/// we assert the GCRA invariant directly: from a full bucket at `now`, after
/// `burst` admissions the TAT is exactly `now + burst * interval`, and the
/// next admission is denied without further advancing the word.
#[test]
fn single_word_state_advances_atomically() {
    let now = 7_000_000_000u64;
    let rate = 1000u64; // interval = 1ms
    let burst = 8u64;
    let interval = NANOS_PER_SEC / rate;

    let bucket = TokenBucket::new();
    bucket.theoretical_arrival_ns.store(now, Ordering::Relaxed);

    for i in 0..burst {
        assert!(bucket.try_take(now, rate, burst), "burst token {i}");
        assert_eq!(
            bucket.theoretical_arrival_ns.load(Ordering::Relaxed),
            now + (i + 1) * interval,
            "each admit advances the single state word by exactly one \
                 interval — refill+consume committed together"
        );
    }
    // Bucket empty at the frozen instant.
    assert!(!bucket.try_take(now, rate, burst), "burst exhausted");
    assert_eq!(
        bucket.theoretical_arrival_ns.load(Ordering::Relaxed),
        now + burst * interval,
        "a denied call must NOT advance the state word"
    );
}

/// A zero rate disables the limiter (opt-out): always allowed, counter
/// never moves.
#[test]
fn zero_rate_disables_limiter() {
    let _g = global_bucket_test_lock();
    let reason = GeneratedErrorReason::Reject;
    let t0 = 12_000_000_000u64;
    reset_bucket_for_test(reason, t0);
    let before = rate_limited_count(reason);
    for _ in 0..10_000 {
        assert!(
            allow_generated_error_at(reason, t0, 0, 1),
            "rate 0 means unlimited"
        );
    }
    assert_eq!(
        rate_limited_count(reason),
        before,
        "a disabled limiter must never bump the rate-limited counter"
    );
}

use crate::afxdp::types::FastMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// Build a `ForwardingState` carrying a fresh per-zone Reject limiter for
/// each given zone id (#3618 test helper; #9901 F-074: limiters, not buckets).
fn forwarding_with_reject_zones(zone_ids: &[u16]) -> ForwardingState {
    let mut reject_buckets: FastMap<u16, Arc<ZoneLimiter>> = FastMap::default();
    for &id in zone_ids {
        reject_buckets.insert(id, Arc::new(ZoneLimiter::new()));
    }
    ForwardingState {
        reject_buckets,
        ..ForwardingState::default()
    }
}

/// #5856 test helper: build a `ForwardingState` carrying a fresh per-zone
/// limiter for EVERY reason (Reject, Time-Exceeded, Packet-Too-Big) for each
/// given zone id — the shape `populate_zones` produces for a configured zone.
fn forwarding_with_all_zone_buckets(zone_ids: &[u16]) -> ForwardingState {
    let mut reject_buckets: FastMap<u16, Arc<ZoneLimiter>> = FastMap::default();
    let mut time_exceeded_buckets: FastMap<u16, Arc<ZoneLimiter>> = FastMap::default();
    let mut packet_too_big_buckets: FastMap<u16, Arc<ZoneLimiter>> = FastMap::default();
    for &id in zone_ids {
        reject_buckets.insert(id, Arc::new(ZoneLimiter::new()));
        time_exceeded_buckets.insert(id, Arc::new(ZoneLimiter::new()));
        packet_too_big_buckets.insert(id, Arc::new(ZoneLimiter::new()));
    }
    ForwardingState {
        reject_buckets,
        time_exceeded_buckets,
        packet_too_big_buckets,
        ..ForwardingState::default()
    }
}

/// #9901 (F-074): test sources. Fixed documentation-range addresses; the
/// slot assertions never hardcode a layout (see `ZoneLimiter::slot_for_test`).
fn src_a() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
}
fn src_b() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))
}

/// #5856 HEADLINE fail-on-revert: a TTL=1/hop-limit=1 flood that drains ZONE
/// A's per-zone Time-Exceeded bucket must NOT prevent ZONE B from generating
/// its Time-Exceeded reply. Before #5856 TE used a SINGLE process-global
/// bucket, so draining A emptied the one shared bucket and B was then denied —
/// a cross-zone denial of the generated-error service. Reverting the per-zone
/// split (collapsing TE back to one global bucket, e.g. by making
/// `generated_error_bucket(TimeExceeded, _)` return `None`) makes this
/// assertion go RED. Direct proof of the #5856 per-zone isolation fix.
#[test]
fn time_exceeded_per_zone_flood_does_not_starve_other_zone_5856() {
    let _g = global_bucket_test_lock();
    let reason = GeneratedErrorReason::TimeExceeded;
    // Sparse, realistic stable-name-hash zone ids (NOT dense 1,2).
    let zone_a = 41_337u16;
    let zone_b = 9_002u16;
    let t0 = 3_100_000_000u64;
    let forwarding = forwarding_with_all_zone_buckets(&[zone_a, zone_b]);
    // Drain zone A at a frozen instant (burst = 4).
    for i in 0..4 {
        assert!(
            allow_generated_error_zoned_at(&forwarding, reason, zone_a, Some(src_a()), t0, 1000, 4),
            "zone A Time-Exceeded token {i} within burst must pass"
        );
    }
    assert!(
        !allow_generated_error_zoned_at(&forwarding, reason, zone_a, Some(src_a()), t0, 1000, 4),
        "zone A Time-Exceeded bucket must be drained after its burst"
    );
    // Zone B, under no load, still generates its Time-Exceeded at the SAME
    // instant — per-zone isolation.
    assert!(
        allow_generated_error_zoned_at(&forwarding, reason, zone_b, Some(src_b()), t0, 1000, 4),
        "zone B must NOT be starved by zone A's Time-Exceeded flood (per-zone isolation)"
    );
}

/// #5856 HEADLINE fail-on-revert (Packet-Too-Big sibling): an oversized-DF
/// flood that drains ZONE A's per-zone PTB bucket must NOT prevent ZONE B from
/// generating its PMTUD reply. Reverting to a single global PTB bucket makes
/// draining A suppress B → RED.
#[test]
fn packet_too_big_per_zone_flood_does_not_starve_other_zone_5856() {
    let _g = global_bucket_test_lock();
    let reason = GeneratedErrorReason::PacketTooBig;
    let zone_a = 41_337u16;
    let zone_b = 9_002u16;
    let t0 = 3_200_000_000u64;
    let forwarding = forwarding_with_all_zone_buckets(&[zone_a, zone_b]);
    for i in 0..4 {
        assert!(
            allow_generated_error_zoned_at(&forwarding, reason, zone_a, Some(src_a()), t0, 1000, 4),
            "zone A Packet-Too-Big token {i} within burst must pass"
        );
    }
    assert!(
        !allow_generated_error_zoned_at(&forwarding, reason, zone_a, Some(src_a()), t0, 1000, 4),
        "zone A Packet-Too-Big bucket must be drained after its burst"
    );
    assert!(
        allow_generated_error_zoned_at(&forwarding, reason, zone_b, Some(src_b()), t0, 1000, 4),
        "zone B must NOT be starved by zone A's oversized-DF flood (per-zone isolation)"
    );
}

/// #5856: an unzoned (id 0) or otherwise-unknown from-zone id has no per-zone
/// TE/PTB limiter, so the gate falls back to the reason's shared process-global
/// `*_FALLBACK_LIMITER` — a real limiter (never fail-open) that still rate-limits
/// and never panics on the absent key. Both an unknown id and id 0 SHARE the
/// one fallback budget.
#[test]
fn generated_error_unknown_and_unzoned_share_fallback_bucket_5856() {
    let _g = global_bucket_test_lock();
    for reason in [
        GeneratedErrorReason::TimeExceeded,
        GeneratedErrorReason::PacketTooBig,
    ] {
        let t0 = 6_100_000_000u64;
        // Reset the reason's fallback bucket (+ aggregate) to full at epoch t0.
        reset_bucket_for_test(reason, t0);
        // Empty map: every zone id resolves to the fallback.
        let forwarding = ForwardingState::default();
        let unknown = 55_555u16;
        // burst = 2 on the shared fallback: an unknown-id and an unzoned (id 0)
        // error each take one token; the third is denied.
        assert!(allow_generated_error_zoned_at(
            &forwarding,
            reason,
            unknown,
            None,
            t0,
            1000,
            2
        ));
        assert!(allow_generated_error_zoned_at(
            &forwarding,
            reason,
            0,
            None,
            t0,
            1000,
            2
        ));
        assert!(
            !allow_generated_error_zoned_at(&forwarding, reason, unknown, None, t0, 1000, 2),
            "unknown / unzoned {reason:?} errors share and are bounded by the fallback bucket"
        );
    }
}

/// #5856 metric-preservation fail-on-revert: the aggregate
/// `{time_exceeded,packet_too_big}_rate_limited_total` (a SINGLE global atomic
/// per reason, NOT a per-zone sum) is bumped on EVERY per-zone deny, so the
/// coordinator status / Prometheus contract is unchanged by the per-zone split.
/// Drain two zones by K1 and K2 and assert the aggregate advanced by exactly
/// K1 + K2.
#[test]
fn generated_error_aggregate_counter_sums_across_zones_5856() {
    let _g = global_bucket_test_lock();
    for reason in [
        GeneratedErrorReason::TimeExceeded,
        GeneratedErrorReason::PacketTooBig,
    ] {
        let t0 = 8_100_000_000u64;
        reset_bucket_for_test(reason, t0); // aggregate -> 0
        let zone_a = 111u16;
        let zone_b = 222u16;
        let forwarding = forwarding_with_all_zone_buckets(&[zone_a, zone_b]);
        let before = rate_limited_count(reason);
        let k1 = 3u64;
        let k2 = 5u64;
        // burst = 1 per zone: one pass, then K denies each.
        assert!(allow_generated_error_zoned_at(
            &forwarding,
            reason,
            zone_a,
            Some(src_a()),
            t0,
            1000,
            1
        ));
        for _ in 0..k1 {
            assert!(!allow_generated_error_zoned_at(
                &forwarding,
                reason,
                zone_a,
                Some(src_a()),
                t0,
                1000,
                1
            ));
        }
        assert!(allow_generated_error_zoned_at(
            &forwarding,
            reason,
            zone_b,
            Some(src_b()),
            t0,
            1000,
            1
        ));
        for _ in 0..k2 {
            assert!(!allow_generated_error_zoned_at(
                &forwarding,
                reason,
                zone_b,
                Some(src_b()),
                t0,
                1000,
                1
            ));
        }
        assert_eq!(
            rate_limited_count(reason),
            before + k1 + k2,
            "aggregate {reason:?} rate_limited_total must sum every per-zone deny (metric unchanged)"
        );
    }
}

/// #5856: the three reasons stay isolated from each other AND per-zone within a
/// reason. Draining zone A's Time-Exceeded bucket must not affect zone A's
/// Packet-Too-Big or Reject bucket (reason isolation), nor zone B's
/// Time-Exceeded (per-zone isolation).
#[test]
fn generated_error_reason_and_zone_isolation_5856() {
    let _g = global_bucket_test_lock();
    let zone_a = 700u16;
    let zone_b = 701u16;
    let t0 = 10_100_000_000u64;
    let forwarding = forwarding_with_all_zone_buckets(&[zone_a, zone_b]);
    // Drain zone A's Time-Exceeded bucket (burst = 1).
    assert!(allow_generated_error_zoned_at(
        &forwarding,
        GeneratedErrorReason::TimeExceeded,
        zone_a,
        Some(src_a()),
        t0,
        1000,
        1
    ));
    assert!(!allow_generated_error_zoned_at(
        &forwarding,
        GeneratedErrorReason::TimeExceeded,
        zone_a,
        Some(src_a()),
        t0,
        1000,
        1
    ));
    // Same zone, DIFFERENT reasons — untouched.
    assert!(
        allow_generated_error_zoned_at(
            &forwarding,
            GeneratedErrorReason::PacketTooBig,
            zone_a,
            Some(src_a()),
            t0,
            1000,
            1
        ),
        "zone A Packet-Too-Big must be independent of its Time-Exceeded exhaustion"
    );
    assert!(
        allow_generated_error_zoned_at(
            &forwarding,
            GeneratedErrorReason::Reject,
            zone_a,
            Some(src_a()),
            t0,
            1000,
            1
        ),
        "zone A Reject must be independent of its Time-Exceeded exhaustion"
    );
    // Different zone, SAME reason — untouched.
    assert!(
        allow_generated_error_zoned_at(
            &forwarding,
            GeneratedErrorReason::TimeExceeded,
            zone_b,
            Some(src_b()),
            t0,
            1000,
            1
        ),
        "zone B Time-Exceeded must be independent of zone A's exhaustion"
    );
}

/// #3618 HEADLINE fail-on-revert: a rejected-flow flood that drains ZONE A's
/// per-zone Reject bucket must NOT prevent ZONE B from generating its
/// reject. Reverting to a SINGLE global Reject bucket makes draining A empty
/// the one shared bucket, so B is then denied and this assertion goes RED.
/// This is the direct proof of the #3618 per-zone isolation fix — one
/// ingress zone can no longer starve another's reject-generation.
#[test]
fn reject_per_zone_flood_does_not_starve_other_zone_3618() {
    let _g = global_bucket_test_lock();
    // Sparse, realistic stable-name-hash zone ids (NOT dense 1,2).
    let zone_a = 41_337u16;
    let zone_b = 9_002u16;
    let t0 = 3_000_000_000u64;
    let forwarding = forwarding_with_reject_zones(&[zone_a, zone_b]);
    // Drain zone A at a frozen instant (burst = 4).
    for i in 0..4 {
        assert!(
            allow_generated_reject_at(&forwarding, zone_a, Some(src_a()), t0, 1000, 4),
            "zone A token {i} within burst must pass"
        );
    }
    assert!(
        !allow_generated_reject_at(&forwarding, zone_a, Some(src_a()), t0, 1000, 4),
        "zone A bucket must be drained after its burst"
    );
    // Zone B, under no load, still generates its reject at the SAME instant.
    assert!(
        allow_generated_reject_at(&forwarding, zone_b, Some(src_b()), t0, 1000, 4),
        "zone B must NOT be starved by zone A's flood (per-zone isolation)"
    );
}

/// #3618: an unzoned (id 0) or otherwise-unknown from-zone id has no
/// per-zone limiter, so the gate falls back to the shared process-global
/// `REJECT_FALLBACK_LIMITER` — a real limiter (never fail-open) that still
/// rate-limits and never panics on the absent key. Both an unknown id and
/// id 0 SHARE the one fallback budget.
#[test]
fn reject_unknown_and_unzoned_share_fallback_bucket_3618() {
    let _g = global_bucket_test_lock();
    let t0 = 6_000_000_000u64;
    // Reset the fallback bucket (+ aggregate) to full at epoch t0.
    reset_bucket_for_test(GeneratedErrorReason::Reject, t0);
    // Empty map: every zone id resolves to the fallback.
    let forwarding = ForwardingState::default();
    let unknown = 55_555u16;
    // burst = 2 on the shared fallback: an unknown-id reject and an
    // unzoned (id 0) reject each take one token; the third is denied.
    assert!(allow_generated_reject_at(&forwarding, unknown, None, t0, 1000, 2));
    assert!(allow_generated_reject_at(&forwarding, 0, None, t0, 1000, 2));
    assert!(
        !allow_generated_reject_at(&forwarding, unknown, None, t0, 1000, 2),
        "unknown / unzoned rejects share and are bounded by the fallback bucket"
    );
}

/// #3618 metric-preservation fail-on-revert: the aggregate
/// `reject_rate_limited_total` (a SINGLE global atomic, NOT a per-zone sum)
/// is bumped on EVERY per-zone deny, so the coordinator status / Prometheus
/// contract is unchanged by the per-zone split. Drain two zones by K1 and K2
/// and assert the aggregate advanced by exactly K1 + K2.
#[test]
fn reject_aggregate_counter_sums_across_zones_3618() {
    let _g = global_bucket_test_lock();
    let t0 = 8_000_000_000u64;
    reset_bucket_for_test(GeneratedErrorReason::Reject, t0); // aggregate -> 0
    let zone_a = 111u16;
    let zone_b = 222u16;
    let forwarding = forwarding_with_reject_zones(&[zone_a, zone_b]);
    let before = rate_limited_count(GeneratedErrorReason::Reject);
    let k1 = 3u64;
    let k2 = 5u64;
    // burst = 1 per zone: one pass, then K denies each.
    assert!(allow_generated_reject_at(&forwarding, zone_a, Some(src_a()), t0, 1000, 1));
    for _ in 0..k1 {
        assert!(!allow_generated_reject_at(&forwarding, zone_a, Some(src_a()), t0, 1000, 1));
    }
    assert!(allow_generated_reject_at(&forwarding, zone_b, Some(src_b()), t0, 1000, 1));
    for _ in 0..k2 {
        assert!(!allow_generated_reject_at(&forwarding, zone_b, Some(src_b()), t0, 1000, 1));
    }
    assert_eq!(
        rate_limited_count(GeneratedErrorReason::Reject),
        before + k1 + k2,
        "aggregate reject_rate_limited_total must sum every per-zone deny (metric unchanged)"
    );
}

/// #3618: per-zone Reject buckets stay isolated from the TimeExceeded /
/// PacketTooBig reasons (reason isolation, #2472). Draining a zone's Reject
/// bucket must not affect the TE/PTB global buckets, and vice-versa.
#[test]
fn reject_per_zone_isolated_from_other_reasons_3618() {
    let _g = global_bucket_test_lock();
    let t0 = 10_000_000_000u64;
    reset_bucket_for_test(GeneratedErrorReason::TimeExceeded, t0);
    let zone_a = 700u16;
    let forwarding = forwarding_with_reject_zones(&[zone_a]);
    // Drain zone A's Reject bucket (burst = 1).
    assert!(allow_generated_reject_at(&forwarding, zone_a, Some(src_a()), t0, 1000, 1));
    assert!(!allow_generated_reject_at(&forwarding, zone_a, Some(src_a()), t0, 1000, 1));
    // TimeExceeded (a different reason, global bucket) is untouched.
    assert!(
        allow_generated_error_at(GeneratedErrorReason::TimeExceeded, t0, 1000, 1),
        "TE bucket must be independent of a zone's Reject exhaustion"
    );
}

/// #9901 (F-074): probe documentation-range addresses for `n` sources in
/// DISTINCT limiter slots. Seed-adaptive (probes via `slot_for_test`), so it
/// never hardcodes a seed-dependent layout.
fn distinct_slot_sources(n: usize) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for i in 0..10_000 {
        let addr = IpAddr::V4(Ipv4Addr::new(
            192,
            0,
            ((i / 250) % 250) as u8,
            (i % 250 + 1) as u8,
        ));
        let slot = ZoneLimiter::slot_for_test(&addr);
        if seen.insert(slot) {
            out.push(addr);
            if out.len() == n {
                return out;
            }
        }
    }
    panic!("could not find {n} distinct-slot sources in 10000 probes");
}

/// #9901 (F-074): probe for a second source colliding with `anchor`'s slot.
fn colliding_source(anchor: &IpAddr) -> IpAddr {
    let want = ZoneLimiter::slot_for_test(anchor);
    for i in 1..10_000 {
        let addr = IpAddr::V4(Ipv4Addr::new(
            198,
            51,
            ((i / 250) % 250) as u8,
            (i % 250 + 1) as u8,
        ));
        if &addr != anchor && ZoneLimiter::slot_for_test(&addr) == want {
            return addr;
        }
    }
    panic!("could not find a colliding source in 10000 probes");
}

/// #9901 (F-074) seed-math pin: 192.0.2.1 and 192.0.2.65 differ ONLY above
/// the low 6 address bits, and 2001:db8::1 vs 2001:db8:1::1 differ only in
/// the high half. The pre-fix multiply-only mix mapped the slot from mod-64
/// of a product — which sees only the low 6 factors — so the v4 pair shared
/// a slot under EVERY seed and one source could drain the other's bucket
/// (the `distinct_slot_sources` probe above silently avoided the shape
/// instead of testing it). After diffusion the slot is a function of the
/// whole address: each pair must separate under most seeds. Deterministic
/// (fixed mix, swept seeds) with a huge margin: diffusion separates
/// ~252/256; the old math separated 0/256 (v4) — verified by revert.
#[test]
fn low_bit_neighbors_separate_under_most_seeds_9901() {
    for (a, b) in [
        (
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 65)),
        ),
        (
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1)),
        ),
    ] {
        let mut separated = 0u32;
        for seed in 0..256u64 {
            if slot_and_tag(seed, &a).0 != slot_and_tag(seed, &b).0 {
                separated += 1;
            }
        }
        assert!(
            separated > 200,
            "diffused slots must separate {a} vs {b} under most seeds (got {separated}/256)"
        );
    }
}

/// #9901 (F-074) HEADLINE fail-on-revert: one source flooding a zone must NOT
/// starve another source in the SAME zone. A attempts 1000 errors at a frozen
/// instant against a zone aggregate of burst 1000: exactly its 100-token
/// source budget passes, the other 900 are source-denied (and counted), and
/// B — idle until now — still passes. Before F-074 the zone held a single
/// bucket, so A's 1000 attempts drained the whole zone budget and B was
/// denied → RED. Severing the source tier (all to the aggregate) reds this
/// the same way.
#[test]
fn per_source_flood_does_not_starve_other_source_9901() {
    let _g = global_bucket_test_lock();
    let reason = GeneratedErrorReason::Reject;
    let zone = 41_337u16;
    let t0 = 13_100_000_000u64;
    reset_bucket_for_test(reason, t0); // aggregate -> 0
    let forwarding = forwarding_with_reject_zones(&[zone]);
    let pair = distinct_slot_sources(2);
    let (a, b) = (pair[0], pair[1]);
    let mut passed = 0u32;
    for _ in 0..1000 {
        if allow_generated_reject_at(&forwarding, zone, Some(a), t0, 1000, 1000) {
            passed += 1;
        }
    }
    assert_eq!(
        passed, 100,
        "one source is capped at its 100-token source budget, not the zone aggregate"
    );
    assert_eq!(
        rate_limited_count(reason),
        900,
        "the 900 source-denied errors must still be counted (metric unchanged)"
    );
    assert!(
        allow_generated_reject_at(&forwarding, zone, Some(b), t0, 1000, 1000),
        "source B must NOT be starved by source A's flood (per-source fairness)"
    );
}

/// #9901 (F-074): the zone aggregate still caps the zone as a whole — five
/// FRESH sources against a zone burst of 4 admit exactly 4; the 5th is
/// aggregate-denied. Per-source fairness must not become per-source
/// entitlement that multiplies the zone cap by the source count. Removing
/// the aggregate check reds this (all 5 pass).
#[test]
fn zone_aggregate_cap_survives_many_sources_9901() {
    let _g = global_bucket_test_lock();
    let reason = GeneratedErrorReason::TimeExceeded;
    let zone = 9_002u16;
    let t0 = 13_200_000_000u64;
    let forwarding = forwarding_with_all_zone_buckets(&[zone]);
    let sources = distinct_slot_sources(5);
    for (i, src) in sources.iter().enumerate().take(4) {
        assert!(
            allow_generated_error_zoned_at(&forwarding, reason, zone, Some(*src), t0, 1000, 4),
            "fresh source {i} within the zone burst must pass"
        );
    }
    assert!(
        !allow_generated_error_zoned_at(&forwarding, reason, zone, Some(sources[4]), t0, 1000, 4),
        "the 5th fresh source must be aggregate-denied against a zone burst of 4"
    );
}

/// #9901 (F-074): two sources colliding in ONE slot share that slot's
/// sustained rate — 200 alternating attempts at a frozen instant admit
/// exactly the 100-token slot budget. No takeover reset, no per-source
/// entitlement within a slot: colliders split one budget. Routing each
/// attempt to a fresh slot reds this (all 200 pass).
#[test]
fn colliding_sources_share_one_slot_budget_9901() {
    let _g = global_bucket_test_lock();
    let reason = GeneratedErrorReason::PacketTooBig;
    let zone = 7_700u16;
    let t0 = 13_300_000_000u64;
    let forwarding = forwarding_with_all_zone_buckets(&[zone]);
    let a = src_a();
    let b = colliding_source(&a);
    assert_eq!(
        ZoneLimiter::slot_for_test(&a),
        ZoneLimiter::slot_for_test(&b),
        "test setup: the pair must collide"
    );
    let mut passed = 0u32;
    for i in 0..200 {
        let src = if i % 2 == 0 { a } else { b };
        if allow_generated_error_zoned_at(&forwarding, reason, zone, Some(src), t0, 1000, 1000) {
            passed += 1;
        }
    }
    assert_eq!(
        passed, 100,
        "colliding sources share one 100-token slot budget"
    );
}

/// #9901 (F-074): an unzoned/unknown zone resolves to the fallback LIMITER
/// (not a bare bucket), so per-source fairness holds there too: A spends its
/// 100-token source budget, is then source-denied, and idle B still passes —
/// all against the shared fallback aggregate. Collapsing the fallback to a
/// single bucket reds this (A drains the burst, B denied).
#[test]
fn fallback_limiter_keeps_per_source_fairness_9901() {
    let _g = global_bucket_test_lock();
    let reason = GeneratedErrorReason::Reject;
    let t0 = 13_400_000_000u64;
    reset_bucket_for_test(reason, t0);
    let forwarding = ForwardingState::default();
    let unknown = 55_555u16;
    let pair = distinct_slot_sources(2);
    let (a, b) = (pair[0], pair[1]);
    for i in 0..100 {
        assert!(
            allow_generated_reject_at(&forwarding, unknown, Some(a), t0, 1000, 1000),
            "fallback source token {i} within budget must pass"
        );
    }
    assert!(
        !allow_generated_reject_at(&forwarding, unknown, Some(a), t0, 1000, 1000),
        "source A must be source-denied past its 100-token budget"
    );
    assert!(
        allow_generated_reject_at(&forwarding, unknown, Some(b), t0, 1000, 1000),
        "source B must NOT be starved by source A on the fallback limiter"
    );
}

/// #9901 (F-074) gate-order pin (#5567 applied to the tier order): a
/// source-deny consumes NOTHING shared. A drains its 100-token source
/// budget; 50 further A attempts are all denied WITHOUT moving the zone
/// aggregate's TAT; B then passes and advances it by exactly one interval.
/// Consuming the aggregate BEFORE the source tier reds this (the 50 denies
/// move the TAT).
#[test]
fn source_deny_consumes_no_aggregate_token_9901() {
    let _g = global_bucket_test_lock();
    let reason = GeneratedErrorReason::TimeExceeded;
    let zone = 8_800u16;
    let t0 = 13_500_000_000u64;
    let forwarding = forwarding_with_all_zone_buckets(&[zone]);
    let limiter = forwarding
        .generated_error_bucket(reason, zone)
        .expect("per-zone limiter");
    let pair = distinct_slot_sources(2);
    let (a, b) = (pair[0], pair[1]);
    for _ in 0..100 {
        assert!(allow_generated_error_zoned_at(
            &forwarding,
            reason,
            zone,
            Some(a),
            t0,
            1000,
            1000
        ));
    }
    let arrival_after_budget = limiter.aggregate_arrival_ns();
    assert_ne!(
        arrival_after_budget, 0,
        "the 100 admissions must have advanced the aggregate TAT"
    );
    for _ in 0..50 {
        assert!(!allow_generated_error_zoned_at(
            &forwarding,
            reason,
            zone,
            Some(a),
            t0,
            1000,
            1000
        ));
    }
    assert_eq!(
        limiter.aggregate_arrival_ns(),
        arrival_after_budget,
        "50 source-denied errors must not move the shared aggregate TAT"
    );
    assert!(allow_generated_error_zoned_at(
        &forwarding,
        reason,
        zone,
        Some(b),
        t0,
        1000,
        1000
    ));
    assert_eq!(
        limiter.aggregate_arrival_ns(),
        arrival_after_budget + 1_000_000,
        "B's admission advances the aggregate by exactly one 1000/s interval"
    );
}
