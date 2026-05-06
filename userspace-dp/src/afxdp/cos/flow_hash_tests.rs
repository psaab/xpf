// Tests for afxdp/cos/flow_hash.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep flow_hash.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "flow_hash_tests.rs"]` from flow_hash.rs.

use super::*;
use crate::afxdp::tx::test_support::*;
use crate::afxdp::types::COS_FLOW_FAIR_BUCKETS;

#[test]
fn exact_cos_flow_bucket_is_stable_for_same_seed_and_flow() {
    // Required property (#693): determinism inside one runtime instance.
    // Enqueue/dequeue bucket accounting would break if the same flow key
    // hashed to different buckets between push and pop. One random seed
    // drawn from the OS, same 5-tuple in, same bucket out, every time.
    let flow = test_session_key(9000, 5201);
    let seed = cos_flow_hash_seed_from_os();
    let first = cos_flow_bucket_index(seed, Some(&flow));
    for _ in 0..4096 {
        assert_eq!(first, cos_flow_bucket_index(seed, Some(&flow)));
    }
}

#[test]
fn exact_cos_flow_bucket_diverges_across_seeds_for_same_flow() {
    // Required property (#693): the bucket mapping is not an externally-
    // probeable pure function of the 5-tuple. Two queues with different
    // seeds must be able to send the same flow into different buckets.
    // A deterministic hash would make this test a tautology that always
    // fails, so we scan seeds until we find a divergence; with the
    // 4096-bucket output, collision rate is ~1/4096 per seed pair, so
    // 8191 attempts is well below any reasonable flake tolerance
    // (collision probability ≈ (1/4096)^8191 if the hash were uniform).
    let flow = test_session_key(9000, 5201);
    let reference = cos_flow_bucket_index(0, Some(&flow));
    let mut saw_divergence = false;
    for seed in 1u64..8192u64 {
        if cos_flow_bucket_index(seed, Some(&flow)) != reference {
            saw_divergence = true;
            break;
        }
    }
    assert!(
        saw_divergence,
        "hash must diverge across seeds; seed is not being mixed into the bucket function"
    );
}

#[test]
fn exact_cos_flow_bucket_preserves_legacy_behavior_at_zero_seed() {
    // Required property (#693): preserve existing behavior for queues
    // with a zero seed. The pre-seed hash initialized `seed = protocol ^
    // (addr_family << 8)`; the seeded hash initializes `seed = queue_seed
    // ^ protocol ^ (addr_family << 8)`. At `queue_seed = 0` the two are
    // byte-identical. Pin this so a future refactor that reorders the
    // mix cannot silently change the bucket mapping under zero seed.
    let flow_v4 = test_session_key(1111, 5201);
    let mut flow_v6 = test_session_key(2222, 5201);
    flow_v6.src_ip = IpAddr::V6("2001:db8::1".parse().unwrap());
    flow_v6.dst_ip = IpAddr::V6("2001:db8::2".parse().unwrap());
    flow_v6.addr_family = libc::AF_INET6 as u8;
    let b_v4 = cos_flow_bucket_index(0, Some(&flow_v4));
    let b_v6 = cos_flow_bucket_index(0, Some(&flow_v6));
    // #711 + GEMINI-NEXT.md fairness: hash-mix regression pins,
    // updated for the bucket-count grow 1024 → 4096. The hash
    // function itself is unchanged at seed=0; the values move only
    // because the mask widens from 10 bits (0x3FF) to 12 bits
    // (0xFFF). Under the original 6-bit (64-bucket) mask these were
    // 26 (v4) and 4 (v6); under the 10-bit (1024-bucket) mask they
    // were 410 and 260; under the new 12-bit (4096-bucket) mask
    // they are 410 (unchanged — its bits 10/11 are zero) and 1284
    // (= 260 + 1024).
    // A refactor that reorders the mix or adds a term still fails
    // here and becomes an explicit decision. Update baselines only
    // after live re-validation of 5201 fairness on the loss HA
    // cluster.
    // Sanity: low 6 bits of the new pins equal the old pins
    // (26 and 4 respectively), confirming the mask-widening
    // interpretation above.
    assert_eq!(b_v4 & 0x3F, 26);
    assert_eq!(b_v6 & 0x3F, 4);
    assert_eq!(b_v4, 410);
    assert_eq!(b_v6, 1284);
}

#[test]
fn exact_cos_flow_bucket_handles_missing_flow_key() {
    // An item without a flow_key (e.g. a non-TCP/UDP frame, or a
    // pre-session packet) must still produce a valid bucket. Pick
    // bucket 0 deterministically so these items share one SFQ lane
    // rather than splaying across the ring and inflating
    // active_flow_buckets.
    assert_eq!(cos_flow_bucket_index(0, None), 0);
    assert_eq!(cos_flow_bucket_index(0x1234_5678_9abc_def0, None), 0);
}

#[test]
fn exact_cos_flow_bucket_distribution_keeps_collisions_below_budget() {
    // #711 correctness pin. The whole point of growing buckets
    // 64 → 1024 → 4096 is collision reduction. A hash-mix regression
    // can produce acceptable distribution on one seed while
    // clustering badly under others; a single-seed test is too easy
    // to accidentally satisfy. Exercise multiple deterministic seeds
    // and mix v4/v6 tuples so the guarantee covers a realistic
    // traffic shape.
    //
    // Theoretical baseline for 64 uniform flows into 4096 buckets:
    // E[colliding pairs] ≈ 64·63/(2·4096) ≈ 0.49 — so ~63-64
    // distinct buckets on average. A budget of 58/64 per seed is
    // very conservative under a uniform-hash null hypothesis;
    // if this test fires, the hash function has become materially
    // non-uniform and the fairness guarantee is silently gone.
    use std::collections::BTreeSet;

    let seeds: [u64; 3] = [0, 0xA5A5_0000_C3C3_FFFF, 0x0123_4567_89AB_CDEF];
    for &seed in &seeds {
        let mut buckets = BTreeSet::new();
        for i in 0..64u16 {
            let mut flow = test_session_key(10_000 + i, 5201);
            // Alternate between v4 and v6 tuples so the test
            // exercises both address-family branches of the hash.
            if i & 1 == 1 {
                flow.addr_family = libc::AF_INET6 as u8;
                let v6 = format!("2001:db8::{i:x}")
                    .parse::<std::net::Ipv6Addr>()
                    .expect("v6 literal");
                flow.src_ip = IpAddr::V6(v6);
                flow.dst_ip = IpAddr::V6(
                    "2001:db8::5201"
                        .parse::<std::net::Ipv6Addr>()
                        .expect("v6 literal"),
                );
            }
            buckets.insert(cos_flow_bucket_index(seed, Some(&flow)));
        }
        assert!(
            buckets.len() >= 58,
            "seed={:#x}: 64 flows landed in only {} distinct buckets — \
             hash distribution regressed",
            seed,
            buckets.len()
        );
        assert!(
            buckets.iter().all(|&b| b < COS_FLOW_FAIR_BUCKETS),
            "bucket index out of range after mask: seed={seed:#x}"
        );
    }
}

/// #784 regression pin: narrow-input flow distribution.
///
/// The iperf3-style workload hits an SFQ bucket collision
/// cliff that the mixed-v4/v6 distribution test above misses:
/// 12 flows to the same (src_ip, dst_ip, dst_port, proto,
/// addr_family) differing only in src_port (consecutive
/// ephemeral range, all v4 TCP). Real-world iperf3 reports
/// 3 flows at ~145 Mbps with 0 retrans and 9 flows at
/// ~60 Mbps with thousands of retrans each — caused by
/// multiple flows landing on the same SFQ bucket and having
/// their flow_share caps shrunk (each bucket's share = total
/// buffer / prospective_active_flows, halved/thirded if a
/// bucket holds 2-3 flows).
///
/// Budget: for 12 narrow-input flows in 4096 buckets under a
/// good hash, E[colliding pairs] ≈ 12*11/(2*4096) ≈ 0.016 —
/// essentially always 12 distinct buckets. Under the prior
/// boost-style hash_combine, narrow inputs observably collapse
/// to 3-6 distinct buckets across most seeds. Demand >=11
/// distinct buckets (allowing one pair collision worst-case
/// under uniform null).
///
/// Adversarial review posture: if this test ever weakens to
/// accept fewer distinct buckets, or drops the all-v4 shape,
/// the iperf3 fairness regression WILL return silently.
#[test]
fn exact_cos_flow_bucket_distribution_narrow_inputs_all_v4() {
    use std::collections::BTreeSet;

    // Production-like ephemeral port range. Linux kernel's
    // default ephemeral range is 32768-60999; 12 consecutive
    // ports starting at 39754 matches the actual iperf3
    // capture that motivated this test.
    let ports: Vec<u16> = (39754..39754 + 12).collect();
    // Test multiple seeds so a hash-mix fix cannot pass by
    // accident on a lucky seed. Including 0 pins the
    // pre-flow-fair default.
    let seeds: [u64; 5] = [
        0,
        0xA5A5_0000_C3C3_FFFF,
        0x0123_4567_89AB_CDEF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xDEAD_BEEF_CAFE_BABE,
    ];
    for &seed in &seeds {
        let mut buckets = BTreeSet::new();
        for port in &ports {
            let flow = test_session_key(*port, 5201);
            // Explicitly v4 TCP — no mixed-family shortcut.
            assert_eq!(flow.addr_family, libc::AF_INET as u8);
            buckets.insert(cos_flow_bucket_index(seed, Some(&flow)));
        }
        assert!(
            buckets.len() >= 11,
            "seed={:#x}: 12 all-v4 iperf3-style flows landed in only {} distinct \
             buckets — SFQ fairness regression. This is the flow-spread bug from #784; \
             if this fires, the hash function is not spreading narrow-variance inputs \
             (identical src_ip/dst_ip/dst_port/proto/family, only src_port differs).",
            seed,
            buckets.len()
        );
    }
}

/// #784 companion: also pin the wider 12-flow case with
/// non-consecutive src_ports (simulating a different
/// ephemeral-port allocator or long-running connections
/// from different source processes).
#[test]
fn exact_cos_flow_bucket_distribution_narrow_inputs_scattered_ports() {
    use std::collections::BTreeSet;
    // 12 src_ports scattered across the ephemeral range.
    let ports: [u16; 12] = [
        33000, 35719, 38112, 41003, 43517, 46281, 48907, 51214, 53841, 56118, 58792, 60999,
    ];
    let seeds: [u64; 3] = [0, 0xA5A5_0000_C3C3_FFFF, 0x0123_4567_89AB_CDEF];
    for &seed in &seeds {
        let mut buckets = BTreeSet::new();
        for port in &ports {
            let flow = test_session_key(*port, 5201);
            buckets.insert(cos_flow_bucket_index(seed, Some(&flow)));
        }
        assert!(
            buckets.len() >= 11,
            "seed={:#x}: 12 scattered all-v4 flows landed in only {} distinct \
             buckets — SFQ hash regression on non-consecutive src_ports",
            seed,
            buckets.len()
        );
    }
}

#[test]
fn cos_flow_hash_seed_from_os_never_returns_zero() {
    // Regression guard for the API contract: cos_flow_hash_seed_from_os
    // remaps a zero entropy draw to 1, so every call must return a
    // non-zero seed regardless of source (getrandom(2) or fallback).
    // Four independent draws is a generous lower bound on call paths
    // exercised; the per-call invariant is the load-bearing one.
    for _ in 0..4 {
        assert_ne!(
            cos_flow_hash_seed_from_os(),
            0,
            "seed source returned 0 despite zero-to-one remapping"
        );
    }
}
