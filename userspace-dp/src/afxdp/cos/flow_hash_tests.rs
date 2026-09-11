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
    // pre-session packet) must still produce a valid bucket. All keyless
    // items share ONE dedicated SFQ lane rather than splaying across the
    // ring and inflating active_flow_buckets — the reserved keyless
    // bucket, independent of the queue seed.
    assert_eq!(cos_flow_bucket_index(0, None), COS_FLOW_FAIR_KEYLESS_BUCKET);
    assert_eq!(
        cos_flow_bucket_index(0x1234_5678_9abc_def0, None),
        COS_FLOW_FAIR_KEYLESS_BUCKET
    );
}

#[test]
fn keyless_lane_is_reserved_from_real_flows() {
    // #hb166 T-7: no real 5-tuple flow may land on the reserved keyless
    // SFQ lane, so keyless traffic never dilutes a real flow's fair
    // share. Pre-fix, real flows masked into the keyless bucket with
    // probability 1/COS_FLOW_FAIR_BUCKETS, so scanning this many
    // (seed, flow) pairs is virtually certain to hit it on the un-fixed
    // code (RED-on-revert); the fix steers every such flow off the
    // reserved bucket onto the fallback lane.
    let mut real_flows_on_reserved = 0usize;
    for seed in 0u64..64 {
        for port in 0u16..2048 {
            let flow = test_session_key(10_000 + port, 5201);
            if cos_flow_bucket_index(seed, Some(&flow)) == COS_FLOW_FAIR_KEYLESS_BUCKET {
                real_flows_on_reserved += 1;
            }
        }
    }
    assert_eq!(
        real_flows_on_reserved, 0,
        "a real 5-tuple flow landed on the reserved keyless SFQ bucket {} \
         ({} of 131072 scanned flows)",
        COS_FLOW_FAIR_KEYLESS_BUCKET, real_flows_on_reserved
    );
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

// #9645: a key that differs from another ONLY by routing domain or ONLY by
// tunnel discriminator is a different session, and must not share a flow-fair
// bucket by construction. Before the fix such keys hashed identically for EVERY
// seed, so this scan can never find a separating seed on the reverted code; on
// the fixed code a chance collision survives 256 independent seeds with
// probability about (1/4096)^256.
fn first_separating_seed_9645(a: &SessionKey, b: &SessionKey) -> Option<u64> {
    (0u64..256).find(|&seed| {
        cos_flow_bucket_index(seed, Some(a)) != cos_flow_bucket_index(seed, Some(b))
    })
}

#[test]
fn flow_fair_bucket_separates_identical_tuples_in_different_routing_domains_9645() {
    let default_domain = test_session_key(9000, 5201);
    let mut tenant_a = default_domain.clone();
    tenant_a.routing_domain = 0x5a5a_0001;
    let mut tenant_b = default_domain.clone();
    tenant_b.routing_domain = 0x5a5a_0002;
    // Two ids that differ only in their upper half: FNV-1a ids are 32-bit, so
    // this is a real shape, and a single mix of the whole u32 cannot see it.
    let mut high_a = default_domain.clone();
    high_a.routing_domain = 0x0001_0000;
    let mut high_b = default_domain.clone();
    high_b.routing_domain = 0x0002_0000;
    for (label, a, b) in [
        ("default vs tenant", &default_domain, &tenant_a),
        ("tenant vs tenant", &tenant_a, &tenant_b),
        ("upper-half-only ids", &high_a, &high_b),
    ] {
        assert!(
            first_separating_seed_9645(a, b).is_some(),
            "{label}: identical 5-tuples in different routing domains share one flow-fair bucket for every seed"
        );
    }
}

#[test]
fn flow_fair_bucket_separates_tunnel_discriminators_9645() {
    let mut base = test_session_key(0, 0);
    base.protocol = 47; // GRE: no L4 ports, the discriminator is the identity.
    let classes = [
        TunnelDiscriminator::None,
        TunnelDiscriminator::Unkeyed,
        TunnelDiscriminator::Keyed(1),
        TunnelDiscriminator::Keyed(2),
        TunnelDiscriminator::Keyed(0x0001_0000),
        TunnelDiscriminator::Keyed(0x0002_0000),
        TunnelDiscriminator::Pptp(1),
        TunnelDiscriminator::Unparseable,
    ];
    for (i, da) in classes.iter().enumerate() {
        for db in &classes[i + 1..] {
            let mut a = base.clone();
            a.discriminator = *da;
            let mut b = base.clone();
            b.discriminator = *db;
            assert!(
                first_separating_seed_9645(&a, &b).is_some(),
                "GRE keys differing only by discriminator ({da:?} vs {db:?}) share one flow-fair bucket for every seed"
            );
        }
    }
}

/// The pre-#9645 bucket function, kept verbatim so the cell below can prove
/// the default key space did not move.
fn legacy_exact_cos_flow_bucket_9645(queue_seed: u64, flow_key: &SessionKey) -> u16 {
    let mut seed = queue_seed ^ (flow_key.protocol as u64) ^ ((flow_key.addr_family as u64) << 8);
    for ip in [flow_key.src_ip, flow_key.dst_ip] {
        match ip {
            IpAddr::V4(ip) => mix_cos_flow_bucket(&mut seed, u32::from(ip) as u64),
            IpAddr::V6(ip) => {
                for chunk in ip.octets().chunks_exact(8) {
                    mix_cos_flow_bucket(&mut seed, u64::from_be_bytes(chunk.try_into().unwrap()));
                }
            }
        }
    }
    mix_cos_flow_bucket(&mut seed, flow_key.src_port as u64);
    mix_cos_flow_bucket(&mut seed, flow_key.dst_port as u64);
    seed as u16
}

#[test]
fn flow_fair_bucket_is_unchanged_for_default_domain_without_discriminator_9645() {
    let mut v6 = test_session_key(0, 443);
    v6.src_ip = IpAddr::V6("2001:db8::10".parse().unwrap());
    v6.dst_ip = IpAddr::V6("2001:db8::20".parse().unwrap());
    v6.addr_family = libc::AF_INET6 as u8;
    for seed in [0u64, 1, 0x9e37_79b9_7f4a_7c15, u64::MAX] {
        for port in 0u16..512 {
            let v4 = test_session_key(20_000 + port, 5201);
            let mut v6p = v6.clone();
            v6p.src_port = 30_000 + port;
            for key in [&v4, &v6p] {
                assert_eq!(
                    exact_cos_flow_bucket(seed, Some(key)),
                    legacy_exact_cos_flow_bucket_9645(seed, key),
                    "the default routing domain with no discriminator must keep the pre-#9645 bucket (seed {seed:#x}, key {key:?})"
                );
            }
        }
    }
}

