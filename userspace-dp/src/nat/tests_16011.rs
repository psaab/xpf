//! #16011: RFC 6056 keyed PAT port selection regression tests.
//!
//! Pre-fix, fresh PAT ports were handed out in ascending order from a
//! shared monotonic cursor (`fetch_add % range` / CAS cursor), the
//! interface PAT walk started at a shared round-robin counter, and the
//! deterministic block probe always claimed the lowest free port — so
//! an observer of one translated port (e.g. a colluding server) could
//! predict the next. These tests pin the keyed behaviour with seeded
//! cores (deterministic, no reliance on the per-boot secret's value):
//!   * same tuple + same secret => same first candidate (stability);
//!   * varied tuples => ports spread over the range, not +1 steps;
//!   * wrong secret => different mapping (prediction requires secret);
//!   * bounded probe still finds the sole free port and fails closed
//!     (None / AllocatorExhausted) only when genuinely full;
//!   * concurrent claims never duplicate a port.
//! Reverting to sequential allocation makes the spread/secret tests
//! fail: sequential claims are exactly port_low, port_low+1, ...

use super::allocator::{
    PoolAddressFamily, PortAllocator, pat_keyed_offset_for_test as pat_keyed_offset,
    pat_mix_for_test as pat_mix,
};
use super::source::{PersistentNatPermit, SourceNatFlowKey};
use super::*;
use std::net::{IpAddr, Ipv4Addr};

fn flow(src_port: u16, dst_port: u16) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: 17,
        src_ip: "10.0.1.100".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port,
        dst_port,
        routing_scope: 0,
    }
}

#[test]
fn pat_keyed_offset_is_stable_and_secret_dependent_16011() {
    // Stability: identical (secret, key, range) always yields the same offset.
    for key in [0u64, 1, 42, u64::MAX] {
        assert_eq!(
            pat_keyed_offset(0x5EED, key, 64512),
            pat_keyed_offset(0x5EED, key, 64512)
        );
        assert!(pat_keyed_offset(0x5EED, key, 64512) < 64512);
    }
    // Secret dependence: over many keys, a different secret must move
    // most mappings — an observer without the secret cannot predict.
    let moved = (0..1000u64)
        .filter(|&k| pat_keyed_offset(0xAAAA, k, 64512) != pat_keyed_offset(0xBBBB, k, 64512))
        .count();
    assert!(
        moved > 900,
        "changing the secret must remap >90% of keys, moved {moved}/1000"
    );
    // Range edge cases fail closed (0), never panic / out of range.
    assert_eq!(pat_keyed_offset(1, 1, 0), 0);
    assert_eq!(pat_keyed_offset(1, 1, 1), 0);
}

#[test]
fn pat_fresh_ports_are_not_sequential_16011() {
    // Drive the seeded occupancy claim directly: 512 distinct flow keys
    // over a large range must NOT come out as port_low..port_low+512.
    let occ_ports: Vec<u16> = {
        // Use PortAllocator's public-in-crate claim path via allocate_translation
        // on distinct flows; collect translated ports.
        let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
        let addrs = [pool_ip];
        let alloc = PortAllocator::new(1, 1024, 65535);
        (0..512u16)
            .map(|i| {
                alloc
                    .allocate_translation(
                        flow(20000 + i, 53),
                        PoolAddressFamily::V4(&addrs),
                        0,
                        false,
                        false,
                        PersistentNatPermit::TargetHostPort,
                        0,
                        0,
                        1_000,
                        NatHolder::Untracked,
                        0,
                    )
                    .expect("fresh allocation must succeed")
                    .port
            })
            .collect()
    };
    // No duplicates (bitmap ownership still exact).
    let mut sorted = occ_ports.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        occ_ports.len(),
        "keyed claims must never duplicate a port"
    );
    // Not the sequential run 1024, 1025, ... (pre-fix behaviour).
    let sequential: Vec<u16> = (0..512u16).map(|i| 1024 + i).collect();
    assert_ne!(
        occ_ports, sequential,
        "fresh PAT ports must not be handed out in ascending order"
    );
    // Successive-difference check: at most a handful of +1 adjacencies
    // are expected by chance (~512/64512); sequential gives 511.
    let plus_one = occ_ports
        .windows(2)
        .filter(|w| w[1] == w[0].wrapping_add(1))
        .count();
    assert!(
        plus_one < 20,
        "too many +1 adjacencies ({plus_one}) — looks sequential"
    );
    // Spread: ports must cover many distinct 4096-port buckets.
    let buckets: std::collections::HashSet<u16> = occ_ports.iter().map(|p| p / 4096).collect();
    assert!(
        buckets.len() > 8,
        "ports must spread across the range, buckets={}",
        buckets.len()
    );
}

#[test]
fn pat_next_port_prediction_advantage_is_bounded_16011() {
    // Attacker model from the issue: observe N translated ports for
    // known tuples, then guess the next flow's port as observed+1
    // (the pre-fix optimal strategy). Under keyed selection this must
    // succeed at ~random chance, not ~always.
    let pool_ip: Ipv4Addr = "203.0.113.9".parse().unwrap();
    let addrs = [pool_ip];
    let alloc = PortAllocator::new(1, 1024, 65535);
    let mut prev: Option<u16> = None;
    let mut hits = 0usize;
    let trials = 2000usize;
    for i in 0..trials {
        let t = alloc
            .allocate_translation(
                flow(30000 + (i % 30000) as u16, 443),
                PoolAddressFamily::V4(&addrs),
                0,
                false,
                false,
                PersistentNatPermit::TargetHostPort,
                0,
                0,
                1_000,
                NatHolder::Untracked,
                0,
            )
            .expect("allocation must succeed");
        if let Some(p) = prev {
            if t.port == p.wrapping_add(1) {
                hits += 1;
            }
        }
        prev = Some(t.port);
        // Release so the range does not exhaust; reuse must also be keyed.
        let f = flow(30000 + (i % 30000) as u16, 443);
        alloc.release_flow(f, t, 2_000, NatHolder::Untracked);
    }
    // Random chance is ~trials/64512 ≈ 0.03; sequential pre-fix = trials-1.
    assert!(
        hits < 10,
        "next-port +1 prediction hit {hits}/{trials} times — predictable allocation"
    );
}

#[test]
fn pat_keyed_probe_bounded_and_fail_closed_16011() {
    // Fill all but one port via seeded owners; the keyed probe must
    // still find the sole free port (bounded probe, no spurious
    // exhaustion), then fail closed when genuinely full.
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    let alloc = PortAllocator::new(1, 1024, 1031); // 8 ports
    for p in 1024..=1030u16 {
        alloc.debug_seed_owner(0, IpAddr::V4(pool_ip), p);
    }
    let t = alloc
        .allocate_translation(
            flow(40000, 53),
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            false,
            PersistentNatPermit::TargetHostPort,
            0,
            0,
            1_000,
            NatHolder::Untracked,
            0,
        )
        .expect("sole free port must be found by the bounded keyed probe");
    assert_eq!(t.port, 1031, "the only free port must be claimed");
    let err = alloc.allocate_translation(
        flow(40001, 53),
        PoolAddressFamily::V4(&addrs),
        0,
        false,
        false,
        PersistentNatPermit::TargetHostPort,
        0,
        0,
        1_000,
        NatHolder::Untracked,
        0,
    );
    assert!(
        err.is_err(),
        "genuinely full allocator must fail closed, got {err:?}"
    );
}

#[test]
fn pat_concurrent_claims_never_duplicate_16011() {
    // Concurrent worker mix: many threads claiming distinct flows from
    // one allocator must never receive the same port twice.
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let alloc = std::sync::Arc::new(PortAllocator::new(1, 1024, 8191));
    let mut handles = Vec::new();
    for worker in 0..8u16 {
        let a = alloc.clone();
        handles.push(std::thread::spawn(move || {
            let addrs = [pool_ip];
            (0..256u16)
                .map(|i| {
                    a.allocate_translation(
                        SourceNatFlowKey {
                            protocol: 6,
                            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, worker as u8, 1)),
                            dst_ip: "8.8.8.8".parse().unwrap(),
                            src_port: 10000 + i,
                            dst_port: 443,
                            routing_scope: 0,
                        },
                        PoolAddressFamily::V4(&addrs),
                        0,
                        false,
                        false,
                        PersistentNatPermit::TargetHostPort,
                        0,
                        0,
                        1_000,
                        NatHolder::Untracked,
                        0,
                    )
                    .expect("concurrent allocation must succeed")
                    .port
                })
                .collect::<Vec<u16>>()
        }));
    }
    let mut all: Vec<u16> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    let total = all.len();
    all.sort_unstable();
    all.dedup();
    assert_eq!(
        all.len(),
        total,
        "concurrent keyed claims duplicated a port"
    );
    // The sorted concurrent set must have gaps (keyed spread over
    // 1024..=8191), not be the contiguous block 1024..1024+total.
    let contiguous =
        all.first() == Some(&1024) && all.last().copied() == Some(1024 + total as u16 - 1);
    assert!(
        !contiguous,
        "concurrent claims filled a contiguous sequential block"
    );
    let _ = pat_mix(0); // keep import used if allocator re-exports change
}

#[test]
fn pat_exclusions_are_bounded_by_addresses_times_range_16011_fold() {
    // FOLD fold-3: an exclusion set covering all but ZERO ports must
    // terminate after O(addresses x range) probe work — exclusion calls
    // are counted, and may not exceed the offset space (+ per-address
    // ring re-checks bounded by a small constant per claim call).
    // Seeded core: drive claim_seeded_filtered directly.
    // Via PortAllocator: exclude everything; allocation must fail closed.
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    let alloc = PortAllocator::new(1, 20000, 20007); // range 8
    let calls = std::sync::atomic::AtomicU32::new(0);
    let excluded = |_: usize, _: u16| {
        calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        true
    };
    let err = alloc.allocate_translation_with_exclusions(
        flow(40000, 53),
        PoolAddressFamily::V4(&addrs),
        0,
        false,
        false,
        PersistentNatPermit::TargetHostPort,
        0,
        0,
        1_000,
        NatHolder::Untracked,
        0,
        &excluded,
    );
    assert!(err.is_err(), "all-excluded allocator must fail closed");
    let n = calls.load(std::sync::atomic::Ordering::Relaxed);
    // Hard bound: each claim attempt checks <= range offsets (+ ring).
    // Attempts on this address are bounded by the rejected-port loop,
    // itself bounded by range distinct claims. 8*8*4 is generous.
    assert!(
        n <= 256,
        "exclusion work must be bounded by addresses x range, got {n} calls"
    );
    assert_eq!(
        alloc.debug_occupied_count(),
        0,
        "excluded candidates must never be claimed"
    );
}

#[test]
fn pat_overlap_exclusion_advances_probe_16011_fold() {
    // FOLD fold-2 (allocator level): excluding the port a plain claim
    // would mint must make the excluded claim mint a DIFFERENT port on
    // the first retry — never re-claim/rollback the same port.
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    let alloc = PortAllocator::new(1, 20000, 20099);
    let f = flow(41000, 53);
    // Claim+release once to learn this flow's first keyed port.
    let first = alloc
        .allocate_translation(
            f,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            false,
            PersistentNatPermit::TargetHostPort,
            0,
            0,
            1_000,
            NatHolder::Untracked,
            0,
        )
        .expect("first");
    alloc.release_flow(f, first, 2_000, NatHolder::Untracked);
    let excluded_port = first.port;
    let second = alloc
        .allocate_translation_with_exclusions(
            f,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            false,
            PersistentNatPermit::TargetHostPort,
            0,
            0,
            3_000,
            NatHolder::Untracked,
            0,
            &|_, p| p == excluded_port,
        )
        .expect("excluded claim must advance to another port");
    assert_ne!(
        second.port, excluded_port,
        "exclusion must advance the probe, not retry the same port"
    );
    assert!((20000..=20099).contains(&second.port));
}

#[test]
fn pat_peer_overlap_retry_mints_distinct_identity_16011_fold() {
    // FOLD fold-2 (production match path): two overlapping pools over
    // one address (20000..=20001). Pool A mints first; every subsequent
    // peer-pool mint must land on the OTHER port — the keyed probe
    // advances past the peer-owned candidate instead of repeatedly
    // minting, colliding, and rolling back.
    use super::source::parse_source_nat_rules;
    use crate::SourceNATRuleSnapshot;
    fn rule(name: &str, pool: &str, src: &str) -> SourceNATRuleSnapshot {
        SourceNATRuleSnapshot {
            name: name.to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec![src.to_string()],
            pool_name: pool.to_string(),
            pool_addresses: vec!["203.0.113.1/32".to_string()],
            port_low: 20000,
            port_high: 20001,
            ..SourceNATRuleSnapshot::default()
        }
    }
    let rules = parse_source_nat_rules(&[
        rule("r1", "a", "10.0.0.0/24"),
        rule("r2", "b", "10.1.0.0/24"),
    ]);
    let mint = |src: &str, sport: u16| {
        match_source_nat_result_for_tuple(
            &InterfaceNatAllocators::default(),
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src.parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            Some(6),
            sport,
            443,
            None,
            None,
            1_000,
            false,
            false,
            NatHolder::Untracked,
            &mut None,
        )
    };
    let first = mint("10.0.0.7", 1111);
    let first_port = match &first {
        SourceNatLookup::Matched(d) => d.rewrite_src_port.expect("port"),
        other => panic!("first mint failed: {other:?}"),
    };
    // Peer mints (distinct source networks, same remote): each must
    // succeed with the non-colliding port, never a duplicate, never
    // stuck in a retry-collision loop.
    for (src, sport) in [("10.1.0.7", 2222u16)] {
        match mint(src, sport) {
            SourceNatLookup::Matched(d) => {
                assert_ne!(
                    d.rewrite_src_port,
                    Some(first_port),
                    "peer mint must not duplicate pool A's identity"
                );
            }
            other => panic!("peer mint must advance past the peer-owned port, got {other:?}"),
        }
    }
}
