//! #16481: `reseed_retained_deterministic_v6_from` carries retained
//! deterministic (NAPT64 mode-2) live flows into a fresh allocator when
//! the pool length changes, so the fresh allocator does not re-mint a
//! surviving session's port. Tuples that no longer satisfy
//! `deterministic_v6_tuple_matches` under the NEW params are not carried.

use super::allocator::{DeterministicV6, NatHolder, PortAllocator};
use super::source::{PersistentNatPermit, SourceNatFlowKey};
use rustc_hash::FxHashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
const POOL_A: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const POOL_B: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);

fn params(host_count: u32) -> DeterministicV6 {
    DeterministicV6 {
        block_size: 32,
        blocks_per_ip: 2016,
        host_prefix_len: 32,
        host_base: "2001:db8::".parse::<Ipv6Addr>().unwrap().octets(),
        host_count,
    }
}

fn flow(src: Ipv6Addr, src_port: u16, dst: Ipv4Addr) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: 6,
        src_ip: IpAddr::V6(src),
        dst_ip: IpAddr::V4(dst),
        src_port,
        dst_port: 443,
        routing_scope: 0,
    }
}

fn map(pairs: &[(usize, usize)]) -> FxHashMap<usize, usize> {
    pairs.iter().copied().collect()
}

#[test]
fn det_reseed_append_carries_retained_and_blocks_reissue_16481() {
    let sub: Ipv6Addr = "2001:db8:0:5::".parse().unwrap();
    let dst = Ipv4Addr::new(8, 8, 8, 8);
    let prev = PortAllocator::new(1, 1024, 65535);
    let f1 = flow(sub, 40001, dst);
    let t1 = prev
        .allocate_deterministic_v6_at(
            f1,
            &[POOL_A],
            params(2016),
            sub,
            1_000,
            NatHolder::Untracked,
        )
        .expect("F1");
    assert_eq!(t1.port, 1184);

    // Fresh allocator for pool [A, B] (host_count 4032).
    let fresh = PortAllocator::new(2, 1024, 65535);
    let out = fresh.reseed_retained_deterministic_v6_from(
        &prev,
        &map(&[(0, 0)]),
        &[POOL_A, POOL_B],
        params(4032),
        2_000,
    );
    assert_eq!(out.reseeded, 1);
    assert_eq!(out.reseeded_deterministic, 1);
    assert_eq!(out.skipped_deterministic_invalid, 0);
    assert_eq!(fresh.live_flow_count(), 1);

    // The carried BIB lease carries the NEW identity.
    let lease = fresh
        .debug_persistent_lease_for_flow(&f1, PersistentNatPermit::AnyRemoteHost)
        .expect("carried lease");
    assert!(lease.deterministic);
    assert_eq!(
        lease.deterministic_identity,
        Some(super::DeterministicPortedIdentity::V6(params(4032)))
    );
    assert_eq!(lease.translated, t1);

    // A second flow from the same subscriber to the same remote gets a
    // different port; a same-socket flow to a new remote joins the BIB.
    let f2 = flow(sub, 40002, dst);
    let t2 = fresh
        .allocate_deterministic_v6_at(
            f2,
            &[POOL_A, POOL_B],
            params(4032),
            sub,
            3_000,
            NatHolder::Untracked,
        )
        .expect("F2");
    assert_ne!(t2, t1, "#16481: F2 must not reissue live F1 port");
    let f3 = flow(sub, 40001, Ipv4Addr::new(9, 9, 9, 9));
    let t3 = fresh
        .allocate_deterministic_v6_at(
            f3,
            &[POOL_A, POOL_B],
            params(4032),
            sub,
            3_000,
            NatHolder::Untracked,
        )
        .expect("F3 EIM");
    assert_eq!(
        t3, t1,
        "#16481: same-socket new-remote must join carried BIB"
    );
}

#[test]
fn det_reseed_shrink_carries_retained_drops_removed_16481() {
    let dst = Ipv4Addr::new(8, 8, 8, 8);
    let sub0: Ipv6Addr = "2001:db8:0:5::".parse().unwrap();
    let sub_b: Ipv6Addr = "2001:db8:0:7e5::".parse().unwrap(); // word 2021 -> B, block 5
    let prev = PortAllocator::new(2, 1024, 65535);
    let f1 = flow(sub0, 40001, dst);
    let t1 = prev
        .allocate_deterministic_v6_at(
            f1,
            &[POOL_A, POOL_B],
            params(4032),
            sub0,
            1_000,
            NatHolder::Untracked,
        )
        .expect("sub0 F1");
    let g1 = flow(sub_b, 40001, dst);
    let tg = prev
        .allocate_deterministic_v6_at(
            g1,
            &[POOL_A, POOL_B],
            params(4032),
            sub_b,
            1_000,
            NatHolder::Untracked,
        )
        .expect("subB F1");
    assert_eq!(tg.ip, IpAddr::V4(POOL_B));

    let fresh = PortAllocator::new(1, 1024, 65535);
    let out = fresh.reseed_retained_deterministic_v6_from(
        &prev,
        &map(&[(0, 0)]),
        &[POOL_A],
        params(2016),
        2_000,
    );
    assert_eq!(out.reseeded, 1, "only retained subscriber carried");
    assert_eq!(out.reseeded_deterministic, 1);
    assert_eq!(
        out.skipped_deterministic_invalid, 1,
        "removed subscriber counted invalid"
    );
    assert_eq!(fresh.live_flow_count(), 1);

    let f2 = flow(sub0, 40002, dst);
    let t2 = fresh
        .allocate_deterministic_v6_at(
            f2,
            &[POOL_A],
            params(2016),
            sub0,
            3_000,
            NatHolder::Untracked,
        )
        .expect("sub0 F2");
    assert_ne!(t2, t1);
}

#[test]
fn det_reseed_block_change_does_not_carry_16481() {
    // #15178 control at allocator level: block 32 -> 1024 moves the
    // subscriber's block, so the old tuple must NOT be carried.
    let sub: Ipv6Addr = "2001:db8:0:5::".parse().unwrap();
    let dst = Ipv4Addr::new(8, 8, 8, 8);
    let prev = PortAllocator::new(1, 1024, 65535);
    let f1 = flow(sub, 40001, dst);
    let _t1 = prev
        .allocate_deterministic_v6_at(
            f1,
            &[POOL_A],
            params(2016),
            sub,
            1_000,
            NatHolder::Untracked,
        )
        .expect("F1");
    let mut new_params = params(2016);
    new_params.block_size = 1024;
    let fresh = PortAllocator::new(1, 1024, 65535);
    let out = fresh.reseed_retained_deterministic_v6_from(
        &prev,
        &map(&[(0, 0)]),
        &[POOL_A],
        new_params,
        2_000,
    );
    assert_eq!(out.reseeded, 0);
    assert_eq!(out.skipped_deterministic_invalid, 1);
    assert_eq!(fresh.live_flow_count(), 0);
    // New flow mints in the NEW block [6144, 7167].
    let t2 = fresh
        .allocate_deterministic_v6_at(f1, &[POOL_A], new_params, sub, 3_000, NatHolder::Untracked)
        .expect("new-block mint");
    assert!((6144..=7167).contains(&t2.port), "got {}", t2.port);
}
