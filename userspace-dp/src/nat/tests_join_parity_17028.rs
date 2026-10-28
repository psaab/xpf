//! #17028 (R4-Q11-02): table-driven join/retire parity across all six
//! persistent-lease join shapes.
//!
//! Shapes: (1) local PAT `allocate_translation`, (2) deterministic
//! BIB full-block, (3) deterministic BIB claimed-port, (4) synced PAT
//! `reserve_flow_maybe_persistent`, (5) synced address-only
//! `reserve_address_only_maybe_persistent`, (6) local address-only
//! `reserve_address_only_persistent`. Each drives an IDLE and an
//! ACTIVE lease and asserts the activation snapshot fields, expiry-
//! index membership (idle only), `active_flows`, and — for the BIB
//! cap-failure — `exhaustion_total` per the declared policy (every
//! cap failure bumps it, including the claimed-port copy that used
//! to return silently).

use super::allocator::{
    DeterministicV6, NatHolder, PoolAddressFamily, PortAllocator, TranslatedTuple,
};
use super::source::{PersistentNatPermit, SourceNatFlowKey};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const POOL: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const TIMEOUT_NS: u64 = 300_000_000_000;
const BIB_PARAMS: DeterministicV6 = DeterministicV6 {
    block_size: 32,
    blocks_per_ip: 2,
    host_prefix_len: 32,
    host_base: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    host_count: 1,
};
const SUB: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

fn v4_flow(src_ip: &str, src_port: u16, dst_ip: &str) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: 6,
        src_ip: src_ip.parse().unwrap(),
        dst_ip: dst_ip.parse().unwrap(),
        src_port,
        dst_port: 443,
        routing_scope: 0,
    }
}

fn bib_flow(src_port: u16, dst_ip: &str) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: 6,
        src_ip: IpAddr::V6(SUB),
        dst_ip: dst_ip.parse().unwrap(),
        src_port,
        dst_port: 443,
        routing_scope: 0,
    }
}

fn assert_index_membership(
    alloc: &PortAllocator,
    flow: &SourceNatFlowKey,
    permit: PersistentNatPermit,
    idle_indexed: bool,
    ctx: &str,
) {
    let key = flow.persistent_source_key(permit);
    let live = alloc.debug_live();
    let lease = live
        .persistent_by_source
        .get(&key)
        .unwrap_or_else(|| panic!("{ctx}: lease must exist"));
    let entry = (lease.expires_at_ns, key);
    assert_eq!(
        live.lease_expirations.contains(&entry),
        idle_indexed,
        "{ctx}: global expiry index membership (idle_indexed={idle_indexed})"
    );
    assert_eq!(
        live.lease_expirations_by_addr[lease.addr_index].contains(&entry),
        idle_indexed,
        "{ctx}: per-addr expiry index membership (idle_indexed={idle_indexed})"
    );
}

fn snapshot_fields(
    alloc: &PortAllocator,
    flow: &SourceNatFlowKey,
    permit: PersistentNatPermit,
) -> (bool, bool, u64, u64, u32) {
    let st = alloc
        .debug_persistent_lease_for_flow(flow, permit)
        .expect("debug lease state");
    (
        st.activation_saw_completion,
        st.activation_had_previous_lease,
        st.activation_previous_expires_at_ns,
        st.activation_previous_timeout_ns,
        st.active_flows,
    )
}

/// One row of the parity table: mint a lease, drain it to idle,
/// record the pre-join snapshot baseline, join a second flow, and
/// check the 0->1 re-arm; then join a third flow on the ACTIVE lease
/// and check no snapshot churn.
#[test]
fn lease_join_parity_all_modes_17028() {
    // ---- Shape 1: local PAT -------------------------------------------
    {
        let addrs = [POOL];
        let alloc = PortAllocator::new(1, 1024, 65535);
        let f1 = v4_flow("10.0.70.1", 40000, "8.8.8.8");
        let t1 = alloc
            .allocate_translation(
                f1,
                PoolAddressFamily::V4(&addrs),
                0,
                false,
                true,
                PersistentNatPermit::AnyRemoteHost,
                0,
                TIMEOUT_NS,
                1_000,
                NatHolder::Untracked,
                0,
            )
            .expect("PAT mint");
        assert!(alloc.release_flow(f1, t1, 2_000, NatHolder::Untracked));
        assert_index_membership(
            &alloc,
            &f1,
            PersistentNatPermit::AnyRemoteHost,
            true,
            "PAT idle-before-join",
        );
        let pre = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        let f2 = v4_flow("10.0.70.1", 40000, "1.1.1.1");
        let t2 = alloc
            .allocate_translation(
                f2,
                PoolAddressFamily::V4(&addrs),
                0,
                false,
                true,
                PersistentNatPermit::AnyRemoteHost,
                0,
                TIMEOUT_NS,
                3_000,
                NatHolder::Untracked,
                0,
            )
            .expect("PAT idle join");
        assert_eq!(t1, t2, "PAT: idle join reuses tuple");
        let post = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        assert!(!post.0 && post.1, "PAT idle join: snapshot re-armed (saw_completion=false, had_previous=true), got {post:?} pre {pre:?}");
        assert_eq!(
            post.2,
            pre.2.max(post.2),
            "PAT idle join: previous expiry snapshot recorded"
        );
        assert_eq!(post.4, 1, "PAT idle join: active_flows 0->1");
        assert_index_membership(
            &alloc,
            &f1,
            PersistentNatPermit::AnyRemoteHost,
            false,
            "PAT after idle join",
        );
        // Active join: third flow, snapshot must not churn.
        let snap_active = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        let f3 = v4_flow("10.0.70.1", 40000, "9.9.9.9");
        alloc
            .allocate_translation(
                f3,
                PoolAddressFamily::V4(&addrs),
                0,
                false,
                true,
                PersistentNatPermit::AnyRemoteHost,
                0,
                TIMEOUT_NS,
                4_000,
                NatHolder::Untracked,
                0,
            )
            .expect("PAT active join");
        let post3 = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        assert_eq!(post3.4, 2, "PAT active join: active_flows 1->2");
        assert_eq!(
            post3.2, snap_active.2,
            "PAT active join: snapshot expiry unchanged"
        );
        assert_eq!(
            post3.3, snap_active.3,
            "PAT active join: snapshot timeout unchanged"
        );
        assert_index_membership(
            &alloc,
            &f1,
            PersistentNatPermit::AnyRemoteHost,
            false,
            "PAT after active join",
        );
    }

    // ---- Shapes 2+3: deterministic BIB (full-block + claimed-port) --
    // A fresh mint goes through the claimed-port branch; releasing it
    // to idle and re-joining exercises the other branch when the block
    // is full. Both must produce identical snapshot/index outcomes.
    for full_block in [false, true] {
        let ctx = if full_block {
            "BIB full-block"
        } else {
            "BIB claimed-port"
        };
        // Claimed-port: wide block. Full-block: block_size=1, single
        // port (1024) — after release, claim returns None (the idle
        // BIB's own bit) and the full-block branch joins it.
        let (lo, hi, params) = if full_block {
            (
                1024,
                1024,
                DeterministicV6 {
                    block_size: 1,
                    blocks_per_ip: 1,
                    ..BIB_PARAMS
                },
            )
        } else {
            (1024, 1087, BIB_PARAMS)
        };
        let alloc = PortAllocator::new(1, lo, hi);
        let f1 = bib_flow(40000, "8.8.8.8");
        let t1 = alloc
            .allocate_deterministic_v6_at(f1, &[POOL], params, SUB, 1_000, NatHolder::Untracked)
            .expect("BIB mint");
        assert!(alloc.release_flow(f1, t1, 2_000, NatHolder::Untracked));
        assert_index_membership(
            &alloc,
            &f1,
            PersistentNatPermit::AnyRemoteHost,
            true,
            &format!("{ctx} idle-before-join"),
        );
        let f2 = bib_flow(40000, "1.1.1.1");
        let t2 = alloc
            .allocate_deterministic_v6_at(f2, &[POOL], params, SUB, 3_000, NatHolder::Untracked)
            .unwrap_or_else(|e| panic!("{ctx} idle join: {e:?}"));
        assert_eq!(t1, t2, "{ctx}: idle join reuses BIB tuple");
        let post = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        assert!(
            !post.0 && post.1,
            "{ctx} idle join: snapshot re-armed, got {post:?}"
        );
        assert_eq!(post.4, 1, "{ctx} idle join: active_flows 0->1");
        assert_index_membership(
            &alloc,
            &f1,
            PersistentNatPermit::AnyRemoteHost,
            false,
            &format!("{ctx} after idle join"),
        );
        let snap_active = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        let f3 = bib_flow(40000, "9.9.9.9");
        // Single-port pool at cap (max_tracked == 1): an active join
        // here would be refused — use release+rejoin instead there.
        if full_block {
            assert!(alloc.release_flow(f2, t2, 4_000, NatHolder::Untracked));
            let t3 = alloc
                .allocate_deterministic_v6_at(f3, &[POOL], params, SUB, 5_000, NatHolder::Untracked)
                .expect("BIB full-block rejoin after release");
            assert_eq!(t3, t1);
        } else {
            alloc
                .allocate_deterministic_v6_at(f3, &[POOL], params, SUB, 4_000, NatHolder::Untracked)
                .expect("BIB active join");
            let post3 = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
            assert_eq!(post3.4, 2, "{ctx} active join: active_flows 1->2");
            assert_eq!(
                post3.2, snap_active.2,
                "{ctx} active join: snapshot unchanged"
            );
            assert_index_membership(
                &alloc,
                &f1,
                PersistentNatPermit::AnyRemoteHost,
                false,
                &format!("{ctx} after active join"),
            );
        }
    }

    // ---- Shape 4: synced PAT ------------------------------------------
    {
        let alloc = PortAllocator::new(1, 1024, 65535);
        let f1 = v4_flow("10.0.70.4", 40000, "8.8.8.8");
        let key = f1.persistent_source_key(PersistentNatPermit::AnyRemoteHost);
        let tuple = TranslatedTuple {
            ip: IpAddr::V4(POOL),
            port: 21000,
        };
        assert!(
            alloc.reserve_flow_maybe_persistent(
                f1,
                tuple,
                0,
                false,
                1_000,
                NatHolder::Untracked,
                Some((key, TIMEOUT_NS)),
                false,
                &mut None
            ),
            "synced PAT mint-join"
        );
        assert!(alloc.release_flow(f1, tuple, 2_000, NatHolder::Untracked));
        assert_index_membership(
            &alloc,
            &f1,
            PersistentNatPermit::AnyRemoteHost,
            true,
            "synced PAT idle-before-join",
        );
        let f2 = v4_flow("10.0.70.4", 40000, "1.1.1.1");
        assert!(
            alloc.reserve_flow_maybe_persistent(
                f2,
                tuple,
                0,
                false,
                3_000,
                NatHolder::Untracked,
                Some((key, TIMEOUT_NS)),
                false,
                &mut None
            ),
            "synced PAT idle join"
        );
        let post = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        assert!(
            !post.0 && post.1,
            "synced PAT idle join: snapshot re-armed, got {post:?}"
        );
        assert_eq!(post.4, 1);
        assert_index_membership(
            &alloc,
            &f1,
            PersistentNatPermit::AnyRemoteHost,
            false,
            "synced PAT after idle join",
        );
        let f3 = v4_flow("10.0.70.4", 40000, "9.9.9.9");
        assert!(
            alloc.reserve_flow_maybe_persistent(
                f3,
                tuple,
                0,
                false,
                4_000,
                NatHolder::Untracked,
                Some((key, TIMEOUT_NS)),
                false,
                &mut None
            ),
            "synced PAT active join"
        );
        assert_eq!(
            snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost).4,
            2,
            "synced PAT active join refcount"
        );
    }

    // ---- Shape 5: synced address-only ---------------------------------
    {
        let alloc = PortAllocator::new(1, 1024, 65535);
        let f1 = v4_flow("10.0.70.5", 40000, "8.8.8.8");
        let key = f1.persistent_source_key(PersistentNatPermit::AnyRemoteHost);
        let t1 = alloc
            .reserve_address_only_maybe_persistent(
                f1,
                IpAddr::V4(POOL),
                0,
                1_000,
                NatHolder::Untracked,
                Some((key, TIMEOUT_NS)),
                false,
                &mut None,
            )
            .expect("synced AO mint-join");
        assert!(alloc.release_flow(f1, t1, 2_000, NatHolder::Untracked));
        assert_index_membership(
            &alloc,
            &f1,
            PersistentNatPermit::AnyRemoteHost,
            true,
            "synced AO idle-before-join",
        );
        let f2 = v4_flow("10.0.70.5", 40000, "1.1.1.1");
        alloc
            .reserve_address_only_maybe_persistent(
                f2,
                IpAddr::V4(POOL),
                0,
                3_000,
                NatHolder::Untracked,
                Some((key, TIMEOUT_NS)),
                false,
                &mut None,
            )
            .expect("synced AO idle join");
        let post = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        assert!(
            !post.0 && post.1,
            "synced AO idle join: snapshot re-armed, got {post:?}"
        );
        assert_eq!(post.4, 1);
        assert_index_membership(
            &alloc,
            &f1,
            PersistentNatPermit::AnyRemoteHost,
            false,
            "synced AO after idle join",
        );
        let f3 = v4_flow("10.0.70.5", 40000, "9.9.9.9");
        alloc
            .reserve_address_only_maybe_persistent(
                f3,
                IpAddr::V4(POOL),
                0,
                4_000,
                NatHolder::Untracked,
                Some((key, TIMEOUT_NS)),
                false,
                &mut None,
            )
            .expect("synced AO active join");
        assert_eq!(
            snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost).4,
            2,
            "synced AO active join refcount"
        );
    }

    // ---- Shape 6: local address-only ----------------------------------
    {
        let addrs = [POOL];
        let alloc = PortAllocator::new(1, 1024, 65535);
        let f1 = v4_flow("10.0.70.6", 40000, "8.8.8.8");
        let t1 = alloc
            .reserve_address_only_persistent(
                f1,
                PoolAddressFamily::V4(&addrs),
                0,
                false,
                PersistentNatPermit::AnyRemoteHost,
                0,
                TIMEOUT_NS,
                1_000,
                NatHolder::Untracked,
                0,
            )
            .expect("local AO mint");
        assert!(alloc.release_flow(f1, t1, 2_000, NatHolder::Untracked));
        assert_index_membership(
            &alloc,
            &f1,
            PersistentNatPermit::AnyRemoteHost,
            true,
            "local AO idle-before-join",
        );
        let f2 = v4_flow("10.0.70.6", 40000, "1.1.1.1");
        let t2 = alloc
            .reserve_address_only_persistent(
                f2,
                PoolAddressFamily::V4(&addrs),
                0,
                false,
                PersistentNatPermit::AnyRemoteHost,
                0,
                TIMEOUT_NS,
                3_000,
                NatHolder::Untracked,
                0,
            )
            .expect("local AO idle join");
        assert_eq!(t1.ip, t2.ip, "local AO: idle join keeps pinned address");
        let post = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        assert!(
            !post.0 && post.1,
            "local AO idle join: snapshot re-armed, got {post:?}"
        );
        assert_eq!(post.4, 1);
        assert_index_membership(
            &alloc,
            &f1,
            PersistentNatPermit::AnyRemoteHost,
            false,
            "local AO after idle join",
        );
        let f3 = v4_flow("10.0.70.6", 40000, "9.9.9.9");
        alloc
            .reserve_address_only_persistent(
                f3,
                PoolAddressFamily::V4(&addrs),
                0,
                false,
                PersistentNatPermit::AnyRemoteHost,
                0,
                TIMEOUT_NS,
                4_000,
                NatHolder::Untracked,
                0,
            )
            .expect("local AO active join");
        assert_eq!(
            snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost).4,
            2,
            "local AO active join refcount"
        );
        assert_index_membership(
            &alloc,
            &f1,
            PersistentNatPermit::AnyRemoteHost,
            false,
            "local AO after active join",
        );
    }
}

/// #17028 divergence-1: the claimed-port BIB cap-fail must bump
/// `exhaustion_total`, exactly like the full-block branch. Pool of a
/// single port (max_tracked == 1): mint one BIB, then a second flow
/// for the SAME BIB hits the claimed-port join cap.
#[test]
fn bib_claimed_port_cap_fail_bumps_exhaustion_17028() {
    let params = DeterministicV6 {
        block_size: 32,
        blocks_per_ip: 2,
        ..BIB_PARAMS
    };
    let alloc = PortAllocator::new(1, 1024, 1024);
    let f1 = bib_flow(40000, "8.8.8.8");
    alloc
        .allocate_deterministic_v6_at(f1, &[POOL], params, SUB, 1_000, NatHolder::Untracked)
        .expect("BIB mint on single-port pool");
    let before = alloc.snapshot().exhaustion_total;
    let f2 = bib_flow(40000, "1.1.1.1");
    let err =
        alloc.allocate_deterministic_v6_at(f2, &[POOL], params, SUB, 2_000, NatHolder::Untracked);
    assert!(
        err.is_err(),
        "second BIB flow at cap must exhaust, got {err:?}"
    );
    assert_eq!(
        alloc.snapshot().exhaustion_total,
        before + 1,
        "claimed-port cap-fail must bump exhaustion_total (divergence-1 policy)"
    );
    // The lease itself is untouched by the refused join.
    assert_eq!(
        snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost).4,
        1
    );
}

/// #17028 divergence-2: a revoked lease with live flows is never
/// joined by the BIB path (it refuses — the BIB has no unpinned
/// fallback) and never retired while live; the PAT path's answer is
/// `LiveModeMismatch` (serve unpinned), exercised by #9536 cells.
/// Here: import an idle BIB, clear (revokes + removes idle), then a
/// live revoked shell via a second allocator is left standing.
#[test]
fn bib_revoked_live_lease_is_not_joined_17028() {
    // Build a revoked-live shell: mint + join, then clear while live.
    let params = BIB_PARAMS;
    let alloc = PortAllocator::new(1, 1024, 1087);
    let f1 = bib_flow(40000, "8.8.8.8");
    let t1 = alloc
        .allocate_deterministic_v6_at(f1, &[POOL], params, SUB, 1_000, NatHolder::Untracked)
        .expect("BIB mint");
    let cleared = alloc.clear_persistent_leases(2_000);
    assert_eq!(cleared, 1, "live BIB becomes a revoked shell");
    // A new flow for the same subscriber transport must NOT join the
    // revoked shell: it refuses (exhaustion) and the shell stands.
    let f2 = bib_flow(40000, "1.1.1.1");
    let err =
        alloc.allocate_deterministic_v6_at(f2, &[POOL], params, SUB, 3_000, NatHolder::Untracked);
    assert!(
        err.is_err(),
        "revoked-live BIB must not be joined, got {err:?}"
    );
    let st = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
    assert_eq!(st.4, 1, "revoked shell keeps its live flow count");
    // The original flow still releases cleanly off the shell.
    assert!(alloc.release_flow(f1, t1, 4_000, NatHolder::Untracked));
}
