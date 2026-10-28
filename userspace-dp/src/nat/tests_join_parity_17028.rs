//! #17028 (R4-Q11-02): table-driven join/retire parity across all six
//! persistent-lease join shapes.
//!
//! Shapes: (1) local PAT `allocate_translation`, (2) deterministic
//! BIB full-block, (3) deterministic BIB claimed-port, (4) synced PAT
//! `reserve_flow_maybe_persistent`, (5) synced address-only
//! `reserve_address_only_maybe_persistent`, (6) local address-only
//! `reserve_address_only_persistent`. Each drives an IDLE and an
//! ACTIVE lease and asserts the activation snapshot fields, the
//! CURRENT `expires_at_ns` / `timeout_ns` (join-time + timeout where
//! the site's `JoinPolicy` refreshes expiry, bit-identical to the
//! pre-join value where it must not; the local PAT / address-only
//! 0 -> 1 edge adopts a second, distinct caller timeout), expiry-
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
/// #17028 fold: a second, distinct timeout for rejoin-adoption pins.
/// PAT and local address-only adopt it on the 0 -> 1 edge (non-imported
/// leases: `promote_imported` applies immediately); both synced joins
/// and both BIB branches must NOT adopt it, and an already-active join
/// must not adopt it either. It sits inside the bounded range
/// `[1s, 24h]` so `bounded_persistent_nat_timeout_ns` passes it
/// through verbatim on every local path.
const TIMEOUT2_NS: u64 = 120_000_000_000;
/// The deterministic BIB's fixed timeout (mirrors
/// `DETERMINISTIC_NAT64_BIB_TIMEOUT_NS` = 300 s, equal to `TIMEOUT_NS`):
/// a BIB rejoin must keep it, whatever timeout the caller asked for.
const BIB_TIMEOUT_NS: u64 = TIMEOUT_NS;
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

/// The full join-relevant snapshot: the activation fields, the lease's
/// CURRENT `expires_at_ns` / `timeout_ns`, and `active_flows`, in that
/// order (asserts name them by position).
/// #17028 fold: the current expiry/timeout pin `JoinPolicy::refresh_expiry`
/// and the 0 -> 1 timeout adoption — a join that refreshes when it
/// must not (or vice versa), or drops/adopts the wrong timeout, now
/// fails instead of passing silently behind the snapshot fields.
fn snapshot_fields(
    alloc: &PortAllocator,
    flow: &SourceNatFlowKey,
    permit: PersistentNatPermit,
) -> (bool, bool, u64, u64, u64, u64, u32) {
    let st = alloc
        .debug_persistent_lease_for_flow(flow, permit)
        .expect("debug lease state");
    (
        st.activation_saw_completion,
        st.activation_had_previous_lease,
        st.activation_previous_expires_at_ns,
        st.activation_previous_timeout_ns,
        st.expires_at_ns,
        st.timeout_ns,
        st.active_flows,
    )
}

/// One row of the parity table: mint a lease, drain it to idle,
/// record the pre-join snapshot baseline, join a second flow (with a
/// distinct timeout where the API carries one), and check the 0->1
/// re-arm — snapshot, current expiry/timeout per the site's policy,
/// and refcount; then join a third flow on the ACTIVE lease and
/// check no snapshot/expiry/timeout churn.
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
        // Precondition for the pins below: the drain to idle re-armed
        // the expiry from the mint timeout (release at 2_000).
        assert_eq!(
            (pre.4, pre.5),
            (2_000 + TIMEOUT_NS, TIMEOUT_NS),
            "PAT pre-join: drain re-armed expiry/timeout, got {pre:?}"
        );
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
                TIMEOUT2_NS,
                3_000,
                NatHolder::Untracked,
                0,
            )
            .expect("PAT idle join");
        assert_eq!(t1, t2, "PAT: idle join reuses tuple");
        let post = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        assert!(
            !post.0 && post.1,
            "PAT idle join: snapshot re-armed (saw_completion=false, had_previous=true), got {post:?} pre {pre:?}"
        );
        assert_eq!(
            post.2, pre.4,
            "PAT idle join: previous expiry snapshot == pre-join expires_at"
        );
        assert_eq!(
            post.3, pre.5,
            "PAT idle join: previous timeout snapshot == pre-join timeout"
        );
        assert_eq!(
            post.4,
            3_000 + TIMEOUT2_NS,
            "PAT idle join (refresh_expiry=true): expires_at = join-time + adopted timeout"
        );
        assert_eq!(
            post.5, TIMEOUT2_NS,
            "PAT idle join: 0->1 adopts the caller's TIMEOUT2 timeout"
        );
        assert_eq!(post.6, 1, "PAT idle join: active_flows 0->1");
        assert_index_membership(
            &alloc,
            &f1,
            PersistentNatPermit::AnyRemoteHost,
            false,
            "PAT after idle join",
        );
        // Active join: third flow, snapshot must not churn — not even
        // under a THIRD timeout: no refresh, no adoption off the edge.
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
        assert_eq!(post3.6, 2, "PAT active join: active_flows 1->2");
        assert_eq!(
            post3.2, snap_active.2,
            "PAT active join: snapshot expiry unchanged"
        );
        assert_eq!(
            post3.3, snap_active.3,
            "PAT active join: snapshot timeout unchanged"
        );
        assert_eq!(
            post3.4, snap_active.4,
            "PAT active join: expires_at unchanged (refresh is 0->1 only)"
        );
        assert_eq!(
            post3.5, snap_active.5,
            "PAT active join: timeout unchanged (adoption is 0->1 only)"
        );
        assert_index_membership(
            &alloc,
            &f1,
            PersistentNatPermit::AnyRemoteHost,
            false,
            "PAT after active join",
        );
        // Drain fully, then a fresh 0->1 at TIMEOUT_NS restores the
        // mint timeout — adoption is per-edge, not sticky-once.
        assert!(alloc.release_flow(f3, t1, 5_000, NatHolder::Untracked));
        assert!(alloc.release_flow(f2, t2, 6_000, NatHolder::Untracked));
        let pre_rejoin = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        assert_eq!(
            (pre_rejoin.4, pre_rejoin.5),
            (6_000 + TIMEOUT2_NS, TIMEOUT2_NS),
            "PAT drained: last release re-armed from the adopted timeout, got {pre_rejoin:?}"
        );
        let f4 = v4_flow("10.0.70.1", 40000, "8.8.4.4");
        alloc
            .allocate_translation(
                f4,
                PoolAddressFamily::V4(&addrs),
                0,
                false,
                true,
                PersistentNatPermit::AnyRemoteHost,
                0,
                TIMEOUT_NS,
                7_000,
                NatHolder::Untracked,
                0,
            )
            .expect("PAT rejoin at mint timeout");
        let post4 = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        assert_eq!(
            (post4.2, post4.3),
            (pre_rejoin.4, pre_rejoin.5),
            "PAT rejoin: snapshot == pre-rejoin expiry/timeout"
        );
        assert_eq!(
            post4.4,
            7_000 + TIMEOUT_NS,
            "PAT rejoin: expiry refreshed to join-time + TIMEOUT_NS"
        );
        assert_eq!(
            post4.5, TIMEOUT_NS,
            "PAT rejoin: timeout re-adopts the caller's TIMEOUT_NS"
        );
        assert_eq!(post4.6, 1, "PAT rejoin: active_flows 0->1");
    }

    // ---- Shapes 2+3: deterministic BIB (full-block + claimed-port) --
    // A fresh mint goes through the claimed-port branch; releasing it
    // to idle and re-joining exercises the other branch when the block
    // is full. Both mint and rejoin at the FIXED BIB timeout
    // (`BIB_TIMEOUT_NS`, the call takes no timeout parameter), so the
    // timeout pin is equality, not adoption — but the EXPIRY pin
    // differs by branch, the #15948 policy the consolidation kept:
    // full-block refreshes on the 0 -> 1 edge (join-time + timeout),
    // claimed-port leaves `expires_at_ns` bit-identical to pre-join.
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
        let pre = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        assert_eq!(
            (pre.4, pre.5),
            (2_000 + BIB_TIMEOUT_NS, BIB_TIMEOUT_NS),
            "{ctx} pre-join: drain re-armed expiry/timeout, got {pre:?}"
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
        assert_eq!(
            (post.2, post.3),
            (pre.4, pre.5),
            "{ctx} idle join: snapshot == pre-join expiry/timeout"
        );
        if full_block {
            assert_eq!(
                post.4,
                3_000 + BIB_TIMEOUT_NS,
                "{ctx} idle join (refresh_expiry=true): expires_at = join-time + BIB timeout"
            );
        } else {
            assert_eq!(
                post.4, pre.4,
                "{ctx} idle join (refresh_expiry=false): expires_at unchanged from pre-join"
            );
        }
        assert_eq!(
            post.5, BIB_TIMEOUT_NS,
            "{ctx} idle join: timeout stays the fixed BIB timeout"
        );
        assert_eq!(post.6, 1, "{ctx} idle join: active_flows 0->1");
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
            let pre_rejoin = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
            assert_eq!(
                (pre_rejoin.4, pre_rejoin.5),
                (4_000 + BIB_TIMEOUT_NS, BIB_TIMEOUT_NS),
                "{ctx} pre-rejoin: drain re-armed expiry/timeout, got {pre_rejoin:?}"
            );
            let t3 = alloc
                .allocate_deterministic_v6_at(f3, &[POOL], params, SUB, 5_000, NatHolder::Untracked)
                .expect("BIB full-block rejoin after release");
            assert_eq!(t3, t1);
            let post3 = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
            assert_eq!(
                (post3.2, post3.3),
                (pre_rejoin.4, pre_rejoin.5),
                "{ctx} rejoin: snapshot == pre-rejoin expiry/timeout"
            );
            assert_eq!(
                post3.4,
                5_000 + BIB_TIMEOUT_NS,
                "{ctx} rejoin (refresh_expiry=true): expires_at = join-time + BIB timeout"
            );
            assert_eq!(
                post3.5, BIB_TIMEOUT_NS,
                "{ctx} rejoin: timeout stays the fixed BIB timeout"
            );
            assert_eq!(post3.6, 1, "{ctx} rejoin: active_flows 0->1");
        } else {
            alloc
                .allocate_deterministic_v6_at(f3, &[POOL], params, SUB, 4_000, NatHolder::Untracked)
                .expect("BIB active join");
            let post3 = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
            assert_eq!(post3.6, 2, "{ctx} active join: active_flows 1->2");
            assert_eq!(
                post3.2, snap_active.2,
                "{ctx} active join: snapshot unchanged"
            );
            assert_eq!(
                (post3.4, post3.5),
                (snap_active.4, snap_active.5),
                "{ctx} active join: expires_at/timeout unchanged"
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
    // Synced joins preserve peer origin: `promote_imported=false`,
    // `refresh_expiry=false`. Rejoining idle with a DIFFERENT timeout
    // must leave BOTH `expires_at_ns` and `timeout_ns` bit-identical
    // to the pre-join values — the peer timeout is mint-only here.
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
        let pre = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        assert_eq!(
            (pre.4, pre.5),
            (2_000 + TIMEOUT_NS, TIMEOUT_NS),
            "synced PAT pre-join: drain re-armed expiry/timeout, got {pre:?}"
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
                Some((key, TIMEOUT2_NS)),
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
        assert_eq!(
            (post.2, post.3),
            (pre.4, pre.5),
            "synced PAT idle join: snapshot == pre-join expiry/timeout"
        );
        assert_eq!(
            post.4, pre.4,
            "synced PAT idle join (refresh_expiry=false): expires_at unchanged from pre-join"
        );
        assert_eq!(
            post.5, pre.5,
            "synced PAT idle join (promote_imported=false): timeout NOT adopted from TIMEOUT2"
        );
        assert_eq!(post.6, 1);
        assert_index_membership(
            &alloc,
            &f1,
            PersistentNatPermit::AnyRemoteHost,
            false,
            "synced PAT after idle join",
        );
        let snap_active = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        let f3 = v4_flow("10.0.70.4", 40000, "9.9.9.9");
        assert!(
            alloc.reserve_flow_maybe_persistent(
                f3,
                tuple,
                0,
                false,
                4_000,
                NatHolder::Untracked,
                Some((key, TIMEOUT2_NS)),
                false,
                &mut None
            ),
            "synced PAT active join"
        );
        let post3 = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        assert_eq!(post3.6, 2, "synced PAT active join refcount");
        assert_eq!(
            (post3.2, post3.3, post3.4, post3.5),
            (snap_active.2, snap_active.3, snap_active.4, snap_active.5),
            "synced PAT active join: snapshot/expiry/timeout unchanged"
        );
    }

    // ---- Shape 5: synced address-only ---------------------------------
    // Same peer-origin policy as synced PAT: no refresh, no adoption.
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
        let pre = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        assert_eq!(
            (pre.4, pre.5),
            (2_000 + TIMEOUT_NS, TIMEOUT_NS),
            "synced AO pre-join: drain re-armed expiry/timeout, got {pre:?}"
        );
        let f2 = v4_flow("10.0.70.5", 40000, "1.1.1.1");
        alloc
            .reserve_address_only_maybe_persistent(
                f2,
                IpAddr::V4(POOL),
                0,
                3_000,
                NatHolder::Untracked,
                Some((key, TIMEOUT2_NS)),
                false,
                &mut None,
            )
            .expect("synced AO idle join");
        let post = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        assert!(
            !post.0 && post.1,
            "synced AO idle join: snapshot re-armed, got {post:?}"
        );
        assert_eq!(
            (post.2, post.3),
            (pre.4, pre.5),
            "synced AO idle join: snapshot == pre-join expiry/timeout"
        );
        assert_eq!(
            post.4, pre.4,
            "synced AO idle join (refresh_expiry=false): expires_at unchanged from pre-join"
        );
        assert_eq!(
            post.5, pre.5,
            "synced AO idle join (promote_imported=false): timeout NOT adopted from TIMEOUT2"
        );
        assert_eq!(post.6, 1);
        assert_index_membership(
            &alloc,
            &f1,
            PersistentNatPermit::AnyRemoteHost,
            false,
            "synced AO after idle join",
        );
        let snap_active = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        let f3 = v4_flow("10.0.70.5", 40000, "9.9.9.9");
        alloc
            .reserve_address_only_maybe_persistent(
                f3,
                IpAddr::V4(POOL),
                0,
                4_000,
                NatHolder::Untracked,
                Some((key, TIMEOUT2_NS)),
                false,
                &mut None,
            )
            .expect("synced AO active join");
        let post3 = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        assert_eq!(post3.6, 2, "synced AO active join refcount");
        assert_eq!(
            (post3.2, post3.3, post3.4, post3.5),
            (snap_active.2, snap_active.3, snap_active.4, snap_active.5),
            "synced AO active join: snapshot/expiry/timeout unchanged"
        );
    }

    // ---- Shape 6: local address-only ----------------------------------
    // Same local policy as PAT: refresh + adopt on the 0 -> 1 edge only.
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
        let pre = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        assert_eq!(
            (pre.4, pre.5),
            (2_000 + TIMEOUT_NS, TIMEOUT_NS),
            "local AO pre-join: drain re-armed expiry/timeout, got {pre:?}"
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
                TIMEOUT2_NS,
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
        assert_eq!(
            (post.2, post.3),
            (pre.4, pre.5),
            "local AO idle join: snapshot == pre-join expiry/timeout"
        );
        assert_eq!(
            post.4,
            3_000 + TIMEOUT2_NS,
            "local AO idle join (refresh_expiry=true): expires_at = join-time + adopted timeout"
        );
        assert_eq!(
            post.5, TIMEOUT2_NS,
            "local AO idle join: 0->1 adopts the caller's TIMEOUT2 timeout"
        );
        assert_eq!(post.6, 1);
        assert_index_membership(
            &alloc,
            &f1,
            PersistentNatPermit::AnyRemoteHost,
            false,
            "local AO after idle join",
        );
        let snap_active = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
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
        let post3 = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        assert_eq!(post3.6, 2, "local AO active join refcount");
        assert_eq!(
            (post3.2, post3.3, post3.4, post3.5),
            (snap_active.2, snap_active.3, snap_active.4, snap_active.5),
            "local AO active join: snapshot/expiry/timeout unchanged"
        );
        assert_index_membership(
            &alloc,
            &f1,
            PersistentNatPermit::AnyRemoteHost,
            false,
            "local AO after active join",
        );
        // Drain fully, then a fresh 0->1 at TIMEOUT_NS restores the
        // mint timeout — adoption is per-edge, not sticky-once.
        assert!(alloc.release_flow(f3, t2, 5_000, NatHolder::Untracked));
        assert!(alloc.release_flow(f2, t2, 6_000, NatHolder::Untracked));
        let pre_rejoin = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        assert_eq!(
            (pre_rejoin.4, pre_rejoin.5),
            (6_000 + TIMEOUT2_NS, TIMEOUT2_NS),
            "local AO drained: last release re-armed from the adopted timeout, got {pre_rejoin:?}"
        );
        let f4 = v4_flow("10.0.70.6", 40000, "8.8.4.4");
        alloc
            .reserve_address_only_persistent(
                f4,
                PoolAddressFamily::V4(&addrs),
                0,
                false,
                PersistentNatPermit::AnyRemoteHost,
                0,
                TIMEOUT_NS,
                7_000,
                NatHolder::Untracked,
                0,
            )
            .expect("local AO rejoin at mint timeout");
        let post4 = snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost);
        assert_eq!(
            (post4.2, post4.3),
            (pre_rejoin.4, pre_rejoin.5),
            "local AO rejoin: snapshot == pre-rejoin expiry/timeout"
        );
        assert_eq!(
            post4.4,
            7_000 + TIMEOUT_NS,
            "local AO rejoin: expiry refreshed to join-time + TIMEOUT_NS"
        );
        assert_eq!(
            post4.5, TIMEOUT_NS,
            "local AO rejoin: timeout re-adopts the caller's TIMEOUT_NS"
        );
        assert_eq!(post4.6, 1, "local AO rejoin: active_flows 0->1");
    }
}

/// #17028 divergence-1: the claimed-port BIB cap-fail must bump
/// `exhaustion_total`, exactly like the full-block branch. Ports
/// 1024..=1027 give a tracked-flow cap of 4, but `block_size = 2` /
/// `blocks_per_ip = 1` confine this subscriber to the block
/// [1024, 1025]: the mint claims 1024; each later same-BIB flow claims
/// 1025 as a temporary candidate, JOINS the existing lease, returns
/// its existing lease tuple (port 1024), and releases candidate 1025
/// back to the pool (flows = 4 = cap).
/// A fifth flow again claims 1025 and then hits the claimed-port
/// `admit_one` cap-fail (the divergence-1 bump) — ports 1026/1027 sit
/// outside the block and are never claimed, so the full-block
/// exhaustion branch cannot fire instead.
#[test]
fn bib_claimed_port_cap_fail_bumps_exhaustion_17028() {
    let params = DeterministicV6 {
        block_size: 2,
        blocks_per_ip: 1,
        ..BIB_PARAMS
    };
    let alloc = PortAllocator::new(1, 1024, 1027);
    let f1 = bib_flow(40000, "8.8.8.8");
    let t1 = alloc
        .allocate_deterministic_v6_at(f1, &[POOL], params, SUB, 1_000, NatHolder::Untracked)
        .expect("BIB mint on block [1024, 1025]");
    assert_eq!(t1.port, 1024, "mint claims the first block port");
    let before = alloc.snapshot().exhaustion_total;
    // Three more same-BIB flows (distinct remotes, same subscriber
    // transport): each claims 1025 temporarily and joins the lease,
    // returning the existing lease tuple (port 1024) while releasing
    // candidate 1025 back to the pool. They raise the tracked-flow
    // count to the cap of 4 without touching the exhaustion counter.
    for (i, dst) in ["1.1.1.1", "2.2.2.2", "3.3.3.3"].iter().enumerate() {
        let joined = alloc
            .allocate_deterministic_v6_at(
                bib_flow(40000, dst),
                &[POOL],
                params,
                SUB,
                2_000 + i as u64,
                NatHolder::Untracked,
            )
            .expect("claimed-port join below the cap");
        assert_eq!(
            joined, t1,
            "claimed-port join returns the existing lease tuple (port 1024)"
        );
        assert!(
            !alloc.debug_is_port_occupied(0, 1025),
            "claimed-port join must release temporary candidate 1025 back to the pool"
        );
        assert!(
            alloc.debug_is_port_occupied(0, 1024),
            "claimed-port join must leave the BIB's port 1024 occupied"
        );
        assert_eq!(
            alloc.snapshot().exhaustion_total,
            before,
            "claimed-port join below the cap must not bump exhaustion_total"
        );
    }
    assert_eq!(
        snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost).6,
        4,
        "lease carries all four admitted flows (tracked-flow cap reached)"
    );
    // Fifth flow: claims 1025 again, then the claimed-port
    // `admit_one` cap-fail refuses it.
    let f5 = bib_flow(40000, "4.4.4.4");
    let err =
        alloc.allocate_deterministic_v6_at(f5, &[POOL], params, SUB, 5_000, NatHolder::Untracked);
    assert!(
        err.is_err(),
        "fifth BIB flow at the claimed-port cap must exhaust, got {err:?}"
    );
    assert!(
        !alloc.debug_is_port_occupied(0, 1025),
        "cap-failed claimed-port call must release temporary candidate 1025 back to the pool"
    );
    assert_eq!(
        alloc.snapshot().exhaustion_total,
        before + 1,
        "claimed-port cap-fail must bump exhaustion_total (divergence-1 policy)"
    );
    // The lease itself is untouched by the refused join.
    assert_eq!(
        snapshot_fields(&alloc, &f1, PersistentNatPermit::AnyRemoteHost).6,
        4
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
    assert_eq!(st.6, 1, "revoked shell keeps its live flow count");
    // The original flow still releases cleanly off the shell.
    assert!(alloc.release_flow(f1, t1, 4_000, NatHolder::Untracked));
}
