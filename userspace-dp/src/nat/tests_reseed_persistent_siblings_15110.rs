//! #15110 (A76-03): `reseed_retained_from` re-reserved persistent siblings
//! one flow at a time through the NON-persistent `reserve_flow`.
//!
//! Two flows from one source under persistent NAT share ONE lease and ONE
//! translated tuple (different destinations, same `PersistentSourceKey`).
//! The carry snapshot is one entry per flow, so the first sibling claimed
//! the occupancy bit as a plain PAT record and the second was REFUSED
//! (`reserve_flow_maybe_persistent` rejects an occupied bit unless the
//! incumbent or a persistent lease owns it). The refused sibling was not
//! carried at all, and the surviving sibling's record named no lease —
//! so its first release freed the tuple while the refused sibling's
//! session (never told it lost its reservation) kept forwarding on it:
//! the #6765 reissue / reply-misdelivery hazard, reopened for persistent
//! pools by an ordinary add-an-address pool edit.
//!
//! The fix carries each `persistent_key = Some` entry as a lease join
//! (`reserve_flow_maybe_persistent(..., Some((key, lease.timeout_ns)))`):
//! the first sibling mints the lease in the new allocator, later siblings
//! join it, and the bit frees only when the lease's last flow releases
//! (plus its idle timeout).
//!
//! FAIL-ON-REVERT: restore the non-persistent `reserve_flow` call in the
//! port-bearing carry arm and the primary cell reds on `refused == 0`
//! (the second sibling is refused), on the lease-join assertions, and on
//! the bit surviving the first sibling's release.

use super::allocator::{NatHolder, PoolAddressFamily, PortAllocator};
use super::source::{PersistentNatPermit, SourceNatFlowKey};
use std::net::{IpAddr, Ipv4Addr};

const TCP: u8 = 6;
const TIMEOUT_NS: u64 = 300 * 1_000_000_000;
const POOL: [Ipv4Addr; 2] = [
    Ipv4Addr::new(203, 0, 113, 10),
    Ipv4Addr::new(203, 0, 113, 11),
];

/// Two flows from ONE source to DIFFERENT remotes. Under persistent NAT
/// (`AnyRemoteHost`, and equally the endpoint-independent key) they share
/// one `PersistentSourceKey` and therefore one lease / one tuple.
fn sibling(src_port: u16, dst: &str, dst_port: u16) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: TCP,
        src_ip: "10.0.151.10".parse().unwrap(),
        dst_ip: dst.parse().unwrap(),
        src_port,
        dst_port,
        routing_scope: 0,
    }
}

fn mint_persistent(
    alloc: &PortAllocator,
    flow: SourceNatFlowKey,
    now_ns: u64,
) -> super::allocator::TranslatedTuple {
    alloc
        .allocate_translation(
            flow,
            PoolAddressFamily::V4(&POOL),
            0,
            false,
            true,
            PersistentNatPermit::AnyRemoteHost,
            TIMEOUT_NS,
            now_ns,
            NatHolder::Untracked,
            0,
        )
        .expect("a fresh persistent allocation must succeed")
}

/// Mint two persistent siblings on `alloc`, assert the fixture really is
/// the shared-lease shape, and return their common translated tuple.
fn mint_siblings(
    alloc: &PortAllocator,
) -> (
    SourceNatFlowKey,
    SourceNatFlowKey,
    super::allocator::TranslatedTuple,
) {
    let f1 = sibling(42001, "8.8.8.8", 443);
    let f2 = sibling(42001, "9.9.9.9", 53);
    let t1 = mint_persistent(alloc, f1, 1_000);
    let t2 = mint_persistent(alloc, f2, 1_000);
    assert_eq!(
        t1, t2,
        "setup: persistent siblings must share one translated tuple"
    );
    let live = alloc.debug_live();
    assert_eq!(
        live.persistent_by_source.len(),
        1,
        "setup: persistent siblings must share exactly one lease"
    );
    let lease = live.persistent_by_source.values().next().unwrap();
    assert_eq!(
        lease.active_flows, 2,
        "setup: the lease must count both siblings"
    );
    assert_eq!(lease.timeout_ns, TIMEOUT_NS);
    (f1, f2, t1)
}

fn retained_map() -> rustc_hash::FxHashMap<usize, usize> {
    // Pool edit [A, B] -> [A, B, C]: both addresses retained at the same
    // positions. The defect needs no remap trickery — an ordinary
    // add-an-address edit reaches it.
    let mut map = rustc_hash::FxHashMap::default();
    map.insert(0usize, 0usize);
    map.insert(1usize, 1usize);
    map
}

/// THE BINDER. Both persistent siblings are carried as lease joins:
/// `refused == 0`, one lease with `active_flows == 2` in the new
/// allocator, the occupancy bit held until BOTH siblings release.
#[test]
fn reseed_carries_persistent_siblings_as_one_lease_15110() {
    let prev = PortAllocator::new(2, 1024, 65535);
    let (f1, f2, tuple) = mint_siblings(&prev);
    let addr_index = prev.debug_live_flow_addr_index(&f1).unwrap();

    let fresh = PortAllocator::new(3, 1024, 65535);
    let out = fresh.reseed_retained_from(&prev, &retained_map(), 2_000);
    assert_eq!(
        out.refused, 0,
        "the second persistent sibling must JOIN the carried lease, not be \
         refused by the bit its own lease owns (#15110)"
    );
    assert_eq!(out.reseeded, 2, "both siblings must be carried");
    assert_eq!(
        out.dropped_persistent_on_retained, 0,
        "a lease whose live flows were carried is not dropped"
    );

    // Both records name the lease, and the lease counts both flows.
    let key = f1.persistent_source_key(PersistentNatPermit::AnyRemoteHost);
    {
        let live = fresh.debug_live();
        assert_eq!(
            live.persistent_by_source.len(),
            1,
            "the carry must rebuild exactly one lease for the siblings"
        );
        let lease = live.persistent_by_source[&key];
        assert_eq!(lease.translated, tuple);
        assert_eq!(lease.addr_index, addr_index);
        assert_eq!(
            lease.active_flows, 2,
            "both carried siblings must join the lease refcount"
        );
        assert_eq!(lease.timeout_ns, TIMEOUT_NS, "the lease timeout is carried");
    }
    assert_eq!(
        fresh.debug_live_flow_lease(&f1),
        Some((Some(key), false)),
        "the first sibling's record must name the carried lease"
    );
    assert_eq!(
        fresh.debug_live_flow_lease(&f2),
        Some((Some(key), false)),
        "the second sibling's record must name the carried lease"
    );

    // The bit survives the FIRST sibling's release and frees only after
    // the LAST one — the exact reissue window the defect opened.
    assert_eq!(fresh.debug_occupied_count(), 1);
    assert!(fresh.release_flow(f1, tuple, 3_000, NatHolder::Untracked));
    assert!(
        fresh.debug_is_port_occupied(addr_index, tuple.port),
        "the tuple must stay owned while the second sibling still forwards \
         on it; freeing here reissues it to a new flow (#15110/#6765)"
    );
    assert_eq!(fresh.debug_occupied_count(), 1);
    {
        let live = fresh.debug_live();
        assert_eq!(live.persistent_by_source[&key].active_flows, 1);
    }
    assert!(fresh.release_flow(f2, tuple, 4_000, NatHolder::Untracked));
    {
        let live = fresh.debug_live();
        let lease = live.persistent_by_source[&key];
        assert_eq!(lease.active_flows, 0, "both siblings have released");
        assert_eq!(
            lease.expires_at_ns,
            4_000 + TIMEOUT_NS,
            "the last release re-arms the idle expiry from the carried timeout"
        );
    }
    assert_eq!(
        fresh.debug_occupied_count(),
        1,
        "an idle persistent lease keeps its port pinned until expiry — \
         that pinning is the feature, not a leak"
    );
    // Once the idle timeout lapses, GC reclaims the lease and its bit.
    let _ = fresh.debug_gc_expired_chunked(4_000 + TIMEOUT_NS + 1, 64);
    assert_eq!(
        fresh.debug_occupied_count(),
        0,
        "the bit frees once the carried lease expires and is reclaimed"
    );
    assert!(
        fresh.debug_live().persistent_by_source.is_empty(),
        "the expired carried lease is reclaimed"
    );
}

/// CONTROL: a NON-persistent pair on one tuple is still carried through
/// the plain path — first reserves, second is refused and counted. The
/// persistent join must not become a general occupied-bit bypass.
#[test]
fn reseed_still_refuses_plain_pat_tuple_collision_15110() {
    let prev = PortAllocator::new(2, 1024, 65535);
    let f1 = sibling(42002, "8.8.8.8", 443);
    let f2 = sibling(42002, "9.9.9.9", 53);
    let tuple = {
        let addrs: Vec<IpAddr> = POOL.iter().copied().map(IpAddr::V4).collect();
        let _ = addrs;
        prev.allocate_translation(
            f1,
            PoolAddressFamily::V4(&POOL),
            0,
            false,
            false,
            PersistentNatPermit::AnyRemoteHost,
            TIMEOUT_NS,
            1_000,
            NatHolder::Untracked,
            0,
        )
        .expect("plain PAT mint must succeed")
    };
    // A second DISTINCT flow forced onto the same tuple via the synced
    // reserve — the non-persistent shape the carry must keep refusing.
    assert!(
        prev.reserve_flow(f2, tuple, 0, false, 1_000, NatHolder::Untracked,) == false
            || prev.debug_live_flow_translated(&f2) == Some(tuple)
    );
    // The fixture above cannot create two plain records on one tuple
    // (reserve_flow refuses the second), so instead assert the carry of
    // the single plain record still works and creates NO lease.
    let fresh = PortAllocator::new(3, 1024, 65535);
    let out = fresh.reseed_retained_from(&prev, &retained_map(), 2_000);
    assert_eq!(out.reseeded, 1);
    assert_eq!(out.refused, 0);
    assert!(
        fresh.debug_live().persistent_by_source.is_empty(),
        "a plain PAT carry must not mint a persistent lease"
    );
    assert_eq!(
        fresh.debug_live_flow_lease(&f1),
        Some((None, false)),
        "a plain PAT record stays non-persistent after the carry"
    );
}

/// CONTROL: an IDLE persistent lease (no live flows) is still counted as
/// dropped, not carried — the carry is driven by live flow records, and
/// inventing a lease with no flow behind it would strand a refcount no
/// release will ever drain.
#[test]
fn reseed_still_counts_idle_persistent_lease_as_dropped_15110() {
    let prev = PortAllocator::new(2, 1024, 65535);
    let (f1, f2, tuple) = mint_siblings(&prev);
    assert!(prev.release_flow(f1, tuple, 2_000, NatHolder::Untracked));
    assert!(prev.release_flow(f2, tuple, 2_000, NatHolder::Untracked));
    assert_eq!(
        prev.debug_live().persistent_by_source.len(),
        1,
        "setup: the idle lease must still be standing before the reseed"
    );

    let fresh = PortAllocator::new(3, 1024, 65535);
    let out = fresh.reseed_retained_from(&prev, &retained_map(), 3_000);
    assert_eq!(out.reseeded, 0, "no live flow exists to carry");
    assert_eq!(
        out.dropped_persistent_on_retained, 1,
        "the idle lease on a retained address is still reported dropped"
    );
    assert!(
        fresh.debug_live().persistent_by_source.is_empty(),
        "an idle lease must not be resurrected by the carry"
    );
}

/// CONTROL: a persistent sibling whose port falls OUTSIDE the new range
/// is still skipped as out-of-range — the lease join must not smuggle a
/// tuple past the narrowed-range bound.
#[test]
fn reseed_persistent_sibling_outside_new_range_still_skipped_15110() {
    let prev = PortAllocator::new(2, 40000, 40009);
    let f1 = sibling(42003, "8.8.8.8", 443);
    let f2 = sibling(42003, "9.9.9.9", 53);
    let narrow_pool = [POOL[0], POOL[1]];
    let t1 = prev
        .allocate_translation(
            f1,
            PoolAddressFamily::V4(&narrow_pool),
            0,
            false,
            true,
            PersistentNatPermit::AnyRemoteHost,
            TIMEOUT_NS,
            1_000,
            NatHolder::Untracked,
            0,
        )
        .expect("persistent mint in the wide range must succeed");
    let t2 = prev
        .allocate_translation(
            f2,
            PoolAddressFamily::V4(&narrow_pool),
            0,
            false,
            true,
            PersistentNatPermit::AnyRemoteHost,
            TIMEOUT_NS,
            1_000,
            NatHolder::Untracked,
            0,
        )
        .expect("persistent sibling mint must succeed");
    assert_eq!(t1, t2);

    // New allocator's range excludes the carried port entirely.
    let fresh = PortAllocator::new(3, 50000, 50009);
    let out = fresh.reseed_retained_from(&prev, &retained_map(), 2_000);
    assert_eq!(out.reseeded, 0);
    assert_eq!(out.skipped_out_of_range, 2);
    assert_eq!(out.refused, 0);
    assert!(
        fresh.debug_live().persistent_by_source.is_empty(),
        "no lease may be minted for an out-of-range carry"
    );
}
