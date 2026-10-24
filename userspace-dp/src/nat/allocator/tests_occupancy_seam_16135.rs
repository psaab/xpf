//! #16135 seam tests: `AddressOccupancy` driven WITHOUT a `PortAllocator`.
//!
//! Before the split every occupancy behaviour was only reachable through
//! the facade or its `#[cfg(test)]` debug accessors. These cells pin the
//! moved module's contract directly: fresh-cursor claim, FIFO recycle
//! (oldest-freed first, #3011), reserve / already-held rejection, the
//! deterministic block probe (#9902), and port/offset range rejection.
//! They do NOT cover retain-on-collision (a recycled token whose bit is
//! already set being re-queued, 062-10) or the exhausted-address
//! short-circuit counters (`recycle_scan_pops` / `recycle_scan_walks`);
//! that coverage stays with the facade-level tests in tests_pool.rs.
//! Reverting the split (or re-inlining occupancy into the facade) breaks
//! these at compile time; changing FIFO/atomic behaviour breaks them at
//! run time.

use super::occupancy::AddressOccupancy;

#[test]
fn occupancy_seam_claims_fresh_then_recycles_fifo_16135() {
    // #16011: seeded claim with distinct keys; the SET of fresh ports is
    // the whole range (order is keyed, not ascending), then the FIFO
    // ring drains oldest-freed first once every offset is occupied/free.
    let occ = AddressOccupancy::new(1024, 4);
    let mut fresh: Vec<u16> = (0..4u64)
        .map(|k| occ.claim_seeded(k, 0xA5A5).expect("fresh port"))
        .collect();
    fresh.sort_unstable();
    assert_eq!(
        fresh,
        vec![1024, 1025, 1026, 1027],
        "fresh claims must cover the range exactly once"
    );
    assert_eq!(
        occ.claim_seeded(99, 0xA5A5),
        None,
        "full address claims nothing"
    );
    // Free in reverse order; FIFO must hand back oldest-freed first via
    // the probe (the freed offsets are the only free ones).
    assert!(occ.free_recycle(1025));
    assert!(occ.free_recycle(1024));
    // #16011: keyed probe reaches freed offsets in keyed order.
    let mut reused = vec![
        occ.claim_seeded(100, 0xA5A5).expect("freed port"),
        occ.claim_seeded(101, 0xA5A5).expect("freed port"),
    ];
    reused.sort_unstable();
    assert_eq!(reused, vec![1024, 1025]);
    assert_eq!(occ.claim_seeded(102, 0xA5A5), None);
    assert_eq!(occ.occupied_count(), 4);
}

#[test]
fn occupancy_seam_reserve_and_block_probe_16135() {
    let occ = AddressOccupancy::new(1024, 64);
    assert!(occ.reserve(1024));
    assert!(!occ.reserve(1024), "a held bit cannot be re-claimed");
    // #16011: keyed block probe claims a free port inside the block
    // (1024 is reserved); exact port is secret-dependent.
    let claimed = occ.claim_in_block(1024, 1087).expect("free port in block");
    assert!(
        (1025..=1087).contains(&claimed),
        "keyed claim must stay in block, got {claimed}"
    );
    assert_eq!(occ.claim_in_block(1024, 1024), None);
    assert!(occ.free_no_recycle(1024));
    assert_eq!(occ.claim_in_block(1024, 1024), Some(1024));
}

#[test]
fn occupancy_seam_port_of_rejects_out_of_range_16135() {
    let occ = AddressOccupancy::new(1024, 4);
    assert_eq!(occ.port_of(0), Some(1024));
    assert_eq!(occ.port_of(4), None, "#5660: out-of-range must not wrap");
    assert_eq!(occ.offset_of(1023), None);
    assert_eq!(occ.offset_of(1028), None);
}

const T0: u64 = 1_000_000_000_000;
const QUARANTINE_NS: u64 = 60_000_000_000;

/// #16035 fold (a): a repeat free of an already-queued port must move
/// its stamp to the LATEST free. Shape: claim both ports, free one
/// at T0 (token queued), re-claim its bit out-of-band via
/// `claim_in_block` (which ignores the ring), free it again at
/// T0+50s. Without the stamp update the token keeps T0 and becomes
/// claimable at T0+60s — 50 s before the second free's window ends.
/// With it, the ring yields nothing until T0+110s.
#[test]
fn repeat_free_refreshes_quarantine_stamp_16035() {
    let occ = AddressOccupancy::new(1024, 2);
    let p1 = occ.claim_seeded(1, 0xA5A5).expect("fresh 1");
    let _p2 = occ.claim_seeded(2, 0xA5A5).expect("fresh 2");
    assert!(occ.free_recycle_at(p1, T0));
    // Out-of-band reclaim of the same bit, then a second free.
    assert_eq!(occ.claim_in_block(p1, p1), Some(p1));
    assert!(occ.free_recycle_at(p1, T0 + 50_000_000_000));
    // Exactly one token, still quarantined at the FIRST stamp's expiry.
    assert_eq!(occ.claim_recycled_only_at(T0 + QUARANTINE_NS), None);
    assert_eq!(occ.claim_recycled_only_at(T0 + 110_000_000_000 - 1), None);
    assert_eq!(
        occ.claim_recycled_only_at(T0 + 110_000_000_000),
        Some(p1),
        "claimable only when the SECOND free's delay elapses"
    );
}

/// #16035 fold (d): a collision-retained token (popped, bit occupied
/// out-of-band, re-queued) must keep its dedup bit, so a later free
/// of the occupying bit updates the SAME token instead of pushing a
/// duplicate. Pre-fix requeue left the bit unset after the collision
/// pop unmarked it, and the ring ended with two tokens for one port.
#[test]
fn collision_requeue_keeps_dedup_bit_16035() {
    let occ = AddressOccupancy::new(1024, 2);
    let p1 = occ.claim_seeded(1, 0xA5A5).expect("fresh 1");
    let _p2 = occ.claim_seeded(2, 0xA5A5).expect("fresh 2");
    assert!(occ.free_recycle_at(p1, T0));
    // Out-of-band owner takes the bit while the token is queued.
    assert_eq!(occ.claim_in_block(p1, p1), Some(p1));
    // Ring walk at post-quarantine time: pops the token, CAS fails
    // (occupied), retains it.
    assert_eq!(occ.claim_recycled_only_at(T0 + QUARANTINE_NS), None);
    // The out-of-band owner frees: exactly one token must exist.
    assert!(occ.free_recycle_at(p1, T0 + QUARANTINE_NS));
    assert_eq!(
        occ.claim_recycled_only_at(T0 + 2 * QUARANTINE_NS),
        Some(p1),
        "the single retained token claims the port"
    );
    assert_eq!(
        occ.claim_recycled_only_at(T0 + 2 * QUARANTINE_NS),
        None,
        "no duplicate token may remain for the same port"
    );
}
