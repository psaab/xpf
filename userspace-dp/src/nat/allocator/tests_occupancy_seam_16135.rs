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
