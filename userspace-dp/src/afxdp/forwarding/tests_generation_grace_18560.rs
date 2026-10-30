//! #18560: the post-advance metadata generation grace. A publish advances the
//! worker's validation before Go rewrites `userspace_ctrl`, so packets keep
//! arriving stamped with the pair the worker just left. These cells pin which
//! stamps the grace admits (the previous pair, inside the deadline) and which it
//! must never admit (a stamp AHEAD of the worker — #6592 — an unrelated older
//! stamp, a reset, anything after the deadline).

use super::super::test_fixtures::*;
use super::*;

fn vs(config: u64, fib: u32) -> ValidationState {
    ValidationState {
        snapshot_installed: true,
        config_generation: config,
        fib_generation: fib,
        neighbor_generation: 0,
    }
}

fn stamped(config: u64, fib: u32) -> UserspaceDpMeta {
    let mut meta = valid_meta();
    meta.config_generation = config;
    meta.fib_generation = fib;
    meta
}

const T0: u64 = 10_000_000_000;

#[test]
fn route_only_republish_admits_previous_config_stamp_18560() {
    // apply_snapshot of a routes-only overlay: config 11 -> 12, FIB unchanged.
    let grace = MetadataGenerationGrace::after_advance(vs(11, 7), vs(12, 7), T0);
    let (disposition, admitted) =
        classify_metadata_with_grace(stamped(11, 7), vs(12, 7), grace, T0 + 1_000_000);
    assert_eq!(disposition, PacketDisposition::Valid);
    assert!(admitted, "the admit must be counted, or the witness counter lies");
    // The strict classifier still calls the same packet a mismatch: the
    // grace is an addition, not a weakening of classify_metadata.
    assert_eq!(
        classify_metadata(stamped(11, 7), vs(12, 7)),
        PacketDisposition::ConfigGenerationMismatch
    );
}

#[test]
fn fib_bump_admits_previous_fib_stamp_18560() {
    let grace = MetadataGenerationGrace::after_advance(vs(12, 7), vs(12, 8), T0);
    let (disposition, admitted) =
        classify_metadata_with_grace(stamped(12, 7), vs(12, 8), grace, T0);
    assert_eq!(disposition, PacketDisposition::Valid);
    assert!(admitted);
}

#[test]
fn snapshot_plus_bump_admits_either_previous_half_18560() {
    // apply_snapshot (11 -> 12) and its FIB bump (7 -> 8) land in one
    // worker tick; Go has rewritten neither half of the stamp yet.
    let grace = MetadataGenerationGrace::after_advance(vs(11, 7), vs(12, 8), T0);
    for (c, f) in [(11, 7), (12, 7), (11, 8)] {
        let (disposition, admitted) =
            classify_metadata_with_grace(stamped(c, f), vs(12, 8), grace, T0);
        assert_eq!(disposition, PacketDisposition::Valid, "stamp ({c},{f})");
        assert!(admitted, "stamp ({c},{f})");
    }
}

#[test]
fn stamp_ahead_of_worker_stays_dropped_18560() {
    // #6592: the shim already stamps the NEW pair while this worker still
    // holds the old tables. Forwarding it under stale tables is the defect
    // the fence exists for, so no grace may admit it.
    let grace = MetadataGenerationGrace::after_advance(vs(10, 6), vs(11, 7), T0);
    let (disposition, admitted) =
        classify_metadata_with_grace(stamped(12, 7), vs(11, 7), grace, T0);
    assert_eq!(disposition, PacketDisposition::ConfigGenerationMismatch);
    assert!(!admitted);
    let (disposition, admitted) =
        classify_metadata_with_grace(stamped(11, 8), vs(11, 7), grace, T0);
    assert_eq!(disposition, PacketDisposition::FibGenerationMismatch);
    assert!(!admitted);
}

#[test]
fn older_than_previous_stamp_stays_dropped_18560() {
    let grace = MetadataGenerationGrace::after_advance(vs(11, 7), vs(12, 7), T0);
    let (disposition, admitted) =
        classify_metadata_with_grace(stamped(10, 7), vs(12, 7), grace, T0);
    assert_eq!(disposition, PacketDisposition::ConfigGenerationMismatch);
    assert!(!admitted);
}

#[test]
fn grace_expires_18560() {
    let grace = MetadataGenerationGrace::after_advance(vs(11, 7), vs(12, 7), T0);
    let (disposition, admitted) = classify_metadata_with_grace(
        stamped(11, 7),
        vs(12, 7),
        grace,
        T0 + METADATA_GENERATION_GRACE_NS,
    );
    assert_eq!(disposition, PacketDisposition::ConfigGenerationMismatch);
    assert!(!admitted);
}

#[test]
fn reset_first_install_and_neighbor_only_earn_no_grace_18560() {
    // A generation that went DOWN is a config-transition reset: strict.
    assert_eq!(
        MetadataGenerationGrace::after_advance(vs(20, 7), vs(3, 7), T0),
        MetadataGenerationGrace::default()
    );
    assert_eq!(
        MetadataGenerationGrace::after_advance(vs(20, 9), vs(21, 2), T0),
        MetadataGenerationGrace::default()
    );
    // No previous snapshot, no previous stamp.
    let mut none = vs(0, 0);
    none.snapshot_installed = false;
    assert_eq!(
        MetadataGenerationGrace::after_advance(none, vs(1, 1), T0),
        MetadataGenerationGrace::default()
    );
    // A neighbor-only republish moves neither stamp.
    let mut neighbor = vs(12, 7);
    neighbor.neighbor_generation = 1;
    assert_eq!(
        MetadataGenerationGrace::after_advance(vs(12, 7), neighbor, T0),
        MetadataGenerationGrace::default()
    );
    // And the default grace admits nothing.
    let (disposition, admitted) = classify_metadata_with_grace(
        stamped(11, 7),
        vs(12, 7),
        MetadataGenerationGrace::default(),
        0,
    );
    assert_eq!(disposition, PacketDisposition::ConfigGenerationMismatch);
    assert!(!admitted);
}

#[test]
fn grace_keeps_the_address_family_gate_18560() {
    let grace = MetadataGenerationGrace::after_advance(vs(11, 7), vs(12, 7), T0);
    let mut meta = stamped(11, 7);
    meta.addr_family = 0;
    let (disposition, admitted) = classify_metadata_with_grace(meta, vs(12, 7), grace, T0);
    assert_eq!(disposition, PacketDisposition::UnsupportedPacket);
    assert!(!admitted);
}
