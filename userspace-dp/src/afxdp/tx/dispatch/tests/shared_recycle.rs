// Shared-recycle target-index resolution tests: `shared_recycle_target_index`,
// `shared_recycle_target_index_for_split` (lookup hit / stale-scan / drop), and
// `record_shared_recycle_unknown_slot_drops` counter accounting. Local fixture
// `test_split_slot_at`.

use super::*;

fn test_split_slot_at(
    left: &[u32],
    current_index: usize,
    current_slot: u32,
    right: &[u32],
    target_index: usize,
) -> Option<u32> {
    if target_index == current_index {
        return Some(current_slot);
    }
    if target_index < current_index {
        return left.get(target_index).copied();
    }
    right
        .get(target_index.saturating_sub(current_index + 1))
        .copied()
}

#[test]
fn shared_recycle_target_uses_lookup_when_slot_matches() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 1);
    let slots = [10, 20, 30];

    assert_eq!(
        shared_recycle_target_index(slots.len(), &lookup, 20, |idx| slots.get(idx).copied()),
        Some(1)
    );
}

#[test]
fn shared_recycle_target_scans_when_lookup_is_stale_or_wrong_slot() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 1);
    let slots = [10, 99, 20];

    assert_eq!(
        shared_recycle_target_index(slots.len(), &lookup, 20, |idx| slots.get(idx).copied()),
        Some(2)
    );
}

#[test]
fn shared_recycle_target_drops_unknown_or_out_of_range_slot() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 99);
    let slots = [10, 30];

    assert_eq!(
        shared_recycle_target_index(slots.len(), &lookup, 20, |idx| slots.get(idx).copied()),
        None
    );
}

#[test]
fn shared_recycle_split_target_scans_when_lookup_is_stale() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 1);
    let left = [10, 99];
    let current_index = 2;
    let current_slot = 30;
    let right = [20, 40];

    assert_eq!(
        shared_recycle_target_index_for_split(left.len(), right.len(), &lookup, 20, |idx| {
            test_split_slot_at(&left, current_index, current_slot, &right, idx)
        }),
        Some(3)
    );
}

#[test]
fn shared_recycle_split_target_drops_unknown_slot() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 9);
    let left = [10, 30];
    let current_index = 2;
    let current_slot = 40;
    let right = [50, 60];

    assert_eq!(
        shared_recycle_target_index_for_split(left.len(), right.len(), &lookup, 20, |idx| {
            test_split_slot_at(&left, current_index, current_slot, &right, idx)
        }),
        None
    );
}

#[test]
fn shared_recycle_unknown_slot_drop_increments_tx_errors() {
    let live = BindingLiveState::new();

    record_shared_recycle_unknown_slot_drops(Some(&live), 2);
    record_shared_recycle_unknown_slot_drops(Some(&live), 0);
    record_shared_recycle_unknown_slot_drops(None, 5);

    assert_eq!(live.tx_errors.load(std::sync::atomic::Ordering::Relaxed), 2);
    assert_eq!(
        live.tx_shared_recycle_unknown_slot_drops
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );
}

// F-149 (#9904) STEP-0 repro: an unresolved `(slot, offset)` for a
// shared UMEM is drained, counted and never reinserted, so in a
// shared-UMEM group each drop permanently shrinks total RX/TX capacity
// by a frame. In a single-region worker (all surviving bindings share
// one UMEM allocation) the offset is NOT foreign to any survivor, so
// it must be preserved via the same-region backstop instead of lost.
// RED on base (dropped); GREEN once the backstop rescues it.
#[test]
fn shared_recycle_unknown_slot_preserves_frame_in_single_region_9904() {
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
    ];
    // Single-region worker: both survivors share one UMEM allocation.
    bindings[1].umem = bindings[0].umem.clone();
    assert!(
        bindings[1].umem.shares_allocation_with(&bindings[0].umem),
        "fixture must share one UMEM allocation"
    );
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    // Slot 99 never existed: stale/removed target, live shared region.
    let mut shared_recycles = vec![(99u32, 0x1000u64)];
    let _ = apply_shared_recycles_to_bindings(&mut bindings, &lookup, &mut shared_recycles);
    assert!(shared_recycles.is_empty(), "recycles must be drained");
    let preserved = bindings
        .iter()
        .any(|b| b.tx_pipeline.pending_fill_frames.contains(&0x1000u64));
    assert!(
        preserved,
        "F-149 (#9904) RED: unknown-slot offset 0x1000 for a live shared \
         UMEM region was dropped instead of preserved via the same-region \
         backstop — each such drop permanently shrinks RX/TX capacity by a frame"
    );
}

// F-149 (#9904): the backstop must NOT fire in a mixed-region worker —
// with two live allocations the unknown offset's home region is
// unknowable from `(slot, offset)` alone (private UMEMs share the same
// numeric ranges), so the fail-closed drop path is kept and the rescued
// counter stays at zero.
#[test]
fn shared_recycle_unknown_slot_still_drops_in_mixed_region_9904() {
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
    ];
    assert!(
        !bindings[1].umem.shares_allocation_with(&bindings[0].umem),
        "fixture must have two separate UMEM allocations"
    );
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mut shared_recycles = vec![(99u32, 0x1000u64)];
    let dropped =
        apply_shared_recycles_to_bindings(&mut bindings, &lookup, &mut shared_recycles);
    assert_eq!(dropped, 1);
    assert!(shared_recycles.is_empty(), "recycles must be drained");
    for (idx, binding) in bindings.iter().enumerate() {
        assert!(
            !binding.tx_pipeline.pending_fill_frames.contains(&0x1000u64),
            "mixed-region unknown offset must not land in binding {idx}'s fill queue"
        );
    }
    let live0 = &bindings[0].live;
    assert_eq!(live0.tx_errors.load(Ordering::Relaxed), 1);
    assert_eq!(
        live0.tx_shared_recycle_unknown_slot_drops.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        live0.tx_shared_recycle_unknown_slot_rescued.load(Ordering::Relaxed),
        0
    );
}

// F-149 (#9904): error taxonomy for a rescued unknown — it joins the
// `tx_errors` aggregate (an unknown slot is a routing anomaly regardless
// of fate) with the rescued subset distinguishing recovery from loss:
// `tx_errors == drops + rescued`.
#[test]
fn shared_recycle_unknown_slot_rescue_pins_error_taxonomy_9904() {
    let live = BindingLiveState::new();
    record_shared_recycle_unknown_slot_rescues(Some(&live), 2);
    record_shared_recycle_unknown_slot_rescues(Some(&live), 0);
    record_shared_recycle_unknown_slot_rescues(None, 5);
    assert_eq!(live.tx_errors.load(Ordering::Relaxed), 2);
    assert_eq!(
        live.tx_shared_recycle_unknown_slot_rescued.load(Ordering::Relaxed),
        2
    );
    assert_eq!(
        live.tx_shared_recycle_unknown_slot_drops.load(Ordering::Relaxed),
        0
    );
}

// F-149 (#9904): split-slice path (`shared_recycle.rs:26`, the issue's
// cited site) rescues exactly like the all-bindings cleanup path when
// the worker is single-region.
#[test]
fn shared_recycle_split_unknown_slot_rescues_in_single_region_9904() {
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        BindingWorker::new_for_mirror_test(2, 0, 33, 0),
    ];
    bindings[1].umem = bindings[0].umem.clone();
    bindings[2].umem = bindings[0].umem.clone();
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let (left, rest) = bindings.split_at_mut(1);
    let (mid, right) = rest.split_at_mut(1);
    let current = &mut mid[0];
    let mut shared_recycles = vec![(99u32, 0x2000u64)];
    apply_shared_recycles(left, 1, current, right, &lookup, &mut shared_recycles);
    assert!(shared_recycles.is_empty(), "recycles must be drained");
    assert!(
        current.tx_pipeline.pending_fill_frames.contains(&0x2000u64),
        "split-path unknown-slot offset must be rescued to the current \
         binding's fill queue in a single-region worker"
    );
    assert_eq!(
        current.live.tx_shared_recycle_unknown_slot_rescued.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        current.live.tx_shared_recycle_unknown_slot_drops.load(Ordering::Relaxed),
        0
    );
}

// F-149 (#9904): split path with MIXED allocations still fails closed —
// the backstop must not fire when the offset's home region is unknowable.
#[test]
fn shared_recycle_split_unknown_slot_still_drops_in_mixed_region_9904() {
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        BindingWorker::new_for_mirror_test(2, 0, 33, 0),
    ];
    assert!(
        !bindings[1].umem.shares_allocation_with(&bindings[0].umem),
        "fixture must have separate UMEM allocations"
    );
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let (left, rest) = bindings.split_at_mut(1);
    let (mid, right) = rest.split_at_mut(1);
    let current = &mut mid[0];
    let mut shared_recycles = vec![(99u32, 0x3000u64)];
    apply_shared_recycles(left, 1, current, right, &lookup, &mut shared_recycles);
    assert!(shared_recycles.is_empty(), "recycles must be drained");
    assert!(
        !current.tx_pipeline.pending_fill_frames.contains(&0x3000u64),
        "mixed-region split-path unknown must not be rescued"
    );
    assert_eq!(current.live.tx_errors.load(Ordering::Relaxed), 1);
    assert_eq!(
        current.live.tx_shared_recycle_unknown_slot_drops.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        current.live.tx_shared_recycle_unknown_slot_rescued.load(Ordering::Relaxed),
        0
    );
}

// F-149 (#9904): the single-binding worker is trivially single-region, so
// an unknown slot there rescues to the sole survivor. Sound (not the
// forbidden arbitrary push): with one live region every worker-local
// offset belongs to it — there is no second region to be foreign to.
#[test]
fn shared_recycle_unknown_slot_rescues_in_single_binding_worker_9904() {
    let mut bindings = vec![BindingWorker::new_for_mirror_test(0, 0, 11, 0)];
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mut shared_recycles = vec![(99u32, 0x4000u64)];
    let dropped =
        apply_shared_recycles_to_bindings(&mut bindings, &lookup, &mut shared_recycles);
    assert_eq!(dropped, 0);
    assert!(
        bindings[0].tx_pipeline.pending_fill_frames.contains(&0x4000u64),
        "single-binding unknown-slot offset must be rescued, not lost"
    );
    assert_eq!(bindings[0].live.tx_errors.load(Ordering::Relaxed), 1);
    assert_eq!(
        bindings[0].live.tx_shared_recycle_unknown_slot_drops.load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        bindings[0].live.tx_shared_recycle_unknown_slot_rescued.load(Ordering::Relaxed),
        1
    );
}
