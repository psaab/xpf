// Phase 10 + cross-tick shared-UMEM recycle routing (#1443).
//
// Pure code motion from `dispatch/mod.rs` — every function in this
// file lived in `dispatch.rs` before the #1443 split. The dispatch
// `mod.rs` re-exports `apply_shared_recycles`,
// `apply_shared_recycles_to_bindings`, and `resolve_tx_binding_ifindex`
// at `pub(in crate::afxdp)` so the 16+ external call sites and the
// `use self::tx::dispatch::*;` glob at `afxdp/mod.rs:140` resolve
// verbatim.

use super::*;

pub(in crate::afxdp) fn apply_shared_recycles(
    left: &mut [BindingWorker],
    current_index: usize,
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    if shared_recycles.is_empty() {
        return;
    }
    // F-149 (#9904): computed ONCE per drain, not per unknown slot: O(N)
    // `Rc::ptr_eq` compares where N = worker bindings (typically < 32) —
    // single-digit ns against the drain's per-frame ring ops. Deliberately
    // not lazy-gated behind the first unknown: the gate would cost the same
    // order as the scan it skips.
    let backstop = split_is_single_region(left, current, right);
    let mut dropped = 0u64;
    let mut rescued = 0u64;
    let mut first_drop = None;
    let mut first_rescue = None;
    for (slot, offset) in shared_recycles.drain(..) {
        if route_shared_recycle_by_slot(
            left,
            current_index,
            current,
            right,
            binding_lookup,
            slot,
            offset,
        ) {
            continue;
        }
        if backstop {
            // Same-region per the premise above: kernel-masked to the chunk
            // base on consume, bounds-checked, growth-bounded. See note.
            current.tx_pipeline.pending_fill_frames.push_back(offset);
            first_rescue.get_or_insert((slot, offset));
            rescued = rescued.saturating_add(1);
        } else {
            first_drop.get_or_insert((slot, offset));
            dropped = dropped.saturating_add(1);
        }
    }
    log_shared_recycle_unknown_slot_drops(dropped, first_drop);
    log_shared_recycle_unknown_slot_rescues(rescued, first_rescue);
    record_shared_recycle_unknown_slot_drops(Some(&current.live), dropped);
    record_shared_recycle_unknown_slot_rescues(Some(&current.live), rescued);
}

// F-149 (#9904): same-region backstop premise, stated because the rescue
// below is sound ONLY while all three hold:
//
// (a) Recycle provenance is worker-local. The `shared_recycles`
// accumulator is a worker-local `Vec` (built per poll loop, never sent
// across threads), and every record in it originates from this worker's
// own `PreparedTxRequest`s. Cross-worker redirect carries owned `TxRequest`
// bytes (`MpscInbox<TxRequest>`), never `PreparedTxRequest`, so no foreign
// slot/offset pair migrates in.
//
// (b) Shared groups are intra-worker. `WorkerUmem` is `Rc`-shared
// (`shares_allocation_with` is `Rc::ptr_eq`), so two bindings share an
// allocation only within one worker.
//
// (c) Bindings are immutable after setup. `WorkerBindingLookup` is built
// once in `worker/loop_body/setup.rs` and the bindings slice is never
// pushed/removed/reordered in the poll loop, so an unknown slot is a
// routing anomaly (stale/buggy stamp), never a departed binding whose
// region vanished.
//
// Given (a)+(b)+(c), in a single-region worker EVERY offset in the
// accumulator belongs to the one live region, so routing an unknown-slot
// offset to any survivor's fill queue is NOT the foreign-offset push
// `tx/README.md` forbids — it is a same-region backstop. In a mixed-region
// worker the offset's home region is unknowable from `(slot, offset)`
// alone (private UMEMs share the same numeric ranges), so the fail-closed
// drop path is kept. A future cross-worker recycle producer MUST extend
// the record with region identity before touching this.
//
// Offset shape at the rescue pushes: the offset may be headroom-shifted
// (RX `desc.addr`) or TX-shifted (VLAN descriptor views) within its chunk;
// the kernel's aligned-mode mask maps any intra-chunk address back to the
// chunk base (F-069), and out-of-range values cannot corrupt — the kernel
// bounds-checks FILL entries and accounts violations as invalid descs
// (`rx_invalid_descs`), never DMA out of bounds. Growth is bounded by
// construction: each rescue preserves a REAL pool frame, and
// `pending_fill_frames` drains every tick, so steady-state accumulation
// without a producer bug is impossible.
pub(in crate::afxdp) fn split_is_single_region(
    left: &[BindingWorker],
    current: &BindingWorker,
    right: &[BindingWorker],
) -> bool {
    left.iter()
        .chain(right.iter())
        .all(|binding| binding.umem.shares_allocation_with(&current.umem))
}

fn single_region_backstop_index(bindings: &[BindingWorker]) -> Option<usize> {
    let first = bindings.first()?;
    bindings
        .iter()
        .all(|binding| binding.umem.shares_allocation_with(&first.umem))
        .then_some(0)
}

fn route_shared_recycle_by_slot(
    left: &mut [BindingWorker],
    current_index: usize,
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    slot: u32,
    offset: u64,
) -> bool {
    let target_index = shared_recycle_target_index_for_split(
        left.len(),
        right.len(),
        binding_lookup,
        slot,
        |idx| split_binding_slot_at(left, current_index, current, right, idx),
    );
    if let Some(target_index) = target_index
        && let Some(binding) =
            binding_by_index_mut(left, current_index, current, right, target_index)
    {
        binding.tx_pipeline.pending_fill_frames.push_back(offset);
        return true;
    }
    false
}

pub(super) fn shared_recycle_target_index_for_split<F>(
    left_len: usize,
    right_len: usize,
    binding_lookup: &WorkerBindingLookup,
    slot: u32,
    slot_at: F,
) -> Option<usize>
where
    F: FnMut(usize) -> Option<u32>,
{
    shared_recycle_target_index(
        left_len.saturating_add(1).saturating_add(right_len),
        binding_lookup,
        slot,
        slot_at,
    )
}

fn split_binding_slot_at(
    left: &[BindingWorker],
    current_index: usize,
    current: &BindingWorker,
    right: &[BindingWorker],
    target_index: usize,
) -> Option<u32> {
    if target_index == current_index {
        return Some(current.slot);
    }
    if target_index < current_index {
        return left.get(target_index).map(|binding| binding.slot);
    }
    right
        .get(target_index.saturating_sub(current_index + 1))
        .map(|binding| binding.slot)
}

pub(super) fn shared_recycle_target_index<F>(
    binding_count: usize,
    binding_lookup: &WorkerBindingLookup,
    slot: u32,
    mut slot_at: F,
) -> Option<usize>
where
    F: FnMut(usize) -> Option<u32>,
{
    if let Some(target_index) = binding_lookup.slot_index(slot)
        && target_index < binding_count
        && slot_at(target_index) == Some(slot)
    {
        return Some(target_index);
    }
    (0..binding_count).find(|&idx| slot_at(idx) == Some(slot))
}

pub(in crate::afxdp) fn record_shared_recycle_unknown_slot_drops(
    error_live: Option<&BindingLiveState>,
    dropped: u64,
) {
    if dropped == 0 {
        return;
    }
    if let Some(live) = error_live {
        live.tx_errors.fetch_add(dropped, Ordering::Relaxed);
        live.tx_shared_recycle_unknown_slot_drops
            .fetch_add(dropped, Ordering::Relaxed);
    }
}

// F-149 (#9904): rescued unknowns join the `tx_errors` aggregate like drops
// do — an unknown slot is a routing anomaly regardless of fate — with the
// rescued subset distinguishing "recovered via the same-region backstop"
// from "lost". `tx_errors == drops + rescued` for unknown slots.
pub(in crate::afxdp) fn record_shared_recycle_unknown_slot_rescues(
    error_live: Option<&BindingLiveState>,
    rescued: u64,
) {
    if rescued == 0 {
        return;
    }
    if let Some(live) = error_live {
        live.tx_errors.fetch_add(rescued, Ordering::Relaxed);
        live.tx_shared_recycle_unknown_slot_rescued
            .fetch_add(rescued, Ordering::Relaxed);
    }
}

pub(in crate::afxdp) fn log_shared_recycle_unknown_slot_drops(
    dropped: u64,
    first_drop: Option<(u32, u64)>,
) {
    if dropped == 0 {
        return;
    }
    if let Some((slot, offset)) = first_drop {
        eprintln!(
            "xpf-userspace-dp: dropping {} shared UMEM recycles for unknown slots \
             (first slot {} offset {})",
            dropped, slot, offset
        );
    } else {
        eprintln!(
            "xpf-userspace-dp: dropping {} shared UMEM recycles for unknown slots",
            dropped
        );
    }
}

pub(in crate::afxdp) fn log_shared_recycle_unknown_slot_rescues(
    rescued: u64,
    first_rescue: Option<(u32, u64)>,
) {
    if rescued == 0 {
        return;
    }
    if let Some((slot, offset)) = first_rescue {
        eprintln!(
            "xpf-userspace-dp: rescued {} shared UMEM recycles for unknown slots \
             via the same-region backstop (first slot {} offset {})",
            rescued, slot, offset
        );
    } else {
        eprintln!(
            "xpf-userspace-dp: rescued {} shared UMEM recycles for unknown slots \
             via the same-region backstop",
            rescued
        );
    }
}

pub(in crate::afxdp) fn apply_shared_recycles_to_bindings(
    bindings: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> u64 {
    if shared_recycles.is_empty() {
        return 0;
    }
    // F-149 (#9904): computed ONCE per drain, not per unknown slot: O(N)
    // `Rc::ptr_eq` compares where N = worker bindings (typically < 32) —
    // single-digit ns against the drain's per-frame ring ops. Deliberately
    // not lazy-gated behind the first unknown: the gate would cost the same
    // order as the scan it skips.
    let backstop = single_region_backstop_index(bindings);
    let mut dropped = 0u64;
    let mut rescued = 0u64;
    let mut first_drop = None;
    let mut first_rescue = None;
    for (slot, offset) in shared_recycles.drain(..) {
        let target_index =
            shared_recycle_target_index(bindings.len(), binding_lookup, slot, |idx| {
                bindings.get(idx).map(|binding| binding.slot)
            });
        if let Some(target_index) = target_index
            && let Some(binding) = bindings.get_mut(target_index)
        {
            binding.tx_pipeline.pending_fill_frames.push_back(offset);
            continue;
        }
        if let Some(host) = backstop
            && let Some(binding) = bindings.get_mut(host)
        {
            // Same-region per the premise above: kernel-masked to the chunk
            // base on consume, bounds-checked, growth-bounded. See note.
            binding.tx_pipeline.pending_fill_frames.push_back(offset);
            first_rescue.get_or_insert((slot, offset));
            rescued = rescued.saturating_add(1);
        } else {
            first_drop.get_or_insert((slot, offset));
            dropped = dropped.saturating_add(1);
        }
    }
    log_shared_recycle_unknown_slot_drops(dropped, first_drop);
    log_shared_recycle_unknown_slot_rescues(rescued, first_rescue);
    record_shared_recycle_unknown_slot_drops(
        bindings.first().map(|binding| binding.live.as_ref()),
        dropped,
    );
    record_shared_recycle_unknown_slot_rescues(
        bindings.first().map(|binding| binding.live.as_ref()),
        rescued,
    );
    dropped
}

pub(in crate::afxdp) fn resolve_tx_binding_ifindex(
    forwarding: &ForwardingState,
    egress_ifindex: i32,
) -> i32 {
    if let Some(fabric) = forwarding
        .fabrics
        .iter()
        .find(|fabric| fabric.parent_ifindex == egress_ifindex)
    {
        return fabric.parent_ifindex;
    }
    forwarding
        .egress
        .get(&egress_ifindex)
        .map(|iface| iface.bind_ifindex)
        .filter(|ifindex| *ifindex > 0)
        .unwrap_or(egress_ifindex)
}
