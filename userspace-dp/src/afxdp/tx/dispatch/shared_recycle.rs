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

/// #17178: cumulative unknown-slot drop log lines emitted. Throttle gate
/// for `log_shared_recycle_unknown_slot_drops`, mirroring the
/// `tx/rings.rs` UMEM-anomaly convention (`fetch_add(1) < 10`).
pub(in crate::afxdp) static SHARED_RECYCLE_UNKNOWN_SLOT_DROPS_LOGGED: AtomicU64 = AtomicU64::new(0);
/// #17178: cumulative unknown-slot rescue log lines emitted. Throttle
/// gate for `log_shared_recycle_unknown_slot_rescues`.
pub(in crate::afxdp) static SHARED_RECYCLE_UNKNOWN_SLOT_RESCUES_LOGGED: AtomicU64 =
    AtomicU64::new(0);

/// #17178: borrow-shape adapter for the ONE drain loop. The two public
/// wrappers differ only in how a binding index maps onto their slices
/// (split `left/current/right` vs one flat slice) and which binding is
/// charged for unknown slots — never in drop/rescue accounting.
trait SharedRecycleBindings {
    fn binding_count(&self) -> usize;
    fn slot_at(&self, target_index: usize) -> Option<u32>;
    fn push(&mut self, target_index: usize, offset: u64);
    fn blame_live(&self) -> Option<&BindingLiveState>;
}

impl SharedRecycleBindings for [BindingWorker] {
    fn binding_count(&self) -> usize {
        self.len()
    }
    fn slot_at(&self, target_index: usize) -> Option<u32> {
        self.get(target_index).map(|binding| binding.slot)
    }
    fn push(&mut self, target_index: usize, offset: u64) {
        if let Some(binding) = self.get_mut(target_index) {
            binding.tx_pipeline.pending_fill_frames.push_back(offset);
        }
    }
    fn blame_live(&self) -> Option<&BindingLiveState> {
        self.first().map(|binding| binding.live.as_ref())
    }
}

struct SplitBindings<'a> {
    left: &'a mut [BindingWorker],
    current_index: usize,
    current: &'a mut BindingWorker,
    right: &'a mut [BindingWorker],
}

impl SharedRecycleBindings for SplitBindings<'_> {
    fn binding_count(&self) -> usize {
        self.left.len() + 1 + self.right.len()
    }
    fn slot_at(&self, target_index: usize) -> Option<u32> {
        split_binding_slot_at(
            self.left,
            self.current_index,
            self.current,
            self.right,
            target_index,
        )
    }
    fn push(&mut self, target_index: usize, offset: u64) {
        if let Some(binding) = binding_by_index_mut(
            self.left,
            self.current_index,
            self.current,
            self.right,
            target_index,
        ) {
            binding.tx_pipeline.pending_fill_frames.push_back(offset);
        }
    }
    fn blame_live(&self) -> Option<&BindingLiveState> {
        Some(&self.current.live)
    }
}

fn drain_shared_recycles<B: SharedRecycleBindings + ?Sized>(
    bindings: &mut B,
    binding_lookup: &WorkerBindingLookup,
    shared_recycles: &mut Vec<(u32, u64)>,
    backstop: Option<usize>,
) -> u64 {
    let mut dropped = 0u64;
    let mut rescued = 0u64;
    let mut first_drop = None;
    let mut first_rescue = None;
    for (slot, offset) in shared_recycles.drain(..) {
        let target_index =
            shared_recycle_target_index(bindings.binding_count(), binding_lookup, slot, |idx| {
                bindings.slot_at(idx)
            });
        if let Some(target_index) = target_index {
            bindings.push(target_index, offset);
            continue;
        }
        if let Some(host) = backstop {
            // Same-region per the premise on `split_is_single_region`:
            // kernel-masked to the chunk base on consume, bounds-checked,
            // growth-bounded. See note there.
            bindings.push(host, offset);
            first_rescue.get_or_insert((slot, offset));
            rescued = rescued.saturating_add(1);
        } else {
            first_drop.get_or_insert((slot, offset));
            dropped = dropped.saturating_add(1);
        }
    }
    log_shared_recycle_unknown_slot_drops(dropped, first_drop);
    log_shared_recycle_unknown_slot_rescues(rescued, first_rescue);
    let blame_live = bindings.blame_live();
    record_shared_recycle_unknown_slot_drops(blame_live, dropped);
    record_shared_recycle_unknown_slot_rescues(blame_live, rescued);
    dropped
}

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
    // order as the scan it skips. The rescue host is `current` itself.
    let backstop = split_is_single_region(left, current, right).then_some(current_index);
    let mut bindings = SplitBindings {
        left,
        current_index,
        current,
        right,
    };
    drain_shared_recycles(&mut bindings, binding_lookup, shared_recycles, backstop);
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
    // #17178: delegate to the ONE single-region predicate — `first` as
    // the split path's `current`, the remaining bindings as its `right`.
    split_is_single_region(&[], first, &bindings[1..]).then_some(0)
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
    // #17178: throttle like the `tx/rings.rs` UMEM-anomaly logs — only
    // the first 10 drop lines are emitted process-wide; the per-binding
    // live counters keep counting every drop.
    if SHARED_RECYCLE_UNKNOWN_SLOT_DROPS_LOGGED.fetch_add(1, Ordering::Relaxed) >= 10 {
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
    // #17178: throttle like the `tx/rings.rs` UMEM-anomaly logs — only
    // the first 10 rescue lines are emitted process-wide; the per-binding
    // live counters keep counting every rescue.
    if SHARED_RECYCLE_UNKNOWN_SLOT_RESCUES_LOGGED.fetch_add(1, Ordering::Relaxed) >= 10 {
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
    drain_shared_recycles(bindings, binding_lookup, shared_recycles, backstop)
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
