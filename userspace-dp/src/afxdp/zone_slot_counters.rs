//! #17204 (R4-Q51-04): the ONE per-zone slot-counter machine, generic over
//! the counted block.
//!
//! Before this module, `zone_counters.rs` (per-zone traffic VOLUME) and
//! `flood_counters.rs` (per-zone flood EVENTS) each hand-implemented the same
//! type-independent machinery: a 64-slot zone→slot LUT, per-slot `Arc` atomic
//! totals, a zone-id-keyed store with snapshot/clear/reconcile/fold, a
//! `touched_slots` pending batch with a mask-walk reset, and a thread-local
//! accumulator with record/flush. Only the block type differed, yet every
//! structural change (the #6946 touched-slot bound, the #14619 layout stamp)
//! had to be written, reviewed and tested TWICE — and the two copies' equality
//! was pinned together by a cross-module `const assert!` plus a "same zones"
//! test rather than by construction.
//!
//! This module holds that machinery exactly once:
//!
//! * [`SlotBlock`] — the per-zone atomic block contract (fold a pending delta
//!   in / reset in place / zero check / wire-row projection).
//! * [`ZoneSlotMap`] — the flat `[u8; 65536]` zone-id → slot LUT, built ONCE
//!   per config apply and shared by both counter families, so a zone is
//!   slotted for both or neither BY CONSTRUCTION (the property the deleted
//!   `const assert!` used to guard).
//! * [`ZoneSlotStore<B>`] — the zone-id-keyed, config-apply-surviving store.
//!   Its snapshot is row-type-agnostic (sparse `(zone_id, block)` pairs); each
//!   family projects its own wire rows.
//! * [`ZoneSlotPending<D>`] — the per-worker thread-local dense accumulator
//!   with the single #6946 mask-walk reset, generic over the delta type `D`.
//!
//! The two family modules keep only their block/delta types, their `record_*`
//! functions and their wire-row mapping.
//!
//! ## Hot path (no per-packet hash, no per-packet atomic, no per-batch lock)
//!
//! [`ZoneSlotMap`] resolves a zone id with one array read; the recorders
//! accumulate into a per-worker thread-local dense [`ZoneSlotPending`] — the
//! same coalesce-then-fold technique `policy::record_policy_hit_counter` /
//! `filter::record_filter_counter` use. The per-RX-batch flush folds the
//! coalesced per-slot deltas into the shared per-zone atomics the slot map
//! caches. The generic is fully monomorphised and the recorders stay
//! `#[inline]` over fixed `[_; 64]` arrays and a `u64` touched mask, so the
//! record-path codegen is unchanged and no allocation is added there.
//!
//! ## Store (lock-free per-batch fold, mutex only off the hot path — #5163)
//!
//! The store holds one block PER zone id
//! (`Arc<Mutex<FxHashMap<u32, Arc<B>>>>`) and the mutex guards only the MAP
//! STRUCTURE — get-or-create at config-apply, and iterate at snapshot / clear
//! / reconcile — all off the hot path (≤ once per commit or per 1 s status
//! poll). Each configured slot caches its zone's `Arc<B>` in the slot map at
//! build time, so the per-batch fold is a straight `Relaxed` `fetch_add` into
//! per-zone atomics with NO lock and NO map lookup — exactly the lock-free
//! shared-counter shape the `policy`/`filter` hit counters already use.
//!
//! The store stays keyed by the STABLE zone id, not by slot, so a config
//! apply that renumbers slots never mis-attributes counts: the slot map's
//! cached `Arc` is resolved from the zone-id-keyed store, so a surviving zone
//! keeps the SAME atomic block across applies (get-or-create returns the
//! existing Arc) while a renumbered slot simply points at that same stable
//! block. The store rides `ForwardingState` (cloned forward from the previous
//! state across applies, like a persistent Arc) so totals survive config
//! commits. `clear` resets each zone's block IN PLACE (it must not drop the
//! map entry, or a live slot map would keep folding into an orphaned Arc that
//! the snapshot no longer sees).

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use rustc_hash::{FxHashMap, FxHashSet};

/// Dense hot-path slot count. Slot 0 is reserved (unassigned / unzoned), so
/// `ZONE_SLOT_SLOTS - 1` zones are assignable to a slot; a configured zone
/// past that capacity sets `overflow_active` and its counters go uncounted
/// (documented, same posture as the cold-path histogram `overflow_active`).
/// 63 assignable slots covers every realistic deployment (the legacy dense
/// `zone_counters` array held 64) while keeping the per-worker thread-local
/// accumulator small (64 × 4 × 8 = 2 KiB for the traffic delta).
pub(in crate::afxdp) const ZONE_SLOT_SLOTS: usize = 64;

/// #6946: `ZoneSlotPending::touched_slots` is a `u64` bitmask, one bit per
/// slot. Raising the slot count past 64 would make `1u64 << slot` shift out
/// of range — a panic in debug and a silently WRONG mask in release, which
/// would drop whole zones' counters with no error. The bound is asserted at
/// compile time so the capacity cannot be raised without also widening the
/// mask.
const _: () = assert!(ZONE_SLOT_SLOTS <= 64);

/// Number of assignable slots (slot 0 reserved).
pub(in crate::afxdp) const ZONE_SLOT_ASSIGNABLE_SLOTS: usize = ZONE_SLOT_SLOTS - 1;

/// The per-zone atomic block a [`ZoneSlotStore`] counts into.
///
/// Implemented by the traffic totals (four `Relaxed` atomics) and the flood
/// totals (drop + alarm triples). All methods run OFF the per-packet record
/// path except `fold_delta`, which is the per-RX-batch fold — a straight
/// `Relaxed` `fetch_add` per field, never a lock.
pub(in crate::afxdp) trait SlotBlock: Default {
    /// The per-slot pending delta this block folds (the thread-local
    /// accumulator's element type).
    type Delta: SlotDelta;

    /// Fold one slot's coalesced `delta` into the shared atomics.
    fn fold_delta(&self, delta: &Self::Delta);

    /// Zero every field IN PLACE (operator clear). In place — never dropped
    /// from the store map — so a live slot map's cached `Arc` keeps counting
    /// from zero instead of folding into an orphaned block.
    fn reset(&self);

    /// True while every field is zero. The store's sparse snapshot omits
    /// all-zero blocks, so a zone with no counted events publishes no row.
    fn is_zero(&self) -> bool;
}

/// One slot's coalesced pending delta in a [`ZoneSlotPending`].
///
/// `Copy` keeps the accumulator a plain fixed array of inline values — no
/// allocation, no indirection on the record path.
pub(in crate::afxdp) trait SlotDelta: Copy + Default {
    /// True while the delta carries nothing to fold.
    fn is_zero(&self) -> bool;

    /// Clear the delta in place (the mask-walk reset zeroes only touched
    /// slots; an untouched slot's delta is already zero).
    fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Flat direct-index zone-id → hot-path slot LUT, built at config apply.
///
/// `slot_of[zone_id]` is 0 for an unassigned zone (unzoned id 0, or a zone
/// past the slot capacity), else the dense slot `[1, ZONE_SLOT_ASSIGNABLE_SLOTS]`.
/// `inverse[slot]` recovers the zone id (0 = free slot). A single 16-bit zone
/// id makes the flat LUT feasible where the cold-path 32-bit zone-PAIR key
/// needed a `HashMap`.
///
/// ONE map is built per apply and shared by both counter families
/// ([`ZoneSlotStore<ZoneTotalsAtomic>`] /
/// [`ZoneSlotStore<FloodTotalsAtomic>`]), so a zone is slotted for both
/// families or neither by construction — the asymmetry the deleted
/// cross-module `const assert!` used to guard against cannot arise.
///
/// [`ZoneTotalsAtomic`]: crate::afxdp::zone_counters::ZoneTotalsAtomic
/// [`FloodTotalsAtomic`]: crate::afxdp::flood_counters::FloodTotalsAtomic
pub(in crate::afxdp) struct ZoneSlotMap {
    slot_of: Box<[u8; 65536]>,
    inverse: [u32; ZONE_SLOT_SLOTS],
    /// True if some configured zone could not be assigned a slot because the
    /// `ZONE_SLOT_ASSIGNABLE_SLOTS` capacity was exhausted. Surfaced as
    /// `ProcessStatus.zone_counter_overflow_active` /
    /// `flood_counter_overflow_active`.
    pub(in crate::afxdp) overflow_active: bool,
}

impl Default for ZoneSlotMap {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::fmt::Debug for ZoneSlotMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Summarize rather than dumping the 64 KiB LUT.
        let assigned = self.inverse.iter().filter(|&&z| z != 0).count();
        f.debug_struct("ZoneSlotMap")
            .field("assigned_zones", &assigned)
            .field("overflow_active", &self.overflow_active)
            .finish()
    }
}

impl ZoneSlotMap {
    /// An empty map: every zone resolves to slot 0 (uncounted).
    pub(in crate::afxdp) fn empty() -> Self {
        Self {
            slot_of: Box::new([0u8; 65536]),
            inverse: [0u32; ZONE_SLOT_SLOTS],
            overflow_active: false,
        }
    }

    /// Assign slots from the configured zone-id set, in sorted zone-id order
    /// (deterministic for a given config); a duplicate or zero id is ignored.
    /// Because the stores are zone-id keyed, slot assignment does NOT need to
    /// be stable across applies (unlike the cold-path histogram, whose slot
    /// IS the accumulator index), so this is a plain rebuild with no
    /// previous-map retention.
    ///
    /// Each assigned slot resolves (get-or-create) its zone's shared block in
    /// BOTH family stores and caches the `Arc`s in the returned
    /// [`ZoneSlotCaches`]. A zone that survives this apply gets the SAME
    /// atomic blocks it had before (the stores are zone-id keyed and carried
    /// forward), so counts never reset or double across a slot renumber; the
    /// per-batch folds then never touch either store's mutex.
    pub(in crate::afxdp) fn build<B1: SlotBlock, B2: SlotBlock>(
        zone_ids: &[u32],
        store1: &ZoneSlotStore<B1>,
        store2: &ZoneSlotStore<B2>,
    ) -> (Self, ZoneSlotCaches<B1, B2>) {
        let mut ids: Vec<u32> = zone_ids.iter().copied().filter(|&z| z != 0).collect();
        ids.sort_unstable();
        ids.dedup();

        let mut slot_of = Box::new([0u8; 65536]);
        let mut inverse = [0u32; ZONE_SLOT_SLOTS];
        let mut slot_totals1: [Option<Arc<B1>>; ZONE_SLOT_SLOTS] = std::array::from_fn(|_| None);
        let mut slot_totals2: [Option<Arc<B2>>; ZONE_SLOT_SLOTS] = std::array::from_fn(|_| None);
        let mut overflow_active = false;
        let mut next_slot = 1usize;
        for zid in ids {
            if zid > u16::MAX as u32 {
                overflow_active = true;
                continue;
            }
            if next_slot > ZONE_SLOT_ASSIGNABLE_SLOTS {
                overflow_active = true;
                break;
            }
            slot_of[zid as usize] = next_slot as u8;
            inverse[next_slot] = zid;
            slot_totals1[next_slot] = Some(store1.zone_totals(zid));
            slot_totals2[next_slot] = Some(store2.zone_totals(zid));
            next_slot += 1;
        }
        (
            Self {
                slot_of,
                inverse,
                overflow_active,
            },
            ZoneSlotCaches {
                slot_totals1,
                slot_totals2,
            },
        )
    }

    /// Resolve the hot-path slot for `zone_id` (0 = unassigned / uncounted).
    #[inline]
    pub(in crate::afxdp) fn slot_of(&self, zone_id: u32) -> u8 {
        // #16557: dense array is u16-indexed; ids above it hold no slot.
        if zone_id > u16::MAX as u32 {
            return 0;
        }
        self.slot_of[zone_id as usize]
    }

    /// #14619: zone ids currently holding a live slot, in slot order
    /// (which is sorted zone-id order — see `build`). Published on the
    /// wire so consumers can distinguish a slotted-but-idle zone from a
    /// zone past capacity when overflow is active.
    pub(in crate::afxdp) fn slotted_zone_ids(&self) -> Vec<u32> {
        self.inverse.iter().copied().filter(|&z| z != 0).collect()
    }

    /// Test-only peek at the inverse map (slot → zone id), so tests in the
    /// family modules can pin slot assignment without a second accessor on
    /// the production surface.
    #[cfg(test)]
    pub(in crate::afxdp) fn inverse_for_test(&self) -> [u32; ZONE_SLOT_SLOTS] {
        self.inverse
    }
}

/// Per-slot handles to the assigned zones' shared atomic blocks, resolved
/// from the two zone-id-keyed stores at build time (see
/// [`ZoneSlotMap::build`]). The per-batch folds read `slot_totals*[slot]`
/// and `fetch_add` directly, so they never lock a store or do a map lookup
/// on the hot path. `None` for an unassigned slot (slot 0 and any slot past
/// the configured zones).
///
/// Family 1 is the traffic store, family 2 the flood store; the pair is
/// carried inside the ONE shared [`ZoneSlotMap`]'s caches so both families
/// always fold through the same slot assignment.
pub(in crate::afxdp) struct ZoneSlotCaches<B1, B2> {
    slot_totals1: [Option<Arc<B1>>; ZONE_SLOT_SLOTS],
    slot_totals2: [Option<Arc<B2>>; ZONE_SLOT_SLOTS],
}

impl<B1, B2> Clone for ZoneSlotCaches<B1, B2> {
    fn clone(&self) -> Self {
        Self {
            slot_totals1: self.slot_totals1.clone(),
            slot_totals2: self.slot_totals2.clone(),
        }
    }
}

impl<B1, B2> Default for ZoneSlotCaches<B1, B2> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<B1, B2> std::fmt::Debug for ZoneSlotCaches<B1, B2> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneSlotCaches").finish_non_exhaustive()
    }
}

impl<B1, B2> ZoneSlotCaches<B1, B2> {
    /// An empty caches value: every slot unassigned (the `ForwardingState`
    /// default before the first config apply builds the real one).
    pub(in crate::afxdp) fn empty() -> Self {
        Self {
            slot_totals1: std::array::from_fn(|_| None),
            slot_totals2: std::array::from_fn(|_| None),
        }
    }

    /// The family-1 (traffic) block cached for `slot`, if assigned.
    #[inline]
    pub(in crate::afxdp) fn totals1(&self, slot: usize) -> Option<&Arc<B1>> {
        self.slot_totals1[slot].as_ref()
    }

    /// The family-2 (flood) block cached for `slot`, if assigned.
    #[inline]
    pub(in crate::afxdp) fn totals2(&self, slot: usize) -> Option<&Arc<B2>> {
        self.slot_totals2[slot].as_ref()
    }
}

/// Select the rows publishable from a sparse store snapshot: a row survives
/// only when its zone is BOTH still configured AND holds a live hot-path
/// slot. The second condition is the one that is easy to miss, because it is
/// about a TRANSITION rather than a steady state.
///
/// The store outlives the slot map. Config apply carries the store forward
/// and `reconcile` retains every still-configured zone, while
/// [`ZoneSlotMap::build`] assigns only [`ZONE_SLOT_ASSIGNABLE_SLOTS`] slots
/// in sorted zone-id order. So a zone that accumulated counts and is then
/// pushed past capacity by a later config — e.g. 63 lower-id zones added
/// alongside it — remains configured, keeps its retained nonzero totals, and
/// gets slot 0. It is no longer counted, but its old numbers are still in the
/// store.
///
/// Publishing that row makes the Go side mirror a total that can never
/// advance again: a FROZEN counter that under-reports every subsequent
/// packet while looking perfectly alive. Omitting it instead makes the zone
/// read as "not populated" end to end, which is the honest answer — its
/// traffic really is uncounted — with `overflow_active` explaining why.
///
/// Reasoning about "a zone that was never counted" is not enough to
/// establish this; the dangerous case is a zone that WAS counted and then
/// stopped.
///
/// Shared by both families: each passes its own `project` closure mapping
/// `(zone_id, &block)` to its wire row.
pub(in crate::afxdp) fn publishable_rows<B: SlotBlock, R>(
    store: &ZoneSlotStore<B>,
    slot_map: &ZoneSlotMap,
    is_configured: impl Fn(u32) -> bool,
    project: impl Fn(u32, &B) -> R,
) -> Vec<R> {
    store
        .snapshot_blocks()
        .into_iter()
        .filter(|(zone_id, _)| is_configured(*zone_id) && slot_map.slot_of(*zone_id) != 0)
        .map(|(zone_id, block)| project(zone_id, &block))
        .collect()
}

/// Coordinator-owned, config-apply-surviving cumulative per-zone store,
/// keyed by the stable zone id. The mutex guards only the MAP STRUCTURE
/// (get-or-create at config-apply, iterate at snapshot/clear/reconcile) —
/// all off the hot path. The per-batch fold never locks it: it `fetch_add`s
/// into the per-zone `Arc<B>` the slot map cached at build time (#5163).
/// `Clone` shares the inner `Arc<Mutex>`, so cloning `ForwardingState`
/// (worker publish) keeps every generation pointing at the same totals.
pub(in crate::afxdp) struct ZoneSlotStore<B: SlotBlock> {
    totals: Arc<Mutex<FxHashMap<u32, Arc<B>>>>,
}

impl<B: SlotBlock> Clone for ZoneSlotStore<B> {
    fn clone(&self) -> Self {
        Self {
            totals: Arc::clone(&self.totals),
        }
    }
}

impl<B: SlotBlock> std::fmt::Debug for ZoneSlotStore<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneSlotStore").finish_non_exhaustive()
    }
}

impl<B: SlotBlock> Default for ZoneSlotStore<B> {
    fn default() -> Self {
        Self {
            totals: Arc::new(Mutex::new(FxHashMap::default())),
        }
    }
}

impl<B: SlotBlock> ZoneSlotStore<B> {
    /// Get-or-create the shared atomic block for a stable zone id, under the
    /// map mutex. Config-apply path only (called from `ZoneSlotMap::build`
    /// to cache the `Arc` per slot); NOT the hot path. A surviving zone gets
    /// the SAME `Arc` back across applies, so its totals never reset or
    /// double.
    fn zone_totals(&self, zone_id: u32) -> Arc<B> {
        let mut totals = crate::sync_util::lock_tolerant(&self.totals);
        Arc::clone(totals.entry(zone_id).or_default())
    }

    /// Sparse snapshot: one `(zone_id, block)` pair per zone with any counted
    /// events, in deterministic (sorted by zone id) order. Row-type-agnostic
    /// — each family projects its own wire rows from the blocks (the traffic
    /// snapshot is a straight field copy; the flood snapshot deliberately
    /// stays drops-only, see `flood_counters`).
    pub(in crate::afxdp) fn snapshot_blocks(&self) -> Vec<(u32, Arc<B>)> {
        let totals = crate::sync_util::lock_tolerant(&self.totals);
        let mut out: Vec<(u32, Arc<B>)> = totals
            .iter()
            .filter(|(_, t)| !t.is_zero())
            .map(|(&zone_id, t)| (zone_id, Arc::clone(t)))
            .collect();
        out.sort_unstable_by_key(|(zone_id, _)| *zone_id);
        out
    }

    /// Sparse wire-row snapshot: project each non-zero block to its row.
    /// Each family passes its own projection, so the wire shapes stay in the
    /// family modules while the sparsity/sort contract lives here once.
    pub(in crate::afxdp) fn snapshot<R>(&self, project: impl Fn(u32, &B) -> R) -> Vec<R> {
        self.snapshot_blocks()
            .into_iter()
            .map(|(zone_id, block)| project(zone_id, &block))
            .collect()
    }

    /// Test-only: read one zone's block through a closure (the flood alarm
    /// triple is deliberately not on the wire snapshot; tests still need to
    /// observe it). Returns `None` when the zone holds no block.
    #[cfg(test)]
    pub(in crate::afxdp) fn block_for_test<R>(
        &self,
        zone_id: u32,
        read: impl Fn(&B) -> R,
    ) -> Option<R> {
        let totals = self
            .totals
            .lock()
            .expect("zone slot counter store poisoned");
        totals.get(&zone_id).map(|t| read(t))
    }

    /// Operator clear (`clear_zone_counters` / `clear_flood_counters` IPC):
    /// zero every zone's cumulative totals so the pre-clear value is not
    /// snapped back on the next status poll. Load-bearing half of the
    /// operator clear.
    ///
    /// #6843: a cleared zone then reads as NOT POPULATED, not as zero — the
    /// snapshot omits all-zero rows and the Go side replaces its offset map
    /// from that snapshot, so the row is dropped rather than set to 0.
    ///
    /// #5163: resets each block IN PLACE rather than clearing the map,
    /// because a live slot map caches each zone's `Arc`; dropping the map
    /// entry would leave workers folding into an orphaned block the snapshot
    /// no longer sees (traffic would appear to stop counting until the next
    /// config apply).
    pub(in crate::afxdp) fn clear(&self) {
        let totals = crate::sync_util::lock_tolerant(&self.totals);
        for block in totals.values() {
            block.reset();
        }
    }

    /// Drop totals for zones that are no longer configured (config apply
    /// hygiene). Correctness does not depend on this — the coordinator
    /// snapshot accessor also filters to configured zones — but it bounds
    /// the map to the live zone set. A `configured` zone's `Arc` is
    /// retained, so a slot map rebuilt in the same apply resolves the SAME
    /// block (no reset/double).
    pub(in crate::afxdp) fn reconcile(&self, configured: &FxHashSet<u32>) {
        crate::sync_util::lock_tolerant(&self.totals)
            .retain(|zone_id, _| configured.contains(zone_id));
    }

    /// #5163: fold a worker's coalesced per-slot deltas into the shared
    /// per-zone atomics the slot map cached at build time. LOCK-FREE — a
    /// straight `Relaxed` `fetch_add` per touched slot; it does NOT lock
    /// `self.totals` (that mutex is only for the ≤ 1 s snapshot/clear/
    /// reconcile map-structure ops). This is the load-bearing change: the
    /// pre-#5163 fold locked `self.totals` on EVERY worker EVERY batch,
    /// bouncing one cache line at line rate. Reintroducing a
    /// `self.totals.lock()` here (the per-batch global fold) is exactly what
    /// `worker_fold_makes_progress_while_status_reader_holds_the_lock`
    /// catches. The slot → zone attribution is fixed by which `Arc` each
    /// slot cached at build time, so a slot renumber across applies cannot
    /// mis-attribute (the fold and the intervening `record_*` calls always
    /// read the SAME slot map).
    ///
    /// `totals_of` selects the family's cache array inside the shared
    /// [`ZoneSlotCaches`] (family 1 or family 2).
    pub(in crate::afxdp) fn fold_pending<B1: SlotBlock, B2: SlotBlock>(
        &self,
        pending: &ZoneSlotPending<B::Delta>,
        caches: &ZoneSlotCaches<B1, B2>,
        totals_of: impl Fn(&ZoneSlotCaches<B1, B2>, usize) -> Option<&Arc<B>>,
    ) {
        // #6946: walk the touched bits instead of all 64 slots. Slot 0 is
        // the unassigned sentinel and is never recorded into, so it cannot
        // be set.
        let mut mask = pending.touched_slots;
        while mask != 0 {
            let slot = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            let Some(totals) = totals_of(caches, slot) else {
                continue;
            };
            let delta = &pending.deltas[slot];
            if delta.is_zero() {
                continue;
            }
            totals.fold_delta(delta);
        }
    }

    /// Test-only: every zone id the store currently holds a block for,
    /// INCLUDING zones whose totals are all zero.
    ///
    /// #5716: [`Self::snapshot_blocks`] is deliberately SPARSE — it omits
    /// all-zero rows — so it cannot see a block that was get-or-created and
    /// never counted into. That is exactly the residue a rejected config
    /// build leaves behind if it resolves the candidate's zone blocks out of
    /// the carried-forward (Arc-shared, LIVE) store, so a fixture asserting
    /// "a rejected build did not mutate the live store" has to look HERE
    /// rather than at the operator-visible snapshot.
    #[cfg(test)]
    pub(in crate::afxdp) fn tracked_zone_ids_for_test(&self) -> Vec<u32> {
        let totals = self
            .totals
            .lock()
            .expect("zone slot counter store poisoned");
        let mut ids: Vec<u32> = totals.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Test-only handle to the map mutex, so a test can hold the shared store
    /// lock (as the ≤ 1 s snapshot/clear path does) and prove the per-batch
    /// fold still makes progress — the #5163 lock-freedom invariant.
    #[cfg(test)]
    pub(in crate::afxdp) fn lock_totals_for_test(
        &self,
    ) -> std::sync::MutexGuard<'_, FxHashMap<u32, Arc<B>>> {
        self.totals
            .lock()
            .expect("zone slot counter store poisoned")
    }
}

/// Per-worker thread-local dense slot accumulator, generic over the delta
/// type. Touched only by the owning worker thread on the hot path; folded
/// into the shared store per RX batch.
pub(in crate::afxdp) struct ZoneSlotPending<D: SlotDelta> {
    pub(in crate::afxdp) deltas: [D; ZONE_SLOT_SLOTS],
    /// #6946: one bit per touched slot, replacing a single `touched: bool`.
    ///
    /// The bool made both per-batch operations O(SLOTS) regardless of how
    /// many slots actually moved: `reset` cleared the whole accumulator and
    /// `fold_pending` scanned all 64 slots, to flush what is typically ONE
    /// zone. The cost that matters is cache, not cycles — dirtied lines per
    /// flush per worker per RX batch.
    pub(in crate::afxdp) touched_slots: u64,
}

impl<D: SlotDelta> Default for ZoneSlotPending<D> {
    fn default() -> Self {
        Self {
            deltas: [D::default(); ZONE_SLOT_SLOTS],
            touched_slots: 0,
        }
    }
}

impl<D: SlotDelta> ZoneSlotPending<D> {
    /// Clear only the slots that moved (#6946). Whole-array assignment
    /// dirtied every line whether or not it held a delta. This is the ONE
    /// mask-walk reset both families share: the flood #7086 hazard —
    /// "clearing only `counts` would re-fold stale alarm deltas" — cannot
    /// recur, because there is a single `deltas` array per family and this
    /// single reset clears every touched slot of it.
    pub(in crate::afxdp) fn reset(&mut self) {
        let mut mask = self.touched_slots;
        while mask != 0 {
            let slot = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            self.deltas[slot].reset();
        }
        self.touched_slots = 0;
    }
}
