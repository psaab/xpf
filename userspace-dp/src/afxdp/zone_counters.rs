//! #3651: per-zone ingress/egress traffic (packet + byte) counters.
//!
//! The eBPF-era dense `zone_counters` BPF array was deleted in the #1476
//! retirement; the Go read surfaces (`show security zones` Traffic statistics,
//! REST `/security/zones`, the Prometheus collector) key a sparse offset map
//! and report `ErrCounterNotPopulated` ("not available") because nothing
//! sources per-zone volume. This module is the userspace POPULATE half
//! (design of record: `docs/research/3643-dead-counters/plan.md` §5A).
//!
//! The slot map, store, pending accumulator and fold are the shared
//! [`crate::afxdp::zone_slot_counters`] machine (#17204); this module keeps
//! only the traffic block/delta types, [`record_zone_traffic`] and the
//! wire-row mapping. See that module for the hot-path and store contracts.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::afxdp::zone_slot_counters::{
    SlotBlock, SlotDelta, ZoneSlotCaches, ZoneSlotMap, ZoneSlotPending, ZoneSlotStore,
};
use crate::protocol::ZoneTrafficCounterStatus;

/// Wire/layout version stamped into `ProcessStatus.zone_counter_layout_version`
/// (#3651). #14619: stamped UNCONDITIONALLY by the status publisher, even
/// with no rows, so ">0, no row" reads as idle; 0/absent remains reserved
/// for a pre-#3651 helper that never sets the field.
pub(in crate::afxdp) const ZONE_COUNTER_LAYOUT_VERSION: u32 = 1;

/// #5163: shared cumulative per-zone traffic totals as four `Relaxed`
/// atomics, one block per slot-assigned zone id (see
/// [`crate::afxdp::zone_slot_counters`] for the store contract).
#[derive(Debug, Default)]
pub(in crate::afxdp) struct ZoneTotalsAtomic {
    ingress_packets: AtomicU64,
    ingress_bytes: AtomicU64,
    egress_packets: AtomicU64,
    egress_bytes: AtomicU64,
}

impl ZoneTotalsAtomic {
    /// Independent relaxed loads; the quad is eventual-consistent.
    fn load(&self) -> (u64, u64, u64, u64) {
        (
            self.ingress_packets.load(Ordering::Relaxed),
            self.ingress_bytes.load(Ordering::Relaxed),
            self.egress_packets.load(Ordering::Relaxed),
            self.egress_bytes.load(Ordering::Relaxed),
        )
    }
}

impl SlotBlock for ZoneTotalsAtomic {
    type Delta = ZoneTrafficDelta;

    fn fold_delta(&self, d: &ZoneTrafficDelta) {
        if d.ingress_packets != 0 {
            self.ingress_packets
                .fetch_add(d.ingress_packets, Ordering::Relaxed);
        }
        if d.ingress_bytes != 0 {
            self.ingress_bytes
                .fetch_add(d.ingress_bytes, Ordering::Relaxed);
        }
        if d.egress_packets != 0 {
            self.egress_packets
                .fetch_add(d.egress_packets, Ordering::Relaxed);
        }
        if d.egress_bytes != 0 {
            self.egress_bytes
                .fetch_add(d.egress_bytes, Ordering::Relaxed);
        }
    }

    /// Zero all four fields in place (operator clear). In place — never dropped
    /// from the store map — so a live slot map's cached `Arc` keeps counting
    /// from zero instead of folding into an orphaned block.
    fn reset(&self) {
        self.ingress_packets.store(0, Ordering::Relaxed);
        self.ingress_bytes.store(0, Ordering::Relaxed);
        self.egress_packets.store(0, Ordering::Relaxed);
        self.egress_bytes.store(0, Ordering::Relaxed);
    }

    fn is_zero(&self) -> bool {
        let (ingress_packets, ingress_bytes, egress_packets, egress_bytes) = self.load();
        ingress_packets == 0 && ingress_bytes == 0 && egress_packets == 0 && egress_bytes == 0
    }
}

/// One slot's coalesced per-zone traffic delta (the thread-local
/// accumulator's element type).
#[derive(Clone, Copy, Debug, Default)]
pub(in crate::afxdp) struct ZoneTrafficDelta {
    ingress_packets: u64,
    ingress_bytes: u64,
    egress_packets: u64,
    egress_bytes: u64,
}

impl SlotDelta for ZoneTrafficDelta {
    fn is_zero(&self) -> bool {
        self.ingress_packets == 0
            && self.ingress_bytes == 0
            && self.egress_packets == 0
            && self.egress_bytes == 0
    }
}

/// Rows publishable on `ProcessStatus.zone_traffic_counters` (configured
/// AND slotted; see [`crate::afxdp::zone_slot_counters::publishable_rows`]).
pub(in crate::afxdp) fn publishable_zone_rows(
    store: &ZoneCounterStore,
    slot_map: &ZoneSlotMap,
    is_configured: impl Fn(u32) -> bool,
) -> Vec<ZoneTrafficCounterStatus> {
    crate::afxdp::zone_slot_counters::publishable_rows(
        store,
        slot_map,
        is_configured,
        |zone_id, t| {
            let (ingress_packets, ingress_bytes, egress_packets, egress_bytes) = t.load();
            ZoneTrafficCounterStatus {
                zone_id,
                ingress_packets,
                ingress_bytes,
                egress_packets,
                egress_bytes,
            }
        },
    )
}

/// Per-zone traffic store (see [`crate::afxdp::zone_slot_counters::ZoneSlotStore`]).
pub(in crate::afxdp) type ZoneCounterStore = ZoneSlotStore<ZoneTotalsAtomic>;

/// Shared per-family block caches (family 1 = traffic, family 2 = flood).
pub(in crate::afxdp) type ZoneCounterCaches =
    ZoneSlotCaches<ZoneTotalsAtomic, crate::afxdp::flood_counters::FloodTotalsAtomic>;

/// Sparse wire-row snapshot of the traffic store.
pub(in crate::afxdp) fn zone_counter_snapshot(
    store: &ZoneCounterStore,
) -> Vec<ZoneTrafficCounterStatus> {
    store.snapshot(|zone_id, t| {
        let (ingress_packets, ingress_bytes, egress_packets, egress_bytes) = t.load();
        ZoneTrafficCounterStatus {
            zone_id,
            ingress_packets,
            ingress_bytes,
            egress_packets,
            egress_bytes,
        }
    })
}

thread_local! {
    static ZONE_PENDING: RefCell<ZoneSlotPending<ZoneTrafficDelta>> =
        RefCell::new(ZoneSlotPending::default());
}

/// Record one forwarded packet against its ingress and egress zone. The zone
/// ids are already resolved (ingress from the shim meta, egress from the
/// forwarding resolution), so this is two flat-LUT reads plus a thread-local
/// accumulate — no hash, no atomic, no allocation. An unassigned zone (slot 0)
/// contributes nothing.
///
/// #7173: the two slots are gated INDEPENDENTLY — a call with one side
/// unzoned still attributes the other. That is deliberate: if the ingress zone
/// is known and the egress is not, counting the ingress is correct, because
/// each slot is a per-zone traffic counter and not half of a flow record.
/// Requiring both would discard true information about the known side to avoid
/// an incompleteness no consumer reads that way.
///
/// So do not "fix" this by gating both slots on both zones being resolved. The
/// result would be silently lower per-zone totals on exactly the traffic whose
/// other half could not be resolved — a counter that undercounts is worse than
/// one that is candid about counting each side on its own knowledge.
/// #12865: egress zone selection for per-zone counters. A FabricRedirect
/// resolution's egress ifindex is the fabric transport, not the intended
/// destination; when admission captured the intended zone, credit that.
/// Otherwise the pair computed from the current resolution, then the
/// resolution-derived fallback.
#[inline]
pub(in crate::afxdp) fn counter_egress_zone(
    disposition: crate::afxdp::ForwardingDisposition,
    admission_to_zone: u32,
    computed_to_zone: u32,
    fallback: u32,
) -> u32 {
    use crate::afxdp::ForwardingDisposition;
    if disposition == ForwardingDisposition::FabricRedirect && admission_to_zone != 0 {
        admission_to_zone
    } else if computed_to_zone != 0 {
        computed_to_zone
    } else {
        fallback
    }
}

#[inline]
pub(in crate::afxdp) fn record_zone_traffic(
    slot_map: &ZoneSlotMap,
    ingress_zone_id: u32,
    egress_zone_id: u32,
    packet_bytes: u64,
) {
    let ingress_slot = slot_map.slot_of(ingress_zone_id);
    let egress_slot = slot_map.slot_of(egress_zone_id);
    if ingress_slot == 0 && egress_slot == 0 {
        return;
    }
    ZONE_PENDING.with(|pending| {
        let mut p = pending.borrow_mut();
        if ingress_slot != 0 {
            let s = ingress_slot as usize;
            p.deltas[s].ingress_packets = p.deltas[s].ingress_packets.saturating_add(1);
            p.deltas[s].ingress_bytes = p.deltas[s].ingress_bytes.saturating_add(packet_bytes);
            p.touched_slots |= 1u64 << s;
        }
        if egress_slot != 0 {
            let s = egress_slot as usize;
            p.deltas[s].egress_packets = p.deltas[s].egress_packets.saturating_add(1);
            p.deltas[s].egress_bytes = p.deltas[s].egress_bytes.saturating_add(packet_bytes);
            p.touched_slots |= 1u64 << s;
        }
    });
}

/// Fold this worker's coalesced traffic deltas (lock-free, #5163; see
/// [`crate::afxdp::zone_slot_counters::ZoneSlotStore::fold_pending`]).
pub(in crate::afxdp) fn flush_recorded_zone_counters(
    store: &ZoneCounterStore,
    _slot_map: &ZoneSlotMap,
    caches: &ZoneCounterCaches,
) {
    ZONE_PENDING.with(|pending| {
        let mut p = pending.borrow_mut();
        if p.touched_slots == 0 {
            return;
        }
        store.fold_pending(&p, caches, |c, slot| c.totals1(slot));
        p.reset();
    });
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    // #17204: the shared slot-machine fixture. Each cell builds the ONE
    // `ZoneSlotMap` for both family stores and folds through the shared
    // caches (family 1 = traffic, family 2 = flood), exactly as
    // `forwarding_build::attach_zone_counters` does per apply.
    use crate::afxdp::flood_counters::FloodCounterStore;
    use crate::afxdp::zone_counters::ZoneCounterCaches;
    use crate::afxdp::zone_slot_counters::{ZoneSlotMap, ZoneSlotPending};
    use rustc_hash::FxHashSet;

    fn build_map(
        zone_ids: &[u32],
        store: &ZoneCounterStore,
        flood_store: &FloodCounterStore,
    ) -> (ZoneSlotMap, ZoneCounterCaches) {
        ZoneSlotMap::build(zone_ids, store, flood_store)
    }

    fn flush(store: &ZoneCounterStore, map: &ZoneSlotMap, caches: &ZoneCounterCaches) {
        flush_recorded_zone_counters(store, map, caches);
    }

    fn snap(store: &ZoneCounterStore) -> Vec<ZoneTrafficCounterStatus> {
        store.snapshot(|zone_id, t| {
            let (ingress_packets, ingress_bytes, egress_packets, egress_bytes) = t.load();
            ZoneTrafficCounterStatus {
                zone_id,
                ingress_packets,
                ingress_bytes,
                egress_packets,
                egress_bytes,
            }
        })
    }

    /// #6946: the touched-slot bitmask must clear every slot it folded, and
    /// must reach the HIGHEST assignable slot.
    ///
    /// The dangerous regression is not "a delta is lost" — it is "a delta is
    /// folded but not cleared", because the stale value is then added AGAIN
    /// the next time that same slot is touched, and the counter over-counts.
    ///
    /// The second batch must touch the SAME zone, and that is not obvious.
    /// A second batch on a DIFFERENT zone cannot detect the bug: the fold
    /// walks the mask, so with the stale slot's bit cleared its residue is
    /// never revisited. The first version of this cell used a different zone
    /// and stayed GREEN under its own killing mutation — it was measuring
    /// nothing, and only the mutation matrix showed it.
    #[test]
    fn touched_slot_mask_clears_what_it_folded_6946() {
        let store = ZoneCounterStore::default();
        let flood_store = FloodCounterStore::default();
        let (map, caches) = build_map(&[11, 22], &store, &flood_store);

        // Batch 1: traffic on zone 11 only.
        record_zone_traffic(&map, 11, 0, 100);
        flush(&store, &map, &caches);

        // Batch 2: the SAME zone again. If reset() left slot 11's values in
        // place, this folds 100 (residue) + 100 (new) = 200 bytes.
        record_zone_traffic(&map, 11, 0, 100);
        flush(&store, &map, &caches);

        // Batch 3: a different zone, so the assertion above cannot pass by the
        // mask having stopped recording zone 11 altogether.
        record_zone_traffic(&map, 22, 0, 500);
        flush(&store, &map, &caches);

        let rows = snap(&store);
        let z11 = rows
            .iter()
            .find(|r| r.zone_id == 11)
            .expect("zone 11 must be counted");
        assert_eq!(
            (z11.ingress_packets, z11.ingress_bytes),
            (2, 200),
            "zone 11 folded twice — reset() did not clear the slot it folded, so \
             the stale delta was re-added on the next batch (#6946)"
        );
        let z22 = rows
            .iter()
            .find(|r| r.zone_id == 22)
            .expect("zone 22 must be counted");
        assert_eq!((z22.ingress_packets, z22.ingress_bytes), (1, 500));
    }

    /// #6946: the mask is a u64, so the capacity must never exceed 64 — a
    /// larger slot count makes `1u64 << slot` shift out of range, which is a
    /// panic in debug and a silently WRONG mask in release.
    ///
    /// This asserts the CEILING, not the floor. Filling slots and checking
    /// they arrive passes identically with no bound at all; what would break
    /// is a slot ABOVE the mask width, and the compile-time
    /// `const _: () = assert!(ZONE_SLOT_SLOTS <= 64)` in zone_slot_counters is what prevents it.
    /// This runtime cell fails loudly if that guard is ever deleted along
    /// with the const it protects.
    #[test]
    fn slot_capacity_fits_the_touched_mask_6946() {
        assert!(
            crate::afxdp::zone_slot_counters::ZONE_SLOT_SLOTS <= 64,
            "ZONE_SLOT_SLOTS exceeds the 64 bits of \
             the touched-slot mask; `1u64 << slot` would shift out of range \
             and whole zones would stop being folded (#6946)"
        );
        assert!(
            crate::afxdp::zone_slot_counters::ZONE_SLOT_SLOTS <= 64,
            "ZONE_SLOT_SLOTS exceeds the 64 bits of the touched-slot mask"
        );
        // The top assignable slot must round-trip through the mask: bit 63 is
        // the one an off-by-one in the shift would lose.
        let mut p = ZoneSlotPending::<ZoneTrafficDelta>::default();
        let top = crate::afxdp::zone_slot_counters::ZONE_SLOT_SLOTS - 1;
        p.deltas[top].ingress_packets = 7;
        p.touched_slots |= 1u64 << top;
        p.reset();
        assert_eq!(
            p.deltas[top].ingress_packets, 0,
            "the highest slot was not cleared by reset(); an off-by-one in the \
             mask width loses exactly this slot"
        );
        assert_eq!(p.touched_slots, 0, "reset() must clear the mask");
    }

    #[test]
    fn build_assigns_slots_for_wide_stable_hash_zone_ids() {
        // #3075 stable name-hash ids span [1, 65533]; a dense id-indexed table
        // would drop these. The flat LUT + slot map must count them.
        let store = ZoneCounterStore::default();
        let flood_store = FloodCounterStore::default();
        let (map, _caches) = build_map(&[40000, 7, 65533], &store, &flood_store);
        assert!(!map.overflow_active);
        // sorted → 7 gets slot 1, 40000 slot 2, 65533 slot 3.
        assert_eq!(map.slot_of(7), 1);
        assert_eq!(map.slot_of(40000), 2);
        assert_eq!(map.slot_of(65533), 3);
        assert_eq!(map.inverse_for_test()[1], 7);
        assert_eq!(map.inverse_for_test()[2], 40000);
        assert_eq!(map.inverse_for_test()[3], 65533);
        // Unconfigured / unzoned resolve to slot 0.
        assert_eq!(map.slot_of(0), 0);
        assert_eq!(map.slot_of(123), 0);
    }

    #[test]
    fn build_dedups_and_skips_zero() {
        let store = ZoneCounterStore::default();
        let flood_store = FloodCounterStore::default();
        let (map, _caches) = build_map(&[0, 5, 5, 9, 0, 5], &store, &flood_store);
        assert_eq!(map.slot_of(5), 1);
        assert_eq!(map.slot_of(9), 2);
        assert_eq!(map.slot_of(0), 0);
        assert!(!map.overflow_active);
    }

    #[test]
    fn build_sets_overflow_past_capacity() {
        let store = ZoneCounterStore::default();
        let ids: Vec<u32> =
            (1..=(crate::afxdp::zone_slot_counters::ZONE_SLOT_ASSIGNABLE_SLOTS as u32 + 5))
                .collect();
        let flood_store = FloodCounterStore::default();
        let (map, _caches) = build_map(&ids, &store, &flood_store);
        assert!(
            map.overflow_active,
            "exceeding assignable slots must set overflow_active"
        );
        // Exactly the capacity is assigned; the rest are slot 0.
        let assigned = (1..=65535u32).filter(|&z| map.slot_of(z) != 0).count();
        assert_eq!(
            assigned,
            crate::afxdp::zone_slot_counters::ZONE_SLOT_ASSIGNABLE_SLOTS
        );
    }

    /// #6843: a zone that was POPULATED and is then pushed past the hot-path
    /// slot capacity by a later config must STOP being published.
    ///
    /// This is the transition the pre-existing overflow tests never reached.
    /// They build an over-capacity map from scratch and check `slot_of == 0` +
    /// `overflow_active` — true, but only about a zone that was never counted.
    /// The dangerous zone is one that WAS counted: the store is carried forward
    /// across applies and `reconcile` retains it (it is still configured), so
    /// its nonzero totals survive while its slot does not. Publishing that row
    /// mirrors a total that can never advance again — a frozen counter that
    /// under-reports every subsequent packet while looking alive.
    #[test]
    fn populated_zone_stops_publishing_once_pushed_past_capacity() {
        let store = ZoneCounterStore::default();

        // Apply 1: one high-hash zone, alone and comfortably within capacity.
        const Z: u32 = 50675; // config::StableZoneID("trust")
        let flood_store = FloodCounterStore::default();
        let (map1, caches1) = build_map(&[Z], &store, &flood_store);
        assert_ne!(map1.slot_of(Z), 0, "Z must hold a slot in apply 1");
        record_zone_traffic(&map1, Z, 0, 1500);
        record_zone_traffic(&map1, Z, 0, 1500);
        flush(&store, &map1, &caches1);

        let published = publishable_zone_rows(&store, &map1, |_| true);
        assert_eq!(published.len(), 1, "apply 1 must publish Z: {published:?}");
        assert_eq!(published[0].ingress_packets, 2);

        // Apply 2: add enough LOWER ids to consume every assignable slot. Z is
        // still configured, so reconcile keeps its accumulated totals — but
        // sorted-order slot assignment exhausts capacity before reaching it.
        let mut ids: Vec<u32> =
            (1..=(crate::afxdp::zone_slot_counters::ZONE_SLOT_ASSIGNABLE_SLOTS as u32)).collect();
        ids.push(Z);
        let configured: FxHashSet<u32> = ids.iter().copied().collect();
        store.reconcile(&configured);
        let flood_store = FloodCounterStore::default();
        let (map2, _caches2) = build_map(&ids, &store, &flood_store);

        assert!(map2.overflow_active, "apply 2 must overflow");
        assert_eq!(map2.slot_of(Z), 0, "Z must have lost its slot in apply 2");

        // The retained totals are still in the store — this is the setup for
        // the bug, and asserting it keeps the test honest: it is NOT passing
        // because the data vanished.
        let raw: Vec<_> = snap(&store)
            .into_iter()
            .filter(|s| s.zone_id == Z)
            .collect();
        assert_eq!(raw.len(), 1, "store must still retain Z's totals");
        assert_eq!(raw[0].ingress_packets, 2);

        // The publish filter must nevertheless drop it.
        let published = publishable_zone_rows(&store, &map2, |zid| configured.contains(&zid));
        assert!(
            !published.iter().any(|s| s.zone_id == Z),
            "a populated zone that lost its slot must STOP publishing — otherwise \
             its retained total freezes and under-reports forever: {published:?}"
        );
    }

    /// #6843 companion: the filter must not over-reach. A zone that still holds
    /// a slot keeps publishing even when a SIBLING overflowed, so the fix
    /// cannot be satisfied by dropping everything once `overflow_active` is set.
    #[test]
    fn slotted_zones_keep_publishing_while_a_sibling_overflows() {
        let store = ZoneCounterStore::default();
        let mut ids: Vec<u32> =
            (1..=(crate::afxdp::zone_slot_counters::ZONE_SLOT_ASSIGNABLE_SLOTS as u32)).collect();
        const OVERFLOWED: u32 = 65533;
        ids.push(OVERFLOWED);
        let flood_store = FloodCounterStore::default();
        let (map, caches) = build_map(&ids, &store, &flood_store);
        assert!(map.overflow_active);
        assert_eq!(map.slot_of(OVERFLOWED), 0);

        // Move traffic on a zone that DID get a slot.
        record_zone_traffic(&map, 1, 0, 64);
        flush(&store, &map, &caches);

        // A REAL configured set, and one that excludes a slotted-with-traffic
        // zone (2). `|_| true` here would let the configured predicate be
        // deleted with this test still green — the assertion must exercise both
        // predicates, not just the one the test is named for.
        record_zone_traffic(&map, 2, 0, 64);
        flush(&store, &map, &caches);
        let configured: FxHashSet<u32> = [1u32, OVERFLOWED].into_iter().collect();
        let published = publishable_zone_rows(&store, &map, |z| configured.contains(&z));
        assert!(
            published.iter().any(|s| s.zone_id == 1),
            "a slotted, configured zone must keep publishing during overflow: {published:?}"
        );
        assert!(!published.iter().any(|s| s.zone_id == OVERFLOWED));
        assert!(
            !published.iter().any(|s| s.zone_id == 2),
            "zone 2 holds a slot and has traffic but is NOT configured, so the \
             configured predicate must still drop it: {published:?}"
        );
    }

    /// #6843: the configured filter is still independently load-bearing — an
    /// unconfigured zone is dropped even while it holds a slot. Without this,
    /// the slot check alone could be mistaken for the whole contract.
    #[test]
    fn unconfigured_zone_is_dropped_even_with_a_live_slot() {
        let store = ZoneCounterStore::default();
        // Build over capacity so a THIRD zone (UNSLOTTED) also carries traffic.
        // With only slotted zones present, the slot predicate could be deleted
        // and this test would still pass — it must exercise both predicates.
        const UNSLOTTED: u32 = 65533;
        let mut ids: Vec<u32> =
            (1..=(crate::afxdp::zone_slot_counters::ZONE_SLOT_ASSIGNABLE_SLOTS as u32)).collect();
        ids.push(UNSLOTTED);
        let flood_store = FloodCounterStore::default();
        let (map, caches) = build_map(&ids, &store, &flood_store);
        assert_ne!(map.slot_of(10), 0, "10 must hold a slot");
        assert_ne!(map.slot_of(20), 0, "20 must hold a slot");
        assert_eq!(
            map.slot_of(UNSLOTTED),
            0,
            "the third zone must be unslotted"
        );

        // Flush after EACH record, with the slot map the traffic was recorded
        // against. The pending accumulator is a shared thread-local, so a flush
        // folds whatever is pending through whichever slot map it is handed —
        // recording against two maps before flushing once mis-attributes the
        // first map's deltas and then resets them.
        record_zone_traffic(&map, 10, 20, 100);
        flush(&store, &map, &caches);
        // Give the unslotted zone retained totals directly in the store, as a
        // carried-forward apply would, so it is a real publish candidate.
        let flood_store = FloodCounterStore::default();
        let (seed, seed_caches) = build_map(&[UNSLOTTED], &store, &flood_store);
        record_zone_traffic(&seed, UNSLOTTED, 0, 64);
        flush(&store, &seed, &seed_caches);

        let published = publishable_zone_rows(&store, &map, |zid| zid != 10);
        assert!(
            !published.iter().any(|s| s.zone_id == 10),
            "an unconfigured zone must be dropped regardless of its slot: {published:?}"
        );
        assert!(published.iter().any(|s| s.zone_id == 20));
        assert!(
            !published.iter().any(|s| s.zone_id == UNSLOTTED),
            "a configured zone with retained totals but NO slot must still be \
             dropped, so the slot predicate stays bound here too: {published:?}"
        );
    }

    #[test]
    fn record_flush_snapshot_accumulates_both_directions() {
        let store = ZoneCounterStore::default();
        let flood_store = FloodCounterStore::default();
        let (map, caches) = build_map(&[100, 200], &store, &flood_store);
        // A packet from zone 100 to zone 200: +ingress on 100, +egress on 200.
        record_zone_traffic(&map, 100, 200, 1500);
        record_zone_traffic(&map, 100, 200, 500);
        // A reply from zone 200 to zone 100.
        record_zone_traffic(&map, 200, 100, 40);
        flush(&store, &map, &caches);

        let mut snap = snap(&store);
        snap.sort_unstable_by_key(|s| s.zone_id);
        assert_eq!(snap.len(), 2);

        let z100 = &snap[0];
        assert_eq!(z100.zone_id, 100);
        assert_eq!(z100.ingress_packets, 2);
        assert_eq!(z100.ingress_bytes, 2000);
        assert_eq!(z100.egress_packets, 1);
        assert_eq!(z100.egress_bytes, 40);

        let z200 = &snap[1];
        assert_eq!(z200.zone_id, 200);
        assert_eq!(z200.ingress_packets, 1);
        assert_eq!(z200.ingress_bytes, 40);
        assert_eq!(z200.egress_packets, 2);
        assert_eq!(z200.egress_bytes, 2000);
    }

    #[test]
    fn unassigned_and_zero_zones_are_uncounted() {
        let store = ZoneCounterStore::default();
        let flood_store = FloodCounterStore::default();
        let (map, caches) = build_map(&[100], &store, &flood_store);
        // Egress zone 999 is unconfigured (slot 0); ingress 0 is unzoned.
        record_zone_traffic(&map, 0, 999, 1500);
        // Ingress 100 counted; egress 999 uncounted.
        record_zone_traffic(&map, 100, 999, 1500);
        flush(&store, &map, &caches);
        let snap = snap(&store);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].zone_id, 100);
        assert_eq!(snap[0].ingress_packets, 1);
        assert_eq!(snap[0].egress_packets, 0);
    }

    #[test]
    fn clear_resets_totals() {
        let store = ZoneCounterStore::default();
        let flood_store = FloodCounterStore::default();
        let (map, caches) = build_map(&[100], &store, &flood_store);
        record_zone_traffic(&map, 100, 100, 64);
        flush(&store, &map, &caches);
        assert_eq!(snap(&store).len(), 1);
        store.clear();
        assert!(snap(&store).is_empty());
        // #5163: clear resets the atomics IN PLACE (keeps the map entry), so the
        // live slot map's cached Arc keeps counting from zero after the clear.
        record_zone_traffic(&map, 100, 100, 64);
        flush(&store, &map, &caches);
        let snap = snap(&store);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].ingress_packets, 1);
        assert_eq!(snap[0].egress_packets, 1);
    }

    #[test]
    fn reconcile_drops_removed_zones() {
        let store = ZoneCounterStore::default();
        let flood_store = FloodCounterStore::default();
        let (map, caches) = build_map(&[100, 200], &store, &flood_store);
        record_zone_traffic(&map, 100, 200, 64);
        flush(&store, &map, &caches);
        assert_eq!(snap(&store).len(), 2);
        let keep: FxHashSet<u32> = [100u32].into_iter().collect();
        store.reconcile(&keep);
        let snap = snap(&store);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].zone_id, 100);
    }

    #[test]
    fn surviving_zone_keeps_the_same_atomic_block_across_a_slot_renumber() {
        // #5163: the store is zone-id keyed and carried forward across applies.
        // A rebuild that renumbers slots (a lower id appears) must NOT reset or
        // double a surviving zone's totals — the new slot map resolves the SAME
        // Arc for the surviving zone.
        let store = ZoneCounterStore::default();
        let flood_store = FloodCounterStore::default();
        let (map1, caches1) = build_map(&[200], &store, &flood_store);
        assert_eq!(map1.slot_of(200), 1);
        record_zone_traffic(&map1, 200, 200, 100);
        flush(&store, &map1, &caches1);
        // Config apply adds zone 100 (< 200), which takes slot 1 and pushes 200
        // to slot 2 — a renumber. Store carried forward (same instance here).
        let flood_store = FloodCounterStore::default();
        let (map2, caches2) = build_map(&[100, 200], &store, &flood_store);
        assert_eq!(map2.slot_of(100), 1);
        assert_eq!(map2.slot_of(200), 2);
        record_zone_traffic(&map2, 200, 200, 100);
        flush(&store, &map2, &caches2);
        let snap = snap(&store);
        let z200 = snap.iter().find(|s| s.zone_id == 200).expect("zone 200");
        // 2 packets total across the renumber — not reset to 1, not doubled.
        assert_eq!(z200.ingress_packets, 2);
        assert_eq!(z200.egress_packets, 2);
        assert_eq!(z200.ingress_bytes, 200);
    }

    // ── #5163 RED-on-revert gate ──────────────────────────────────────────
    //
    // Two assertions together pin the contention fix. Reverting the fold to the
    // pre-#5163 per-batch global-mutex fold makes AT LEAST the lock-freedom
    // test fail:
    //
    //   1. `concurrent_workers_fold_lock_free_without_lost_counts` — correctness
    //      of the new accumulation: N worker threads each fold M batches into
    //      the SHARED store concurrently; the merged total must equal N*M with
    //      no lost or double counts. (A broken fetch_add merge fails here; a
    //      mutex fold would also pass, so this is the correctness half.)
    //
    //   2. `worker_fold_makes_progress_while_status_reader_holds_the_lock` — the
    //      LOAD-BEARING structural assertion: while the ≤1 s status/clear path
    //      holds the shared store mutex, a worker's per-batch fold must still
    //      COMPLETE promptly. The lock-free fold `fetch_add`s into the slot
    //      map's cached atomics and returns in microseconds. Reverting to the
    //      per-batch-global-mutex fold makes the fold BLOCK on the held mutex
    //      until the reader releases (300 ms here), so the `< 150 ms` bound
    //      FAILS — a clean assertion failure, not a hang (the holder always
    //      releases).

    #[test]
    fn concurrent_workers_fold_lock_free_without_lost_counts() {
        const WORKERS: u64 = 8;
        const PER_WORKER: u64 = 20_000;
        const BYTES: u64 = 100;
        let store = ZoneCounterStore::default();
        // One shared slot map, exactly as every worker shares `forwarding`.
        let flood_store = FloodCounterStore::default();
        let (map_inner, caches_inner) = build_map(&[100, 200], &store, &flood_store);
        let map = Arc::new(map_inner);
        let caches = Arc::new(caches_inner);

        let mut handles = Vec::new();
        for _ in 0..WORKERS {
            let map = Arc::clone(&map);
            let caches = Arc::clone(&caches);
            // The shared store, exactly as every worker holds a ForwardingState
            // clone that shares the same `Arc<Mutex>` store.
            let store = store.clone();
            handles.push(thread::spawn(move || {
                // Each worker (own thread → own ZONE_PENDING) records and folds
                // one "batch" per iteration, hammering the shared per-zone
                // atomics concurrently with every other worker.
                for _ in 0..PER_WORKER {
                    record_zone_traffic(&map, 100, 200, BYTES);
                    flush(&store, &map, &caches);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let snap = snap(&store);
        let z100 = snap.iter().find(|s| s.zone_id == 100).expect("zone 100");
        assert_eq!(z100.ingress_packets, WORKERS * PER_WORKER);
        assert_eq!(z100.ingress_bytes, WORKERS * PER_WORKER * BYTES);
        let z200 = snap.iter().find(|s| s.zone_id == 200).expect("zone 200");
        assert_eq!(z200.egress_packets, WORKERS * PER_WORKER);
        assert_eq!(z200.egress_bytes, WORKERS * PER_WORKER * BYTES);
    }

    #[test]
    fn worker_fold_makes_progress_while_status_reader_holds_the_lock() {
        let store = ZoneCounterStore::default();
        let flood_store = FloodCounterStore::default();
        let (map, caches) = build_map(&[100], &store, &flood_store);

        // A second thread parks on the shared store mutex for 300 ms — standing
        // in for the ≤1 s status/clear path holding it under contention.
        let held = store.clone();
        let (locked_tx, locked_rx) = mpsc::channel();
        let holder = thread::spawn(move || {
            let guard = held.lock_totals_for_test();
            locked_tx.send(()).unwrap();
            thread::sleep(Duration::from_millis(300));
            drop(guard);
        });
        // Wait until the lock is definitely held elsewhere.
        locked_rx.recv().unwrap();

        // A worker records + folds while the shared lock is held. The lock-free
        // fold must return without waiting on that mutex.
        let start = Instant::now();
        record_zone_traffic(&map, 100, 100, 64);
        flush(&store, &map, &caches);
        let elapsed = start.elapsed();

        holder.join().unwrap();
        assert!(
            elapsed < Duration::from_millis(150),
            "per-batch worker fold blocked on the shared store lock for {elapsed:?} \
             — the fold must be lock-free (issue #5163). A per-batch global-mutex \
             fold would block until the status reader released the lock (~300 ms)."
        );
        // The fold still landed the count (lock-free path is correct, not a no-op).
        let snap = snap(&store);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].ingress_packets, 1);
        assert_eq!(snap[0].egress_packets, 1);
    }
}

#[cfg(test)]
mod counter_egress_zone_tests {
    use super::counter_egress_zone;
    use crate::afxdp::ForwardingDisposition;

    #[test]
    fn fabric_redirect_credits_admission_zone() {
        assert_eq!(
            counter_egress_zone(ForwardingDisposition::FabricRedirect, 7, 9, 9),
            7,
            "redirect must credit the intended zone, not the fabric transport"
        );
        assert_eq!(
            counter_egress_zone(ForwardingDisposition::FabricRedirect, 0, 9, 9),
            9,
            "no admission capture: computed zone is the only information"
        );
        assert_eq!(
            counter_egress_zone(ForwardingDisposition::ForwardCandidate, 7, 3, 9),
            3,
            "non-redirect uses the computed pair"
        );
        assert_eq!(
            counter_egress_zone(ForwardingDisposition::ForwardCandidate, 7, 0, 9),
            9,
            "unresolved computed zone falls back to the resolution zone"
        );
    }
}
