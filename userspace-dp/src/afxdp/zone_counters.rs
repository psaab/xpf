//! #3651: per-zone ingress/egress traffic (packet + byte) counters.
//!
//! The eBPF-era dense `zone_counters` BPF array was deleted in the #1476
//! retirement; the Go read surfaces (`show security zones` Traffic statistics,
//! REST `/security/zones`, the Prometheus collector) key a sparse offset map
//! and report `ErrCounterNotPopulated` ("not available") because nothing
//! sources per-zone volume. This module is the userspace POPULATE half
//! (design of record: `docs/research/3643-dead-counters/plan.md` §5A).
//!
//! ## Hot path (no per-packet hash, no per-packet atomic, no per-batch lock)
//!
//! [`ZoneCounterSlotMap`] is a flat direct-index `[u8; 65536]` zone-id → slot
//! LUT built at config-apply time. A forwarded packet resolves its ingress and
//! egress zone slot with two array reads (Codex+AGY r1 mandate: a per-packet
//! `HashMap::get` would throttle forwarding) and accumulates into a per-worker
//! thread-local dense [`ZonePending`] accumulator — the same coalesce-then-fold
//! technique `policy::record_policy_hit_counter` / `filter::record_filter_counter`
//! use. The per-RX-batch [`flush_recorded_zone_counters`] folds the coalesced
//! per-slot deltas into the shared per-zone atomics the slot map caches.
//!
//! ## Store (lock-free per-batch fold, mutex only off the hot path — #5163)
//!
//! Before #5163 the fold locked a single `Arc<Mutex<FxHashMap>>` on the shared
//! [`ZoneCounterStore`] EVERY RX batch on EVERY worker, so all RX queues
//! bounced one mutex cache line at line rate — cross-worker serialization on
//! the hot path. The store now holds one [`ZoneTotalsAtomic`] block PER zone id
//! (`Arc<Mutex<FxHashMap<u16, Arc<ZoneTotalsAtomic>>>>`) and the mutex guards
//! only the MAP STRUCTURE — get-or-create at config-apply, and iterate at
//! snapshot / clear / reconcile — all off the hot path (≤ once per commit or per
//! 1 s status poll). Each configured slot caches its zone's `Arc<ZoneTotalsAtomic>`
//! in the slot map at build time, so the per-batch fold is a straight `Relaxed`
//! `fetch_add` into per-zone atomics with NO lock and NO map lookup — exactly
//! the lock-free shared-counter shape the `policy`/`filter` hit counters already
//! use.
//!
//! The store stays keyed by the STABLE zone id, not by slot, so a config apply
//! that renumbers slots never mis-attributes counts: the slot map's cached
//! `Arc` is resolved from the zone-id-keyed store, so a surviving zone keeps the
//! SAME atomic block across applies (get-or-create returns the existing Arc)
//! while a renumbered slot simply points at that same stable block. That removes
//! the cold-path `zero_slot` reassignment machinery entirely. The store rides
//! `ForwardingState` (cloned forward from the previous state across applies,
//! like a persistent Arc) so totals survive config commits. `clear` resets each
//! zone's atomics IN PLACE (it must not drop the map entry, or a live slot map
//! would keep folding into an orphaned Arc that the snapshot no longer sees) so
//! the operator `clear_zone_counters` control IPC zeroes the totals while
//! forwarding keeps counting from zero.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rustc_hash::{FxHashMap, FxHashSet};

use crate::protocol::ZoneTrafficCounterStatus;

/// Dense hot-path slot count. Slot 0 is reserved (unassigned / unzoned), so
/// `ZONE_COUNTER_SLOTS - 1` zones are assignable to a slot; a configured zone
/// past that capacity sets `overflow_active` and its traffic goes uncounted
/// (documented, same posture as the cold-path histogram `overflow_active`).
/// 63 assignable slots covers every realistic deployment (the legacy dense
/// `zone_counters` array held 64) while keeping the per-worker thread-local
/// accumulator small (64 × 4 × 8 = 2 KiB).
pub(in crate::afxdp) const ZONE_COUNTER_SLOTS: usize = 64;

/// #6946: `ZonePending::touched_slots` is a `u64` bitmask, one bit per slot.
/// Raising the slot count past 64 would make `1u64 << slot` shift out of
/// range — a panic in debug and a silently WRONG mask in release, which
/// would drop whole zones' counters with no error. The bound is asserted at
/// compile time so the capacity cannot be raised without also widening the
/// mask.
const _: () = assert!(ZONE_COUNTER_SLOTS <= 64);

/// Number of assignable slots (slot 0 reserved).
pub(in crate::afxdp) const ZONE_COUNTER_ASSIGNABLE_SLOTS: usize = ZONE_COUNTER_SLOTS - 1;

/// Wire/layout version stamped into `ProcessStatus.zone_counter_layout_version`
/// when the block is populated (#3651). 0/absent = pre-#3651 helper.
pub(in crate::afxdp) const ZONE_COUNTER_LAYOUT_VERSION: u32 = 1;

/// Flat direct-index zone-id → hot-path slot LUT, built at config apply.
///
/// `slot_of[zone_id]` is 0 for an unassigned zone (unzoned id 0, or a zone
/// past the slot capacity), else the dense slot `[1, ZONE_COUNTER_ASSIGNABLE_SLOTS]`.
/// `inverse[slot]` recovers the zone id for the flush's slot → zone-id
/// translation (0 = free slot). A single 16-bit zone id makes the flat LUT
/// feasible where the cold-path 32-bit zone-PAIR key needed a `HashMap`.
pub(in crate::afxdp) struct ZoneCounterSlotMap {
    slot_of: Box<[u8; 65536]>,
    inverse: [u16; ZONE_COUNTER_SLOTS],
    /// #5163: per-slot handle to the assigned zone's shared atomic block,
    /// resolved from the zone-id-keyed [`ZoneCounterStore`] at build time. The
    /// per-batch fold reads `slot_totals[slot]` and `fetch_add`s directly, so
    /// it never locks the store or does a map lookup on the hot path. `None`
    /// for an unassigned slot (slot 0 and any slot past the configured zones).
    slot_totals: [Option<Arc<ZoneTotalsAtomic>>; ZONE_COUNTER_SLOTS],
    /// True if some configured zone could not be assigned a slot because the
    /// `ZONE_COUNTER_ASSIGNABLE_SLOTS` capacity was exhausted. Surfaced as
    /// `ProcessStatus.zone_counter_overflow_active`.
    pub(in crate::afxdp) overflow_active: bool,
}

impl Default for ZoneCounterSlotMap {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::fmt::Debug for ZoneCounterSlotMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Summarize rather than dumping the 64 KiB LUT.
        let assigned = self.inverse.iter().filter(|&&z| z != 0).count();
        f.debug_struct("ZoneCounterSlotMap")
            .field("assigned_zones", &assigned)
            .field("overflow_active", &self.overflow_active)
            .finish()
    }
}

impl ZoneCounterSlotMap {
    /// An empty map: every zone resolves to slot 0 (uncounted).
    pub(in crate::afxdp) fn empty() -> Self {
        Self {
            slot_of: Box::new([0u8; 65536]),
            inverse: [0u16; ZONE_COUNTER_SLOTS],
            slot_totals: std::array::from_fn(|_| None),
            overflow_active: false,
        }
    }

    /// Build the slot map from the configured zone-id set. Slots are assigned
    /// in sorted zone-id order (deterministic for a given config); a duplicate
    /// or zero id is ignored. Because the shared store is zone-id keyed, slot
    /// assignment does NOT need to be stable across applies (unlike the
    /// cold-path histogram, whose slot IS the accumulator index), so this is a
    /// plain rebuild with no previous-map retention.
    ///
    /// #5163: each assigned slot caches its zone's shared `Arc<ZoneTotalsAtomic>`,
    /// resolved (get-or-create) from `store`. A zone that survives this apply
    /// gets the SAME atomic block it had before (the store is zone-id keyed and
    /// carried forward), so counts never reset or double across a slot renumber;
    /// the per-batch fold then never touches the store's mutex.
    pub(in crate::afxdp) fn build(zone_ids: &[u16], store: &ZoneCounterStore) -> Self {
        let mut ids: Vec<u16> = zone_ids.iter().copied().filter(|&z| z != 0).collect();
        ids.sort_unstable();
        ids.dedup();

        let mut slot_of = Box::new([0u8; 65536]);
        let mut inverse = [0u16; ZONE_COUNTER_SLOTS];
        let mut slot_totals: [Option<Arc<ZoneTotalsAtomic>>; ZONE_COUNTER_SLOTS] =
            std::array::from_fn(|_| None);
        let mut overflow_active = false;
        let mut next_slot = 1usize;
        for zid in ids {
            if next_slot > ZONE_COUNTER_ASSIGNABLE_SLOTS {
                overflow_active = true;
                break;
            }
            slot_of[zid as usize] = next_slot as u8;
            inverse[next_slot] = zid;
            slot_totals[next_slot] = Some(store.zone_totals(zid));
            next_slot += 1;
        }
        Self {
            slot_of,
            inverse,
            slot_totals,
            overflow_active,
        }
    }

    /// Resolve the hot-path slot for `zone_id` (0 = unassigned / uncounted).
    #[inline]
    pub(in crate::afxdp) fn slot_of(&self, zone_id: u16) -> u8 {
        self.slot_of[zone_id as usize]
    }
}

/// Select the rows publishable on `ProcessStatus.zone_traffic_counters`.
///
/// A row survives only when its zone is BOTH still configured AND holds a live
/// hot-path slot. The second condition is the one that is easy to miss, because
/// it is about a TRANSITION rather than a steady state.
///
/// The store outlives the slot map. Config apply carries the store forward and
/// `reconcile` retains every still-configured zone, while
/// [`ZoneCounterSlotMap::build`] assigns only [`ZONE_COUNTER_ASSIGNABLE_SLOTS`]
/// slots in sorted zone-id order. So a zone that accumulated traffic and is
/// then pushed past capacity by a later config — e.g. 63 lower-id zones added
/// alongside it — remains configured, keeps its retained nonzero totals, and
/// gets slot 0. It is no longer counted, but its old numbers are still in the
/// store.
///
/// Publishing that row makes the Go side mirror a total that can never advance
/// again: a FROZEN counter that under-reports every subsequent packet while
/// looking perfectly alive. Omitting it instead makes the zone read as
/// "not populated" end to end, which is the honest answer — its traffic really
/// is uncounted — with `overflow_active` explaining why.
///
/// Reasoning about "a zone that was never counted" is not enough to establish
/// this; the dangerous case is a zone that WAS counted and then stopped.
pub(in crate::afxdp) fn publishable_zone_rows(
    store: &ZoneCounterStore,
    slot_map: &ZoneCounterSlotMap,
    is_configured: impl Fn(u16) -> bool,
) -> Vec<ZoneTrafficCounterStatus> {
    store
        .snapshot()
        .into_iter()
        .filter(|s| is_configured(s.zone_id) && slot_map.slot_of(s.zone_id) != 0)
        .collect()
}

/// #5163: shared cumulative per-zone traffic totals as four `Relaxed` atomics.
/// One block per SLOT-ASSIGNED zone id — not per configured zone.
/// [`ZoneCounterSlotMap::build`] skips zone id 0 and stops once
/// [`ZONE_COUNTER_ASSIGNABLE_SLOTS`] are taken, so a config carrying zone 0 or
/// more than that many zones resolves a block for a strict SUBSET of what it
/// configures; the rest get slot 0 and go uncounted (`overflow_active`). The
/// per-batch worker fold `fetch_add`s
/// into it lock-free (the same lock-free shared-counter shape as
/// `PolicyRuleCounter`), and the ≤ 1 s status/clear path reads/zeroes it under
/// the store mutex. Cache-line sharing between workers `fetch_add`ing the same
/// zone is the accepted policy/filter-counter posture — vastly cheaper than the
/// pre-#5163 global mutex the whole fold used to take every batch.
#[derive(Debug, Default)]
struct ZoneTotalsAtomic {
    ingress_packets: AtomicU64,
    ingress_bytes: AtomicU64,
    egress_packets: AtomicU64,
    egress_bytes: AtomicU64,
}

impl ZoneTotalsAtomic {
    #[inline]
    fn add_ingress(&self, packets: u64, bytes: u64) {
        if packets != 0 {
            self.ingress_packets.fetch_add(packets, Ordering::Relaxed);
        }
        if bytes != 0 {
            self.ingress_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    #[inline]
    fn add_egress(&self, packets: u64, bytes: u64) {
        if packets != 0 {
            self.egress_packets.fetch_add(packets, Ordering::Relaxed);
        }
        if bytes != 0 {
            self.egress_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Independent relaxed loads of the four fields. Each field is exact; the
    /// quad is eventual-consistent (a snapshot may straddle one in-flight
    /// fold), the same contract `PolicyRuleCounter::snapshot` accepts.
    fn load(&self) -> (u64, u64, u64, u64) {
        (
            self.ingress_packets.load(Ordering::Relaxed),
            self.ingress_bytes.load(Ordering::Relaxed),
            self.egress_packets.load(Ordering::Relaxed),
            self.egress_bytes.load(Ordering::Relaxed),
        )
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
}

/// Coordinator-owned, config-apply-surviving cumulative per-zone traffic
/// store, keyed by the stable zone id. The mutex guards only the MAP STRUCTURE
/// (get-or-create at config-apply, iterate at snapshot/clear/reconcile) — all
/// off the hot path. The per-batch fold never locks it: it `fetch_add`s into
/// the per-zone `Arc<ZoneTotalsAtomic>` the slot map cached at build time
/// (#5163). `Clone` shares the inner `Arc<Mutex>`, so cloning `ForwardingState`
/// (worker publish) keeps every generation pointing at the same totals.
#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct ZoneCounterStore {
    totals: Arc<Mutex<FxHashMap<u16, Arc<ZoneTotalsAtomic>>>>,
}

impl ZoneCounterStore {
    /// Get-or-create the shared atomic block for a stable zone id, under the
    /// map mutex. Config-apply path only (called from `ZoneCounterSlotMap::build`
    /// to cache the `Arc` per slot); NOT the hot path. A surviving zone gets the
    /// SAME `Arc` back across applies, so its totals never reset or double.
    fn zone_totals(&self, zone_id: u16) -> Arc<ZoneTotalsAtomic> {
        let mut totals = self.totals.lock().expect("zone counter store poisoned");
        Arc::clone(totals.entry(zone_id).or_default())
    }

    /// Sparse snapshot for the status wire: one row per zone with any traffic.
    /// Deterministic order (sorted by zone id) for a stable wire.
    pub(in crate::afxdp) fn snapshot(&self) -> Vec<ZoneTrafficCounterStatus> {
        let totals = self.totals.lock().expect("zone counter store poisoned");
        let mut out: Vec<ZoneTrafficCounterStatus> = totals
            .iter()
            .filter_map(|(&zone_id, t)| {
                let (ingress_packets, ingress_bytes, egress_packets, egress_bytes) = t.load();
                if ingress_packets == 0
                    && ingress_bytes == 0
                    && egress_packets == 0
                    && egress_bytes == 0
                {
                    return None;
                }
                Some(ZoneTrafficCounterStatus {
                    zone_id,
                    ingress_packets,
                    ingress_bytes,
                    egress_packets,
                    egress_bytes,
                })
            })
            .collect();
        out.sort_unstable_by_key(|s| s.zone_id);
        out
    }

    /// Operator clear (`clear_zone_counters` IPC): zero every zone's cumulative
    /// totals so the pre-clear value is not snapped back on the next status
    /// poll. Load-bearing half of the operator clear.
    ///
    /// #6843: a cleared zone then reads as NOT POPULATED, not as zero -- the
    /// snapshot above omits all-zero rows and the Go side replaces its offset
    /// map from that snapshot, so the row is dropped rather than set to 0.
    ///
    /// #5163: resets each block IN PLACE rather than clearing the map, because a
    /// live slot map caches each zone's `Arc`; dropping the map entry would
    /// leave workers folding into an orphaned block the snapshot no longer sees
    /// (traffic would appear to stop counting until the next config apply).
    pub(in crate::afxdp) fn clear(&self) {
        let totals = self.totals.lock().expect("zone counter store poisoned");
        for block in totals.values() {
            block.reset();
        }
    }

    /// Drop totals for zones that are no longer configured (config apply
    /// hygiene). Correctness does not depend on this — the coordinator snapshot
    /// accessor also filters to configured zones — but it bounds the map to the
    /// live zone set. A `configured` zone's `Arc` is retained, so a slot map
    /// rebuilt in the same apply resolves the SAME block (no reset/double).
    pub(in crate::afxdp) fn reconcile(&self, configured: &FxHashSet<u16>) {
        self.totals
            .lock()
            .expect("zone counter store poisoned")
            .retain(|zone_id, _| configured.contains(zone_id));
    }

    /// #5163: fold a worker's coalesced per-slot deltas into the shared per-zone
    /// atomics the slot map cached at build time. LOCK-FREE — a straight
    /// `Relaxed` `fetch_add` per touched slot; it does NOT lock `self.totals`
    /// (that mutex is only for the ≤ 1 s snapshot/clear/reconcile map-structure
    /// ops). This is the load-bearing change: the pre-#5163 fold locked
    /// `self.totals` on EVERY worker EVERY batch, bouncing one cache line at
    /// line rate. Reintroducing a `self.totals.lock()` here (the per-batch
    /// global fold) is exactly what
    /// `worker_fold_makes_progress_while_status_reader_holds_the_lock` catches.
    /// The slot → zone attribution is fixed by which `Arc` each slot cached at
    /// build time, so a slot renumber across applies cannot mis-attribute (the
    /// fold and the intervening `record_zone_traffic` calls always read the SAME
    /// slot map).
    fn fold_pending(&self, pending: &ZonePending, slot_map: &ZoneCounterSlotMap) {
        // #6946: walk the touched bits instead of all 64 slots. Slot 0 is the
        // unassigned sentinel and is never recorded into, so it cannot be set.
        let mut mask = pending.touched_slots;
        while mask != 0 {
            let slot = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            let Some(totals) = &slot_map.slot_totals[slot] else {
                continue;
            };
            let ip = pending.ingress_packets[slot];
            let ib = pending.ingress_bytes[slot];
            let ep = pending.egress_packets[slot];
            let eb = pending.egress_bytes[slot];
            if ip == 0 && ib == 0 && ep == 0 && eb == 0 {
                continue;
            }
            totals.add_ingress(ip, ib);
            totals.add_egress(ep, eb);
        }
    }

    /// Test-only: every zone id the store currently holds a block for,
    /// INCLUDING zones whose four totals are all zero.
    ///
    /// #5716: [`Self::snapshot`] is deliberately SPARSE — it omits all-zero
    /// rows — so it cannot see a block that was get-or-created and never
    /// counted into. That is exactly the residue a rejected config build
    /// leaves behind if it resolves the candidate's zone blocks out of the
    /// carried-forward (Arc-shared, LIVE) store, so a fixture asserting "a
    /// rejected build did not mutate the live store" has to look HERE rather
    /// than at the operator-visible snapshot.
    #[cfg(test)]
    pub(in crate::afxdp) fn tracked_zone_ids_for_test(&self) -> Vec<u16> {
        let totals = self.totals.lock().expect("zone counter store poisoned");
        let mut ids: Vec<u16> = totals.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Test-only handle to the map mutex, so a test can hold the shared store
    /// lock (as the ≤ 1 s snapshot/clear path does) and prove the per-batch fold
    /// still makes progress — the #5163 lock-freedom invariant.
    #[cfg(test)]
    fn lock_totals_for_test(
        &self,
    ) -> std::sync::MutexGuard<'_, FxHashMap<u16, Arc<ZoneTotalsAtomic>>> {
        self.totals.lock().expect("zone counter store poisoned")
    }
}

/// Per-worker thread-local dense slot accumulator. Touched only by the owning
/// worker thread on the hot path; folded into the shared store per RX batch.
struct ZonePending {
    ingress_packets: [u64; ZONE_COUNTER_SLOTS],
    ingress_bytes: [u64; ZONE_COUNTER_SLOTS],
    egress_packets: [u64; ZONE_COUNTER_SLOTS],
    egress_bytes: [u64; ZONE_COUNTER_SLOTS],
    /// #6946: one bit per touched slot, replacing a single `touched: bool`.
    ///
    /// The bool made both per-batch operations O(SLOTS) regardless of how
    /// many slots actually moved: `reset` cleared 4 x [u64; 64] = 2048 B and
    /// `fold_pending` scanned all 64 slots, to flush what is typically ONE
    /// zone. The cost that matters is cache, not cycles — 32 dirtied lines
    /// per flush per worker per RX batch.
    touched_slots: u64,
}

impl Default for ZonePending {
    fn default() -> Self {
        Self {
            ingress_packets: [0; ZONE_COUNTER_SLOTS],
            ingress_bytes: [0; ZONE_COUNTER_SLOTS],
            egress_packets: [0; ZONE_COUNTER_SLOTS],
            egress_bytes: [0; ZONE_COUNTER_SLOTS],
            touched_slots: 0,
        }
    }
}

impl ZonePending {
    fn reset(&mut self) {
        // #6946: clear only the slots that moved. Whole-array assignment
        // dirtied every line whether or not it held a delta.
        let mut mask = self.touched_slots;
        while mask != 0 {
            let slot = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            self.ingress_packets[slot] = 0;
            self.ingress_bytes[slot] = 0;
            self.egress_packets[slot] = 0;
            self.egress_bytes[slot] = 0;
        }
        self.touched_slots = 0;
    }
}

thread_local! {
    static ZONE_PENDING: RefCell<ZonePending> = RefCell::new(ZonePending::default());
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
    admission_to_zone: u16,
    computed_to_zone: u16,
    fallback: u16,
) -> u16 {
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
    slot_map: &ZoneCounterSlotMap,
    ingress_zone_id: u16,
    egress_zone_id: u16,
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
            p.ingress_packets[s] = p.ingress_packets[s].saturating_add(1);
            p.ingress_bytes[s] = p.ingress_bytes[s].saturating_add(packet_bytes);
            p.touched_slots |= 1u64 << s;
        }
        if egress_slot != 0 {
            let s = egress_slot as usize;
            p.egress_packets[s] = p.egress_packets[s].saturating_add(1);
            p.egress_bytes[s] = p.egress_bytes[s].saturating_add(packet_bytes);
            p.touched_slots |= 1u64 << s;
        }
    });
}

/// Fold this worker thread's coalesced per-zone deltas into the shared per-zone
/// atomics the slot map caches. Called once per RX batch alongside
/// `flush_recorded_filter_counters` / `flush_recorded_policy_hit_counters`.
/// `slot_map` must be the SAME map the intervening `record_zone_traffic` calls
/// used (guaranteed: both read the loop iteration's `forwarding` snapshot), so
/// each slot's cached atomic block matches the zone it accumulated for.
///
/// #5163: lock-free — the fold `fetch_add`s into the slot map's cached
/// `Arc<ZoneTotalsAtomic>` blocks and never takes the `store` mutex, so the
/// per-batch worker path no longer serializes on a cross-worker lock. `store`
/// stays in the signature as the aggregation owner (the ≤ 1 s snapshot/clear
/// path locks it); the fold itself does not.
pub(in crate::afxdp) fn flush_recorded_zone_counters(
    store: &ZoneCounterStore,
    slot_map: &ZoneCounterSlotMap,
) {
    ZONE_PENDING.with(|pending| {
        let mut p = pending.borrow_mut();
        if p.touched_slots == 0 {
            return;
        }
        store.fold_pending(&p, slot_map);
        p.reset();
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

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
        let map = ZoneCounterSlotMap::build(&[11, 22], &store);

        // Batch 1: traffic on zone 11 only.
        record_zone_traffic(&map, 11, 0, 100);
        flush_recorded_zone_counters(&store, &map);

        // Batch 2: the SAME zone again. If reset() left slot 11's values in
        // place, this folds 100 (residue) + 100 (new) = 200 bytes.
        record_zone_traffic(&map, 11, 0, 100);
        flush_recorded_zone_counters(&store, &map);

        // Batch 3: a different zone, so the assertion above cannot pass by the
        // mask having stopped recording zone 11 altogether.
        record_zone_traffic(&map, 22, 0, 500);
        flush_recorded_zone_counters(&store, &map);

        let rows = store.snapshot();
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
    /// `const _: () = assert!(ZONE_COUNTER_SLOTS <= 64)` is what prevents it.
    /// This runtime cell fails loudly if that guard is ever deleted along
    /// with the const it protects.
    #[test]
    fn slot_capacity_fits_the_touched_mask_6946() {
        assert!(
            ZONE_COUNTER_SLOTS <= 64,
            "ZONE_COUNTER_SLOTS = {ZONE_COUNTER_SLOTS} exceeds the 64 bits of \
             ZonePending::touched_slots; `1u64 << slot` would shift out of range \
             and whole zones would stop being folded (#6946)"
        );
        assert!(
            crate::afxdp::flood_counters::FLOOD_COUNTER_SLOTS <= 64,
            "FLOOD_COUNTER_SLOTS exceeds the 64 bits of FloodPending::touched_slots"
        );
        // The top assignable slot must round-trip through the mask: bit 63 is
        // the one an off-by-one in the shift would lose.
        let mut p = ZonePending::default();
        let top = ZONE_COUNTER_SLOTS - 1;
        p.ingress_packets[top] = 7;
        p.touched_slots |= 1u64 << top;
        p.reset();
        assert_eq!(
            p.ingress_packets[top], 0,
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
        let map = ZoneCounterSlotMap::build(&[40000, 7, 65533], &store);
        assert!(!map.overflow_active);
        // sorted → 7 gets slot 1, 40000 slot 2, 65533 slot 3.
        assert_eq!(map.slot_of(7), 1);
        assert_eq!(map.slot_of(40000), 2);
        assert_eq!(map.slot_of(65533), 3);
        assert_eq!(map.inverse[1], 7);
        assert_eq!(map.inverse[2], 40000);
        assert_eq!(map.inverse[3], 65533);
        // Unconfigured / unzoned resolve to slot 0.
        assert_eq!(map.slot_of(0), 0);
        assert_eq!(map.slot_of(123), 0);
    }

    #[test]
    fn build_dedups_and_skips_zero() {
        let store = ZoneCounterStore::default();
        let map = ZoneCounterSlotMap::build(&[0, 5, 5, 9, 0, 5], &store);
        assert_eq!(map.slot_of(5), 1);
        assert_eq!(map.slot_of(9), 2);
        assert_eq!(map.slot_of(0), 0);
        assert!(!map.overflow_active);
    }

    #[test]
    fn build_sets_overflow_past_capacity() {
        let store = ZoneCounterStore::default();
        let ids: Vec<u16> = (1..=(ZONE_COUNTER_ASSIGNABLE_SLOTS as u16 + 5)).collect();
        let map = ZoneCounterSlotMap::build(&ids, &store);
        assert!(
            map.overflow_active,
            "exceeding {ZONE_COUNTER_ASSIGNABLE_SLOTS} assignable slots must set overflow_active"
        );
        // Exactly the capacity is assigned; the rest are slot 0.
        let assigned = (1..=65535u16).filter(|&z| map.slot_of(z) != 0).count();
        assert_eq!(assigned, ZONE_COUNTER_ASSIGNABLE_SLOTS);
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
        const Z: u16 = 50675; // config::StableZoneID("trust")
        let map1 = ZoneCounterSlotMap::build(&[Z], &store);
        assert_ne!(map1.slot_of(Z), 0, "Z must hold a slot in apply 1");
        record_zone_traffic(&map1, Z, 0, 1500);
        record_zone_traffic(&map1, Z, 0, 1500);
        flush_recorded_zone_counters(&store, &map1);

        let published = publishable_zone_rows(&store, &map1, |_| true);
        assert_eq!(published.len(), 1, "apply 1 must publish Z: {published:?}");
        assert_eq!(published[0].ingress_packets, 2);

        // Apply 2: add enough LOWER ids to consume every assignable slot. Z is
        // still configured, so reconcile keeps its accumulated totals — but
        // sorted-order slot assignment exhausts capacity before reaching it.
        let mut ids: Vec<u16> = (1..=(ZONE_COUNTER_ASSIGNABLE_SLOTS as u16)).collect();
        ids.push(Z);
        let configured: FxHashSet<u16> = ids.iter().copied().collect();
        store.reconcile(&configured);
        let map2 = ZoneCounterSlotMap::build(&ids, &store);

        assert!(map2.overflow_active, "apply 2 must overflow");
        assert_eq!(map2.slot_of(Z), 0, "Z must have lost its slot in apply 2");

        // The retained totals are still in the store — this is the setup for
        // the bug, and asserting it keeps the test honest: it is NOT passing
        // because the data vanished.
        let raw: Vec<_> = store
            .snapshot()
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
        let mut ids: Vec<u16> = (1..=(ZONE_COUNTER_ASSIGNABLE_SLOTS as u16)).collect();
        const OVERFLOWED: u16 = 65533;
        ids.push(OVERFLOWED);
        let map = ZoneCounterSlotMap::build(&ids, &store);
        assert!(map.overflow_active);
        assert_eq!(map.slot_of(OVERFLOWED), 0);

        // Move traffic on a zone that DID get a slot.
        record_zone_traffic(&map, 1, 0, 64);
        flush_recorded_zone_counters(&store, &map);

        // A REAL configured set, and one that excludes a slotted-with-traffic
        // zone (2). `|_| true` here would let the configured predicate be
        // deleted with this test still green — the assertion must exercise both
        // predicates, not just the one the test is named for.
        record_zone_traffic(&map, 2, 0, 64);
        flush_recorded_zone_counters(&store, &map);
        let configured: FxHashSet<u16> = [1u16, OVERFLOWED].into_iter().collect();
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
        const UNSLOTTED: u16 = 65533;
        let mut ids: Vec<u16> = (1..=(ZONE_COUNTER_ASSIGNABLE_SLOTS as u16)).collect();
        ids.push(UNSLOTTED);
        let map = ZoneCounterSlotMap::build(&ids, &store);
        assert_ne!(map.slot_of(10), 0, "10 must hold a slot");
        assert_ne!(map.slot_of(20), 0, "20 must hold a slot");
        assert_eq!(map.slot_of(UNSLOTTED), 0, "the third zone must be unslotted");

        // Flush after EACH record, with the slot map the traffic was recorded
        // against. The pending accumulator is a shared thread-local, so a flush
        // folds whatever is pending through whichever slot map it is handed —
        // recording against two maps before flushing once mis-attributes the
        // first map's deltas and then resets them.
        record_zone_traffic(&map, 10, 20, 100);
        flush_recorded_zone_counters(&store, &map);
        // Give the unslotted zone retained totals directly in the store, as a
        // carried-forward apply would, so it is a real publish candidate.
        let seed = ZoneCounterSlotMap::build(&[UNSLOTTED], &store);
        record_zone_traffic(&seed, UNSLOTTED, 0, 64);
        flush_recorded_zone_counters(&store, &seed);

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
        let map = ZoneCounterSlotMap::build(&[100, 200], &store);
        // A packet from zone 100 to zone 200: +ingress on 100, +egress on 200.
        record_zone_traffic(&map, 100, 200, 1500);
        record_zone_traffic(&map, 100, 200, 500);
        // A reply from zone 200 to zone 100.
        record_zone_traffic(&map, 200, 100, 40);
        flush_recorded_zone_counters(&store, &map);

        let mut snap = store.snapshot();
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
        let map = ZoneCounterSlotMap::build(&[100], &store);
        // Egress zone 999 is unconfigured (slot 0); ingress 0 is unzoned.
        record_zone_traffic(&map, 0, 999, 1500);
        // Ingress 100 counted; egress 999 uncounted.
        record_zone_traffic(&map, 100, 999, 1500);
        flush_recorded_zone_counters(&store, &map);
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].zone_id, 100);
        assert_eq!(snap[0].ingress_packets, 1);
        assert_eq!(snap[0].egress_packets, 0);
    }

    #[test]
    fn clear_resets_totals() {
        let store = ZoneCounterStore::default();
        let map = ZoneCounterSlotMap::build(&[100], &store);
        record_zone_traffic(&map, 100, 100, 64);
        flush_recorded_zone_counters(&store, &map);
        assert_eq!(store.snapshot().len(), 1);
        store.clear();
        assert!(store.snapshot().is_empty());
        // #5163: clear resets the atomics IN PLACE (keeps the map entry), so the
        // live slot map's cached Arc keeps counting from zero after the clear.
        record_zone_traffic(&map, 100, 100, 64);
        flush_recorded_zone_counters(&store, &map);
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].ingress_packets, 1);
        assert_eq!(snap[0].egress_packets, 1);
    }

    #[test]
    fn reconcile_drops_removed_zones() {
        let store = ZoneCounterStore::default();
        let map = ZoneCounterSlotMap::build(&[100, 200], &store);
        record_zone_traffic(&map, 100, 200, 64);
        flush_recorded_zone_counters(&store, &map);
        assert_eq!(store.snapshot().len(), 2);
        let keep: FxHashSet<u16> = [100u16].into_iter().collect();
        store.reconcile(&keep);
        let snap = store.snapshot();
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
        let map1 = ZoneCounterSlotMap::build(&[200], &store);
        assert_eq!(map1.slot_of(200), 1);
        record_zone_traffic(&map1, 200, 200, 100);
        flush_recorded_zone_counters(&store, &map1);
        // Config apply adds zone 100 (< 200), which takes slot 1 and pushes 200
        // to slot 2 — a renumber. Store carried forward (same instance here).
        let map2 = ZoneCounterSlotMap::build(&[100, 200], &store);
        assert_eq!(map2.slot_of(100), 1);
        assert_eq!(map2.slot_of(200), 2);
        record_zone_traffic(&map2, 200, 200, 100);
        flush_recorded_zone_counters(&store, &map2);
        let snap = store.snapshot();
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
        let map = Arc::new(ZoneCounterSlotMap::build(&[100, 200], &store));

        let mut handles = Vec::new();
        for _ in 0..WORKERS {
            let map = Arc::clone(&map);
            // The shared store, exactly as every worker holds a ForwardingState
            // clone that shares the same `Arc<Mutex>` store.
            let store = store.clone();
            handles.push(thread::spawn(move || {
                // Each worker (own thread → own ZONE_PENDING) records and folds
                // one "batch" per iteration, hammering the shared per-zone
                // atomics concurrently with every other worker.
                for _ in 0..PER_WORKER {
                    record_zone_traffic(&map, 100, 200, BYTES);
                    flush_recorded_zone_counters(&store, &map);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let snap = store.snapshot();
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
        let map = ZoneCounterSlotMap::build(&[100], &store);

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
        flush_recorded_zone_counters(&store, &map);
        let elapsed = start.elapsed();

        holder.join().unwrap();
        assert!(
            elapsed < Duration::from_millis(150),
            "per-batch worker fold blocked on the shared store lock for {elapsed:?} \
             — the fold must be lock-free (issue #5163). A per-batch global-mutex \
             fold would block until the status reader released the lock (~300 ms)."
        );
        // The fold still landed the count (lock-free path is correct, not a no-op).
        let snap = store.snapshot();
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
