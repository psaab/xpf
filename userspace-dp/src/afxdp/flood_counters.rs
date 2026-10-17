//! #3651: per-zone SYN / ICMP / UDP flood-EVENT counters.
//!
//! The sibling of [`crate::afxdp::zone_counters`], for the other half of the
//! dead per-zone counter families the #3643 HIDE marked "not available". Where
//! the traffic half accounts forwarded VOLUME, this one accounts flood EVENTS
//! — as two separate triples, DROPS and (#7086) ALARMS:
//! the counts `show security screen ids-option statistics` renders as
//! "SYN flood events" / "ICMP flood events" / "UDP flood events" per zone
//! (`dataplane.FloodState.SynCount/ICMPCount/UDPCount`).
//!
//! ## This is NEW accounting, not a snapshot of existing state
//!
//! The screen module holds per-zone rate-LIMITER state (`screen/mod.rs`
//! `ZoneScreenState`) — token buckets and count-min sketches whose job is to
//! decide the next verdict, not to remember how many verdicts were taken. The
//! durable screen accounting that exists today is GLOBAL/per-reason
//! (`BatchCounters::record_screen_drop` → `screen_reason_drops`, #3343), never
//! per zone. So there was nothing to publish: this module is the per-zone tally
//! itself, added on the drop path.
//!
//! ## Two arms, never merged
//!
//! [`record_zone_flood_drop`] is called only from
//! [`crate::afxdp::BatchCounters::record_screen_drop`], i.e. only when a screen
//! check has already decided to DROP. That is off the forwarding fast path.
//!
//! [`record_zone_flood_alarm`] (#7086) is its counterpart on the
//! `alarm-without-drop` arm of `stage_screen_check`: the check TRIPPED, the
//! drop was suppressed, a log-only alarm was raised and the packet was
//! PERMITTED and forwarded. It accumulates into a SEPARATE triple and is never
//! folded into the drop counts — a counter whose name and call-site contract
//! say DROP must not report forwarded packets. Junos `alarm-without-drop`
//! suppresses the drop, not the statistic, so both arms are real flood events;
//! what differs is the disposition, and the surface needs to tell them apart.
//!
//! Note the alarm arm is the HOTTER of the two: `alarm-without-drop` is a
//! per-ZONE profile flag, so a zone in alarm mode suppresses every flood drop
//! it would take, and a volumetric flood runs that path per packet on every
//! worker with no drop thinning it. Both arms share the LUT, the per-zone
//! atomic block and the per-batch fold; only the destination triple differs.
//!
//! It is nevertheless coalesced per RX batch rather than `fetch_add`ing
//! directly, because a screen drop is not rare when it matters: a SYN flood is
//! the primary `screen_drops` trigger, so under volumetric attack this path
//! runs per packet on every worker at once. `stage_screen_check` already
//! documents that constraint for the aggregate (#1187 — unbatched atomics here
//! would MESI-ping-pong with the coordinator's status reads under attack), and
//! a per-ZONE tally would concentrate the contention harder still: every worker
//! hammering the ONE zone under attack. So this mirrors the zone-counter shape
//! exactly — flat `[u8; 65536]` zone-id → slot LUT, per-worker thread-local
//! dense accumulator, one per-RX-batch fold into per-zone atomics the slot map
//! cached at build time (lock-free, #5163).
//!
//! ## Store
//!
//! [`FloodCounterStore`] is zone-id keyed and rides `ForwardingState`, so a
//! surviving zone keeps the SAME atomic block across a config apply that
//! renumbers slots. `clear` zeroes the blocks IN PLACE (never drops the map
//! entry) so a live slot map's cached `Arc` keeps counting from zero — the
//! `clear_flood_counters` operator IPC.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rustc_hash::{FxHashMap, FxHashSet};

use crate::protocol::ZoneFloodCounterStatus;

/// Dense hot-path slot count, mirroring [`ZONE_COUNTER_SLOTS`]. Slot 0 is
/// reserved (unassigned / unzoned).
///
/// [`ZONE_COUNTER_SLOTS`]: crate::afxdp::zone_counters::ZONE_COUNTER_SLOTS
pub(in crate::afxdp) const FLOOD_COUNTER_SLOTS: usize = 64;

/// #6946: `FloodPending::touched_slots` is a `u64` bitmask, one bit per slot.
/// Raising the slot count past 64 would make `1u64 << slot` shift out of
/// range — a panic in debug and a silently WRONG mask in release, dropping
/// whole zones' flood counts with no error. Asserted at compile time so the
/// capacity cannot be raised without widening the mask. (The sibling
/// assertion below pins FLOOD == ZONE; this one pins the mask width, and
/// both are needed: keeping the two counts equal does not keep either
/// within 64.)
const _: () = assert!(FLOOD_COUNTER_SLOTS <= 64);

/// Number of assignable slots (slot 0 reserved).
pub(in crate::afxdp) const FLOOD_COUNTER_ASSIGNABLE_SLOTS: usize = FLOOD_COUNTER_SLOTS - 1;

/// The two per-zone counter families MUST have the same capacity. Both build
/// their slot map from the SAME configured zone-id set in the same sorted
/// order, so equal capacity means a zone is either slotted for both families or
/// neither. Diverging capacities would make a zone report live traffic volume
/// while its flood counts read "not available" (or the reverse) with nothing on
/// any surface to explain the asymmetry.
const _: () = assert!(FLOOD_COUNTER_SLOTS == crate::afxdp::zone_counters::ZONE_COUNTER_SLOTS);

/// Wire/layout version stamped into `ProcessStatus.flood_counter_layout_version`
/// (#3651). #14619: stamped UNCONDITIONALLY, like the traffic twin;
/// 0/absent = helper with no per-zone flood accounting.
pub(in crate::afxdp) const FLOOD_COUNTER_LAYOUT_VERSION: u32 = 1;

/// Per-zone flood-counter ordinal for a screen drop reason, or `None` when the
/// reason is not one of the three FLOOD checks.
///
/// Deliberately an independent match rather than a reuse of
/// [`crate::screen::screen_reason_drop_index`]: this ordinal indexes a 3-wide
/// per-zone accumulator whose layout is the wire's
/// `syn_flood_events`/`icmp_flood_events`/`udp_flood_events` triple, not the
/// 15-wide per-reason array. The two happen to agree on 0/1/2 today and
/// `flood_reason_index_tracks_the_screen_reason_strings` pins that the REASON
/// STRINGS stay shared — a rename in `screen/mod.rs` that silently un-wired this
/// tally is exactly what that test catches.
#[inline]
pub(in crate::afxdp) fn flood_reason_index(reason: &str) -> Option<usize> {
    Some(match reason {
        "syn-flood" => 0,
        "icmp-flood" => 1,
        "udp-flood" => 2,
        _ => return None,
    })
}

/// Number of per-zone flood families (syn / icmp / udp).
pub(in crate::afxdp) const FLOOD_KINDS: usize = 3;

/// Flat direct-index zone-id → hot-path slot LUT, built at config apply.
/// Structurally identical to `ZoneCounterSlotMap`; see this module's header for
/// why the flood half is coalesced the same way despite being on the drop path.
pub(in crate::afxdp) struct FloodCounterSlotMap {
    slot_of: Box<[u8; 65536]>,
    inverse: [u16; FLOOD_COUNTER_SLOTS],
    /// Per-slot handle to the assigned zone's shared atomic block, resolved
    /// from the zone-id-keyed [`FloodCounterStore`] at build time so the
    /// per-batch fold never locks the store. `None` for an unassigned slot.
    slot_totals: [Option<Arc<FloodTotalsAtomic>>; FLOOD_COUNTER_SLOTS],
    /// True if some configured zone could not be assigned a slot because the
    /// `FLOOD_COUNTER_ASSIGNABLE_SLOTS` capacity was exhausted. Surfaced as
    /// `ProcessStatus.flood_counter_overflow_active`.
    pub(in crate::afxdp) overflow_active: bool,
}

impl Default for FloodCounterSlotMap {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::fmt::Debug for FloodCounterSlotMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Summarize rather than dumping the 64 KiB LUT.
        let assigned = self.inverse.iter().filter(|&&z| z != 0).count();
        f.debug_struct("FloodCounterSlotMap")
            .field("assigned_zones", &assigned)
            .field("overflow_active", &self.overflow_active)
            .finish()
    }
}

impl FloodCounterSlotMap {
    /// An empty map: every zone resolves to slot 0 (uncounted).
    pub(in crate::afxdp) fn empty() -> Self {
        Self {
            slot_of: Box::new([0u8; 65536]),
            inverse: [0u16; FLOOD_COUNTER_SLOTS],
            slot_totals: std::array::from_fn(|_| None),
            overflow_active: false,
        }
    }

    /// Build the slot map from the configured zone-id set. Slots are assigned
    /// in sorted zone-id order — the SAME order `ZoneCounterSlotMap::build`
    /// uses, so with equal capacity the two families slot identically. A
    /// duplicate or zero id is ignored. Each assigned slot caches its zone's
    /// shared `Arc<FloodTotalsAtomic>` (get-or-create from `store`), so a zone
    /// surviving this apply keeps the same block and its counts never reset or
    /// double across a slot renumber.
    pub(in crate::afxdp) fn build(zone_ids: &[u16], store: &FloodCounterStore) -> Self {
        let mut ids: Vec<u16> = zone_ids.iter().copied().filter(|&z| z != 0).collect();
        ids.sort_unstable();
        ids.dedup();

        let mut slot_of = Box::new([0u8; 65536]);
        let mut inverse = [0u16; FLOOD_COUNTER_SLOTS];
        let mut slot_totals: [Option<Arc<FloodTotalsAtomic>>; FLOOD_COUNTER_SLOTS] =
            std::array::from_fn(|_| None);
        let mut overflow_active = false;
        let mut next_slot = 1usize;
        for zid in ids {
            if next_slot > FLOOD_COUNTER_ASSIGNABLE_SLOTS {
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

    /// #14619: zone ids currently holding a live flood slot, in slot
    /// order. Twin of `ZoneCounterSlotMap::slotted_zone_ids`; capacities
    /// are asserted equal so the two sets agree.
    pub(in crate::afxdp) fn slotted_zone_ids(&self) -> Vec<u16> {
        self.inverse.iter().copied().filter(|&z| z != 0).collect()
    }
}

/// Select the rows publishable on `ProcessStatus.zone_flood_counters`.
///
/// Same two-filter contract as `publishable_zone_rows`: a row survives only when
/// its zone is BOTH still configured AND holds a live hot-path slot.
///
/// The slot filter is the load-bearing one, and it is about a TRANSITION rather
/// than a steady state. The store outlives the slot map — config apply carries
/// it forward and `reconcile` retains every still-configured zone — so a zone
/// that accumulated flood events and is then pushed past capacity by a later
/// config stays configured, keeps its retained nonzero counts, and gets slot 0.
/// Publishing that row would make the Go side mirror a total that can never
/// advance again: a FROZEN flood count that under-reports every subsequent
/// attack while looking perfectly alive. Omitting it makes the zone read
/// "not available" end to end, which is the honest answer, with
/// `flood_counter_overflow_active` carrying the reason.
pub(in crate::afxdp) fn publishable_flood_rows(
    store: &FloodCounterStore,
    slot_map: &FloodCounterSlotMap,
    is_configured: impl Fn(u16) -> bool,
) -> Vec<ZoneFloodCounterStatus> {
    store
        .snapshot()
        .into_iter()
        .filter(|s| is_configured(s.zone_id) && slot_map.slot_of(s.zone_id) != 0)
        .collect()
}

/// Shared cumulative per-zone flood-event totals as three `Relaxed` atomics.
/// One block per configured zone id; the per-batch worker fold `fetch_add`s into
/// it lock-free and the ≤ 1 s status/clear path reads/zeroes it under the store
/// mutex.
#[derive(Debug, Default)]
struct FloodTotalsAtomic {
    syn: AtomicU64,
    icmp: AtomicU64,
    udp: AtomicU64,
    /// #7086: the same three families counted on the ALARM arm — a flood
    /// check tripped, `alarm-without-drop` suppressed the drop, and the
    /// packet was PERMITTED and forwarded. Kept in a separate triple from
    /// the drop counts above, never folded into them: a counter whose name
    /// and call-site contract say DROP must not report permitted packets.
    syn_alarms: AtomicU64,
    icmp_alarms: AtomicU64,
    udp_alarms: AtomicU64,
}

impl FloodTotalsAtomic {
    #[inline]
    fn add(&self, kind: usize, count: u64) {
        if count == 0 {
            return;
        }
        match kind {
            0 => self.syn.fetch_add(count, Ordering::Relaxed),
            1 => self.icmp.fetch_add(count, Ordering::Relaxed),
            _ => self.udp.fetch_add(count, Ordering::Relaxed),
        };
    }

    /// #7086: the alarm-arm sibling of [`Self::add`]. Separate fields, so a
    /// zone that is alarming and permitting can never be read as dropping.
    #[inline]
    fn add_alarm(&self, kind: usize, count: u64) {
        if count == 0 {
            return;
        }
        match kind {
            0 => self.syn_alarms.fetch_add(count, Ordering::Relaxed),
            1 => self.icmp_alarms.fetch_add(count, Ordering::Relaxed),
            _ => self.udp_alarms.fetch_add(count, Ordering::Relaxed),
        };
    }

    /// #7086: alarm-arm counterpart of [`Self::load`], same relaxed contract.
    #[cfg(test)]
    fn load_alarms(&self) -> (u64, u64, u64) {
        (
            self.syn_alarms.load(Ordering::Relaxed),
            self.icmp_alarms.load(Ordering::Relaxed),
            self.udp_alarms.load(Ordering::Relaxed),
        )
    }

    /// Independent relaxed loads. Each field is exact; the triple is
    /// eventual-consistent (a snapshot may straddle one in-flight fold), the
    /// same contract `ZoneTotalsAtomic::load` accepts.
    fn load(&self) -> (u64, u64, u64) {
        (
            self.syn.load(Ordering::Relaxed),
            self.icmp.load(Ordering::Relaxed),
            self.udp.load(Ordering::Relaxed),
        )
    }

    /// Zero all three fields in place (operator clear). In place — never dropped
    /// from the store map — so a live slot map's cached `Arc` keeps counting
    /// from zero instead of folding into an orphaned block.
    fn reset(&self) {
        self.syn.store(0, Ordering::Relaxed);
        self.icmp.store(0, Ordering::Relaxed);
        self.udp.store(0, Ordering::Relaxed);
        // #7086: the operator clear is one action over the whole per-zone
        // flood block. Zeroing only the drop triple would leave a cleared
        // zone reporting pre-clear alarm totals.
        self.syn_alarms.store(0, Ordering::Relaxed);
        self.icmp_alarms.store(0, Ordering::Relaxed);
        self.udp_alarms.store(0, Ordering::Relaxed);
    }
}

/// Coordinator-owned, config-apply-surviving cumulative per-zone flood-event
/// store, keyed by the stable zone id. The mutex guards only the MAP STRUCTURE
/// (get-or-create at config apply, iterate at snapshot/clear/reconcile) — all
/// off the hot path. `Clone` shares the inner `Arc<Mutex>`, so cloning
/// `ForwardingState` keeps every generation pointing at the same totals.
#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct FloodCounterStore {
    totals: Arc<Mutex<FxHashMap<u16, Arc<FloodTotalsAtomic>>>>,
}

impl FloodCounterStore {
    /// Get-or-create the shared atomic block for a stable zone id, under the map
    /// mutex. Config-apply path only; NOT the hot path.
    fn zone_totals(&self, zone_id: u16) -> Arc<FloodTotalsAtomic> {
        let mut totals = self.totals.lock().expect("flood counter store poisoned");
        Arc::clone(totals.entry(zone_id).or_default())
    }

    /// Sparse snapshot for the status wire: one row per zone with any flood
    /// events. Deterministic order (sorted by zone id) for a stable wire.
    ///
    /// ## #7086: still DROPS-only, deliberately
    ///
    /// The alarm triple is NOT part of this predicate and is not on the wire
    /// yet. Widening the predicate to emit a row for an alarm-only zone,
    /// without also teaching the Go render about alarms, would strictly
    /// WORSEN the surface: `Manager.ReadFloodCounters` returns
    /// `ErrCounterNotPopulated` only when the offset map has no row, so a row
    /// of zeroed drop counts renders "SYN flood events: 0" on a zone that is
    /// actively alarming — a confident wrong answer replacing an honest
    /// "not available".
    ///
    /// That is not hypothetical for some zones and safe for others:
    /// `alarm-without-drop` is a per-ZONE profile flag, so an alarming zone
    /// has zero drops BY CONSTRUCTION and is exactly the row this predicate
    /// omits. Predicate and render must therefore change together, in the
    /// follow-up that gives the flood surface the same cause-naming treatment
    /// #7907 gave the zone half.
    pub(in crate::afxdp) fn snapshot(&self) -> Vec<ZoneFloodCounterStatus> {
        let totals = self.totals.lock().expect("flood counter store poisoned");
        let mut out: Vec<ZoneFloodCounterStatus> = totals
            .iter()
            .filter_map(|(&zone_id, t)| {
                let (syn_flood_events, icmp_flood_events, udp_flood_events) = t.load();
                if syn_flood_events == 0 && icmp_flood_events == 0 && udp_flood_events == 0 {
                    return None;
                }
                Some(ZoneFloodCounterStatus {
                    zone_id,
                    syn_flood_events,
                    icmp_flood_events,
                    udp_flood_events,
                })
            })
            .collect();
        out.sort_unstable_by_key(|s| s.zone_id);
        out
    }

    /// Operator clear (`clear_flood_counters` IPC): zero every zone's cumulative
    /// counts so the pre-clear value is not snapped back on the next status
    /// poll. Load-bearing half of the operator clear.
    ///
    /// A cleared zone then reads as NOT POPULATED, not as zero — the snapshot
    /// above omits all-zero rows and the Go side REPLACES its offset map from
    /// that snapshot, so the row is dropped rather than set to 0.
    ///
    /// Resets each block IN PLACE rather than clearing the map, because a live
    /// slot map caches each zone's `Arc`; dropping the map entry would leave
    /// workers folding into an orphaned block the snapshot no longer sees.
    pub(in crate::afxdp) fn clear(&self) {
        let totals = self.totals.lock().expect("flood counter store poisoned");
        for block in totals.values() {
            block.reset();
        }
    }

    /// Drop totals for zones that are no longer configured (config apply
    /// hygiene). A `configured` zone's `Arc` is retained, so a slot map rebuilt
    /// in the same apply resolves the SAME block (no reset/double).
    pub(in crate::afxdp) fn reconcile(&self, configured: &FxHashSet<u16>) {
        self.totals
            .lock()
            .expect("flood counter store poisoned")
            .retain(|zone_id, _| configured.contains(zone_id));
    }

    /// Fold a worker's coalesced per-slot deltas into the shared per-zone
    /// atomics the slot map cached at build time. LOCK-FREE — a straight
    /// `Relaxed` `fetch_add` per touched slot; it does NOT lock `self.totals`.
    fn fold_pending(&self, pending: &FloodPending, slot_map: &FloodCounterSlotMap) {
        // #6946: walk the touched bits rather than all 64 slots. Slot 0 is
        // the unassigned sentinel and is never recorded into.
        let mut mask = pending.touched_slots;
        while mask != 0 {
            let slot = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            let Some(totals) = &slot_map.slot_totals[slot] else {
                continue;
            };
            for (kind, counts) in pending.counts.iter().enumerate() {
                totals.add(kind, counts[slot]);
            }
            for (kind, alarms) in pending.alarms.iter().enumerate() {
                totals.add_alarm(kind, alarms[slot]);
            }
        }
    }

    /// #7086 test-only read of a zone's ALARM triple. Deliberately not on
    /// `snapshot`: see the note there for why the wire stays drops-only until
    /// the surface can render the alarming-and-permitting state.
    #[cfg(test)]
    pub(in crate::afxdp) fn alarm_zones_for_test(&self) -> Vec<(u16, (u64, u64, u64))> {
        let totals = self.totals.lock().expect("flood counter store poisoned");
        let mut out: Vec<(u16, (u64, u64, u64))> = totals
            .iter()
            .map(|(&zone_id, t)| (zone_id, t.load_alarms()))
            .filter(|(_, (s, i, u))| *s != 0 || *i != 0 || *u != 0)
            .collect();
        out.sort_unstable_by_key(|(zone_id, _)| *zone_id);
        out
    }

    /// Test-only handle to the map mutex, so a test can hold the shared store
    /// lock (as the ≤ 1 s snapshot/clear path does) and prove the per-batch fold
    /// still makes progress — the lock-freedom invariant.
    #[cfg(test)]
    fn lock_totals_for_test(
        &self,
    ) -> std::sync::MutexGuard<'_, FxHashMap<u16, Arc<FloodTotalsAtomic>>> {
        self.totals.lock().expect("flood counter store poisoned")
    }
}

/// Per-worker thread-local dense slot accumulator. Touched only by the owning
/// worker thread on the drop path; folded into the shared store per RX batch.
struct FloodPending {
    counts: [[u64; FLOOD_COUNTER_SLOTS]; FLOOD_KINDS],
    /// #7086: alarm-arm deltas, same slot/kind indexing as `counts`. Shares
    /// `touched_slots` with it — a slot is touched if EITHER arm recorded,
    /// so the fold and the reset stay one walk over one bitmask.
    alarms: [[u64; FLOOD_COUNTER_SLOTS]; FLOOD_KINDS],
    /// #6946: one bit per touched slot, replacing a single `touched: bool`.
    /// See the ZonePending field of the same name; the flood case matters
    /// more because this accumulator is fed from the screen DROP path, so it
    /// is hot on every worker at once during precisely the flood the counter
    /// exists to measure.
    touched_slots: u64,
}

impl Default for FloodPending {
    fn default() -> Self {
        Self {
            counts: [[0; FLOOD_COUNTER_SLOTS]; FLOOD_KINDS],
            alarms: [[0; FLOOD_COUNTER_SLOTS]; FLOOD_KINDS],
            touched_slots: 0,
        }
    }
}

impl FloodPending {
    fn reset(&mut self) {
        // #6946: clear only the slots that moved, across every kind.
        let mut mask = self.touched_slots;
        while mask != 0 {
            let slot = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            for counts in self.counts.iter_mut() {
                counts[slot] = 0;
            }
            // #7086: a touched slot may carry an alarm delta, a drop delta or
            // both. Clearing only `counts` would re-fold stale alarm deltas
            // into the next batch.
            for alarms in self.alarms.iter_mut() {
                alarms[slot] = 0;
            }
        }
        self.touched_slots = 0;
    }
}

thread_local! {
    static FLOOD_PENDING: RefCell<FloodPending> = RefCell::new(FloodPending::default());
}

/// Record one screen DROP against its ingress zone, when `reason` is one of the
/// three flood checks. Called from `BatchCounters::record_screen_drop`, so every
/// screen drop site feeds this without the site having to know about it — the
/// same centralization that keeps the aggregate and per-reason tallies from
/// drifting.
///
/// A non-flood reason, an unzoned packet, or a zone with no slot contributes
/// nothing. Cost on a flood drop: one flat-LUT read plus a thread-local
/// accumulate — no hash, no atomic, no allocation.
#[inline]
pub(in crate::afxdp) fn record_zone_flood_drop(
    slot_map: &FloodCounterSlotMap,
    zone_id: u16,
    reason: &str,
) {
    let Some(kind) = flood_reason_index(reason) else {
        return;
    };
    let slot = slot_map.slot_of(zone_id);
    if slot == 0 {
        return;
    }
    FLOOD_PENDING.with(|pending| {
        let mut p = pending.borrow_mut();
        let s = slot as usize;
        p.counts[kind][s] = p.counts[kind][s].saturating_add(1);
        p.touched_slots |= 1u64 << s;
    });
}

/// #7086: record one flood check that TRIPPED but was suppressed by the zone's
/// `alarm-without-drop` profile — a log-only alarm was raised and the packet
/// was PERMITTED and forwarded.
///
/// ## Why this is a separate tally and not a call into `record_zone_flood_drop`
///
/// Feeding the alarm arm into the drop counter would make a counter whose
/// name, module doc and call-site contract all say DROP report packets that
/// were forwarded. An operator reading "N flood drops" on a zone where nothing
/// was dropped is worse off than one reading "not available". So the alarm arm
/// gets its own triple, and the surface can distinguish three states: dropping
/// / alarming-and-permitting / nothing recorded.
///
/// ## Why it is batched, like the drop path and more so
///
/// `alarm-without-drop` is a per-ZONE profile flag (`ScreenProfile`), so a zone
/// in alarm mode suppresses EVERY flood drop it would otherwise take. Under a
/// volumetric flood this path therefore runs per packet on every worker at
/// once, with no drop to thin the traffic out — strictly hotter than the drop
/// path this mirrors, and exactly the MESI ping-pong against the coordinator's
/// status reads that #1187 documents. Hence the same flat-LUT lookup plus
/// thread-local accumulate, folded once per RX batch: no hash, no atomic, no
/// allocation on the packet path.
///
/// A non-flood reason, an unzoned packet, or a zone with no slot contributes
/// nothing, identically to the drop recorder.
#[inline]
pub(in crate::afxdp) fn record_zone_flood_alarm(
    slot_map: &FloodCounterSlotMap,
    zone_id: u16,
    reason: &str,
) {
    let Some(kind) = flood_reason_index(reason) else {
        return;
    };
    let slot = slot_map.slot_of(zone_id);
    if slot == 0 {
        return;
    }
    FLOOD_PENDING.with(|pending| {
        let mut p = pending.borrow_mut();
        let s = slot as usize;
        p.alarms[kind][s] = p.alarms[kind][s].saturating_add(1);
        p.touched_slots |= 1u64 << s;
    });
}

/// Fold this worker thread's coalesced per-zone flood deltas into the shared
/// store. Called once per RX batch alongside `flush_recorded_zone_counters`.
/// `slot_map` must be the SAME map the intervening `record_zone_flood_drop`
/// calls used (guaranteed: both read the loop iteration's `forwarding`
/// snapshot), so each slot's cached atomic block matches the zone it
/// accumulated for.
pub(in crate::afxdp) fn flush_recorded_flood_counters(
    store: &FloodCounterStore,
    slot_map: &FloodCounterSlotMap,
) {
    FLOOD_PENDING.with(|pending| {
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
    //! ## Why there is no serialization guard here, and why none is needed
    //!
    //! These tests assert EXACT counter values, which is normally a #6819-class
    //! flake risk (concurrent tests mutating a shared counter). It is not one
    //! here, and the reason is worth recording so nobody adds a mutex that
    //! protects nothing — or, worse, deletes a test because they assume it is
    //! flaky.
    //!
    //! There is no process-global counter in this module. [`FloodCounterStore`]
    //! is an ordinary value; every test builds its own with
    //! `FloodCounterStore::default()`, so no two tests can reach the same
    //! totals. The only state that LOOKS shared is the [`FLOOD_PENDING`]
    //! thread-local accumulator.
    //!
    //! That one is per-test in practice: libtest runs each test on its own
    //! thread even under `--test-threads=1` (the `make test-rust` invocation),
    //! so each test gets a fresh `FLOOD_PENDING`. Verified directly rather than
    //! assumed — a probe pair in which the first test deliberately recorded
    //! WITHOUT flushing and the second flushed into a fresh store observed
    //! distinct thread ids and ZERO leaked rows.
    //!
    //! Two consequences. Residue cannot cross a test boundary, so a test that
    //! records without flushing cannot corrupt a neighbour. And a
    //! `record`/`flush` pair must still be matched WITHIN a test against the
    //! SAME slot map — the accumulator is slot-indexed, so flushing pending
    //! deltas through a DIFFERENT map mis-attributes them to whatever zone now
    //! owns that slot.

    use super::*;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    /// The three flood reason strings must be exactly the ones the screen
    /// module emits. `flood_reason_index` is an independent match (it indexes a
    /// different, 3-wide accumulator), so nothing else stops a rename in
    /// `screen/mod.rs` from silently un-wiring the per-zone tally: the drop
    /// would still be counted in the aggregate and this map would just stop
    /// matching.
    #[test]
    fn flood_reason_index_tracks_the_screen_reason_strings() {
        for reason in ["syn-flood", "icmp-flood", "udp-flood"] {
            // Assert the reason is a KNOWN SCREEN REASON, not that the two
            // ordinals coincide. The contract this test exists to protect is
            // the STRING: a rename in `screen/mod.rs` would silently stop the
            // per-zone tally matching while the aggregate kept counting.
            //
            // Deliberately NOT `assert_eq!(flood_reason_index(r),
            // screen_reason_drop_index(r))`. They agree on 0/1/2 today, but the
            // screen ordinals index a 15-wide Go-facing array and this indexes a
            // 3-wide accumulator whose layout is the wire's syn/icmp/udp triple
            // (see the `flood_reason_index` doc). Pinning equality would make a
            // legitimate renumber of the screen ordinals red HERE, inviting
            // someone to "fix" it by renumbering `flood_reason_index` — which
            // would silently permute the flood wire fields.
            assert!(
                flood_reason_index(reason).is_some(),
                "flood reason {reason:?} must have a per-zone flood ordinal"
            );
            assert!(
                crate::screen::screen_reason_drop_index(reason).is_some(),
                "flood reason {reason:?} is no longer a known screen reason — a \
                 rename in screen/mod.rs has un-wired the per-zone flood tally \
                 while leaving the aggregate counting"
            );
        }
        // Every other screen reason must be excluded — the per-zone flood
        // surface renders exactly three counters.
        for reason in [
            "port-scan",
            "ip-sweep",
            "land-attack",
            "ping-of-death",
            "teardrop",
            "tcp-syn-fin",
            "tcp-no-flag",
            "tcp-fin-no-ack",
            "winnuke",
            "ip-source-route",
            "syn-frag",
            "session-limit-src",
            "session-limit-dst",
            "syn-cookie",
            "strict-syn-check",
            "icmp-fragment",
        ] {
            assert_eq!(
                flood_reason_index(reason),
                None,
                "{reason:?} is not a flood check and must not feed the per-zone \
                 flood counters"
            );
        }
    }

    #[test]
    fn build_assigns_slots_for_wide_stable_hash_zone_ids() {
        // #3075 stable name-hash ids span [1, 65533]; a dense id-indexed table
        // would drop these.
        let store = FloodCounterStore::default();
        let map = FloodCounterSlotMap::build(&[40000, 7, 65533], &store);
        assert!(!map.overflow_active);
        assert_eq!(map.slot_of(7), 1);
        assert_eq!(map.slot_of(40000), 2);
        assert_eq!(map.slot_of(65533), 3);
        assert_eq!(map.slot_of(0), 0);
        assert_eq!(map.slot_of(123), 0);
    }

    #[test]
    fn build_sets_overflow_past_capacity() {
        let store = FloodCounterStore::default();
        let ids: Vec<u16> = (1..=(FLOOD_COUNTER_ASSIGNABLE_SLOTS as u16 + 5)).collect();
        let map = FloodCounterSlotMap::build(&ids, &store);
        assert!(map.overflow_active);
        let assigned = (1..=65535u16).filter(|&z| map.slot_of(z) != 0).count();
        assert_eq!(assigned, FLOOD_COUNTER_ASSIGNABLE_SLOTS);
    }

    /// The traffic and flood slot maps must agree zone-for-zone. Equal capacity
    /// plus the same sorted assignment order is what makes that true; this pins
    /// the observable consequence rather than the constants.
    #[test]
    fn flood_and_traffic_slot_maps_cover_the_same_zones() {
        use crate::afxdp::zone_counters::{ZoneCounterSlotMap, ZoneCounterStore};
        let ids: Vec<u16> = (1..=(FLOOD_COUNTER_ASSIGNABLE_SLOTS as u16 + 3))
            .map(|z| z.wrapping_mul(37).max(1))
            .collect();
        let flood = FloodCounterSlotMap::build(&ids, &FloodCounterStore::default());
        let traffic = ZoneCounterSlotMap::build(&ids, &ZoneCounterStore::default());
        assert_eq!(flood.overflow_active, traffic.overflow_active);
        for &z in &ids {
            assert_eq!(
                flood.slot_of(z) != 0,
                traffic.slot_of(z) != 0,
                "zone {z} is slotted for one counter family but not the other — \
                 an operator would see live volume with 'not available' flood \
                 counts (or the reverse) and nothing explaining the asymmetry"
            );
        }
    }

    #[test]
    fn record_flush_snapshot_accumulates_each_flood_family() {
        let store = FloodCounterStore::default();
        let map = FloodCounterSlotMap::build(&[100, 200], &store);
        record_zone_flood_drop(&map, 100, "syn-flood");
        record_zone_flood_drop(&map, 100, "syn-flood");
        record_zone_flood_drop(&map, 100, "icmp-flood");
        record_zone_flood_drop(&map, 200, "udp-flood");
        flush_recorded_flood_counters(&store, &map);

        let snap = store.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].zone_id, 100);
        assert_eq!(snap[0].syn_flood_events, 2);
        assert_eq!(snap[0].icmp_flood_events, 1);
        assert_eq!(snap[0].udp_flood_events, 0);
        assert_eq!(snap[1].zone_id, 200);
        assert_eq!(snap[1].syn_flood_events, 0);
        assert_eq!(snap[1].udp_flood_events, 1);
    }

    #[test]
    fn non_flood_reasons_and_unslotted_zones_are_uncounted() {
        let store = FloodCounterStore::default();
        let map = FloodCounterSlotMap::build(&[100], &store);
        // A real screen drop, but not a FLOOD check.
        record_zone_flood_drop(&map, 100, "port-scan");
        // A flood check on an unconfigured zone, and on the unzoned id 0.
        record_zone_flood_drop(&map, 999, "syn-flood");
        record_zone_flood_drop(&map, 0, "syn-flood");
        flush_recorded_flood_counters(&store, &map);
        assert!(
            store.snapshot().is_empty(),
            "non-flood reasons and unslotted zones must contribute nothing: {:?}",
            store.snapshot()
        );
    }

    #[test]
    fn clear_resets_totals_and_keeps_counting() {
        let store = FloodCounterStore::default();
        let map = FloodCounterSlotMap::build(&[100], &store);
        record_zone_flood_drop(&map, 100, "syn-flood");
        flush_recorded_flood_counters(&store, &map);
        assert_eq!(store.snapshot().len(), 1);
        store.clear();
        assert!(store.snapshot().is_empty());
        // The clear resets the atomics IN PLACE (keeps the map entry), so the
        // live slot map's cached Arc keeps counting from zero after the clear.
        record_zone_flood_drop(&map, 100, "syn-flood");
        flush_recorded_flood_counters(&store, &map);
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].syn_flood_events, 1);
    }

    #[test]
    fn reconcile_drops_removed_zones() {
        let store = FloodCounterStore::default();
        let map = FloodCounterSlotMap::build(&[100, 200], &store);
        record_zone_flood_drop(&map, 100, "syn-flood");
        record_zone_flood_drop(&map, 200, "udp-flood");
        flush_recorded_flood_counters(&store, &map);
        assert_eq!(store.snapshot().len(), 2);
        let keep: FxHashSet<u16> = [100u16].into_iter().collect();
        store.reconcile(&keep);
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].zone_id, 100);
    }

    #[test]
    fn surviving_zone_keeps_the_same_atomic_block_across_a_slot_renumber() {
        let store = FloodCounterStore::default();
        let map1 = FloodCounterSlotMap::build(&[200], &store);
        assert_eq!(map1.slot_of(200), 1);
        record_zone_flood_drop(&map1, 200, "syn-flood");
        flush_recorded_flood_counters(&store, &map1);
        // Config apply adds zone 100 (< 200), which takes slot 1 and pushes 200
        // to slot 2 — a renumber. Store carried forward (same instance here).
        let map2 = FloodCounterSlotMap::build(&[100, 200], &store);
        assert_eq!(map2.slot_of(200), 2);
        record_zone_flood_drop(&map2, 200, "syn-flood");
        flush_recorded_flood_counters(&store, &map2);
        let snap = store.snapshot();
        let z200 = snap.iter().find(|s| s.zone_id == 200).expect("zone 200");
        // 2 events total across the renumber — not reset to 1, not doubled.
        assert_eq!(z200.syn_flood_events, 2);
    }

    /// A zone that WAS counted and is then pushed past the hot-path slot
    /// capacity by a later config must STOP being published. Its retained
    /// counts survive in the carried-forward store, so publishing them would
    /// mirror a total that can never advance again.
    #[test]
    fn populated_zone_stops_publishing_once_pushed_past_capacity() {
        let store = FloodCounterStore::default();
        const Z: u16 = 50675; // config::StableZoneID("trust")
        let map1 = FloodCounterSlotMap::build(&[Z], &store);
        assert_ne!(map1.slot_of(Z), 0);
        record_zone_flood_drop(&map1, Z, "syn-flood");
        record_zone_flood_drop(&map1, Z, "syn-flood");
        flush_recorded_flood_counters(&store, &map1);
        let published = publishable_flood_rows(&store, &map1, |_| true);
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].syn_flood_events, 2);

        // Apply 2: enough LOWER ids to consume every assignable slot.
        let mut ids: Vec<u16> = (1..=(FLOOD_COUNTER_ASSIGNABLE_SLOTS as u16)).collect();
        ids.push(Z);
        let configured: FxHashSet<u16> = ids.iter().copied().collect();
        store.reconcile(&configured);
        let map2 = FloodCounterSlotMap::build(&ids, &store);
        assert!(map2.overflow_active);
        assert_eq!(map2.slot_of(Z), 0);

        // The retained counts are still in the store — asserting this keeps the
        // test honest: it is NOT passing because the data vanished.
        let raw: Vec<_> = store
            .snapshot()
            .into_iter()
            .filter(|s| s.zone_id == Z)
            .collect();
        assert_eq!(raw.len(), 1);
        assert_eq!(raw[0].syn_flood_events, 2);

        let published = publishable_flood_rows(&store, &map2, |zid| configured.contains(&zid));
        assert!(
            !published.iter().any(|s| s.zone_id == Z),
            "a populated zone that lost its slot must STOP publishing — otherwise \
             its retained flood count freezes and under-reports forever: {published:?}"
        );
    }

    /// The publish filter must not over-reach: a zone that still holds a slot
    /// keeps publishing while a SIBLING overflows, and the configured predicate
    /// is independently load-bearing.
    #[test]
    fn publish_filter_drops_only_the_unslotted_and_unconfigured() {
        let store = FloodCounterStore::default();
        let mut ids: Vec<u16> = (1..=(FLOOD_COUNTER_ASSIGNABLE_SLOTS as u16)).collect();
        const OVERFLOWED: u16 = 65533;
        ids.push(OVERFLOWED);
        let map = FloodCounterSlotMap::build(&ids, &store);
        assert!(map.overflow_active);
        assert_eq!(map.slot_of(OVERFLOWED), 0);

        record_zone_flood_drop(&map, 1, "syn-flood");
        record_zone_flood_drop(&map, 2, "icmp-flood");
        flush_recorded_flood_counters(&store, &map);
        // Give the overflowed zone retained counts directly in the store, as a
        // carried-forward apply would, so it is a real publish candidate.
        let seed = FloodCounterSlotMap::build(&[OVERFLOWED], &store);
        record_zone_flood_drop(&seed, OVERFLOWED, "udp-flood");
        flush_recorded_flood_counters(&store, &seed);

        // Zone 2 has a slot AND traffic but is NOT configured.
        let configured: FxHashSet<u16> = [1u16, OVERFLOWED].into_iter().collect();
        let published = publishable_flood_rows(&store, &map, |z| configured.contains(&z));
        assert!(
            published.iter().any(|s| s.zone_id == 1),
            "a slotted, configured zone must keep publishing during overflow: {published:?}"
        );
        assert!(
            !published.iter().any(|s| s.zone_id == OVERFLOWED),
            "a configured zone with retained counts but NO slot must be dropped: {published:?}"
        );
        assert!(
            !published.iter().any(|s| s.zone_id == 2),
            "zone 2 holds a slot and has counts but is NOT configured, so the \
             configured predicate must still drop it: {published:?}"
        );
    }

    #[test]
    fn concurrent_workers_fold_lock_free_without_lost_counts() {
        const WORKERS: u64 = 8;
        const PER_WORKER: u64 = 20_000;
        let store = FloodCounterStore::default();
        let map = Arc::new(FloodCounterSlotMap::build(&[100], &store));

        let mut handles = Vec::new();
        for _ in 0..WORKERS {
            let map = Arc::clone(&map);
            let store = store.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..PER_WORKER {
                    record_zone_flood_drop(&map, 100, "syn-flood");
                    flush_recorded_flood_counters(&store, &map);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let snap = store.snapshot();
        let z100 = snap.iter().find(|s| s.zone_id == 100).expect("zone 100");
        assert_eq!(z100.syn_flood_events, WORKERS * PER_WORKER);
    }

    #[test]
    fn worker_fold_makes_progress_while_status_reader_holds_the_lock() {
        let store = FloodCounterStore::default();
        let map = FloodCounterSlotMap::build(&[100], &store);

        // A second thread parks on the shared store mutex for 300 ms — standing
        // in for the ≤ 1 s status/clear path holding it under contention.
        let held = store.clone();
        let (locked_tx, locked_rx) = mpsc::channel();
        let holder = thread::spawn(move || {
            let guard = held.lock_totals_for_test();
            locked_tx.send(()).unwrap();
            thread::sleep(Duration::from_millis(300));
            drop(guard);
        });
        locked_rx.recv().unwrap();

        let start = Instant::now();
        record_zone_flood_drop(&map, 100, "syn-flood");
        flush_recorded_flood_counters(&store, &map);
        let elapsed = start.elapsed();

        holder.join().unwrap();
        assert!(
            elapsed < Duration::from_millis(150),
            "per-batch worker fold blocked on the shared store lock for {elapsed:?} \
             — the fold must be lock-free. A per-batch global-mutex fold would \
             block until the status reader released the lock (~300 ms)."
        );
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].syn_flood_events, 1);
    }

    // ---------------- #7086: the alarm arm ----------------

    /// The operator clear is one action over a zone's whole flood block. If
    /// `FloodTotalsAtomic::reset` zeroes only the drop triple, a cleared zone
    /// keeps reporting pre-clear alarm totals for ever — the counters never
    /// decay on their own.
    #[test]
    fn clear_zeroes_the_alarm_triple_too_7086() {
        const Z: u16 = 4242;
        let store = FloodCounterStore::default();
        let map = FloodCounterSlotMap::build(&[Z], &store);

        record_zone_flood_alarm(&map, Z, "udp-flood");
        record_zone_flood_alarm(&map, Z, "syn-flood");
        flush_recorded_flood_counters(&store, &map);
        assert_eq!(
            store.alarm_zones_for_test(),
            vec![(Z, (1, 0, 1))],
            "precondition: the alarms must be there to be cleared"
        );

        store.clear();
        assert!(
            store.alarm_zones_for_test().is_empty(),
            "clear must zero the ALARM triple as well as the drop triple"
        );
    }

    /// `FloodPending::reset` clears the per-slot deltas of every TOUCHED slot.
    /// A slot can be touched by either arm, so a reset that clears only
    /// `counts` leaves the alarm delta in place and the NEXT batch folds it a
    /// second time.
    ///
    /// The shape matters: the second batch records a DROP on the same slot, so
    /// the slot is touched and folded again. A test that simply flushed twice
    /// would return early on `touched_slots == 0` and never re-fold — passing
    /// against the broken reset.
    #[test]
    fn a_flushed_alarm_delta_is_not_refolded_by_the_next_batch_7086() {
        const Z: u16 = 909;
        let store = FloodCounterStore::default();
        let map = FloodCounterSlotMap::build(&[Z], &store);

        record_zone_flood_alarm(&map, Z, "icmp-flood");
        flush_recorded_flood_counters(&store, &map);
        assert_eq!(store.alarm_zones_for_test(), vec![(Z, (0, 1, 0))]);

        // Second batch: a DROP on the same slot, so the slot is touched and
        // the fold walks it again.
        record_zone_flood_drop(&map, Z, "icmp-flood");
        flush_recorded_flood_counters(&store, &map);

        assert_eq!(
            store.alarm_zones_for_test(),
            vec![(Z, (0, 1, 0))],
            "the alarm delta was already folded in the first batch; folding it \
             again would double-count every alarm on any zone that later takes \
             a drop in the same slot"
        );
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(
            snap[0].icmp_flood_events, 1,
            "the second batch's drop must land exactly once"
        );
    }

    /// The alarm arm must apply the same reason filter as the drop arm: a
    /// non-flood screen reason is a real alarm but not a FLOOD alarm, and
    /// folding it into one of the three families would make "UDP flood alarms"
    /// silently include port scans.
    #[test]
    fn a_non_flood_reason_contributes_no_zone_alarm_7086() {
        const Z: u16 = 77;
        let store = FloodCounterStore::default();
        let map = FloodCounterSlotMap::build(&[Z], &store);

        record_zone_flood_alarm(&map, Z, "port-scan");
        record_zone_flood_alarm(&map, Z, "teardrop");
        record_zone_flood_alarm(&map, Z, "syn-cookie");
        flush_recorded_flood_counters(&store, &map);

        assert!(
            store.alarm_zones_for_test().is_empty(),
            "only the three flood families may enter the per-zone alarm tally"
        );
    }

    /// An unzoned packet or a zone with no hot-path slot contributes nothing,
    /// identically to the drop recorder — the `slot == 0` sentinel guard.
    #[test]
    fn an_unslotted_zone_contributes_no_alarm_7086() {
        const MAPPED: u16 = 11;
        const UNMAPPED: u16 = 12;
        let store = FloodCounterStore::default();
        let map = FloodCounterSlotMap::build(&[MAPPED], &store);

        record_zone_flood_alarm(&map, UNMAPPED, "syn-flood");
        flush_recorded_flood_counters(&store, &map);
        assert!(
            store.alarm_zones_for_test().is_empty(),
            "a zone with no slot must not attribute its alarms to slot 0"
        );

        // Positive control: the SAME call on a mapped zone does record, so the
        // emptiness above is the slot guard and not a broken fixture.
        record_zone_flood_alarm(&map, MAPPED, "syn-flood");
        flush_recorded_flood_counters(&store, &map);
        assert_eq!(store.alarm_zones_for_test(), vec![(MAPPED, (1, 0, 0))]);
    }
}
