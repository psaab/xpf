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
//! Coalesced per RX batch (not direct `fetch_add`) for the #1187 MESI
//! reason the traffic half documents. The slot map, store, pending
//! accumulator and fold are the shared
//! [`crate::afxdp::zone_slot_counters`] machine (#17204), built ONCE per
//! apply and shared with the traffic family; this module keeps only the
//! flood block/delta types, the `record_*` functions and the wire mapping.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::afxdp::zone_counters::ZoneTotalsAtomic;
use crate::afxdp::zone_slot_counters::{
    SlotBlock, SlotDelta, ZoneSlotCaches, ZoneSlotMap, ZoneSlotPending, ZoneSlotStore,
};
use crate::protocol::ZoneFloodCounterStatus;

/// Wire/layout version stamped into `ProcessStatus.flood_counter_layout_version`
/// (#3651). #14619: stamped UNCONDITIONALLY, like the traffic twin;
/// 0/absent = helper with no per-zone flood accounting.
pub(in crate::afxdp) const FLOOD_COUNTER_LAYOUT_VERSION: u32 = 1;

/// Flood ordinal (syn/icmp/udp) for a screen reason, or `None`. Deliberately
/// independent of `screen_reason_drop_index` (different width/layout); the
/// reason STRINGS are pinned shared by
/// `flood_reason_index_tracks_the_screen_reason_strings`.
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

/// Shared cumulative per-zone flood-event totals as three `Relaxed` atomics.
/// One block per configured zone id; the per-batch worker fold `fetch_add`s into
/// it lock-free and the ≤ 1 s status/clear path reads/zeroes it under the store
/// mutex.
#[derive(Debug)]
pub(in crate::afxdp) struct FloodTotalsAtomic {
    drops: [AtomicU64; FLOOD_KINDS],
    /// #7086: the ALARM arm — a flood check tripped, `alarm-without-drop`
    /// suppressed the drop, the packet was PERMITTED. Separate from `drops`:
    /// a DROP-named counter must never report permitted packets.
    alarms: [AtomicU64; FLOOD_KINDS],
}

impl Default for FloodTotalsAtomic {
    fn default() -> Self {
        Self {
            drops: std::array::from_fn(|_| AtomicU64::new(0)),
            alarms: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl FloodTotalsAtomic {
    #[inline]
    fn add(&self, kind: usize, count: u64) {
        if count != 0 {
            self.drops[kind].fetch_add(count, Ordering::Relaxed);
        }
    }

    #[inline]
    fn add_alarm(&self, kind: usize, count: u64) {
        if count != 0 {
            self.alarms[kind].fetch_add(count, Ordering::Relaxed);
        }
    }

    #[cfg(test)]
    fn load_alarms(&self) -> (u64, u64, u64) {
        (
            self.alarms[0].load(Ordering::Relaxed),
            self.alarms[1].load(Ordering::Relaxed),
            self.alarms[2].load(Ordering::Relaxed),
        )
    }

    fn load(&self) -> (u64, u64, u64) {
        (
            self.drops[0].load(Ordering::Relaxed),
            self.drops[1].load(Ordering::Relaxed),
            self.drops[2].load(Ordering::Relaxed),
        )
    }
}

impl SlotBlock for FloodTotalsAtomic {
    type Delta = FloodDelta;

    fn fold_delta(&self, delta: &FloodDelta) {
        for (kind, counts) in delta.counts.iter().enumerate() {
            self.add(kind, *counts);
        }
        for (kind, alarms) in delta.alarms.iter().enumerate() {
            self.add_alarm(kind, *alarms);
        }
    }

    /// Zero all three fields in place (operator clear). In place — never dropped
    /// from the store map — so a live slot map's cached `Arc` keeps counting
    /// from zero instead of folding into an orphaned block.
    fn reset(&self) {
        // #7086: clear BOTH triples — zeroing only drops would leave a
        // cleared zone reporting pre-clear alarm totals.
        for a in self.drops.iter().chain(self.alarms.iter()) {
            a.store(0, Ordering::Relaxed);
        }
    }

    /// DROPS-only, deliberately (#7086): the alarm triple is not on the
    /// wire yet; an alarm-only zone has zero drops by construction, so
    /// emitting a zeroed drop row would render a confident wrong answer.
    /// Predicate and render must change together in the follow-up.
    fn is_zero(&self) -> bool {
        let (syn, icmp, udp) = self.load();
        syn == 0 && icmp == 0 && udp == 0
    }
}

/// One slot's flood delta: drop + #7086 alarm triples. One touched bit
/// covers either arm; the single shared mask-walk reset clears both.
#[derive(Clone, Copy, Debug, Default)]
pub(in crate::afxdp) struct FloodDelta {
    counts: [u64; FLOOD_KINDS],
    alarms: [u64; FLOOD_KINDS],
}

impl SlotDelta for FloodDelta {
    fn is_zero(&self) -> bool {
        self.counts
            .iter()
            .chain(self.alarms.iter())
            .all(|&v| v == 0)
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Rows publishable on `ProcessStatus.zone_flood_counters` (configured
/// AND slotted; see [`crate::afxdp::zone_slot_counters::publishable_rows`]).
pub(in crate::afxdp) fn publishable_flood_rows(
    store: &FloodCounterStore,
    slot_map: &ZoneSlotMap,
    is_configured: impl Fn(u32) -> bool,
) -> Vec<ZoneFloodCounterStatus> {
    crate::afxdp::zone_slot_counters::publishable_rows(
        store,
        slot_map,
        is_configured,
        |zone_id, t| {
            let (syn_flood_events, icmp_flood_events, udp_flood_events) = t.load();
            ZoneFloodCounterStatus {
                zone_id,
                syn_flood_events,
                icmp_flood_events,
                udp_flood_events,
            }
        },
    )
}

/// Coordinator-owned, config-apply-surviving cumulative per-zone flood-event
/// store, keyed by the stable zone id. See
/// [`crate::afxdp::zone_slot_counters::ZoneSlotStore`] for the lock contract;
/// the per-batch fold never locks it.
pub(in crate::afxdp) type FloodCounterStore = ZoneSlotStore<FloodTotalsAtomic>;

/// The shared slot map's per-family block caches (family 1 = traffic,
/// family 2 = flood).
pub(in crate::afxdp) type FloodCounterCaches = ZoneSlotCaches<ZoneTotalsAtomic, FloodTotalsAtomic>;

/// Sparse wire-row snapshot of the flood store (drops only, #7086).
pub(in crate::afxdp) fn flood_counter_snapshot(
    store: &FloodCounterStore,
) -> Vec<ZoneFloodCounterStatus> {
    store.snapshot(|zone_id, t| {
        let (syn_flood_events, icmp_flood_events, udp_flood_events) = t.load();
        ZoneFloodCounterStatus {
            zone_id,
            syn_flood_events,
            icmp_flood_events,
            udp_flood_events,
        }
    })
}

/// Test-only: every zone with a non-zero ALARM triple.
#[cfg(test)]
pub(in crate::afxdp) fn flood_alarm_zones_for_test(
    store: &FloodCounterStore,
) -> Vec<(u32, (u64, u64, u64))> {
    let mut out: Vec<(u32, (u64, u64, u64))> = Vec::new();
    // Alarm-only zones are drop-zero and thus absent from the sparse
    // snapshot; probe via tracked ids.
    for zone_id in store.tracked_zone_ids_for_test() {
        if let Some(triple) = store.block_for_test(zone_id, |t| t.load_alarms()) {
            if triple != (0, 0, 0) {
                out.push((zone_id, triple));
            }
        }
    }
    out
}

thread_local! {
    static FLOOD_PENDING: RefCell<ZoneSlotPending<FloodDelta>> =
        RefCell::new(ZoneSlotPending::default());
}

/// Record one screen DROP against its ingress zone (flood reasons only).
/// Called from `BatchCounters::record_screen_drop`. One LUT read +
/// thread-local accumulate; no hash/atomic/allocation.
#[inline]
pub(in crate::afxdp) fn record_zone_flood_drop(slot_map: &ZoneSlotMap, zone_id: u32, reason: &str) {
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
        p.deltas[s].counts[kind] = p.deltas[s].counts[kind].saturating_add(1);
        p.touched_slots |= 1u64 << s;
    });
}

/// #7086: record one flood check TRIPPED but suppressed by
/// `alarm-without-drop` (log-only alarm, packet PERMITTED). Separate tally
/// from drops: a DROP-named counter must not report forwarded packets.
/// Batched like the drop arm (per-zone alarm mode runs per packet under
/// flood, #1187). Non-flood/unslotted contributes nothing.
#[inline]
pub(in crate::afxdp) fn record_zone_flood_alarm(
    slot_map: &ZoneSlotMap,
    zone_id: u32,
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
        p.deltas[s].alarms[kind] = p.deltas[s].alarms[kind].saturating_add(1);
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
    _slot_map: &ZoneSlotMap,
    caches: &FloodCounterCaches,
) {
    FLOOD_PENDING.with(|pending| {
        let mut p = pending.borrow_mut();
        if p.touched_slots == 0 {
            return;
        }
        store.fold_pending(&p, caches, |c, slot| c.totals2(slot));
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
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    // #17204: the shared slot-machine fixture (see zone_counters tests).
    use crate::afxdp::zone_counters::ZoneCounterStore;
    use crate::afxdp::zone_slot_counters::ZoneSlotMap;
    use rustc_hash::FxHashSet;

    fn build_map(
        zone_ids: &[u32],
        store: &FloodCounterStore,
        traffic_store: &ZoneCounterStore,
    ) -> (ZoneSlotMap, FloodCounterCaches) {
        ZoneSlotMap::build(zone_ids, traffic_store, store)
    }

    fn flush(store: &FloodCounterStore, map: &ZoneSlotMap, caches: &FloodCounterCaches) {
        flush_recorded_flood_counters(store, map, caches);
    }

    fn snap(store: &FloodCounterStore) -> Vec<ZoneFloodCounterStatus> {
        store.snapshot(|zone_id, t| {
            let (syn_flood_events, icmp_flood_events, udp_flood_events) = t.load();
            ZoneFloodCounterStatus {
                zone_id,
                syn_flood_events,
                icmp_flood_events,
                udp_flood_events,
            }
        })
    }

    fn alarm_zones(store: &FloodCounterStore) -> Vec<(u32, (u64, u64, u64))> {
        store
            .snapshot_blocks()
            .into_iter()
            .map(|(zone_id, t)| (zone_id, t.load_alarms()))
            .filter(|(_, (s, i, u))| *s != 0 || *i != 0 || *u != 0)
            .collect()
    }

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
        let traffic_store = ZoneCounterStore::default();
        let (map, _caches) = build_map(&[40000, 7, 65533], &store, &traffic_store);
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
        let ids: Vec<u32> =
            (1..=(crate::afxdp::zone_slot_counters::ZONE_SLOT_ASSIGNABLE_SLOTS as u32 + 5))
                .collect();
        let traffic_store = ZoneCounterStore::default();
        let (map, _caches) = build_map(&ids, &store, &traffic_store);
        assert!(map.overflow_active);
        let assigned = (1..=65535u32).filter(|&z| map.slot_of(z) != 0).count();
        assert_eq!(
            assigned,
            crate::afxdp::zone_slot_counters::ZONE_SLOT_ASSIGNABLE_SLOTS
        );
    }

    #[test]
    fn record_flush_snapshot_accumulates_each_flood_family() {
        let store = FloodCounterStore::default();
        let traffic_store = ZoneCounterStore::default();
        let (map, caches) = build_map(&[100, 200], &store, &traffic_store);
        record_zone_flood_drop(&map, 100, "syn-flood");
        record_zone_flood_drop(&map, 100, "syn-flood");
        record_zone_flood_drop(&map, 100, "icmp-flood");
        record_zone_flood_drop(&map, 200, "udp-flood");
        flush(&store, &map, &caches);

        let snap = snap(&store);
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
        let traffic_store = ZoneCounterStore::default();
        let (map, caches) = build_map(&[100], &store, &traffic_store);
        // A real screen drop, but not a FLOOD check.
        record_zone_flood_drop(&map, 100, "port-scan");
        // A flood check on an unconfigured zone, and on the unzoned id 0.
        record_zone_flood_drop(&map, 999, "syn-flood");
        record_zone_flood_drop(&map, 0, "syn-flood");
        flush(&store, &map, &caches);
        assert!(
            snap(&store).is_empty(),
            "non-flood reasons and unslotted zones must contribute nothing: {:?}",
            snap(&store)
        );
    }

    #[test]
    fn clear_resets_totals_and_keeps_counting() {
        let store = FloodCounterStore::default();
        let traffic_store = ZoneCounterStore::default();
        let (map, caches) = build_map(&[100], &store, &traffic_store);
        record_zone_flood_drop(&map, 100, "syn-flood");
        flush(&store, &map, &caches);
        assert_eq!(snap(&store).len(), 1);
        store.clear();
        assert!(snap(&store).is_empty());
        // The clear resets the atomics IN PLACE (keeps the map entry), so the
        // live slot map's cached Arc keeps counting from zero after the clear.
        record_zone_flood_drop(&map, 100, "syn-flood");
        flush(&store, &map, &caches);
        let snap = snap(&store);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].syn_flood_events, 1);
    }

    #[test]
    fn reconcile_drops_removed_zones() {
        let store = FloodCounterStore::default();
        let traffic_store = ZoneCounterStore::default();
        let (map, caches) = build_map(&[100, 200], &store, &traffic_store);
        record_zone_flood_drop(&map, 100, "syn-flood");
        record_zone_flood_drop(&map, 200, "udp-flood");
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
        let store = FloodCounterStore::default();
        let traffic_store = ZoneCounterStore::default();
        let (map1, caches1) = build_map(&[200], &store, &traffic_store);
        assert_eq!(map1.slot_of(200), 1);
        record_zone_flood_drop(&map1, 200, "syn-flood");
        flush(&store, &map1, &caches1);
        // Config apply adds zone 100 (< 200), which takes slot 1 and pushes 200
        // to slot 2 — a renumber. Store carried forward (same instance here).
        let traffic_store = ZoneCounterStore::default();
        let (map2, caches2) = build_map(&[100, 200], &store, &traffic_store);
        assert_eq!(map2.slot_of(200), 2);
        record_zone_flood_drop(&map2, 200, "syn-flood");
        flush(&store, &map2, &caches2);
        let snap = snap(&store);
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
        const Z: u32 = 50675; // config::StableZoneID("trust")
        let traffic_store = ZoneCounterStore::default();
        let (map1, caches1) = build_map(&[Z], &store, &traffic_store);
        assert_ne!(map1.slot_of(Z), 0);
        record_zone_flood_drop(&map1, Z, "syn-flood");
        record_zone_flood_drop(&map1, Z, "syn-flood");
        flush(&store, &map1, &caches1);
        let published = publishable_flood_rows(&store, &map1, |_| true);
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].syn_flood_events, 2);

        // Apply 2: enough LOWER ids to consume every assignable slot.
        let mut ids: Vec<u32> =
            (1..=(crate::afxdp::zone_slot_counters::ZONE_SLOT_ASSIGNABLE_SLOTS as u32)).collect();
        ids.push(Z);
        let configured: FxHashSet<u32> = ids.iter().copied().collect();
        store.reconcile(&configured);
        let traffic_store = ZoneCounterStore::default();
        let (map2, _caches2) = build_map(&ids, &store, &traffic_store);
        assert!(map2.overflow_active);
        assert_eq!(map2.slot_of(Z), 0);

        // The retained counts are still in the store — asserting this keeps the
        // test honest: it is NOT passing because the data vanished.
        let raw: Vec<_> = snap(&store)
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
        let mut ids: Vec<u32> =
            (1..=(crate::afxdp::zone_slot_counters::ZONE_SLOT_ASSIGNABLE_SLOTS as u32)).collect();
        const OVERFLOWED: u32 = 65533;
        ids.push(OVERFLOWED);
        let traffic_store = ZoneCounterStore::default();
        let (map, caches) = build_map(&ids, &store, &traffic_store);
        assert!(map.overflow_active);
        assert_eq!(map.slot_of(OVERFLOWED), 0);

        record_zone_flood_drop(&map, 1, "syn-flood");
        record_zone_flood_drop(&map, 2, "icmp-flood");
        flush(&store, &map, &caches);
        // Give the overflowed zone retained counts directly in the store, as a
        // carried-forward apply would, so it is a real publish candidate.
        let traffic_store = ZoneCounterStore::default();
        let (seed, seed_caches) = build_map(&[OVERFLOWED], &store, &traffic_store);
        record_zone_flood_drop(&seed, OVERFLOWED, "udp-flood");
        flush(&store, &seed, &seed_caches);

        // Zone 2 has a slot AND traffic but is NOT configured.
        let configured: FxHashSet<u32> = [1u32, OVERFLOWED].into_iter().collect();
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
        let traffic_store = ZoneCounterStore::default();
        let (map_inner, caches_inner) = build_map(&[100], &store, &traffic_store);
        let map = Arc::new(map_inner);
        let caches = Arc::new(caches_inner);

        let mut handles = Vec::new();
        for _ in 0..WORKERS {
            let map = Arc::clone(&map);
            let caches = Arc::clone(&caches);
            let store = store.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..PER_WORKER {
                    record_zone_flood_drop(&map, 100, "syn-flood");
                    flush(&store, &map, &caches);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let snap = snap(&store);
        let z100 = snap.iter().find(|s| s.zone_id == 100).expect("zone 100");
        assert_eq!(z100.syn_flood_events, WORKERS * PER_WORKER);
    }

    #[test]
    fn worker_fold_makes_progress_while_status_reader_holds_the_lock() {
        let store = FloodCounterStore::default();
        let traffic_store = ZoneCounterStore::default();
        let (map, caches) = build_map(&[100], &store, &traffic_store);

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
        flush(&store, &map, &caches);
        let elapsed = start.elapsed();

        holder.join().unwrap();
        assert!(
            elapsed < Duration::from_millis(150),
            "per-batch worker fold blocked on the shared store lock for {elapsed:?} \
             — the fold must be lock-free. A per-batch global-mutex fold would \
             block until the status reader released the lock (~300 ms)."
        );
        let snap = snap(&store);
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
        const Z: u32 = 4242;
        let store = FloodCounterStore::default();
        let traffic_store = ZoneCounterStore::default();
        let (map, caches) = build_map(&[Z], &store, &traffic_store);

        record_zone_flood_alarm(&map, Z, "udp-flood");
        record_zone_flood_alarm(&map, Z, "syn-flood");
        flush(&store, &map, &caches);
        assert_eq!(
            flood_alarm_zones_for_test(&store),
            vec![(Z, (1, 0, 1))],
            "precondition: the alarms must be there to be cleared"
        );

        store.clear();
        assert!(
            flood_alarm_zones_for_test(&store).is_empty(),
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
        const Z: u32 = 909;
        let store = FloodCounterStore::default();
        let traffic_store = ZoneCounterStore::default();
        let (map, caches) = build_map(&[Z], &store, &traffic_store);

        record_zone_flood_alarm(&map, Z, "icmp-flood");
        flush(&store, &map, &caches);
        assert_eq!(flood_alarm_zones_for_test(&store), vec![(Z, (0, 1, 0))]);

        // Second batch: a DROP on the same slot, so the slot is touched and
        // the fold walks it again.
        record_zone_flood_drop(&map, Z, "icmp-flood");
        flush(&store, &map, &caches);

        assert_eq!(
            flood_alarm_zones_for_test(&store),
            vec![(Z, (0, 1, 0))],
            "the alarm delta was already folded in the first batch; folding it \
             again would double-count every alarm on any zone that later takes \
             a drop in the same slot"
        );
        let snap = snap(&store);
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
        const Z: u32 = 77;
        let store = FloodCounterStore::default();
        let traffic_store = ZoneCounterStore::default();
        let (map, caches) = build_map(&[Z], &store, &traffic_store);

        record_zone_flood_alarm(&map, Z, "port-scan");
        record_zone_flood_alarm(&map, Z, "teardrop");
        record_zone_flood_alarm(&map, Z, "syn-cookie");
        flush(&store, &map, &caches);

        assert!(
            flood_alarm_zones_for_test(&store).is_empty(),
            "only the three flood families may enter the per-zone alarm tally"
        );
    }

    /// An unzoned packet or a zone with no hot-path slot contributes nothing,
    /// identically to the drop recorder — the `slot == 0` sentinel guard.
    #[test]
    fn an_unslotted_zone_contributes_no_alarm_7086() {
        const MAPPED: u32 = 11;
        const UNMAPPED: u32 = 12;
        let store = FloodCounterStore::default();
        let traffic_store = ZoneCounterStore::default();
        let (map, caches) = build_map(&[MAPPED], &store, &traffic_store);

        record_zone_flood_alarm(&map, UNMAPPED, "syn-flood");
        flush(&store, &map, &caches);
        assert!(
            flood_alarm_zones_for_test(&store).is_empty(),
            "a zone with no slot must not attribute its alarms to slot 0"
        );

        // Positive control: the SAME call on a mapped zone does record, so the
        // emptiness above is the slot guard and not a broken fixture.
        record_zone_flood_alarm(&map, MAPPED, "syn-flood");
        flush(&store, &map, &caches);
        assert_eq!(
            flood_alarm_zones_for_test(&store),
            vec![(MAPPED, (1, 0, 0))]
        );
    }
}
