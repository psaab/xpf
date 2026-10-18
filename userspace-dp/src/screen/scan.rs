//! Port-scan + IP-sweep windowed trackers used by the advanced screen
//! checks. Each tracks a per-`(zone_id, source-IP)` unique-set over a
//! configurable per-zone MICROSECOND detection window (the Junos
//! `threshold` value); detection fires when the distinct-destination count
//! reaches the FIXED Junos `SCAN_DETECT_COUNT` (10) within that window
//! (#4114). Before #4114 xpf had these swapped — a configurable COUNT over a
//! hard-coded 10-second window — so a copied Junos `threshold 5000` (meant as
//! 5000 microseconds) was misread as a count and clamped to never-fire, while
//! the default-armed sweep false-dropped normal browsing.
//!
//! #2209 — per-zone + bounded:
//!
//! - **Per-zone keying.** Junos screen thresholds are read from the
//!   per-zone screen profile, so the scan/sweep history MUST be keyed by
//!   `(zone_id, src_ip)`. A single global per-src tracker (the pre-#2209
//!   shape) bled one zone's scan activity into another zone's threshold
//!   evaluation — a `wan`-side scan could trip (or mask) the `dmz`
//!   threshold for one `dmz` packet from the same source.
//!
//! - **Bounded, fail-safe state.** The backing maps are attacker-driven
//!   (a spoofed-source flood multiplies the source keys; a fan-out flood
//!   multiplies the inner unique entries). Both axes are capped:
//!   `MAX_SOURCES_PER_ZONE` distinct source keys per zone and
//!   `MAX_UNIQUE_PER_SOURCE` unique entries per source. On the UNIQUE-entry
//!   axis the set is capped, but the detection threshold is CLAMPED to
//!   `MAX_UNIQUE_PER_SOURCE - 1` so a source that fills the set ALWAYS
//!   crosses it: a threshold larger than the cap detects AT THE CAP rather
//!   than never (fail-CLOSED, #2227 MAJOR-1). The maps never grow without
//!   bound. This mirrors the #2134/#2177 session-limit per-IP bound
//!   discipline (skip-on-full, never a phantom growth) plus a fail-closed
//!   clamp on the inner axis.
//!
//! - **Bounded per-zone eviction on source-axis saturation (#2234, #4890,
//!   #14673).**
//!   The per-zone source cap was originally a HARD cliff: once a zone held
//!   `MAX_SOURCES_PER_ZONE` keys a brand-new `(zone, src_ip)` was SKIPPED
//!   (bumping `skipped_pressure`). That is fail-safe for forwarding but a
//!   DETECTION-DoS: a high-cardinality spoofed flood fills the table and a
//!   subsequently-arriving REAL scanner is never tracked — and so never
//!   detected — until the detection window expires, which the attacker can defer
//!   indefinitely by keeping its 4096 sources fresh. The new-source path now
//!   makes BOUNDED room instead of skipping: it samples at most
//!   `EVICT_SCAN_LIMIT` SAME-ZONE sources, reclaims the first expired
//!   same-zone window it finds, and if none is expired evicts a live
//!   same-zone entry within that sample (originally the stalest
//!   `window_start`; #4418 changed the live-victim choice to the
//!   least-suspicious entry — see below).
//!
//!   Since this branch only runs when the target zone alone holds
//!   `>= MAX_SOURCES_PER_ZONE` keys (>> `EVICT_SCAN_LIMIT`), a same-zone
//!   victim is found and a fresh real scanner is admissible under
//!   saturation. The pre-#4890 search sampled a FIXED GLOBAL PREFIX of
//!   `per_src` (`iter().take(EVICT_SCAN_LIMIT)`, budget counting EVERY
//!   iterated entry, same-zone or not); in a many-zone table whose first
//!   `EVICT_SCAN_LIMIT` global positions held no target-zone entry, eviction
//!   found no victim and skipped the fresh scanner (the #4890 fail-open of
//!   DETECTION; forwarding was never fail-open).
//!
//!   #14673: the sample itself must ROTATE. The #4890 sample was a static
//!   `per_zone_srcs[zone].iter().take(EVICT_SCAN_LIMIT)` prefix — the same
//!   64 buckets of an unseeded `FxHashSet` (deterministic, attacker-
//!   computable bucket order) on every eviction. An attacker who pinned 63
//!   prefix entries at `SCAN_DETECT_COUNT - 1` and kept its scanner at
//!   count 8 inside the prefix made the scanner the deterministic
//!   lowest-count victim; one decoy packet wiped its history and its next
//!   probe re-seeded it at count 1, so it never reached the detection
//!   count. The sample now walks the dense `key_ring` from a persistent
//!   `evict_cursor` offset by a per-boot secret (`seed`, #2364 pattern),
//!   counting only SAME-ZONE slots toward `EVICT_SCAN_LIMIT` and advancing
//!   past the examined span, so successive evictions rotate across the
//!   whole zone and the start is unpredictable off-box.
//!
//!   The per-new-flow worst case stays bounded: at most
//!   `EVICT_SCAN_LIMIT + 8 * EVICT_SCAN_LIMIT` ring slots per eviction,
//!   NOT an O(sources) min-scan (a full scan on every new flow under a
//!   saturation flood would itself be an O(n)-per-packet amplifier). The
//!   per-zone source count is served by `per_zone_srcs` (`.len()` is the
//!   O(1) cap test); the victim walk is served by `key_ring`. Each eviction
//!   bumps `evicted_pressure`, and a rare logarithmic threshold crossing
//!   surfaces a `scan-table-pressure` screen event (see
//!   `take_pressure_event`) so the operator is told the detector is
//!   saturated — never a per-flow log.
//!
//! - **Bounded-EXAMINATION, window-aware cleanup (#4353/#4379/#6239).** The
//!   periodic sweep EXAMINES at most `CLEANUP_BUDGET` candidates per call and
//!   removes only those found expired — the per-call cost is O(`CLEANUP_BUDGET`)
//!   regardless of the table size. #6239 replaced the pre-existing
//!   `HashMap::retain` walk, which WALKED every entry (O(sources)) and budgeted
//!   only the REMOVALS: once the removal budget was spent, `retain` still
//!   visited every remaining bucket on ONE packet worker — an attacker who
//!   populated sources across many zones re-created the exact per-packet
//!   full-table-scan latency spike #2209 forbade. The bounded form keeps a
//!   dense `key_ring` of live source keys and a PERSISTENT round-robin
//!   `cleanup_cursor`: each call examines the next `CLEANUP_BUDGET` ring slots
//!   and advances, so every source is eventually visited across calls WITHOUT
//!   any single call walking the whole table. Removal is an O(1) swap-remove of
//!   the ring slot routed — like eviction — through the SINGLE `remove_src`
//!   primitive, which drops the key from `per_src`, `per_zone_srcs`, AND the
//!   `key_ring` in lock-step (a removal touching only one index would corrupt
//!   the O(1) zone cap count or the cursor domain). Table size is still
//!   independently bounded by the `MAX_SOURCES_PER_ZONE` per-zone source cap;
//!   the cursor just spreads reclamation across ticks. The reap
//!   floor is WINDOW-AWARE: #4353 made the `threshold` a configurable
//!   MICROSECOND detection window that the compiler PRESERVES even above the
//!   Junos 1s max, so cleanup is passed the LONGEST configured window across
//!   the live profiles (clamped to `MAX_CLEANUP_WINDOW_MICROS`) as its floor.
//!   A fixed 1s floor (the pre-#4379 shape) reaped an accumulating
//!   distinct-destination set before the detection count was reached for any
//!   operator window > 1s, so a slow scan spread across the configured window
//!   EVADED detection (fail-open); the window-aware floor retains state for
//!   the full configured window. #4418 raised the `MAX_CLEANUP_WINDOW_MICROS`
//!   ceiling to the u32 `threshold` type maximum (~71.6 min) so the clamp can
//!   NEVER bite a configurable window — the pre-#4418 5-min ceiling reopened
//!   the same evasion for any window > 5 min. Memory stays bounded by the
//!   per-source/zone caps regardless (the ceiling is a reclamation-timing
//!   bound, never a memory bound).
//!
//! - **Least-suspicious source-saturation eviction (#4418).** When a zone is
//!   at `MAX_SOURCES_PER_ZONE` and a brand-new source arrives, the bounded
//!   eviction (below) now displaces the LEAST-suspicious live same-zone entry
//!   — the one with the FEWEST accumulated distinct destinations — rather than
//!   the one with the oldest `window_start`. A near-threshold slow scanner
//!   (high count, old-but-live window) is therefore NOT evicted by a flood of
//!   fresh decoy sources (each at count 1) WITHIN ONE SAMPLE; the decoys are
//!   reclaimed first. The pre-#4418 stalest-by-`window_start` policy let an
//!   attacker evict a near-threshold slow scanner by keeping the table full of
//!   fresher decoys, reopening the evasion on the source-saturation axis. Ties
//!   on count fall back to the stalest `window_start` so old low-count churn
//!   is still reclaimed (#2234). #14673 note: least-suspicious WITHIN a static
//!   sample was itself exploitable (the scanner IS the lowest-count entry of
//!   a pinned prefix), so the sample rotates (above) — the victim is the
//!   least-suspicious entry of a ROTATING seeded window, not of a fixed
//!   attacker-chosen set.

use rustc_hash::{FxHashMap, FxHashSet};
use std::net::IpAddr;

/// Maximum distinct source IPs tracked per zone. A `/24` legitimate scan
/// touches <=254 sources; this cap absorbs that with headroom while
/// putting a hard ceiling on attacker-controlled growth. When the cap is
/// reached, a *new* source key for that zone is skipped (not recorded),
/// degrading to no-count for that source — never a fail-open drop.
const MAX_SOURCES_PER_ZONE: usize = 4096;

/// Maximum unique entries (dst ports for port-scan, dst IPs for IP-sweep)
/// tracked per source within the window. This caps memory for a source
/// whose unique fan-out is large; the bounded set can hold at most
/// `MAX_UNIQUE_PER_SOURCE` entries.
///
/// This is purely a MEMORY bound. Detection fires at the fixed
/// [`SCAN_DETECT_COUNT`] (10), which is far below this cap, so the verdict is
/// never gated by it. #4114 removed the pre-existing configurable-COUNT
/// semantics (and its `MAX_UNIQUE_PER_SOURCE - 1` fail-closed clamp): the
/// detection count is now a fixed Junos constant well under this cap, and the
/// configurable `threshold` is the detection WINDOW in microseconds instead.
const MAX_UNIQUE_PER_SOURCE: usize = 1024;

/// Maximum candidates a single `cleanup` call EXAMINES — and therefore the
/// most it can remove — per tick (#6239). Bounds the worst-case per-tick
/// cleanup cost to O(`CLEANUP_BUDGET`) so a large source table cannot stall a
/// single packet worker. Pre-#6239 this bounded only the REMOVALS while the
/// `HashMap::retain` walk still examined every entry (O(sources)); the cursor
/// sweep now bounds the EXAMINED work too, and eventual coverage of the whole
/// table is preserved by advancing a persistent cursor across calls.
const CLEANUP_BUDGET: usize = 256;

/// Hard upper bound on the number of SAME-ZONE sources examined while looking
/// for an eviction victim on the source-saturation path
/// (#2234/#4890/#14673). The new-flow worst case is bounded, NOT O(sources):
/// a full min-scan over all `MAX_SOURCES_PER_ZONE` entries on every new flow
/// under a saturation flood would itself be an O(n)-per-packet DoS amplifier.
/// We instead sample `EVICT_SCAN_LIMIT` same-zone candidates from a ROVING,
/// per-boot-seeded window over the dense `key_ring` (#14673), counting only
/// same-zone slots toward the limit and capping the total walk at
/// `EVICT_SCAN_LIMIT + 8 * EVICT_SCAN_LIMIT` ring slots. Since this path only
/// runs when the zone is at `>= MAX_SOURCES_PER_ZONE` (>> `EVICT_SCAN_LIMIT`),
/// a victim is found under saturation. The pre-#4890 code sampled a fixed
/// GLOBAL prefix of `per_src`; the #4890 code sampled a fixed PER-ZONE prefix
/// of `per_zone_srcs[zone]` — both static, the latter deterministic in
/// `FxHashSet` bucket order and exploitable per #14673.
const EVICT_SCAN_LIMIT: usize = 64;

/// Fixed Junos scan/sweep detection COUNT (#4114). A source that touches this
/// many DISTINCT destinations (ports for port-scan, IPs for ip-sweep) within
/// the configurable per-zone detection window is flagged. Junos hard-codes
/// this at 10 and makes only the WINDOW configurable (the `threshold` value,
/// in microseconds); the pre-#4114 xpf shape had it backwards (configurable
/// count over a fixed 10-second window).
///
/// SSOT: mirrors the Go `scanSweepDetectCount` in
/// `pkg/config/compiler_security_screen.go`. The two MUST stay in sync.
pub(super) const SCAN_DETECT_COUNT: usize = 10;

/// Defensive UPPER BOUND (microseconds) on the window-aware cleanup reap floor
/// (#4379/#4418). The periodic, zone-agnostic [`ScanCore::cleanup`] is passed
/// the LONGEST configured detection window across the live screen profiles as
/// its reap floor (so a legitimate slow-scan window is not reaped early — the
/// #4379 evasion). This ceiling only clamps a floor that EXCEEDS the largest
/// value a configured `threshold` can express.
///
/// #4418: the ceiling is the u32 `threshold` type's maximum (~71.6 min), so it
/// NEVER clamps a value an operator can actually configure. The pre-#4418
/// ceiling was 5 minutes, which reaped an accumulating distinct-destination set
/// at 300s for any configured window > 5 min BEFORE that window elapsed — the
/// slow-scan evasion reopened for that pathological band (a >5min window is far
/// outside the Junos [1000, 1000000] us range and already draws a commit-time
/// advisory from `validateScreenScanSweepWindows`, but the dataplane must not
/// silently reopen the evasion for a value the operator was merely WARNED
/// about, not rejected). Raising the ceiling to the type maximum closes the
/// evasion for EVERY configurable window while keeping the floor provably
/// bounded (defence against a future where the reap floor could exceed the u32
/// range — e.g. a wider threshold type).
///
/// Why raising the ceiling is safe: this is a RECLAMATION-TIMING bound ONLY,
/// never a memory bound. The per-source / per-zone caps
/// ([`MAX_UNIQUE_PER_SOURCE`] / [`MAX_SOURCES_PER_ZONE`]) are enforced by
/// [`ScanCore::check`] at INSERT time, so the table is bounded regardless of
/// the window — a longer floor only defers reclamation of idle entries, it
/// cannot grow the ceiling. The 71-min worst case is bounded by the SAME
/// 4096-source / 1024-entry caps as a 5-min or 5-second window. The exact
/// per-zone `window_micros` still governs the inline reset/verdict in
/// [`ScanCore::check`] and the eviction path.
const MAX_CLEANUP_WINDOW_MICROS: u64 = u32::MAX as u64;

/// Compile-time guard: the eviction sample must be smaller than the per-zone
/// source cap, otherwise the "sample a bounded prefix of the zone's index"
/// bound would be meaningless (it could scan the whole zone). It must also be
/// non-empty so the new-source path can always find a victim once the zone is
/// saturated (`per_zone_srcs[zone].len() >= MAX_SOURCES_PER_ZONE`).
const _: () = assert!(EVICT_SCAN_LIMIT > 0 && EVICT_SCAN_LIMIT < MAX_SOURCES_PER_ZONE);

/// Compile-time guard: the fixed detection count must sit strictly below the
/// per-source memory cap so a scanning source can always reach it before the
/// bounded set saturates (otherwise detection could never fire) (#4114).
const _: () = assert!(SCAN_DETECT_COUNT > 0 && SCAN_DETECT_COUNT < MAX_UNIQUE_PER_SOURCE);

/// Test-only accessor for the per-zone source cap, used by the
/// `ScreenState`-level bounded-state test in `screen/tests.rs`.
#[cfg(test)]
pub(super) fn max_sources_per_zone_for_test() -> usize {
    MAX_SOURCES_PER_ZONE
}

/// Test-only accessor for the bounded eviction sample limit (#2234), used by
/// the bounded-cost eviction test in `screen/tests.rs`.
#[cfg(test)]
pub(super) fn evict_scan_limit_for_test() -> usize {
    EVICT_SCAN_LIMIT
}

/// Per-zone scan/sweep tracker key: `(zone_id, src_ip)`.
type ScanKey = (u16, IpAddr);

/// Per-source tracker record held in `per_src`. Carries the window state plus
/// the source key's dense position in `key_ring` (`slot`) so the #6239 cursor
/// cleanup can swap-remove an expired source in O(1) without an O(sources)
/// search. `slot` is an internal back-pointer maintained in lock-step by
/// [`ScanCore::insert_src`] / [`ScanCore::remove_src`]; nothing outside those
/// primitives may mutate it.
#[derive(Debug, Clone)]
struct SrcEntry<T> {
    /// Window open time (monotonic microseconds). The distinct-entry set is
    /// cleared and this is reset once the configured window elapses.
    window_start: u64,
    /// Distinct destinations (dst ports for port-scan, dst IPs for IP-sweep)
    /// seen within the current window; bounded to `MAX_UNIQUE_PER_SOURCE`.
    entries: FxHashSet<T>,
    /// This key's position in `key_ring` — the O(1) swap-remove index.
    slot: usize,
}

/// Shared bounded windowed-unique tracker core (#2209/#2227/#2234). Both
/// the port-scan (`T = u16`) and IP-sweep (`T = IpAddr`) trackers are thin
/// `T`-specialised wrappers over this single implementation so the bound /
/// eviction / pressure logic exists in exactly ONE place (engineering-style
/// "one source of truth" — the pre-#2234 free functions duplicated the
/// formula across the two trackers).
#[derive(Debug, Clone)]
struct ScanCore<T: std::hash::Hash + Eq> {
    per_src: FxHashMap<ScanKey, SrcEntry<T>>,
    /// Per-zone index of the distinct source IPs tracked in `per_src`
    /// (`zone_id -> {src_ip}`). The per-zone source count is
    /// `per_zone_srcs[zone].len()`, so the cap test is O(1) (#2234) — the
    /// pre-#2234 code walked every key to count one zone
    /// (`sources_in_zone`, O(sources)), which on the new-source-at-cap path
    /// under a saturation flood is O(n) per packet. Since #14673 the
    /// victim-search domain is `key_ring`, not this index (the static
    /// `FxHashSet` prefix was deterministic; see the module doc).
    ///
    /// Kept in lock-step with `per_src`: a key is added on insert and removed
    /// on eviction / cleanup. It is bounded by the same per-zone/source caps as
    /// `per_src` (at most `MAX_SOURCES_PER_ZONE` IPs per zone), so it adds no
    /// unbounded growth.
    per_zone_srcs: FxHashMap<u16, FxHashSet<IpAddr>>,
    /// Dense list of every live source key — the DOMAIN of the bounded #6239
    /// cleanup cursor and the #14673 eviction cursor. Each key's index is
    /// mirrored in `SrcEntry.slot`, so a removal is an O(1) swap-remove
    /// instead of an O(sources) search, and `key_ring.len() == per_src.len()`
    /// always. Bounded by the same per-zone/source caps as `per_src` (at most
    /// `MAX_SOURCES_PER_ZONE` keys per zone); after warmup it stops growing
    /// (worker-local, no steady-state alloc). Maintained ONLY by
    /// `insert_src` / `remove_src`.
    key_ring: Vec<ScanKey>,
    /// Persistent round-robin cursor into `key_ring` (#6239). Each `cleanup`
    /// call examines at most `CLEANUP_BUDGET` keys starting here and advances,
    /// so the whole table is eventually visited across calls WITHOUT any single
    /// call walking all of it. Survives across calls; wraps at the ring end and
    /// is re-clamped if the ring shrank since the last call.
    cleanup_cursor: usize,
    /// Persistent round-robin eviction cursor (#14673), stored in the
    /// UNSEEDED frame: the next eviction sample starts at
    /// `(evict_cursor + seed_offset) % ring_len`. Each eviction examines at
    /// most `EVICT_SCAN_LIMIT` SAME-ZONE candidates from that start and
    /// advances the cursor past the examined span (translated back into
    /// this frame), so successive evictions rotate contiguously across the
    /// whole zone instead of re-examining the same static `FxHashSet`
    /// prefix. The actual start is never stored directly — it is always
    /// derived with the per-boot `seed_offset` — so the start offset is
    /// unpredictable off-box and reshuffles on every restart while the
    /// cursor still guarantees eventual coverage within a boot.
    evict_cursor: usize,
    /// Per-boot secret (#14673, #2364 pattern): drawn once from
    /// `hot_hash_seed::hot_path_hash_seed()` at construction and mixed into
    /// the eviction walk start so the sampled window is unpredictable to an
    /// off-box attacker who knows the insertion history. Stable for the
    /// lifetime of the tracker, so the cursor still visits every slot over
    /// time. Test cores pin it via `with_seed`.
    seed: u64,
    /// Test-only log of the source keys examined by the most recent `cleanup`
    /// pass(es), used by the bounded-examination and eventual-coverage tests to
    /// observe exactly which ring slots the cursor visited. Not compiled into
    /// release builds — zero production cost.
    #[cfg(test)]
    examined_log: Vec<ScanKey>,
    /// Test-only log of the source keys examined by the most recent eviction
    /// sample (#14673), used to prove the sample rotates. Not compiled into
    /// release builds.
    #[cfg(test)]
    evict_examined_log: Vec<ScanKey>,
    /// Count of records skipped because a per-source unique-entry cap was
    /// hit, or because eviction could not free a same-zone slot within the
    /// bounded per-zone sample (rare). Pure observability — exposed for the
    /// bounded-state tests and the screen status surface. Never affects a
    /// verdict.
    skipped_pressure: u64,
    /// Count of stalest-eviction events on the source-saturation path
    /// (#2234): a brand-new source displaced an expired-or-stalest existing
    /// source so a fresh real scanner stays trackable. Pure observability.
    evicted_pressure: u64,
    /// Next `evicted_pressure` value at which a `scan-table-pressure` screen
    /// event should be surfaced. Grows geometrically (see
    /// [`ScanCore::take_pressure_event`]) so the operator alarm fires at a
    /// LOGARITHMIC rate — never per-flow — even under a sustained flood.
    pressure_event_at: u64,
}

impl<T: std::hash::Hash + Eq> Default for ScanCore<T> {
    fn default() -> Self {
        Self::with_seed(crate::hot_hash_seed::hot_path_hash_seed())
    }
}

impl<T: std::hash::Hash + Eq> ScanCore<T> {
    /// Seed-pinned constructor (#14673). Production goes through `Default`,
    /// which draws the per-boot secret; tests pin the seed to assert
    /// seed-dependent start offsets and cross-seed reshuffling.
    fn with_seed(seed: u64) -> Self {
        Self {
            per_src: FxHashMap::default(),
            per_zone_srcs: FxHashMap::default(),
            key_ring: Vec::new(),
            cleanup_cursor: 0,
            evict_cursor: 0,
            seed,
            #[cfg(test)]
            examined_log: Vec::new(),
            #[cfg(test)]
            evict_examined_log: Vec::new(),
            skipped_pressure: 0,
            evicted_pressure: 0,
            // First eviction surfaces an event; thereafter the bar doubles.
            pressure_event_at: 1,
        }
    }
}

impl<T: std::hash::Hash + Eq> ScanCore<T> {
    /// Bounded windowed-unique check (#4114 Junos semantics). `entry_val` is
    /// the per-(zone_id, src_ip) unique entry (dst port or dst IP). Detection
    /// fires when the distinct-entry count reaches the FIXED
    /// [`SCAN_DETECT_COUNT`] (10) within `window_micros` — the per-zone
    /// configurable Junos `threshold` expressed as a MICROSECOND TIME WINDOW.
    /// `now_micros` is a monotonic microsecond clock. A `window_micros` of 0
    /// means the check is disabled (the caller gates on `threshold > 0`, but
    /// this guards defensively too).
    ///
    /// Bounds (fail-safe, never fail-OPEN):
    /// - a brand-new source key for a zone already holding
    ///   `MAX_SOURCES_PER_ZONE` keys triggers a BOUNDED eviction
    ///   (#2234/#4418/#4890/#14673): the LEAST-suspicious (fewest distinct
    ///   destinations, or any expired) entry within a rotating seeded
    ///   `EVICT_SCAN_LIMIT`-sized same-zone sample of `key_ring` is removed
    ///   to admit the fresh source, so a real scanner is always
    ///   trackable AND a near-threshold slow scanner is not displaced by a
    ///   decoy flood within one sample; the skip-on-full fallback (bumps
    ///   `skipped_pressure`, returns `false`) remains only as a defensive
    ///   guard for a zone below the cap with no evictable entry (bounded).
    /// - a new unique entry for a source whose set already holds
    ///   `MAX_UNIQUE_PER_SOURCE` entries is SKIPPED, but the fixed detection
    ///   count is still evaluated against the current (capped) set size. The
    ///   count (10) sits well below the cap (1024), so the memory bound never
    ///   gates the verdict (#4114 removed the pre-existing configurable-count
    ///   fail-closed clamp — there is no operator count to exceed the cap).
    #[inline]
    fn check(
        &mut self,
        zone_id: u16,
        src_ip: IpAddr,
        entry_val: T,
        now_micros: u64,
        window_micros: u64,
    ) -> bool {
        if window_micros == 0 {
            return false;
        }
        let key: ScanKey = (zone_id, src_ip);
        let exists = self.per_src.contains_key(&key);
        // Per-zone source-count bound. A brand-new source for a zone at the
        // cap makes BOUNDED room by eviction (#2234) instead of the old
        // hard skip-on-full cliff. An existing key is always allowed through
        // (it is bounded on the inner axis below).
        if !exists && self.zone_count(zone_id) >= MAX_SOURCES_PER_ZONE {
            if !self.evict_stalest_in_zone(zone_id, now_micros, window_micros) {
                // No same-zone victim within the bounded sample (pathological
                // many-zone interleave). Preserve the fail-safe: skip, never
                // fail-open. Cost is still O(EVICT_SCAN_LIMIT).
                self.skipped_pressure += 1;
                return false;
            }
        }
        if !exists {
            // Brand-new source: wire it into `per_src`, the per-zone index, AND
            // the cleanup `key_ring` in lock-step (the sole insertion path).
            self.insert_src(key, now_micros);
        }
        let entry = self
            .per_src
            .get_mut(&key)
            .expect("entry inserted above or pre-existing");
        // Reset the window if the configured microsecond window has elapsed
        // since it opened.
        if now_micros.saturating_sub(entry.window_start) >= window_micros {
            entry.window_start = now_micros;
            entry.entries.clear();
        }
        // Per-source unique-entry bound: once the set is full, skip new
        // entries (counting pressure) but still evaluate the detection count.
        if entry.entries.len() >= MAX_UNIQUE_PER_SOURCE {
            if !entry.entries.contains(&entry_val) {
                self.skipped_pressure += 1;
            }
        } else {
            entry.entries.insert(entry_val);
        }
        // Junos verdict: fire once the source has touched SCAN_DETECT_COUNT
        // distinct destinations within the window.
        entry.entries.len() >= SCAN_DETECT_COUNT
    }

    /// Insert a brand-new source key, wiring `per_src`, the per-zone source
    /// index, AND the cleanup `key_ring` in lock-step. The key's `key_ring`
    /// position is stamped into `SrcEntry.slot` so [`ScanCore::remove_src`] can
    /// swap-remove it in O(1). This is the SOLE insertion path; callers MUST
    /// have confirmed the key is not already present.
    #[inline]
    fn insert_src(&mut self, key: ScanKey, now_micros: u64) {
        let slot = self.key_ring.len();
        self.key_ring.push(key);
        self.per_src.insert(
            key,
            SrcEntry {
                window_start: now_micros,
                entries: FxHashSet::default(),
                slot,
            },
        );
        self.per_zone_srcs.entry(key.0).or_default().insert(key.1);
    }

    /// The SINGLE source-removal primitive (#6239). Drops `key` from `per_src`,
    /// the per-zone source index, AND the dense `key_ring` in lock-step, so the
    /// three structures never drift — a removal that updated only one would
    /// corrupt either the O(1) per-zone cap count or the cursor domain. The
    /// ring drop is an O(1) `swap_remove`: the tail key is moved into the
    /// vacated slot and its `SrcEntry.slot` back-pointer is repaired so every
    /// entry's slot stays exact. Both eviction and cleanup route their removals
    /// through here. Returns `true` if the key was present and removed.
    #[inline]
    fn remove_src(&mut self, key: &ScanKey) -> bool {
        let Some(entry) = self.per_src.remove(key) else {
            return false;
        };
        let slot = entry.slot;
        let last = self.key_ring.len() - 1;
        self.key_ring.swap_remove(slot);
        // If the removed slot was not the tail, the former tail now sits at
        // `slot` — fix its back-pointer so `slot == key_ring index` holds.
        if slot != last {
            let moved = self.key_ring[slot];
            if let Some(m) = self.per_src.get_mut(&moved) {
                m.slot = slot;
            }
        }
        if let Some(s) = self.per_zone_srcs.get_mut(&key.0) {
            s.remove(&key.1);
        }
        true
    }

    /// O(1) per-zone source count — the size of the per-zone source index.
    #[inline]
    fn zone_count(&self, zone_id: u16) -> usize {
        self.per_zone_srcs.get(&zone_id).map_or(0, |s| s.len())
    }

    /// Evict one same-zone source so a fresh source can be admitted under
    /// source-axis saturation (#2234/#4890/#14673). Examines at most
    /// `EVICT_SCAN_LIMIT` SAME-ZONE candidates and removes the FIRST
    /// expired-or-empty same-zone entry it finds, or — failing that — the
    /// LEAST-SUSPICIOUS live same-zone entry within the sample.
    ///
    /// Victim selection among LIVE (non-expired, non-empty) candidates is by
    /// FEWEST accumulated distinct destinations (#4418), with the STALEST
    /// (oldest `window_start`) as the tiebreak on equal counts. A brand-new
    /// decoy source sits at count 1, while a slow scanner that has already
    /// probed several destinations sits near the detection count — so a flood
    /// of fresh decoys evicts one another (or the lowest-count live entry)
    /// and CANNOT displace a near-threshold slow scanner. The pre-#4418 policy
    /// evicted the stalest `window_start` regardless of count, which let an
    /// attacker keeping the table full of fresher decoys evict a slow scanner
    /// whose window opened earlier (its old-but-LIVE window made it "stalest")
    /// — reopening the slow-scan evasion on the source-saturation axis. The
    /// stalest tiebreak preserves #2234's reclamation of old low-count churn.
    ///
    /// #14673 sample: a ROVING cursor over the dense `key_ring`, not a static
    /// `per_zone_srcs[zone].iter().take(EVICT_SCAN_LIMIT)` prefix. The
    /// pre-#14673 prefix re-examined the same 64 `FxHashSet` buckets (bucket
    /// order of an unseeded hasher — deterministic and attacker-computable)
    /// on every eviction: an attacker who pinned 63 prefix entries at
    /// `SCAN_DETECT_COUNT - 1` and kept its scanner at count 8 inside the
    /// prefix made the scanner the deterministic lowest-count victim, wiped
    /// its history with one decoy packet, and re-seeded it at count 1 on the
    /// next probe — never reaching the detection count. The cursor walks
    /// `key_ring` from `(evict_cursor + seed_mix) % ring_len`, counting only
    /// SAME-ZONE slots toward `EVICT_SCAN_LIMIT`, and advances past the
    /// examined same-zone span, so successive evictions rotate across the
    /// whole zone. The per-eviction walk therefore visits at most
    /// `EVICT_SCAN_LIMIT + (other-zone slots in the window)` ring slots.
    /// When other zones interleave densely the walk is capped at
    /// `EVICT_SCAN_LIMIT + MAX_OTHER_ZONE_SKIP` ring slots so adversarial
    /// interleave cannot turn eviction into an O(ring) scan; if the cap is
    /// hit before `EVICT_SCAN_LIMIT` same-zone candidates are seen, the
    /// best victim found so far is still returned when one exists (the
    /// caller only reaches here at `zone_count >= MAX_SOURCES_PER_ZONE`,
    /// so same-zone entries are dense in the ring in the saturating case).
    ///
    /// Cost bound: at most `EVICT_SCAN_LIMIT + MAX_OTHER_ZONE_SKIP` ring
    /// slots per eviction, independent of the table size. Since this branch
    /// only runs when the TARGET zone holds `>= MAX_SOURCES_PER_ZONE` keys
    /// (>> `EVICT_SCAN_LIMIT`), a victim is found under saturation and the
    /// fresh scanner is admitted. The pre-#4890 search sampled a fixed
    /// GLOBAL prefix of `per_src` whose budget counted every iterated entry
    /// regardless of zone; in a many-zone table where the first
    /// `EVICT_SCAN_LIMIT` global positions held no target-zone entry it found
    /// no victim and skipped the fresh scanner (the #4890 fail-open of
    /// detection). Returns `true` if a victim was evicted (index updated,
    /// `evicted_pressure` bumped), `false` otherwise.
    #[inline]
    fn evict_stalest_in_zone(&mut self, zone_id: u16, now_micros: u64, window_micros: u64) -> bool {
        /// Hard cap on non-target-zone ring slots skipped in one eviction
        /// walk (#14673). Bounds the walk when zones interleave densely;
        /// 8x the sample is far beyond any legitimate interleave at
        /// saturation (the saturating zone alone holds 4096 slots).
        const MAX_OTHER_ZONE_SKIP: usize = EVICT_SCAN_LIMIT * 8;
        const WALK_CAP: usize = EVICT_SCAN_LIMIT + MAX_OTHER_ZONE_SKIP;
        let ring_len = self.key_ring.len();
        if ring_len == 0 {
            return false;
        }
        if self.evict_cursor >= ring_len {
            self.evict_cursor = 0;
        }
        // Per-boot unpredictable offset (#14673): splitmix-style diffusion
        // of the secret so the start slot cannot be precomputed off-box.
        // `evict_cursor` is stored in the UNSEEDED frame: the walk starts
        // at `(evict_cursor + seed_offset) % ring_len`, and the cursor is
        // advanced below by translating the next start back into that
        // frame. Storing the absolute next index instead would re-add the
        // seed offset on the next call and make successive windows jump by
        // `seed_offset` each time, so coverage of the ring would depend on
        // `gcd(seed_offset + span, ring_len)` rather than being a plain
        // contiguous rotation.
        let seed_mix = self
            .seed
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .rotate_left(32) as usize;
        let seed_offset = seed_mix % ring_len;
        let start = (self.evict_cursor + seed_offset) % ring_len;
        let walk_cap = WALK_CAP.min(ring_len);
        let mut victim_src: Option<IpAddr> = None;
        let mut victim_count = usize::MAX;
        let mut victim_start = u64::MAX;
        let mut expired_victim: Option<IpAddr> = None;
        let mut examined_same_zone = 0usize;
        let mut last_examined_idx: Option<usize> = None;
        for step in 0..walk_cap {
            let idx = (start + step) % ring_len;
            let (k_zone, src) = self.key_ring[idx];
            if k_zone != zone_id {
                continue;
            }
            examined_same_zone += 1;
            last_examined_idx = Some(idx);
            #[cfg(test)]
            self.evict_examined_log.push((k_zone, src));
            let e = match self.per_src.get(&(zone_id, src)) {
                Some(entry) => entry,
                // Ring/table skew (should not happen — they are kept in
                // lock-step); ignore defensively.
                None => {
                    if examined_same_zone >= EVICT_SCAN_LIMIT {
                        break;
                    }
                    continue;
                }
            };
            // An expired-or-empty window is dead weight — evict it first.
            if now_micros.saturating_sub(e.window_start) >= window_micros || e.entries.is_empty() {
                expired_victim = Some(src);
                break;
            }
            // Least-suspicious first: fewest distinct destinations, then
            // the stalest window on a tie (#4418 / #2234).
            let count = e.entries.len();
            if count < victim_count || (count == victim_count && e.window_start < victim_start) {
                victim_count = count;
                victim_start = e.window_start;
                victim_src = Some(src);
            }
            if examined_same_zone >= EVICT_SCAN_LIMIT {
                break;
            }
        }
        // Advance the cursor so the next walk starts just past the examined
        // span, translated back into the unseeded cursor frame (see above).
        // Re-clamp against the pre-removal ring length; the next call
        // re-clamps if the ring shrank.
        let next_start = if let Some(idx) = last_examined_idx {
            (idx + 1) % ring_len
        } else {
            // No same-zone slot in the walked window: advance past it so a
            // repeated call does not rescan the same dead window.
            (start + walk_cap) % ring_len
        };
        self.evict_cursor = (next_start + ring_len - seed_offset) % ring_len;
        // Fallback (#4890 guard): if the bounded rotating window found no
        // same-zone candidate at all (the target zone is sparse in a huge
        // ring — e.g. 3 target entries among 100k other-zone entries, the
        // #4890 test shape, which calls this directly below the cap), take
        // a ROTATING sample of the zone's own index instead of rescanning
        // the ring: start at `(evict_cursor + seed_offset) % zone_len` in
        // `per_zone_srcs[zone]` iteration order and wrap, examining at most
        // `EVICT_SCAN_LIMIT` same-zone entries. The skip is bounded by the
        // per-zone cap (`MAX_SOURCES_PER_ZONE`), never by the total table
        // size, and at real saturation (`zone_count >= MAX_SOURCES_PER_ZONE`)
        // the dense ring window above finds a victim first, so this path
        // is cold. Victim choice is identical: expired-first, then
        // least-suspicious.
        let mut victim = expired_victim.or(victim_src);
        if victim.is_none() {
            if let Some(srcs) = self.per_zone_srcs.get(&zone_id) {
                let zone_len = srcs.len();
                if zone_len > 0 {
                    let off = (self.evict_cursor + seed_offset) % zone_len;
                    let mut v2_src: Option<IpAddr> = None;
                    let mut v2_count = usize::MAX;
                    let mut v2_start = u64::MAX;
                    let mut exp2: Option<IpAddr> = None;
                    for src in srcs
                        .iter()
                        .skip(off)
                        .chain(srcs.iter().take(off))
                        .take(EVICT_SCAN_LIMIT)
                    {
                        #[cfg(test)]
                        self.evict_examined_log.push((zone_id, *src));
                        let Some(e) = self.per_src.get(&(zone_id, *src)) else {
                            continue;
                        };
                        if now_micros.saturating_sub(e.window_start) >= window_micros
                            || e.entries.is_empty()
                        {
                            exp2 = Some(*src);
                            break;
                        }
                        let count = e.entries.len();
                        if count < v2_count || (count == v2_count && e.window_start < v2_start) {
                            v2_count = count;
                            v2_start = e.window_start;
                            v2_src = Some(*src);
                        }
                    }
                    victim = exp2.or(v2_src);
                }
            }
        }
        if let Some(src) = victim {
            // Route through the single removal primitive so `per_src`,
            // `per_zone_srcs`, and the cleanup `key_ring` stay in lock-step.
            if self.remove_src(&(zone_id, src)) {
                self.evicted_pressure += 1;
                return true;
            }
        }
        false
    }

    /// Bounded-EXAMINATION periodic cleanup (#6239). EXAMINES at most
    /// `CLEANUP_BUDGET` source keys per call — starting from the persistent
    /// `cleanup_cursor` into the dense `key_ring` — and removes those found
    /// expired-or-empty. The per-call cost is O(`CLEANUP_BUDGET`) regardless of
    /// how many sources the table holds. Returns the number of candidates
    /// examined (used by the bounded-examination test; ignored in production).
    ///
    /// This replaced the pre-#6239 `HashMap::retain` sweep, which budgeted only
    /// the REMOVALS: once `CLEANUP_BUDGET` expired entries were removed the
    /// `retain` closure still ran for EVERY remaining bucket on that ONE packet
    /// worker (O(sources)). An attacker populating sources across many zones
    /// exhausted the removal budget and then paid the full-table walk on a
    /// single unlucky packet — the exact per-packet latency spike #2209
    /// forbade. The cursor advances across calls so every source is eventually
    /// visited without any single call walking the whole table; a live (not yet
    /// expired) entry is stepped over and revisited on a later sweep. Each
    /// removal goes through [`ScanCore::remove_src`], keeping `per_src`,
    /// `per_zone_srcs`, and `key_ring` in lock-step so the O(1) cap test and the
    /// eviction victim-search domain stay exact.
    ///
    /// `now_micros` is the monotonic microsecond clock. This periodic sweep is
    /// zone-agnostic (it has no single per-zone `window_micros`), so the caller
    /// passes `reap_floor_micros` — the LONGEST configured detection window
    /// across the live screen profiles (#4379). An entry untouched for longer
    /// than the longest window is dead under EVERY per-zone window, so cleanup
    /// can reclaim it. Using the fixed 1s Junos-max floor (the pre-#4379 shape)
    /// reaped an accumulating set before the detection count was reached for
    /// any operator window > 1s → a slow scan spread across the configured
    /// window EVADED detection (fail-open). The floor is clamped to
    /// [`MAX_CLEANUP_WINDOW_MICROS`] so a pathological (fat-fingered) window
    /// cannot make the sweep retain dead weight indefinitely; memory is
    /// independently bounded by the per-source/zone caps regardless. The exact
    /// per-zone window still governs the inline reset/verdict in
    /// [`ScanCore::check`]; cleanup only reclaims memory.
    #[inline]
    fn cleanup(&mut self, now_micros: u64, reap_floor_micros: u64) -> usize {
        let floor = reap_floor_micros.min(MAX_CLEANUP_WINDOW_MICROS);
        let start_len = self.key_ring.len();
        if start_len == 0 {
            self.cleanup_cursor = 0;
            return 0;
        }
        // Clamp a cursor left dangling past the ring end by removals since the
        // last call (eviction shrinks the ring between cleanups).
        if self.cleanup_cursor >= start_len {
            self.cleanup_cursor = 0;
        }
        let budget = CLEANUP_BUDGET.min(start_len);
        let mut examined = 0usize;
        let mut i = self.cleanup_cursor;
        while examined < budget {
            let len = self.key_ring.len();
            if len == 0 {
                i = 0;
                break;
            }
            if i >= len {
                i = 0;
            }
            let key = self.key_ring[i];
            #[cfg(test)]
            self.examined_log.push(key);
            examined += 1;
            let expired = match self.per_src.get(&key) {
                Some(e) => {
                    now_micros.saturating_sub(e.window_start) >= floor || e.entries.is_empty()
                }
                // Ring/table skew (should not happen — lock-step maintained);
                // reclaim the dangling ring slot defensively.
                None => true,
            };
            if expired {
                // Swap-removes `key_ring[i]`, moving the tail key into slot `i`;
                // do NOT advance so that swapped-in key is examined next.
                self.remove_src(&key);
            } else {
                i += 1;
            }
        }
        let len = self.key_ring.len();
        self.cleanup_cursor = if len == 0 { 0 } else { i % len };
        examined
    }

    /// Returns `true` once each time the cumulative eviction count crosses a
    /// geometric threshold (1, 2, 4, 8, ...). Surfacing a `scan-table-
    /// pressure` screen event on this rare transition (#2234) tells the
    /// operator the detector is saturated — at a LOGARITHMIC rate, never
    /// per-flow, so a sustained flood produces a handful of alarms rather
    /// than a per-packet log storm (CLAUDE.md logging rules). Consumes the
    /// crossing (idempotent until the next boundary).
    #[inline]
    fn take_pressure_event(&mut self) -> bool {
        if self.evicted_pressure >= self.pressure_event_at {
            // Advance to the next power-of-two boundary above the current
            // count so repeated calls within the same epoch do not re-fire.
            // `checked_next_power_of_two` returns None when no power of two
            // fits in u64 (count > 2^63); saturate to u64::MAX there so the
            // gate never panics/wraps and simply stops firing (the alarm has
            // long since been raised). Cannot regress below the current bar.
            self.pressure_event_at = self
                .evicted_pressure
                .saturating_add(1)
                .checked_next_power_of_two()
                .unwrap_or(u64::MAX);
            true
        } else {
            false
        }
    }

    /// Test-only: rebuild `per_zone_srcs` AND the cleanup `key_ring` (with fresh
    /// `SrcEntry.slot` back-pointers) from the current `per_src` contents. Tests
    /// that populate `per_src` DIRECTLY (bypassing [`ScanCore::check`], to keep
    /// the setup O(few) rather than filling the 4096-entry cap) must call this
    /// so the per-zone index — the eviction victim-search domain and the O(1)
    /// cap count (#4890) — AND the ring / slot indices (#6239) match the table.
    #[cfg(test)]
    fn rebuild_zone_index_for_test(&mut self) {
        self.per_zone_srcs.clear();
        self.key_ring.clear();
        self.cleanup_cursor = 0;
        self.evict_cursor = 0;
        let keys: Vec<ScanKey> = self.per_src.keys().copied().collect();
        for (idx, key) in keys.into_iter().enumerate() {
            self.per_zone_srcs.entry(key.0).or_default().insert(key.1);
            self.key_ring.push(key);
            if let Some(e) = self.per_src.get_mut(&key) {
                e.slot = idx;
            }
        }
    }

    /// Test-only invariant checker (#6239): `per_src`, `per_zone_srcs`, and the
    /// cleanup `key_ring` must stay in perfect lock-step after any sequence of
    /// inserts / evictions / bounded cleanups.
    #[cfg(test)]
    fn assert_consistent(&self) {
        // Ring length mirrors the table size, and every slot back-pointer is
        // exact (`key_ring[e.slot] == key`).
        assert_eq!(
            self.key_ring.len(),
            self.per_src.len(),
            "key_ring and per_src must have equal length"
        );
        for (i, key) in self.key_ring.iter().enumerate() {
            let e = self
                .per_src
                .get(key)
                .expect("every key_ring entry must exist in per_src");
            assert_eq!(e.slot, i, "SrcEntry.slot must equal its key_ring index");
        }
        // Per-zone index and per_src are mutual: every zone entry maps to a live
        // table key, and the zone index sizes sum to the table size.
        let mut zone_total = 0usize;
        for (zone, srcs) in &self.per_zone_srcs {
            zone_total += srcs.len();
            for src in srcs {
                assert!(
                    self.per_src.contains_key(&(*zone, *src)),
                    "per_zone_srcs entry ({zone}, {src}) missing from per_src"
                );
            }
        }
        assert_eq!(
            zone_total,
            self.per_src.len(),
            "per_zone_srcs sizes must sum to per_src length"
        );
        for key in self.per_src.keys() {
            assert!(
                self.per_zone_srcs
                    .get(&key.0)
                    .is_some_and(|s| s.contains(&key.1)),
                "per_src key ({}, {}) missing from per_zone_srcs",
                key.0,
                key.1
            );
        }
    }
}

/// Tracks unique destination ports per `(zone_id, source IP)` within a
/// time window (port-scan detection). Thin wrapper over [`ScanCore`].
#[derive(Debug, Clone, Default)]
pub(super) struct PortScanTracker {
    core: ScanCore<u16>,
}

impl PortScanTracker {
    /// Check if `(zone_id, src_ip)` reached the fixed port-scan detection
    /// count within `window_micros`. Returns true if flagged. Bounded +
    /// fail-safe (see [`ScanCore::check`]). `window_micros` is the per-zone
    /// Junos `threshold` (a microsecond time window, #4114).
    pub(super) fn check(
        &mut self,
        zone_id: u16,
        src_ip: IpAddr,
        dst_port: u16,
        now_micros: u64,
        window_micros: u64,
    ) -> bool {
        self.core
            .check(zone_id, src_ip, dst_port, now_micros, window_micros)
    }

    /// Remove expired entries (budgeted periodic cleanup). `now_micros` is a
    /// monotonic microsecond clock; `reap_floor_micros` is the window-aware
    /// reap floor (longest configured port-scan window across profiles, #4379).
    pub(super) fn cleanup(&mut self, now_micros: u64, reap_floor_micros: u64) {
        self.core.cleanup(now_micros, reap_floor_micros);
    }

    /// Records skipped due to a per-source unique-entry cap or a failed
    /// bounded eviction (fail-safe overflow pressure). Pure observability.
    pub(super) fn skipped_pressure(&self) -> u64 {
        self.core.skipped_pressure
    }

    /// Stalest-evictions on the source-saturation path (#2234). Pure
    /// observability.
    pub(super) fn evicted_pressure(&self) -> u64 {
        self.core.evicted_pressure
    }

    /// Rare (logarithmic) pressure-event transition for the operator alarm
    /// (#2234). See [`ScanCore::take_pressure_event`].
    pub(super) fn take_pressure_event(&mut self) -> bool {
        self.core.take_pressure_event()
    }

    #[cfg(test)]
    pub(super) fn tracked_sources(&self) -> usize {
        self.core.per_src.len()
    }
}

/// Tracks unique destination IPs per `(zone_id, source IP)` within a time
/// window (IP-sweep detection). Thin wrapper over [`ScanCore`].
#[derive(Debug, Clone, Default)]
pub(super) struct IpSweepTracker {
    core: ScanCore<IpAddr>,
}

impl IpSweepTracker {
    /// Check if `(zone_id, src_ip)` reached the fixed IP-sweep detection count
    /// within `window_micros`. Returns true if flagged. Bounded + fail-safe
    /// (see [`ScanCore::check`]). `window_micros` is the per-zone Junos
    /// `threshold` (a microsecond time window, #4114).
    pub(super) fn check(
        &mut self,
        zone_id: u16,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        now_micros: u64,
        window_micros: u64,
    ) -> bool {
        self.core
            .check(zone_id, src_ip, dst_ip, now_micros, window_micros)
    }

    /// Remove expired entries (budgeted periodic cleanup). `now_micros` is a
    /// monotonic microsecond clock; `reap_floor_micros` is the window-aware
    /// reap floor (longest configured ip-sweep window across profiles, #4379).
    pub(super) fn cleanup(&mut self, now_micros: u64, reap_floor_micros: u64) {
        self.core.cleanup(now_micros, reap_floor_micros);
    }

    /// Records skipped due to a per-source unique-entry cap or a failed
    /// bounded eviction (fail-safe overflow pressure). Pure observability.
    pub(super) fn skipped_pressure(&self) -> u64 {
        self.core.skipped_pressure
    }

    /// Stalest-evictions on the source-saturation path (#2234). Pure
    /// observability.
    pub(super) fn evicted_pressure(&self) -> u64 {
        self.core.evicted_pressure
    }

    /// Rare (logarithmic) pressure-event transition for the operator alarm
    /// (#2234). See [`ScanCore::take_pressure_event`].
    pub(super) fn take_pressure_event(&mut self) -> bool {
        self.core.take_pressure_event()
    }

    #[cfg(test)]
    pub(super) fn tracked_sources(&self) -> usize {
        self.core.per_src.len()
    }
}

#[cfg(test)]
mod scan_tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, a))
    }

    /// Build a `SrcEntry` for tests that seed `per_src` DIRECTLY (bypassing
    /// [`ScanCore::check`]). The `slot` back-pointer is a placeholder; every
    /// such test then calls [`ScanCore::rebuild_zone_index_for_test`], which
    /// rebuilds the ring and stamps the correct slot indices (#6239).
    fn seed_entry<T>(window_start: u64, entries: FxHashSet<T>) -> SrcEntry<T> {
        SrcEntry {
            window_start,
            entries,
            slot: 0,
        }
    }

    /// Junos default window (microseconds) used across the windowing tests.
    const W: u64 = 5_000;

    /// The pre-#4379 fixed cleanup floor (the Junos in-range max window, 1s).
    /// Retained as a test anchor: the budgeted/count cleanup tests age entries
    /// relative to it and pass it explicitly as the (now window-aware) reap
    /// floor argument.
    const OLD_CLEANUP_FLOOR: u64 = 1_000_000;

    #[test]
    fn port_scan_keyed_per_zone_no_cross_count() {
        let mut t = PortScanTracker::default();
        let src = v4(1);
        // Zone 1: the first SCAN_DETECT_COUNT-1 distinct ports do not fire.
        // A GLOBAL tracker would carry this count into zone 2 below.
        for p in 0..(SCAN_DETECT_COUNT as u16 - 1) {
            assert!(!t.check(1, src, 8000 + p, 100, W));
        }
        // Zone 2 from the SAME src starts fresh — the same distinct-port count
        // does NOT trip (per-zone keying, #2209).
        for p in 0..(SCAN_DETECT_COUNT as u16 - 1) {
            assert!(!t.check(2, src, 9000 + p, 100, W));
        }
        // Zone 2's SCAN_DETECT_COUNT-th distinct port crosses ITS own count.
        assert!(t.check(2, src, 9999, 100, W));
        // Zone 1's SCAN_DETECT_COUNT-th distinct port crosses zone 1's count,
        // independent of zone 2.
        assert!(t.check(1, src, 8999, 100, W));
    }

    #[test]
    fn ip_sweep_keyed_per_zone_no_cross_count() {
        let mut t = IpSweepTracker::default();
        let src = v4(1);
        for i in 0..(SCAN_DETECT_COUNT as u8 - 1) {
            assert!(!t.check(1, src, v4(10 + i), 100, W));
        }
        // Zone 2 starts fresh for the same src.
        for i in 0..(SCAN_DETECT_COUNT as u8 - 1) {
            assert!(!t.check(2, src, v4(100 + i), 100, W));
        }
        assert!(t.check(2, src, v4(200), 100, W));
        assert!(t.check(1, src, v4(50), 100, W));
    }

    #[test]
    fn source_table_bounded_and_not_fail_open() {
        let mut t = IpSweepTracker::default();
        // Fill zone 0 to the source cap with distinct sources, one dst each
        // (well under SCAN_DETECT_COUNT, so none trips and nothing is evicted
        // by detection). A wide in-range window keeps every entry live.
        for i in 0..MAX_SOURCES_PER_ZONE {
            let src = IpAddr::V4(Ipv4Addr::from((0x0a00_0000u32) + i as u32));
            assert!(!t.check(0, src, v4(1), 100, 1_000_000));
        }
        assert_eq!(t.tracked_sources(), MAX_SOURCES_PER_ZONE);
        assert_eq!(t.skipped_pressure(), 0);
        assert_eq!(t.evicted_pressure(), 0);
        // #2234: one more brand-new source must NOW be admitted by BOUNDED
        // stalest-eviction (not skipped), so a fresh real scanner is always
        // trackable — and must NOT fail-open (returns false = no drop). The
        // table must STAY bounded at the cap (eviction made room, the table
        // never grows). A window of 0 disables the check (early return, no
        // admit); a real window admits via eviction.
        let overflow_src = IpAddr::V4(Ipv4Addr::from(0x0b00_0000u32));
        assert!(!t.check(0, overflow_src, v4(1), 100, 0));
        assert!(!t.check(0, overflow_src, v4(2), 100, 1_000_000));
        assert_eq!(
            t.tracked_sources(),
            MAX_SOURCES_PER_ZONE,
            "eviction must keep the table bounded at the cap, not grow it"
        );
        assert!(
            t.evicted_pressure() >= 1,
            "admitting an over-cap source records eviction pressure"
        );
    }

    /// #4114 fail-on-revert (WINDOW semantics, fast scan): SCAN_DETECT_COUNT
    /// distinct destinations reached WITHIN the microsecond window fire
    /// detection on the SCAN_DETECT_COUNT-th. The count is FIXED (10), not the
    /// configurable knob — the configurable knob is the window.
    #[test]
    fn detects_fixed_count_within_window() {
        let mut t = IpSweepTracker::default();
        let src = v4(1);
        let now = 1_000_000u64;
        // The first SCAN_DETECT_COUNT-1 distinct dests within the window do
        // not fire.
        for i in 0..(SCAN_DETECT_COUNT as u32 - 1) {
            let dst = IpAddr::V4(Ipv4Addr::from(0x0e00_0000u32 + i));
            assert!(!t.check(0, src, dst, now, W));
        }
        // The SCAN_DETECT_COUNT-th distinct dest within the SAME window fires.
        let dst = IpAddr::V4(Ipv4Addr::from(
            0x0e00_0000u32 + (SCAN_DETECT_COUNT as u32 - 1),
        ));
        assert!(
            t.check(0, src, dst, now, W),
            "{SCAN_DETECT_COUNT} distinct dests within the window must fire"
        );
    }

    /// #4114 fail-on-revert (WINDOW semantics, slow probe): the SAME
    /// SCAN_DETECT_COUNT distinct destinations spread so each lands MORE than
    /// `window_micros` after the previous never fire — every probe opens a
    /// fresh window and the distinct count resets to 1. Under the pre-#4114
    /// count-over-fixed-window misinterpretation these same distinct dests
    /// would have accumulated a count of 10 and tripped (that is what goes RED
    /// on revert). A configurable µs window means a slow scan is not a scan.
    #[test]
    fn no_detect_when_dests_spread_beyond_window() {
        let mut t = IpSweepTracker::default();
        let src = v4(1);
        let mut now = 1_000_000u64;
        for i in 0..(SCAN_DETECT_COUNT as u32 + 5) {
            let dst = IpAddr::V4(Ipv4Addr::from(0x0f00_0000u32 + i));
            assert!(
                !t.check(0, src, dst, now, W),
                "a probe spread beyond the window must never fire (window resets)"
            );
            now += W + 1; // the next probe opens a brand-new window
        }
    }

    #[test]
    fn per_source_unique_entries_bounded() {
        let mut t = IpSweepTracker::default();
        let src = v4(1);
        // A single wide window (nothing resets); flood unique dst IPs past the
        // per-source memory cap. Detection fires early (ignored) but the set
        // is still bounded at MAX_UNIQUE_PER_SOURCE.
        for i in 0..(MAX_UNIQUE_PER_SOURCE + 100) {
            let dst = IpAddr::V4(Ipv4Addr::from(0x0c00_0000u32 + i as u32));
            t.check(7, src, dst, 100, 1_000_000);
        }
        // The inner set is capped; the surplus is recorded as pressure.
        assert_eq!(t.tracked_sources(), 1);
        assert!(
            t.skipped_pressure() >= 100,
            "surplus unique entries record pressure: {}",
            t.skipped_pressure()
        );
    }

    #[test]
    fn window_expiry_resets_per_key() {
        let mut t = PortScanTracker::default();
        let src = v4(1);
        let now = 1_000u64;
        // SCAN_DETECT_COUNT distinct ports within the window fire on the last.
        for p in 0..(SCAN_DETECT_COUNT as u16 - 1) {
            assert!(!t.check(3, src, 8000 + p, now, W));
        }
        assert!(t.check(3, src, 8999, now, W));
        // After the window elapses the set resets and the count restarts, so a
        // single new port does not fire.
        assert!(!t.check(3, src, 7000, now + W, W));
    }

    #[test]
    fn cleanup_is_budgeted() {
        let mut t = IpSweepTracker::default();
        // Seed more expired entries than the budget; one cleanup call must
        // remove at most CLEANUP_BUDGET so the per-tick cost is bounded.
        let seed = CLEANUP_BUDGET + 50;
        for i in 0..seed {
            let src = IpAddr::V4(Ipv4Addr::from(0x0d00_0000u32 + i as u32));
            t.check(0, src, v4(1), 0, 1_000_000);
        }
        assert_eq!(t.tracked_sources(), seed);
        // Far past the cleanup window — all are expired, but one sweep removes
        // only up to the budget.
        t.cleanup(2 * OLD_CLEANUP_FLOOR, OLD_CLEANUP_FLOOR);
        assert_eq!(t.tracked_sources(), seed - CLEANUP_BUDGET);
    }

    /// #2234 fail-on-revert: a brand-new REAL scanner that arrives AFTER the
    /// per-zone source table is saturated must still be tracked AND detected.
    /// Pre-#2234 the new source was SKIPPED on a full table (returns false,
    /// only bumps `skipped_pressure`), so a high-cardinality spoofed flood
    /// could suppress detection of a subsequently-arriving genuine scanner
    /// indefinitely — a detection-DoS. Reverting `evict_stalest_in_zone` to
    /// the skip-on-full cliff breaks this test (the scanner never fires).
    #[test]
    fn fresh_scanner_tracked_and_detected_after_saturation() {
        let mut t = IpSweepTracker::default();
        // Fill zone 0 to the cap with spoofed sources, one dst each so none
        // trips (the flood is high-cardinality, low-per-source fan-out).
        let flood_t = 0u64;
        for i in 0..MAX_SOURCES_PER_ZONE {
            let src = IpAddr::V4(Ipv4Addr::from(0x0a00_0000u32 + i as u32));
            assert!(!t.check(0, src, v4(1), flood_t, 1_000_000));
        }
        assert_eq!(t.tracked_sources(), MAX_SOURCES_PER_ZONE);
        // A real scanner arrives later, sweeping SCAN_DETECT_COUNT+ distinct
        // destinations within its window. Even though the table is full, it
        // must be admitted by eviction and cross the fixed detection count.
        let scanner = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let now = flood_t + 1; // still inside the flood's window
        let mut fired = false;
        for d in 0..(SCAN_DETECT_COUNT as u32 + 3) {
            let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, d as u8));
            if t.check(0, scanner, dst, now, 1_000_000) {
                fired = true;
                break;
            }
        }
        assert!(
            fired,
            "a fresh real scanner arriving after saturation MUST be tracked \
             and detected (pre-#2234 it was skipped on a full table → never \
             detected)"
        );
        // The table must remain bounded (eviction made room, not growth).
        assert_eq!(
            t.tracked_sources(),
            MAX_SOURCES_PER_ZONE,
            "eviction keeps the table at the cap"
        );
        assert!(t.evicted_pressure() >= 1, "admission recorded an eviction");
    }

    /// #2234/#4418: on a tie in accumulated distinct-destination count,
    /// eviction must prefer the STALEST (oldest `window_start`) entry over
    /// fresher ones when no entry is expired. Every entry here holds exactly
    /// one distinct destination (count 1), so the least-suspicious selection
    /// (#4418) is a tie on count and the stalest tiebreak decides — the source
    /// whose window is oldest is the one removed. (Exercising the victim-choice
    /// logic on `ScanCore` directly keeps this O(few) instead of filling the
    /// 4096-entry cap.)
    #[test]
    fn eviction_prefers_stalest_window() {
        let mut core: ScanCore<u16> = ScanCore::default();
        // Seed a handful of zone-9 entries with DISTINCT, increasing window
        // starts so exactly one is the stalest. (Direct ScanCore access keeps
        // this O(few) instead of filling 4096 cap entries.) Each set is
        // NON-EMPTY and the window is FRESH so the expired-or-empty branch
        // never fires — the victim choice is decided purely by window_start.
        let mut nonempty = |p: u16| {
            let mut s = FxHashSet::default();
            s.insert(p);
            s
        };
        let stale_src = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1));
        core.per_src.insert((9, stale_src), seed_entry(100, nonempty(1)));
        for i in 2..=8u32 {
            let s = IpAddr::V4(Ipv4Addr::from(0x0a09_0000u32 + i));
            core.per_src
                .insert((9, s), seed_entry(200 + i as u64, nonempty(i as u16)));
        }
        core.rebuild_zone_index_for_test();
        let before = core.per_src.len();
        // `now` close to the stalest start so NOTHING is expired within a wide
        // window (force the stalest-not-expired branch).
        let now = 105u64;
        assert!(
            core.evict_stalest_in_zone(9, now, 1_000_000),
            "a same-zone victim must be found"
        );
        assert_eq!(core.per_src.len(), before - 1, "exactly one evicted");
        assert!(
            !core.per_src.contains_key(&(9, stale_src)),
            "the STALEST (window_start=100) entry must be the one evicted, \
             not a fresher one"
        );
        assert_eq!(core.evicted_pressure, 1);
    }

    /// #2234: eviction prefers an EXPIRED window even if it is not the
    /// numerically-oldest in iteration order — dead weight is reclaimed first.
    #[test]
    fn eviction_prefers_expired_window() {
        let mut core: ScanCore<u16> = ScanCore::default();
        let expired_src = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 50));
        // One expired entry plus several fresh ones.
        core.per_src
            .insert((9, expired_src), seed_entry(0, FxHashSet::default()));
        for i in 1..=5u32 {
            let s = IpAddr::V4(Ipv4Addr::from(0x0a09_1000u32 + i));
            let mut set = FxHashSet::default();
            set.insert(i as u16);
            core.per_src.insert((9, s), seed_entry(1_000, set));
        }
        core.rebuild_zone_index_for_test();
        // now far past the expired entry's window but inside the fresh
        // entries' (window = 100us here).
        let now = 1_050u64;
        assert!(core.evict_stalest_in_zone(9, now, 100));
        assert!(
            !core.per_src.contains_key(&(9, expired_src)),
            "the EXPIRED entry must be reclaimed first"
        );
    }

    /// #4418 fail-on-revert (source-saturation eviction): a near-threshold slow
    /// scanner (many accumulated distinct destinations, an OLD but still-LIVE
    /// window) must NOT be evicted by a flood of fresher decoy sources (each at
    /// count 1) that keeps the per-zone source table full. The pre-#4418 policy
    /// evicted the STALEST `window_start` regardless of count, so the slow
    /// scanner — whose window opened FIRST — was the victim: its accumulated
    /// count was lost and it re-seeded at count 1 on its next probe → evasion.
    /// The least-suspicious policy evicts a count-1 decoy instead, so the slow
    /// scanner survives and trips. RED on revert: the stalest-by-window policy
    /// evicts the slow scanner and the trip assertion fails.
    #[test]
    fn slow_scanner_survives_decoy_flood_eviction() {
        let mut core: ScanCore<u16> = ScanCore::default();
        let zone = 9u16;
        let window = 1_000_000u64; // 1s — every seeded entry is LIVE below
        // The slow scanner opened its window FIRST (oldest start=100) and has
        // already probed SCAN_DETECT_COUNT-1 distinct ports (near threshold).
        let scanner = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let mut scanner_set = FxHashSet::default();
        for p in 0..(SCAN_DETECT_COUNT as u16 - 1) {
            scanner_set.insert(8000 + p);
        }
        core.per_src.insert((zone, scanner), seed_entry(100, scanner_set));
        // Fill the rest of a full bounded sample with FRESHER decoys at count 1
        // (a high-cardinality spoofed flood: one probe each, later windows).
        for i in 1..EVICT_SCAN_LIMIT as u64 {
            let d = IpAddr::V4(Ipv4Addr::from(0x0a09_0000u32 + i as u32));
            let mut s = FxHashSet::default();
            s.insert(1u16);
            // fresher than scanner
            core.per_src.insert((zone, d), seed_entry(100 + i, s));
        }
        core.rebuild_zone_index_for_test();
        // `now` after every start but well within the 1s window → nothing is
        // expired; the victim is decided purely by the least-suspicious rule.
        let now = 100_000u64;
        assert!(
            core.evict_stalest_in_zone(zone, now, window),
            "a same-zone victim must be found in the full sample"
        );
        assert!(
            core.per_src.contains_key(&(zone, scanner)),
            "the near-threshold slow scanner must NOT be evicted by a decoy \
             flood (pre-#4418 the stalest-by-window policy evicted it)"
        );
        assert_eq!(core.evicted_pressure, 1, "exactly one decoy evicted");
        // Having survived the flood, the scanner trips on its
        // SCAN_DETECT_COUNT-th distinct port (its window is still live, so the
        // accumulated set is intact — no eviction is triggered for an existing
        // key, and the zone is well under the source cap).
        assert!(
            core.check(zone, scanner, 8999, now, window),
            "the surviving slow scanner must trip on its 10th distinct port"
        );
    }

    /// #4890 fail-on-revert (PER-ZONE victim search): the source-saturation
    /// eviction must sample victims from the TARGET zone's own source index,
    /// NOT a fixed GLOBAL prefix of `per_src`. When a huge number of
    /// OTHER-zone entries crowd the front of the global iterator so that the
    /// first `EVICT_SCAN_LIMIT` global positions hold NO target-zone entry, the
    /// pre-#4890 `per_src.iter().take(EVICT_SCAN_LIMIT)` sample found no
    /// same-zone victim → `evict_stalest_in_zone` returned false → `check()`
    /// SKIPPED the brand-new scanner in the saturated zone → its distinct-
    /// destination count never accrued → detection never fired even though its
    /// packets were still forwarded. The per-zone index makes the
    /// `EVICT_SCAN_LIMIT` budget count only SAME-ZONE candidates, so a
    /// same-zone victim is always found under zone saturation and the fresh
    /// scanner is admitted + detected.
    ///
    /// RED on revert: reverting to the global-prefix sample makes
    /// `evict_stalest_in_zone(target)` return false here (the 3 target-zone
    /// entries almost never land in the first `EVICT_SCAN_LIMIT` of the huge
    /// global table), so the "a same-zone victim must be found" assertion
    /// fails and the admitted-scanner detection below is never reached.
    #[test]
    fn fresh_scanner_admitted_when_zone_entries_outside_global_prefix_4890() {
        let mut core: ScanCore<u16> = ScanCore::default();
        let other_zone = 1u16;
        let target_zone = 9u16;
        let window = 1_000_000u64;
        let start = 1_000u64;
        // `now` is inside the window for every seeded entry, so NOTHING is
        // expired — the victim is decided purely by the least-suspicious rule
        // over the PER-ZONE sample (not by the expired-first branch).
        let now = 1_500u64;

        // Crowd the GLOBAL `per_src` iterator with a very large number of
        // OTHER-zone sources (inserted directly to keep the setup O(pad), each
        // live + non-empty). Under the pre-#4890 global-prefix sample the first
        // EVICT_SCAN_LIMIT global positions hold no target-zone entry; the
        // per-zone index (this fix) iterates only the target zone's own
        // sources, so the pad is irrelevant to it.
        let pad = 100_000u32;
        for i in 0..pad {
            let s = IpAddr::V4(Ipv4Addr::from(0x0b00_0000u32 + i));
            let mut set = FxHashSet::default();
            set.insert((i & 0xffff) as u16);
            core.per_src.insert((other_zone, s), seed_entry(start, set));
        }

        // Exactly three LIVE target-zone sources with DISTINCT accumulated
        // counts, so the least-suspicious victim choice (#4418) is unambiguous:
        // the count-2 source must be the one evicted, the others must survive.
        let mut seed = |a: u8, count: u16| {
            let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, a));
            let mut set = FxHashSet::default();
            for p in 0..count {
                set.insert(9000 + p);
            }
            core.per_src.insert((target_zone, src), seed_entry(start, set));
            src
        };
        let victim = seed(1, 2); // fewest distinct dsts → the eviction victim
        let keep_mid = seed(2, 5);
        let keep_high = seed(3, 8);
        core.rebuild_zone_index_for_test();
        assert_eq!(core.zone_count(target_zone), 3);

        // Per-zone search: a same-zone victim is found even though the global
        // iterator prefix is all other-zone. Pre-#4890 this returns false.
        assert!(
            core.evict_stalest_in_zone(target_zone, now, window),
            "a same-zone victim MUST be found by the PER-ZONE search even when \
             the first EVICT_SCAN_LIMIT GLOBAL positions hold no target-zone \
             entry (#4890 — pre-fix the global-prefix sample found nothing)"
        );
        assert_eq!(core.evicted_pressure, 1, "exactly one same-zone eviction");
        assert!(
            !core.per_src.contains_key(&(target_zone, victim)),
            "the least-suspicious (count-2) target source must be evicted"
        );
        assert!(
            core.per_src.contains_key(&(target_zone, keep_mid))
                && core.per_src.contains_key(&(target_zone, keep_high)),
            "the higher-count target sources must survive (victim choice \
             preserved over the per-zone sample)"
        );
        // The per-zone index tracked the removal (O(1) cap count stays exact).
        assert_eq!(core.zone_count(target_zone), 2);

        // End-to-end: a brand-new scanner in the (now-admissible) target zone
        // accrues distinct destinations and FIRES detection — the behaviour the
        // pre-#4890 skip suppressed. It sweeps SCAN_DETECT_COUNT distinct ports
        // within the window and must trip.
        let scanner = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200));
        let mut fired = false;
        for p in 0..(SCAN_DETECT_COUNT as u16 + 3) {
            if core.check(target_zone, scanner, 7000 + p, now, window) {
                fired = true;
                break;
            }
        }
        assert!(
            fired,
            "an admitted scanner in the saturated zone must accrue distinct \
             destinations and fire detection (#4890)"
        );
    }

    /// #2234 bounded-cost guard: the eviction sample is FIXED
    /// (`EVICT_SCAN_LIMIT`), never an O(sources) scan. With many more
    /// same-zone entries than the limit, one eviction must examine at most
    /// the limit and still succeed — and the per-zone count is maintained
    /// exactly across repeated admit-with-eviction so the cap test stays O(1).
    #[test]
    fn eviction_is_bounded_and_count_exact() {
        assert!(
            evict_scan_limit_for_test() < MAX_SOURCES_PER_ZONE,
            "the sample must be a fixed PREFIX, not the whole table"
        );
        let mut t = PortScanTracker::default();
        // Saturate zone 4.
        for i in 0..MAX_SOURCES_PER_ZONE {
            let src = IpAddr::V4(Ipv4Addr::from(0x0a04_0000u32 + i as u32));
            assert!(!t.check(4, src, 80, 0, 1_000_000));
        }
        assert_eq!(t.tracked_sources(), MAX_SOURCES_PER_ZONE);
        // Admit many fresh sources; each must evict one (bounded) and the
        // table size must never exceed the cap.
        for i in 0..1024u32 {
            let fresh = IpAddr::V4(Ipv4Addr::from(0x0b04_0000u32 + i));
            t.check(4, fresh, 80, 1, 1_000_000);
            assert!(
                t.tracked_sources() <= MAX_SOURCES_PER_ZONE,
                "the table must never exceed the cap under sustained churn"
            );
        }
        assert_eq!(
            t.tracked_sources(),
            MAX_SOURCES_PER_ZONE,
            "sustained admit-with-eviction keeps the table exactly at the cap"
        );
        assert!(t.evicted_pressure() >= 1024);
        assert_eq!(t.skipped_pressure(), 0, "single-zone flood never skips");
    }

    /// #2234: the per-zone count is decremented on budgeted cleanup so the
    /// O(1) cap test stays exact after entries age out.
    #[test]
    fn per_zone_count_tracks_cleanup() {
        let mut core: ScanCore<u16> = ScanCore::default();
        for i in 0..10u32 {
            let s = IpAddr::V4(Ipv4Addr::from(0x0a05_0000u32 + i));
            core.check(5, s, 80, 0, 1_000_000);
        }
        assert_eq!(core.zone_count(5), 10);
        // Age everything out; cleanup removes them and the count follows.
        core.cleanup(2 * OLD_CLEANUP_FLOOR, OLD_CLEANUP_FLOOR);
        assert_eq!(core.zone_count(5), 0, "count decremented on cleanup");
        assert_eq!(core.per_src.len(), 0);
    }

    /// #2234: the pressure-event transition fires at a LOGARITHMIC rate
    /// (powers of two), never per eviction — so a sustained flood yields a
    /// handful of operator alarms, not a per-flow log storm.
    #[test]
    fn pressure_event_is_logarithmic() {
        let mut core: ScanCore<u16> = ScanCore::default();
        let mut events = 0u32;
        // Simulate 1000 evictions, asking for a pressure event after each.
        for _ in 0..1000u64 {
            core.evicted_pressure += 1;
            if core.take_pressure_event() {
                events += 1;
            }
        }
        // 1000 evictions cross boundaries 1,2,4,...,512 → 10 events.
        assert_eq!(
            events, 10,
            "pressure events must be logarithmic in eviction count, got {events}"
        );
    }

    /// #4379 fail-on-revert: with an operator-configured detection window LONGER
    /// than the old fixed 1s cleanup floor, a SLOW scan whose distinct
    /// destinations are spread across that window (each within the window, the
    /// span > 1s) must still be DETECTED — the periodic cleanup must NOT reap
    /// the accumulating tracker state at the old fixed 1s floor. Pre-#4379,
    /// `cleanup` reaped any entry older than a fixed 1s floor (the historical
    /// `CLEANUP_WINDOW_MICROS`), so a probe landing >1s after the window opened
    /// found its distinct-destination set already reclaimed, the count reset to
    /// 1, and the scan EVADED detection (fail-open). The window-aware floor
    /// (the configured window) retains the state for the full window. RED on
    /// revert: the tracker never fires because cleanup drops the state at 1s.
    #[test]
    fn slow_scan_within_window_survives_cleanup_reap() {
        let mut t = IpSweepTracker::default();
        let src = v4(1);
        // Operator-configured 5s window (> the old 1s cleanup floor). This is
        // what #4379 passes to cleanup as the window-aware reap floor.
        let window = 5_000_000u64;
        let mut now = 1_000_000u64;
        let mut fired = false;
        for i in 0..SCAN_DETECT_COUNT as u32 {
            let dst = IpAddr::V4(Ipv4Addr::from(0x0e00_0000u32 + i));
            if t.check(0, src, dst, now, window) {
                fired = true;
            }
            // A periodic cleanup fires between probes (production runs it every
            // >=30s from the new-flow hook). With the window-aware floor the
            // live entry survives; with the pre-#4379 fixed 1s floor it is
            // reaped once `now - start >= 1s`, resetting the distinct count.
            t.cleanup(now, window);
            now += 250_000; // 250ms between probes → the 10 probes span ~2.25s
        }
        assert!(
            fired,
            "a slow scan spread across the configured window must be detected: \
             the cleanup must not reap live tracker state at the old 1s floor"
        );
        // Control: reaping at the OLD fixed 1s floor DOES lose the state — this
        // is exactly the evasion the window-aware floor closes. A fresh tracker
        // fed the same slow scan but cleaned at the 1s floor never fires.
        let mut evaded = IpSweepTracker::default();
        let mut now2 = 1_000_000u64;
        let mut fired2 = false;
        for i in 0..SCAN_DETECT_COUNT as u32 {
            let dst = IpAddr::V4(Ipv4Addr::from(0x0e00_0000u32 + i));
            if evaded.check(0, src, dst, now2, window) {
                fired2 = true;
            }
            evaded.cleanup(now2, OLD_CLEANUP_FLOOR); // pre-#4379 fixed floor
            now2 += 250_000;
        }
        assert!(
            !fired2,
            "control: reaping at the fixed 1s floor loses the accumulating set \
             so the slow scan evades — this is the #4379 fail-open"
        );
    }

    /// #4379: a SUB-1s configured window reaps at the WINDOW, not at the old
    /// fixed 1s floor — idle state is not held longer than the operator's
    /// window needs. RED on revert: the fixed 1s floor would retain the entry
    /// (6ms < 1s), so this asserts the floor genuinely tracks the window.
    #[test]
    fn small_window_reaps_at_window_not_old_floor() {
        let mut t = IpSweepTracker::default();
        let src = v4(1);
        let window = W; // 5ms — a sub-1s window
        t.check(0, src, v4(9), 1_000_000, window);
        assert_eq!(t.tracked_sources(), 1);
        // 6ms later: past the 5ms window but far under the old 1s floor. The
        // window-aware floor reaps; the pre-#4379 fixed floor would retain.
        t.cleanup(1_000_000 + window + 1_000, window);
        assert_eq!(
            t.tracked_sources(),
            0,
            "a sub-1s window must reap at the window, not be held to the 1s floor"
        );
    }

    /// #4418 fail-on-revert (cleanup 5-min cap): an operator window LONGER than
    /// 5 minutes must retain its accumulating distinct-destination set for the
    /// FULL window — the periodic cleanup must NOT reap it at the pre-#4418
    /// `MAX_CLEANUP_WINDOW_MICROS = 300s` ceiling. Pre-#4418 the reap floor was
    /// clamped to 300s, so a slow scan spread across a >5min window found its
    /// set reclaimed at the 5-min mark, the distinct count reset, and the scan
    /// EVADED detection (fail-open) for that pathological band. Raising the
    /// ceiling to the u32 `threshold` type maximum closes it. RED on revert:
    /// the tracker never fires because cleanup drops the state at 300s.
    #[test]
    fn slow_scan_survives_cleanup_beyond_five_min_cap() {
        let mut t = IpSweepTracker::default();
        let src = v4(1);
        // A 10-minute operator window (> the pre-#4418 5-min cleanup cap). This
        // is what #4379/#4418 passes to cleanup as the window-aware reap floor.
        let window = 600_000_000u64; // 10 min
        // Ten distinct probes spread one per minute → the span (9 min) exceeds
        // the old 5-min cap but stays inside the 10-min window, so every probe
        // is within the window and the count must accumulate to the trip.
        let step = 60_000_000u64; // 1 min between probes
        let mut now = 1_000_000u64;
        let mut fired = false;
        for i in 0..SCAN_DETECT_COUNT as u32 {
            let dst = IpAddr::V4(Ipv4Addr::from(0x0e10_0000u32 + i));
            if t.check(0, src, dst, now, window) {
                fired = true;
            }
            // Periodic cleanup fires between probes (production runs it every
            // >=30s). With the type-max ceiling the live entry survives past
            // the 5-min mark; with the pre-#4418 300s cap it is reaped once
            // `now - start >= 300s`, resetting the distinct count.
            t.cleanup(now, window);
            now += step;
        }
        assert!(
            fired,
            "a slow scan spread across a >5min configured window must be \
             detected: cleanup must not reap live state at the old 300s cap"
        );

        // Control: reaping at the OLD fixed 300s ceiling DOES lose the state —
        // this is exactly the evasion the #4418 fix closes. A fresh tracker fed
        // the same slow scan but cleaned with the floor clamped at 300s never
        // fires.
        const OLD_CEILING: u64 = 300_000_000; // pre-#4418 MAX_CLEANUP_WINDOW_MICROS
        let mut evaded = IpSweepTracker::default();
        let mut now2 = 1_000_000u64;
        let mut fired2 = false;
        for i in 0..SCAN_DETECT_COUNT as u32 {
            let dst = IpAddr::V4(Ipv4Addr::from(0x0e10_0000u32 + i));
            if evaded.check(0, src, dst, now2, window) {
                fired2 = true;
            }
            // Emulate the pre-#4418 clamp: never let the floor exceed 300s.
            evaded.cleanup(now2, window.min(OLD_CEILING));
            now2 += step;
        }
        assert!(
            !fired2,
            "control: clamping the reap floor at 300s loses the accumulating \
             set past 5 min so the slow scan evades — the #4418 fail-open"
        );
    }

    /// #4418 upper bound: the reap floor is still provably bounded. A floor
    /// LARGER than the u32 `threshold` type can express (a value no real config
    /// can produce, guarding a future wider-threshold regression) is clamped to
    /// `MAX_CLEANUP_WINDOW_MICROS` so cleanup cannot retain dead weight for an
    /// unbounded time. (Memory is independently bounded by the per-source/zone
    /// caps regardless; this only bounds reclamation TIMING.)
    #[test]
    fn cleanup_floor_clamped_above_type_max() {
        let mut t = IpSweepTracker::default();
        let src = v4(1);
        // An entry opened at t=0 under a floor far beyond the ceiling.
        t.check(0, src, v4(9), 0, u64::MAX);
        assert_eq!(t.tracked_sources(), 1);
        // now just past the CEILING but far under the raw floor: the clamp
        // makes the entry expired; without the clamp it would survive.
        t.cleanup(MAX_CLEANUP_WINDOW_MICROS + 1, u64::MAX);
        assert_eq!(
            t.tracked_sources(),
            0,
            "a reap floor above the type maximum must be clamped to the ceiling \
             so it cannot retain dead-weight state indefinitely"
        );
    }

    /// #4379: the memory caps still bound state independently of the
    /// window-aware cleanup floor. Even with a huge window (so cleanup would
    /// retain everything), a single source's unique-entry set is capped at
    /// `MAX_UNIQUE_PER_SOURCE` and the surplus is counted as pressure — the
    /// cleanup floor change does not unbound memory.
    #[test]
    fn memory_caps_bound_state_under_wide_window() {
        let mut t = IpSweepTracker::default();
        let src = v4(1);
        let wide = MAX_CLEANUP_WINDOW_MICROS; // nothing resets or reaps in-test
        for i in 0..(MAX_UNIQUE_PER_SOURCE + 50) {
            let dst = IpAddr::V4(Ipv4Addr::from(0x0c10_0000u32 + i as u32));
            t.check(9, src, dst, 100, wide);
        }
        assert_eq!(t.tracked_sources(), 1);
        assert!(
            t.skipped_pressure() >= 50,
            "the per-source set stays capped even under a wide window: {}",
            t.skipped_pressure()
        );
    }

    /// #6239 fail-on-revert (the crux): one `cleanup` call must EXAMINE at most
    /// `CLEANUP_BUDGET` candidates, independent of how many sources the table
    /// holds. This is the bound the pre-#6239 `HashMap::retain` sweep violated:
    /// it budgeted only the REMOVALS, so with every entry LIVE (nothing
    /// removable) the closure still ran for EVERY bucket on one packet worker —
    /// an O(sources) full-table scan. Here an attacker populates far more than
    /// the budget of LIVE sources spread across several zones; a single sweep at
    /// a clock inside every window removes nothing yet must still touch at most
    /// `CLEANUP_BUDGET` of them. Reverting `cleanup` to the retain full-walk
    /// makes `examined == per_src.len()` (> the budget) and this goes RED.
    #[test]
    fn cleanup_examines_at_most_budget_per_call() {
        let mut core: ScanCore<u16> = ScanCore::default();
        let total = CLEANUP_BUDGET + 100;
        // Spread the sources across several zones (the "attacker populates
        // sources across many zones" shape from the issue) — all LIVE.
        for i in 0..total {
            let zone = (i % 4) as u16;
            let src = IpAddr::V4(Ipv4Addr::from(0x0a00_0000u32 + i as u32));
            core.check(zone, src, (i & 0xffff) as u16, 1_000, 1_000_000);
        }
        assert_eq!(core.per_src.len(), total);
        core.examined_log.clear();
        // Wide floor + a clock barely past insertion → NOTHING is expired: a
        // retain walk would examine all `total` entries; the cursor examines at
        // most the budget.
        let examined = core.cleanup(1_500, 1_000_000);
        assert!(
            examined <= CLEANUP_BUDGET,
            "cleanup examined {examined} candidates, must be <= CLEANUP_BUDGET \
             ({CLEANUP_BUDGET}) regardless of table size"
        );
        assert_eq!(
            core.examined_log.len(),
            examined,
            "the examination counter and the per-call examined log must agree"
        );
        // Nothing was expired, so nothing was removed — the table is intact and
        // the indexes stay in lock-step.
        assert_eq!(core.per_src.len(), total, "no live entry may be reclaimed");
        core.assert_consistent();
    }

    /// #6239: the persistent cursor eventually visits EVERY source across
    /// enough calls, even when every entry stays LIVE (so no entry is ever
    /// removed and the cursor must genuinely ADVANCE past live entries rather
    /// than re-examining the same prefix). A stuck / non-advancing cursor would
    /// visit only the first `CLEANUP_BUDGET` slots forever and this fails.
    #[test]
    fn cleanup_cursor_eventually_covers_all_live_sources() {
        let mut core: ScanCore<u16> = ScanCore::default();
        let total = CLEANUP_BUDGET * 2 + 5;
        let mut expected: FxHashSet<ScanKey> = FxHashSet::default();
        for i in 0..total {
            let zone = (i % 4) as u16;
            let src = IpAddr::V4(Ipv4Addr::from(0x0a10_0000u32 + i as u32));
            core.check(zone, src, (i & 0xffff) as u16, 1_000, 1_000_000);
            expected.insert((zone, src));
        }
        assert_eq!(core.per_src.len(), total);
        // A wide floor keeps every entry LIVE, so cleanup removes nothing and
        // the cursor must sweep the whole ring to cover it. Run enough calls to
        // wrap the ring at least once.
        let mut seen: FxHashSet<ScanKey> = FxHashSet::default();
        let calls = total.div_ceil(CLEANUP_BUDGET) + 1;
        for _ in 0..calls {
            core.examined_log.clear();
            let examined = core.cleanup(2_000, 1_000_000);
            assert!(examined <= CLEANUP_BUDGET, "still bounded per call");
            for k in &core.examined_log {
                seen.insert(*k);
            }
        }
        assert_eq!(
            core.per_src.len(),
            total,
            "nothing expired, so nothing was reclaimed"
        );
        assert_eq!(
            seen, expected,
            "the cursor must eventually examine EVERY live source across calls"
        );
    }

    /// #6239: `per_src`, `per_zone_srcs`, and `key_ring` stay in perfect
    /// lock-step after a run of bounded cleanups that reclaim only part of the
    /// table (interleaved expired + live sources across zones). The single
    /// `remove_src` primitive must update all three indexes together — the
    /// expired half is fully reclaimed, the live half survives, and the O(1)
    /// zone counts + slot back-pointers remain exact.
    #[test]
    fn indexes_stay_consistent_after_bounded_cleanup() {
        let mut core: ScanCore<u16> = ScanCore::default();
        let total = CLEANUP_BUDGET + 128;
        let mut live_keys: FxHashSet<ScanKey> = FxHashSet::default();
        for i in 0..total {
            let zone = (i % 3) as u16;
            let src = IpAddr::V4(Ipv4Addr::from(0x0a20_0000u32 + i as u32));
            // Even entries open OLD windows (will be reaped); odd entries open
            // RECENT windows (stay live under the floor below).
            let start = if i % 2 == 0 { 0 } else { 5_000_000 };
            core.check(zone, src, (i & 0xffff) as u16, start, 1_000_000);
            if i % 2 != 0 {
                live_keys.insert((zone, src));
            }
        }
        assert_eq!(core.per_src.len(), total);
        // Clock 5.5s: entries opened at t=0 are expired (>= 1s floor), entries
        // opened at t=5s are still live. Several sweeps reclaim the expired half
        // (each sweep must advance the cursor past the interleaved live ones).
        let now = 5_500_000u64;
        let floor = 1_000_000u64;
        for _ in 0..8 {
            core.cleanup(now, floor);
            core.assert_consistent();
        }
        // The live (odd) half survives; the expired (even) half is fully gone.
        assert_eq!(
            core.per_src.len(),
            live_keys.len(),
            "exactly the live half must remain after cleanup drains the expired"
        );
        for k in &live_keys {
            assert!(
                core.per_src.contains_key(k),
                "a live source must not be reclaimed by cleanup"
            );
        }
        core.assert_consistent();
    }

    /// #6239: the bounded cursor still fully drains an all-expired table across
    /// `ceil(N / CLEANUP_BUDGET)` calls (each call removes at most the budget).
    /// This guards the removal path: a source can only be reclaimed if the
    /// cursor examined it, so reaching an empty table proves every slot was
    /// eventually visited, and the per-zone index drains in lock-step.
    #[test]
    fn cleanup_drains_all_expired_within_ceil_calls() {
        let mut core: ScanCore<u16> = ScanCore::default();
        let total = CLEANUP_BUDGET * 3 + 7;
        for i in 0..total {
            let zone = (i % 8) as u16;
            let src = IpAddr::V4(Ipv4Addr::from(0x0a30_0000u32 + i as u32));
            core.check(zone, src, (i & 0xffff) as u16, 0, 1_000_000);
        }
        assert_eq!(core.per_src.len(), total);
        let now = 10_000_000u64; // far past the floor — everything is expired
        let floor = 1_000_000u64;
        let calls = total.div_ceil(CLEANUP_BUDGET);
        for _ in 0..calls {
            let examined = core.cleanup(now, floor);
            assert!(examined <= CLEANUP_BUDGET, "each call stays bounded");
        }
        assert_eq!(
            core.per_src.len(),
            0,
            "ceil(N / CLEANUP_BUDGET) calls must reclaim every expired source"
        );
        assert!(
            core.per_zone_srcs.values().all(|s| s.is_empty()),
            "the per-zone index must drain in lock-step with per_src"
        );
        core.assert_consistent();
    }
    /// #14673 helpers: seed a core with `n` zone-`zone` entries of given
    /// `(src, count, window_start)` directly (O(few), bypasses the cap).
    fn seed_core(
        seed: u64,
        zone: u16,
        specs: &[(IpAddr, u16, u64)],
    ) -> ScanCore<u16> {
        let mut core: ScanCore<u16> = ScanCore::with_seed(seed);
        for (src, count, start) in specs {
            let mut set = FxHashSet::default();
            for p in 0..*count {
                set.insert(8000 + p);
            }
            core.per_src.insert((zone, *src), seed_entry(*start, set));
        }
        core.rebuild_zone_index_for_test();
        core
    }

    /// #14673 decisive regression (static-prefix self-evict): the report's
    /// exact scene recreated in Rust. The first `EVICT_SCAN_LIMIT` entries
    /// of the zone index in iteration order are pinned: 63 at
    /// `SCAN_DETECT_COUNT - 1` (9) and the scanner at 8. Every OTHER zone
    /// entry is at count 1 (thousands of decoys the static prefix never
    /// examines). Pre-fix, `srcs.iter().take(64)` examines exactly that
    /// prefix, so the scanner (8 < 9) is the deterministic lowest-count
    /// victim of the next decoy-triggered eviction and its history is
    /// wiped. Post-fix the sample rotates over `key_ring`, so the decoy
    /// eviction hits a count-1 entry and the scanner survives to trip on
    /// its 10th distinct port. RED on revert to the static prefix.
    #[test]
    fn pinned_prefix_scanner_not_self_evicted_14673() {
        let zone = 1u16;
        let window = 10_000_000u64;
        // Attacker scene: 200 sources. Discover the static-prefix
        // iteration order with a probe core, pick the entry sitting
        // inside the first EVICT_SCAN_LIMIT positions as the scanner
        // (count 8), pin the other 63 prefix entries at count 9, and
        // leave every entry outside the prefix at count 1. Pre-fix the
        // static `take(64)` sampler would evict the scanner (8 < 9);
        // post-fix the rotating ring sample must find a count-1 victim.
        let total = 200usize;
        let probe: ScanCore<u16> = {
            let mut c: ScanCore<u16> = ScanCore::with_seed(0x14673);
            for i in 0..total {
                let s = IpAddr::V4(Ipv4Addr::from(0x0a00_0000u32 + i as u32));
                let mut set = FxHashSet::default();
                set.insert(1u16);
                c.per_src.insert((zone, s), seed_entry(100, set));
            }
            c.rebuild_zone_index_for_test();
            c
        };
        let order: Vec<IpAddr> = probe
            .per_zone_srcs
            .get(&zone)
            .unwrap()
            .iter()
            .copied()
            .collect();
        assert_eq!(order.len(), total);
        let scanner = order[EVICT_SCAN_LIMIT / 2];
        let mut specs: Vec<(IpAddr, u16, u64)> = Vec::new();
        for (pos, ip) in order.iter().enumerate() {
            let count: u16 = if *ip == scanner {
                8
            } else if pos < EVICT_SCAN_LIMIT {
                9
            } else {
                1
            };
            specs.push((*ip, count, 100));
        }
        let mut core = seed_core(0x14673, zone, &specs);
        // One decoy-triggered eviction (new source at cap).
        assert!(core.evict_stalest_in_zone(zone, 1_000, window));
        assert!(
            core.per_src.contains_key(&(zone, scanner)),
            "scanner at count 8 inside a 63x count-9 pinned prefix must NOT \
             be the eviction victim when thousands of count-1 entries exist \
             outside the prefix (#14673 static-prefix self-evict)"
        );
        // The victim must be a count-1 entry outside the pinned prefix.
        // Scanner still trips on its 10th distinct port.
        assert!(!core.check(zone, scanner, 8008, 1_000, window));
        assert!(
            core.check(zone, scanner, 8009, 1_000, window),
            "surviving scanner must trip on its 10th distinct port"
        );
        core.assert_consistent();
    }

    /// #14673 rotation: successive evictions must not re-examine the
    /// identical candidate set. Bounded: each sample <= EVICT_SCAN_LIMIT.
    #[test]
    fn eviction_sample_rotates_across_calls_14673() {
        let zone = 7u16;
        let window = 1_000_000u64;
        let total = EVICT_SCAN_LIMIT * 4;
        let specs: Vec<(IpAddr, u16, u64)> = (0..total)
            .map(|i| {
                (
                    IpAddr::V4(Ipv4Addr::from(0x0a07_0000u32 + i as u32)),
                    // Vary counts so victims differ per window.
                    ((i % 5) + 1) as u16,
                    100 + i as u64,
                )
            })
            .collect();
        let mut core = seed_core(42, zone, &specs);
        assert_eq!(core.per_src.len(), total);
        let mut sets: Vec<FxHashSet<ScanKey>> = Vec::new();
        for _ in 0..3 {
            core.evict_examined_log.clear();
            assert!(core.evict_stalest_in_zone(zone, 1_000, window));
            assert!(
                core.evict_examined_log.len() <= EVICT_SCAN_LIMIT,
                "eviction examined {}, must be <= EVICT_SCAN_LIMIT",
                core.evict_examined_log.len()
            );
            let s: FxHashSet<ScanKey> = core.evict_examined_log.iter().copied().collect();
            sets.push(s);
        }
        assert!(
            sets[0] != sets[1] && sets[1] != sets[2] && sets[0] != sets[2],
            "successive eviction samples must rotate, not repeat the static prefix"
        );
        core.assert_consistent();
    }

    /// #14673 eventual coverage: repeated evictions over a static (no
    /// refill) table eventually examine every entry. Each direct eviction
    /// removes one entry, so refill with a fresh count-1 source after
    /// each eviction to keep the table size constant.
    #[test]
    fn eviction_eventually_covers_all_entries_14673() {
        let zone = 8u16;
        let window = 1_000_000u64;
        let total = 200usize;
        let specs: Vec<(IpAddr, u16, u64)> = (0..total)
            .map(|i| {
                (
                    IpAddr::V4(Ipv4Addr::from(0x0a08_0000u32 + i as u32)),
                    5u16,
                    100,
                )
            })
            .collect();
        let mut core = seed_core(7, zone, &specs);
        let expected: FxHashSet<ScanKey> =
            core.key_ring.iter().copied().collect();
        let mut seen: FxHashSet<ScanKey> = FxHashSet::default();
        let mut fresh_counter: u32 = 0;
        for _ in 0..(total * 3) {
            core.evict_examined_log.clear();
            assert!(core.evict_stalest_in_zone(zone, 1_000, window));
            for k in &core.evict_examined_log {
                seen.insert(*k);
            }
            // Refill to keep the ring size constant.
            fresh_counter += 1;
            let fresh = IpAddr::V4(Ipv4Addr::from(0x0b08_0000u32 + fresh_counter));
            assert!(!core.check(zone, fresh, 80, 1_000, window));
            if expected.is_subset(&seen) {
                break;
            }
        }
        assert!(
            expected.is_subset(&seen),
            "roving eviction must eventually examine every entry (saw {}/{})",
            seen.len(),
            expected.len()
        );
    }

    /// #14673 preserved #6239-style bound under other-zone interleave: an
    /// eviction for a sparse zone must terminate (not walk the whole ring)
    /// while a victim exists.
    #[test]
    fn eviction_bounded_under_other_zone_interleave_14673() {
        let target = 9u16;
        let other = 1u16;
        let window = 1_000_000u64;
        let mut core: ScanCore<u16> = ScanCore::with_seed(99);
        // Many other-zone entries then a few target entries at the tail.
        for i in 0..2_000u32 {
            let s = IpAddr::V4(Ipv4Addr::from(0x0b00_0000u32 + i));
            let mut set = FxHashSet::default();
            set.insert(1u16);
            core.per_src.insert((other, s), seed_entry(100, set));
        }
        let victim = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        for (a, count) in [(1u8, 2u16), (2, 5), (3, 8)] {
            let s = IpAddr::V4(Ipv4Addr::new(203, 0, 113, a));
            let mut set = FxHashSet::default();
            for p in 0..count {
                set.insert(9000 + p);
            }
            core.per_src.insert((target, s), seed_entry(100, set));
            let _ = victim;
        }
        core.rebuild_zone_index_for_test();
        // The rotating ring window may miss the 3 sparse target entries;
        // the bounded per-zone fallback must still find a same-zone victim
        // (least-suspicious among the sampled candidates) without any
        // full-ring scan. Same-zone examination stays <= 2x
        // EVICT_SCAN_LIMIT (window + fallback sample), never O(ring). The
        // victim need not be the global count-2 entry — at saturation the
        // contract is the least-suspicious entry of a bounded sample.
        let before = core.per_src.len();
        core.evict_examined_log.clear();
        assert!(core.evict_stalest_in_zone(target, 1_500, window));
        assert!(
            core.evict_examined_log.len() <= 2 * EVICT_SCAN_LIMIT,
            "same-zone examination must stay <= 2*EVICT_SCAN_LIMIT under interleave, got {}",
            core.evict_examined_log.len()
        );
        assert_eq!(core.per_src.len(), before - 1, "exactly one eviction");
        core.assert_consistent();
    }
    /// #14673 seed sensitivity: the same insertion sequence yields a
    /// different first-sample start under different pinned seeds.
    #[test]
    fn eviction_start_depends_on_seed_14673() {
        let zone = 3u16;
        let window = 1_000_000u64;
        let specs: Vec<(IpAddr, u16, u64)> = (0..128u32)
            .map(|i| {
                (
                    IpAddr::V4(Ipv4Addr::from(0x0a03_0000u32 + i)),
                    3u16,
                    100,
                )
            })
            .collect();
        let first_of = |seed: u64| -> ScanKey {
            let mut core = seed_core(seed, zone, &specs);
            core.evict_examined_log.clear();
            assert!(core.evict_stalest_in_zone(zone, 1_000, window));
            core.evict_examined_log[0]
        };
        let a = first_of(1);
        let b = first_of(0x9e37_79b9_7f4a_7c15);
        let c = first_of(0xdead_beef_cafe_f00d);
        assert!(
            a != b || b != c || a != c,
            "different seeds must reshuffle the first sampled key (got {a:?} {b:?} {c:?})"
        );
    }

    /// #14673 expired-first preserved over the rotating sample.
    #[test]
    fn eviction_rotating_still_prefers_expired_14673() {
        let zone = 5u16;
        let expired_src = IpAddr::V4(Ipv4Addr::new(10, 5, 0, 50));
        let mut specs: Vec<(IpAddr, u16, u64)> = (0..100u32)
            .map(|i| {
                (
                    IpAddr::V4(Ipv4Addr::from(0x0a05_1000u32 + i)),
                    1u16,
                    1_000,
                )
            })
            .collect();
        specs.push((expired_src, 0, 0));
        // Only the empty expired entry (window_start 0) is expired at
        // now=1050 with window 100; every live entry starts at 1000.
        let mut core = seed_core(0, zone, &specs);
        // Set the cursor so the seeded start lands on the expired entry:
        // start = (evict_cursor + seed_offset) % len, seed 0 gives offset 0.
        let pos = core
            .key_ring
            .iter()
            .position(|k| *k == (zone, expired_src))
            .unwrap();
        core.evict_cursor = pos;
        assert!(core.evict_stalest_in_zone(zone, 1_050, 100));
        assert!(
            !core.per_src.contains_key(&(zone, expired_src)),
            "expired entry inside the rotating window must be reclaimed first"
        );
        core.assert_consistent();
    }

    /// #14673 full end-to-end (real `check` fill to the 4096 cap): the
    /// report's cycle repeated — scanner probes 8, decoy triggers an
    /// eviction, scanner probes on — must reach detection. Pre-fix the
    /// scanner is deterministically self-evicted whenever it lands in the
    /// static prefix with the pinned shape; post-fix the rotating sample
    /// evicts count-1 background entries and the scanner accumulates.
    #[test]
    fn scanner_detected_through_decoy_evictions_at_cap_14673() {
        let mut t = PortScanTracker::default();
        let zone = 1u16;
        let window = 10_000_000u64;
        // Fill the zone exactly to the cap with count-1 background sources.
        for i in 0..MAX_SOURCES_PER_ZONE {
            let src = IpAddr::V4(Ipv4Addr::from(0x0a00_0000u32 + i as u32));
            assert!(!t.check(zone, src, 80, 1_000, window));
        }
        assert_eq!(t.tracked_sources(), MAX_SOURCES_PER_ZONE);
        let scanner = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200));
        let mut detected = false;
        let mut next_port: u16 = 2000;
        // Scanner interleaves batches of <=8 probes with fresh decoys.
        // Each decoy admission evicts a background count-1 source (the
        // rotating sample always has count-1 candidates and 8 > 1), never
        // the scanner once admitted. The scanner must reach 10.
        for round in 0..20u32 {
            for _ in 0..8 {
                if t.check(zone, scanner, next_port, 2_000, window) {
                    detected = true;
                }
                next_port += 1;
                if detected {
                    break;
                }
            }
            if detected {
                break;
            }
            let decoy = IpAddr::V4(Ipv4Addr::from(0x0c00_0000u32 + round));
            assert!(!t.check(zone, decoy, 9999, 2_001, window));
            assert!(
                t.core.per_src.contains_key(&(zone, scanner)),
                "scanner must survive decoy-triggered eviction round {round} (#14673)"
            );
        }
        assert!(detected, "scanner must reach SCAN_DETECT_COUNT through decoy evictions");
        assert_eq!(t.tracked_sources(), MAX_SOURCES_PER_ZONE);
    }
}
