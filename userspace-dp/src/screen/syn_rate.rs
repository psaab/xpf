//! Per-zone per-key flood rate limiter — a count-min sketch of limiter cells
//! (#3315 SYN-flood per-source/per-destination; #4112 ICMP/UDP per-destination).
//!
//! `source-threshold` and `destination-threshold` cap the SYN/s rate for a
//! single source IP or destination IP, distinct from the aggregate per-zone
//! `attack-threshold`. The aggregate counter cannot express them: a single hot
//! destination (a victim, possibly flooded from spoofed sources) can be driven
//! hard while the zone aggregate stays under budget, and `destination-threshold`
//! exists precisely to cap that.
//!
//! The same substrate backs the per-destination ICMP/UDP flood caps (#4112):
//! Junos measures `icmp flood` / `udp flood threshold` PER DESTINATION (UDP
//! additionally per destination PORT), not per zone aggregate. `increment` keys
//! on the destination IP (ICMP, and a port-less UDP fragment — #4567);
//! `increment_ip_port` mixes the destination port in (UDP with a real L4 port).
//! The per-zone aggregate `TokenBucket` is retained as a coarser SECONDARY
//! ceiling above these per-destination caps.
//!
//! ## The cell type is generic over [`SketchCell`] (#5805)
//!
//! The sketch is parameterized over its per-cell limiter so the SAME count-min
//! structure serves two consumers with different admission semantics:
//!
//! - The #3315 SYN per-source / per-destination sketches (`for_dst` /
//!   `for_src`) and the #4112 / #5805 ICMP/UDP per-destination flood sketches
//!   (`for_flood_dst`) all use `TokenBucket` cells
//!   (`SynRateSketch<TokenBucket>`). A flood cap is a pure rate gate: a
//!   destination or source parked at exactly `threshold` events/second must
//!   stay admitted STEADILY. `RateCounter` collapsed it to ~0 after the first
//!   second (count-all whole-second window, #5805; SYN sketches #13954 — a
//!   dst/src trip is a HARD drop, not a recoverable response, so the
//!   count-all over-throttle was not defensible there either); the token
//!   bucket refills continuously so the configured rate is honoured, while a
//!   sub-millisecond boundary straddle still sees at most `threshold` tokens
//!   (#2937 preserved) and an over-threshold destination is still limited DOWN
//!   to the rate. The SYN sketches admit via the same all-row
//!   prepare/commit transaction as the flood sketch, so phase-staggered rows
//!   cannot multiply the sustained rate (#10319). `RateCounter` cells remain
//!   available for deliberate count-all consumers (SYN aggregate / alarm).
//!
//! ## Substrate — count-min sketch of `SketchCell`s, NO eviction
//!
//! The limiter is a **count-min sketch (CMS)**: `ROWS` independent rows of
//! `cols` cells. A key (an IP) maps, via `ROWS` INDEPENDENT seeded hashes, to
//! one cell per row. `increment` advances and counts the key in all `ROWS`
//! cells and reports whether it is over the threshold.
//!
//! Trip semantics depend on the cell type, and the two MUST NOT be conflated:
//!
//! - Count-all `RateCounter` cells (retained only for test seams now): trip
//!   ⟺ EVERY row reports over-threshold — the classic CMS `min`-read
//!   (`min_i(trailing_sum_i) > threshold`), implemented as the logical **AND**
//!   of the per-row results. It MUST be AND/MIN, never OR/MAX: an OR/MAX
//!   inversion would blow the false-positive rate from `(load)^ROWS` to
//!   `~ROWS*load`. Pinned by `some_but_not_all_rows_does_not_trip` on an
//!   explicit `RateCounter` sketch.
//! - `TokenBucket` cells (ALL production sketches since #13954: SYN dst/src
//!   and ICMP/UDP flood): admission is an all-row prepare/commit transaction
//!   (#10319) — an event is admitted only when EVERY selected row holds a
//!   token, then every row consumes one. A single drained row therefore
//!   blocks admission. This is DELIBERATELY stricter than AND/MIN counting:
//!   it is what bounds the sustained admitted rate to the configured
//!   threshold even when rows are phase-staggered (a min-read token sketch
//!   would let staggered rows multiply the rate, #10319). The tradeoff is
//!   accepted and explicit: the `(load)^ROWS` CMS false-positive bound does
//!   NOT apply to token sketches — a key colliding with a hot key in ANY
//!   one row is throttled at that row's rate (false-positive ~`ROWS*load`,
//!   still fail-closed: collisions never admit an over-threshold key).
//!   Pinned on the production SYN constructors by
//!   `syn_sketch_one_drained_row_blocks_admission_13954`.
//!
//! ### Why a count-min sketch and not an eviction cache
//!
//! Any BOUNDED *eviction* structure (set-associative cache, stalest-eviction
//! hash map) has two collision-starvation modes a flooder can exploit:
//! **Hot-Set Lockout** (a victim whose slots are already taken by hot keys is
//! never tracked, so it never trips) and a **Cold-Start Eviction Race** (a
//! victim ramping 0→threshold is the coldest entry and gets evicted/reset
//! before it can cross). The CMS has NO eviction and NO per-key slot: every key
//! is ALWAYS mapped to its `ROWS` cells. `TokenBucket` cells refill
//! continuously, so a victim's own over-threshold flood still drives all
//! rows over threshold (each row must hold a token for admission).
//! Flood `TokenBucket` cells are different: refill makes their state decrease,
//! and the flood sketch therefore uses an all-row prepare/commit transaction.
//! A flood event is admitted only when EVERY selected row has a token, then
//! all rows consume one token atomically; a phase-staggered set of rows cannot
//! multiply the configured sustained rate.
//!
//! ### Fail-CLOSED collision bias
//!
//! Collisions can only OVER-estimate a key's rate (another hot key sharing a
//! cell consumes capacity), never under-estimate it. Both cell types therefore
//! fail closed: a real flood cannot evade its selected rows, while a
//! legitimate key may be throttled when collisions exhaust every row. The
//! flood sketch's atomic token transaction additionally bounds the sustained
//! admitted rate to the configured threshold (apart from its configured burst
//! capacity). For a security rate limiter, over-count is the correct bias.
//!
//! ### Per-source saturation under spoofing
//!
//! Under a heavy spoofed flood the distinct-source cardinality explodes and the
//! per-source sketch would saturate (every cell hot → all legit sources
//! throttled). This is bounded NOT by the structure but by the caller's gate:
//! the per-source sketch is consulted ONLY when the zone is not SYN-cookie
//! active, and the zone goes cookie-active exactly when the aggregate
//! `attack-threshold` trips (the high-cardinality regime). So per-source CMS
//! only runs in the sub-aggregate regime, where source cardinality is bounded
//! and the sketch is accurate. Per-destination has no such concern (destination
//! cardinality is bounded by the real forwarded-server set) and always runs.
//!
//! ## Cost / memory
//!
//! Per non-validated initial SYN with the feature enabled: `ROWS` cell
//! `increment`s per consulted sketch (each an integer add + compare; one cache
//! line of cells per row) plus the all-row reduction. No allocation, no rehash, no
//! eviction scan — steady-state AND under a spoofed flood. Allocated once at
//! config for zones that configure a threshold; freed when disabled.
//!
//! Both `RateCounter` and `TokenBucket` cells are ≈ 16 B, so the per-cell size
//! (and thus the sketch's memory bound) is identical whichever cell the sketch
//! carries. Per configured zone, per worker: per-dest `ROWS*DST_COLS*16 = 64
//! KiB` + per-source `ROWS*SRC_COLS*16 = 128 KiB` = 192 KiB/zone, ×
//! num_workers. Fixed at construction, never resized — bounded by the Go
//! commit-time memory advisory.

use super::rate::{RateCounter, TokenBucket};
use crate::hot_hash_seed::HotPathSeededState;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::IpAddr;

/// One count-min sketch cell: charge an event and report whether the key is
/// OVER its per-cell limit. This abstracts the two per-cell limiters the sketch
/// can carry so the count-min structure (rows, seeded hashing, all-row update,
/// AND/MIN reduction) is written ONCE and shared:
///
/// - [`RateCounter`] — the count-all two-bucket sliding window. Retained for
///   deliberate count-all consumers where "admitted" means "skip a recoverable
///   security response" (the SYN-flood aggregate that activates SYN cookies /
///   raises the alarm).
/// - [`TokenBucket`] — the monotonic-nanosecond shaper (#3607). Used by the
///   #4112 / #5805 ICMP/UDP per-destination FLOOD sketches and, since #13954,
///   the #3315 SYN per-source / per-destination sketches: pure rate gates that
///   MUST admit a key parked at exactly `threshold` events/second without
///   collapsing after the first second (the #5805 / #13954 fix), because a
///   dst/src trip is a hard drop.
///
/// Both cells are 16 bytes, so the sketch's `ROWS*cols*16` memory bound is
/// identical for either. `now` is a monotonic time value whose UNIT is defined
/// by the impl — wall/monotonic SECONDS for `RateCounter`, monotonic
/// NANOSECONDS for `TokenBucket` — and the caller passes the matching clock
/// (the batch-cached `loop_now_ns` for every `TokenBucket` sketch).
pub(super) trait SketchCell: Clone + Default {
    /// Charge one event against this cell; return `true` when the key is
    /// OVER LIMIT (drop) and `false` when admitted.
    fn charge(&mut self, now: u64, threshold: u32) -> bool;

    /// Whether this cell participates in the two-phase all-row admission
    /// transaction used by flood sketches (#10319).
    const ATOMIC_ADMIT: bool = false;

    /// Prepare one admission without consuming it. The default preserves the
    /// existing single-cell semantics for count-all `RateCounter` sketches.
    fn prepare_admit(&mut self, now: u64, threshold: u32) -> bool {
        !self.charge(now, threshold)
    }

    /// Commit a prepared admission. Count-all cells have no second phase.
    fn commit_admit(&mut self) {}
}

impl SketchCell for RateCounter {
    #[inline]
    fn charge(&mut self, now_secs: u64, threshold: u32) -> bool {
        self.increment(now_secs, threshold)
    }
}

impl SketchCell for TokenBucket {
    #[inline]
    fn charge(&mut self, now_ns: u64, threshold: u32) -> bool {
        // The single-cell API retains consume-on-admit semantics for the
        // aggregate flood bucket and test seams. The sketch itself uses the
        // all-row transaction below.
        self.admit_is_over(now_ns, threshold)
    }

    const ATOMIC_ADMIT: bool = true;

    #[inline]
    fn prepare_admit(&mut self, now_ns: u64, threshold: u32) -> bool {
        TokenBucket::prepare_admit(self, now_ns, threshold)
    }

    #[inline]
    fn commit_admit(&mut self) {
        TokenBucket::commit_admit(self)
    }
}

/// Number of independent hash rows (`d`). 4 keeps the over-count false-positive
/// rate (`~load^4`) below noise while bounding the per-packet cache-line touches.
pub(super) const ROWS: usize = 4;

/// Columns (`w`) for the per-DESTINATION sketch. Power of two for mask indexing.
pub(super) const DST_COLS: usize = 1024;

/// Columns (`w`) for the per-SOURCE sketch — wider than DST because the
/// (gated, sub-aggregate) source cardinality can still exceed the bounded
/// destination set.
pub(super) const SRC_COLS: usize = 2048;

// Compile-time invariant: the `& (cols - 1)` index masking is only correct for
// power-of-two column counts.
const _: () = assert!(DST_COLS.is_power_of_two() && SRC_COLS.is_power_of_two());

/// Independent per-row seeds. Distinct values so the `ROWS` rows hash
/// independently — same-seed rows would collapse the sketch to a single row and
/// inflate the false-positive rate (it never affects the fail-closed bias).
///
/// These fixed per-row constants provide row INDEPENDENCE, not secrecy. FxHash
/// updates its state additively, so the hash difference for a chosen key pair
/// is independent of the per-boot seed; address-word deltas can therefore form
/// predictable colliding families across restarts (#12789). The per-boot
/// `SynRateSketch::seed` (drawn once from `hot_hash_seed::hot_path_hash_seed`,
/// #2364) is used by the keyed hash in `cell_index` and `cell_index_ip_port`,
/// preventing offline construction of those key-pair collisions.
const ROW_SEEDS: [u64; ROWS] = [
    0x9E37_79B9_7F4A_7C15,
    0xC2B2_AE3D_27D4_EB4F,
    0x1656_67B1_9E37_79F9,
    0x27D4_EB2F_1656_67C5,
];

/// Count-min sketch of [`SketchCell`]s with no eviction. See module docs.
///
/// Generic over the per-cell limiter `C`. The SYN per-source /
/// per-destination sketches (#3315, #13954) and the ICMP/UDP per-destination
/// flood sketches (#5805) use `SynRateSketch<TokenBucket>` so a
/// sustained-at-threshold key is admitted at the configured rate rather than
/// collapsing after the first second.
pub(super) struct SynRateSketch<C = RateCounter> {
    /// `ROWS` rows of `cols` cells. `Box<[Box<[C]>]>` is allocated once at
    /// construction and never resized — the hot path only indexes.
    rows: Box<[Box<[C]>]>,
    /// Index mask (`cols - 1`); `cols` is a power of two.
    mask: usize,
    /// Per-boot secret folded into the cell hash alongside `ROW_SEEDS[row]`
    /// (#4382). Drawn once from `hot_hash_seed::hot_path_hash_seed()` at
    /// construction and stable for the process lifetime, so a given key maps to
    /// a stable cell across its whole window (counting behaviour unchanged) while
    /// the key→cell mapping is unpredictable off-box and reshuffles on every
    /// restart — the attacker cannot precompute a colliding source-IP set.
    seed: u64,
}

impl<C: SketchCell> SynRateSketch<C> {
    /// Seed-parameterized generic core. Builds `ROWS` rows of `cols`
    /// default-initialised cells. Split out so adversarial tests can pin the
    /// seed and assert (a) intra-seed stability of the key→cell mapping and (b)
    /// cross-seed reshuffling — mirroring `FlowCache::set_index_seeded`.
    /// Production allocates through the typed `with_cols` / `for_flood_dst`
    /// constructors, which supply the per-boot process seed. Both cell types
    /// cold-start correctly from `default()` (an empty `RateCounter` window / a
    /// cold `TokenBucket` that begins FULL on first use).
    fn build_seeded(cols: usize, seed: u64) -> Self {
        debug_assert!(
            cols.is_power_of_two(),
            "SynRateSketch cols must be a power of two"
        );
        let rows = (0..ROWS)
            .map(|_| vec![C::default(); cols].into_boxed_slice())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            rows,
            mask: cols - 1,
            seed,
        }
    }

    /// Cell index for `ip` in row `row` (independent seeded hash, masked to the
    /// column count).
    #[inline]
    fn cell_index(&self, row: usize, ip: &IpAddr) -> usize {
        let mut h = HotPathSeededState::new(self.seed).build_hasher();
        (ROW_SEEDS[row], ip).hash(&mut h);
        (h.finish() as usize) & self.mask
    }

    /// Count one event for `ip` and report whether `ip` is over `threshold`.
    ///
    /// `now` is the cell's clock unit — `now_secs` for a `RateCounter` sketch,
    /// the batch-cached `loop_now_ns` for a `TokenBucket` sketch.
    ///
    /// Count-all cells retain their historical non-short-circuiting AND
    /// semantics. Flood cells use a two-phase transaction: every selected
    /// row must have a token before any row consumes one (#10319).
    pub(super) fn increment(&mut self, ip: &IpAddr, now: u64, threshold: u32) -> bool {
        let mut indices = [0usize; ROWS];
        for (row, slot) in indices.iter_mut().enumerate() {
            *slot = self.cell_index(row, ip);
        }
        self.increment_indices(indices, now, threshold)
    }

    /// Apply one event to a set of row cells. `true` means drop.
    fn increment_indices(&mut self, indices: [usize; ROWS], now: u64, threshold: u32) -> bool {
        if C::ATOMIC_ADMIT {
            let mut all_admit = true;
            for (row, &idx) in indices.iter().enumerate() {
                all_admit &= self.rows[row][idx].prepare_admit(now, threshold);
            }
            if all_admit {
                for (row, &idx) in indices.iter().enumerate() {
                    self.rows[row][idx].commit_admit();
                }
            }
            !all_admit
        } else {
            let mut over_all = true;
            for (row, &idx) in indices.iter().enumerate() {
                let over = self.rows[row][idx].charge(now, threshold);
                over_all &= over;
            }
            over_all
        }
    }

    /// Cell index for `(ip, port)` in row `row`: the seeded per-row hash of the
    /// address WITH the L4 destination port mixed in. Keys the per-DESTINATION
    /// UDP flood sketch on `(dst_ip, dst_port)` — matching Junos `udp flood
    /// threshold`, which caps the rate to a destination IP AND port (#4112).
    #[inline]
    fn cell_index_ip_port(&self, row: usize, ip: &IpAddr, port: u16) -> usize {
        let mut h = HotPathSeededState::new(self.seed).build_hasher();
        (ROW_SEEDS[row], ip, port).hash(&mut h);
        (h.finish() as usize) & self.mask
    }

    /// Count one packet for `(ip, port)` and report whether it is over
    /// `threshold`. Mirrors `increment` but keys on the L4 destination port too
    /// — the UDP per-destination-port flood cap (#4112 F18).
    pub(super) fn increment_ip_port(
        &mut self,
        ip: &IpAddr,
        port: u16,
        now: u64,
        threshold: u32,
    ) -> bool {
        let mut indices = [0usize; ROWS];
        for (row, slot) in indices.iter_mut().enumerate() {
            *slot = self.cell_index_ip_port(row, ip, port);
        }
        self.increment_indices(indices, now, threshold)
    }

    /// Total cell capacity (`ROWS * cols`). Test seam to assert no growth under a
    /// flood (the structure is fixed-capacity).
    #[cfg(test)]
    pub(super) fn capacity(&self) -> usize {
        self.rows.iter().map(|r| r.len()).sum()
    }

    /// The `ROWS` cell indices `ip` maps to. Test seam for the AND-not-OR test.
    #[cfg(test)]
    pub(super) fn cell_indices(&self, ip: &IpAddr) -> [usize; ROWS] {
        let mut out = [0usize; ROWS];
        for (row, slot) in out.iter_mut().enumerate() {
            *slot = self.cell_index(row, ip);
        }
        out
    }

    /// The `ROWS` cell indices `(ip, port)` maps to. Test seam for the
    /// #10319 port-keyed desync cell (mirrors `cell_indices`).
    #[cfg(test)]
    pub(super) fn cell_indices_ip_port(&self, ip: &IpAddr, port: u16) -> [usize; ROWS] {
        let mut out = [0usize; ROWS];
        for (row, slot) in out.iter_mut().enumerate() {
            *slot = self.cell_index_ip_port(row, ip, port);
        }
        out
    }

    /// Charge one selected cell at a caller-provided time. Test seam for
    /// constructing phase-staggered token buckets without collider search.
    #[cfg(test)]
    pub(super) fn charge_cell(&mut self, row: usize, col: usize, now: u64, threshold: u32) {
        self.rows[row][col].charge(now, threshold);
    }

    /// Directly drive a specific `(row, col)` cell over `threshold`, simulating
    /// colliding hot keys without searching for collider IPs. Test seam only.
    /// Charges the cell `threshold + 1` times at the SAME `now`, which drives a
    /// `RateCounter` window strictly above `threshold` AND drains a `TokenBucket`
    /// cell to empty (cold-start capacity is `threshold`), so the cell reports
    /// over-limit for either cell type.
    #[cfg(test)]
    pub(super) fn saturate_cell(&mut self, row: usize, col: usize, now: u64, threshold: u32) {
        for _ in 0..=threshold {
            self.rows[row][col].charge(now, threshold);
        }
    }
}

impl SynRateSketch<RateCounter> {
    /// Seed-pinned `RateCounter` constructor (test seam). Production SYN
    /// sketches are `TokenBucket` since #13954; this remains for the
    /// count-all cell-mapping / hash-vector tests.
    fn with_cols_seeded(cols: usize, seed: u64) -> Self {
        Self::build_seeded(cols, seed)
    }
}

impl SynRateSketch<TokenBucket> {
    fn with_cols(cols: usize) -> Self {
        Self::build_seeded(cols, crate::hot_hash_seed::hot_path_hash_seed())
    }

    /// Seed-pinned `TokenBucket` constructor. Production calls through
    /// `with_cols` / `for_dst` / `for_src` / `for_flood_dst`; adversarial
    /// tests pin the seed to assert key->cell mapping stability and
    /// cross-seed reshuffling.
    fn with_cols_seeded(cols: usize, seed: u64) -> Self {
        Self::build_seeded(cols, seed)
    }

    /// Allocate the per-DESTINATION SYN sketch (`DST_COLS` columns) with
    /// monotonic-ns `TokenBucket` cells (#13954, ex-#3315 `RateCounter`).
    /// A dst trip is a hard drop, so the configured rate must be honoured
    /// steadily; the all-row transaction bounds sustained admission to the
    /// rate (plus the cold-start burst capacity = threshold, #2937).
    pub(super) fn for_dst() -> Self {
        Self::with_cols(DST_COLS)
    }

    /// Allocate the per-SOURCE SYN sketch (`SRC_COLS` columns), `TokenBucket`
    /// cells (#13954, ex-#3315 `RateCounter`).
    pub(super) fn for_src() -> Self {
        Self::with_cols(SRC_COLS)
    }

    /// Allocate the per-DESTINATION ICMP/UDP FLOOD sketch (`DST_COLS` columns)
    /// with monotonic-ns `TokenBucket` cells (#5805). A distinct constructor
    /// name (not `for_dst`) keeps the flood-path sketch unambiguously separate
    /// from the SYN-path `SynRateSketch::for_dst()`. The token bucket admits a
    /// destination parked at exactly `threshold` events/second steadily (the
    /// #5805 fix) while still bounding a burst to capacity (#2937) and limiting
    /// an over-threshold destination down to the configured rate.
    pub(super) fn for_flood_dst() -> Self {
        Self::build_seeded(DST_COLS, crate::hot_hash_seed::hot_path_hash_seed())
    }
}

#[cfg(test)]
#[path = "syn_rate_tests.rs"]
mod tests;
