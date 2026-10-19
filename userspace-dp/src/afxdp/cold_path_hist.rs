//! #1612 step-3: cold-path latency histogram primitives.
//!
//! This module provides the math + helpers consumed by
//! `worker_cold_path.rs` (counter aggregation) and the cold-path
//! sampling site in `poll_descriptor/mod.rs`. Hot-path callers see:
//!
//! - `sample_tsc_start() -> u64` / `sample_tsc_end() -> u64` —
//!   asymmetric TSC read pair: start does `LFENCE; RDTSCP`, end does
//!   `RDTSCP; LFENCE`, both with `compiler_fence` brackets. Per
//!   Intel SDM §17.17 measurement-window recipe. Wrapper baseline
//!   ~25-40 ns on the loss cluster. (Codex code-r1 finding 1 +
//!   Copilot code-r1: the prior `sample_tsc()` alias was removed
//!   to prevent foot-gun usage at the end of a window.)
//! - `bucket_index_for_ns_48(ns)` — #1635 log-linear 48-bucket select:
//!   32 linear 16-ns buckets over `[0, 512)` ns + 15 pow-2 buckets over
//!   `[512, 2^24)` ns + 1 saturate bucket. Fixes the #1622 F1
//!   bucket-0 resolution floor (a 5-10× p50 error at low rule counts).
//! - `ColdPathSlotMap` + `lookup_slot(map, from, to)` — #1635 DIRECT
//!   `(from_zone_id, to_zone_id) → slot` map (256 slots) built at
//!   config apply. Replaces the splitmix64 16-slot hash that collided
//!   at 88.2% with 8 active zone-pairs (#1622 F2).
//!
//! Each slot keeps a `first_key` + `builder_collision` pair (renamed
//! from `alias_seen` per AGY r1 [1.6]). With the direct map a
//! `builder_collision` should NEVER fire — it indicates the snapshot
//! builder produced two distinct keys for one slot and is treated as a
//! hard error in operator dashboards.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering, compiler_fence};

/// Number of histogram buckets per zone-pair slot.
///
/// #1635: pinned at 48 (was 24). The layout is log-linear:
///   - 32 LINEAR buckets of 16-ns stride covering `[0, 512)` ns
///     (bucket `b` covers `[b*16, (b+1)*16)` for `0 ≤ b ≤ 31`).
///   - 15 EXPONENTIAL buckets covering `[512, 2^24)` ns
///     (bucket `32+i` covers `[2^(9+i), 2^(10+i))` for `0 ≤ i ≤ 14`).
///   - 1 SATURATE bucket (index 47) for `ns ≥ 2^24` (≈16.8 ms).
///
/// The linear band gives ~16-ns resolution in the operator-critical
/// 50-150 ns range that the old pow-2-from-0 layout collapsed into a
/// single 1024-ns bucket-0 (a 5-10× p50 reporting error). See #1622
/// PLAN-KILL finding F1.
pub(in crate::afxdp) const POLICY_COLD_PATH_HIST_BUCKETS: usize = 48;
const _: () = assert!(POLICY_COLD_PATH_HIST_BUCKETS == 48);

/// Number of LINEAR buckets at the low end (16-ns stride, `[0, 512)` ns).
pub(in crate::afxdp) const COLD_PATH_LINEAR_BUCKETS: usize = 32;
/// Linear-band stride in nanoseconds.
pub(in crate::afxdp) const COLD_PATH_LINEAR_STRIDE_NS: u64 = 16;
/// Pivot: first nanosecond value handled by the exponential band.
pub(in crate::afxdp) const COLD_PATH_PIVOT_NS: u64 =
    (COLD_PATH_LINEAR_BUCKETS as u64) * COLD_PATH_LINEAR_STRIDE_NS; // 512
const _: () = assert!(COLD_PATH_PIVOT_NS == 512);

/// Number of per-zone-pair slots in the histogram.
///
/// #1635: pinned at 256 (was 16). The slot map is now a DIRECT
/// `(from_zone_id, to_zone_id) → slot` assignment built at config
/// apply (see [`ColdPathSlotMap`]). 256 gives ~21× headroom over the
/// largest known deployment; wire cost is bounded by SPARSE
/// serialization (only slots with `samples > 0` ride the wire), so
/// the static cap does not impose a per-scrape byte cost.
pub(in crate::afxdp) const POLICY_COLD_PATH_ZONE_PAIR_SLOTS: usize = 256;

/// Number of atomic operations one `publish_from_local` writes, and one
/// `snapshot()` pass reads: every bucket, four metadata fields per slot, plus
/// the two monotonic fields.
///
/// Derived rather than written down, because the last time this surface grew
/// (#1635, 16×24 → 256×48, a 30× increase) the constant was only updated in a
/// doc comment while a second comment and the concurrency test's writer
/// throttle kept the old scale. A reader pass is this expensive, so anything
/// that has to bracket a reader pass — notably the seqlock's even-window —
/// must be sized from it and not from a literal.
pub(in crate::afxdp) const COLD_PATH_PUBLISH_ATOMIC_OPS: usize = POLICY_COLD_PATH_ZONE_PAIR_SLOTS
    * POLICY_COLD_PATH_HIST_BUCKETS
    + POLICY_COLD_PATH_ZONE_PAIR_SLOTS * 4
    + 2;
const _: () = assert!(POLICY_COLD_PATH_ZONE_PAIR_SLOTS == 256);

/// Maximum number of ASSIGNABLE slots. Slot index 255 (`u8::MAX`) is
/// never handed out — the accumulator arrays are 256 wide for alignment
/// and to keep slot indices identity-mapped, and reserving the top index
/// keeps a `u8` slot id unambiguous. Capacity is therefore 255 active
/// zone-pairs (~21× the largest known deployment). #3075: overflow past
/// this capacity (not zone-id magnitude) is the only `overflow_active`
/// trigger now that the slot map is keyed sparsely by the `(from, to)`
/// pair (`ColdPathSlotMap::slot_by_pair`) rather than a 65×65 flat table.
pub(crate) const COLD_PATH_ASSIGNABLE_SLOTS: usize = POLICY_COLD_PATH_ZONE_PAIR_SLOTS - 1;
const _: () = assert!(COLD_PATH_ASSIGNABLE_SLOTS == 255);

// #3075: the old 65×65 flat lookup table (`COLD_PATH_ZONE_DIM` /
// `cold_path_flat_index`, `from * 65 + to`) was removed. Zone ids are now
// stable name-hashes spanning [1,65533] (not sequential 1..MaxZones), so a
// dense table is infeasible and a flat index dropped every pair with an id
// ≥ 65 — silently dark-ing the #1635 histogram for every real config. The
// slot map is now keyed sparsely by the `(from, to)` pair itself
// (`ColdPathSlotMap::slot_by_pair`).

/// Wire/layout version stamped into the status payload (#1635).
pub(in crate::afxdp) const COLD_PATH_LAYOUT_VERSION: u32 = 3;

/// 48-bucket log-linear ns histogram bucket selector.
///
/// #1635 (replaces `bucket_index_for_ns_24`):
///   - `ns < 512`            → linear: `ns / 16` ∈ `[0, 32)`.
///   - `512 ≤ ns < 2^24`     → exponential: `32 + (floor(log2(ns)) - 9)`
///                             ∈ `[32, 47)`.
///   - `ns ≥ 2^24`           → saturate: `47`.
///
/// Branchless within each band; one predicate selects the band.
#[inline]
pub(in crate::afxdp) fn bucket_index_for_ns_48(ns: u64) -> usize {
    if ns < COLD_PATH_PIVOT_NS {
        // Linear band: 16-ns stride, indices [0, 32).
        (ns / COLD_PATH_LINEAR_STRIDE_NS) as usize
    } else {
        // Exponential band: floor(log2(ns)) ∈ [9, +) for ns ≥ 512.
        // log2 = 63 - clz(ns); bucket = 32 + (log2 - 9).
        let log2 = (63 - ns.leading_zeros()) as usize;
        let b = COLD_PATH_LINEAR_BUCKETS + (log2 - 9);
        b.min(POLICY_COLD_PATH_HIST_BUCKETS - 1)
    }
}

/// Inclusive upper boundary in nanoseconds for histogram bucket `idx`,
/// for the Prometheus `le` label. Mirrors [`bucket_index_for_ns_48`]:
///   - `idx < 32`        → `(idx + 1) * 16 - 1`  (15, 31, …, 511).
///   - `32 ≤ idx ≤ 46`   → `2^(10 + idx - 32) - 1` (1023, 2047, …).
///   - `idx ≥ 47`        → `u64::MAX` (rendered as `+Inf` on the wire).
#[inline]
pub(in crate::afxdp) fn bucket_upper_bound_ns_48(idx: usize) -> u64 {
    if idx < COLD_PATH_LINEAR_BUCKETS {
        (idx as u64 + 1) * COLD_PATH_LINEAR_STRIDE_NS - 1
    } else if idx >= POLICY_COLD_PATH_HIST_BUCKETS - 1 {
        u64::MAX
    } else {
        (1u64 << (10 + idx - COLD_PATH_LINEAR_BUCKETS)) - 1
    }
}

/// Pack zone IDs into a u64 key suitable for the slot-map `first_key`
/// collision sentinel. `+ 1` keeps `(0, 0)` from collapsing to the
/// zero "no sample yet" sentinel while preserving injectivity over
/// distinct `(u16, u16)` pairs (Codex r3 finding 1).
#[inline]
pub(in crate::afxdp) fn zone_pair_packed_key(from_zone_id: u16, to_zone_id: u16) -> u64 {
    (((from_zone_id as u64) << 16) | (to_zone_id as u64)) + 1
}

/// #1635: direct `(from_zone_id, to_zone_id) → slot` map built at
/// config-apply time. Replaces the splitmix64 16-slot hash that
/// collided at 88.2% with 8 active zone-pairs (birthday paradox), the
/// F2 finding in the #1622 PLAN-KILL.
///
/// Lookup is a sparse `(from, to) → slot` hash map (#3075: stable
/// name-hash zone ids span [1,65533], so the prior 65×65 flat table was
/// removed). A miss (pair absent) means no slot assigned (capacity
/// exhausted); the sample is dropped at the hot path.
///
/// The map is built from `PolicyState::configured_zone_pairs()`, which
/// (#3783) enumerates not only the EXACT configured zone-pairs but also the
/// concrete pairs implied by the `from-zone any` / `to-zone any` / both-any
/// wildcard tiers (#3090) and by `junos-global` rules (#3148). Without that
/// expansion a wildcard/global-only deployment (the common vSRX catch-all
/// design) produced no exact pairs, so the concrete `(from, to)` a packet
/// traverses had no slot and its first-packet latency sample was silently
/// dropped — the histogram went dark for exactly those configs.
///
/// `inverse[slot]` is the reverse map used by the status path to emit
/// per-zone-pair labels for the sparse wire encoding.
#[derive(Clone, Debug)]
pub(in crate::afxdp) struct ColdPathSlotMap {
    /// Sparse `(from_zone_id, to_zone_id) → slot` map (#3075). Replaces
    /// the old 65×65 flat table: stable name-hash ids span [1,65533], so
    /// a flat `from*65+to` index dropped every pair with an id ≥ 65. A
    /// pair absent from the map = no slot assigned.
    pub(in crate::afxdp) slot_by_pair: std::collections::HashMap<(u16, u16), u8>,
    /// `slot → Some((from, to))` for assigned slots, `None` for free.
    pub(in crate::afxdp) inverse: Vec<Option<(u16, u16)>>,
    /// True if some configured zone-pair could not be assigned a slot
    /// because the 255-slot capacity was exhausted. #15092: also set by
    /// the forwarding build when `configured_zone_pairs_bounded` capped
    /// the wildcard/global expansion before this map saw the pairs.
    pub(in crate::afxdp) overflow_active: bool,
}

impl Default for ColdPathSlotMap {
    fn default() -> Self {
        Self::empty()
    }
}

impl ColdPathSlotMap {
    /// An empty map: every lookup misses.
    pub(in crate::afxdp) fn empty() -> Self {
        Self {
            slot_by_pair: std::collections::HashMap::new(),
            inverse: vec![None; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
            overflow_active: false,
        }
    }

    /// Build a direct slot map from a set of configured zone-pairs,
    /// optionally reusing a previous map's slot assignments so retained
    /// pairs keep their slot (and their accumulated histogram) across a
    /// config apply.
    ///
    /// Returns the new map plus the list of slots that received a NEW
    /// zone-pair (every Pass-2 assignment). The worker zeroes these
    /// slots' accumulators before recording into them so a slot never
    /// carries an EARLIER zone-pair's counts (plan §2.4 / F4).
    ///
    /// Codex code-r1 finding 1: zero-out MUST cover every newly-assigned
    /// slot, not just slots the *immediately previous* map showed as
    /// occupied. The worker-local accumulator can carry stale counts
    /// from ANY earlier config generation (e.g. A assigns slot 0, B
    /// frees it without reuse, C reassigns slot 0 — B's map shows slot 0
    /// free, but the worker never cleared A's counts). Zeroing a
    /// genuinely-fresh slot is a harmless no-op (it is already zero).
    ///
    /// `pairs` should be deduplicated and in a stable order (the caller
    /// passes a `BTreeSet`-derived `Vec`) so slot assignment is
    /// deterministic for a given config.
    pub(in crate::afxdp) fn build(
        previous: Option<&ColdPathSlotMap>,
        pairs: &[(u16, u16)],
    ) -> (Self, Vec<u8>) {
        let mut slot_by_pair: std::collections::HashMap<(u16, u16), u8> =
            std::collections::HashMap::with_capacity(pairs.len());
        let mut inverse: Vec<Option<(u16, u16)>> =
            vec![None; POLICY_COLD_PATH_ZONE_PAIR_SLOTS];
        let mut used = [false; POLICY_COLD_PATH_ZONE_PAIR_SLOTS];
        let mut slots_to_zero: Vec<u8> = Vec::new();
        let mut overflow_active = false;

        // Pass 1: retain slot assignments for pairs that survive from
        // the previous map (so their accumulated histogram is kept).
        let mut pending: Vec<(u16, u16)> = Vec::with_capacity(pairs.len());
        for &(from, to) in pairs {
            // #3075: every (u16, u16) pair is representable — the stable
            // name-hash id space [1,65533] is keyed sparsely by the pair
            // itself, so there is no id-magnitude "unrepresentable" case.
            // `overflow_active` is set only when the SLOT capacity is
            // exhausted (Pass 2).
            let retained = previous.and_then(|p| {
                let s = p.slot_by_pair.get(&(from, to)).copied()?;
                if p.inverse[s as usize] == Some((from, to)) {
                    Some(s)
                } else {
                    None
                }
            });
            match retained {
                Some(s) => {
                    used[s as usize] = true;
                    inverse[s as usize] = Some((from, to));
                    slot_by_pair.insert((from, to), s);
                }
                None => pending.push((from, to)),
            }
        }

        // Pass 2: assign the lowest free slot to each new pair. EVERY
        // newly-assigned slot is queued for zero-out (Codex finding 1) —
        // the worker-local accumulator may carry stale counts from an
        // earlier generation regardless of what `previous` shows.
        let mut next_free = 0usize;
        for &(from, to) in &pending {
            while next_free < COLD_PATH_ASSIGNABLE_SLOTS && used[next_free] {
                next_free += 1;
            }
            if next_free >= COLD_PATH_ASSIGNABLE_SLOTS {
                overflow_active = true;
                break;
            }
            let s = next_free;
            used[s] = true;
            inverse[s] = Some((from, to));
            slot_by_pair.insert((from, to), s as u8);
            // Queue zero-out for every newly-assigned slot when a
            // PREVIOUS map existed — the worker may have accumulated
            // counts for an earlier pair in this slot during any prior
            // generation (Codex finding 1). On the very first build
            // (previous == None) the worker's accumulators are still
            // default-zero, so no zero-out is needed.
            if previous.is_some() {
                slots_to_zero.push(s as u8);
            }
        }

        (
            Self {
                slot_by_pair,
                inverse,
                overflow_active,
            },
            slots_to_zero,
        )
    }
}

/// Look up the slot for `(from, to)` in the direct map. Returns `None`
/// for unmapped pairs (capacity exhausted). #3075: one sparse hash-map
/// probe keyed on the `(from, to)` pair (any u16 zone id), replacing the
/// old 65×65 flat-table index that dropped ids ≥ 65.
#[inline]
pub(in crate::afxdp) fn lookup_slot(map: &ColdPathSlotMap, from: u16, to: u16) -> Option<u8> {
    map.slot_by_pair.get(&(from, to)).copied()
}

/// Read the TSC at the **start** of a measurement window via
/// `LFENCE; RDTSCP` per Intel SDM §17.17.
///
/// Recipe rationale (Codex code-r1 finding 1):
/// - Leading `compiler_fence(SeqCst)` prevents rustc from reordering
///   prior stores past the LFENCE.
/// - `_mm_lfence` drains the load buffer so any preceding load
///   (e.g. flow-cache key reads) commits before the TSC capture.
/// - `__rdtscp` partially serializes on the prior-completion side
///   (waits for all prior instructions to complete) and provides
///   the timestamp.
///
/// **Use `sample_tsc_end()` for the closing timestamp** — RDTSCP
/// alone does NOT prevent subsequent instructions from being
/// dispatched before its retirement, so the end side needs a
/// TRAILING `_mm_lfence()`.
///
/// Returns 0 on non-x86_64 builds; the caller should branch on the
/// `ClockSource` field before using the value.
#[inline]
#[cfg(target_arch = "x86_64")]
pub(in crate::afxdp) fn sample_tsc_start() -> u64 {
    compiler_fence(Ordering::SeqCst);
    unsafe { core::arch::x86_64::_mm_lfence() };
    let mut _aux: u32 = 0;
    let tsc = unsafe { core::arch::x86_64::__rdtscp(&mut _aux) };
    compiler_fence(Ordering::SeqCst);
    tsc
}

/// Read the TSC at the **end** of a measurement window via
/// `RDTSCP; LFENCE` per Intel SDM §17.17.
///
/// Codex code-r1 finding 1 fix: the end side needs a **hardware**
/// `_mm_lfence` AFTER `__rdtscp` to prevent subsequent instructions
/// (e.g. histogram-bucket updates) from being dispatched before the
/// timestamp read retires. A `compiler_fence(SeqCst)` only keeps the
/// compiler honest; aggressive OoO cores (Skylake-X / Ice Lake /
/// Sapphire Rapids) can still hardware-reorder. Wrapper-baseline
/// calibration cannot absorb this — calibration subtracts constant
/// cost, not variable ordering noise.
///
/// Returns 0 on non-x86_64 builds.
#[inline]
#[cfg(target_arch = "x86_64")]
pub(in crate::afxdp) fn sample_tsc_end() -> u64 {
    compiler_fence(Ordering::SeqCst);
    let mut _aux: u32 = 0;
    let tsc = unsafe { core::arch::x86_64::__rdtscp(&mut _aux) };
    unsafe { core::arch::x86_64::_mm_lfence() };
    compiler_fence(Ordering::SeqCst);
    tsc
}

// Copilot code-r1 + Codex code-r1 finding 1: the prior `sample_tsc()`
// alias has been REMOVED to avoid a foot-gun where callers using it
// as an end timestamp would silently skip the trailing `_mm_lfence()`
// required by Intel SDM §17.17. All call sites must now explicitly
// use `sample_tsc_start()` (LFENCE; RDTSCP) at the START of a window
// and `sample_tsc_end()` (RDTSCP; LFENCE) at the END. Tests updated.

#[inline]
#[cfg(not(target_arch = "x86_64"))]
pub(in crate::afxdp) fn sample_tsc_start() -> u64 {
    0
}

#[inline]
#[cfg(not(target_arch = "x86_64"))]
pub(in crate::afxdp) fn sample_tsc_end() -> u64 {
    0
}

/// Per-worker clock source for cold-path latency sampling.
///
/// Worker startup probes `/proc/cpuinfo` for ALL THREE flags
/// `constant_tsc + nonstop_tsc + rdtscp` (Codex code-r1 finding 2:
/// the first two attest TSC stability; the third attests the
/// instruction is legal — x86_64 mandates SSE2 but NOT RDTSCP)
/// AND `/sys/devices/system/clocksource/clocksource0/current_clocksource
/// == tsc`. If ALL FOUR pass, `Tsc` is selected; otherwise
/// `ClockGettime` fallback. The harness gates Scale Target table
/// publication on every worker reporting `Tsc`.
/// #1620 plan v4 (AGY r3 [MED-1]): `#[repr(u8)]` is load-bearing.
/// Embedding a `#[repr(Rust)]` enum inside a `#[repr(C)]` struct
/// (WorkerColdPathCounters) makes the offset of subsequent fields
/// implementation-defined — the compiler may choose a 1, 2, or 4-byte
/// representation. `#[repr(u8)]` pins this to 1 byte so the layout
/// math in plan §4.1 (clock_source at offset 32, alias_seen at 33)
/// holds under the C ABI rules the rest of the struct relies on.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum ClockSource {
    /// TSC unavailable, fall back to `clock_gettime(CLOCK_MONOTONIC_RAW)`.
    ClockGettime = 2,
    /// Invariant TSC available, `rdtscp` is used.
    Tsc = 1,
    /// Unset (worker not yet calibrated).
    Unset = 0,
}

impl ClockSource {
    #[inline]
    pub(in crate::afxdp) fn as_u8(self) -> u8 {
        self as u8
    }

    #[inline]
    pub(in crate::afxdp) fn from_u8(v: u8) -> Self {
        match v {
            1 => ClockSource::Tsc,
            2 => ClockSource::ClockGettime,
            _ => ClockSource::Unset,
        }
    }

    pub(in crate::afxdp) fn as_str(self) -> &'static str {
        match self {
            ClockSource::Tsc => "tsc",
            ClockSource::ClockGettime => "clock_gettime",
            ClockSource::Unset => "",
        }
    }
}

/// Probe the host for TSC invariance + RDTSCP availability. Returns
/// `Tsc` only if ALL THREE conditions hold:
/// - `/proc/cpuinfo` reports `constant_tsc` AND `nonstop_tsc` AND
///   `rdtscp` (Codex code-r1 finding 2: the first two attest TSC
///   stability; `rdtscp` attests the INSTRUCTION itself is legal —
///   x86_64 mandates SSE2 but NOT rdtscp; #UD on missing).
/// - `/sys/devices/system/clocksource/clocksource0/current_clocksource
///   == tsc` (kernel agrees TSC is usable as the active clocksource).
/// Otherwise `ClockGettime` — the sampler will skip RDTSCP entirely
/// and the harness will TSC-gate the run out of the published table.
///
/// Called once per worker at thread spawn AFTER `pthread_setaffinity_np`
/// has pinned the worker to its core (Claude SMR r1 NIT 2). The probe is
/// conservative: it only enables `Tsc` when every `/proc/cpuinfo` block
/// reports `constant_tsc`, `nonstop_tsc`, and `rdtscp`.
pub(in crate::afxdp) fn probe_clock_source() -> ClockSource {
    #[cfg(target_arch = "x86_64")]
    {
        let cpuinfo_ok = std::fs::read_to_string("/proc/cpuinfo")
            .map(|s| {
                // Codex code-r1 finding 2: rdtscp instruction support
                // is NOT implied by constant_tsc/nonstop_tsc. Check it
                // explicitly. Linux exposes the CPUID rdtscp feature
                // flag as the literal token "rdtscp" in the flags line.
                //
                // AGY code-r1 NIT 2: parse the `flags` line as
                // whitespace-separated tokens rather than a free-text
                // substring grep. A virtualized hypervisor or guest
                // admin who sets a custom CPU model name containing
                // any of these tokens would otherwise yield a false-
                // positive probe.
                let mut saw_any_block = false;
                for block in s.split("\n\n").filter(|b| !b.trim().is_empty()) {
                    saw_any_block = true;
                    let flags_line = block
                        .lines()
                        .find(|l| {
                            let trimmed = l.trim_start();
                            trimmed.starts_with("flags")
                                || trimmed.starts_with("Features")
                        })
                        .and_then(|l| l.split(':').nth(1));
                    let Some(flags) = flags_line else {
                        return false;
                    };
                    let tokens: std::collections::HashSet<&str> =
                        flags.split_ascii_whitespace().collect();
                    if !(tokens.contains("constant_tsc")
                        && tokens.contains("nonstop_tsc")
                        && tokens.contains("rdtscp"))
                    {
                        return false;
                    }
                }
                saw_any_block
            })
            .unwrap_or(false);
        let clocksource_ok = std::fs::read_to_string(
            "/sys/devices/system/clocksource/clocksource0/current_clocksource",
        )
        .map(|s| s.trim() == "tsc")
        .unwrap_or(false);
        if cpuinfo_ok && clocksource_ok {
            return ClockSource::Tsc;
        }
    }
    ClockSource::ClockGettime
}

/// Q32 fixed-point `ns_per_tsc_tick` multiplier.
///
/// `delta_ns ≈ (delta_tsc * ns_per_tsc_q32) >> 32`. Computed once at
/// worker startup by measuring TSC ticks against `std::time::Instant`
/// over a 10 ms calibration window (Codex code-r1 finding 3: prior
/// docstring claimed `CLOCK_MONOTONIC_RAW` but the impl uses Rust's
/// `Instant` which is `CLOCK_MONOTONIC`, not raw). For a one-shot
/// calibration on a constant-tsc invariant host the distinction is
/// not measurable; we use `Instant` for portability + no external
/// libc surface.
pub(in crate::afxdp) fn calibrate_ns_per_tsc_q32() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // Copilot code-r2: guard against RDTSCP #UD on x86_64 hosts
        // that don't expose the CPUID rdtscp feature. The probe is
        // cheap (two file reads + token-set parse) and runs once per
        // worker startup; returning 0 here makes the caller's
        // ns_per_tsc_q32 zero, which downstream code treats as
        // "TSC unavailable, use clock_gettime fallback".
        if probe_clock_source() != ClockSource::Tsc {
            return 0;
        }
        use std::time::Instant;
        let start_tsc = sample_tsc_start();
        let start_inst = Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let end_inst = Instant::now();
        let end_tsc = sample_tsc_end();
        let elapsed_ns = end_inst.duration_since(start_inst).as_nanos() as u64;
        let elapsed_tsc = end_tsc.saturating_sub(start_tsc);
        if elapsed_tsc == 0 || elapsed_ns == 0 {
            return 0;
        }
        // ns_per_tsc_q32 = (elapsed_ns << 32) / elapsed_tsc
        //
        // Operator precedence trap (Codex r3 finding 2): `<<` binds
        // LOWER than `/` in Rust, so `(elapsed_ns as u128) << 32 /
        // (elapsed_tsc as u128)` parses as `elapsed_ns << (32 /
        // elapsed_tsc)`, not as the intended `(elapsed_ns << 32) /
        // elapsed_tsc`. Parenthesize the shift explicitly.
        (((elapsed_ns as u128) << 32) / (elapsed_tsc as u128)) as u64
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// Per-worker wrapper-baseline calibration. Runs N=4096 rdtscp/rdtscp
/// pairs (back-to-back) and returns the **median** of the deltas in
/// ns. The median is robust against scheduler jitter; the calibration
/// runs after `pthread_setaffinity_np` has pinned the worker.
///
/// Returns 0 if TSC is unavailable on this target.
pub(in crate::afxdp) fn calibrate_wrapper_baseline_ns(ns_per_tsc_q32: u64) -> u64 {
    if ns_per_tsc_q32 == 0 {
        return 0;
    }
    // Copilot code-r2: same #UD guard as calibrate_ns_per_tsc_q32.
    // A non-zero ns_per_tsc_q32 from a malformed caller (e.g. unit
    // test passing 42) shouldn't bypass the RDTSCP availability gate.
    #[cfg(target_arch = "x86_64")]
    {
        if probe_clock_source() != ClockSource::Tsc {
            return 0;
        }
    }
    const N: usize = 4096;
    let mut deltas = Vec::with_capacity(N);
    for _ in 0..N {
        // Wrapper baseline measures the round-trip between a START
        // timestamp and an END timestamp — the same fence recipe the
        // hot path will use — so the calibration absorbs the correct
        // ordering cost (Codex code-r1 finding 1).
        let a = sample_tsc_start();
        let b = sample_tsc_end();
        deltas.push(b.saturating_sub(a));
    }
    deltas.sort_unstable();
    let median_tsc = deltas[N / 2];
    ((median_tsc as u128 * ns_per_tsc_q32 as u128) >> 32) as u64
}

/// Atomic-publish view of the per-worker cold-path histogram.
///
/// Lives alongside `WorkerRuntimeAtomics` in `worker_runtime.rs`
/// but with its own dedicated `cold_window_gen` field per Codex
/// plan-r1 finding 2 — the cold-path seqlock is INDEPENDENT of the
/// runtime seqlock because the runtime's even-flip only fires inside
/// the 60s window-rotation branch, while cold-path counters must
/// publish every ~1 s tick.
///
/// Publish protocol (every ~1 s; called from `publish()` regardless
/// of whether the 60s rotation branch fires):
///   1. `cold_window_gen.fetch_add(1, AcqRel)` (even → odd).
///   2. Relaxed-store 16 × 24 = 384 bucket counts + 16 × 4 = 64
///      metadata fields (sum_ns / samples / first_key / alias_seen).
///   3. `cold_window_gen.fetch_add(1, Release)` (odd → even).
///
/// Readers Acquire-load `cold_window_gen` (s1), Relaxed-load the
/// payload, `fence(Acquire)`, Relaxed-load `cold_window_gen` (s2).
/// If `s2 == s1` and even, the payload was observed within a single
/// committed epoch.
///
/// #1620 plan v3 Amendment A: `#[repr(C, align(64))]` is load-bearing.
/// `align(64)` was already in #1619 (cacheline isolation). The `C` is
/// added in #1620 so the hot fields (`cold_window_gen`,
/// `ns_per_tsc_q32`, `wrapper_ns_baseline`, `clock_source`) stay at
/// the top of the struct under the compiler's hand. Default
/// `#[repr(Rust)]` is free to reorder fields and would defeat the
/// cacheline-0 hot-set design.
#[repr(C, align(64))]
pub(in crate::afxdp) struct WorkerColdPathAtomics {
    // === HOT FIELDS (cacheline 0; touched on every publish) ===
    /// Per-tick seqlock generation. Separate from
    /// `WorkerRuntimeAtomics.window_gen` per Codex r1 finding 2.
    pub(in crate::afxdp) cold_window_gen: AtomicU64,
    /// #1621 plan v2 (AGY r1 F3 + Codex r1 F5 + Claude SMR r1 F4):
    /// monotonic count of snapshot() calls that exhausted their
    /// retry budget. Incremented by snapshot() ON THE READER
    /// THREAD before returning None. Surfaced as
    /// `xpf_userspace_worker_cold_path_snapshot_failed_total` so
    /// operators can distinguish "no data this scrape" from
    /// "snapshot failed under publish contention".
    pub(in crate::afxdp) snapshot_failed: AtomicU64,
    /// #1620 plan v4 (AGY r3 [HIGH-1]): per-worker monotonic
    /// session-miss counter mirrored from
    /// `WorkerColdPathCounters.sample_phase`. Without this published,
    /// #1621/Prometheus + #1622/harness cannot compute the actual
    /// sampling rate (samples / sample_phase) and cannot validate
    /// that the configured `sample_mask` is being respected.
    pub(in crate::afxdp) sample_phase: AtomicU64,
    /// Calibration: set once at worker startup. Outside the per-tick seqlock.
    pub(in crate::afxdp) ns_per_tsc_q32: AtomicU64,
    /// Calibration: set once at worker startup. Outside the per-tick seqlock.
    pub(in crate::afxdp) wrapper_ns_baseline: AtomicU64,
    /// #1620 plan v4 (AGY r3 AXIS 6 diagnostic): monotonic count of
    /// samples where `raw_ns < wrapper_ns_baseline`. Without this,
    /// `saturating_sub` silently absorbs persistent underflow
    /// (frequency scaling, OoO jitter, ultra-fast policy_eval),
    /// falsely skewing the histogram toward bucket 0.
    pub(in crate::afxdp) wrapper_underflow_count: AtomicU64,
    /// Calibration: set once at worker startup. Outside the per-tick seqlock.
    pub(in crate::afxdp) clock_source: AtomicU8,
    // === COLD FIELDS (written by publish_from_local) ===
    /// #1635 (renamed from `alias_seen`): set true if a sample's packed
    /// key differs from the slot's `first_key`. With the direct slot
    /// map this should NEVER fire; a set bit means the snapshot builder
    /// mapped two distinct zone-pairs to one slot (AGY r1 [1.6]).
    pub(in crate::afxdp) builder_collision: [AtomicBool; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    /// First packed zone-pair key seen in this slot during the current
    /// publish window. Zero = no sample yet.
    pub(in crate::afxdp) first_key: [AtomicU64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) sum_ns: [AtomicU64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) samples: [AtomicU64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) buckets: [[AtomicU64; POLICY_COLD_PATH_HIST_BUCKETS];
        POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
}

impl Default for WorkerColdPathAtomics {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkerColdPathAtomics {
    pub(in crate::afxdp) fn new() -> Self {
        Self {
            cold_window_gen: AtomicU64::new(0),
            snapshot_failed: AtomicU64::new(0),
            sample_phase: AtomicU64::new(0),
            ns_per_tsc_q32: AtomicU64::new(0),
            wrapper_ns_baseline: AtomicU64::new(0),
            wrapper_underflow_count: AtomicU64::new(0),
            clock_source: AtomicU8::new(ClockSource::Unset.as_u8()),
            builder_collision: std::array::from_fn(|_| AtomicBool::new(false)),
            first_key: std::array::from_fn(|_| AtomicU64::new(0)),
            sum_ns: std::array::from_fn(|_| AtomicU64::new(0)),
            samples: std::array::from_fn(|_| AtomicU64::new(0)),
            buckets: std::array::from_fn(|_| {
                std::array::from_fn(|_| AtomicU64::new(0))
            }),
        }
    }

    /// Set the calibration fields. Called once per worker after thread
    /// affinity is set; samples after this call use the calibrated
    /// multiplier.
    pub(in crate::afxdp) fn install_calibration(
        &self,
        ns_per_tsc_q32: u64,
        wrapper_ns_baseline: u64,
        clock_source: ClockSource,
    ) {
        self.ns_per_tsc_q32
            .store(ns_per_tsc_q32, Ordering::Relaxed);
        self.wrapper_ns_baseline
            .store(wrapper_ns_baseline, Ordering::Relaxed);
        self.clock_source
            .store(clock_source.as_u8(), Ordering::Relaxed);
    }

    /// Publish a full snapshot of the worker's local cold-path
    /// counters under the per-tick seqlock.
    ///
    /// #1620 plan v4 (AGY r3 [HIGH-1]): also publishes `sample_phase`
    /// and `wrapper_underflow_count` so external telemetry can
    /// compute the sampling rate (samples / sample_phase) and
    /// observe baseline drift.
    pub(in crate::afxdp) fn publish_from_local(&self, local: &WorkerColdPathCounters) {
        // 1. Bump gen even → odd. AcqRel forbids subsequent Relaxed
        //    stores from being hoisted above this point.
        self.cold_window_gen.fetch_add(1, Ordering::AcqRel);
        // 2. Relaxed-store the payload. #1635 grew this surface from the
        //    old 16×24 dense shape to POLICY_COLD_PATH_ZONE_PAIR_SLOTS ×
        //    POLICY_COLD_PATH_HIST_BUCKETS = 256 × 48, so one publish now
        //    writes 12_288 bucket stores + 256 × 4 metadata + 2 monotonic
        //    = 13_314 atomics, not the ~450 this comment used to claim.
        //    The number matters to readers: a snapshot pass is the same
        //    size, so the seqlock's even-window has to be wide enough for
        //    a whole reader pass or `snapshot()` can never return Some.
        //    See COLD_PATH_PUBLISH_ATOMIC_OPS, which the tests pin.
        self.sample_phase
            .store(local.sample_phase, Ordering::Relaxed);
        self.wrapper_underflow_count
            .store(local.wrapper_underflow_count, Ordering::Relaxed);
        for slot in 0..POLICY_COLD_PATH_ZONE_PAIR_SLOTS {
            for b in 0..POLICY_COLD_PATH_HIST_BUCKETS {
                self.buckets[slot][b].store(local.buckets[slot][b], Ordering::Relaxed);
            }
            self.sum_ns[slot].store(local.sum_ns[slot], Ordering::Relaxed);
            self.samples[slot].store(local.samples[slot], Ordering::Relaxed);
            self.first_key[slot].store(local.first_key[slot], Ordering::Relaxed);
            self.builder_collision[slot]
                .store(local.builder_collision[slot], Ordering::Relaxed);
        }
        // 3. Bump gen odd → even with Release.
        self.cold_window_gen.fetch_add(1, Ordering::Release);
    }

    /// Snapshot for status readers. Seqlock protocol: Acquire-load
    /// `cold_window_gen` (s1), Relaxed-load the full payload, issue
    /// `fence(Acquire)` to seal the Relaxed loads, then Relaxed-load
    /// `cold_window_gen` (s2). If s1 and s2 are equal and even the
    /// payload is coherent.
    ///
    /// AGY code-r2 finding 2: returns `Option<WorkerColdPathCounters>`.
    /// `None` indicates the retry budget exhausted (caller should treat
    /// as "stale, try again next tick"); `Some(_)` is a coherent
    /// payload. Previously `snapshot()` returned `default()` on giveup,
    /// which a Prometheus scraper or the harness could not distinguish
    /// from a legitimately-empty worker, masking retry-starvation
    /// regimes under heavy publish contention.
    ///
    /// AGY code-r2 finding 2 (continued): the retry budget is now 8192
    /// with an exponential `std::hint::spin_loop` backoff. #1635 grew
    /// the payload from the old 16×24 dense surface to 256 slots × 48
    /// buckets, so one publish now writes ~13k atomics instead of ~450.
    /// The larger budget keeps status-path snapshots coherent under a
    /// concurrent publish without changing the hot path.
    pub(in crate::afxdp) fn snapshot(&self) -> Option<WorkerColdPathCounters> {
        const RETRY_BUDGET: u32 = 8192;
        for attempt in 0..RETRY_BUDGET {
            let s1 = self.cold_window_gen.load(Ordering::Acquire);
            if s1 & 1 != 0 {
                // Adaptive backoff: spin a few cycles on early
                // retries, longer on later ones to give a contested
                // writer time to complete its publish cycle.
                for _ in 0..(1u32 << (attempt.min(6))) {
                    std::hint::spin_loop();
                }
                continue;
            }
            let mut out = WorkerColdPathCounters::default();
            // #1620 plan v4 (AGY r3 [HIGH-1]): load sample_phase +
            // wrapper_underflow_count so external telemetry can
            // compute sampling rate and observe baseline drift.
            out.sample_phase = self.sample_phase.load(Ordering::Relaxed);
            out.wrapper_underflow_count = self
                .wrapper_underflow_count
                .load(Ordering::Relaxed);
            for slot in 0..POLICY_COLD_PATH_ZONE_PAIR_SLOTS {
                for b in 0..POLICY_COLD_PATH_HIST_BUCKETS {
                    out.buckets[slot][b] = self.buckets[slot][b].load(Ordering::Relaxed);
                }
                out.sum_ns[slot] = self.sum_ns[slot].load(Ordering::Relaxed);
                out.samples[slot] = self.samples[slot].load(Ordering::Relaxed);
                out.first_key[slot] = self.first_key[slot].load(Ordering::Relaxed);
                out.builder_collision[slot] =
                    self.builder_collision[slot].load(Ordering::Relaxed);
            }
            // Seal Relaxed loads before s2 re-check.
            std::sync::atomic::fence(Ordering::Acquire);
            let s2 = self.cold_window_gen.load(Ordering::Relaxed);
            if s2 == s1 {
                out.ns_per_tsc_q32 = self.ns_per_tsc_q32.load(Ordering::Relaxed);
                out.wrapper_ns_baseline = self.wrapper_ns_baseline.load(Ordering::Relaxed);
                out.clock_source = ClockSource::from_u8(self.clock_source.load(Ordering::Relaxed));
                return Some(out);
            }
            std::hint::spin_loop();
        }
        // Retry budget exhausted — return None so the caller can
        // distinguish from a legitimately-empty worker (AGY code-r2
        // finding 2). A Prometheus scraper sees this as "stale", not
        // as "all zeros".
        //
        // #1621 plan v2 (AGY r1 F3 + Codex r1 F5): also bump the
        // snapshot_failed counter so operators can DETECT this regime
        // via `xpf_userspace_worker_cold_path_snapshot_failed_total`
        // rather than only see an empty payload.
        self.snapshot_failed.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// #1621 plan v2: Counter accessor for the snapshot-failed counter.
    /// Used by the coordinator status path to emit a Prometheus metric
    /// even when `snapshot()` returns None.
    pub(in crate::afxdp) fn snapshot_failed_count(&self) -> u64 {
        self.snapshot_failed.load(Ordering::Relaxed)
    }

    /// #1635 (plan §2.4): atomically zero one slot's accumulator
    /// fields. Called by the owning worker on its next tick after a
    /// config apply reassigns the slot to a new zone-pair, so the
    /// reused slot never carries the previous pair's counts. Stores are
    /// Relaxed under the same single-writer discipline as
    /// `publish_from_local`; the caller runs this inside the worker's
    /// publish path so the seqlock brackets it.
    pub(in crate::afxdp) fn zero_slot(&self, idx: usize) {
        debug_assert!(idx < POLICY_COLD_PATH_ZONE_PAIR_SLOTS);
        for b in 0..POLICY_COLD_PATH_HIST_BUCKETS {
            self.buckets[idx][b].store(0, Ordering::Relaxed);
        }
        self.sum_ns[idx].store(0, Ordering::Relaxed);
        self.samples[idx].store(0, Ordering::Relaxed);
        self.first_key[idx].store(0, Ordering::Relaxed);
        self.builder_collision[idx].store(false, Ordering::Relaxed);
    }
}

/// Worker-local mutable cold-path counters. Touched only by the
/// owning worker thread on the hot path. The owner writes
/// non-atomically; the publisher (same thread) `store(Relaxed)` into
/// `WorkerColdPathAtomics` under the cold_window_gen seqlock.
///
/// #1620 plan v3 Amendment A: `#[repr(C)]` is load-bearing. The hot
/// fields (`sample_phase`, `ns_per_tsc_q32`, `wrapper_ns_baseline`,
/// `clock_source`) are declared FIRST so the hot-path read pattern
/// (`sample_phase` + mask, `ns_per_tsc_q32` + `wrapper_ns_baseline`
/// in the q32-skip block) hits cacheline 0. Without `#[repr(C)]` the
/// default `#[repr(Rust)]` is free to reorder fields to optimize
/// packing, which would destroy the hot-cacheline isolation.
///
/// Verified layout (AGY r2 axis 2 + Claude SMR r3 cross-check; offsets
/// re-derived for the #1635 256-slot / 48-bucket sizes):
///   [0..7]      sample_phase
///   [8..15]     ns_per_tsc_q32
///   [16..23]    wrapper_ns_baseline
///   [24..31]    wrapper_underflow_count
///   [32]        clock_source (enum #[repr(u8)])
///   [33..288]   builder_collision [bool; 256] (alignment 1, no padding)
///   [288..295]  PADDING                       (to align next u64 array)
///   first_key / sum_ns / samples / buckets follow as [_; 256] arrays.
///
/// The hot-path read set (sample_phase, ns_per_tsc_q32,
/// wrapper_ns_baseline, clock_source) still lands in cacheline 0
/// ([0..63]); the cold per-slot arrays start at offset 33.
#[repr(C)]
#[derive(Clone, Debug)]
pub(in crate::afxdp) struct WorkerColdPathCounters {
    // === HOT FIELDS (cacheline 0, read on every session-miss) ===
    /// v3 sample-phase counter: worker-local monotonic counter
    /// incremented on every session-miss path through the policy-
    /// eval site. NOT a per-poll BatchCounters accumulator. The
    /// sample gate is `phase & sample_mask == 0`.
    pub(in crate::afxdp) sample_phase: u64,
    /// Mirror of `WorkerColdPathAtomics.ns_per_tsc_q32`. Read on
    /// every sampled packet inside the q32-skip block.
    pub(in crate::afxdp) ns_per_tsc_q32: u64,
    /// Calibrated wrapper baseline (sample_tsc_start/end pair cost).
    /// Subtracted from `raw_ns` per #1620 plan v3 Amendment B so the
    /// recorded delta reflects only the policy_eval body cost.
    pub(in crate::afxdp) wrapper_ns_baseline: u64,
    /// #1620 plan v4 (AGY r3 AXIS 6 diagnostic): monotonic count of
    /// samples where `raw_ns < wrapper_ns_baseline`. Worker-local
    /// mirror of `WorkerColdPathAtomics.wrapper_underflow_count`.
    pub(in crate::afxdp) wrapper_underflow_count: u64,
    /// Per-worker clock source set once at startup.
    pub(in crate::afxdp) clock_source: ClockSource,
    // === COLD FIELDS (written only when sample fires) ===
    /// #1635 (renamed from `alias_seen`): per-slot flag set when a
    /// sample arrives with a key different from `first_key`. With the
    /// direct slot map this is a builder-bug signal, not an aliasing
    /// gate. Once true, stays true for the publish window.
    pub(in crate::afxdp) builder_collision: [bool; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    /// First packed zone-pair key per slot (0 = none).
    pub(in crate::afxdp) first_key: [u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) sum_ns: [u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) samples: [u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
    pub(in crate::afxdp) buckets:
        [[u64; POLICY_COLD_PATH_HIST_BUCKETS]; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
}

impl Default for WorkerColdPathCounters {
    fn default() -> Self {
        Self {
            sample_phase: 0,
            ns_per_tsc_q32: 0,
            wrapper_ns_baseline: 0,
            wrapper_underflow_count: 0,
            clock_source: ClockSource::Unset,
            builder_collision: [false; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
            first_key: [0u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
            sum_ns: [0u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
            samples: [0u64; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
            buckets: [[0u64; POLICY_COLD_PATH_HIST_BUCKETS]; POLICY_COLD_PATH_ZONE_PAIR_SLOTS],
        }
    }
}

impl WorkerColdPathCounters {
    /// #1635 hot-path sample record. The caller resolves `slot` via
    /// [`lookup_slot`] against the per-config `ColdPathSlotMap` and
    /// skips the call entirely on a miss, so this fn never needs to
    /// hash. `from_zone_id` / `to_zone_id` are still passed so the
    /// `first_key` / `builder_collision` invariant can detect a builder
    /// bug (two distinct pairs mapped to one slot). Inlined; only
    /// invoked at the sampling rate.
    #[inline]
    pub(in crate::afxdp) fn record_sample(
        &mut self,
        slot: u8,
        from_zone_id: u16,
        to_zone_id: u16,
        delta_ns: u64,
    ) {
        let slot = slot as usize;
        debug_assert!(slot < POLICY_COLD_PATH_ZONE_PAIR_SLOTS);
        let bucket = bucket_index_for_ns_48(delta_ns);
        self.buckets[slot][bucket] = self.buckets[slot][bucket].saturating_add(1);
        self.sum_ns[slot] = self.sum_ns[slot].saturating_add(delta_ns);
        self.samples[slot] = self.samples[slot].saturating_add(1);
        // builder_collision invariant: with the direct slot map every
        // sample in a slot MUST carry the same packed key. A mismatch
        // means the snapshot builder mapped two pairs to one slot.
        let key = zone_pair_packed_key(from_zone_id, to_zone_id);
        if self.first_key[slot] == 0 {
            self.first_key[slot] = key;
        } else if self.first_key[slot] != key {
            self.builder_collision[slot] = true;
        }
    }

    /// #1635 (plan §2.4): zero one slot's local accumulator. Called by
    /// the owning worker when a config apply reassigns the slot, before
    /// the first `record_sample` into the new zone-pair.
    #[inline]
    pub(in crate::afxdp) fn zero_slot(&mut self, slot: usize) {
        debug_assert!(slot < POLICY_COLD_PATH_ZONE_PAIR_SLOTS);
        self.buckets[slot] = [0u64; POLICY_COLD_PATH_HIST_BUCKETS];
        self.sum_ns[slot] = 0;
        self.samples[slot] = 0;
        self.first_key[slot] = 0;
        self.builder_collision[slot] = false;
    }
}

#[cfg(test)]
#[path = "cold_path_hist_tests.rs"]
mod tests;
