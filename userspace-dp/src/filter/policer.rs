// Token-bucket and three-color policer state for the userspace filter path.
//
// #5390: the metered hot path is LOCK-FREE. `ThreeColorPolicerState` splits
// into an immutable `ThreeColorPolicerConfig` (mode/rates/bursts/treatments,
// set once at compile) and a cache-line-isolated `ThreeColorPolicerHot`
// carrying only atomics: the two token buckets packed into ONE `AtomicU64`
// (committed in the high 32 bits, peak/excess in the low 32) plus per-rate
// `last_refill_ns` `AtomicU64`s. `meter()` is `&self` and mutates state through
// bounded `compare_exchange_weak` retry loops — the RSS-spread flow aggregate
// (6 workers on the mlx5 VF) no longer serializes on a per-packet
// `Mutex<ThreeColorPolicerState>` futex. Both buckets live in the same atomic
// word so a green consume (which debits committed AND peak in trTCM) commits
// atomically; the shared-lease v8 pattern (afxdp/types/shared_cos_lease) is the
// precedent. The aggregate CIR/PIR/CBS/PBS contract is preserved EXACTLY (all
// workers still meter one shared bucket) — only the synchronization primitive
// changed from a Mutex to lock-free CAS.

use std::sync::atomic::{AtomicU64, Ordering};

// #5390: token buckets are byte-granular u32 counts packed two-per-`AtomicU64`.
// A Junos policer burst-size is bounded far below 4 GiB; clamp to the packed
// range so pack/unpack never overlaps. (Pre-#5390 the buckets were scaled u128
// `bytes × 1e9`; the sub-byte fractional credit that scaling preserved is now
// carried across refills by rewinding `last_refill_ns`, exactly as
// `afxdp::cos::token_bucket::refill_cos_tokens` does — see `compute_refill_add`.)
const TOKEN_BYTE_CAP: u64 = u32::MAX as u64;

// `last_refill_ns` sentinel meaning "never metered". A real monotonic
// `now_ns` (ktime since boot) is never `u64::MAX`, so this cleanly separates
// the uninitialized bucket from one legitimately stamped at `t == 0` (the
// unit-test clock starts at 0). On first touch the bucket is already at its
// burst cap from construction, so the sentinel path only stamps the timestamp
// and adds no tokens — matching the pre-#5390 `initialized` first-refill.
const UNINITIALIZED_NS: u64 = u64::MAX;

const NANOS_PER_SEC: u128 = 1_000_000_000;

#[inline(always)]
fn clamp_burst(bytes: u64) -> u64 {
    bytes.min(TOKEN_BYTE_CAP)
}

#[inline(always)]
fn pack_tokens(committed: u64, peak: u64) -> u64 {
    debug_assert!(committed <= TOKEN_BYTE_CAP);
    debug_assert!(peak <= TOKEN_BYTE_CAP);
    (committed << 32) | (peak & 0xffff_ffff)
}

#[inline(always)]
fn unpack_tokens(v: u64) -> (u64, u64) {
    (v >> 32, v & 0xffff_ffff)
}

/// Compute the whole-byte token grant for one bucket over `[last_ns, now_ns]`
/// at `rate_bytes_per_sec`, returning `(added_bytes, advance_to_ns)` or `None`
/// when the timestamp must NOT advance (no time elapsed, zero rate, or less
/// than one whole byte accrued — the sub-byte credit keeps accumulating against
/// the original `last_ns`, the #4261 low-rate dust fix).
///
/// `added_bytes` is capped at `TOKEN_BYTE_CAP` so the later `min(space)` at the
/// call site stays within the packed u32 range; `advance_to_ns` is rewound by
/// the time-equivalent of the ungranted sub-byte remainder so cumulative grant
/// equals `floor(total_elapsed × rate / 1e9)` — the same conservation the
/// pre-#5390 scaled-`u128` bucket had, and the same rewind `refill_cos_tokens`
/// performs. `rate × elapsed` is computed in `u128` and never overflows for any
/// `u64` inputs `((2^64-1)^2 < u128::MAX)`.
#[inline]
fn compute_refill_add(rate_bytes_per_sec: u64, last_ns: u64, now_ns: u64) -> Option<(u64, u64)> {
    if now_ns <= last_ns || rate_bytes_per_sec == 0 {
        return None;
    }
    let elapsed_ns = now_ns - last_ns;
    let scaled = u128::from(elapsed_ns) * u128::from(rate_bytes_per_sec);
    let added_full = scaled / NANOS_PER_SEC;
    if added_full == 0 {
        // No whole byte accrued: leave `last_ns` untouched so the fractional
        // credit is not discarded (low-rate classes never refill otherwise).
        return None;
    }
    let remainder = scaled - added_full * NANOS_PER_SEC;
    // `remainder < 1e9` and `rate >= 1`, so `leftover_ns < 1e9` and (since
    // `added_full >= 1` implies `elapsed_ns >= 1e9 / rate`) `leftover_ns <=
    // elapsed_ns`; `now_ns - leftover_ns` stays in `[last_ns, now_ns]`.
    let leftover_ns = (remainder / u128::from(rate_bytes_per_sec)) as u64;
    let added = added_full.min(u128::from(TOKEN_BYTE_CAP)) as u64;
    Some((added, now_ns - leftover_ns))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PacketColor {
    Green,
    Yellow,
    Red,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ThreeColorMode {
    SingleRate,
    TwoRate,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ColorTreatment {
    pub(crate) dscp_rewrite: Option<u8>,
    pub(crate) drop: bool,
}

impl ColorTreatment {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn rewrite(dscp: u8) -> Self {
        Self {
            dscp_rewrite: Some(dscp & 0x3f),
            drop: false,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn drop() -> Self {
        Self {
            dscp_rewrite: None,
            drop: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ThreeColorTreatments {
    pub(crate) green: ColorTreatment,
    pub(crate) yellow: ColorTreatment,
    pub(crate) red: ColorTreatment,
}

impl ThreeColorTreatments {
    fn treatment_for(self, color: PacketColor) -> ColorTreatment {
        match color {
            PacketColor::Green => self.green,
            PacketColor::Yellow => self.yellow,
            PacketColor::Red => self.red,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ThreeColorDecision {
    pub(crate) color: PacketColor,
    pub(crate) dscp_rewrite: Option<u8>,
    pub(crate) drop: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PolicerConfigError {
    ZeroRate,
    ZeroBurst,
    PeakRateBelowCommittedRate,
    PeakBurstBelowCommittedBurst,
}

/// Immutable per-policer shape: mode, rates, (clamped) bursts, color-mode, and
/// per-color treatments. Set once at compile and only READ on the hot path, so
/// it carries no interior mutability and drives `same_runtime_shape`. Bursts
/// are clamped to `TOKEN_BYTE_CAP` for the packed token representation; rates
/// stay full `u64` (a 100 Gbps policer is ~1.25e10 bytes/s, above `u32::MAX`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ThreeColorPolicerConfig {
    mode: ThreeColorMode,
    color_blind: bool,
    committed_rate_bytes_per_sec: u64,
    committed_burst_bytes: u64,
    peak_or_excess_rate_bytes_per_sec: u64,
    peak_or_excess_burst_bytes: u64,
    treatments: ThreeColorTreatments,
}

/// #5390: cache-line-isolated hot state. `#[repr(align(64))]` keeps the CAS
/// word off the cache line of the runtime's `Relaxed` per-color counters so
/// contention on one does not false-share the other. `credits` packs both
/// token buckets (committed high 32 bits, peak/excess low 32) so a green
/// consume debits both atomically in one CAS. `committed_last_refill_ns` /
/// `peak_last_refill_ns` are the per-rate refill clocks (srTCM uses only the
/// committed clock; the excess bucket is fed by committed overflow).
#[repr(align(64))]
#[derive(Debug)]
pub(crate) struct ThreeColorPolicerHot {
    credits: AtomicU64,
    committed_last_refill_ns: AtomicU64,
    peak_last_refill_ns: AtomicU64,
}

impl ThreeColorPolicerHot {
    fn new(committed_burst_bytes: u64, peak_or_excess_burst_bytes: u64) -> Self {
        Self {
            // Start both buckets at their burst caps (a freshly-installed
            // policer admits a full burst) — matches the pre-#5390 constructor
            // that seeded `committed_tokens = scaled(committed_burst)`.
            credits: AtomicU64::new(pack_tokens(committed_burst_bytes, peak_or_excess_burst_bytes)),
            committed_last_refill_ns: AtomicU64::new(UNINITIALIZED_NS),
            peak_last_refill_ns: AtomicU64::new(UNINITIALIZED_NS),
        }
    }
}

/// Compact RFC 2697/2698 policer. Metering is lock-free (`meter(&self)` via CAS
/// over `hot`); the shape lives in `config`.
#[derive(Debug)]
pub(crate) struct ThreeColorPolicerState {
    config: ThreeColorPolicerConfig,
    hot: ThreeColorPolicerHot,
}

impl ThreeColorPolicerState {
    pub(crate) fn fail_closed(color_blind: bool) -> Self {
        Self {
            config: ThreeColorPolicerConfig {
                mode: ThreeColorMode::Unsupported,
                color_blind,
                committed_rate_bytes_per_sec: 0,
                committed_burst_bytes: 0,
                peak_or_excess_rate_bytes_per_sec: 0,
                peak_or_excess_burst_bytes: 0,
                treatments: ThreeColorTreatments::default(),
            },
            hot: ThreeColorPolicerHot::new(0, 0),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn sr_tcm(
        committed_rate_bytes_per_sec: u64,
        committed_burst_bytes: u64,
        excess_burst_bytes: u64,
        color_blind: bool,
    ) -> Result<Self, PolicerConfigError> {
        Self::sr_tcm_with_treatments(
            committed_rate_bytes_per_sec,
            committed_burst_bytes,
            excess_burst_bytes,
            color_blind,
            ThreeColorTreatments::default(),
        )
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn sr_tcm_with_treatments(
        committed_rate_bytes_per_sec: u64,
        committed_burst_bytes: u64,
        excess_burst_bytes: u64,
        color_blind: bool,
        treatments: ThreeColorTreatments,
    ) -> Result<Self, PolicerConfigError> {
        if committed_rate_bytes_per_sec == 0 {
            return Err(PolicerConfigError::ZeroRate);
        }
        if committed_burst_bytes == 0 || excess_burst_bytes == 0 {
            return Err(PolicerConfigError::ZeroBurst);
        }
        let committed_burst_bytes = clamp_burst(committed_burst_bytes);
        let excess_burst_bytes = clamp_burst(excess_burst_bytes);
        Ok(Self {
            config: ThreeColorPolicerConfig {
                mode: ThreeColorMode::SingleRate,
                color_blind,
                committed_rate_bytes_per_sec,
                committed_burst_bytes,
                peak_or_excess_rate_bytes_per_sec: 0,
                peak_or_excess_burst_bytes: excess_burst_bytes,
                treatments,
            },
            hot: ThreeColorPolicerHot::new(committed_burst_bytes, excess_burst_bytes),
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn tr_tcm(
        committed_rate_bytes_per_sec: u64,
        committed_burst_bytes: u64,
        peak_rate_bytes_per_sec: u64,
        peak_burst_bytes: u64,
        color_blind: bool,
    ) -> Result<Self, PolicerConfigError> {
        Self::tr_tcm_with_treatments(
            committed_rate_bytes_per_sec,
            committed_burst_bytes,
            peak_rate_bytes_per_sec,
            peak_burst_bytes,
            color_blind,
            ThreeColorTreatments::default(),
        )
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn tr_tcm_with_treatments(
        committed_rate_bytes_per_sec: u64,
        committed_burst_bytes: u64,
        peak_rate_bytes_per_sec: u64,
        peak_burst_bytes: u64,
        color_blind: bool,
        treatments: ThreeColorTreatments,
    ) -> Result<Self, PolicerConfigError> {
        if committed_rate_bytes_per_sec == 0 || peak_rate_bytes_per_sec == 0 {
            return Err(PolicerConfigError::ZeroRate);
        }
        if committed_burst_bytes == 0 || peak_burst_bytes == 0 {
            return Err(PolicerConfigError::ZeroBurst);
        }
        if peak_rate_bytes_per_sec < committed_rate_bytes_per_sec {
            return Err(PolicerConfigError::PeakRateBelowCommittedRate);
        }
        if peak_burst_bytes < committed_burst_bytes {
            return Err(PolicerConfigError::PeakBurstBelowCommittedBurst);
        }
        let committed_burst_bytes = clamp_burst(committed_burst_bytes);
        let peak_burst_bytes = clamp_burst(peak_burst_bytes);
        Ok(Self {
            config: ThreeColorPolicerConfig {
                mode: ThreeColorMode::TwoRate,
                color_blind,
                committed_rate_bytes_per_sec,
                committed_burst_bytes,
                peak_or_excess_rate_bytes_per_sec: peak_rate_bytes_per_sec,
                peak_or_excess_burst_bytes: peak_burst_bytes,
                treatments,
            },
            hot: ThreeColorPolicerHot::new(committed_burst_bytes, peak_burst_bytes),
        })
    }

    /// Meter one packet. Lock-free: refills through per-rate timestamp CAS then
    /// consumes tokens through a bounded `compare_exchange_weak` loop over the
    /// packed `credits` word. `&self` (not `&mut self`): the state is shared
    /// across all workers behind an `Arc` and metered concurrently — the
    /// #5390 fix that removed the per-packet `Mutex`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn meter(
        &self,
        now_ns: u64,
        packet_bytes: u64,
        incoming_color: PacketColor,
    ) -> ThreeColorDecision {
        if self.config.mode == ThreeColorMode::Unsupported {
            return ThreeColorDecision {
                color: PacketColor::Red,
                dscp_rewrite: None,
                drop: true,
            };
        }
        self.refill(now_ns);
        let effective_incoming_color = if self.config.color_blind {
            PacketColor::Green
        } else {
            incoming_color
        };
        let color = self.consume(packet_bytes, effective_incoming_color);
        let treatment = self.config.treatments.treatment_for(color);
        ThreeColorDecision {
            color,
            dscp_rewrite: treatment.dscp_rewrite,
            drop: treatment.drop,
        }
    }

    pub(crate) fn mode_name(&self) -> &'static str {
        match self.config.mode {
            ThreeColorMode::SingleRate => "single-rate",
            ThreeColorMode::TwoRate => "two-rate",
            ThreeColorMode::Unsupported => "unsupported",
        }
    }

    pub(crate) fn color_blind(&self) -> bool {
        self.config.color_blind
    }

    /// Create an independent token bucket with this immutable config shape.
    pub(crate) fn fresh_instance(&self) -> Self {
        Self {
            config: self.config,
            hot: ThreeColorPolicerHot::new(
                self.config.committed_burst_bytes,
                self.config.peak_or_excess_burst_bytes,
            ),
        }
    }

    /// Two runtimes are shape-equivalent (token/counter state reusable across a
    /// snapshot refresh) iff their immutable configs match. No lock: `config`
    /// is plain data.
    pub(crate) fn same_runtime_shape(&self, other: &Self) -> bool {
        self.config == other.config
    }

    fn refill(&self, now_ns: u64) {
        match self.config.mode {
            ThreeColorMode::SingleRate => self.refill_sr_tcm(now_ns),
            ThreeColorMode::TwoRate => self.refill_tr_tcm(now_ns),
            ThreeColorMode::Unsupported => {}
        }
    }

    /// srTCM refill: the committed bucket fills at CIR; overflow past CBS spills
    /// into the excess bucket (capped at EBS). One rate → one timestamp.
    fn refill_sr_tcm(&self, now_ns: u64) {
        loop {
            let last = self.hot.committed_last_refill_ns.load(Ordering::Acquire);
            if last == UNINITIALIZED_NS {
                if self
                    .hot
                    .committed_last_refill_ns
                    .compare_exchange(UNINITIALIZED_NS, now_ns, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return;
                }
                continue;
            }
            let Some((added, advance_to)) =
                compute_refill_add(self.config.committed_rate_bytes_per_sec, last, now_ns)
            else {
                return;
            };
            if self
                .hot
                .committed_last_refill_ns
                .compare_exchange(last, advance_to, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                // Lost the timestamp advance to another worker — it owns this
                // window's credit add. Re-observe; no double refill.
                continue;
            }
            // Won the window: add `added` bytes, committed-first, overflow to
            // excess. Retry the packed-credits CAS until it lands.
            loop {
                let credits = self.hot.credits.load(Ordering::Acquire);
                let (committed, peak) = unpack_tokens(credits);
                let committed_space = self.config.committed_burst_bytes.saturating_sub(committed);
                let committed_add = added.min(committed_space);
                let excess_add = added - committed_add;
                let excess_space = self
                    .config
                    .peak_or_excess_burst_bytes
                    .saturating_sub(peak);
                let new_credits =
                    pack_tokens(committed + committed_add, peak + excess_add.min(excess_space));
                if self
                    .hot
                    .credits
                    .compare_exchange_weak(credits, new_credits, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return;
                }
            }
        }
    }

    /// trTCM refill: committed fills at CIR, peak fills at PIR, independently
    /// (two rates → two timestamps).
    fn refill_tr_tcm(&self, now_ns: u64) {
        self.refill_independent_bucket(now_ns, self.config.committed_rate_bytes_per_sec, true);
        self.refill_independent_bucket(
            now_ns,
            self.config.peak_or_excess_rate_bytes_per_sec,
            false,
        );
    }

    /// Refill one independent-rate bucket (`committed` when `is_committed`, else
    /// `peak`) into its half of the packed `credits` word. Same win-the-window
    /// timestamp CAS as srTCM; only this bucket's half is mutated so a
    /// concurrent sibling-bucket refill retries and both converge.
    fn refill_independent_bucket(&self, now_ns: u64, rate_bytes_per_sec: u64, is_committed: bool) {
        let (ts, burst) = if is_committed {
            (
                &self.hot.committed_last_refill_ns,
                self.config.committed_burst_bytes,
            )
        } else {
            (
                &self.hot.peak_last_refill_ns,
                self.config.peak_or_excess_burst_bytes,
            )
        };
        loop {
            let last = ts.load(Ordering::Acquire);
            if last == UNINITIALIZED_NS {
                if ts
                    .compare_exchange(UNINITIALIZED_NS, now_ns, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return;
                }
                continue;
            }
            let Some((added, advance_to)) = compute_refill_add(rate_bytes_per_sec, last, now_ns)
            else {
                return;
            };
            if ts
                .compare_exchange(last, advance_to, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            loop {
                let credits = self.hot.credits.load(Ordering::Acquire);
                let (committed, peak) = unpack_tokens(credits);
                let new_credits = if is_committed {
                    let space = burst.saturating_sub(committed);
                    pack_tokens(committed + added.min(space), peak)
                } else {
                    let space = burst.saturating_sub(peak);
                    pack_tokens(committed, peak + added.min(space))
                };
                if self
                    .hot
                    .credits
                    .compare_exchange_weak(credits, new_credits, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return;
                }
            }
        }
    }

    /// Classify + debit one packet against the (already refilled) buckets via a
    /// bounded CAS loop. Byte-granular thresholds are identical to the pre-#5390
    /// scaled-`u128` decision (the `× 1e9` scale cancels in every comparison). A
    /// Red packet consumes nothing, so it returns without a CAS.
    fn consume(&self, cost: u64, incoming_color: PacketColor) -> PacketColor {
        loop {
            let credits = self.hot.credits.load(Ordering::Acquire);
            let (committed, peak) = unpack_tokens(credits);
            match self.config.mode {
                ThreeColorMode::SingleRate => {
                    if incoming_color == PacketColor::Green && committed >= cost {
                        let new = pack_tokens(committed - cost, peak);
                        if self
                            .hot
                            .credits
                            .compare_exchange_weak(
                                credits,
                                new,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                        {
                            return PacketColor::Green;
                        }
                        continue;
                    }
                    if incoming_color != PacketColor::Red && peak >= cost {
                        let new = pack_tokens(committed, peak - cost);
                        if self
                            .hot
                            .credits
                            .compare_exchange_weak(
                                credits,
                                new,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                        {
                            return PacketColor::Yellow;
                        }
                        continue;
                    }
                    return PacketColor::Red;
                }
                ThreeColorMode::TwoRate => {
                    if incoming_color == PacketColor::Green && peak >= cost && committed >= cost {
                        let new = pack_tokens(committed - cost, peak - cost);
                        if self
                            .hot
                            .credits
                            .compare_exchange_weak(
                                credits,
                                new,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                        {
                            return PacketColor::Green;
                        }
                        continue;
                    }
                    if incoming_color != PacketColor::Red && peak >= cost {
                        let new = pack_tokens(committed, peak - cost);
                        if self
                            .hot
                            .credits
                            .compare_exchange_weak(
                                credits,
                                new,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                        {
                            return PacketColor::Yellow;
                        }
                        continue;
                    }
                    return PacketColor::Red;
                }
                ThreeColorMode::Unsupported => return PacketColor::Red,
            }
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn sr_tcm(
        committed_rate_bytes_per_sec: u64,
        committed_burst_bytes: u64,
        excess_burst_bytes: u64,
        color_blind: bool,
    ) -> ThreeColorPolicerState {
        ThreeColorPolicerState::sr_tcm(
            committed_rate_bytes_per_sec,
            committed_burst_bytes,
            excess_burst_bytes,
            color_blind,
        )
        .expect("valid srTCM config")
    }

    fn tr_tcm(
        committed_rate_bytes_per_sec: u64,
        committed_burst_bytes: u64,
        peak_rate_bytes_per_sec: u64,
        peak_burst_bytes: u64,
        color_blind: bool,
    ) -> ThreeColorPolicerState {
        ThreeColorPolicerState::tr_tcm(
            committed_rate_bytes_per_sec,
            committed_burst_bytes,
            peak_rate_bytes_per_sec,
            peak_burst_bytes,
            color_blind,
        )
        .expect("valid trTCM config")
    }

    #[test]
    fn srTCM_green_yellow_red_at_thresholds() {
        let policer = sr_tcm(100, 100, 50, true);

        let green = policer.meter(0, 100, PacketColor::Green);
        let yellow = policer.meter(0, 50, PacketColor::Green);
        let red = policer.meter(0, 1, PacketColor::Green);

        assert_eq!(green.color, PacketColor::Green);
        assert_eq!(yellow.color, PacketColor::Yellow);
        assert_eq!(red.color, PacketColor::Red);
    }

    #[test]
    fn srTCM_c_overflow_refills_e_bucket() {
        let policer = sr_tcm(100, 100, 200, true);

        let first = policer.meter(0, 150, PacketColor::Green);
        assert_eq!(first.color, PacketColor::Yellow);

        let green = policer.meter(1_000_000_000, 100, PacketColor::Green);
        assert_eq!(green.color, PacketColor::Green);

        let yellow = policer.meter(1_000_000_000, 150, PacketColor::Green);
        assert_eq!(yellow.color, PacketColor::Yellow);
    }

    #[test]
    fn trTCM_independent_CIR_PIR() {
        let policer = tr_tcm(100, 100, 200, 200, true);

        let initial = policer.meter(0, 100, PacketColor::Green);
        assert_eq!(initial.color, PacketColor::Green);

        let yellow = policer.meter(500_000_000, 100, PacketColor::Green);
        assert_eq!(yellow.color, PacketColor::Yellow);

        let green = policer.meter(1_000_000_000, 100, PacketColor::Green);
        assert_eq!(green.color, PacketColor::Green);
    }

    #[test]
    fn color_aware_never_promotes_incoming_yellow_or_red() {
        let sr_policer = sr_tcm(100, 100, 100, false);

        let yellow = sr_policer.meter(0, 50, PacketColor::Yellow);
        let red = sr_policer.meter(0, 50, PacketColor::Red);

        assert_eq!(yellow.color, PacketColor::Yellow);
        assert_eq!(red.color, PacketColor::Red);

        let tr_policer = tr_tcm(100, 100, 100, 100, false);

        let yellow = tr_policer.meter(0, 50, PacketColor::Yellow);
        let red = tr_policer.meter(0, 50, PacketColor::Red);

        assert_eq!(yellow.color, PacketColor::Yellow);
        assert_eq!(red.color, PacketColor::Red);
    }

    #[test]
    fn color_blind_ignores_incoming_color() {
        let policer = sr_tcm(100, 100, 100, true);

        let green = policer.meter(0, 50, PacketColor::Red);

        assert_eq!(green.color, PacketColor::Green);
    }

    #[test]
    fn burst_clamps_to_packed_u32_range_without_panic() {
        // #5390: bursts beyond the packed u32 byte range clamp rather than
        // overflow the two-buckets-in-one-u64 layout. A max-realistic frame
        // still meters green against the (clamped-full) committed bucket, and
        // the metering never panics on boundary inputs.
        let policer = sr_tcm(u64::MAX, u64::MAX, u64::MAX, true);
        let jumbo = policer.meter(0, 9_000, PacketColor::Green);
        assert_eq!(jumbo.color, PacketColor::Green);
        // A full-u32 packet still fits the clamped committed bucket after a
        // refill — no panic, no wraparound.
        let refilled = policer.meter(1_000_000_000, u32::MAX as u64, PacketColor::Green);
        assert_eq!(refilled.color, PacketColor::Green);
    }

    #[test]
    fn three_color_dscp_rewrite() {
        let treatments = ThreeColorTreatments {
            green: ColorTreatment::rewrite(10),
            yellow: ColorTreatment::rewrite(20),
            red: {
                let mut treatment = ColorTreatment::drop();
                treatment.dscp_rewrite = Some(30);
                treatment
            },
        };
        let policer =
            ThreeColorPolicerState::sr_tcm_with_treatments(100, 100, 50, true, treatments)
                .expect("valid srTCM config");

        let green = policer.meter(0, 100, PacketColor::Green);
        let yellow = policer.meter(0, 50, PacketColor::Green);
        let red = policer.meter(0, 1, PacketColor::Green);

        assert_eq!(green.dscp_rewrite, Some(10));
        assert!(!green.drop);
        assert_eq!(yellow.dscp_rewrite, Some(20));
        assert!(!yellow.drop);
        assert_eq!(red.dscp_rewrite, Some(30));
        assert!(red.drop);
    }

    #[test]
    fn hot_state_is_cacheline_aligned() {
        // #5390: the CAS word must sit on its own cache line, isolated from the
        // runtime's Relaxed per-color counters (no false sharing under load).
        assert_eq!(std::mem::align_of::<ThreeColorPolicerHot>(), 64);
    }

    #[test]
    fn low_rate_refill_carries_sub_byte_dust() {
        // #4261 conservation, preserved by the byte-granular rewind: a bucket
        // that accrues < 1 whole byte per meter call must still refill over
        // time rather than stall (the pre-#5390 scaled-u128 bucket kept the
        // fraction in the token count; the atomic bucket keeps it in the
        // rewound timestamp). CIR = 1000 B/s, CBS = 100 B: after draining, a
        // stream of 1 ns steps (each accruing 1e-6 bytes) must eventually
        // re-admit green rather than stall forever.
        let policer = sr_tcm(1000, 100, 100, true);
        assert_eq!(
            policer.meter(0, 100, PacketColor::Green).color,
            PacketColor::Green
        );
        // Bucket empty; single-nanosecond ticks each accrue 1e-6 bytes.
        let mut admitted = 0u64;
        for step in 1..=200_000_000u64 {
            if policer.meter(step, 1, PacketColor::Green).color == PacketColor::Green {
                admitted += 1;
            }
            if admitted >= 50 {
                break;
            }
        }
        assert!(
            admitted >= 50,
            "sub-byte dust must accrue into whole-byte green admissions, got {admitted}"
        );
    }

    #[test]
    fn concurrent_meter_is_lock_free_and_preserves_trTCM_thresholds() {
        // #5390 fail-on-revert: hammer ONE shared policer from many threads
        // through `&self` metering (the shared-Arc contract the Mutex revert
        // cannot satisfy — `ThreeColorPolicerState::meter` would be `&mut self`
        // again and this shared-borrow call would not compile). The aggregate
        // green bytes must EXACTLY equal the committed burst budget: trTCM color
        // thresholds hold under concurrent CAS with no torn / lost / double
        // updates.
        //
        // CIR = 1e9 B/s, CBS = 1e6 B, PIR = 2e9 B/s, PBS = 2e6 B. All meters
        // share now_ns = 0 (no refill), so admitted green bytes are bounded by
        // the initial committed burst CBS = 1e6 B; the offered load
        // (8×20000×100 = 16e6 B) far exceeds it, so a correct meter admits
        // EXACTLY the budget.
        let policer = Arc::new(tr_tcm(
            1_000_000_000,
            1_000_000,
            2_000_000_000,
            2_000_000,
            true,
        ));
        const THREADS: usize = 8;
        const PER_THREAD: usize = 20_000;
        const PKT: u64 = 100;
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let p = Arc::clone(&policer);
            handles.push(std::thread::spawn(move || {
                let mut green_bytes = 0u64;
                for _ in 0..PER_THREAD {
                    if p.meter(0, PKT, PacketColor::Green).color == PacketColor::Green {
                        green_bytes += PKT;
                    }
                }
                green_bytes
            }));
        }
        let total_green: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(
            total_green, 1_000_000,
            "concurrent green admissions must exactly equal the CBS token budget (no torn CAS)"
        );
    }

    #[test]
    fn concurrent_refill_under_contention_neither_over_nor_under_grants_6307() {
        // #6307 fail-on-revert: the bundled
        // `concurrent_meter_is_lock_free_and_preserves_trTCM_thresholds` pins
        // `now_ns = 0`, so it exercises only the consume `compare_exchange_weak`
        // under contention — the REFILL path (the win-the-window timestamp CAS
        // plus the #4261 sub-byte rewind composing across concurrent partial
        // windows) never runs there, and that is the actual over-grant hazard
        // of the lock-free design. This test advances the clock while N threads
        // meter, so refills and consumes race.
        //
        // SHARED-BUDGET LOOP (not equal per-thread iteration counts): every op
        // claims its timestamp from one `fetch_add` clock and threads race until
        // the shared budget is exhausted, so a fast thread simply takes more ops
        // and a descheduled thread cannot shorten the run. Total simulated time
        // is therefore EXACTLY `T_MAX_NS` no matter how the scheduler
        // interleaves, which is what makes the ceiling below deterministic.
        //
        // Ceiling arithmetic (committed bucket binds; see below):
        //   CBS = 50_000 B initial burst
        //   + CIR x T_MAX_NS / 1e9 = 1e6 x 0.175 = 175_000 B refilled
        //   = 225_000 B of green budget over the whole run.
        // Offered load is 250_000 x 100 B = 25_000_000 B, i.e. ~100x the supply,
        // so the committed bucket is drained continuously: it never re-saturates
        // (a saturated bucket would silently discard grants and blur the
        // ceiling) and it ends holding less than one packet.
        //
        // STEP_NS = 700 with CIR = 1e6 B/s accrues 0.7 B per op, so most ops
        // grant NOTHING and `compute_refill_add` must carry the sub-byte credit
        // across ops via its `last_refill_ns` rewind — the #4261 dust path, here
        // composed across concurrent partial windows.
        //
        // The peak bucket never binds: PIR = 1e9 B/s regrants 700 B per 700 ns
        // step against a 100 B debit, so `peak >= cost` always holds and a
        // packet is Green exactly when the COMMITTED bucket covers it. Packets
        // that miss committed fall to Yellow (they are not counted).
        use std::sync::Barrier;

        const THREADS: usize = 8;
        const PKT: u64 = 100;
        const STEP_NS: u64 = 700;
        const OPS: u64 = 250_000;
        const T_MAX_NS: u64 = OPS * STEP_NS;
        const CIR: u64 = 1_000_000;
        const CBS: u64 = 50_000;
        const PIR: u64 = 1_000_000_000;
        const PBS: u64 = 5_000_000;

        // #7841: the non-vacuity guard at the end of this test asserts that
        // the threads actually interleaved. That is a property of the
        // SCHEDULER, not of the policer, and on a loaded box (this repo's CI
        // runs ten-plus concurrent gates) the threads can degenerate to serial
        // execution — the guard then reds a test whose subject is fine.
        //
        // Retrying rather than deleting or weakening the guard: a serial run
        // genuinely proved nothing about the refill RACE, so accepting it would
        // make the cell silently vacuous, which is what the guard exists to
        // prevent. What a serial run does still prove is the refill
        // ARITHMETIC, so the over-grant and under-grant assertions are checked
        // on EVERY attempt and a real defect fails on the first one — only the
        // contention precondition is retried.
        //
        // Failing after MAX_ATTEMPTS is deliberate and is not a flake: eight
        // threads failing to interleave five times running is a real signal
        // (a single-core runner, or a policer that serialises internally),
        // and it reports the per-attempt rates so the reader can tell which.
        const MAX_ATTEMPTS: usize = 5;
        let mut attempt_rates: Vec<f64> = Vec::new();
        for attempt in 1..=MAX_ATTEMPTS {
        let policer = Arc::new(tr_tcm(CIR, CBS, PIR, PBS, true));
        // Prime both refill clocks at t=0 from ONE thread. Without this the
        // first thread to reach `refill()` stamps `last_refill_ns` at ITS
        // timestamp and the window [0, that timestamp) is never granted, which
        // would make the ceiling scheduler-dependent. Priming also opens PKT
        // bytes of headroom in the committed bucket so the very first
        // concurrent refill has somewhere to land (no start-of-run saturation
        // loss). Its 100 green bytes are counted in the total below.
        assert_eq!(
            policer.meter(0, PKT, PacketColor::Green).color,
            PacketColor::Green,
            "the priming meter must be Green (the bucket starts at CBS)"
        );

        let clock = Arc::new(AtomicU64::new(0));
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let p = Arc::clone(&policer);
            let clock = Arc::clone(&clock);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let mut green_bytes = 0u64;
                let mut ops = 0u64;
                // How many of this thread's ops saw the shared clock move by
                // more than its own step since its previous op — i.e. observed
                // another thread's advance. This is the achieved-contention
                // RATE, reported below; 0 means the run degenerated to serial
                // execution and the race was never exercised.
                let mut interleaved = 0u64;
                let mut prev_ns = 0u64;
                barrier.wait();
                loop {
                    let now_ns = clock.fetch_add(STEP_NS, Ordering::Relaxed) + STEP_NS;
                    if now_ns > T_MAX_NS {
                        break;
                    }
                    if ops > 0 && now_ns != prev_ns + STEP_NS {
                        interleaved += 1;
                    }
                    prev_ns = now_ns;
                    ops += 1;
                    if p.meter(now_ns, PKT, PacketColor::Green).color == PacketColor::Green {
                        green_bytes += PKT;
                    }
                }
                (green_bytes, ops, interleaved)
            }));
        }
        let results: Vec<(u64, u64, u64)> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();
        let total_green: u64 = PKT + results.iter().map(|r| r.0).sum::<u64>();
        let total_ops: u64 = results.iter().map(|r| r.1).sum();
        let interleaved: u64 = results.iter().map(|r| r.2).sum();

        // The shared-budget loop must have consumed exactly the budget — this
        // pins T_MAX_NS as the real elapsed window the ceiling is computed from.
        assert_eq!(
            total_ops, OPS,
            "the shared timestamp budget must be fully consumed exactly once"
        );
        eprintln!(
            "#6307 refill-under-contention: {total_ops} ops / {THREADS} threads, \
             per-thread ops {:?}, {interleaved} ops ({:.1}%) observed a foreign \
             clock advance, {total_green} B green admitted",
            results.iter().map(|r| r.1).collect::<Vec<_>>(),
            100.0 * interleaved as f64 / total_ops as f64,
        );

        let refilled = CIR * T_MAX_NS / 1_000_000_000;
        let ceiling = CBS + refilled;

        // NO OVER-GRANT. A refill window credited twice (the losing side of the
        // `last_refill_ns` compare_exchange adding tokens anyway) admits green
        // bytes the aggregate CIR/CBS contract never issued.
        assert!(
            total_green <= ceiling,
            "over-grant under concurrent refill: admitted {total_green} B green \
             but the CBS + CIR*T budget is only {ceiling} B \
             (CBS {CBS} + {refilled} refilled over {T_MAX_NS} ns)"
        );

        // NO LOST REFILL. Demand is ~100x supply, so a correct meter ends with
        // less than one packet of committed credit unspent. Slack accounts for
        // that residue (<PKT), the at-most-one-byte of sub-byte dust still owed
        // at T_MAX_NS, and one packet of margin. A dropped refill (e.g. the
        // window winner abandoning its credit add when the packed-credits CAS
        // loses) starves the policer by far more than this.
        const SLACK: u64 = 3 * PKT;
        assert!(
            total_green + SLACK >= ceiling,
            "starved under concurrent refill: admitted only {total_green} B \
             green against a {ceiling} B budget (CBS {CBS} + {refilled} \
             refilled over {T_MAX_NS} ns) — a refill was lost"
        );

        // Non-vacuity, checked LAST so a real over/under-grant is reported
        // first: with 8 threads over 250_000 ops this floor of ONE observed
        // foreign advance is many orders of magnitude below the measured
        // 99.4-99.7%, so it fires only if the run degenerated to strictly
        // serial execution — in which case the two assertions above proved
        // nothing about the refill race and the result must not read as
        // covered.
        attempt_rates.push(100.0 * interleaved as f64 / total_ops as f64);
        if interleaved > 0 {
            return;
        }
        eprintln!(
            "#7841: attempt {attempt}/{MAX_ATTEMPTS} degenerated to serial \
             execution (0 interleaved ops); the over/under-grant assertions \
             passed, retrying for a contended run"
        );
        }
        panic!(
            "no op observed another thread's clock advance in {MAX_ATTEMPTS} \
             attempts: the threads ran serially every time and the refill race \
             was never exercised. Per-attempt contention rates: {attempt_rates:?}. \
             A loaded box normally still measures 99.4-99.7%, so five consecutive \
             zeroes indicates a single-core runner or a policer that serialises \
             internally rather than scheduler noise (#7841)."
        );
    }

    #[test]
    fn meter_hot_path_takes_no_shared_mutex_source_guard() {
        // #5390 fail-on-revert source guard: bind the metered hot path to the
        // lock-free design. A revert to `Mutex<ThreeColorPolicerState>` +
        // `state.lock()` on the meter path reddens this assertion (an assertion
        // failure, not merely a build break). Mirrors the source-scan guards in
        // afxdp/types/shared_cos_lease/shared_cos_lease_tests.rs.
        // The negative (no-Mutex) checks read filter/mod.rs — the runtime
        // wrapper, a DIFFERENT file — so they never self-match the literals
        // written in this test's own assertions. The positive (CAS/atomic)
        // checks read policer.rs (this file), whose real meter code carries
        // those markers whether or not the test mentions them.
        use std::path::Path;
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/filter");
        let policer = std::fs::read_to_string(src.join("policer.rs")).unwrap();
        let mod_rs = std::fs::read_to_string(src.join("mod.rs")).unwrap();

        assert!(
            policer.contains("compare_exchange_weak") && policer.contains("AtomicU64"),
            "policer meter path must use lock-free CAS over atomics (#5390)"
        );
        assert!(
            policer.contains("#[repr(align(64))]"),
            "hot state must be cache-line isolated from the Relaxed counters (#5390)"
        );
        assert!(
            !mod_rs.contains("Mutex<ThreeColorPolicerState>"),
            "the three-color policer runtime must not wrap its state in a Mutex (#5390)"
        );
        assert!(
            !mod_rs.contains("self.state.lock()"),
            "the meter path must not take a per-packet lock (#5390 futex convoy)"
        );
    }
}
