//! Per-zone rate counters used by ICMP/UDP/SYN flood detection and
//! SYN-cookie standby ACK rate limiting.
//!
//! The limiter is a two-bucket **sliding-window counter** keyed on a
//! 1-second granularity clock (`now_secs`). It bounds the admitted event
//! rate across any rolling 1-second interval, not just within a fixed
//! calendar second.
//!
//! ## Why not a fixed wall-second window (#2937)
//!
//! The previous implementation reset `count` to zero whenever `now_secs`
//! advanced. That is a fixed wall-clock window, and it admits a boundary
//! double-burst: a sender consuming the full budget at the end of second
//! N and another full budget at the start of second N+1 passes ~2x the
//! nominal threshold in an arbitrarily short interval straddling the
//! boundary. For flood screens that delays enforcement during exactly the
//! burst shape an attacker uses; for standby SYN-cookie ACK validation it
//! permits roughly twice the intended number of plausible ACKs before the
//! standby refuses to spend CPU validating cookies.
//!
//! ## Sliding-window counter
//!
//! Two adjacent 1-second buckets are retained: the count for the current
//! second (`count`) and the count for the immediately preceding second
//! (`prev_count`). An event is admitted only when
//! `prev_count + count <= threshold`. Because the previous second's tally
//! still contributes for the whole of the current second, a sender that
//! exhausts the budget just before a boundary cannot immediately spend a
//! fresh budget just after it — the trailing 1-second sum stays bounded by
//! `threshold` regardless of where the boundary falls.
//!
//! A gap of two or more seconds clears the previous bucket (no stale
//! carryover from an idle period).
//!
//! The hot path is allocation-free and integer-only (two `u32` adds and a
//! compare per event).
//!
//! ## `RateCounter` over-throttles a sender parked AT the threshold (#3607)
//!
//! Because `RateCounter` counts *rejected* events (the offending packet is
//! always counted) and gives the whole previous second constant weight for
//! the entire current second, a sender delivering exactly `threshold`
//! events/second is admitted only in the first second and then dropped to ~0
//! until a fully idle second resets the window — the true sustained ceiling
//! is `threshold/2`, not `threshold`. That over-throttle is acceptable (and
//! deliberately retained) for the consumers where "admitted" means "skip a
//! security response" — the SYN-flood aggregate that activates SYN cookies
//! when `syn-cookie` is ON (a challenge is a recoverable extra RTT), the
//! alarm-threshold arrival-rate measurement, and the #3315 per-source /
//! per-destination sketch. Consumers where "admitted" is a pure shaper /
//! validate-budget decision (ICMP/UDP flood aggregate, the standby
//! SYN-cookie ACK validation budget, and the SYN-flood aggregate drop path
//! when `syn-cookie` is OFF) instead use [`TokenBucket`] below, which admits
//! a sustained-at-threshold stream correctly while still bounding a burst to
//! the capacity. See `docs/syn-cookie-flood-protection.md` and
//! `docs/research/3607-screen-rate/plan.md`.

/// Sliding-window rate counter over two adjacent 1-second buckets.
#[derive(Debug, Clone, Default)]
pub(super) struct RateCounter {
    /// Events counted in the current 1-second bucket.
    pub(super) count: u32,
    /// Events counted in the immediately preceding 1-second bucket.
    /// Contributes to the admission decision for the whole current second
    /// so a boundary crossing cannot reset the budget to zero.
    prev_count: u32,
    /// Wall-clock second that `count` accumulates into.
    window_start_secs: u64,
}

impl RateCounter {
    /// Roll the buckets forward so `count` tracks `now_secs`.
    ///
    /// Advancing by exactly one second demotes the current bucket to the
    /// previous bucket. Advancing by two or more seconds means a full
    /// rolling window elapsed with no events in between, so both buckets
    /// are cleared (no stale carryover).
    fn advance(&mut self, now_secs: u64) {
        if now_secs == self.window_start_secs {
            return;
        }
        if now_secs == self.window_start_secs.wrapping_add(1) {
            self.prev_count = self.count;
        } else {
            self.prev_count = 0;
        }
        self.count = 0;
        self.window_start_secs = now_secs;
    }

    /// Increment and return true if admitting this event would exceed the
    /// threshold over the trailing 1-second sliding window.
    ///
    /// The event is always counted (so a sustained over-limit sender keeps
    /// the window saturated), mirroring the original fixed-window
    /// behaviour where the offending packet incremented the counter.
    pub(super) fn increment(&mut self, now_secs: u64, threshold: u32) -> bool {
        self.advance(now_secs);
        self.count = self.count.saturating_add(1);
        self.prev_count.saturating_add(self.count) > threshold
    }

    /// Advance the window ONCE, count this event, and classify the trailing
    /// 1-second sum against TWO thresholds in a single pass (#3315 D7).
    ///
    /// Returns `(over_attack, over_alarm)`. This avoids a peek-then-increment
    /// double-advance: `increment` rolls the buckets forward on each call, so
    /// comparing against a second threshold via a separate call would advance
    /// the window twice and could miscount across a second boundary. The event
    /// is always counted (same as `increment`). Both compares read the same
    /// already-computed trailing sum, so the classification is internally
    /// consistent: a sum can never be "over attack" without also being "over
    /// alarm" when `alarm <= attack` (the validated Junos ordering, though the
    /// caller does not rely on that — it gates the alarm on `!over_attack`).
    pub(super) fn increment_and_classify(
        &mut self,
        now_secs: u64,
        attack: u32,
        alarm: u32,
    ) -> (bool, bool) {
        self.advance(now_secs);
        self.count = self.count.saturating_add(1);
        let trailing = self.prev_count.saturating_add(self.count);
        (trailing > attack, trailing > alarm)
    }

    /// Reset counter (used in tests).
    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) fn reset(&mut self) {
        self.count = 0;
        self.prev_count = 0;
        self.window_start_secs = 0;
    }
}

/// Fixed-point scale for [`TokenBucket`]: `tokens_q` units per whole token.
/// Chosen equal to nanoseconds-per-second so the per-nanosecond refill rate
/// at `threshold`/second is exactly `threshold` fixed-point units
/// (`threshold * ONE / NANOS_PER_SEC == threshold`), i.e. the refill over
/// `elapsed_ns` is simply `elapsed_ns * threshold` — an integer multiply with
/// NO per-packet 64-bit divide.
const ONE: u64 = 1_000_000_000;

/// Cap the refill window at one second. Any gap of >= 1s already refills a
/// bucket to capacity (capacity == `threshold` whole tokens, and one second
/// accrues exactly `threshold` tokens), and capping the elapsed term keeps
/// `elapsed_ns * threshold` from overflowing `u64` at very high thresholds
/// (AGY round-4 hardening).
const MAX_REFILL_ELAPSED_NS: u64 = 1_000_000_000;

/// Bucket capacity in fixed-point units for `threshold` whole tokens.
#[inline]
fn capacity_q(threshold: u32) -> u64 {
    (threshold as u64).saturating_mul(ONE)
}

/// Fixed-point tokens accrued over `elapsed_ns` nanoseconds at `threshold`
/// tokens/second. `elapsed_ns` is pre-capped at [`MAX_REFILL_ELAPSED_NS`] by
/// the caller, so the multiply cannot overflow `u64` for any realistic
/// threshold; `saturating_mul` is a belt-and-braces guard.
#[inline]
fn refill_q(elapsed_ns: u64, threshold: u32) -> u64 {
    elapsed_ns.saturating_mul(threshold as u64)
}

/// Monotonic-nanosecond **token bucket** (#3607).
///
/// Admits a sustained sender at exactly `threshold` events/second while
/// bounding a burst to `threshold` (the capacity), fixing the [`RateCounter`]
/// sustained-at-threshold over-throttle for the shaper / validate-budget
/// consumers (see the module doc). The bucket refills continuously, so an
/// at-threshold stream never runs dry, and a sub-millisecond boundary
/// straddle sees at most `threshold` tokens — preserving the #2937
/// anti-micro-burst property without the sliding window's count-all defect.
///
/// Fixed-point: `tokens_q` counts tokens scaled by [`ONE`]; one whole token
/// is `ONE` units. The hot path is one multiply-add, a clamp, and a
/// conditional subtract — integer-only, allocation-free, no per-packet clock
/// syscall (it reuses the batch-cached `loop_now_ns`), and no divide.
///
/// 16 bytes; per-worker; never serialized, persisted, or HA-synced.
#[derive(Debug, Clone, Default)]
pub(super) struct TokenBucket {
    /// Fixed-point available tokens (scaled by [`ONE`]). Clamped to
    /// `capacity_q(threshold)` on every refill.
    tokens_q: u64,
    /// Monotonic nanoseconds at the last refill. `0` is the "uninitialised"
    /// sentinel: a fresh bucket cold-starts FULL on first use so a new zone
    /// admits the first `threshold` events, matching `RateCounter`'s
    /// first-window behaviour.
    last_refill_ns: u64,
}

impl TokenBucket {
    /// Charge one event against the bucket. Returns `true` when the event is
    /// OVER LIMIT (drop / limited) and `false` when admitted — the SAME
    /// polarity as [`RateCounter::increment`], so it is a drop-in at the
    /// existing `true == drop` screen call sites.
    ///
    /// `now_ns` is the batch-cached `CLOCK_MONOTONIC` nanosecond already read
    /// once per poll loop (`loop_now_ns`); there is no per-packet clock read.
    /// A non-monotonic `now_ns` (`< last_refill_ns`) accrues no refill
    /// (`saturating_sub` yields 0 elapsed) AND does NOT move `last_refill_ns`
    /// backwards: the field is a MONOTONIC high-water mark
    /// (`last_refill_ns = last_refill_ns.max(now_ns)`). Were it allowed to dip
    /// to the backwards sample, the next forward `now_ns` would compute a large
    /// elapsed against the dip and over-credit the bucket — a clock glitch
    /// would reset the burst allowance and let a flood through in exactly the
    /// scenario this limiter hardens. `threshold` is passed per call (a config
    /// change needs no realloc), so the capacity clamp always tracks the live
    /// threshold.
    pub(super) fn admit_is_over(&mut self, now_ns: u64, threshold: u32) -> bool {
        self.refill(now_ns, threshold);
        if self.has_token() {
            self.consume_one();
            false // admitted
        } else {
            true // over limit — do NOT consume
        }
    }

    /// Refill the bucket and report whether one whole token is available,
    /// without consuming it. The flood sketch uses this as the first half of
    /// its all-row admission transaction (#10319).
    pub(super) fn prepare_admit(&mut self, now_ns: u64, threshold: u32) -> bool {
        self.refill(now_ns, threshold);
        self.has_token()
    }

    /// Commit one admission after every selected flood-sketch row prepared
    /// successfully (#10319).
    pub(super) fn commit_admit(&mut self) {
        self.consume_one();
    }

    #[inline]
    fn refill(&mut self, now_ns: u64, threshold: u32) {
        if self.last_refill_ns == 0 {
            // Cold start: begin FULL so a fresh zone admits the first
            // `threshold` events. `max(1)` never leaves the sentinel behind
            // even if the monotonic clock reports 0 on the first read.
            self.tokens_q = capacity_q(threshold);
            self.last_refill_ns = now_ns.max(1);
        } else {
            let elapsed = now_ns
                .saturating_sub(self.last_refill_ns)
                .min(MAX_REFILL_ELAPSED_NS);
            self.tokens_q = self
                .tokens_q
                .saturating_add(refill_q(elapsed, threshold))
                .min(capacity_q(threshold));
            self.last_refill_ns = self.last_refill_ns.max(now_ns);
        }
    }

    #[inline]
    fn has_token(&self) -> bool {
        self.tokens_q >= ONE
    }

    #[inline]
    fn consume_one(&mut self) {
        debug_assert!(self.has_token());
        self.tokens_q -= ONE;
    }

    /// Whole tokens currently available (fixed-point value floored). Test seam.
    #[cfg(test)]
    pub(super) fn available_tokens(&self) -> u64 {
        self.tokens_q / ONE
    }

    /// True if the bucket has never been charged (cold — no refill latched).
    /// Distinguishes "untouched" from "drained" (both report 0 available).
    #[cfg(test)]
    pub(super) fn is_cold(&self) -> bool {
        self.last_refill_ns == 0
    }

    /// Reset (used in tests).
    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) fn reset(&mut self) {
        self.tokens_q = 0;
        self.last_refill_ns = 0;
    }
}

#[cfg(test)]
#[path = "rate_tests.rs"]
mod tests;
