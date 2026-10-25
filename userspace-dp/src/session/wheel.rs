// Bucketed timer-wheel session GC (#965) extracted from session/mod.rs
// (#1047 P2 step 3). Pure relocation — bodies are byte-for-byte
// identical except visibilities widened from file-private to
// pub(super) for items that SessionTable in session/mod.rs accesses
// directly (struct fields, helper fns, exposed constants).
//
// SessionWheel encapsulates a 256-bucket × 1-second-tick wheel.
// Long-timeout sessions (> 256 s) re-bucket via FAR_FUTURE_OFFSET
// on pop; see docs/pr/965-session-gc-timer-wheel/plan.md.

use super::*;

// #965: bucketed timer-wheel session GC.
// 256 buckets x 1-second ticks = 256-second window. Long-timeout
// sessions (> 256 s) re-bucket via the FAR_FUTURE_OFFSET path on
// pop; see plan docs/pr/965-session-gc-timer-wheel/plan.md.
pub(super) const WHEEL_BUCKETS: usize = 256;
const WHEEL_MASK: u64 = (WHEEL_BUCKETS as u64) - 1;
// Wheel tick must equal the GC interval — `expire_stale_entries`
// is gated by `SESSION_GC_INTERVAL_NS` and the cursor advances one
// bucket per tick. If these diverge the cadence math gets silently
// out of sync (Copilot review: bind WHEEL_TICK_NS to the gate).
pub(super) const WHEEL_TICK_NS: u64 = SESSION_GC_INTERVAL_NS;
pub(super) const FAR_FUTURE_OFFSET: u64 = (WHEEL_BUCKETS as u64) - 1;
// Compile-time invariant: bucket_for_tick uses `tick & WHEEL_MASK`
// which only computes `tick % WHEEL_BUCKETS` correctly when
// WHEEL_BUCKETS is a power of two (Copilot review: footgun if
// someone changes the bucket count without updating the helper).
const _: () = assert!(
    WHEEL_BUCKETS.is_power_of_two(),
    "WHEEL_BUCKETS must be a power of two for the WHEEL_MASK trick to compute tick % WHEEL_BUCKETS",
);

#[inline]
pub(super) fn bucket_for_tick(tick: u64) -> usize {
    (tick & WHEEL_MASK) as usize
}

/// Compute the absolute wheel tick at which an entry expiring at
/// `expiration_ns` should be checked, given the current `now_ns`.
/// Floors the expiration to a tick boundary; entries past their
/// expiration land in the current tick (delta=0), entries in the
/// far future are clamped to FAR_FUTURE_OFFSET ticks ahead and get
/// re-checked there (still-alive case triggers re-bucketing in pop).
#[inline]
pub(super) fn target_tick_for(now_ns: u64, expiration_ns: u64) -> u64 {
    let now_tick = now_ns / WHEEL_TICK_NS;
    let expiration_tick = expiration_ns / WHEEL_TICK_NS;
    let delta = expiration_tick.saturating_sub(now_tick);
    now_tick + delta.min(FAR_FUTURE_OFFSET)
}

#[derive(Clone, Debug)]
pub(super) struct WheelEntry {
    pub(super) key: SessionKey,
    pub(super) scheduled_tick: u64,
}

pub(super) struct SessionWheel {
    pub(super) buckets: Box<[VecDeque<WheelEntry>]>,
    /// Absolute tick of the next bucket to pop. Advances 1 per
    /// elapsed wheel tick during `expire_stale_entries`. The bucket
    /// index is `cursor_tick & WHEEL_MASK`.
    pub(super) cursor_tick: u64,
    pub(super) initialized: bool,
}

impl SessionWheel {
    pub(super) fn new() -> Self {
        let mut buckets: Vec<VecDeque<WheelEntry>> = Vec::with_capacity(WHEEL_BUCKETS);
        for _ in 0..WHEEL_BUCKETS {
            buckets.push(VecDeque::new());
        }
        Self {
            buckets: buckets.into_boxed_slice(),
            cursor_tick: 0,
            initialized: false,
        }
    }
}
