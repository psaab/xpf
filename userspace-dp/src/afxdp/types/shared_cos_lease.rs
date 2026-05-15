use super::*;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// #1035 P4: shared CoS lease + MQFQ V_min coordination types extracted
// from types.rs. Implements the cross-worker virtual-time floor
// (PaddedVtimeSlot, SharedCoSQueueVtimeFloor) and the lease handshake
// state used by the shared-exact CoS queue scheduler
// (SharedCoSLeaseConfig/State, SharedCoSQueueLease, SharedCoSRootLease).
//
// The corresponding inline `#[cfg(test)] mod tests` block moves
// with the production code per modularity-discipline test-colocation.

pub(in crate::afxdp) struct SharedCoSQueueLease {
    config: SharedCoSLeaseConfig,
    state: SharedCoSLeaseState,
    /// #1229 Phase 6 v8 — `Some` for guarantee-phase exact queue
    /// leases that participate in per-worker fair-share scheduling.
    /// `None` for legacy callers (root, transparent-rate,
    /// surplus-sharing, non-exact). Mode is fixed at construction.
    v8: Option<V8State>,
}

// === #1229 Phase 6 v8: per-worker fair lease ===
// Plan: docs/pr/1229-cross-worker-vtime/phase6-fair-lease.md (commit
// c159dbd5+, PLAN-READY at task-mowjwl1o-ob7bc5).
//
// Mechanism: 200µs epochs; per-worker fair share = (my_active_flows *
// epoch_total_grant_cap) / total_active_flow_buckets. Linearizable
// class CAS via packed (epoch_tag, total_granted). Tag-checked
// per-worker grants via packed (epoch_tag, worker_granted) — eliminates
// cross-epoch fetch_add contamination. Two-CAS-with-rollback for
// outstanding-leased cap (legacy state.credits accounting). Bounded
// rollback retries. Seqlock-style rotation: epoch_seq EVEN→ODD→EVEN.
// Surplus claiming opens only when the CPU-bound bypass detector arms;
// the 100µs grace timestamp remains part of the bypass telemetry and
// legacy detector history. Rate-cap clamped via
// elapsed_ns.min(EPOCH_DURATION_NS).

/// Epoch duration. Picked to match existing refill cadence.
pub(in crate::afxdp) const EPOCH_DURATION_NS: u64 = 200_000;

/// Bound on seqlock-snapshot retries.
const MAX_SEQ_SPINS: u32 = 64;

/// Bound on tag_checked_rollback retries.
const MAX_ROLLBACK_RETRIES: u32 = 16;

/// Packed (epoch_tag << 32 | granted_bytes). Used for both class-wide
/// `epoch_total_granted` and per-worker `worker_grants[id]`. Cross-
/// epoch CAS naturally rejected because rotation bumps the tag.
#[repr(align(64))]
struct PackedEpochGrant(AtomicU64);

impl PackedEpochGrant {
    #[inline(always)]
    const fn pack(tag: u32, granted: u32) -> u64 {
        ((tag as u64) << 32) | (granted as u64)
    }

    #[inline(always)]
    const fn unpack(v: u64) -> (u32, u32) {
        ((v >> 32) as u32, v as u32)
    }

    fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    fn store_for_new_epoch(&self, new_tag: u32) {
        self.0.store(Self::pack(new_tag, 0), Ordering::Release);
    }
}

#[repr(align(64))]
struct SharedCoSEpochState {
    /// Bit 0: 0=stable, 1=rotating. Increments by 2 per completed
    /// rotation. Upper bits double as a generation counter.
    /// epoch_tag = (seq >> 1) as u32.
    epoch_seq: AtomicU64,
    epoch_start_ns: AtomicU64,
    /// Capped at u32::MAX. Computed as
    /// `rate × min(elapsed, EPOCH_DURATION_NS)` per rotation.
    epoch_total_grant_cap: AtomicU64,
    epoch_grace_expires_ns: AtomicU64,
    /// Packed (epoch_tag, total_granted_this_epoch).
    packed_granted: PackedEpochGrant,
    /// Diagnostic: increments when tag_checked_rollback exceeds
    /// MAX_ROLLBACK_RETRIES with tag still matching. Failure mode is
    /// undergrant (class shows extra outstanding bytes until next
    /// rotation), NOT overshoot.
    rollback_retry_exceeded: AtomicU64,
    /// #1231 v5: 'all peers CPU-bound' bypass-grace countdown. When
    /// set to N > 0 by rotation, the next N rotations open the surplus
    /// path immediately (no grace-period gate) for active workers.
    /// Rotation arms it when ANY active worker had a starvation event
    /// in the prior epoch, aggregate grant was materially sub-cap, and
    /// at least one active non-signaling peer was both under-utilized
    /// and had queue-lease demand in that epoch. Decays one rotation
    /// at a time when the full detector does not fire.
    bypass_grace_rotations_remaining: AtomicU32,
    /// #1231 v5: telemetry — count of rotations where the bypass was
    /// armed. Operator-visible via Prometheus.
    bypass_grace_arm_count: AtomicU64,
    /// #1231 v5: telemetry — count of acquire calls that took surplus
    /// because bypass was active (would have been blocked by grace
    /// otherwise). Useful to confirm bypass is actually being
    /// consumed when armed.
    bypass_grace_use_count: AtomicU64,
}

impl SharedCoSEpochState {
    fn new() -> Self {
        Self {
            epoch_seq: AtomicU64::new(0),
            epoch_start_ns: AtomicU64::new(0),
            epoch_total_grant_cap: AtomicU64::new(0),
            epoch_grace_expires_ns: AtomicU64::new(0),
            packed_granted: PackedEpochGrant::new(),
            rollback_retry_exceeded: AtomicU64::new(0),
            bypass_grace_rotations_remaining: AtomicU32::new(0),
            bypass_grace_arm_count: AtomicU64::new(0),
            bypass_grace_use_count: AtomicU64::new(0),
        }
    }
}

struct V8State {
    epoch: SharedCoSEpochState,
    rate_mode: V8RateMode,
    /// Per-worker grants this epoch. Length = max_worker_id + 1.
    /// Each slot is packed (epoch_tag, worker_granted_this_epoch).
    /// Single-writer-per-slot: only worker `id` writes worker_grants[id].
    worker_grants: Box<[PackedEpochGrant]>,
    /// Per-worker active flow bucket count. Length = max_worker_id + 1.
    /// Single-writer-per-slot: only worker `id` writes its own slot
    /// (deltas via active_buckets.rs helpers, install via rehydrate).
    worker_active_flow_buckets: Box<[AtomicU32]>,
    /// Per-worker fair share (bytes/epoch) snapshot, recomputed at
    /// rotation. Length = max_worker_id + 1.
    worker_fair_share: Box<[AtomicU64]>,
    /// #1231 v5: per-worker starvation events this epoch. Each slot is
    /// packed (epoch_tag, event_count). Bumped via tag-checked CAS at
    /// the narrow-signal exit in acquire_v8: "primary exhausted AND
    /// class room remains AND active AND still_needed > 0". Reset at
    /// rotation via atomic swap (returned old captures any in-flight
    /// bumps; tag mismatch on subsequent in-flight CAS naturally
    /// rejects them). Length = max_worker_id + 1.
    worker_starvation_events: Box<[PackedEpochGrant]>,
    /// #1290 round-2: per-worker queue-lease demand events this epoch.
    /// Bumped once per active acquire_v8 call before granting. Rotation
    /// uses this to distinguish a genuinely backlogged under-utilized
    /// peer from a naturally quiet peer whose active-flow counter is
    /// merely nonzero. Length = max_worker_id + 1.
    worker_demand_events: Box<[PackedEpochGrant]>,
    equal_flow: V8EqualFlowSuppressState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum V8RateMode {
    /// Existing v8/Cstruct behavior: active-flow-proportional primary
    /// share, with explicit CPU-bound bypass allowed to claim surplus.
    CstructDefault,
    /// Opt-in prototype for #1304. Rotation samples the prior epoch and
    /// publishes a per-flow cap only after every active worker has been
    /// sampled for a short valid streak. Acquire stays O(1) by loading
    /// that already-published cap.
    EqualFlowSuppress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum V8EqualFlowFailOpenReason {
    None = 0,
    Disabled = 1,
    InsufficientSampledWorkers = 2,
    UnsampledActiveWorker = 3,
    ZeroTarget = 4,
    NoActiveFlows = 5,
    NotEnoughValidStreak = 6,
    StaleOrTagMismatch = 7,
    ArithmeticInvalid = 8,
    LowDemandWorker = 9,
}

impl V8EqualFlowFailOpenReason {
    fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::None,
            1 => Self::Disabled,
            2 => Self::InsufficientSampledWorkers,
            3 => Self::UnsampledActiveWorker,
            4 => Self::ZeroTarget,
            5 => Self::NoActiveFlows,
            6 => Self::NotEnoughValidStreak,
            7 => Self::StaleOrTagMismatch,
            8 => Self::ArithmeticInvalid,
            9 => Self::LowDemandWorker,
            _ => Self::ArithmeticInvalid,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Disabled => "disabled",
            Self::InsufficientSampledWorkers => "insufficient_sampled_workers",
            Self::UnsampledActiveWorker => "unsampled_active_worker",
            Self::ZeroTarget => "zero_target",
            Self::NoActiveFlows => "no_active_flows",
            Self::NotEnoughValidStreak => "not_enough_valid_streak",
            Self::StaleOrTagMismatch => "stale_or_tag_mismatch",
            Self::ArithmeticInvalid => "arithmetic_invalid",
            Self::LowDemandWorker => "low_demand_worker",
        }
    }
}

struct V8EqualFlowSuppressState {
    epoch_tag: AtomicU32,
    enforced: AtomicU32,
    valid_streak: AtomicU32,
    current_target_per_flow: AtomicU64,
    current_worker_cap: AtomicU64,
    smoothed_target_per_flow: AtomicU64,
    cap_hit_events: AtomicU64,
    suppressed_grant_bytes: AtomicU64,
    fail_open_reason: AtomicU32,
    fail_open_count: AtomicU64,
}

impl V8EqualFlowSuppressState {
    fn new() -> Self {
        Self {
            epoch_tag: AtomicU32::new(0),
            enforced: AtomicU32::new(0),
            valid_streak: AtomicU32::new(0),
            current_target_per_flow: AtomicU64::new(0),
            current_worker_cap: AtomicU64::new(0),
            smoothed_target_per_flow: AtomicU64::new(0),
            cap_hit_events: AtomicU64::new(0),
            suppressed_grant_bytes: AtomicU64::new(0),
            fail_open_reason: AtomicU32::new(V8EqualFlowFailOpenReason::Disabled as u32),
            fail_open_count: AtomicU64::new(0),
        }
    }

    fn fail_open(&self, new_tag: u32, reason: V8EqualFlowFailOpenReason) {
        self.epoch_tag.store(new_tag, Ordering::Release);
        self.enforced.store(0, Ordering::Release);
        self.current_target_per_flow.store(0, Ordering::Release);
        self.current_worker_cap.store(0, Ordering::Release);
        self.fail_open_reason
            .store(reason as u32, Ordering::Release);
        self.fail_open_count.fetch_add(1, Ordering::Relaxed);
        if reason != V8EqualFlowFailOpenReason::NotEnoughValidStreak {
            self.valid_streak.store(0, Ordering::Release);
            self.smoothed_target_per_flow.store(0, Ordering::Release);
        }
    }
}

const EQUAL_FLOW_VALID_STREAK_REQUIRED: u32 = 2;
const EQUAL_FLOW_MIN_WORKER_UTIL_NUM: u64 = 4;
const EQUAL_FLOW_MIN_WORKER_UTIL_DEN: u64 = 5;

pub(in crate::afxdp) struct SharedCoSRootLease {
    config: SharedCoSLeaseConfig,
    state: SharedCoSLeaseState,
}

/// #917 — cross-worker MQFQ V_min synchronization. Per-worker
/// slot of the most recent committed `queue_vtime` for a
/// shared_exact CoS queue. Each worker writes its OWN slot
/// (Release store, single-writer) and reads peers' slots
/// (Acquire load) on each scheduling decision (subject to
/// the K-cadence throttle in tx.rs). The minimum across
/// participating workers' slots is the cross-worker V_min;
/// a worker whose local `queue_vtime` advances more than
/// `LAG_THRESHOLD` past V_min throttles itself for one
/// timer-wheel tick to let slower peers catch up.
///
/// Sentinel value `NOT_PARTICIPATING = u64::MAX` means the
/// slot's worker has no flows on this queue. Peers skip
/// `NOT_PARTICIPATING` slots in the V_min reduction so an
/// idle worker doesn't peg V_min near zero.
///
/// Memory ordering (plan §3.4): `publish` and `vacate` use
/// Release stores; readers use Acquire loads. This
/// establishes a happens-before ordering so any observed
/// vtime is paired with the corresponding pre-vtime queue
/// state mutations.
///
/// Cache layout: each `PaddedVtimeSlot` is 64-byte aligned
/// to prevent false sharing across the worker writers; reads
/// pull each peer's line into Shared once per K-cadence
/// check. See plan §3.3 for the cost analysis.
#[repr(align(64))]
pub(in crate::afxdp) struct PaddedVtimeSlot {
    pub(in crate::afxdp) vtime: AtomicU64,
    _pad: [u8; 56],
}

pub(in crate::afxdp) const NOT_PARTICIPATING: u64 = u64::MAX;

impl PaddedVtimeSlot {
    pub(in crate::afxdp) const fn not_participating() -> Self {
        Self {
            vtime: AtomicU64::new(NOT_PARTICIPATING),
            _pad: [0; 56],
        }
    }

    /// Worker calls this on commit boundary publish. Six call
    /// sites total:
    ///   - 4 post-settle TX-ring commit sites in
    ///     `cos/queue_service/service.rs` (each immediately after
    ///     `settle_*`/commit), via the `publish_committed_queue_vtime`
    ///     helper.
    ///   - 1 demote-restore site in `tx/cos_classify.rs:641` (after
    ///     `demote_prepared_cos_queue_to_local` restores the saved
    ///     `queue_vtime`), via the same helper.
    ///   - 1 direct call in `cos/queue_ops/push.rs:126` on the
    ///     rollback path of `cos_queue_push_front`, restoring the
    ///     pre-pop `queue_vtime` so peers don't see the inflated
    ///     speculative value.
    ///
    /// Release ordering ensures any prior writes to
    /// `flow_bucket_*_finish_bytes` and `queue_vtime` are
    /// visible to peers that observe this slot Acquire.
    ///
    /// **No first-enqueue publish.** #941 Work item A's "symmetric
    /// publish on bucket-count 0 → ≥1 transition" was deliberately
    /// dropped during implementation. Rationale: a freshly-enqueued
    /// (or freshly-vacated-then-re-entering) worker has no committed
    /// vtime to broadcast, and peers correctly skip its slot via
    /// `slot.read() == None` (NOT_PARTICIPATING) in the V_min
    /// reduction (see `participating_v_min_snapshot` and its caller
    /// `cos_queue_v_min_continue`). Publishing the stale
    /// pre-vacate `queue_vtime` would broadcast a value that does
    /// NOT correspond to committed work, falsely throttling peers.
    /// The test `vmin_no_first_enqueue_publish` enforces this
    /// invariant.
    pub(in crate::afxdp) fn publish(&self, vtime: u64) {
        debug_assert_ne!(
            vtime, NOT_PARTICIPATING,
            "live vtime must not equal sentinel"
        );
        self.vtime.store(vtime, Ordering::Release);
    }

    /// Worker calls this when the queue's last bucket drains
    /// for this worker — i.e., the worker has no more
    /// flows on this queue.
    pub(in crate::afxdp) fn vacate(&self) {
        self.vtime.store(NOT_PARTICIPATING, Ordering::Release);
    }

    /// Peer reads. Returns `Some(vtime)` if the slot's
    /// worker is participating, `None` otherwise (skip in
    /// the V_min reduction).
    pub(in crate::afxdp) fn read(&self) -> Option<u64> {
        let v = self.vtime.load(Ordering::Acquire);
        if v == NOT_PARTICIPATING {
            None
        } else {
            Some(v)
        }
    }
}

/// #917 V_min coordination structure for a shared_exact CoS
/// queue. Allocated lazily on shared_exact promotion (see
/// `coordinator.rs`). The slot count is fixed at construction
/// time and matches the configured worker count. Holding an
/// `Arc` of this structure pins it across HA / config-commit
/// transitions.
pub(in crate::afxdp) struct SharedCoSQueueVtimeFloor {
    /// One slot per worker. Index by the worker's
    /// 0-based id.
    pub(in crate::afxdp) slots: Box<[PaddedVtimeSlot]>,
}

impl SharedCoSQueueVtimeFloor {
    pub(in crate::afxdp) fn new(num_workers: usize) -> Self {
        let slots = (0..num_workers)
            .map(|_| PaddedVtimeSlot::not_participating())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self { slots }
    }

    /// Single-pass snapshot of the participating peers' V_min
    /// state, excluding `worker_id`'s own slot.
    ///
    /// Returns `(participating_count, Some(v_min))` if at least
    /// one peer is participating, `(0, None)` if every peer is
    /// `NOT_PARTICIPATING` (caller treats the queue as unthrottled).
    /// `v_min` is the minimum across only participating peers.
    ///
    /// **Memory ordering**: each `slot.read()` is an independent
    /// `Ordering::Acquire` load, paired with the corresponding
    /// `Ordering::Release` store inside `PaddedVtimeSlot::publish` /
    /// `vacate`. The iteration is **non-atomic across slots** —
    /// a slot can transition `vtime → NOT_PARTICIPATING` (or
    /// vice versa) between two reads in the same iteration. There
    /// is no lock, seqlock, retry, or epoch; the result is the set
    /// of values observed during the scan, where each individual
    /// value is a valid Acquire-load of that slot at some moment
    /// within the scan window. Cross-slot atomicity is not
    /// provided. The throttle decision is a hint with staleness
    /// bounded by the K-cadence read interval, not a hard barrier.
    /// Introducing a global lock or seqlock would re-introduce
    /// the contention the algorithm was designed to eliminate.
    ///
    /// Single-pass helper that `cos_queue_v_min_continue` calls
    /// for the (count, v_min) pair on each cadence tick.
    /// Centralizes the memory-ordering contract in one place.
    #[inline]
    pub(in crate::afxdp) fn participating_v_min_snapshot(
        &self,
        worker_id: u32,
    ) -> (u32, Option<u64>) {
        let mut participating = 0u32;
        let mut v_min = u64::MAX;
        for (idx, slot) in self.slots.iter().enumerate() {
            if idx == worker_id as usize {
                continue;
            }
            if let Some(peer) = slot.read() {
                participating += 1;
                v_min = v_min.min(peer);
            }
        }
        if participating == 0 {
            (0, None)
        } else {
            (participating, Some(v_min))
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SharedCoSLeaseConfig {
    rate_bytes: u64,
    burst_bytes: u64,
    lease_bytes: u64,
    max_total_leased: u64,
    active_shards: usize,
}

#[repr(align(64))]
#[derive(Debug)]
struct SharedCoSLeaseState {
    credits: AtomicU64,
    last_refill_ns: AtomicU64,
}

const COS_ROOT_LEASE_TARGET_US: u64 = 200;
const COS_ROOT_LEASE_MIN_BYTES: u64 = 1500;
const COS_ROOT_LEASE_MAX_BYTES: u64 = 512 * 1024;

fn compute_shared_cos_lease_config(
    rate_bytes: u64,
    burst_bytes: u64,
    active_shards: usize,
) -> SharedCoSLeaseConfig {
    let burst_bytes = burst_bytes
        .max(COS_ROOT_LEASE_MIN_BYTES)
        .min(u32::MAX as u64);
    let active_shards = active_shards.max(1);
    let target_lease_bytes =
        ((rate_bytes as u128) * (COS_ROOT_LEASE_TARGET_US as u128) / 1_000_000u128) as u64;
    let lease_ceiling = burst_bytes
        .saturating_div(8)
        .min(COS_ROOT_LEASE_MAX_BYTES)
        .max(COS_ROOT_LEASE_MIN_BYTES);
    let lease_bytes = target_lease_bytes
        .max(COS_ROOT_LEASE_MIN_BYTES)
        .min(lease_ceiling);
    let max_frame_lease_bytes = lease_bytes.max(tx_frame_capacity() as u64);
    let max_total_leased = burst_bytes
        .saturating_div(4)
        .min(max_frame_lease_bytes.saturating_mul(active_shards as u64));
    debug_assert!(max_total_leased <= u32::MAX as u64);
    SharedCoSLeaseConfig {
        rate_bytes,
        burst_bytes,
        lease_bytes,
        max_total_leased,
        active_shards,
    }
}

#[inline(always)]
fn pack_shared_cos_lease_credits(available_tokens: u64, outstanding_leased_tokens: u64) -> u64 {
    debug_assert!(available_tokens <= u32::MAX as u64);
    debug_assert!(outstanding_leased_tokens <= u32::MAX as u64);
    (available_tokens << 32) | outstanding_leased_tokens
}

#[inline(always)]
fn unpack_shared_cos_lease_credits(credits: u64) -> (u64, u64) {
    ((credits >> 32) as u64, (credits as u32) as u64)
}

fn shared_cos_lease_acquire(
    config: SharedCoSLeaseConfig,
    state: &SharedCoSLeaseState,
    now_ns: u64,
    requested: u64,
) -> u64 {
    if requested == 0 {
        return 0;
    }
    refill_shared_cos_lease_state(config, state, now_ns);
    loop {
        let credits = state.credits.load(Ordering::Acquire);
        let (available_tokens, outstanding_leased_tokens) =
            unpack_shared_cos_lease_credits(credits);
        let lease_headroom = config
            .max_total_leased
            .saturating_sub(outstanding_leased_tokens);
        let granted = requested.min(available_tokens).min(lease_headroom);
        if granted == 0 {
            return 0;
        }
        let new_credits = pack_shared_cos_lease_credits(
            available_tokens.saturating_sub(granted),
            outstanding_leased_tokens.saturating_add(granted),
        );
        if state
            .credits
            .compare_exchange_weak(credits, new_credits, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return granted;
        }
    }
}

fn shared_cos_lease_consume(state: &SharedCoSLeaseState, bytes: u64) {
    if bytes == 0 {
        return;
    }
    loop {
        let credits = state.credits.load(Ordering::Acquire);
        let (available_tokens, outstanding_leased_tokens) =
            unpack_shared_cos_lease_credits(credits);
        let new_credits = pack_shared_cos_lease_credits(
            available_tokens,
            outstanding_leased_tokens.saturating_sub(bytes),
        );
        if state
            .credits
            .compare_exchange_weak(credits, new_credits, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return;
        }
    }
}

#[inline(always)]
fn shared_cos_lease_available_cap(
    config: SharedCoSLeaseConfig,
    outstanding_leased_tokens: u64,
) -> u64 {
    config.burst_bytes.saturating_sub(outstanding_leased_tokens)
}

fn shared_cos_lease_release_unused(
    config: SharedCoSLeaseConfig,
    state: &SharedCoSLeaseState,
    bytes: u64,
) {
    if bytes == 0 {
        return;
    }
    loop {
        let credits = state.credits.load(Ordering::Acquire);
        let (available_tokens, outstanding_leased_tokens) =
            unpack_shared_cos_lease_credits(credits);
        let new_outstanding = outstanding_leased_tokens.saturating_sub(bytes);
        let new_available = available_tokens
            .saturating_add(bytes)
            .min(shared_cos_lease_available_cap(config, new_outstanding));
        let new_credits = pack_shared_cos_lease_credits(new_available, new_outstanding);
        if state
            .credits
            .compare_exchange_weak(credits, new_credits, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return;
        }
    }
}

fn refill_shared_cos_lease_state(
    config: SharedCoSLeaseConfig,
    state: &SharedCoSLeaseState,
    now_ns: u64,
) {
    if config.burst_bytes == 0 {
        return;
    }
    loop {
        let last_refill_ns = state.last_refill_ns.load(Ordering::Acquire);
        if last_refill_ns == 0 {
            if state
                .last_refill_ns
                .compare_exchange(0, now_ns, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
            continue;
        }
        if now_ns <= last_refill_ns || config.rate_bytes == 0 {
            return;
        }
        let elapsed_ns = now_ns - last_refill_ns;
        let added = ((elapsed_ns as u128) * (config.rate_bytes as u128) / 1_000_000_000u128) as u64;
        if added == 0 {
            return;
        }
        if state
            .last_refill_ns
            .compare_exchange(last_refill_ns, now_ns, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            continue;
        }
        loop {
            let credits = state.credits.load(Ordering::Acquire);
            let (available_tokens, outstanding_leased_tokens) =
                unpack_shared_cos_lease_credits(credits);
            let new_available =
                available_tokens
                    .saturating_add(added)
                    .min(shared_cos_lease_available_cap(
                        config,
                        outstanding_leased_tokens,
                    ));
            let new_credits =
                pack_shared_cos_lease_credits(new_available, outstanding_leased_tokens);
            if state
                .credits
                .compare_exchange_weak(credits, new_credits, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }
}

impl SharedCoSQueueLease {
    pub(in crate::afxdp) fn new(rate_bytes: u64, burst_bytes: u64, active_shards: usize) -> Self {
        let config = compute_shared_cos_lease_config(rate_bytes, burst_bytes, active_shards);
        Self {
            config,
            state: SharedCoSLeaseState {
                credits: AtomicU64::new(pack_shared_cos_lease_credits(config.burst_bytes, 0)),
                last_refill_ns: AtomicU64::new(0),
            },
            v8: None,
        }
    }

    /// #1229 Phase 6 v8: per-worker fair-share lease for guarantee-
    /// phase exact queues. `max_worker_id` is the TRUE maximum worker
    /// id seen across the worker map (not `workers.len()` — sparse
    /// IDs allowed). The lease internally sizes its per-worker arrays
    /// to `max_worker_id + 1`; sparse slots stay at zero forever
    /// (workers not bound to this queue never request).
    pub(in crate::afxdp) fn new_v8(
        rate_bytes: u64,
        burst_bytes: u64,
        active_shards: usize,
        max_worker_id: usize,
    ) -> Self {
        Self::new_v8_with_rate_mode(
            rate_bytes,
            burst_bytes,
            active_shards,
            max_worker_id,
            V8RateMode::CstructDefault,
        )
    }

    pub(in crate::afxdp) fn new_v8_with_rate_mode(
        rate_bytes: u64,
        burst_bytes: u64,
        active_shards: usize,
        max_worker_id: usize,
        rate_mode: V8RateMode,
    ) -> Self {
        let config = compute_shared_cos_lease_config(rate_bytes, burst_bytes, active_shards);
        let len = max_worker_id + 1;
        let worker_grants = (0..len)
            .map(|_| PackedEpochGrant::new())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let worker_active_flow_buckets = (0..len)
            .map(|_| AtomicU32::new(0))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let worker_fair_share = (0..len)
            .map(|_| AtomicU64::new(0))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        // #1231 v5: per-worker starvation event slots, same size + tag-
        // checked-CAS pattern as worker_grants.
        let worker_starvation_events = (0..len)
            .map(|_| PackedEpochGrant::new())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let worker_demand_events = (0..len)
            .map(|_| PackedEpochGrant::new())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            config,
            state: SharedCoSLeaseState {
                credits: AtomicU64::new(pack_shared_cos_lease_credits(config.burst_bytes, 0)),
                last_refill_ns: AtomicU64::new(0),
            },
            v8: Some(V8State {
                epoch: SharedCoSEpochState::new(),
                rate_mode,
                worker_grants,
                worker_active_flow_buckets,
                worker_fair_share,
                worker_starvation_events,
                worker_demand_events,
                equal_flow: V8EqualFlowSuppressState::new(),
            }),
        }
    }

    pub(in crate::afxdp) fn is_v8(&self) -> bool {
        self.v8.is_some()
    }

    pub(in crate::afxdp) fn lease_bytes(&self) -> u64 {
        self.config.lease_bytes
    }

    pub(in crate::afxdp) fn matches_config(
        &self,
        rate_bytes: u64,
        burst_bytes: u64,
        active_shards: usize,
    ) -> bool {
        // Legacy match: ignores v8 mode. v8 callers use `matches_config_v8`.
        self.config == compute_shared_cos_lease_config(rate_bytes, burst_bytes, active_shards)
            && self.v8.is_none()
    }

    /// #1229 Phase 6 v8: extended config match including per-worker
    /// array sizing. Lease must be rebuilt on `max_worker_id` change.
    pub(in crate::afxdp) fn matches_config_v8(
        &self,
        rate_bytes: u64,
        burst_bytes: u64,
        active_shards: usize,
        max_worker_id: usize,
        rate_mode: V8RateMode,
    ) -> bool {
        let Some(v8) = self.v8.as_ref() else {
            return false;
        };
        self.config == compute_shared_cos_lease_config(rate_bytes, burst_bytes, active_shards)
            && v8.worker_grants.len() == max_worker_id + 1
            && v8.rate_mode == rate_mode
    }

    pub(in crate::afxdp) fn acquire(&self, now_ns: u64, requested: u64) -> u64 {
        shared_cos_lease_acquire(self.config, &self.state, now_ns, requested)
    }

    /// #1229 Phase 6 v8: per-worker fair-share acquire path. Returns 0
    /// if `worker_id` is out of range (in addition to the normal
    /// requested==0 / cap-reached paths). Caller passes the worker's
    /// stable id; the lease's per-worker arrays index by that id.
    pub(in crate::afxdp) fn acquire_v8(
        &self,
        worker_id: usize,
        now_ns: u64,
        requested: u64,
    ) -> u64 {
        let Some(v8) = self.v8.as_ref() else {
            debug_assert!(false, "acquire_v8 called on legacy lease");
            return 0;
        };
        if requested == 0 {
            return 0;
        }
        if v8.worker_grants.get(worker_id).is_none() {
            debug_assert!(
                false,
                "worker_id {} out of range (len {})",
                worker_id,
                v8.worker_grants.len()
            );
            return 0;
        }

        // Phase 1: maybe rotate.
        self.maybe_rotate_epoch_v8(now_ns);

        // Phase 2: seqlock snapshot of stable epoch state.
        let Some((cap, my_share, grace, my_tag)) = self.snapshot_epoch_v8(worker_id) else {
            return 0; // gave up after MAX_SEQ_SPINS
        };
        if cap == 0 {
            return 0;
        }

        let active = v8
            .worker_active_flow_buckets
            .get(worker_id)
            .map(|a| a.load(Ordering::Relaxed) > 0)
            .unwrap_or(false);
        if active {
            bump_epoch_event(&v8.worker_demand_events[worker_id], my_tag);
        }
        let equal_flow_cap = self.equal_flow_cap_v8(v8, worker_id, my_tag);
        let equal_flow_enforced = equal_flow_cap.is_some();
        let my_effective_share = equal_flow_cap
            .map(|cap| my_share.min(cap))
            .unwrap_or(my_share);

        let mut total_granted: u64 = 0;
        let mut still_needed = requested;

        // === PRIMARY PATH: bounded by my_fair_share AND class cap ===
        let my_pg = &v8.worker_grants[worker_id];
        loop {
            if still_needed == 0 {
                break;
            }
            // Tag-checked snapshot of my_consumed.
            let my_curr = my_pg.0.load(Ordering::Acquire);
            let (my_curr_tag, my_consumed) = PackedEpochGrant::unpack(my_curr);
            if my_curr_tag != my_tag {
                break; // rotation happened; abandon primary
            }
            if (my_consumed as u64) >= my_effective_share {
                break; // primary share exhausted
            }
            let class_curr = v8.epoch.packed_granted.0.load(Ordering::Acquire);
            let (class_tag, class_granted) = PackedEpochGrant::unpack(class_curr);
            if class_tag != my_tag {
                break;
            }
            if (class_granted as u64) >= cap {
                break;
            }
            let class_room = cap - class_granted as u64;
            let my_room = my_effective_share - my_consumed as u64;
            let take = still_needed
                .min(class_room)
                .min(my_room)
                .min(u32::MAX as u64);
            if take == 0 {
                break;
            }

            // Step A: bump class total via tag-checked CAS.
            let class_new = PackedEpochGrant::pack(class_tag, class_granted + take as u32);
            if v8
                .epoch
                .packed_granted
                .0
                .compare_exchange_weak(class_curr, class_new, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue; // contention or rotation; retry
            }
            // Step B: bump outstanding (legacy state.credits) cap.
            if !try_bump_outstanding(&self.state, take, self.config.max_total_leased) {
                tag_checked_rollback(
                    &v8.epoch.packed_granted,
                    my_tag,
                    take as u32,
                    &v8.epoch.rollback_retry_exceeded,
                );
                break; // outstanding cap reached for this epoch
            }
            // Step C: bump my worker grant. If tag mismatched (rotation
            // between A and C), worker_grant_bump returns false; that's
            // OK because rotation also reset our grant counter, and the
            // class CAS we did in A was tag-checked against the OLD tag
            // (so it lived in the old epoch and was reset by rotation).
            let _ = worker_grant_bump(&v8.worker_grants[worker_id], my_tag, take as u32);
            total_granted += take;
            still_needed -= take;
        }

        // === SURPLUS PATH: bypass only; active workers only ===
        // #1231 v5: bypass-grace flag set by rotation when 'all peers
        // CPU-bound' regime detected. Cheap-predicate-gated narrow-signal
        // bump (per Codex v5 probe F): only do the expensive tag-checked
        // reads if cheap conditions all hold.
        let bypass = v8
            .epoch
            .bypass_grace_rotations_remaining
            .load(Ordering::Relaxed)
            > 0;
        if still_needed > 0 && active {
            // Cheap predicates passed; do the expensive tag-checked reads
            // to confirm the narrow exit "primary exhausted AND class
            // room remains AND active AND still_needed>0". This signal
            // deliberately remains live after grace because strict exact
            // CoS no longer opens unarmed post-grace surplus.
            let my_curr = v8.worker_grants[worker_id].0.load(Ordering::Acquire);
            let (my_curr_tag, my_consumed_now) = PackedEpochGrant::unpack(my_curr);
            let class_curr = v8.epoch.packed_granted.0.load(Ordering::Acquire);
            let (class_curr_tag, class_granted_now) = PackedEpochGrant::unpack(class_curr);
            if my_curr_tag == my_tag
                && class_curr_tag == my_tag
                && (my_consumed_now as u64) >= my_effective_share
                && (class_granted_now as u64) < cap
            {
                // Narrow signal: bump starvation event for this worker.
                // Tag-checked CAS — old-tag bump after rotation fails
                // naturally; bounded retry is unnecessary because one
                // missed bump per epoch is fine (rotation only checks
                // count > 0).
                bump_epoch_event(&v8.worker_starvation_events[worker_id], my_tag);
                if equal_flow_enforced {
                    v8.equal_flow.cap_hit_events.fetch_add(1, Ordering::Relaxed);
                    let suppressed =
                        still_needed.min((cap - class_granted_now as u64).min(u32::MAX as u64));
                    if suppressed > 0 {
                        v8.equal_flow
                            .suppressed_grant_bytes
                            .fetch_add(suppressed, Ordering::Relaxed);
                    }
                }
            }
        }

        // Strict per-flow fairness path: do not automatically let
        // faster workers claim peer primary-share slack just because
        // half the epoch elapsed. That old post-grace behavior was
        // work-conserving, but it also let workers with fewer active
        // flows exceed their active-flow-proportional share during
        // normal shaper-bound traffic. Keep surplus available only
        // when the explicit CPU-bound bypass has armed; that path is
        // already gated by prior-epoch starvation + aggregate underuse
        // + peer-utilization checks at rotation.
        let surplus_open = bypass && !equal_flow_enforced;
        // #1231 v5: telemetry — track if any surplus byte was granted
        // while bypass was the reason (now_ns < grace AND bypass).
        let bypass_was_reason = bypass && now_ns < grace;
        if still_needed > 0 && surplus_open && active {
            let surplus_start_total = total_granted;
            loop {
                if still_needed == 0 {
                    break;
                }
                let class_curr = v8.epoch.packed_granted.0.load(Ordering::Acquire);
                let (class_tag, class_granted) = PackedEpochGrant::unpack(class_curr);
                if class_tag != my_tag {
                    break;
                }
                if (class_granted as u64) >= cap {
                    break;
                }
                let class_room = cap - class_granted as u64;
                let take = still_needed.min(class_room).min(u32::MAX as u64);
                if take == 0 {
                    break;
                }
                let class_new = PackedEpochGrant::pack(class_tag, class_granted + take as u32);
                if v8
                    .epoch
                    .packed_granted
                    .0
                    .compare_exchange_weak(
                        class_curr,
                        class_new,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
                {
                    continue;
                }
                if !try_bump_outstanding(&self.state, take, self.config.max_total_leased) {
                    tag_checked_rollback(
                        &v8.epoch.packed_granted,
                        my_tag,
                        take as u32,
                        &v8.epoch.rollback_retry_exceeded,
                    );
                    break;
                }
                let _ = worker_grant_bump(&v8.worker_grants[worker_id], my_tag, take as u32);
                total_granted += take;
                still_needed -= take;
            }
            if bypass_was_reason && total_granted > surplus_start_total {
                v8.epoch
                    .bypass_grace_use_count
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        total_granted
    }

    /// #1229 Phase 6 v8: returns the per-worker active-flow-bucket
    /// counter for the given worker id, or `None` if `worker_id` is
    /// out of range or this lease is in legacy mode. The
    /// `active_buckets.rs` helpers use this via `Option::and_then`
    /// for in-bounds delta updates.
    pub(in crate::afxdp) fn worker_active_flow_buckets_for(
        &self,
        worker_id: usize,
    ) -> Option<&AtomicU32> {
        self.v8.as_ref()?.worker_active_flow_buckets.get(worker_id)
    }

    /// #1229 Phase 6 v8: worker-side rehydration at lease install.
    /// Called by the worker after observing the new lease Arc, with
    /// `count` = the calling runtime's `active_flow_buckets` for this
    /// `(ifindex, queue_id)` lease.
    ///
    /// **Additive semantics** (Codex code-review finding #1, 2026-05-08):
    /// uses `fetch_add` so multiple runtimes sharing the same worker
    /// thread + lease (e.g. multiple BindingWorkers, see worker/mod.rs)
    /// each contribute additively to the per-worker slot. A `store`
    /// would have clobbered the prior runtime's contribution, leaving
    /// the slot under-counted and eventually allowing decrements to
    /// drive it to zero while other runtimes still have active flows.
    ///
    /// Plan §v5.3 specified "worker-level aggregate rehydration"; the
    /// additive form delivers that without requiring the install path
    /// to walk every runtime on the worker. Per-runtime install + Arc-
    /// swap detection (token_bucket.rs `ensure_v8_lease_attached`)
    /// guarantees this fires exactly once per (runtime, lease-Arc)
    /// pair — so the sum is correct after all runtimes complete their
    /// first top-up against the new lease.
    pub(in crate::afxdp) fn rehydrate_worker_active_count(&self, worker_id: usize, count: u32) {
        let Some(v8) = self.v8.as_ref() else {
            return;
        };
        if count == 0 {
            return;
        }
        if let Some(slot) = v8.worker_active_flow_buckets.get(worker_id) {
            slot.fetch_add(count, Ordering::Relaxed);
        }
    }

    /// #1229 Phase 6 v8: rollback-retry-exceeded count for telemetry.
    /// Returns 0 for legacy leases.
    pub(in crate::afxdp) fn v8_rollback_retry_exceeded(&self) -> u64 {
        self.v8
            .as_ref()
            .map(|v| v.epoch.rollback_retry_exceeded.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// #1231 v5: returns true if 'all peers CPU-bound' bypass-grace is
    /// currently active (rotations_remaining > 0). Returns false for
    /// legacy leases.
    pub(in crate::afxdp) fn v8_bypass_grace_active(&self) -> bool {
        self.v8
            .as_ref()
            .map(|v| {
                v.epoch
                    .bypass_grace_rotations_remaining
                    .load(Ordering::Relaxed)
                    > 0
            })
            .unwrap_or(false)
    }

    /// #1231 v5: count of rotations where bypass-grace was armed.
    pub(in crate::afxdp) fn v8_bypass_grace_arms(&self) -> u64 {
        self.v8
            .as_ref()
            .map(|v| v.epoch.bypass_grace_arm_count.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// #1231 v5: count of acquire calls where surplus was opened by
    /// bypass-grace (grace had not expired).
    pub(in crate::afxdp) fn v8_bypass_grace_uses(&self) -> u64 {
        self.v8
            .as_ref()
            .map(|v| v.epoch.bypass_grace_use_count.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub(in crate::afxdp) fn v8_equal_flow_active(&self) -> bool {
        self.v8
            .as_ref()
            .map(|v| v.rate_mode == V8RateMode::EqualFlowSuppress)
            .unwrap_or(false)
    }

    pub(in crate::afxdp) fn v8_equal_flow_enforced(&self) -> bool {
        self.v8
            .as_ref()
            .map(|v| v.equal_flow.enforced.load(Ordering::Relaxed) != 0)
            .unwrap_or(false)
    }

    pub(in crate::afxdp) fn v8_equal_flow_target_per_flow(&self) -> u64 {
        self.v8
            .as_ref()
            .map(|v| v.equal_flow.current_target_per_flow.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub(in crate::afxdp) fn v8_equal_flow_target_per_flow_bps(&self) -> u64 {
        let bytes_per_epoch = self.v8_equal_flow_target_per_flow() as u128;
        let bits_per_sec = bytes_per_epoch
            .saturating_mul(8)
            .saturating_mul(1_000_000_000u128)
            / (EPOCH_DURATION_NS as u128);
        bits_per_sec.min(u64::MAX as u128) as u64
    }

    pub(in crate::afxdp) fn v8_equal_flow_worker_cap(&self) -> u64 {
        self.v8
            .as_ref()
            .map(|v| v.equal_flow.current_worker_cap.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub(in crate::afxdp) fn v8_equal_flow_cap_hit_events(&self) -> u64 {
        self.v8
            .as_ref()
            .map(|v| v.equal_flow.cap_hit_events.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub(in crate::afxdp) fn v8_equal_flow_suppressed_grant_bytes(&self) -> u64 {
        self.v8
            .as_ref()
            .map(|v| v.equal_flow.suppressed_grant_bytes.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub(in crate::afxdp) fn v8_equal_flow_fail_open_reason(&self) -> V8EqualFlowFailOpenReason {
        self.v8
            .as_ref()
            .map(|v| {
                V8EqualFlowFailOpenReason::from_u32(
                    v.equal_flow.fail_open_reason.load(Ordering::Relaxed),
                )
            })
            .unwrap_or(V8EqualFlowFailOpenReason::Disabled)
    }

    pub(in crate::afxdp) fn v8_equal_flow_fail_open_reason_label(&self) -> &'static str {
        self.v8_equal_flow_fail_open_reason().as_str()
    }

    pub(in crate::afxdp) fn v8_equal_flow_fail_open_count(&self) -> u64 {
        self.v8
            .as_ref()
            .map(|v| v.equal_flow.fail_open_count.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub(in crate::afxdp) fn consume(&self, bytes: u64) {
        shared_cos_lease_consume(&self.state, bytes);
    }

    pub(in crate::afxdp) fn release_unused(&self, bytes: u64) {
        shared_cos_lease_release_unused(self.config, &self.state, bytes);
    }

    /// #1229 Phase 6 v8: seqlock-protected snapshot of stable epoch
    /// fields. Returns `None` if MAX_SEQ_SPINS is exceeded
    /// (pathological rotation churn or preempted rotation winner).
    fn snapshot_epoch_v8(&self, worker_id: usize) -> Option<(u64, u64, u64, u32)> {
        let v8 = self.v8.as_ref()?;
        let mut spins: u32 = 0;
        loop {
            let seq_before = v8.epoch.epoch_seq.load(Ordering::Acquire);
            if seq_before & 1 == 1 {
                spins += 1;
                if spins >= MAX_SEQ_SPINS {
                    return None;
                }
                std::hint::spin_loop();
                continue;
            }
            let cap = v8.epoch.epoch_total_grant_cap.load(Ordering::Acquire);
            let share = v8
                .worker_fair_share
                .get(worker_id)
                .map(|a| a.load(Ordering::Acquire))
                .unwrap_or(0);
            let grace = v8.epoch.epoch_grace_expires_ns.load(Ordering::Acquire);
            let seq_after = v8.epoch.epoch_seq.load(Ordering::Acquire);
            if seq_after == seq_before {
                return Some((cap, share, grace, (seq_before >> 1) as u32));
            }
            spins += 1;
            if spins >= MAX_SEQ_SPINS {
                return None;
            }
        }
    }

    fn equal_flow_cap_v8(&self, v8: &V8State, worker_id: usize, epoch_tag: u32) -> Option<u64> {
        if v8.rate_mode != V8RateMode::EqualFlowSuppress {
            return None;
        }
        if v8.equal_flow.enforced.load(Ordering::Acquire) == 0 {
            return None;
        }
        if v8.equal_flow.epoch_tag.load(Ordering::Acquire) != epoch_tag {
            v8.equal_flow.fail_open_reason.store(
                V8EqualFlowFailOpenReason::StaleOrTagMismatch as u32,
                Ordering::Release,
            );
            v8.equal_flow
                .fail_open_count
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let target = v8
            .equal_flow
            .current_target_per_flow
            .load(Ordering::Acquire);
        if target == 0 {
            v8.equal_flow.fail_open_reason.store(
                V8EqualFlowFailOpenReason::ZeroTarget as u32,
                Ordering::Release,
            );
            v8.equal_flow
                .fail_open_count
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let active_flows = v8
            .worker_active_flow_buckets
            .get(worker_id)
            .map(|a| a.load(Ordering::Relaxed) as u64)
            .unwrap_or(0);
        if active_flows == 0 {
            return Some(0);
        }
        match target.checked_mul(active_flows) {
            Some(cap) => Some(cap),
            None => {
                v8.equal_flow.fail_open_reason.store(
                    V8EqualFlowFailOpenReason::ArithmeticInvalid as u32,
                    Ordering::Release,
                );
                v8.equal_flow
                    .fail_open_count
                    .fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// #1229 Phase 6 v8: rotate epoch when current epoch has expired.
    /// Seqlock pattern: CAS seq EVEN→ODD claims rotation; updates
    /// state; CAS seq ODD→EVEN publishes completion.
    fn maybe_rotate_epoch_v8(&self, now_ns: u64) {
        let Some(v8) = self.v8.as_ref() else {
            return;
        };
        let seq = v8.epoch.epoch_seq.load(Ordering::Acquire);
        if seq & 1 == 1 {
            return; // peer rotating; acquirers will spin in snapshot
        }
        let start = v8.epoch.epoch_start_ns.load(Ordering::Acquire);
        // First-rotation special case: start==0 means lease was just
        // created; we always rotate immediately to publish initial
        // (cap, fair_share, grace).
        if start != 0 && now_ns < start.saturating_add(EPOCH_DURATION_NS) {
            return;
        }
        // Try EVEN→ODD CAS to claim rotation. Only one winner per cycle.
        if v8
            .epoch
            .epoch_seq
            .compare_exchange(seq, seq + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return; // peer claimed first
        }

        // We are the rotation winner; seq is now ODD.
        let new_tag = ((seq >> 1) + 1) as u32;
        let new_packed_zero = PackedEpochGrant::pack(new_tag, 0);

        // #1231 v5 STEP 1: ATOMIC-SWAP packed_granted to capture
        // prior-epoch grant AND publish new-tag/0 reset in one
        // operation. Old-tag CAS after this swap fails (tag mismatch);
        // old-tag CAS before this swap is captured in the returned
        // old value. This is the linearization point for prev_granted.
        let prev_packed_granted = v8
            .epoch
            .packed_granted
            .0
            .swap(new_packed_zero, Ordering::AcqRel);
        let (_prev_class_tag, prev_granted_u32) = PackedEpochGrant::unpack(prev_packed_granted);
        let prev_granted = prev_granted_u32 as u64;
        let prev_cap = v8.epoch.epoch_total_grant_cap.load(Ordering::Acquire);

        // #1231 v5.5 stack scratch for per-worker swap captures.
        const MAX_WORKERS_SCRATCH: usize = 32;
        let n_workers = v8.worker_grants.len().min(MAX_WORKERS_SCRATCH);
        debug_assert!(v8.worker_grants.len() <= MAX_WORKERS_SCRATCH);
        let mut signaled_by_worker = [false; MAX_WORKERS_SCRATCH];
        let mut demanded_by_worker = [false; MAX_WORKERS_SCRATCH];
        let mut prev_grants = [0u32; MAX_WORKERS_SCRATCH];
        let mut active_by_worker = [false; MAX_WORKERS_SCRATCH];
        let mut active_flows_by_worker = [0u32; MAX_WORKERS_SCRATCH];
        let mut active_outside_scratch = false;

        // STEP 2: swap event slots, track per-worker signal/demand flags.
        let mut any_active_worker_signaled = false;
        for id in 0..v8.worker_starvation_events.len() {
            let old_starvation = v8.worker_starvation_events[id]
                .0
                .swap(new_packed_zero, Ordering::AcqRel);
            let (_old_starvation_tag, old_starvation_count) =
                PackedEpochGrant::unpack(old_starvation);
            let old_demand = v8.worker_demand_events[id]
                .0
                .swap(new_packed_zero, Ordering::AcqRel);
            let (_old_demand_tag, old_demand_count) = PackedEpochGrant::unpack(old_demand);
            let active = v8
                .worker_active_flow_buckets
                .get(id)
                .map(|c| c.load(Ordering::Relaxed))
                .unwrap_or(0);
            if id < n_workers {
                active_by_worker[id] = active > 0;
                active_flows_by_worker[id] = active;
                demanded_by_worker[id] = old_demand_count > 0;
                if active > 0 && old_starvation_count > 0 {
                    signaled_by_worker[id] = true;
                    any_active_worker_signaled = true;
                }
            } else if active > 0 {
                active_outside_scratch = true;
                if old_starvation_count > 0 {
                    any_active_worker_signaled = true;
                }
            }
        }

        // STEP 3: swap worker_grants, capture prev_grant for peer-util.
        for (id, grant) in v8.worker_grants.iter().enumerate() {
            let old = grant.0.swap(new_packed_zero, Ordering::AcqRel);
            if id < n_workers {
                let (_, prev) = PackedEpochGrant::unpack(old);
                prev_grants[id] = prev;
            }
        }

        if v8.rate_mode == V8RateMode::EqualFlowSuppress {
            publish_equal_flow_epoch_v8(
                v8,
                new_tag,
                n_workers,
                active_outside_scratch,
                &active_by_worker,
                &active_flows_by_worker,
                &demanded_by_worker,
                &prev_grants,
            );
        } else {
            v8.equal_flow.epoch_tag.store(new_tag, Ordering::Release);
            v8.equal_flow.enforced.store(0, Ordering::Release);
            v8.equal_flow.fail_open_reason.store(
                V8EqualFlowFailOpenReason::Disabled as u32,
                Ordering::Release,
            );
        }

        // #1231 v5.5 + #1290 round-2 STEP 3.5: peer-utilization
        // gate. iperf-c saturation has CPU-bound peers consuming
        // <60% of share; iperf-e shaper-bound peers consume ~90%.
        // #1290 adds the demand flag so a naturally quiet peer whose
        // active-flow counter is merely nonzero cannot be mistaken
        // for a CPU-bound peer with stranded capacity.
        let mut any_peer_cpu_bound_under_util = false;
        for id in 0..n_workers {
            if !active_by_worker[id] || signaled_by_worker[id] {
                continue;
            }
            if !demanded_by_worker[id] {
                continue;
            }
            let share = v8
                .worker_fair_share
                .get(id)
                .map(|s| s.load(Ordering::Relaxed))
                .unwrap_or(0);
            if share == 0 {
                continue;
            }
            // util < 60%: 5 * prev_grant < 3 * share. Empirical
            // sweep:
            // - 75% threshold (v5.6) caused iperf-d 5-flow worker
            //   to drop to 770 Mbps/flow (other workers claimed its
            //   surplus too aggressively, starving its 5 flows).
            // - 60% threshold (v5.5) leaves moderately-utilized
            //   peers alone; only fires on CPU-bound regimes.
            if (prev_grants[id] as u64).saturating_mul(5) < share.saturating_mul(3) {
                any_peer_cpu_bound_under_util = true;
                break;
            }
        }

        // #1231 v5.1 STEP 4: aggregate-underuse condition. Tightened
        // from 5% to 14% slack (cap / 7) per empirical comparison:
        // - iperf-e at ~89% of cap (14.2G/16G) → 11% under cap →
        //   does NOT fire (margin 3pp).
        // - iperf-c push at ~80% of cap (20.2G/25G) → 20% under cap →
        //   fires (margin 6pp).
        let underuse_slack = prev_cap / 7;
        let aggregate_underuse = prev_granted.saturating_add(underuse_slack) < prev_cap;

        // #1231 v5 + #1290 round-2 STEP 5: arm or decay bypass.
        // All conditions must hold: some active worker hit its
        // primary share while class room remained, aggregate grants
        // were materially sub-cap, and at least one active
        // non-signaling peer both requested queue-lease credit and
        // consumed <60% of its primary share.
        if any_active_worker_signaled && aggregate_underuse && any_peer_cpu_bound_under_util {
            v8.epoch
                .bypass_grace_rotations_remaining
                .store(5, Ordering::Release);
            v8.epoch
                .bypass_grace_arm_count
                .fetch_add(1, Ordering::Relaxed);
        } else {
            let curr = v8
                .epoch
                .bypass_grace_rotations_remaining
                .load(Ordering::Acquire);
            if curr > 0 {
                v8.epoch
                    .bypass_grace_rotations_remaining
                    .store(curr - 1, Ordering::Release);
            }
        }

        // STEP 6: existing publication of total_flows / fair_share /
        // cap / grace_expires_ns / start_ns / seq EVEN bump.
        let total_flows: u64 = v8
            .worker_active_flow_buckets
            .iter()
            .map(|c| c.load(Ordering::Relaxed) as u64)
            .sum::<u64>()
            .max(1);
        let elapsed_ns = if start == 0 {
            EPOCH_DURATION_NS
        } else {
            (now_ns - start).min(EPOCH_DURATION_NS)
        };
        let new_cap_raw =
            ((self.config.rate_bytes as u128) * (elapsed_ns as u128) / 1_000_000_000u128) as u64;
        let new_cap = new_cap_raw.min(u32::MAX as u64);
        v8.epoch
            .epoch_total_grant_cap
            .store(new_cap, Ordering::Release);
        let grace_ns = now_ns.saturating_add(EPOCH_DURATION_NS / 2);
        v8.epoch
            .epoch_grace_expires_ns
            .store(grace_ns, Ordering::Release);
        for (id, count_atom) in v8.worker_active_flow_buckets.iter().enumerate() {
            let my_count = count_atom.load(Ordering::Relaxed) as u64;
            let my_share = ((new_cap as u128) * (my_count as u128) / (total_flows as u128)) as u64;
            if let Some(share_atom) = v8.worker_fair_share.get(id) {
                share_atom.store(my_share, Ordering::Release);
            }
        }
        v8.epoch.epoch_start_ns.store(now_ns, Ordering::Release);
        // Publish completion: seq ODD→EVEN.
        v8.epoch.epoch_seq.store(seq + 2, Ordering::Release);
    }
}

fn publish_equal_flow_epoch_v8(
    v8: &V8State,
    new_tag: u32,
    n_workers: usize,
    active_outside_scratch: bool,
    active_by_worker: &[bool],
    active_flows_by_worker: &[u32],
    demanded_by_worker: &[bool],
    prev_grants: &[u32],
) {
    if active_outside_scratch {
        v8.equal_flow
            .fail_open(new_tag, V8EqualFlowFailOpenReason::UnsampledActiveWorker);
        return;
    }

    let mut active_workers = 0u32;
    let mut sampled_workers = 0u32;
    for id in 0..n_workers {
        if !active_by_worker[id] {
            continue;
        }
        active_workers = active_workers.saturating_add(1);
        if !demanded_by_worker[id] || prev_grants[id] == 0 {
            v8.equal_flow
                .fail_open(new_tag, V8EqualFlowFailOpenReason::UnsampledActiveWorker);
            return;
        }
        sampled_workers = sampled_workers.saturating_add(1);
    }

    if active_workers == 0 {
        v8.equal_flow
            .fail_open(new_tag, V8EqualFlowFailOpenReason::NoActiveFlows);
        return;
    }
    if sampled_workers < 2 {
        v8.equal_flow.fail_open(
            new_tag,
            V8EqualFlowFailOpenReason::InsufficientSampledWorkers,
        );
        return;
    }

    let mut candidate_target = u64::MAX;
    let mut max_worker_cap = 0u64;

    for id in 0..n_workers {
        if !active_by_worker[id] {
            continue;
        }
        let active_flows = active_flows_by_worker[id] as u64;
        if active_flows == 0 {
            v8.equal_flow
                .fail_open(new_tag, V8EqualFlowFailOpenReason::ArithmeticInvalid);
            return;
        }
        let per_flow = (prev_grants[id] as u64) / active_flows;
        if per_flow == 0 {
            v8.equal_flow
                .fail_open(new_tag, V8EqualFlowFailOpenReason::ZeroTarget);
            return;
        }
        let prior_share = v8
            .worker_fair_share
            .get(id)
            .map(|share| share.load(Ordering::Acquire))
            .unwrap_or(0);
        if prior_share == 0 {
            v8.equal_flow
                .fail_open(new_tag, V8EqualFlowFailOpenReason::UnsampledActiveWorker);
            return;
        }
        // Equal-flow suppression is safe only when the sample is demand
        // saturated enough to represent a real slow per-flow rate. A
        // quiet worker, or a rotation-boundary worker-grant sample that
        // missed enough old-epoch grants, must fail open instead of
        // dragging the whole queue down to an artificial low target.
        if (prev_grants[id] as u64).saturating_mul(EQUAL_FLOW_MIN_WORKER_UTIL_DEN)
            < prior_share.saturating_mul(EQUAL_FLOW_MIN_WORKER_UTIL_NUM)
        {
            v8.equal_flow
                .fail_open(new_tag, V8EqualFlowFailOpenReason::LowDemandWorker);
            return;
        }
        candidate_target = candidate_target.min(per_flow);
    }

    if candidate_target == u64::MAX || candidate_target == 0 {
        v8.equal_flow
            .fail_open(new_tag, V8EqualFlowFailOpenReason::ZeroTarget);
        return;
    }

    let prev_smoothed = v8
        .equal_flow
        .smoothed_target_per_flow
        .load(Ordering::Acquire);
    let smoothed = if prev_smoothed == 0 {
        candidate_target
    } else {
        prev_smoothed
            .saturating_mul(3)
            .saturating_add(candidate_target)
            / 4
    };
    if smoothed == 0 {
        v8.equal_flow
            .fail_open(new_tag, V8EqualFlowFailOpenReason::ZeroTarget);
        return;
    }
    for id in 0..n_workers {
        if !active_by_worker[id] {
            continue;
        }
        let Some(worker_cap) = smoothed.checked_mul(active_flows_by_worker[id] as u64) else {
            v8.equal_flow
                .fail_open(new_tag, V8EqualFlowFailOpenReason::ArithmeticInvalid);
            return;
        };
        max_worker_cap = max_worker_cap.max(worker_cap);
    }

    let streak = v8
        .equal_flow
        .valid_streak
        .load(Ordering::Acquire)
        .saturating_add(1);
    v8.equal_flow.valid_streak.store(streak, Ordering::Release);
    v8.equal_flow
        .smoothed_target_per_flow
        .store(smoothed, Ordering::Release);

    if streak < EQUAL_FLOW_VALID_STREAK_REQUIRED {
        v8.equal_flow
            .fail_open(new_tag, V8EqualFlowFailOpenReason::NotEnoughValidStreak);
        return;
    }

    v8.equal_flow.epoch_tag.store(new_tag, Ordering::Release);
    v8.equal_flow
        .current_target_per_flow
        .store(smoothed, Ordering::Release);
    v8.equal_flow
        .current_worker_cap
        .store(max_worker_cap, Ordering::Release);
    v8.equal_flow
        .fail_open_reason
        .store(V8EqualFlowFailOpenReason::None as u32, Ordering::Release);
    v8.equal_flow.enforced.store(1, Ordering::Release);
}

/// #1229 Phase 6 v8: try to bump outstanding_leased_tokens by `take`.
/// Returns `true` if successful; `false` if cap reached (caller must
/// rollback the corresponding epoch grant).
fn try_bump_outstanding(state: &SharedCoSLeaseState, take: u64, max_total_leased: u64) -> bool {
    loop {
        let credits = state.credits.load(Ordering::Acquire);
        let (available, outstanding) = unpack_shared_cos_lease_credits(credits);
        if outstanding.saturating_add(take) > max_total_leased {
            return false;
        }
        let new_credits = pack_shared_cos_lease_credits(available, outstanding + take);
        if state
            .credits
            .compare_exchange_weak(credits, new_credits, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return true;
        }
    }
}

#[inline]
fn bump_epoch_event(pg: &PackedEpochGrant, my_tag: u32) {
    let curr = pg.0.load(Ordering::Acquire);
    let (curr_tag, curr_count) = PackedEpochGrant::unpack(curr);
    if curr_tag == my_tag && curr_count < u32::MAX {
        let new = PackedEpochGrant::pack(curr_tag, curr_count + 1);
        let _ =
            pg.0.compare_exchange_weak(curr, new, Ordering::AcqRel, Ordering::Acquire);
    }
}

/// #1229 Phase 6 v8: tag-checked CAS-based bump of a per-worker grant
/// slot. Returns `false` if tag mismatched (rotation occurred);
/// caller treats that as "abandon this grant", since rotation already
/// reset accounting.
#[inline]
fn worker_grant_bump(pg: &PackedEpochGrant, my_tag: u32, take: u32) -> bool {
    loop {
        let curr = pg.0.load(Ordering::Acquire);
        let (curr_tag, curr_granted) = PackedEpochGrant::unpack(curr);
        if curr_tag != my_tag {
            return false;
        }
        let Some(new_granted) = curr_granted.checked_add(take) else {
            debug_assert!(
                false,
                "worker_grants overflow: tag={} curr={} take={}",
                curr_tag, curr_granted, take
            );
            return false;
        };
        let new = PackedEpochGrant::pack(curr_tag, new_granted);
        if pg
            .0
            .compare_exchange_weak(curr, new, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return true;
        }
    }
}

/// #1229 Phase 6 v8: bounded-retry rollback of a tag-matched grant.
/// If tag mismatches before the rollback CAS succeeds, rotation has
/// already cleared the counter — skip silently. If the retry budget
/// is exhausted with the tag still matching, increment the metric
/// and bail; failure mode is undergrant (extra outstanding bytes
/// stay debited until next rotation), NOT overshoot.
#[inline]
fn tag_checked_rollback(pg: &PackedEpochGrant, my_tag: u32, take: u32, metric: &AtomicU64) {
    for _retry in 0..MAX_ROLLBACK_RETRIES {
        let curr = pg.0.load(Ordering::Acquire);
        let (curr_tag, curr_granted) = PackedEpochGrant::unpack(curr);
        if curr_tag != my_tag {
            return; // rotation occurred; rollback unnecessary
        }
        let new_granted = curr_granted.saturating_sub(take);
        let new = PackedEpochGrant::pack(curr_tag, new_granted);
        if pg
            .0
            .compare_exchange_weak(curr, new, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return;
        }
    }
    metric.fetch_add(1, Ordering::Relaxed);
}

impl SharedCoSRootLease {
    pub(in crate::afxdp) fn new(
        shaping_rate_bytes: u64,
        burst_bytes: u64,
        active_shards: usize,
    ) -> Self {
        let config =
            compute_shared_cos_lease_config(shaping_rate_bytes, burst_bytes, active_shards);
        Self {
            config,
            state: SharedCoSLeaseState {
                credits: AtomicU64::new(pack_shared_cos_lease_credits(config.burst_bytes, 0)),
                last_refill_ns: AtomicU64::new(0),
            },
        }
    }

    pub(in crate::afxdp) fn lease_bytes(&self) -> u64 {
        self.config.lease_bytes
    }

    pub(in crate::afxdp) fn matches_config(
        &self,
        shaping_rate_bytes: u64,
        burst_bytes: u64,
        active_shards: usize,
    ) -> bool {
        self.config
            == compute_shared_cos_lease_config(shaping_rate_bytes, burst_bytes, active_shards)
    }

    pub(in crate::afxdp) fn acquire(&self, now_ns: u64, requested: u64) -> u64 {
        shared_cos_lease_acquire(self.config, &self.state, now_ns, requested)
    }

    pub(in crate::afxdp) fn consume(&self, bytes: u64) {
        shared_cos_lease_consume(&self.state, bytes);
    }

    pub(in crate::afxdp) fn release_unused(&self, bytes: u64) {
        shared_cos_lease_release_unused(self.config, &self.state, bytes);
    }
}

#[cfg(test)]
#[path = "shared_cos_lease_tests.rs"]
mod tests;
