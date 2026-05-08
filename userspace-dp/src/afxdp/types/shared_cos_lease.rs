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
// 100µs grace period before surplus claiming opens. Rate-cap clamped
// via elapsed_ns.min(EPOCH_DURATION_NS).

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
        }
    }
}

struct V8State {
    epoch: SharedCoSEpochState,
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
}

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
        Self {
            config,
            state: SharedCoSLeaseState {
                credits: AtomicU64::new(pack_shared_cos_lease_credits(config.burst_bytes, 0)),
                last_refill_ns: AtomicU64::new(0),
            },
            v8: Some(V8State {
                epoch: SharedCoSEpochState::new(),
                worker_grants,
                worker_active_flow_buckets,
                worker_fair_share,
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
    ) -> bool {
        let Some(v8) = self.v8.as_ref() else {
            return false;
        };
        self.config == compute_shared_cos_lease_config(rate_bytes, burst_bytes, active_shards)
            && v8.worker_grants.len() == max_worker_id + 1
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
            debug_assert!(false, "worker_id {} out of range (len {})",
                worker_id, v8.worker_grants.len());
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
            if (my_consumed as u64) >= my_share {
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
            let my_room = my_share - my_consumed as u64;
            let take = still_needed
                .min(class_room)
                .min(my_room)
                .min(u32::MAX as u64);
            if take == 0 {
                break;
            }

            // Step A: bump class total via tag-checked CAS.
            let class_new = PackedEpochGrant::pack(class_tag, class_granted + take as u32);
            if v8.epoch.packed_granted.0
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

        // === SURPLUS PATH: post-grace AND active workers only ===
        let active = v8
            .worker_active_flow_buckets
            .get(worker_id)
            .map(|a| a.load(Ordering::Relaxed) > 0)
            .unwrap_or(false);
        if still_needed > 0 && now_ns >= grace && active {
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
                if v8.epoch.packed_granted.0
                    .compare_exchange_weak(class_curr, class_new, Ordering::AcqRel, Ordering::Acquire)
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
    /// `count` = sum of active_flow_buckets across the worker's
    /// queues bound to this lease. Single-writer-per-slot.
    pub(in crate::afxdp) fn rehydrate_worker_active_count(
        &self,
        worker_id: usize,
        count: u32,
    ) {
        let Some(v8) = self.v8.as_ref() else {
            return;
        };
        if let Some(slot) = v8.worker_active_flow_buckets.get(worker_id) {
            slot.store(count, Ordering::Relaxed);
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
        if v8.epoch.epoch_seq
            .compare_exchange(seq, seq + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return; // peer claimed first
        }

        // We are the rotation winner; seq is now ODD.
        let new_tag = ((seq >> 1) + 1) as u32;

        // Reset class atomic with new tag (atomic store of the packed pair).
        v8.epoch.packed_granted.store_for_new_epoch(new_tag);
        // Reset every per-worker grant slot with new tag.
        for grant in v8.worker_grants.iter() {
            grant.store_for_new_epoch(new_tag);
        }

        // Recompute total_flows + per-worker fair shares + cap.
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
        let new_cap_raw = ((self.config.rate_bytes as u128) * (elapsed_ns as u128)
            / 1_000_000_000u128) as u64;
        let new_cap = new_cap_raw.min(u32::MAX as u64);
        v8.epoch.epoch_total_grant_cap.store(new_cap, Ordering::Release);
        let grace_ns = now_ns.saturating_add(EPOCH_DURATION_NS / 2);
        v8.epoch.epoch_grace_expires_ns.store(grace_ns, Ordering::Release);
        for (id, count_atom) in v8.worker_active_flow_buckets.iter().enumerate() {
            let my_count = count_atom.load(Ordering::Relaxed) as u64;
            let my_share = ((new_cap as u128) * (my_count as u128)
                / (total_flows as u128)) as u64;
            if let Some(share_atom) = v8.worker_fair_share.get(id) {
                share_atom.store(my_share, Ordering::Release);
            }
        }
        v8.epoch.epoch_start_ns.store(now_ns, Ordering::Release);
        // Publish completion: seq ODD→EVEN.
        v8.epoch.epoch_seq.store(seq + 2, Ordering::Release);
    }
}

/// #1229 Phase 6 v8: try to bump outstanding_leased_tokens by `take`.
/// Returns `true` if successful; `false` if cap reached (caller must
/// rollback the corresponding epoch grant).
fn try_bump_outstanding(
    state: &SharedCoSLeaseState,
    take: u64,
    max_total_leased: u64,
) -> bool {
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
            debug_assert!(false, "worker_grants overflow: tag={} curr={} take={}",
                curr_tag, curr_granted, take);
            return false;
        };
        let new = PackedEpochGrant::pack(curr_tag, new_granted);
        if pg.0
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
fn tag_checked_rollback(
    pg: &PackedEpochGrant,
    my_tag: u32,
    take: u32,
    metric: &AtomicU64,
) {
    for _retry in 0..MAX_ROLLBACK_RETRIES {
        let curr = pg.0.load(Ordering::Acquire);
        let (curr_tag, curr_granted) = PackedEpochGrant::unpack(curr);
        if curr_tag != my_tag {
            return; // rotation occurred; rollback unnecessary
        }
        let new_granted = curr_granted.saturating_sub(take);
        let new = PackedEpochGrant::pack(curr_tag, new_granted);
        if pg.0
            .compare_exchange_weak(curr, new, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return;
        }
    }
    metric.fetch_add(1, Ordering::Relaxed);
}

impl SharedCoSRootLease {
    pub(in crate::afxdp) fn new(shaping_rate_bytes: u64, burst_bytes: u64, active_shards: usize) -> Self {
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

