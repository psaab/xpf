// #2158 (P2): the SharedCoS{Queue,Root}Lease token-bucket + v8 fair-share
// acquire path, extracted from shared_cos_lease/mod.rs as a pure
// code-motion split. Type/impl/const/fn bodies are byte-identical to the
// pre-split form; atomic memory orderings, the seqlock snapshot, and the
// CAS retry loops are preserved exactly.
//
// VISIBILITY WIDENING (the only non-move edits in this file): the
// `SharedCoSQueueLease` struct now lives here, but the rotation impl
// (`maybe_rotate_epoch_v8`) lives in the sibling submodule
// `rotate_epoch_v8.rs`, which reaches `self.config` and `self.v8`.
// Because a sibling submodule is not a descendant of `lease`, those two
// fields are widened from inherent-private to `pub(super)` (the `state`
// field has no sibling-submodule reader; it is `pub(super)` only so the
// co-located `tests` module can read `lease.state.credits`). All epoch-state
// types this file reaches (`V8State`, `SharedCoSEpochState`,
// `PackedEpochGrant`, the enums, the consts, …) live in the sibling
// `epoch.rs` and are already widened to `pub(super)` there.

use super::*;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

// #1035 P4: shared CoS lease + MQFQ V_min coordination types extracted
// from types.rs. Implements the cross-worker virtual-time floor
// (PaddedVtimeSlot, SharedCoSQueueVtimeFloor) and the lease handshake
// state used by the shared-exact CoS queue scheduler
// (SharedCoSLeaseConfig/State, SharedCoSQueueLease, SharedCoSRootLease).
//
// The corresponding inline `#[cfg(test)] mod tests` block moves
// with the production code per modularity-discipline test-colocation.

pub(in crate::afxdp) struct SharedCoSQueueLease {
    // pub(super): `config` is read by `rotate_epoch_v8.rs`
    // (self.config.rate_bytes in the carry math) and by the co-located
    // `tests` module (`lease.config.burst_bytes`).
    pub(super) config: SharedCoSLeaseConfig,
    // pub(super): `state` is reached by the co-located `tests` module
    // (`lease.state.credits` / `lease.state.last_refill_ns`). It had
    // inherent-private access when this struct lived in `mod.rs`.
    pub(super) state: SharedCoSLeaseState,
    /// #1229 Phase 6 v8 — `Some` for guarantee-phase exact queue
    /// leases that participate in per-worker fair-share scheduling.
    /// `None` for legacy callers (root, transparent-rate,
    /// surplus-sharing, non-exact). Mode is fixed at construction.
    // pub(super): `v8` is read by `rotate_epoch_v8.rs` (self.v8.as_ref())
    // and by the co-located `tests` module (`lease.v8`).
    pub(super) v8: Option<V8State>,
}

pub(in crate::afxdp) struct SharedCoSRootLease {
    // pub(super): `config`/`state` are reached by the co-located `tests`
    // module (root-lease refill/release/burst-clamp assertions). They had
    // inherent-private access when this struct lived in `mod.rs`.
    pub(super) config: SharedCoSLeaseConfig,
    pub(super) state: SharedCoSLeaseState,
}

// pub(super): named/field-reached by the co-located `tests` module and
// the `config`/`state` fields above; the only inner field a non-`tests`
// sibling reaches is `rate_bytes` (rotate). `burst_bytes` widens for the
// `tests` module (`lease.config.burst_bytes`); the rest stay private.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct SharedCoSLeaseConfig {
    pub(super) rate_bytes: u64,
    pub(super) burst_bytes: u64,
    lease_bytes: u64,
    max_total_leased: u64,
    active_shards: usize,
}

// pub(super): named + its fields reached by the co-located `tests` module
// (`lease.state.credits` / `last_refill_ns`). Inherent-private before the
// split.
#[repr(align(64))]
#[derive(Debug)]
pub(super) struct SharedCoSLeaseState {
    pub(super) credits: AtomicU64,
    pub(super) last_refill_ns: AtomicU64,
}

const COS_ROOT_LEASE_TARGET_US: u64 = 200;
const COS_ROOT_LEASE_MIN_BYTES: u64 = 1500;
const COS_ROOT_LEASE_MAX_BYTES: u64 = 512 * 1024;

/// #1630 (P1): per-queue exact leases bank an N-frame burst
/// (`COS_EXACT_QUEUE_LEASE_BANK_BYTES`); the root lease does not. The
/// `bank_floor` flag selects whether the outstanding-credit cap is
/// floored at the bank. It MUST be the same for a given lease across
/// rebuilds (it is fixed by the lease kind), so `matches_config*` passes
/// the same value the constructor did.
fn compute_shared_cos_lease_config(
    rate_bytes: u64,
    burst_bytes: u64,
    active_shards: usize,
) -> SharedCoSLeaseConfig {
    compute_shared_cos_lease_config_with_bank(rate_bytes, burst_bytes, active_shards, false)
}

fn compute_shared_cos_lease_config_with_bank(
    rate_bytes: u64,
    burst_bytes: u64,
    active_shards: usize,
    bank_floor: bool,
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
    // #1630 (P1): the per-queue exact lease token bucket is watermarked at
    // an N-frame burst bank (COS_EXACT_QUEUE_LEASE_BANK_BYTES, see
    // afxdp::mod / maybe_top_up_cos_queue_lease). The v8/legacy QUEUE
    // lease refuses grants once outstanding credit reaches
    // `max_total_leased`, so the outstanding-credit cap must rise in
    // lock-step or a low-`active_shards` queue can never bank the full N
    // frames (at active_shards=6 the old floor was 4096×6=24 KB < the 32
    // KB bank). The ROOT lease is NOT bank-watermarked (its top-up uses
    // `lease_bytes.max(tx_frame_capacity)`), so `bank_floor` is false for
    // it and its cap is unchanged. Raising the per-frame floor only widens
    // the outstanding window; the rate is still metered by the refill rate
    // (`rate_bytes`) and the actual-byte `consume`, so the hard-cap
    // (Gate 4) is preserved.
    let bank_bytes = if bank_floor {
        COS_EXACT_QUEUE_LEASE_BANK_BYTES
    } else {
        0
    };
    let max_frame_lease_bytes = lease_bytes
        .max(tx_frame_capacity() as u64)
        .max(bank_bytes);
    // The base cap keeps the lease from handing out more than a quarter of
    // the burst pool. #1630: that `burst/4` term (≈24 KB at the 96 KB
    // burst floor) is BELOW the N-frame bank (32 KB at N=8), so the cap
    // alone defeats the watermark even though `max_frame_lease_bytes` was
    // raised. For queue leases, floor the outstanding cap at one full bank
    // so a single shard can hold N frames of credit, but never exceed the
    // credit pool (`burst_bytes`) — outstanding credit can never exceed
    // available tokens, so flooring at the bank only relaxes the safety
    // margin, it does not raise the steady-state rate.
    let max_total_leased = burst_bytes
        .saturating_div(4)
        .min(max_frame_lease_bytes.saturating_mul(active_shards as u64))
        .max(bank_bytes.min(burst_bytes));
    debug_assert!(max_total_leased <= u32::MAX as u64);
    SharedCoSLeaseConfig {
        rate_bytes,
        burst_bytes,
        lease_bytes,
        max_total_leased,
        active_shards,
    }
}

// pub(super): reached by the co-located `tests` module
// (pack/unpack/refill assertions). Inherent-private before the split.
#[inline(always)]
pub(super) fn pack_shared_cos_lease_credits(
    available_tokens: u64,
    outstanding_leased_tokens: u64,
) -> u64 {
    debug_assert!(available_tokens <= u32::MAX as u64);
    debug_assert!(outstanding_leased_tokens <= u32::MAX as u64);
    (available_tokens << 32) | outstanding_leased_tokens
}

// pub(super): reached by the co-located `tests` module.
#[inline(always)]
pub(super) fn unpack_shared_cos_lease_credits(credits: u64) -> (u64, u64) {
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

// pub(super): reached by the co-located `tests` module (refill timing
// assertions). Inherent-private before the split.
pub(super) fn refill_shared_cos_lease_state(
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
        // #1630 (P1): queue leases bank an N-frame burst, so the
        // outstanding-credit cap is floored at the bank (bank_floor = true).
        let config =
            compute_shared_cos_lease_config_with_bank(rate_bytes, burst_bytes, active_shards, true);
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

    /// #1746: rate-mode constructor with the byte-unchanged default
    /// equal-flow target policy (`Slowest`). Callers that thread an
    /// operator-selected policy use `new_v8_with_rate_mode_and_policy`.
    pub(in crate::afxdp) fn new_v8_with_rate_mode(
        rate_bytes: u64,
        burst_bytes: u64,
        active_shards: usize,
        max_worker_id: usize,
        rate_mode: V8RateMode,
    ) -> Self {
        Self::new_v8_with_rate_mode_and_policy(
            rate_bytes,
            burst_bytes,
            active_shards,
            max_worker_id,
            rate_mode,
            EqualFlowTargetPolicy::Slowest,
        )
    }

    pub(in crate::afxdp) fn new_v8_with_rate_mode_and_policy(
        rate_bytes: u64,
        burst_bytes: u64,
        active_shards: usize,
        max_worker_id: usize,
        rate_mode: V8RateMode,
        equal_flow_target_policy: EqualFlowTargetPolicy,
    ) -> Self {
        // #1630 (P1): queue leases bank an N-frame burst (bank_floor = true).
        let config =
            compute_shared_cos_lease_config_with_bank(rate_bytes, burst_bytes, active_shards, true);
        let len = max_worker_id + 1;
        let worker_grants = (0..len)
            .map(|_| PackedEpochGrant::new())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let worker_active_flow_buckets = (0..len)
            .map(|_| PaddedAtomicU32(AtomicU32::new(0)))
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
        // #1745: per-worker acquire-time active-flow sample slots, same
        // size + tag-checked-CAS pattern as worker_demand_events. Built
        // unconditionally so it stays in lock-step with worker_grants on
        // every lease rebuild (HA failover, config change); only WRITTEN
        // in EqualFlowSuppress mode.
        let worker_equal_flow_active_samples = (0..len)
            .map(|_| PackedEpochGrant::new())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        // #1863 Step-0: cumulative per-worker requested/granted flow.
        let worker_requested_bytes = (0..len)
            .map(|_| PaddedAtomicU64(AtomicU64::new(0)))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let worker_granted_bytes = (0..len)
            .map(|_| PaddedAtomicU64(AtomicU64::new(0)))
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
                equal_flow_target_policy,
                worker_grants,
                worker_active_flow_buckets,
                worker_fair_share,
                worker_starvation_events,
                worker_demand_events,
                worker_equal_flow_active_samples,
                worker_requested_bytes,
                worker_granted_bytes,
                equal_flow: V8EqualFlowSuppressState::new(),
                rotation_scratch: Mutex::new(V8RotationScratch::new(len)),
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
        // #1630 (P1): queue leases use the bank-floored config
        // (bank_floor = true) — must match what `new`/`new_v8*` built.
        self.config
            == compute_shared_cos_lease_config_with_bank(
                rate_bytes,
                burst_bytes,
                active_shards,
                true,
            )
            && self.v8.is_none()
    }

    /// #1229 Phase 6 v8: extended config match including per-worker
    /// array sizing. Lease must be rebuilt on `max_worker_id` change.
    /// #1746: a live `equal-flow-target-policy` change must rebuild the
    /// lease — otherwise a stale lease keeps publishing with the old
    /// policy. The policy is part of the config identity here.
    pub(in crate::afxdp) fn matches_config_v8(
        &self,
        rate_bytes: u64,
        burst_bytes: u64,
        active_shards: usize,
        max_worker_id: usize,
        rate_mode: V8RateMode,
        equal_flow_target_policy: EqualFlowTargetPolicy,
    ) -> bool {
        let Some(v8) = self.v8.as_ref() else {
            return false;
        };
        // #1630 (P1): queue leases use the bank-floored config
        // (bank_floor = true) — must match what `new_v8*` built.
        self.config
            == compute_shared_cos_lease_config_with_bank(
                rate_bytes,
                burst_bytes,
                active_shards,
                true,
            )
            && v8.worker_grants.len() == max_worker_id + 1
            && v8.rate_mode == rate_mode
            && v8.equal_flow_target_policy == equal_flow_target_policy
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
        self.acquire_v8_with_cause(worker_id, now_ns, requested).0
    }

    /// #1782 Step-1: `acquire_v8` plus the shortfall cause that ended
    /// the call short of `requested` (`AcquireV8ShortfallCause::None`
    /// when fully granted). The cause is tracked at the existing break
    /// sites — no extra atomics, no extra loop work — so the hot path
    /// cost is a couple of register writes.
    pub(in crate::afxdp) fn acquire_v8_with_cause(
        &self,
        worker_id: usize,
        now_ns: u64,
        requested: u64,
    ) -> (u64, AcquireV8ShortfallCause) {
        let Some(v8) = self.v8.as_ref() else {
            debug_assert!(false, "acquire_v8 called on legacy lease");
            return (0, AcquireV8ShortfallCause::None);
        };
        if requested == 0 {
            return (0, AcquireV8ShortfallCause::None);
        }
        if v8.worker_grants.get(worker_id).is_none() {
            debug_assert!(
                false,
                "worker_id {} out of range (len {})",
                worker_id,
                v8.worker_grants.len()
            );
            return (0, AcquireV8ShortfallCause::None);
        }
        // #1863 Step-0: count the ask unconditionally (even calls that
        // end 0-granted on SeqlockGiveUp / CapZero / rotation) — the
        // attribution math needs "did this worker ask at all" as the
        // sampling-loss discriminator. Own-slot relaxed add; no
        // cross-worker contention.
        v8.worker_requested_bytes[worker_id]
            .0
            .fetch_add(requested, Ordering::Relaxed);

        // Phase 1: maybe rotate.
        self.maybe_rotate_epoch_v8(now_ns);

        // Phase 2: seqlock snapshot of stable epoch state.
        let Some((cap, my_share, grace, my_tag)) = self.snapshot_epoch_v8(worker_id) else {
            // gave up after MAX_SEQ_SPINS
            return (0, AcquireV8ShortfallCause::SeqlockGiveUp);
        };
        if cap == 0 {
            return (0, AcquireV8ShortfallCause::CapZero);
        }
        // #1782 Step-1: last limiting bound observed at a break site.
        // Overwritten as the call progresses; only reported when the
        // call ends with `still_needed > 0`.
        let mut shortfall = AcquireV8ShortfallCause::None;

        let active_flows = v8
            .worker_active_flow_buckets
            .get(worker_id)
            .map(|a| a.0.load(Ordering::Relaxed))
            .unwrap_or(0);
        let active = active_flows > 0;
        if active {
            bump_epoch_event(&v8.worker_demand_events[worker_id], my_tag);
            // #1745: in EqualFlowSuppress mode, record a tagged sticky-max
            // active-flow sample at acquire time. This is the sample source
            // the rotation/publisher uses for the equal-flow set, decoupled
            // from the rotation-instant flow-bucket read. The default
            // CstructDefault path is byte-unaffected (no write here).
            if v8.rate_mode == V8RateMode::EqualFlowSuppress {
                record_equal_flow_active_sample(
                    &v8.worker_equal_flow_active_samples[worker_id],
                    my_tag,
                    active_flows,
                );
            }
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
                shortfall = AcquireV8ShortfallCause::EpochRotated;
                break; // rotation happened; abandon primary
            }
            if (my_consumed as u64) >= my_effective_share {
                shortfall = AcquireV8ShortfallCause::ShareExhausted;
                break; // primary share exhausted
            }
            let class_curr = v8.epoch.packed_granted.0.load(Ordering::Acquire);
            let (class_tag, class_granted) = PackedEpochGrant::unpack(class_curr);
            if class_tag != my_tag {
                shortfall = AcquireV8ShortfallCause::EpochRotated;
                break;
            }
            if (class_granted as u64) >= cap {
                shortfall = AcquireV8ShortfallCause::ClassCap;
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
                shortfall = AcquireV8ShortfallCause::OutstandingCap;
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
                    shortfall = AcquireV8ShortfallCause::EpochRotated;
                    break;
                }
                if (class_granted as u64) >= cap {
                    shortfall = AcquireV8ShortfallCause::ClassCap;
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
                    shortfall = AcquireV8ShortfallCause::OutstandingCap;
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

        // #1863 Step-0: count the grant side of the ask. Paired with
        // the `worker_requested_bytes` bump at entry.
        if total_granted > 0 {
            v8.worker_granted_bytes[worker_id]
                .0
                .fetch_add(total_granted, Ordering::Relaxed);
        }

        // #1782 Step-1: report the last limiting bound only when the
        // call actually ended short. A fully-granted call may have
        // touched a break site on an earlier loop iteration via the
        // `still_needed == 0` exit and must report `None`.
        if still_needed == 0 {
            (total_granted, AcquireV8ShortfallCause::None)
        } else {
            (total_granted, shortfall)
        }
    }

    /// #1863 Step-0: per-worker cumulative (requested, granted) byte
    /// counters for this lease, or `None` on a legacy (non-v8) lease.
    /// Read by the coordinator status overlay — relaxed loads; the
    /// counters are monotonic and independently meaningful per slot.
    pub(in crate::afxdp) fn v8_worker_claim_flow(&self) -> Option<(Vec<u64>, Vec<u64>)> {
        let v8 = self.v8.as_ref()?;
        let requested = v8
            .worker_requested_bytes
            .iter()
            .map(|a| a.0.load(Ordering::Relaxed))
            .collect();
        let granted = v8
            .worker_granted_bytes
            .iter()
            .map(|a| a.0.load(Ordering::Relaxed))
            .collect();
        Some((requested, granted))
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
        // #4270 (R-9): slots are cache-line-padded (`PaddedAtomicU32`);
        // hand callers the inner `&AtomicU32` so the four mutation sites
        // stay unchanged.
        self.v8
            .as_ref()?
            .worker_active_flow_buckets
            .get(worker_id)
            .map(|s| &s.0)
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
            slot.0.fetch_add(count, Ordering::Relaxed);
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

    pub(in crate::afxdp) fn v8_equal_flow_stale_or_tag_mismatch_events(&self) -> u64 {
        self.v8
            .as_ref()
            .map(|v| {
                v.equal_flow
                    .stale_or_tag_mismatch_events
                    .load(Ordering::Relaxed)
            })
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

    /// #1746: label of the active equal-flow target policy ("slowest" /
    /// "mean" / "ideal-share"). Meaningful only when the lease is in
    /// EqualFlowSuppress mode; defaults to "slowest" otherwise.
    pub(in crate::afxdp) fn v8_equal_flow_target_policy_label(&self) -> &'static str {
        self.v8
            .as_ref()
            .map(|v| v.equal_flow_target_policy.as_str())
            .unwrap_or(EqualFlowTargetPolicy::Slowest.as_str())
    }

    pub(in crate::afxdp) fn v8_equal_flow_fail_open_count(&self) -> u64 {
        self.v8
            .as_ref()
            .map(|v| v.equal_flow.fail_open_count.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
    /// #9117: the per-worker fair share this lease last published. Test-only
    /// accessor so a cell can assert the PRECONDITION of the mid-epoch-newcomer
    /// shape (share published as 0) rather than assuming its setup produced it.
    #[cfg(test)]
    pub(in crate::afxdp) fn v8_worker_fair_share_for_test(&self, id: usize) -> u64 {
        self.v8
            .as_ref()
            .and_then(|v| v.worker_fair_share.get(id))
            .map(|s| s.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    /// #9117: workers excluded for one epoch as mid-epoch newcomers. A flat
    /// fail-open count beside a climbing exclusion count is the fix working:
    /// the class keeps enforcing while the un-comparable worker sits out.
    pub(in crate::afxdp) fn v8_newly_active_excluded_count(&self) -> u64 {
        self.v8
            .as_ref()
            .map(|v| v.equal_flow.newly_active_excluded_count.load(Ordering::Relaxed))
            .unwrap_or(0)
    }


    pub(in crate::afxdp) fn consume(&self, bytes: u64) {
        shared_cos_lease_consume(&self.state, bytes);
    }

    pub(in crate::afxdp) fn release_unused(&self, bytes: u64) {
        shared_cos_lease_release_unused(self.config, &self.state, bytes);
    }

    /// #4246 (T-1, folds R-5(a)): v8-aware lease give-back. The legacy
    /// `release_unused` only moves `outstanding -> available` in the
    /// `state.credits` word — it never touches the v8 epoch ledger. But
    /// `acquire_v8_with_cause` charges every grant to THREE places:
    /// `packed_granted` (the class ledger the ClassCap gate reads),
    /// `outstanding` (state.credits), and `worker_grants[worker_id]`. So a
    /// release that only frees `outstanding` leaves the class + worker
    /// ledgers charged for bytes the queue returned — a mid-rate exact
    /// class oscillating empty<->backlogged at epoch timescale hits
    /// ClassCap early and parks until the next rotation (~94% service; the
    /// plausible #1630 cause-2 mechanism).
    ///
    /// This re-credits the epoch ledger, mirroring the `tag_checked_rollback`
    /// CAS discipline the acquire path uses when `try_bump_outstanding`
    /// fails after a class CAS:
    ///
    ///  1. Free the legacy `outstanding` word (unchanged behaviour).
    ///  2. Claim the credit from THIS worker's current-epoch grant slot via
    ///     a tag-checked CAS, capped at what the slot still holds. The CAS
    ///     serialises concurrent releases (each claims a disjoint slice) and
    ///     a rotation between grant and release safely no-ops: rotation
    ///     swaps the slot to `(new_tag, 0)`, so `consumed` reads 0 ->
    ///     `credit == 0` -> return. Capping at the worker's current-epoch
    ///     grant is what keeps the invariant `sum(worker_grants) ==
    ///     packed_granted` intact when banked burst tokens span an epoch
    ///     boundary — without it a release carrying prior-epoch bytes could
    ///     decrement the class total below the sum of the OTHER workers'
    ///     grants (over-admission).
    ///  3. Decrement `packed_granted` by the SAME claimed credit, tag-
    ///     checked. A rotation between the worker-slot claim (step 2) and
    ///     here fails the tag match and no-ops (rotation reset
    ///     `packed_granted` first, at rotate_epoch_v8 STEP 1).
    ///
    /// For a legacy (non-v8) shared queue lease `self.v8` is `None` and this
    /// reduces to `release_unused`, so every queue-lease give-back site can
    /// route through it unconditionally.
    pub(in crate::afxdp) fn release_unused_v8(&self, worker_id: usize, bytes: u64) {
        // Step 1: legacy leg — free the outstanding/credits word.
        shared_cos_lease_release_unused(self.config, &self.state, bytes);
        let Some(v8) = self.v8.as_ref() else {
            return;
        };
        if bytes == 0 {
            return;
        }
        let Some(my_pg) = v8.worker_grants.get(worker_id) else {
            debug_assert!(
                false,
                "release_unused_v8 worker_id {} out of range (len {})",
                worker_id,
                v8.worker_grants.len()
            );
            return;
        };
        // Step 2: claim the credit from this worker's current-epoch grant.
        let (tag, credit) = loop {
            let curr = my_pg.0.load(Ordering::Acquire);
            let (tag, consumed) = PackedEpochGrant::unpack(curr);
            // Cap at the worker's current-epoch grant: a release carrying
            // banked bytes granted in a PRIOR epoch must not decrement more
            // than this worker holds this epoch.
            let credit = bytes.min(consumed as u64) as u32;
            if credit == 0 {
                return; // nothing granted this epoch, or rotated — no-op
            }
            let new = PackedEpochGrant::pack(tag, consumed - credit);
            if my_pg
                .0
                .compare_exchange_weak(curr, new, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break (tag, credit);
            }
        };
        // Step 3: decrement the class ledger by the SAME claimed credit.
        // A rotation between step 2 and here (tag mismatch) or retry-budget
        // exhaustion makes this a no-op — `recredited` reports what actually
        // reached packed_granted (0 in those cases).
        let recredited = tag_checked_rollback(
            &v8.epoch.packed_granted,
            tag,
            credit,
            &v8.epoch.rollback_retry_exceeded,
        );
        // #1630 cause-2 empirical hook: accumulate ONLY bytes genuinely
        // re-credited to the class ledger so give-back can be summed
        // against per-class undershoot without over-reporting (#4246
        // Copilot comment 3). A step-3 no-op contributes nothing here.
        if recredited > 0 {
            v8.epoch
                .release_recredited_bytes
                .fetch_add(recredited as u64, Ordering::Relaxed);
        }
    }

    /// #4246 (T-1): cumulative bytes re-credited to the epoch ledger by
    /// `release_unused_v8`. Returns 0 for legacy leases. Diagnostic hook
    /// for the #1630 cause-2 falsification test.
    pub(in crate::afxdp) fn v8_release_recredited_bytes(&self) -> u64 {
        self.v8
            .as_ref()
            .map(|v| v.epoch.release_recredited_bytes.load(Ordering::Relaxed))
            .unwrap_or(0)
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
            // #1643: seqlock reader payload loads are Relaxed and SEALED
            // by an explicit `fence(Acquire)` before the trailing
            // `seq_after` re-read. The previous `Acquire` loads only
            // prevented LATER ops from hoisting above each load; they did
            // NOT pin these payload reads ABOVE the `seq_after` read, so on
            // a weakly-ordered CPU (ARM/POWER) `seq_after` could retire
            // before the payload loads and the even-equal validation could
            // pass against torn cross-epoch data (the #1619 tearing class).
            // The fence guarantees all payload loads complete before
            // `seq_after` is read, matching the verified-correct
            // `cold_path_hist.rs::snapshot` reference. Latent on the
            // x86-TSO i40e/mlx5 deploy targets but a real hazard on any
            // weakly-ordered CPU.
            let cap = v8.epoch.epoch_total_grant_cap.load(Ordering::Relaxed);
            let share = v8
                .worker_fair_share
                .get(worker_id)
                .map(|a| a.load(Ordering::Relaxed))
                .unwrap_or(0);
            let grace = v8.epoch.epoch_grace_expires_ns.load(Ordering::Relaxed);
            std::sync::atomic::fence(Ordering::Acquire);
            let seq_after = v8.epoch.epoch_seq.load(Ordering::Relaxed);
            if seq_after == seq_before {
                return Some((cap, share, grace, (seq_before >> 1) as u32));
            }
            spins += 1;
            if spins >= MAX_SEQ_SPINS {
                return None;
            }
        }
    }

    /// #4260 (hb166 R-3) test hook: expose the private seqlock snapshot so
    /// the writer/reader ordering-correctness test can observe the raw
    /// `(cap, share, grace, tag)` tuple and assert the cross-field
    /// tag/grace invariant a torn read would violate. Test-only — never
    /// compiled into the shipping helper.
    #[cfg(test)]
    pub(in crate::afxdp) fn test_snapshot_epoch_v8(
        &self,
        worker_id: usize,
    ) -> Option<(u64, u64, u64, u32)> {
        self.snapshot_epoch_v8(worker_id)
    }

    // pub(super): called by the co-located `tests` module (equal-flow cap
    // unit tests). Inherent-private before the split.
    pub(super) fn equal_flow_cap_v8(
        &self,
        v8: &V8State,
        worker_id: usize,
        epoch_tag: u32,
    ) -> Option<u64> {
        if v8.rate_mode != V8RateMode::EqualFlowSuppress {
            return None;
        }
        // Acquire-side cap evaluation is intentionally read-only. Epoch
        // rotation owns fail-open publication; stale acquirers must not
        // overwrite the freshly-published payload for a new epoch. Keep
        // the transient stale-tag signal on a separate monotonic side
        // channel so operators still see the fail-open class.
        if v8.equal_flow.epoch_tag.load(Ordering::Acquire) != epoch_tag {
            v8.equal_flow
                .stale_or_tag_mismatch_events
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        if v8.equal_flow.enforced.load(Ordering::Acquire) == 0 {
            return None;
        }
        let target = v8
            .equal_flow
            .current_target_per_flow
            .load(Ordering::Acquire);
        if target == 0 {
            return None;
        }
        let active_flows = v8
            .worker_active_flow_buckets
            .get(worker_id)
            .map(|a| a.0.load(Ordering::Relaxed) as u64)
            .unwrap_or(0);
        if active_flows == 0 {
            return Some(0);
        }
        target.checked_mul(active_flows)
    }
}

/// #1229 Phase 6 v8: try to bump outstanding_leased_tokens by `take`.
/// Returns `true` if successful; `false` if cap reached (caller must
/// rollback the corresponding epoch grant).
// #[inline]: cross-module hot helper (called from `acquire_v8` primary +
// surplus loops). LTO is off (codegen-units 16) for this crate, so the
// move across the file boundary would otherwise lose the implicit
// single-translation-unit inlining the pre-split form had. (#2158 §6)
#[inline]
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

/// #1745: tag-checked sticky-max record of a per-worker active-flow
/// sample. Records `max(curr, active_flows)` for the current epoch tag.
///
/// CRITICAL race safety: an acquirer snapshots `my_tag` from the seqlock
/// before this call. The rotation winner installs the fresh `(new_tag, 0)`
/// into every sample slot (the gated swap in `rotate_epoch_v8`) BEFORE it
/// publishes the new epoch via the seqlock seq store, so by the time any
/// acquirer observes `my_tag = N` the slot already carries tag `N`. The
/// only writable case is therefore `curr_tag == my_tag`; on any mismatch
/// we no-op.
///
/// The match is **tag EQUALITY, not ordering** — identical to the
/// discipline of `bump_epoch_event` / `worker_grant_bump`. A relational
/// `curr_tag > my_tag` check would be UNSAFE at the `u32` tag wrap (every
/// ~9.94 days at the 200 µs epoch): a stale acquirer holding
/// `my_tag = u32::MAX` racing a rotation that reset the slot to `(0, 0)`
/// would see `0 > u32::MAX == false` and write its wrapped-old tag
/// backwards over the fresh epoch (Codex code-review HIGH). Equality
/// no-ops on the wrap mismatch exactly as it does on any other rotation,
/// dropping at most one sample — the same tolerated, wrap-safe behaviour
/// the sibling helpers already rely on.
// pub(super): reached by the co-located `tests` module (the acquire-time
// equal-flow sampling regression tests). Inherent-private before split.
#[inline]
pub(super) fn record_equal_flow_active_sample(
    pg: &PackedEpochGrant,
    my_tag: u32,
    active_flows: u32,
) {
    loop {
        let curr = pg.0.load(Ordering::Acquire);
        let (curr_tag, curr_count) = PackedEpochGrant::unpack(curr);
        if curr_tag != my_tag {
            return; // rotation occurred (incl. tag wrap); drop this sample
        }
        if curr_count >= active_flows {
            return; // already at or above the sticky-max; nothing to do
        }
        let new = PackedEpochGrant::pack(my_tag, active_flows);
        if pg
            .0
            .compare_exchange_weak(curr, new, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return;
        }
    }
}

/// #1826 (#1663 finding 1.11): release-visible invariant-violation counter
/// for the grant-overflow guard in `worker_grant_bump`. The
/// `debug_assert!` there is compiled out in release builds, so without
/// this the violation (refuse-the-grant + continue) is invisible in
/// production. Local-only diagnostic — intentionally NOT plumbed into the
/// wire status protocol; read via the first-hit stderr line.
static WORKER_GRANT_OVERFLOWS: AtomicU64 = AtomicU64::new(0);

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
            // Cold path: never taken unless grant accounting is already
            // broken. First hit logs once to journald (stderr).
            if WORKER_GRANT_OVERFLOWS.fetch_add(1, Ordering::Relaxed) == 0 {
                eprintln!(
                    "xpf-userspace-dp: invariant violation: worker_grants \
                     overflow tag={curr_tag} curr={curr_granted} take={take} \
                     (local counter only)"
                );
            }
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
///
/// Returns the amount ACTUALLY decremented from `pg`: `min(take,
/// curr_granted)` on a successful tag-matched CAS, or 0 when a rotation
/// (tag mismatch) or retry-budget exhaustion prevented the decrement.
/// The acquire-rollback callers ignore the return; `release_unused_v8`
/// uses it so its #1630 diagnostic counter only counts bytes that
/// genuinely reached `packed_granted` (#4246 Copilot comment 3).
#[inline]
fn tag_checked_rollback(pg: &PackedEpochGrant, my_tag: u32, take: u32, metric: &AtomicU64) -> u32 {
    for _retry in 0..MAX_ROLLBACK_RETRIES {
        let curr = pg.0.load(Ordering::Acquire);
        let (curr_tag, curr_granted) = PackedEpochGrant::unpack(curr);
        if curr_tag != my_tag {
            return 0; // rotation occurred; rollback unnecessary
        }
        let new_granted = curr_granted.saturating_sub(take);
        let new = PackedEpochGrant::pack(curr_tag, new_granted);
        if pg
            .0
            .compare_exchange_weak(curr, new, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // saturating_sub means the real delta is min(take, curr_granted).
            return curr_granted - new_granted;
        }
    }
    metric.fetch_add(1, Ordering::Relaxed);
    0
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

    #[inline]
    pub(in crate::afxdp) fn active_shards(&self) -> usize {
        self.config.active_shards
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
