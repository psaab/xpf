// #2158 (P2): #1229 Phase 6 v8 epoch-state cluster, extracted from
// shared_cos_lease/mod.rs as a pure code-motion split. Type/impl/const
// bodies are byte-identical to the pre-split form; atomic memory
// orderings and the seqlock contract are preserved exactly.
//
// VISIBILITY WIDENING (the only non-move edits in this file):
// the lease/rotation/publish logic lives in sibling submodules
// (`lease.rs`, `rotate_epoch_v8.rs`, `publish_equal_flow_epoch_v8.rs`).
// In Rust a private item is visible only within its defining module and
// that module's *descendants*; a sibling submodule is NOT a descendant.
// Before this split these epoch types were defined in the parent
// (`mod.rs`), so every descendant submodule saw their inherent-private
// fields for free. Moving the definitions into this child submodule makes
// those fields private-to-`epoch`, so each item a sibling reaches across
// the new file boundary is widened from inherent-private to `pub(super)`
// — the SAME minimal widening the already-extracted `rotate_epoch_v8.rs`
// / `publish_equal_flow_epoch_v8.rs` (PR #1588) documented. No new `pub`
// / `pub(crate)` surface; no cross-crate change. The exhaustive widening
// list is recorded inline at each item below and summarized in the PR.
//
// The mode/cause/fail-open enums that are part of the lease's public-to-
// afxdp surface keep their original `pub(in crate::afxdp)` visibility
// (they are re-exported by `types/mod.rs` and consumed across afxdp).

use super::*;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

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
// pub(super): read by `lease.rs` (acquire_v8 bps math) and
// `rotate_epoch_v8.rs`.
pub(super) const EPOCH_DURATION_NS: u64 = 200_000;

/// #1630 (cause-1): rate-recovery width for the rotation credit carry.
///
/// `maybe_rotate_epoch_v8` is purely lazy — a low-rate exact class is
/// only rotated when the scheduler next visits its queue, so the gap
/// (`lag = now − epoch_start`) between two rotations of the SAME queue
/// routinely exceeds one epoch under round-robin across 11+ classes. The
/// pre-#1630 clamp computed `elapsed = min(lag, EPOCH)` and then reset
/// `epoch_start := now`, permanently discarding `rate × (lag − EPOCH)` of
/// grant per lagged rotation. That pinned the lowest-rate classes well
/// below shape even SOLO (100m 81 %, 1g 84 %).
///
/// `MAX_ROTATION_LAG_EPOCHS` (K) is the number of epochs of lag a single
/// rotation recovers in full. It is the bounded relaxation of the clamp:
/// a single rotation can grant at most `K × rate × EPOCH` of base credit,
/// so the per-class post-stall burst is hard-bounded (the invariant the
/// old clamp protected). K = 8 matches the diagnostic probe that lifted
/// the SOLO ceilings; the §3.6 SOLO A/B confirmed small-K + P2 clears the
/// scoped Gate-1 (100m/1g) without an aggregate-burst hazard (Fork A).
// pub(super): read by `rotate_epoch_v8.rs` (carry window math).
pub(super) const MAX_ROTATION_LAG_EPOCHS: u64 = 8;

/// #1630 (cause-1): cold-resume cutoff FLOOR for the rotation credit
/// carry, DECOUPLED from `MAX_ROTATION_LAG_EPOCHS`.
///
/// A lag beyond the stall window is not a legitimate intermittent
/// visit gap — it is a worker/RG stall (GC pause, scheduler
/// starvation) or an HA demote→promote gap on a REUSED lease (leases
/// are reused when config matches, so `epoch_start` survives across a
/// failover and the first post-promotion rotation sees
/// `lag ≈ demotion_duration`). In that regime the rotation cold-
/// resumes to a single-epoch grant and DROPS any banked carry, so a
/// long-stalled or just-promoted worker cannot emit a stall-duration
/// burst.
///
/// #15100 (A70-02): the FIXED 256-epoch floor (51.2 ms) alone
/// misclassifies a low-rate class's OWN self-scheduled park as a
/// stall: a backlogged exact queue parks until a full frame refills at
/// its configured rate (`cos_refill_ns_until`), which at 64 kbps is
/// 187.5 ms for a 1500 B frame — beyond the fixed window — so every
/// revisit cold-resumed and dropped the credit, blackholing the
/// class. The effective window is therefore
/// `max(floor, frame-refill time at this lease's rate)`, computed by
/// `stall_window_ns_for_rate` below. The fixed floor keeps its
/// original role for rates whose frame time is shorter: the failback
/// path is ≥100 ms (≥500 epochs), so a genuinely stalled or
/// just-promoted lease still cold-resumes once its lag exceeds BOTH.
// pub(super): read by `rotate_epoch_v8.rs` (stall window math).
pub(super) const STALL_THRESHOLD_EPOCHS: u64 = 256;

/// #15100 (A70-02): the largest frame a scheduled queue can be
/// waiting to refill, in bytes (one UMEM frame — the lease bank's own
/// frame unit). The stall window's rate-relative term uses it
/// (`stall_window_ns_for_rate`): a backlogged exact queue parks until
/// its head frame refills, and head frames run to the full frame
/// capacity, so the window must cover a full-capacity refill at the
/// configured rate before a lag may be called a stall. At 8000 B/s
/// that is 4096 B / 8000 B/s = 512 ms; at 1 Mbps, 32.8 ms (below the
/// fixed floor, which then dominates).
// pub(super): read by `rotate_epoch_v8.rs` (stall window math).
pub(super) const FRAME_BYTES: u64 = 4096;

/// #15100 (A70-02): self-scheduled park time at the largest frame
/// this scheduler serves — alias kept for the stall-window helper.
pub(super) const STALL_FRAME_BYTES: u64 = FRAME_BYTES;

/// #15100 (A70-02): rate-relative lag (K) window for a lease at
/// `rate_bytes` B/s: the fixed `K × EPOCH` window, or the time to
/// refill one full frame at this rate, whichever is longer. A
/// backlogged exact queue's revisit lag IS its frame refill time, so
/// the recovery window must cover it or the rotation grants only
/// `K × EPOCH` of credit per park and banks the rest into a carry the
/// next equally-lagged visit cannot drain in time. The byte burst is
/// still bounded: `rate × lag_window` never exceeds
/// `max(K × rate × EPOCH, FRAME_BYTES)`. A rate of 0 yields the fixed
/// window (a transparent lease has no self-park to protect).
pub(super) fn lag_window_ns_for_rate(rate_bytes: u64) -> u64 {
    let fixed_ns = EPOCH_DURATION_NS * MAX_ROTATION_LAG_EPOCHS;
    if rate_bytes == 0 {
        return fixed_ns;
    }
    let frame_ns = ((FRAME_BYTES as u128) * 1_000_000_000u128) / (rate_bytes as u128);
    let frame_ns = frame_ns.min(u128::from(u64::MAX)) as u64;
    fixed_ns.max(frame_ns)
}

/// #15100 (A70-02): effective stall (cold-resume) window for a lease
/// at `rate_bytes` B/s: the fixed `STALL_THRESHOLD_EPOCHS` floor, or
/// twice the rate-relative lag window, whichever is longer. The stall
/// cutoff must sit ABOVE the lag window or a self-parked class whose
/// lag lands between them cold-resumes and drops its banked carry on
/// every revisit. A rate of 0 yields the fixed floor.
pub(super) fn stall_window_ns_for_rate(rate_bytes: u64) -> u64 {
    let floor_ns = EPOCH_DURATION_NS * STALL_THRESHOLD_EPOCHS;
    if rate_bytes == 0 {
        return floor_ns;
    }
    floor_ns.max(lag_window_ns_for_rate(rate_bytes).saturating_mul(2))
}

/// #1630 (cause-1): reservoir cap for the rotation credit carry — the
/// MAXIMUM unbanked rate credit a class can ever owe. Bounds the
/// post-stall catch-up burst.
///
/// #15100 (A70-02): the reservoir is sized in BYTES at lease creation
/// (`V8State::carry_max_bytes` / `carry_drain_max_bytes`), not in
/// epochs: at low rates the epoch-sized cap
/// (`MAX_ROTATION_LAG_EPOCHS × rate × EPOCH` = 12.8 B at 8000 B/s) is
/// below one frame, so a banked residual could never reassemble even
/// a single frame and the class blackholed. The byte cap is at least
/// one frame so the self-parked class can always rebuild its next
/// frame; the drain keeps the `(K−1)/K` proportion of the reservoir so
/// a single rotation's carry draw stays a bounded fraction of the
/// bank. For rates whose epoch-cap already exceeds a frame the byte
/// caps equal the epoch caps exactly (no behaviour change).
// pub(super): read by `rotate_epoch_v8.rs` (carry reservoir math).
pub(super) const CARRY_MAX_EPOCHS: u64 = MAX_ROTATION_LAG_EPOCHS;
pub(super) const CARRY_DRAIN_MAX_EPOCHS: u64 = MAX_ROTATION_LAG_EPOCHS - 1;

/// #15100 (A70-02): reservoir floor in bytes — at least one maximum-
/// size frame, so the banked credit of a self-parked class can always
/// reassemble the frame it is parked waiting for. 4096 matches the
/// UMEM frame capacity the lease bank already uses
/// (`COS_EXACT_QUEUE_LEASE_BANK_BYTES` frames are 4096 B).
pub(super) const CARRY_FRAME_BYTES: u64 = 4096;

/// Bound on seqlock-snapshot retries.
// pub(super): read by `lease.rs` (snapshot_epoch_v8 spin bound).
pub(super) const MAX_SEQ_SPINS: u32 = 64;

/// Bound on tag_checked_rollback retries.
// pub(super): read by `lease.rs` (tag_checked_rollback retry budget).
pub(super) const MAX_ROLLBACK_RETRIES: u32 = 16;

/// Packed (epoch_tag << 32 | granted_bytes). Used for both class-wide
/// `epoch_total_granted` and per-worker `worker_grants[id]`. Cross-
/// epoch CAS naturally rejected because rotation bumps the tag.
// pub(super): named + constructed + `.0`-accessed by `lease.rs` and
// `rotate_epoch_v8.rs`. The tuple field is widened (pub(super)) because
// both siblings load/CAS the inner `AtomicU64` directly via `pg.0`.
#[repr(align(64))]
pub(super) struct PackedEpochGrant(pub(super) AtomicU64);

/// #1863 Step-0: cache-line-aligned cumulative counter slot. Same
/// 64-byte isolation contract as `PackedEpochGrant`, for per-worker
/// slots written on every acquire (`worker_requested_bytes` /
/// `worker_granted_bytes`) — without the epoch-tag packing those
/// monotonic counters do not need.
// pub(super): named (as a `V8State` field type) + `.0`-accessed by
// `lease.rs` (acquire_v8 fetch_add / v8_worker_claim_flow loads).
#[repr(align(64))]
pub(super) struct PaddedAtomicU64(pub(super) AtomicU64);

/// #4270 (R-9): cache-line-aligned per-worker `AtomicU32` slot. Same
/// 64-byte isolation contract as `PackedEpochGrant` / `PaddedAtomicU64`,
/// for `worker_active_flow_buckets` — the per-worker active-flow counter
/// written per flow-bucket activation/teardown by each worker on its OWN
/// slot (single-writer-per-slot) and read on every `acquire_v8` /
/// `equal_flow_cap_v8`. Before this padding, 16 raw `AtomicU32`s packed
/// onto one cache line and false-shared on every per-flow-churn write —
/// the one per-acquire-written per-worker array the isolation rule had
/// missed.
// pub(super): named (as the `V8State::worker_active_flow_buckets` element
// type) + `.0`-accessed by `lease.rs` / `rotate_epoch_v8.rs` /
// `publish_equal_flow_epoch_v8.rs`.
#[repr(align(64))]
pub(super) struct PaddedAtomicU32(pub(super) AtomicU32);

// #4270 (R-9): pin the padding at compile time — RED if the
// `#[repr(align(64))]` is dropped or the atomic grows past a line.
const _: () = assert!(core::mem::align_of::<PaddedAtomicU32>() == 64);
const _: () = assert!(core::mem::size_of::<PaddedAtomicU32>() == 64);

impl PackedEpochGrant {
    // pub(super): pack/unpack/new called from `lease.rs` and
    // `rotate_epoch_v8.rs`. `store_for_new_epoch` retained at its
    // original (private) visibility — it has no cross-submodule caller.
    #[inline(always)]
    pub(super) const fn pack(tag: u32, granted: u32) -> u64 {
        ((tag as u64) << 32) | (granted as u64)
    }

    #[inline(always)]
    pub(super) const fn unpack(v: u64) -> (u32, u32) {
        ((v >> 32) as u32, v as u32)
    }

    pub(super) fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    fn store_for_new_epoch(&self, new_tag: u32) {
        self.0.store(Self::pack(new_tag, 0), Ordering::Release);
    }
}

// pub(super): `SharedCoSEpochState` is the `V8State::epoch` field type and
// its fields are read/written across the lease/rotate/publish siblings;
// every field reached by a sibling is widened to pub(super) below.
#[repr(align(64))]
pub(super) struct SharedCoSEpochState {
    /// Bit 0: 0=stable, 1=rotating. Increments by 2 per completed
    /// rotation. Upper bits double as a generation counter.
    /// epoch_tag = (seq >> 1) as u32.
    pub(super) epoch_seq: AtomicU64,
    pub(super) epoch_start_ns: AtomicU64,
    /// Capped at u32::MAX. Computed as `rate × elapsed + carry_draw` per
    /// rotation, where `elapsed` is bounded by `K × EPOCH_DURATION_NS`
    /// (#1630 cause-1 credit carry — was `rate × min(elapsed, EPOCH)`).
    pub(super) epoch_total_grant_cap: AtomicU64,
    /// #1630 (cause-1): ROTATION-PRIVATE bounded credit deficit (bytes).
    ///
    /// Holds the rate credit a lagged rotation could not grant in full
    /// (`rate × (lag − K×EPOCH)`), banked for the next visit and clamped
    /// at `CARRY_MAX_EPOCHS × rate × EPOCH`. Read AND written ONLY by the
    /// rotation winner, entirely inside the seqlock ODD critical section
    /// (between the EVEN→ODD CAS and the ODD→EVEN publish in
    /// `maybe_rotate_epoch_v8`). It is deliberately NOT part of the
    /// `snapshot_epoch_v8` published payload — acquirers never read it —
    /// so it adds no new reader-visible seqlock surface (would otherwise
    /// be the #1619 tearing class). This privacy is ENFORCED by a grep
    /// test in `shared_cos_lease_tests.rs`; do NOT add a `pub` accessor or
    /// read it from `acquire_v8`/`snapshot_epoch_v8`/`coordinator/status`.
    /// Reset to 0 on cold-resume (lag > STALL or start==0) so it cannot
    /// leak a stale deficit across an HA demote→promote gap.
    pub(super) epoch_carry_bytes: AtomicU64,
    pub(super) epoch_grace_expires_ns: AtomicU64,
    /// Packed (epoch_tag, total_granted_this_epoch).
    pub(super) packed_granted: PackedEpochGrant,
    /// Diagnostic: increments when tag_checked_rollback exceeds
    /// MAX_ROLLBACK_RETRIES with tag still matching. Failure mode is
    /// undergrant (class shows extra outstanding bytes until next
    /// rotation), NOT overshoot.
    pub(super) rollback_retry_exceeded: AtomicU64,
    /// #4246 (T-1): cumulative bytes re-credited to `packed_granted` by
    /// `release_unused_v8` on lease give-back (queue drained mid-epoch).
    /// Monotonic, relaxed. Exposed so an operator can sum give-back
    /// against per-class undershoot on a mid-rate on/off pattern — the
    /// falsification test for the #1630 cause-2 attribution (the ~6%
    /// mid-rate residual may be this ledger double-charge). Diagnostic
    /// only; not part of the seqlock-published epoch payload.
    pub(super) release_recredited_bytes: AtomicU64,
    /// #1231 v5: 'all peers CPU-bound' bypass-grace countdown. When
    /// set to N > 0 by rotation, the next N rotations open the surplus
    /// path immediately (no grace-period gate) for active workers.
    /// Rotation arms it when ANY active worker had a starvation event
    /// in the prior epoch, aggregate grant was materially sub-cap, and
    /// at least one active non-signaling peer was both under-utilized
    /// and had queue-lease demand in that epoch. Decays one rotation
    /// at a time when the full detector does not fire.
    pub(super) bypass_grace_rotations_remaining: AtomicU32,
    /// #1231 v5: telemetry — count of rotations where the bypass was
    /// armed. Operator-visible via Prometheus.
    pub(super) bypass_grace_arm_count: AtomicU64,
    /// #1231 v5: telemetry — count of acquire calls that took surplus
    /// because bypass was active (would have been blocked by grace
    /// otherwise). Useful to confirm bypass is actually being
    /// consumed when armed.
    pub(super) bypass_grace_use_count: AtomicU64,
}

impl SharedCoSEpochState {
    // pub(super): constructed from `lease.rs` (V8State build in new_v8*).
    pub(super) fn new() -> Self {
        Self {
            epoch_seq: AtomicU64::new(0),
            epoch_start_ns: AtomicU64::new(0),
            epoch_total_grant_cap: AtomicU64::new(0),
            epoch_carry_bytes: AtomicU64::new(0),
            epoch_grace_expires_ns: AtomicU64::new(0),
            packed_granted: PackedEpochGrant::new(),
            rollback_retry_exceeded: AtomicU64::new(0),
            release_recredited_bytes: AtomicU64::new(0),
            bypass_grace_rotations_remaining: AtomicU32::new(0),
            bypass_grace_arm_count: AtomicU64::new(0),
            bypass_grace_use_count: AtomicU64::new(0),
        }
    }
}

// pub(super): `V8State` is the `SharedCoSQueueLease::v8` payload, built in
// `lease.rs` and read by `lease.rs`/`rotate_epoch_v8.rs`/
// `publish_equal_flow_epoch_v8.rs`. Every field is reached by at least one
// sibling, so all fields are widened to pub(super).
pub(super) struct V8State {
    pub(super) epoch: SharedCoSEpochState,
    pub(super) rate_mode: V8RateMode,
    /// #15100 (A70-02): rate-relative lag (recovery) window in
    /// nanoseconds, computed once at lease creation:
    /// `max(K × EPOCH, FRAME_BYTES × 1e9 / rate)`. The rotation grants
    /// `rate × min(lag, lag_window)` per visit, so a self-parked
    /// low-rate class recovers its full frame credit on revisit while
    /// the byte burst stays bounded (`rate × lag_window` is at most
    /// `max(K × rate × EPOCH, FRAME_BYTES)`). Equals the fixed
    /// `K × EPOCH` window whenever that already covers a frame.
    pub(super) lag_window_ns: u64,
    /// #15100 (A70-02): carry reservoir cap in BYTES:
    /// `rate × lag_window` (the largest deficit one lagged rotation
    /// can owe), floored at one frame. Equals the pre-#15100
    /// `CARRY_MAX_EPOCHS × rate × EPOCH` cap whenever the fixed window
    /// dominates.
    pub(super) carry_max_bytes: u64,
    /// #15100 (A70-02): per-rotation carry DRAIN cap in bytes:
    /// `carry_max_bytes × (K−1)/K`, floored at one frame when the
    /// reservoir itself is floored so a banked frame can drain in a
    /// single visit. Equals the pre-#15100 epoch drain cap whenever
    /// the fixed window dominates.
    pub(super) carry_drain_max_bytes: u64,
    /// #1746: equal-flow target policy. Read only by
    /// `publish_equal_flow_epoch_v8` (once per rotation, in
    /// EqualFlowSuppress mode only). `Slowest` is the byte-unchanged
    /// default; a config policy change rebuilds the lease
    /// (`matches_config_v8` includes it).
    pub(super) equal_flow_target_policy: EqualFlowTargetPolicy,
    /// Per-worker grants this epoch. Length = max_worker_id + 1.
    /// Each slot is packed (epoch_tag, worker_granted_this_epoch).
    /// Single-writer-per-slot: only worker `id` writes worker_grants[id].
    pub(super) worker_grants: Box<[PackedEpochGrant]>,
    /// Per-worker active flow bucket count. Length = max_worker_id + 1.
    /// Single-writer-per-slot: only worker `id` writes its own slot
    /// (deltas via active_buckets.rs helpers, install via rehydrate).
    pub(super) worker_active_flow_buckets: Box<[PaddedAtomicU32]>,
    /// Per-worker fair share (bytes/epoch) snapshot, recomputed at
    /// rotation. Length = max_worker_id + 1.
    pub(super) worker_fair_share: Box<[AtomicU64]>,
    /// #1231 v5: per-worker starvation events this epoch. Each slot is
    /// packed (epoch_tag, event_count). Bumped via tag-checked CAS at
    /// the narrow-signal exit in acquire_v8: "primary exhausted AND
    /// class room remains AND active AND still_needed > 0". Reset at
    /// rotation via atomic swap (returned old captures any in-flight
    /// bumps; tag mismatch on subsequent in-flight CAS naturally
    /// rejects them). Length = max_worker_id + 1.
    pub(super) worker_starvation_events: Box<[PackedEpochGrant]>,
    /// #1290 round-2: per-worker queue-lease demand events this epoch.
    /// Bumped once per active acquire_v8 call before granting. Rotation
    /// uses this to distinguish a genuinely backlogged under-utilized
    /// peer from a naturally quiet peer whose active-flow counter is
    /// merely nonzero. Length = max_worker_id + 1.
    pub(super) worker_demand_events: Box<[PackedEpochGrant]>,
    /// #1745: per-worker tagged max active-flow sample, recorded at
    /// `acquire_v8` time (when the worker requests lease credit while
    /// active). Each slot is packed (epoch_tag, max_active_flows_seen).
    /// Decouples the equal-flow sample set from the rotation-instant
    /// `worker_active_flow_buckets` read + the per-epoch demand boolean,
    /// which together missed exact-queue workers running on banked tokens:
    /// they skip `acquire_v8` at the bank watermark
    /// (`cos/token_bucket.rs`) and so did not bump demand for an epoch
    /// whose consumption stayed under the bank, even while their flow
    /// bucket was nonzero. Recorded ONLY in `EqualFlowSuppress` rate mode
    /// (the default `CstructDefault` path never touches this array, on
    /// both the acquire and rotation sides — see the gates in
    /// `acquire_v8` and `rotate_epoch_v8`). Swapped at rotation alongside
    /// `worker_demand_events`. Length = max_worker_id + 1, in lock-step
    /// with `worker_grants`. Single-writer-per-slot on the acquire side
    /// (only worker `id` writes its slot); rotation winner is the sole
    /// swapper.
    pub(super) worker_equal_flow_active_samples: Box<[PackedEpochGrant]>,
    /// #1863 Step-0: per-worker CUMULATIVE acquire-flow counters —
    /// requested bytes (every `acquire_v8` call with `requested > 0`,
    /// counted whether or not the call grants) and granted bytes
    /// (`total_granted` at call exit). Unlike the per-epoch arrays
    /// above these are NEVER reset at rotation: they are monotonic
    /// counters whose deltas attribute the honored-realization gap
    /// between share/demand mismatch (workers asking beyond their
    /// share) and claim-sampling loss (workers not asking at all) —
    /// the registered Path-A Step-0 decision rule in
    /// `docs/pr/1863-realization-gap/plan.md` §5. Single
    /// relaxed fetch_add per acquire on the caller's own slot, in a
    /// cache-line-aligned wrapper (`PaddedAtomicU64`) so per-worker
    /// slots never share a line — the same isolation rule
    /// `PackedEpochGrant` enforces for every other per-acquire-written
    /// per-worker array (review r1: unpadded `AtomicU64` slots would
    /// have put 8 workers on one line and bounced it on every
    /// acquire). Length = max_worker_id + 1.
    pub(super) worker_requested_bytes: Box<[PaddedAtomicU64]>,
    pub(super) worker_granted_bytes: Box<[PaddedAtomicU64]>,
    pub(super) equal_flow: V8EqualFlowSuppressState,
    /// #1830 (e): pre-allocated rotation scratch, sized to
    /// `max_worker_id + 1` at lease construction. Replaces the former
    /// fixed `[_; 32]` stack arrays in `maybe_rotate_epoch_v8`, which
    /// silently degraded hosts with >32 workers (workers past the cap
    /// were lumped into `active_outside_scratch` and forced an
    /// equal-flow fail-open every epoch).
    ///
    /// Concurrency: only the rotation WINNER (the unique thread whose
    /// EVEN→ODD CAS on `epoch_seq` succeeds for a cycle) touches this,
    /// so the `Mutex` is uncontended by construction — `lock()` costs
    /// one uncontended CAS, at most once per `EPOCH_DURATION_NS`
    /// (200 µs) per lease. The Mutex exists to express that exclusivity
    /// in safe Rust, not to arbitrate real contention. No heap
    /// allocation ever happens at rotation time; the boxes are built
    /// once in `new_v8_with_rate_mode` (cold: lease build/rebuild on
    /// config commit or HA transition).
    pub(super) rotation_scratch: Mutex<V8RotationScratch>,
}

/// #1830 (e): per-rotation scratch capturing the just-ended epoch's
/// per-worker swap results. Every slot is unconditionally overwritten
/// by the rotation winner before being read (see `maybe_rotate_epoch_v8`
/// STEP 2/3 and the EqualFlowSuppress sample swap), so no cross-rotation
/// state leaks through it.
// pub(super): named (as a `V8State` field type), constructed from
// `lease.rs`, and its fields are accessed by `rotate_epoch_v8.rs`.
pub(super) struct V8RotationScratch {
    pub(super) signaled_by_worker: Box<[bool]>,
    pub(super) demanded_by_worker: Box<[bool]>,
    pub(super) active_by_worker: Box<[bool]>,
    pub(super) prev_grants: Box<[u32]>,
    pub(super) sampled_active_flows_by_worker: Box<[u32]>,
}

impl V8RotationScratch {
    // pub(super): constructed from `lease.rs` (V8State build in new_v8*).
    pub(super) fn new(len: usize) -> Self {
        Self {
            signaled_by_worker: vec![false; len].into_boxed_slice(),
            demanded_by_worker: vec![false; len].into_boxed_slice(),
            active_by_worker: vec![false; len].into_boxed_slice(),
            prev_grants: vec![0u32; len].into_boxed_slice(),
            sampled_active_flows_by_worker: vec![0u32; len].into_boxed_slice(),
        }
    }
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

/// #1782 Step-1 (§5.2 mechanism (ii) disambiguation): the bound that
/// ended an `acquire_v8` call short of its request. `None` means the
/// request was fully granted (or no shortfall attribution applies —
/// `requested == 0` / legacy-lease / out-of-range debug paths).
/// `EpochRotated` is additive beyond the plan's five named causes: a
/// tag-checked break caused by a concurrent epoch rotation is a
/// transient, not a capacity bound, and folding it into
/// `ShareExhausted`/`ClassCap` would corrupt the per-cause attribution
/// the Step-1 counters exist to provide.
///
/// Consumed by the selector sites in `cos/queue_service/mod.rs`: the
/// cause is only COUNTED when the post-top-up `queue.hot.tokens <
/// head_len` comparison shows the queue could not service its head
/// (plan r2 F1 — `acquire_v8` itself never sees `head_len`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) enum AcquireV8ShortfallCause {
    /// Fully granted, or no v8 shortfall attribution applies.
    #[default]
    None,
    /// `snapshot_epoch_v8` gave up after `MAX_SEQ_SPINS`.
    SeqlockGiveUp,
    /// Stable epoch snapshot returned `cap == 0`.
    CapZero,
    /// Tag-checked read/CAS observed a concurrent epoch rotation.
    EpochRotated,
    /// This worker's fair share (`my_effective_share`) is consumed.
    ShareExhausted,
    /// The class-wide epoch cap (`cap`) is consumed.
    ClassCap,
    /// `try_bump_outstanding` hit `max_total_leased`.
    OutstandingCap,
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
    // pub(super): `from_u32` is called from `lease.rs`
    // (v8_equal_flow_fail_open_reason); `as_str` is called from `lease.rs`
    // (v8_equal_flow_fail_open_reason_label). Both were inherent-private
    // before the split and are widened to pub(super) for the sibling.
    pub(super) fn from_u32(v: u32) -> Self {
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

    pub(super) fn as_str(self) -> &'static str {
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

// pub(super): named (as a `V8State` field type) + its fields/methods are
// reached by `lease.rs` (acquire_v8 + the v8_equal_flow_* accessors) and
// `publish_equal_flow_epoch_v8.rs`/`rotate_epoch_v8.rs` (fail_open /
// enforce_epoch / disable_for_epoch + valid_streak). Every reached field
// and method is widened to pub(super).
pub(super) struct V8EqualFlowSuppressState {
    pub(super) epoch_tag: AtomicU32,
    pub(super) enforced: AtomicU32,
    pub(super) valid_streak: AtomicU32,
    pub(super) current_target_per_flow: AtomicU64,
    pub(super) current_worker_cap: AtomicU64,
    pub(super) smoothed_target_per_flow: AtomicU64,
    pub(super) cap_hit_events: AtomicU64,
    pub(super) suppressed_grant_bytes: AtomicU64,
    pub(super) stale_or_tag_mismatch_events: AtomicU64,
    pub(super) fail_open_reason: AtomicU32,
    pub(super) fail_open_count: AtomicU64,
    /// #9117: workers EXCLUDED from the sample set for one epoch because they
    /// went idle -> active mid-epoch, so their share was published as 0 at the
    /// last rotation and their sample covers only part of this one.
    ///
    /// Counted rather than left as a local, because the exclusion is otherwise
    /// invisible: it is the difference between "the class target was computed
    /// from every active worker" and "from every active worker except the ones
    /// that had just woken", and those are different measurements. It also
    /// distinguishes this shape from the fail-open it replaced — a flat
    /// fail_open_count with a climbing exclusion count is exactly the fix
    /// working.
    pub(super) newly_active_excluded_count: AtomicU64,
}

impl V8EqualFlowSuppressState {
    // pub(super): constructed from `lease.rs` (V8State build in new_v8*).
    pub(super) fn new() -> Self {
        Self {
            epoch_tag: AtomicU32::new(0),
            enforced: AtomicU32::new(0),
            valid_streak: AtomicU32::new(0),
            current_target_per_flow: AtomicU64::new(0),
            current_worker_cap: AtomicU64::new(0),
            smoothed_target_per_flow: AtomicU64::new(0),
            cap_hit_events: AtomicU64::new(0),
            suppressed_grant_bytes: AtomicU64::new(0),
            stale_or_tag_mismatch_events: AtomicU64::new(0),
            fail_open_reason: AtomicU32::new(V8EqualFlowFailOpenReason::Disabled as u32),
            fail_open_count: AtomicU64::new(0),
            newly_active_excluded_count: AtomicU64::new(0),
        }
    }

    // pub(super): called from `publish_equal_flow_epoch_v8.rs`.
    pub(super) fn fail_open(&self, new_tag: u32, reason: V8EqualFlowFailOpenReason) {
        // Publish the payload first and the tag last. Readers acquire
        // `epoch_tag` before consulting these fields; seeing `new_tag`
        // must therefore imply seeing this fail-open payload, not the
        // previous enforced epoch's cap.
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
        self.epoch_tag.store(new_tag, Ordering::Release);
    }

    // pub(super): called from `rotate_epoch_v8.rs` (non-equal-flow branch).
    pub(super) fn disable_for_epoch(&self, new_tag: u32) {
        self.enforced.store(0, Ordering::Release);
        self.current_target_per_flow.store(0, Ordering::Release);
        self.current_worker_cap.store(0, Ordering::Release);
        self.fail_open_reason.store(
            V8EqualFlowFailOpenReason::Disabled as u32,
            Ordering::Release,
        );
        self.valid_streak.store(0, Ordering::Release);
        self.smoothed_target_per_flow.store(0, Ordering::Release);
        self.epoch_tag.store(new_tag, Ordering::Release);
    }

    // pub(super): called from `publish_equal_flow_epoch_v8.rs`.
    pub(super) fn enforce_epoch(&self, new_tag: u32, target_per_flow: u64, max_worker_cap: u64) {
        self.current_target_per_flow
            .store(target_per_flow, Ordering::Release);
        self.current_worker_cap
            .store(max_worker_cap, Ordering::Release);
        self.fail_open_reason
            .store(V8EqualFlowFailOpenReason::None as u32, Ordering::Release);
        self.enforced.store(1, Ordering::Release);
        // Last-store publication barrier. `equal_flow_cap_v8` loads this
        // with Acquire before using the payload above.
        self.epoch_tag.store(new_tag, Ordering::Release);
    }
}

// pub(super): read by `publish_equal_flow_epoch_v8.rs` (streak gate +
// util thresholds).
pub(super) const EQUAL_FLOW_VALID_STREAK_REQUIRED: u32 = 2;
pub(super) const EQUAL_FLOW_MIN_WORKER_UTIL_NUM: u64 = 4;
pub(super) const EQUAL_FLOW_MIN_WORKER_UTIL_DEN: u64 = 5;
