// Issue #1329 / PR #1588: maybe_rotate_epoch_v8 extracted from
// shared_cos_lease/mod.rs as a pure code-motion split, preserving
// atomic memory orderings and branch structure.
//
// #1830 (e): the former fixed `[_; 32]` stack-scratch arrays
// (MAX_WORKERS_SCRATCH) are replaced by the lease's pre-allocated
// `V8RotationScratch` (sized to the true worker-array length at
// construction). >32-worker hosts previously fell into the
// `active_outside_scratch` path and equal-flow failed open every
// epoch; now every worker is captured. The scratch lock is
// uncontended by construction (only the seqlock rotation winner
// reaches it) and the rotation path performs no heap allocation.
//
// Visibility widens from inherent-private to `pub(super)` so the
// rotation tick path in `mod.rs` continues to find it. `#[inline]`
// hints the single-call-site inlining decision the compiler made
// implicitly on master.
//
// Calls `publish_equal_flow_epoch_v8` (sibling submodule) when the
// lease is in EqualFlowSuppress rate mode; the explicit `use`
// below brings the symbol into lexical scope after pub(super)
// widening.

use super::*;
use std::sync::atomic::Ordering;

use super::publish_equal_flow_epoch_v8::publish_equal_flow_epoch_v8;

impl SharedCoSQueueLease {
    /// #1229 Phase 6 v8: rotate epoch when current epoch has expired.
    /// Seqlock pattern: CAS seq EVEN→ODD claims rotation; updates
    /// state; CAS seq ODD→EVEN publishes completion.
    #[inline]
    pub(super) fn maybe_rotate_epoch_v8(&self, now_ns: u64) {
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

        // #4260 (hb166 R-3) — seqlock writer half (Boehm's seqlock recipe).
        // The EVEN→ODD claim CAS above is AcqRel, but its Release half
        // orders only writes SEQUENCED-BEFORE the CAS, and no reader
        // synchronizes-with it by reading the ODD value (readers spin on
        // ODD, they never accept it). So the CAS does NOT order the Relaxed
        // payload stores below relative to the ODD claim.
        //
        // (a) Writer-side intuition. This Release fence is a store-store
        // ordering barrier: it prevents the Relaxed payload stores that
        // follow it from becoming visible before the ODD claim that
        // precedes it. Without it, on a weakly-ordered CPU (ARM/POWER) a
        // payload store could publish before the ODD claim, so a reader
        // could read seq=EVEN(old), read new-epoch payload (torn), re-read
        // seq=EVEN(old), and pass the even-equal validation against a
        // cross-epoch mix — the #1619 tearing class, of which #1643 fixed
        // only the reader half.
        //
        // (b) Formal guarantee ([atomics.fences]/2, the fence-fence rule).
        // The reader's payload reads in `snapshot_epoch_v8` (lease.rs) are
        // Relaxed LOADS sealed by an Acquire FENCE before its trailing
        // `seq_after` load. If the reader's Relaxed payload LOAD (not the
        // fence — a fence performs no access) reads the value written by a
        // Relaxed payload STORE that is sequenced-AFTER this Release fence,
        // then this Release fence (FA) synchronizes-with the reader's
        // Acquire fence (FB). Everything sequenced-before FA — the ODD
        // claim CAS — therefore happens-before everything sequenced-after
        // FB — the reader's `seq_after` load — so `seq_after` observes the
        // ODD claim (or the later EVEN publish) and the reader retries. The
        // fence orders the reader's LOAD; the LOAD is what reads the store.
        // This is the write-side partner of the #1643 reader-fence half.
        // One fence per rotation (~200 µs, EPOCH_DURATION_NS).
        std::sync::atomic::fence(Ordering::Release);

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

        // #1830 (e): heap scratch for per-worker swap captures, sized
        // to the lease's true worker-array length at construction
        // (replaces the former fixed `[_; 32]` stack arrays, which
        // forced an every-epoch equal-flow fail-open on >32-worker
        // hosts). We are the unique rotation winner here (EVEN→ODD CAS
        // above), so the lock is uncontended by construction; no heap
        // allocation happens on this path. Every slot in
        // `0..n_workers` is unconditionally overwritten below before
        // it is read, so no state leaks across rotations.
        let n_workers = v8.worker_grants.len();
        let mut scratch = match v8.rotation_scratch.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let scratch = &mut *scratch;
        debug_assert_eq!(scratch.active_by_worker.len(), n_workers);
        debug_assert_eq!(v8.worker_starvation_events.len(), n_workers);
        debug_assert_eq!(v8.worker_demand_events.len(), n_workers);
        debug_assert_eq!(v8.worker_active_flow_buckets.len(), n_workers);
        let signaled_by_worker = &mut scratch.signaled_by_worker;
        let demanded_by_worker = &mut scratch.demanded_by_worker;
        let prev_grants = &mut scratch.prev_grants;
        let active_by_worker = &mut scratch.active_by_worker;

        // STEP 2: swap event slots, track per-worker signal/demand flags.
        let mut any_active_worker_signaled = false;
        for id in 0..n_workers {
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
                .map(|c| c.0.load(Ordering::Relaxed))
                .unwrap_or(0);
            active_by_worker[id] = active > 0;
            demanded_by_worker[id] = old_demand_count > 0;
            let signaled = active > 0 && old_starvation_count > 0;
            signaled_by_worker[id] = signaled;
            any_active_worker_signaled |= signaled;
        }

        // STEP 3: swap worker_grants, capture prev_grant for peer-util.
        for (id, grant) in v8.worker_grants.iter().enumerate() {
            let old = grant.0.swap(new_packed_zero, Ordering::AcqRel);
            let (_, prev) = PackedEpochGrant::unpack(old);
            prev_grants[id] = prev;
        }

        // #1746 (Codex r1 F1): the carry/elapsed/new_cap computation moved
        // ABOVE the equal-flow publish (pure reordering inside the same
        // single-writer ODD seqlock section — identical values, identical
        // stores) so the IdealShare policy can divide the TRUE per-rotation
        // budget (`new_cap` = rate x elapsed + carry, lag-recovered) instead
        // of a fixed one-EPOCH nominal that over-throttled lagged classes.
        // #1630 (cause-1): bounded rotation credit carry. The cap this
        // rotation grants is `rate × elapsed + carry_draw`, where:
        //   * `elapsed` is the wall-clock lag bounded by `K × EPOCH`
        //     (`MAX_ROTATION_LAG_EPOCHS`) — recovers the rate credit the
        //     old `.min(EPOCH)` clamp discarded for a low-rate class that
        //     is only visited intermittently;
        //   * `carry_draw` releases a bounded slice of the banked deficit
        //     accrued when a single lag exceeded `K × EPOCH`.
        //
        // Three regimes (DECOUPLED stall cutoff so a legitimate heavy-tail
        // visit lag is never penalised as a stall):
        //   1. lag ≤ K          — normal recovery: grant raw lag, drain a
        //                         bounded carry slice.
        //   2. K < lag ≤ STALL  — bank-residual: grant the K-epoch ceiling
        //                         now, bank `rate × (lag − K×EPOCH)` into
        //                         carry (clamped) for the next visit.
        //   3. lag > STALL or
        //      start == 0       — cold-resume: grant exactly one epoch and
        //                         DROP carry. Bounds the post-stall /
        //                         post-failback burst to `rate × EPOCH` and
        //                         prevents carry leaking across an HA
        //                         demote→promote gap on a reused lease.
        //
        // #15100 (A70-02): STALL here is the rate-relative window from
        // `stall_window_ns_for_rate` (fixed 51.2 ms floor OR one full
        // frame's refill at this rate), NOT the bare fixed epoch count:
        // a self-parked low-rate class's revisit lag IS its frame
        // refill time and must land in regime 2 (bank + drain), never
        // regime 3. The reservoir/drain caps are byte-sized at lease
        // creation for the same reason (see `epoch.rs`).
        //
        // `epoch_carry_bytes` is rotation-private (single-writer, inside
        // the seqlock ODD section); the Acquire/Release on it are redundant
        // with the surrounding CAS fence but self-documenting. See the
        // struct doc-comment for the enforced reader-private invariant.
        let rate_bytes = self.config.rate_bytes as u128;
        // #15100 (A70-02): byte-sized reservoir computed at lease
        // creation (floored at one frame for low rates); equals the
        // epoch-sized caps whenever those exceed a frame.
        let carry_max = v8.carry_max_bytes;
        let carry_drain_max = v8.carry_drain_max_bytes;

        // Regime boundaries are compared on EXACT wall-clock nanoseconds,
        // NOT a floored epoch count: a floored `lag = raw / EPOCH` would
        // admit a regime-1 lag of up to `(K+1)×EPOCH − 1ns` (floors to K),
        // so the regime-1 base grant could reach almost `(K+1)×rate×EPOCH`
        // and, with a full carry drain, breach the `(2K−1)×rate×EPOCH`
        // per-rotation bound by one epoch; and a raw lag just over the
        // stall window would skip the regime-3 cold-resume and bank
        // instead of dropping stale carry across an HA gap. Comparing raw
        // nanoseconds against the exact `K×EPOCH` and stall-window
        // thresholds closes both boundary holes.
        let raw_elapsed_ns = now_ns.saturating_sub(start);
        // #15100 (A70-02): rate-relative lag window stored at lease
        // creation (fixed K×EPOCH OR one full frame's refill at this
        // rate). A self-parked low-rate class revisits after
        // `frame / rate`, which the fixed window alone credited only
        // 1.6 ms of, banking the rest past a stall cutoff that then
        // dropped it.
        let k_window_ns = v8.lag_window_ns;
        // #15100 (A70-02): rate-relative stall window — the fixed
        // 51.2 ms floor OR twice the lag window, whichever is longer.
        // Must sit above the lag window or a self-parked class whose
        // lag lands between them cold-resumes and drops its carry.
        let stall_window_ns = stall_window_ns_for_rate(self.config.rate_bytes);

        // #1863 Path A-ii: the just-ended epoch's UNCLAIMED class budget.
        // Workers claim their flow-proportional share only at drain-visit
        // acquires; a worker whose visits miss an epoch lets its share
        // evaporate at this rotation even though the class is backlogged
        // (the Step-0 cells measured 21-29% of the class cap evaporating
        // this way under aggressor pressure while EVERY active worker
        // cumulatively over-asked its entitlement — claim-sampling loss,
        // docs/pr/1863-realization-gap/plan.md §5). Bank the
        // remainder into the SAME bounded carry the lag machinery uses:
        // the next rotation's `new_cap` draws it back and the share
        // formula below re-deals it flow-proportionally, so per-worker
        // isolation is preserved (no mid-epoch class-room racing — the
        // rejected A-i shape) and every existing bound holds unchanged
        // (`carry_max` = K epochs banked, `carry_drain_max` per draw,
        // per-rotation grant ≤ (2K−1)×rate×EPOCH, regime-3 cold-resume
        // still drops stale carry across HA gaps). Conservation: a banked
        // byte was published in exactly one prior cap and not granted;
        // re-banking a drawn-but-again-unclaimed byte loops the same
        // budget, so Σ granted ≤ rate × wall-time + carry_max — the
        // long-run hard cap (Gate 4) is unchanged. A fully-claimed epoch
        // (`prev_granted == prev_cap`, the healthy steady state) banks 0
        // and this rotation is byte-identical to pre-#1863 behavior.
        //
        // Equal-flow gate: banking is restricted to the default
        // (CstructDefault) rate mode. In EqualFlowSuppress mode the
        // unclaimed remainder of an ENFORCED epoch is budget the policy
        // deliberately suppressed — recycling it would re-grant
        // suppressed bytes later and partially defeat enforcement — and
        // even fail-open epochs feed `new_cap` into the IdealShare
        // target numerator (#1746), so banking there would couple the
        // per-flow target to claim-sampling noise. Equal-flow leases
        // therefore keep the pre-#1863 evaporation semantics
        // byte-for-byte (their suite pins this); the #1863 gap was
        // measured and is fixed in the default mode.
        let prev_unclaimed = if v8.rate_mode == V8RateMode::EqualFlowSuppress {
            0
        } else {
            prev_cap.saturating_sub(prev_granted)
        };

        let (elapsed_ns, carry_draw) = if start == 0 || raw_elapsed_ns > stall_window_ns {
            // REGIME 3 — cold-resume. One epoch, drop any stale carry
            // (including the just-ended epoch's unclaimed remainder: a
            // post-stall class must not burst stale budget).
            v8.epoch.epoch_carry_bytes.store(0, Ordering::Release);
            (EPOCH_DURATION_NS, 0u64)
        } else if raw_elapsed_ns > k_window_ns {
            // REGIME 2 — bank residual beyond the K-epoch ceiling. Grant
            // exactly `K×EPOCH` now; bank `rate × (raw − K×EPOCH)` plus
            // the just-ended epoch's unclaimed remainder (#1863 A-ii).
            let overshoot_ns = (raw_elapsed_ns - k_window_ns) as u128;
            let new_owed = ((rate_bytes * overshoot_ns) / 1_000_000_000u128) as u64;
            let prev_carry = v8.epoch.epoch_carry_bytes.load(Ordering::Acquire);
            let carry = prev_carry
                .saturating_add(new_owed)
                .saturating_add(prev_unclaimed)
                .min(carry_max);
            v8.epoch.epoch_carry_bytes.store(carry, Ordering::Release);
            (k_window_ns, 0u64)
        } else {
            // REGIME 1 — normal recovery. `raw_elapsed_ns ≤ K×EPOCH` here
            // (regime 2 caught anything above), so the base grant is
            // bounded by `K×rate×EPOCH`; the carry drain adds at most
            // `(K−1)×rate×EPOCH`, keeping the per-rotation grant ≤
            // `(2K−1)×rate×EPOCH`. #1863 A-ii: bank the just-ended
            // epoch's unclaimed remainder BEFORE drawing, so a one-epoch
            // sampling miss is redistributable on the very next epoch.
            let prev_carry = v8.epoch.epoch_carry_bytes.load(Ordering::Acquire);
            let banked = prev_carry.saturating_add(prev_unclaimed).min(carry_max);
            let draw = banked.min(carry_drain_max);
            v8.epoch
                .epoch_carry_bytes
                .store(banked - draw, Ordering::Release);
            (raw_elapsed_ns, draw)
        };

        let base_cap =
            ((self.config.rate_bytes as u128) * (elapsed_ns as u128) / 1_000_000_000u128) as u64;
        let new_cap = base_cap.saturating_add(carry_draw).min(u32::MAX as u64);

        if v8.rate_mode == V8RateMode::EqualFlowSuppress {
            // #1745: swap the acquire-time active-flow sample slots and
            // capture the just-ended epoch's sticky-max per worker. This
            // swap is INSIDE the EqualFlowSuppress branch so the default
            // CstructDefault path performs zero extra atomic ops per
            // rotation. A slot is only counted when its swapped-out tag
            // matches the just-ended epoch tag (= seq>>1); a slot never
            // written this epoch swaps out with the prior tag and is
            // correctly excluded as 0.
            let just_ended_tag = (seq >> 1) as u32;
            let sampled_active_flows_by_worker = &mut scratch.sampled_active_flows_by_worker;
            debug_assert_eq!(v8.worker_equal_flow_active_samples.len(), n_workers);
            for id in 0..n_workers {
                let old_sample = v8.worker_equal_flow_active_samples[id]
                    .0
                    .swap(new_packed_zero, Ordering::AcqRel);
                let (old_tag, old_count) = PackedEpochGrant::unpack(old_sample);
                sampled_active_flows_by_worker[id] = if old_tag == just_ended_tag {
                    old_count
                } else {
                    0
                };
            }
            // #1746: the IdealShare nominal numerator is the TRUE budget
            // this rotation grants (`new_cap` = rate x elapsed + carry,
            // computed above), NOT a fixed `rate x EPOCH` — under rotation
            // lag the cap consumer (`target x active_flows` vs this
            // window's grants) and the class budget scale together, so a
            // lagged class keeps its lag-recovered credit (Codex r1 F1).
            publish_equal_flow_epoch_v8(
                v8,
                new_tag,
                n_workers,
                active_by_worker,
                sampled_active_flows_by_worker,
                demanded_by_worker,
                prev_grants,
                new_cap,
            );
        } else {
            v8.equal_flow.disable_for_epoch(new_tag);
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
            .map(|c| c.0.load(Ordering::Relaxed) as u64)
            .sum::<u64>()
            .max(1);
        // #1643: payload store downgraded to Relaxed — the single Release
        // on `epoch_seq` below is the sole publish the fenced-Acquire reader
        // synchronizes-with (matching the cold_path_hist reference writer).
        v8.epoch
            .epoch_total_grant_cap
            .store(new_cap, Ordering::Relaxed);
        let grace_ns = now_ns.saturating_add(EPOCH_DURATION_NS / 2);
        v8.epoch
            .epoch_grace_expires_ns
            .store(grace_ns, Ordering::Relaxed);
        for (id, count_atom) in v8.worker_active_flow_buckets.iter().enumerate() {
            let my_count = count_atom.0.load(Ordering::Relaxed) as u64;
            let my_share = ((new_cap as u128) * (my_count as u128) / (total_flows as u128)) as u64;
            if let Some(share_atom) = v8.worker_fair_share.get(id) {
                share_atom.store(my_share, Ordering::Relaxed);
            }
        }
        v8.epoch.epoch_start_ns.store(now_ns, Ordering::Relaxed);
        // Publish completion: seq ODD→EVEN. This Release is the seqlock
        // publish that synchronizes-with the reader's fenced-Acquire
        // re-read (#1643); all payload stores above happen-before it in
        // this single rotation-winner thread's program order.
        v8.epoch.epoch_seq.store(seq + 2, Ordering::Release);
    }
}
