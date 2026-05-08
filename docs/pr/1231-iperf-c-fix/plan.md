# #1231 — 'all peers CPU-bound' detector to fix iperf-c push -15% regression

**Status:** DRAFT v1 — pending adversarial plan review

## Issue framing

PR #1230 shipped Phase 6 v8 (per-worker fair lease) which reduces
iperf-e per-flow CoV from 60% → 13.3%. **Trade-off:** iperf-c push
saturated workload (25G EXACT, 12-stream) regressed -15%
aggregate (22.7 Gbps → 19.3 Gbps).

Root cause (plan §v8.10 open question 6 + smoke results doc):
- v8's surplus path is gated on `now_ns >= grace_expires_ns`
  (100µs into a 200µs epoch).
- During the first half of each epoch, only primary share is
  available; surplus is closed.
- Under saturation with all workers CPU-bound, fast workers
  exhaust their primary share and idle waiting for grace,
  unable to absorb slow peers' unconsumed primary. Slow peers
  themselves can't consume because they're CPU-pegged.
- Net result: ~half of each epoch's per-worker capacity is
  unused. Aggregate drops.

Empirical contrast:
- iperf-e (16G EXACT, sub-saturation): grace gate works as
  designed; fast workers can't snap up slow peers' share too
  early; per-flow fairness preserved.
- iperf-c (25G EXACT, saturation): grace gate hurts; need to
  detect this regime and disable.

## Honest scope/value framing

This issue restores ~3-4 Gbps of aggregate iperf-c push throughput
WITHOUT compromising the iperf-e CoV win. The trade-off space:

| Workload | Pre-#1231 (v8) | Post-#1231 target |
|----------|---------------|-------------------|
| iperf-e CoV | 13.3% ✓ | ≤ 15% (preserve) |
| iperf-c push aggregate | 19.3 Gbps ⚠️ | ≥ 22.0 Gbps |
| iperf-c reverse aggregate | 22.1 Gbps ✓ | preserve |
| Pass A/B 0-retrans | clean ✓ | preserve |

If reviewers conclude the detector design is unsound or the perf
gain is too narrow to justify the complexity, PLAN-KILL is an
acceptable verdict. Specific kill triggers:

- Detector has false-positive risk that compromises iperf-e CoV
  (e.g. iperf-e under transient bursty workloads briefly looks
  CPU-bound and grace gets disabled, leaking polling skew).
- Detection cost on the hot path is measurable.
- Detector state introduces a new concurrency hazard.

## What's already shipped

PR #1230 final state (master HEAD c16e518e + Copilot SWE Agent
follow-ups 81250ddf, 9a4304c5):
- v8 lease internals: PackedEpochGrant, V8State, acquire_v8,
  rotation, snapshot, worker_grant_bump, tag_checked_rollback.
- All transition sites mirror to per-worker counter (no Arc
  clones in hot path; NLL pattern).
- Stack-allocated sidecar in submit_cos_batch.
- Coordinator emits v8 leases for guarantee-phase exact queues.
- Token-bucket lazy install + rehydration.
- 1079 tests pass.

The v8 cap CAS spine (linearizable, tag-checked, two-CAS-rollback)
is unchanged by this issue. Only the grace-period gate semantics
change.

## Concrete design

### v1.1 Detection signal

Three candidate signals, ranked by cost:

**Candidate A: per-worker token starvation rate** (CHEAPEST)
- Each worker's `queue.hot.tokens` is monotonically drained by
  TX and refilled by `maybe_top_up_cos_queue_lease`.
- If `acquire_v8` returns 0 for >= K consecutive top-up calls
  on the same worker → worker is starved (lease budget reached
  for this epoch).
- Aggregate signal: count of workers in starvation state across
  the lease.
- Detection threshold: ≥ N-1 of N workers starved within the
  last `EPOCH_DURATION_NS / 2` window (i.e., during grace).

**Candidate B: TX-rate vs class-rate ratio** (MEDIUM)
- Per-class measured TX rate over the last `EPOCH_DURATION_NS × M`
  window vs configured `rate_bytes`.
- If `measured_tx_rate >= rate_bytes × 0.95` for 3+ consecutive
  rotations → saturated.
- Requires per-class TX-byte counter (already exists via
  `consume()` accounting on `outstanding_leased_tokens`).

**Candidate C: bypass via aggregate active_flow_buckets** (CHEAPEST)
- If `total_active_flow_buckets >= total_workers` (every active
  worker has at least one flow bucket) AND aggregate measured
  TX equals class rate, bypass grace.
- Equivalent shape to (B); simpler implementation.

**Pick (A)**: simplest signal, directly captures the failure
mode (starvation = "couldn't get more lease this epoch"), no
new global counters. Per-worker starvation count is read at
acquire path; threshold is per-class.

### v1.2 State changes

Add to `V8State`:

```rust
struct V8State {
    // ... existing fields ...
    /// #1231: per-worker starvation counter. Each `acquire_v8`
    /// call that returns 0 increments this; each successful
    /// grant resets it to 0. The lease aggregates across workers
    /// to detect 'all peers CPU-bound' regime.
    worker_starvation_count: Box<[AtomicU16]>,
    /// #1231: lease-wide flag. Set to true when ≥ N-1 of N
    /// workers have starvation_count >= STARVATION_THRESHOLD;
    /// reset to false when any worker successfully grants
    /// 'large' (> primary share) without dipping into surplus.
    /// Read by acquire path's surplus gate (post-grace OR
    /// bypass_grace).
    bypass_grace: AtomicBool,
}
```

Sized like `worker_grants` and `worker_active_flow_buckets`:
length = max_worker_id + 1.

### v1.3 Acquire path changes

```rust
fn acquire_v8_v1_1(...) -> u64 {
    // ... existing snapshot + primary path ...

    let primary_granted = total_granted;

    // === Starvation detection ===
    let primary_succeeded = primary_granted > 0;

    // === SURPLUS PATH ===
    // Bypass grace if EITHER condition holds:
    //   (1) now_ns >= grace_expires_ns (existing v8 logic), OR
    //   (2) lease.bypass_grace is set (new #1231 logic).
    let bypass_grace = v8.epoch.bypass_grace.load(Relaxed);
    let active = v8.worker_active_flow_buckets[worker_id]
        .load(Relaxed) > 0;
    let surplus_open = (now_ns >= grace_expires_ns) || bypass_grace;
    if still_needed > 0 && surplus_open && active {
        // ... existing surplus loop ...
    }

    // === Update starvation counter ===
    if total_granted == 0 {
        let new_count = v8.worker_starvation_count[worker_id]
            .fetch_add(1, Relaxed)
            .saturating_add(1);
        // Threshold: N-1 of N workers (i.e., all but possibly one).
        if new_count >= STARVATION_THRESHOLD as u16 {
            // Check if quorum of workers is starved.
            let total_workers = v8.worker_starvation_count.len();
            let starved = v8.worker_starvation_count.iter()
                .filter(|c| c.load(Relaxed) >= STARVATION_THRESHOLD as u16)
                .count();
            if starved + 1 >= total_workers {
                v8.epoch.bypass_grace.store(true, Relaxed);
            }
        }
    } else {
        // Successful grant — reset our starvation counter and
        // reset the lease-wide bypass_grace flag (the regime
        // has improved).
        v8.worker_starvation_count[worker_id].store(0, Relaxed);
        if total_granted > my_fair_share {
            // We grabbed surplus — bypass might still be needed.
            // Don't reset.
        } else {
            // Got primary share — workload may have come back to
            // sub-saturation.
            v8.epoch.bypass_grace.store(false, Relaxed);
        }
    }

    total_granted
}
```

`STARVATION_THRESHOLD` = 4 (matches typical 200µs × 4 epochs =
800µs of starvation before triggering bypass — short enough to
respond, long enough to filter transient idle).

### v1.4 Reset semantics

`bypass_grace` is rotation-independent (NOT reset by epoch
rotation). Once set, stays set until any worker gets a non-surplus
grant ≤ primary_share, indicating workload is no longer
saturating peers.

`worker_starvation_count[id]` is rotation-independent at u16 size
(saturates at 65535, plenty of headroom).

### v1.5 Cost analysis

Per acquire call:
- 1 atomic load of `bypass_grace` (replacing 1 comparison
  against `now_ns`).
- 1 atomic store/fetch_add of `worker_starvation_count[id]`
  (only on grant=0 OR successful grant).

Hot-path cost: negligible. The starvation counter is
single-writer-per-slot (same as worker_active_flow_buckets).

### v1.6 False-positive resilience

Question: can a transient burst on iperf-e accidentally trigger
bypass_grace?

Analysis: iperf-e under sub-saturation is the desired-fair regime
where each worker's primary share is well above its actual TX rate
(workers process below cap and don't run out of lease budget).
acquire_v8 returns successful grants regularly, keeping
worker_starvation_count[id] at 0. The threshold `4 consecutive
zero-grants` requires 800µs of continuous starvation, which only
happens under genuine saturation.

Edge case: if iperf-e momentarily exceeds 16G shaper rate (e.g.,
TCP burst), workers WILL starve briefly. They'd accumulate
starvation_count. After 800µs, bypass_grace flips. Fast worker
takes surplus immediately on next acquire. **But:** a successful
grant ≤ primary_share resets bypass_grace. So as soon as the
burst subsides and workers hit normal primary share grants again,
the bypass turns off.

Net: bypass_grace tracks saturation regime closely; no
overshoot.

## Public API preservation

- `SharedCoSQueueLease::acquire_v8` signature unchanged.
- `SharedCoSQueueLease::new_v8` signature unchanged.
- Internal V8State gains 2 new fields (Box<[AtomicU16]> +
  AtomicBool); construction adds 2 lines.

## Hidden invariants

1. **bypass_grace consistency**: lease-wide flag, lazy-set when
   quorum of workers is starved. Reset on any non-surplus grant.
   No new concurrency hazard — Relaxed atomics, no synchronization
   across slots needed.
2. **Starvation counter monotonicity**: u16 saturating_add;
   wrap impossible.
3. **Single-writer-per-slot for starvation_count**: same as
   worker_active_flow_buckets — only the owning worker writes.

## Risk assessment

| Class | Severity | Notes |
|-------|----------|-------|
| Behavioral regression | LOW | bypass_grace defaults false; existing v8 path unchanged unless saturation is detected. |
| Lifetime / borrow-checker | LOW | New atomics, owned by lease. |
| Performance regression | LOW | 1 extra atomic load + 1 conditional store per acquire. Bounded by lease's existing CAS cost. |
| iperf-e false positive | LOW-MED | False trigger would briefly leak polling skew. Mitigated by reset-on-success semantics. Empirical validation required. |
| Concurrency / correctness | LOW | Relaxed atomics, single-writer per slot, no new ordering constraints. |

## Test plan

- Cargo build clean.
- Cargo test --release: 1079+ tests pass.
- New tests in shared_cos_lease_tests.rs:
  - **bypass_grace_triggers_after_N_starvation**: simulate
    consecutive zero-grant returns; assert bypass flips after
    threshold.
  - **bypass_grace_resets_on_successful_grant**: after bypass
    fires, simulate a non-surplus grant; assert reset.
  - **bypass_grace_does_not_fire_on_single_worker_starve**:
    1 worker starving while N-1 are not should NOT trigger
    bypass.
- Cluster smoke matrix:
  - **Pass A** (CoS off): no regression vs v8.
  - **Pass B** (24 per-class): no regression vs v8.
  - **iperf-e canonical** (sub-saturation): per-flow CoV ≤ 15%
    (preserve v8's 13.3%).
  - **iperf-c push saturated**: aggregate ≥ 22.0 Gbps (recover
    from v8's 19.3 Gbps).
  - **iperf-c reverse**: aggregate flat at ≥ 21 Gbps.

## Out of scope

- Adaptive grace duration (could be follow-up if 100µs/200µs is
  wrong scale for some workload).
- Cross-binding redirection (#937, PLAN-KILLED).
- Sender-side TCP head-start mitigation (#1233).
- Multi-sample variance check infrastructure (#1232).

## Open questions for adversarial review

1. **Starvation threshold (4 epochs = 800µs)**: too short → false
   positives on iperf-e bursts; too long → slow recovery for
   iperf-c push. Walk through the math with real arrival
   patterns.

2. **bypass_grace reset criterion**: "non-surplus grant resets".
   Is that strong enough? A pathological case might have all
   workers continuously hitting surplus path even after workload
   subsides, never resetting bypass. Bounded transient or real
   risk?

3. **Detection vs root cause**: bypass_grace papers over the
   underlying issue (grace period throttles fast workers under
   saturation). A more principled fix might shorten grace to
   25µs of the 200µs epoch. Why prefer the bypass-flag over
   smaller grace?

4. **Interaction with rotation**: bypass_grace is NOT reset by
   epoch rotation. Is that correct, or should rotation also
   re-evaluate?

5. **iperf-c push saturated empirical claim**: predicted
   recovery to ≥ 22.0 Gbps. Show the mechanism: with bypass on,
   fast worker's surplus path opens at acquire time (no grace
   wait); claims unconsumed primary share from CPU-bound peers;
   aggregate matches what greedy would deliver minus per-worker
   share contention. Verify the math.

6. **Quorum threshold (N-1 of N)**: with 6 workers, requires 5
   starved before bypass. Too strict? In iperf-c push with
   [6,5,1] flows, only 3 workers are active; threshold should
   probably be N-1 of ACTIVE workers, not N-1 of all workers.
   Refine to "active_workers - 1 of active_workers".

7. **Cost on hot path**: 1 extra atomic load + counter store
   per acquire. At 5K acquires/sec/worker, ~30K extra atomic
   ops/sec total. Negligible per Codex's prior evaluation, but
   confirm.

8. **Telemetry**: should bypass_grace transitions emit a counter
   increment for monitoring? If bypass is firing constantly,
   operator should know.

9. **Does this re-open #1211 territory?**: #1211 was
   PLAN-KILLED (race-safe AFD ECN/drop overlay) because PR #1220
   showed the cluster was at structural ceiling. Post-v8 the
   ceiling moved; this issue addresses one specific regression.
   Is this an "AFD-style" fix in disguise? Verify the design
   distinction.

10. **iperf-e CoV impact under bypass**: if iperf-e ever
    triggers bypass (transient burst), CoV momentarily spikes.
    Multi-sample harness (#1232) would catch this. Acceptable
    risk?
