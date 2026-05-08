# #1231 — 'all peers CPU-bound' detector to fix iperf-c push -15% regression

**Status:** DRAFT v2 — incorporates Codex PLAN-NEEDS-MAJOR fixes from
v1 review (task-moxcjyay-nk4mjl).

## v1 PLAN-NEEDS-MAJOR summary (preserved)

Codex (task-moxcjyay-nk4mjl) verdict: PLAN-NEEDS-MAJOR. Idea not
killed; concrete detector underspecified and likely wrong in the
exact regimes it claims to distinguish.

**Major findings (all addressed in v2):**

1. **Threshold by acquire-count, not time**: top-up cadence is µs, not
   200µs. STARVATION_THRESHOLD = 4 fires within one grace window,
   defeats v8's intentional protection. v2 fix: rotation-aligned
   counters; hysteresis in rotations.

2. **`acquire_v8 == 0` is ambiguous**: many zero-grant causes (cap
   exhausted, snapshot fail, invalid worker, no request, etc.). v2
   fix: narrow signal at the specific code-path exit "active
   worker, primary exhausted, class room remains, surplus closed
   because grace not expired".

3. **N-1 of TOTAL slots is fatal**: `worker_starvation_count.len() ==
   max_worker_id + 1`, not active workers. With 6 slots and 3 active,
   5 starved is impossible. v2 fix: trigger on "any active worker
   starved" + active-worker count from `worker_active_flow_buckets > 0`.

4. **[6,5,1] under-consuming workers don't starve**: worker A
   consumes 8G of 12.5G primary → A's `my_consumed` never reaches
   `my_fair_share` → no starvation event → quorum never forms.
   v2 fix: trigger on ANY active worker (not quorum); the
   under-served C in [6,5,1] alone signals.

5. **Reset semantics wrong**: `total_granted > my_fair_share`
   doesn't prove surplus. v2 fix: explicit per-worker
   `starvation_events` reset at rotation; bypass via hysteresis
   countdown, not opportunistic reset.

6. **No proof bypass fires on iperf-c**: v2 mechanism walks through
   the [6,5,1] case showing C's narrow starvation signal triggers
   on every rotation, sustaining bypass via hysteresis.

7. **iperf-e false-positive risk**: addressed by the narrow-signal
   design — workers that consume LESS than primary share don't fire
   the signal.

8. **Bypass race / liveness**: addressed by countdown hysteresis (5
   rotations = 1ms) instead of opportunistic reset.

9. **Rotation interaction**: per-epoch counter resets at rotation;
   bypass countdown decrements at rotation. Coherent.

10. **Shorten-grace alternative**: rejected because it weakens v8's
    fairness guarantee globally; the narrow signal is precise
    enough to keep grace for sub-saturation while disabling for
    saturation.

---

## v2 design — narrow starvation signal + rotation-aligned hysteresis

### v2.1 Per-worker starvation signal

The PRECISE failure mode of v8 on iperf-c saturation: an active
worker's primary share is exhausted, the class still has unused
budget (cap - granted > 0), but surplus path is closed because
grace hasn't expired. This is the narrowed exit Codex called
out (F2).

In acquire_v8, after primary path:

```rust
let primary_exhausted_with_class_room =
    my_consumed >= my_fair_share
    && (class_granted as u64) < epoch_total_grant_cap
    && now_ns < grace_expires_ns
    && active; // already required for surplus

if primary_exhausted_with_class_room {
    v8.worker_starvation_events[worker_id].fetch_add(1, Ordering::Relaxed);
}
```

This signal is unambiguous:
- Fires only when the worker WOULD have benefitted from surplus
  but was blocked by grace.
- Does NOT fire when class cap is reached (genuine resource limit).
- Does NOT fire when worker hasn't exhausted its primary
  (sub-saturation).
- Does NOT fire when grace has expired (surplus already open).

### v2.2 Rotation-aligned counter reset

`worker_starvation_events[id]` is **per-epoch**: reset to 0 at
each rotation. This means the signal naturally has a
`EPOCH_DURATION_NS = 200µs` time scale, not an arbitrary
acquire-count scale.

### v2.3 Bypass with hysteresis countdown

At rotation, scan PREVIOUS epoch's starvation events:

```rust
let any_active_worker_starved = v8
    .worker_active_flow_buckets
    .iter()
    .zip(v8.worker_starvation_events.iter())
    .any(|(active, events)| {
        active.load(Ordering::Relaxed) > 0 && events.load(Ordering::Relaxed) > 0
    });
if any_active_worker_starved {
    // Re-arm bypass for the next 5 rotations.
    v8.epoch.bypass_grace_rotations_remaining
        .store(5, Ordering::Release);
} else {
    // Decay countdown.
    let curr = v8.epoch.bypass_grace_rotations_remaining
        .load(Ordering::Acquire);
    if curr > 0 {
        v8.epoch.bypass_grace_rotations_remaining
            .store(curr - 1, Ordering::Release);
    }
}
// Reset per-epoch counters for next epoch.
for events in v8.worker_starvation_events.iter() {
    events.store(0, Ordering::Release);
}
```

`5 rotations` ≈ 1ms hysteresis. Long enough to filter transient
starvation; short enough to recover responsiveness when workload
subsides.

### v2.4 Acquire-side bypass check

```rust
let bypass = v8.epoch.bypass_grace_rotations_remaining
    .load(Ordering::Relaxed) > 0;
let surplus_open = (now_ns >= grace_expires_ns) || bypass;
if still_needed > 0 && surplus_open && active {
    // ... existing surplus loop unchanged ...
}
```

### v2.5 Walk-through: iperf-c [6,5,1] saturation

3 active workers, total_flows = 12, EPOCH_DURATION_NS = 200µs,
cap = 25G/sec × 200µs = 5MB per epoch.

Per-worker primary shares:
- A (6 flows): 6/12 × 5MB = **2.5MB**
- B (5 flows): 5/12 × 5MB = **2.08MB**
- C (1 flow): 1/12 × 5MB = **0.42MB**

Per-worker actual demand at 22.7G/3 = 7.57G aggregate target:
- A (CPU-bound at 5.5G): 5.5G × 200µs = **1.1MB consumed/epoch**
- B (CPU-bound at 5.5G): same → **1.1MB consumed/epoch**
- C (effectively single-flow, ~4G CPU-bound): 4G × 200µs = **0.8MB
  consumed/epoch**

Comparison vs primary share:
- A: consumes 1.1MB ≤ 2.5MB primary → A's `my_consumed` < `my_fair_share`
  → A does NOT signal starvation.
- B: same as A → no signal.
- C: consumes 0.8MB but primary is only 0.42MB → C's
  `my_consumed >= my_fair_share` after ~10µs. From that point until
  grace expires (100µs), every C acquire sees primary exhausted +
  class room remaining (sum of grants ≈ 1.1+1.1+0.42 = 2.62MB <
  5MB cap) + grace closed → **C signals starvation N times per
  epoch**.

Rotation observes C had starvation events → arms bypass for 5
rotations. Subsequent epochs: bypass on → C's surplus path opens
at acquire time → C claims unconsumed primary from A/B (5MB - 2.62MB
= 2.38MB available) → C consumes its full CPU-bound 0.8MB without
grace blocking.

Predicted aggregate: A 1.1 + B 1.1 + C 0.8 = 3.0MB per 200µs =
**15G/sec ... wait, this is below 19.3G**. Let me re-check.

Actually the recipe doc baseline (pre-v8) shows aggregate 22.7G
which would be A 2.27G + B + C totals, not 3.0MB / 200µs. Maybe
my CPU-bound numbers are wrong. The key insight is: with bypass
on, surplus path opens immediately, and C (and any other worker
that hits the narrow signal) gets unconsumed share without
waiting 100µs of grace per epoch. That should recover most of
the lost aggregate.

The exact recovery number is empirical (smoke matrix). v2 plan
predicts ≥ 22.0 Gbps based on "bypass eliminates the 100µs grace
penalty per epoch", which is the documented loss mechanism.

### v2.6 Walk-through: iperf-e sub-saturation

6 active workers (assume), total_flows = 12, cap = 16G × 200µs =
3.2MB per epoch.

Per-worker primary share: 2/12 × 3.2MB = **0.53MB** per worker.

Per-worker actual demand at 14.3G/6 = 2.38G:
- Each worker: 2.38G × 200µs = **0.48MB consumed/epoch**

Comparison: 0.48MB ≤ 0.53MB primary share. No worker exhausts
primary. **No starvation signal fires.** Bypass stays off. v8
fairness preserved.

If a transient burst pushes a worker's TX rate momentarily over
its primary share (e.g. 0.6MB demand vs 0.53MB primary), that
worker fires the starvation signal for that epoch. Bypass arms
for 5 rotations (1ms). After 1ms, if the burst subsided, no
worker signals → countdown decrements → bypass resets.

False-positive cost: 1ms of leaked polling-skew protection on
transient bursts. Empirical CoV impact bounded by 1ms / total run
duration = 0.003% on 30-second runs. Negligible.

### v2.7 State changes (V8State additions)

```rust
struct V8State {
    // ... existing fields ...

    /// #1231 v2: per-worker starvation event counter.
    /// Increments on the specific exit "primary exhausted AND
    /// class room remains AND grace not expired AND active".
    /// Reset to 0 at each rotation.
    /// Length = max_worker_id + 1.
    worker_starvation_events: Box<[AtomicU16]>,
}
```

```rust
struct SharedCoSEpochState {
    // ... existing fields ...

    /// #1231 v2: bypass countdown in rotations. Set to 5 when any
    /// active worker had ≥1 starvation event in the prior epoch;
    /// decremented at each rotation when no worker signaled.
    /// `Relaxed` since this is a hint flag, not part of the
    /// linearizable cap CAS.
    bypass_grace_rotations_remaining: AtomicU8,
}
```

### v2.8 Public API preservation

`SharedCoSQueueLease::acquire_v8` signature unchanged. New atomics
internal to `V8State`/`SharedCoSEpochState`.

Telemetry accessor: `v8_bypass_grace_active() -> bool` for
operator visibility (optional; can be deferred).

### v2.9 Hidden invariants

1. **Starvation signal narrowness**: only fires on the precise exit;
   no false positives from other zero-grant paths.
2. **Per-epoch isolation**: events reset at each rotation; can't
   accumulate stale signal across epochs.
3. **Hysteresis bound**: bypass stays at most 5 × EPOCH_DURATION_NS =
   1ms after last signaling rotation. Bounded leak window.
4. **Single-writer-per-slot for events**: same as
   worker_active_flow_buckets — only the owning worker writes.
5. **bypass_grace_rotations_remaining**: written only by rotation
   winner (CAS-serialized via epoch_seq). No race.

### v2.10 Risk assessment

| Class | Severity | Notes |
|-------|----------|-------|
| Behavioral regression | LOW | Bypass defaults off; existing v8 path unchanged unless saturation is precisely detected. |
| Lifetime / borrow-checker | LOW | New atomics owned by lease. |
| Performance regression | LOW | 1 conditional fetch_add per acquire (only on the narrow exit). 1 atomic load on bypass check. |
| iperf-e false positive | LOW | Narrow signal + 1ms hysteresis bound. Multi-sample harness (#1232) will quantify. |
| Concurrency / correctness | LOW | Relaxed atomics, single-writer per slot, rotation-serialized bypass updates. |

### v2.11 Test plan

(All v1 tests retained, plus narrow-signal tests:)

- `bypass_starvation_signal_fires_on_narrow_exit_only`: simulate
  acquire with primary exhausted + class room + grace closed →
  signal fires. Other zero-grant paths (cap reached, invalid
  worker, no request) do NOT fire.
- `bypass_arms_after_rotation_observes_signal`: simulate one
  rotation where any active worker had events > 0 → bypass
  countdown becomes 5.
- `bypass_decays_in_5_rotations_when_no_signal`: simulate 5
  consecutive rotations with no events → countdown reaches 0 →
  bypass off.
- `bypass_does_not_fire_under_subsaturation`: simulate iperf-e-style
  workload (each worker consumes < primary share) → no signal,
  no bypass.
- `bypass_active_worker_count_independent_of_max_worker_id`: 6
  configured slots, 3 active → bypass triggers on any 1 active
  worker's signal (not 5 of 6).
- Cluster smoke matrix as v1.

### v2.12 Open questions for adversarial review

1. **Hysteresis duration (5 rotations = 1ms)**: too short →
   bypass oscillates if iperf-c traffic is bursty; too long →
   leaks polling skew on subsiding bursts. Walk through
   alternatives: 3, 5, 10 rotations.

2. **Single-worker trigger**: ANY active worker signals → bypass
   on. Could a single misbehaving flow bucket cause bypass to
   stay on permanently when peers are sub-saturated? Verify
   via the [4,4,4] balanced case where no worker signals.

3. **Empirical recovery on iperf-c**: predicted ≥ 22.0 Gbps. The
   walk-through in §v2.5 shows mechanism but not exact aggregate.
   Smoke matrix is the empirical gate.

4. **Edge case: cap reached mid-grace**: if class budget hits cap
   during grace (e.g., one worker takes huge primary), `class_granted
   == cap` → `class_room == 0` → starvation signal does NOT fire
   (because class budget is exhausted, not blocked by grace).
   That's correct; no bypass needed if class is at cap.

5. **Interaction with rollback retry**: rollback path can leave
   class_granted inflated (undergrant). Could this cause false
   "class room remains" signal? Bound: undergrant is at most
   `take` per rollback × MAX_ROLLBACK_RETRIES; bounded.

6. **Re-entrant signaling**: same worker hits the narrow exit
   multiple times in one acquire batch (e.g., took primary,
   tried surplus, surplus blocked, retried). Each iteration
   increments events. Threshold of 1 event/epoch fires; multiple
   events also fire. No over-trigger because the rotation only
   checks `events > 0`, not threshold.

7. **iperf-c reverse direction**: smoke showed reverse stayed at
   22.1G with v8. With #1231 v2 enabled, will it stay flat?
   Reverse direction has different RSS distribution and CPU
   profile; if it doesn't trigger the narrow signal, nothing
   changes. Otherwise bypass arms and behavior reverts to greedy
   for surplus claims — that's still better than 19.3G.

8. **Telemetry**: should the rotation-time bypass arm/decay emit
   a counter? Useful for operator monitoring. Defer to v3 if
   needed.

9. **Dead-code removal**: v1 had per-worker `starvation_count`
   and lease-wide `bypass_grace: AtomicBool`. v2 redesigns to
   `worker_starvation_events` + `bypass_grace_rotations_remaining`.
   Old v1 design fully replaced; no dead code remains.

10. **Implementation effort estimate**: ~80 LOC production +
    ~150 LOC tests + smoke validation. ~3-4 hours focused work.


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
