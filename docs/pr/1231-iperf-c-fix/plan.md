# #1231 — 'all peers CPU-bound' detector to fix iperf-c push -15% regression

**Status:** DRAFT v4 — incorporates Codex v3 PLAN-NEEDS-MAJOR fixes
(task-moxd44lk-0tthoz).

## v3 PLAN-NEEDS-MAJOR summary (preserved)

Codex (task-moxd44lk-0tthoz): "Spine is sound: narrow local signal +
aggregate-underuse AND gate + epoch-tagged events is the right
shape. Two concurrency/liveness details + one ordering ambiguity."

**Fixes (all addressed in v4 §below):**

1. Signal placement: under active bypass, surplus consumes
   `still_needed` → no signal fires → bypass decays after 5
   rotations → grace re-closes → starvation resumes → bypass
   re-arms. **Oscillator.** Fix: signal on "would have been
   blocked by grace" check immediately after primary exhaustion,
   BEFORE bypass surplus path runs.

2. Event reset race: scan-then-store reset can lose an old-tag
   CAS that succeeds between scan and store. Bounded missed
   boolean, but proof needs fixing. **Fix:** atomic
   `swap(pack(new_tag, 0))` per slot at rotation; old returned
   count is reliably the prior epoch's value.

3. Rotation order ambiguity: pseudocode contradicts itself.
   **Fix:** explicit ordered pseudocode in §v4.2.

Plus minor: probe F typo (75 KB derivation), LOC estimate
closer to 100-140 prod (status/protocol surfacing).

---

## v4 design — fix signal placement, atomic-swap reset,
## explicit rotation order

### v4.1 Signal placement (Codex v3 fix #1)

The narrow signal must fire at the precise point where the worker's
primary share is exhausted AND grace is still closed AND class
room remains AND `still_needed > 0`, REGARDLESS of whether bypass
opens surplus immediately after. The signal records that "this
worker would have been blocked by grace if bypass were not active",
which is the regime-detection question we want to answer.

```rust
// PRIMARY PATH (existing logic, unchanged) ...
// At end of primary path, check the narrow signal exit:
let primary_exhausted_with_class_room =
    still_needed > 0
    && my_consumed_after_primary >= my_fair_share
    && (class_granted_after_primary as u64) < epoch_total_grant_cap
    && now_ns < grace_expires_ns
    && active;

if primary_exhausted_with_class_room {
    // Tag-checked CAS bump on starvation events (v3.2).
    bump_starvation_event(&v8.worker_starvation_events[worker_id], my_tag);
}

// SURPLUS PATH: open if grace expired OR bypass active.
// (existing v3 logic unchanged) ...
```

The signal is a "would have been blocked by grace" probe. Even
when bypass turns surplus open and the worker proceeds to claim
surplus successfully, the SIGNAL was registered first — so the
rotation observer sees that a worker hit the regime. Bypass is
sustained as long as the regime persists.

When the regime ends (workload subsides, primary becomes
sufficient), no worker hits the narrow exit → no signal → bypass
decays in 5 rotations.

### v4.2 Atomic-swap reset + explicit rotation order (Codex v3 fixes #2, #3)

Rotation pseudocode, ordered:

```rust
fn maybe_rotate_epoch_v8_with_v4_bypass(now_ns: u64) {
    // STEP 0: existing seqlock-claim CAS (EVEN→ODD).
    let seq = v8.epoch.epoch_seq.load(Acquire);
    if seq & 1 == 1 { return; }
    let start = v8.epoch.epoch_start_ns.load(Acquire);
    if start != 0 && now_ns < start.saturating_add(EPOCH_DURATION_NS) {
        return;
    }
    if v8.epoch.epoch_seq.compare_exchange(seq, seq + 1, AcqRel, Acquire)
        .is_err()
    {
        return;
    }

    // STEP 1: read prior-epoch aggregate state BEFORE resetting.
    let prev_packed_granted = v8.epoch.packed_granted.0.load(Acquire);
    let (_prev_class_tag, prev_granted) =
        PackedEpochGrant::unpack(prev_packed_granted);
    let prev_cap = v8.epoch.epoch_total_grant_cap.load(Acquire);

    // STEP 2: atomic-swap each event slot to new_tag/0; collect
    // returned old (tag, count) pairs to determine which active
    // workers signaled.
    let new_tag = ((seq >> 1) + 1) as u32;
    let new_packed = PackedEpochGrant::pack(new_tag, 0);
    let mut any_active_worker_signaled = false;
    for (worker_id, pg) in v8.worker_starvation_events.iter().enumerate() {
        let old = pg.0.swap(new_packed, AcqRel);
        let (_old_tag, old_count) = PackedEpochGrant::unpack(old);
        // Only count if this worker was active in the prior epoch.
        let active = v8
            .worker_active_flow_buckets
            .get(worker_id)
            .map(|c| c.load(Relaxed) > 0)
            .unwrap_or(false);
        if active && old_count > 0 {
            any_active_worker_signaled = true;
        }
        // After this swap, any old-tag CAS attempt by an in-flight
        // acquire fails naturally (its observed pre-swap value no
        // longer matches the post-swap value AND the tag mismatches
        // even if it did). No event leak.
    }

    // STEP 3: aggregate-underuse condition.
    let underuse_slack = prev_cap / 20; // 5%
    let aggregate_underuse =
        (prev_granted as u64).saturating_add(underuse_slack) < prev_cap;

    // STEP 4: arm or decay bypass.
    if any_active_worker_signaled && aggregate_underuse {
        v8.epoch
            .bypass_grace_rotations_remaining
            .store(5, Release);
        v8.epoch.bypass_grace_arm_count.fetch_add(1, Relaxed);
    } else {
        let curr = v8.epoch
            .bypass_grace_rotations_remaining
            .load(Acquire);
        if curr > 0 {
            v8.epoch
                .bypass_grace_rotations_remaining
                .store(curr - 1, Release);
        }
    }

    // STEP 5: reset class grant counter (existing v8 logic).
    v8.epoch.packed_granted.store_for_new_epoch(new_tag);
    for grant in v8.worker_grants.iter() {
        grant.store_for_new_epoch(new_tag);
    }

    // STEP 6+: existing rotation publication (cap, grace, fair_share,
    // start_ns), seq EVEN bump.
    // ... unchanged ...
}
```

Key invariants this ordering guarantees:
- prev_granted/prev_cap reads see the actual prior-epoch
  values (Step 1, before Step 5 reset).
- Event swap (Step 2) atomically captures-or-rejects in-flight
  bumps. No lost or stale signal.
- Bypass decision (Step 4) uses both prior-epoch aggregate
  state AND prior-epoch signal state. Coherent decision.

### v4.3 Cost adjustment (Codex v3 LOC note)

Updated estimate: ~120 prod LOC (including Prometheus/status
surfacing for the two telemetry counters), ~180 test LOC. ~5
hours focused work.

### v4.4 Open questions for adversarial review (v4)

1. **Step 2 swap semantics**: `swap` returns the old packed
   value before atomically replacing. If an in-flight acquire
   has loaded the old value but not yet CASed, the swap stores
   new_tag/0 first; the in-flight CAS sees old value (mismatch
   with current swap-stored value) → fails. So no double-count.
   Verify this behavior against `compare_exchange_weak`
   semantics.

2. **Bypass decay race**: rotation winner reads
   `bypass_grace_rotations_remaining` (Step 4 Acquire), decrements,
   stores. Another rotation can't run concurrently (epoch_seq CAS
   serializes), so no race.

3. **Hot-path cost**: signal-bump path is one tag-checked CAS
   (cold; only fires on the narrow exit). Bypass-load is one
   Relaxed read per acquire. Existing CAS cost unchanged.

4. **Iperf-c regression validation**: predicted recovery to ≥
   22.0 Gbps. Walk-through in v3 §5 (with v4 typo fix:
   `200µs × 3G/sec ÷ 8 = 75 KB`). Bypass arms continuously
   under saturation; surplus opens immediately; aggregate
   matches greedy minus class CAS contention.

5. **Iperf-e [4,3,4,1] revalidation**: per-worker consumption
   below primary share for all workers (per v3.4 walk-through).
   No signal. Bypass off. v8 fairness preserved. ✓.

6. **Round 4 readiness**: spine sound, three Codex v3
   blockers all addressed mechanically. Should be PLAN-READY.

---

## DEPRECATED v3 — superseded by v4 above

(v3 spec preserved below for diff readability; v4 supersedes.)

## v2 PLAN-NEEDS-MAJOR summary (preserved)

Codex (task-moxcusww-thgqy7) — "v2 is not a kill. Spine is
salvageable. Three blockers."

1. **Signal still too broad**: early-polling worker in balanced
   saturated epoch can exhaust its primary BEFORE peers acquire
   (class room remains simply because peers haven't shown up
   yet). Reintroduces polling skew. Must AND with aggregate
   condition + `still_needed > 0`.

2. **Reset race**: rotation winner resets `AtomicU16`
   worker_starvation_events while in-flight acquire from old
   snapshot may bump it. Loses the bump or carries stale event
   into new epoch. Need epoch-tagged events (PackedEpochGrant
   pattern, not plain counter).

3. **Wrong iperf-e distribution**: v2 walk-through used
   [2,2,2,2,2,2] (6 active, balanced). Real iperf-e is
   [4,3,4,1] on 4 active workers per recipe doc. The 1-flow
   worker's primary share is 1.33G; ≥1.33G TX would trigger
   bypass even at sub-saturated aggregate.

Plus 2 minor:
- 5 rotations / 1ms hysteresis: acceptable after trigger fix.
- Single-worker trigger: defensible only with epoch-end aggregate
  guard; percentage quorum would miss [6,5,1] case.

## v3 design — narrow signal + aggregate-underuse AND-gate +
## epoch-tagged events

### v3.1 Signal narrowing (Codex F1 fix)

The starvation signal must require ALL of:
- `still_needed > 0` (worker actually wants more — wasn't the
  end of a finished batch)
- `my_consumed >= my_fair_share` (primary exhausted)
- `class_granted as u64 < epoch_total_grant_cap` (class still
  has budget — not at cap)
- `now_ns < grace_expires_ns` (grace closed)
- `active` (worker has flow buckets queued)

Critically, the bypass arm condition at rotation requires LOCAL
signal AND aggregate-underuse:

```rust
let any_active_worker_signaled = /* event > 0 on any active slot */;
let prev_cap = epoch.epoch_total_grant_cap.load(Acquire);
let prev_packed = epoch.packed_granted.0.load(Acquire);
let (_, prev_granted) = PackedEpochGrant::unpack(prev_packed);
// Aggregate-underuse: prior epoch granted less than ~95% of cap.
// If at or near cap, system was operating at hardware limit — no
// 'lost capacity' from grace gating; bypass would only leak
// fairness without recovery.
let underuse_slack = prev_cap / 20; // 5% slack
let aggregate_underuse = (prev_granted as u64) + underuse_slack < prev_cap;

if any_active_worker_signaled && aggregate_underuse {
    epoch.bypass_grace_rotations_remaining.store(5, Release);
} else {
    let curr = epoch.bypass_grace_rotations_remaining.load(Acquire);
    if curr > 0 {
        epoch.bypass_grace_rotations_remaining.store(curr - 1, Release);
    }
}
```

Why aggregate-underuse?
- iperf-c saturated post-v8: aggregate 19.3G vs cap 25G ≈ 77%
  ≪ 95% slack → underuse fires AND C signals → bypass arms.
- iperf-c saturated pre-v8 / hardware limit: aggregate 22.7G vs
  cap 25G ≈ 91% ≪ 95% → underuse fires. If C still signals,
  bypass arms; this is actually fine because eliminating grace
  delay would let C's stranded primary be claimed faster
  without harming the aggregate (already at hardware limit).
- iperf-e sub-saturation balanced: aggregate 14.3G vs cap 16G
  ≈ 89% < 95% → underuse fires. BUT no worker exhausts primary
  in balanced [4,3,4,1] (per §v3.5 walk-through with REAL
  numbers). So no signal → no bypass.
- iperf-e degenerate [10,1,1,0]: dominant worker A might exhaust
  primary; signal fires; aggregate is under cap; bypass arms;
  v8 fairness leaks momentarily until distribution balances.
  Mitigated by 1ms hysteresis duration; bypass decays once
  signal stops.

### v3.2 Epoch-tagged events (Codex F2 fix)

Replace `worker_starvation_events: Box<[AtomicU16]>` with
`Box<[PackedEpochGrant]>` (reusing the existing tagged-CAS
pattern). Slot is `(epoch_tag << 32) | event_count`.

- **Bump**: tag-checked CAS. If tag mismatches (rotation since
  snapshot), abandon — the new epoch starts fresh anyway.
- **Reset at rotation**: store `(new_tag, 0)` for every slot.
  Atomic store — no lost increments because old-tag bumps
  observe the new tag and abandon their CAS.

Acquire-path bump:

```rust
// After primary path, after surplus path, signal check:
if still_needed > 0
    && /* my_consumed >= my_fair_share */
    && /* class_granted < epoch_total_grant_cap */
    && now_ns < grace_expires_ns
    && active
{
    // Tag-checked CAS bump. Failure (tag mismatch) means rotation
    // happened — silent skip; the new epoch starts at events=0
    // and the next acquire will signal cleanly if the regime
    // persists.
    let pg = &v8.worker_starvation_events[worker_id];
    let curr = pg.0.load(Ordering::Acquire);
    let (curr_tag, curr_count) = PackedEpochGrant::unpack(curr);
    if curr_tag == my_tag && curr_count < u32::MAX {
        let new = PackedEpochGrant::pack(curr_tag, curr_count + 1);
        let _ = pg.0.compare_exchange_weak(
            curr, new, Ordering::AcqRel, Ordering::Acquire);
        // CAS failure: contention or rotation; not retried — one
        // missed signal in N is fine (rotation-time aggregator
        // only checks for ANY signal).
    }
}
```

Rotation reset:

```rust
let new_tag = ((seq >> 1) + 1) as u32;
// ... existing reset of packed_granted, worker_grants ...

// NEW: scan PREVIOUS epoch's events (current tag = old_tag) before
// resetting them.
let any_active_signaled = v8.worker_active_flow_buckets.iter()
    .zip(v8.worker_starvation_events.iter())
    .any(|(active_atom, pg)| {
        active_atom.load(Ordering::Relaxed) > 0 && {
            let v = pg.0.load(Ordering::Acquire);
            let (_tag, count) = PackedEpochGrant::unpack(v);
            count > 0
        }
    });

// Aggregate-underuse check (BEFORE resetting packed_granted).
let prev_packed = v8.epoch.packed_granted.0.load(Ordering::Acquire);
let (_, prev_granted) = PackedEpochGrant::unpack(prev_packed);
let prev_cap = v8.epoch.epoch_total_grant_cap.load(Ordering::Acquire);
let underuse_slack = prev_cap / 20;
let aggregate_underuse = (prev_granted as u64) + underuse_slack < prev_cap;

if any_active_signaled && aggregate_underuse {
    v8.epoch.bypass_grace_rotations_remaining.store(5, Ordering::Release);
    v8.epoch.bypass_grace_arm_count.fetch_add(1, Ordering::Relaxed);
} else {
    let curr = v8.epoch.bypass_grace_rotations_remaining.load(Ordering::Acquire);
    if curr > 0 {
        v8.epoch.bypass_grace_rotations_remaining.store(curr - 1, Ordering::Release);
    }
}

// Reset events for the NEW epoch (atomic store with new tag).
for pg in v8.worker_starvation_events.iter() {
    pg.0.store(PackedEpochGrant::pack(new_tag, 0), Ordering::Release);
}
```

### v3.3 Telemetry counters (Codex F5 prescription)

Add to `SharedCoSEpochState`:

```rust
struct SharedCoSEpochState {
    // ... existing ...
    /// #1231 v3: incremented at each rotation that arms bypass.
    /// Diagnostic; visible via Prometheus.
    bypass_grace_arm_count: AtomicU64,
    /// #1231 v3: incremented at each acquire that benefits from
    /// bypass (took surplus that was opened by bypass, not by
    /// grace expiry).
    bypass_grace_use_count: AtomicU64,
}
```

Telemetry accessor:

```rust
pub(in crate::afxdp) fn v8_bypass_grace_arms(&self) -> u64 { ... }
pub(in crate::afxdp) fn v8_bypass_grace_uses(&self) -> u64 { ... }
pub(in crate::afxdp) fn v8_bypass_grace_active(&self) -> bool { ... }
```

### v3.4 Real iperf-e walk-through with [4,3,4,1] (Codex F3 fix)

Per recipe doc and PR #1230 smoke results, iperf-e canonical
12-stream reproducer post-v8 distribution: [4,3,4,1] across 4
active workers. Aggregate 14.3G vs 16G shaper.

Per-epoch values at 200µs:
- cap = 16G/8 × 200µs = 400 KB
- A primary (4/12): 133 KB
- B primary (3/12): 100 KB
- D primary (4/12): 133 KB
- E primary (1/12): 33 KB

Per-flow rate (post-v8): 1196 Mbps mean (per smoke results).
Per-worker bytes per epoch:
- A (4 flows × 1.196 G/sec × 200µs ÷ 8) = 4 × 30 KB = **120 KB**
- B (3 × 30 KB) = **90 KB**
- D (4 × 30 KB) = **120 KB**
- E (1 × 30 KB) = **30 KB**

Comparison vs primary:
- A: 120 < 133 → no signal
- B: 90 < 100 → no signal
- D: 120 < 133 → no signal
- E: 30 < 33 → no signal

**Result:** zero workers signal. Bypass stays off. v8 CoV
preserved. ✓

Edge case [10,1,1,0]: 3 active workers, 12 flows.
- W0 primary (10/12): 333 KB; per-epoch consume at 10 flows ×
  per-flow rate. If per-flow rate stays 1.2G → 10 × 30 KB = 300
  KB. 300 < 333 → no signal. Even degenerate distribution is
  resilient as long as per-flow rates stay stable.

Riskier edge case [12,0,0,0]: 1 active worker, 12 flows on
single worker. Per-flow rate would drop to ~0.5G under CPU-bound
saturation. Worker primary (12/12): 400 KB; consumes 12 × 0.5G ×
200µs ÷ 8 = 12 × 12.5 KB = 150 KB. 150 < 400 → no signal.

OK across realistic distributions, balanced + degenerate +
extreme, the narrow signal stays quiescent on iperf-e.

### v3.5 Real iperf-c walk-through with [6,5,1]

Per recipe doc, iperf-c canonical push 12-stream distribution:
[6,5,1] across 3 active workers. Pre-v8 aggregate 22.7G; post-v8
19.3G.

Per-epoch values at 200µs, cap = 25G/8 × 200µs = 625 KB:
- A primary (6/12): 313 KB
- B primary (5/12): 260 KB
- C primary (1/12): 52 KB

Pre-v8 per-flow rate (saturation): mean ≈ 1.89G (22.7G / 12).
- A: 6 × 47 KB = 283 KB ≤ 313 → no signal (close though)
- B: 5 × 47 KB = 237 KB ≤ 260 → no signal
- C: 1 × 47 KB = 47 KB ≤ 52 → no signal

Hmm — pre-v8 saturated DIDN'T signal either. Let me reconsider.

Post-v8 the per-flow rate dropped because v8 throttled. So
pre-v8 numbers don't show the failure.

Post-v8 per-flow rate: 19.3G / 12 = 1.61G mean. But the
distribution was uneven; specifically C's flow ran at ~3.19G
in user's pre-v8 sample (one big flow, no neighbors).

Wait — recipe doc says C had 1 flow at ~3.98G post-sym-key-pin
(at 22.7G aggregate). Pre-v8 in the user's sample C's 1 flow was
at 3190 Mbps.

Post-v8 with bypass off and grace gating, C's flow effectively
gets capped at primary share + half-epoch surplus. C primary
share = 52 KB/200µs = 0.26 GB/sec = 2.08 G/sec. C's CPU can do
~4G; v8 caps at primary plus surplus only after 100µs grace,
effectively halving C's throughput → ~2.5-3G observed.

Per-epoch C consumes whatever its CPU + grace allows ≈ 0.0001s × 3G
= 75 KB. C's primary is 52 KB. C exhausts primary AT the rate it
can consume but the lookups happen in granular acquire calls.

The mechanism: C calls acquire_v8 hundreds of times per epoch (each
batch top-up). Some calls get primary (up to 52 KB total). After
that, every C acquire returns 0 (primary exhausted, class room
exists, grace not expired) → signal fires.

So C signals reliably under post-v8 saturation. ✓

Aggregate post-v8 = 19.3G < 95% × 25G = 23.75G → underuse fires.
Bypass arms.

### v3.6 Public API preservation (v3)

Same as v2: `acquire_v8` signature unchanged. New atomics
internal to V8State / SharedCoSEpochState. Three new accessor
methods for telemetry.

### v3.7 Hidden invariants (v3)

1. Same as v2 plus:
2. Tag-checked event bump: rotation-safe.
3. Aggregate-underuse check: rotation-time only, after both
   prev_granted and prev_cap are read but BEFORE reset.
4. Single-writer-per-slot for events: still holds, but writes
   use tag-checked CAS so concurrent same-slot writes from old-
   tag context fail naturally.

### v3.8 Risk assessment (v3)

| Class | Severity | Notes |
|-------|----------|-------|
| Behavioral regression | LOW | Bypass requires LOCAL signal AND aggregate-underuse — both conditions must hold. |
| Lifetime / borrow-checker | LOW | New atomics owned by lease. |
| Performance regression | LOW | 1 conditional tag-checked CAS per acquire (only on the narrow exit). 1 atomic load on bypass check. Aggregate-underuse computed once per rotation. |
| iperf-e false positive | LOW | Narrow signal + aggregate gate + 1ms hysteresis. Real distribution walk-throughs [4,3,4,1], [10,1,1,0], [12,0,0,0] all show zero signal. |
| Concurrency / correctness | LOW | Tag-checked CAS for events; rotation-serialized bypass updates; Relaxed for non-CAS paths. |

### v3.9 Test plan (v3)

(All v2 tests retained, plus:)
- `bypass_signal_requires_still_needed_gt_zero`: simulate end-of-batch
  acquire with `still_needed == 0` → no signal even if other
  conditions hold.
- `bypass_aggregate_underuse_gates_arming`: simulate prev epoch
  granted == cap (no slack) → bypass does NOT arm even if signal
  present.
- `bypass_event_tag_check_drops_old_epoch_writes`: simulate
  acquire with stale tag → CAS fails, no inflight bump leaks.
- `bypass_telemetry_counters_increment`: cover arm/use counters.
- iperf-e [10,1,1,0] simulated walk-through: no signal across
  workers.
- iperf-c [6,5,1] simulated walk-through: C signals; bypass arms.

### v3.10 Out of scope (v3)

- Adaptive hysteresis duration (5 rotations is fixed).
- Cross-class bypass coordination (per-class only).
- Bypass-arm rate-limiting (acceptable to arm every rotation
  under sustained saturation).

---

(Original v2 spec preserved below for diff-readability; v3
supersedes.)

## DEPRECATED v2 — superseded by v3 above

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
