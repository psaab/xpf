# Plan v1 — #1625 per-queue epoch-cap mechanism in waterfill selector

> Step-2 of #1614 Axis A. Step-1 (PR #1618 / 31c42d279) shipped the
> wire surface, scaffold, A4 commit warning and the simul-load smoke
> harness. This plan turns the scaffold into a behaviorally functional
> per-class allocator that satisfies the Pass C gate in
> `test/incus/cos-simul-load-smoke.sh`.

## 1. Goal / scope

Replace the existing **per-pass total-byte cap** mechanism in
`select_exact_cos_guarantee_queue_waterfill` (file
`userspace-dp/src/afxdp/cos/queue_service/mod.rs`, fn at lines
~771-1007) with a **per-queue, per-epoch byte allowance** that
genuinely throttles large classes when small classes are still owed
their configured guarantee. Concretely, after this PR:

- A 100 Mbps exact class lands ≥ 95% of its 100 Mbps shape under
  simul-load with 11 saturated classes summing to ~110 Gbps offered.
- A 6 Gbps exact class lands ≥ 95% of 6 Gbps under the same load.
- Large classes (12g..24g) take the residual after small classes
  are honored. The 24g class is allowed to drop substantially —
  this is the documented operator-visible trade-off in
  `docs/fairness-regimes.md` "CoS oversubscription policy".
- Default `Proportional` mode is bit-for-bit unchanged. The legacy
  selector path is untouched.

**Out of scope** (explicitly):
- A2 priority-low min-share (#1614 Axis A2 — defers to its own
  follow-up; the wire field is already plumbed).
- A3 CoDel-style sojourn AQM (already-deferred Axis A3).
- B-axis mechanisms (B1 first-SYN affinity, B2 cross-worker shared
  shaper-budget atomic, B4 dedicated cores).
- Modifying `userspace-dp/src/policy/` (owned by parallel #1623
  sub-agent).
- Modifying `test/incus/synthetic-policy-gen.py` or
  `cold-path-microbench.sh` (owned by parallel #1622 sub-agent).
- Any change to `pkg/cluster/` HA paths.

File-zone disjoint with parallel sub-agents on #1622 (`test/incus/`)
and #1623 (`userspace-dp/src/policy/`). This PR owns
`userspace-dp/src/afxdp/cos/` and `userspace-dp/src/afxdp/types/cos.rs`
exclusively.

## 2. Diagnosis of why the step-1 scaffold doesn't change distribution

The existing v5.1 scaffold (post-#1618) implements:

- Phase 1 ascending walk consuming a single shared
  `waterfill_pass1_remaining_bytes` byte budget = `quantum_sum ×
  fraction`. Each Phase 1 selection decrements that budget by the
  selected queue's per-visit secondary_budget.
- Phase 2 descending walk that visits ANY queue not yet honored
  this epoch and lets it transmit up to its quantum.

The defect is that Phase 2's descending visit **has no per-queue
per-time bound at all**. The selector returns a 24g-class queue with
quantum 524288 B (the
`COS_GUARANTEE_QUANTUM_MAX_BYTES` clamp), the worker drains 512 KB,
returns, the selector is called again 200-500 ns later, Phase 1
still has zero `pass1_remaining` so we skip ahead to Phase 2, pick a
large class again, drain its quantum, etc. Token-bucket math doesn't
gate this because under saturation arrival each visit replenishes
`hot.tokens` up to the burst cap (typically ≥ 1 MB for 12g+
classes), and `secondary_budget` = `min(tokens, quantum) ≥
head_len`. Over 30 s of simul-load the result is RR-style equal-byte
allocation across all 11 classes ≈ aggregate / 11 ≈ 1.9 Gbps per
class, observed by PR #1618 smoke as ~21% per class. Small classes
get vastly more than their shape (100 Mbps class hits ~1.9 Gbps =
19×); large classes get vastly less (24g class hits ~1.9 Gbps =
8% of shape).

**Why the existing per-queue token-bucket doesn't help**: under
saturated arrival, `last_refill_ns` deltas accumulate enough
`hot.tokens` between visits to satisfy `quantum_bytes` ≤ tokens for
ANY queue. The token bucket bounds long-term per-queue throughput
to ≤ `transmit_rate_bytes`, BUT only when the queue is *not*
visited often enough. When the worker's RR is so fast that every
queue is visited within 200 µs (the existing `COS_GUARANTEE_VISIT_NS`
constant — the same as the proposed epoch), large queues effectively
drain at their shape rate AND small queues drain at ≥ 1500 B per
visit (the `COS_GUARANTEE_QUANTUM_MIN_BYTES` floor) which at the
same visit cadence converts to over-share for small classes.

The step-1 scaffold's `pass1_remaining` mechanism narrowed the
problem (Phase 1 visits smaller classes first) but didn't change
**how much** each class is allowed to transmit per epoch — every
class still gets its full quantum, just in a different order.

## 3. Mechanism — per-queue per-epoch cap with race-free reset

We add two `u64` fields to `CoSQueueHotState` (single-writer = the
owner binding; no atomics needed):

```
pub(in crate::afxdp) struct CoSQueueHotState {
    // ... existing fields ...
    /// #1625: bytes serviced from this queue in the current
    /// 200 µs epoch under GuaranteeRate policy. Reset to 0 at
    /// epoch boundary by `cos_guarantee_epoch_maybe_rotate`.
    /// Owner-only writes; not consulted by Proportional mode.
    pub(in crate::afxdp) epoch_bytes_serviced: u64,
}
```

We add two epoch-rotation fields to `CoSInterfaceRuntime`:

```
pub(in crate::afxdp) struct CoSInterfaceRuntime {
    // ... existing fields ...
    /// #1625: monotonic timestamp when the current per-queue
    /// epoch began. Rotated when `now_ns ≥ guarantee_epoch_start_ns
    /// + COS_GUARANTEE_VISIT_NS`. Owner-only writes.
    pub(in crate::afxdp) guarantee_epoch_start_ns: u64,
}
```

The selector, at the top of each call when `GuaranteeRate` policy
is active, runs:

```
let elapsed = now_ns.saturating_sub(root.guarantee_epoch_start_ns);
if elapsed >= COS_GUARANTEE_VISIT_NS {
    // Epoch rotation: reset per-queue counters and Phase 1 budget.
    for queue in &mut root.queues {
        queue.hot.epoch_bytes_serviced = 0;
    }
    root.guarantee_epoch_start_ns = now_ns;
    root.waterfill_pass1_remaining_bytes = 0;  // forces Phase 1 refill below
    root.waterfill_phase2_cursor = 0;
}
```

Then, when picking a candidate queue (BOTH Phase 1 and Phase 2),
**before** consuming the per-visit secondary_budget:

```
// Per-queue per-epoch cap. Compute the byte allowance this queue
// is owed in the current 200 µs epoch from its configured
// transmit_rate_bytes. Skip the queue if it has already serviced
// at or above its allowance this epoch.
let allowance =
    cos_per_queue_epoch_allowance_bytes(queue, root.oversubscription_guarantee_fraction);
if queue.hot.epoch_bytes_serviced >= allowance {
    continue;
}
```

with helper:

```
#[inline]
pub(in crate::afxdp) fn cos_per_queue_epoch_allowance_bytes(
    queue: &CoSQueueRuntime,
    guarantee_fraction: f64,
) -> u64 {
    // Allowance in bytes = transmit_rate_bytes × COS_GUARANTEE_VISIT_NS / 1e9
    // (the per-epoch slice of the queue's configured rate).
    // Then floor at the configured min-quantum (1500 B) so a
    // 100 Mbps queue still gets at least 1 packet per epoch
    // (without this, a 100 Mbps queue's allowance = 12_500 B / s
    // × 200 µs = 2_500 B which is correct, but a 50 Mbps queue
    // would be 1_250 B which is below MTU; the 1500 B floor
    // preserves "1 packet per visit" liveness).
    let allowance = ((queue.transmit_rate_bytes() as u128)
        * (COS_GUARANTEE_VISIT_NS as u128) / 1_000_000_000u128) as u64;
    // Use guarantee_fraction as a scaling factor that increases
    // the allowance for small classes proportionally: at frac=0.7,
    // each queue gets allowance × (1/frac) = 1.43× allowance,
    // letting small classes consume their share PLUS surplus
    // share before being capped. At frac=1.0 (strict guarantee
    // only), allowance is unchanged. At frac=0.0 the mechanism
    // is disabled (selector falls through to the legacy
    // proportional path before this code runs).
    //
    // NOTE: this is the precise inverse of v5.1's pass1_budget
    // shrink. v5.1 multiplied total budget by frac; we divide
    // per-queue allowance by frac so smaller frac means each
    // queue is allowed to over-shoot more.
    //
    // Codex/AGY question: is dividing by frac the right
    // semantics? Alternative: scale by `1/(1-frac)` so frac=0
    // means strict per-queue cap and frac=1 means unbounded;
    // or always cap at exactly `rate × epoch_ns / 1e9` and let
    // frac control the Phase 1 budget split only. PROVISIONAL
    // PICK: always cap at exactly rate × epoch (ignore frac in
    // the per-queue cap). frac retains its v5.1 meaning as
    // Phase 1 budget multiplier. This is the simplest semantics
    // and most defensible: per-queue cap == queue's true rate,
    // no operator surprises.
    allowance.max(COS_GUARANTEE_QUANTUM_MIN_BYTES)
}
```

After the visit, the chosen secondary_budget is debited against
both `pass1_remaining` (Phase 1) and the queue's
`epoch_bytes_serviced` (always):

```
// In Phase 1 selection:
root.waterfill_pass1_remaining_bytes = ...;  // existing
queue.hot.epoch_bytes_serviced =
    queue.hot.epoch_bytes_serviced.saturating_add(candidate_budget);

// In Phase 2 selection:
queue.hot.epoch_bytes_serviced =
    queue.hot.epoch_bytes_serviced.saturating_add(candidate_budget);
```

That's the mechanism. Key properties:

1. **Per-queue cap is exact**: a queue cannot transmit more than
   `transmit_rate_bytes × 200 µs / 1e9` per epoch. This matches the
   queue's configured rate.
2. **Epoch rotation is owner-only**: no atomics. Each binding
   worker maintains its own copy of `CoSInterfaceRuntime`. There
   is no cross-binding aggregation here.
3. **Race-free reset**: rotation is timer-based — when
   `now_ns - epoch_start ≥ 200 µs`, the owner resets all
   counters in one pass. No CAS, no swap.
4. **Default Proportional mode is bit-for-bit unchanged**:
   `epoch_bytes_serviced` field is initialized to 0, never read or
   written outside the `GuaranteeRate` selector path.

## 4. Cross-binding question — per-binding-per-queue OR shared?

**Picked: per-binding-per-queue.** The PerEpochCap state lives in
`CoSQueueHotState` (per-binding-per-queue, owner-only). It does NOT
extend the cross-binding `SharedCoSQueueLease` mechanism from #917 /
#1229 Phase 6 v8.

Rationale:
- The `SharedCoSQueueLease` already coordinates cross-binding token
  budget for `shared_exact` queues — see
  `queue.queue_lease_v8: Option<Arc<SharedCoSQueueLease>>`. If a
  queue is `shared_exact`, the cross-binding rate enforcement
  already binds it (each binding can only pull a small lease at a
  time, the lease refills at rate × elapsed). The per-queue
  per-epoch cap is *additive* on top: it caps how many lease bytes
  this binding can spend on this queue per epoch, even if the
  global lease has room.
- For non-shared_exact queues, the queue is owned by exactly one
  binding. Per-binding-per-queue == per-queue.
- A shared cross-binding `epoch_bytes_serviced` would require an
  atomic and would re-introduce the contention that #1229 Phase 6
  v8 was designed to eliminate (the seqlock-rotated fair lease
  pattern is owner-only on the hot path, with a cross-binding
  reconciliation step only at epoch boundaries). Adding a
  cross-binding atomic to the per-epoch cap path would regress
  that work.
- For the simul-load smoke specifically, each iperf3 sender's
  flows hash to a single RSS queue → single binding owner.
  Per-binding caps are sufficient.

**Open question for reviewers**: under cross-binding-skewed
ingress (e.g., #1614's documented per-binding starvation case
where one binding sees 9 of 11 classes), does a per-binding cap
fail to enforce the global per-class rate? Yes — if 1 binding
sees 100% of a class's traffic and the cap is per-binding, the
cap = true rate. If 2 bindings each see 50%, each binding's cap =
true rate → effective cap = 2× rate. This is the SAME limitation
#1230 Phase 6 v8 v_min coordination addresses for the
`shared_exact` case, and is OUT OF SCOPE for this PR (would need
a cross-binding lease covering ALL exact queues). For the smoke
gate the cap is per-binding because the test fixture pins each
class to a single sender.

## 5. Refill arithmetic, race conditions, and integer overflow

- `transmit_rate_bytes × COS_GUARANTEE_VISIT_NS = u64::MAX-safe`
  iff `rate ≤ u64::MAX / 200000 ≈ 9.2e13` bytes/s = 738 Tbps. Yes,
  safe. We compute in u128 to be defensive.
- Floor at `COS_GUARANTEE_QUANTUM_MIN_BYTES = 1500 B` so a 5 Mbps
  queue still gets a packet per epoch. **Trade-off**: queues with
  rate < 60 Mbps will exceed their pro-rata share by the ratio
  `1500 / (rate × 200 µs)` (at 5 Mbps that's 1500 / 125 ≈ 12×,
  matching today's over-share for the smallest class). For the
  smoke fixture (100 Mbps minimum) the floor is barely above the
  natural allowance: 100 Mbps × 200 µs = 2500 B which IS above
  1500 B, so the floor doesn't bind.
- Saturating arithmetic everywhere; no panic risk under
  pathological config.
- The `epoch_bytes_serviced` reset MUST happen on every visit if
  we're past the epoch boundary. The simplest place is a
  one-shot at the top of `select_exact_cos_guarantee_queue_waterfill`.
  We chose top-of-call because that's where `now_ns` enters.

## 6. Files touched

- `userspace-dp/src/afxdp/types/cos.rs` — add `epoch_bytes_serviced`
  to `CoSQueueHotState`, add `guarantee_epoch_start_ns` to
  `CoSInterfaceRuntime`.
- `userspace-dp/src/afxdp/cos/builders.rs` — initialize both new
  fields (`epoch_bytes_serviced: 0`, `guarantee_epoch_start_ns:
  now_ns`).
- `userspace-dp/src/afxdp/cos/queue_service/mod.rs` —
  - Add `cos_per_queue_epoch_allowance_bytes` helper.
  - Add epoch rotation at top of
    `select_exact_cos_guarantee_queue_waterfill`.
  - Add per-queue allowance check at both Phase 1 and Phase 2
    selection sites, BEFORE the existing
    `pass1_remaining_bytes` check.
  - Debit `epoch_bytes_serviced` at both selection commit sites.
- `userspace-dp/src/afxdp/cos/queue_service/tests.rs` — new tests
  per §8 below.
- `userspace-dp/src/afxdp/worker/cos/tests.rs` — update test
  initializers that build `CoSQueueRuntime` / `CoSInterfaceRuntime`
  literals (there are many; per `grep`,
  `waterfill_pass1_remaining_bytes: 0` appears 7× in this file).
- `docs/fairness-regimes.md` — update "CoS oversubscription policy"
  section to document that the algorithm is now functional, including
  the per-class predicted-behavior table.
- `docs/pr/1625-per-queue-epoch-cap/` — plan and review docs.

No protocol/wire changes (the knobs `oversubscription_policy` and
`oversubscription_guarantee_fraction` already shipped in #1618).
No Go-side changes.

## 7. Performance considerations

- One extra `u64` per `CoSQueueHotState`: 8 B per queue, 11 queues
  × 1 interface × (#bindings ≈ 6) ≈ 528 B per worker. Negligible.
- One extra `u64` per `CoSInterfaceRuntime`: 8 B per interface.
  Negligible.
- Hot path: one extra `saturating_sub` + comparison per queue
  visit in the selector. The epoch rotation loop is O(queue_count)
  = O(11) once per 200 µs per interface per worker ≈ 5000
  iterations/sec/worker ≈ 5 µs of arithmetic/sec/worker. Order of
  noise.
- Proportional mode untouched — zero overhead.

## 8. Test plan

### 8.1 Cargo unit tests (BLOCKING)

Append to `userspace-dp/src/afxdp/cos/queue_service/tests.rs`:

1. `waterfill_per_queue_cap_limits_large_class_within_epoch` —
   build a 2-class runtime (100 Mbps + 6 Gbps), feed
   `select_exact_cos_guarantee_queue_waterfill` repeatedly across
   a synthetic now_ns sweep that stays within ONE 200 µs epoch.
   Assert the 6g class's total `secondary_budget` ≤ its allowance
   = 6 Gbps × 200 µs = 150 KB.
2. `waterfill_per_queue_cap_resets_at_epoch_boundary` — same
   2-class runtime, advance now_ns by exactly 200 µs in the middle
   of a busy selection sequence. Assert that `epoch_bytes_serviced`
   resets to 0 for all queues at the boundary and the next
   selection succeeds.
3. `waterfill_per_queue_cap_honors_small_class_with_oversub` —
   3-class runtime (100m, 1g, 6g) with all three saturated, run
   1000 selection iterations, assert each class's accumulated
   bytes is within ±5% of `rate × elapsed_ns × fraction`.
4. `waterfill_per_queue_cap_proportional_mode_unchanged` — set
   `oversubscription_policy = Proportional`, verify the selector
   never touches `epoch_bytes_serviced`.
5. `waterfill_per_queue_cap_min_quantum_floor_preserves_liveness`
   — build a 50 Mbps queue (allowance = 1250 B < 1500 B),
   assert it still gets exactly 1 packet (≥1500 B head) per
   epoch.

### 8.2 Cargo flake check (BLOCKING)

```
cargo test --manifest-path userspace-dp/Cargo.toml waterfill_per_queue \
    -- --test-threads=1
```
Run 5× in a row. All 5 must pass.

### 8.3 Existing tests (BLOCKING)

```
cargo test --manifest-path userspace-dp/Cargo.toml
```
Full suite must pass. The known waterfill tests
`waterfill_default_proportional_mode_uses_legacy_rr`,
`waterfill_guarantee_rate_mode_picks_smallest_rate_first`,
`waterfill_guarantee_rate_skips_non_exact_queues` MUST continue
to pass (Phase 1's ascending-walk ordering invariant is
unchanged).

### 8.4 Go tests (BLOCKING)

```
make test
```
No Go behaviour changes expected; the suite must still pass.

### 8.5 HA failover (BLOCKING — CoS-touching)

```
make test-failover
```
Must show ≤ 60 ms failover and zero TCP RST. This PR doesn't
touch HA code but the CLAUDE.md mandate applies because the CoS
hot path is in scope.

### 8.6 Smoke matrix (BLOCKING — Pass A, B, C)

On the loss userspace cluster (`loss:xpf-userspace-fw0/fw1`):

- **Pass A** — best-effort, CoS-off: full 30-measurement matrix
  per `feedback_smoke_push_and_reverse` (v4/v6 × push/reverse ×
  baseline + multi-stream). Aggregate ≥ 22 Gbps push, ≥ 18 Gbps
  reverse on the simple v4 single-stream baseline.
- **Pass B** — CoS-on, NOT oversubscribed: apply
  `cos-iperf-config.set` fixture, run per-class smoke on ports
  5201-5211 with `STREAMS=1` (not saturated). Each class must
  achieve ≥ 95% of its shape.
- **Pass C — THE BLOCKING GATE** —
  `./test/incus/cos-simul-load-smoke.sh push`. All gates 1, 2, 3
  must pass:
  - gate_1: small classes (100m, 1g, 3g, 6g) achieve ≥ 95% of
    their shape under saturated 11-class simul load.
  - gate_2: priority-low achieves ≥ 5% of cluster ceiling
    (~900 Mbps).
  - gate_3: per-class retransmits ≤ 100/30 s.

  Run reverse direction as well:
  `./test/incus/cos-simul-load-smoke.sh reverse`.
  Reverse direction aggregate ≥ 22 Gbps confirms the
  firewall is not the bottleneck (gate_8).

If Pass C gate 1 fails, this PR is rejected. Plan-kill may be
the appropriate outcome.

## 9. Risk / what could go wrong

1. **The mechanism still doesn't change distribution.** If the
   actual root cause of #1614's 21%/class is OUTSIDE the
   selector (e.g., it's in the token-bucket refill rate which is
   already shape-rate-correct, or in cross-binding skew, or in
   the upstream RSS hash distribution funnelling all classes to
   the same binding), then per-queue per-epoch caps in the
   selector won't help. The smoke is the final arbiter.
2. **The 1500 B floor breaks small classes.** If a class is
   configured at < 60 Mbps, the 1500 B floor lets it exceed its
   shape by the ratio `1500 / (rate × 200µs)`. The smoke fixture
   doesn't include any < 100 Mbps classes, but operator configs
   may. Mitigation: document in `docs/fairness-regimes.md`.
3. **The 200 µs epoch is too coarse for low-rate queues.** A 5
   Mbps queue allowed 1500 B per 200 µs = 60 Mbps effective
   rate. Mitigation: same as risk 2 — documented limitation.
4. **Epoch rotation overlap on slow workers.** If a worker is
   slow (long syscall, NIC stall) and skips multiple epoch
   boundaries, our rotation logic only resets once on the next
   selector call. This is correct — we don't owe queues
   "back-pay" for missed epochs (that would let them burst). The
   rotation IS lossy and the queue rate is enforced epoch by
   epoch, NOT averaged over time. This matches the existing
   token-bucket semantics (token bucket likewise caps at burst
   capacity, not accumulated long-run owed).
5. **Cross-binding skew defeats per-binding caps.** Covered in
   §4. If both bindings see traffic for the same class, each
   enforces the same cap → effective cap is 2×. Acceptable for
   PR-1625 because the smoke fixture pins each class to a
   single binding. Will need #1614 Axis B follow-up if real
   workloads pin differently.

## 10. Open questions for reviewers

1. **Phase 1 budget interaction with per-queue caps.** With
   per-queue caps in place, is the v5.1 `pass1_remaining_bytes`
   mechanism still useful? Arguments for keeping it: it
   preserves the "small-first within an epoch" ordering when
   multiple small classes are eligible. Arguments for removing
   it: the per-queue cap alone is sufficient — Phase 1 / Phase 2
   distinction becomes a no-op. PROVISIONAL: keep
   `pass1_remaining_bytes` (Phase 1 ascending walk wins ties
   even when both queues are under their epoch cap). REVIEWERS
   PUSH BACK if you have a stronger view.

2. **Epoch boundary semantics — common or per-queue?**
   Single shared `guarantee_epoch_start_ns` per interface.
   Alternative: per-queue `epoch_start_ns` so each queue rotates
   independently when it has been visited. Why not per-queue:
   complicates the reset logic (need to track "next visit due"
   per queue), and the simulation under simul-load shows all
   queues are saturated → all rotate at the same wall-clock
   boundary anyway. REVIEWERS: alternative arguments?

3. **The 1500 B `COS_GUARANTEE_QUANTUM_MIN_BYTES` floor.**
   Should the per-queue allowance respect it (preserves
   liveness, breaks rate-honoring for < 60 Mbps queues), or
   ignore it (rate-honoring strict, but a 5 Mbps queue might
   not transmit at all for many epochs)? PROVISIONAL: floor.
   REVIEWERS: alternative?

4. **`guarantee_fraction` semantics.** v5.1 uses it as the
   Phase 1 budget multiplier. This PR preserves that, AND
   does NOT scale the per-queue cap. So at frac=1.0, ALL
   queues get exactly `rate × 200 µs` per epoch — strict
   guarantee enforcement, residual lost. At frac=0.5, Phase 1
   honors half the queues then surplus available for Phase 2
   but per-queue cap still bounds large classes. Is this the
   right semantics? REVIEWERS: should `fraction` ALSO scale
   the per-queue cap (e.g., cap = `rate × 200µs × (1/frac)`)
   to allow surplus over-shoot? PROVISIONAL: NO — cleaner
   operator mental model if the per-queue cap == queue's true
   rate, always.

5. **Pass C gate plausibility.** Given the §2 diagnosis, do
   reviewers believe the per-queue cap will actually achieve
   ≥ 95% on the 100 Mbps class under simul load? If the
   diagnosis is wrong (root cause is elsewhere), this entire
   plan is wasted. REVIEWERS: please challenge the §2
   diagnosis HARD before declaring PLAN-READY. Counter-example:
   if the actual issue is cross-binding skew (a single binding
   sees all 11 classes), per-binding caps won't enforce the
   global rate at all — the smoke would still fail.

## 11. Plan-kill conditions

This plan is PLAN-KILLED if reviewers establish, with evidence,
any of:

- The §2 diagnosis is materially wrong (e.g., the real bottleneck
  is in the upstream RSS hash or in the per-binding worker thread
  scheduling, not in the CoS selector).
- The per-queue per-epoch cap mechanism is structurally
  insufficient to honor small-class guarantees under simul-load
  on the smoke fixture (e.g., because the cross-binding skew in
  §4 dominates).
- The mechanism would regress the working `Proportional` default
  mode and the proposed structural insulation (gated on policy
  enum) is not sufficient.

If PLAN-KILLED, the right alternative is one of:
- Cross-binding shared per-class lease (extends #917 V_min to
  ALL exact queues, not just `shared_exact`). Much larger work.
- Reduce `COS_GUARANTEE_VISIT_NS` to e.g. 50 µs and accept the
  RR cycle cost. Doesn't address root cause.
- Re-architecture: per-class dedicated workers (#1614 Axis B4
  — declared OUT OF SCOPE).
