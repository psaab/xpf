# #1296 — Plan v2: hybrid work-conserving equal-flow mode

**Status:** DRAFT v2 — pending adversarial plan review.

This supersedes the PLAN-KILL framing in plan v1 (preserved as the
historical record on disk). Both Codex round-1
(task-mpnhvhnt-d8pfry) and AGY round-1
(adversarial-review-mpnhwmkc-ce8q3k) returned PLAN-NEEDS-MAJOR with a
convergent finding: the existing `equal-flow-enforcement` knob is a
*non*-work-conserving suppressor that's mutually exclusive with
`surplus-sharing` (`pkg/config/compiler.go:432`). The issue body's
"Option 2" (surplus donation gated by an epoch per-flow cap) is a
genuine third mode and is **not** structurally blocked by AF_XDP ZC
physics, because it's a logical egress rate cap, not packet steering.

This plan implements that hybrid as **#1304 Phase 1** (#1296 is the
parent evidence cited by #1304 itself). The contract pivots from
"PLAN-KILL because nothing to ship" to "ship the hybrid mode AGY
proved viable, validate empirically on smoke, fall back to no-merge
if implementation reveals the egress-cap framing was wrong".

## Issue framing (restated)

Post-#1295 measurements show that with `surplus-sharing` enabled,
the harness reports structural PASS but raw per-flow CoV is high
(0.49-0.71 mean across q2/q3/q6). The structural PASS is correct
under the #1217 contract — but it does not deliver the product goal
of low raw per-flow CoV.

Existing options today:

| Mode | Aggregate throughput | Raw per-flow CoV | Configured by |
|---|---|---|---|
| Default (`Cstruct`) | High (structural cap) | High (~0.5-0.7 under RSS skew) | omitted |
| `surplus-sharing` | High (above structural) | High (same; +redistribution) | `set ... surplus-sharing` |
| `equal-flow-enforcement` | Low (≤ structural cap, no surplus) | Low (~0.04-0.14, strict-exact) | `set ... equal-flow-enforcement` |

The product gap is the **High-aggregate × Low-CoV cell**. AGY's
worked example argues that this cell is reachable for the
*structural-slack* sub-regime where the bottleneck worker has more
active flows than peers, and peers have spare primary share that the
bottleneck would otherwise be unable to consume.

## Hybrid Option 2 — design

### Junos surface

Allow `equal-flow-enforcement` to be combined with `surplus-sharing`.
Compiler validation in `pkg/config/compiler.go:432` currently rejects
this; relax that check. Document the combined semantics in
`docs/fairness-regimes.md`:

- Both flags set: hybrid work-conserving equal-flow.
  - Per-flow target `target_per_flow_bps` published per epoch by the
    existing `publish_equal_flow_epoch_v8` machinery.
  - Per-worker cap `worker_cap_i = target_per_flow_bps *
    active_flows_i`.
  - `acquire_v8` enforces `total_granted[i] ≤ worker_cap_i` across
    primary + surplus combined.
  - Surplus path remains open subject to that hybrid cap and to the
    class total cap.

### Dataplane: new V8RateMode variant

Today's `V8RateMode::EqualFlowSuppress` (mod.rs:368) is the
non-work-conserving suppressor that drives `surplus_open = false`
when enforced (mod.rs:1186). Hybrid Option 2 requires a third variant
so `acquire_v8` can branch correctly:

```rust
pub(in crate::afxdp) enum V8RateMode {
    CstructDefault,
    EqualFlowSuppress,         // strict-exact-like (no surplus, opt-in)
    EqualFlowWorkConserving,   // NEW: surplus-open + per-worker cap (hybrid)
}
```

Coordinator (`userspace-dp/src/afxdp/coordinator/mod.rs:1063`)
selects:

```rust
let rate_mode = match (queue.equal_flow_enforcement, queue.surplus_sharing) {
    (true, true)  => V8RateMode::EqualFlowWorkConserving,
    (true, false) => V8RateMode::EqualFlowSuppress,
    (false, _)    => V8RateMode::CstructDefault,
};
```

### `acquire_v8` modifications (mod.rs:1018-1244)

Three minimal edits:

1. **Generalize the cap check.** `equal_flow_cap_v8` returns the
   per-worker cap when either equal-flow variant is enforced; today
   it only fires for `EqualFlowSuppress` (mod.rs:1459).

2. **Open `surplus_open` for hybrid.** Replace
   `surplus_open = bypass && !equal_flow_enforced` (mod.rs:1186)
   with:

   ```rust
   let work_conserving_eq_flow =
       v8.rate_mode == V8RateMode::EqualFlowWorkConserving;
   let surplus_open =
       bypass && (!equal_flow_enforced || work_conserving_eq_flow);
   ```

   Net behavior:
   - `EqualFlowSuppress` (existing): `surplus_open = bypass && false`
     = false — strict-exact, unchanged.
   - `EqualFlowWorkConserving` (new): `surplus_open = bypass && true`
     = bypass — surplus still gated by the existing bypass-grace
     CPU-bound flag; **the hybrid does not weaken when surplus is
     allowed**.
   - `CstructDefault` (existing): `surplus_open = bypass && true` =
     bypass — unchanged.

3. **Hybrid cap on surplus draw.** In the surplus loop
   (mod.rs:1190-1236), enforce the per-worker cap on the combined
   primary+surplus total. Today the surplus loop only respects
   `class_cap`; under hybrid it must also respect
   `my_effective_share = equal_flow_cap` (already computed at line
   1062).

   ```rust
   // existing surplus loop:
   let class_room = cap - class_granted as u64;
   let take = still_needed.min(class_room).min(u32::MAX as u64);
   // becomes (only for EqualFlowWorkConserving):
   let my_room = if work_conserving_eq_flow {
       let my_curr = my_pg.0.load(Ordering::Acquire);
       let (my_tag2, my_consumed) = PackedEpochGrant::unpack(my_curr);
       if my_tag2 != my_tag { break; }
       my_effective_share.saturating_sub(my_consumed as u64)
   } else {
       u64::MAX
   };
   let take = still_needed.min(class_room).min(my_room).min(u32::MAX as u64);
   if take == 0 { break; }
   ```

   This keeps the surplus loop's existing tag-checked CAS structure
   intact. The only added work is the `my_pg` Acquire load per
   surplus iteration, which is already done once in the bypass-event
   probe at mod.rs:1149.

### `publish_equal_flow_epoch_v8` (rotate_epoch_v8.rs +
publish_equal_flow_epoch_v8.rs) — no change required

The cap-publishing math is unchanged because the cap is computed
from `prev_grant[i] / active_flows[i]`. The donor that left primary
share unused under hybrid will still have low `prev_grant`, which
correctly drives `target_per_flow` *down* (preserving fairness).
The fail-open `LowDemandWorker` reason (publish_equal_flow_epoch_v8.rs:98)
correctly catches a quiet donor whose under-utilization would
otherwise drag the cap below the bottleneck worker's actual delivery.

**Critical stability check (must be verified in implementation):**
under hybrid, a surplus *consumer* worker's `prev_grant[i]` includes
the surplus bytes. That makes its per-flow sample
`prev_grant[i]/active_flows[i]` = approximately
`(primary_share + surplus_share) / active_flows[i]`. The
`target_per_flow = min_active(per_flow_i)` will then be set by the
LEAST-served worker — typically the donor whose surplus was just
consumed by the bottleneck. So the cap rises by ~1 epoch's worth of
surplus consumption per epoch, then plateaus when surplus draw stops
covering the gap.

Stability requires the smoothing factor `(3*prev + cand)/4` (`/4` in
publish_equal_flow_epoch_v8.rs:124) and `EQUAL_FLOW_VALID_STREAK_REQUIRED`
(line 153) to dampen oscillation; if measured oscillation is large
enough to break the fairness gate, plan v2 implementation MUST be
revisited or PLAN-KILLED with the empirical evidence.

### Compiler/parser changes

- `pkg/config/compiler.go:432`: relax the rejection to only block
  the *strict-exact mode* combination — i.e., reject the combination
  only when ALSO some flag forbidding surplus (none today besides
  `transmit_rate_exact == false`, which is already caught at
  :427-430). For the hybrid path, allow the combination and let the
  dataplane select `EqualFlowWorkConserving`.

  Concretely: remove the bare `equal_flow && surplus` check, retain
  the `equal_flow && !transmit_rate_exact` check.

- `pkg/cmdtree/tree.go:1056-1059`: update help text for both keys to
  note the combined hybrid mode.

- `pkg/config/parser_class_of_service_test.go:308-330`: revise tests
  that asserted the combination is rejected. New tests should:
  - assert the combination is *accepted* and compiles to
    `EqualFlowEnforcement=true && SurplusSharing=true`
  - assert the snapshot wire propagates both flags
  - keep the existing strict-exact-without-transmit-rate test

### Documentation

`docs/fairness-regimes.md`: add a new "Equal-flow work-conserving"
section describing the hybrid mode, its empirical evidence (citing
#1220 and the smoke verification this PR ships), and the
relationship to the strict `equal-flow-enforcement` (renamed in
prose to "equal-flow strict") and `Cstruct` modes.

`docs/per-5-tuple/state.md`: update the mutual-exclusion note (line
467 area) to reflect the new combination.

### Telemetry — what's needed

The existing `xpf_userspace_cos_equal_flow_suppressed_grant_bytes_total`
metric counts bytes the *strict* mode would have granted but
suppressed. Under hybrid, the meaning shifts: bytes that the cap
forbade in the surplus loop. Update the metric description in
`pkg/api/metrics_descriptors.go:310` to clarify this. Add a new
companion metric `xpf_userspace_cos_equal_flow_surplus_grant_bytes_total`
for surplus bytes *granted* under hybrid (i.e., the work-conservation
win).

`xpf_fairness_equal_flow_suppressed_bps`: similar disposition.
Update the help text.

The Prometheus exposition's mode label should expose
{cstruct,equal_flow_strict,equal_flow_work_conserving} so dashboards
can pivot.

## Empirical verification (smoke matrix)

Acceptance: `≤ 0.10` raw per-flow CoV on q2/q3/q6 saturated samples
under hybrid mode (i.e., both `surplus-sharing` and
`equal-flow-enforcement` set on the scheduler). Note: this is
TIGHTER than #1304's "≤ 0.20" gate because the hybrid mode promises
work-conserving behavior — if it can't beat 0.20 by a margin, it's
not delivering the value claim.

Smoke commands (canonical):

```bash
# Pass A: CoS disabled (best-effort, regression check)
# Standard skill matrix per docs/triple-review SKILL.md.

# Pass B: hybrid equal-flow enabled on q2/q3/q6
# Modify test/incus/cos-iperf-config.set: add equal-flow-enforcement
# to the q2-sched / q3-sched / q6-sched (or whichever schedulers
# bind to iperf-e / iperf-f / iperf-c).
sg incus-admin -c "./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0"

# Run cos-headroom-q2q3q6 (the harness from #1220)
sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
  fairness-eval --queues q2-iperf-e-16g,q3-iperf-f-19g,q6-iperf-c-25g \
                --multisample 5 --duration 30"

# Pass criteria:
#   - aggregate throughput within 10% of pre-hybrid (Pass A)
#   - raw per-flow CoV ≤ 0.10 mean, ≤ 0.15 max
#   - 0 starved flows
#   - structural PASS verdict preserved (observed ≤ Cstruct + 0.05)
#   - Pass A unchanged (no regression in CoS-disabled fast path)
```

If acceptance is met → merge.
If acceptance is NOT met → PR is held in `AWAITING-DESIGN-DECISION`
state. Possible reasons:
- target_per_flow oscillation drags throughput down (smoothing
  insufficient)
- hybrid converges to strict-exact behavior in practice (no work
  conservation benefit)
- new failure mode (e.g., starved flows under specific RSS
  placements)
- the egress-logical-cap framing was wrong (cross-binding
  coordination required → kill)

## Out of scope (#1304 explicit deferrals)

- Phase 0 measurement-only estimator (already shipped via #1220
  fairness-eval).
- Phase 2 harness side-by-side qualification — separate PR.
- Phase 3 product contract docs polish — separate PR; this PR ships
  the minimum doc needed to describe the hybrid mode.
- New equal-flow mechanism for the non-saturated regime.
- ECN drop overlay (#1211 archive — different mechanism class).

## Risk assessment

| Class | Risk | Mitigation |
|---|---|---|
| Behavioral regression | LOW-MED | new variant gated by hybrid config combination; both `Cstruct` and strict `EqualFlowSuppress` paths byte-identical to master |
| Lifetime / borrow-checker | LOW | one new `V8RateMode` discriminant; no new lifetime; new variant lives in same enum |
| Performance regression | LOW | hybrid path adds one Acquire load per surplus iteration (already done once at line 1149); strict and default paths unchanged |
| Stability of target_per_flow under surplus draw | **MEDIUM** | mitigated by existing `(3p+c)/4` smoothing + valid-streak gate; verified empirically on smoke. If oscillation is unstable, plan v2 KILLED. |
| Architectural mismatch (#946 Phase 2 / #1211 dead-end pattern) | LOW | logical egress rate cap inside existing acquire_v8 lease state machine; AGY independently traced no cross-worker re-routing required |
| Telemetry semantics drift | LOW | metric names retained, help text updated, new companion metric added rather than mutating existing |

## Open questions for adversarial review

1. **Stability** — does the `prev_grant[i]/active_flows[i]` cap math
   feedback-loop into instability when surplus draws boost
   `prev_grant`? The fail-open `LowDemandWorker` catches one end of
   the asymmetry; does it catch both? Worked numeric trace required
   from the reviewer.

2. **Donor identification** — under hybrid, the "donor" is a worker
   with fewer active flows than peers. Its `prev_grant` should
   stay near `target_per_flow * active_flows` (its own cap). Is
   there a starvation-of-donor risk if the consumer's surplus draw
   slows the donor's primary path (e.g., via class-cap contention
   on the CAS)?

3. **Telemetry naming** — should the existing
   `xpf_userspace_cos_equal_flow_suppressed_grant_bytes_total`
   metric be renamed under hybrid, or should the hybrid mode emit a
   parallel metric? Operator dashboards may already exist.

4. **#1304 phase alignment** — is this Phase 1 of #1304, or a
   sibling? The #1304 issue body's Phase 1 says "Apply caps at an
   existing CoS dequeue/acquire boundary with O(1) local state".
   Hybrid Option 2 matches that exactly. Confirm.

5. **AGY's worked example assumed all consumers had primary-share
   slack available**. In the asymmetric-demand case where both
   donor and consumer want surplus, the cap correctly slows the
   consumer — but does it deliver CoV reduction or just preserve
   the structural ceiling? Smoke evidence required, not just
   reviewer assertion.

6. **Rollback story** — `EqualFlowWorkConserving` requires the
   compiler to allow the previously-forbidden combination. Existing
   configs that asserted this rejection (parser_class_of_service_test.go
   has at least one such test) must be migrated. Is there a config
   on the loss userspace cluster that would unexpectedly start
   compiling under hybrid? Inspection required.

## Test plan

### Cargo
- `cargo build --release` clean
- `cargo test --release` full suite — must include new
  V8RateMode::EqualFlowWorkConserving unit tests
- 5/5 flake on new hybrid-mode tests
- 952+ existing tests preserved

### Go
- `go test ./pkg/config/...` — including new hybrid-config
  validation tests
- `go test ./pkg/api/...` — verify Prometheus metric help-text
  updates
- 30 Go packages clean

### Smoke (loss userspace cluster, per skill triple-review SKILL.md)
- Pass A: CoS disabled, v4+v6 × push+reverse, 0 retrans
- Pass B: per-class CoS smoke (5201-5206) v4+v6 push+reverse, all 24
  measurements pass with 0 retrans for unshaped classes
- **Pass C: fairness verification** — q2/q3/q6 hybrid run via
  fairness-eval; raw CoV ≤ 0.10 mean ≤ 0.15 max; structural PASS
  preserved; 0 starved flows; aggregate within 10% of Pass A unshaped
  best-effort fast path

If Pass C does not meet acceptance, PR is held and we **stop and
report** rather than push through (per user's mandate).

## Reviewer prompts (for round-2 dispatch)

Both Codex and AGY should verify:

1. The V8RateMode variant approach is the right surgery shape (vs.
   e.g. a `surplus_open` override flag on the existing variant).
2. The compiler relaxation is safe (no existing valid configs
   accidentally enable hybrid).
3. The metric naming/help-text changes preserve dashboard
   compatibility.
4. The target_per_flow stability claim holds under worked-trace
   analysis (donor-feedback loop under surplus draw).
5. The smoke matrix exercises the hybrid mode end-to-end.
6. The kill-or-merge criterion in "Empirical verification" is
   honest — i.e., if hybrid fails to deliver CoV ≤ 0.10 by a real
   margin, we DON'T ship.
