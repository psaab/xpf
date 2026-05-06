---
status: DRAFT — disposition + forward path for #789 / #1204 fairness work
date: 2026-05-06
checkout: master @ 06c7a30c, plus experiment branches off of it
---

## TL;DR

The xpf userspace dataplane already implements every engineering action
that the #1204 expert mandate, the Phase 2 PLAN-KILL reviewers, and the
#789 fairness gate would require to clear ≤20% per-flow CoV under
ideal placement. Empirical CoV on iperf-c P=12 t=120 is **28%**.

The remaining 8 percentage points is **structural**, not buggy:
per-worker MQFQ + V_min sync cannot equalize flows distributed unevenly
across workers by RSS hashing, even when intra-queue scheduling math is
provably correct. iperf-d (non-saturated) clears the gate at 16%;
iperf-b/c/e/f (saturated) sit at 24-29%.

Three honest paths forward, ordered by reversibility:

1. **In-flight measurement (this session)**: V_min knob tuning sweep on
   `experiment/789-vmin-tuning`. If any cell drives saturated CoV under
   20% with aggregate ≥22 Gb/s, ship a tiny PR with new defaults.
2. **Architectural lever (deferred)**: investigate #937 ingress-side
   XDP_REDIRECT before UMEM ownership locks. If feasible, this is the
   only known mechanism that preserves aggregate throughput AND solves
   the RSS-skew root cause.
3. **Workload-aware gate (escalation)**: re-evaluate #789's ≤20% target
   for saturated workloads. iperf-d-style passes; saturated workloads
   are TCP-cwnd-jitter bound below 30s measurement windows.

## What ships in current tree (verified)

| Component | State | Citation |
|---|---|---|
| MQFQ vtime semantics | served-finish (correct) | `pop.rs:112` (commit `62f829d6` PR #928) |
| flow_fair on shared_exact | enabled | `admission.rs:478-486` (post-#785 Phase 3) |
| Bucket count | 4096 | `types/cos.rs:103` (since #785 Phase 3) |
| Cross-worker V_min sync | slot-floor with hard-cap | `queue_ops/v_min.rs` (#917 + #941) |
| Rate-aware admission | `max(fair_share*2, bdp_floor)` | `cos_queue_flow_share_limit` (#914) |
| ECN policy | per-flow on owner-local, aggregate on shared_exact | `cos/ecn.rs` |

Three of #1204's four mandate points have **no code work to do**:

- ❌ "Fix #913" — already shipped (PR #928, served-finish semantics)
- ❌ "Expand bucket count to 4096+" — already 4096 (since #785)
- ❌ "Trust RSS once intra-queue is sound" — intra-queue IS sound; RSS
  alone doesn't clear the gate empirically
- ✅ "Close PR #1203" — done (closed earlier this session)

## Empirical floor with the existing architecture

iperf P=12 t=120 with rate-aware admission + flow_fair on shared_exact +
#917 V_min sync (current master, commit `06c7a30c`):

| Class | Shape | Saturated? | Aggregate | CoV | Gate ≤20% |
|---|---|---|---|---|---|
| iperf-b (5202) | 10 Gb/s | Yes | 9.54 | 28.9% | ✗ |
| iperf-c (5203) | 25 Gb/s | Yes | 22.71 | 28.2% | ✗ |
| iperf-d (5204) | 13 Gb/s | No (95% util) | 12.40 | **16.4%** | ✓ |
| iperf-e (5205) | 16 Gb/s | Yes | 15.26 | 26.3% | ✗ |
| iperf-f (5206) | 19 Gb/s | Yes | 18.12 | 24.5% | ✗ |

**Saturation is the differentiator.** When shape rate < cluster
throughput capability, scheduling math has time to converge.
When ≥ capability, packets queue at the per-worker scheduler and TCP
cwnd jitter dominates within-queue per-flow variance.

## The structural limit (Codex retrospective in `/tmp/cos-findings.md`)

> V_min synchronizes per-worker queue virtual time. It does not make
> a global per-flow scheduler.
>
> Worker A has 1 heavy flow. Worker B has 3 heavy flows. Both transmit
> at comparable byte rates. Local queue_vtime values advance at
> comparable rates. V_min sees little or no lag. A's single flow gets
> the whole worker share. B's three flows split one worker share.
>
> That is not a bug in the current V_min implementation. It is the
> structural limit of per-worker fair queueing under RSS-skewed flow
> placement.

This same finding was reached independently by:

- This session's own #1203 Phase 2 plan-review (Codex `task-motkn4l0`,
  Gemini Pro 3 `task-motknsyz`, both PLAN-KILL)
- This session's own #936 plan-review (Codex `task-mou3gcvw`,
  PLAN-NEEDS-MAJOR with the "premise is stale" headline)
- The expert mandate at #1204 itself

Three independent reviewers reaching the same architectural diagnosis
is dispositive. The next move is empirical, not architectural.

## Path 1 — V_min knob tuning sweep (in-flight, this session)

Branch: `experiment/789-vmin-tuning`

Scaffold: `XPF_V_MIN_LAG_THRESHOLD_NS` and `XPF_V_MIN_READ_CADENCE`
env vars added as one-shot `OnceLock`-cached overrides in
`queue_ops/mod.rs`. Not for production — reverted to `const` before any
merge.

Sweep matrix:

- `lag_ns ∈ {100_000, 250_000, 1_000_000, 5_000_000}` (4 values; current
  default 1ms)
- `cadence ∈ {1, 8, 16}` (3 values; current default 8)
- ports: 5203 (iperf-c, worst CoV) + 5204 (iperf-d, baseline that
  passes — regression check)
- 12 cells × 2 ports × 60s iperf3 = ~28 min

**Acceptance for shipping a tuning PR:**
- iperf-c P=12 t=60 CoV ≤ 20%
- aggregate ≥ 22 Gb/s (no >5% regression)
- iperf-d unchanged or improved
- retransmits ≤ 200 averaged

**If no cell clears**: documented finding, close out with workload-aware
gate proposal (see Path 3).

## Path 2 — #937 ingress-side XDP_REDIRECT (architectural, deferred)

The only architectural lever Codex identified that could solve cross-
worker fairness without sacrificing aggregate. Distinct from PR #1203's
transmit-side cross-binding redirect (which was constrained by AF_XDP
UMEM ownership and didn't help).

**Idea**: redirect packets at the ingress XDP program **before** the
AF_XDP socket binding — i.e., before UMEM ownership is locked to a
specific worker. If feasible, RSS skew can be corrected at the XDP
layer without per-tuple HW state.

**Open questions**:
- Is XDP_REDIRECT to a different RX queue/CPU even possible without
  going through XSKMAP (which locks UMEM)?
- What's the latency cost vs current XDP path?
- How does this interact with the existing per-binding-worker model
  (would each worker still own its UMEM, or do we move to a shared
  pool)?

**Effort estimate**: weeks (research + prototype + plan-review +
implementation + smoke matrix). Not a session's-worth.

**Recommendation**: file a research issue (or revive the #937 issue
body) with the specific feasibility questions; gate any work on a
prototype answering them.

## Path 3 — Workload-aware gate

Honest acknowledgement that ≤20% CoV is unreachable for saturated
workloads on this architecture. Propose:

| Workload class | Gate |
|---|---|
| Non-saturated (shape < cluster capability) | ≤ 20% per-flow CoV |
| Saturated (shape ≥ cluster capability) | ≤ 30% per-flow CoV |

Document on #789 / #1204 with the structural limit explanation. Close
both with the disposition recorded.

This is the right call if Path 1 finds nothing AND Path 2 isn't
prioritized. Lets us mark #789 done with documented expectations
instead of an open issue chasing an unreachable target.

## Codex-suggested follow-on work (not gating fairness)

Codex's findings document recommends infrastructure hygiene that would
make any future fairness attempt cheaper. Listed in priority order:

### A. Doc/code drift check (LOW effort, HIGH value)

Add a lightweight test or pre-commit script that fails on stale
references like `COS_FLOW_FAIR_BUCKETS = 1024` or
`flow_fair = queue.exact && !shared_exact`. This session burned three
plan-review cycles on stale-anchor mistakes; a 50-line grep test would
prevent the next one.

**Concrete proposal**: `tests/cos_doc_drift_test.rs` that asserts none
of these patterns appear in active `userspace-dp/src/afxdp/cos/` or
`docs/pr/` files. Run in CI.

### B. Split `CoSQueueRuntime` (MEDIUM effort, MEDIUM value)

Current struct mixes 8 concerns (immutable config, token bucket,
runnable/parking, byte counters, flow-fair arrays, FIFO storage, V_min,
telemetry). Cold 4096-bucket arrays (~232 KB/queue) sit inline next to
hot fields, hurting cache locality.

**Suggested split**:
```rust
struct CoSQueueRuntime {
    config: CoSQueueConfigRuntime,
    hot: CoSQueueHotState,
    flow_fair: Option<Box<FlowFairState>>,  // boxed so non-fair queues don't pay
    v_min: VMinQueueState,
    telemetry: CoSQueueTelemetry,
}
```

Tracked separately from #789 — file as a follow-on after V_min sweep
completes.

### C. Consolidate `queue_service/service.rs` (MEDIUM effort, LOW-MEDIUM value)

4 variants of the same skeleton (local FIFO / local flow_fair /
prepared FIFO / prepared flow_fair). Refactor around one monomorphized
`service_skeleton<Adapter>` that takes a scratch-adapter trait
implementation.

### D. AFD/CSFQ per-flow ECN overlay (HIGH effort, MEDIUM value)

Codex notes shared_exact uses aggregate ECN only. Adding a per-flow
congestion signal via approximate fair dropping (#838 retrospective:
implemented, killed for race-safety; revisit with single-writer
sharding) would give TCP a smoother feedback loop.

This is in the same architectural family as #936; if Path 2 is funded
this becomes a complementary mechanism.

### E. Modularity housekeeping

Codex flags 4 files >2K LOC that should be watched (and possibly
refactored): `poll_descriptor.rs`, `worker/mod.rs`,
`coordinator/mod.rs`, `frame/mod.rs`. The modularity-discipline rule
in `docs/engineering-style.md` already covers this; just keep the
audit current.

## Recommended decision tree

```
Path 1 sweep result
├── Clears ≤20% gate on iperf-c with aggregate preserved
│      → ship tuning PR with new defaults; close #789 + #1204
├── Improves but doesn't clear gate
│      → ship tuning PR for the partial win + propose Path 3 gate
└── No improvement
       → propose Path 3 (workload-aware gate); close #789 + #1204

Independent of Path 1:
├── Path 2 feasibility study (file as new issue, separate effort)
└── Path A doc-drift check (file as immediate small PR)
```

## Anti-patterns to avoid (lessons from this session)

- **Don't plan against issue body language; plan against current code.**
  This session repeatedly drafted plans citing stale issue text or
  comments (`cos.rs:432-434` "shared_exact bypasses flow_fair"). The
  code was already past those text descriptions.
- **Don't build new schedulers when the existing one is correct.** PR
  #1203 (steering), Phase 2 (byte-rate), #936 v1 (cross-worker shared
  vtime) all proposed mechanisms that either already existed or
  couldn't theoretically clear the gate.
- **Don't claim a partial win is OK without explicit acceptance**.
  PR #1203 measured 49-55% CoV (gate ≤20%) and was framed as "ship
  the mechanism, document the gap" — closed once the user (acting as
  expert) called it correctly as masking a non-bug.
- **Don't skip empirical verification before architectural plans.**
  Five minutes of `grep` against the actual code would have prevented
  three plan-review cycles. The drift check (Path A above) is the
  systemic answer.

## Status of this session's branches

- `master` — clean, deployed; flow-steering knob removed from CLI
- `refactor/789-fairness-via-ntuple` — Phase 1 (closed PR #1203);
  Rust-side per-binding flow-inventory foundation preserved for
  potential telemetry reuse
- `refactor/789-phase2-byte-rate` — Phase 2 PLAN-KILL recorded;
  no code touched
- `refactor/936-shared-perflow-vtime` — #936 plan v1 WITHDRAWN;
  three stale "1024 buckets" docstring scrubs are the only retainable
  output
- `experiment/789-vmin-tuning` (current) — env-var override scaffold +
  this disposition doc; revert overrides before any merge

## Open issues to close once Path 1 completes

- **#789** — disposition documented; close with workload-aware gate
  if Path 1 doesn't clear it.
- **#1204** — close with reference to this doc; mandate's actions
  already shipped or empirically inadequate.
- **#936** — close with Codex's "structural limit, not bug" framing;
  reopen only if Path 2 (#937) prototype shows feasibility.
- **#937** — re-prioritize as "feasibility study"; do not commit
  implementation work without a prototype answering the open
  questions.
