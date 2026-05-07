# Per-5-Tuple Fairness Drive — State

**As of 2026-05-07.** This document records the standing mandate, the
shipped foundations, the killed mechanisms, and the surviving design
options for cross-worker per-(dip,dport,sip,sport) fairness on the
xpf userspace AF_XDP dataplane. It is a living state file — update
when issues open, ship, or close. The intent is that the next session
can read this file and inherit a clean working set rather than re-deriving
the history from issue/PR archaeology.

## Standing mandate

Drive per-(dip,dport,sip,sport) fairness end-to-end. The aggregate
fairness target is captured by the structural CoV contract shipped in
PR #1217:

> observed_CoV ≤ Cstruct + 0.05

where `Cstruct` is computed from the per-worker active-flow distribution
`{aᵢ}`, plus a starved-flow hard fail and a saturated-only aggregate gate.

The user accepts aggregate throughput regression on degenerate RSS
distributions if it buys per-flow fairness on the realistic ones.

## Shipped foundations

### PR #1217 — Fairness regimes contract (e1ec6b90, 2026-05-07)

Defines the contract a fairness mechanism must clear:

- structural CoV: `observed_CoV ≤ Cstruct + 0.05`
- starved-flow hard fail: any flow that gets ≤ 1% of mean per-flow
  throughput for the entire steady-state window fails the gate
- saturated-only aggregate gate: the `(observed_aggregate <
  structural_cap × 0.97)` check applies only when the offered load is
  large enough to expect saturation
- structural cap: `(n_active / n_total_workers) × shaper_rate`

Document: `docs/fairness-regimes.md`. Pinned worked examples live in
`userspace-dp/src/fairness.rs::tests`.

### PR #1220 — Fairness harness (bf87cf71, 2026-05-07)

Empirically measures `Cstruct` and `observed_CoV` from a real iperf3
run. Answers the operational question "is observed_CoV at the
structural ceiling, or is there a scheduler bug?"

- BPF-side: `last_used_epoch: u16` on `FlowCacheEntry`, owner-only
  writes on lookup hit; no per-packet hot-path cost.
- Userspace-dp: `count_active_flows()` scans 4096-entry flow_cache
  every ~65 ms (umem 0xFFFF gate, ~15 Hz publish rate); writes
  `BindingLiveState.active_flow_count: AtomicU32`.
- Exposure: `xpf_userspace_binding_active_flow_count{binding_slot,
  queue_id, worker_id, iface}` Prometheus gauge.
- Harness: `test/incus/fairness-harness.sh` runs iperf3 + 1 Hz
  /metrics scrape; `userspace-dp/src/bin/fairness-eval` parses
  iperf3 -J + 6-col TSV, aggregates per-worker on filtered iface,
  emits PASS/FAIL verdict JSON.

Operational measurement (iperf-c P=12 -R, ge-0-0-2): observed_CoV
≈ 47% **is below** the structural ceiling for the RSS distribution
the cluster produced. **No scheduler bug; structurally skew-bound
under that input.** Any fairness mechanism must be evaluated against
this gate, not against an unconditional CoV target.

## Killed mechanisms

| # | Issue | Killed | Reason |
|---|-------|--------|--------|
| 1 | #840 | reverted | runtime NIC RSS indirection-table tuning can't fix cross-binding skew with long-lived flows |
| 2 | #1215 | PLAN-KILL | local-stall mechanism: head-of-line blocking on a single worker doesn't compose across workers |
| 3 | #836 | PLAN-KILL | shared HOL queue: AF_XDP UMEM ownership prevents cross-worker descriptor sharing |
| 4 | #840 / #1203 | PLAN-KILL | RSS steering at AF_XDP-ZC binding time is permanent physics — kernel pins flow→queue at bind |
| 5 | #937 | PLAN-KILL | ingress XDP_REDIRECT for fairness: kernel feature support not present, would need upstream work |
| 6 | #1211 | PLAN-KILL | Path 2 race-safe AFD overlay: closed 2026-05-07 after 8 Codex rounds + 3 Gemini rounds. PR #1220 empirical PASS on the motivating workload made the design solving a non-existent problem. See `docs/per-5-tuple/path2-archive/CLOSING-RATIONALE.md` for full rationale. |

The table above is the current canonical triage for killed mechanisms
and reviewer findings.

## Surviving design options

### Path 2: race-safe AFD overlay (#1211) — CLOSED 2026-05-07

**Status**: PLAN-KILL. Issue #1211 closed 2026-05-07 after 8 Codex
rounds + 3 Gemini rounds. v10 round added the empirical merge bar
from PR #1220, and both reviewers converged on stop-the-prototype:
Gemini explicit PLAN-KILL ("v10 successfully uses empirical data to
prove its own irrelevance"), Codex tighten-the-gate-and-pause-until-
failing-workload-exists. PR #1220's PASS verdict on the motivating
workload made the AFD design solving a non-existent problem.

**Archive**: see `docs/per-5-tuple/path2-archive/` for the v10 plan
(with full v2-v9 review history inline) plus a CLOSING-RATIONALE.md
covering when to revisit and how NOT to revisit. **Do not re-open
#1211 with new arguments** — start a fresh issue if any of the
revisit criteria fire.

### Path 4: workload-aware gate

**Status**: not yet captured in an issue. Concept is to gate the
harness's verdict on the workload class rather than blindly applying
the CoV+0.05 contract — e.g. for trivially-skewed RSS (one worker has
all flows), the contract correctly returns PASS because Cstruct is
already large; for balanced RSS the contract correctly demands tight
CoV. The harness already does this implicitly via `Cstruct`. What's
missing is an *operational* gate: the firewall config should be
allowed to declare "I expect balanced RSS and want to be paged on
structural skew" — a declarative fairness expectation that gets
checked at runtime, not just in test.

If pursued, this is a smaller-than-Path-2 swing and pure userspace.

## Open work

- **#547 — Deterministic RSS-skew test fixture**: the harness today
  reads whatever RSS happens to produce on the cluster. A fixture
  that black-box-tests `fairness-eval`'s CLI/IO/exit-code contract
  against synthetic inputs closes one regression-coverage gap. After
  Codex round-1 narrowed the scope (no fairness-mechanism validation
  claim — that's at cluster harness level), v2+ plan is in flight.
- **#1211 follow-up (only if gate flips to FAIL)**: open a fresh issue
  using the revisit criteria in the Path 2 closure archive. Do not
  re-open #1211 directly.
- **Path 4** has no issue yet; consider filing one if the workload-
  aware gate concept matures.

## How to apply

When considering a new fairness mechanism:

1. Read `docs/fairness-regimes.md` (the contract).
2. Run the harness on the loss userspace cluster against the current
   master to capture the baseline `(observed_CoV, Cstruct, gap)` for
   the targeted workload (e.g. iperf-c P=12 -R, ge-0-0-2).
3. Plan the mechanism with the gate baked in: "must reduce
   observed_CoV by at least Δ on workload X without regressing
   workload Y".
4. Triple-review the plan (Codex hostile + Gemini adversarial + this
   doc as architectural prior).
5. Bench against the harness, not against ad-hoc one-off
   measurements. The harness's verdict is the merge bar.

## Change log

- 2026-05-07: doc created; PR #1220 merged (harness shipped). Path 2
  v9 plan in flight; #547 deterministic fixture pending.
- 2026-05-07 (later): #1211 Path 2 CLOSED as PLAN-KILL after v10
  reviewer convergence. Archived under `path2-archive/`. #547 v2 in
  flight after Codex MAJOR rewrite.
