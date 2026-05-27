# #1296 — CoS surplus-sharing: structural pass still allows high raw per-flow CoV

**Status:** DRAFT v1 — pending adversarial plan review

## Issue framing

Issue body cites artifact `/tmp/cos-headroom-q2q3q6-post1295-20260513T080324Z`
(post-#1295 idle-telemetry fix), surplus-sharing enabled:

| Class | Verdict | Avg Mbps | Util  | Mean CoV | Max CoV |
|---|---:|---:|---:|---:|---:|
| q2-iperf-e-16g | PASS | 20555.851 | 1.285 | 0.490 | 0.667 |
| q3-iperf-f-19g | PASS | 21069.702 | 1.109 | 0.647 | 0.708 |
| q6-iperf-c-25g | PASS | 20354.922 | 0.814 | 0.393 | 0.484 |

Verbatim q3 sample showing the contract math: `observed_cov=0.6700`,
`cstruct=0.6753`, `gap=-0.0053`, `verdict=PASS`.

Issue reads as a request to either:

1. **Product-contract clarification (Option 1 in the issue body)**:
   document that surplus-sharing is throughput-mode, structural-fairness
   gate only, and that equal-flow is a separate opt-in mode.
2. **Equal-flow-preserving surplus mode (Option 2)**: only donate
   surplus when it doesn't raise peers above an epoch-published
   per-flow cap.
3. **Backpressure / AFD mode (Option 3)**: slow peers to match the
   bottleneck worker's per-flow rate.

## Empirical state — what the artifact actually shows

The artifact data in the issue body shows **PASS verdicts under the
#1217 product contract**. The contract is:

> `observed_CoV ≤ Cstruct + 0.05` where `Cstruct` is computed from the
> per-worker active-flow distribution `{aᵢ}`.

For q3 sample, `distribution_a_i=[0,1,2,3,1,5]`, `cstruct=0.6753`,
`observed_cov=0.6700`, `gap=-0.0053`. **observed < ceiling**. This is
not a bug in the scheduler; it is the **structural ceiling for the
RSS placement the hardware produced**, and the scheduler is delivering
strictly below it.

Cross-reference [[project_1211_killed]]: PR #1220's fairness harness
empirically demonstrated that 47% per-flow CoV on the iperf-c P=12 -R
workload was below structural ceiling. After 8 Codex + 3 Gemini rounds
across v2-v10 of an AFD-Lite design, the converged verdict was
**PLAN-KILL: "v10 successfully uses empirical data to prove its own
irrelevance. PR #1217 is the correct steady-state product."**

Cross-reference [[project_per5tuple_fairness_killed]]: seven (#1215,
#836, #838, #840, #1203, #937, #1211) independent re-routing /
cross-worker / AFD mechanisms have all been PLAN-KILLED. AF_XDP ZC
queue-binding is permanent physics: `xsk_rcv_check` enforces
`xs->dev == xdp->rxq->dev AND xs->queue_id == xdp->rxq->queue_index`.

Cross-reference [[feedback_cross_binding_impossible]]: cross-binding
traffic-steering is structurally impossible on this dataplane.

## Hostile premise check (Standing rule from per-5-tuple memory)

> Plan must clearly state which: is per-flow CoV equalization within a
> CoS class even achievable given AF_XDP UMEM-owner-binding?

**Within a single binding's worker**: yes, the existing
`equal-flow-enforcement` scheduler knob already does this (see
`pkg/config/compiler_class_of_service.go:252` + `V8RateMode::
EqualFlowSuppress` in `userspace-dp/src/afxdp/types/shared_cos_lease/
mod.rs`). The issue body's q2/q3/q6 PASS observations on the surplus
mode validate that switching to `equal-flow-enforcement` would lower
per-flow CoV — at the cost of aggregate throughput, exactly as the
issue body's strict-exact comparison shows (q2 13.5 Gb/s w/ CoV 0.039
vs 20.5 Gb/s w/ CoV 0.490).

**Across bindings**: no. All seven cross-worker/cross-binding
mechanisms are PLAN-KILLED. Cstruct is the floor.

## Existing implementation (already shipped — discovered during plan)

Option 2 from the issue body **is already implemented and opt-in**:

- Junos knob: `set class-of-service schedulers <name>
  equal-flow-enforcement` (companion to `surplus-sharing` per #915).
  Source: `pkg/cmdtree/tree.go:1056-1059`, parser in
  `pkg/config/parser_class_of_service_test.go:98+`, compiler in
  `pkg/config/compiler_class_of_service.go:252` setting
  `sched.EqualFlowEnforcement = true`.
- Dataplane: `V8RateMode::EqualFlowSuppress` lease mode, with
  `equal_flow_cap_v8` enforcing per-flow cap on `acquire_v8`'s primary
  share path. Stale-tag fail-open is explicit; cap reads are
  hot-path-clean (no cross-worker atomics on every packet).
  `mod.rs:1458` for the cap function, `:1186` for `surplus_open =
  bypass && !equal_flow_enforced` interlock.
- Metric: `xpf_userspace_cos_equal_flow_suppressed_grant_bytes_total`
  + `xpf_fairness_equal_flow_suppressed_bps`. Source:
  `pkg/api/metrics_descriptors.go:310`, `:574`.
- Telemetry: `v8_equal_flow_*` accessors on the lease
  (`mod.rs:1332-1370`).

This means the issue's stated work item #2 has nothing to ship.

## What's actually missing (the work surface that DOESN'T overlap with #1211 or #1217)

The acceptance criteria list three deliverables:

1. **"Add a gate/metric that distinguishes raw equal-flow CoV from
   Cstruct-adjusted structural pass."** — partially exists. The
   fairness-eval harness already emits both `observed_cov` and
   `cstruct` per the artifact JSON sample. What's NOT shipped is
   making this surface visible at the **default reporting/dashboard
   level** so operators can't read "PASS" and assume equal-flow
   bandwidth. The honest fix is a **labels/tagging change in the
   harness and the Prometheus exposition** — three lines in metric
   descriptions plus a harness output column.

2. **"For equal-flow mode, q2/q3/q6 12-flow tests should meet a raw
   CoV target such as <= 0.20 while saturated, or explicitly fail with
   a product-contract reason."** — requires re-running the
   12-flow tests with `equal-flow-enforcement` enabled on each
   scheduler and confirming raw CoV target met. **This is a harness
   change + a measurement campaign, not a dataplane fix.** Will the
   harness even hit ≤ 0.20 raw under equal-flow mode? The issue body's
   strict-exact reference is q2 0.039 / q3 0.088 / q6 0.136, so
   ≤ 0.20 is plausibly already satisfied with the existing
   `equal-flow-enforcement` knob. **The work is verification, not
   implementation.**

3. **"For throughput mode, docs and harness output must label the
   result as structural/work-conserving, not equal-flow bandwidth."**
   — pure doc + harness-output label change. This is the **honest
   contract clarification**.

4. **"No hot-path shared global atomic on every packet; any global
   per-flow cap must be epoch-published/sharded."** — already
   satisfied by the existing `equal_flow_cap_v8` design (cap
   epoch-tagged with stale-tag fail-open, no cross-worker RMW in
   `acquire_v8`).

## Honest scope/value framing

The dataplane work for #1296 is **zero**. The compiler/parser work is
zero. The Prometheus collector work is roughly two new metric
descriptions (label/help text) — call it 30 lines including tests.
The harness work is a single output-column rename + verdict-label
rewrite to make "structural PASS" distinguishable from "equal-flow
PASS" in operator-facing output — call it 200-400 lines including
fairness-eval CLI surface.

If reviewers conclude this is **all documentation and labeling and
not worth a triple-review cycle**, PLAN-KILL is an acceptable verdict.
A doc-only PR that lands `docs/fairness-regimes.md` clarification
(surplus vs equal-flow product modes) and a one-paragraph
status-command note may be the right level of effort.

## Open questions for adversarial review (PLAN-KILL invited)

1. **Does the empirical artifact in the issue body already disprove
   the bug premise?** observed_cov ≤ cstruct + 0.05 = PASS by #1217
   contract. The "raw CoV is high" framing inverts the contract — the
   contract explicitly DOES NOT gate on raw CoV. If reviewers conclude
   this is a contract-misreading rather than a scheduler defect, the
   right outcome is PLAN-KILL with a comment on the issue pointing at
   `docs/fairness-regimes.md` and the existing `equal-flow-enforcement`
   knob.

2. **Is anything in Acceptance Criteria 1-4 not already shipped?**
   Specifically, walk the issue body acceptance criteria against:
   - `equal-flow-enforcement` Junos knob (shipped in #915 companion)
   - `V8RateMode::EqualFlowSuppress` dataplane mode (shipped)
   - `xpf_fairness_equal_flow_suppressed_bps` Prometheus metric
     (shipped)
   - `docs/fairness-regimes.md` regime contract (shipped via #1217)
   - fairness-eval harness Cstruct compute + JSON output (shipped via
     #1220)

   If all four are shipped, this issue is a CLOSE-PENDING-VERIFICATION
   issue: re-run the q2/q3/q6 campaign with `equal-flow-enforcement`
   set on the relevant schedulers, confirm raw CoV ≤ 0.20, close.
   That's not a triple-review-worthy refactor.

3. **#1211 review history & revisit criteria.** Per
   `docs/per-5-tuple/path2-archive/CLOSING-RATIONALE.md` revisit
   criterion 1: "A failing workload appears. The fairness harness
   verdict on master flips to FAIL." The artifact in the issue body
   shows PASS, not FAIL. **Does this issue meet the documented
   revisit criteria?** If not, the work needs to be redirected toward
   contract clarification, not new mechanism.

4. **Is there a hidden non-#1211 mechanism left to try?** The seven
   PLAN-KILLs cover every cross-worker / cross-binding / RSS-rerouting
   approach. If a reviewer can name a mechanism not in
   `project_per5tuple_fairness_killed.md`, propose it. Otherwise, the
   plan should explicitly state that no new dataplane mechanism is in
   scope.

5. **Cost-benefit of "Option 1" (product clarification) vs full work
   item.** If the answer is "Option 1 only", do we need a PR at all?
   A targeted issue comment + a `docs/fairness-regimes.md` paragraph
   addition is one commit, no plan-review needed. Triple-review skill
   may not be the right tool here.

## Concrete design (conditional on PLAN-READY)

If reviewers ratify that there IS scope-worthy work beyond a doc
comment, the proposed scope is exactly:

1. Add a paragraph to `docs/fairness-regimes.md` explicitly naming the
   two product modes (surplus-sharing vs equal-flow-enforcement) and
   their fairness contracts. Reference the `set class-of-service
   schedulers <name>` knob names.

2. Add a `mode` column or `mode` JSON field to the fairness-eval
   harness output that reads the `surplus_sharing` /
   `equal_flow_enforcement` flag off each scheduler in the active
   config, so PASS verdicts are labeled with which contract was being
   enforced.

3. Re-run q2/q3/q6 with `equal-flow-enforcement` enabled, capture
   artifact, document raw CoV ≤ 0.20 (or fail with reason).

4. Add a single-line `cli` show-cos-status line distinguishing
   "throughput mode" vs "equal-flow mode" schedulers.

Nothing in this set touches the hot path. Nothing touches
`acquire_v8`. Nothing touches the lease state machine.

## Risk assessment

| Class | Risk |
|---|---|
| Behavioral regression | LOW — doc + harness label + status string only |
| Lifetime / borrow-checker | LOW — no Rust dataplane changes |
| Performance regression | NONE — no hot-path edit |
| Architectural mismatch (#946 Phase 2 / #1211 dead-end pattern) | **HIGH** — this issue may be entirely a misread of the #1217 contract. PLAN-KILL is the high-probability outcome. |

## Test plan (conditional)

- Re-run cos-headroom-q2q3q6 with `equal-flow-enforcement` set on
  schedulers `iperf-e`/`iperf-f`/`iperf-c`. Confirm:
  - PASS verdict under both contracts (structural AND raw)
  - raw CoV ≤ 0.20 on saturated regime per acceptance criterion #2
  - throughput drop matches strict-exact baseline (q2 ~13.5 Gb/s,
    q3 ~14.8 Gb/s, q6 ~17.6 Gb/s) within noise
- `cargo build --release` + `cargo test --release` clean
- Go suite: `go test ./pkg/api/... ./pkg/config/...` clean

## Out of scope (explicitly)

- Any new dataplane mechanism. The seven PLAN-KILLs stand.
- Any change to `acquire_v8`, `equal_flow_cap_v8`, or
  `rotate_epoch_v8`. The existing implementation is correct per
  Codex's #1211 review history.
- Reopening or relitigating the #1217 contract. Cstruct + 0.05 is
  the steady-state gate; this issue does not propose changing it.
- Any AFD-style cross-worker AQM. See #1211 archive +
  CLOSING-RATIONALE.md "how NOT to revisit".

## Expected outcome

**Most likely (per the eight prior PLAN-KILLs on this fairness
stream): PLAN-KILL**, with a comment on #1296 explaining:

- The artifact's PASS verdict is the contract's expected outcome.
- `equal-flow-enforcement` already exists as the opt-in equal-flow
  contract.
- The cross-worker mechanism the issue would need to "fix" raw CoV
  while keeping high throughput is structurally unreachable per
  `project_per5tuple_fairness_killed.md`.

**Second most likely: PLAN-NEEDS-MAJOR**, scoped down to a doc-only
+ harness-label PR. If accepted, the implementation is mechanical
and ships in 1-2 days with one round of code review (no triple-review
needed).
