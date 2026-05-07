# #1211 Path 2 race-safe AFD overlay — CLOSED 2026-05-07

**Status**: CLOSED with rationale. Not deleted; archived. The v10 plan
(below as `plan-v10.md`) is preserved verbatim so future engineers can
read the full design space exploration.

## Why closed

Two reviewer signals converged on stop-the-prototype:

- **Gemini round-1 verdict (task-movo8pif, 2026-05-07)**: PLAN-KILL.
  "v10 successfully uses empirical data to prove its own irrelevance.
  PR #1217 (fairness-regimes contract) is the correct steady-state
  product. Close #1211 and commit this plan doc as an archived design
  decision."

- **Codex round-1 verdict (task-movo84bs, 2026-05-07)**: PLAN-NEEDS-MAJOR
  in the *gate*, not the design. "v10 is directionally right: no AFD
  prototype should start until there is a real workload where master
  fails the fairness contract." Until that workload is identified,
  the prototype has nothing to prove.

The core architectural reason this kept dying through rounds v2–v9:

- AF_XDP zero-copy pins flow → queue at bind time. Per-flow re-routing
  for fairness is structurally unreachable on this architecture
  (convergent finding: Codex task-mounv6zx + task-mouozcic; Gemini
  task-mounvopl + task-mouozuvq).
- The remaining lever was AFD-style ECN/drop overlay, which Codex
  thought was buildable with batched ArcSwap + settle-time
  accounting + RFC 3168 ECN curve, but Gemini consistently flagged
  cache-line bouncing, QSBR ordering, and ECN deployment reality
  (TCP receivers must honor ECE) as deal-breakers.

PR #1220 then shipped the fairness harness (bf87cf71, 2026-05-07).
The harness's empirical PASS verdict on the workload that motivated
this entire research stream (iperf-c P=12 -R, ge-0-0-2: gap ≈
−0.08, PASS) is decisive: the 47% per-flow CoV is below the
structural ceiling for the RSS distribution the cluster produces,
which means **there is no scheduler bug to fix on this workload**.

## Archived artefacts

- `plan-v10.md` — the v10 plan with the full v2–v9 review history
  inline. Reflects 8 rounds of Codex hostile review and 3+ rounds
  of Gemini adversarial review. Kept for the design-space record;
  not for re-use as a starting point unless a failing workload is
  identified.

## When to revisit

The honest "what would change my mind" criteria:

1. **A failing workload appears.** The fairness harness verdict on
   master flips to FAIL on a real production workload (not a
   synthetic fixture). The failure must be AFD-actionable per
   Codex round-1 finding #1: long-lived TCP, shared_exact CoS,
   ECN/drop-responsive senders, no app/server bottleneck, no
   background-flow pollution.
2. **A different RSS regime.** A NIC change, kernel upgrade, or
   workload mix produces a structural distribution where Cstruct +
   ε is being exceeded today.
3. **A different mechanism.** Someone proposes per-flow cross-worker
   sharing that Codex + Gemini both think is feasible (different
   from AFD ECN-mark / drop). Both reviewers PLAN-KILLed every prior
   variant in this design space; v10 sequence shipped its harness as
   the gate any future proposal must clear.

If any of those happen, start a fresh issue and cite this archive
plus PR #1220 + #1217 as the prior art. **Do not** simply re-open
#1211 with new arguments — the v2–v9 history shows that re-opening
without a fundamentally new gate just re-litigates the same dead
ends.

## How NOT to revisit

The wrong way to revisit is what almost happened in v10: extend the
plan with another round of cache-line-aware design refinements,
hoping reviewer convergence will arrive. Two reviewers have now
explicitly said the design space is settled. Ignoring that costs
weeks per round and produces no shipped value.

## Cross-references

- PR #1217 (fairness-regimes contract) — e1ec6b90, 2026-05-07. The
  contract this archive's plan was trying to clear.
- PR #1220 (fairness harness) — bf87cf71, 2026-05-07. Empirical
  evidence that the contract is being met today.
- `docs/per-5-tuple/state.md` — living state document for the
  per-5-tuple drive. The Path 2 entry there is updated in the same
  PR as this archive to point readers here for the full rationale,
  and the "Killed mechanisms" table includes attribution for the
  prior #1215, #836, #840/#1203, #937 PLAN-KILLs.

(The author also maintains an offline memory store outside this
repo with notes for those prior PLAN-KILLs. Those notes are not
part of the repo and not required reading for this archive.)
