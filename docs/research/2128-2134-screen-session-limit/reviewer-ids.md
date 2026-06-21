# Reviewer ledger — #2128 + #2134 research

Companions (Codex / AGY) are infra-degraded for this campaign, so the
3-way convergence uses TWO independent hostile Claude plan reviewers
(spawned via the Agent tool) + the Claude SMR (in-conversation). All
three are HOSTILE (default-refute), not synthesizers.

## Round 1 (against plan r1)
- Claude reviewer A (general-purpose agent, correctness/security focus)
  — agentId `a55e0edde6812c597` — VERDICT: NEEDS-REVISION
  (BLOCKER: per-packet self-drop; MAJOR: single-choke-point false,
  stale line refs, is_reverse-refresh audit)
- Claude reviewer B (general-purpose agent, hot-path + HA focus)
  — agentId `a5dfa7ab617bfa306` — VERDICT: NEEDS-REVISION
  (MAJOR: OFF-gate cost, demote decrement, promote increment)
- Claude SMR (in-conversation) — VERDICT: NEEDS-REVISION
  (+ SMR-1 check must precede both counted forward installs;
  + SMR-2 all-protocol coverage)

## Round 2 (against plan r2)
- Claude reviewer A r2 — agentId `ad1d7cf57c30c1826` —
  VERDICT: PLAN-READY-WITH-NITS (all 4 r1 findings fixed; 4 doc NITs)
- Claude reviewer B r2 — agentId `a5cca8597926b4dfe` —
  VERDICT: NEEDS-REVISION (all 4 r1 fixed; 1 new MAJOR =
  clear-on-disable; 1 MINOR audit; 2 impl NITs)
- Claude SMR r2 — in-conversation — VERDICT: NEEDS-REVISION on r2
  (concur MAJOR), PLAN-READY on r3 (clear-on-disable folded)

r3 folds the clear-on-disable MAJOR + the audit MINOR + all NITs.

## Round 3 (against plan r3) — convergence confirmation
- Claude reviewer B r3 — agentId `a617576aea48cbb2f` —
  VERDICT: PLAN-READY (both r2 findings resolved; no new defect)
- Claude reviewer A — already PLAN-READY-WITH-NITS at r2; all its
  findings (r1 + the 4 NITs) are folded in r3, so it carries to
  PLAN-READY at r3.
- Claude SMR — PLAN-READY on r3 (claude-smr-plan-r2.md).

## CONVERGENCE: 3-way PLAN-READY on r3
- Claude reviewer A: PLAN-READY (PLAN-READY-WITH-NITS @ r2 → nits folded)
- Claude reviewer B: PLAN-READY (@ r3)
- Claude SMR:        PLAN-READY (@ r3)
Companions (Codex/AGY) infra-degraded — substituted with 2 independent
hostile Claude reviewers + SMR per the campaign note.
