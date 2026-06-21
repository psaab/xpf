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

## Round 2 (against plan r2) — pending
- Claude reviewer A r2 — TBD
- Claude reviewer B r2 — TBD
- Claude SMR r2 — TBD
