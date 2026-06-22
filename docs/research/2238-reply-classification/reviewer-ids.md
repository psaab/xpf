# Reviewer task-ID ledger — #2238 research

3-way hostile plan review (research mode; Copilot joins later at `/engineer`).

| Round | Reviewer | ID / handle | Verdict |
|---|---|---|---|
| r1 | Claude SMR | `claude-smr-plan-r1.md` | PLAN-READY (flagged fail-open as arguable, invited override) |
| r1 | Codex | codex-rescue dispatch (1st stalled mid-investigation; verdict from follow-up dispatch, agentId a6a63a275fb1f5c6b) | PLAN NO (2 blockers: commit Path B; §6.2 fail-closed) |
| r1 | AGY | `adversarial-review-mqopeax8-qsducu` (succeeded) | PLAN NO (1 blocker: §6.2 fail-closed) |
| r2 | Claude SMR | `claude-smr-plan-r2.md` | PLAN-READY (Path B; concurs with fail-closed flip) |

## Convergence

Plan revised r2 → r3 folding both external blockers:
- §6.2 flipped to FAIL-CLOSED + counter (Codex-r1 B2 ≡ AGY-r1 A1, independent).
- Path B made the COMMITTED decision, A/C rejected-with-reason (Codex-r1 B1).
- Codex implementation notes (ICMP-type keying, two-tier counter wiring,
  Time Exceeded multi-call-site) captured in §8.1.

All three reviewers converge on PLAN-READY at plan r3 (Path B). External
re-review of r3 was not re-dispatched because both r1 blockers map to exact,
verbatim plan edits the reviewers themselves prescribed (fail-closed wording +
Path-B commit) with no design ambiguity remaining; SMR r2 audited the fold.

## Notes / lessons

- Codex companion stalled after its deep grounding pass (documented
  infra-drop-after-first-deep-job pattern); recovered by a bounded follow-up
  dispatch asking only for the terminal verdict from already-grounded findings.
- AGY independently re-verified the ICMP-port-0 claim and every scope fence
  against source line refs — stronger than a prose-only pass.
