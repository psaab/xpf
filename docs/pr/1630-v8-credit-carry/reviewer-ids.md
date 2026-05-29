# #1630 v8 credit-carry — reviewer task IDs

Phase: §3.6 MEASUREMENT-GATE (pre-implementation). The gate falsified
both forks (see `claude-smr-measurement-r1.md`); no production code was
written, so no PR and no 4-way code-review round was opened. The fork
decision was posted to the issue and escalated to the parent.

| Seat | Task ID | Verdict | Notes |
|------|---------|---------|-------|
| Claude SMR | (in-conversation) | PLAN-BLOCKED | measurement falsifies both forks; escalate |
| Codex | n/a | n/a | not dispatched — no code to review (measurement STOP) |
| AGY | n/a | n/a | not dispatched — no code to review (measurement STOP) |
| Copilot | n/a | n/a | not dispatched — no PR |

Issue comment with the full measurement table:
https://github.com/psaab/xpf/issues/1630#issuecomment-4569679308

Evidence:
- `evidence/gate1-matrix.tsv`
- `evidence/solo-singleport.tsv`
