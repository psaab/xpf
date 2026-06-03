# #1751 count-balance — reviewer task-id ledger

Per `feedback_codex_session_loss_continuation`: record every reviewer task-id so
a long-running session can fetch results by id after Codex `status` forgets.

## Round 1 (plan v1)

| Reviewer | Tool | Task / session id | Verdict |
|---|---|---|---|
| Codex | codex (isolated fg, unique CODEX_COMPANION_SESSION_ID) | _pending_ | _pending_ |
| AGY | agy_adversarial_review | _pending_ | _pending_ |
| Claude-SMR | self (docs/research/1751-count-balance/claude-smr-plan-r1.md) | n/a | _pending_ |

## Notes
- `/research` mode: stop at PLAN-READY / PLAN-KILL. No PR, no production code.
- AGY is review-only; revert any code it writes to the worktree or main checkout.
- Push Codex/AGY to engage the #1203-49%-vs-R1-3.8% contradiction (§4) with
  quoted-line / measured counter-examples; no KILL without proof.
