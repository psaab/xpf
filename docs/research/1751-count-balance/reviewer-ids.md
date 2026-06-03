# #1751 count-balance — reviewer task-id ledger

Per `feedback_codex_session_loss_continuation`: record every reviewer task-id so
a long-running session can fetch results by id after Codex `status` forgets.

## Round 1 (plan v1)

| Reviewer | Tool | Task / session id | Verdict |
|---|---|---|---|
| Codex | codex exec (isolated fg, CODEX_COMPANION_SESSION_ID=research-1751-r1-*) | research-1751-r1 (codex-cli 0.135.0) | **PLAN-NEEDS-MAJOR** (4 findings: #1203 not-kill but rephrase; count must be post-filter steerable + no staleness guard; convergence proof wrong (max-min counterexample [3,3,3,3,1,1,1,1]); add pre-code CoS-ON manual re-pin gate) |
| AGY | agy_adversarial_review | adversarial-review-mpxeval5-4q2iwn | **PLAN-READY** (verified #1735 shared_exact MQFQ on master; flagged unsteerable-count divergence + shared_exact vtime_floor sync risk as documented-not-blocking) |
| Claude-SMR | self (claude-smr-plan-r1.md) | n/a | **PLAN-NEEDS-MINOR** (converges with Codex: fix convergence proof to L1-to-target; post-filter steerable count; phrase #1735 precisely; endorse pre-code CoS-ON re-pin gate) |

## Notes
- `/research` mode: stop at PLAN-READY / PLAN-KILL. No PR, no production code.
- AGY is review-only; revert any code it writes to the worktree or main checkout.
- Push Codex/AGY to engage the #1203-49%-vs-R1-3.8% contradiction (§4) with
  quoted-line / measured counter-examples; no KILL without proof.
