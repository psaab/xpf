# #1880 plan review — Claude SMR, rounds 4-5 (final)

Verdict on r4: PLAN-NEEDS-REVISION (concur Codex r4: the retry writer
invalidated my own r1 "does not widen the concurrency surface"
endorsement — the claim had to move from applySem to reloadMu — and the
gate-1 list omission was mine).
Verdict on r5: **PLAN-READY**.

Final hostile checks on r5:
- The pre-cancel-before-acquire ordering is the right shape: cancel is
  cheap and idempotent; the in-flight retry's pgroup dies within one
  WaitDelay, so the ≤45s commit bound composes (40s own + 5s teardown).
- The confGen clear-condition + the woken-retry cancellation check both
  execute under reloadMu — no TOCTOU between gauge state and exec.
- §7 gate 4 remains the decisive end-to-end gate: two consecutive
  FIRST-run-after-deploy failover passes, which is the literal smoke
  failure precondition from #1871/#1877.
- Residual accepted risks are explicit (§8) and the kill criteria in §5
  were answered with evidence, not assertion.

Convergence: Codex r5 task-mqacm8ay-gj863y PLAN-READY (findings none);
AGY r5 adversarial-review-mqacpdjl-lb9e7w PLAN-READY; Claude SMR r5
PLAN-READY.
