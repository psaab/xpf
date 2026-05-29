# Reviewer task-id ledger — #1649 initial-placement research

Per `feedback_codex_session_loss_continuation` — record every task-id so
continuations can re-fetch by id rather than re-dispatch.

## Round 1

- Codex: (pending)
- AGY: (pending)
- Claude SMR: docs/research/1649-initial-placement/claude-smr-plan-r1.md

## Round 1 (recorded)

- Codex: codex exec read-only (no persistent task-id; verdict PLAN-NEEDS-WORK, masked src-port-residue counter-example) — saved codex-plan-r1.md
- AGY: adversarial-review-mpqehy8u-aywovr (PLAN-READY) — saved agy-plan-r1.md
- Claude SMR: claude-smr-plan-r1.md (PLAN-NEEDS-WORK → resolved in r2)

## Round 2 (CONVERGED — all three PLAN-READY on the KILL)

- Codex: codex exec read-only confirmation — VERDICT: PLAN-READY (kill correct) — saved codex-plan-r2.md
- AGY: adversarial-review-mpqeu1la-c6tr50 — PLAN-READY (kill correct, rationale sound) — saved agy-plan-r2.md
- Claude SMR: claude-smr-plan-r2.md — PLAN-READY (kill correct)

Convergence SHA recorded at commit of r2-final.
