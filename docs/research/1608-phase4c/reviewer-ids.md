# #1608 v3 research — reviewer task ID ledger

Branch: `research/1608-phase4c` (off origin/master @ 6bdf9d73e)
Plan: `docs/research/1608-phase4c/plan.md`

## Convergence: PLAN-KILL-CONFIRMED (3-of-3)

- **Claude SMR**: PLAN-KILL-CONFIRMED — `claude-smr-plan-r1.md`
- **AGY**: PLAN-KILL-CONFIRMED — `agy-plan-r1.md`
  (job `adversarial-review-mprtnd0w-pqgs6r`)
- **Codex**: PLAN-KILL-CONFIRMED at r4 — `codex-plan-r1.md` + raw
  `codex-raw-r{1,2,3}.txt`

## Round trail

- r1: SMR PLAN-KILL, AGY PLAN-KILL, Codex PLAN-NEEDS-MAJOR
  (one MAJOR: stale #1615/870-Kpps premise; 7 confirmations).
- r2: folded #1615-resolved correction + 2 AGY structural hazards.
  Codex r2 PLAN-NEEDS-MAJOR (residual stale clause at plan.md:180).
- r3: removed line-180 clause. Codex r3 PLAN-NEEDS-MAJOR (two more
  stale clauses at Section 5 line 173 + Section 10).
- r4: purged Section 5 + Section 10 stale premises.
  **Codex r4: PLAN-KILL-CONFIRMED.** All three converge.

## Codex invocation note

Local `codex exec --sandbox read-only` (codex-cli 0.133.0); no MCP/task
IDs. Raw transcripts archived as `codex-raw-r{1,2,3}.txt` in this dir.
