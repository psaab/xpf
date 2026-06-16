# #1917 increment B — reviewer task IDs

Plan: `docs/research/1917b-inplace-upgrade-mechanism/plan.md`

## Codex (companion — ONE job global)
- round 2: session resumed (codex_1917b_r2) — verdict pending
- round 1: session 019ed0e5-4b18-7361-9f66-c97bdd864aaf — PLAN-NEEDS-REVISION (6 findings)

## AGY (adversarial-review)
- round 1: adversarial-review-mqgr7nc7-eo9bge — PLAN-NEEDS-REVISION (4 findings)

## Claude SMR
- round 1: docs/research/1917b-inplace-upgrade-mechanism/claude-smr-r1.md — PLAN-NEEDS-REVISION

## Round 2
- AGY: adversarial-review-mqgrjndm-y3bv6k
- Claude SMR: docs/research/1917b-inplace-upgrade-mechanism/claude-smr-r2.md — PLAN-READY

## Round 2 verdicts
- Codex: session 019ed0e5 (resumed) — PLAN-NEEDS-REVISION (3 refinements: postinst stage-only on node-id alone; ExecStart-template journaled substep; PREFLIGHT account DB snapshot). 5/6 r1 findings confirmed resolved.
- AGY: adversarial-review-mqgrjndm-y3bv6k succeeded but result flaked (no capture); re-dispatched round 2b below.
- Claude SMR: claude-smr-r2.md — PLAN-READY (folded the argv[0]/ExecStart hard-step it surfaced).

## Round 3
- Codex: session 019ed0e5 (resumed) round 3 — PLAN-NEEDS-REVISION → only a stale §7 doc contradiction (ExecStart said 'current' symlink); fixed in v4. Codex: "Fixing the stale §7 current path should make this PLAN-READY."
- AGY: adversarial-review-mqgrqf8j-y14zjg (round 2b on v3)
