# #1608 v3 research — reviewer task ID ledger

Branch: `research/1608-phase4c` (off origin/master @ 6bdf9d73e)
Plan: `docs/research/1608-phase4c/plan.md`

## Round 1

- Claude SMR r1: `claude-smr-plan-r1.md` — **PLAN-KILL-CONFIRMED** (Path A)
- AGY r1: `adversarial-review-mprtnd0w-pqgs6r` → `agy-plan-r1.md` — **PLAN-KILL-CONFIRMED**
- Codex r1: local `codex exec` (read-only) → `codex-plan-r1.md` — **PLAN-NEEDS-MAJOR**
  (one MAJOR: stale #1615/870 Kpps premise; conclusion endorsed). Raw out:
  `/tmp/codex-1608-r1-out.txt` (1.3 MB).

## Round 2

- Plan v3 r2: #1615-resolved correction folded into Section 3 + Path D +
  Recommendation; AGY's two structural hazards (verdict-cache 0%-hit
  L1/L2 pollution; rate-limit bottleneck-shift) folded into Path B/C.
- Codex r2: re-confirm finding #1 closed → (pending)
- AGY r1 already PLAN-KILL-CONFIRMED (no new code; verdict stands).
- Claude SMR r2: verdict unchanged PLAN-KILL-CONFIRMED (premise corrected).
