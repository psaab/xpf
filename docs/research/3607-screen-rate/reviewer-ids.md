# Reviewer ID ledger — #3607 research plan

Three plan reviewers (Codex + AGY + Claude SMR). Copilot is NOT a research
reviewer; it joins at `/engineer` on the code PR.

## Round 1 (plan v1)
- Codex (agent id `a2c4dcc2b3099e1c4`): **NEEDS-REVISION** — BLOCKER Option A
  low-threshold hole; BLOCKER SYN-aggregate count-before-classify invariant
  change; recommends Option B (token bucket) with aggregate invariant note or
  defer.
- AGY (agent id `ae198321601d8a3dd`): **NEEDS-REVISION** — BLOCKER not-counting-
  rejected opens T/sec cookie bypass on the SYN aggregate; MAJOR token-bucket dual
  threshold 32 B; MINOR Option A low-threshold roughness.
- Claude SMR r1 (`claude-smr-plan-r1.md`): NEEDS-REVISION — formula fix, Option A
  limitation overstated at high T, both-defects-necessary, L14 moot; **MINOR-5
  later retracted** (was wrong about SYN-aggregate safety).

## Round 2 (plan v2 — consumer-split token bucket)
- Codex: <pending>
- AGY: <pending>
- Claude SMR r2 (`claude-smr-plan-r2.md`): **PLAN-READY on Option B
  (consumer-split)**, PLAN-DEFER-operator as honest fallback.
