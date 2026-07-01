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
- Codex (agent id `a1447d8a19e9d7064`): NEEDS-REVISION — all 4 round-1 findings
  RESOLVED; NEW: BLOCKER sketch token-bucket cells vs #3315 fail-closed
  (stay-tripped); MAJOR cookie-off aggregate still drops legit sustained SYNs;
  MAJOR `admit()` polarity must be pinned; MAJOR missing-profile warn dampener
  must NOT migrate (wants suppress-until-idle).
- AGY (agent id `a80a8fc2b5e0ccf9c`): NEEDS-REVISION — all 3 round-1 findings
  RESOLVED; NEW: BLOCKER cookie-off aggregate drops legit sustained SYNs (safely
  fixable); MAJOR cookie-on permanent cookie-lock at threshold; MINOR standby-ACK
  validator signature churn.
- Claude SMR r2 (`claude-smr-plan-r2.md`): PLAN-READY on Option B (consumer-split).

## Round 3 (plan v3 — cookie-OFF aggregate bucket + sketch fail-closed re-derivation)
- Codex: <pending>
- AGY: <pending>
- Claude SMR r3 (`claude-smr-plan-r3.md`): **PLAN-READY on Option B
  (consumer-split, v3)**, PLAN-DEFER-operator / DEFER-the-sketch as fallbacks.
