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
- Codex (agent id `abcb30eef8fd9703c`): NEEDS-REVISION — cookie-OFF/polarity/
  missing-profile RESOLVED; held sketch fail-closed BLOCKER (stay-tripped vs
  rate-enforced); NEW MAJORs: alarm gating precision in the OFF path, TokenBucket
  cold-start unspecified.
- AGY (agent id `a79a2c6b688398a34`): **PLAN-READY** — all round-2 findings
  RESOLVED/ADDRESSED; NEW MINORs: TokenBucket init-full on first call,
  `saturating_sub` on the clock delta.
- Claude SMR r3 (`claude-smr-plan-r3.md`): PLAN-READY on Option B (consumer-split).

## Round 4 (plan v4 — sketch DEFERRED, alarm gating pinned, cold-start-full)
- Codex (agent id `a84f671afa1aa04fa`): NEEDS-REVISION — all 3 round-3 findings
  RESOLVED, sketch-not-required CONFIRMED; NEW BLOCKER: §5a wiring double-quota
  (OFF bucket only on the over_attack excess + cold-start-full ⇒ instant ~2·T).
- AGY (agent id `aacc6d578ffff0108`): **PLAN-READY** — both round-3 MINORs
  RESOLVED, sketch deferral acceptable; NEW MINORs: cap `elapsed` at 1 s (refill
  overflow), explicit `!over_attack` alarm gate.
- Claude SMR r4 (`claude-smr-plan-r4.md`): PLAN-READY on Option B (reduced scope).

## Round 5 (plan v5 — cookie-OFF token bucket is the SOLE drop authority)
- Codex (agent id `aabe380933d225afb`): NEEDS-REVISION — round-4 wiring BLOCKER
  RESOLVED; NEW MAJOR: `tokens_q + refill_q` unchecked add before `.min` (use
  `saturating_add`).
- AGY (agent id `a1b88e33f6952fa74`): **PLAN-READY** — both round-4 MINORs
  RESOLVED, no new findings.
- Claude SMR r5 (`claude-smr-plan-r5.md`): PLAN-READY on Option B (reduced scope).

## Round 6 (plan v6 — saturating_add hardening on the token accumulation)
- Codex (agent id `a3c53ed222f496dc1`): **PLAN-READY** — round-5 MAJOR RESOLVED
  (`saturating_add` before `.min`); remaining findings: none.
- AGY: **PLAN-READY** carries forward from v5 (v6 = v5 + `saturating_add`, a strict
  overflow-hardening AGY itself prescribed the sibling `saturating_sub` for; no
  design change).
- Claude SMR r6 (`claude-smr-plan-r6.md`): **PLAN-READY on Option B (reduced
  scope; v6 hardening)**.

## CONVERGED at v6 (SHA 569edd3b9) — 3/3 PLAN-READY (Codex + AGY + Claude SMR)
