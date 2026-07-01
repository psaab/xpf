# Claude SMR — hostile plan review r5 (#3607)

Reviewing `plan.md` v5. AGY was PLAN-READY on v4; Codex found one real BLOCKER
(the v4 §5a wiring double-quota). v5 fixes it and folds AGY's two MINORs.

## Verdict: PLAN-READY on Option B (reduced scope, single-gate cookie-OFF wiring)

## Round-4 findings → v5 resolution
- **cookie-OFF double-quota** (Codex BLOCKER): v5 §5a makes the token bucket the
  SOLE drop authority when `syn-cookie` is OFF — consulted on EVERY initial SYN,
  decoupled from the measured `over_attack`. There is now ONE budget, so the "T
  pass the aggregate + T from a full bucket" double path is gone; the cold-start
  burst is bounded to capacity = `T` and a sub-ms micro-burst finds ≤ `T` tokens
  (#2937 preserved). ✓
- **refill overflow** (AGY MINOR): `elapsed` capped at 1 s before
  `elapsed * threshold` (§5). ✓
- **explicit `!over_attack` alarm gate** (AGY MINOR): §5a. ✓

## Residual hostile checks on v5 (no blocker)
- **Does making the bucket the sole gate drop legit sub-threshold SYNs?** No —
  a sub-threshold sender consumes < refill, bucket stays near full, all admitted.
- **Does `increment_and_classify` still running (count-all) alongside the bucket
  double-count?** They are independent: the count-all measures arrival rate for
  the alarm/cookie-ON; the bucket is the shaper for the drop. No interference; two
  cheap integer updates per SYN when cookie is OFF.
- **Alarm during a burst the bucket admits?** The alarm is explicitly gated on the
  MEASURED `!over_attack`, so an over-attack SYN the bucket admits does NOT raise
  the alarm — same as today (today it would Drop; either way no alarm). ✓
- **Convergence check:** the architecture has been stable since v2; v5 is a
  wiring correction + two overflow/underflow guards. Surface has shrunk each
  round. This is convergence.

## Bottom line
v5 resolves Codex's BLOCKER with the fix Codex's own analysis prescribed, and
folds AGY's MINORs. AGY + Claude SMR are PLAN-READY; a Codex round-5 confirmation
of the single-gate wiring is the last step. PLAN-READY on Option B (ICMP/UDP flood
+ standby-ACK + cookie-OFF SYN aggregate; sketch deferred); issue stays open,
label `plan-deferred-research`, awaiting manual `/engineer`. PLAN-DEFER-operator
remains an explicit fallback.
