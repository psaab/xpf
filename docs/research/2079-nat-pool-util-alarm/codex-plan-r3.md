# Codex hostile plan review r3 — #2079

Agent: a4d0c901a2724e30d. Duration ~105s, 1 tool use.

## Verdict: PLAN-REVISE (confirmed all 4 r2 folds; 2 NEW MAJOR + 1 MINOR)

### Confirmed (r2 folds all resolved)
1. CONFIRMED NEW-3 nil-guard placed before any cfg deref (§6.1 257-260).
2. CONFIRMED NEW-2 `eligible` set + prune reconciles against it (§6.1 269-291).
3. CONFIRMED NEW-1 raise `>=`, clear strict `<`, text+code agree (§6.1/§6.2).
4. CONFIRMED FOLD-5 uint64 operands cast before subtraction (§6.1 278-280).

### NEW findings (folded into r4)
5. **MAJOR — transient-sample clear:** `eligible` was marked only AFTER the
   capacity/sample guards, so one transient bad snapshot (`AddressCount==0` or
   invalid ports) drops the pool from `eligible` → prune clears an
   already-raised alarm. Conflates "no longer eligible" with "sample
   uncomputable this tick". r4: separate SEMANTIC eligibility (in-config AND
   non-deterministic, marked BEFORE the sample guards) from SAMPLE validity (a
   bad sample HOLDS, no raise/clear, does not prune).
6. **MAJOR — silent withdraw vs syslog contract:** r3 silently withdrew alarms
   on nil-config / disabled / prune, but Path B (§6.4) says transitions emit
   syslog → a consumer could see a raise with no matching clear. r4: all
   withdrawals emit a clear; only the HOLD (no-transition) case is silent.
7. **MINOR — stale text:** §9 risk table said "commit-warn" and §10 treated
   `clear=0` as open, contradicting the resolved hard-commit-error in §6.2. r4:
   §9/§10 updated to the hard-error resolution.

All three folded into r4. Findings 5 and 6 are legitimate second-order issues
the earlier passes missed; #5 is the exact transient-snapshot edge anticipated
in the r3 dispatch prompt.
