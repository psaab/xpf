# Codex hostile plan review r4 — #2079

Agent: a9f456c3813ea0c67. ~170s, 1 tool use.

## Verdict: PLAN-REVISE (confirmed all 3 r3 folds; 1 NEW MAJOR + 1 MINOR + 1 NIT)

### Confirmed (r3 folds all resolved)
1. FOLD-#5 CONFIRMED — semantic eligibility marked before sample guards.
2. FOLD-#6 CONFIRMED — prune calls clear(), nil/disabled early-return clears
   every entry, §6.4 states raise/clear symmetry.
3. FOLD-#7 CONFIRMED — §9/§10 hard commit error, stale warn/open removed.
6. NIT-check (no defect) — no double-emit: a pool cleared in the per-pool loop is
   removed from `activeAlarms` before the prune ranges it.

### NEW findings (folded into r5)
4. **MAJOR — absent-snapshot clear:** `eligible` was still derived only from
   pools PRESENT in `status.SourceNATPools`. A configured non-deterministic pool
   with an active alarm but NO snapshot entry this tick is pruned + cleared,
   contradicting "only config-removal/rename/det-conversion makes it ineligible".
   r4 fixed bad-field samples (#5) but not ABSENT samples. r5: make eligibility
   CONFIG-derived (iterate cfg pools); absent snapshot → HOLD (case b),
   config-removed/det → CLEAR (case a), bad sample → HOLD (case c).
5. **MINOR — clear-all lock discipline:** snapshot active keys under the alarm
   mutex, invoke the normal clear path per key WITHOUT holding the mutex across
   syslog emission, else risk self-deadlock / holding the render mutex during I/O.
   r5: §6.1 concurrency note added.
7. **NIT — stale deterministic wording:** §9 said "r1 uses raw UsedPorts" for
   deterministic+persistent; should say deterministic SKIPPED in r1, persistent
   uses raw UsedPorts. r5: §9 corrected.

Finding #4 is the absent-sample analog of the r3 #5 bad-sample fix — a genuine
second-order gap. All folded into r5.
