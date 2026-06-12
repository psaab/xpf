# #1880 plan review — Claude SMR, round 3 (HOSTILE)

Verdict on r3: PLAN-NEEDS-REVISION (concur Codex r3 H/M, AGY r3 f1/f2).
Verdict on r4 (as edited): PLAN-READY.

Independent check of the r4 contracts:
- Lifecycle: Manager-owned ctx + Stop() wired into daemon shutdown +
  pgroup kill on cancel + cleanup-never-retries + test-hygiene clause
  covers both the Codex daemon-exit path and the AGY test-leak path.
- Generation contract: reloadMu over the full write+reload critical
  section + confGen captured-before/checked-after closes the
  stale-success edge; the required unit test pins it. Note the retry
  must RE-CHECK degraded-cleared inside reloadMu before exec (AGY f2's
  cancel-on-success) — the r4 text specifies episode cancellation
  observed by the woken retry; implementation must do that check under
  the same mutex to avoid a TOCTOU between gauge-clear and retry exec.
  This is an implementation note, not a plan gap: the plan's "observes
  the episode cancelled exits without exec'ing" combined with
  "reloadMu serializes the retry against applySem-driven reloads"
  already forces the check inside the critical section.
- Timeout bound corrected to ≤40s (30s + ≤2×5s WaitDelay).
- Gauge: 0/1, no labels — cardinality concern closed.

No remaining plan-level objections. The residual risk register (§8) and
Phase-2 gates (§7) cover the implementation-phase hazards.
