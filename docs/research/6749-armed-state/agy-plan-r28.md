# AGY plan review — round 28 — #6749 armed-state plan v8.23 (6c6d00b09)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r28-prompt.txt` (122,808 bytes —
r27 transport + the r27 table swapped in, the v8.23 normative edits
replayed, the boilerplate rewritten for the v8.23 deltas). Raw
output: `/tmp/agy-6749-r28.out`. Background bash `bz8wc08no`
(direct `agy --print-timeout 9m --print`).

**Verdict: DEMAND-REVISION** (1 MAJOR + 1 MINOR + 1 NIT).

---

1. **[MAJOR] Unbacked 1Hz retry loop and unpostured backoff for
   failing completion tails** (plan §1 SMR27-1, §5-C (ii), §8,
   §9 (a)): the iterate-pending-set model re-invokes the drain on
   a failing entry every 1s tick, bypassing the tail debt's
   exponential backoff (5/10/30/60s) and lacking the periodic
   Warn posture. (= SMR r28 SMR28-2; folded v8.24: a per-entry
   `nextAttempt` on the standing backoff ladder, the per-tick
   pass skips not-yet-due entries, the failure Warns on the
   standing edge-detect, and §9 (a) asserts two consecutive
   failures do not produce back-to-back full drains.)
2. **[MINOR] Missing-entry contract scope ambiguity across the
   synchronous `ApplyResult` accessors** (plan §5-C (ii), §6):
   the contract was framed around "the drain's cursor lookup",
   but the synchronous Compile-leg wrapper ALSO calls the
   manager's cursor method — and the scheduler's iterate drain
   picks up a Compile-leg entry concurrently with its wrapper
   (the wrapper's next phase call can hit a GC'd key). (Folded
   v8.24: the missing-entry contract applies uniformly to ALL
   registry accessors — drain AND synchronous wrapper — each
   returning already-terminal; §9 (a) gains the wrapper-vs-GC
   assertion = AGY f3. NOTE the race also requires SMR r28
   SMR28-1's claim-or-skip tri-state, folded in the same
   revision: per-phase pending → claimed → complete with the
   claim atomic under `m.mu`, a duplicate claimant skipping —
   the wrapper/scheduler overlap executes each phase exactly
   once.)
3. **[NIT] §9 (a) missing the synchronous-wrapper × GC race
   assertion** — folds with f2.

Evidence wishes (informational): the cursor registry struct and
`m.mu` methods; the 1s scheduler tick and notice drain
implementations.

DEMAND-REVISION
