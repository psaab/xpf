# AGY plan review — round 29 — #6749 armed-state plan v8.24 (50f0ef069)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r29-prompt.txt` (125,164 bytes —
r28 transport + the r28 table swapped in, the v8.24 normative edits
replayed, the boilerplate rewritten for the v8.24 deltas). Raw
output: `/tmp/agy-6749-r29.out`. Background bash `ba1ume11d`
(direct `agy --print-timeout 9m --print`).

**Verdict: DEMAND-REVISION** (1 MAJOR + 1 MINOR + 2 NIT).

---

1. **[MAJOR] Goroutine panic conflated with process crash in the
   tri-state lifetime** (plan §1 r28 row 1, §5-C (ii)): "a
   claimed-but-crashed drain is the in-memory-loss case the crash
   rule re-derives" only covers PROCESS crashes (boot recovery);
   a goroutine PANIC (process lives) leaves the phase `claimed`
   forever — duplicate claimants skip it, it never reaches
   terminal, it is never GC'd, and no boot recovery ever runs
   (the "un-leased `claimed` trap"). (Fix folded v8.25: (i) a
   `defer` wrapper around every phase execution catches panics
   and atomically reverts claimed → pending WITH `nextAttempt`
   under `m.mu`; (ii) a claim lease — `claimedAt` + a steal
   after the named bound with a claim-generation guard (a stale
   claimant's late advance is refused). SMR r29 SMR29-2's
   named-bounds/D-state fold is superseded by the lease.)
2. **[MINOR] Non-atomic claim release and `nextAttempt`
   assignment on tail failure** (plan §5-C (ii)): the release
   (claimed → pending) and the backoff set must be ONE `m.mu`
   operation, or a racing iterate tick re-claims immediately and
   the 1Hz loop returns via the claim path. (= SMR r29 SMR29-1;
   folded v8.25 — the claim-side due-check also refuses claims
   whose `nextAttempt` is in the future, notice drain included.)
3. **[NIT] Unspecified ladder reset across phase boundaries**:
   folded v8.25 as AGY's form (a SUCCESSFUL phase resets the
   entry's ladder to the base step for the remaining phases —
   each phase's first attempt is prompt; a failed phase advances
   the ladder), SUPERSEDING SMR r29 SMR29-3's terminal-only
   form (each phase's failure is operation-specific — the
   standing debt behavior resets on success).
4. **[NIT] §9 (a) lacks the panic-injection assertion**: folded
   v8.25 (a panicking phase execution reverts claimed → pending
   with backoff applied).

Evidence wishes (informational): the `phaseCursor`/
`completionState` struct layout; the drain wrapper's `defer`
recovery logic.

DEMAND-REVISION
