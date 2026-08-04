# AGY plan review — round 41 — #6749 armed-state plan v8.36 (29a9ca319)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r41-prompt.txt` (129,651 argv
bytes — r40 transport + the r40 table swapped in, the v8.36
normative edits replayed, the boilerplate rewritten + compressed
for the v8.36 deltas). Raw output: `/tmp/agy-6749-r41.out`.
Background bash `b3931bptn` (direct `agy --print-timeout 9m
--print`).

**Verdict: DEMAND-REVISION** (1 BLOCKER + 1 MAJOR + 1 NIT).

---

1. **[BLOCKER] The dedup-completion path omits
   `acceptedCommitRevision`/`acceptedBuildSeq` advancement —
   an infinite GO-LOCAL re-sync loop** (plan §5-C (ii), §1 r40
   row 1; process_status.go:2271-2275): the dedup suppresses
   the send, so no status echo for the new revision ever
   arrives; `acceptedCommitRevision` stays old; the GO-LOCAL
   rule sees a false helper-behind on every poll and re-drives
   `StartCompile` endlessly. (= SMR r41 SMR41-1 — FULL
   convergence. AGY's own remediation (advance
   `acceptedCommitRevision`/`acceptedBuildSeq` +
   `markAppliedSnapshotLocked()`) was EVALUATED AND REJECTED
   in the v8.37 fold: it opens the OTHER leg — the NONZERO
   helper-behind clause reads helper-stored(old) <
   accepted(new) and re-drives into the same dedup — the loop
   moves instead of dying. The adopted form:
   `contentConvergedRevision` feeding ONLY the GO-LOCAL
   comparator, with `acceptedCommitRevision` NOT advancing
   (the note CAS authority stays the last-sent lineage —
   both legs stay quiet).)
2. **[MAJOR] §9 (a) false-green gap for deduped completions**:
   §9 (a) asserted the notice+stamp but not the lineage
   advancement or the re-sync quietness. Folded v8.37: §9 (a)
   asserts NO GO-LOCAL fire AND NO helper-behind fire
   post-completion (+ SMR41-2's deferred-restage variant).
3. **[NIT] §1 r40 row 1 prematurely marks AGY f1 CLOSED** —
   folded v8.37 (the row is amended: the f1 closure completes
   only with v8.37's convergence semantics).

Evidence wishes (informational): `markAppliedSnapshotLocked()` /
`acceptedBuildSeq` assignments; the GO-LOCAL rule's Go-side
guard conditions.

DEMAND-REVISION
