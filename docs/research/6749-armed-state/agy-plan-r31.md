# AGY plan review — round 31 — #6749 armed-state plan v8.26 (c09cceed3)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r31-prompt.txt` (130,750 bytes —
r30 transport + the r30 table swapped in, the v8.26 normative edits
replayed, the boilerplate rewritten for the v8.26 deltas, attack
surfaces compressed to fit MAX_ARG_STRLEN). Raw output:
`/tmp/agy-6749-r31.out`. First dispatch died on a
RESOURCE_EXHAUSTED 429 (exit 1, no output — per the 429 rule it
was retried after a 90 s backoff, successfully); background bash
`b7oovjpes` (direct `agy --print-timeout 9m --print`).

**Verdict: DEMAND-REVISION** (1 MAJOR + 1 MINOR + 1 NIT), with the
architectural audit clean ("no new architectural race conditions or
deadlocks were introduced by v8.26 — the CAS stamp, entry fence,
ladder decay, context cancellation, and missing-entry panic revert
are sound additions").

---

1. **[MAJOR] §9 (a) permits a false-green implementation of the
   steal fences** (plan §9 (a)): the assertions cover only the
   dead-at-entry case; a claim stolen MID-execution (side effects
   land under `applySem`, the completion record is refused at
   `m.mu`, the stealer re-executes idempotently) is untested — an
   implementation could omit the generation check on
   `MarkPhaseComplete` and still green the suite. (= SMR r31
   SMR31-1's interleaving assertion; folded v8.27 with the
   mid-drain walk spelled out in §5-C (ii) AND the §9 (a)
   assertion.)
2. **[MINOR] The ctx-cancellation claim is imprecise for
   in-memory store operations** (plan §5-C (ii)):
   `setAppliedDigest` takes no `context.Context` — its stale
   safety is the CAS (fence b), not cancellation (fence d).
   (= SMR r31 SMR31-2; folded v8.27: cancellation bounds the I/O
   tails (conn writes, socket operations); in-memory store
   mutations rely on the CAS revision verification.)
3. **[NIT] The mid-drain completion-refusal → stealer
   re-execution trace is not spelled out** (plan §1 row 6, §5-C
   (ii)) — folded v8.27 with SMR31-1.

Evidence wishes (informational): `setAppliedDigest`'s exact CAS
contract; the cursor registry struct; the invalidation handlers'
idempotency.

DEMAND-REVISION
