# AGY plan review — round 30 — #6749 armed-state plan v8.25 (c9c70de90)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r30-prompt.txt` (127,630 bytes —
r29 transport + the r29 table swapped in, the v8.25 normative edits
replayed, the boilerplate rewritten for the v8.25 deltas). Raw
output: `/tmp/agy-6749-r30.out`. Background bash `bdtzbc3ik`
(direct `agy --print-timeout 9m --print`).

**Verdict: DEMAND-REVISION** (2 BLOCKER + 1 MINOR + 1 NIT).

---

1. **[BLOCKER] Un-fenced stale-claimant side effects under the
   lease steal** (plan §5-C (ii); daemon_apply_commit.go:245-285;
   store.go:787-794): the generation guard refuses the stale
   claimant's completion RECORD, but its tail EXECUTION runs
   outside `m.mu` and mutates the world anyway — a late
   `MarkActiveApplied(B)` regresses `appliedRevision` after C
   stamped C (store stamp corruption: `ActiveApplied()` reports
   false for C permanently, breaking HA takeover readiness), and
   a late invalidation(A,B) deletes sessions C re-permitted.
   (SMR r30 SMR30-1's idempotency "proofs" were WRONG for the
   multi-commit case — the stamp is a regression, not an
   idempotent set; the late invalidation is the SMR24-1 class
   reopened.) Folded v8.26: the drain's claim checks LIVENESS
   AT ENTRY (a stolen/dead claim aborts the drain before any
   side effect — the missing/stolen-entry contract); the stamp
   uses the CAS form (expected store-current revision — refuses
   when the store moved past); and the drain's `applySem` hold
   + the drain-time-EXPOSED composition order the mid-drain
   cases (no exposure moves while the drain holds the
   semaphore).
2. **[BLOCKER] Unbounded goroutine leak / 5s steal spin on a
   hanging phase** (plan §5-C (ii)): the steal fires every
   namedBound with no context cancellation and no cadence decay
   — each stealer hangs on the same resource, spawning a
   goroutine every 5s indefinitely. Folded v8.26: the steal (i)
   CANCELS the stale claimant's context (the tail operations
   take the claim's ctx and abort on cancellation — a
   kernel-wedged residue is the budgeted D-state class), (ii)
   ADVANCES the entry's ladder (the steal cadence decays to the
   60s floor, not a fixed spin), and (iii) is a REPLACEMENT
   (exactly one live claim generation per entry — a second
   steal is refused while a live one stands).
3. **[MINOR] §9 (a) false-green gaps for steal side-effects and
   the goroutine leak** — folded v8.26 (assertions for the
   late-stamp refusal, the late-invalidation composition, the
   steal's cancellation + cadence decay, and the panic-revert's
   missing-entry no-op).
4. **[NIT] The panic-revert's missing-entry handling** (= SMR
   r30 SMR30-2) — folded v8.25/v8.26 (the revert rides the
   uniform missing-entry → already-terminal contract).

Evidence wishes (informational): `MarkActiveApplied` /
invalidation dispatch signatures; the cursor generation-check
and socket timeout settings.

DEMAND-REVISION
