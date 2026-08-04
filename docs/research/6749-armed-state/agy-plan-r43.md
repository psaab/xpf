# AGY plan review — round 43 — #6749 armed-state plan v8.38 (07762de4d)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r43-prompt.txt` (131,067 argv
bytes — r42 transport + the r42 table swapped in, the v8.38
normative edits replayed, the boilerplate rewritten + trimmed
byte-by-byte to fit MAX_ARG_STRLEN). Raw output:
`/tmp/agy-6749-r43.out`. Background bash `b20ekewg1` (direct `agy
--print-timeout 9m --print`).

**Verdict: DEMAND-REVISION** (1 BLOCKER + 1 MAJOR + 1 MINOR + 1
NIT).

---

1. **[BLOCKER] Helper (re)spawn retains stale
   `contentConvergedRevision`, allegedly disabling the
   Go-local re-drive indefinitely** — **NOT-VERIFIED** by the
   SMR r43 post-AGY evaluation (source in hand): AGY's trace
   stops at the GO-LOCAL comparator and never engages the
   plan's OWN respawn-recovery authority — the echo-0
   helper-behind case keeps the STARTUP RE-APPLY OWNER
   (plan.md:5485), which fires on a zero-stored helper's
   status echo independently of the comparator, and the fresh
   helper accepts everything zero-stored (the standing
   SMR20-8 benign-respawn rule). The recovery's publish
   cannot dedup either: `stopLocked()` resets
   `m.publishedSnapshot = 0` (verified process.go:259), so
   the dedup's `publishedSnapshot != 0` gate is closed and a
   real send lands. The dataplane is never unconfigured past
   the echo-0 owner's own latency. The marker's staleness
   after a helper death is real but harmless — its ONLY
   reader is the comparator, whose quietness during the
   window is safe precisely because the comparator was never
   the recovery path. (A hygiene clear-on-helper-death is
   optional, not required.)
2. **[MAJOR] §9 (a) exercises only the manager restart, not
   the helper respawn** — VALID as a test-coverage point (not
   as evidence for f1's blackhole): §9 (a) gains the
   helper-respawn recovery assertion (the echo-0 startup
   re-apply owner drives the full bring-up after a deduped
   pair; the comparator's quietness is NOT the recovery
   authority).
3. **[MINOR] The wasted restart cycle's Compile side effects
   run before the dedup decision** — valid documentation
   point, folded (the cycle includes the Compile-side
   XDP/pin/shim/bootstrap mutations, idempotent-vs-the-running
   -helper because the rebuild targets the CURRENT plan with
   identical content (plan-keyed writes of the same values;
   the v8.14 publish-leg-entry validation already orders them
   before any send decision)).
4. **[NIT] The content hash's session-policy coverage
   citation** — valid, folded (the hash covers the
   session-policy structures (zone assignments, address
   books, application definitions), so a session-policy
   change forces a hash mismatch and bypasses the dedup —
   the SMR42-2 fence caveat's proof obligation).

DEMAND-REVISION
