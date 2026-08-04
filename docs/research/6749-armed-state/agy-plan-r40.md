# AGY plan review — round 40 — #6749 armed-state plan v8.35 (64bad83d7)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r40-prompt.txt` (129,350 argv
bytes — r39 transport + the r39 table swapped in, the v8.35
normative edits replayed, the boilerplate rewritten for the v8.35
deltas). Raw output: `/tmp/agy-6749-r40.out`. Background bash
`b68r80jq7` (direct `agy --print-timeout 9m --print`).

**Verdict: DEMAND-REVISION** (1 MAJOR + 2 MINOR).

---

1. **[MAJOR] The content-hash dedup strands the catch-up
   completion for same-content / new-revision snapshots**
   (process_status.go:58-61; plan §5-C (ii), §6): the dedup
   (`hash == m.lastSnapshotHash`) advances `publishedSnapshot`
   and returns nil WITHOUT a send and WITHOUT the completion
   machinery — a deferred/staged same-content pair's push and
   stamp never run (no wrapper exists for the deferred leg),
   and its cursor strands pending until the sweep. (Verified
   against the code: `process_status.go:2271-2275` — the early
   return has no completion hook. SMR r40 missed it (DEMAND
   this round — recorded honestly).) Folded v8.36: when the
   dedup matches AND a pending first-exposure cursor exists
   for the pair, the catch-up runs the completion (the
   notice/the stamp+push from the snapshot field — the
   helper's enforced content IS the pair's (identical), so
   the exposure is real); §9 (a) asserts it (= AGY f3).
2. **[MINOR] Unspecified wire posture and missing protocol
   canary for `ConfigSnapshot.capturedDigest`** (= SMR r40
   SMR40-1, convergent): folded v8.36 as MANAGER-LOCAL — the
   field is NOT marshaled to the helper (the manager's
   in-memory snapshot struct carries it; the wire encode
   omits it; the builder's zero set (builder.go:156-178)
   grows to cover it so the content-hash dedup never sees a
   field-only delta); §6 notes the posture explicitly (no
   wire field, no protocol canary — stated).
3. **[MINOR] §9 (a) false-green gap for the same-content
   catch-up completion** — folds with f1.

Evidence wishes (informational): the Rust
`userspace-dp/src/protocol/snapshot.rs` unknown-field posture
(moot under the manager-local form).

DEMAND-REVISION
