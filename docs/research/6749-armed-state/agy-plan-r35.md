# AGY plan review — round 35 — #6749 armed-state plan v8.30 (1b3cf5138)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r35-prompt.txt` (118,744 argv
bytes — r34 transport + the r34 table swapped in, the v8.30
normative edits replayed, the boilerplate rewritten for the v8.30
deltas). Raw output: `/tmp/agy-6749-r35.out`. Background bash
`bu8x365x1` (direct `agy --print-timeout 9m --print`).

**Verdict: DEMAND-REVISION** (1 BLOCKER + 1 MINOR).

---

1. **[BLOCKER] Locus ambiguity & TOCTOU in `pair.capturedDigest`
   under the gated successor** (plan §1 r34 row, §5-C (ii) (b),
   §6; store.go:787-853; process_status.go:10-140): the v8.30
   "the pair's OWN digest" leaves the capture locus open — with
   C1 exposed and C2 store-active-but-gated, a capture via
   `store.ActiveDigest()` at catch-up-acceptance or notice-drain
   time samples `s.active == C2`, so
   `MarkAppliedDigest(digest(C2))` makes the read-side
   `ActiveApplied()` report the GATED UNEXPOSED C2 as APPLIED
   while the dataplane runs C1 — the #6296 class reopened.
   (= SMR r35 SMR35-1, same locus from the plan side; folded
   v8.31: the digest is computed from the store's RETAINED TREE
   for the pair's revision (the rollback/archive trees) via
   `DigestOfRevision(rev)` (`s.mu`), captured at the cursor's
   install for BOTH legs — never from `s.active` at capture
   time; the `m.mu` → `s.mu` edge is safe (the store never
   calls into the manager).)
2. **[MINOR] §9 (a) omits the mandated interleaving sequence**:
   without promote-C1 → expose-C1 → promote-C2(gated) → drain,
   a drain-time-`ActiveDigest()` implementation passes a
   sequential test run and masks f1. (Folded v8.31 with the
   precise assertions: `appliedDigest == digest(C1)` AND
   `ActiveApplied() == false` after the drain; `== digest(C2)`
   + `ActiveApplied() == true` after C2's apply.)

Evidence wishes (informational): `beginFirstExposure`/
`phaseCursor`/notice struct definitions; `MarkAppliedDigest`'s
empty-digest behavior.

DEMAND-REVISION
