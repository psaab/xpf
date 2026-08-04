# AGY plan review — round 44 — #6749 armed-state plan v8.39 (44ab7a630)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r44-prompt.txt` (131,022 argv
bytes — r43 transport + the r43 table swapped in, the v8.39
normative edits replayed, the two settled excerpts (SyncApply
guard, daemon_run phases) elided with pointers, the boilerplate
rewritten + trimmed byte-by-byte to fit MAX_ARG_STRLEN). Raw
output: `/tmp/agy-6749-r44.out`. Background bash `be74u0mln`
(direct `agy --print-timeout 9m --print`).

**Verdict: DEMAND-REVISION** (1 BLOCKER + 1 MAJOR + 1 MINOR + 1
NIT).

---

1. **[BLOCKER] The §1-vs-§5-C (ii) echo-0 trigger
   contradiction** (plan §1 r43 row 1 vs §5-C (ii)
   (plan.md:5485)): the normative sentence reads "the echo-0
   helper-behind case keeps the startup re-apply owner — AND
   it FIRES on the GO-LOCAL rule" — and "it" is genuinely
   ambiguous: the nearest antecedent (the echo-0 case —
   AGY's reading, under which the echo-0 owner is
   comparator-gated and the respawn blackhole returns) vs
   the paragraph subject (the re-sync debt — SMR's r43
   reading, under which the debt's GO-LOCAL rule is a
   SEPARATE abandoned/failed-build path and the echo-0 owner
   is independent). SMR r44's post-AGY evaluation records it
   VALID-AS-AMBIGUITY (not as evidence of the blackhole —
   the echo-0 owner exists either way — but the sentence
   supported the gated reading and had to stop). Folded
   v8.40: DISAMBIGUATED — the echo-0 startup re-apply owner
   fires on the zero-stored helper's status echo
   (`LastSnapshotGeneration == 0` / the lineage echo zero)
   INDEPENDENTLY of the comparator; the re-sync debt's
   GO-LOCAL rule is the separate abandoned/failed-build
   path.
2. **[MAJOR] The SMR43-2 wrapper-coverage sentence never
   landed in §5-C (ii)** (plan §1 r43 row 6 vs §5-C (ii)) —
   CONFIRMED by SMR r44 as a claimed-but-wrong citation in
   its own fold (the statement existed in the narrative and
   the table row, not in the normative section). Folded
   v8.40 into §5-C (ii) with a corrected row.
3. **[MINOR] Test 20 (a) depends on f1's resolution** —
   folds with the disambiguation (§9 (a) asserts the echo-0
   owner's independence explicitly).
4. **[NIT] Test both hygiene-clear forms** — folds (§9 (a)
   notes both the OPTIONAL clear and no-clear forms pass).

Evidence wishes (informational): `stopLocked()`
(process.go:230-270) and the status-poll handlers'
mutation paths for `acceptedCommitRevision` /
`contentConvergedRevision`.

DEMAND-REVISION
