# AGY plan review — round 36 — #6749 armed-state plan v8.31 (31fea1cef)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r36-prompt.txt` (120,850 argv
bytes — r35 transport + the r35 table swapped in, the v8.31
normative edits replayed, the boilerplate rewritten for the v8.31
deltas). Raw output: `/tmp/agy-6749-r36.out`. Background bash
`b589drbw8` (direct `agy --print-timeout 9m --print`).

**Verdict: DEMAND-REVISION** (1 MAJOR + 1 MINOR + 2 NIT).

---

1. **[MAJOR] Missing error signature & retention-expiry contract
   for `DigestOfRevision(rev)`** (plan §5-C (ii), §1 r35 row 1,
   §6): retained trees have bounded retention; an aged-out
   revision's lookup fails and v8.31 specifies no error return
   or handling. (= SMR r36 SMR36-1's retention concern,
   convergent; folded v8.32 as: the digest is captured AT BUILD
   time inside Compile (while `s.active` is the pair — the
   #6296 pattern) and RIDES the staged object into the cursor
   (no drain-time lookup at all; the two legs' digests
   identical by construction); the accessor
   (`DigestOfRevision(rev) → (digest, error)`, node-cached
   O(1) per AGY f3) is the RECOVERY-fallback only, with the
   missing-revision contract — empty digest ⇒ the stamp phase
   skips with an edge Warn while invalidation and push
   proceed; the marker heals on the next full apply.)
2. **[MINOR] §9 (a) does not enforce the store-retained digest
   source vs snapshot-text substitution** (plan §9 (a)): a
   manager-side snapshot-text digest can diverge from the
   store's render (compilation normalization) while passing a
   naive test. (= SMR r36 SMR36-2's single-renderer property;
   folded v8.32: all digest values come from the store's ONE
   renderer (build-time `ActiveDigest()` or the retained tree's
   render of the same tree) — no manager-side re-render is ever
   compared against a store render — and §9 (a) asserts it
   with a config carrying compilation-stripped formatting
   (comments/whitespace): `appliedDigest` matches the store's
   render, never a snapshot-text digest.)
3. **[NIT] Tree-digest re-computation latency under `m.mu` →
   `s.mu`**: folded v8.32 (the digest is node-cached (computed
   once at commit/promotion) — `DigestOfRevision` is an O(1)
   lookup under `s.mu`; the primary build-time capture avoids
   the under-`m.mu` accessor call entirely).
4. **[NIT] Imprecise post-rollback window prose** (plan §1 r35
   row 2, §5-C (ii)): "rollback-to-C1 ⇒ applied" is wrong in
   the promotion window — immediately post-rollback-promotion
   (`s.active == C1`), `appliedDigest` is still `digest(C2)`
   ⇒ `ActiveApplied() == false` until the rollback's OWN apply
   stamps `digest(C1)`. (Folded v8.32: the window text now
   distinguishes rollback-PROMOTION (not applied) from
   post-rollback-APPLY (applied).)

Evidence wishes (informational): `DigestOfRevision`'s
implementation, retention depth/GC, node digest pre-computation.

DEMAND-REVISION
