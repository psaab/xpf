# AGY plan review — round 42 — #6749 armed-state plan v8.37 (6099e19f9)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r42-prompt.txt` (131,063 argv
bytes — r41 transport + the r41 table swapped in, the v8.37
normative edits replayed, the boilerplate rewritten + trimmed
byte-by-byte to fit MAX_ARG_STRLEN). Raw output:
`/tmp/agy-6749-r42.out`. Background bash `bynat193y` (direct `agy
--print-timeout 9m --print`).

**Verdict: PLAN-READY-WITH-NITS** (1 MINOR + 1 NIT) — the third
non-DEMAND verdict of the campaign, with the v8.37 mechanism
"re-derived and verified sound for running manager instances".

---

1. **[MINOR] Unstated single-tick GO-LOCAL re-drive on manager
   restart** (plan §5-C (ii), §8): `contentConvergedRevision` is
   in-memory; a restart loses it, the comparator fires ONCE per
   deduped pair, and convergence restores within one drain cycle
   (rebuild dedups and re-records the marker). (= SMR r42
   SMR42-1, convergent; folded v8.38: the marker is ADVISORY
   and rebuilds on the next dedup match (no persistence);
   exactly ONE wasted drain cycle per restart (the newest
   deduped pair's re-drive converges every older deduped
   revision with it — the comparator is a max), bounded,
   self-correcting, Warn-visible; §9 (a) asserts the
   single-cycle convergence.) AGY's evidence wish noted an
   optional optimization (seed the marker from the helper
   status at startup when the hash matches — avoiding even the
   one tick) — not folded (the statement form is sufficient;
   the optimization is an /engineer-time choice).
2. **[NIT] §9 (a) assertion gaps**: assert
   `acceptedCommitRevision == helper_stored_revision` post-dedup
   (an advance-accepted implementation FAILS — the rejected
   form's guard) and the single-cycle post-restart convergence.
   (Folded v8.38; SMR r42 SMR42-2's fence-untouched caveat
   folds alongside.)

PLAN-READY-WITH-NITS
