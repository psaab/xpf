# AGY plan review — round 38 — #6749 armed-state plan v8.33 (00d9567ae)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r38-prompt.txt` (122,754 argv
bytes — r37 transport + the r37 table swapped in, the v8.33
normative edits replayed, the boilerplate rewritten for the v8.33
deltas). Raw output: `/tmp/agy-6749-r38.out`. Background bash
`bth9q4s50` (direct `agy --print-timeout 9m --print`).

**Verdict: DEMAND-REVISION** (2 MAJOR + 1 MINOR + 1 NIT).

---

1. **[MAJOR] Non-staged apply `capturedDigest` carrier missing**
   (plan §5-C (ii), §1 r37 row): staged objects exist ONLY for
   deferred/pending-XSK compiles — a DIRECT durable apply (the
   common case) creates none, so "beginFirstExposure copies it
   from the staged object" yields `""` and every direct apply
   takes the complete-skipped path — direct applies NEVER stamp
   and `ActiveApplied()` stays false across all standard
   commits. (SMR r38 missed this (PLAN-READY-WITH-NITS this
   round — recorded honestly in the r38 ledger).) Folded v8.34:
   the digest's transport is the ACCEPTANCE'S OWN captured
   value — the Compile's result (`ApplyResult` gains
   `capturedDigest`) for the Compile leg, the staged object for
   the deferred leg — and `beginFirstExposure` takes it as an
   argument (never reads the staged object itself).
2. **[MAJOR] The §5-C (ii) GC predicate omits `complete-skipped`**
   (plan §5-C (ii) vs §9 (a)): the normative GC text still
   enumerates "(completed or SUPERSEDED)" — an implementation
   executing it strands every complete-skipped entry (the f1
   memory leak returns). Folded v8.34: the terminal set is
   {complete, complete-skipped, SUPERSEDED} at both the phase
   and entry levels.
3. **[MINOR] The edge-Warn scope for multi-acceptance aged-out
   revisions** (plan §5-C (ii), §9 (a)): per-revision or
   per-ledgerID? Folded v8.34: per-CURSOR (each skip is a
   distinct exposure event), and the pair-keyed resume rule
   (v8.18's "an incomplete replay resumes its phase") dedups
   the recovery re-derivation (a second crash mid-recovery
   resumes the SAME cursor rather than minting a second — no
   duplicate cursors for one logical exposure).
4. **[NIT] "The marker heals" terminology**: folded v8.34 — the
   aged-out pair's own marker is abandoned (unreachable); the
   marker CORRECTS for the CURRENT pair when its own apply
   stamps.

Evidence wishes (informational): `CompileResult`/`StartCompile`
signatures and the `m.staged` lifecycle; `beginFirstExposure`'s
implementation; `MarkAppliedDigest`/`ActiveApplied`.

DEMAND-REVISION
