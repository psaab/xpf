# AGY plan review — round 39 — #6749 armed-state plan v8.34 (6c01344b3)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r39-prompt.txt` (125,440 argv
bytes — r38 transport + the r38 table swapped in, the v8.34
normative edits replayed, the boilerplate rewritten for the v8.34
deltas). Raw output: `/tmp/agy-6749-r39.out`. Background bash
`b8wo7jva1` (direct `agy --print-timeout 9m --print`).

**Verdict: DEMAND-REVISION** (2 MAJOR + 1 MINOR + 1 NIT).

---

1. **[MAJOR] Transport carrier gap for the status-loop catch-up
   leg** (plan §5-C (ii), §6; process_status.go:10-140): the
   v8.34 transport names `ApplyResult` (Compile leg) and the
   staged object (deferred leg) — but the catch-up leg for a
   non-staged apply has neither. SMR r39's independent walk
   PARTIALLY VERIFIED the concern: every deferred snapshot
   comes from Compile's `pendingXSKStartup` branch (which
   stages the object the v8.34 transport names — the excerpt's
   own comment calls it "the sole producer of an unpublished
   lastSnapshot"), so the carrier exists in both defer shapes
   — but the TEXT's enumeration can be read as the linkcycle
   case only. Folded v8.35 by killing the ambiguity class: the
   digest is a FIELD of the built snapshot (minted at build
   time inside Compile), and EVERY acceptance leg (the
   Compile-leg result, the staged object (which wraps the
   snapshot), the catch-up (`m.lastSnapshot.capturedDigest`))
   reads that ONE field — no dependence on the defer shape.
2. **[MAJOR] Undefined completion behavior on same-pair
   re-applies (`firstExposure == false`)** (plan §5-C (ii),
   §6): a pair that took complete-skipped can never re-stamp
   on a re-apply if the stamp is cursor-exclusive
   (`firstExposure == false` suppresses the cursor). (= SMR
   r39 SMR39-1, independently derived; folded v8.35: the stamp
   runs on EVERY successful apply/publish of the exposed pair
   (the Compile-leg wrapper from the result's digest; the
   catch-up from the snapshot field — first-exposure via the
   cursor's stamp phase, non-first idempotently from the same
   field) — the wrapper's stamp is never suppressed by the
   cursor; the complete-skipped state heals on the next
   successful apply of the exposed pair, from any transport.)
3. **[MINOR] §9 (a) assertion gaps for the catch-up carrier,
   the re-apply stamp, and the deferred-leg extraction** —
   folded v8.35 (all three asserted).
4. **[NIT] Ambiguous cursor overwrite policy on duplicate
   `beginFirstExposure` calls** (= SMR r39 SMR39-3): folded
   v8.35 — the install is IDEMPOTENT per pair (a second call
   for the same pair+ledgerID no-ops; the digest is
   install-time-immutable; an empty digest never overwrites a
   valid captured value; a NEW first exposure (new revision)
   installs a new cursor).

Evidence wishes (informational): `beginFirstExposure` and
`syncSnapshotLocked` implementations; the wrapper's result-field
consumption.

DEMAND-REVISION
