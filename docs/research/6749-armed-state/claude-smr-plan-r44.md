# Claude SMR plan review — round 44 — #6749 armed-state plan v8.39 (44ab7a630)

**Reviewer:** Claude SMR (hostile; the yellow-flag note stands —
the trace below is the evidence). Attack surface: the echo-0
owner citation, the §9 (a) helper-respawn assertion, the
wasted-cycle side effects, the hash coverage citation, the
incarnation-guard and wrapper-coverage sentences, and Q1 (44th
enumeration).

**Verdict: PLAN-READY-WITH-NITS** — 0 BLOCKER + 0 MAJOR + 0
MINOR + 2 NIT. After the full hostile sweep (including the
echo-0 leg's own timing/trigger semantics and the plan-change
restart path), only two statement-level nits survived. Codex
remains infra-blocked (twenty-third documented attempt).

---

## SMR44-1 (NIT) — the recovery window is the standing respawn posture, not the dedup machinery's

The echo-0 recovery's latency (death detection + respawn +
the zero echo's arrival on the next 1s poll + the full
apply) is the PRE-EXISTING respawn posture (the helper died
— the config loss is the death's), and the v8.39 text should
say so once, so the dedup machinery is never read as
EXTENDING the window (the dedup's `publishedSnapshot != 0`
gate is closed after `stopLocked()` (verified
process.go:259), so the recovery's own publish is a full
send by construction — the machinery adds zero latency to
the standing posture).

## SMR44-2 (NIT) — the plan-change restart's full-send guarantee

The plan-change restart path (process_status.go:60's
`publishedPlanKey != planKey` branch) also goes through
`stopLocked()` → `publishedSnapshot = 0` → the dedup
suppressed → a full send of the current plan lands on the
fresh helper — the same guarantee as the echo-0 recovery,
worth one sentence next to SMR44-1 (the two restart shapes
share the gate).

## Attack trace (what I tried, and why it fails to break v8.39)

1. **A same-content commit DURING the recovery window.** The
   recovery's drain re-reads the ACTIVE config at drain time
   (the standing latest-wins drain semantics) — the new
   commit is included; the dedup's gate is closed
   (`publishedSnapshot == 0`); a full send of the LATEST
   config lands. Coherent.
2. **A second helper death mid-recovery.** The echo-0 leg is
   level-triggered on the zero echo (each poll reports zero
   until the recovery's send lands) — it re-fires — the
   recovery is idempotent (a full apply of the same latest
   config). Coherent.
3. **The OPTIONAL hygiene clear.** Both forms are safe: the
   echo-0 owner is the recovery authority either way; the
   clear only adds one redundant comparator fire (idempotent).
   The v8.39 text's OPTIONAL marking is honest (an
   implementer picking either passes). Coherent.
4. **The hash coverage × a session-policy change.** A
   session-policy change is forwarding-relevant (zone
   assignments, address books, application definitions are
   hash inputs) — it forces a hash mismatch and bypasses the
   dedup entirely — so the SMR42-2 fence caveat's premise
   (a deduped pair can never differ in session policy) holds
   by construction. Coherent.
5. **Q1, forty-fourth enumeration.** The v8.39 mechanics
   (the echo-0 citation, the §9 (a) assertion, the
   side-effect and hash-coverage statements, the
   incarnation-guard and wrapper-coverage sentences) mutate
   NO binding slots on any refuse/degrade path. No new
   `Registered && !Armed && state==none` producer. Q1 holds.
6. **The r43 disposition table.** Every row re-derived against
   the file: AGY f1 (NOT-VERIFIED with the echo-0 evidence),
   AGY f2/f3/f4 (the clarifications), SMR43-1/SMR43-2 — all
   present and correctly cited.

## Required for convergence

Nothing mandatory. Optional for v8.40 (or `/engineer`-time):
SMR44-1's standing-posture sentence; SMR44-2's plan-change
sentence. AGY r44 pending at this writing — its verdict may
add to this list (a DEMAND from AGY returns the loop to the
fold).

**Verdict: PLAN-READY-WITH-NITS** (2 NIT — the attack trace
stands as the evidence this is not a soft pass).

---

## Post-AGY addendum (round 44, after `agy-plan-r44.md` landed)

AGY r44 returned DEMAND-REVISION (1 BLOCKER + 1 MAJOR + 1
MINOR + 1 NIT). My evaluation, source in hand:

- **AGY f1 (BLOCKER — the §1-vs-§5-C (ii) echo-0 trigger
  contradiction): VALID AS A TEXTUAL AMBIGUITY, and it
  partially re-opens my r43 NOT-VERIFIED evaluation.** The
  normative sentence (plan.md:5485) reads "the echo-0
  helper-behind case keeps the startup re-apply owner — AND
  it FIRES on the GO-LOCAL rule" — and "it" is genuinely
  ambiguous: the nearest antecedent (the echo-0 case, AGY's
  reading — under which the echo-0 owner is comparator-gated
  and the respawn blackhole returns) vs the paragraph
  subject (the re-sync debt, my r43 reading — under which
  the debt's GO-LOCAL rule is a SEPARATE firing path for the
  abandoned/failed-build case and the echo-0 owner is
  independent). My r43 evaluation answered the SEMANTIC
  question correctly (the recovery path must be independent)
  but did not notice the sentence SUPPORTS AGY's reading —
  and an implementer reading it AGY's way builds the
  blackhole AGY traced. The v8.40 fold DISAMBIGUATES: the
  echo-0 startup re-apply owner fires on the zero-stored
  helper's status echo (`LastSnapshotGeneration == 0` / the
  lineage echo zero) INDEPENDENTLY of the comparator; the
  re-sync debt's GO-LOCAL rule is the separate
  abandoned/failed-build path. AGY's f1 is therefore recorded
  VALID-AS-AMBIGUITY (not as evidence of the blackhole —
  the echo-0 owner exists either way — but the sentence had
  to stop supporting the gated reading).
- **AGY f2 (MAJOR — the SMR43-2 wrapper-coverage sentence
  never landed in §5-C (ii)): CONFIRMED — a claimed-but-wrong
  citation in MY OWN r43 fold.** The wrapper-coverage
  statement exists in the version-history narrative and the
  r43 table row (which cites §5-C (ii)) but never made it
  into the normative section. Folded v8.40 into §5-C (ii)
  with a corrected row.
- **AGY f3 (MINOR — test 20 (a) depends on f1's resolution):**
  folds with the disambiguation (§9 (a) asserts the echo-0
  owner's independence explicitly).
- **AGY f4 (NIT — test both hygiene-clear forms):** folds
  (§9 (a) notes both the OPTIONAL clear and no-clear forms
  pass — the echo-0 owner is the authority either way).
