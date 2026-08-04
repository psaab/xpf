# Claude SMR plan review — round 45 — #6749 armed-state plan v8.40 (c13b6da34)

**Reviewer:** Claude SMR (hostile; the yellow-flag note stands —
the trace below is the evidence). Attack surface: the echo-0
disambiguation, the wrapper-coverage sentence, the §9 (a)
independence and both-forms assertions, the standing-posture
and plan-change sentences, and Q1 (45th enumeration).

**Verdict: PLAN-READY-WITH-NITS** — 0 BLOCKER + 0 MAJOR + 0
MINOR + 2 NIT. After the full hostile sweep (including the
Compile-leg's own publish-dedup question and the wedge-vs-
death posture split), only two statement-level nits survived.
Codex remains infra-blocked (twenty-fourth documented
attempt).

---

## SMR45-1 (NIT) — the Compile-leg's own publish-dedup question has a written answer either way

Does the Compile's OWN publish leg run the content-hash dedup
(the syncSnapshotLocked gate), or does it always send? The
question matters only for which tail authority covers a
same-content Compile-leg commit — and the answer is that BOTH
shapes are covered: if the Compile's publish dedups (no new
generation reaches the helper), the daemon wrapper's standing
Compile-leg tails run (the stamp from the result's
`capturedDigest` + the structured-transaction push — the
v8.40 wrapper-coverage sentence); if it sends (a redundant-
but-identical snapshot), the helper accepts, the cursor
installs, and the same tails run through the cursor. The
deferred-resume leg (the only place the dedup gates a
NEEDED send) is the dedup-completion's (v8.36/37). One
sentence so the division is explicit rather than inferred
(the Compile-leg is covered under either publish behavior;
the deferred-resume leg is the dedup-completion's).

## SMR45-2 (NIT) — the wedged-helper posture is a different class from the death-detection trigger

The OPTIONAL hygiene clear's trigger is helper DEATH
detection (the control socket loss / the process exit); a
WEDGED helper (stops responding without dying) is the
persistent-control-failure class (the standing budget:
indefinite fail-closed with retries and diagnostics alive) —
owned by the helper-behind detection, not by the
hygiene-clear or the echo-0 owner. One sentence so the two
postures are not conflated (the clear's trigger never
depends on distinguishing them, but the operator-facing
semantics differ).

## Attack trace (what I tried, and why it fails to break v8.40)

1. **Does the GO-LOCAL rule EVER need to fire for a fresh
   helper?** No: the echo-0 startup re-apply owner drives a
   full apply of the active config, which is everything the
   fresh helper needs; the comparator's quietness is
   irrelevant to the fresh helper's recovery (the
   disambiguated text now says exactly this). Coherent.
2. **The both-forms hygiene clear.** With the clear: the
   comparator fires once, redundantly with the echo-0 owner
   (idempotent — the recovery's apply is the same full apply
   either way). Without: the echo-0 owner alone drives it.
   Both safe. Coherent.
3. **The disambiguation × the abandoned/failed-build path.**
   The re-sync debt's GO-LOCAL rule remains the
   abandoned/failed-build owner (the v8.15 firing condition,
   untouched by the disambiguation — the disambiguation only
   separated the echo-0 owner from it). Coherent.
4. **Q1, forty-fifth enumeration.** The v8.40 mechanics
   (the disambiguation, the wrapper-coverage sentence, the
   §9 (a) assertions, the two sentences) mutate NO binding
   slots on any refuse/degrade path. No new
   `Registered && !Armed && state==none` producer. Q1 holds.
5. **The r44 disposition table.** Every row re-derived against
   the file: AGY f1 (the disambiguation), AGY f2 (the §5-C
   (ii) wrapper-coverage sentence), AGY f3/f4 (the §9 (a)
   assertions), SMR44-1/SMR44-2 (the two sentences) — all
   present and correctly cited.

## Required for convergence

Nothing mandatory. Optional for v8.41 (or `/engineer`-time):
SMR45-1's division sentence; SMR45-2's wedge-vs-death note.
AGY r45 pending at this writing — its verdict may add to
this list (a DEMAND from AGY returns the loop to the fold).

**Verdict: PLAN-READY-WITH-NITS** (2 NIT — the attack trace
stands as the evidence this is not a soft pass).

---

## Post-AGY addendum — AGY r45 verdict received (PLAN-READY-WITH-NITS, 1 MINOR + 2 NIT); findings evaluated

AGY r45 returned PLAN-READY-WITH-NITS with three findings. Each
evaluated hostilely against the committed v8.40 blob (`c13b6da34`)
before any fold:

1. **AGY f1 (MINOR) — §9 (a) lacks the DIRECT Compile-leg
   same-content dedup assertion: VALID, fold.** Re-derived: §9 item
   20 (a) asserts the DEFERRED same-content catch-up completion
   (v8.36), the convergence-legs-quiet pair (v8.37), the restart
   window (v8.38), the helper-respawn recovery (v8.39/40), and the
   hygiene forms — but no assertion names a NON-staged Compile-leg
   commit whose publish dedups in `syncSnapshotLocked`. The wrapper-
   coverage sentence (§5-C (ii)) states the behavior; the test plan
   never pins it. An implementation skipping the wrapper tails on a
   direct deduped apply would pass every §9 (a) assertion. Folded
   v8.41 (§9 (a): the `capturedDigest` stamp + the push +
   `ActiveApplied() == true`, skip-FAILS).
2. **AGY f2 (NIT) — §11 item 6 "left un-updated from v8.18":
   NOT-VERIFIED.** The committed blob's §11 item 6 (plan.md:10779 @
   `c13b6da34`) reads "**Round-44 disposition table audit.** §1's
   r44 table maps every r44 finding ... to its v8.40 fold" —
   already current. AGY's citation (`plan.md#L1106`) does not match
   the reviewed file (line 1106 is mid-§1-history, not §11); the
   inline-evidence transport's line numbering or a stale read is
   the likely cause. Rejected as a defect; folded anyway as the
   standing per-round maintenance (item 6 re-points to the r45
   table / v8.41 — the same roll every round performs).
3. **AGY f3 (NIT) — `acceptedCommitRevision` manager-side
   persistence unstated: VALID as a documentation gap, fold.** The
   semantic is already entailed (the comparator's max() form, the
   r41 rejection of advancing `acceptedCommitRevision` on dedup,
   and `stopLocked()`'s documented reset set — `publishedSnapshot`/
   `publishedPlanKey`/the three latch collections, never the commit
   lineage), but §5-C (ii) never said WHY the comparator is quiet
   on a benign respawn. Stating it closes the implementer-mistake
   class AGY names (resetting the lineage on helper death would
   re-open the GO-LOCAL fire the echo-0 owner exists to make
   unnecessary). Folded v8.41 (§5-C (ii)).

**Convergence.** Both active reviewers are non-DEMAND on the same
committed blob (v8.40 @ `c13b6da34`) — the campaign's second
convergent round (after r42; r43/r44 broke convergence on a REAL
textual ambiguity that v8.40 resolved). Codex remains infra-blocked
(twenty-fourth documented attempt; usage-limit reset Aug 10 06:57
UTC) — 2-of-3 per the codex-infra-blocked exception, with the
retry ledger in `reviewer-ids.md`. The v8.41 folds are doc-level
only (one test assertion, three clarifying sentences, one §11
pointer refresh) with ZERO mechanism changes — re-reviewing a
doc-only fold is the infinite-regress the loop protocol terminates
on. **Verdict: PLAN-READY** (v8.41 is the convergence record).
