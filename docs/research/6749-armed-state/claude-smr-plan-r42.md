# Claude SMR plan review — round 42 — #6749 armed-state plan v8.37 (6099e19f9)

**Reviewer:** Claude SMR (hostile; the yellow-flag note stands —
the trace below is the evidence). Attack surface: the
`contentConvergedRevision` comparator, the
accepted-lineage non-advance, the helper-lineage caveat, the
§9 (a) quiet-legs assertions, the r40 row amendment, and Q1
(42nd enumeration).

**Verdict: PLAN-READY-WITH-NITS** — 0 BLOCKER + 0 MAJOR + 0
MINOR + 2 NIT. After the full hostile sweep (including the
comparator's restart lifecycle and the note-CAS lineage
interplay), only two statement-level nits survived. Codex
remains infra-blocked (twenty-first documented attempt).

---

## SMR42-1 (NIT) — the marker's restart-window statement

`contentConvergedRevision` is in-memory and dies with the
manager process. The window between a manager restart and the
next dedup match: the deduped pairs' revisions exceed the
(re-seeded) `acceptedCommitRevision`, so the GO-LOCAL rule
fires ONCE per restart — the drain re-drives the full apply,
the rebuild dedups AGAIN (the content is still identical),
and the marker re-records — exactly ONE wasted drain cycle
per restart (the newest deduped pair's re-drive converges
every older deduped revision with it, since the comparator
is a max), bounded and self-correcting, Warn-visible at the
edge. The v8.37 text should say the marker is advisory and
rebuilds on the next dedup match (no persistence needed), so
an implementer does not invent a durable form for it.

## SMR42-2 (NIT) — the fence-untouched caveat

The session-admission fence (the helper's stored
`commit_revision` + the Go-side high-water) is untouched by
the dedup (no send): sessions continue under the old lineage
with IDENTICAL enforced content (the dedup match's whole
premise), so no session can be admitted under a policy the
helper is not enforcing, and no session is dropped by a
lineage the helper never saw. One sentence next to the
helper-lineage caveat.

## Attack trace (what I tried, and why it fails to break v8.37)

1. **The comparator across a real send.** A real (non-deduped)
   send's acceptance advances `acceptedCommitRevision` past
   the marker; `max()` keeps the comparator at the accepted
   value; a later dedup advances the marker again; the
   comparator never regresses (both operands are monotonic).
   Coherent.
2. **The note CAS lineage across the dedup.** The CAS's
   `expected_rev` reads `acceptedCommitRevision` (unadvanced
   by the dedup) — matching the helper's stored value — the
   idempotent-success arm; the next real send advances both
   sides in order. Coherent.
3. **The restage variant.** T1 deduped; T2 re-staged the same
   pair and ALSO deduped: the exemption is content-keyed (T2's
   hash matches too), T1's OVERLAP-cancelled cursor is dead
   per the standing rule, and T2's cursor owns the
   completion — and the marker advances to T2's revision
   (monotonic). Coherent.
4. **The drain-loop's absence under the rejected form, re-checked.**
   Had `acceptedCommitRevision` advanced (AGY's rejected form):
   helper-stored(old) < accepted(new) ⇒ the NONZERO
   helper-behind leg fires ⇒ the re-drive dedups ⇒ the
   condition persists — confirming the rejection was the
   right call (the loop moves instead of dying under that
   form; under the adopted form both legs read quiet).
   Coherent.
5. **Q1, forty-second enumeration.** The v8.37 mechanics
   (contentConvergedRevision, the comparator change, the
   helper-lineage caveat, the quiet-legs assertions) mutate
   NO binding slots on any refuse/degrade path. No new
   `Registered && !Armed && state==none` producer. Q1 holds.
6. **The r41 disposition table.** Every row re-derived against
   the file: SMR41-1 (the comparator + non-advance + caveat +
   §9 (a)), SMR41-2 (the restage variant), SMR41-3 (the §6
   precision), AGY f3 (the r40 row amendment) — all present
   and correctly cited.

## Required for convergence

Nothing mandatory. Optional for v8.38 (or `/engineer`-time):
SMR42-1's restart-window statement; SMR42-2's fence caveat.
AGY r42 pending at this writing — its verdict may add to
this list (a DEMAND from AGY returns the loop to the fold).

**Verdict: PLAN-READY-WITH-NITS** (2 NIT — the attack trace
stands as the evidence this is not a soft pass).
