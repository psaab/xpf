# Claude SMR hostile plan review — #6751 plan v15.12 (round 25 fold-check, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v15.12 folds AGY r25's
equal-generation CAS blocker, which is the kind of finding that
invalidates a whole class of "obviously correct" concurrency designs:
my r25 fold-check endorsed the generation-CAS with `>=` semantics
without tracing the generation ASSIGNMENT, and AGY r25 traced it and
found the admission path reusing the disconnect's generation. This
review owns that miss and verifies the two-discipline fix against the
slot lifecycle. Codex r25 was dispatched before AGY r25 landed and its
verdict is still in flight.

## Owning the r25 miss

My r25 fold-check said "the CAS IS the commit point; there is no
separate validation step to race." AGY r25's counterexample shows the
race is not in the CAS but in the ASSIGNMENT: C1's abort increments
the counter to g and its disconnect callback binds g; C2's admission
READS the same g without incrementing, so its connect callback also
binds g. Two callbacks for two different connections share one
generation. If C2's connect commits `(g, true)` first, C1's delayed
disconnect callback passes `g >= g` and overwrites the live state with
`(g, false)` — a stale disconnect flipping a live connect's state.
The `>=` rule was sound only under the assumption that distinct events
get distinct generations, and nothing in v15.11 guaranteed it.

## The two-discipline fix, verified

- **Discipline (i) — strict monotonic advance across admissions**:
  every lifecycle event (abort, ADMISSION, disconnect) draws a FRESH
  generation from the counter; a new slot's admission NEVER reuses the
  current value. Under this rule the AGY scenario cannot exist: C1's
  disconnect binds g, C2's admission binds g+1, and the disconnect
  callback (g) fails the monotonic check against any state written at
  g+1. This is the honest monotonic discipline — the counter is an
  event sequencer, not a connection attribute.
- **Discipline (ii) — strict-inequality CAS for value-flipping
  mutations**: for fields whose semantics are connected-state flips
  (`syncPeerConnected`, priming flags), a mutation commits only if
  `g_event > g_stored` — defense-in-depth so that even if a future
  change reintroduces a shared-generation path, an equal-generation
  stale write can never flip active state. Value-nonmonotonic
  transitions (true → false → true) remain free because the CAS orders
  by generation, not value.
- The two disciplines compose correctly: (i) prevents the collision,
  (ii) makes the collision harmless even if it recurs. The equal-
  generation overwrite case is pinned as a regression test.
- AGY's minor 2 (outboundBulkAcked / inboundBulkAcked at sync.go:479)
  is a genuine inventory gap — those flags are lifecycle state set
  during bulk ACK processing and belong under the same CAS discipline.
  Folded.
- AGY's nit 3 (the 4+3 counter taxonomy) is folded as an explicit
  enumeration in §5.8.

## Attacks attempted

- Does discipline (i) break the abort-generation's other uses (clause
  (4) frame validation, slot stamps)? The counter now advances on
  admissions too, so slot stamps and frame generations draw from the
  same monotonically advancing sequence — an admission advancing the
  counter does NOT invalidate frames from OTHER live slots (their
  generations are older but their slots are still admitted and no
  fence is set — clause (4) checks staleness relative to the ABORT
  events of their own slot lineage, not the global counter). This
  must be stated precisely in §5.6: clause (4)'s guard compares a
  frame's slot-lineage generation against the abort generation
  relevant to that slot, not the global maximum, so a routine new
  admission elsewhere does not poison live slots. (One-line
  clarification folded.)
- Does the strict-inequality rule deadlock the disconnect callback
  that must write `false` at the SAME generation as an abort it
  belongs to? The abort event itself advances the counter to g and
  the disconnect's write binds g+1 (the disconnect is a distinct
  event from the abort that caused it) — so no self-blockage. Verified
  against the discipline-(i) assignment rule.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.12. The
lifecycle CAS is now linearizable by construction (strict event
sequencing for assignments, strict inequality for value-flips), the
inventory covers the bulk-ack flags, and the counter taxonomy is
explicit. If Codex r25 converges, this is terminal.
