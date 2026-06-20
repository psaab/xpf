# Claude SMR — Hostile Plan Review r9 — #2079

Reviewing plan.md r9 after folding AGY r8's PLAN-REVISE (HelperCaughtUp predicate
fix).

## Verdict: PLAN-READY

AGY r8 caught a real bug in my own r8 `HelperCaughtUp` definition, and the r9 fix
is correct. I verified the underlying generation-tracking against source.

- **HelperCaughtUp invariant:** Verified `m.lastSnapshot = snap` is set in the
  deferred-startup path (`manager.go:648`) while `m.publishedSnapshot` is advanced
  separately (`manager.go:699/805/958/1312`) — so `lastSnapshot.Generation` can
  LEAD `publishedSnapshot`. Since `view.Config = m.lastSnapshot.Config` (the
  leading gen), r8's `status == publishedSnapshot` (lagging) could be TRUE while
  config is a newer gen → skew. r9's `HelperCaughtUp := status.LastSnapshotGeneration
  == view.Generation` (= `m.lastSnapshot.Generation`) ties the caught-up check to
  the SAME gen as `view.Config`, so `numericEval` is true only when the helper
  counters are for exactly the config being evaluated. Correct invariant. RESOLVED.

## Corroboration
The fresh-session Codex r7-retry returned a full 12-point PLAN-READY on r7 (the
base for r8/r9) — independent validation that every other dimension
(rule-referenced eligibility, dedup, comparators, HOLD semantics, prune, lock
discipline, both render sites, commit validation, uint arithmetic) is sound. The
only open thread after that was the apply-window gen-coherency, addressed by
r8's coherent view + r9's predicate fix.

## Independent re-trace of r9
- Single coherent view; `view.Generation` is the gen of `view.Config`. ✓
- `HelperCaughtUp == (status gen == view.Generation)`; numericEval gates per-pool
  numeric eval; prune unconditional. ✓
- `Available==false` → HOLD-all; cfg nil / disabled → clear-all + return. ✓
- Eligibility rule-referenced; dedup in view; raise `>=` / clear strict `<` /
  else-if updatePct; lock discipline; both render sites; commit validation; uint
  cast. ✓

## New issues from r9 — none
The predicate change is a one-symbol fix (publishedSnapshot → view.Generation)
that makes the same-generation invariant exact. No new surface.

## Convergence assessment
Findings have moved from the monitor-loop layer (r2-r6) to the commit/apply
ordering layer (r7-r9), and the r9 fix closes the last generation-coherency edge.
The fresh Codex r7-retry's clean 12-point pass + AGY's progression to a
single-predicate fix indicate the plan is at its fixed point. PLAN-READY.
