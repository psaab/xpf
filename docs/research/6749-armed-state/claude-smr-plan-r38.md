# Claude SMR plan review — round 38 — #6749 armed-state plan v8.33 (00d9567ae)

**Reviewer:** Claude SMR (hostile; the r33/r37 yellow-flag note
stands — a near-clean SMR verdict must be earned by the trace,
and the trace is below). Attack surface: the `complete-skipped`
terminal outcome, the Compile capture point, the determinism
citation, the §9 (a) GC assertion, the whole digest/stamp
machinery's end state, and Q1 (38th enumeration).

**Verdict: PLAN-READY-WITH-NITS** — 0 BLOCKER + 0 MAJOR + 0
MINOR + 2 NIT. After the full hostile sweep (including the
missing-revision skip's full reachability analysis), only two
statement-level nits survived. Codex remains infra-blocked
(seventeenth documented attempt).

---

## SMR38-1 (NIT) — the skip's dedup and the recovery-path count

The `complete-skipped` outcome is per-entry (ledgerID-keyed),
and two observations pin it cleanly: (i) a same-pair RESTAGE
cannot produce a second missing-revision skip —
`beginFirstExposure` returns `firstExposure=false` for the
re-exposure (the pair already exposed once), so no second
first-exposure cursor exists for the same pair-revision; and
(ii) the recovery fallback's skip count is bounded by the
number of concurrently-incomplete exposures at crash time
(the SMR26-4 handful) — each a DISTINCT pair, each earning
its own one-time Warn. Stated so the dedup question has a
written answer.

## SMR38-2 (NIT) — the skip case's self-consistency statement

The missing-revision skip is reachable ONLY in the
aged-out-AND-superseded window: (i) if the pair R is still
store-ACTIVE at recovery, `DigestOfRevision(R)` hits the
active tree (no skip — the stamp lands normally); and (ii) if
R is the exposed pair with a newer store-active-but-gated
successor, the exposed-currency gate admits R's stamp and the
retained tree almost certainly still holds it (the window is
minutes) — and when the successor later exposes, ITS own
apply stamps the then-current tree and the marker is correct
for the enforced config regardless. The skip's residue is
therefore exactly: the aged-out pair's own `ActiveApplied()`
is unreachable (its tree is gone from active) — and the
boot/current apply heals the marker for the CURRENT pair.
Stated.

## Attack trace (what I tried, and why it fails to break v8.33)

1. **The terminal forms set.** `complete-skipped` joins
   {complete, SUPERSEDED} as terminal — the claim releases and
   the outcome records in one `m.mu` op (the tri-state's
   claim-or-skip discipline is untouched), and the GC collects
   all terminal forms. Coherent.
2. **The Warn-once × the sweep.** The Warn fires at the
   marking (one `m.mu` op); the entry GCs on the next pass;
   no second drain of the entry exists (the pending set no
   longer contains it). Coherent.
3. **The capture point × the failure paths.** A Compile that
   fails after the capture but before staging (a shim
   compilation error) discards the value with the stack frame
   — no staged object, no cursor, no digest residue; a
   Compile that fails BEFORE the AST completes never captures.
   Both are cursor-free. Coherent.
4. **The digest's whole lifecycle, walked end-to-end.** Build
   capture (AST-success point) → staged object (carried) →
   OVERLAP-clear (discarded together) / catch-up install
   (copied into the cursor) / Compile-leg wrapper (same value)
   → exposed-currency gate (admission) → `MarkAppliedDigest`
   (lands) → `ActiveApplied()` windows (stated) → GC/fallback
   (terminal forms + the recovery contract). Every transition
   has a named owner and a terminal rule. Coherent.
5. **Q1, thirty-eighth enumeration.** The v8.33 mechanics
   (complete-skipped outcome, capture point, determinism
   citation, GC assertion) mutate NO binding slots on any
   refuse/degrade path. No new `Registered && !Armed &&
   state==none` producer. Q1 holds.
6. **The r37 disposition table.** Every row re-derived against
   the file: AGY f1 (the terminal outcome + §9 (a)), AGY f2
   (the capture point), SMR37-1/AGY f3 (the determinism),
   SMR37-2/AGY f4 (the naming + GC assertion) — all present
   and correctly cited.
7. **The full-model residual sweep (carried from r33/r37).**
   The digest/stamp machinery's cross-connections re-walked
   with the recovery paths included — no unwalked seam remains
   at MINOR or above.

## Required for convergence

Nothing mandatory. Optional for v8.34 (or `/engineer`-time):
SMR38-1's dedup note; SMR38-2's self-consistency statement.
AGY r38 pending at this writing — its verdict may add to
this list (a DEMAND from AGY returns the loop to the fold).

**Verdict: PLAN-READY-WITH-NITS** (2 NIT — the attack trace
stands as the evidence this is not a soft pass).
