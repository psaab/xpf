# Claude SMR plan review — round 37 — #6749 armed-state plan v8.32 (83b95df94)

**Reviewer:** Claude SMR (hostile; the r33 yellow-flag note stands
— a near-clean SMR verdict must be earned by the trace, and the
trace is below). Attack surface: the build-time digest capture,
the recovery fallback's missing-revision contract, the
single-renderer property, the rollback-window precision, the
§9 (a) renderer enforcement, and Q1 (37th enumeration).

**Verdict: PLAN-READY-WITH-NITS** — 0 BLOCKER + 0 MAJOR + 0
MINOR + 2 NIT. After the full hostile sweep, only two
statement-level nits survived. Codex remains infra-blocked
(sixteenth documented attempt).

---

## SMR37-1 (NIT) — the render determinism citation

The build-time capture's identity argument rests on the store's
`Format()` being deterministic for a given tree (the same-pair
staged reshape: T1's build captures, T2's build re-captures,
`s.active` is the same tree — the digests must be byte-equal).
The plan asserts it; the citation should name it (the store's
canonical `Format()` render is deterministic per tree (sorted
keys / canonical layout — the same property
`configTextDigest`'s own use in `ActiveApplied()` already
relies on), so two captures of the same revision are
byte-identical).

## SMR37-2 (NIT) — the stamp-skip phase's outcome naming

In the recovery-fallback's missing-revision path, the entry's
invalidation and push phases complete while the stamp phase is
skipped (missing source): the entry's terminal marking should
name the outcome (the stamp phase records
`skipped-missing-source` (a named phase outcome, Warn-edged at
the edge transition), the entry still goes terminal-completed
and GCs, and the marker heals on the next full apply) — so an
operator reading the cursor ledger can distinguish
"stamp skipped by missing source" from "stamp landed".

## Attack trace (what I tried, and why it fails to break v8.32)

1. **The capture point's Compile-window.** The promotion and
   the Compile both run inside the same `applySem` hold
   (`commitAndApply`), so `s.active` is the pair for the whole
   Compile — any capture point inside is the #6296 pattern.
   A failed pre-staging Compile never stages (the captured
   digest dies with the discarded object, never reaching a
   cursor). Coherent.
2. **The staged-object digest × the OVERLAP clear.** The clear
   discards the staged object and its digest together; the
   re-drive's rebuild re-captures from the same active pair —
   identical value. Coherent (given SMR37-1).
3. **The fallback × the terminal GC.** A cursor re-derived at
   startup with a rotated-out revision: empty digest ⇒ stamp
   skips with the edge Warn; the invalidation and push run
   (the pair's exposure is real and current); the entry goes
   terminal and GCs; the next full apply stamps from the
   then-current tree and heals `ActiveApplied()`. Bounded and
   visible. Coherent (given SMR37-2's naming).
4. **The renderer identity × the stage reshape.** One capture
   per build, one renderer (the store's `configTextDigest` of
   `s.active.Format()` at build time), so T1's and T2's
   staged digests for the same pair are byte-equal (SMR37-1's
   determinism); a manager-side re-render is never produced
   anywhere in the machinery. Coherent.
5. **The rollback window × the stamp's own path.** The
   rollback executor's apply is an ordinary serialized apply
   (its wrapper stamps on success via the #6296 captured form
   — the rollback's promotion leaves `ActiveApplied() == false`
   until that stamp — AGY f4's precision, now in the text).
   Coherent.
6. **Q1, thirty-seventh enumeration.** The v8.32 mechanics
   (build-time capture, the fallback contract, the
   single-renderer property, the rollback precision) mutate NO
   binding slots on any refuse/degrade path. No new
   `Registered && !Armed && state==none` producer. Q1 holds.
7. **The r36 disposition table.** Every row re-derived against
   the file: SMR36-1 (build-time capture + the fallback
   contract), SMR36-2 (the single-renderer property + §9 (a)
   enforcement), AGY f4 (the rollback precision + the r35
   row-2 amendment) — all present and correctly cited.
8. **The full-model residual sweep (carried from r33).** The
   cursor/stamp/digest machinery's cross-connections re-walked
   end-to-end (build capture → staged object → cursor install
   → notice/sweep drain → exposed-currency gate → captured-
   digest stamp → marker windows → GC/fallback) — no unwalked
   seam remains at MINOR or above.

## Required for convergence

Nothing mandatory. Optional for v8.33 (or `/engineer`-time):
SMR37-1's determinism citation; SMR37-2's outcome naming. AGY
r37 pending at this writing — its verdict may add to this
list (a DEMAND from AGY returns the loop to the fold).

**Verdict: PLAN-READY-WITH-NITS** (2 NIT — the attack trace
stands as the evidence this is not a soft pass).
