# Claude SMR hostile plan-review — #1630 cause-2 — r2

Reviewer: Claude SMR (CoS-shaper / token-bucket / AF_XDP-drain /
WFQ-waterfill domain).
Target: plan.md @ v2 (`66c9043cc`).
Posture: HOSTILE + **self-correcting a decisive r1 error.**

**VERDICT: PLAN-NEEDS-MAJOR.** Codex r2 BLOCKING-1 is CORRECT and my r1
"reject BLOCKING-2 as hallucination" was WRONG. The waterfill drain path
EXISTS on origin/master, and it is almost certainly the cause-2
mechanism. v2 is built on the wrong drain path and must be rewritten to
v3 around the waterfill selector.

## The r1 error (mine and the agy-r1 doc), fully owned

In r1 I "verified" that no waterfill drain path exists by grepping
`userspace-dp/src/`. **That grep ran against the main checkout
`/home/ps/git/bpfrx` at detached HEAD `e01472f4a`** (the session-start
HEAD), which PREDATES the #1614 A1 waterfill merge. The research worktree
and origin/master are at `0e5bb3812`, which DOES contain
`select_exact_cos_guarantee_queue_waterfill`. This is exactly the
MEMORY-documented "grep the wrong tree" failure
(`feedback_wire_protocol_both_sides` cousin). I incorrectly told Codex it
hallucinated; Codex was right in BOTH r1 and r2.

Verified now against the WORKTREE (`66c9043cc`, == origin/master tree):
- `queue_service/mod.rs:603-614`: `if GuaranteeRate && fraction > 0.0 {
  return select_exact_cos_guarantee_queue_waterfill(...) }`.
- `select_exact_cos_guarantee_queue_waterfill` at `:771`, two-phase:
  Phase 1 ascending honored set with budget `quantum_sum × fraction`
  (`:787-799`), Phase 2 descending residual that **explicitly does NOT
  park** (`:973-977` "Don't park in Phase 2 … best-effort residual, not
  a guarantee").

The smoke config is `guarantee-rate 0.7`, so 3g/6g traverse the
WATERFILL selector, NOT the legacy RR path v2 §2.4/§3 modeled.

## The new mechanism this exposes (the likely real cause 2)

The §3.6 measurement that isolated cause-2 ran the 4-class
small-four-alone AND truly-solo single-port harnesses. Computing the
Phase-1 boundary for those configs (arithmetic, fraction 0.7):

- **solo 3g**: `quantum_sum = 75000`, Phase-1 budget = `0.7 × 75000 =
  52500`. 3g's quantum 75000 > 52500 ⇒ **3g is NOT honored in Phase 1**
  (the `candidate_budget > pass1_remaining` break at `:889` fires
  immediately). 3g is served only in Phase 2 — the NON-PARKING
  best-effort residual.
- **solo 6g**: `0.7 × 150000 = 105000 < 150000` ⇒ same; 6g not honored
  in Phase 1.
- **4-class small-four-alone**: Phase-1 honors 100m/1g/3g, boundary at
  **6g** (quantum 150000 > remaining 74250).

So the effective guaranteed budget for a boundary/solo class is
`fraction` (=0.7) of its quantum per epoch; the residual `(1−fraction)`
rides Phase 2, which does not park and is "best-effort, not a
guarantee." **This is a fixed fractional shortfall set by
`guarantee_fraction`, independent of K (cause 1), P2 (selector frame
cap), and contention** — precisely the P1/P2/P3/P4 signature of the
measured residual. The ~6-7% is plausibly the Phase-2 inefficiency on
that residual 30% (Phase 2 doesn't park, so it serves opportunistically
when root tokens + bucket allow, losing whatever it can't place that
epoch).

This mechanism is FAR more consistent with the measurement than the
timer-wheel: it is structurally flat (a fraction), it is exactly what
`guarantee-rate 0.7` introduced (the regression appeared with #1626/#1629
activating the knob — the issue title literally says "under
guarantee-rate 0.7"), and it explains why the carry (cause 1) and the
frame cap (P2) don't move it.

## Concurrence with Codex r2

- **BLOCKING-1 (waterfill exists) — CONCUR, decisive.** Self-corrected.
- **BLOCKING-2 (F-E worker-share busy-poll) — CONCUR.** `class_granted <
  cap` is class-wide; a worker can be share-exhausted
  (`my_consumed >= my_effective_share`, `mod.rs:1081`) with class room
  remaining and obtain NO new grant until rotation. F-E would busy-poll.
  But F-E is moot now — the fix target is the waterfill Phase-1 budget,
  not the wheel.
- **BLOCKING-3 (bisection contamination) — CONCUR + sharpened.** With the
  waterfill path, `total_granted < cap_granted` is EXPECTED by design for
  a boundary class (Phase-1 only grants `fraction × quantum`); it is NOT
  a drain-park signal. The bisection must be re-derived around the
  waterfill Phase-1-vs-Phase-2 split, not the legacy park counters.
- **MAJOR-1 (max_total_leased formula) — CONCUR.** `max_total_leased =
  min(burst/4, max_frame_lease×active_shards)` (`mod.rs:713-715`), not
  `burst/4` flat. v2 §6/R4 wording wrong.
- **MAJOR-2 (H-TCP byte normalization) — CONCUR.** `goodput/drain_sent`
  needs L2/header normalization; `drain_sent` is frame bytes,
  `cos_item_len` counts `req.bytes.len()`/`req.len`.

## What v3 must do (major rewrite)

1. **Re-ground §2 + §3 on the waterfill selector** (`:771`), not the
   legacy RR. The leading hypothesis becomes **H-WATERFILL**: a
   solo/boundary mid-rate exact class is honored for only `fraction ×
   quantum` per epoch in Phase 1, with the residual on the non-parking
   Phase-2 best-effort path → fixed fractional loss ≈ `(1−fraction)` ×
   (Phase-2 inefficiency). Show the boundary arithmetic for solo 3g/6g
   and the 4-class harness.
2. **Re-derive §5** around: per-class Phase-1-honored bytes vs Phase-2
   bytes vs not-served bytes per epoch; whether the residual rides Phase
   2 and how much Phase 2 actually places. The counter that matters is
   "fraction of the class's quantum served in Phase 1 vs Phase 2 vs
   dropped," not the wheel park histogram.
3. **Replace the fix mechanism.** Candidates: (a) make the Phase-1 budget
   per-class-rate-proportional so a solo class gets its FULL quantum
   honored (the fraction should bound CROSS-class oversubscription, not
   shrink a single class below its own rate); (b) make Phase 2 a real
   guaranteed pass for exact classes (park-capable) so the residual is
   not best-effort; (c) re-examine whether `quantum_sum × fraction` is
   the right Phase-1 budget at all when the eligible set is a single
   class. This is squarely the #1614 oversubscription allocator — the fix
   may be a genuine scheduler change, NOT a one-line wheel tweak.
4. **Reassess seqlock/layering (§9):** the waterfill state
   (`waterfill_pass1_remaining_bytes`, `waterfill_phase2_cursor`) is
   per-`CoSInterfaceRuntime` (per-binding, single-worker) — verify it is
   NOT shared/seqlock'd, so the cause-2 fix is still drain-layer and
   composes with the cause-1 meter change.
5. **Keep H-TCP and H-LEASE as secondary** — but the waterfill Phase-1
   truncation is now the prime suspect, and the §5 measurement should
   test it FIRST (it is checkable from the existing waterfill state +
   per-phase byte counters).

## Process note

Both AGY r1 and agy-r1.md carried my wrong "no waterfill" framing; v3
must correct the agy doc too. The r1 round's "reject BLOCKING-2" is
formally retracted.
