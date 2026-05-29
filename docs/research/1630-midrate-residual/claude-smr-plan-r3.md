# Claude SMR hostile plan-review — #1630 cause-2 — r3

Reviewer: Claude SMR (CoS-shaper / WFQ-waterfill / oversubscription /
AF_XDP-drain domain).
Target: plan.md @ v3 (`aefb44520`).
Posture: HOSTILE.

**VERDICT: PLAN-NEEDS-MAJOR** (for any fix mechanism) → converge v4 to a
**MEASUREMENT-FIRST plan with NO pre-committed fix.** Codex r3
BLOCKING-1 is CORRECT and decisive: H-WATERFILL — the v3 leading
hypothesis — is FALSIFIED by code + arithmetic. AGY r3 returned
PLAN-READY but on a FALSE config assumption (see below). I side with
Codex on the evidence.

## Codex r3 BLOCKING-1 is correct (verified independently)

`quantum_sum` iterates `root.exact_queues_by_rate_ascending`
(`queue_service/mod.rs:789`), which is built ONCE at config-apply over
EVERY configured exact+guarantee queue (`builders.rs:80-83`,
comment "Built once at config-apply time; runtime is read-only"). There
is **NO nonempty/runnable guard** in the `quantum_sum` loop (verified:
`:787-800` has no `is_empty`/`continue`). So the Phase-1 budget is
`0.7 × quantum_sum(ALL configured exact classes)`, NOT
`0.7 × quantum_sum(eligible)`.

The smoke/solo harness applies the FULL `cos-iperf-config.set` via
`load merge` (`apply-cos-config.sh:73,140`) — all 10 exact classes
configured — and sends traffic to one (solo) or four (small-four) ports.
So in EVERY measurement config:
- full-config `quantum_sum = 2 651 076 B`, Phase-1 budget = `1 855 753 B`.
- empty queues are skipped in the Phase-1 WALK (`:811-816`) but still
  COUNT toward the budget.
- 3g quantum (75 000) and 6g quantum (150 000) are ≪ 1.85 MB ⇒ **3g/6g
  are Phase-1-HONORED every epoch in BOTH the truly-solo and 4-class
  runs.** They are NOT relegated to the non-parking Phase 2.

**Therefore H-WATERFILL does not explain the measured solo/4-class
residual, and F-W1 would be a no-op for it.** My v3 §3.2 boundary
arithmetic silently assumed `quantum_sum` was over the ELIGIBLE set; it
is over the STATIC config. That assumption is the v3 defect.

## Why AGY r3 PLAN-READY is wrong

AGY r3 §1 "confirmed" the boundary by writing "For a solo 3g class,
`quantum_sum = 75,000`." That is only true if the running CONFIG contains
ONLY 3g. The harness configures ALL 10 classes (`apply-cos-config.sh`
loads the full `cos-iperf-config.set`); traffic-solo ≠ config-solo. AGY
did not account for `exact_queues_by_rate_ascending` being static over
the configured set (the exact point of Codex BLOCKING-1). AGY's
PLAN-READY rests on a config assumption the test harness contradicts.
(AGY's §2/§3/§5/§6 — Phase-2-lossiness, counter separation, layering,
scope honesty — are independently fine; only the load-bearing §1 is
wrong, and it is load-bearing enough to flip the verdict.)

## The honest state after three rounds: every mechanism is falsified

| Hypothesis | Status |
|-----------|--------|
| Timer-wheel 50µs park floor (v1/v2 H-WHEEL/H7) | Demoted — park basis is `head_len` (~2µs), and 3g/6g in Phase 1 park on the wheel only briefly; not shown to be 6%. |
| Lease-target (H-LEASE) | KILLED (AGY r2 #6): epoch ceiling caps grant at `rate×200µs` regardless of `lease_bytes`. |
| Waterfill Phase-1 relegation (v3 H-WATERFILL) | KILLED (Codex r3 B1): full-config Phase-1 budget honors 3g/6g every epoch. |
| Integer truncation / grace / fair-share-solo | killed by arithmetic / single-worker (solo → total_flows=1 → no rounding). |

**No code-derived mechanism survives.** That is the actual finding: the
~6% mid-rate residual cannot be attributed to any specific shaper code
path from static analysis. This is exactly the situation where the
disciplined /research output is a **measurement-first plan**: ship the §5
instrumented bisection, run it on the free cluster, and let the four
ratios (phase1/phase2/drain_sent/goodput) NAME the layer — then design
the fix in a follow-up. The plan must NOT pre-commit a mechanism it
cannot derive.

## What v4 must do (converge)

1. **Re-scope to MEASUREMENT-FIRST.** The deliverable is the §5
   instrumentation + decision table, explicitly with NO pre-committed
   fix. State plainly: three mechanism hypotheses were code-falsified
   across r1-r3; the residual's layer is unknown and the bisection is the
   gate before any fix.
2. **Fix §3.2** — remove the false "solo 3g never Phase-1-honored" claim;
   replace with the CORRECT arithmetic (full-config budget honors 3g/6g)
   and note this FALSIFIES H-WATERFILL. Keep the waterfill walk as
   documented context, demoted to a measured falsifier (counter:
   phase1_honored for 3g/6g should be ~all if my correction holds).
3. **§5 stays the core deliverable** (it survives — Codex confirmed the
   counters; AGY confirmed the separation). Add: the FIRST thing the
   instrumentation must report is `phase1_honored_bytes` for 3g/6g — if
   ~all (per the correction), H-WATERFILL is dead at runtime too and the
   bisection moves to drain_sent/goodput.
4. **§6 fix becomes "deferred pending §5."** List the candidate fixes per
   measured layer (drain/TX/TCP/fair-share) but commit to NONE. The
   honest position is: the fix is unknown until the §5 numbers land.
5. **Keep §7/§9 layering** (verified by both Codex and AGY) as the
   composition contract for WHATEVER fix the measurement selects, with
   the caveat that a meter-side cause (fair-share) couples to the carry.
6. **§10-R3 scope honesty stays** (both reviewers endorsed it): this plan
   targets the solo/4-class flat residual, not the full-simul #1614
   failure.

## Verdict rationale

PLAN-NEEDS-MAJOR for v3-as-written (it asserts a falsified mechanism).
v4 converges to PLAN-READY **as a measurement-first plan** — the §5
bisection is sound, necessary, cheap, and is the only honest next step
when static analysis has falsified every mechanism. This is the same
discipline the cause-1 plan reached at its §12 fork: when the code can't
tell you, measure first. Do NOT ship a fix on a falsified hypothesis.
