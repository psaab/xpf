# Codex hostile plan re-review — #1751 count-balance, round 2

Session: CODEX_COMPANION_SESSION_ID=research-1751-r2-* (codex-cli 0.135.0,
read-only). Verifying the v2 fixes to the 4 round-1 findings.

## Verdict: PLAN-NEEDS-MINOR (3 of 4 fixed; convergence proof still had a hole)

1. **#1203/#1735 — FIXED.** §4.3 now says exact + shared_exact promote eagerly,
   non-exact lazily; runtime pop dispatch keys off `flow_fair_state.is_some()`
   (plan §4.3). Matches master: admission allocates `FlowFairState` for exact
   queues, leaves non-exact `None`; `flow_fair()` is `is_some()`; pop FIFO is only
   `!flow_fair()`.

2. **Count/rows atomicity — FIXED.** §2.4 + §3.1 require post-filter steerable
   rows only, reject the Prometheus atomic for decisions, and explicitly say
   Path A has no snapshot-age staleness guard (plan §2.4, §3.1, §6.2).

3. **Convergence proof — STILL WRONG (v2).** Two issues: §3.2 left the stale
   line "guarantees each admitted move strictly reduces max-min"; §3.4 overclaims
   "neither overshoots the mean / decreases Ψ by ≥2" for the L1 potential.
   Counterexample: `[2,2,2,2,0]`, N=8, V=5, mean 1.6; the admitted move `2→0`
   makes the source `1` (below mean) and L1 drops only `3.2 → 2.4`, not by ≥2.
   **Fix: use sum-of-squares**, where `delta ≥ 2` gives a clean strict decrease
   (the mean cancels), or a floor/ceil excess-deficit potential.

4. **Live gate — FIXED.** §10 item 1 is the decisive cheap pre-code CoS-ON manual
   re-pin gate (run first, CoS loaded, -P12 -p5210, scope-split on ~3-4% vs ~50%).

**Final: PLAN-NEEDS-MINOR — #1 yes, #2 yes, #3 not yet, #4 yes.**

## Resolution (v3)
v3 rewrote §3.2 + §3.4 to the **sum-of-squares** potential `Ψ = Σ(counts[w]-μ)²`
with the worked `ΔΨ = 2 − 2(c_hi − c_lo) ≤ −2` derivation (mean cancels), and
verified it against BOTH counterexamples (`[3,3,3,3,1,1,1,1]` and `[2,2,2,2,0]`:
SoS 3.2→1.2, ΔΨ=−2.0). AGY r2 independently reached the identical fix.
