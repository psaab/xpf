# Claude-SMR hostile plan review — #1751 count-balance, round 2

Verifying the v3 plan after both Codex r2 and AGY r2 independently landed the SAME
remaining blocker (the convergence proof) and the SAME fix (sum-of-squares).

## Verdict: PLAN-READY

All four round-1 findings are folded, and the one round-2 blocker (convergence
proof) is now correct. I re-derived the sum-of-squares result independently to
confirm v3 is right, not just plausible.

### Convergence proof (v3) — independently re-derived, CORRECT
Potential `Ψ = Σ_w (counts[w] - μ)²`, `μ = N/Nᵥ` (any real). A move
`c_hi → c_hi-1`, `c_lo → c_lo+1`:
```
ΔΨ = (c_hi-1-μ)² + (c_lo+1-μ)² - (c_hi-μ)² - (c_lo-μ)²
```
Expand `(x-1)² - x² = -2x+1` with `x=(c_hi-μ)`, and `(y+1)² - y² = 2y+1` with
`y=(c_lo-μ)`:
```
ΔΨ = (-2(c_hi-μ)+1) + (2(c_lo-μ)+1) = 2 - 2(c_hi - c_lo)
```
The `μ` terms cancel — **the result is mean-independent**, which is exactly what
defeats both the L1 fractional-mean counterexamples (Codex `[2,2,2,2,0]`, AGY
`[2,2,1,1,1,0]`). With the overshoot guard `c_hi - c_lo ≥ 2`: `ΔΨ ≤ -2 < 0`.
Equivalent to AGY's uncentered `Φ = Σc_w²` form (`ΔΦ = 2(c_hi-c_lo-1) ≥ 2`) since
the two differ by the constant `Nᵥ·μ²`. `Ψ ≥ 0`, strictly drops by ≥2 each
admitted move ⇒ termination in `≤ Ψ₀/2` moves. v3 §3.4 states this with the
worked `[2,2,2,2,0]` check (3.2→1.2, ΔΨ=-2.0) — verified correct. The stale §3.2
"reduces max-min" line is also fixed to point at SoS. **PLAN-READY on this axis.**

### Cross-checks on the other findings (re-verified in v3)
- §3.1/§2.4: count is unambiguously over post-filter steerable `FlowSample`s;
  the no-staleness-guard honesty is explicit and consistent across §2.4/§6.2/risk
  table. ✓
- §4.3: #1735 phrasing precise (eager exact/shared_exact vs lazy non-exact),
  matches master, confirmed by all three reviewers independently. NOT-A-KILL on
  #1203 stands. ✓
- §10 item 1: pre-code CoS-ON manual re-pin gate present as the decisive cheap
  de-risk. ✓
- §3.3.1 + unit test for the unsteerable-count divergence; destination-overload
  follow-up documented. ✓

### Convergence of all three reviewers
Round 2 produced a clean convergence: Codex (NEEDS-MINOR, sum-of-squares) + AGY
(NEEDS-MINOR, sum-of-squares, independent counterexample) + Claude-SMR — all on
the SAME single point with the SAME fix, now applied. No reviewer holds an open
blocker against v3. The #1203 KILL-risk is resolved NOT-A-KILL with code-grounded
evidence and gated by a cheap pre-code measurement. **PLAN-READY.**
