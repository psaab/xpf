# AGY adversarial plan re-review — #1751 count-balance, round 2

Job: adversarial-review-mpxf8o8j-wytenk (succeeded). Verifying v2 fixes.

## Verdict: NEEDS-MINOR (independently found the SAME convergence hole as Codex r2)

1. **§3.4 Convergence — DEFECT VERIFIED (fractional-mean hole).** Independent
   counterexample (N=7, W=6, μ=7/6≈1.167): `c=[2,2,1,1,1,0]`, `c_hi-c_lo=2`
   admitted, move 0→5 gives `[1,2,1,1,1,1]`; source crosses the fractional mean;
   L1 `Ψ` drops `20/6≈3.333 → 10/6≈1.667`, ΔΨ=1.667 < 2. **Fix: sum-of-squares
   `Φ=Σc_w²`**; for admitted `c_hi-c_lo≥2`, `ΔΦ = 2(c_hi-c_lo-1) ≥ 2`
   unconditionally, independent of fractional mean. (Identical to Codex r2's
   prescription and to the centered `Σ(c_w-μ)²` form — mean cancels.)

2. **§3.1/§2.4 steerable count + staleness disclaimer — INTERNALLY CONSISTENT.**
   Post-filter steerable `flows` ensures the `hi` source has a movable flow
   (no `NoEligibleFlow`); not comparison-gating against raw count avoids the
   #1750-r2 stale-snapshot livelock; dwell(2)+cooldown absorb publish lag.

3. **§4.3 #1735 phrasing — VERIFIED CORRECT vs master** (`cos/admission.rs:525-529`
   eager-exact `FlowFairState` alloc, non-exact `None`; `flow_fair()` is
   `is_some()` → MQFQ pop).

4. **§10 item 1 pre-code manual re-pin gate — SOUND.** Isolates scheduler from
   controller; verifies post-#1735 shared_exact MQFQ hits the CoV floor before
   any controller code.

**Final: NEEDS-MINOR** — quoted evidence: "neither overshoots the mean, so each
admitted move strictly decreases `Ψ` by ≥ 2" (plan.md:254-255, v2).

## Resolution (v3)
v3 adopts sum-of-squares exactly as AGY (and Codex r2) prescribed. Both
reviewers' final blocker was the same single point; v3 closes it.
