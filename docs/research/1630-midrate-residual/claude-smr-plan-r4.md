# Claude SMR plan-review — #1630 cause-2 — r4 (final)

Reviewer: Claude SMR (CoS-shaper / AF_XDP-drain / rate-accuracy domain).
Target: plan.md @ v5 (r4 amendments folded).
Posture: HOSTILE → **PLAN-READY as a measurement-first plan** once the
r4 amendments land (they do, in v5).

**VERDICT: PLAN-READY** (measurement-first; fix deferred to §5 outcome).

## Convergence at r4

Both external reviewers converged on the SAME three amendments:
- Codex r4: PLAN-NEEDS-MAJOR with three fixable gaps — (1) §5 missing the
  fifth-layer offered-load counter; (2) instrumentation-perturbation A/B
  not a gate; (3) stale H-WATERFILL/F-W1 text in §5/§10.
- AGY r4: PLAN-READY-with-amendments — (1) ingress offered-load counter;
  (2) cause-1+#1643 scope gating; (3) H-TCP L2 normalization.

These overlap exactly (offered-load + scope + normalization). v5 folds
ALL of them:
- §5.0 + counter 0: per-class offered/ingress bytes, gated FIRST (Codex
  #1 / AGY #1).
- §5.4: instrumentation-perturbation A/B as a HARD gate (≤0.5pp) (Codex
  #2).
- §5.1 counter 8: L2-normalized goodput (AGY #3).
- §6.1: ordered procedure — A/B gate → offered-load → ratios → fix.
- §5.2 / §10 / §11: stale H-WATERFILL/F-W1 "Expected primary"/"CANNOT be
  Phase-1-honored" text removed; H-TCP is the leading expected outcome;
  R5 scope-gates a cause-1-only PR (Codex #3 / AGY #2).

## Why this is a legitimate PLAN-READY

This is a /research deliverable, and the disciplined output when static
analysis falsifies every derived mechanism (timer-wheel, lease-target,
waterfill — all code-killed across r1-r3) is a measurement-first plan:
the instrumented bisection + decision table + acceptance gate + the
explicit list of dead hypotheses (so they are not re-chased). The fix is
correctly DEFERRED to the layer §5 names; the leading expected outcome is
H-TCP (loss outside the shaper), with §6.4 as the honest PLAN-KILL exit
if it is delivery/transport physics.

The plan does NOT over-claim: §10-R3 scopes it to the solo/4-class flat
residual (NOT the 11-class simul, which is #1614), and §10-R4/§6.4 admit
the residual may be a ~6% physics floor that 95% cannot reach for solo
mid-rate classes — the same honesty the cause-1 §12 fork reached.

## Residual nits (non-blocking)

- §2 still describes the waterfill data-path in detail; that is correct
  CONTEXT (it IS the drain path) even though the relegation mechanism is
  falsified — keep it as the verified spine.
- The §5 offered-load counter site (`ingest_cos_pending_tx` / queue push)
  should be pinned to an exact line at /engineer when the instrumented
  build is written; the plan names the site, which is enough for a
  /research doc.

PLAN-READY. The next step is `/engineer 1630` to run §5 (offered-load +
the four ratios) and design the fix for whatever layer it names.
