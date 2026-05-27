# #1296 reviewer task IDs

## Plan v1 review round 1 (commit 56fa22d11584fbd93267b679a50039a323c8fdbf)

- **Codex hostile plan review**: `task-mpnhvhnt-d8pfry`
- **AGY adversarial plan review**: `adversarial-review-mpnhwmkc-ce8q3k`

Dispatched 2026-05-26 03:18 UTC.

Plan expectation: PLAN-KILL is the high-probability outcome. Grounds:
1. Artifact's observed_cov=0.6700 ≤ cstruct+0.05=0.7253 = PASS by #1217 contract
2. equal-flow-enforcement + V8RateMode::EqualFlowSuppress + Prometheus + regime contract already shipped
3. Seven cross-worker mechanisms PLAN-KILLED on AF_XDP ZC physics
4. #1211 archive revisit criterion 1 (harness FAIL) not met

## Plan v2 review round 2 (commit 385934e6b)

- **Codex hostile plan review**: `task-mpnjv3mp-bw37nw`
- **AGY adversarial plan review**: `adversarial-review-mpnjvioo-t18ynf`

Dispatched 2026-05-26 21:36 UTC.

Plan v2 hypothesis: hybrid Option 2 (surplus-open + per-worker cap)
is implementable as a new `V8RateMode::EqualFlowWorkConserving`
variant. Acceptance gate is raw per-flow CoV ≤ 0.10 mean on
q2/q3/q6 fairness-eval runs with hybrid enabled.

### Outcome (2026-05-26, round-2): PLAN-KILLED ×2

Both reviewers landed PLAN-NEEDS-MAJOR with convergent fatal
findings that together amount to a PLAN-KILL for plan v2:

- **Codex (task-mpnjv3mp-bw37nw)**: blocking finding is enforcement
  layer mismatch. `acquire_v8` is the wrong boundary for #915
  surplus bytes; those bypass the per-queue lease and consume root
  tokens via `select_cos_surplus_batch` (queue_service/mod.rs:830).
  `tx_completion_tests.rs:60` has an explicit test asserting that
  the surplus phase must NOT free queue-lease headroom. Capping
  `acquire_v8` alone does nothing to cap actual surplus bytes.
  Also: #1304 alignment is false (#1304 docs explicitly reject
  work-conserving hybrid).

- **AGY (adversarial-review-mpnjvioo-t18ynf)**: AGY round-1 authored
  the hybrid argument; in round 2 it provided a worked numeric trace
  proving the design has a mathematical deadlock. Two simultaneous
  failures:
  1. If cap math reacts to donor demand, consumer is throttled BELOW
     its own primary share → work-conservation destroyed AND donor
     slack stranded.
  2. With donor demand naturally low, CoV is structurally pinned at
     ~0.47 by donor/consumer rate spread — ≤ 0.10 is impossible
     without strict-exact (which is the existing
     `EqualFlowSuppress`).

  Closing recommendation: "Pivot the implementation away from the
  speculative work-conserving hybrid, and focus purely on delivering
  the robust, non-work-conserving Phase 1 strict-exact equal-flow
  suppression as originally framed in #1304."

The user's explicit kill clause fires: "If implementation reveals
the egress-logical-cap framing is wrong … STOP and report rather
than push through." Hybrid Option 2 is mathematically deadlocked;
both reviewers agree.

## Outcome (2026-05-26, round-1, both reviewers landed)

- **Codex (task-mpnhvhnt-d8pfry): PLAN-NEEDS-MAJOR**
  Accepted Ground 1 (PASS by contract math) and Ground 4 (#1211
  criteria not met). Rejected Ground 2 ("Option 2 already shipped"
  is false as written) because compiler.go:432 makes
  equal-flow-enforcement mutually exclusive with surplus-sharing;
  the shipped feature is a non-work-conserving equal-flow
  suppressor. Ground 5 (hot-path atomic-free claim) overstated.
  Two acceptable endgames offered: PLAN-KILL the new mechanism as
  a product decision, or a small PR for structural-PASS
  labeling/verification under existing equal-flow mode.
- **AGY (adversarial-review-mpnhwmkc-ce8q3k): PLAN-NEEDS-MAJOR**
  Rejected PLAN-KILL outright. Walked the config wire end-to-end
  (no gap). Demonstrated with a worked 2-worker example that the
  hybrid Option 2 mode (surplus-open + total grant capped at
  `equal_flow_cap`) achieves CoV=0 with full class utilization
  where master strands 0.5*T capacity. Argued the AF_XDP-ZC
  physics ceiling blocks ingress packet steering, NOT logical
  egress rate caps inside acquire_v8.

Convergent finding: Option 2 is a genuine, valuable, AF_XDP-physics-
compatible refactor not covered by the existing kill chain.

Round-1 verdict reported back to parent for direction. No PR opened;
no PLAN-KILL label applied. The v2 plan (implement hybrid Option 2)
is a larger work surface than a fast-path triple-review can usefully
ratify in one round.
