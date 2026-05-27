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
