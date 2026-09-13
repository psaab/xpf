# KILLED — Design A: kernel-assisted adjudication (`RTM_GETROUTE` egress-zone lookup on the NoRoute slow path)

**Date:** 2026-09-13. **Decided by:** parent ruling after 4 hostile plan-review rounds.
**Branch:** `fix/9522-learned-route-cap`. **Artifacts preserved:** `docs/pr/9522/plan.md` (v1–v4),
`docs/pr/9522/reviews/round{1,2,3,4}-{astra,glm}-*.md` (8 raw reviews).

## Review trajectory

| Round | Astra (`openai-codex/gpt-6-astra`) | GLM (`zai/glm-5.3`) |
|---|---|---|
| 1 (chunked-verb v1) | PLAN-KILL (scoped: live clear-and-refill) | NEEDS-MAJOR |
| 2 (lookup Design A v2) | PLAN-KILL (scoped: counterfactual query, gate deletion, attestation) | NEEDS-MAJOR |
| 3 (mirror-query v3) | PLAN-KILL (scoped: mirror equality, uncertainty contract, doctrine) | NEEDS-MINOR |
| 4 (gated mirror v4) | PLAN-KILL (scoped: effective-hash admission, authoritative attestation, enforceable exclusion) | NEEDS-MINOR (R4-1/R4-2 doc-level) |

## Why killed (parent ruling)

4 rounds, 4 scoped Astra KILLs. The trajectory converged (each round strictly simpler; round-4
disagreement reduced to attestation-completeness attribution + hash-policy admission), but the
remainder needs **parent-approved weakened guarantees (G1 authorization freshness ≤ TTL) +
doctrine exceptions (G2 path E under v10)** that the parent will not grant to force agreement.
GLM's round-4 fixes (R4-1 `fib_multipath_hash_policy` admission, R4-2 per-build raw `FRA_*`
TLV walk) are recorded as correct and transferable if any future work revisits kernel-assisted
lookup — the failure is architectural confidence (Astra: "insufficiently characterized routing
oracle as real-zone authorization authority"), not effort.

## What survives for future work

- The reinject-mirror fidelity target (query the kernel's post-reinject RPDB walk, never
  operator intent) — proven by the tree's own #7409 MAIN-resolution vector
  (`tests_fragment.rs:826-841`).
- The `update_neighbors` envelope idioms, the capped-gate-as-fallback shape, tri-state
  absent=legacy skew handling, the linear-scan bound analysis (`fib.rs:428-431`, NoRoute
  uncacheable), and the measurement-first gate discipline (M1–M4 + census).
- GLM R4-1/R4-2 deltas, if lookup is ever revived.

## Re-scope

Design B (chunked/delta incremental route verb — the issue's PRIMARY direction) proceeds in
`docs/pr/9522-designB/` on this branch. Design A artifacts above are frozen, not deleted.
