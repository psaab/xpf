# Reviewer ledger — #5837 research plan

Plan: docs/research/5837-xdp-dnat-before-local/plan.md
Branch: research/5837-xdp-dnat-before-local
Base: origin/master 7d2cd112fec4
Plan committed at: 36f830996db4

## Round 1
- Codex (codex:codex-rescue): dispatched
- AGY (agy:agy-rescue): dispatched
- Claude SMR: docs/research/5837-xdp-dnat-before-local/claude-smr-plan-r1.md

## Round 1 outcomes
- AGY: INFRA-BLOCKED. The `agy` headless CLI auto-denies its internal `command`
  permission and produces no output even with `--dangerously-skip-permissions`
  (retried 3×: plain, +skip-permissions, +no-sandbox+skip-permissions — identical
  "jetski: no output produced" each time). Root cause is the agy runtime in this
  environment, not the plan. Per the research skill's infra-block exception, proceed
  2-of-3 (Codex + Claude SMR); AGY alone is never enough and it is not being relied
  on as the sole reviewer here.
- Claude SMR: REVISE (r1) — B1 resolved favorably on self-verification, B2 downgraded,
  B3 stands. See claude-smr-plan-r1.md.
- Codex: pending.

## Round 2
- Plan revised to v2 @ e17c2676d969.
- Codex: re-review dispatched (resumed agent, r1 context preserved).
- AGY: still infra-blocked (no retry — environmental).
- Claude SMR: PLAN-READY (r2) — claude-smr-plan-r2.md. New-map rollout re-verified safe
  (validateUserspaceShimLivePins skips absent pins). 3 non-blocking clarifications.

## Round 3
- Plan revised to v3 @ bd1dbbfb9209 (concrete impl spec + loud diagnostics + factual fixes).
- Codex: r3 re-review dispatched (resumed).
- AGY: infra-blocked (environmental; not retried).
- Claude SMR: PLAN-READY (r3) — claude-smr-plan-r3.md. All Codex r2 fixes code-verified.

## Round 4
- Plan revised to v4 @ a36aac626b37 (rollback-safe txn, IPv6-AH guard, restart reconcile, mandatory pins).
- Codex: r4 re-review dispatched (resumed). At r3 it accepted the architecture + verifier bounding for a research plan.
- AGY: infra-blocked (environmental).
- Claude SMR: PLAN-READY (r4) — claude-smr-plan-r4.md. All Codex r3 fixes code-verified incl. IPv6-AH regression.

## Round 5
- Plan revised to v5 @ 16fd7f6c83cf (degraded-path closure §5e, AH-before-session-hit §5a,
  gen-safe delete §5d, capability bitmask §5c, §13 research/impl boundary).
- Codex: r5 re-review dispatched (resumed).
- AGY: infra-blocked (environmental).
- Claude SMR: PLAN-READY (r5) — claude-smr-plan-r5.md. All 3 material Codex r4 findings
  (degraded-path, AH ordering, gen-safe delete) code-verified + resolved. Residual = impl-execution per §13.

## Round 6
- Plan revised to v6 @ 5192b6057915 (closes Codex r5's six design blockers: strict txn order,
  intent_authoritative gate, ingress-iface proof, disarmed-refresh publish-before-accept,
  reclaim-targets-exact-both, absent/legacy capability semantics).
- Codex: r6 re-review dispatched (resumed). At r5 it CLOSED architecture + verifier bounding +
  AH + gen-race + pins + availability, leaving 6 concrete design blockers (now closed).
- AGY: infra-blocked (environmental).
- Claude SMR: PLAN-READY (r6) — claude-smr-plan-r6.md. All 6 Codex r5 blockers resolved + code-verified.

## Round 6 → CONVERGED (PLAN-KILL of drive-by + Track-1 warning)
- Codex r6: REVISE, MATERIAL — disproved 2 of v6's closures (intent_authoritative doesn't
  fail-closed for a missing/failed-insert key; ingress-interface proof factually wrong) + surfaced
  an unaddressed HA-failover generation-safety dimension (first-order for an HA firewall) + worker-
  visible publication ordering + defer_workers new-plan path + capability boot-timing.
- Claude SMR r6: self-corrected PLAN-READY → concur PLAN-KILL-of-drive-by (SMR-soft-pass pattern:
  I closed findings faster than truly closed). claude-smr-plan-r6.md.
- AGY: infra-blocked every round.
- CONVERGED VERDICT (plan v7 §0): PLAN-KILL the drive-by dataplane fix (verifier make-or-break
  unvalidated + growing surface, tail-call forbidden; fail-closed-incomplete-state + HA-failover
  generation-safety genuinely unsolved) → ship the Track-1 commit-time WARNING (§0a, tiny, zero
  verifier risk, makes the silent bypass loud) → Track-2 full Option-B fix deferred as a scoped,
  verifier-gated, HA-aware project (§0b lists the 6 remaining hard problems). Matches the team-
  lead's explicitly-blessed PLAN-KILL-with-pragmatic-fallback.
