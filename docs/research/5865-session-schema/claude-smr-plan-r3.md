# Claude SMR — plan review r3 (#5865)

Reviewing `plan.md` v4 @ `24ba06dfd4fd`. v4 folds Codex r2's REVISE. Hostile pass
on whether v4 converges.

## Verdict: PLAN-READY (Phase 1 + Phase-2-contract-as-follow-up) — 1 nit to fold

v4 resolves the r2 REVISE. The producer inventory is now accurate (P0–P5, with the
corrected P4 since-threshold / ABI-field-hardcoded-0 / NAT64-absent nuances), the
severity is correctly restated as a *persistent* degraded standby copy, Phase 1 is
a bounded and safe unit, and Phase 2 is a complete invariant contract properly
scoped as a dedicated follow-up. The phased convergence is the right research
outcome for what has proven to be a resync-protocol redesign, not a bounded bug.

## R2 items — addressed

- Producer model corrected (P0 added; P3 dual-emit + auto loss-resync; P4/P5
  reclassified). ✓
- Phase-2 safety: lost-OPEN backfill required **before** suppressing P4 (§7.1);
  full-SET resync with stale-key deletion + empty-set + ACK-before-readiness
  (§7.2); off-read-loop execution (§7.3); incarnation token as an explicit wire
  decision (§7.4). ✓
- Capability gate completed: attests the full projection, gates binary
  OPEN/UPDATE + JSON, default-closed, connection-bound, drain-before-pop,
  readiness latch, source→target propagation, node-to-node ISSU (§8). ✓
- Export fail-closed via `ok=false` + per-worker accounting (dropped-counter is
  not a completeness certificate). ✓
- Tests: typed projection, OPEN-only binary parity + JSON-CLOSE + unchanged
  binary-CLOSE, `nat64` marker separate, resurrection matrix, overflow/backfill/
  lost-CLOSE/empty-set/owner-RG, whole `SessionValue`. ✓

## Nit (fold into v5) — Phase 1 overflow should fail closed to durable-unready, not escalate to P0

§6.4 recommends a permanently-over-4096 binding "escalate to the binary bulk
export (P0)." But §3/§7.2 establish that **P0 is OPEN-only** — a lost CLOSE leaves
a stale peer key, and empty-bulk skips stale reconciliation. So escalating Phase-1
overflow to P0 inherits P0's incompleteness and **drags a Phase-2 correctness
concern (full-set reconciliation) into Phase 1**, breaking Phase 1's "bounded"
property. For Phase 1 to stay self-contained and honest, overflow should
**fail closed to durable unready** (refuse to claim a complete resync it cannot
deliver) and let Phase 2 introduce the complete full-set export as the escalation
target. Change §6.4's recommendation from "escalate to P0" to "durable unready;
Phase 2 adds the complete-export escalation."

## Stress-tested and sound

- **Phase 1 self-containment.** The capability field + gate ship in the same .deb
  as the helper, so a current helper reports it and passes; the gate only bites on
  genuine version skew — no regression to the normal single-node upgrade. The
  typed-projection refactor of the binary encoder is a pure byte-identical
  refactor guarded by the wire fixture + golden test.
- **Node-to-node deferral.** Phase 1 changes only the helper↔daemon JSON; the
  node-to-node wire already length-gates the fields, so deferring node-to-node
  semantic capability to Phase 2 introduces no Phase-1 gap.
- **Phase-2 as follow-up.** §7 is a genuine, complete requirements contract — not
  hand-waving — so splitting it is a real scoping decision, not a soft pass.

## Required for PLAN-READY

Fold the §6.4 overflow nit (durable-unready, not P0 escalation). Then Phase 1 is a
clean, bounded, mergeable unit and Phase 2 is a well-seeded follow-up. Pending
Codex r3 concurrence on the phased convergence.
