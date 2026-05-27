# #1326 Phase 2+ — reviewer verdicts (PLAN-KILL × 2)

Both reviewers PLAN-KILLED on round 1 with quote-grounded evidence.

## AGY r1 (`review-mpnhty2a-865y0o`) — PLAN-KILL

> After a hostile, quote-grounded, and read-only analysis of the
> master branch (`e07f733a6`) and the proposed plan at
> `docs/pr/1326-worker-loop-phase2/plan.md`, the **PLAN-KILL**
> recommendation is **correct, sound, and fully ratified**.

Key findings:

- Perf-top granularity vs `#[inline]` contradiction stands.
- 11 phases tightly order-coupled; no reordering, hoisting, or
  batching possible.
- `WorkerLoopState` bundle would lock all 30+ fields mutably;
  typed sub-bundles do not rescue because dependencies cross-cut.
- Same architectural pattern as #946 Phase 2 PLAN-KILL.
- The `DBG_REPORT_INTERVAL_NS` throttle on BindingLive atomics is
  intentional (avoids L1 line-bouncing with monitoring daemon),
  not a bug.
- No concrete future-edit scenario where Phase 2 measurably helps.

## Codex r1-retry (`task-mpnhx2ga-7lerzp`) — PLAN-KILL

Note: original `task-mpnhtpl2-jd5l99` returned INFRA-BLOCKED
(codex-linux-sandbox missing). Per repo policy
[[feedback_codex_infra_must_retry]], retried with plan + code
pasted inline.

Key findings:

1. Perf-top win is contradictory (§3a vs §5c).
2. Phase boundaries are not clean — forwarding-refresh block
   (L282-L405) mutates ~10 separate pieces of state, "Arc refresh"
   is a misleading helper name for it.
3. Borrow-shape objection stands; typed sub-bundles don't help
   because the same mutable state is shared across most phases.
4. **New finding (not in plan v1):** `ha_runtime = ha_state.load()`
   snapshot is reused by `apply_worker_commands` AND `poll_binding`
   in the same tick. A split design must preserve this single
   snapshot — reloading in `commands.rs` AND `poll_drive.rs` would
   be a subtle ordering regression.
5. **Correction:** §7e said the throttle was ~5s. It's actually 1s
   (`DBG_REPORT_INTERVAL_NS = 1_000_000_000`). Substantive point
   stands; cadence number was wrong.
6. Architecturally weaker than #946 Phase 2 (no semantic batching
   proposed) but same "name stages over an order-coupled body" smell.
7. Cannot name a concrete future edit that Phase 2 measurably helps.

> PLAN-KILL stands.

## Combined outcome

Both reviewers independently verified the plan author's KILL
recommendation. No reviewer found a concrete counter-example.
Phase 1 (PR #1569) is the final shipped scope for #1326.

Issue #1326 should be closed wontfix-with-rationale. The branch
`refactor/1326-worker-loop-phase2` is preserved at the plan-KILL
commit as historical record.
