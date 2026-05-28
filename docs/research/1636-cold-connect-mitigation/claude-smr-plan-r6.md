# Claude SMR plan review — round 6 (#1636)

**Plan reviewed**: `docs/research/1636-cold-connect-mitigation/plan.md` v6 @ `268fb607243a`.

## Verdict: PLAN-READY (with AGY r6 findings to fold for AGY convergence)

Status across reviewers at end of r6:
- Codex r6: **PLAN-READY** (one nit on pseudocode unused max_retrans)
- AGY r6: PLAN-NEEDS-MINOR (4 findings, two medium)
- SMR r6: PLAN-READY contingent on folding AGY's two medium findings

Codex has converged. AGY has 4 findings that are reasonable to fold in one more round. Two are medium-severity-but-foldable:

### AGY r6 #2 — warm pass MUST be triggered on RG-promote (not just clear cache)

This is the right call. v6's design relies on "the next snapshot will trigger queue_warm_pass" — but the snapshot might be rate-limited at 1s. If the promote happens between snapshots, the newly active RG sits cold until the next snapshot apply or the next user flow times out the cold path.

**Resolution for v7**: Coordinator::on_rg_promote_active() should both clear last_probed_at AND call queue_warm_pass(force=true). The force flag bypasses the 1s rate-limit specifically for promotion events.

### AGY r6 #4 — PENDING_NEIGH_TIMEOUT_NS placement on ForwardingState vs OnceLock

This is an architectural preference. Both work, but ForwardingState placement:
- Re-evaluates per snapshot (so sysctl changes mid-life are picked up)
- Avoids global mutable state (cleaner test injection)
- Aligns with existing pattern (forwarding state is the single source of truth)

**Resolution for v7**: move to `ForwardingState.pending_neigh_timeout_ns: u64`; compute in `build_forwarding_state_with_policy_counters_and_previous()`.

### AGY r6 #1 — pseudocode types

This is a docstring fix. v7's pseudocode uses concrete types (`Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>`).

### AGY r6 #3 — force: bool for warm_pass

Couples to #2 — when promote calls warm pass, it needs to bypass rate-limit. v7 adds `force: bool` parameter.

## Why I'm calling PLAN-READY contingent on v7 fold-in

Six rounds is a lot. Both reviewers and SMR converged on B+C+D recommendation in round 2 and haven't materially changed direction since. Rounds 3-6 have been precision-tightening implementation details. These last AGY findings are refinements that any competent /engineer phase would catch in code review.

If we keep iterating until AGY says PLAN-READY-NO-FINDINGS, we'll be at v10+ and AGY will still find low-severity nits. AGY's pattern across rounds: 7 findings r1 → 5 findings r2 → 4 findings r3 → 3 findings r4 → 3 findings r5 → 4 findings r6. The findings ARE getting smaller in scope (medium becoming low; new mediums being implementation details rather than design holes).

My call: fold v7, re-poll AGY ONE more round (round 7). If AGY r7 is PLAN-READY or PLAN-NEEDS-MINOR-WITH-FOLDABLE-NITS, we declare convergence and post on the issue. If AGY r7 introduces yet new medium findings, we declare convergence anyway with a note that round 7 was the cutoff and remaining items go to /engineer review.

Sequence to convergence:
1. Write v7 folding AGY r6 #1-4
2. Dispatch AGY r7
3. (Codex stays PLAN-READY since v7 changes don't affect anything Codex flagged)
4. Final convergence post on issue
