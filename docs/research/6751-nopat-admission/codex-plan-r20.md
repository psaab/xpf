# Codex hostile plan review — #6751 (round 20)

# PLAN-NEEDS-REVISION

1. **BLOCKER — abort completion does not normatively detach wedged connection slots or fence post-admission work.**

   The six-clause contract is present and normative, including generation inheritance and commit-time validation ([plan.md:687](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:687)). However, clause 5 permits `AbortFenceTimeout` to complete while a handler has not detached and only mandates resetting bulk/quarantine/capability state ([plan.md:719](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:719)). It never requires the transition to forcibly clear or invalidate `conn0/conn1` before clearing the fence.

   That matters because current code clears slots only from `handleDisconnect` ([sync_conn.go:480](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:480)), and recognizes an empty→connected edge only when both slots are nil ([sync_conn.go:248](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:248)). That edge is what arms `needColdPrime` ([sync_conn.go:278](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:278)). Therefore:

   - One handler wedges with its slot still registered.
   - `AbortFenceTimeout` resets state and clears the fence.
   - The next connection replaces/joins a nonempty registry, observes `wasDisconnected == false`, and can miss the fresh cold-prime that clause 6 promises ([plan.md:728](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:728)).

   There is also an adjacent admission TOCTOU: `installConn` returns, after which receive-loop launch, clock sync, callbacks, and cold-prime occur separately ([sync_conn.go:130](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:130)). An abort can advance the generation after an ADMITTED verdict but before those actions; clauses 2 and 4 cover REFUSED connections and frame commits, not this already-admitted setup tail.

   Required fold: the abort transition must generation-invalidate and logically detach both slots before fence release—even on timeout—with late callbacks treated as stale. The ADMITTED verdict’s generation must also be revalidated before every post-install action, or those actions must be committed atomically with admission. Add tests for a timeout with a still-registered slot and for abort-between-verdict-and-loop/callback/cold-prime. The existing five-test list does not pin either condition ([plan.md:744](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:744)).

2. **MINOR — the capability transport remains contradictory.**

   §5.6 first selects a dedicated ticker, but then still permits “a new periodic capability ticker, or piggybacking” and says the implementer chooses ([plan.md:565](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:565), [plan.md:573](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:573)). This contradicts §6 and §11’s ticker-only statements. The round-19 transport finding was not fully folded.

3. **NIT — §5.8 still does not explicitly enumerate the overflow counter.**

   §5.8 promises three Go-side counters but its actual list names only `...forward_wire_alias_ignored_total` and `...quarantine_admitted_total` ([plan.md:1003](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1003), [plan.md:1025](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1025)). `...alias_quarantine_overflow_total` appears in §5.6 and is summarized in §6, but not in §5.8’s counter list.

No new blocker was found in the registry/mint/holder/tri-state/staged-replacement/drain/quarantine/probe/counter core. The remaining blocker is confined to the alias-abort connection lifecycle.

Codex session ID: 019fc96d-dec6-7870-9c69-3ed87e33cf03
Resume in Codex: codex resume 019fc96d-dec6-7870-9c69-3ed87e33cf03
