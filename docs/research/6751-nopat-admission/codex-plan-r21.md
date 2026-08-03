# Codex hostile plan review — #6751 (round 21)

# PLAN-NEEDS-REVISION

1. **BLOCKER — Clause (2b) closes the TOCTOU only by placing an unbounded, potentially deadlocking tail inside the serialized commit.**

   The plan requires verdict, receive-loop launch, clock sync, lifecycle callbacks, and cold-prime to execute as one serialized step ([plan.md:716](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:716)). In current code, that tail includes synchronous clock I/O, replay of up to 10,000 journal entries, and `doBulkSync()` ([sync_conn.go:132](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:132), [sync_conn.go:137](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:137), [sync_conn.go:141](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:141), [sync_conn.go:194](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:194)). `BulkSync` walks every owned IPv4 and IPv6 forward session and writes each frame synchronously ([sync_bulk.go:92](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:92), [sync_bulk.go:133](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:133)). Each write gets a fresh two-second deadline ([sync_protocol.go:59](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go:59)), so the serialized duration is effectively unbounded in session cardinality and network backpressure.

   Running this under `s.mu` is impossible: `BulkSync → getActiveConn` re-enters `s.mu`, a self-deadlock the code explicitly documents ([sync_conn.go:588](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:588)). Running it on the proposed serialized event executor instead prevents abort, deadline, quarantine, and frame-commit events from progressing for the whole bulk.

   Moreover, there is no existing global serialized receiver loop: each connection launches its own `receiveLoop` ([sync_conn.go:132](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:132), [sync_conn_read.go:14](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:14)); the code acknowledges two fabric receive loops ([sync_conn_gen.go:381](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:381)).

   Clause (2b) needs a bounded atomic unit: install/stamp the slot and atomically enqueue generation-bound setup intents. Clock I/O, callbacks, journal replay, and cold-prime must execute outside the arbiter, with generation/slot revalidation before their effects and cancellation or stale completion after abort. Pin blocked-I/O and large-bulk tests showing AbortFenceTimeout remains bounded.

2. **NIT — §11 still describes a nonexistent fabric gate.**

   The open question says the signature has “fabric gate false-positives” only on genuine self-NAT ([plan.md:1413](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1413)), while the normative design explicitly has **no disposition gate** and also quarantines non-fabric identity-NPTv6 rows ([plan.md:618](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:618), [plan.md:1178](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1178)). Correct the stale question text.

Fold adjudication:

- **Blocker 1a is closed.** Clause (5) unconditionally generation-invalidates and detaches both slots before fence release, including timeout ([plan.md:724](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:724)). A late disconnect then hits the existing stale-pointer branch ([sync_conn.go:480](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:480)); both-nil restores the genuine cold-prime edge ([sync_conn.go:248](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:248), [sync_conn.go:278](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:278)).
- **Blocker 1b remains open** as finding 1.
- **Transport contradiction is closed.** §5.6, §6, and §11 consistently specify the dedicated periodic ticker; no piggyback alternative survives.
- **Overflow bullet is present** at [plan.md:1058](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1058).
- No additional blocker was found in the registry, mint, holder, tri-state, staged-replacement, drain, quarantine, probe, or counter design. The settled option fork was not reopened.

Codex session ID: 019fc983-5b3a-72e0-adf1-3b666963566c
Resume in Codex: codex resume 019fc983-5b3a-72e0-adf1-3b666963566c
