# Codex hostile plan review — #6751 (round 15)

# PLAN-NEEDS-REVISION

1. **BLOCKER — Deferred timeout admission is not bulk-epoch safe.**

   v15 quarantines before bulk bookkeeping and dispatches the stored frame up to five seconds later through the “complete normal import path” ([plan.md](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:591), [plan.md](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:626)). But bulk membership is ambient state: the handler adds the key to whichever `bulkRecvV4/V6` map is current when dispatch occurs, with no frame-carried epoch ([sync_conn_read.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:111), [sync_conn_read.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:137)).

   Two failing scenarios follow:

   - Bulk E1 receives identity-NPTv6 row Q and quarantines it. E1 `BulkEnd` arrives before five seconds. Q is absent from E1’s received set, so reconciliation can delete an existing Q; the receiver nevertheless ACKs the bulk and fires `OnBulkSyncReceived`, releasing the safety hold while Q is missing ([sync_conn_read.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:240), [sync_conn_read.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:244)).
   - If E2 starts before Q’s E1 timeout, the deferred E1 frame is counted as part of E2. If Q disappeared between snapshots and its delete was lost—the exact condition authoritative bulk reconciliation repairs—the stale Q is installed and falsely retained by E2.

   `reconcileStaleSessions` clears the current receive set at BulkEnd, confirming there is no late membership mechanism ([sync.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync.go:1086), [sync.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync.go:1089)).

   Additionally, a timer goroutine cannot directly invoke the import path: generation check → install → generation record is explicitly safe only because receiver application is single-threaded ([sync_conn_gen.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:381)).

   Required fold: pin each quarantine entry to its arrival bulk epoch and define BulkEnd behavior—most simply, keep BulkEnd/reconcile/ACK/readiness pending until that epoch’s quarantines confirm or timeout. Timeout/delete events must re-enter the serialized receiver event loop. Tests need both scenarios above.

2. **MINOR — Capability UNKNOWN has no defined transition to legacy/unsupported.**

   v15 simultaneously says alias emission is held until capability is known and `UNKNOWN → KEEP DERIVING` ([plan.md](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:566)). An old peer never advertises, so the plan must define how UNKNOWN becomes UNSUPPORTED and releases held aliases—e.g. receipt of the first non-capability frame, or a bounded setup timeout.

   This is implementable, but it must occur before exposing the connection to the send loop. Today `installConn` marks the connection active/connected before `sendClockSync` ([sync_conn.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:130), [sync_conn.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:137)); the independent send loop can immediately write queued data once that connection is visible ([sync_conn_write.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go:276)). Merely adding another post-install write does not guarantee “pre-data.”

3. **NIT — The new admission counter exists, but the inventory count is stale.**

   The requested `xpf_userspace_session_sync_alias_quarantine_admitted_total` is explicitly present ([plan.md](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:837)). However, the plan still says “four helper counters plus one Go counter” and tests “five counters” ([plan.md](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:804), [plan.md](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1113)). It now defines six: four helper-side plus two Go-side.

The fabric-gate removal otherwise checks out: with the full address-and-port signature, ordinary address-changing SNAT/NPTv6 rows do not match; mapped-port PAT/static rows fail the port equality; NAT64 is excluded. The remaining matches are source-identity cases intentionally priced for timeout admission.

The revised open/close ordering also matches the exporter: base then alias on open ([daemon_ha_userspace_stream.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:370)), and base delete then alias delete on close ([daemon_ha_userspace_stream.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:398)). I found no remaining confirmed-wrong admission or suppression-clear inversion in those stated scenarios.

Codex session ID: 019fc8fe-d80b-77c2-bee8-f91fd6c6288c
Resume in Codex: codex resume 019fc8fe-d80b-77c2-bee8-f91fd6c6288c
