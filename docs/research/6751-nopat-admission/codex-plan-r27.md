# Codex hostile plan review — #6751 (round 27)

# PLAN-NEEDS-REVISION

Reviewed v15.14 at `8a2eb427c`.

1. **BLOCKER — the epoch barrier does not establish a valid content-order cut.**

   The plan equates enqueue time with content origin and claims every new-epoch delta is safe around the bulk via #2170 ([plan.md:946](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:946), [plan.md:995](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:995)). Two code-backed counterexamples remain:

   - `QueueSessionV4` stamps and encodes content before calling `queueMessage`; an abort can occur between those operations, causing pre-abort content to receive the new epoch at enqueue ([sync_conn_write.go:56](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go:56)).
   - Bulk iteration copies batches of up to 256 values before their callbacks execute ([maps_session.go:237](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/maps_session.go:237)). After `K=V_old` is copied, a close/replacement can receive generation `G1`; when the bulk later reaches that stale copy, it stamps `V_old` with `G2 > G1` ([sync_bulk.go:95](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:95), [sync_conn_gen.go:59](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:59)).

   Because bulk and delta writers release `writeMu` per frame, either wire order is wrong: delta-first allows stale `G2` to overwrite `G1`; bulk-first causes the real `G1` close/replacement to be rejected as older ([sync_conn_gen.go:205](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:205), [sync_conn_gen.go:282](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:282)). The receiver records `K` as received, so `BulkEnd` retains the stale row ([sync_conn_read.go:109](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:109), [sync_conn_read.go:205](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:205)).

   The design needs snapshot/delta content-origin serialization or versioning—not merely wire serialization—and corresponding before/between/after tests.

2. **BLOCKER — barrier-timeout recovery is not authoritative on the userspace path.**

   The plan advances the epoch before draining, then says a pre-start timeout is retried by recovery machinery ([plan.md:973](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:973)). Current retry calls `bulkSyncViaEventStreamOrFallback` ([daemon_ha_sync.go:269](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:269)). In userspace, the adapter supports the event-stream exporter, so that function returns successfully without reaching `ss.BulkSync()` ([daemon_ha_sync.go:289](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:289), [legacy_dataplane.go:611](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/legacy_dataplane.go:611)).

   That export contains only point-in-time Open deltas—not `BulkStart`/`BulkEnd` or absence reconciliation ([export.rs:85](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/export.rs:85), [export.rs:143](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/export.rs:143))—and Go forwards them through lossy `queueMessage` ([sync_conn_write.go:36](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go:36)). Therefore, an old delete discarded by the epoch guard can remain absent from every retry, leaving the peer’s stale row unreconciled. Retry caps and readiness timeout prevent a permanent hold, but can release readiness without satisfying the authoritative-prime obligation.

   Barrier failure must persistently re-arm direct `doBulkSync`/`forceResync`, or force a fenced reconnect whose cold-prime is authoritative.

3. **MINOR — `stopClusterComms` does not always bump `syncReadyTimerGen`.**

   Bulk-received and disconnect call `stopSyncReadyTimer` unconditionally, and the normal teardown ordering is correctly bump-before-`ss.Stop()` ([daemon_ha_sync.go:19](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:19), [daemon_ha_sync.go:90](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:90)). But teardown calls it only inside `if ss != nil` ([daemon_ha_sync.go:1405](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:1405)), while bringup can arm the timer before `SessionSync` exists ([daemon_run_bringup.go:226](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_run_bringup.go:226)). Move the timer invalidation outside that branch. Connected-state revalidation keeps this from reopening BLOCKER 1.

4. **NIT — clarify the stalled-timeout test seam.**

   The plan calls the lifecycle queue serialized, but describes an event stalling after validation while a newer event commits ([plan.md:877](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:877), [plan.md:881](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:881)). The stall must be before entry into the serialized commit gate; once inside, a newer event cannot commit.

5. **NIT — lifecycle inventory documentation names a nonexistent flag.**

   `inboundBulkAcked` is named twice ([plan.md:849](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:849), [plan.md:899](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:899)); the code has `bulkEverCompleted` and `outboundBulkAcked` ([sync.go:478](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync.go:478)). A stray duplicate `minor 2)` also remains at [plan.md:904](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:904).

The readiness-timeout fold otherwise closes the original three-step race in both commit orders, and all four production `SetSyncReady` sites are covered. All six requested §9 regressions are explicitly present, although the prime-barrier test does not cover findings 1–2. The binding-direction sentence is corrected. I found no new blocker in the settled registry/mint/holder/tri-state/staged-replacement/drain/quarantine/probe/counter core or alias discipline.

A concurrent uncommitted edit added a barrier-drain bound after review began; it does not resolve either blocker. I left it untouched.
