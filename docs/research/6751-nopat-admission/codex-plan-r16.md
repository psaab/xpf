# Codex hostile plan review — #6751 (round 16)

**PLAN-NEEDS-REVISION**

1. **BLOCKER — quarantine-cap eviction is not implementably bounded.**

   The quarantine is capped at 4096 entries ([plan.md:618](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:618)), but eviction allegedly waits for the complete received set at BulkEnd ([plan.md:1119](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1119)). Current bulk bookkeeping retains only keys, not payloads ([sync_conn_read.go:200](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:200)); the decoded value is otherwise consumed immediately ([sync_conn_read.go:110](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:110)).

   Therefore an evicted frame cannot later be admitted unless its full payload is retained elsewhere, which makes the stated 4096 cap ineffective/unbounded. Immediate admission can poison the alias path; immediate drop can lose genuine self-NAT/NPTv6 rows. The plan needs a bounded overflow terminal action, such as aborting the incomplete bulk without ACK and re-priming.

2. **BLOCKER — the claimed bulk-liveness teardown does not exist, and a real E1→E2 supersession path remains undefined.**

   There is no receive-bulk deadline. Read timeouts merely send heartbeats and continue while the peer responds ([sync_conn_read.go:27](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:27)); the 30-second VRRP timeout releases sync hold in degraded mode but does not tear down the bulk ([manager.go:372](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/vrrp/manager.go:372)).

   More importantly, if fabric 0 drops mid-E1 while fabric 1 survives, receiver bulk state is not reset—the reset runs only when all fabrics are down ([sync_conn.go:496](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:496), [sync_conn.go:554](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:554)). The sender can re-drive a new bulk on the survivor ([sync_conn.go:572](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:572)), while E2’s BulkStart unconditionally overwrites E1’s epoch and received maps ([sync_conn_read.go:183](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:183), [sync_conn_read.go:198](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:198)).

   Thus E1’s pinned quarantines never receive their own BulkEnd. This is the third-epoch scenario. The plan must define both a real bulk deadline/teardown and the superseding-BulkStart rule before E2 replaces E1.

3. **MINOR — capability rediscovery is not fully specified against the actual connection lifecycle.**

   The queue points that must be gated are all four alias branches: V4/V6 open ([daemon_ha_userspace_stream.go:373](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:373), [daemon_ha_userspace_stream.go:386](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:386)) and V4/V6 close ([daemon_ha_userspace_stream.go:400](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:400), [daemon_ha_userspace_stream.go:413](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:413)). The mid-stream transition itself is covered by receiver quarantine.

   However, no periodic clock-sync tick currently exists: `sendClockSync` is called only once during connection setup ([sync_conn.go:137](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:137)). The plan should name the new ticker/piggyback path and explicitly reset capability state to UNKNOWN on peer reconnection.

4. **NIT — six counters are intended, but the prose still says five.**

   The list contains four helper counters plus two Go counters ([plan.md:850](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:850), [plan.md:878](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:878), [plan.md:883](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:883)). Section 6 still calls the Go counter “the fifth” ([plan.md:906](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:906)). The correct total is six.

The AGY bookkeeping blocker is closed: the exact decoded forward key is recorded before import, and reconcile deletes only eligible forward rows whose exact key is absent ([session_store.go:627](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/session_store.go:627), [session_store.go:634](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/session_store.go:634)). The normal E1-BulkEnd scenario and ordinary E1/E2 timeout crossover are also closed. I found no new blocker in the unchanged registry/mint/holders/tri-state/staged-replacement/drain/probe design; the remaining blockers are in alias-quarantine lifecycle completeness.

Codex session ID: 019fc91d-f77c-7c73-a301-d885ec99f21e
Resume in Codex: codex resume 019fc91d-f77c-7c73-a301-d885ec99f21e
