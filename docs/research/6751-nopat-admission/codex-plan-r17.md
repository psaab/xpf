# Codex hostile plan review — #6751 (round 17)

# PLAN-NEEDS-REVISION

Reviewed v15.3 at `0e11e0040`; current HEAD only adds the SMR r17 review and does not alter the plan.

1. **BLOCKER — terminal abort has no mechanism that causes the sender to retry.**

   The plan says overflow/deadline aborts without ACK and “lets the sender’s bulk machinery retry” ([plan.md:631](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:631)). That is false today:

   - `BulkSync()` records the pending ACK, writes `BulkEnd`, and returns success without waiting for the ACK ([sync_bulk.go:169](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:169), [sync_bulk.go:183](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:183), [sync_bulk.go:195](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:195)).
   - Connection setup clears `needColdPrime` when that write-only operation succeeds, before any ACK ([sync_conn.go:194](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:194)).
   - A missing ACK merely remains in `pendingBulkAckEpoch`; only an actual ACK clears it ([sync_conn_read.go:257](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:257)). There is no ACK-timeout retry.
   - The claimed E1→E2 survivor re-drive also fails in steady state: single-fabric disconnect redrives only while `outboundBulkAcked == false` ([sync_conn.go:572](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:572)), but that flag is intentionally sticky and never reset after the first acknowledged bulk ([sync.go:479](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync.go:479)). Thus a connection reset during any later bulk need not produce the superseding `BulkStart` promised at [plan.md:660](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:660).
   - Aborting while leaving the stream open is also undefined: current session handlers use `bulkInProgress` only for received-key bookkeeping and then install the frame normally ([sync_conn_read.go:109](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:109)). Trailing frames from the aborted bulk would therefore become apparent incremental traffic unless the design specifies discard-until-end or transport teardown.

   This is the uncovered fourth epoch-death shape: **single active-fabric reset after a prior successful bulk while the other fabric survives**. Peer/receiver process restart normally drops both fabrics and gets the full-disconnect cleanup/re-prime path; this one does not.

   Required fold: choose an explicit recovery contract—e.g. a NACK/resync request, an ACK-timeout retry debt retained until matching ACK, or a defined connection teardown that guarantees a full reconnect—and specify handling of the remaining frames from the aborted epoch. Backoff alone limits retry rate; it does not create a retry.

2. **MINOR — capability lifecycle is substantively covered, but the transport contract remains internally inconsistent.**

   All four required alias branches exist and must be gated: V4/V6 opens at [daemon_ha_userspace_stream.go:373](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:373) and [daemon_ha_userspace_stream.go:386](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:386), closes at [daemon_ha_userspace_stream.go:400](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:400) and [daemon_ha_userspace_stream.go:413](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:413). UNKNOWN-on-reconnection and periodic re-advertisement are stated.

   However, §5.6 leaves the transport as several alternatives ([plan.md:562](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:562)), while §6 still calls it a handshake field ([plan.md:941](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:941)). That cannot cover unkeyed deployments because their handshake is bypassed ([sync_auth.go:321](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_auth.go:321)). Name one periodic frame/ticker contract consistently.

3. **NIT — the counter inventory is now seven, not six.**

   v15.3 adds the Go-side overflow counter at [plan.md:633](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:633). Together with four helper counters and the two existing Go counters at [plan.md:918](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:918), that is **four helper-side plus three Go-side = seven**. The six-counter claims at [plan.md:953](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:953) and [plan.md:1226](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1226) omit overflow.

4. **NIT — document header remains v15.2.**

   [plan.md:3](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:3) still identifies the document as v15.2 and summarizes the obsolete six-counter state.

Own-`BulkEnd` resolution, pre-overwrite supersession cleanup, the required new receive deadline, all-fabric teardown, and the core registry/mint/holder/tri-state/staged-replacement/drain design otherwise expose no new blocker. The settled option-(a) decision remains intact.

Codex session ID: 019fc930-ed4e-7b43-aeee-cf7f9d6462e3
Resume in Codex: codex resume 019fc930-ed4e-7b43-aeee-cf7f9d6462e3
