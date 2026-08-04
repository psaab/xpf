# Codex hostile plan review — #6751 (round 39)

# PLAN-NEEDS-REVISION

Reviewed the committed `788b256aa` blob. The worktree currently contains an uncommitted §6 correction; it is not part of v15.27 and is not credited here.

1. **BLOCKER — An observed legacy `BulkStart` does not prove remote-both-empty or an authoritative prime.**

   The plan equates the observed prime with the peer’s `needColdPrime` arm at `plan.md@788b256aa:673-680`. That provenance is absent from the wire: `BulkStart` carries only an epoch at [sync_bulk.go:65](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:65). Connected force-resync and survivor re-drive can also initiate bulks without a both-empty transition at [sync_conn_sweep.go:111](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_sweep.go:111) and [sync_conn.go:572](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:572).

   More importantly, the actual no-heartbeat-ACK cohort predates the #5085 authoritative-bulk fix: heartbeat ACK landed in `63ab422cf`, while lossless authoritative bulk landed later in `52fc4a513`. The current source records that the historical override exported asynchronously and lossily, then emitted empty markers at [sync_bulk.go:26](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:26); the fail-on-revert test confirms that exact old behavior at [sync_bulk_override_5085_test.go:57](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk_override_5085_test.go:57).

   Therefore, the receiver’s matching-`BulkEnd` rule at [sync_conn_read.go:205](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:205) proves only framing. It cannot prove that the window was caused by both-empty or that its contents were complete. An old sender can write an incomplete/lossy window, successfully return after `BulkEnd`, and clear `needColdPrime` at [sync_bulk.go:183](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:183) and [sync_conn.go:194](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:194). The new receiver can then perform a definitive alias pass on a non-definitive snapshot.

   Required: provenance/capability-gate the authoritative prime, minimum-version-gate it, or prohibit legacy marker windows from clearing alias lineage, reconciling definitively, ACKing, or releasing the reconciliation hold.

2. **BLOCKER — Re-fencing still provides no bounded mechanism that kills retained legacy C0.**

   The cited “per-frame read deadline, `sync_protocol.go:59`” at `plan.md@788b256aa:677-680` is actually a two-second **write** deadline: [sync_protocol.go:59](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go:59). It does not bound remote receipt or force teardown.

   The real read path deliberately keeps a no-ACK peer alive indefinitely: missed-heartbeat accounting is disabled until an ACK has previously been seen at [sync_conn_read.go:27](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:27). The compatibility regression explicitly requires the connection to remain connected and healthy beyond the silence limit at [sync_test.go:4655](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_test.go:4655). While C0 remains registered, the initiator does not redial at [sync_conn.go:446](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:446).

   Thus, for the retained-C0 trace, **nothing plan-bounded kills C0**. A later OS/TCP failure might, but no bound or required socket policy is specified. Re-fencing cannot create another “full bound” when the relevant detector is intentionally absent.

   The readiness terminal is described honestly as degraded—release the VRRP hold while retaining debt—at `plan.md@788b256aa:2039-2048`. It does not prove both-empty or convergence. There is also an ordering inconsistency: the proposed quiet interval is 7.5 seconds at `plan.md@788b256aa:652-654`, while the production readiness timeout remains five seconds at [daemon.go:1148](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon.go:1148).

3. **MAJOR — The committed §6 still contradicts the load-bearing two-field stage carrier.**

   The detailed design correctly requires two `SyncedSessionEntry` fields and traces the alias stage through the JSON request, binary codec, metadata import, replication, promotion gate, and every exporter at `plan.md@788b256aa:2411-2432`.

   But committed §6 still says `SyncedSessionEntry` gains **ONE** helper-internal `pub_token`, “not read from or written to any Go-facing wire,” at `plan.md@788b256aa:2690-2693`.

   This is load-bearing, not editorial. Today the Go request has no stage at [protocol_ha.go:33](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/protocol_ha.go:33), the Rust request has none at [control.rs:1008](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/protocol/control.rs:1008), metadata is constructed at [session_sync.rs:203](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/server/helpers/session_sync.rs:203) and moved into the table at [upsert_synced.rs:64](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:64), while promotion currently emits `Open` unconditionally at [session/mod.rs:1516](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/mod.rs:1516). An implementor following §6 can omit the stage ingress and recreate suspect→promote→export.

4. **MINOR — The accept-proof mechanism is sound, but its newly promised regression is absent.**

   For C1, the first leg dies at admission: while engaged, `Accept` refuses before issuing a stamp at `plan.md@788b256aa:637-639`. The release-side G2 advance at lines 640-642 is a backup stale-stamp barrier. Legitimate post-release admissions obtain G2 and remain current, so the second advance does not reject them.

   However, line 643 claims §9 pins `accept-after-sweep-start → resume-after-release`. Committed §9 only contains the older `Accept→beginSetup` and `finishSetup→installConn` stalls at `plan.md@788b256aa:2905-2916`. Add the exact new trace.

5. **NIT — The single-lock admission linearization is implied, not explicitly assigned.**

   “Refuses atomically” semantically requires the engaged check, stamp issuance, child registration, release generation advance, and disengagement ordering to share one admission linearization point. The plan does not name that lock or explicitly require advance-before-disengage. That matters because current connection and setup state use separate locks at [sync.go:301](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync.go:301) and [sync.go:322](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync.go:322).

6. **NIT — The rejected “CURRENT store as definitive” phrase remains literally present.**

   The substantive timeout semantics are corrected at `plan.md@788b256aa:2213-2222`, and the fail-on-timeout-clear regression is pinned at lines 3192-3195. Nevertheless, §9 still says “with the CURRENT store as definitive” at lines 3195-3196. The surrounding text now limits this to disposition, so this is wording cleanup rather than the prior lineage bug.

The liveness suite is present at `plan.md@788b256aa:2893-2904`. The export-skip counter is correctly the sixth helper counter, with `6 + 3 = 9`, at lines 2598-2624 and 3279-3284.

No new blocker was found in the option-(a) registry/holder/drain core or the settled §4.0.1/§4.0.2 machinery. The two remaining blockers are in the surviving legacy re-prime mechanism and its use as definitive alias-lineage proof.
