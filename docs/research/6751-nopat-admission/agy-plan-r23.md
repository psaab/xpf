# AGY hostile plan review — #6751 (round 23)

VERDICT: PLAN-READY-WITH-NITS

### Round 23 Convergence Adjudication Findings

#### 1. Attack 1: Provisional Installs & Forwarding Correctness — VERIFIED SAFE (No Issue)
- **Analysis**: In `userspace-dp` HA session sync ([daemon_ha_userspace_convert.go:L328-366](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go#L328-L366)), session frames received during `BulkSync` carry complete, self-contained forwarding structures (`SessionKey`, `ReverseKey`, `NATSrcIP`, `NATSrcPort`, `NATDstIP`, `NATDstPort`, `IngressZone`, `EgressZone`, `FibIfindex`, `FibDmac`, `FibSmac`). Session forwarding in the dataplane relies on these self-contained parameters on the matching session entry; it does not perform dynamic policy or NAT re-lookups.
- **Result**: Already-installed session frames from an aborted bulk represent sessions that were active and admitted on the primary at frame send time. Serving traffic provisionally on these frames is safe and correct. Partial bulks are bounded by the per-bulk receive deadline (dropping fail-closed quarantine entries on timeout) and converge authoritatively at the next complete bulk's `BulkEnd` reconcile.

#### 2. Attack 2: Callback Execution Against Current State — VERIFIED TRUE ([daemon_ha_sync.go:L934-957](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go#L934-L957))
- **Analysis**: Inspection of `OnPeerConnected` in [daemon_ha_sync.go:L934-957](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go#L934-L957) confirms that when the callback executes, it calls `d.clusterConfig()`, `d.nudgeDHCPLeaseSync()`, `d.nudgeIPsecSASync()`, and `d.reconcileConfigSyncToPeer("peer-connect")`. None of these functions use frozen verdict-time snapshots; they evaluate live daemon state (`d`) dynamically at the moment of execution.
- **Result**: The plan's classification of callback work as convergent is accurate with respect to existing codebase behavior today.

#### 3. Attack 3: Journal Replay #2170 Generation Coverage — VERIFIED COMPLETE ([sync_conn_gen.go:L179-322](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go#L179-L322))
- **Analysis**: 
  - `takeDeleteGenV4` ([sync_conn_gen.go:L179](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go#L179)) draws a fresh, strictly greater install generation when generating a delete message.
  - `deleteGenGuardV4` ([sync_conn_gen.go:L282](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go#L282)) checks if `deleteGen < stored`. If so, the stale delete is refused (`false`). Upon applying a valid delete, it records `deleteGen` in `recvGenV4` as a **tombstone**.
  - `installGenGuardV4` ([sync_conn_gen.go:L205](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go#L205)) refuses incoming upserts where `incoming < stored` (where `stored` includes active tombstones).
- **Result**: A replayed stale delete cannot overwrite a newer install, and a replayed stale upsert cannot overwrite a newer delete (it is refused by the stored tombstone). Session state ordering by per-key generation is fully sound without requiring abort-generation coupling on the journal queue.

#### 4. Finding 1 (NIT): Omission of Abort-Generation Test Bullets in Section 9 Summary List ([plan.md:L1307-1467](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1307-L1467))
- **Evidence**: [plan.md:L12-14](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L12-L14) and [plan.md:L804-808](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L804-L808) explicitly state that §9 pins five specific tests (`blocked-I/O`, `large-bulk`, `abort-mid-BulkSync`, `BulkEnd-race`, `callback/journal generation-race`). However, under the `## 9. Test plan` section header ([plan.md:L1307](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1307)), these five test descriptions are omitted from the bulleted test inventory.
- **Remediation**: Copy the 5 named test cases from §5.6 ([plan.md:L804-808](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L804-L808)) into the `## 9. Test plan` section list for completeness.

---

### Final Adjudication Summary
No BLOCKER or MAJOR issues remain in either the core #6751 design or the fabric alias and effect-commit reversibility contracts. The plan document at v15.9 is fully converged and **PLAN-READY-WITH-NITS**.
