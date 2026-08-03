# AGY hostile plan review — #6751 (round 14)

VERDICT: PLAN-READY-WITH-NITS

---

### Convergence Adjudication Summary

The v14 revision of `docs/research/6751-nopat-admission/plan.md` (commit `0e7423efe`) successfully resolves the open blockers from Round 13 by adopting negotiated sender-side alias omission for new-to-new cluster sync, paired with signature quarantine and sibling-base confirmation for the legacy rolling-upgrade window.

1. **Negotiated Sender-Side Alias Omission (New+New)**:
   - Eliminates wire alias traffic, companion poisoning, and collateral for all updated nodes.
   - Verified: In the mixed-version window where a new sender transmits to an old helper, the old helper populates `shared_forward_wire_sessions` upon publishing the base canonical session ([`shared_ops.rs:943-957`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L943-L957)), so forward-wire resolution succeeds without explicit alias frames.

2. **Legacy Window Quarantine & Confirm/Admit**:
   - **B1 Counterexample**: Direct session D sharing alias key K closes while base A is open. Under v14, D's delete is suppressed while A's base is open, causing D's state to linger until its standard session timeout. This is bounded by protocol inactivity timers and is strictly safer than the status quo (where alias arrival clobbers D immediately at publish time).
   - **Identity-NPTv6 / Fabric-Redirect**: Non-fabric identity-NPTv6 flows bypass quarantine via the `FabricRedirect` gate. Fabric-redirect identity-NPTv6 flows enter quarantine and admit upon timeout after 5s (a bounded sync delay during rolling upgrade, zero delay on negotiated new+new).
   - **Sibling-Base Predicate**: `forward_wire_key(K_base) == K_alias` ∧ `NatDecision_base == NatDecision_alias` ∧ `RTFlowSessionID_base == RTFlowSessionID_alias != 0`. Because `RTFlowSessionID` is unique per flow on the active node, a distinct colliding flow (H2) carries a different RT-flow ID than H1's alias and cannot false-positive match.

No open BLOCKER or MAJOR findings remain.

---

### Numbered Findings

1. **MINOR: Capability Channel Mechanism in `pkg/cluster` for Unauthenticated Clusters**
   - **File:Line Evidence**: [`pkg/cluster/sync_auth.go:331-334`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_auth.go#L331-L334), [`pkg/cluster/sync_conn.go:100-137`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L100-L137), [`plan.md:551-554, 812-816`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L551-L554)
   - **Analysis**: The plan specifies that the receiver advertises an additive capability in the cluster handshake ([`plan.md:551`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L551)). In the codebase, `performSyncHandshake` ([`sync_auth.go:331`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_auth.go#L331)) is an auth-specific handshake that is bypassed when no auth key is configured (`len(key) == 0`). In unauthenticated setups, `handleNewConnection` ([`sync_conn.go:100`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L100)) opens the TCP stream without running a connection setup handshake.
   - **Recommendation**: Specify that unauthenticated connections advertise capabilities either by sending a zero-key `syncMsgAuthHello` frame during connection setup or by sending an additive post-connect message (such as `syncMsgCapability` or extending `syncMsgClockSync` at [`sync_conn.go:137`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L137)).

2. **NIT: Quarantine Timeout Admission Callback Pipeline**
   - **File:Line Evidence**: [`pkg/cluster/sync_conn_read.go:110`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go#L110), [`plan.md:597-601`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L597-L601)
   - **Analysis**: When a quarantined entry times out after 5 seconds, it is admitted as canonical.
   - **Recommendation**: Ensure the timer expiry callback dispatches the stored frame directly into the standard `SessionSync.importSession` / `bulkRecv` pipeline so generation tracking, sequence numbers, and helper dispatch (`WorkerCommand::UpsertSynced`) execute identically to non-quarantined frames.

3. **NIT: Clarify Legacy Alias Drop Attribution in Counter Metric**
   - **File:Line Evidence**: [`plan.md:784-789`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L784-L789)
   - **Analysis**: `xpf_userspace_interface_snat_sync_identity_conflict_drops_total` counts coordinator import conflict drops, including benign legacy alias drops during the legacy window.
   - **Recommendation**: Note in metric documentation that non-zero counts during a mixed-version rolling upgrade are expected when receiving from legacy senders.
