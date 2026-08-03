# AGY hostile plan review — #6751 (round 18)

PLAN-READY-WITH-NITS

### Verification of v15.4 Folded Findings

1. **Recovery Contract (Cluster-Level Teardown)**:
   - **(a) Path existence & reset**: Verified. In [sync.go:L500-L517](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync.go#L500-L517) and [sync_conn.go](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go), full disconnect (all fabrics down) arms `needColdPrime` and resets connection/epoch state across both nodes.
   - **(b) Abort shapes**: Verified. Overflow and deadline aborts trigger connection teardown (closing both connections), converting the abort directly to the proven full-disconnect path. Superseding `BulkStart` frames (single-fabric flips) drop prior epoch pinned entries fail-closed before map overwrite. No abort shape bypasses teardown.
   - **(c) Healthy-peer cost**: Verified. A receiver-side overflow tears down both connections, triggering a routine cluster reconnect and a single cold re-prime re-drive by the healthy sender.

2. **Capability Transport**:
   - Verified. The transport is specified as a single named contract — an additive periodic `syncMsgCapability` frame on a dedicated ticker. §6 and §5.6 explicitly clarify that it is NOT a handshake field.

3. **Counters**:
   - Verified. The document header and §6 correctly inventory seven total counters (4 helper-side + 3 Go-side: `confirmed-dropped`, `quarantine-admitted`, `quarantine-overflow`).

---

### Findings (Ranked)

1. **MINOR**: Stale "handshake capability field" phrasing in §11 Open Question 2
   - Evidence: [plan.md:L1310-L1312](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1310-L1312)
   - Description: Open Question 2 asks *"is the additive handshake capability field the right negotiation channel..."*, which contradicts §5.6 ([plan.md:L568](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L568)), §6 ([plan.md:L975](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L975)), and the header ([plan.md:L10](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L10)), which state that the capability frame is periodic and explicitly *not* a handshake field.

2. **NIT**: Stale counter count references in prose sections (§5.8, §6, §9)
   - Evidence: [plan.md:L925-L926](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L925-L926), [plan.md:L978](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L978), [plan.md:L1014](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1014), [plan.md:L1200](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1200)
   - Description: While the status header ([plan.md:L11-L12](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L11-L12)), §6 ([plan.md:L985-L987](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L985-L987)), and §9 ([plan.md:L1257](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1257)) correctly state 7 total counters (4 helper-side + 3 Go-side), residual prose text retains sub-totals from earlier iterations:
     - L925: *"PLUS one GO-side Prometheus counter"* (should be 3 Go-side counters)
     - L978: *"the fifth, the alias-ignored counter"* (should reference the three Go-side counters)
     - L1014 & L1200: *"the TWO Go-side counters"* / *"two Go-side counters"* (should be three)
