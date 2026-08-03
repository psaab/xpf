# AGY hostile plan review — #6751 (round 24)

**PLAN-READY-WITH-NITS**

### Executive Summary & Convergence Adjudication

Both round-23 Codex blockers have been folded into v15.10 ([`docs/research/6751-nopat-admission/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1-L15)) with sound, technically complete solutions:
1. **Callback Lifecycle**: Work is correctly bifurcated into (a) convergent reads (evaluating live daemon state at execution) and (b) daemon lifecycle state mutations, which are now generation-ordered at their commit point (`abortGen == admissionGen && slot == admittedSlot`).
2. **Journal Disposition**: A three-layer contract (pre-abort envelope discard, documented unordered class bounded by authoritative bulk reconcile, sender-cap bulk drive trigger) honestly addresses ordering limits while scoping out pre-existing #2221 behavior.
3. **Test Coverage**: §9 explicitly enumerates the abort/fence race tests, callback commit-guard races, and journal envelope/cap tests.

No `BLOCKER` or `MAJOR` issues remain. Below are the minor implementation guidelines and nits.

---

### Findings

#### 1. MINOR: Atomic revalidation-and-commit under daemon lifecycle lock
- **Evidence**: [`plan.md:798-807`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L798-L807) & [`pkg/daemon/daemon_ha_sync.go:51-88`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go#L51-L88)
- **Analysis**: `OnPeerConnected` callbacks execute asynchronously on background goroutines (`go s.OnPeerConnected()`, [`sync_conn.go:144`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L144)). If revalidating the guard (`abortGen == admissionGen && slot == admittedSlot`) and performing the lifecycle state stores (`d.syncPeerConnected.Store(true)`, etc.) are not performed atomically together under a lifecycle mutex (e.g. `d.syncMu`), a Time-of-Check to Time-of-Use (TOCTOU) race exists: a disconnect event (`onSessionSyncPeerDisconnected`, [`daemon_ha_sync.go:109`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go#L109)) on another thread can advance `abortGen`, detach the slot, and store `syncPeerConnected = false` *after* the connect callback revalidates but *before* it writes `syncPeerConnected = true`.
- **Recommendation**: Mandate in §5.6 that the commit guard revalidation and state mutation must be executed atomically under the daemon lifecycle lock.

#### 2. MINOR: Minimum inter-bulk interval (cooldown) for sender-cap bulk triggers
- **Evidence**: [`plan.md:851-857`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L851-L857) & [`pkg/cluster/sync_conn_gen.go:45`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go#L45)
- **Analysis**: Under sustained capacity saturation (>200,000 active sessions), continuous session churn repeatedly triggers layer (c)'s sender-cap bulk drive. Marking the key range for a bulk drive must coalesce on a single "bulk dirty/pending" flag and respect a minimum inter-bulk cooldown timer to prevent a continuous bulk-sync CPU/network storm under heavy load.
- **Recommendation**: Explicitly specify dirty-flag coalescing and minimum inter-bulk cooldown in layer (c).

#### 3. NIT: Complete enumeration of bulk lifecycle callback stores
- **Evidence**: [`plan.md:788-807`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L788-L807) & [`pkg/daemon/daemon_ha_sync.go:90-107`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go#L90-L107)
- **Analysis**: Line 789 explicitly names `onSessionSyncPeerConnected` (`:51/:68/:81`), but `onSessionSyncBulkReceived` ([`daemon_ha_sync.go:90`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go#L90)) and `onSessionSyncBulkAckReceived` ([`daemon_ha_sync.go:103`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go#L103)) also perform lifecycle stores (`syncBulkPrimed=true`, VRRP hold release, `syncPeerBulkPrimed=true`).
- **Recommendation**: Include `onSessionSyncBulkReceived` and `onSessionSyncBulkAckReceived` alongside `onSessionSyncPeerConnected` in the lifecycle store inventory for completeness.
