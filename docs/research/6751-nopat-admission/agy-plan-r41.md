# AGY hostile plan review — #6751 (round 41)

# Adversarial PLAN Review — #6751 (Round 41: Convergence Re-verification)

**Repo (worktree)**: `/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission`  
**Plan doc**: [`docs/research/6751-nopat-admission/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md) (v15.29, commit `d34e8faf1`)  
**Verdict**: **PLAN-READY-WITH-NITS**

---

### Executive Summary

In Round 40, Codex identified 2 BLOCKERs, 1 MAJOR, and 1 MINOR regarding capability advertisement ordering, authority binding, degraded terminal code-reality, and debt terminal composition. Version **v15.29** folded all four findings. 

This Round 41 review executed a line-by-line adversarial attack against the v15.29 folds and performed grep-level verification across the repository codebase ([`pkg/cluster/sync_conn.go`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go), [`pkg/cluster/sync_conn_read.go`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go), [`pkg/cluster/sync.go`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync.go), [`pkg/daemon/daemon_ha_sync.go`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go), [`pkg/vrrp/manager.go`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/vrrp/manager.go), and [`userspace-dp/src/nat/source.rs`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs)).

No BLOCKER or MAJOR issue survives. Both fundamental design choices remain settled:
1. **Behavior Fork**: Option (a) — preserve-first + PAT-on-collision (wire-stable for non-colliding flows).
2. **Substrate Fork**: PATH A — helper as sole writer of session mirror rows with exact-incarnation transactions.

---

### Detailed Attack & Analysis of v15.29 Folds

#### 1. Codex r40 BLOCKER 1 Fold Analysis
*(Per-window authority binding; disposition-only non-capable resolution with suspects keeping marks; ordered pre-data capability send with UNKNOWN = non-capable; fresh capable prime on first-learn)*

* **(a) Placement of ordered send in connection path**:
  In [`pkg/cluster/sync_conn.go:130-137`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L130-L137), `installConn` is called and `receiveLoop` is spawned. Under v15.29 ([`plan.md:724-726`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L724-L726)), the contract requires sending the capability frame on the TCP connection immediately after handshake wrapping and before `s.sendClockSync` or `doBulkSync`. 
  *Can a fast peer's `BulkStart` win the race?* No. TCP stream delivery guarantees strict FIFO byte ordering. Peer A emits `CapabilityFrame` followed by `BulkStart`. Peer B's `receiveLoop` processes `CapabilityFrame` first, updating Peer A's state to `CAPABLE`, before reading `BulkStart`. At `BulkStart`, Peer B records the window authority class matching the peer's capability at that exact moment (`CAPABLE`). If Peer A is legacy (no capability frame sent), Peer B's capability state for Peer A remains `UNKNOWN` (reset on setup, treated as non-capable), binding the window to `FRAMING-ONLY`.
* **(b) Capability frame lost mid-connection**:
  If a frame is delayed or lost, the receiver keeps state as `UNKNOWN` (`FRAMING-ONLY` window). Once the capability frame arrives (via the periodic `syncMsgCapability` ticker), the receiver learns capability for the first time mid-connection. Under v15.29 ([`plan.md:727-731`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L727-L731)), the receiver immediately forces a **fresh capable prime** (`prime-REQUEST`). The capable peer responds with an authoritative bulk snapshot, allowing all pending `alias-suspect` rows held under prior framing-only windows to resolve at the definitive pass.
* **(c) Disposition-only resolution vs. ACK rule for genuine rows**:
  Under a non-capability window ([`plan.md:712-718`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L712-L718)), the resolution is **disposition-only**: provisional import succeeds so genuine rows import normally (preserving legacy interop), but suspect rows retain their `alias-suspect` mark UNRESOLVED. This cleanly decouples framing transport ACK from lineage resolution: delivery debt discharges at `BulkEnd-ACK`, while receiver alias-proof debt stays open until a capable snapshot arrives or the row closes.

#### 2. Codex r40 BLOCKER 2 Fold Analysis
*(Derived interval from ≈20s detector; fence-owned disconnected-eligible degraded terminal; preserved 5s connected-only timer; classic RETH VRRP 30s hold + private-RG gate as outer bounds)*

* **(a) Precedence between fence release and 5s timer**:
  [`pkg/daemon/daemon_ha_sync.go:41,109`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go#L41) shows the 5s readiness timer checks `!d.syncPeerConnected.Load()` and aborts on disconnect (pinned by [`pkg/daemon/session_sync_readiness_test.go:33`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/session_sync_readiness_test.go#L33)). The fence degraded release ([`plan.md:760-774`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L760-L774)) is explicitly **fence-owned and disconnected-eligible**, using the fence's own cycle timer (`quiet interval + re-fence`). There is no conflict: the connected 5s timer handles connected-peer readiness, while the fence timer handles disconnected or unresponsive peers.
* **(b) Derived quiet interval**:
  Verified in [`pkg/cluster/sync.go:90`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync.go#L90) (`syncReadDeadline = 10s`) and [`pkg/cluster/sync_conn_read.go:33-36`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go#L33) (`missedHeartbeats >= 2`). ACK-capable disconnect detection takes 2 × 10s = 20s. The quiet interval derives directly from this 20s bound plus jitter margin.
* **(c) Fence release vs. Classic 30s VRRP hold**:
  In [`pkg/vrrp/manager.go:351`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/vrrp/manager.go#L351), `SetSyncHold` defaults to 30s. The fence degraded release fires at ≈20s + jitter margin (e.g. ~25s), which occurs before the VRRP 30s safety timeout expires. The plan explicitly acknowledges and prices this worst-case failover delay bound ([`plan.md:772`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L772)).

#### 3. Codex r40 MAJOR Fold Analysis
*(Two separate debt terminals: delivery debt at BulkEnd-ACK vs alias-proof debt on capable snapshot or row close)*

* **Peer capability oscillation across reconnects**:
  - *Connection 1 (Capable)*: Peer advertises capability. Capable window authority is bound at `BulkStart`. Definitive pass runs, resolving pending `alias-suspect` rows. Alias-proof debt discharges.
  - *Connection 2 (Legacy / Lost capability frame)*: Peer capability state resets to `UNKNOWN` on connection setup. Window authority binds as `FRAMING-ONLY`. Suspects imported keep `alias-suspect` marks. `BulkEnd-ACK` fires, discharging **delivery debt** (legacy interop preserved), but **alias-proof debt stays open**.
  - *Connection 3 (Capable again)*: Peer advertises capability. State updates to `CAPABLE`, triggering a fresh capable prime. Window authority binds as `CAPABLE`. The definitive pass runs, clearing or lineaging suspects and discharging alias-proof debt.
  - Composition is state-clean and free of residual corruption.

---

### Findings

#### NIT 1: Explicit Jitter Margin Formula in §5.6
* **Location**: [`docs/research/6751-nopat-admission/plan.md:763`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L763)
* **Evidence**: Line 763 states `"for ACK-capable peers, the read-deadline-plus-two-misses bound (≈20s) plus jitter margin"`.
* **Description**: While `≈20s` (derived from `2 * syncReadDeadline` at [`pkg/cluster/sync.go:90`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync.go#L90)) is well-specified, §5.6 could explicitly name the exact additive jitter constant (e.g. `25s` or `syncReadDeadline*2 + 5s`) to prevent minor implementation drift during the upcoming PR phase.

#### NIT 2: Struct Plumbing Inventory for Periodic Ticker Handle
* **Location**: [`docs/research/6751-nopat-admission/plan.md:2787-2797`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2787)
* **Evidence**: Section 6 lists additive Go struct fields (`pub_token`, `alias-stage` on `SyncedSessionEntry`).
* **Description**: Section 6 should explicitly note the `syncCapabilityTicker` (or reuse of `heartbeatTicker`) field inside `SessionSync` in [`pkg/cluster/sync.go`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync.go) to make the `syncMsgCapability` periodic advertisement inventory 100% complete.

---

### Final Convergence Assessment

With v15.29, the plan has achieved complete convergence across all three review teams (AGY, Codex, and Claude SMR). 

* **Option-(a) Core Integrity**: Un-falsified across 41 rounds.
* **PATH A Substrate**: Fully specified with exact-incarnation helper transactions and bounded queue refusal.
* **Capability Machinery**: Wire-honest, bootstrap-ordered, and per-window bound.
* **Debt & Degraded Terminals**: Separated and grounded in empirical codebase bounds.

The plan is **READY** for implementation.
