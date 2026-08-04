# AGY hostile plan review — #6751 (round 44)

# Adversarial Plan Review: Issue #6751 — Research Round 44 (Convergence Adjudication)

**Target Document**: [`docs/research/6751-nopat-admission/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md) (v15.32, commit `4912e3043`)  
**Verdict**: **`PLAN-READY`**

---

## Executive Summary & Fold Verification

All four Codex r43 `BLOCKER`s, one `MINOR`, and AGY r43's `NIT` have been folded into v15.32 (commit `4912e3043`). Grep-level verification against [`plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md) confirms that:
1. Decode-time insertion confirmation is evidence-based (requiring equal non-zero `RTFlowSessionID`s) while window-authority decisions (definitive BulkEnd, P1 re-evaluation, lineage clear, purges) are capability-qualified.
2. The direct/no-VRRP sync-readiness gate covers the full direct domain (`NoRethVRRP || PrivateRGElection`), supports either endpoint pair (`ControlInterface + PeerAddress` or fabric), and preserves the peer-dead election bypass.
3. Cold-start startup has a bounded degraded release while preserving the no-release-without-reconnect rule for warm disconnects.
4. Classic hold re-arming routes through the lifecycle queue as a generation-bound fence-cycle event, eliminating the untagged `time.AfterFunc` race, with §9 explicitly pinning stale expiry after re-arm.

---

## Targeted Verification & Attack Findings

### 1. Codex r43 BLOCKER 1 Fold Attack (Evidence-Based Confirmation vs Window Authority)

- **(a) Pre-Learn Mixed Deployment**:
  - A new sender that has not yet learned the receiver's capability advertisement emits non-zero `RTFlowSessionID`s. Decode-time insertion confirmation evaluates equal non-zero `RTFlowSessionID`s between base and alias frames (`plan.md:3073-3080`). Equal non-zero IDs are intrinsic per-frame evidence, so insertion confirmation drops aliases cleanly on any window class.
  - When the receiver's capability advertisement arrives mid-connection/mid-window (via ordered pre-data send or periodic re-advertisement, `plan.md:727-734`), sender omission kicks in for subsequent frames. Mid-connection capability discovery triggers a fresh capable prime on the receiver (`plan.md:735-738`).
- **(b) Forged-ID Trust Model**:
  - Confirmation requires the alias `RTFlowSessionID` to equal the sibling base session ID (`plan.md:2497-2498`). Chassis cluster session sync connections operate between PSK-authenticated daemons (`pkg/cluster/sync_conn.go`). Intra-cluster cluster nodes are trusted infrastructure; the quarantine and confirmation mechanism protects against cross-session return traffic misdirection and race conditions, not malicious cluster peers.
- **(c) Capability-Qualified Window Authority**:
  - Verified across all relevant passages: window-authority decisions (definitive BulkEnd pass, P1 re-evaluation, lineage clears, snapshot purges) are explicitly capability-qualified and execute **ONLY** against capability-advertising windows ([`plan.md:704-712`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L704-L712), [`plan.md:2427-2433`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2427-L2433), [`plan.md:2527-2529`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2527-L2529), [`plan.md:2561-2563`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2561-L2563), [`plan.md:3080-3088`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3080-L3088), [`plan.md:3395`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3395), [`plan.md:3522`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3522)).

---

### 2. Codex r43 BLOCKER 2 Fold Attack (Direct Takeover Domain, Endpoint Pairs & Peer-Dead Bypass)

- **Direct Takeover Domain**:
  - The sync-readiness gate covers the entire direct takeover domain (`NoRethVRRP || PrivateRGElection`, [`pkg/daemon/daemon_ha_vip.go:100`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_vip.go#L100), [`pkg/vrrp/vrrp.go:139`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/vrrp/vrrp.go#L139)), including the `no-private-rg-election + no-reth-vrrp` variant ([`compiler_validate_strict_reth_vrrp_4826_test.go:116`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/config/compiler_validate_strict_reth_vrrp_4826_test.go#L116)) ([`plan.md:860-869`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L860-L869)).
- **Endpoint Pair Configuration**:
  - Session sync configuration predicate engages when session sync is configured with either supported endpoint pair: control-link (`ControlInterface + PeerAddress`, preferred) or fabric endpoints fallback ([`pkg/daemon/daemon_ha_sync.go:774`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go#L774)) ([`plan.md:869-874`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L869-L874)).
- **Control-Link Failure in Dual-Configured Setup**:
  - Session sync configuration (`IsSyncConfigured()`) is a static daemon configuration property established at bringup. If the control link fails mid-run in a dual-configured deployment, session sync transport falls back or enters disconnected state.
  - If the peer is dead, the peer-dead election bypass ([`pkg/cluster/election.go:427`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/election.go#L427)) fires to allow ungated crash takeover ([`plan.md:883-886`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L883-L886)). If the peer is alive, `syncReady` tracks transport connection health while the configuration predicate remains `true`.

---

### 3. Codex r43 BLOCKER 3 Fold Attack (Cold-Start Release, Heartbeat Precondition & Warm Disconnect)

- **Cold-Start Bounded Degraded Release**:
  - For a never-connected cold start where `syncReady` starts false ([`pkg/cluster/manager.go:299`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/manager.go#L299)) and initial session sync TCP dials fail ([`pkg/cluster/sync_conn.go:462`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L462)), the `readiness-timeout` event fires at the cold-start bound to execute degraded release (`SetSyncReady(true)` without setting `syncBulkPrimed`). Takeover then proceeds by normal VRRP priority with the heartbeat-alive precondition ([`plan.md:776-791`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L776-L791)).
- **Heartbeat UP vs Peer Dead Behind Partition**:
  - If the peer is actually dead behind a partition, the peer-dead election bypass ([`pkg/cluster/election.go:427`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/election.go#L427)) fires first, enabling immediate crash takeover without waiting for any timer ([`plan.md:790-791`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L776-L791), [`plan.md:883-886`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L883-L886)). If heartbeat is UP, normal VRRP priority elects exactly one master.
- **Text Separation (Warm Disconnect vs Cold Start)**:
  - Warm disconnects (connected, then disconnected) retain the [`session_sync_readiness_test.go:33`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/session_sync_readiness_test.go#L33) rule (no release on timeout alone without reconnect, [`pkg/daemon/daemon_ha_sync.go:113`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go#L113)). Never-connected cold start is an explicit separate state ([`plan.md:792-798`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L792-L798)).
- **Fence Parameter Inventory**:
  - The cold-start bound is named at implementation alongside `quiet_interval = 2 × syncReadDeadline + 5s` (25s) ([`plan.md:671`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L671), [`plan.md:773`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L773), [`plan.md:798`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L798)).

---

### 4. Codex r43 BLOCKER 4 Fold Verification (Hold Re-Arm & Section 9 Stale-Expiry Pin)

- **Lifecycle Queue Re-Arm**:
  - Re-arming the classic hold goes through the lifecycle queue as a generation-bound fence-cycle event (or fence-owned degraded terminal as sole release path), eliminating the untagged `time.AfterFunc` race at `manager.go:354/372/389` ([`plan.md:829-843`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L829-L843)).
- **Section 9 Stale-Expiry Pin**:
  - §9 explicitly pins firing old fence-cycle expiry after a higher-generation abort/re-arm and asserting NO readiness flip, NO VRRP-hold release, and NO private-gate release ([`plan.md:2397-2401`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2397-L2401)).

---

### 5. Full-Plan Convergence Sweep

- Both substrate/architecture forks (Path A sole-writer helper; Option (a) reserve-or-PAT core) remain settled with four independent no-kill-shot confirmations ([`plan.md:205`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L205), [`plan.md:922-970`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L922-L970)).
- Confirmation classes are split, readiness gate is conditioned, cold start is bounded, and hold re-arm is generation-bound.
- All event inventory recaps are aligned with the 7-event inventory ([`plan.md:1753`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1753), [`plan.md:3266`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3266)).
- No open BLOCKER, MAJOR, MINOR, or NIT findings remain in v15.32.

---

## Final Verdict

**`PLAN-READY`**

The plan is fully converged, self-consistent, and ready for implementation.
