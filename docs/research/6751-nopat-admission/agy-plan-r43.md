# AGY hostile plan review — #6751 (round 43)

# Adversarial Plan Review: Issue #6751 — Research Round 43 (Convergence Adjudication)

**Target Document**: [`docs/research/6751-nopat-admission/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md) (v15.31, commit `a74b81dad`)  
**Verdict**: **`PLAN-READY-WITH-NITS`**

---

## Executive Summary & Attack Verification

All four Codex r42 `BLOCKER`s, two `MAJOR`s, and one `NIT` — as well as AGY r42's two `NIT`s — have been folded into v15.31 (commit `a74b81dad`). Grep-level verification confirms that the text-level contradiction class is exhausted, the logic hole in fence engagement/hold arming is closed, the private-RG readiness gate is correctly conditioned on configured fabric endpoints, and historical steady-state policy reversals are explicitly priced and pinned.

---

## Targeted Verification & Attack Findings

### 1. Codex r42 BLOCKER 3 Fold Attack (Fence Engagement & Hold Arming Logic)

- **(a) Engagement Arming vs. Aborted Fence**:
  - [`plan.md:797-799`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L797-L799) explicitly specifies that the fence-engagement lifecycle event's commit unit sets `syncReady = false` with its event tag AND re-arms the classic RETH VRRP sync hold.
  - If a fence aborts prior to its degraded terminal, generation bumping ([`plan.md:779-782`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L779-L782)) invalidates the old fence timer. Readiness stays `false` until a peer reconnects and completes a bulk sync ([`plan.md:1738-1748`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1738-L1748), [`plan.md:2072-2073`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2072-L2073)).
  - This is the correct fail-closed posture: an aborted/in-progress fence must not permit election takeover before session state is fully re-synchronized.
- **(b) 30s VRRP Hold Bound vs. Degraded Terminal Ordering**:
  - The derived fence quiet interval is `2 × syncReadDeadline + 5s` = 25s ([`plan.md:668`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L668), [`plan.md:770`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L770), [`plan.md:3474`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3474)).
  - The classic RETH VRRP hold bound is 30s (`pkg/vrrp/manager.go:351`).
  - The fence-owned degraded terminal fires first at 25s (within the 30s bound), executing a degraded release (`SetSyncReady(true)` without setting `syncBulkPrimed`) ([`plan.md:802-808`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L802-L808)).
  - [`plan.md:833-835`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L833-L835) explicitly names that the fence's release cannot outlast the applicable class's own bound. Ordering is coherent.
- **(c) Disjointness from Issue #466 Ordinary Disconnects**:
  - Text placement at [`plan.md:18-19`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L18-L19) and [`plan.md:799-801`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L799-L801) explicitly decouples the paths: ordinary unfenced disconnects retain the #466 warm-disconnect preserve rule (`pkg/daemon/daemon_ha_sync.go:113-136`), whereas fence engagement is an explicit lifecycle event whose commit unit sets readiness `false` and re-arms the hold. The two paths are disjoint by event type.

---

### 2. Codex r42 BLOCKER 4 Fold Attack (Conditioned Private-RG Gate & Permanently Down Peer)

- **Conditioned Arming Predicate**:
  - [`plan.md:820-831`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L820-L831) conditions the private-RG sync-readiness gate on session sync being configured with fabric endpoints (matching the startup timer arming predicate in `pkg/daemon/daemon_run_bringup.go:238-240`). Default private-RG clusters without session sync are untouched no-ops.
- **Permanent Peer Down Analysis**:
  - For a sync-configured cluster where the peer is permanently dead/down, takeover is **not** stranded forever:
    1. At startup, the bringup release timer (`daemon_run_bringup.go:238-240`) fires at 30s to set sync ready.
    2. During runtime after a fence event, the fence-owned degraded terminal ([`plan.md:773-774`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L773-L774), [`plan.md:802-804`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L802-L804)) fires at 25s, releasing the sync hold.
- **Section 9 Test Pins**:
  - Both takeover refusal on un-ready sync-configured clusters and the no-op behavior on non-sync clusters are pinned at [`plan.md:3127-3133`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3127-L3133).

---

### 3. Codex r42 BLOCKER 1 / MAJOR 6 Sweep Verification

- **Grep Sweep for `definitive`**:
  - Verified across all occurrences in `plan.md`. Every passage claiming definitive alias resolution or snapshot purging is explicitly qualified with `WHEN THE WINDOW IS CAPABILITY-ADVERTISING` (e.g., [`plan.md:2467`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2467), [`plan.md:3005`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3005), [`plan.md:3315`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3315), [`plan.md:3442`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3442)) or describes the complete-prime pass (which is capability-advertising by definition).
- **Grep Sweep for `current store`**:
  - Line 2968's impossible "current store" reference has been replaced at [`plan.md:3000-3004`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3000-L3004) with the **decode-time BASE-IDENTITY INDEX**, where `RTFlowSessionID` exists before BPF lifting. Remaining uses of "current store" ([`plan.md:2411`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2411), [`plan.md:3454`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3454)) are restricted to incremental-delta fallback dispositioning, which does not perform lineage clearing.

---

### 4. Codex r42 MAJOR 5 Fold Verification

- **Section 8 Pricing & History Refs**:
  - Priced as `MED (priced)` at [`plan.md:3042`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3042).
  - Cited history refs verified to exist at exact line numbers: [`docs/issues/issue-history.md:8513-8527`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/issues/issue-history.md#L8513-L8527) and [`docs/issues/pr-history.md:4277-4289`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/issues/pr-history.md#L4277-L4289).
- **Section 9 Test Pins & Permissive Test Update**:
  - The permissive expectation update at `pkg/daemon/vip_readiness_test.go:345-389` and the refusal/no-op pins are explicitly documented in §8 ([`plan.md:3042`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3042)) and §9 ([`plan.md:3127-3133`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3127-L3133)).

---

### 5. Full-Plan Convergence Sweep & Findings

Both architecture/substrate forks (Path A sole-writer helper; Option (a) reserve-or-PAT core) remain settled with four independent no-kill-shot confirmations. The fence arms what it releases, the gate is conditioned, and text-level contradictions are eliminated.

#### Finding 1 (NIT) — Incomplete 5-event inventory recap in Section 9 callback race summary
- **File & Lines**: [`docs/research/6751-nopat-admission/plan.md:3186`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3186)
- **Detail**: While §4 ([`plan.md:778`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L778)) and §5.6 ([`plan.md:1698`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1698)) explicitly define the complete seven-event inventory `(abort, admission, disconnect, bulk-received, bulk-ack-received, readiness-timeout, AND fence-cycle expiry)`, a historical recap line in §9 ([`plan.md:3186`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3186)) summarizes the older r24 callback list as `(connect, disconnect, bulk-received, bulk-ack-received, readiness-timeout)`.
- **Remediation**: Update line 3186 parenthetical to align with the complete seven-event inventory.

---

## Final Verdict

**`PLAN-READY-WITH-NITS`**

The plan is fully converged, self-consistent, and ready for implementation.
