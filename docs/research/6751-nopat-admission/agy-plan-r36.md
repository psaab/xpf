# AGY hostile plan review — #6751 (round 36)

# AGY Hostile Plan Review — #6751 Plan v15.24 (Round 36 Convergence Adjudication)

**Verdict**: **PLAN-READY-WITH-NITS**

---

### Executive Summary & Convergence Decision

Plan doc [`docs/research/6751-nopat-admission/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md) (v15.24, commit `5e664a8ee`) has been reviewed line-by-line against Codex r35's 6 findings (1 BLOCKER, 1 MAJOR, 3 MINORs, 1 NIT), AGY r35's 3 items, and Claude SMR r36's fold-check. 

- **Substrate & Core Status**: Both design forks are fully settled (**PATH A** sole-writer helper in [§4.0.1](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L193-L451); **Option (a)** preserve-first + exact PAT fallback in [§4](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L542-L654)). Three independent passes (AGY r35, Codex r35, Claude SMR r36) have confirmed zero kill-shots against the option-(a) core.
- **Fold Verification**: All Codex r35 and AGY r35 findings are correctly, textually, and cleanly integrated into v15.24.
- **Convergence**: Zero BLOCKER or MAJOR defects survive in v15.24. No internal contradictions between sections remain. The remaining items are minor implementation-level clarifications.

---

### 1. Codex r35 BLOCKER Attack & Fold Verification (Quiet Interval Admission Fence)

**Fold Verification** ([`plan.md#L8-L12`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L8-L12), [`plan.md#L513-L522`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L513-L522)):
Codex r35 BLOCKER 1 noted that an old-peer fallback fence relying solely on outbound dial backoff allowed an old peer (initiator) to redial an empty fabric before both slots cleared on a non-initiator. v15.24 converts the quiet interval into an **ADMISSION fence in BOTH directions** — refusing authenticated inbound connections *and* suppressing outbound dialing on both fabrics until the interval exceeding the peer's disconnect-detection bound elapses.

**Hostile Attack Results**:
- **(a) Mutual Fencing (Liveness & Deadlock Analysis)**: If both nodes trigger fencing simultaneously (e.g. dual fabric flap), Node A and Node B enter the quiet interval `T_quiet > T_disconnect_bound`. Both nodes refuse inbound and suppress outbound. During `T_quiet`, both nodes observe all connection slots empty. Because `T_quiet` is governed by a bounded local timer (not waiting on a peer message), when `T_quiet` expires on both sides, both nodes lift their admission fence. The address-selected initiator dials out; the non-initiator accepts inbound. Both sides observe a clean both-slots-empty prior state, successfully arming `needColdPrime`. **No deadlock occurs; liveness is preserved.**
- **(b) Wire Behavior vs 1s Retry (Dual-Slot Race Elimination)**: During `T_quiet`, the peer (initiator) retries connections every 1s ([`sync_conn.go:435`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L435)). The fencing node refuses authenticated inbound (by closing the socket / rejecting authentication). Each retry fails, leaving the peer's connection slots `nil`. Because all retries fail across `T_quiet > T_disconnect_bound`, the peer provably registers both slots empty. When `T_quiet` expires, the peer's next 1s retry succeeds on fabric 0. Since fabric 1 was also confirmed empty during `T_quiet`, the peer observes `wasDisconnected == true` on fabric 0 connection, arming cold-prime. **No post-interval dual-slot race exists.**
- **(c) Fence vs Readiness Timeout**: If a fencing node holds sync hold and a fenced epoch fails to achieve convergence (e.g., persistent isolation), the 30s readiness timeout (`manager.go:372`) fires as a global upper bound, releasing sync hold degraded. **This is the exact designed, bounded failure posture.**

---

### 2. Codex r35 MAJOR Attack & Fold Verification (Worker Outcomes & §5.6 Supersession)

**Fold Verification** ([`plan.md#L12-L15`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L12-L15), [`plan.md#L248-L259`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L248-L259)):
Codex r35 MAJOR 2 identified that worker handlers returned `()`, allowing worker reserve/install refusals to disappear while `BulkEnd` ACKed. v15.24 makes worker outcome reporting mandatory before the barrier ACK and explicitly supersedes §5.6's legacy "not fed back" text.

**Hostile Attack Result (Outcome Channel Aggregation)**:
- *Attack*: What is the aggregate import outcome when forward command succeeds on Worker A, but reverse companion command is refused on Worker B?
- *Adjudication*: Under [§4.0.1 Rule 2 & Rule 3](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L248-L312), an import requires complete forward, reverse, and worker installs to complete. If any worker command returns refusal/failure, the entry in the install-confirmation ledger aggregates to **`Failed`** (or stays `Pending` if timed out).
- There is no ambiguous "partial install" or 6th state: `Failed` is the explicit terminal state for any non-successful install. Per Rule 2(c), any `Failed` outcome suppresses `BulkEnd` ACK and aborts/fences the receive epoch.

---

### 3. Codex r35 MINORs Attack & Fold Verification

1. **Daemon-Issued Incarnation** ([`plan.md#L15-L18`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L15-L18), [`plan.md#L409-L416`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L409-L416)):
   - *Fold*: Incarnation is a daemon-issued monotonic generation bound to the validated helper instance.
   - *Attack*: On helper restart, Rust per-worker sequence numbers reset to zero (`event_stream/mod.rs:261`). If incarnation were reused, stale `(E, 100)` frames from the old helper could reject valid `(E, 1..100)` frames from the restarted helper. Because the daemon issues a monotonic generation `G_inc`, the restarted helper carries `G_inc + 1`. Go validates `G_inc + 1 > G_inc`, resets per-worker high-water marks, and invalidates any lingering `G_inc` frames. **Watermark reuse dies.**
2. **`ConfirmedAliasNoop` Terminalization** ([`plan.md#L18-L19`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L18-L19), [`plan.md#L304-L312`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L304-L312)):
   - *Fold*: `ConfirmedAliasNoop` terminalizes only after P2's purge reports one of `deleted`, `absent`, or `publication-mismatch-to-newer`.
   - *Attack*: A provisional alias import stays `Pending` until P2 executes inside the helper. If P2 returns `deleted`/`absent`, or finds the entry replaced by a newer session (`publication-mismatch-to-newer`), it transitions to `ConfirmedAliasNoop`. Purge failure yields `Failed`; timeout yields `Pending` (fencing before reconcile). **No unpurged alias publication can linger behind an ACKed bulk.**
3. **Origin-Predicate Replica Refresh with Monotonic `last_seen`** ([`plan.md#L19-L21`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L19-L21), [`plan.md#L365-L378`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L365-L378)):
   - *Fold*: Refresh updates evaluate the entry's `Origin` marker. Only `origin == Owner` updates policy_id and counters; non-owner replicas update only `last_seen` via `max(current, candidate)`.
   - *Attack*: Replicas sharing the adopted `session_id` can no longer corrupt owner policy/counter state or drag `last_seen` backward with a stale timestamp. **State corruption and timestamp regression are eliminated.**

---

### 4. Full-Plan Re-Attack & Cross-Sectional Sweep

A full sweep across all sections of v15.24 (`plan.md#L1-L3059`) confirms complete internal consistency:
- **Substrate vs Mechanism**: PATH A sole-writer helper (§4.0.1) and Option (a) identity reservation (§4) interface cleanly.
- **Ledgers vs Reconcile**: Section 4.0.1 Rule 3's two-ledger model (`bulkRecv` membership recorded at decode vs helper `install-confirmation` ledger) aligns with Section 5.6 quarantine resolution.
- **Wire Preservation**: Section 6 ([`plan.md#L2457-L2488`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2457-L2488)) accurately reflects the #1961-safe additive optional fields (`syncMsgCapability`, ordering tuple `(worker_id, seq, incarnation/epoch)`, prime-REQUEST bit, provenance bit).
- **Test Coverage**: Section 9 ([`plan.md#L2612-L3059`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2612-L3059)) includes exhaustive test cases for every race, fence, epoch boundary, and arbiter placement rule.

---

### 5. Numbered Findings (Nits Only)

1. **[NIT] Outbound Disconnect Socket Teardown Wire Mechanism**
   - **File:Line**: [`plan.md#L513-L522`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L513-L522) (§4.0.2 / §5.6)
   - **Description**: While inbound refusal is correctly specified as dropping/refusing authenticated connections, implementation PRs should explicitly specify TCP socket close/RST (rather than passive drop) for immediate connection failure feedback to the peer's 1s retry loop.

2. **[NIT] Quiet Interval Duration Parameterization**
   - **File:Line**: [`plan.md#L516-L518`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L516-L518) (§4.0.2)
   - **Description**: The quiet interval duration is specified as "exceeding the peer's disconnect-detection bound". The implementation PR should define this explicitly as `quiet_interval = 2.5 * keepalive_timeout` (e.g. 7.5s for a 3s keepalive timeout) to ensure safety against network jitter.

---

### Conclusion

v15.24 is **PLAN-READY-WITH-NITS**. All architectural, mathematical, state-machine, and concurrency boundaries are fully specified and verified across all three independent reviewer channels. Implementation may proceed.
