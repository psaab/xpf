# AGY hostile plan review — #6751 (round 45)

# Adversarial PLAN Review — #6751 (Round 45, Convergence Re-Verification)

**Document**: [`docs/research/6751-nopat-admission/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md) — v15.33 (commit `277230cd8`)  
**Verdict**: **PLAN-READY-WITH-NITS**

---

### Detailed Attack & Verification Analysis

#### 1. Codex r44 BLOCKER 1 Fold (Evidence vs Authority Split Verification)
- **Grep Sweep**: Searched `definitive` and `confirm` across all 3,771 lines of [`plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md).
- **Passage Checks**:
  1. [`plan.md:704-718`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L704-L718) & [`:733-734`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L733-L734): Inline qualification explicitly states the gate governs *window-authority decisions only*, while decode-time insertion confirmation remains *evidence-based* (equal non-zero `RTFlowSessionID`, decoding to 0 on old-sender windows per [`sync_protocol.go:491`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go#L491) / [`sync_rtflow_session_id_5212_test.go:64`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_rtflow_session_id_5212_test.go#L64)).
  2. [`plan.md:2465-2471`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2465-L2471): Scoped epoch pass as `LINEAGE-DEFINITIVE only for capability-advertising windows, and DISPOSITION-ONLY for non-capable windows`.
  3. [`plan.md:2478-2486`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2478-L2486): BulkEnd sibling-base check qualified with `WHEN THE WINDOW IS CAPABILITY-ADVERTISING`, while non-capable windows run admission without lineage-definitive clearing.
  4. [`plan.md:2610-2612`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2610-L2612) & [`:3461-3462`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3461-L3462): Rule (P1) re-evaluation at BulkEnd scoped to `every completed CAPABILITY-ADVERTISING BulkEnd`.
  5. [`plan.md:3125-3143`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3125-L3143): Confirmation class broken out cleanly in summary text.
- **Verification Result**: Clean. Zero remaining passages assert unconditional lineage confirmation or definitive resolution on non-capability windows.

---

#### 2. Codex r44 BLOCKER 2 Fold (Mode-Aware Three-Epoch Commit Predicate)
- **Epoch-Zero Collision (Boot N → Boot N+1)**: Stale events from boot N cannot commit in boot N+1. The event's lifecycle tag `(abortGeneration, lifecycleSequence)` ([`plan.md:1814-1815`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1814-L1815)) advances on any teardown/bringup. Boot N's event fails the tag CAS regardless of connection epoch 0 matching.
- **Mid-Bound Connect Transition (Arming Epoch 0 → Current Epoch 1)**: If connection completes during the `syncReadyTimeout` bound:
  - Branch (i) (`arming epoch ZERO and still zero at commit`, [`plan.md:1821`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1821)) fails because current epoch is 1.
  - Branch (iii) (`STILL CONNECTED at the arming epoch`, [`plan.md:1830`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1830)) fails because arming epoch (0) != current epoch (1).
  - No release occurs from the timer; the fresh connection's own bulk path drives readiness normally.
- **Bare-Boolean Connected Check Sweep**: Verified at [`plan.md:1833`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1833) that connected state is evaluated strictly as an epoch comparison (`current epoch == arming epoch`), replacing bare boolean checks.

---

#### 3. Codex r44 BLOCKER 3 Fold (Unified Configured Predicate)
- **Mid-Run Transport Re-configuration Attack**: Evaluating `sessionSyncConfigured` as a stable configuration predicate (control-link OR fabric endpoints configured in daemon config) is correct.
- **Rationale**: Live socket flapping (connected vs disconnected) is tracked dynamically via connection epochs. If `sessionSyncConfigured` tracked live socket state, temporary network drops would flip the predicate to "not configured", illegally disarming timers or bypassing the readiness gate mid-run. Tracking stable configuration ensures the readiness gate and cold-start arming remain active whenever session sync is configured. Verified at [`plan.md:795-805`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L795-L805), [`:890-904`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L890-L904), and [`:3254`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3254).

---

#### 4. Codex r44 MINOR / NIT Folds Verification
- **Named Bound**: `syncReadyTimeout` ([`daemon.go:1148`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon.go#L1148)) explicitly named at [`plan.md:28`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L28) and [`plan.md:3248`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3248).
- **Four Regression Cases Pinned**: Verified in §9 at [`plan.md:3250-3259`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3250-L3259):
  1. Simultaneous-never-connected cold boot with healthy heartbeat but failed sync TCP ([`plan.md:3250-3253`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3250-L3253)).
  2. Control-link-only private RG ([`plan.md:3254-3255`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3254-L3255)).
  3. Whole direct domain (`NoRethVRRP || PrivateRGElection`) ([`plan.md:3255-3257`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3255-L3257)).
  4. Peer-dead election-state bypass ([`plan.md:3257-3259`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3257-L3259)).
- **Seven-Event Recap**: Verified in §9 at [`plan.md:3331-3333`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3331-L3333), explicitly naming: `abort`, `admission/connect`, `disconnect`, `bulk-received`, `bulk-ack-received`, `readiness-timeout`, and `fence-cycle expiry`.

---

#### 5. Full-Plan Convergence Sweep
- Both PATH A (sender-side capability frame + receiver-side framing quarantine) and option-(a) (allocator/occupancy/registry/holder core) remain fully settled and intact.
- No new kill-shots or unresolved BLOCKER/MAJOR issues remain in v15.33.

---

### Findings

1. **NIT — Parenthetical in §5.2 branch (ii) connected-state check uses `arming epoch > 0` rather than `current epoch != arming epoch` ([`plan.md:1826`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1826)).**
   While the summary at [`plan.md:20`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L20) correctly states `(epoch differs: INVALIDATED, no release)`, the formal breakdown in §5.2 at [`plan.md:1826`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1826) defines branch (ii) as `(ii) CONNECTED-THEN-DISCONNECTED (arming epoch > 0 and the current epoch differs from the arming epoch)`. If a cold start (arming epoch = 0) connects during the bound (current epoch becomes 1), branch (i) fails (`still zero at commit` is false) and branch (iii) fails (`still connected at arming epoch` is false). The event is logically invalidated as intended, but branch (ii)'s parenthetical precondition strictly says `arming epoch > 0`. Replacing `arming epoch > 0` with `current epoch != arming epoch` in branch (ii)'s parenthetical eliminates any technical ambiguity.
