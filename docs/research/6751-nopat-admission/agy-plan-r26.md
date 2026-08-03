# AGY hostile plan review — #6751 (round 26)

**PLAN-READY-WITH-NITS**

---

### Round 26 Convergence Adjudication Analysis

#### 1. Lifecycle Event Ordering & Effect Scoping (`(abortGeneration, lifecycleSequence)`)
* **Attack 1(a) — Is queue-admission the only tag source?**
  * **Verified.** In [`docs/research/6751-nopat-admission/plan.md:833-842`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L833-L842), tags are minted exclusively at the point of admission onto the serialized lifecycle event queue (`Enqueue`). Event callbacks only receive pre-tagged event envelopes `(abortGeneration, lifecycleSequence)`; they do not access or invoke the tag generator directly. No callback can forge ahead or generate out-of-order tags.
* **Attack 1(b) — Does strict-inequality tag CAS close the `true@G`/`false@G` scenario by construction?**
  * **Verified.** Even when two events share the same `abortGeneration` $G$ (e.g., C1 disconnect $D1$ and C2 connect $A2$), queue admission assigns monotonically increasing sequence numbers: $\text{tag}(D1) = (G, k)$ and $\text{tag}(A2) = (G, k+1)$. If $A2$ commits first, storing $(G, k+1)$ with value `true`, a delayed $D1$ callback executing later evaluates $\text{tag}(D1) > \text{tag}_{\text{stored}} \implies (G, k) > (G, k+1)$, which evaluates to `false`. The stale `false` write is rejected by the CAS. If $D1$ commits first, $A2$'s tag $(G, k+1) > (G, k)$ succeeds and stores `true`. The stored state deterministically reflects queue admission order regardless of callback execution timing.
* **Attack 1(c) — Does the effects-inside-commit-unit rule cover [`pkg/daemon/daemon_ha_sync.go:90`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go#L90)?**
  * **Verified.** Safety-critical side-effects (`stopSyncReadyTimer`, `vrrpMgr.ReleaseSyncHold`, `cluster.SetSyncReady`) in [`daemon_ha_sync.go:90-101`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go#L90-L101) are placed inside the commit unit executed when `onSessionSyncBulkReceived`'s tag CAS succeeds [`plan.md:853-864`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L853-L864). If the CAS fails due to a stale event, the handler returns immediately without executing any side-effects.

#### 2. Send Guard & Epoch Envelope Discipline
* **Attack 2(a) — Do all four flow shapes pass through the envelope path?**
  * **Verified against [`pkg/cluster/sync_conn_write.go:36/135/268`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go#L36)**:
    1. Direct session upserts (`QueueSessionV4/V6` [`:56/:63`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go#L56-L63)).
    2. Direct session deletes (`QueueDeleteV4/V6` [`:77/:87`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go#L77-L87)).
    3. Replayed deletes from journal (`flushDeleteJournal` [`:135-175`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go#L135-L175)).
    4. Cold-prime bulk transfers (`doBulkSync` [`sync_conn.go:194`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L194)).
    All four enqueue via `queueMessage` / envelope wrappers stamping `envelope{msg, epoch: s.currentEpoch}` at enqueue time [`:36`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go#L36). `sendLoop` [`:268`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go#L268) inspects every dequeued envelope and drops any entry where `envelope.epoch < s.currentEpoch`.
* **Attack 2(b) — Does any transition discard deltas without scheduling a prime?**
  * **Verified against [`pkg/cluster/sync_conn.go:178/208/235/278`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L178)**: Connections created on a full disconnect $\rightarrow$ connect edge (`d.wasDisconnected == true` [`sync_conn.go:278`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L278)) advance the connection epoch AND set `needColdPrime = true`, driving `doBulkSync()` [`sync_conn.go:194`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L194). Routine single-fabric flips (`d.wasDisconnected == false` [`sync_conn.go:178/208`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L178)) do NOT advance the epoch, so `sendLoop` retains all valid deltas queued prior to or during the flip. No transition discards deltas without an authoritative cold-prime backstop.

---

### Findings

#### NIT 1: Line number references in lifecycle inventory documentation
* **File & Line**: [`docs/research/6751-nopat-admission/plan.md:868-870`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L868-L870)
* **Description**: Section 5.6 lists explicit source line numbers for callbacks in [`pkg/daemon/daemon_ha_sync.go`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go) (`:51/:68/:81`, `:109`, `:90`, `:103`). While exact for current master, line numbers drift as surrounding functions are edited.
* **Recommendation**: Maintain function/symbol names as the primary identifier in plan text, marking line numbers as illustrative snapshot points.

#### NIT 2: Prometheus metric descriptor registration test assertion
* **File & Line**: [`docs/research/6751-nopat-admission/plan.md:1325-1339`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1325-L1339)
* **Description**: Section 5.8 specifies 7 total counters (4 helper + 3 Go cluster). To prevent registration panics or silent omissions during metric init, §9's test suite should explicitly assert `prometheus.MustRegister` coverage for all 7 counter descriptors.
* **Recommendation**: Add a 1-line explicit check in §9 verifying unit test initialization of the 7 metric descriptors.

---

### Summary of Work

1. **Adjudication**: Executed a read-only convergence review of [`docs/research/6751-nopat-admission/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md) (v15.13+, commit `71f7ee78c` on branch `research/6751-nopat-admission`).
2. **Verification**: Checked all attack vectors across lifecycle event tagging (`(abortGeneration, lifecycleSequence)`), strict-inequality CAS, committed effect scoping in [`pkg/daemon/daemon_ha_sync.go`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go), epoch envelope stamping at enqueue in [`pkg/cluster/sync_conn_write.go`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go), and epoch advance rules in [`pkg/cluster/sync_conn.go`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go).
3. **Verdict**: Issued **PLAN-READY-WITH-NITS** with zero BLOCKERs or MAJORs remaining.
