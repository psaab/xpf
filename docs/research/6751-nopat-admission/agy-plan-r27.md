# AGY hostile plan review — #6751 (round 27)

# Adversarial PLAN Review — #6751 (Round 27 Convergence Adjudication)

**Verdict: PLAN-READY-WITH-NITS**

Plan document reviewed: [`docs/research/6751-nopat-admission/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md) (v15.14, commit `8a2eb427c` on branch `research/6751-nopat-admission`).

---

### Executive Summary & Convergence Status

All BLOCKER and MAJOR findings raised in Round 26 (Codex r26 blockers 1 & 2) have been successfully resolved in v15.14:
1. **Readiness-Timeout Lifecycle Integration**: Readiness-timer expiry no longer executes direct state mutations outside the lifecycle CAS (`daemon_ha_sync.go:40-46`). Expiry only enqueues a transition-tagged `readiness-timeout` lifecycle event; its commit unit re-validates arming generation + connected state and executes `SetSyncReady(true)` under the strict-inequality `(abortGeneration, lifecycleSequence)` tag CAS.
2. **Epoch Barrier & Lossless Direct Bulk Writes**: Prime ordering is now implemented via an **Epoch Barrier** rather than lossy `sendCh` envelope routing. Bulk sync retains its lossless direct-write discipline (`sync_bulk.go:95`), with `BulkEnd` guaranteed to be emitted only after all bulk frames are losslessly written.
3. **§9 Test Enumeration**: All 6 required regression tests (equal-tag overwrite, stale-effects, stalled-after-validation, queued-behind-A, no-prime-flip retention, prime-barrier) are explicitly pinned and testable.

---

### Attack Analysis of v15.14 Folds

#### 1. Readiness-Timeout Fold (Codex r26 BLOCKER 1)

* **(a) Commit Orderings (Expiry Event $E_t$ vs. Disconnect/Cold-Start $E_d$)**:
  * **$E_d$ commits first ($T_d > T_t$)**: $E_d$ sets readiness to `false` and bumps `syncReadyTimerGen`. When the delayed $E_t$ callback attempts to commit, arming-generation re-validation fails. Even if generation validation were bypassed, the tag CAS $T_t > T_d$ fails. $E_t$ produces zero side-effects.
  * **$E_t$ commits first ($T_t < T_d$)**: $E_t$ sets readiness to `true` at tag $T_t$. $E_d$ subsequently commits at tag $T_d > T_t$, setting readiness to `false`. The final state correctly reflects the disconnect.
* **(b) Stop Paths without Disconnect Events (`stopSyncReadyTimer`)**:
  * `onSessionSyncBulkReceived` ([`daemon_ha_sync.go:94`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go#L94)) and comms teardown ([`daemon_ha_sync.go:1413`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go#L1413)) both call `stopSyncReadyTimer()`, which atomically increments `syncReadyTimerGen`.
  * If an expiry event was already enqueued prior to `stopSyncReadyTimer()`, its commit unit re-validates the armed generation against `syncReadyTimerGen`. The check fails, preventing any readiness flip or sync-hold release in a torn-down or bulk-completed lifecycle.
* **(c) Liveness of Designed Timeout Path**:
  * On a genuine cold-start where no bulk arrives, the timer fires and enqueues $E_t$. Arming generation matches, `syncPeerConnected` is `true`, and tag $T_t > T_{\text{connect}}$ succeeds. The commit unit executes `SetSyncReady(true)` and releases the VRRP hold as expected.
* **(d) Inventory Completeness Verification**:
  * Grepping `SetSyncReady` across `pkg/` and `cmd/` yields production calls exclusively in [`pkg/daemon/daemon_ha_sync.go`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go#L46): `:46` (timer expiry), `:83` (connect cold-start), `:99` (bulk received), and `:134` (disconnect). The 6-event inventory (abort, admission, disconnect, bulk-received, bulk-ack-received, readiness-timeout) is exhaustive and complete.

#### 2. Epoch Barrier Fold (Codex r26 BLOCKER 2)

* **(a) Drain Bound & Sustained Session Churn**:
  * When a prime starts, step (i) advances `s.currentEpoch` first. Any new delta enqueued during or after step (i) is stamped with epoch $N+1$.
  * The barrier drain condition in step (ii) only waits for envelopes stamped with epoch $N$ (queued before the advance) to clear `sendCh`. Because no new epoch-$N$ envelopes can ever be created, the count of old-epoch envelopes is strictly bounded by `sendCh` capacity. Sustained churn under epoch $N+1$ cannot cause prime starvation or livelock during the drain phase.
* **(b) New-Epoch-Delta Interleave Safety**:
  * A new-epoch $N+1$ delta sent before, during, or after bulk frames is safe in all three positions because its content post-dates the abort, just as the bulk snapshot does. The receiver's per-key `#2170` generation guard (`installGenGuardV4/V6`) adjudicates any same-key overlap deterministically.
* **(c) Deadlock Analysis (`sendLoop` vs `writeMu`)**:
  * [`pkg/cluster/sync_conn_write.go:268`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go#L268) (`sendLoop`) reads envelopes from `sendCh` without holding `writeMu`. It acquires `writeMu` only per-frame write and releases it immediately. `doBulkSync` waits on channel drain without holding `writeMu`. No circular lock dependency exists.
* **(d) Pre-Start Bulk Abort Safety**:
  * If the barrier drain exceeds its bound, the prime aborts *before* writing any frames. Because `BulkEnd` is never emitted, the peer receiver never runs `reconcileStaleSessions` against an incomplete payload. The recovery machinery retries the bulk cleanly on the next iteration.

#### 3. §9 Regression Test Plan Verification

All six regression tests added in v15.14 ([`plan.md:1600-1645`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1600-L1645)) are non-vacuous and directly testable:
1. `equal-tag overwrite`: Asserts strict-inequality rejection when two callbacks share $(G, k)$.
2. `stale-effects`: Verifies suppression of `stopSyncReadyTimer` and `ReleaseSyncHold` on CAS failure.
3. `stalled-after-validation`: Simulates timer validation pass followed by disconnect commit, verifying expiry CAS failure.
4. `queued-behind-A`: Asserts envelope stamped epoch $N$ is dropped by `sendLoop` when dequeued under epoch $N+1$.
5. `no-prime-flip retention`: Asserts single-fabric reconnect (`wasDisconnected == false`) does not advance epoch or drop deltas.
6. `prime-barrier`: Asserts epoch barrier drains prior to bulk writes and mid-bulk write failure suppresses `BulkEnd`.

#### 4. Full-Plan Re-Attack

* **Alias Quarantine & Event Loop Separation**: The daemon's lifecycle event queue (`daemon_ha_sync.go`) and `pkg/cluster`'s receiver event loop (`sync_conn_read.go`) operate on independent event queues in distinct packages. The readiness-timeout lifecycle fold does not interfere with the alias quarantine event loop.
* **Quarantine Timeout-Admission & Bulk Bookkeeping**: Bulk bookkeeping (`s.bulkRecvV4/V6`) continues to record quarantined keys at decode time, preventing premature stale-session deletion at `BulkEnd`. The epoch barrier guarantees that `BulkEnd` is received only after a complete, lossless bulk transmission.

---

### Findings (Nits)

#### NIT 1: Implementation-level barrier drain timeout parameterization
* **File & Line**: [`docs/research/6751-nopat-admission/plan.md:1006-1008`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1006-L1008)
* **Description**: Section 5.6 specifies that if the delta queue does not drain within the barrier bound, the prime aborts before starting. While §9 specifies testing this bound, §5.6 should note the concrete default parameter (e.g. 2–5 seconds) alongside the other timeout parameters listed at line 1728.
* **Recommendation**: Add a brief parenthetical note in §5.6 specifying the concrete barrier drain timeout value for implementation guidance.

---

### Summary of Work

1. **Adjudication**: Executed an adversarial convergence review of [`docs/research/6751-nopat-admission/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md) (v15.14, commit `8a2eb427c`).
2. **Verification**: Validated the readiness-timeout lifecycle event fold, `SetSyncReady` call site inventory in [`pkg/daemon/daemon_ha_sync.go`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go), epoch barrier drain dynamics, and absence of deadlocks between `sendLoop` and `writeMu`.
3. **Verdict**: Issued **PLAN-READY-WITH-NITS**. Zero BLOCKERs or MAJORs remain.
