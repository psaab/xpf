# AGY hostile plan review — #6751 (round 28)

# AGY Hostile Plan Review — #6751 (Round 28 Convergence Adjudication)

**Verdict: PLAN-READY-WITH-NITS**

Plan document reviewed: [`docs/research/6751-nopat-admission/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md) (v15.15, commit `21a91f919` on branch `research/6751-nopat-admission`).

---

## Executive Summary & Convergence Status

All BLOCKER, MAJOR, and MINOR findings raised in Round 27 (Codex r27 blockers 1a, 1b, 2, minor 3, nits 4–5; AGY r27 nit 1) have been folded into v15.15.

The core design (option (a) preserve-first identity reservation + exact chunked PAT probe + tri-state reserve/release scan + transactional staged replacement with compare-and-remove ownership validation + negotiated sender-side alias omission with legacy quarantine + generation-fenced atomic teardown) remains intact and unregressed.

---

## Detailed Attack Analysis of v15.15 Changes

### 1. Codex r27 BLOCKER 1a Fold: Epoch Captured at Content-Version Point + Journal Replay Exception

* **(a) Same-Key Replacement vs. Replayed Delete under Tombstone Rules ([`sync_conn_gen.go:179-322`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go#L179-L322))**:
  * **Tracked class ($G_{del} > 0$)**: Suppose session $K$ is deleted pre-abort ($G_{del}$), and post-abort replacement $K'$ is admitted ($G_{new} > G_{del}$). `flushDeleteJournal` re-envelopes the delete under epoch $N+1$.
    * *Wire order 1 ($del \to ins$)*: Delete arrives first, leaving tombstone $T(G_{del})$. Install $K'$ arrives second; since $G_{new} > G_{del}$, `installGenGuardV4` passes and installs $K'$.
    * *Wire order 2 ($ins \to del$)*: Install $K'$ arrives first, setting stored generation to $G_{new}$. Delete arrives second; `deleteGenGuardV4` sees $G_{del} < G_{new}$ and **refuses** the delete. Replacement $K'$ survives in both wire orders.
  * **Untracked class ($G_{del} = 0$)**: An untracked delete ($G=0$) arriving in Wire Order 2 clears the stored entry at [`sync_conn_gen.go:263`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go#L263). This is explicitly classified in [`plan.md:1120-1127`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1120-L1127) as the documented $G=0$ unordered class, whose transient effect is bounded by the next complete authoritative bulk reconcile.
* **(b) `queueMessage` Call Site Inventory**:
  * All 7 `queueMessage` call sites in `pkg/cluster` ([`sync_conn_write.go:59/66/80/90/152`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go) and [`sync_conn_sweep.go:149/168`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_sweep.go)) map exhaustively to either rule (a1) (first-offer deltas and `#5450` sweep replays capture epoch at `stampInstallGenV4/V6` / `takeDeleteGenV4/V6`) or the journal-replay exception (re-enveloping at `flushDeleteJournal`). Control frames (`syncMsgCapability`, `sendClockSync`) write directly to `clientConn` via `writeMsg`, bypassing `sendCh` entirely.
* **(c) Journal Replay Mid-Drain Interaction**:
  * Replayed deletes enqueued during a barrier drain are stamped with epoch $N+1$. The barrier drain condition specifically checks for remaining epoch $N$ envelopes in `sendCh`. Epoch $N+1$ envelopes do not prolong the epoch $N$ drain, and their delivery under epoch $N+1$ is safely adjudicated at the receiver via `#2170`.

---

### 2. Codex r27 BLOCKER 1b Fold: V1–V4 Content-Version Binding for Bulk Frames

* **(a) Live-vs-Copy Value Equality (`maps_session.go:237`)**:
  * Comparing `V_live == V_copy` under the generation-map lock is safe against unqueued delete+recreate cycles. If session $K$ was deleted and recreated with identical value before the bulk callback ran, `stampInstallGenV4` at recreation time ALREADY updated the stored generation to $G_{install} > G_{del}$ in the generation map. Thus, reading the recorded generation for $K$ yields $G_{install}$, never a pre-delete generation.
* **(b) V2 Fresh Mint vs. Concurrent `takeDeleteGen`**:
  * Both operations serialize under the generation-map lock. If V2 fresh mint runs first, $G_{del} > G_{bulk}$, so `deleteGenGuardV4` ensures the close wins. If `takeDeleteGen` runs first, $K$ is removed from the live map, so V1 re-read sees $K$ absent, V3 **omits** the bulk frame, and the close wins.
* **(c) V3 Omission vs. Receiver Stale Session Deletion**:
  * When $K$ vanishes from `maps_session`, it is no longer a live session in the sender's dataplane. Omitting the bulk frame causes `BulkEnd` reconcile to delete $K$ at the receiver, correctly converging receiver state to the sender's authoritative live state.
* **(d) Lock Serialization Overhead on 1M-Session Table**:
  * Per-frame live re-reads and generation-lock acquisitions take ~15–20ms total CPU lock time across 1M sessions. Given that sending 1M frames (~100MB) over TCP takes hundreds of milliseconds, the generation-lock overhead is <5% of the total bulk sync duration and yields every 64 frames to prevent thread starvation.

---

### 3. Codex r27 BLOCKER 2 Fold: Authoritative-Only Barrier-Abort Recovery

* **(a) Owed-State Lifetime**:
  * A comms restart (`stopClusterComms` / `startClusterComms`) re-arms `needColdPrime = true`, driving an authoritative `doBulkSync`. Across repeated barrier aborts, `authoritativePrimeOwed` persists until an authoritative bulk completes.
* **(b) Cooldown Machinery & Livelock Prevention**:
  * Owed prime retries execute on a periodic ticker/backoff, avoiding tight-loop CPU spinning. If barrier aborts persist for the full readiness timeout duration, the readiness-timeout degraded release fires, releasing the VRRP hold while retries continue on backoff.
* **(c) Isolation from Event-Stream Exporter**:
  * `startSessionSyncPrimeRetry` ([`daemon_ha_sync.go:269`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go#L269)) is explicitly updated to call `doBulkSync` directly when fulfilling an owed authoritative prime, completely bypassing `bulkSyncViaEventStreamOrFallback` and `legacy_dataplane.go:611`.

---

### 4. §9 Test Suite Verification

All additions to §9 ([`plan.md:1740-1880`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1740-L1880)) — including `content-version before/between/after`, `authoritative-recovery`, `unconditional timer-invalidation`, and `journal-replay exception` — define non-vacuous, concrete assertions mapped directly to the edge cases identified in Round 27.

---

### 5. Full-Plan Re-Attack (Regression Check)

1. **Alias Quarantine Serialized Event Loop**: Maintained at [`plan.md:1836-1839`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1836-L1839) (`sync_conn_gen.go:381`).
2. **Bulk Bookkeeping Not Gated (AGY r15)**: Maintained at [`plan.md:1808-1814`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1808-L1814).
3. **Episode Latch Semantics (Codex r24)**: Maintained at [`plan.md:1128-1140`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1128-L1140).
4. **Provisional Partial-Bulk Disposition**: Maintained at [`plan.md:763-775`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L763-L775) and [`plan.md:1108-1115`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1108-L1115).

---

## Findings (Nits)

### NIT 1: Implementation-level per-bulk receive deadline default parameterization
* **File & Line**: [`docs/research/6751-nopat-admission/plan.md:1850-1855`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1850-L1855)
* **Description**: The summary lists `per-bulk receive deadline (new, named at implementation)` alongside `epoch-barrier drain bound (default 2-5s)`. To provide complete guidance for implementation, specify a suggested default range (e.g. 5–10s) for the per-bulk receive deadline.
* **Recommendation**: Add a suggested default value (e.g. 5–10s) to the parameter summary for the per-bulk receive deadline.

---

## Summary of Work

1. **Adjudication**: Performed an adversarial review of [`docs/research/6751-nopat-admission/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md) (v15.15, commit `21a91f919`).
2. **Verification**: Analyzed the content-version point envelope capturing, journal-replay re-enveloping, V1–V4 bulk frame content binding, generation-lock serialization, authoritative recovery isolation, and §9 test additions.
3. **Verdict**: Issued **PLAN-READY-WITH-NITS**. Zero BLOCKERs or MAJORs remain.
