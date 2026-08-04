# AGY Hostile Plan Review — #6751 (Round 29 Convergence Adjudication)

**Verdict: PLAN-READY**

Plan document reviewed: [`docs/research/6751-nopat-admission/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md) (v15.16, commit `917ab990a` on branch `research/6751-nopat-admission`).

---

## Executive Summary & Convergence Adjudication

All 4 BLOCKERs, 2 MAJORs, and 1 MINOR raised by Codex in Round 28, as well as AGY r28 Nit 1, have been folded into v15.16 of the plan.

This pass performed an adversarial re-attack on all v15.16 fold designs, including the **producer-ordering invariant**, **daemon-lifetime debt**, **effective-destination IP+port canonicalization**, **decode-time base-identity index**, **universal producer atomicity**, and a full-plan regression check.

Zero BLOCKERs or MAJORs survive. The design has reached full convergence.

---

## Detailed Attack Analysis of v15.16 Folds & Edge Cases

### 1. Producer-Ordering Invariant Attack (Codex r28 Blocker 1 Fold)

* **(a) Open Direction Interleavings vs. `receivedSet` Reconciliation**:
  * *Delta-during-bulk*: If an `Open` delta is published before its mirror row is inserted, the bulk iterator re-reads the mirror and omits $K$. However, the `Open` delta itself (lossless per `#2874`) is processed into Go's `receivedSet`. Upon receiving `BulkEnd`, `reconcileStaleSessions` checks `receivedSet` and observes $K$ present, so $K$ is **not** deleted.
  * *Delta-after-BulkEnd*: If the `Open` delta is delayed in `sendCh` and arrives after `BulkEnd` reconciliation:
    * If $K$ is a new session, it was absent from the receiver's store prior to `BulkEnd`, so `BulkEnd` reconciliation ignores it. The `Open` delta then arrives post-reconcile and installs $K$.
    * If $K$ is a replacement for a previous session, `BulkEnd` reconciliation deletes the stale session, and the `Open` delta post-reconcile reinstalls $K$ with generation $G_{\text{new}}$.
* **(b) Peer-Owned Rows in Active/Active or Failback Topology**:
  * Peer-owned rows imported on a node are assigned `val.IngressZone` corresponding to the peer's zone. The bulk snapshot iterator explicitly filters via `ShouldSyncZone(val.IngressZone)` and `val.IsReverse != 0` ([`sync_bulk.go:96-102`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go#L96-L102)), excluding peer-owned rows from the bulk snapshot. Delete publications for peer-owned sessions originate on the owning peer and travel via the receiver import path, preserving the producer-ordering invariant scope.
* **(c) Known-Stale Omission Residual & Sweep Cadence**:
  * When `syncBackfillNeeded` is set, the incremental sweep executes on an `activeInterval` of 1s ([`sync_conn_sweep.go:47`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_sweep.go#L47)). Queue backpressure (`sendCh` full) delays sweep execution until `sendCh` drains, stretching the re-send window. This is explicitly documented in [`plan.md:1139-1147`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1139-L1147) as an accepted sub-second standby gap residual for mid-bulk session mutations.

---

### 2. Daemon-Lifetime Debt Attack (Codex r28 Blocker 2 Fold)

* **(a) Monotonic Generation (`debtGen`) Mapping across Outstanding Primes**:
  * Arming increments `debtGen` monotonically under the daemon lifecycle lock. When a `BulkEnd-ACK` arrives from a receiver, it carries the `debtGen` active when that bulk was launched. If a second abort or prime request occurred in the interim (bumping `debtGen`), the exact-generation compare `ack.debtGen == current.debtGen` evaluates to `false`, preventing an older asynchronous completion from prematurely clearing newer debt.
* **(b) Teardown without Replacement (HA Disable)**:
  * Disabling chassis-cluster HA cleans up `SessionSync`. The `authoritativePrimeDebt` fields (`owed: bool`, `debtGen: uint64`) reside in the `Daemon` struct, consuming trivial memory with no attached goroutines or channels. If HA is later re-enabled without daemon restart, the new `SessionSync` inherits `owed = true` and immediately drives an authoritative cold-prime on its first connection.
* **(c) Unacknowledged BulkEnd & Silent Peer Timeline**:
  * Sender writes `BulkStart` through `BulkEnd`. If the peer goes silent and never returns `BulkEnd-ACK`, `authoritativePrimeDebt.owed` remains `true` because discharge is strictly gated on `BulkEnd-ACK`. When the VRRP readiness timeout (e.g. 30s) fires, it releases the VRRP hold (degraded path) but **never** clears `authoritativePrimeDebt`. Upon eventual reconnection, `SessionSync` observes `owed = true` and re-drives an authoritative `doBulkSync()` under an incremented `debtGen`.

---

### 3. Effective-Destination IP+Port Canonicalization Attack (Codex r28 Blocker 3 Fold)

* **(a) Complete Enumeration of `SourceNatFlowKey` Construction Sites**:
  * Verified all production construction sites in `userspace-dp`:
    * [`nat/source.rs:807`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs#L807) & [`nat/source.rs:880`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs#L880) (release and reservation)
    * [`nat/source.rs:1191`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs#L1191) (SNAT lookup evaluation)
    * [`nat64.rs:1179`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat64.rs#L1179), [`nat64.rs:1254`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat64.rs#L1254), & [`nat64.rs:1337`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat64.rs#L1337) (NAT64 allocation, release, and reservation)
  * Every site canonicalizes effective destination IP (`nat.rewrite_dst.unwrap_or(key.dst_ip)`) and effective destination port (`nat.rewrite_dst_port.unwrap_or(key.dst_port)`).
* **(b) Rolling Upgrade & Teardown Lookup Alignment**:
  * Upgrading the Rust dataplane binary restarts `userspace-dp`, re-initializing in-memory allocators (`live_by_flow`). Synced sessions re-populate reservations using canonicalized flow keys (`dst_port`), matching release-path key construction. No key mismatch or memory leak across binary upgrades.

---

### 4. Decode-Time Base-Identity Index Attack (Codex r28 Blocker 4 Fold)

* **(a) Memory Discipline on 1M-Session Snapshot**:
  * The index is populated at frame decode time and maps `forward-wire relation -> RTFlowSessionID`. Memory is bounded by the same cap discipline as the quarantine map (e.g. 200k entries). Any cap overflow triggers a quarantine-overflow fail-closed bulk abort, clearing the index map.
* **(b) Expiry Alignment**:
  * Incremental-path index entries expire strictly with the 5s quarantine fallback window, ensuring base identity lookup remains available throughout the alias fallback duration.
* **(c) Subsystem Isolation**:
  * The decode-time index is strictly a receiver-side lookup map for quarantine insertion. It does not interact with `#6522` sibling-replica reaping or holder-completeness rules.

---

### 5. Universal Producer Atomicity & Envelope Discipline (Codex r28 Majors 5–6 Fold)

* All 6 producer paths (`QueueSessionV4/V6`, `QueueDeleteV4/V6`, `flushDeleteJournal`, sweep re-sends, bulk callback, and `writeBarrierMessage`) enforce atomic (draw generation, capture epoch, record generation) critical sections under `genSentMu` / generation lock. Control-only messages (`syncMsgCapability`, `sendClockSync`, `syncMsgHeartbeat`) write directly via `writeMsg`.

---

### 6. Full-Plan Re-Attack & Invariant Verification

1. **Quarantine Order-Agnostic Confirmation**: Maintained at [`plan.md:1403-1413`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1403-L1413).
2. **Bulk Bookkeeping Not Gated**: Maintained at [`plan.md:1424`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1424) & [`plan.md:1445`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1445).
3. **Episode Latch Anti-Self-Rearm**: Maintained at [`plan.md:1246-1260`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1246-L1260).
4. **Provisional Partial-Bulk Disposition**: Maintained at [`plan.md:1230`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1230) & [`plan.md:1337`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1337).

---

## Conclusion & Next Steps

The plan is **PLAN-READY**. All identified edge cases, race conditions, and architectural boundaries have been fully resolved and verified.
