# AGY hostile plan review — #6751 (round 16)

**PLAN-READY-WITH-NITS**

---

### Round 16 Convergence Adjudication Analysis

#### 1. Round-15 AGY Blocker Verification (Bulk Bookkeeping & Reconcile / Nil-Map Write) — **RESOLVED (DEAD)**
- **Failure Mode 1 (Reconcile deletes quarantined session as stale at ~50ms)**:
  - *Mechanism*: In v15.1/v15.2 (`plan.md:644-654`, `plan.md:1085-1092`), signature-matching quarantined frames record their key into `s.bulkRecvV4/V6` at decode time (`sync_conn_read.go:110`), before the quarantine gate.
  - *Result*: When `ReconcileClusterBulk` / `reconcileStaleSessions` (`sync.go:1086-1126`) executes at `BulkEnd`, the quarantined key is present in the received set. Reconcile never treats live genuine self-NAT or identity-NPTv6 sessions as stale.
- **Failure Mode 2 (t=5s admission writes to nil'd `s.bulkRecvV4/V6` map)**:
  - *Mechanism*: In v15.2 (`plan.md:631-643`, `plan.md:1103-1116`), all bulk-pinned quarantine entries resolve at their own epoch's `BulkEnd` in the same single-threaded pass. No bulk entry ever defers to t=5s.
  - *Result*: Incremental deltas (outside bulk sync) have a guarded bookkeeping touch (`ONLY IF a bulk is currently open`, `plan.md:673-678`). Since `s.bulkRecvV4/V6` is nil'd after `BulkEnd` (`sync.go:1090`), post-bulk/out-of-bulk admissions bypass the map write completely. No nil-map write can occur.

Both failure modes from the AGY r15 blocker are completely eliminated.

---

#### 2. Round-15 Codex Blocker Verification (Epoch Safety & Execution Model) — **RESOLVED (DEAD)**
- **Codex Scenario 1 (Bulk ACK & Sync-Hold Release while Quarantine is Unresolved)**:
  - *Mechanism*: Quarantined entries are pinned to their arrival bulk epoch (`plan.md:618-643`). At `BulkEnd`, the complete snapshot is present in `s.bulkRecvV4/V6`. The receiver executes an epoch-definitive resolution pass: entries matching a sibling base in the received set confirm-alias and drop; all remaining entries admit through the complete normal import path (`installClusterSynced*`, `sync_conn_read.go:110` → `sync_conn_gen.go:435`).
  - *Result*: The resolution pass completes in the same single-threaded event loop step *before* the bulk ACK is sent and the sync-hold is released (`sync_conn_read.go:240/244`). Scenario 1 is dead.
- **Codex Scenario 2 (Cross-Epoch Retention of Lost-Delete Stale Rows)**:
  - *Mechanism*: Quarantine entries never defer across bulk epochs (`plan.md:1103-1116`). An entry received in bulk epoch $E_1$ resolves at $E_1$'s `BulkEnd`.
  - *Result*: No entry from $E_1$ survives into bulk epoch $E_2$ to pollute $E_2$'s `bulkRecv` bookkeeping or delay reconcile. Scenario 2 is dead.
- **Single-Threaded Safety Contract**:
  - *Mechanism*: All quarantine insertions, confirmations, admissions, and timer wakeups run as events on the receiver's serialized event loop (`sync_conn_gen.go:381`, `plan.md:628-631`). Timers only enqueue a wakeup signal onto the loop thread.
  - *Result*: State updates across session maps, generation tracking, and bookkeeping remain strictly single-threaded.

---

#### 3. Round-15 Codex Minor Verification (Capability Transition & Life-Cycle) — **RESOLVED**
- **Lifecycle & Discovery**:
  - *Mechanism*: The capability frame `syncMsgCapability` (or `syncMsgClockSync` extension, `sync_conn.go:137`) is re-advertised periodically on every clock-sync tick (`plan.md:559-570`). Sender posture is `DERIVE-UNTIL-CAPABLE`.
  - *Unauthenticated Clusters*: Capability transmission bypasses `performSyncHandshake` (`sync_auth.go:331-334`, `sync_auth.go:321`), sending capability frames on unauthenticated links as well.
  - *Transition Window*: When a receiver advertises capability mid-stream, the sender transitions to omitting alias derivations at the queue branch (`delta.FabricRedirect && !delta.FabricIngress`, `daemon_ha_userspace_stream.go:370/379`). Any in-flight aliases sent prior to the transition hit the receiver quarantine, where they are confirmed against the canonical base and dropped. Permanently lost capability frames keep the sender in legacy `UNKNOWN` state without dropping sync.

---

#### 4. Adjudication Findings

##### 1. NIT — Quarantine Capacity Eviction Resolution Rule
- **File:Line**: `docs/research/6751-nopat-admission/plan.md:1119-1121` (referencing `sync_conn_read.go:110`)
- **Detail**: If a bulk contains >4096 signature-matching frames, the bounded quarantine map capacity is reached. Evicted entries must not be blindly admitted or silently dropped. As folded into §9 implementation notes, capacity eviction resolves as an `admit-after-confirm-check` against the complete received set at that epoch's `BulkEnd`.

##### 2. NIT — Stalled Bulk Teardown Quarantine Resolution Pass
- **File:Line**: `docs/research/6751-nopat-admission/plan.md:1121-1123` (referencing `sync_conn_read.go:240`)
- **Detail**: If a peer stalls mid-bulk and the bulk never reaches a clean `BulkEnd`, bulk-pinned quarantine entries must be resolved during the bulk teardown path triggered by the existing bulk-liveness timeout mechanism, ensuring no pinned entries leak across connection resets.

---

### Summary
The v15.2 / v15.2.1 plan successfully closes all architectural, ordering, bulk-epoch, and concurrency failure modes identified in prior rounds. No open BLOCKERs or MAJORs remain in either the alias discipline or the core #6751 reserve-or-PAT admission design. The plan is **PLAN-READY-WITH-NITS**.
I have completed the round-16 convergence adjudication review for issue #6751 (`docs/research/6751-nopat-admission/plan.md` v15.2+).

### Summary of Adjudication:
1. **AGY Round-15 Blocker (Bulk Bookkeeping & Reconcile / Nil-Map Panic)**: **DEAD**. Quarantined keys are recorded in `s.bulkRecvV4/V6` at decode time, preventing `ReconcileClusterBulk` (`sync.go:1086-1126`) from deleting live self-NAT / identity-NPTv6 rows at `BulkEnd`. Bulk-pinned quarantines resolve at `BulkEnd` before the map is nil'd (`sync.go:1090`), and incremental delta admissions guard the bookkeeping touch (`ONLY IF a bulk is currently open`).
2. **Codex Round-15 Blocker (Epoch Safety & Execution Model)**: **DEAD**. All entries are epoch-pinned and resolve at `BulkEnd` before bulk ACK and sync-hold release (`sync_conn_read.go:240/244`). Quarantine actions run strictly on the receiver's single-threaded event loop (`sync_conn_gen.go:381`).
3. **Codex Round-15 Minor (Capability Transition)**: **VERIFIED**. The sender operates `DERIVE-UNTIL-CAPABLE` with per-tick re-advertisements (`sync_conn.go:137`), covering unauthenticated clusters (`sync_auth.go:321`) and providing a clean transition window.
4. **Final Verdict**: **PLAN-READY-WITH-NITS** (incorporating the cap-eviction resolution rule and stalled-bulk teardown resolution pass as §9 implementation notes).
