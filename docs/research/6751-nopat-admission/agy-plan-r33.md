# AGY hostile plan review — #6751 (round 33, fork adjudication)

### Executive Summary & Verdict

- **Fork Adjudication**: **PATH B (Table-Truth Substrate) WINS UNANIMOUSLY.**
  - **PATH A Adjudication**: **Definitively Rejected.** Rerouting Go-side mutations (`manager_ha.go:1058` and `daemon_policy_invalidate.go:357`) through the Rust helper's `WorkerCommand` queue (`session_import.rs:238`) is indefensible. The queue (`userspace-dp/src/afxdp/worker_queue.rs:45`) is an unbounded `VecDeque` with zero backpressure. Furthermore, carrying bulk HA import over the shared Unix domain control socket via `requestSessionSync` (`manager_ha.go:1775`) directly violates the project's hard architecture limit (*CLAUDE.md*: shared control socket starves at >1/s of new traffic).
  - **Kill-Shot Verification**: **NOTHING in the option-(a) registry core or surviving machinery depends on the BPF mirror substrate.** The registry (`InterfaceNatAllocators`), occupancy model (`InterfaceOwnerKey` vs `AddressOnlyReverseKey`), holder tracking (`{Worker(W)}` / `{Shared}`), commit validator & snapshot-builder drain, status counters, #2170 delta generation ordering, and alias omission/quarantine machinery are 100% independent of the BPF mirror.
- **Verdict**: **PLAN-NEEDS-REVISION** (v15.20 presents §4.0 for adjudication while retaining PATH-A mirror-defense text in §5.x/§7/§9; v15.21 must execute the surgical purge of retired mirror-defense machinery per §4.0.1).

---

### 1. Adjudication of PATH A

#### (a) The `WorkerCommand` Import Channel Route
In `userspace-dp/src/afxdp/ha/session_import.rs:238`, commands are pushed into per-worker queues:
```rust
pending.push_back(WorkerCommand::UpsertSynced(entry.clone()));
```
Inspecting `userspace-dp/src/afxdp/worker_queue.rs:45`, the queue handle `rec.handle.commands` is defined as:
```rust
pub(in crate::afxdp) fn lock_recover(
    m: &Mutex<VecDeque<WorkerCommand>>,
) -> MutexGuard<'_, VecDeque<WorkerCommand>>
```
This is an **unbounded `VecDeque`** with no upper limit or backpressure mechanism. High-rate mutation bursts or bulk HA imports pushed through this channel risk unbounded memory allocation on worker threads.

#### (b) Control Socket Contention Budget
Go-side mutations (`manager_ha.go:1058` `SetSessionV4` / `SetClusterSyncedSessionV4` and `daemon_policy_invalidate.go:357` `DeleteBatchKnownV4`) communicate with the Rust helper via `requestSessionSync` (`manager_ha.go:1775`), which marshals JSON control requests over the shared control socket. 

During initial sync, failover, or bulk policy invalidation (thousands to 200k+ sessions), sending every session operation over the shared control socket starves all other control socket traffic (status polling, config pushes, interface snapshot updates). It is physically impossible for bulk HA import over the control socket to avoid exceeding the >1/s contention budget.

#### (c) Rerouting Complexity & Cross-Process Atomicity Seams
As Codex r32 (Blockers 1 & 7) and SMR r33 demonstrated, attempting to make the BPF mirror gate atomic across two independent OS processes (Rust helper + Go daemon) forces complex cross-process locks. Every review round for six rounds discovered new un-serialized writers (e.g. `bpf_map/mod.rs:429/451` refresh-restore writebacks, `session_delta.rs:420` derived key deletes). 

**Conclusion on PATH A**: Definitively rejected.

---

### 2. Adversarial Attack & Deep-Dive on PATH B (§4.0.1)

#### (a) Horizon Semantics Walkthrough
`SnapshotStart{epoch, generation_horizon}` captures the sender's #2170 generation high-water mark $G_H$ at snapshot start.
1. **Session created DURING snapshot (post-horizon, $G_{new} > G_H$)**:
   - The session is omitted from early snapshot pages or created after the iterator passed.
   - It is conveyed via the incremental delta stream (`QueueSessionV4`) to the receiver.
   - At `SnapshotEnd` reconcile (`reconcileStaleSessions` in `pkg/cluster/sync.go`), the receiver checks the entry's generation: because $G_{new} > G_H$, the entry is **exempt from absence deletion**. It is retained safely without requiring a carry-forward accumulator.
2. **Session closed DURING snapshot (in snapshot page, closed before `SnapshotEnd`)**:
   - The session was included in `SnapshotPage 1` and recorded in `received_set`.
   - Before `SnapshotEnd`, the sender closes the session and emits `QueueDeleteV4` with tombstone $G_{del} > G_{new}$.
   - If `QueueDeleteV4` reaches the receiver before `SnapshotEnd`, it deletes the entry from the receiver's `SessionStore`. At `SnapshotEnd`, reconcile walks live entries; since the closed session is no longer in the store, reconcile does nothing.
   - If `QueueDeleteV4` arrives after `SnapshotEnd`, reconcile sees the session in `received_set` and keeps it; milliseconds later, `QueueDeleteV4` executes and deletes it via tombstone generation ordering.

#### (b) Table Iteration Consistency & Mutation Sequence
- **Can a page skip a live entry under concurrent worker mutation?**
  In `userspace-dp/src/session/mod.rs:713`, `SessionTable` stores entries using `slab::Slab<SessionRecord>`. Slot indices assigned by `Slab::insert` are **stable for the lifetime of an entry** and never shift when other entries are inserted or deleted.
  If a session $S_{old}$ existed before `SnapshotStart` ($G \le G_H$), its slot index $i$ is fixed. A monotonic iteration over slot indices $[0, \text{slot\_high\_watermark}]$ is guaranteed to visit slot $i$. It cannot skip $S_{old}$. If a new session is inserted during iteration into a recycled lower slot index, its generation $G > G_H$ triggers the horizon exemption at the receiver.
- **Is the claimed per-entry mutation sequence real and queryable?**
  `SessionEntry` (`session/mod.rs:344`) carries `created_ns: u64` (`CLOCK_MONOTONIC` timestamp, line 358), `install_epoch: u64`, and `session_id: u64` (`session/mod.rs:460`, unique node-wide ID). `SyncedSessionEntry` (`ha/session_import.rs:390`) carries `generation: u64`. The ordering token exposed by the paginated snapshot channel is the monotonic #2170 `generation` or `session_id`.

#### (c) Retired-Machinery Residuals
- **Go Incremental Sweep Backfill (`sync_conn_sweep.go`)**:
  Currently, `sync_conn_sweep.go:142` iterates `s.sessions` (the BPF mirror) when `syncBackfillNeeded` is true. Under PATH B, `s.sessions` exits the sync path. When delta queue overflow occurs (`overflow = true` at `sync_conn_sweep.go:180`), `syncBackfillNeeded` must set `forceResync` or trigger a fresh snapshot pull over the table-truth channel, rather than walking `s.sessions`.
- **Carry-Forward Residual Duty Across Aborted Attempts**:
  If a snapshot attempt aborts mid-transfer, the receiver discards the incomplete `received_set`. When the replacement snapshot starts, `SnapshotStart` captures a fresh horizon $G_{H2}$. Deltas post-dating $G_{H2}$ are protected by $G_{H2}$, while deltas between $G_{H1}$ and $G_{H2}$ are either captured in the new snapshot pages or tombstoned. No carry-forward accumulator is needed across retries.

#### (d) Stale-Close Shrink & Producer Ordering
- **Same-Worker Producer Order**:
  Worker $W$ processes events sequentially. On close-and-replace, $W$ emits `Close(S, G_del)` then `Open(S_new, G_new)`. The event stream mux and `queueMessage` preserve this FIFO order. Go receives `Close` first then `Open`, drawing $G_{del} < G_new$. The tombstone loses to $G_{new}$ by construction.
- **Cross-Worker Migration**:
  When steering rebalances a flow from worker $W_1$ to $W_2$, the table EPOCH is bumped. Pre-rebalance closes on $W_1$ carrying the old epoch are suppressed or generation-guarded, preventing cross-worker race conditions.

#### (e) Alias Discipline Under PATH B
- **Does the helper's `SessionTable` ever hold an alias row?**
  **NO.** `SessionTable` (`session/mod.rs`) only holds canonical forward/reverse rows installed by local admission or HA sync import. Alias rows were purely a Go-side fabric-redirect optimization (`daemon_ha_userspace_stream.go:370`).
- **What remains in the New+New cell?**
  The receiver advertises `syncMsgCapability`. The new sender sees it and **skips alias derivation entirely** at all 4 alias branches (`daemon_ha_userspace_stream.go:370/379/398/413`). Zero alias frames are sent on the wire. Quarantine receives zero entries in steady state.
- **Legacy Cell (Old Sender + New Receiver)**:
  Quarantine filters signature-matching alias rows at decode. At `SnapshotEnd`, if the sibling canonical base is in `received_set`, the alias is confirmed and dropped. If unconfirmed after 5s (lost base / self-NAT), it timeout-admits as a provisional canonical row. P1/P2 purge re-evaluates provisional rows against subsequent snapshot completions using exact-publication `session_id` compare-and-delete on the receiver's serialized event loop.

#### (f) Remaining Correctness Consumers of the BPF Mirror
A complete codebase audit of `pkg/` shows:
1. `pkg/grpcapi/server_sessions.go`, `pkg/natshow/*`, `pkg/api/*`: **Cosmetic display only** (`show security flow session`, REST, Prometheus metrics). Drift is non-fatal.
2. `pkg/cluster/sync_conn_sweep.go`: Sweep iteration (`ForEachV4`). **Replaced by PATH B table-truth snapshot channel.**
3. `pkg/daemon/daemon_policy_invalidate.go`: Policy invalidation session sweep. **Replaced by helper table RPC / control interface.**

**Result**: ZERO correctness consumers of the BPF mirror remain in the dataplane!

#### (g) Debt Driving the New Channel
An authoritative-prime debt is armed with a monotonic `debtGen`. `SnapshotStart{epoch, generation_horizon, debtGen}` initiates iteration. Upon receiving `SnapshotEnd{epoch, debtGen, checksum}` and completing reconciliation, the receiver returns `SnapshotACK{epoch, debtGen}`. The sender performs exact-generation compare-and-clear on `debtGen`. Older/stale ACKs are ignored.

---

### 3. Surgical Rewrite List & The Kill-Shot Question

#### Kill-Shot Answer
> **Does anything in the option-(a) core or surviving machinery actually depend on the mirror substrate?**

**NO.** The entire option-(a) core (`InterfaceNatAllocators`, occupancy split, holder counting `{Worker(W)}`/`{Shared}`, commit validator, snapshot-builder drain, status counters, #2170 delta generation ordering, and alias omission/quarantine) operates strictly on Rust helper memory and Go delta streams. Not a single line reads or depends on the BPF mirror substrate.

#### Minimal §5.x Surgical Rewrite List for v15.21
1. **Purge Retired Mirror-Defense Machinery (§5.3, §5.6, §7, §9)**:
   - Remove V1-V4 live BPF mirror re-read.
   - Remove BPF failed-delete omission index.
   - Remove BPF compare-and-delete atomics & cross-process arbiter text.
   - Remove BPF mirror-hole carry-forward accumulator.
2. **Incorporate §4.0.1 Specification (§5.1 - §5.6)**:
   - Specify dedicated gRPC/control snapshot RPC on helper (`ExportOwnerRGSessions` variant) with `SnapshotStart` $\to$ paginated `SnapshotPage` $\to$ `SnapshotEnd` framing.
   - Detail `SnapshotACK` exact-generation debt discharge (`debtGen`).
3. **Update Incremental Sweep Backfill (§5.6)**:
   - Direct `syncBackfillNeeded` to trigger table-truth snapshot re-sync instead of scanning `s.sessions`.
4. **Align Stale-Close Discipline (§5.6)**:
   - Document per-worker delta stream FIFO ordering ($G_{del} < G_{new}$) for same-worker closes, and table-epoch bump for cross-worker migration.

---

### 4. Findings & Verdict

### Verdict: PLAN-NEEDS-REVISION

v15.20 successfully formulates §4.0 and §4.0.1, establishing PATH B as the winning substrate. However, §5.x, §7, and §9 retain legacy PATH-A mirror-defense text. v15.21 must execute the surgical rewrites detailed below.

#### Findings

1. **[MAJOR] Contradiction between §4.0.1 (PATH B) and surviving §5.6 / §7 / §9 text (PATH A residual text)**
   - **File:Line**: [plan.md:1217](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1217), [plan.md:1478](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1478), [plan.md:2404](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2404), [plan.md:2428](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2428)
   - **Description**: Sections 5.6, 7, and 9 retain extensive text describing retired mirror-defense mechanisms (V1-V4 live BPF mirror re-read, BPF failed-delete omission index, BPF compare-and-delete atomics, BPF carry-forward accumulator). This directly contradicts §4.0.1.
   - **Remediation**: Execute the surgical purge in v15.21 as outlined in Section 3 above.

2. **[MAJOR] Table iteration ordering token clarification in §4.0.1**
   - **File:Line**: [plan.md:266](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L266), [`userspace-dp/src/session/mod.rs:713`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/mod.rs#L713)
   - **Description**: §4.0.1 states that the table's "own per-entry mutation sequence, already present for RT_FLOW ids, orders pages against concurrent mutation". `SessionTable` uses `slab::Slab<SessionRecord>` where slot indices are reused on deletion. `SessionEntry` carries `session_id`, `created_ns`, and `install_epoch`.
   - **Remediation**: Explicitly specify in §4.0.1 that `session_id` (or #2170 `generation`) is the monotonic ordering token used across paginated snapshot calls to prevent page-skipping ambiguity.

3. **[MINOR] Incremental sweep backfill trigger path after mirror retirement**
   - **File:Line**: [plan.md:1623](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1623), [`pkg/cluster/sync_conn_sweep.go:125`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_sweep.go#L125)
   - **Description**: `sync_conn_sweep.go:142` currently backfills on `syncBackfillNeeded` by scanning `s.sessions` (the BPF mirror).
   - **Remediation**: Update §4.0.1 and §5.6 to specify that `syncBackfillNeeded` under PATH B triggers an authoritative snapshot request over the new table-truth channel or sets `forceResync`.

4. **[MINOR] `WorkerCommand` queue capacity monitoring**
   - **File:Line**: [`userspace-dp/src/afxdp/ha/session_import.rs:238`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs#L238), [`userspace-dp/src/afxdp/worker_queue.rs:45`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker_queue.rs#L45)
   - **Description**: `rec.handle.commands` is an unbounded `VecDeque`. While PATH B removes Go mirror updates from this queue, HA sync commands during high-volume bursts still pass through it.
   - **Remediation**: Note in §5.1 that worker command queue lengths should be monitored via `WORKER_COMMAND_QUEUE_POISON_RECOVERIES` or queue length metrics.

5. **[NIT] Metric descriptor registration scope qualification**
   - **File:Line**: [plan.md:2132](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2132), [plan.md:2704](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2704)
   - **Description**: §5.8 inventories 8 total counters (5 helper-side + 3 Go-side).
   - **Remediation**: Clarify that `prometheus.MustRegister` coverage tests in Go apply to the 3 Go-side cluster counters and the helper status mirrors in `pkg/api/metrics.go`.

---

### Summary of Work

1. **Adjudicated §4.0 Substrate Fork**: Confirmed PATH B (table-truth substrate via lossless paginated RPC) wins decisively over PATH A (cross-process BPF mirror arbiter). Evaluated `WorkerCommand` queue bounds (`worker_queue.rs:45`) and control socket contention (`manager_ha.go:1775`) with code evidence.
2. **Attacked PATH B (§4.0.1)**: Addressed all 7 technical sub-questions (horizon semantics, slab table iteration, sweep backfill residuals, producer ordering, alias omission/quarantine, mirror consumers, and debt discharge).
3. **Verified Option-(a) Core Independence**: Confirmed via code analysis that zero components in the option-(a) registry core depend on the BPF mirror substrate.
4. **Delivered Verdict & Surgical Rewrite Plan**: Issued **PLAN-NEEDS-REVISION** for v15.20 to guide the v15.21 surgical rewrites purging legacy mirror-defense prose.
