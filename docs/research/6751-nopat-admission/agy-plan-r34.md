# AGY hostile plan review — #6751 (round 34)

# Adversarial PLAN Review — #6751 (Round 34, Convergence Adjudication on PATH A)

### Executive Summary & Re-Adjudication

- **Re-Adjudication**: **PATH A (Sole-Writer Helper) IS ADJUDICATED AND ACCEPTED.**
  - My Round 33 review (`agy-plan-r33.md`) rejected PATH A based on a factual premise that Codex r33 disproved: sole-writer rerouting does **not** touch the shared control socket's >1/s budget. The helper binds a **dedicated session socket** (`userspace-dp-sessions.sock`, `lifecycle.rs:165-175` / `process_control.go:172-178`), serviced on a dedicated thread (`lifecycle.rs:344-381`), which HA imports already ride (`manager_ha.go:1112-1167`).
  - Furthermore, Codex r33 demonstrated four fatal factual errors in PATH B as written (no gRPC server, per-worker private tables, `WorkerLocalImport` retag excluded by owner export, and worker tables holding alias rows).
  - Therefore, my r33 rejection of PATH A on socket contention does **not** stand. PATH A is the correct, factually grounded substrate.
- **Option-(a) Core Verification**: The option-(a) core (`InterfaceNatAllocators`, occupancy split between `InterfaceOwnerKey` and `AddressOnlyReverseKey`, counting holder sets `{Worker(W)}`/`{Shared}`, commit validator, snapshot-builder drain, status counters, #2170 delta ordering, and alias omission/quarantine) remains 100% sound and independent of BPF mirror substrate flaws.
- **Verdict**: **PLAN-NEEDS-REVISION** (v15.21 is near-terminal, but carries one MAJOR internal specification contradiction between Rule 3 and §5.6's decode-time bookkeeping, plus 2 MINORs and 2 NITs).

---

### 1. Re-Adjudication & Bounded Admission (Rule 2)

- **Dedicated Session Socket**: Because `userspace-dp-sessions.sock` is serviced on a dedicated thread in `userspace-dp`, rerouting Go-side session mutations over this socket incurs zero traffic on the shared control socket.
- **Rule 2 Attack (`enqueue-release-wait` implementability & bounds)**:
  - **Deadlock Analysis**: On the helper, the session socket listener thread receives Go requests and enqueues `WorkerCommand` variants into per-worker queues (`rec.handle.commands`). Worker threads drain these queues in their main packet-processing loop (`session_glue/mod.rs:663-704`). Because worker threads process commands off their queues independently of the session socket thread, the `enqueue-release-wait` pattern (enqueue under queue lock, drop lock, wait worker atomic ACKs) avoids deadlock **provided the session socket thread holds no global mutexes (such as `ServerState` or `sessions.synced`) while waiting for ACKs**.
  - **Wait Bounds**: Rule 2 must explicitly specify a per-request deadline (e.g. 5s/15s, matching `OwnerRgExportWait` at `export.rs:245`). If a worker thread is dead or stalled, the wait times out with `Err(TimedOut)`, preventing the session socket thread from blocking indefinitely.
  - **Refusal Semantics**: When a worker queue reaches its bound (`pending.len() >= BOUND`), enqueue returns immediate explicit refusal (`Err(ImportCapReached)`), which maps directly to per-key failure reporting in Go.

---

### 2. Attack on Rule 1's Writer Inventory

Rule 1 lists 10 mutation classes (local publish, refresh, close, imported fwd/rev, DNAT/session-map companions, policy clear, filtered clears, clear-all).

- **The 11th BPF Mirror-Mutating Call Site**:
  - `restoreBPFSessionV4Locked` / `restoreBPFSessionV6Locked` at [`pkg/dataplane/userspace/manager_ha.go:1320-1331`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/manager_ha.go#L1320-L1331) (#5305).
  - When an HA sync install or update fails or requires rollback in Go, `restoreBPFSessionV4Locked` executes direct BPF writes (`m.bpfShim.SetSessionV4` / `m.bpfShim.DeleteSessionV4`) to restore the prior pre-image. Under sole-writer discipline, this direct Go BPF write is an 11th mirror mutator and must be replaced by a helper-transactional rollback over the session socket.

---

### 3. Attack on Rule 3 (Applied Transaction vs Quarantine Bookkeeping)

- **The Contradiction**:
  - **Rule 3 (§4.0.1)** states: *"bulk bookkeeping records a key only AFTER the helper confirms the install"*.
  - **Quarantine Rule (§5.6, lines 1832-1840)** states: *"Bulk bookkeeping is NOT gated... a quarantined key is STILL RECORDED in `s.bulkRecvV4/V6` at decode time... because `ReconcileClusterBulk` treats any live session whose key is absent from the received set as stale and DELETES it at BulkEnd"*.
- **Impact**: If Rule 3 unconditionally suppresses `bulkRecv` recording for quarantined frames pending helper confirmation, then at `BulkEnd`, `ReconcileClusterBulk` will see live self-NAT and NPTv6 sessions as unrecorded in `bulkRecv` and **delete them ~50ms post-bulk**! This re-creates the exact AGY r15 blocker 1 bug.
- **Resolution**: Rule 3 must be clarified: `bulkRecv` membership at decode time (for reconcile protection) is distinct from helper-install confirmation tracking (for `BulkEnd` ACK zero-failure conditioning).

---

### 4. Attack on Rule 4 (Delete Transaction & Policy Invalidation)

- **Scenario**: Session S (id=100) was active under Policy P1. S is re-admitted locally under Policy P2 (id=101). Policy P1 is invalidated. Go issues a delete for expected id=100.
- **Helper Transaction**: The helper compares expected id=100 against current id=101 under the per-key stripe. Mismatch! The helper refuses the delete for id=101, preserving live Session S under Policy P2.
- **Peer Notification & Residual Analysis**:
  - Because the delete was refused, Go suppresses emitting a `Close` delta to the peer.
  - Local re-admission under Policy P2 ALREADY emitted an `Open` delta (`PolicyID = P2`) to the peer over the event stream (`QueueSessionV4/V6`).
  - The peer's stored session state already reflects `PolicyID = P2`. Suppressing the `Close` for id=100 ensures the peer does not delete the live P2 session.
  - **Residual**: Suppressing `Close` on refusal is safe and prevents peer-side zombie deletion.

---

### 5. Attack on Rule 5 & Rule 6 (Dual-Lane Dedup & Event Stream Reconnect)

- **Scenario**: Event stream disconnects and reconnects.
- **Hazard**: If the Rust worker's source sequence resets to 0 on event stream reconnect while Go's `highest_seen_seq` remains at e.g. 50,000, all new event-stream frames will be dropped as duplicates (`seq <= 50,000`). Conversely, if Go resets `highest_seen_seq` to 0 on reconnect while stale fallback frames (`seq = 49,990`) remain in the 5s RPC fallback buffer: when the fallback lane drains those frames, Go's `highest_seen_seq` jumps to 49,990, causing subsequent real event-stream frames (`seq = 1..100`) to be dropped!
- **Requirement**: Source sequences must be per-worker monotonic across stream reconnects (never reset to 0 mid-lifetime), and the barriered handoff on stream reconnect MUST flush/invalidate pending fallback buffer entries for that worker under a stream-epoch generation.

---

### 6. Attack on Rule 7 & §4.0.2 (Alias Provenance & Consequence Map)

- **Rule 7 (Alias Provenance through Promotion)**:
  - On HA failover, `sync-imported` sessions are promoted to locally-originated.
  - On the negotiated-omission path (new+new), zero alias frames exist on the wire. In the legacy window, quarantined alias entries either confirm-and-drop or timeout-admit as provisional canonical rows. Upon promotion, provisional canonical rows must have their provenance updated to local-canonical or cleared.
- **§4.0.2 Consequence Map**:
  - **V1-V4 Shrink**: Sound. Producer-side races are eliminated by sole-writer; Go-side known-stale omission check handles the local window between batch copy and callback.
  - **Carry-Forward + `prime-REQUEST` Field**: Additive 1-bit field. Old peers ignore it; the receiver detects no prime arrived and falls back to reconnect cold-prime. Sound.
  - **Debt Recorded Before End**: `(epoch -> debtGen)` recorded before `BulkEnd` with ACK-only discharge. Prevents premature debt clearing. Sound.

---

### 7. Survival of r33 PATH-B Findings under PATH A

1. **Ordering Token (`session_id` / #2170 generation)**: **Survives (MINOR)**. Helper snapshot bulk exports (`export.rs:95` `snapshot_all_sessions_export`) and table iteration still require a monotonic ordering token (`session_id`) to prevent row-skipping during concurrent worker updates.
2. **Sweep Backfill Trigger Path (`syncBackfillNeeded` at `sync_conn_sweep.go:142`)**: **DROPPED under PATH A**. Under PATH A, the BPF mirror (`s.sessions`) is consistent by construction, so Go scanning `s.sessions` for sweep backfill is valid and safe.
3. **`WorkerCommand` Queue Capacity Monitoring (`worker_queue.rs:45`)**: **Survives (NIT)**. Bounded queues (Rule 2) require metrics tracking queue depth and refusal events.
4. **Metric Scope Qualification (8 counters)**: **Survives (NIT)**. 5 helper-side + 3 Go-side Prometheus counters.

---

### 8. Full-Plan Re-Attack & Final Findings

### Verdict: PLAN-NEEDS-REVISION

v15.21 successfully adjudicates PATH A and establishes a complete sole-writer specification in §4.0.1 and §4.0.2. However, a MAJOR internal specification contradiction exists between Rule 3 and §5.6's decode-time bookkeeping rule, alongside minor dual-lane dedup and writer-inventory gaps.

#### Numbered Findings

1. **[MAJOR] Specification Contradiction: Rule 3 (Applied Transaction) vs §5.6 Quarantine Decode-Time Bookkeeping**
   - **File:Line**: [`plan.md:228-232`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L228) (§4.0.1 Rule 3) vs [`plan.md:1832-1840`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1832) (§5.6)
   - **Description**: Rule 3 mandates that bulk bookkeeping records a key *only AFTER the helper confirms the install*. In contrast, §5.6 explicitly requires that quarantined keys *must be recorded in `bulkRecv` at decode time* (before helper confirm) to prevent `ReconcileClusterBulk` at `BulkEnd` from prematurely deleting live self-NAT and NPTv6 sessions (AGY r15 blocker 1). Strictly enforcing Rule 3 text on quarantined frames re-introduces the AGY r15 session-deletion bug.
   - **Remediation**: Re-word Rule 3 to explicitly distinguish between `bulkRecv` membership for reconcile protection (quarantine path) and helper-install confirmation tracking for `BulkEnd` ACK zero-failure conditioning.

2. **[MINOR] Event Stream Reconnect Sequence Reset vs Dual-Lane Dedup Hazard (Rule 6)**
   - **File:Line**: [`plan.md:258-270`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L258) (§4.0.1 Rule 6)
   - **Description**: Rule 6 uses a worker source sequence to deduplicate the RPC fallback lane against the event stream. If a stream reconnect resets worker sequences or if Go resets `highest_seen_seq` while stale fallback frames remain in the 5s fallback buffer, `highest_seen_seq` can be corrupted by stale fallback sequence numbers, causing subsequent valid event-stream frames to be dropped as duplicates.
   - **Remediation**: Specify in Rule 6 that worker source sequences must be monotonic across stream reconnects, and barriered handoff on stream reconnect must flush/invalidate pending fallback buffer entries for that worker.

3. **[MINOR] Missing 11th BPF Mirror Mutation Site in Rule 1 Writer Inventory**
   - **File:Line**: [`plan.md:200-210`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L200) (§4.0.1 Rule 1), [`pkg/dataplane/userspace/manager_ha.go:1320-1331`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/manager_ha.go#L1320-L1331)
   - **Description**: Rule 1 enumerates 10 writer call sites but omits `restoreBPFSessionV4Locked` / `restoreBPFSessionV6Locked` (#5305), which executes direct BPF writes in Go to restore pre-images on failed sync installs.
   - **Remediation**: Add `restoreBPFSessionV4Locked`/`V6Locked` to Rule 1's inventory and specify that helper-transactional rollbacks replace direct Go BPF writes here as well.

4. **[NIT] Session Socket Request Latency Posture for Operator Clears**
   - **File:Line**: [`plan.md:208-210`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L208), [`pkg/dataplane/userspace/manager_ha.go:1449-1496`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/manager_ha.go#L1449-L1496)
   - **Description**: Rerouting `ClearAllSessions` and filtered clears over the dedicated session socket turns bulk operator clears into chunked IPC requests over the socket.
   - **Remediation**: Explicitly state the latency posture for operator `clear security flow session all` (chunked IPC with per-chunk timeout) in §5.1/§5.6.

5. **[NIT] Metric Descriptor Registration Scope Qualification**
   - **File:Line**: [`plan.md:2200-2245`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2200) (§5.8)
   - **Description**: Clarify that `prometheus.MustRegister` coverage tests apply to the 3 Go-side cluster counters and the 5 helper status mirrors in `pkg/api/metrics.go`.

---

### Summary of Work

1. **Re-Adjudicated Substrate Fork**: Conceded PATH-A rejection after verifying Codex r33's evidence that `userspace-dp-sessions.sock` is a dedicated session socket (`lifecycle.rs:165-175`) serviced on its own thread, with zero contention on the shared control socket.
2. **Attacked §4.0.1 & §4.0.2**: Analyzed all seven sole-writer rules and the consequence map, uncovering a MAJOR conflict between Rule 3 and §5.6 quarantine decode-time bookkeeping, a sequence-reset dedup hazard in Rule 6, and a missing 11th BPF mutation site (`restoreBPFSessionV4Locked` at `manager_ha.go:1320`).
3. **Re-Evaluated r33 Findings**: Confirmed `session_id` ordering token, queue monitoring, and metric scope survive under PATH A, while the sweep backfill rewrite finding is dropped as `s.sessions` remains valid under sole-writer mirror consistency.
4. **Issued Verdict**: Delivered **PLAN-NEEDS-REVISION** with 5 numbered findings to guide v15.22.
