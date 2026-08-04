# AGY hostile plan review — #6751 (round 35)

# AGY hostile plan review — #6751 plan v15.23 (round 35)

### Executive Summary & Final Adjudication

- **Verdict**: **PLAN-READY-WITH-NITS**
- **Substrate & Core Status**: Both forks are fully settled and closed. **PATH A (Sole-Writer Helper)** is adjudicated and specified in §4.0.1/§4.0.2. The **Option-(a) Core** (`InterfaceNatAllocators`, address-only occupancy split, holder model, snapshot-builder drain, #2170 delta ordering, and alias quarantine) is sound, robust, and independent of BPF mirror substrate flaws.
- **Fold Verification**: All 5 AGY r34 findings (1 MAJOR, 2 MINORs, 2 NITs) and all 11 Codex r34 findings (10 BLOCKERs, 1 MAJOR) have been folded into v15.23 (`fbca4ab8f`).
- **Full-Plan Re-Attack**: No BLOCKER or MAJOR specification defects remain. The internal specification contradiction between Rule 3 and §5.6 decode-time bookkeeping identified at r34 is resolved. Two MINOR/NIT implementation-level specification clarifications remain regarding Go-side arbiter scoping (Rule 6) and connection teardown as the re-bulk trigger (F2).

---

### 1. AGY r34 MAJOR Verification: Two-Ledger Applied Transaction (§4.0.1 Rule 3 vs §5.6)

- **Verification of Resolution**:
  - **Ledger 1 (`bulkRecv` Membership)**: Recorded at **DECODE time** (`sync_conn_read.go:110`) for *every* received key, quarantined or not ([`plan.md:275-278`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L275), [`plan.md:1997-2007`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1997)). This guarantees reconcile protection (`ReconcileClusterBulk` at `BulkEnd` will not delete live self-NAT or identity-NPTv6 sessions post-bulk).
  - **Ledger 2 (`install-confirmation` Ledger)**: Tracks helper installation outcomes for keys dispatched to the helper ([`plan.md:279-284`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L279)). Its terminal outcomes are explicitly enumerated as `Applied`, `AlreadyNewer`, `ConfirmedAliasNoop` (intentional non-install drop), `Failed`, and `Pending` ([`plan.md:291-294`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L291)).
  - **`BulkEnd` ACK Condition**: Requires **ZERO `Failed` / `Pending`** entries across the ledger ([`plan.md:283-285`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L283), [`plan.md:294`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L294)).
- **Quarantined-Key-Never-Resolves Case**:
  - Quarantined keys enter Ledger 2 as `Pending`.
  - At `BulkEnd`, all remaining quarantined keys are resolved in a single serialized pass before ACK evaluation ([`plan.md:1967-1974`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1967)):
    1. Keys matching a base identity in the received set become `ConfirmedAliasNoop` (terminal, non-failure).
    2. Non-matching keys (lost bases / self-NAT) are dispatched to the helper via `WorkerCommand::UpsertSynced`, transitioning from `Pending` to `Applied`, `AlreadyNewer`, or `Failed`.
  - If a bulk deadline, teardown, or superseding `BulkStart` interrupts resolution ([`plan.md:1975-1991`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1975)), the bulk **aborts WITHOUT ACK** (fencing the receive epoch).
- **Conclusion**: The contradiction is completely eliminated.

---

### 2. AGY r34 MINORs Verification & Rule 6 Arbiter Placement Attack

- **Fold Verification**:
  - **Minor 2 (Dedup Reconnect Invalidation)**: Folded in Rule 6 ([`plan.md:381`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L381)) — barriered handoff on event stream reconnect flushes/invalidates pending fallback buffer entries for that worker.
  - **Minor 3 (`restoreBPFSession` 11th Writer)**: Folded in Rule 1 ([`plan.md:211-218`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L211)) — `restoreBPFSessionV4Locked`/`V6Locked` (#5305) included in the sole-writer inventory, replaced by transactional rollback over the session socket.
- **Rule 6 Arbiter Placement Attack**:
  - *Analysis*: Rust worker threads generate delta events and stamp ordering tuples `(worker_id, source_seq, helper_incarnation/epoch)`. Go receives these frames over two independent transport paths (event stream callback and 5s RPC fallback drain).
  - *Arbiter Placement*: An IPC critical section spanning across the Rust-Go process boundary per frame is not implementable. The Arbiter **must be scoped Go-side**, wrapping incoming event-stream callbacks and fallback-buffer drains under a single Go mutex (`sync.Mutex`). Inside this Go-side critical section, Go evaluates the Rust-carried tuple against Go's per-worker high-water mark and draws the #2170 generation (`takeDeleteGenV4`/`takeOpenGenV4`).
  - *Plan Text*: Line 383 states "Go draws #2170 generations in consumption order inside the arbiter", but line 361 states "The rule is ONE ARBITER... covering source admission, high-water update, AND the #2170 generation draw". To prevent implementation confusion, line 361 should explicitly state that the arbiter is **Go-side**, fed by Rust-carried tuples. (Logged as **Finding 1 [MINOR]**).

---

### 3. Codex r34 Folds Re-Attack

1. **F2 (One Deadline + Reserve-Before-Mutate + Fence-on-Unknown)**:
   - *Attack*: Line 267 states "with an explicit NACK or a forced authoritative re-bulk". In `pkg/cluster`, no `NACK` frame type exists in the wire protocol. Forcing a re-bulk requires the receiver to **disconnect the cluster socket**, which triggers the sender's disconnect re-drive at `sync_conn.go:572`.
   - *Verdict*: Sound concept, but the wire mechanism must be explicitly defined as connection teardown rather than an assumed non-existent wire message. (Logged as **Finding 2 [MINOR]**).
2. **F4 (Table-Authoritative Predicate + One Close Producer + Go Delete Request Re-validation)**:
   - *Attack*: Go policy invalidation sends a delete request for expected `id=100`. In Rust, under the per-key stripe lock, the helper compares `table[key].id == request.id`. If replaced by `id=101`, delete is refused and no Close is published. If key is absent, no entry is deleted and no Close is published (preventing double-publication).
   - *Verdict*: Sound. Go delete requests are safe requests re-evaluated against Rust table truth.
3. **F5 (Replica Refresh Field Ownership)**:
   - *Attack*: BPF writes replace the whole value. Helper executes a stripe-guarded RMW. Counter and policy ownership is singular: only the session's owning worker updates counters and policy ID.
   - *Verdict*: Sound. (Logged as **Finding 3 [NIT]** to explicitly note replica workers update only `last_seen`).
4. **F7 (Sticky Lineage Across Demote-then-Repromote)**:
   - *Attack*: An old-peer alias timeout-admitted on Standby gets promoted (`SyncImport` -> `SharedPromote`) on VRRP failover. Lineage metadata (`IsAliasLineage`) is orthogonal and sticky across promotion, demotion, and reconciliation. Export paths check `IsAliasLineage` and exclude the session from export to new peers.
   - *Verdict*: Sound. Promotion leak is closed.
5. **F8 (Copy-Time Binding)**:
   - *Attack*: Batch copy binds `(key, publication_id, recorded_generation)` at copy time (`maps_session.go:231`). Callbacks check binding mismatch before emitting. A intervening Close advances the generation, causing binding mismatch and safe frame omission.
   - *Verdict*: Sound.
6. **F9 (Helper Framed Snapshot as Recovery Source)**:
   - *Attack*: Extended `ExportOwnerRGSessions` includes `SharedPromote` rows, excludes sticky alias lineage, and carries `BulkStart`/`BulkEnd` absence-reconciliation framing. Cold-prime from an Active node post-failover correctly includes promoted rows for the new Standby.
   - *Verdict*: Sound.
7. **F10 (Quiet Interval)**:
   - *Attack*: To force an old peer (which only arms cold-prime on both connection slots being empty) to re-prime, the fencing node disconnects both fabrics and waits a quiet interval exceeding the peer's keepalive/heartbeat timeout before reconnecting.
   - *Verdict*: Sound. Dual-slot reconnect race is excluded.
8. **M11 (P2 In-Helper)**:
   - *Attack*: P2 exact-publication alias purge executes inside the Rust helper under Rule 4's transaction with publication identity, carrying the local-only delete shape (`delete_synced.rs:20`, no Close toward canonical owner). Retained Go-loop text in §5.6 is aligned.
   - *Verdict*: Sound.

---

### 4. AGY r34 NITs Verification

1. **Clear Latency Posture**: Folded in [`plan.md:236-242`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L236) — operator clears run as chunked IPC with per-chunk deadlines over the dedicated session socket.
2. **Metric Scope Qualification**: Folded in [`plan.md:2351-2410`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L2351) — 5 helper status mirrors + 3 Go cluster Prometheus counters = 8 total, with `Describe` registration at `metrics.go:791`.

---

### 5. Full-Plan Re-Attack & Final Findings

No BLOCKER or MAJOR defects remain in §4.0.1, §4.0.2, §5.x, §6, §7, or §8. The option-(a) core, machinery text, and sole-writer specifications are internally consistent.

#### Numbered Findings

1. **[MINOR] Arbiter Placement Scoping in Rule 6**
   - **File:Line**: [`plan.md:353-365`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L353) (§4.0.1 Rule 6)
   - **Description**: Rule 6 mandates "ONE ARBITER covering source admission, high-water update, AND the #2170 generation draw as a single critical section". Because source sequences are generated in Rust while generation drawing occurs in Go across two separate IPC lanes (event stream and RPC fallback), an inter-process critical section is impossible.
   - **Remediation**: Clarify in Rule 6 that the Arbiter is implemented **Go-side** (a `sync.Mutex` wrapping the Go event-stream callback and fallback-drain handlers), evaluating the Rust-carried tuple `(worker_id, source_seq, helper_epoch)` and drawing #2170 generations in a single Go critical section.

2. **[MINOR] Explicit Wire Mechanism for Fenced Receive Epoch / Forced Re-bulk (F2)**
   - **File:Line**: [`plan.md:267-272`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L267) (§4.0.1 Rule 2)
   - **Description**: Rule 2 specifies that helper refusal/timeout/unknown results abort the receive epoch "with an explicit NACK or a forced authoritative re-bulk". The `pkg/cluster` wire protocol contains no `NACK` message type.
   - **Remediation**: Explicitly state in Rule 2 that forced re-bulk is actuated by the receiver **tearing down (disconnecting) the cluster sync socket**, which triggers sender re-drive via `sync_conn.go:572`.

3. **[NIT] Non-Owner Replica Refresh Update Scope (F5)**
   - **File:Line**: [`plan.md:348-351`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L348) (§4.0.1 Rule 5)
   - **Description**: Rule 5 states that counter ownership is singular to the owning worker.
   - **Remediation**: Explicitly note that a non-owner replica worker's refresh update is strictly limited to updating the `last_seen` timestamp, preserving owner counters and policy state.

---

### Summary of Work

1. **Adjudicated & Fold-Checked v15.23**: Verified AGY r34 findings (Rule 3 two-ledger split, dedup invalidation, `restoreBPFSession` 11th writer, clear latency, metric scope) and Codex r34 findings (F1-F10, M11).
2. **Re-Attacked Specification Surface**: Confirmed the two-ledger applied transaction eliminates the decode-time `bulkRecv` deletion hazard while maintaining ACK integrity.
3. **Scoped Implementation Boundaries**: Identified Go-side arbiter placement and socket teardown re-bulk triggers as minor specification clarifications.
4. **Issued Final Verdict**: Delivered **PLAN-READY-WITH-NITS**.
