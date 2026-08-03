# AGY hostile plan review — #6751 (round 17)

**PLAN-READY-WITH-NITS**

---

### Adjudication & Evaluation of v15.3 Folds

#### 1. Overflow Terminal Action (Bulk Abort without ACK)
- **Mechanism**: Quarantine overflow (>4096 signature-matching frames in a single bulk) is now specified as a terminal bulk abort without ACK (`sync_conn_read.go:200`). This completely resolves Codex r16 B1: because bulk bookkeeping retains only keys (`sync_conn_read.go:200`) and frame payloads are consumed at decode time, evicted entries cannot be admitted later.
- **State Machine & Retry Integrity**: When the receiver aborts an incomplete bulk without ACK, `s.bulkInProgress` is set to `false` and `bulkRecvV4`/`bulkRecvV6` maps are discarded without releasing the sync-hold or running reconcile (`sync.go:1086`). The sender's bulk ACK timer expires, triggering a clean bulk re-drive.
- **Livelock Bound**: If a deployment genuinely exceeds the 4096 signature-matching threshold, repeated re-drives will hit the cap again. This is not a deadlock; the per-peer re-prime backoff prevents CPU spinning, `xpf_userspace_session_sync_alias_quarantine_overflow_total` alerts the operator, and the cap is user-configurable. Terminal abort without ACK is the only honest, fail-closed posture when payload memory is un-retained.

#### 2. Epoch-Death (Earliest-of-Three Terminal Points)
- **Terminal Point (i) - Own BulkEnd**: Quarantined frames are definitively evaluated against the full bulk received map (`bulkRecvV4`/`bulkRecvV6`). Matching base sessions confirm-and-drop the alias; unmatched entries are admitted before sending `syncMsgBulkAck` (`sync_conn_read.go:240`).
- **Terminal Point (ii) - Superseding BulkStart**: `sync_conn.go:496/554` shows that receiver bulk state resets only when *all* fabrics disconnect. If fabric 0 drops mid-E1 while fabric 1 stays up, E1 remains in progress until E2's `syncMsgBulkStart` arrives (`sync_conn_read.go:183/198`), which unconditionally overwrites E1's epoch and maps. Dropping E1's pinned quarantine entries fail-closed *before* overwriting the maps guarantees zero cross-epoch stale frame leakage.
- **Terminal Point (iii) - Per-Bulk Receive Deadline**: Existing read deadlines (`sync_conn_read.go:27`) only handle connection heartbeats. A stalled sender mid-bulk is now terminated by an explicit per-bulk receive deadline, aborting the bulk without ACK and dropping pinned entries fail-closed.
- **Exhaustive Edge Analysis (No 4th Death Shape)**:
  - *Peer Process / Daemon Restart*: Causes connection drop; `handleDisconnect` (`sync_conn.go:480`) resets state when all fabrics disconnect (`!connected`), dropping entries fail-closed.
  - *Single-Fabric Drop without Re-drive*: Covered by Terminal Point (iii) (Receive Deadline).
  - *Mid-Bulk Re-connect*: Triggers Terminal Point (ii) (`BulkStart`).

#### 3. Capability Lifecycle
- **Four-Branch Omission Gate**: Skips alias derivation across all 4 alias creation/deletion locations in `pkg/daemon/daemon_ha_userspace_stream.go`: line 373 (V4 open), line 386 (V6 open), line 400 (V4 close), and line 413 (V6 close). This prevents orphaned alias deletes from being transmitted for sessions opened before capability discovery.
- **Periodic Re-Advertisement**: Because `sendClockSync` (`sync_conn.go:137`) runs only once at connection setup, capability frames ride a named periodic transport (e.g. periodic capability ticker or piggybacked message).
- **Reset to UNKNOWN**: Capability state resets to `UNKNOWN` on every connection/re-connection (`sync_conn.go:480`), ensuring safe fallback to `DERIVE-UNTIL-CAPABLE`.

#### 4. Final Adjudication
No BLOCKER or MAJOR issues remain in the alias discipline or the core #6751 design. All invariants (node-lifetime `InterfaceNatAllocators` registry, tri-state reserve scan, tuple-versioned staged replacement records, `HolderSet` scope counts, overlap foreclosure with atomic drain, and production counters) are fully specified and consistent.

---

### Numbered Findings

1. **NIT**: Named Periodic Transport Selection for Capability Re-Advertisement
   - **File/Line**: [`pkg/cluster/sync_conn.go:137`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L137), [`pkg/daemon/daemon_ha_userspace_stream.go:370`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go#L370)
   - **Detail**: Section 5.6 specifies that capability re-advertisement rides a named periodic transport (either a dedicated capability ticker or piggybacking on an existing periodic message stream). The precise choice between a new ticker vs piggybacking on clock sync should be selected during implementation.

2. **NIT**: Prometheus Reason Labeling for Registry Cap Exhaustion Counter
   - **File/Line**: [`docs/research/6751-nopat-admission/plan.md:903`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L903)
   - **Detail**: Section 5.8 defines `xpf_userspace_interface_snat_registry_cap_exhaustion_total` for both per-address flow cap (64512) and retained allocator cap (256). Adding an optional `reason` label (`flow_cap` vs `allocator_cap`) will assist operators in distinguishing registry storage exhaustion from flow density limits.

3. **NIT**: Structured Diagnostic Logging on Per-Peer Quarantine Overflow
   - **File/Line**: [`pkg/cluster/sync_conn_read.go:200`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go#L200)
   - **Detail**: When a quarantine overflow (>4096 signature-matching frames) triggers a terminal bulk abort, an `slog.Warn` log should be emitted alongside incrementing `xpf_userspace_session_sync_alias_quarantine_overflow_total`, logging the remote peer address and epoch ID for operational debugging.
