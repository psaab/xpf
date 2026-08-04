# AGY hostile plan review — #6751 (round 42)

# Adversarial Plan Review: Issue #6751 — Research Round 42 (Convergence Adjudication)

**Target Document**: [`docs/research/6751-nopat-admission/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md) (v15.30, commit `7a5c3e91e`)  
**Verdict**: **`PLAN-READY-WITH-NITS`**

---

## Executive Summary & Convergence Status

All four Codex r41 `BLOCKER` findings have been folded cleanly into v15.30. Both substrate and behavior forks remain settled (Path A sole-writer helper; Option (a) reserve-or-PAT). No new `BLOCKER` or `MAJOR` issues survive grep-level verification. Two minor summary/inventory text `NIT`s remain.

---

## Detailed Attack & Verification Analysis

### 1. Codex r41 BLOCKER 1 Fold Analysis (Capability Emission Gate & Scoping)

- **(a) Gate Placement & Reader-Start Order**:
  - The capability frame is specified as an **ordered pre-data send** of additive `syncMsgCapability` sent as a checked direct write **BEFORE** the connection is published (`installConn`) for general selection by the global writer (`plan.md:1394-1400`).
  - Because writing occurs synchronously before registering the connection into active selection maps (`sync_conn_write.go:268-300`), lossy `queueMessage` dispatches cannot precede or overtake the capability frame on TCP. Reader loop launch (`receiveLoop`) on the remote peer naturally receives the capability frame first on the incoming stream. The placement text is unambiguous.
- **(b) Fail-Closed Posture vs. Safe Degradation**:
  - `plan.md:1406-1408` explicitly states: *"under the gate, a failed capability write fails the connection and its cold-prime, and no data frame can precede the capability frame"*.
  - The pricing is explicit: failed writes abort connection setup and rely on standard sync reconnect retries (`sync_conn.go:435`). Starting UNKNOWN degradation (`plan.md:1427-1433`) serves as the safe runtime default if a remote peer does not advertise capability.
- **(c) Verification of `definitive` Scoping**:
  - Grep verification confirms that primary normative sections (§1 lines 10–14, §4 lines 717–723, §5.6 lines 2333–2343) strictly scope lineage-definitive epoch resolution to capability-advertising windows, leaving non-capable windows as disposition-only.
  - *(See Nit 1 for minor un-scoped recap phrases in §9).*

---

### 2. Codex r41 BLOCKER 2 Fold Verification (Derived Interval Everywhere)

- **Grep Verification**:
  - `2.5×keepalive` / `7.5s` references: **0 active operational occurrences found**. `2.5` appears only in status recap notes (`plan.md:15`, `plan.md:667`) explaining the fold.
  - `7.5s`: **0 occurrences**.
  - All operational sites updated to `quiet_interval = 2 × syncReadDeadline + 5s` (`plan.md:15-16`, `668`, `770`).
- **Verdict**: BLOCKER 2 is fully resolved.

---

### 3. Codex r41 BLOCKER 3 Fold Analysis (Seventh Lifecycle Event & Ordering)

- **(a) Cancellation Primitive**:
  - The 7th event (`fence-cycle expiry`) mints an `(abortGeneration, lifecycleSequence)` tuple at admission (`plan.md:779-783`).
  - Cancellation is achieved via generation invalidation at the CAS commit gate (`plan.md:1718-1725`) combined with explicit timer stopping (`stopSyncReadyTimer` / `Timer.Stop()`).
- **(b) Fence-State Revalidation Placement**:
  - `plan.md:784-789` and `plan.md:19-21` explicitly state that fence-state revalidation executes **INSIDE the readiness commit unit** alongside arming generation and connected state.
  - This prevents async disconnect notification races (`sync_conn.go:569-570`) from releasing readiness if fence engagement committed prior to execution.
- **(c) Completeness of Distinct Release Effect**:
  - `plan.md:790-796` explicitly isolates the degraded release: it releases the sync hold **WITHOUT** setting `syncBulkPrimed = true`, **WITHOUT** recording `bulk-sync-complete` (`daemon_ha_sync.go:90-100` / `vrrp/manager.go:380-405`), and **WITHOUT** discharging either delivery or alias debt.
  - No extraneous callbacks or debt discharges leak into the degraded release path.

---

### 4. Codex r41 BLOCKER 4 Fold Analysis (Private-RG Gate Introduction)

- **Blast Radius & Precedent**:
  - Production code today (`pkg/daemon/daemon_ha_vip.go:40-55`) omits `IsSyncReady()` checks for private-RG takeover.
  - v15.30 explicitly introduces the private-RG sync readiness gate (`plan.md:24-29`, `798-810`, `3081`), mirroring the classic RETH VRRP 30s sync hold (`pkg/vrrp/manager.go:351-376`).
  - **Blast Radius & Cost**: Private-RG failovers will now wait until `IsSyncReady()` is true or until the fence's degraded terminal fires. This delay prevents premature takeover before session tables sync (preventing packet drops/state corruption). The delay and §9 refusal pin are explicitly priced (`plan.md:806-812`).

---

### 5. Full-Plan Convergence Sweep & Findings

#### Finding 1 (NIT) — Un-scoped recap text in Section 9 summary checklist
- **File & Lines**: [`docs/research/6751-nopat-admission/plan.md:3266-3268`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3266-L3268) and [`plan.md:3390-3393`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L3390-L3393)
- **Detail**: While §1 (`L10-L14`), §4 (`L717-L723`), and §5.6 (`L2333-L2343`) explicitly scope lineage-definitive resolution to capability-advertising windows only, summary lines in §9 (`L3266` and `L3390`) retain un-scoped legacy recap phrasing (*"at BulkEnd the complete snapshot makes the sibling-base check definitive"*).
- **Remediation**: Append `WHEN THE WINDOW IS CAPABILITY-ADVERTISING` to the summary recap phrases in §9 for full textual consistency.

#### Finding 2 (NIT) — Older 6-event parenthetical in Section 5.6
- **File & Lines**: [`docs/research/6751-nopat-admission/plan.md:1674-1675`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1674-L1675)
- **Detail**: The status header (`L16-L18`) and §4 (`L778-L783`) explicitly document `fence-cycle expiry` joining as the 7th lifecycle event type. However, the parenthetical in §5.6 (`L1674-L1675`) still lists 6 events: `(abort, admission, disconnect, bulk-received, bulk-ack-received, AND readiness-timeout — the complete event inventory, Codex r26 blocker 1)`.
- **Remediation**: Update line 1675 parenthetical to include `fence-cycle expiry` as the 7th inventory item.

---

## Final Verdict

**`PLAN-READY-WITH-NITS`**

The plan is mathematically and architecturally complete. Implementors may proceed with execution.
