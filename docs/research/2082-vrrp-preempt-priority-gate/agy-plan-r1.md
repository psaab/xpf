# Adversarial Design Review: VRRP Preempt Priority Gate (Issue #2082)

This document contains a hostile design and reachability review of the plan proposed in `docs/research/2082-vrrp-preempt-priority-gate/plan.md`.

---

## 1. Executive Summary & Verdict

**Overall Plan Verdict:** **`PLAN-NEEDS-WORK`**

The implementation direction proposed in the plan is **correct in its core diagnosis**—the lower-priority preempt path is fully reachable, and the bug causes a transient dual-master state on sync-hold release. However, the plan contains a **critical deadlock risk** in its lock-ordering analysis and is **over-engineered and non-compliant with RFC 5798** in its handling of equal-priority preemption. Furthermore, the integration test plan is **blind** because the default test configurations do not enable the preempt flag.

---

## 2. Detailed Findings

### Specific Attack Point (1): Reachability Analysis
* **Verdict:** **`VERIFIED REACHABLE`**
* **Evidence & Source Verification:**
  1. **Preempt flag replication:** `RedundancyGroup.Preempt` is parsed as a global setting in `pkg/config/compiler_system.go:1038`. In `pkg/vrrp/vrrp.go:97, 154, 173`, this boolean is copied to the VRRP config (`cfg.Preempt`) of both primary and secondary nodes. Thus, the Secondary node has `Preempt = true` whenever preempt is configured on the RG.
  2. **Secondary Priority:** Under `pkg/cluster/group_state.go:212-217`, `LocalPriorities()` assigns priority `200` to the Primary node and `100` to the Secondary node.
  3. **Release sync hold trigger:** When bulk session sync completes on the rejoining Secondary node, `onSessionSyncBulkReceived()` (`pkg/daemon/daemon_ha_sync.go:88`) calls `d.vrrpMgr.ReleaseSyncHold()`. This calls `releaseSyncHoldWithReason()` (`pkg/vrrp/manager.go:159-162`), which loops over all instances and calls `vi.restorePreempt()` (restoring `Preempt = true` on the Secondary node) and `vi.triggerPreemptNow()` (writing to `vi.preemptNowCh`).
  4. **Unconditional takeover:** In `pkg/vrrp/instance.go:423-437`, the `run()` loop handles `preemptNowCh` by reading `vi.getPreempt() || force`. Since `vi.getPreempt()` returns `true` (it was just restored) and `force` is `false`, it calls `vi.becomeMaster()` unconditionally, completely ignoring the priority mismatch.
* **Conclusion:** The path is fully reachable. The Secondary node (priority 100) will unconditionally transition to MASTER on sync-hold release, causing a transient dual-master state. A `PLAN-KILL` on the grounds of unreachability is rejected.

---

### Specific Attack Point (2): Path A's Gate Correctness & Deadlock Hazard
* **Verdict:** **`PLAN-NEEDS-WORK`**
* **Lock-Ordering Deadlock (CRITICAL):**
  - The plan proposes to implement `shouldPreemptObservedMaster()` under `vi.mu` (locking `vi.mu.Lock()` or `vi.mu.RLock()`), and inside it, call `getPriority()` and `masterDownInterval()`.
  - Both `getPriority()` and `masterDownInterval()` internally acquire `vi.mu.RLock()` (see `instance.go:266` and `instance.go:346`).
  - In Go, nested read locks on a `sync.RWMutex` can easily deadlock if a writer lock request is pending. If another goroutine (such as the cluster manager calling `setTrackDown` or `setState`) requests a write lock (`vi.mu.Lock()`) while the outer reader lock is held, the write request blocks. Consequently, any subsequent read lock requests (including the nested reader locks inside `getPriority()` or `masterDownInterval()`) will block behind the pending writer. This creates an immediate recursive read-lock deadlock.
  - **Correction required:** The implementation must define unlocked private helper variants (e.g. `getPriorityLocked()` and `masterDownIntervalLocked()`) and use them within the locked scope of the gate, or extract the priority and timer values *before* acquiring the gate lock.
* **RFC 5798 Compliance and Equal Priority Tie-break:**
  - The plan proposes using an IP tie-break for equal-priority nodes (`getPriority() == lastMasterPriority`).
  - Under RFC 5798 §6.4.2, a backup node of equal priority does **not** preempt an active master, even if the backup has a higher IP address. Preemption is strictly reserved for higher-priority backups. The IP tie-break is only used in `handleMasterRx` to resolve MASTER-MASTER collision states.
  - Incorporating the IP tie-break into the preempt gate is non-compliant with RFC 5798 and introduces unnecessary state bloating (requiring the instance to record and track the peer master's IP address).
  - **Correction required:** The gate should use strict `>`: `getPriority() > lastMasterPriority`. If priorities are equal, it should return `false` (no preemption).
* **Staleness Threshold:**
  - Gating preemption on `lastMasterSeen` being within `masterDownInterval()` is correct and does not create a deadlock. If the master dies, the `masterDownTimer` expires and promotes the backup node unconditionally via a separate code block (`case <-masterDownTimer.C:`), bypassing the gate.

---

### Specific Attack Point (3): Timing Regression & Priority-0 Takeover
* **Verdict:** **`VERIFIED SAFE`**
* **Evidence & Source Verification:**
  - **ForceRGMaster:** Secondary->Primary cluster-directed promotion calls `ForceRGMaster` (`pkg/daemon/daemon_ha.go:243`), which sets `vi.forcePreemptOnce = true` under lock and triggers `preemptNowCh`. Since the gate is bypassed when `force == true` (`if force || shouldPreemptObservedMaster()`), the transition remains immediate and does not regress the ~60ms budget.
  - **Priority-0 Takeover:** Immediate takeover upon receiving a peer's priority-0 advertisement is handled in the `vi.rxCh` case inside `handleBackupRx` (`instance.go:783-792`). It resets `masterDownTimer` to `1ms` directly, bypassing the `preemptNowCh` flow entirely.
  - **Primary Preemption:** When the Primary node (priority 200) boots or completes bulk sync, it will have recorded `lastMasterPriority = 100` from the Secondary node's adverts. The gate evaluates `200 > 100`, which passes instantly, resulting in zero-delay preemption.

---

### Specific Attack Point (4): Test Plan Strength
* **Verdict:** **`PLAN-NEEDS-WORK`**
* **Test Blindness:**
  - The proposed unit tests are strong and will correctly fail on unpatched code.
  - However, the integration test suite (`make test-failover`) runs on configs (`docs/ha-cluster-userspace.conf` and `docs/ha-cluster-loss.conf`) that do **not** have the `preempt` flag enabled on any redundancy group.
  - Because `preempt` is false, `cfg.Preempt` remains false on sync-hold release, and the unpatched code's bug path is never executed. Thus, `make test-failover` will pass on unpatched code, rendering it useless as an integration-level regression guard.
  - **Correction required:** The test plan must include modifying `ha-cluster-userspace.conf` to enable `preempt` on `redundancy-group 1` (or another group), verifying that unpatched code fails or logs dual-master states, and verifying that patched code passes cleanly.

---

## 3. Required Modifications for PLAN-READY

To transition the plan to `PLAN-READY`, the architect must revise the plan to address the following:

1. **Deadlock Prevention:** Explicitly document the creation of unlocked helper methods (`getPriorityLocked()` and `masterDownIntervalLocked()`) to avoid recursive read-lock acquisitions.
2. **RFC Compliance:** Remove the IP tie-break from the gate. Use a strict priority comparison: `getPriority() > lastMasterPriority`. Do not record the master's IP address.
3. **Integration Test Hardening:** Specify a change to the test configuration (e.g. `ha-cluster-userspace.conf`) to enable preemption, ensuring that `make test-failover` is a functional regression test.
